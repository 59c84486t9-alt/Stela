//! StelaGPU's call gate: the window through which the StelaGPU kext opens a
//! connection for each task and the task enters the native GPU service
//! with no kernel crossing per call.
//!
//! Page 0 is the kext's control page. Page `n` (1 to [`CONNECTIONS`]) is
//! connection `n`'s gate, which the kext maps into the one task it opened
//! the connection for: holding that mapping is the task's authority. Pages
//! are the guest's 16 KiB, so no task maps another's gate.
//!
//! A 64-bit store to a gate's `CALL` names a call record in the storing
//! thread's memory. The service runs it in the store's own step, on that
//! thread's PE and address space ([`Gate::serve`]), and completes the
//! record in place; the store retires once the call has. Only when the
//! record itself is out of the thread's reach does the gate's `FAULT`
//! report why.
use super::bus::{Access, Direction, MmioDevice, MmioError, Width, refuse};
use alloc::{boxed::Box, collections::BTreeMap};
use core::num::NonZeroU64;
use stela_contracts::{
    bus::AdvancePolicy,
    gate::{CallerFault, CallerMemory},
};

/// The guest's page: the unit one task maps.
pub const PAGE: u64 = 0x4000;
/// Connections the window has gates for.
pub const CONNECTIONS: usize = 255;
/// The window: the control page and every gate.
pub const BYTES: u64 = PAGE * (CONNECTIONS as u64 + 1);

/// Control: a store opens a connection.
const OPEN: u64 = 0x00;
/// Control: the gate page of the last open, 0 when it failed.
const OPENED: u64 = 0x08;
/// Control: a store of a gate page closes its connection.
const CLOSE: u64 = 0x10;
/// Control: the number of gate pages.
const COUNT: u64 = 0x18;
/// Gate: a store names a call record.
const CALL: u64 = 0x00;
/// Gate: why the last call's record was out of reach, 0 for none.
const FAULT: u64 = 0x08;

/// [`FAULT`] values.
const DENIED: u64 = 1;
const NOT_RAM: u64 = 2;
const UNSUPPORTED: u64 = 3;

const NAME: &str = "stela-gpu-gate";

/// The native service the gate enters.
pub trait GateService {
    fn connect(&mut self) -> Result<NonZeroU64, &'static str>;
    /// Releases what the connection holds; in-flight work completes.
    fn disconnect(&mut self, connection: NonZeroU64);
    /// Runs the call whose record is at `record` in `caller`, completing
    /// the record; fails only when the record is out of reach.
    fn serve(
        &mut self,
        connection: NonZeroU64,
        record: u64,
        caller: &mut dyn CallerMemory,
    ) -> Result<(), CallerFault>;
}

pub struct Gate {
    service: Box<dyn GateService>,
    /// The connection of each gate page, by page - 1.
    connections: [Option<NonZeroU64>; CONNECTIONS],
    faults: [u64; CONNECTIONS],
    opened: u64,
    /// The call each PE's store named, until that store's step serves it.
    pending: BTreeMap<usize, (usize, u64)>,
}

impl Gate {
    pub fn new(service: Box<dyn GateService>) -> Self {
        Self {
            service,
            connections: [None; CONNECTIONS],
            faults: [0; CONNECTIONS],
            opened: 0,
            pending: BTreeMap::new(),
        }
    }

    /// Runs the call PE `cpu`'s store named, on that PE's address space.
    pub fn serve(&mut self, cpu: usize, caller: &mut dyn CallerMemory) {
        let Some((gate, record)) = self.pending.remove(&cpu) else {
            return;
        };
        // A close between the store and its step leaves nothing to run.
        let Some(connection) = self.connections[gate] else {
            return;
        };
        self.faults[gate] = match self.service.serve(connection, record, caller) {
            Ok(()) => 0,
            Err(CallerFault::Denied { .. }) => DENIED,
            Err(CallerFault::NotRam { .. }) => NOT_RAM,
            Err(CallerFault::Unsupported(_)) => UNSUPPORTED,
        };
    }

    fn open(&mut self) {
        self.opened = 0;
        let Some(gate) = self.connections.iter().position(Option::is_none) else {
            return;
        };
        if let Ok(connection) = self.service.connect() {
            self.connections[gate] = Some(connection);
            self.faults[gate] = 0;
            self.opened = gate as u64 + 1;
        }
    }

    fn close(&mut self, page: u64) -> Result<(), &'static str> {
        let gate = gate_index(page).ok_or("no gate page")?;
        let connection = self.connections[gate].take().ok_or("a closed gate")?;
        self.pending.retain(|_, &mut (pending, _)| pending != gate);
        self.service.disconnect(connection);
        Ok(())
    }
}

/// The gate index of gate page `page`.
fn gate_index(page: u64) -> Option<usize> {
    let gate = usize::try_from(page).ok()?.checked_sub(1)?;
    (gate < CONNECTIONS).then_some(gate)
}

impl MmioDevice for Gate {
    fn advance_policy(&self) -> AdvancePolicy {
        AdvancePolicy::Passive
    }

    fn name(&self) -> &'static str {
        NAME
    }

    fn read(
        &mut self,
        offset: u64,
        width: Width,
        _access: &mut Access<'_>,
    ) -> Result<u64, MmioError> {
        let refused = |reason| refuse(NAME, offset, width, Direction::Read, reason);
        if width != Width::Double {
            return Err(refused("registers are 64-bit"));
        }
        let (page, register) = (offset / PAGE, offset % PAGE);
        match (page, register) {
            (0, OPENED) => Ok(self.opened),
            (0, COUNT) => Ok(CONNECTIONS as u64),
            (_, FAULT) => {
                let gate = gate_index(page).ok_or_else(|| refused("no such register"))?;
                Ok(self.faults[gate])
            }
            _ => Err(refused("no such register")),
        }
    }

    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let refused = |reason| refuse(NAME, offset, width, Direction::Write, reason);
        if width != Width::Double {
            return Err(refused("registers are 64-bit"));
        }
        let (page, register) = (offset / PAGE, offset % PAGE);
        match (page, register) {
            (0, OPEN) => self.open(),
            (0, CLOSE) => self.close(value).map_err(refused)?,
            (_, CALL) => {
                let gate = gate_index(page).ok_or_else(|| refused("no such register"))?;
                if self.connections[gate].is_none() {
                    return Err(refused("a call through a closed gate"));
                }
                self.pending.insert(access.cpu, (gate, value));
            }
            _ => return Err(refused("no such register")),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{rc::Rc, vec::Vec};
    use core::cell::RefCell;
    use stela_contracts::interrupt::{InterruptSink, Wire};

    #[derive(Default)]
    struct Log {
        next: u64,
        disconnected: Vec<u64>,
        served: Vec<(u64, u64, u8)>,
    }

    struct Service(Rc<RefCell<Log>>);

    impl GateService for Service {
        fn connect(&mut self) -> Result<NonZeroU64, &'static str> {
            let mut log = self.0.borrow_mut();
            log.next += 1;
            NonZeroU64::new(log.next).ok_or("exhausted")
        }

        fn disconnect(&mut self, connection: NonZeroU64) {
            self.0.borrow_mut().disconnected.push(connection.get());
        }

        fn serve(
            &mut self,
            connection: NonZeroU64,
            record: u64,
            caller: &mut dyn CallerMemory,
        ) -> Result<(), CallerFault> {
            let mut byte = [0];
            caller.read(record, &mut byte)?;
            self.0
                .borrow_mut()
                .served
                .push((connection.get(), record, byte[0]));
            Ok(())
        }
    }

    /// One byte per address below 0x100.
    struct Caller;

    impl CallerMemory for Caller {
        fn read(&mut self, address: u64, buffer: &mut [u8]) -> Result<(), CallerFault> {
            let byte = u8::try_from(address).map_err(|_| CallerFault::Denied { address })?;
            buffer.fill(byte);
            Ok(())
        }

        fn write(&mut self, address: u64, _data: &[u8]) -> Result<(), CallerFault> {
            Err(CallerFault::Denied { address })
        }
    }

    struct NoInterrupts;

    impl InterruptSink for NoInterrupts {
        fn set_level(&mut self, _wire: Wire, _asserted: bool) {}
    }

    fn store(gate: &mut Gate, cpu: usize, offset: u64, value: u64) -> Result<(), MmioError> {
        gate.write(
            offset,
            Width::Double,
            value,
            &mut Access::new(cpu, 0, &mut NoInterrupts),
        )
    }

    fn load(gate: &mut Gate, offset: u64) -> u64 {
        gate.read(
            offset,
            Width::Double,
            &mut Access::new(0, 0, &mut NoInterrupts),
        )
        .unwrap()
    }

    fn opened(gate: &mut Gate) -> u64 {
        store(gate, 0, OPEN, 0).unwrap();
        load(gate, OPENED)
    }

    #[test]
    fn each_pe_serves_the_call_its_own_store_named() {
        let log = Rc::new(RefCell::new(Log::default()));
        let mut gate = Gate::new(Box::new(Service(log.clone())));
        assert_eq!(load(&mut gate, COUNT), CONNECTIONS as u64);
        let (first, second) = (opened(&mut gate), opened(&mut gate));
        assert_eq!((first, second), (1, 2));
        store(&mut gate, 3, first * PAGE + CALL, 0x11).unwrap();
        store(&mut gate, 5, second * PAGE + CALL, 0x22).unwrap();
        gate.serve(5, &mut Caller);
        gate.serve(3, &mut Caller);
        gate.serve(3, &mut Caller);
        assert_eq!(log.borrow().served, [(2, 0x22, 0x22), (1, 0x11, 0x11)]);
        store(&mut gate, 3, first * PAGE + CALL, 0x1000).unwrap();
        gate.serve(3, &mut Caller);
        assert_eq!(load(&mut gate, first * PAGE + FAULT), DENIED);
    }

    #[test]
    fn closed_gates_refuse_calls_and_drop_pending_ones() {
        let log = Rc::new(RefCell::new(Log::default()));
        let mut gate = Gate::new(Box::new(Service(log.clone())));
        let page = opened(&mut gate);
        store(&mut gate, 0, page * PAGE + CALL, 0x11).unwrap();
        store(&mut gate, 0, CLOSE, page).unwrap();
        gate.serve(0, &mut Caller);
        assert!(log.borrow().served.is_empty());
        assert_eq!(log.borrow().disconnected, [1]);
        assert!(store(&mut gate, 0, page * PAGE + CALL, 0x11).is_err());
        assert!(store(&mut gate, 0, CLOSE, page).is_err());
        assert!(store(&mut gate, 0, (CONNECTIONS as u64 + 1) * PAGE + CALL, 0).is_err());
        assert!(
            gate.write(
                OPEN,
                Width::Word,
                0,
                &mut Access::new(0, 0, &mut NoInterrupts)
            )
            .is_err()
        );
    }
}
