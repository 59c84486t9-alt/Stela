//! A call gate: native code a guest thread enters through a device access,
//! reaching that thread's memory as its own unprivileged loads and stores
//! would.
use alloc::sync::Arc;
use core::num::NonZeroU64;

/// Why the caller's memory refused an access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerFault {
    /// The address is unmapped, or the caller may not access it so.
    Denied { address: u64 },
    /// The address maps something other than ordinary RAM.
    NotRam { address: u64 },
    /// The caller's translation uses a configuration the model does not
    /// implement.
    Unsupported(&'static str),
}

/// The address space of the thread whose device access is being served,
/// checked with EL0 permissions in its current translation regime.
pub trait CallerMemory {
    fn read(&mut self, address: u64, buffer: &mut [u8]) -> Result<(), CallerFault>;
    /// Writes nothing unless every byte is writable RAM.
    fn write(&mut self, address: u64, data: &[u8]) -> Result<(), CallerFault>;
}

/// The native service a gate enters, by connection. Calls run on the PEs
/// that make them, outside the board's lock, so one call's length is no
/// other PE's; the service orders them itself.
pub trait GateService: Send + Sync {
    fn connect(&self) -> Result<NonZeroU64, &'static str>;
    /// Releases what the connection holds; in-flight work completes.
    fn disconnect(&self, connection: NonZeroU64);
    /// Runs the call whose record is at `record` in `caller`, completing
    /// the record; fails only when the record is out of reach.
    fn serve(
        &self,
        connection: NonZeroU64,
        record: u64,
        caller: &mut dyn CallerMemory,
    ) -> Result<(), CallerFault>;
    /// Whether the GPU completed work since this last answered true. Under
    /// the board's lock, so it answers at once.
    fn signaled(&self) -> bool;
}

/// What a store to a gate window asks of the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateRequest {
    Open,
    Close(NonZeroU64),
    Serve {
        gate: usize,
        connection: NonZeroU64,
        record: u64,
    },
}

/// A request's result, for the gate to record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateOutcome {
    Opened(Option<NonZeroU64>),
    Closed,
    Served {
        gate: usize,
        connection: NonZeroU64,
        fault: Option<CallerFault>,
    },
}

/// A store's request, taken from the gate to run in that store's own step
/// outside the board's lock.
pub struct GateCall {
    service: Arc<dyn GateService>,
    request: GateRequest,
}

impl GateCall {
    pub fn new(service: Arc<dyn GateService>, request: GateRequest) -> Self {
        Self { service, request }
    }

    pub fn run(self, caller: &mut dyn CallerMemory) -> GateOutcome {
        match self.request {
            GateRequest::Open => GateOutcome::Opened(self.service.connect().ok()),
            GateRequest::Close(connection) => {
                self.service.disconnect(connection);
                GateOutcome::Closed
            }
            GateRequest::Serve {
                gate,
                connection,
                record,
            } => GateOutcome::Served {
                gate,
                connection,
                fault: self.service.serve(connection, record, caller).err(),
            },
        }
    }
}

/// Defines a block of 64-bit layout constants and [`LAYOUT`] listing them,
/// from which the kext's header is generated.
macro_rules! layout {
    ($($(#[doc = $doc:literal])* $name:ident = $value:expr;)*) => {
        $($(#[doc = $doc])* pub const $name: u64 = $value;)*
        /// Every constant above, by name.
        pub const LAYOUT: &[(&str, u64)] = &[$((stringify!($name), $name)),*];
    };
}

/// The StelaGPU gate window at `/arm-io/stela-gpu`, as the runtime models
/// it and the StelaGPU kext drives it.
///
/// Page 0 is the kext's control page. Page `n` (1 to [`CONNECTIONS`]) is
/// connection `n`'s gate, which the kext maps into the one task it opened
/// the connection for. Every register is 64-bit.
pub mod window {
    layout! {
        /// The guest's page: the unit one task maps.
        PAGE = 0x4000;
        /// Connections the window has gates for.
        CONNECTIONS = 255;
        /// The window: the control page and every gate.
        BYTES = PAGE * (CONNECTIONS + 1);

        /// Control: a store opens a connection.
        OPEN = 0x00;
        /// Control: the gate page of the last open, 0 when it failed.
        OPENED = 0x08;
        /// Control: a store of a gate page closes its connection.
        CLOSE = 0x10;
        /// Control: the number of gate pages.
        COUNT = 0x18;
        /// Control: 1 while completed work is unacknowledged.
        STATUS = 0x20;
        /// Control: a store acknowledges completed work.
        ACK = 0x28;

        /// Gate: a store names a call record.
        CALL = 0x00;
        /// Gate: why the last call's record was out of reach, 0 for none.
        FAULT = 0x08;

        /// `FAULT`: the record is unmapped or not the caller's to access.
        FAULT_DENIED = 1;
        /// `FAULT`: the record is not RAM.
        FAULT_NOT_RAM = 2;
        /// `FAULT`: the caller's translation is one the model lacks.
        FAULT_UNSUPPORTED = 3;
    }
}
