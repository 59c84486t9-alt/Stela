//! Retained native requester and register ownership for the polled xHCI core.
use super::*;
use crate::bus::{
    dma::{
        mapping::DmaDomain,
        memory::{CacheAttribute, PageSource},
        region,
    },
    irq::{IrqError, IrqRegistration},
    mmio::owned::{Mapping, Protection},
    pci::{ConfigSpace, owned::OwnedConfig},
};
use alloc::sync::Arc;
use core::{cell::Cell, mem::ManuallyDrop};

/// The actual paired resources. Numeric PCI/BAR geometry does not grant them.
pub struct Resources {
    pub function: Function<OwnedConfig>,
    pub registers: Mapping,
    pub pages: Arc<dyn PageSource>,
    pub domain: Arc<dyn DmaDomain>,
    pub irq: Box<dyn IrqRegistration>,
    pub clock: Clock,
}

#[derive(Debug)]
pub enum Error {
    Controller(BlockError),
    Irq(IrqError),
    Registers,
    BusMaster,
}

struct Owner {
    // Until an actual stop/original-domain drain/IRQ drain/unmap boundary is
    // implemented, dropping any native handle retains this complete owner.
    // Neither a replacement domain nor HCRST certifies old-route retirement.
    resources: RefCell<ManuallyDrop<Resources>>,
    register_failure: Rc<Cell<Option<usize>>>,
}

struct Access(Rc<Owner>);
impl Registers for Access {
    fn read32(&mut self, offset: usize) -> u32 {
        if self.0.register_failure.get().is_some() {
            return u32::MAX;
        }
        let resources = self.0.resources.borrow();
        let Ok(pointer) = resources.registers.address(offset, 4) else {
            self.0.register_failure.set(Some(offset));
            return u32::MAX;
        };
        if !(pointer.as_ptr() as usize).is_multiple_of(4) {
            self.0.register_failure.set(Some(offset));
            return u32::MAX;
        }
        // SAFETY: actual retained UC BAR mapping; exclusive serialized access.
        u32::from_le(unsafe { pointer.as_ptr().cast::<u32>().read_volatile() })
    }
    fn write32(&mut self, offset: usize, value: u32) {
        if self.0.register_failure.get().is_some() {
            return;
        }
        let resources = self.0.resources.borrow();
        let Ok(pointer) = resources.registers.address(offset, 4) else {
            self.0.register_failure.set(Some(offset));
            return;
        };
        if !(pointer.as_ptr() as usize).is_multiple_of(4) {
            self.0.register_failure.set(Some(offset));
            return;
        }
        // SAFETY: same checked original UC BAR, exclusive writer.
        unsafe {
            pointer.as_ptr().cast::<u32>().write_volatile(value.to_le());
        }
    }
    fn size(&self) -> Option<usize> {
        self.0.resources.borrow().registers.bytes().ok()
    }
}

pub struct Failure {
    pub error: Error,
    owner: Rc<Owner>,
    controller: Option<Box<Controller>>,
    memory: Option<Rc<memory::Native>>,
}
impl Failure {
    pub fn dma_error(&self) -> Option<region::Error> {
        self.memory.as_ref().and_then(|m| m.error())
    }
    pub fn register_error(&self) -> Option<usize> {
        self.owner.register_failure.get()
    }
    pub fn retains_controller_storage(&self) -> bool {
        self.controller.is_some()
    }
    pub fn retains_original_requester(&self) -> bool {
        Rc::strong_count(&self.owner) != 0
    }
}

struct NoBoot;
impl DmaAllocator for NoBoot {
    fn allocate(&mut self, _: usize, _: usize) -> Result<DmaBuffer, BlockError> {
        Err(BlockError::Unsupported(
            "native xHCI cannot allocate identity DMA",
        ))
    }
}

/// CPU-owned actual requester-domain payload. No device address escapes.
/// Submission consumes this owner; a live/uncertain TD exposes no CPU slice.
pub struct Payload {
    buffer: memory::Buffer,
    memory: Rc<memory::Native>,
}
impl Payload {
    pub fn len(&self) -> usize {
        self.buffer.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), BlockError> {
        let end = offset
            .checked_add(bytes.len())
            .filter(|end| *end <= self.len())
            .ok_or(BlockError::Unsupported("native USB payload bounds"))?;
        self.buffer.bytes_mut()[offset..end].copy_from_slice(bytes);
        Ok(())
    }
    pub fn read(&self, offset: usize, bytes: &mut [u8]) -> Result<(), BlockError> {
        let end = offset
            .checked_add(bytes.len())
            .filter(|end| *end <= self.len())
            .ok_or(BlockError::Unsupported("native USB payload bounds"))?;
        bytes.copy_from_slice(&self.buffer.bytes()[offset..end]);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Service {
    Ordinary,
    Stream(u16),
    Isochronous(IsoSchedule),
}

enum Ticket {
    Ordinary(TransferTicket),
    Stream(StreamTransfer),
    Isochronous(IsoTransfer),
}

pub struct Transfer {
    payload: Payload,
    ticket: Ticket,
    length: usize,
    retired: bool,
}
impl Transfer {
    fn device_id(&self) -> SlotId {
        match &self.ticket {
            Ticket::Ordinary(ticket) => ticket.device_id(),
            Ticket::Stream(ticket) => ticket.device_id(),
            Ticket::Isochronous(ticket) => ticket.device_id(),
        }
    }
    /// Only a real successful completion or acknowledged cancellation returns
    /// CPU access. Dropping an unresolved transfer quarantines original pins.
    pub fn into_payload(self) -> Result<Payload, Self> {
        if self.retired {
            Ok(self.payload)
        } else {
            Err(self)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Completion {
    Ordinary(usize),
    Stream(usize),
    Isochronous(IsoCompletion),
}

pub struct SubmitFailure {
    pub error: BlockError,
    retained: Payload,
}
impl SubmitFailure {
    pub fn retains_original_payload(&self) -> bool {
        self.retained.buffer.len() != 0
    }
}

impl Controller {
    pub fn native_dma_error(&self) -> Option<region::Error> {
        self.native_memory
            .as_ref()
            .and_then(|memory| memory.error())
    }

    pub fn allocate_native_payload(&mut self, bytes: usize) -> Result<Payload, BlockError> {
        self.ready()?;
        if bytes == 0 || bytes > MAX_TD {
            return Err(BlockError::Unsupported("native USB payload size"));
        }
        let memory = self
            .native_memory
            .as_ref()
            .ok_or(BlockError::Unsupported("USB controller uses boot DMA"))?;
        // Match the one-TRB 64KiB boundary using the actual allocated IOVA.
        let buffer = memory.allocate(bytes, MAX_TD, self.dma_profile.maximum())?;
        Ok(Payload {
            buffer,
            memory: memory.clone(),
        })
    }

    /// Reuses actual descriptor/TT/route enumeration, allocating every context
    /// and EP0 buffer through this retained native memory owner.
    pub fn enumerate_native(
        &mut self,
        failures: &mut Vec<(String, BlockError)>,
    ) -> Result<Vec<Device>, BlockError> {
        if self.native_memory.is_none() {
            return Err(BlockError::Unsupported("USB controller uses boot DMA"));
        }
        self.ready()?;
        Ok(self.enumerate(&mut NoBoot, failures))
    }

    pub fn configure_native(
        &mut self,
        id: SlotId,
        endpoints: &[Endpoint],
    ) -> Result<(), BlockError> {
        if self.native_memory.is_none() {
            return Err(BlockError::Unsupported("USB controller uses boot DMA"));
        }
        self.device(id)?.configure(endpoints, None, &mut NoBoot)
    }

    pub fn configure_native_streams(
        &mut self,
        id: SlotId,
        endpoints: &[Endpoint],
        selected: &[u8],
        requested: u16,
    ) -> Result<u16, BlockError> {
        if self.native_memory.is_none() {
            return Err(BlockError::Unsupported("USB controller uses boot DMA"));
        }
        self.device(id)?
            .configure_streams(endpoints, selected, requested, &mut NoBoot)
    }

    pub fn submit_native(
        &mut self,
        id: SlotId,
        dci: u8,
        payload: Payload,
        length: usize,
        service: Service,
    ) -> Result<Transfer, SubmitFailure> {
        let result = (|| {
            let slot = self.validate_id(id)?;
            let memory = self
                .native_memory
                .as_ref()
                .ok_or(BlockError::Unsupported("USB controller uses boot DMA"))?;
            if !Rc::ptr_eq(memory, &payload.memory) || length > payload.len() {
                return Err(BlockError::Unsupported(
                    "foreign native USB payload or bounds",
                ));
            }
            memory.ready()?;
            payload.buffer.sync_dirty()?;
            let address = payload.buffer.device_address();
            match service {
                Service::Ordinary => self
                    .submit_ticket_buffer(slot, dci, address, length)
                    .map(Ticket::Ordinary),
                Service::Stream(stream) => self
                    .submit_stream_buffer(slot, dci, stream, address, length)
                    .map(Ticket::Stream),
                Service::Isochronous(schedule) => self
                    .submit_iso_scheduled_buffer(slot, dci, address, length, schedule)
                    .map(Ticket::Isochronous),
            }
        })();
        match result {
            Ok(ticket) => Ok(Transfer {
                payload,
                ticket,
                length,
                retired: false,
            }),
            // Errors can follow Cycle publication. Never return CPU access by
            // assuming that a failed sync or doorbell means no DMA occurred.
            Err(error) => Err(SubmitFailure {
                error,
                retained: payload,
            }),
        }
    }

    pub fn completed_native(
        &mut self,
        transfer: &mut Transfer,
    ) -> Option<Result<Completion, BlockError>> {
        if transfer.retired {
            return Some(Err(BlockError::Unsupported(
                "native USB transfer already retired",
            )));
        }
        if let Err(error) = self.validate_id(transfer.device_id()) {
            return Some(Err(error));
        }
        if self
            .native_memory
            .as_ref()
            .is_none_or(|m| !Rc::ptr_eq(m, &transfer.payload.memory))
        {
            return Some(Err(BlockError::Unsupported("foreign native USB transfer")));
        }
        let result = match &transfer.ticket {
            Ticket::Ordinary(ticket) => self
                .completed_ticket(ticket)
                .map(|r| r.map(Completion::Ordinary)),
            Ticket::Stream(ticket) => self
                .completed_stream(ticket)
                .map(|r| r.map(Completion::Stream)),
            Ticket::Isochronous(ticket) => self
                .completed_iso(ticket)
                .map(|r| r.map(Completion::Isochronous)),
        }?;
        Some(result.and_then(|completion| {
            // SAFETY: genuine terminal event granted this exact TD's payload.
            unsafe {
                transfer.payload.buffer.sync_cpu(0..transfer.length)?;
            }
            transfer.retired = true;
            Ok(completion)
        }))
    }

    /// Actual Stop/Set-Dequeue (and any required Reset/TT clear) must ACK.
    /// Success supplies ownership only, never a fabricated receive byte count.
    pub fn cancel_native(&mut self, transfer: &mut Transfer) -> Result<(), BlockError> {
        self.validate_id(transfer.device_id())?;
        if self
            .native_memory
            .as_ref()
            .is_none_or(|m| !Rc::ptr_eq(m, &transfer.payload.memory))
        {
            return Err(BlockError::Unsupported("foreign native USB transfer"));
        }
        if transfer.retired {
            return Ok(());
        }
        match &transfer.ticket {
            Ticket::Ordinary(ticket) => {
                self.cancel_ticket(ticket)?;
            }
            Ticket::Stream(ticket) => {
                self.cancel_native_stream(ticket)?;
            }
            Ticket::Isochronous(ticket) => {
                self.cancel_native_iso(ticket)?;
            }
        }
        // SAFETY: acknowledged actual endpoint retirement, not a timeout.
        unsafe {
            transfer.payload.buffer.sync_cpu(0..transfer.length)?;
        }
        transfer.retired = true;
        Ok(())
    }
}

/// Attach the actual retained requester using separate native CPU and IOVA views.
///
/// # Safety
/// These are the exclusively owned actual requester, UC BAR0, D0 power/root
/// route, isolated original DMA domain, fresh exclusive RAM source and original
/// IRQ registration. The requester is initially stopped with BME clear. Every
/// former firmware/driver/bypass/peer DMA path and callback is already stopped
/// and drained with its original backing retained; attaching a new domain does
/// not establish that fact. In particular, an unresolved boot controller cannot
/// be replaced by passing its BDF and a new domain here. The IRQ registration
/// covers every old source/callback and can acknowledge their actual retirement.
/// The clock is calibrated/advancing in this serialized process context. No
/// concurrent firmware, hot-removal, class, MMIO or reset actor may run. RAM
/// returned by the source is exclusively CPU-owned until publication.
///
/// Native raw-address payload submission is unavailable; use consumed typed
/// payloads. Full controller retirement is a separate boundary. Dropping this owner
/// permanently retains its actual configuration/BAR/IRQ/power resources.
pub unsafe fn attach(
    resources: Resources,
    firmware: &dyn crate::firmware::Provider,
) -> Result<Controller, Failure> {
    let owner = Rc::new(Owner {
        resources: RefCell::new(ManuallyDrop::new(resources)),
        register_failure: Rc::new(Cell::new(None)),
    });
    let mut controller = None;
    let mut retained_memory = None;
    let result = (|| {
        let (clock, native_memory, policy, location) = {
            let mut resources = owner.resources.borrow_mut();
            clock_ready(resources.clock).map_err(Error::Controller)?;
            if resources.registers.attribute() != Ok(CacheAttribute::Uncached)
                || resources.registers.protection() != Ok(Protection::ReadWrite)
            {
                return Err(Error::Registers);
            }
            let streams =
                streams::pci_policy(&mut resources.function).map_err(Error::Controller)?;
            let quirks =
                quirks::Profile::pci(&mut resources.function).map_err(Error::Controller)?;
            let function = &mut resources.function;
            let low = function.config().read32(0x10);
            if low & 1 != 0 || !matches!(low & 6, 0 | 4) {
                return Err(Error::Registers);
            }
            let high = if low & 6 == 4 {
                u64::from(function.config().read32(0x14)) << 32
            } else {
                0
            };
            if resources
                .registers
                .physical_span()
                .map_err(|_| Error::Registers)?
                .start()
                != high | u64::from(low & !15)
            {
                return Err(Error::Registers);
            }
            if resources.function.config().read16(4) & 4 != 0 {
                return Err(Error::BusMaster);
            }
            // Actual original source mask, callback synchronization and route
            // retirement; IMAN.IE=0 alone cannot establish these facts.
            resources.irq.retire().map_err(Error::Irq)?;
            let command = resources.function.config().read16(4);
            resources.function.config().write16(4, command | 2 | 0x400);
            if resources.function.config().read16(4) & 0x406 != 0x402 {
                return Err(Error::BusMaster);
            }
            let clock = resources.clock;
            renesas::prepare(&mut resources.function, clock, firmware)
                .map_err(|e| Error::Controller(e.transport()))?;
            let function = &resources.function;
            let address = function.address;
            let location = format!(
                "native xhci {:04x}:{:02x}:{:02x}.{}",
                address.segment, address.bus, address.device, address.function
            );
            let policy = hardware::Policy {
                dma: dma::Profile::pci(function.vendor, function.device),
                streams,
                quirks,
            };
            let memory = Rc::new(memory::Native::new(
                resources.pages.clone(),
                resources.domain.clone(),
                owner.clone(),
                owner.register_failure.clone(),
            ));
            (clock, memory, policy, location)
        };
        let reset_owner = owner.clone();
        retained_memory = Some(native_memory.clone());
        let core = Controller::with_memory_profile(
            Box::new(Access(owner.clone())),
            clock,
            &mut NoBoot,
            location,
            policy,
            move || quirks::after_reset(&mut reset_owner.resources.borrow_mut().function, clock),
            Some(native_memory),
        )
        .map_err(Error::Controller)?;
        controller = Some(Box::new(core));
        if owner.register_failure.get().is_some() {
            return Err(Error::Registers);
        }
        let mut resources = owner.resources.borrow_mut();
        let command = resources.function.config().read16(4);
        resources.function.config().write16(4, command | 6 | 0x400);
        if resources.function.config().read16(4) & 0x406 != 0x406 {
            return Err(Error::BusMaster);
        }
        if owner.register_failure.get().is_some() {
            return Err(Error::Registers);
        }
        Ok(())
    })();
    match result {
        Ok(()) => Ok(*controller.take().expect("initialized native controller")),
        Err(error) => Err(Failure {
            error,
            owner,
            controller,
            memory: retained_memory,
        }),
    }
}
