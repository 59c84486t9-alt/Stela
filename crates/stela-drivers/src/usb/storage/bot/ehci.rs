//! Bulk-Only Transport over an EHCI controller's high-speed bulk pipes. The
//! controller runs one transfer at a time through its own bounce buffer, so
//! each stage copies through it and completes before the next begins.
use super::{Bot, COMMAND_US, Io, TransportBuffer, quirks};
use crate::{
    Clock,
    block::BlockError,
    bus::dma::DmaBuffer,
    usb::{
        descriptor::{Endpoint, Interface, interfaces},
        ehci::{self, host},
        xhci::STALL,
    },
};
use alloc::{string::String, vec::Vec};

/// The wait between looks at a transfer in flight; each look stops the
/// controller's schedule.
const POLL_US: u64 = 250;

/// An EHCI controller's failure as the storage layer reports it: a STALL
/// in the completion code BOT clears halts on, anything else a failure its
/// reset recovery answers.
pub(in crate::usb) fn block(error: ehci::Error) -> BlockError {
    match error {
        ehci::Error::Device(_) if error.stalled() => BlockError::Device { status: STALL },
        ehci::Error::Device(_) => BlockError::Protocol("EHCI transaction error"),
        ehci::Error::Timeout => BlockError::Timeout,
        ehci::Error::Unsupported(why) => BlockError::Unsupported(why),
        ehci::Error::Stale | ehci::Error::Removed => {
            BlockError::Unsupported("EHCI device no longer attached")
        }
        ehci::Error::Quarantined => BlockError::Unsupported("EHCI controller quarantined"),
        ehci::Error::Preparation(_) => BlockError::Protocol("EHCI requester preparation failed"),
        ehci::Error::Busy => BlockError::Protocol("EHCI transfer while another is in flight"),
        ehci::Error::Memory(_) | ehci::Error::Exhausted => BlockError::NoDmaMemory,
        ehci::Error::Dma(_) => BlockError::Protocol("EHCI DMA mapping failure"),
        ehci::Error::Invalid | ehci::Error::Register | ehci::Error::Clock => {
            BlockError::Protocol("EHCI controller refused the request")
        }
    }
}

/// A Bulk-Only interface's pipes on an EHCI root device.
pub(in crate::usb) struct EhciBulk {
    controller: host::Shared,
    device: ehci::DeviceId,
    pipes: Vec<ehci::BulkPipe>,
    clock: Clock,
    descriptor: [u8; 18],
}

impl EhciBulk {
    pub(in crate::usb) fn new(
        controller: host::Shared,
        device: ehci::DeviceId,
        pipes: Vec<ehci::BulkPipe>,
        clock: Clock,
        descriptor: [u8; 18],
    ) -> Self {
        Self {
            controller,
            device,
            pipes,
            clock,
            descriptor,
        }
    }
    fn pipe(&self, endpoint: Endpoint) -> Result<ehci::BulkPipe, BlockError> {
        self.pipes
            .iter()
            .find(|pipe| pipe.endpoint_address() == endpoint.address)
            .cloned()
            .ok_or(BlockError::Unsupported(
                "BOT endpoint outside the EHCI configuration",
            ))
    }
}

impl Io for EhciBulk {
    fn ready(&mut self) -> Result<(), BlockError> {
        self.controller
            .borrow()
            .validate(&self.device)
            .map_err(block)
    }
    fn control(&mut self, request: [u8; 8]) -> Result<Vec<u8>, BlockError> {
        let mut controller = self.controller.borrow_mut();
        if request[0] & 0x80 != 0 {
            controller.control_in(&self.device, request)
        } else {
            controller
                .control_out(&self.device, request, &[])
                .map(|()| Vec::new())
        }
        .map_err(block)
    }
    fn clear(&mut self, endpoint: Endpoint) -> Result<(), BlockError> {
        let pipe = self.pipe(endpoint)?;
        self.controller
            .borrow_mut()
            .clear_halt(&pipe)
            .map_err(block)
    }
    fn bulk(
        &mut self,
        endpoint: Endpoint,
        buffer: &mut DmaBuffer,
        length: usize,
    ) -> Result<usize, BlockError> {
        let pipe = self.pipe(endpoint)?;
        let mut controller = self.controller.borrow_mut();
        let ticket = if endpoint.is_in() {
            controller.submit_bulk_in(&pipe, length, COMMAND_US)
        } else {
            controller.submit_bulk_out(&pipe, &buffer.bytes()[..length], COMMAND_US)
        }
        .map_err(block)?;
        loop {
            if let Some(done) = controller.poll(&ticket).map_err(block)? {
                if endpoint.is_in() {
                    buffer.bytes_mut()[..done.actual].copy_from_slice(&done.data[..done.actual]);
                }
                return Ok(done.actual);
            }
            self.clock.delay(POLL_US);
        }
    }
    fn delay(&self, micros: u64) {
        self.clock.delay(micros);
    }
    fn now_us(&self) -> u64 {
        self.clock.now_us()
    }
    /// Disable the device's root: PE0 isolates it before its address can
    /// serve another device.
    fn quarantine(&mut self) {
        let _ = self.controller.borrow_mut().disable_port(&self.device);
    }
}

impl Bot<EhciBulk> {
    /// A Bulk-Only interface of a configured high-speed EHCI device.
    pub(in crate::usb) fn ehci(
        io: EhciBulk,
        setting: &Interface,
        dma: &mut dyn crate::bus::dma::DmaAllocator,
    ) -> Result<Self, BlockError> {
        let flags = quirks::Flags::high_speed(&io.descriptor).map_err(BlockError::Unsupported)?;
        let endpoints = endpoints(setting)?;
        Self::with_flags(io, setting.number, endpoints, dma, flags)
    }

    /// Linux `usb_reset_device` for a root device: reset its port, address
    /// and configure it afresh, check it is the same device and keep the
    /// two transport allocations, as [`Bot::reset_and_rebind`] does on xHCI.
    pub(in crate::usb) fn reset_and_rebind_ehci(&mut self) -> Result<Self, (String, BlockError)> {
        self.poisoned = true;
        let fail = |why| {
            (
                String::from("BOT reset/rebind"),
                BlockError::Unsupported(why),
            )
        };
        if !self.buffer.present() || !self.wrapper.present() {
            return Err(fail("BOT transport DMA owners already transferred"));
        }
        let controller = self.io.controller.clone();
        let port = self.io.device.root_port();
        let failed = |operation: &str, error: ehci::Error| (String::from(operation), block(error));
        let addressed =
            host::address(&controller, port).map_err(|e| failed("BOT reset root", e))?;
        let id = addressed.id.clone();
        let result = (|| {
            if addressed.descriptor != self.io.descriptor {
                return Err(fail("USB device identity/descriptors changed across reset"));
            }
            let pipes = {
                let mut c = controller.borrow_mut();
                let configuration = host::configuration(&mut c, &id, 0)
                    .map_err(|e| failed("BOT reset read configuration", e))?;
                if !interfaces(&configuration)
                    .iter()
                    .any(|i| i.number == self.interface && super::super::bulk_only(i))
                {
                    return Err(fail("USB reset lost the BOT interface"));
                }
                c.configure(&id, 0)
                    .map_err(|e| failed("BOT reset restore configuration", e))?
            };
            let flags = quirks::Flags::high_speed(&addressed.descriptor).map_err(fail)?;
            let mut io = EhciBulk::new(
                controller.clone(),
                id.clone(),
                pipes,
                self.io.clock,
                addressed.descriptor,
            );
            let max_lun = Self::startup(&mut io, self.interface, flags)
                .map_err(|e| (String::from("BOT reset reconstruct transport"), e))?;
            // Every fallible step is done and the old device's handles were
            // retired by the reset; move the unique buffer owners.
            let mut buffer: TransportBuffer = self.buffer.transfer();
            let mut wrapper: TransportBuffer = self.wrapper.transfer();
            buffer.bytes_mut().fill(0);
            wrapper.bytes_mut().fill(0);
            Ok(Self::with_buffers(
                io,
                self.interface,
                self.endpoints,
                buffer,
                wrapper,
                flags,
                max_lun,
            ))
        })();
        if result.is_err() {
            let _ = controller.borrow_mut().disable_port(&id);
        }
        result
    }
}

/// The interface's bulk IN and OUT endpoints, in BOT's order.
fn endpoints(setting: &Interface) -> Result<[Endpoint; 2], BlockError> {
    let bulk = |input: bool| {
        setting
            .endpoints
            .iter()
            .copied()
            .find(|e| e.kind() == 2 && e.is_in() == input)
            .ok_or(BlockError::Unsupported(
                "Bulk-Only interface without bulk IN and OUT endpoints",
            ))
    };
    Ok([bulk(true)?, bulk(false)?])
}
