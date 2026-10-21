//! xHCI-backed physical HCI I/O. DMA storage lives for the rest of the boot,
//! including when an unplugged/faulted controller cannot acknowledge a stop.
use super::super::xhci::{Device, Endpoint, Shared};
use super::{ACL_READ, Binding, EVENT_READ, Hci, Io, Pipe};
use crate::{
    Clock,
    block::BlockError,
    bus::dma::{DmaAllocator, DmaBuffer},
};
use alloc::vec::Vec;
use core::sync::atomic::{Ordering, fence};

const SEND_US: u64 = 5_000_000;

struct Receive {
    endpoint: Endpoint,
    buffer: DmaBuffer,
    queued: Option<u64>,
}

/// Physical backend, constructed only by the xHCI attachment path. Endpoint/DMA
/// details stay private so an initializer cannot detach an active DMA buffer.
pub struct Host {
    controller: Shared,
    slot: u8,
    clock: Clock,
    events: Receive,
    input: Receive,
    output: Endpoint,
    transmit: DmaBuffer,
    transmit_pending: bool,
    control_pending: bool,
    closed: bool,
}

impl Hci<Host> {
    pub(crate) fn attach(
        controller: Shared,
        device: &Device,
        binding: Binding,
        dma: &mut dyn DmaAllocator,
    ) -> Result<Self, BlockError> {
        let clock = controller.borrow().clock;
        // Power-of-two size/alignment keeps each single-TRB buffer within a
        // 64 KiB boundary, including the largest supported ACL packet.
        let events = Receive {
            endpoint: binding.events,
            buffer: dma.allocate(EVENT_READ, EVENT_READ)?,
            queued: None,
        };
        let input = Receive {
            endpoint: binding.input,
            buffer: dma.allocate(ACL_READ, ACL_READ)?,
            queued: None,
        };
        let transmit = dma.allocate(ACL_READ, ACL_READ)?;
        let output = binding.output;
        let host = Host {
            controller,
            slot: device.slot,
            clock,
            events,
            input,
            output,
            transmit,
            transmit_pending: false,
            control_pending: false,
            closed: false,
        };
        Ok(Self::from_io(binding, host))
    }
}

impl Host {
    fn open(&self) -> Result<(), BlockError> {
        if self.closed {
            return Err(BlockError::Unsupported("USB Bluetooth transport closed"));
        }
        if !self.controller.borrow_mut().connected(self.slot)? {
            return Err(BlockError::Unsupported("USB Bluetooth device disconnected"));
        }
        Ok(())
    }
}

impl Io for Host {
    fn control(&mut self, setup: [u8; 8], packet: &[u8]) -> Result<(), BlockError> {
        self.open()?;
        self.control_pending = true;
        self.controller
            .borrow_mut()
            .control(self.slot, setup, packet)?;
        self.control_pending = false;
        Ok(())
    }

    fn receive(&mut self, pipe: Pipe) -> Result<Option<Vec<u8>>, BlockError> {
        self.open()?;
        let receive = match pipe {
            Pipe::Event => &mut self.events,
            Pipe::Acl => &mut self.input,
        };
        let mut controller = self.controller.borrow_mut();
        let length = receive.buffer.len();
        let trb = match receive.queued {
            Some(trb) => trb,
            None => {
                let trb = controller.submit(
                    self.slot,
                    receive.endpoint.dci(),
                    receive.buffer.physical(),
                    length,
                )?;
                receive.queued = Some(trb);
                trb
            }
        };
        match controller.completed(self.slot, receive.endpoint.dci(), trb, length) {
            Some(Ok(length)) => {
                receive.queued = None;
                fence(Ordering::Acquire);
                Ok(Some(receive.buffer.bytes()[..length].to_vec()))
            }
            // Keep the TD recorded until close acknowledges stop/dequeue. A
            // controller-fatal error is not necessarily a completed transfer.
            Some(Err(error)) => Err(error),
            None => Ok(None),
        }
    }

    fn write_acl(&mut self, packet: &[u8]) -> Result<(), BlockError> {
        self.open()?;
        if packet.len() > self.transmit.len() {
            return Err(BlockError::Unsupported("USB Bluetooth ACL buffer size"));
        }
        self.controller
            .borrow_mut()
            .endpoint_ready(self.slot, self.output.dci())?;
        self.transmit.bytes_mut()[..packet.len()].copy_from_slice(packet);
        fence(Ordering::Release);
        let dci = self.output.dci();
        let trb = self.controller.borrow_mut().submit(
            self.slot,
            dci,
            self.transmit.physical(),
            packet.len(),
        )?;
        self.transmit_pending = true;
        let deadline = self.clock.deadline(SEND_US);
        loop {
            let completed =
                self.controller
                    .borrow_mut()
                    .completed(self.slot, dci, trb, packet.len());
            if let Some(result) = completed {
                let length = result?;
                if length != packet.len() {
                    return Err(BlockError::Unsupported("short USB Bluetooth ACL output"));
                }
                self.transmit_pending = false;
                return Ok(());
            }
            if deadline.passed() {
                return Err(BlockError::Timeout);
            }
            crate::waiting();
            core::hint::spin_loop();
        }
    }

    fn quiesce_bulk(&mut self) -> Result<(), BlockError> {
        self.open()?;
        if self.input.queued.is_some() {
            self.controller
                .borrow_mut()
                .cancel(self.slot, self.input.endpoint.dci())?;
            self.input.queued = None;
        }
        Ok(())
    }

    fn close(&mut self) -> Result<(), BlockError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let mut failure = None;
        let mut controller = self.controller.borrow_mut();
        for (active, dci) in [
            (self.events.queued.is_some(), self.events.endpoint.dci()),
            (self.input.queued.is_some(), self.input.endpoint.dci()),
            (self.transmit_pending, self.output.dci()),
            (self.control_pending, 1),
        ] {
            if active && let Err(error) = controller.cancel(self.slot, dci) {
                failure.get_or_insert(error);
            }
        }
        // The host never reopens or reuses DMA after close, even when just one
        // endpoint could not stop. DmaBuffer owns boot-lifetime reserved memory.
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
    fn now_us(&self) -> u64 {
        self.clock.now_us()
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
