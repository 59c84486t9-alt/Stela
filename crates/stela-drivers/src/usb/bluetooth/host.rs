// SPDX-License-Identifier: MIT
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

mod media;

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
    media: Option<media::Native>,
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
            media: None,
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

    fn control_read(&mut self, setup: [u8; 8]) -> Result<Vec<u8>, BlockError> {
        self.open()?;
        if setup[0] & 0x80 == 0 {
            return Err(BlockError::Unsupported(
                "USB Bluetooth control IN direction",
            ));
        }
        self.control_pending = true;
        let bytes = self
            .controller
            .borrow_mut()
            .control(self.slot, setup, &[])?;
        self.control_pending = false;
        Ok(bytes)
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
        let mut failure = if let Some(mut media) = self.media.take() {
            let failure = media.close(self).err();
            self.media = Some(media);
            failure
        } else {
            None
        };
        self.closed = true;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bus::dma::RegionAllocator,
        usb::xhci::{self, FULL_SPEED},
    };

    #[test]
    fn vendor_control_in_cannot_reuse_ep0_after_failed_running_or_halted_recovery() {
        for halted in [false, true] {
            let mut backing = vec![0u64; 64 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: backing remains live and exclusively owns this test DMA.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let buffer = dma.allocate(64, 64).unwrap();
            let controller = xhci::tests::controller_with_unresolved_td(
                &mut dma,
                buffer.physical(),
                buffer.len(),
                1,
                halted,
            );
            let configuration = vec![
                9, 2, 39, 0, 1, 1, 0, 0x80, 50, 9, 4, 0, 0, 3, 0xe0, 1, 1, 0, 7, 5, 0x81, 3, 16, 0,
                1, 7, 5, 0x82, 2, 64, 0, 0, 7, 5, 2, 2, 64, 0, 0,
            ];
            let device = Device {
                vendor_ethernet_tcr: None,
                vendor_ethernet_revision: None,
                slot: 1,
                speed: FULL_SPEED,
                location: "real xHCI poisoned EP0 model".into(),
                descriptor: [
                    18, 1, 0, 2, 0xe0, 1, 1, 64, 0x8d, 0x0e, 8, 6, 0, 1, 0, 0, 0, 1,
                ],
                configurations: vec![configuration.clone()],
                configuration,
                manufacturer: None,
                product: None,
                serial: None,
            };
            let binding =
                Binding::new(&device, &xhci::interfaces(&device.configuration)[0]).unwrap();
            let mut hci = Hci::attach(controller, &device, binding, &mut dma).unwrap();
            let before = backing.clone();
            assert!(
                hci.io
                    .control_read(xhci::setup(0xc0, 1, 48, 0, 64))
                    .is_err()
            );
            assert!(hci.io.control_pending);
            // The actual outstanding control buffer, transfer/command/event
            // rings and all other DMA bytes remain untouched by this retry.
            assert_eq!(backing, before);
            assert!(hci.close().is_err());
            assert_eq!(hci.state(), super::super::State::Failed);
        }
    }
}
