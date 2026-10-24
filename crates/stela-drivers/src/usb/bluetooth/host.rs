// SPDX-License-Identifier: MIT
//! xHCI-backed physical HCI I/O. DMA storage lives for the rest of the boot,
//! including when an unplugged/faulted controller cannot acknowledge a stop.
use super::super::xhci::{Device, Endpoint, Shared, SlotId, TransferTicket};
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
    queued: Option<TransferTicket>,
}

/// Physical backend, constructed only by the xHCI attachment path. Endpoint/DMA
/// details stay private so an initializer cannot detach an active DMA buffer.
pub struct Host {
    controller: Shared,
    id: SlotId,
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
        controller.borrow_mut().device(device.id)?;
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
            id: device.id,
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
        self.validate()?;
        if self.closed {
            return Err(BlockError::Unsupported("USB Bluetooth transport closed"));
        }
        if !self.controller.borrow_mut().device(self.id)?.connected()? {
            return Err(BlockError::Unsupported("USB Bluetooth device disconnected"));
        }
        Ok(())
    }
    fn write_bulk(&mut self, packet: &[u8], timeout_us: u64) -> Result<(), BlockError> {
        self.validate()?;
        if self.transmit_pending {
            return Err(BlockError::Unsupported(
                "unretired USB Bluetooth bulk output",
            ));
        }
        let deadline = self.clock.deadline(timeout_us);
        self.open()?;
        if packet.len() > self.transmit.len() {
            return Err(BlockError::Unsupported("USB Bluetooth bulk buffer size"));
        }
        self.controller
            .borrow_mut()
            .device(self.id)?
            .endpoint_ready(self.output.dci())?;
        if deadline.passed() {
            return Err(BlockError::Timeout);
        }
        self.transmit.bytes_mut()[..packet.len()].copy_from_slice(packet);
        fence(Ordering::Release);
        let dci = self.output.dci();
        if deadline.passed() {
            return Err(BlockError::Timeout);
        }
        let ticket = self
            .controller
            .borrow_mut()
            .device(self.id)?
            .submit_ticket(dci, self.transmit.physical(), packet.len())?;
        self.transmit_pending = true;
        loop {
            if deadline.passed() {
                return Err(BlockError::Timeout);
            }
            let completed = self
                .controller
                .borrow_mut()
                .device(self.id)?
                .completed_ticket(&ticket);
            if let Some(result) = completed {
                if deadline.passed() {
                    return Err(BlockError::Timeout);
                }
                let length = result?;
                if length != packet.len() {
                    return Err(BlockError::Unsupported("short USB Bluetooth bulk output"));
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
}

impl Io for Host {
    fn validate(&self) -> Result<(), BlockError> {
        self.controller.borrow().validate_device_id(self.id)
    }
    fn control(&mut self, setup: [u8; 8], packet: &[u8]) -> Result<(), BlockError> {
        self.open()?;
        self.control_pending = true;
        self.controller
            .borrow_mut()
            .device(self.id)?
            .control(setup, packet)?;
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
            .device(self.id)?
            .control(setup, &[])?;
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
        let mut device = controller.device(self.id)?;
        if receive.queued.is_none() {
            receive.queued = Some(device.submit_ticket(
                receive.endpoint.dci(),
                receive.buffer.physical(),
                length,
            )?);
        }
        match device.completed_ticket(receive.queued.as_ref().unwrap()) {
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
        self.write_bulk(packet, SEND_US)
    }

    fn write_firmware(&mut self, bytes: &[u8], timeout_us: u64) -> Result<(), BlockError> {
        self.validate()?;
        if timeout_us == 0 {
            return Err(BlockError::Unsupported("zero firmware bulk deadline"));
        }
        self.write_bulk(bytes, timeout_us)
    }

    fn quiesce_bulk(&mut self) -> Result<(), BlockError> {
        self.open()?;
        if self.input.queued.is_some() {
            self.controller
                .borrow_mut()
                .device(self.id)?
                .cancel_ticket(self.input.queued.as_ref().unwrap())?;
            self.input.queued = None;
        }
        Ok(())
    }

    fn close(&mut self) -> Result<(), BlockError> {
        self.validate()?;
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
        let mut device = controller.device(self.id)?;
        for receive in [&self.events, &self.input] {
            if let Some(ticket) = &receive.queued
                && let Err(error) = device.cancel_ticket(ticket)
            {
                failure.get_or_insert(error);
            }
        }
        for (active, dci) in [
            (self.transmit_pending, self.output.dci()),
            (self.control_pending, 1),
        ] {
            if active && let Err(error) = device.cancel(dci) {
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
            let controller = xhci::model::controller_with_unresolved_td(
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
                id: controller.borrow().test_device_id(1).unwrap(),
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
                language: None,
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
    fn firmware_device(id: xhci::SlotId) -> Device {
        let configuration = vec![
            9, 2, 39, 0, 1, 1, 0, 0x80, 50, 9, 4, 0, 0, 3, 0xe0, 1, 1, 0, 7, 5, 0x81, 3, 16, 0, 1,
            7, 5, 0x82, 2, 64, 0, 0, 7, 5, 2, 2, 64, 0, 0,
        ];
        Device {
            id,
            vendor_ethernet_tcr: None,
            vendor_ethernet_revision: None,
            slot: 1,
            speed: FULL_SPEED,
            location: "real QCA firmware DMA model".into(),
            descriptor: [
                18, 1, 0, 2, 0xe0, 1, 1, 64, 0xf3, 0x0c, 0, 0xe3, 0, 1, 0, 0, 0, 1,
            ],
            configurations: vec![configuration.clone()],
            configuration,
            manufacturer: None,
            product: None,
            serial: None,
            language: None,
        }
    }
    #[test]
    fn firmware_bulk_uses_actual_dma_and_expired_or_zero_budget_never_publishes() {
        use alloc::rc::Rc;
        use core::cell::RefCell;
        let mut backing = vec![0u64; 64 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: retained backing exclusively owns these actual modeled DMA pages.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (controller, model) = xhci::model::cancellation_controller(&mut dma);
        let controller = Rc::new(RefCell::new(controller));
        let device = firmware_device(controller.borrow().test_device_id(1).unwrap());
        let binding = Binding::new(&device, &xhci::interfaces(&device.configuration)[0]).unwrap();
        let mut hci = Hci::attach(controller, &device, binding, &mut dma).unwrap();
        hci.io.clock.ticks_per_microsecond = 1000;
        let payload = vec![0xa5; 4096];
        hci.io.write_firmware(&payload, 3_000_000).unwrap();
        assert_eq!(model.borrow().outgoing.last().unwrap(), &payload);
        assert!(!hci.io.transmit_pending);
        let before = backing.clone();
        assert!(hci.io.write_firmware(&[0xbb; 64], 0).is_err());
        assert_eq!(backing, before);
        hci.io.clock.ticks_per_microsecond = 0;
        assert_eq!(
            hci.io.write_firmware(&[0xcc; 64], 3_000_000),
            Err(BlockError::Timeout)
        );
        assert_eq!(backing, before);
        assert!(!hci.io.transmit_pending);
    }
    #[test]
    fn timed_out_firmware_bulk_cannot_rewrite_live_dma_after_failed_retirement() {
        use alloc::rc::Rc;
        use core::cell::RefCell;
        let mut backing = vec![0u64; 64 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: backing outlives the native controller, HCI owner and DMA buffers.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (controller, model) = xhci::model::cancellation_controller(&mut dma);
        model.borrow_mut().silence_transfer = Some(4);
        const STOP_ENDPOINT: u32 = 15;
        const CONTEXT_STATE_ERROR: u32 = 19;
        model.borrow_mut().fail = Some((STOP_ENDPOINT, CONTEXT_STATE_ERROR));
        let controller = Rc::new(RefCell::new(controller));
        let device = firmware_device(controller.borrow().test_device_id(1).unwrap());
        let binding = Binding::new(&device, &xhci::interfaces(&device.configuration)[0]).unwrap();
        let mut hci = Hci::attach(controller, &device, binding, &mut dma).unwrap();
        // Use a generous real publication window: this is a timeout/ownership
        // test, not a wall-time benchmark or a scheduler-latency assertion.
        hci.io.clock.ticks_per_microsecond = 1000;
        assert_eq!(
            hci.io.write_firmware(&[0xa5; 64], 3_000_000),
            Err(BlockError::Timeout)
        );
        assert!(hci.io.transmit_pending);
        let before = backing.clone();
        assert!(hci.io.write_firmware(&[0xbb; 64], 3_000_000).is_err());
        assert_eq!(backing, before);
        assert!(hci.close().is_err());
        assert_eq!(hci.state(), super::super::State::Failed);
        assert!(hci.io.transmit_pending);
        let after = backing.clone();
        assert!(hci.io.write_firmware(&[0xcc; 64], 3_000_000).is_err());
        assert_eq!(backing, after);
    }
}

#[cfg(test)]
pub(crate) mod generation_tests;
