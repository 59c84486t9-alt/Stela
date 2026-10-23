// SPDX-License-Identifier: MIT
//! Raw xHCI EP0/EP2 owner for a pre-HCI bootloader; no receive TD is posted.
use super::{Binding, Bootloader};
use crate::{
    Clock,
    block::BlockError,
    bus::dma::{DmaAllocator, DmaBuffer},
    usb::{
        bluetooth::{Io, Pipe},
        xhci::Shared,
    },
};
use alloc::vec::Vec;
use core::sync::atomic::{Ordering, fence};
pub struct Host {
    controller: Shared,
    slot: u8,
    clock: Clock,
    output: u8,
    buffer: DmaBuffer,
    pending: bool,
    control_pending: bool,
    closed: bool,
}
impl Bootloader<Host> {
    pub(crate) fn attach(
        controller: Shared,
        binding: Binding,
        dma: &mut dyn DmaAllocator,
    ) -> core::result::Result<Self, BlockError> {
        let io = Host {
            clock: controller.borrow().clock,
            slot: binding.device.slot,
            output: binding.output.dci(),
            controller: controller.clone(),
            buffer: dma.allocate(4096, 4096)?,
            pending: false,
            control_pending: false,
            closed: false,
        };
        Ok(Self::from_io(binding, io))
    }
}
impl Host {
    fn open(&mut self) -> core::result::Result<(), BlockError> {
        if self.closed {
            return Err(BlockError::Unsupported("ATH3K raw transport is terminal"));
        }
        if !self.controller.borrow_mut().connected(self.slot)? {
            return Err(BlockError::Unsupported("ATH3K raw USB disconnected"));
        }
        Ok(())
    }
}
impl Io for Host {
    fn control(&mut self, setup: [u8; 8], data: &[u8]) -> core::result::Result<(), BlockError> {
        self.open()?;
        self.control_pending = true;
        self.controller
            .borrow_mut()
            .control(self.slot, setup, data)?;
        self.control_pending = false;
        Ok(())
    }
    fn control_read(&mut self, setup: [u8; 8]) -> core::result::Result<Vec<u8>, BlockError> {
        self.open()?;
        if setup[0] & 0x80 == 0 {
            return Err(BlockError::Unsupported("ATH3K control IN direction"));
        }
        self.control_pending = true;
        let bytes = self
            .controller
            .borrow_mut()
            .control(self.slot, setup, &[])?;
        self.control_pending = false;
        Ok(bytes)
    }
    fn write_acl(&mut self, _: &[u8]) -> core::result::Result<(), BlockError> {
        Err(BlockError::Unsupported("ATH3K bootloader is not HCI"))
    }
    fn receive(&mut self, _: Pipe) -> core::result::Result<Option<Vec<u8>>, BlockError> {
        Err(BlockError::Unsupported(
            "ATH3K bootloader has no HCI receive transport",
        ))
    }
    fn quiesce_bulk(&mut self) -> core::result::Result<(), BlockError> {
        self.open()
    }
    fn write_firmware(
        &mut self,
        bytes: &[u8],
        timeout: u64,
    ) -> core::result::Result<(), BlockError> {
        if timeout == 0 || bytes.is_empty() || bytes.len() > self.buffer.len() {
            return Err(BlockError::Unsupported("ATH3K firmware transfer bounds"));
        }
        if self.pending {
            return Err(BlockError::Unsupported("ATH3K unretired bulk output"));
        }
        let deadline = self.clock.deadline(timeout);
        self.open()?;
        self.controller
            .borrow_mut()
            .endpoint_ready(self.slot, self.output)?;
        if deadline.passed() {
            return Err(BlockError::Timeout);
        }
        self.buffer.bytes_mut()[..bytes.len()].copy_from_slice(bytes);
        fence(Ordering::Release);
        if deadline.passed() {
            return Err(BlockError::Timeout);
        }
        let trb = self.controller.borrow_mut().submit(
            self.slot,
            self.output,
            self.buffer.physical(),
            bytes.len(),
        )?;
        self.pending = true;
        loop {
            if deadline.passed() {
                return Err(BlockError::Timeout);
            }
            let completed =
                self.controller
                    .borrow_mut()
                    .completed(self.slot, self.output, trb, bytes.len());
            if let Some(result) = completed {
                if deadline.passed() {
                    return Err(BlockError::Timeout);
                }
                if result? != bytes.len() {
                    return Err(BlockError::Unsupported("ATH3K short bulk transfer"));
                }
                self.pending = false;
                return Ok(());
            }
            crate::waiting();
            core::hint::spin_loop();
        }
    }
    fn close(&mut self) -> core::result::Result<(), BlockError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let mut failure = None;
        for (active, dci) in [(self.pending, self.output), (self.control_pending, 1)] {
            if active && let Err(error) = self.controller.borrow_mut().cancel(self.slot, dci) {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
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
