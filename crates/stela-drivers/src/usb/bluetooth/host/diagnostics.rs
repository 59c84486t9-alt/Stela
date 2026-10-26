// SPDX-License-Identifier: MIT
//! Actual xHCI owner for the separate Broadcom diagnostic bulk interface.
use super::Host;
use crate::{
    block::BlockError,
    bus::dma::{DmaAllocator, DmaBuffer},
    usb::{
        bluetooth::{
            Hci, Io,
            broadcom::diagnostics::{
                self, DiagnosticIo, MAX_RECORD, Pair, RetiredInput, Retirement,
            },
        },
        xhci::{TransferCancellation, TransferTicket},
    },
};
use alloc::vec::Vec;
use core::sync::atomic::{Ordering, fence};

pub(super) struct Native {
    pair: Pair,
    input: DmaBuffer,
    output: DmaBuffer,
    receive: Option<TransferTicket>,
    receive_intent: bool,
    send: bool,
    output_ticket: Option<TransferTicket>,
    retirement: Retirement,
    configured: bool,
    retired: bool,
    poisoned: bool,
}
impl Hci<Host> {
    /// Separate diagnostic bulk endpoints of this actually initialized native
    /// PatchRAM function. This neither opens SCO nor changes controller firmware.
    pub fn into_broadcom_diagnostics(
        self,
        dma: &mut dyn DmaAllocator,
    ) -> Result<diagnostics::Session<Host>, diagnostics::Error> {
        diagnostics::Session::start(self, dma)
    }
}
impl Native {
    fn new(pair: Pair, dma: &mut dyn DmaAllocator) -> Result<Self, BlockError> {
        Ok(Self {
            pair,
            input: dma.allocate(2048, 2048)?,
            output: dma.allocate(64, 64)?,
            receive: None,
            receive_intent: false,
            send: false,
            output_ticket: None,
            retirement: Retirement::default(),
            configured: false,
            retired: false,
            poisoned: false,
        })
    }
    fn start(&mut self, host: &mut Host, dma: &mut dyn DmaAllocator) -> Result<(), BlockError> {
        host.open()?;
        {
            let mut controller = host.controller.borrow_mut();
            let mut device = controller.device(host.id)?;
            // Caller allocation may reenter after the first admission check.
            // Definitive ownership and publication share this same borrow; a
            // busy refusal has no authority to retire another owner's DCIs.
            device.preflight_endpoints(&self.pair.endpoints())?;
            self.configured = true;
            device.configure(&self.pair.endpoints(), None, dma)?;
        }
        self.post(host)
    }
    fn post(&mut self, host: &mut Host) -> Result<(), BlockError> {
        host.open()?;
        if self.retired || self.poisoned {
            return Err(BlockError::Unsupported("retired diagnostic bulk owner"));
        }
        if self.receive.is_none() {
            self.receive_intent = true;
            self.receive = Some(
                host.controller
                    .borrow_mut()
                    .device(host.id)?
                    .submit_ticket(self.pair.input.dci(), self.input.physical(), MAX_RECORD)?,
            );
        }
        Ok(())
    }
    fn read(&mut self, host: &mut Host) -> Result<Option<Vec<u8>>, BlockError> {
        self.post(host)?;
        let done = host
            .controller
            .borrow_mut()
            .device(host.id)?
            .completed_ticket(self.receive.as_ref().unwrap());
        match done {
            Some(Ok(length)) => {
                if length > MAX_RECORD {
                    return Err(BlockError::Unsupported("diagnostic receive length"));
                }
                self.receive = None;
                self.receive_intent = false;
                fence(Ordering::Acquire);
                Ok(Some(self.input.bytes()[..length].to_vec()))
            }
            Some(Err(error)) => Err(error),
            None => Ok(None),
        }
    }
    fn write(&mut self, host: &mut Host, bytes: [u8; 2]) -> Result<(), BlockError> {
        host.open()?;
        if self.retired || self.poisoned || self.send {
            return Err(BlockError::Unsupported("unretired diagnostic bulk output"));
        }
        let deadline = host
            .clock
            .try_deadline(5_000_000)
            .map_err(|_| BlockError::Unsupported(super::CLOCK_REQUIREMENT))?;
        host.controller
            .borrow_mut()
            .device(host.id)?
            .endpoint_ready(self.pair.output.dci())?;
        if deadline.passed() {
            return Err(BlockError::Timeout);
        }
        self.output.bytes_mut()[..2].copy_from_slice(&bytes);
        fence(Ordering::Release);
        if deadline.passed() {
            return Err(BlockError::Timeout);
        }
        self.send = true;
        self.retirement.output_intent = Some(bytes);
        self.retirement.output = None;
        self.output_ticket = Some(
            host.controller
                .borrow_mut()
                .device(host.id)?
                .submit_ticket(self.pair.output.dci(), self.output.physical(), 2)?,
        );
        loop {
            if deadline.passed() {
                return Err(BlockError::Timeout);
            }
            let done = host
                .controller
                .borrow_mut()
                .device(host.id)?
                .completed_ticket(self.output_ticket.as_ref().unwrap());
            if let Some(result) = done {
                // completed_ticket consumes a successful TD, including a short
                // completion. Retain that actual boundary before deadline or
                // protocol rejection; a stale ticket cannot cancel it again.
                if let Ok(bytes) = &result {
                    self.retirement.output = Some(TransferCancellation::Completed(*bytes));
                    self.send = false;
                    self.output_ticket = None;
                }
                if deadline.passed() {
                    return Err(BlockError::Timeout);
                }
                if result? != 2 {
                    return Err(BlockError::Unsupported("short diagnostic mode delivery"));
                }
                self.send = false;
                self.output_ticket = None;
                return Ok(());
            }
            crate::waiting();
            core::hint::spin_loop();
        }
    }
    pub(super) fn close(&mut self, host: &mut Host) -> Result<(), BlockError> {
        host.validate()?;
        if self.retired {
            return if self.poisoned {
                Err(BlockError::Unsupported(
                    "diagnostic DMA permanently quarantined",
                ))
            } else {
                Ok(())
            };
        }
        self.retired = true;
        self.poisoned = true;
        let mut controller = host.controller.borrow_mut();
        let mut device = controller.device(host.id)?;
        let mut failure = None;
        if self.receive_intent {
            let result = if let Some(ticket) = &self.receive {
                device.cancel_ticket(ticket)
            } else {
                device
                    .cancel(self.pair.input.dci())
                    .map(|()| TransferCancellation::Unknown)
            };
            match result {
                Ok(outcome) => {
                    let length = match outcome {
                        TransferCancellation::Completed(n) | TransferCancellation::Stopped(n) => {
                            Some(n)
                        }
                        TransferCancellation::Unknown => None,
                    };
                    let bytes = if length.is_some_and(|n| n > MAX_RECORD) {
                        failure = Some(BlockError::Unsupported(
                            "diagnostic retirement receive length",
                        ));
                        Vec::new()
                    } else {
                        fence(Ordering::Acquire);
                        length.map_or_else(Vec::new, |n| self.input.bytes()[..n].to_vec())
                    };
                    self.retirement.input = Some(RetiredInput { outcome, bytes });
                    self.receive = None;
                    self.receive_intent = false;
                }
                Err(e) => {
                    failure = Some(e);
                }
            }
        }
        if self.send {
            let result = if let Some(ticket) = &self.output_ticket {
                device.cancel_ticket(ticket)
            } else {
                device
                    .cancel(self.pair.output.dci())
                    .map(|()| TransferCancellation::Unknown)
            };
            match result {
                Ok(outcome) => {
                    self.retirement.output = Some(outcome);
                    self.output_ticket = None;
                    self.send = false;
                }
                Err(e) => {
                    failure.get_or_insert(e);
                }
            }
        }
        if failure.is_none() && self.configured {
            if let Err(e) = device.deconfigure(&self.pair.endpoints()) {
                failure = Some(e);
            } else {
                self.configured = false;
            }
        }
        self.poisoned = failure.is_some();
        match failure {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}
fn with_native<T>(
    host: &mut Host,
    operation: impl FnOnce(&mut Native, &mut Host) -> Result<T, BlockError>,
) -> Result<T, BlockError> {
    host.validate()?;
    let mut native = host
        .diagnostics
        .take()
        .ok_or(BlockError::Unsupported("diagnostic endpoint owner"))?;
    let result = operation(&mut native, host);
    host.diagnostics = Some(native);
    result
}
impl DiagnosticIo for Host {
    fn diagnostic_retirement(&self) -> Option<&Retirement> {
        self.diagnostics.as_ref().map(|native| &native.retirement)
    }
    fn start_diagnostics(
        &mut self,
        pair: Pair,
        dma: &mut dyn DmaAllocator,
    ) -> Result<(), BlockError> {
        self.open()?;
        if self.diagnostics.is_some() {
            return Err(BlockError::Unsupported(
                "diagnostic owner already allocated",
            ));
        }
        self.controller
            .borrow_mut()
            .device(self.id)?
            .preflight_endpoints(&pair.endpoints())?;
        self.diagnostics = Some(Native::new(pair, dma)?);
        with_native(self, |native, host| native.start(host, dma))
    }
    fn read_diagnostic(&mut self) -> Result<Option<Vec<u8>>, BlockError> {
        with_native(self, |native, host| native.read(host))
    }
    fn write_diagnostic(&mut self, bytes: [u8; 2]) -> Result<(), BlockError> {
        with_native(self, |native, host| native.write(host, bytes))
    }
}
