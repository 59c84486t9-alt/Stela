// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2012-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! Exclusive source cold setup prefix. Stops at a real missing BIOS-policy
//! phase; completion of these commands is not radio or transmit readiness.
use super::super::radio::{InitialPlan, Stage};
use super::*;
use alloc::boxed::Box;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColdRadioPhase {
    NotStarted,
    Waiting(Stage),
    PlatformConfigurationRequired,
    Failed,
}
/// Keeps requester/BAR, DMA and the private initialized-NVM owner.
/// Caller-supplied/copied NVM, firmware or command plans cannot construct this.
pub struct ColdRadio<'a, Q: BootIo> {
    pub(super) initialized: UnifiedNvm<'a, Q>,
    phase: ColdRadioPhase,
    plan: Option<InitialPlan>,
    next: usize,
    ticket: Option<CommandTicket>,
    responses: Vec<CommandResponse>,
}
impl<'a, Q: BootIo> UnifiedNvm<'a, Q> {
    /// Only source initialization completion can enter this owner.
    /// Rejection returns the unchanged owner to permit further NVM progress.
    pub fn begin_radio(self) -> Result<ColdRadio<'a, Q>, Box<Self>> {
        if self.phase() != InitializationPhase::Observed {
            return Err(Box::new(self));
        }
        Ok(ColdRadio {
            initialized: self,
            phase: ColdRadioPhase::NotStarted,
            plan: None,
            next: 0,
            ticket: None,
            responses: Vec::new(),
        })
    }
}
impl<Q: BootIo> ColdRadio<'_, Q> {
    pub fn phase(&self) -> ColdRadioPhase {
        self.phase
    }
    pub fn initialized_nvm(&self) -> &InitializedNvm {
        self.initialized
            .receipt()
            .expect("private actual initialized owner")
    }
    /// Raw command completions, never invented radio/key/calibration
    /// status. These borrowed diagnostics grant no reset/policy permission.
    pub fn prefix_responses(&self) -> &[CommandResponse] {
        &self.responses
    }
    pub fn take_firmware_notification(&mut self) -> Option<FirmwareNotification> {
        self.initialized.boot.take_firmware_notification()
    }
    pub fn replenish_completed_receive(&mut self) -> Result<Replenished, Error> {
        self.initialized.boot.replenish_completed_receive()
    }
    pub fn stop(&mut self) -> Result<(), Error> {
        self.initialized.stop()
    }
    /// Advance only after RX completion and canonical descriptor/TB0
    /// CPU handoff. RF-kill is not ignored for these radio setup commands.
    /// # Safety
    /// Source returns fresh exclusive native pages for the
    /// requester/domain under its coherent publication/ownership contract.
    pub unsafe fn advance(&mut self, source: &dyn PageSource) -> Result<ColdRadioPhase, Error> {
        // SAFETY: covered by this function's own safety contract.
        let result = unsafe { self.advance_inner(source) };
        if result.is_err() && !matches!(result, Err(Error::CommandReclaim(_))) {
            self.phase = ColdRadioPhase::Failed;
        }
        result
    }
    unsafe fn advance_inner(&mut self, source: &dyn PageSource) -> Result<ColdRadioPhase, Error> {
        if self.phase == ColdRadioPhase::Failed
            || self.initialized.boot.state != State::PnvmObserved
        {
            return Err(Error::State);
        }
        if self.phase == ColdRadioPhase::PlatformConfigurationRequired {
            return Ok(self.phase);
        }
        if self.plan.is_none() {
            // Canonical firmware plus private completion from this exact owned
            // epoch. Preflight every prefix schema before any new MMIO/DMA.
            self.plan = Some(InitialPlan::prepare(
                &self.initialized.boot.firmware,
                self.initialized.boot.profile.platform(),
                &self.initialized_nvm().information,
            )?);
        }
        if let Some(ticket) = self.ticket.as_ref() {
            match self.initialized.boot.poll_command(ticket)? {
                CommandProgress::Pending => return Ok(self.phase),
                CommandProgress::Completed(response) => {
                    let command = &self.plan.as_ref().unwrap().commands()[self.next - 1];
                    let id = command.id();
                    let group = if id.group == 0 { 1 } else { id.group };
                    if response.command != id.opcode || response.group != group {
                        return Err(Error::InitializationResponse {
                            command: response.command,
                            group: response.group,
                        });
                    }
                    if command.stage() == Stage::BluetoothCoexistence {
                        self.initialized.boot.coexistence.initialized();
                    }
                    self.responses.push(response);
                    self.ticket = None;
                }
            }
        }
        let plan = self.plan.as_ref().unwrap();
        if self.next == plan.commands().len() {
            self.phase = ColdRadioPhase::PlatformConfigurationRequired;
            return Ok(self.phase);
        }
        let command = &plan.commands()[self.next];
        if command.stage() == Stage::BluetoothCoexistence {
            // Match the original reset before BT_CONFIG publication;
            // a send/ACK/reclaim failure cannot establish initialized state.
            self.initialized.boot.coexistence.begin_initialization();
        }
        // SAFETY: covered by this function's own safety contract.
        self.ticket = Some(unsafe {
            self.initialized
                .boot
                .submit_command(command.id(), command.bytes(), source)
        }?);
        self.next += 1;
        self.phase = ColdRadioPhase::Waiting(command.stage());
        Ok(self.phase)
    }
}
