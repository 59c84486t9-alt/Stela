// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2026 Intel Corporation
//! Cold unbound UMAC retirement. Linux mvm/scan.c's UMAC completion handler
//! releases its UID at completion. This owner additionally captures old
//! completed RBs and waits for deferred users before reusing that UID. No PHY,
//! associated channel, station, TCM worker or data queue exists in this owner;
//! there is no operating-channel command to invent as a restoration witness.
use super::*;

/// An immutable post-completion packet, never a BSS for either
/// the completed request or a later request. Keep it until its raw consumer is
/// finished; dropping this receipt releases only that deferred-user reference.
pub struct ScanRawReceive {
    progress: MpduProgress,
    _user: Arc<()>,
}
impl ScanRawReceive {
    pub fn progress(&self) -> &MpduProgress {
        &self.progress
    }
}
/// Historical terminal evidence moved out only after retirement. It
/// owns copied bytes and command receipts, with no native/DMA/scan permission.
pub struct ScanRetirement {
    outcome: protocol::Outcome,
    completion: ScanCompletion,
    start_response: CommandResponse,
    abort_response: Option<CommandResponse>,
    command_bytes: Vec<u8>,
}
impl ScanRetirement {
    pub fn outcome(&self) -> protocol::Outcome {
        self.outcome
    }
    pub fn completion(&self) -> &ScanCompletion {
        &self.completion
    }
    pub fn start_response(&self) -> &CommandResponse {
        &self.start_response
    }
    pub fn abort_response(&self) -> Option<&CommandResponse> {
        self.abort_response.as_ref()
    }
    pub fn command_bytes(&self) -> &[u8] {
        &self.command_bytes
    }
}
impl<Q: BootIo, B: BiosIo, O: CountryIo + OsPolicy> Ax200Scan<'_, Q, B, O> {
    /// Drain MPDUs captured after completion without attributing them
    /// to either request. No rearm, current-ticket lookup or public raw-packet
    /// restoration is performed. None means no captured MPDU this poll; only
    /// retire performs the complete bounded old-RB quiet check.
    pub fn poll_retiring_receive(&mut self) -> Result<Option<ScanRawReceive>, Ax200ScanError> {
        let result = self.poll_retiring_receive_inner();
        if let Err(error @ Ax200ScanError::Boot(_)) = &result {
            self.fail_retirement(error.clone());
        }
        result
    }
    fn poll_retiring_receive_inner(&mut self) -> Result<Option<ScanRawReceive>, Ax200ScanError> {
        self.check_retirement_phase()?;
        let boot = &mut self
            .mac
            .country
            .board
            .scan
            .mcc
            .setup
            .lari
            .radio
            .initialized
            .boot;
        if !boot.hcmd.has_matching(0xc1, 0)
            && matches!(
                boot.poll_one_notification_buffer_with_policy(true)
                    .map_err(Ax200ScanError::Boot)?,
                NotificationPoll::Backpressure
            )
        {
            return Err(Ax200ScanError::ReceiveBackpressure {
                notifications: boot.hcmd.notification_count(),
            });
        }
        let Some(captured) = boot.hcmd.take_matching(0xc1, 0) else {
            return Ok(None);
        };
        let progress = boot
            .decode_captured_mpdu(captured)
            .map_err(Ax200ScanError::Boot)?;
        Ok(Some(ScanRawReceive {
            progress,
            _user: self.users.clone(),
        }))
    }
    fn check_retirement_phase(&self) -> Result<(), Ax200ScanError> {
        if self.phase == Ax200ScanPhase::Failed {
            return Err(self.first_error.clone().unwrap_or(Ax200ScanError::State));
        }
        if self.phase != Ax200ScanPhase::DrainRequired
            || self.scanner.phase() != protocol::Phase::Retiring
            || self.command_ticket.is_some()
            || self.completion.is_none()
            || self.start_response.is_none()
            || self.command_bytes.is_none()
            || self.scan_ticket.is_none()
            || self.mac.phase() != Ax200MacPhase::ScanRequired
            || self.mac.mac_id_and_color() != Some(0)
        {
            return Err(Ax200ScanError::State);
        }
        Ok(())
    }
    fn fail_retirement(&mut self, error: Ax200ScanError) {
        self.first_error.get_or_insert(error);
        self.phase = Ax200ScanPhase::Failed;
    }
    /// Retire this exact completed passive scan in the unchanged cold/unbound
    /// MAC. Successful command polling already reclaimed the original command
    /// DMA; UMAC completion ends its radio lifetime. The live shared RX
    /// pool stays owned by RomBoot: this does not claim its DMA engine stopped.
    ///
    /// Capture every completed RB without rearming, refuse undrained canonical
    /// MPDUs/notifications and wait for all returned scan users. An observed
    /// quiet RX boundary is not an atomic on-air timestamp. The next start
    /// repeats the full prepublication capture/policy checks; stale completions
    /// and MCC events remain canonical and prevent a new UID0 publication.
    pub fn retire(&mut self) -> Result<ScanRetirement, Ax200ScanError> {
        let result = self.retire_inner();
        if let Err(error @ (Ax200ScanError::Boot(_) | Ax200ScanError::StaleNotification)) = &result
        {
            self.fail_retirement(error.clone());
        }
        result
    }
    fn retire_inner(&mut self) -> Result<ScanRetirement, Ax200ScanError> {
        self.check_retirement_phase()?;
        let boot = &mut self
            .mac
            .country
            .board
            .scan
            .mcc
            .setup
            .lari
            .radio
            .initialized
            .boot;
        if boot.state != State::PnvmObserved || boot.hcmd.pending_is_present() {
            return Err(Ax200ScanError::State);
        }
        let mut quiet = false;
        // No producer writes inside this loop: the original fixed pool bounds
        // completed buffers even if firmware is continuously receiving.
        for _ in 0..=boot.entries {
            match boot
                .poll_one_notification_buffer_with_policy(true)
                .map_err(Ax200ScanError::Boot)?
            {
                NotificationPoll::Pending => {
                    quiet = true;
                    break;
                }
                NotificationPoll::Processed => (),
                NotificationPoll::Backpressure => {
                    return Err(Ax200ScanError::ReceiveBackpressure {
                        notifications: boot.hcmd.notification_count(),
                    });
                }
            }
        }
        if !quiet {
            return Err(Ax200ScanError::ReceiveBackpressure {
                notifications: boot.hcmd.notification_count(),
            });
        }
        if boot
            .hcmd
            .has_matching(wire::COMPLETE_OPCODE, wire::COMPLETE_GROUP)
            || boot.hcmd.has_matching(0xc9, 0)
        {
            return Err(Ax200ScanError::StaleNotification);
        }
        if boot.hcmd.has_matching(0xc1, 0) {
            return Err(Ax200ScanError::PostScanReceiveRequired);
        }
        if boot.hcmd.notification_count() != 0 {
            return Err(Ax200ScanError::NotificationsRequired(
                boot.hcmd.notification_count(),
            ));
        }
        let users = Arc::strong_count(&self.users) - 1;
        if users != 0 {
            return Err(Ax200ScanError::DeferredUsers(users));
        }
        let outcome = self
            .scanner
            .retire(self.scan_ticket.unwrap(), protocol::Retirement::Confirmed)
            .map_err(Ax200ScanError::Protocol)?
            .ok_or(Ax200ScanError::State)?;
        let retired = ScanRetirement {
            outcome,
            completion: self.completion.take().unwrap(),
            start_response: self.start_response.take().unwrap(),
            abort_response: self.abort_response.take(),
            command_bytes: self.command_bytes.take().unwrap(),
        };
        self.users = Arc::new(());
        self.scan_ticket = None;
        self.command_deadline = None;
        self.completion_deadline = None;
        self.abort_requested = false;
        // A prior policy/revocation error is historical and still prevents
        // subsequent publication. Retirement never repairs the country epoch.
        self.phase = Ax200ScanPhase::NotStarted;
        Ok(retired)
    }
}
