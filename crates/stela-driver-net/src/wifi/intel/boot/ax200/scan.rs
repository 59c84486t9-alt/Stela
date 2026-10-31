// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2012-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! Original-owner UMAC scanning. ACK, scan-complete and retirement
//! are separate: no UID reuse before cold-unbound request retirement.
//! The shared native RX owner stays live; whole-device extraction is separate.
use super::super::hcmd::{CapturedNotification, NotificationPoll};
use super::*;
use crate::wifi::intel::command::Id;
use crate::wifi::{Band, Channel, regulatory, scan as protocol};
use regulatory::OsPolicy;
mod policy;
mod retirement;
pub use retirement::{ScanRawReceive, ScanRetirement};
mod phy;
mod wire;
pub use phy::{
    Ax200Binding, Ax200BindingError, Ax200BindingPhase, Ax200Coexistence, Ax200CoexistenceError,
    Ax200CoexistencePhase, Ax200LegacyPeer, Ax200LegacyPeerError, Ax200LegacyPeerPhase,
    Ax200ManagementQueue, Ax200ManagementQueueError, Ax200ManagementQueuePhase, Ax200Phy,
    Ax200PhyError, Ax200PhyPhase, Ax200TransmitPower, Ax200TransmitPowerError,
    Ax200TransmitPowerPhase, BindingCommand, BindingCommandKind, LegacyPeer, PeerCommand,
    PeerCommandKind, PhyCommand, PhyCommandKind, TransmitPowerLimit,
};
pub use wire::Probe;
static NEXT_CONTEXT: crate::wifi::Identities = crate::wifi::Identities::new();
const MAX_SCAN_US: u64 = 30_000_000;
/// `IWL_UCODE_TLV_CAPA_DS_PARAM_SET_IE_SUPPORT`.
const DS_PARAMETERS: u32 = 9;
/// `IWL_UCODE_TLV_CAPA_WFA_TPC_REP_IE_SUPPORT`.
const TPC_REPORT: u32 = 10;
/// `IWL_UCODE_TLV_CAPA_HIDDEN_6GHZ_SCAN`.
const HIDDEN_SIX_GHZ: u32 = 59;
/// `IWL_UCODE_TLV_CAPA_SCAN_DONT_TOGGLE_ANT`.
const FIXED_ANTENNA: u32 = 111;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ax200ScanPhase {
    NotStarted,
    WaitingStart,
    Scanning,
    WaitingAbort,
    Cancelling,
    /// Completion observed; restoration/old-RB/user drain still required.
    DrainRequired,
    Failed,
    Stopped,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ax200ScanError {
    Boot(Error),
    Country(Ax200CountryError),
    Regulatory(regulatory::Error),
    Protocol(protocol::Error),
    Normalize(crate::wifi::intel::receive::mpdu::normalize::Error),
    NoMemory,
    MissingApi(u8),
    Version { command: u8, version: u8 },
    ProbePowerRequired,
    UnsupportedRequest,
    ReceiveBackpressure { notifications: usize },
    PreScanReceiveRequired,
    PostScanReceiveRequired,
    DeferredUsers(usize),
    NotificationsRequired(usize),
    StaleNotification,
    CompletionLength(usize),
    CompletionUid(u32),
    CompletionStatus(u8),
    CommandResponse { command: u8, group: u8 },
    AbortResponseLength(usize),
    AbortStatus(u32),
    Deadline,
    State,
}
/// Immutable completed-RB capture. No public constructor can rebind
/// caller-supplied bytes, copied firmware UID or another RX epoch to this scan.
pub struct ScanCompletion {
    captured: CapturedNotification,
    outcome: protocol::Outcome,
}
/// RX receipt plus an observed BSS or explicit normalization/policy
/// rejection. Neither branch authenticates the AP or permits association.
pub struct ScanResult {
    observed: ObservedMpdu,
    result: Result<protocol::result::Bss, Ax200ScanError>,
    _user: Arc<()>,
}
/// Rejected bytes keep the same deferred scan-user lifetime as good results.
pub struct ScanRejectedMpdu {
    rejected: RejectedMpdu,
    _user: Arc<()>,
}
impl ScanRejectedMpdu {
    pub fn error(&self) -> crate::wifi::intel::receive::mpdu::Error {
        self.rejected.error()
    }
    pub fn raw_packet(&self) -> &[u8] {
        self.rejected.raw_packet()
    }
}
impl ScanResult {
    pub fn observed(&self) -> &ObservedMpdu {
        &self.observed
    }
    pub fn result(&self) -> Result<&protocol::result::Bss, &Ax200ScanError> {
        self.result.as_ref()
    }
}
#[allow(
    clippy::large_enum_variant,
    reason = "captured scan results and their deferred-user guards transfer inline without a new allocation or failure branch"
)]
pub enum ScanResultProgress {
    Pending,
    Backpressure { notifications: usize },
    Rejected(ScanRejectedMpdu),
    Observed(ScanResult),
}
impl ScanCompletion {
    pub fn raw_packet(&self) -> &[u8] {
        &self.captured.bytes
    }
    pub fn outcome(&self) -> protocol::Outcome {
        self.outcome
    }
    pub fn last_schedule(&self) -> u8 {
        self.captured.bytes[12]
    }
    pub fn last_iteration(&self) -> u8 {
        self.captured.bytes[13]
    }
    pub fn ebs_status(&self) -> u8 {
        self.captured.bytes[15]
    }
}
pub struct Ax200Scan<'a, Q: BootIo, B: BiosIo, O: CountryIo + OsPolicy> {
    pub(in crate::wifi::intel::boot) mac: Ax200Mac<'a, Q, B, O>,
    phase: Ax200ScanPhase,
    native: regulatory::NativeContext,
    scanner: protocol::Scanner,
    users: Arc<()>,
    scan_ticket: Option<protocol::Ticket>,
    command_ticket: Option<CommandTicket>,
    command_deadline: Option<crate::Deadline>,
    completion_deadline: Option<crate::Deadline>,
    command_bytes: Option<Vec<u8>>,
    start_response: Option<CommandResponse>,
    abort_response: Option<CommandResponse>,
    completion: Option<ScanCompletion>,
    rejected_completion: Option<CapturedNotification>,
    abort_requested: bool,
    first_error: Option<Ax200ScanError>,
}
impl<'a, Q: BootIo, B: BiosIo, O: CountryIo + OsPolicy> Ax200Mac<'a, Q, B, O> {
    /// Attach the same live OS regulatory source to the original unbound MAC.
    /// # Safety
    /// O's OsPolicy lease must pin this SAME CountryIo country
    /// selection, pinned database and selection revision through publication.
    /// Equal revision numbers or implementing both traits alone is insufficient.
    /// It must coordinate restrictive revocation with the original native owner
    /// to stop/cancel/drain pending scans or physically enforce restrictions
    /// before further activity, obeying hardware-before-OS acquisition order.
    /// No other path may publish scans or create firmware radio objects in this
    /// epoch; UID0 has never been submitted. This is a real platform
    /// attachment validation, never an observation-derived radio grant.
    pub unsafe fn begin_scan(self) -> Result<Ax200Scan<'a, Q, B, O>, Box<Self>> {
        if self.phase() != Ax200MacPhase::ScanRequired
            || self.first_error().is_some()
            || self.mac_id_and_color() != Some(0)
            || self
                .country
                .board
                .scan
                .mcc
                .setup
                .lari
                .radio
                .initialized
                .boot
                .state
                != State::PnvmObserved
        {
            return Err(Box::new(self));
        }
        let Some(identity) = NEXT_CONTEXT.next() else {
            return Err(Box::new(self));
        };
        let Ok(scanner) = protocol::Scanner::new(crate::Mac(self.initialized_nvm().address.bytes))
        else {
            return Err(Box::new(self));
        };
        let Some(revision) = self.country.selection_revision() else {
            return Err(Box::new(self));
        };
        Ok(Ax200Scan {
            mac: self,
            phase: Ax200ScanPhase::NotStarted,
            native: regulatory::NativeContext {
                device: identity,
                reset_epoch: identity,
                firmware_epoch: identity,
                policy_revision: revision,
            },
            scanner,
            users: Arc::new(()),
            scan_ticket: None,
            command_ticket: None,
            command_deadline: None,
            completion_deadline: None,
            command_bytes: None,
            start_response: None,
            abort_response: None,
            completion: None,
            rejected_completion: None,
            abort_requested: false,
            first_error: None,
        })
    }
}
impl<Q: BootIo, B: BiosIo, O: CountryIo + OsPolicy> Ax200Scan<'_, Q, B, O> {
    pub fn phase(&self) -> Ax200ScanPhase {
        self.phase
    }
    pub fn protocol_phase(&self) -> protocol::Phase {
        self.scanner.phase()
    }
    pub fn first_error(&self) -> Option<&Ax200ScanError> {
        self.first_error.as_ref()
    }
    pub fn request(&self) -> Option<&protocol::Request> {
        self.scanner.request()
    }
    /// The channels a scan may cover, in the firmware's MCC order:
    /// valid in its channel list, enabled by the NVM SKU and covered by the
    /// selected country's 20 MHz rules, at most one request's worth.
    pub fn channels(&mut self) -> Vec<Channel> {
        let native = self.native;
        let Some(parts) = self.mac.country.scan_policy_parts() else {
            return Vec::new();
        };
        let hardware = policy::Hardware {
            board: parts.board,
            selection: parts.selection,
            channels: parts.channels,
            native,
        };
        hardware
            .channels
            .iter()
            .filter_map(|observation| {
                let band = match observation.channel.band {
                    crate::wifi::intel::mcc::channel::Band::Ghz2 => Band::Ghz2,
                    crate::wifi::intel::mcc::channel::Band::Ghz5 => Band::Ghz5,
                    crate::wifi::intel::mcc::channel::Band::Ghz6 => Band::Ghz6,
                };
                hardware.channel(band, observation.channel.number)
            })
            .collect()
    }
    /// The same channels with the regulatory flags their firmware
    /// restrictions give them.
    pub fn regulated_channels(&mut self) -> Vec<(Channel, u32)> {
        let channels = self.channels();
        let Some(parts) = self.mac.country.scan_policy_parts() else {
            return Vec::new();
        };
        channels
            .into_iter()
            .filter_map(|channel| {
                let observed = parts.channels.iter().find(|observation| {
                    observation.channel.number == channel.number
                        && observation.channel.frequency_mhz == channel.frequency_mhz
                })?;
                let restrictions = observed.restrictions;
                Some((
                    channel,
                    crate::wifi::intel::link::channel_flags(&restrictions),
                ))
            })
            .collect()
    }
    /// The transmit and receive antennas the firmware and NVM both give.
    pub fn chains(&self) -> (u32, u32) {
        let information = &self.mac.initialized_nvm().information;
        (information.tx_chains, information.rx_chains)
    }
    /// What limits a radio with EHT.
    pub fn eht_limits(&self) -> Option<crate::wifi::intel::identity::EhtLimits> {
        self.mac
            .country
            .board
            .scan
            .mcc
            .setup
            .lari
            .radio
            .initialized
            .boot
            .eht_limits()
    }
    pub fn command_bytes(&self) -> Option<&[u8]> {
        self.command_bytes.as_deref()
    }
    pub fn command_ticket(&self) -> Option<&CommandTicket> {
        self.command_ticket.as_ref()
    }
    pub fn start_response(&self) -> Option<&CommandResponse> {
        self.start_response.as_ref()
    }
    pub fn abort_response(&self) -> Option<&CommandResponse> {
        self.abort_response.as_ref()
    }
    pub fn completion(&self) -> Option<&ScanCompletion> {
        self.completion.as_ref()
    }
    pub fn rejected_completion_packet(&self) -> Option<&[u8]> {
        self.rejected_completion
            .as_ref()
            .map(|packet| packet.bytes.as_slice())
    }
    pub fn replenish_completed_receive(&mut self) -> Result<Replenished, Error> {
        self.mac.replenish_completed_receive()
    }
    /// Preserve unrelated traffic without allowing caller diagnostics to steal
    /// the canonical scan completion, MCC revocation or raw MPDU captures.
    pub fn take_other_notification(&mut self) -> Option<FirmwareNotification> {
        self.mac
            .country
            .board
            .scan
            .mcc
            .setup
            .lari
            .radio
            .initialized
            .boot
            .hcmd
            .take_unreserved(&[
                (wire::COMPLETE_OPCODE, wire::COMPLETE_GROUP),
                (0xc9, 0),
                (0xc1, 0),
            ])
    }
    /// Drain a pre-publication MPDU as an unattributed raw observation.
    /// It can never acquire this Scanner's later request ticket or BSS result.
    pub fn poll_pre_scan_receive(&mut self) -> Result<MpduProgress, Ax200ScanError> {
        let result = self.poll_pre_scan_receive_inner();
        if let Err(error @ Ax200ScanError::Boot(_)) = &result {
            self.first_error.get_or_insert_with(|| error.clone());
            self.phase = Ax200ScanPhase::Failed;
        }
        result
    }
    fn poll_pre_scan_receive_inner(&mut self) -> Result<MpduProgress, Ax200ScanError> {
        if self.phase == Ax200ScanPhase::Failed {
            return Err(self.first_error.clone().unwrap_or(Ax200ScanError::State));
        }
        if self.phase != Ax200ScanPhase::NotStarted || self.scanner.phase() != protocol::Phase::Idle
        {
            return Err(Ax200ScanError::State);
        }
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
        boot.poll_mpdu().map_err(Ax200ScanError::Boot)
    }
    /// Consume queued scan MPDUs in RX order before the matching real
    /// completion. No invented raw packet/current-ticket restoration path.
    pub fn poll_result(&mut self) -> Result<ScanResultProgress, Ax200ScanError> {
        let result = self.poll_result_inner();
        if let Err(error @ Ax200ScanError::Boot(_)) = &result {
            self.first_error.get_or_insert_with(|| error.clone());
            self.phase = Ax200ScanPhase::Failed;
        }
        result
    }
    fn poll_result_inner(&mut self) -> Result<ScanResultProgress, Ax200ScanError> {
        if self.phase == Ax200ScanPhase::Failed {
            return Err(self.first_error.clone().unwrap_or(Ax200ScanError::State));
        }
        if !matches!(
            self.phase,
            Ax200ScanPhase::Scanning | Ax200ScanPhase::Cancelling
        ) {
            return Err(Ax200ScanError::State);
        }
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
        if boot
            .hcmd
            .matching_precedes((wire::COMPLETE_OPCODE, wire::COMPLETE_GROUP), (0xc1, 0))
        {
            return Ok(ScanResultProgress::Pending);
        }
        if !boot.hcmd.has_matching(0xc1, 0) {
            if matches!(
                boot.poll_one_notification_buffer_with_policy(true)
                    .map_err(Ax200ScanError::Boot)?,
                NotificationPoll::Backpressure
            ) {
                return Ok(ScanResultProgress::Backpressure {
                    notifications: boot.hcmd.notification_count(),
                });
            }
            if boot
                .hcmd
                .matching_precedes((wire::COMPLETE_OPCODE, wire::COMPLETE_GROUP), (0xc1, 0))
            {
                return Ok(ScanResultProgress::Pending);
            }
        }
        let Some(captured) = boot.hcmd.take_matching(0xc1, 0) else {
            return Ok(ScanResultProgress::Pending);
        };
        let observed = match boot
            .decode_captured_mpdu(captured)
            .map_err(Ax200ScanError::Boot)?
        {
            MpduProgress::Rejected(rejected) => {
                return Ok(ScanResultProgress::Rejected(ScanRejectedMpdu {
                    rejected,
                    _user: self.users.clone(),
                }));
            }
            MpduProgress::Observed(observed) => observed,
            _ => return Err(Ax200ScanError::State),
        };
        let result = (|| {
            self.mac
                .country
                .check_selection()
                .map_err(Ax200ScanError::Country)?;
            let normalized = observed.normalize().map_err(Ax200ScanError::Normalize)?;
            let parts = self
                .mac
                .country
                .scan_policy_parts()
                .ok_or(Ax200ScanError::State)?;
            policy::observe(
                parts,
                self.native,
                &self.scanner,
                self.scan_ticket.ok_or(Ax200ScanError::State)?,
                normalized.frame(),
            )
        })();
        Ok(ScanResultProgress::Observed(ScanResult {
            observed,
            result,
            _user: self.users.clone(),
        }))
    }
    pub fn stop(&mut self) -> Result<(), Error> {
        match self.mac.stop() {
            Ok(()) => {
                self.phase = Ax200ScanPhase::Stopped;
                Ok(())
            }
            Err(error) => {
                self.first_error
                    .get_or_insert_with(|| Ax200ScanError::Boot(error.clone()));
                self.phase = Ax200ScanPhase::Failed;
                Err(error)
            }
        }
    }
    /// Publish one exact forced-passive request under the native and OS
    /// leases. A failed admission/allocation does not mark the protocol
    /// submitted.
    /// # Safety
    /// `source` supplies fresh exclusive coherent pages for this native
    /// requester/domain under RomBoot's complete publication contract.
    pub unsafe fn start(
        &mut self,
        request: protocol::Request,
        budget_us: u64,
        source: &dyn PageSource,
    ) -> Result<Ax200ScanPhase, Ax200ScanError> {
        // SAFETY: forwarded.
        unsafe { self.publish(request, None, budget_us, source) }
    }
    /// As `start`, for a request that probes as `probe` describes.
    /// # Safety
    /// As `start`.
    pub unsafe fn start_probing(
        &mut self,
        request: protocol::Request,
        probe: &Probe,
        budget_us: u64,
        source: &dyn PageSource,
    ) -> Result<Ax200ScanPhase, Ax200ScanError> {
        // SAFETY: forwarded.
        unsafe { self.publish(request, Some(probe), budget_us, source) }
    }
    unsafe fn publish(
        &mut self,
        request: protocol::Request,
        probe: Option<&Probe>,
        budget_us: u64,
        source: &dyn PageSource,
    ) -> Result<Ax200ScanPhase, Ax200ScanError> {
        // SAFETY: original requester/domain publication contract.
        let result = unsafe { self.start_inner(request, probe, budget_us, source) };
        // Pure admission/encoding failure remains unsubmitted and retryable;
        // native I/O/visibility failure preserves the first real error.
        if let Err(error @ Ax200ScanError::Boot(_)) = &result {
            self.first_error.get_or_insert_with(|| error.clone());
            self.phase = Ax200ScanPhase::Failed;
        }
        result
    }
    unsafe fn start_inner(
        &mut self,
        request: protocol::Request,
        probe: Option<&Probe>,
        budget_us: u64,
        source: &dyn PageSource,
    ) -> Result<Ax200ScanPhase, Ax200ScanError> {
        if self.phase == Ax200ScanPhase::Failed {
            return Err(self.first_error.clone().unwrap_or(Ax200ScanError::State));
        }
        if self.phase != Ax200ScanPhase::NotStarted || self.scanner.phase() != protocol::Phase::Idle
        {
            return Err(Ax200ScanError::State);
        }
        if let Some(error) = self.first_error.as_ref() {
            return Err(error.clone());
        }
        if request.active() && probe.is_none() {
            return Err(Ax200ScanError::ProbePowerRequired);
        }
        if !(1..=MAX_SCAN_US).contains(&budget_us) {
            return Err(Ax200ScanError::UnsupportedRequest);
        }
        self.mac
            .country
            .check_selection()
            .map_err(Ax200ScanError::Country)?;
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
        let version = wire::validate(&boot.firmware)?;
        let abilities = wire::Abilities {
            ds_parameters: boot.firmware.supports_capability(DS_PARAMETERS),
            tpc_report: boot.firmware.supports_capability(TPC_REPORT),
            hidden_six_ghz: boot.firmware.supports_capability(HIDDEN_SIX_GHZ),
            fixed_antenna: boot.firmware.supports_capability(FIXED_ANTENNA),
        };
        // Capture every already-completed RB before admitting a new request.
        // This exclusive owner never rearms inside the loop, so the real fixed
        // pool bounds it. Backpressure cannot hide an old MCC/scan/MPDU event
        // and cannot silently turn a pre-publication packet into a new result.
        let mut quiet = false;
        for _ in 0..=boot.entries {
            match boot
                .poll_one_notification_buffer()
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
        if boot.hcmd.has_matching(0xc1, 0) {
            return Err(Ax200ScanError::PreScanReceiveRequired);
        }
        if boot
            .hcmd
            .has_matching(wire::COMPLETE_OPCODE, wire::COMPLETE_GROUP)
        {
            return Err(Ax200ScanError::StaleNotification);
        }
        let options = self.mac.country.board.scan.mcc.setup.options;
        let parts = self
            .mac
            .country
            .scan_policy_parts()
            .ok_or(Ax200ScanError::State)?;
        let hardware = policy::Hardware {
            board: parts.board,
            selection: parts.selection,
            channels: parts.channels,
            native: self.native,
        };
        let os = policy::Os {
            service: parts.os,
            selection_revision: parts.selection.revision,
        };
        let mut owner = regulatory::Owner::new(hardware, os).map_err(Ax200ScanError::Regulatory)?;
        let admission = owner
            .admit_scan(&request, probe.map(|probe| probe.profiles))
            .map_err(Ax200ScanError::Regulatory)?;
        let scanner = &mut self.scanner;
        let scan_ticket = &mut self.scan_ticket;
        let phase = &mut self.phase;
        let command_bytes = &mut self.command_bytes;
        // SAFETY: exact admission-owned immutable request is encoded inside the
        // original hardware+OS guard pair. Scanner is marked submitted
        // before HCMD descriptor visibility, including an uncertain failure.
        let result = unsafe {
            owner.publish_scan(admission, |guard, operation| {
                let bytes = wire::encode(
                    operation.request(),
                    version,
                    scanner.local(),
                    probe,
                    abilities,
                )?;
                let mut checked = policy::CheckedRequest(operation.request());
                let now = options.clock.now_us();
                let ticket = scanner
                    .begin(request, now, budget_us, &mut checked)
                    .map_err(Ax200ScanError::Protocol)?;
                *scan_ticket = Some(ticket);
                scanner
                    .validate_submission(ticket, now, &mut checked)
                    .map_err(Ax200ScanError::Protocol)?;
                scanner
                    .submitted(ticket)
                    .map_err(Ax200ScanError::Protocol)?;
                *phase = Ax200ScanPhase::WaitingStart;
                *command_bytes = Some(bytes);
                // SAFETY: same exact request and kept native page contract.
                guard
                    .submit(wire::REQUEST, command_bytes.as_deref().unwrap(), source)
                    .map_err(Ax200ScanError::Boot)
            })
        }
        .map_err(Ax200ScanError::Regulatory)?;
        match result {
            Ok(ticket) => {
                self.command_ticket = Some(ticket);
                self.command_deadline = Some(options.clock.deadline(options.command_timeout_us));
                Ok(self.phase)
            }
            Err(error) => {
                if self.scanner.phase() != protocol::Phase::Idle {
                    self.phase = Ax200ScanPhase::Failed;
                    self.first_error.get_or_insert_with(|| error.clone());
                }
                Err(error)
            }
        }
    }
    /// Request real firmware cancellation; this supplies no completion proof.
    /// Revocation/RF-kill cannot prevent this control request or hardware stop.
    pub fn cancel(&mut self) -> Result<(), Ax200ScanError> {
        if !matches!(
            self.phase,
            Ax200ScanPhase::WaitingStart
                | Ax200ScanPhase::Scanning
                | Ax200ScanPhase::WaitingAbort
                | Ax200ScanPhase::Cancelling
        ) {
            return Err(Ax200ScanError::State);
        }
        self.scanner
            .cancel(self.scan_ticket.ok_or(Ax200ScanError::State)?)
            .map_err(Ax200ScanError::Protocol)?;
        self.abort_requested = true;
        Ok(())
    }
    fn accept_completion(&mut self) -> Result<(), Ax200ScanError> {
        if self.completion.is_some() {
            return Ok(());
        }
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
        // A completion in the same RB cannot overtake earlier MPDUs;
        // those must be observed/rejected by poll_result before terminal state.
        if boot
            .hcmd
            .matching_precedes((0xc1, 0), (wire::COMPLETE_OPCODE, wire::COMPLETE_GROUP))
        {
            return Ok(());
        }
        let Some(captured) = boot
            .hcmd
            .take_matching(wire::COMPLETE_OPCODE, wire::COMPLETE_GROUP)
        else {
            return Ok(());
        };
        let result = (|| {
            if !boot.hcmd.owns_capture(&captured) {
                return Err(Ax200ScanError::StaleNotification);
            }
            let raw = &captured.bytes[8..];
            if raw.len() != 16 {
                return Err(Ax200ScanError::CompletionLength(raw.len()));
            }
            let uid = u32::from_le_bytes(raw[..4].try_into().unwrap());
            if uid != 0 {
                return Err(Ax200ScanError::CompletionUid(uid));
            }
            let outcome = match raw[6] {
                1 => protocol::Outcome::Completed,
                2 => protocol::Outcome::Aborted,
                status => return Err(Ax200ScanError::CompletionStatus(status)),
            };
            self.scanner
                .completed(self.scan_ticket.ok_or(Ax200ScanError::State)?, outcome)
                .map_err(Ax200ScanError::Protocol)?;
            Ok(outcome)
        })();
        match result {
            Ok(outcome) => {
                self.completion = Some(ScanCompletion { captured, outcome });
                Ok(())
            }
            Err(error) => {
                self.rejected_completion = Some(captured);
                Err(error)
            }
        }
    }
    /// Advance start/abort ACK, original captured scan completion and
    /// command DMA reclaim. Deadline/revocation never invents completion.
    /// # Safety
    /// `source` satisfies the same original requester/domain page contract.
    pub unsafe fn advance(
        &mut self,
        source: &dyn PageSource,
    ) -> Result<Ax200ScanPhase, Ax200ScanError> {
        if self.phase == Ax200ScanPhase::Failed {
            return Err(self.first_error.clone().unwrap_or(Ax200ScanError::State));
        }
        // SAFETY: native page contract is forwarded unchanged.
        let result = unsafe { self.advance_inner(source) };
        if let Err(error) = &result
            && !matches!(error, Ax200ScanError::Boot(Error::CommandReclaim(_)))
        {
            self.first_error.get_or_insert_with(|| error.clone());
            self.phase = Ax200ScanPhase::Failed;
        }
        result
    }
    unsafe fn advance_inner(
        &mut self,
        source: &dyn PageSource,
    ) -> Result<Ax200ScanPhase, Ax200ScanError> {
        if matches!(
            self.phase,
            Ax200ScanPhase::NotStarted | Ax200ScanPhase::Stopped
        ) {
            return Err(Ax200ScanError::State);
        }
        if self
            .mac
            .country
            .board
            .scan
            .mcc
            .setup
            .lari
            .radio
            .initialized
            .boot
            .state
            != State::PnvmObserved
        {
            return Err(Ax200ScanError::State);
        }
        if let Some(ticket) = self.command_ticket.as_ref() {
            let result = self
                .mac
                .country
                .board
                .scan
                .mcc
                .setup
                .lari
                .radio
                .initialized
                .boot
                .poll_command(ticket);
            if matches!(result, Err(Error::CommandReclaim(_)))
                && self
                    .command_deadline
                    .as_ref()
                    .is_some_and(crate::Deadline::passed)
            {
                return Err(Ax200ScanError::Deadline);
            }
            match result.map_err(Ax200ScanError::Boot)? {
                CommandProgress::Pending => {
                    if self
                        .command_deadline
                        .as_ref()
                        .is_some_and(crate::Deadline::passed)
                    {
                        return Err(Ax200ScanError::Deadline);
                    }
                    return Ok(self.phase);
                }
                CommandProgress::Completed(response) => {
                    let abort = self.phase == Ax200ScanPhase::WaitingAbort;
                    let expected = if abort { wire::ABORT } else { wire::REQUEST };
                    let correct =
                        response.command == expected.opcode && response.group == expected.group;
                    let abort_status = if abort {
                        if response.raw.len() != 4 {
                            Err(Ax200ScanError::AbortResponseLength(response.raw.len()))
                        } else {
                            let status = u32::from_le_bytes(response.raw[..4].try_into().unwrap());
                            if status <= 2 {
                                Ok(())
                            } else {
                                Err(Ax200ScanError::AbortStatus(status))
                            }
                        }
                    } else {
                        Ok(())
                    };
                    if abort {
                        self.abort_response = Some(response);
                    } else {
                        self.start_response = Some(response);
                    }
                    self.command_ticket = None;
                    self.command_deadline = None;
                    if !correct {
                        return Err(Ax200ScanError::CommandResponse {
                            command: if abort {
                                self.abort_response.as_ref()
                            } else {
                                self.start_response.as_ref()
                            }
                            .unwrap()
                            .command,
                            group: if abort {
                                self.abort_response.as_ref()
                            } else {
                                self.start_response.as_ref()
                            }
                            .unwrap()
                            .group,
                        });
                    }
                    abort_status?;
                    self.phase = if abort {
                        Ax200ScanPhase::Cancelling
                    } else {
                        Ax200ScanPhase::Scanning
                    };
                }
            }
        } else {
            self.mac
                .country
                .board
                .scan
                .mcc
                .setup
                .lari
                .radio
                .initialized
                .boot
                .poll_one_notification_buffer_with_policy(true)
                .map_err(Ax200ScanError::Boot)?;
        }
        // As with the existing command owner, already-captured terminal
        // RX wins a host polling deadline. Host poll time cannot timestamp its
        // arrival. This records completion only; no radio/RX retirement follows.
        self.accept_completion()?;
        if self.completion.is_some() {
            self.phase = Ax200ScanPhase::DrainRequired;
            return Ok(self.phase);
        }
        // Abort ACK (including NOT_FOUND) does not end the original radio
        // lifetime. Bound the remaining wait while keeping its real owner.
        if self
            .completion_deadline
            .as_ref()
            .is_some_and(crate::Deadline::passed)
        {
            return Err(Ax200ScanError::Deadline);
        }
        if let Err(error) = self.mac.country.check_selection() {
            self.first_error
                .get_or_insert(Ax200ScanError::Country(error));
            self.cancel()?;
        }
        if self
            .mac
            .country
            .board
            .scan
            .mcc
            .setup
            .lari
            .radio
            .initialized
            .boot
            .hcmd
            .has_matching(0xc9, 0)
        {
            self.first_error
                .get_or_insert(Ax200ScanError::StaleNotification);
            self.cancel()?;
        }
        let options = self.mac.country.board.scan.mcc.setup.options;
        if self
            .scanner
            .poll(
                self.scan_ticket.ok_or(Ax200ScanError::State)?,
                options.clock.now_us(),
            )
            .map_err(Ax200ScanError::Protocol)?
        {
            self.abort_requested = true;
        }
        if self.abort_requested && self.phase == Ax200ScanPhase::Scanning {
            self.completion_deadline = Some(options.clock.deadline(options.command_timeout_us));
            // SAFETY: source abort explicitly has CMD_SEND_IN_RFKILL and the
            // UID0 belongs to this owner. It grants no RF use.
            self.command_ticket = Some(
                unsafe {
                    self.mac
                        .country
                        .board
                        .scan
                        .mcc
                        .setup
                        .lari
                        .radio
                        .initialized
                        .boot
                        .submit_command_with_policy(wire::ABORT, &[0; 8], source, true)
                }
                .map_err(Ax200ScanError::Boot)?,
            );
            self.command_deadline = Some(options.clock.deadline(options.command_timeout_us));
            self.phase = Ax200ScanPhase::WaitingAbort;
        }
        Ok(self.phase)
    }
}
