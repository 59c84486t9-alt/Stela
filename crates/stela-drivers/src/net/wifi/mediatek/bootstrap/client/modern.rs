// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2023 MediaTek Inc.
//! Current-association modern command ownership. A prepared context has no
//! permission to enable firmware rate selection or autonomous radio responses.
use super::*;
use crate::net::wifi::station::AssociationContext;

pub(super) struct Configuration {
    context: Arc<AssociationContext>,
    pub(super) wire: wire::modern::Configuration,
    commands: Vec<(Command, Vec<u8>)>,
    filter: crate::net::wifi::mediatek::mcu::init::Request,
    completed: usize,
    pub(super) prepared_edca: [station::phy::AccessCategory; 4],
    pub(super) applied_edca: Option<super::edca::AppliedEdca>,
}
impl Configuration {
    pub(super) fn context(&self) -> &Arc<AssociationContext> {
        &self.context
    }
}

impl<I: BarIo, Q: QueueIo, C: 'static> Client<I, Q, C> {
    /// Program the original canonical key owner and source BSS cipher under
    /// the same complete modern hardware/OS permission. Material/RSC come from
    /// the OS authentication service; this is no supplicant substitute.
    ///
    /// # Safety
    /// The exact-controller, policy retention and revocation requirements of
    /// `configure_modern` apply to both BSS and key command publication.
    pub unsafe fn install_key_modern<
        H: wifi::regulatory::HardwarePolicy,
        O: wifi::regulatory::OsPolicy,
    >(
        &mut self,
        authority: &mut wifi::regulatory::Owner<H, O>,
        admission: wifi::regulatory::AssociationAdmission,
        pairwise: bool,
        index: u8,
        material: &[u8],
        seed: ReplaySeed,
    ) -> Result<KeyIdentity, Error> {
        // SAFETY: covered by this function's own safety contract.
        unsafe { self.modern_key(authority, admission, pairwise, index, material, seed) }
    }

    unsafe fn modern_key<H: wifi::regulatory::HardwarePolicy, O: wifi::regulatory::OsPolicy>(
        &mut self,
        authority: &mut wifi::regulatory::Owner<H, O>,
        admission: wifi::regulatory::AssociationAdmission,
        pairwise: bool,
        index: u8,
        material: &[u8],
        seed: ReplaySeed,
    ) -> Result<KeyIdentity, Error> {
        let s = self.state_mut();
        if s.phase != Phase::Associated {
            return Err(Error::WrongPhase);
        }
        let modern = s.modern.as_ref().ok_or(Error::WrongPhase)?;
        s.station
            .validate_association_context(&modern.context)
            .map_err(Error::Station)?;
        let mut profile = s.profile.ok_or(Error::WrongProfile)?;
        let ciphers = s.ciphers.ok_or(Error::NoKey)?;
        let cipher = if pairwise { ciphers.0 } else { ciphers.1 };
        let bss = if profile.cipher == 0 {
            profile.cipher = match cipher {
                Cipher::Wep40 => 1,
                Cipher::Tkip => 2,
                Cipher::Ccmp128 => 4,
                Cipher::Ccmp256 => 10,
                Cipher::Gcmp128 => 11,
                Cipher::Gcmp256 => 12,
                Cipher::Wep104 => 5,
            };
            Some(
                modern
                    .wire
                    .bss_request(profile, true)
                    .map_err(Error::Codec)?,
            )
        } else {
            None
        };
        let key = if pairwise {
            s.ptk.as_mut()
        } else {
            s.gtk.as_mut()
        }
        .ok_or(Error::NoKey)?;
        let phase = &mut s.phase;
        let current_profile = &mut s.profile;
        let controller = &mut s.controller;
        let replies = &mut s.replies;
        // SAFETY: covered by this function's own safety contract.
        unsafe {
            authority.publish_association(
                admission,
                &s.station,
                wifi::regulatory::AssociationUse::Management,
                |_, _| {
                    *phase = Phase::Quarantined;
                    if let Some(body) = &bss {
                        Self::command_parts(controller, replies, Command::BssInfo, body)?;
                        *current_profile = Some(profile);
                    }
                    let mailbox = controller.state_mut().mailbox.as_mut().unwrap();
                    let result = key.install(mailbox, index, cipher, material, seed);
                    if !key.is_quarantined() {
                        *phase = Phase::Associated;
                    }
                    result.map_err(Error::Key)
                },
            )
        }
        .map_err(Error::Regulatory)?
    }

    /// Begin source-backed single-link modern negotiation. Modern
    /// configuration remains pending until context-bound hardware/OS
    /// admission covers its complete firmware/autonomous transmission set.
    pub fn join_modern(
        &mut self,
        join: Join,
        beacon: scan::result::Bss,
        profile: Profile,
        now: u64,
        source: &dyn PageSource,
        policy: &mut impl station::RegulatoryPolicy,
    ) -> Result<(), Error> {
        self.validate_modern_join(&join, profile)?;
        self.join_inner(join, Some(beacon), profile, now, source, policy)
    }

    pub(super) fn validate_modern_join(&self, join: &Join, profile: Profile) -> Result<(), Error> {
        let requested = join.request.modern().ok_or(Error::WrongProfile)?;
        let actual = self
            .local_advertisement(join.channel.band)
            .map_err(|_| Error::WrongProfile)?;
        actual
            .validate_capabilities(requested.capabilities())
            .map_err(|_| Error::WrongProfile)?;
        if profile.antenna_mask != actual.antenna_mask()
            || matches!(
                requested.width(),
                station::phy::Width::Mhz80P80 | station::phy::Width::Mhz320
            )
        {
            return Err(Error::WrongProfile);
        }
        Ok(())
    }

    /// Private shared context kept by this native owner. Inspection
    /// is neither modern publication permission nor a firmware completion.
    pub fn modern_context(&self) -> Option<&Arc<AssociationContext>> {
        self.state().modern.as_ref().map(|m| &m.context)
    }

    pub fn pending_modern_requests(&self) -> usize {
        if self.phase() == Phase::AwaitingModernAdmission {
            self.state().modern.as_ref().map_or(0, |m| m.commands.len())
        } else {
            0
        }
    }
    /// Derive the complete restricted command before replacing the pending
    /// command. Allocation/validation failure leaves the old owner intact;
    /// this helper performs no native publication or association completion.
    pub(super) fn restrict_prepared_edca(
        &mut self,
        effective: &[station::phy::AccessCategory; 4],
    ) -> Result<(), Error> {
        let s = self.state_mut();
        if s.phase != Phase::AwaitingModernAdmission {
            return Err(Error::WrongPhase);
        }
        let m = s.modern.as_mut().ok_or(Error::WrongPhase)?;
        if m.completed != 0 {
            return Err(Error::WrongPhase);
        }
        let p = s.profile.ok_or(Error::WrongProfile)?;
        let body = m
            .wire
            .edca_restricted_request(p, effective)
            .map_err(Error::Codec)?;
        let pending = m
            .commands
            .iter_mut()
            .find(|(command, _)| *command == Command::Edca)
            .ok_or(Error::WrongPhase)?;
        pending.1 = body;
        m.prepared_edca = *effective;
        Ok(())
    }
    pub fn completed_modern_requests(&self) -> usize {
        self.state().modern.as_ref().map_or(0, |m| m.completed)
    }

    /// Execute this same private current association's complete source command
    /// chain under the canonical hardware/OS guards, then acknowledge it to
    /// Station only after real matching firmware and DMA completions.
    ///
    /// # Safety
    /// `authority` belongs to this exact controller/requester and C,
    /// with current reset/firmware/policy epochs and applied
    /// per-rate power. Its acquired guards serialize this native path; C keeps
    /// their underlying policy/board/radio/queue/key resources alive through
    /// partial/uncertain programming and all armed autonomous/deferred users.
    /// Revocation must enforce/stop/cancel/drain those real users, not
    /// change an admission boolean. A different device's valid permission or a
    /// copied source plan cannot check this native attachment.
    pub unsafe fn configure_modern<
        H: wifi::regulatory::HardwarePolicy,
        O: wifi::regulatory::OsPolicy,
    >(
        &mut self,
        authority: &mut wifi::regulatory::Owner<H, O>,
        admission: wifi::regulatory::AssociationAdmission,
        now: u64,
    ) -> Result<(), Error> {
        use wifi::regulatory::AssociationUse;
        let s = self.state_mut();
        if s.phase != Phase::AwaitingModernAdmission {
            return Err(Error::WrongPhase);
        }
        let p = s.profile.ok_or(Error::WrongProfile)?;
        let m = s.modern.as_ref().ok_or(Error::WrongPhase)?;
        s.station
            .validate_association_context(&m.context)
            .map_err(Error::Station)?;
        if m.completed != 0 {
            return Err(Error::WrongPhase);
        }
        s.replies
            .try_reserve(m.commands.len())
            .map_err(|_| Error::NoMemory)?;
        s.transport_facts
            .try_reserve(1)
            .map_err(|_| Error::NoMemory)?;
        let clock = s.controller.state().control.clock;
        let began = clock.now_us();
        s.phase = Phase::Quarantined;
        let mut started = false;
        let outcome = {
            // Keep Station immutably borrowed with the canonical guards while
            // mutating only its disjoint native controller and raw journals.
            let station = &s.station;
            let controller = &mut s.controller;
            let replies = &mut s.replies;
            let transport_facts = &mut s.transport_facts;
            let format = &mut s.format_generation;
            let m = s.modern.as_mut().unwrap();
            // SAFETY: covered by this function's own safety contract.
            unsafe {
                authority.publish_association(
                    admission,
                    station,
                    AssociationUse::Configure,
                    |_, _| {
                        started = true;
                        *format = None;
                        for (index, (command, body)) in m.commands.iter().enumerate() {
                            if index == 1 {
                                controller
                                    .state_mut()
                                    .control
                                    .clear_peer_admission(p.wcid)
                                    .map_err(|e| {
                                        Error::Bootstrap(super::super::Error::Control(e))
                                    })?;
                            }
                            // Source filter transport precedes the final awake update;
                            // preserve its one-way/raw fact rather than inventing ACK.
                            if index + 1 == m.commands.len() {
                                let fact = controller
                                    .state_mut()
                                    .mailbox
                                    .as_mut()
                                    .unwrap()
                                    .initial(&m.filter)
                                    .map_err(Error::Transport)?;
                                transport_facts.push(fact);
                            }
                            Self::command_parts(controller, replies, *command, body)?;
                            m.completed += 1;
                        }
                        Ok::<(), Error>(())
                    },
                )
            }
        };
        match outcome {
            Err(error) => {
                if !started {
                    s.phase = Phase::AwaitingModernAdmission;
                }
                return Err(Error::Regulatory(error));
            }
            Ok(result) => result?,
        }
        // The plain source STA_REC command/ACK, not WMWA or an opaque generic
        // response, establishes this peer's raw-header generation.
        s.format_generation = Some(s.peer_generation);
        Self::abort_channel(s)?;
        let ticket = s.modern.as_ref().unwrap().context.ticket();
        let completed_now = clock
            .now_us()
            .checked_sub(began)
            .and_then(|elapsed| now.checked_add(elapsed))
            .ok_or(Error::WrongProfile)?;
        s.station
            .complete_configuration(ticket, Completion::Accepted, completed_now)
            .map_err(Error::Station)?;
        // NIC/local issuer and source link negotiation bound the receive
        // window; no session exists until an ADDBA exchange and real BA ACK.
        let n = s.modern.as_ref().unwrap().context.negotiated();
        let window = if n.eht.is_some() {
            1024
        } else if n.he.is_some() {
            256
        } else {
            64
        };
        if n.aggregates() {
            s.station
                .configure_rx_block_ack(window, true)
                .map_err(Error::BlockAck)?;
            s.station
                .configure_tx_block_ack(window)
                .map_err(Error::BlockAck)?;
        }
        let m = s.modern.as_mut().unwrap();
        m.applied_edca = Some(super::edca::AppliedEdca {
            parameter_set_count: m
                .context
                .negotiated()
                .wmm
                .as_ref()
                .map_or(0, |wmm| wmm.parameter_set_count),
            access_categories: m.prepared_edca,
        });
        s.phase = Phase::Associated;
        Ok(())
    }

    pub(super) fn bss_request(
        s: &Owned<I, Q, C>,
        p: Profile,
        enable: bool,
    ) -> Result<Vec<u8>, Error> {
        match s.modern.as_ref() {
            Some(m) => m.wire.bss_request(p, enable),
            None => p.bss_request(enable),
        }
        .map_err(Error::Codec)
    }

    pub(super) fn prepare_modern(
        s: &mut Owned<I, Q, C>,
        ticket: Ticket,
        context: Arc<AssociationContext>,
    ) -> Result<(), Error> {
        s.station
            .validate_association_context(&context)
            .map_err(Error::Station)?;
        let mut p = s.profile.ok_or(Error::WrongProfile)?;
        if context.ticket() != ticket
            || context.bssid() != p.peer
            || context.channel() != p.channel
            || s.modern.is_some()
        {
            return Err(Error::WrongProfile);
        }
        // Keep Station's same private context even if subsequent preparation
        // fails. Existing programmed peer/controller remain owned/quarantined.
        s.phase = Phase::Quarantined;
        let actual = local::current(s, p.channel.band).map_err(|_| Error::WrongProfile)?;
        actual
            .validate_capabilities(context.negotiated().local())
            .map_err(|_| Error::WrongProfile)?;
        p.aid = context.response().aid;
        p.basic_rates = context.negotiated().legacy.basic;
        p.supported_rates = context.negotiated().legacy.supported;
        p.beacon_interval = context.beacon().beacon_interval;
        p.dtim_period = context.dtim_period();
        // Source use_short_slot is always true outside2GHz and follows the
        // AP capability on2GHz; no caller timing guess enters Configure.
        p.slot_time = if p.channel.band != wifi::Band::Ghz2
            || context.response().capabilities & (1 << 10) != 0
        {
            9
        } else {
            20
        };
        let definition = context.definition();
        let (mbssid_indicator, mbssid_index) = mbssid(&context.beacon().elements)?;
        let operation = wire::modern::Operation {
            center_channel: center_channel(p.channel.band, definition.center1_mhz)?,
            second_center_channel: definition
                .center2_mhz
                .map(|mhz| center_channel(p.channel.band, mhz))
                .transpose()?
                .unwrap_or(0),
            punctured: definition.punctured,
            he: context
                .operations()
                .he
                .as_ref()
                .map(|h| wire::modern::HeOperation {
                    packet_extension: h.packet_extension(),
                    rts_threshold: h.rts_threshold(),
                    color_enabled: h.color_enabled(),
                    color: h.color(),
                }),
            mbssid_indicator,
            mbssid_index,
        };
        let wire = wire::modern::Configuration::new(
            p,
            context.negotiated().clone(),
            operation,
            *actual.he_source_maps(),
        )
        .map_err(Error::Codec)?;
        let mut commands = Vec::new();
        commands.try_reserve_exact(7).map_err(|_| Error::NoMemory)?;
        commands.push((
            Command::BssInfo,
            wire.bss_request(p, true).map_err(Error::Codec)?,
        ));
        commands.push((
            Command::StationRecord,
            wire.peer_request(p, true).map_err(Error::Codec)?,
        ));
        commands.push((
            Command::StationRecord,
            p.broadcast_request().map_err(Error::Codec)?,
        ));
        commands.push((Command::Edca, wire.edca_request(p).map_err(Error::Codec)?));
        if context.negotiated().eht.is_some() {
            commands.push((
                Command::BssInfo,
                wire.puncture_request(p).map_err(Error::Codec)?,
            ));
        }
        commands.push((Command::BssInfo, p.beacon_filter().map_err(Error::Codec)?));
        commands.push((Command::BssInfo, p.awake().map_err(Error::Codec)?));
        s.profile = Some(p);
        let filter = p.filter_request(true).map_err(Error::Codec)?;
        let prepared_edca = context.negotiated().edca();
        s.modern = Some(Configuration {
            context,
            wire,
            commands,
            filter,
            completed: 0,
            prepared_edca,
            applied_edca: None,
        });
        // Preparation never acknowledges or publishes modern BSS/peer effects.
        // configure_modern consumes the canonical context-bound admission.
        s.phase = Phase::AwaitingModernAdmission;
        Ok(())
    }
}

pub(super) fn center_channel(band: wifi::Band, mhz: u32) -> Result<u8, Error> {
    if band == wifi::Band::Ghz2 && mhz == 2484 {
        return Ok(14);
    }
    let base = match band {
        wifi::Band::Ghz2 => 2407,
        wifi::Band::Ghz5 => 5000,
        wifi::Band::Ghz6 => 5950,
    };
    let offset = mhz
        .checked_sub(base)
        .filter(|n| n % 5 == 0)
        .ok_or(Error::WrongProfile)?;
    u8::try_from(offset / 5)
        .ok()
        .filter(|n| *n != 0)
        .ok_or(Error::WrongProfile)
}
fn mbssid(mut elements: &[u8]) -> Result<(u8, u8), Error> {
    let mut indicator = None;
    let mut index = None;
    while !elements.is_empty() {
        let n = usize::from(*elements.get(1).ok_or(Error::WrongProfile)?);
        let bytes = elements.get(2..2 + n).ok_or(Error::WrongProfile)?;
        let slot = match elements[0] {
            71 => Some(&mut indicator),
            85 => Some(&mut index),
            _ => None,
        };
        if let Some(slot) = slot {
            let value = *bytes.first().ok_or(Error::WrongProfile)?;
            if slot.is_some_and(|old| old != value) {
                return Err(Error::WrongProfile);
            }
            *slot = Some(value);
        }
        elements = &elements[2 + n..];
    }
    Ok((indicator.unwrap_or(0), index.unwrap_or(0)))
}

#[cfg(test)]
pub(super) mod tests;
