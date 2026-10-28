// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! Explicit finite6GHz native SAE transport. A successful-looking RX or an
//! MCU ACK cannot associate, install keys, authorize a port or enable data.
use super::*;
use station::{external::Session, wire::six_ghz::Selection};
pub(super) use wifi::regulatory::SixGhzAuthenticationUse as Use;
use wifi::regulatory::{
    HardwarePolicy, OsPolicy, Owner, SixGhzAuthenticationBinding, SixGhzAuthenticationGuard,
    SixGhzTransportProfile,
};

pub(super) struct Bound {
    codec: wire::six_ghz::Preauthentication,
    profile: SixGhzTransportProfile,
    binding: SixGhzAuthenticationBinding,
    session: Arc<Session>,
    frontend_start: u64,
    native_start: u64,
    native_deadline: u64,
}
impl Bound {
    /// The 6 GHz codec, which also builds this peer's removal requests.
    pub(super) fn codec(&self) -> &wire::six_ghz::Preauthentication {
        &self.codec
    }
}
/// CPU wire builder only, used exclusively under the actual held transport
/// providers. It supplies no hardware or OS permission on its own.
struct WirePolicy;
impl station::RegulatoryPolicy for WirePolicy {
    fn allow_management_tx(&mut self, channel: wifi::Channel) -> bool {
        channel.band == wifi::Band::Ghz6
    }
    fn allow_data_tx(&mut self, _: wifi::Channel) -> bool {
        false
    }
}
impl<I: BarIo, Q: QueueIo, C: 'static> Client<I, Q, C> {
    /// Native6GHz remains a separate transport API until a genuine OS SAE
    /// service can consume the exact authenticated exchange into association.
    ///
    /// # Safety
    /// Same actual retained requester, board, firmware, policy and DMA owners
    /// as join_modern_pmf. The providers qualify exact real selected transport,
    /// programmed CLC/domain/per-rate/SAR/antenna/indoor policy and the entire
    /// source HE20/OFDM/automatic retry+ACK envelope. Revocation actually stops
    /// or enforces restrictions on already armed radio work and retains every
    /// original owner through cancellation, uncertainty and independent drain.
    /// The OS lease selects this precise request; it does not authenticate SAE.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn begin_six_ghz_external_authentication<H: HardwarePolicy, O: OsPolicy>(
        &mut self,
        authority: &mut Owner<H, O>,
        observed: &Arc<PmfBssObservation>,
        selection: Selection,
        profile: Profile,
        now: u64,
        budget: u64,
    ) -> Result<Arc<Session>, Error> {
        let s = self.state_mut();
        if s.phase != Phase::Idle || s.authentication_end.is_some() || s.six_ghz.is_some() {
            return Err(Error::Busy);
        }
        if !s
            .pmf_observations
            .iter()
            .any(|old| Arc::ptr_eq(old, observed))
            || Some(profile.interface) != s.interface.registered_context()
            || s.reserved_wcid.is_some_and(|wcid| wcid != profile.wcid)
        {
            return Err(Error::WrongProfile);
        }
        let clock = s.controller.state().control.clock;
        let native_start = clock.now_us();
        let native_deadline = native_start.checked_add(budget).ok_or(Error::NeedsDrain)?;
        let actual = s
            .controller
            .state()
            .policy
            .as_ref()
            .ok_or(Error::WrongProfile)?;
        if actual.capabilities().observed().six_ghz() != Some(true)
            || !actual.initial_channel_present(profile.channel.band, profile.channel.number as u8)
            || actual.programmed_mt7925().is_none()
        {
            return Err(Error::WrongProfile);
        }
        let local = local::current(s, wifi::Band::Ghz6).map_err(Error::Local)?;
        if profile.antenna_mask != local.antenna_mask() {
            return Err(Error::WrongProfile);
        }
        let codec =
            wire::six_ghz::Preauthentication::new(profile, local.capabilities(), observed.bss())
                .map_err(Error::Codec)?;
        // All bodies and bounds are prepared before state or native effects.
        let bss = codec.bss_request().map_err(Error::Codec)?;
        let peer = codec.peer_request(true).map_err(Error::Codec)?;
        let broadcast = codec.broadcast_request().map_err(Error::Codec)?;
        let generation = s.peer_generation.checked_add(1).ok_or(Error::NeedsDrain)?;
        let session = s
            .station
            .prepare_six_ghz_authentication(
                observed.clone(),
                selection,
                local.capabilities().clone(),
                now,
                budget,
            )
            .map_err(Error::Station)?;
        let parameters = SixGhzTransportProfile {
            interface: [
                profile.interface.bss_index,
                profile.interface.omac_index,
                profile.interface.band_index,
                profile.interface.wmm_index,
                profile.interface.link_index,
            ],
            wcid: profile.wcid,
            broadcast_wcid: profile.interface.broadcast_wcid,
            antenna_mask: profile.antenna_mask,
            basic_rates: profile.basic_rates,
            supported_rates: profile.supported_rates,
            fixed_rate_table_index: 18 + profile.basic_rates.trailing_zeros() as u8,
            beacon_interval: profile.beacon_interval,
            dtim_period: profile.dtim_period,
            slot_time: profile.slot_time,
            raw_ap_power_type: codec.power_type(),
        };
        // SAFETY: both original real providers stay held through each effect.
        unsafe {
            authority.with_six_ghz_authentication(self, |client, guard| {
                let s = client.state_mut();
                let binding = guard
                    .qualify(&session, &parameters, None, Use::PreparePeer)
                    .map_err(Error::Regulatory)?;
                let after =
                    Self::six_prepared_time(clock, now, native_start, native_deadline, &session)?;
                s.station
                    .commit_six_ghz_authentication(session.clone(), after)
                    .map_err(Error::Station)?;
                s.six_ghz = Some(Bound {
                    codec,
                    profile: parameters,
                    binding,
                    session: session.clone(),
                    frontend_start: now,
                    native_start,
                    native_deadline,
                });
                s.authentication_deadline = Some(native_deadline);
                s.profile = Some(profile);
                s.ciphers = None;
                s.management_cipher = None;
                s.reserved_wcid = Some(profile.wcid);
                s.peer_generation = generation;
                s.format_generation = None;
                s.phase = Phase::Quarantined;
                Self::qualify_six(s, guard, Use::PreparePeer, now)?;
                s.controller
                    .state_mut()
                    .control
                    .clear_peer_admission(profile.wcid)
                    .map_err(|e| Error::Bootstrap(super::super::Error::Control(e)))?;
                for (command, bytes) in [
                    (Command::BssInfo, &bss),
                    (Command::StationRecord, &peer),
                    (Command::StationRecord, &broadcast),
                ] {
                    Self::qualify_six(s, guard, Use::PreparePeer, now)?;
                    Self::command(s, command, bytes)?;
                }
                s.format_generation = Some(generation);
                s.phase = Phase::Joining;
                Ok(session.clone())
            })
        }
        .map_err(Error::Regulatory)?
    }
    fn six_prepared_time(
        clock: crate::Clock,
        now: u64,
        start: u64,
        end: u64,
        session: &Session,
    ) -> Result<u64, Error> {
        let native = clock.now_us();
        let frontend = native
            .checked_sub(start)
            .and_then(|delta| now.checked_add(delta))
            .ok_or(Error::Station(station::Error::ClockRegressed))?;
        if native >= end || frontend >= session.deadline() {
            return Err(Error::Station(station::Error::Timeout));
        }
        Ok(frontend)
    }
    fn six_time(s: &Owned<I, Q, C>, now: u64) -> Result<u64, Error> {
        let six = s.six_ghz.as_ref().ok_or(Error::WrongPhase)?;
        if now < six.frontend_start {
            return Err(Error::Station(station::Error::ClockRegressed));
        }
        let clock = s.controller.state().control.clock;
        let actual = Self::six_prepared_time(
            clock,
            six.frontend_start,
            six.native_start,
            six.native_deadline,
            &six.session,
        )?
        .max(now);
        if actual >= six.session.deadline() {
            return Err(Error::Station(station::Error::Timeout));
        }
        Ok(actual)
    }
    fn current_six(s: &Owned<I, Q, C>, session: &Session) -> Result<(), Error> {
        s.station
            .validate_external_authentication(session)
            .map_err(Error::Station)?;
        let six = s.six_ghz.as_ref().ok_or(Error::WrongPhase)?;
        let observed = session.six_ghz_observation().ok_or(Error::WrongProfile)?;
        if !core::ptr::eq(six.session.as_ref(), session)
            || !s
                .pmf_observations
                .iter()
                .any(|old| Arc::ptr_eq(old, observed))
        {
            return Err(Error::Station(station::Error::Stale));
        }
        Ok(())
    }
    pub(super) fn qualify_six(
        s: &mut Owned<I, Q, C>,
        guard: &mut SixGhzAuthenticationGuard<'_>,
        purpose: Use<'_>,
        now: u64,
    ) -> Result<u64, Error> {
        let six = s.six_ghz.as_ref().ok_or(Error::WrongPhase)?;
        Self::current_six(s, &six.session)?;
        let binding = guard
            .qualify(&six.session, &six.profile, Some(&six.binding), purpose)
            .map_err(Error::Regulatory)?;
        // Lease acquisition and provider qualification can consume time. This
        // check occurs after both, immediately before each native publication.
        let after = Self::six_time(s, now)?;
        s.six_ghz.as_mut().unwrap().binding = binding;
        Ok(after)
    }
    /// # Safety
    /// The real requester/provider/retention/revocation contract of the begin
    /// entrypoint remains in force through queued/deferred TX users.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn transmit_six_ghz_external_authentication<H: HardwarePolicy, O: OsPolicy>(
        &mut self,
        authority: &mut Owner<H, O>,
        session: &Session,
        transaction: u16,
        status: u16,
        data: &[u8],
        now: u64,
        source: &dyn PageSource,
    ) -> Result<Receipt, Error> {
        Self::current_six(self.state(), session)?;
        if self.phase() != Phase::Joining {
            return Err(Error::WrongPhase);
        }
        let s = self.state_mut();
        let after = Self::six_time(s, now)?;
        let queue = s.controller.state().data_tx.as_ref().unwrap();
        if queue.outstanding_tokens() != 0 || queue.pending_descriptors() != 0 {
            return Err(Error::Busy);
        }
        let bytes = s
            .station
            .external_authentication_transmit(
                session,
                transaction,
                status,
                data,
                after,
                &mut WirePolicy,
            )
            .map_err(Error::Station)?;
        // SAFETY: actual freshly held providers cover ROC and final DMA publish.
        let result = unsafe {
            authority.with_six_ghz_authentication(self, |client, guard| {
                let s = client.state_mut();
                Self::qualify_six(s, guard, Use::Transmit(&bytes), now)?;
                Self::reserve_six_channel(s, guard, now)?;
                Self::qualify_six(s, guard, Use::Transmit(&bytes), now)?;
                let prepared = Self::prepare_submission(s, &bytes, None, true, true)?;
                // Includes potentially slow source allocation/map/coherence work;
                // publish_submission's actual submit_if repeats native expiry.
                Self::qualify_six(s, guard, Use::Transmit(&bytes), now)?;
                let receipt =
                    Self::publish_submission(&mut s.controller, source, &bytes, prepared)?;
                s.mlme_receipt = Some(receipt);
                Ok(receipt)
            })
        }
        .map_err(Error::Regulatory)
        .and_then(|r| r);
        if result.is_err() {
            self.revoke_six();
        }
        result
    }
    /// # Safety
    /// The same real owner/revocation contract as begin applies. Only actual
    /// completed native RX under both held current providers is delivered.
    pub unsafe fn poll_six_ghz_external_authentication<H: HardwarePolicy, O: OsPolicy>(
        &mut self,
        authority: &mut Owner<H, O>,
        session: &Session,
        now: u64,
        source: &dyn PageSource,
        policy: &mut (impl station::RegulatoryPolicy + scan::Policy),
    ) -> Result<Vec<Event>, Error> {
        Self::current_six(self.state(), session)?;
        if self.phase() != Phase::Joining {
            return Err(Error::WrongPhase);
        }
        // SAFETY: exact exclusive native owner through real current guards.
        let result = unsafe {
            authority.with_six_ghz_authentication(self, |client, guard| {
                let after = Self::qualify_six(client.state_mut(), guard, Use::Service, now)?;
                let events = client.poll_inner(after, source, policy, None, Some(guard))?;
                if client.phase() == Phase::Joining {
                    Self::retransmit_six(client.state_mut(), guard, now, source)?;
                }
                Ok(events)
            })
        }
        .map_err(Error::Regulatory)
        .and_then(|r| r);
        if result.is_err() {
            self.revoke_six();
        }
        result
    }
    /// `ieee80211_auth` sending the OS's last SAE frame again once its wait
    /// passed, on a freshly reserved channel, requalified as the first was.
    fn retransmit_six(
        s: &mut Owned<I, Q, C>,
        guard: &mut SixGhzAuthenticationGuard<'_>,
        now: u64,
        source: &dyn PageSource,
    ) -> Result<(), Error> {
        let queue = s.controller.state().data_tx.as_ref().unwrap();
        if queue.outstanding_tokens() != 0 || queue.pending_descriptors() != 0 {
            return Ok(());
        }
        let after = Self::six_time(s, now)?;
        let Some(bytes) = s
            .station
            .external_retransmission(after, &mut WirePolicy)
            .map_err(Error::Station)?
        else {
            return Ok(());
        };
        Self::qualify_six(s, guard, Use::Transmit(&bytes), now)?;
        Self::reserve_six_channel(s, guard, now)?;
        Self::qualify_six(s, guard, Use::Transmit(&bytes), now)?;
        let prepared = Self::prepare_submission(s, &bytes, None, true, true)?;
        Self::qualify_six(s, guard, Use::Transmit(&bytes), now)?;
        let receipt = Self::publish_submission(&mut s.controller, source, &bytes, prepared)?;
        s.mlme_receipt = Some(receipt);
        Ok(())
    }
    /// Stop original work even if new providers are missing or revoked. No
    /// cleanup command emits authentication/deauthentication management frames.
    pub fn cancel_six_ghz_external_authentication(
        &mut self,
        session: &Session,
    ) -> Result<(), Error> {
        Self::current_six(self.state(), session)?;
        let s = self.state_mut();
        let action = s.station.disconnect().map_err(Error::Station)?;
        if let Action::Remove { ticket, failure } = action {
            Self::authentication_ended(s, failure);
            Self::remove(s, ticket)
        } else {
            Err(Error::WrongPhase)
        }
    }
    fn revoke_six(&mut self) {
        if let Some(session) = self.state().station.external_authentication().cloned()
            && self
                .state()
                .station
                .validate_external_authentication(&session)
                .is_ok()
        {
            // Preserve the primary refusal. Failed cleanup retains the whole
            // original owner in Removing/Quarantined until independent reset.
            let _ = self.cancel_six_ghz_external_authentication(&session);
        }
    }
}

mod radio;
#[cfg(test)]
mod tests;
