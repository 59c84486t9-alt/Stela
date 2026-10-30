// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! Owning-policy external authentication binds OS commands to scan BSS
//! handles and serializes source/OS regulatory guards through real submission.
//! A 6 GHz session goes through its held transport, under this client's own
//! board and OS permission.
use super::*;
use station::{external::Session, multi_link::Affiliation, wire::six_ghz::Selection};

impl<I: BarIo, Q: QueueIo, C: 'static> ManagedClient<I, Q, C> {
    /// The scan BSS `handle` when `profile` may authenticate with it: seen in
    /// the last 30 seconds, on the profile's channel, rates and beacon.
    fn authentication_bss(
        &self,
        handle: BssHandle,
        profile: &Profile,
        now: u64,
    ) -> Result<&Observed, PolicyError> {
        let observed = self
            .observed
            .iter()
            .find(|b| b.handle == handle)
            .ok_or(PolicyError::Bss)?;
        if now
            .checked_sub(observed.seen)
            .is_none_or(|age| age > BSS_EXPIRE_US)
            || observed.bss.channel != profile.channel
            || observed.bss.bssid != profile.peer
            || observed.bss.transmitter != profile.peer
        {
            return Err(PolicyError::Bss);
        }
        let (supported, basic) =
            rates(&observed.bss.elements, profile.channel.band).map_err(PolicyError::Client)?;
        if profile.supported_rates & !supported != 0
            || profile.basic_rates & !basic != 0
            || profile.beacon_interval != observed.bss.beacon_interval
        {
            return Err(PolicyError::Bss);
        }
        let flags = self
            .snapshot
            .get(profile.channel)
            .ok_or(PolicyError::RestrictionMismatch)?
            .flags;
        if flags & (1 << 6) != 0
            && (profile.channel.band != Band::Ghz2 || profile.basic_rates & 15 == 0)
        {
            return Err(PolicyError::RestrictionMismatch);
        }
        Ok(observed)
    }

    pub fn begin_external_authentication(
        &mut self,
        handle: BssHandle,
        profile: Profile,
        multi_link: Option<Affiliation>,
        now: u64,
        budget: u64,
    ) -> Result<Arc<Session>, PolicyError> {
        self.live()?;
        let observed = self.authentication_bss(handle, &profile, now)?;
        let ssid = observed.bss.ssid.as_ref().ok_or(PolicyError::Bss)?.clone();
        let mut check = Check {
            snapshot: &self.snapshot,
            country: &self.country,
            environment: self.environment,
            revoked: false,
            peer: Some(profile.channel),
        };
        let result = self
            .client
            .begin_external_authentication(profile, ssid, multi_link, now, budget, &mut check)
            .map_err(PolicyError::Client);
        if self.client.phase() != Phase::Idle {
            self.peer = Some(profile.channel);
        }
        result
    }

    /// `NL80211_CMD_AUTHENTICATE` with SAE on 6 GHz: the OS's `selection`,
    /// its RSNE and RSNXE, binds the session to this client's own record of
    /// the BSS, and the board and OS decide each step of the transport.
    pub fn begin_six_ghz_external_authentication(
        &mut self,
        handle: BssHandle,
        selection: Selection,
        profile: Profile,
        now: u64,
        budget: u64,
    ) -> Result<Arc<Session>, PolicyError> {
        self.live()?;
        self.authentication_bss(handle, &profile, now)?;
        let beacon = self.native_beacon(handle)?;
        self.protection.set(true, false);
        // SAFETY: permission and client are private disjoint fields of this
        // same exclusive owning attachment, and the OS selected this network.
        let result = unsafe {
            self.client.begin_six_ghz_external_authentication(
                &mut self.authority,
                &beacon,
                selection,
                profile,
                now,
                budget,
            )
        }
        .map_err(PolicyError::Client);
        if self.client.phase() != Phase::Idle {
            self.peer = Some(profile.channel);
        }
        result
    }

    pub fn transmit_external_authentication(
        &mut self,
        session: &Session,
        frame: station::external::Frame<'_>,
        now: u64,
        source: &dyn PageSource,
    ) -> Result<Receipt, PolicyError> {
        self.live()?;
        if session.six_ghz_observation().is_some() {
            // SAFETY: as for begin_six_ghz_external_authentication.
            return unsafe {
                self.client.transmit_six_ghz_external_authentication(
                    &mut self.authority,
                    session,
                    frame,
                    now,
                    source,
                )
            }
            .map_err(PolicyError::Client);
        }
        let mut check = Check {
            snapshot: &self.snapshot,
            country: &self.country,
            environment: self.environment,
            revoked: false,
            peer: self.peer,
        };
        self.client
            .transmit_external_authentication(session, frame, now, source, &mut check)
            .map_err(PolicyError::Client)
    }

    /// `ieee80211_mgd_assoc` after the OS's SAE exchange authenticated the
    /// station: associate with the OS's SAE request and the BSS it chose.
    pub fn associate_external(
        &mut self,
        session: &Session,
        handle: BssHandle,
        join: Join,
        now: u64,
        source: &dyn PageSource,
    ) -> Result<(), PolicyError> {
        self.live()?;
        let observed = self
            .observed
            .iter()
            .find(|b| b.handle == handle)
            .ok_or(PolicyError::Bss)?;
        if now
            .checked_sub(observed.seen)
            .is_none_or(|age| age > BSS_EXPIRE_US)
            || observed.bss.channel != join.channel
            || observed.bss.bssid != join.bssid
        {
            return Err(PolicyError::Bss);
        }
        if session.six_ghz_observation().is_some() {
            // SAFETY: as for begin_six_ghz_external_authentication.
            return unsafe {
                self.client.associate_six_ghz_external(
                    &mut self.authority,
                    session,
                    join,
                    now,
                    source,
                )
            }
            .map_err(PolicyError::Client);
        }
        let beacon = self.native_beacon(handle)?;
        let mut check = Check {
            snapshot: &self.snapshot,
            country: &self.country,
            environment: self.environment,
            revoked: false,
            peer: self.peer,
        };
        self.protection.set(true, false);
        // SAFETY: permission and client are private disjoint fields of this
        // same exclusive owning attachment, and the OS selected this network.
        unsafe {
            self.client.associate_external_pmf(
                &mut self.authority,
                session,
                PmfJoin {
                    join,
                    observed: &beacon,
                },
                now,
                source,
                &mut check,
            )
        }
        .map_err(PolicyError::Client)
    }

    pub fn cancel_external_authentication(&mut self, session: &Session) -> Result<(), PolicyError> {
        if session.six_ghz_observation().is_some() {
            self.client.cancel_six_ghz_external_authentication(session)
        } else {
            self.client.cancel_external_authentication(session)
        }
        .map_err(PolicyError::Client)
    }
}
