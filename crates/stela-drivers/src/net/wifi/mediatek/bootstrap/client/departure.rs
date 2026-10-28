// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! `ieee80211_set_disassoc`'s departure: the deauthentication a station
//! sends its AP before removing the association.
use super::management::Transmit;
use super::*;
use wifi::regulatory::{
    AssociationAdmission, AssociationUse, HardwarePolicy, OsPolicy, Owner, PmfAuthenticationGuard,
};

/// `ieee80211_send_deauth_disassoc`'s frame to the profile's AP.
fn deauthentication(p: Profile, reason: u16) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(26).map_err(|_| Error::NoMemory)?;
    bytes.extend_from_slice(&[0xc0, 0, 0, 0]);
    bytes.extend_from_slice(&p.peer.0);
    bytes.extend_from_slice(&p.interface.address.0);
    bytes.extend_from_slice(&p.peer.0);
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(&reason.to_le_bytes());
    Ok(bytes)
}

impl<I: BarIo, Q: QueueIo, C: 'static> Client<I, Q, C> {
    /// `ieee80211_send_deauth_disassoc` for the current association,
    /// encrypted under PMF as `IEEE80211_STA_MFP_ENABLED` leaves it, and
    /// otherwise sent in the clear. Removal then waits for its TX-free, as
    /// `ieee80211_flush_queues` waits for the frame to go out.
    ///
    /// # Safety
    /// As `progress_block_ack`.
    pub unsafe fn transmit_deauthentication<H: HardwarePolicy, O: OsPolicy>(
        &mut self,
        authority: &mut Owner<H, O>,
        admission: AssociationAdmission,
        reason: u16,
        source: &dyn PageSource,
    ) -> Result<(), Error> {
        let s = self.state_mut();
        if s.phase != Phase::Associated || s.station.phase() != station::Phase::Associated {
            return Err(Error::WrongPhase);
        }
        if s.station.requires_protected_management() {
            let session = s.management.clone().ok_or(Error::NoKey)?;
            // SAFETY: covered by this function's own safety contract.
            return unsafe {
                self.transmit_management_modern(
                    authority,
                    admission,
                    &session,
                    Transmit::Deauthenticate(reason),
                    source,
                )
            }
            .map(|_| ());
        }
        let bytes = deauthentication(s.profile.ok_or(Error::WrongProfile)?, reason)?;
        let prepared = Self::prepare_submission(s, &bytes, None, true, true)?;
        // SAFETY: covered by this function's own safety contract.
        let result = unsafe {
            authority.publish_association(
                admission,
                &s.station,
                AssociationUse::Management,
                |_, _| Self::publish_submission(&mut s.controller, source, &bytes, prepared),
            )
        }
        .map_err(Error::Regulatory)?;
        if s.controller.state().data_tx.as_ref().unwrap().is_poisoned() {
            s.phase = Phase::Quarantined;
        }
        result.map(|_| ())
    }

    /// `ieee80211_mgd_deauth` while authenticating or associating: the
    /// deauthentication goes out in the clear on the join's channel, which
    /// `drv_mgd_prepare_tx` reserves first.
    pub fn transmit_join_deauthentication(
        &mut self,
        reason: u16,
        source: &dyn PageSource,
        policy: &mut impl station::RegulatoryPolicy,
    ) -> Result<(), Error> {
        let s = self.state_mut();
        if s.station.requires_protected_management()
            && s.station.phase() != station::Phase::ExternalAuthenticating
        {
            return Err(Error::ModernAdmissionRequired);
        }
        Self::join_deauthentication(s, reason, source, policy, None)
    }

    /// `transmit_join_deauthentication` for a PMF join, qualified under the
    /// exchange's held providers.
    ///
    /// # Safety
    /// As `poll_pmf_authentication`.
    pub unsafe fn transmit_join_deauthentication_pmf<H: HardwarePolicy, O: OsPolicy>(
        &mut self,
        authority: &mut Owner<H, O>,
        reason: u16,
        source: &dyn PageSource,
        policy: &mut impl station::RegulatoryPolicy,
    ) -> Result<(), Error> {
        if !self.station().requires_protected_management() {
            return Err(Error::WrongProfile);
        }
        // SAFETY: exclusive same native owner; guard borrows both actual leases.
        unsafe {
            authority.with_pmf_authentication(self, |client, guard| {
                Self::join_deauthentication(client.state_mut(), reason, source, policy, Some(guard))
            })
        }
        .map_err(Error::Regulatory)?
    }

    fn join_deauthentication(
        s: &mut Owned<I, Q, C>,
        reason: u16,
        source: &dyn PageSource,
        policy: &mut impl station::RegulatoryPolicy,
        guard: Option<&mut PmfAuthenticationGuard<'_>>,
    ) -> Result<(), Error> {
        if s.phase != Phase::Joining
            || !matches!(
                s.station.phase(),
                station::Phase::Authenticating
                    | station::Phase::Associating
                    | station::Phase::ExternalAuthenticating
            )
        {
            return Err(Error::WrongPhase);
        }
        let p = s.profile.ok_or(Error::WrongProfile)?;
        if !policy.allow_management_tx(p.channel) {
            return Err(Error::Station(station::Error::Regulatory));
        }
        let bytes = deauthentication(p, reason)?;
        if let Some(guard) = guard {
            let (ticket, ..) = s.station.pmf_authentication().map_err(Error::Station)?;
            Self::qualify_pmf_authentication(s, guard, Some((ticket, &bytes)))?;
        }
        Self::reserve_channel(s)?;
        if s.roc_deadline
            .is_none_or(|d| s.controller.state().control.clock.now_us() >= d)
        {
            return Err(Error::GrantTimeout);
        }
        Self::submit(s, &bytes, None, true, true, source).map(|_| ())
    }
}
