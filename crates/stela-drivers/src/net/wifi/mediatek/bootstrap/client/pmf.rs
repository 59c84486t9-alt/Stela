// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! Explicit original native scan observation and held pre-association policy.
use super::*;
pub(super) const MAX_OBSERVATIONS: usize = 256;

use wifi::regulatory::{HardwarePolicy, OsPolicy, Owner, PmfAuthenticationGuard};

impl<I: BarIo, Q: QueueIo, C: 'static> Client<I, Q, C> {
    /// At most256 current native observations; beginning another scan revokes
    /// membership of all old handles, even if their historical bytes remain.
    pub fn pmf_bss_observations(&self) -> impl Iterator<Item = &Arc<PmfBssObservation>> {
        self.state().pmf_observations.iter()
    }
    /// Explicit PMF association using an actual observation and real OS-selected
    /// pre-association policy, before any peer/ROC/auth/assoc native publication.
    /// Canonical preparation is CPU-only; initial refusal withdraws only that
    /// exact never-submitted request. Partial native work stays quarantined.
    ///
    /// # Safety
    /// Both providers belong to this exact real retained controller/requester.
    /// Their held leases qualify the full pre-association native envelope and
    /// genuinely serialize revocation through peer/ROC/DMA/TX/deferred users.
    /// C must retain those actual policy/board/radio resources through partial
    /// programming, uncertain commands and every pending/deferred native user.
    /// The actual OS selects these exact RSNE/BSS bytes; no parser/scan result
    /// authenticates the peer or substitutes for that OS selection service.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn join_modern_pmf<H: HardwarePolicy, O: OsPolicy>(
        &mut self,
        authority: &mut Owner<H, O>,
        join: Join,
        observed: &Arc<PmfBssObservation>,
        profile: Profile,
        now: u64,
        source: &dyn PageSource,
        policy: &mut impl station::RegulatoryPolicy,
    ) -> Result<(), Error> {
        if join.request.pmf().is_none()
            || !self
                .state()
                .pmf_observations
                .iter()
                .any(|old| Arc::ptr_eq(old, observed))
        {
            return Err(Error::WrongProfile);
        }
        self.validate_modern_join(&join, profile)?;
        let pmf = join.request.pmf().ok_or(Error::WrongProfile)?;
        if observed.bss().kind != scan::result::Kind::Beacon
            || observed.bss().capabilities & 0x10 == 0
        {
            return Err(Error::WrongProfile);
        }
        pmf.validate_peer(&observed.bss().elements, &[])
            .map_err(|e| Error::Station(station::Error::Wire(e)))?;
        let observed = observed.clone();
        // SAFETY: exact same exclusive owner and actual retained provider leases.
        unsafe {
            authority.with_pmf_authentication(self, |client, guard| {
                let beacon = observed.bss.clone();
                client.state_mut().pmf_selected = Some(observed);
                client.join_inner_guarded(
                    join,
                    Some(beacon),
                    profile,
                    now,
                    source,
                    policy,
                    Some(guard),
                )
            })
        }
        .map_err(Error::Regulatory)?
    }
    /// Service the same actual pending auth/assoc Ticket under freshly acquired
    /// original policy/native/revision guards. Each retry and association TX
    /// requalifies its newly generated actual Ticket and exact canonical bytes.
    /// A revoked binding never silently inherits a later policy revision.
    ///
    /// # Safety
    /// The exact same requester/selection, retention and real revocation/drain
    /// contract as join_modern_pmf remains in force through every native user.
    pub unsafe fn poll_pmf_authentication<H: HardwarePolicy, O: OsPolicy>(
        &mut self,
        authority: &mut Owner<H, O>,
        now: u64,
        source: &dyn PageSource,
        policy: &mut (impl station::RegulatoryPolicy + scan::Policy),
    ) -> Result<Vec<Event>, Error> {
        if self.phase() != Phase::Joining || !self.station().requires_protected_management() {
            return Err(Error::WrongPhase);
        }
        // SAFETY: exclusive same native owner; guard borrows both actual leases.
        unsafe {
            authority.with_pmf_authentication(self, |client, guard| {
                Self::qualify_pmf_authentication(client.state_mut(), guard, None)?;
                let events = client.poll_inner(now, source, policy, Some(guard))?;
                let s = client.state_mut();
                if s.phase == Phase::Joining
                    && let Some(action) = s.station.poll(now, policy).map_err(Error::Station)?
                {
                    Self::action_guarded(s, action, now, source, policy, Some(guard))?;
                }
                Ok(events)
            })
        }
        .map_err(Error::Regulatory)?
    }
    pub(super) fn qualify_pmf_authentication(
        s: &mut Owned<I, Q, C>,
        guard: &mut PmfAuthenticationGuard<'_>,
        transmit: Option<(Ticket, &[u8])>,
    ) -> Result<(), Error> {
        let observed = s.pmf_selected.as_ref().ok_or(Error::WrongProfile)?;
        let binding = guard
            .qualify(
                &s.station,
                observed,
                s.pmf_authentication.as_ref(),
                transmit,
            )
            .map_err(Error::Regulatory)?;
        s.pmf_authentication = Some(binding);
        Ok(())
    }
}
