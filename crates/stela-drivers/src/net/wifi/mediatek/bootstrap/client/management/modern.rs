// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! Actual current-association hardware/OS guards around management effects.
//! Attaching this transport sends robust management (including Block Ack
//! actions) to the OS as authenticated observations. It does not automatically
//! run native non-PMF BA MLME under an inferred protection policy. Initial
//! attachment therefore requires all old BA state drained; a future negotiated
//! PMF/OS BA consumer is required to reopen aggregation on this transport.
use super::*;
use wifi::regulatory::{AssociationAdmission, AssociationUse, HardwarePolicy, OsPolicy, Owner};

impl<I: BarIo, Q: QueueIo, C: 'static> Client<I, Q, C> {
    /// Install the initial GTK/IGTK batch for this actual modern association.
    /// The returned transport retains the same private context as the native
    /// peer and canonical Station. This does not negotiate PMF or open a port.
    /// Exact retries preserve the original Session and advanced receive IPN.
    ///
    /// # Safety
    /// The same-controller retained hardware/OS authority and real revocation
    /// contract of configure_modern applies. The actual OS authenticated exchange
    /// supplied this IGTK/IPN for this exact association. Before this initial
    /// combined batch, independently stop/drain every old GTK hardware RX/TX,
    /// DMA/IRQ/work and external deferred key user. Empty native queues and the
    /// canonical BA-record check do not prove that external fence. Serialize
    /// all key/reset/policy operations; uncertain completion retains the entire
    /// owner. No live IGTK rekey or negotiated PMF policy is supplied here.
    pub unsafe fn install_management_key_modern<H: HardwarePolicy, O: OsPolicy>(
        &mut self,
        authority: &mut Owner<H, O>,
        admission: AssociationAdmission,
        epoch: u64,
        index: u8,
        material: &[u8],
        receive: PacketNumber,
    ) -> Result<Arc<Session>, Error>
    where
        C: Send + Sync,
    {
        let s = self.state_mut();
        let (ptk, gtk) = Self::management_keys(s)?;
        if s.station.association_epoch() != Some(epoch) {
            return Err(Error::Station(station::Error::Stale));
        }
        let context = s.modern.as_ref().ok_or(Error::WrongPhase)?.context();
        s.station
            .validate_association_context(context)
            .map_err(Error::Station)?;
        let profile = s.profile.ok_or(Error::WrongProfile)?;
        if context.bssid() != profile.peer || context.channel() != profile.channel {
            return Err(Error::WrongProfile);
        }
        Self::management_drained(s)?;
        let key = s.gtk.as_mut().ok_or(Error::NoKey)?;
        // SAFETY: inherited exact retained requester/policy and independent old
        // hardware/RX/IRQ/deferred-user fence. Guards span the actual command,
        // response and DMA retirement, not just a copied permission precheck.
        let igtk = unsafe {
            authority.publish_association(
                admission,
                &s.station,
                AssociationUse::Management,
                |_, _| {
                    Self::install_management_parts(
                        &mut s.controller,
                        &mut s.phase,
                        key,
                        index,
                        material,
                        receive,
                    )
                },
            )
        }
        .map_err(Error::Regulatory)??;
        Self::management_session(s, epoch, ptk, gtk, igtk)
    }

    /// Revalidate the original authenticated envelope and current OS/hardware
    /// policy at its actual consuming callback. Retaining/reading Received is a
    /// historical observation, never permission to apply a delayed transition.
    /// The OS owns negotiated PMF, SA Query matching/retry/timers and all MLME
    /// decisions; this transport supplies none of those policy effects.
    ///
    /// # Safety
    /// configure_modern's same-requester retained-authority/revocation contract
    /// applies. The callback applies only the real OS policy for this original
    /// association; further deferred effects must retain and revalidate their
    /// original context rather than inherit a copied epoch or this return value.
    pub unsafe fn with_management_modern<H: HardwarePolicy, O: OsPolicy, T>(
        &mut self,
        authority: &mut Owner<H, O>,
        admission: AssociationAdmission,
        received: Received,
        consume: impl FnOnce(&Mpdu, &[u8], PacketNumber) -> T,
    ) -> Result<T, Error> {
        let s = self.state();
        Self::validate_management(s, &received.session)?;
        if s.modern.is_none() {
            return Err(Error::WrongPhase);
        }
        // SAFETY: inherited exact same-requester and consuming-effect contract.
        unsafe {
            authority.publish_association(
                admission,
                &s.station,
                AssociationUse::Management,
                |_, _| consume(&received.frame, &received.body, received.pn),
            )
        }
        .map_err(Error::Regulatory)
    }

    /// Publish a typed OS-selected protected departure or SA Query under the
    /// current association's actual Management guards. PTK firmware PN/IV/MIC
    /// ownership and exact Session/key identity span real DMA/TX-free/unmap.
    /// No host nonce, successful air ACK or automatic MLME effect is invented.
    ///
    /// # Safety
    /// configure_modern's same-controller retained hardware/OS authority and
    /// enforced revocation/drain contract applies through all deferred TX users.
    /// The actual OS separately authorizes negotiated protection and the typed
    /// message for this association; a Session proves transport/key ownership.
    pub unsafe fn transmit_management_modern<H: HardwarePolicy, O: OsPolicy>(
        &mut self,
        authority: &mut Owner<H, O>,
        admission: AssociationAdmission,
        session: &Session,
        message: Transmit,
        source: &dyn PageSource,
    ) -> Result<Receipt, Error> {
        let s = self.state_mut();
        Self::validate_management(s, session)?;
        if s.modern.is_none() {
            return Err(Error::WrongPhase);
        }
        let bytes = message.encode(session.profile);
        let (config, mut owner, grant) =
            Self::prepare_submission(s, &bytes, Some(session.ptk), true, true)?;
        owner.management = s.management.clone();
        // SAFETY: inherited exact retained requester and real deferred-user
        // revocation contract. Both actual page allocation and producer write
        // occur inside the same acquired hardware/OS guards.
        let result = unsafe {
            authority.publish_association(
                admission,
                &s.station,
                AssociationUse::Management,
                |_, _| {
                    Self::publish_submission(
                        &mut s.controller,
                        source,
                        &bytes,
                        (config, owner, grant),
                    )
                },
            )
        }
        .map_err(Error::Regulatory)?;
        if s.controller.state().data_tx.as_ref().unwrap().is_poisoned() {
            s.phase = Phase::Quarantined;
        }
        result
    }
}
