// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! Live native IGTK updates with two kept receive windows and exact session
//! revocation. The single source firmware batch proves no physical air overlap.
use super::*;
use wifi::regulatory::{AssociationAdmission, AssociationUse, HardwarePolicy, OsPolicy, Owner};

impl<I: BarIo, Q: QueueIo, C: 'static> Client<I, Q, C> {
    pub(super) unsafe fn rotate_management_parts(
        controller: &mut Controller<I, Q, C>,
        phase: &mut Phase,
        key: &mut HardwareKey<Arc<C>>,
        index: u8,
        material: &[u8],
        receive: PacketNumber,
    ) -> Result<(), Error> {
        // SAFETY: caller checked native users and inherits authenticated exchange,
        // peer-index replacement policy and the independent hardware drain.
        let outcome = unsafe {
            key.rotate_igtk(
                controller.state_mut().mailbox.as_mut().unwrap(),
                index,
                material,
                receive,
            )
        };
        if key.is_quarantined() {
            *phase = Phase::Quarantined;
        }
        outcome.map(|_| ()).map_err(Error::Key)
    }

    fn rotated_management_session(s: &mut Owned<I, Q, C>) -> Result<Arc<Session>, Error>
    where
        C: Send + Sync,
    {
        let (ptk, gtk) = Self::management_keys(s)?;
        let key = s.gtk.as_ref().ok_or(Error::NoKey)?;
        let igtk = key.installed_igtk().ok_or(Error::NoKey)?;
        let windows = key.installed_igtks();
        if let Some(session) = &s.management
            && session.igtks == windows
            && session.igtk == igtk
        {
            // Installed retry: preserve the original Arc and all advanced
            // replay floors. No new permission is derived from a copied key ID.
            Self::validate_management(s, session)?;
            return Ok(session.clone());
        }
        let epoch = s.station.association_epoch().ok_or(Error::WrongPhase)?;
        // Every prior Received/deferred/TX Session becomes inert immediately.
        // Its historical requester resource/identities remain held by its Arc.
        s.management = None;
        Self::management_session(s, epoch, ptk, gtk, igtk)
    }

    /// Replace one current peer's management receive slot. The other
    /// 4/5 software MIC/IPN window remains intact; every old transport envelope
    /// is revoked on mutation. Does not change data key identities/replay floors,
    /// open a port, negotiate PMF or implement SA Query/MLME/6GHz admission.
    ///
    /// # Safety
    /// The real authenticated OS exchange supplies this exact session's
    /// new IGTK/IPN. Same-index replacement requires the peer to have ceased
    /// using that index's old material; alternating slots keep the other key.
    /// Independently stop/drain old GTK hardware RX/TX, DMA/IRQ/work and all
    /// external deferred users before the repeated combined firmware batch.
    /// Empty native queues do not prove that fence. Serialize all key/reset and
    /// policy operations. Firmware exposes one GTK||IGTK batch with no management
    /// index: physical dual-key delivery/overlap is unchecked, and hardware
    /// ICV/monitor failures remain rejected. An ACK does not establish peer key
    /// retirement or negotiated protection. Modern peers use the guarded API.
    pub unsafe fn rotate_management_key(
        &mut self,
        session: &Session,
        index: u8,
        material: &[u8],
        receive: PacketNumber,
    ) -> Result<Arc<Session>, Error>
    where
        C: Send + Sync,
    {
        let s = self.state_mut();
        Self::validate_management(s, session)?;
        if s.modern.is_some() {
            return Err(Error::ModernAdmissionRequired);
        }
        Self::management_drained(s)?;
        // SAFETY: inherited authenticated input, peer policy and drain.
        unsafe {
            Self::rotate_management_parts(
                &mut s.controller,
                &mut s.phase,
                s.gtk.as_mut().ok_or(Error::NoKey)?,
                index,
                material,
                receive,
            )
        }?;
        Self::rotated_management_session(s)
    }

    /// Apply the same update while current hardware/OS Management guards
    /// span the firmware command, matching response and DMA retirement.
    ///
    /// # Safety
    /// Inherit rotate_management_key's authenticated-input, exact peer-index
    /// retirement and independent old hardware/RX/IRQ/deferred-user drain duties,
    /// and configure_modern's same-requester kept permission/revocation
    /// contract. This backend does not create the OS management policy.
    pub unsafe fn rotate_management_key_modern<H: HardwarePolicy, O: OsPolicy>(
        &mut self,
        authority: &mut Owner<H, O>,
        admission: AssociationAdmission,
        session: &Session,
        index: u8,
        material: &[u8],
        receive: PacketNumber,
    ) -> Result<Arc<Session>, Error>
    where
        C: Send + Sync,
    {
        let s = self.state_mut();
        Self::validate_management(s, session)?;
        if s.modern.is_none() {
            return Err(Error::WrongPhase);
        }
        Self::management_drained(s)?;
        let key = s.gtk.as_mut().ok_or(Error::NoKey)?;
        // SAFETY: inherited peer/key, independent drain and kept
        // hardware/OS permission. Guards enclose real publication, not a precheck.
        unsafe {
            authority.publish_association(
                admission,
                &s.station,
                AssociationUse::Management,
                |_, _| {
                    Self::rotate_management_parts(
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
        Self::rotated_management_session(s)
    }
}
