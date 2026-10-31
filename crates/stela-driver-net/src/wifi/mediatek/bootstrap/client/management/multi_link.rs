// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
// Per-link BIP ownership follows pinned Linux mt7925_set_link_key and
// mt7925_mcu_add_key; original source notices are in wifi/THIRD_PARTY.md.
//! Per-link management key publication and delayed receive validation.
use super::*;
use wifi::regulatory::{AssociationAdmission, AssociationUse, HardwarePolicy, OsPolicy, Owner};

pub(super) struct ReceivedLink {
    context: Arc<station::AssociationContext>,
    ptk: KeyIdentity,
    gtk: KeyIdentity,
    igtks: [Option<bip::Identity>; 2],
}
impl ReceivedLink {
    pub(super) fn link_id(&self) -> u8 {
        self.context.affiliation().unwrap().link_id
    }
}

impl<I: BarIo, Q: QueueIo, C: 'static> Client<I, Q, C> {
    pub(super) fn received_link(
        s: &Owned<I, Q, C>,
        profile: Profile,
    ) -> Result<ReceivedLink, Error> {
        let link = s
            .links
            .iter()
            .find(|link| link.profile == profile)
            .ok_or(Error::WrongProfile)?;
        Ok(ReceivedLink {
            context: link.context.clone(),
            ptk: link.ptk.slot().installed().ok_or(Error::NoKey)?,
            gtk: link.gtk.slot().installed().ok_or(Error::NoKey)?,
            igtks: link.gtk.installed_igtks(),
        })
    }

    pub(super) fn validate_received_management(
        s: &Owned<I, Q, C>,
        received: &Received,
    ) -> Result<(), Error> {
        Self::validate_management(s, &received.session)?;
        if let Some(original) = &received.link {
            let link = s
                .links
                .iter()
                .find(|link| Arc::ptr_eq(&link.context, &original.context))
                .ok_or(Error::Station(station::Error::Stale))?;
            if !s
                .station
                .link_contexts()
                .iter()
                .any(|context| Arc::ptr_eq(context, &original.context))
                || link.ptk.slot().installed() != Some(original.ptk)
                || link.gtk.slot().installed() != Some(original.gtk)
                || link.gtk.installed_igtks() != original.igtks
            {
                return Err(Error::Station(station::Error::Stale));
            }
        }
        Ok(())
    }

    /// Install or rotate the authenticated IGTK of an affiliated secondary
    /// link. The setup link's key and each link's replay windows remain owned
    /// independently. Exact retries preserve their advanced IPN.
    ///
    /// # Safety
    /// Inherit install_management_key_modern's same-requester permission,
    /// authenticated input and independent GTK hardware/RX/IRQ/work/deferred-user
    /// drain contract for this link. For replacement of a live index, the peer
    /// must have ceased using its old material as rotate_management_key requires.
    /// Serialize all key, policy and reset operations through this owner.
    pub unsafe fn install_link_management_key_modern<H: HardwarePolicy, O: OsPolicy>(
        &mut self,
        authority: &mut Owner<H, O>,
        admission: AssociationAdmission,
        link_id: u8,
        index: u8,
        material: &[u8],
        receive: PacketNumber,
    ) -> Result<(), Error> {
        let s = self.state_mut();
        Self::management_keys(s)?;
        let modern = s.modern.as_ref().ok_or(Error::WrongPhase)?;
        s.station
            .validate_association_context(modern.context())
            .map_err(Error::Station)?;
        Self::management_drained(s)?;
        let link = s
            .links
            .iter_mut()
            .find(|link| link.link_id == link_id)
            .ok_or(Error::WrongProfile)?;
        if !s
            .station
            .link_contexts()
            .iter()
            .any(|context| Arc::ptr_eq(context, &link.context))
        {
            return Err(Error::Station(station::Error::Stale));
        }
        let key = &mut link.gtk;
        let cipher = s.management_cipher;
        // SAFETY: the exclusive link/key owner and both current providers are
        // kept through the command, firmware ACK and descriptor/DMA retirement.
        unsafe {
            authority.publish_association(
                admission,
                &s.station,
                AssociationUse::Management,
                |_, _| {
                    if key.installed_igtk().is_some() {
                        Self::rotate_management_parts(
                            &mut s.controller,
                            &mut s.phase,
                            key,
                            index,
                            material,
                            receive,
                        )
                    } else {
                        Self::install_management_parts(
                            &mut s.controller,
                            &mut s.phase,
                            key,
                            cipher,
                            index,
                            material,
                            receive,
                        )
                        .map(|_| ())
                    }
                },
            )
        }
        .map_err(Error::Regulatory)?
    }
}
