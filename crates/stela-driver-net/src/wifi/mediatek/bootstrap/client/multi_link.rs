// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
// Link lifecycle follows pinned Linux mt7925/main.c (mt7925_change_vif_links,
// mt7925_mac_link_bss_add); source notices in wifi/THIRD_PARTY.md.
//! A station MLD association on the MT7925, as mt7925 runs one: the
//! interface rebound to the setup link's own address for authentication,
//! and back to the interface's once the association's peers retire.
use super::*;
use crate::wifi::{mediatek::mcu::client::MldLink, station::AssociationContext};
use alloc::borrow::Cow;
use station::multi_link::Affiliation;

impl<I: BarIo, Q: QueueIo, C: 'static> Client<I, Q, C> {
    /// The registration of the setup link of `affiliation`: the interface's
    /// own slots under the link's address.
    pub(super) fn setup_link_context(
        s: &Owned<I, Q, C>,
        affiliation: &Affiliation,
    ) -> Result<Context, Error> {
        let single = s.interface.registered_context().ok_or(Error::WrongPhase)?;
        if s.single_link.is_some() || affiliation.mld.local != single.address {
            return Err(Error::WrongProfile);
        }
        Ok(Context {
            address: affiliation.local,
            ..single
        })
    }

    /// `mt7925_change_vif_links` as the interface becomes an AP MLD
    /// association's setup link: its registration moves to `link`, the
    /// link's address.
    pub(super) fn bind_setup_link(s: &mut Owned<I, Q, C>, link: Context) -> Result<(), Error> {
        let single = s.interface.registered_context().ok_or(Error::WrongPhase)?;
        s.phase = Phase::Quarantined;
        s.interface
            .rebind(s.controller.state_mut().mailbox.as_mut().unwrap(), link)
            .map_err(|e| Error::Bootstrap(super::super::Error::Interface(e)))?;
        s.single_link = Some(single);
        Ok(())
    }

    /// The MLD record of the setup link of `affiliation`, whose AP
    /// `profile` names.
    pub(super) fn mld_link(affiliation: &Affiliation, profile: Profile) -> MldLink {
        MldLink {
            link_id: affiliation.link_id,
            local: affiliation.mld.local,
            ap: affiliation.mld.ap,
            primary_bss: profile.interface.bss_index,
            primary_wcid: profile.wcid,
            eml: None,
        }
    }

    /// `mt792x_tx` for a management frame of `association` to its AP: sent
    /// with the device's address translation off, it takes the setup link's
    /// addresses, the AP's there as its BSSID.
    pub(super) fn on_setup_link<'a>(
        bytes: &'a [u8],
        association: &AssociationContext,
    ) -> Cow<'a, [u8]> {
        let Some(affiliation) = association.affiliation() else {
            return Cow::Borrowed(bytes);
        };
        if bytes.len() < 22 || bytes[4] & 1 != 0 {
            return Cow::Borrowed(bytes);
        }
        let mut frame = bytes.to_vec();
        let ap = association.bssid();
        frame[4..10].copy_from_slice(&ap.0);
        frame[10..16].copy_from_slice(&affiliation.local.0);
        frame[16..22].copy_from_slice(&ap.0);
        Cow::Owned(frame)
    }

    /// `mt7925_change_vif_links` restoring the single-link station once the
    /// association's peers retired.
    pub(super) fn unbind_links(s: &mut Owned<I, Q, C>) -> Result<(), Error> {
        let Some(single) = s.single_link.take() else {
            return Ok(());
        };
        s.phase = Phase::Quarantined;
        s.interface
            .rebind(s.controller.state_mut().mailbox.as_mut().unwrap(), single)
            .map_err(|e| Error::Bootstrap(super::super::Error::Interface(e)))?;
        s.phase = Phase::Idle;
        Ok(())
    }
}
