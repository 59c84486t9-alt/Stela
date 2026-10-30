// SPDX-License-Identifier: GPL-2.0-only
// Multi-link setup adapted from Linux net/mac80211/mlme.c
// (ieee80211_mgd_assoc, ieee80211_assoc_success); source notices in
// wifi/THIRD_PARTY.md.
//! A non-AP MLD's multi-link setup with one AP MLD, as mac80211 keeps it in
//! its association data: the two MLDs, the link the setup runs on and the
//! station's address there, and each other link it requests with the AP's
//! affiliated BSS and the link's own association request.
use super::{
    Error, NativeBssObservation,
    phy::Mode,
    wire::{self, AssociationRequest, multi_link::MAX_LINKS},
};
use crate::Mac;
use alloc::{sync::Arc, vec::Vec};

/// A non-AP MLD and the AP MLD it sets links up with.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Mld {
    /// The station MLD's address: the interface's own.
    pub local: Mac,
    /// The AP MLD's address.
    pub ap: Mac,
}

/// One link of a station MLD with an AP MLD: its ID at the AP MLD and the
/// station's address on it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Affiliation {
    pub mld: Mld,
    pub link_id: u8,
    /// The station's address on the link, which `ieee80211_mgd_assoc` draws
    /// with `eth_random_addr`.
    pub local: Mac,
}

/// Another link a setup requests.
#[derive(Clone, Debug)]
pub struct Link {
    pub link_id: u8,
    /// The station's address on the link.
    pub local: Mac,
    /// The AP's affiliated BSS on the link, as the native scan observed it.
    pub observation: Arc<NativeBssObservation>,
    /// The association request the link would carry on its own: its mode,
    /// capability field and elements.
    pub request: AssociationRequest,
}

/// The links an MLD association requests.
#[derive(Clone, Debug)]
pub struct Setup {
    /// The link the setup runs on.
    pub association: Affiliation,
    /// The MLD capabilities and operations the station advertises.
    pub mld_capabilities: u16,
    /// The station's EML capabilities.
    pub eml_capabilities: u16,
    /// The other links, at most fourteen.
    pub links: Vec<Link>,
}

impl Setup {
    /// `ieee80211_mgd_assoc`'s checks of an MLD request: distinct link IDs
    /// below IEEE80211_MLD_MAX_NUM_LINKS, distinct unicast station link
    /// addresses, and each link an EHT association with the BSS of its own
    /// observation.
    pub fn validate(&self) -> Result<(), Error> {
        let invalid = |what| Err(Error::Wire(wire::Error::Invalid(what)));
        let association = &self.association;
        if association.mld.ap.is_multicast() || association.mld.ap.0 == [0; 6] {
            return Err(Error::InvalidAddress);
        }
        let mut ids = Vec::from([association.link_id]);
        let mut addresses = Vec::from([association.local]);
        for link in &self.links {
            let bss = link.observation.bss();
            let selection = link
                .request
                .modern()
                .ok_or(Error::Unsupported("multi-link request without its mode"))?;
            if selection.mode() != Mode::Eht
                || selection.capabilities().band() != bss.channel.band
                || bss.transmitter != bss.bssid
            {
                return Err(Error::Unsupported("multi-link link outside EHT on its BSS"));
            }
            ids.push(link.link_id);
            addresses.push(link.local);
        }
        if ids.len() > MAX_LINKS {
            return invalid("multi-link link count");
        }
        ids.sort_unstable();
        if ids.windows(2).any(|pair| pair[0] == pair[1]) || ids.iter().any(|&id| id >= 15) {
            return invalid("multi-link link IDs");
        }
        if addresses.iter().enumerate().any(|(i, address)| {
            address.is_multicast()
                || address.0 == [0; 6]
                || *address == association.mld.local
                || addresses[..i].contains(address)
        }) {
            return Err(Error::InvalidAddress);
        }
        Ok(())
    }

    /// The link of `link_id` the setup requests.
    pub fn link(&self, link_id: u8) -> Option<&Link> {
        self.links.iter().find(|link| link.link_id == link_id)
    }

    /// `ieee80211_assoc_add_ml_elem`'s element for an association request
    /// whose own elements are `outer`.
    pub(super) fn element(&self, outer: &[u8]) -> Vec<u8> {
        let requested: Vec<_> = self
            .links
            .iter()
            .map(|link| wire::multi_link::Requested {
                link_id: link.link_id,
                address: link.local,
                capability: link.request.capabilities(),
                elements: link.request.elements(),
            })
            .collect();
        wire::multi_link::association_request(
            self.association.mld.local,
            self.mld_capabilities,
            self.eml_capabilities,
            outer,
            &requested,
        )
    }
}

#[cfg(test)]
pub(crate) mod tests;
