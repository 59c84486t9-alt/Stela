// SPDX-License-Identifier: GPL-2.0-only
// Multi-link setup adapted from Linux net/mac80211/mlme.c
// (ieee80211_mgd_assoc, ieee80211_assoc_success); source notices in
// wifi/THIRD_PARTY.md.
//! A non-AP MLD's multi-link setup with one AP MLD, as mac80211 keeps it in
//! its association data: the two MLDs, the link the setup runs on and the
//! station's address there, and each other link it requests with the AP's
//! affiliated BSS and the link's own association request.
use super::{
    Error, NativeBssObservation, Phase, Station,
    phy::Mode,
    wire::{self, AssociationRequest, multi_link::MAX_LINKS},
};
use crate::{
    Mac,
    wifi::{Channel, frame::Mpdu},
};
use alloc::{borrow::Cow, sync::Arc, vec::Vec};

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

/// One link of the current association as frames on the air address it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OnAir {
    /// The station's address on the link.
    pub local: Mac,
    /// The AP's address on the link.
    pub ap: Mac,
    pub channel: Channel,
}

impl Station {
    /// The station's and the AP's addresses in the frames of the current
    /// association: the setup link's until the association is made, then the
    /// MLDs' of a multi-link one, as mac80211 addresses its frames.
    pub(super) fn addresses(&self) -> Result<(Mac, Mac), Error> {
        let join = self.join.as_ref().ok_or(Error::NotAssociated)?;
        Ok(match &self.context {
            Some(context) if matches!(self.phase, Phase::Configuring | Phase::Associated) => {
                (self.local, context.peer())
            }
            _ => (self.link_address(), join.bssid),
        })
    }

    /// The links the current association's frames arrive on: the setup link,
    /// then each other link it made.
    pub fn on_air(&self) -> impl Iterator<Item = OnAir> + '_ {
        let setup = self
            .join
            .as_ref()
            .zip(self.current_channel())
            .map(|(join, channel)| OnAir {
                local: self.link_address(),
                ap: join.bssid,
                channel,
            });
        let links = self.link_contexts().iter().filter_map(|context| {
            context.affiliation().map(|affiliation| OnAir {
                local: affiliation.local,
                ap: context.bssid(),
                channel: context.channel(),
            })
        });
        setup.into_iter().chain(links)
    }

    /// mac80211's `ieee80211_prepare_and_rx_handle` for a frame of the
    /// current association: the link whose channel it arrived on, and the
    /// frame with a unicast frame's link addresses replaced by the MLDs'.
    /// Group-addressed frames keep their link's addresses.
    pub fn mld_view<'a>(&self, frame: &'a Mpdu) -> Result<(Cow<'a, Mpdu>, OnAir), Error> {
        let radio = &frame.radio;
        let link = self
            .on_air()
            .find(|link| {
                (radio.band, radio.channel, radio.frequency_mhz)
                    == (
                        link.channel.band,
                        link.channel.number,
                        link.channel.frequency_mhz,
                    )
            })
            .ok_or(Error::WrongChannel)?;
        let affiliation = self
            .context
            .as_ref()
            .filter(|_| matches!(self.phase, Phase::Configuring | Phase::Associated))
            .and_then(|context| context.affiliation());
        let header = frame.header();
        let Some(affiliation) = affiliation
            .filter(|_| !header.receiver.is_multicast() && header.transmitter == Some(link.ap))
        else {
            return Ok((Cow::Borrowed(frame), link));
        };
        let mld = affiliation.mld;
        // A3 only without To/From DS, where it is the BSSID.
        let third = header.control & 0x0300 == 0;
        let view = frame.readdressed(|number, address| match number {
            1 if address == link.local => mld.local,
            2 => mld.ap,
            3 if third && address == link.ap => mld.ap,
            3 if third && address == link.local => mld.local,
            _ => address,
        });
        Ok((Cow::Owned(view), link))
    }
}

#[cfg(test)]
pub(crate) mod tests;
