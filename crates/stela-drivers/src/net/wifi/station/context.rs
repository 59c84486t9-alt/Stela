// SPDX-License-Identifier: GPL-2.0-only
// Association state adapted from Linux net/mac80211/mlme.c, as in station.rs:
// Copyright 2003-2008 Jouni Malinen; 2004 Instant802 Networks, Inc.;
// 2005 Devicescape Software, Inc.; 2006-2007 Jiri Benc; 2007 Michael Wu;
// 2013-2014 Intel Mobile Communications GmbH;
// 2015-2017 Intel Deutschland GmbH; 2018-2026 Intel Corporation.
//! Retained current-association configuration, built only from actual MLME input.
//! This is not OS authentication, native completion or regulatory authority.
use super::{
    Error, Join, Ticket,
    operations::{ChannelDefinition, Operations},
    phy::{Capabilities, Negotiated, Role},
    wire::AssociationResponse,
};
use crate::net::{
    Mac,
    wifi::{
        Channel,
        scan::result::{Bss, Kind},
    },
};
use alloc::{sync::Arc, vec::Vec};

/// Exact observation minted only by a native owner's completed scan RX path.
/// Public protocol parsers cannot construct it. A native owner separately
/// checks original Arc membership; providers retain this same opaque identity.
#[derive(Debug)]
pub struct NativeBssObservation {
    pub(crate) bss: Bss,
}
impl NativeBssObservation {
    pub fn bss(&self) -> &Bss {
        &self.bss
    }
}

/// Explicit actual request/resource mode. No MLD constructor or authority is
/// available; advertising ML or EHT cannot create a multi-link association.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssociationIntent {
    SingleLink,
}

#[derive(Debug)]
pub struct AssociationContext {
    ticket: Ticket,
    bssid: Mac,
    negotiated: Negotiated,
    operations: Operations,
    definition: ChannelDefinition,
    beacon: Bss,
    response: AssociationResponse,
    dtim_period: u8,
    dtim_count: u8,
    pmf: Option<super::wire::pmf::Selection>,
    native_observation: Option<Arc<NativeBssObservation>>,
}
fn failure(error: super::phy::Error) -> Error {
    Error::Phy(error)
}
fn ies(mut bytes: &[u8]) -> Result<Vec<(u8, &[u8])>, Error> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let h = bytes
            .get(..2)
            .ok_or(Error::Wire(super::wire::Error::Truncated))?;
        let b = bytes
            .get(2..2 + usize::from(h[1]))
            .ok_or(Error::Wire(super::wire::Error::Truncated))?;
        out.push((h[0], b));
        bytes = &bytes[2 + b.len()..];
    }
    Ok(out)
}
// Source generic fallback only for missing HT/VHT capability/operation and AP
// WMM parameters. HE/EHT response requirements are not filled from a beacon.
fn fallback_key(id: u8, b: &[u8]) -> Option<u16> {
    match id {
        45 | 61 | 191 | 192 => Some(u16::from(id)),
        221 if b.starts_with(&[0, 0x50, 0xf2, 2, 1]) => Some(221),
        _ => None,
    }
}
fn effective(beacon: &Bss, response: &AssociationResponse) -> Result<Vec<u8>, Error> {
    let response_ies = ies(&response.elements)?;
    let mut out = response.elements.clone();
    for (id, b) in ies(&beacon.elements)? {
        if let Some(key) = fallback_key(id, b)
            && !response_ies
                .iter()
                .any(|&(other, bytes)| fallback_key(other, bytes) == Some(key))
        {
            out.extend_from_slice(&[id, b.len() as u8]);
            out.extend_from_slice(b);
        }
    }
    Ok(out)
}

impl AssociationContext {
    pub(super) fn build(
        ticket: Ticket,
        join: &Join,
        beacon: &Bss,
        response: &AssociationResponse,
    ) -> Result<Self, Error> {
        Self::build_with_native(ticket, join, beacon, response, None)
    }
    pub(super) fn build_with_native(
        ticket: Ticket,
        join: &Join,
        beacon: &Bss,
        response: &AssociationResponse,
        native_observation: Option<&Arc<NativeBssObservation>>,
    ) -> Result<Self, Error> {
        let selection = join
            .request
            .modern()
            .ok_or(Error::Unsupported("missing modern selection"))?;
        if beacon.kind != Kind::Beacon
            || beacon.bssid != join.bssid
            || beacon.transmitter != join.bssid
            || beacon.channel != join.channel
            || beacon.beacon_interval == 0
            || response.aid == 0
            || response.status != 0
        {
            return Err(Error::Unsupported(
                "current beacon/channel/timing/AID required",
            ));
        }
        if let Some(pmf) = join.request.pmf() {
            let observed =
                native_observation.ok_or(Error::Unsupported("native PMF observation required"))?;
            if observed.bss.elements != beacon.elements || observed.bss.ticket != beacon.ticket {
                return Err(Error::Unsupported("native PMF observation mismatch"));
            }
            if beacon.capabilities & 0x10 == 0 || response.capabilities & 0x10 == 0 {
                return Err(Error::Unsupported("PMF AP privacy capability"));
            }
            pmf.validate_peer(&beacon.elements, &response.elements)
                .map_err(Error::Wire)?;
        }
        let mut tim = None;
        for (id, b) in ies(&beacon.elements)? {
            // Outer71 is an unselected, opaque advertisement on this exact
            // transmitted-BSSID path. Outer85 requires profile DTIM handling.
            if id == 85 {
                return Err(Error::Unsupported("nontransmitted BSSID index"));
            }
            if id == 5 {
                if tim.is_some() || b.len() < 4 || b[1] == 0 || b[0] >= b[1] {
                    return Err(Error::Unsupported("beacon TIM/DTIM"));
                }
                tim = Some((b[0], b[1]));
            }
        }
        let (dtim_count, dtim_period) =
            tim.ok_or(Error::Unsupported("actual beacon DTIM required"))?;
        let actual_ssid = ies(join.request.elements())?
            .into_iter()
            .find(|(id, _)| *id == 0)
            .map(|(_, v)| v);
        if beacon
            .ssid
            .as_deref()
            .is_some_and(|ssid| !ssid.is_empty() && Some(ssid) != actual_ssid)
        {
            return Err(Error::Unsupported("selected BSS SSID mismatch"));
        }
        let bytes = effective(beacon, response)?;
        let peer =
            Capabilities::parse(join.channel.band, Role::AccessPoint, &bytes).map_err(failure)?;
        let observed = Capabilities::parse(join.channel.band, Role::AccessPoint, &beacon.elements)
            .map_err(failure)?;
        if peer.rates().basic != observed.rates().basic {
            return Err(Error::Unsupported("response/beacon basic-rate mismatch"));
        }
        if peer
            .vht()
            .zip(observed.vht())
            .is_some_and(|(response, bss)| (response.capability & 3) > (bss.capability & 3))
        {
            return Err(Error::Unsupported("response exceeds BSS MPDU bound"));
        }
        let negotiated = Negotiated::between(
            selection.capabilities(),
            &peer,
            selection.mode(),
            selection.width(),
        )
        .map_err(failure)?;
        // Negotiation requires WMM for every mode beyond legacy, which
        // mac80211 enters for an AP without it.
        let operations = Operations::parse(&bytes).map_err(failure)?;
        let definition = operations
            .channel_for(join.channel, &negotiated)
            .map_err(failure)?;
        if definition.width != selection.width() {
            return Err(Error::Unsupported("selected/advertised width mismatch"));
        }
        // Actual MT7925 uses Linux's normal non-STRICT profile. HT/VHT
        // operation/basic observations remain retained, but their strict-only
        // basic-MCS tests do not reject otherwise usable common rates.
        if let Some(he) = &operations.he
            && negotiated.he.is_some()
            && (!peer.meets_peer_he_basic(he.basic_mcs)
                || !selection
                    .capabilities()
                    .meets_local_he_basic(he.basic_mcs)
                    .map_err(failure)?)
        {
            return Err(Error::Unsupported("HE basic MCS requirement"));
        }
        if let Some(e) = &operations.eht
            && negotiated.eht.is_some()
            && !selection.capabilities().meets_eht_basic(e.basic_mcs)
        {
            return Err(Error::Unsupported("EHT basic MCS requirement"));
        }
        Ok(Self {
            ticket,
            bssid: join.bssid,
            negotiated,
            operations,
            definition,
            beacon: beacon.clone(),
            response: response.clone(),
            dtim_period,
            dtim_count,
            pmf: join.request.pmf().cloned(),
            native_observation: native_observation.cloned(),
        })
    }
    /// Exact original OS-selected RSNE, validated against this actual BSS and
    /// successful association response. This remains unauthenticated input
    /// until the genuine OS service qualifies its protected-management policy.
    pub fn pmf_observation(&self) -> Option<&Arc<NativeBssObservation>> {
        self.native_observation.as_ref()
    }
    pub fn pmf(&self) -> Option<&super::wire::pmf::Selection> {
        self.pmf.as_ref()
    }
    pub fn intent(&self) -> AssociationIntent {
        AssociationIntent::SingleLink
    }
    pub fn ticket(&self) -> Ticket {
        self.ticket
    }
    pub fn bssid(&self) -> Mac {
        self.bssid
    }
    pub fn channel(&self) -> Channel {
        self.definition.control
    }
    /// mac80211 `ieee80211_config_bw` for a later beacon's elements around
    /// the `control` channel the association operates: the channel the AP now
    /// operates, narrowed to the association's width. An error is a mode or
    /// geometry change mac80211 disconnects for.
    pub fn beacon_definition(
        &self,
        elements: &[u8],
        control: Channel,
    ) -> Result<ChannelDefinition, Error> {
        let mut definition = Operations::parse(elements)
            .and_then(|operations| operations.channel_for(control, &self.negotiated))
            .map_err(failure)?;
        let limit = ChannelDefinition {
            width: self.negotiated.width,
            ..self.definition
        };
        while definition.width_mhz() > limit.width_mhz() && definition.downgrade() {}
        Ok(definition)
    }
    pub fn definition(&self) -> ChannelDefinition {
        self.definition
    }
    pub fn negotiated(&self) -> &Negotiated {
        &self.negotiated
    }
    pub fn operations(&self) -> &Operations {
        &self.operations
    }
    pub fn beacon(&self) -> &Bss {
        &self.beacon
    }
    pub fn response(&self) -> &AssociationResponse {
        &self.response
    }
    pub fn dtim_period(&self) -> u8 {
        self.dtim_period
    }
    pub fn dtim_count(&self) -> u8 {
        self.dtim_count
    }
}
