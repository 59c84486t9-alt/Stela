// SPDX-License-Identifier: GPL-2.0-only
//! Retained current-association configuration, built only from actual MLME input.
//! This is not OS authentication, native completion or regulatory authority.
use super::{
    Error, Join, Ticket,
    operations::{ChannelDefinition, Operations},
    phy::{Capabilities, McsMaps, Mode, Negotiated, Role},
    wire::AssociationResponse,
};
use crate::net::{
    Mac,
    wifi::{
        Channel,
        scan::result::{Bss, Kind},
    },
};
use alloc::vec::Vec;

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
fn basic_maps(required: u16, common: McsMaps) -> bool {
    (0..8).all(|n| {
        let r = (required >> (2 * n)) & 3;
        r == 3
            || [common.rx, common.tx].iter().all(|m| {
                let v = (m >> (2 * n)) & 3;
                v != 3 && v >= r
            })
    })
}
impl AssociationContext {
    pub(super) fn build(
        ticket: Ticket,
        join: &Join,
        beacon: &Bss,
        response: &AssociationResponse,
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
        let mut tim = None;
        for (id, b) in ies(&beacon.elements)? {
            if matches!(id, 71 | 85) {
                return Err(Error::Unsupported("multiple-BSSID association"));
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
        if negotiated.wmm.is_none() {
            return Err(Error::Unsupported("modern WMM parameters required"));
        }
        let operations = Operations::parse(&bytes).map_err(failure)?;
        let definition = operations
            .channel_for(join.channel, &negotiated)
            .map_err(failure)?;
        if definition.width != selection.width() {
            return Err(Error::Unsupported("selected/advertised width mismatch"));
        }
        if let Some(ht) = &operations.ht
            && selection.mode() != Mode::Legacy
        {
            let n = negotiated
                .ht
                .as_ref()
                .ok_or(Error::Unsupported("HT basic MCS profile"))?;
            if ht.basic_mcs[..10]
                .iter()
                .zip(n.peer_rx_mcs.iter().zip(&n.local_rx_mcs))
                .any(|(required, (tx, rx))| required & !(tx & rx) != 0)
            {
                return Err(Error::Unsupported("HT basic MCS requirement"));
            }
        }
        if let Some(v) = &operations.vht
            && let Some(n) = &negotiated.vht
            && !basic_maps(v.basic_mcs, n.mcs)
        {
            return Err(Error::Unsupported("VHT basic MCS requirement"));
        }
        if let Some(he) = &operations.he
            && let Some(n) = &negotiated.he
            && !basic_maps(he.basic_mcs, n.mcs_80)
        {
            return Err(Error::Unsupported("HE basic MCS requirement"));
        }
        if let Some(e) = &operations.eht
            && let Some(n) = &negotiated.eht
            && (!selection.capabilities().meets_eht_basic(e.basic_mcs)
                || e.basic_mcs
                    .iter()
                    .zip(n.ranges)
                    .any(|(r, n)| (r & 15) > (n >> 4) || (r >> 4) > (n & 15)))
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
        })
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
