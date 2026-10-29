// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
//! Source initial STATE_NONE peer/BSS and ROC20 codecs. This has
//! no associated Configuration and cannot encode association/key/port success.
use super::{Error, Profile};
use crate::net::wifi::{
    Band,
    scan::result::Bss,
    station::{
        operations::Operations,
        phy::{Capabilities, McsMaps, Role},
    },
};
use alloc::vec::Vec;

#[derive(Clone, Debug)]
pub(in crate::net::wifi::mediatek) struct Preauthentication {
    profile: Profile,
    power_type: u8,
}
impl Preauthentication {
    pub fn new(profile: Profile, local: &Capabilities, bss: &Bss) -> Result<Self, Error> {
        profile.validate_inner(true)?;
        if profile.channel.band != Band::Ghz6
            || profile.aid != 0
            || profile.cipher != 0
            || profile.channel != bss.channel
            || bss.bssid != profile.peer
            || bss.transmitter != profile.peer
            || profile.beacon_interval != bss.beacon_interval
            || bss.capabilities & 0x10 == 0
            || bss.observed.band != Band::Ghz6
            || bss.observed.channel != bss.channel.number
            || bss.observed.frequency_mhz != bss.channel.frequency_mhz
            || local.band() != Band::Ghz6
            || local.role() != Role::Station
        {
            return Err(Error::InvalidNegotiation);
        }
        let peer = Capabilities::parse(Band::Ghz6, Role::AccessPoint, &bss.elements)
            .map_err(|_| Error::InvalidNegotiation)?;
        let operations = Operations::parse(&bss.elements).map_err(|_| Error::InvalidGeometry)?;
        let he = operations.he.as_ref().ok_or(Error::InvalidGeometry)?;
        let six = he.six_ghz.ok_or(Error::InvalidGeometry)?;
        let power_type = (six[1] & 0x78) >> 3;
        if six[0] != profile.channel.number as u8
            || six[1] & 3 != 0
            || six[2] != six[0]
            || six[3] != 0
            || !matches!(power_type, 0 | 3)
            || operations.ht.is_some()
            || operations.vht.is_some()
            || operations.eht.is_some()
        {
            return Err(Error::InvalidGeometry);
        }
        let own_he = local.he().ok_or(Error::InvalidNegotiation)?;
        let peer_he = peer.he().ok_or(Error::InvalidNegotiation)?;
        let common = McsMaps::intersect(own_he.mcs_80, peer_he.mcs_80);
        if local.he_6ghz().is_none_or(|v| v == 0)
            || peer.he_6ghz().is_none_or(|v| v == 0)
            || local.wmm().is_none()
            || peer.wmm().is_none()
            || common.rx & 3 == 3
            || common.tx & 3 == 3
            || !peer.meets_peer_he_basic(he.basic_mcs)
            || !local
                .meets_local_he_basic(he.basic_mcs)
                .map_err(|_| Error::InvalidNegotiation)?
            || profile.basic_rates != peer.rates().basic
            || profile.supported_rates != peer.rates().supported
        {
            return Err(Error::InvalidNegotiation);
        }
        // TIM is required by this finite initial peer profile. Neither
        // caller timing nor an invented DTIM default substitutes for it.
        let mut rest = bss.elements.as_slice();
        let mut dtim = None;
        while !rest.is_empty() {
            let h = rest.get(..2).ok_or(Error::InvalidTiming)?;
            let bytes = rest
                .get(2..2 + usize::from(h[1]))
                .ok_or(Error::InvalidTiming)?;
            if h[0] == 5 && (bytes.len() < 4 || dtim.replace(bytes[1]).is_some()) {
                return Err(Error::InvalidTiming);
            }
            rest = &rest[2 + bytes.len()..];
        }
        if dtim != Some(profile.dtim_period) {
            return Err(Error::InvalidTiming);
        }
        Ok(Self {
            profile,
            power_type,
        })
    }
    pub const fn profile(&self) -> Profile {
        self.profile
    }
    pub const fn power_type(&self) -> u8 {
        self.power_type
    }
    /// The hardware band a ROC grant assigned.
    pub fn set_band_index(&mut self, band: u8) {
        self.profile.interface.band_index = band;
    }
    pub fn bss_request(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = self.profile.bss_request_validated(false, None, true)?;
        // Real nonNULL initial zero-capability peer: source6GHz older-family
        // bitmap is unconditional A|AN|AC|AX5, extension remains zero.
        bytes[4 + 25] = 0xb1;
        Ok(bytes)
    }
    pub fn peer_request(&self, enable: bool) -> Result<Vec<u8>, Error> {
        self.profile
            .peer_request_validated(enable, false, None, true)
    }
    pub fn broadcast_request(&self) -> Result<Vec<u8>, Error> {
        self.profile.broadcast_request()
    }
    pub fn disable_beacon_pm(&self) -> Result<Vec<u8>, Error> {
        self.profile.disable_beacon_pm()
    }
    pub fn filter_request(&self, enable: bool) -> Result<super::super::init::Request, Error> {
        self.profile.filter_request(enable)
    }
    pub fn roc(&self, token: u8, duration: u32) -> Result<super::super::init::Request, Error> {
        self.profile.roc_validated(token, duration, true)
    }
    pub fn abort_roc(&self, token: u8) -> Result<super::super::init::Request, Error> {
        self.profile.abort_roc_validated(token, true)
    }
}
