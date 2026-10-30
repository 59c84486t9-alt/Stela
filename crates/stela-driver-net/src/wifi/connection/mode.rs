// SPDX-License-Identifier: GPL-2.0-only
// Adapted from pinned Linux net/mac80211/mlme.c, util.c and net/wireless/chan.c.
// Copyright 2002-2005, Instant802 Networks, Inc.; 2005-2006, Devicescape
// Software, Inc.; 2006-2010 Johannes Berg; 2013-2014 Intel Mobile
// Communications GmbH; 2018-2026 Intel Corporation. Full source notices in
// THIRD_PARTY.md.
//! The PHY mode and channel a non-STRICT single-link station associates
//! with: `ieee80211_determine_our_sta_mode` bounds them by the station's own
//! capabilities and `ieee80211_determine_chan_mode` by the AP's operation
//! elements and the channels' regulatory flags, then `ieee80211_config_bw`
//! narrows the AP's channel to the bandwidth the station may use.
use crate::wifi::{
    Band, Channel,
    regulatory::channel::{
        DISABLED, NO_20MHZ, NO_80MHZ, NO_160MHZ, NO_320MHZ, NO_EHT, NO_HE, NO_HT40MINUS,
        NO_HT40PLUS, NO_OFDM,
    },
    station::{
        operations::{ChannelDefinition, Operations},
        phy::{Capabilities, Mode, Width},
    },
};

/// Why mac80211 rejects the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// "Rejecting non-HE 6/7 GHz connection".
    NotHe,
    /// "required basic rate or BSS membership selectors not supported".
    Selectors,
    /// "unusable channel ... for connection".
    UnusableChannel,
}

/// The mode and operating channel of one association.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Connection {
    pub mode: Mode,
    pub definition: ChannelDefinition,
}

/// `IEEE80211_CONN_BW_LIMIT_*`, as a width in MHz.
type Limit = u32;

fn mode_limit(mode: Mode) -> Limit {
    match mode {
        Mode::Legacy => 20,
        Mode::Ht => 40,
        Mode::Vht | Mode::He => 160,
        Mode::Eht => 320,
    }
}

/// The next mode down; on 2.4 GHz, where no VHT exists, HE falls to HT.
fn below(mode: Mode, band: Band) -> Mode {
    match mode {
        Mode::Eht => Mode::He,
        Mode::He if band == Band::Ghz2 => Mode::Ht,
        Mode::He => Mode::Vht,
        Mode::Vht => Mode::Ht,
        Mode::Ht | Mode::Legacy => Mode::Legacy,
    }
}

/// A band's channels as cfg80211 registered them: each enabled channel with
/// its flags. A channel not listed is disabled.
#[derive(Clone, Copy)]
pub struct Channels<'a>(pub &'a [(Channel, u32)]);

impl Channels<'_> {
    fn flags(&self, frequency_mhz: u32) -> Option<u32> {
        self.0
            .iter()
            .find(|(channel, _)| u32::from(channel.frequency_mhz) == frequency_mhz)
            .map(|&(_, flags)| flags)
    }

    /// `_cfg80211_chandef_usable` for `local`'s band: every 20 MHz
    /// subchannel lacks `prohibited` and the flags the width adds.
    fn usable(
        &self,
        local: &Capabilities,
        def: &ChannelDefinition,
        mode: Mode,
        prohibited: u32,
    ) -> bool {
        let six = def.control.band == Band::Ghz6;
        let ht = local.ht().map_or(0, |ht| ht.capability);
        let vht = local
            .vht()
            .map(|vht| (vht.capability, vht.tx_highest & 0x2000 != 0));
        let control = u32::from(def.control.frequency_mhz);
        let Some(control_flags) = self.flags(control) else {
            return false;
        };
        let mut prohibited = prohibited;
        match def.width {
            Width::Mhz20 => {
                if mode != Mode::Legacy && local.ht().is_none() && !six {
                    return false;
                }
                prohibited |= NO_20MHZ;
            }
            Width::Mhz40 if !six => {
                // HT_CAP_SUP_WIDTH_20_40, not 40MHZ_INTOLERANT.
                if local.ht().is_none() || ht & 2 == 0 || ht & (1 << 14) != 0 {
                    return false;
                }
                let flag = if def.center1_mhz < control {
                    NO_HT40MINUS
                } else {
                    NO_HT40PLUS
                };
                if control_flags & flag != 0 {
                    return false;
                }
            }
            Width::Mhz40 => {}
            Width::Mhz80 | Width::Mhz80P80 => {
                if def.width == Width::Mhz80P80 && !six {
                    let Some((cap, ext_nss)) = vht else {
                        return false;
                    };
                    let extended = cap >> 30;
                    if !(cap & 0xc == 8
                        || (cap & 0xc == 4 && extended != 0)
                        || (ext_nss && extended > 1))
                    {
                        return false;
                    }
                }
                prohibited |= NO_80MHZ;
                if !six && vht.is_none() {
                    return false;
                }
            }
            Width::Mhz160 => {
                prohibited |= NO_160MHZ;
                if !six {
                    let Some((cap, ext_nss)) = vht else {
                        return false;
                    };
                    if !matches!(cap & 0xc, 4 | 8) && !(ext_nss && cap >> 30 != 0) {
                        return false;
                    }
                }
            }
            Width::Mhz320 => {
                prohibited |= NO_320MHZ;
                if !six || !local.eht().is_some_and(|eht| eht.phy[0] & 2 != 0) {
                    return false;
                }
            }
        }
        if def.width != Width::Mhz20 {
            prohibited |= NO_OFDM;
        }
        let segment = |center: u32| {
            let half = def.width_mhz() / 2;
            (center - half + 10..center + half).step_by(20)
        };
        segment(def.center1_mhz)
            .chain(def.center2_mhz.into_iter().flat_map(segment))
            .all(|frequency| {
                self.flags(frequency)
                    .is_some_and(|flags| flags & prohibited == 0)
            })
    }
}

/// `ieee80211_determine_our_sta_mode`: the highest mode and bandwidth the
/// station's capabilities allow, legacy when the AP has no WMM.
fn own(local: &Capabilities, wmm: bool, channels: Channels<'_>) -> (Mode, Limit) {
    let band = local.band();
    let five = band == Band::Ghz5;
    let six = band == Band::Ghz6;
    if !wmm || (local.ht().is_none() && !six) {
        return (Mode::Legacy, 20);
    }
    let mut mode = Mode::Ht;
    let mut limit = match local.ht() {
        Some(ht) if ht.capability & 2 != 0 => 40,
        _ => 20,
    };
    if five {
        let Some(vht) = local.vht() else {
            return (mode, limit);
        };
        // VHT needs 40 MHz and one channel that allows 80 MHz.
        let eighty = channels
            .0
            .iter()
            .any(|&(_, flags)| flags & (DISABLED | NO_80MHZ) == 0);
        if limit == 20 || !eighty {
            return (mode, limit);
        }
        mode = Mode::Vht;
        limit = if vht.capability & (0xc | 0xc000_0000) != 0 {
            160
        } else {
            80
        };
    } else if !matches!(band, Band::Ghz2) {
        limit = 160;
    }
    let Some(he) = local.he() else {
        return (mode, limit);
    };
    mode = Mode::He;
    match band {
        Band::Ghz2 if he.phy[0] & 2 == 0 => limit = 20,
        Band::Ghz5 if he.phy[0] & 4 == 0 => limit = 20,
        Band::Ghz5 | Band::Ghz6 if he.phy[0] & 8 == 0 => limit = limit.min(80),
        _ => {}
    }
    let Some(eht) = local.eht() else {
        return (mode, limit);
    };
    if six && eht.phy[0] & 2 != 0 {
        limit = 320;
    }
    (Mode::Eht, limit)
}

/// `ieee80211_determine_ap_chan`: the highest mode up to `mode` the AP's
/// elements support, and its channel there.
fn ap(
    operations: &Operations,
    peer: &Capabilities,
    control: Channel,
    mode: Mode,
    vht_caps: Option<(u32, u32)>,
) -> (Mode, ChannelDefinition) {
    let legacy = ChannelDefinition {
        control,
        width: Width::Mhz20,
        center1_mhz: u32::from(control.frequency_mhz),
        center2_mhz: None,
        punctured: 0,
    };
    let at = |mode| operations.channel(control, mode, vht_caps).ok();
    if control.band == Band::Ghz6 {
        if mode < Mode::He || peer.he().is_none() || peer.he_6ghz().is_none() {
            return (Mode::Legacy, legacy);
        }
        let eht = mode == Mode::Eht && operations.eht.is_some() && peer.eht().is_some();
        let mode = if eht { Mode::Eht } else { Mode::He };
        return at(mode).map_or((Mode::Legacy, legacy), |def| (mode, def));
    }
    if mode < Mode::Ht || operations.ht.is_none() || peer.ht().is_none() {
        return (Mode::Legacy, legacy);
    }
    let Some(ht) = at(Mode::Ht) else {
        return (Mode::Legacy, legacy);
    };
    if mode == Mode::Ht {
        return (Mode::Ht, ht);
    }
    // On 5 GHz a missing or invalid VHT operation leaves HT; on 2.4 GHz
    // there is none, and HE builds on HT.
    let base = if control.band == Band::Ghz5 {
        if operations.vht.is_none() || peer.vht().is_none() {
            return (Mode::Ht, ht);
        }
        match at(Mode::Vht) {
            Some(vht) => (Mode::Vht, vht),
            None => return (Mode::Ht, ht),
        }
    } else {
        (Mode::Ht, ht)
    };
    if mode < Mode::He || operations.he.is_none() || peer.he().is_none() {
        return base;
    }
    let Some(he) = at(Mode::He) else {
        return base;
    };
    if mode < Mode::Eht || operations.eht.is_none() || peer.eht().is_none() {
        return (Mode::He, he);
    }
    at(Mode::Eht).map_or((Mode::He, he), |eht| (Mode::Eht, eht))
}

/// `ieee80211_chandef_downgrade` with its effect on the connection.
fn downgrade(def: &mut ChannelDefinition, mode: &mut Mode, limit: &mut Limit) {
    match def.width {
        Width::Mhz20 => {
            *mode = Mode::Legacy;
            *limit = 20;
        }
        Width::Mhz40 | Width::Mhz80 => {
            if *mode == Mode::Vht {
                *mode = Mode::Ht;
            }
            *limit = def.width_mhz() / 2;
        }
        Width::Mhz80P80 => *limit = 80,
        Width::Mhz160 | Width::Mhz320 => *limit = def.width_mhz() / 2,
    }
    def.downgrade();
}

/// The PHY mode and operating channel to associate on `control` with the AP
/// whose capabilities and operation elements these are, `local` being the
/// station's capabilities on that band and `channels` its channels there.
pub fn determine(
    local: &Capabilities,
    peer: &Capabilities,
    operations: &Operations,
    control: Channel,
    channels: Channels<'_>,
) -> Result<Connection, Refusal> {
    let band = control.band;
    let (mut mode, mut limit) = own(local, peer.wmm().is_some(), channels);
    let vht_caps = local
        .vht()
        .zip(peer.vht())
        .map(|(local, peer)| (local.capability, peer.capability));
    loop {
        let (ap_mode, mut def) = ap(operations, peer, control, mode, vht_caps);
        // The AP's elements lower the mode: parse them again for it.
        if ap_mode < mode {
            mode = ap_mode;
            continue;
        }
        if band == Band::Ghz6 && ap_mode < Mode::He {
            return Err(Refusal::NotHe);
        }
        limit = limit.min(mode_limit(ap_mode));
        // HT, VHT, HE and EHT membership; SAE-H2E is never the station's
        // for a PSK network.
        let supported = match mode {
            Mode::Legacy => 0,
            Mode::Ht => 1,
            Mode::Vht => 3,
            Mode::He => 7,
            Mode::Eht => 15,
        };
        if peer.rates().selectors & !supported != 0 {
            return Err(Refusal::Selectors);
        }
        let mut current = mode;
        while !channels.usable(local, &def, current, DISABLED) {
            if def.width == Width::Mhz20 && current == Mode::Legacy {
                return Err(Refusal::UnusableChannel);
            }
            downgrade(&mut def, &mut current, &mut limit);
        }
        if current >= Mode::He && !channels.usable(local, &def, current, NO_HE) {
            current = below(Mode::He, band);
            limit = limit.min(160);
        }
        if current >= Mode::Eht && !channels.usable(local, &def, current, NO_EHT) {
            current = Mode::He;
            limit = limit.min(160);
        }
        if current >= Mode::He
            && let Some(he) = &operations.he
            && (!peer.meets_peer_he_basic(he.basic_mcs)
                || !local.meets_local_he_basic(he.basic_mcs).unwrap_or(false))
        {
            current = below(Mode::He, band);
        }
        if current >= Mode::Eht
            && let Some(eht) = &operations.eht
            && !local.meets_eht_basic(eht.basic_mcs)
        {
            current = Mode::He;
            limit = limit.min(160);
        }
        if current >= Mode::Eht && band != Band::Ghz2 && limit == 40 {
            current = Mode::He;
        }
        // The mode only decreases, so this ends.
        if current != ap_mode {
            mode = current;
            continue;
        }
        while def.bandwidth_mhz() > limit && def.downgrade() {}
        return Ok(Connection {
            mode,
            definition: def,
        });
    }
}

#[cfg(test)]
mod tests;
