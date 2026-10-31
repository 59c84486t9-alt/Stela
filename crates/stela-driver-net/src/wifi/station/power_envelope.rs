// SPDX-License-Identifier: GPL-2.0-only
// Adapted from pinned Linux mac80211/parse.c, mac80211/mlme.c and
// linux/ieee80211-he.h: Copyright 2007-2010 Johannes Berg;
// 2013-2014 Intel Mobile Communications GmbH; 2018-2026 Intel Corporation.
// Full source notices in THIRD_PARTY.md.
//! What a 6 GHz AP's Transmit Power Envelopes limit, `struct
//! ieee80211_parsed_tpe`. An observation, never permission to transmit.

use super::{
    operations::{ChannelDefinition, mhz},
    phy::Width,
};

const TRANSMIT_POWER_ENVELOPE: u8 = 195;
/// `IEEE80211_TPE_MAX_TX_PWR_NO_CONSTRAINT` and `IEEE80211_TPE_PSD_NO_LIMIT`.
const NO_LIMIT: i8 = 127;
const EIRP_ENTRIES: usize = 5;
const PSD_ENTRIES: usize = 16;
const LOCAL_EIRP: u8 = 0;
const LOCAL_PSD: u8 = 1;
const CLIENT_EIRP: u8 = 2;
const CLIENT_PSD: u8 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Eirp {
    pub power: [i8; EIRP_ENTRIES],
    count: u8,
}

impl Eirp {
    /// The limit at `index` of the widths, in dBm.
    pub fn limit(&self, index: usize) -> i8 {
        if index < usize::from(self.count) {
            self.power[index] / 2
        } else {
            i8::MAX
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Psd {
    pub power: [i8; PSD_ENTRIES],
    valid: bool,
    count: u8,
    /// The entries for the AP's HE channel, which come first.
    n: u8,
}

impl Psd {
    /// `iwl_mld_get_primary_psd`: the limit on the control subchannel of
    /// `definition`, in dBm/MHz.
    pub fn primary(&self, definition: &ChannelDefinition) -> i8 {
        if !self.valid {
            return i8::MAX;
        }
        let start = definition.center1_mhz as i32 - mhz(definition.width) as i32 / 2;
        let index = (i32::from(definition.control.frequency_mhz) - start - 10) / 20;
        match usize::try_from(index) {
            Ok(index) if index < usize::from(self.count) => self.power[index] / 2,
            _ => i8::MAX,
        }
    }

    /// The mean of the limits across `subchannels`, in dBm/MHz.
    pub fn mean(&self, subchannels: usize) -> i8 {
        if !self.valid {
            return i8::MAX;
        }
        let count = subchannels.min(usize::from(self.count));
        let limits = self.power[..count]
            .iter()
            .filter(|&&limit| limit != i8::MIN);
        let (sum, valid) = limits.fold((0, 0), |(sum, valid), &limit| {
            (sum + i32::from(limit), valid + 1)
        });
        if valid == 0 {
            i8::MAX
        } else {
            (sum / valid / 2) as i8
        }
    }
}

const EIRP: Eirp = Eirp {
    power: [NO_LIMIT; EIRP_ENTRIES],
    count: 0,
};
const PSD: Psd = Psd {
    power: [NO_LIMIT; PSD_ENTRIES],
    valid: false,
    count: 0,
    n: 0,
};

/// One category's limits, by `IEEE80211_TPE_CAT_6GHZ_DEFAULT` then subordinate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PowerEnvelope {
    pub max_local: [Eirp; 2],
    pub max_client: [Eirp; 2],
    pub psd_local: [Psd; 2],
    pub psd_client: [Psd; 2],
}

/// `ieee80211_valid_tpe_element`.
fn valid(data: &[u8]) -> bool {
    let Some((&info, values)) = data.split_first() else {
        return false;
    };
    let (count, interpret, category) = (info & 7, (info >> 3) & 7, info >> 6);
    if category > 1 {
        return false;
    }
    match interpret {
        LOCAL_EIRP | CLIENT_EIRP => count <= 3 && values.len() > usize::from(count),
        LOCAL_PSD | CLIENT_PSD if count <= 4 => {
            let n = if count == 0 { 1 } else { 1 << (count - 1) };
            match values.get(n) {
                Some(&extension) => values.len() > n + usize::from(extension & 15),
                None => values.len() == n,
            }
        }
        _ => false,
    }
}

/// `ieee80211_chandef_num_subchans`.
fn subchannels(definition: &ChannelDefinition) -> usize {
    match definition.width {
        Width::Mhz80P80 => 8,
        width => (mhz(width) / 20) as usize,
    }
}

/// `ieee80211_chandef_num_widths`.
fn widths(definition: &ChannelDefinition) -> u8 {
    match definition.width {
        Width::Mhz20 => 1,
        Width::Mhz40 => 2,
        Width::Mhz80 | Width::Mhz80P80 => 3,
        Width::Mhz160 => 4,
        Width::Mhz320 => 5,
    }
}

/// `ieee80211_calc_chandef_subchan_offset`: how many subchannels of `ap` lie
/// below the `partial` around its control channel.
fn offset(ap: &ChannelDefinition, partial: usize) -> usize {
    if subchannels(ap) <= partial {
        return 0;
    }
    let mut narrower = *ap;
    let mut offset = 0;
    while subchannels(&narrower) > partial {
        let previous = narrower.center1_mhz;
        narrower = narrower.downgraded();
        if previous < narrower.center1_mhz {
            offset += subchannels(&narrower);
        }
    }
    if ap
        .center2_mhz
        .is_some_and(|second| ap.width == Width::Mhz80P80 && second < ap.center1_mhz)
    {
        offset += 4;
    }
    offset
}

impl Psd {
    /// `ieee80211_rearrange_tpe_psd`: the entries come as the HE channel's then
    /// the rest; this leaves them in the order of `used`'s subchannels.
    fn fit(&mut self, ap: &ChannelDefinition, used: &ChannelDefinition) {
        if !self.valid {
            return;
        }
        let needed = subchannels(used);
        if self.n != 0 {
            let n = usize::from(self.n);
            let start = offset(ap, n);
            let mut ordered = [NO_LIMIT; PSD_ENTRIES];
            for (index, value) in ordered.iter_mut().enumerate().take(subchannels(ap)) {
                *value = if index < start {
                    self.power[index + n]
                } else if index < start + n {
                    self.power[index - start]
                } else {
                    self.power[index]
                };
            }
            self.power = [NO_LIMIT; PSD_ENTRIES];
            let start = offset(ap, needed);
            self.power[..needed].copy_from_slice(&ordered[start..start + needed]);
        }
        self.count = self.count.min(needed as u8);
    }
}

impl PowerEnvelope {
    /// `ieee80211_clear_tpe`.
    pub const fn none() -> Self {
        Self {
            max_local: [EIRP; 2],
            max_client: [EIRP; 2],
            psd_local: [PSD; 2],
            psd_client: [PSD; 2],
        }
    }

    /// Every well-formed envelope among a beacon's `elements`.
    pub fn parse(elements: &[u8]) -> Self {
        let mut envelope = Self::none();
        let mut rest = elements;
        while let [id, length, tail @ ..] = rest {
            let Some((data, next)) = tail.split_at_checked(usize::from(*length)) else {
                break;
            };
            if *id == TRANSMIT_POWER_ENVELOPE && valid(data) {
                envelope.take(data);
            }
            rest = next;
        }
        envelope
    }

    /// The one envelope `data` holds, as a Channel Switch Wrapper carries it.
    pub fn single(data: &[u8]) -> Self {
        let mut envelope = Self::none();
        if valid(data) {
            envelope.take(data);
        }
        envelope
    }

    /// `ieee80211_parse_tpe`, of an element `valid` admitted.
    fn take(&mut self, data: &[u8]) {
        let (info, values) = (data[0], &data[1..]);
        let (count, interpret) = (usize::from(info & 7), (info >> 3) & 7);
        let category = usize::from(info >> 6);
        let signed = |bytes: &[u8], out: &mut [i8]| {
            for (out, byte) in out.iter_mut().zip(bytes) {
                *out = *byte as i8;
            }
        };
        match interpret {
            LOCAL_EIRP | CLIENT_EIRP => {
                let out = if interpret == LOCAL_EIRP {
                    &mut self.max_local[category]
                } else {
                    &mut self.max_client[category]
                };
                signed(&values[..=count], &mut out.power);
                out.count = count as u8 + 1;
                // 320 MHz is an extension `count` does not cover.
                if count == 3 && values.len() > 4 {
                    out.power[4] = values[4] as i8;
                    out.count = 5;
                }
            }
            _ => {
                let out = if interpret == LOCAL_PSD {
                    &mut self.psd_local[category]
                } else {
                    &mut self.psd_client[category]
                };
                out.valid = true;
                if count == 0 {
                    out.power = [values[0] as i8; PSD_ENTRIES];
                    out.count = PSD_ENTRIES as u8;
                    return;
                }
                let n = 1 << (count - 1);
                signed(&values[..n], &mut out.power);
                out.count = n as u8;
                out.n = n as u8;
                if let Some(&extension) = values.get(n) {
                    let extra = usize::from(extension & 15).min(PSD_ENTRIES - n);
                    signed(&values[n + 1..n + 1 + extra], &mut out.power[n..]);
                    out.count += extra as u8;
                }
            }
        }
    }

    /// `ieee80211_rearrange_tpe`: the limits of `ap`'s channel, on the `used`
    /// part of it.
    pub fn fit(&mut self, ap: &ChannelDefinition, used: &ChannelDefinition) {
        let needed = widths(used);
        for category in 0..2 {
            self.psd_local[category].fit(ap, used);
            self.psd_client[category].fit(ap, used);
            for eirp in [
                &mut self.max_local[category],
                &mut self.max_client[category],
            ] {
                eirp.count = eirp.count.min(needed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wifi::{Band, Channel};

    /// A channel of `width` centred at `center`, whose control is `control`.
    fn definition(control: u16, width: Width, center: u32) -> ChannelDefinition {
        ChannelDefinition {
            control: Channel {
                band: Band::Ghz6,
                number: control,
                frequency_mhz: 5950 + 5 * control,
            },
            width,
            center1_mhz: center,
            center2_mhz: None,
            punctured: 0,
        }
    }

    #[test]
    fn nothing_limits_a_beacon_without_an_envelope() {
        assert_eq!(PowerEnvelope::parse(&[0, 1, b'a']), PowerEnvelope::none());
    }

    #[test]
    fn eirp_takes_each_width_and_the_320_mhz_extension() {
        let envelope = PowerEnvelope::parse(&[195, 6, 3, 1, 2, 3, 4, 5]);
        assert_eq!(envelope.max_local[0].power, [1, 2, 3, 4, 5]);
        assert_eq!(envelope.max_local[0].count, 5);
        let client = PowerEnvelope::parse(&[195, 2, 2 << 3, 0xf8]);
        assert_eq!(client.max_client[0].power, [-8, 127, 127, 127, 127]);
        assert_eq!(client.max_local, [EIRP; 2]);
    }

    #[test]
    fn one_psd_value_covers_the_whole_channel() {
        let envelope = PowerEnvelope::parse(&[195, 2, 1 << 3, 20]);
        assert_eq!(envelope.psd_local[0].power, [20; PSD_ENTRIES]);
    }

    #[test]
    fn a_short_or_unknown_envelope_is_ignored() {
        for element in [
            &[195, 1, 1][..],
            &[195, 2, 3 << 6, 1],
            &[195, 2, (1 << 3) | 2, 1],
            &[195, 2, 4 << 3, 1],
            &[195, 4, (1 << 3) | 1, 1, 3, 2],
        ] {
            assert_eq!(PowerEnvelope::parse(element), PowerEnvelope::none());
        }
    }

    #[test]
    fn subordinate_limits_stay_apart_from_the_default() {
        let envelope = PowerEnvelope::parse(&[195, 2, 1 << 6, 7]);
        assert_eq!(envelope.max_local[0], EIRP);
        assert_eq!(envelope.max_local[1].power[0], 7);
    }

    /// An 80 MHz HE part, then the rest of its 160 MHz. Control channel 5 lies
    /// in the lower 80 MHz of channels 1 to 29.
    #[test]
    fn the_he_part_returns_to_its_place_in_the_used_channel() {
        let ap = definition(5, Width::Mhz160, 6025);
        let mut element = vec![195, 11, (1 << 3) | 3];
        element.extend([0, 1, 2, 3, 4, 4, 5, 6, 7]);
        element[1] = element.len() as u8 - 2;
        let mut envelope = PowerEnvelope::parse(&element);
        envelope.fit(&ap, &ap);
        assert_eq!(envelope.psd_local[0].power[..8], [0, 1, 2, 3, 4, 5, 6, 7]);

        let used = definition(5, Width::Mhz80, 5985);
        let mut envelope = PowerEnvelope::parse(&element);
        envelope.fit(&ap, &used);
        assert_eq!(envelope.psd_local[0].power[..4], [0, 1, 2, 3]);
        assert_eq!(envelope.psd_local[0].power[4], NO_LIMIT);
    }

    #[test]
    fn the_used_half_can_be_the_upper_one() {
        let ap = definition(17, Width::Mhz160, 6025);
        assert_eq!(offset(&ap, 4), 4);
        let mut element = vec![195, 0, (1 << 3) | 3];
        element.extend([10, 11, 12, 13, 4, 20, 21, 22, 23]);
        element[1] = element.len() as u8 - 2;
        let mut envelope = PowerEnvelope::parse(&element);
        envelope.fit(&ap, &ap);
        assert_eq!(
            envelope.psd_local[0].power[..8],
            [20, 21, 22, 23, 10, 11, 12, 13]
        );
    }

    #[test]
    fn eirp_counts_stop_at_the_used_width() {
        let ap = definition(5, Width::Mhz160, 6025);
        let used = definition(5, Width::Mhz20, 5975);
        let mut envelope = PowerEnvelope::parse(&[195, 5, 3, 1, 2, 3, 4]);
        envelope.fit(&ap, &used);
        assert_eq!(envelope.max_local[0].count, 1);
    }
}
