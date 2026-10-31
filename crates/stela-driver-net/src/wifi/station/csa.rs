// SPDX-License-Identifier: GPL-2.0-only
// Adapted from pinned Linux mac80211/spectmgmt.c and parse.c, and
// wireless/util.c and chan.c. Copyright 2007-2008 Intel Corporation;
// 2008 Johannes Berg; 2018-2026 Intel Corporation. Full source notices in
// THIRD_PARTY.md.
//! The current AP's channel switch announcements, parsed as mac80211's
//! `ieee80211_parse_ch_switch_ie` does. A parsed switch is an observation:
//! the new channel still needs the regulatory owner's admission.

use super::operations::{ChannelDefinition, HtOperation, Operations, VhtOperation, frequency};
use super::phy::{Error, Mode, Negotiated, Width};
use crate::wifi::{Band, Channel};

/// An announced switch the station can follow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelSwitch {
    /// Channel Switch Mode 1: no transmission until the switch.
    pub block_tx: bool,
    /// Target beacon transmission times until the switch.
    pub count: u8,
    /// The definition the station operates, narrowed to the association.
    pub definition: ChannelDefinition,
    /// The AP's own new definition.
    pub ap: ChannelDefinition,
    /// Max Channel Switch Time in TUs, zero when absent.
    pub max_switch_time: u32,
}

/// The frame the elements came from: an action frame carries the Wide
/// Bandwidth Channel Switch element bare, a beacon inside a Channel Switch
/// Wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Frame {
    Beacon,
    Action,
}

/// `cfg80211`'s minimum bandwidth limit for a width: 80+80 MHz needs 160.
fn limit(width: Width) -> u32 {
    match width {
        Width::Mhz20 => 20,
        Width::Mhz40 => 40,
        Width::Mhz80 => 80,
        Width::Mhz80P80 | Width::Mhz160 => 160,
        Width::Mhz320 => 320,
    }
}

#[derive(Default)]
struct Elements<'a> {
    csa: Option<&'a [u8]>,
    ecsa: Option<&'a [u8]>,
    secondary: Option<u8>,
    wide: Option<&'a [u8]>,
    indication: Option<&'a [u8]>,
    max_switch_time: Option<&'a [u8]>,
}

/// `ieee80211_bandwidth_indication_size_ok`: parameters, the EHT operation
/// information and, when flagged, the disabled subchannel bitmap.
fn indication(data: &[u8]) -> Option<&[u8]> {
    (data.len() >= 4 && (data[0] & 2 == 0 || data.len() >= 6)).then_some(data)
}

fn each<'a>(mut bytes: &'a [u8], mut f: impl FnMut(u8, &'a [u8])) {
    while let [id, len, rest @ ..] = bytes {
        let Some(data) = rest.get(..usize::from(*len)) else {
            return;
        };
        f(*id, data);
        bytes = &rest[data.len()..];
    }
}

impl<'a> Elements<'a> {
    /// The channel switch elements `ieee802_11_parse_elems` keeps for this
    /// mode; a wrongly sized element is absent.
    fn parse(bytes: &'a [u8], frame: Frame, mode: Mode) -> Self {
        let mut e = Self::default();
        each(bytes, |id, data| match id {
            37 if data.len() == 3 => e.csa = Some(data),
            60 if data.len() == 4 => e.ecsa = Some(data),
            62 if mode >= Mode::Ht && data.len() == 1 => e.secondary = Some(data[0]),
            194 if mode >= Mode::Vht && frame == Frame::Action && data.len() >= 3 => {
                e.wide = Some(data)
            }
            196 if mode >= Mode::Vht && frame == Frame::Beacon => {
                let (mut wide, mut bandwidth) = (None, None);
                each(data, |id, sub| match id {
                    194 if wide.is_none() => wide = Some(sub),
                    255 if bandwidth.is_none() && sub.first() == Some(&135) => {
                        bandwidth = Some(&sub[1..])
                    }
                    _ => {}
                });
                if let Some(wide) = wide.filter(|w| w.len() >= 3) {
                    e.wide = Some(wide);
                }
                if mode >= Mode::Eht
                    && let Some(b) = bandwidth.and_then(indication)
                {
                    e.indication = Some(b);
                }
            }
            255 => match data.split_first() {
                Some((52, time)) if time.len() == 3 => e.max_switch_time = Some(time),
                Some((135, b)) if mode >= Mode::Eht => {
                    if let Some(b) = indication(b) {
                        e.indication = Some(b);
                    }
                }
                _ => {}
            },
            _ => {}
        });
        e
    }
}

/// `ieee80211_operating_class_to_band`; 60 GHz has no channel here.
fn class_band(class: u8) -> Option<Result<Band, Error>> {
    match class {
        112 | 115..=130 => Some(Ok(Band::Ghz5)),
        131..=135 | 137 => Some(Ok(Band::Ghz6)),
        81..=84 => Some(Ok(Band::Ghz2)),
        180 => Some(Err(Error::Unsupported("60 GHz channel switch"))),
        _ => None,
    }
}

/// `ieee80211_operating_class_to_chandef`.
fn class_definition(class: u8, control: Channel) -> Option<ChannelDefinition> {
    if class_band(class)?.ok()? != control.band {
        return None;
    }
    let freq = u32::from(control.frequency_mhz);
    let offset = match freq {
        5955.. => freq - 5955,
        5745.. => freq - 5745,
        5180.. => freq - 5180,
        _ => 0,
    } / 20;
    let (width, center) = match class {
        81 | 82 | 115 | 118 | 121 | 124 | 125 | 131 | 136 => (Width::Mhz20, freq),
        83 | 116 | 119 | 122 | 126 => (Width::Mhz40, freq + 10),
        84 | 117 | 120 | 123 | 127 => (Width::Mhz40, freq - 10),
        132 => (Width::Mhz40, freq + 10 - (offset & 1) * 20),
        128 | 133 => (Width::Mhz80, freq + 30 - (offset & 3) * 20),
        129 | 134 => (Width::Mhz160, freq + 70 - (offset & 7) * 20),
        _ => return None,
    };
    Some(ChannelDefinition {
        control,
        width,
        center1_mhz: center,
        center2_mhz: None,
        punctured: 0,
    })
}

/// `wbcs_elem_to_chandef`: the Wide Bandwidth Channel Switch element's
/// definition, when valid.
fn wide_definition(wide: &[u8], control: Channel) -> Option<ChannelDefinition> {
    let center = |segment: u8| frequency(control.band, segment).ok();
    let mut d = ChannelDefinition {
        control,
        width: Width::Mhz40,
        center1_mhz: center(wide[1])?,
        center2_mhz: None,
        punctured: 0,
    };
    match wide[0] {
        2 => d.width = Width::Mhz160,
        3 => {
            d.width = Width::Mhz80P80;
            d.center2_mhz = Some(center(wide[2])?);
        }
        1 => {
            d.width = Width::Mhz80;
            if wide[2] != 0 {
                let diff = wide[1].abs_diff(wide[2]);
                if diff == 8 {
                    d.width = Width::Mhz160;
                    d.center1_mhz = center(wide[2])?;
                } else if diff > 8 {
                    d.width = Width::Mhz80P80;
                    d.center2_mhz = Some(center(wide[2])?);
                }
            }
        }
        _ => {}
    }
    d.validate().ok().map(|()| d)
}

/// `ieee80211_chandef_eht_oper` over a Bandwidth Indication's information.
fn eht_definition(info: &[u8], mut d: ChannelDefinition) -> Option<ChannelDefinition> {
    let center = |segment: u8| frequency(d.control.band, segment).ok();
    d.center1_mhz = center(info[1])?;
    match info[0] & 7 {
        0 => d.width = Width::Mhz20,
        1 => d.width = Width::Mhz40,
        2 => d.width = Width::Mhz80,
        3 => {
            d.width = Width::Mhz160;
            d.center1_mhz = center(info[2])?;
        }
        4 => {
            d.width = Width::Mhz320;
            d.center1_mhz = center(info[2])?;
        }
        _ => {}
    }
    Some(d)
}

/// `validate_chandef_by_ht_vht_oper`: the definition as the HT and VHT
/// operation elements describing it, within the association's mode.
fn ht_vht(d: &ChannelDefinition, negotiated: &Negotiated) -> Option<ChannelDefinition> {
    if negotiated.mode < Mode::Ht || limit(negotiated.width) < 40 {
        return None;
    }
    let control = u32::from(d.control.frequency_mhz);
    let segment = |mhz: u32| {
        u8::try_from(match d.control.band {
            Band::Ghz2 => (mhz - 2407) / 5,
            Band::Ghz5 if mhz < 5000 => (mhz - 4000) / 5,
            _ => (mhz - 5000) / 5,
        })
        .ok()
    };
    let parameter = match control.cmp(&d.center1_mhz) {
        core::cmp::Ordering::Less => 1,
        core::cmp::Ordering::Greater => 3,
        core::cmp::Ordering::Equal => 0,
    };
    let mut center0 = segment(d.center1_mhz)?;
    let mut center1 = d.center2_mhz.map_or(Some(0), segment)?;
    let width = match d.width {
        Width::Mhz320 => return None,
        Width::Mhz160 => {
            center1 = center0;
            center0 = if control < d.center1_mhz {
                center0 - 8
            } else {
                center0 + 8
            };
            1
        }
        Width::Mhz80P80 | Width::Mhz80 => 1,
        _ => 0,
    };
    let operations = Operations {
        ht: Some(HtOperation {
            primary: d.control.number as u8,
            parameter,
            protection: 0,
            stbc: 0,
            basic_mcs: [0; 16],
        }),
        vht: Some(VhtOperation {
            width,
            center0,
            center1,
            basic_mcs: 0,
        }),
        he: None,
        eht: None,
        uora: None,
        mu_edca: None,
    };
    let caps = negotiated
        .local()
        .vht()
        .zip(negotiated.peer().vht())
        .map(|(local, peer)| (local.capability, peer.capability));
    operations
        .channel(d.control, negotiated.mode.min(Mode::Vht), caps)
        .ok()
}

/// `cfg80211_chandef_compatible`: identical, or the narrower one is the
/// wider one's primary part.
fn compatible(a: &ChannelDefinition, b: &ChannelDefinition) -> bool {
    if a == b {
        return true;
    }
    if a.control != b.control || a.width == b.width {
        return false;
    }
    let (narrow, mut wide) = if limit(a.width) < limit(b.width) || b.width == Width::Mhz80P80 {
        (*a, *b)
    } else {
        (*b, *a)
    };
    if narrow.width == Width::Mhz20 {
        return true;
    }
    if narrow.width == Width::Mhz80P80 {
        return false;
    }
    while limit(wide.width) > limit(narrow.width) && wide.downgrade() {}
    wide.width == narrow.width && wide.center1_mhz == narrow.center1_mhz
}

/// An announcement the station cannot follow, which mac80211 disconnects
/// for; `block_tx` is its Channel Switch Mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub block_tx: bool,
    pub error: Error,
}

/// `ieee80211_parse_ch_switch_ie` for the association's `negotiated`
/// operation on `band`: `Ok(None)` when no switch is announced.
/// `ecsa` is a public action frame's own Extended Channel Switch fields.
pub fn parse(
    elements: &[u8],
    frame: Frame,
    ecsa: Option<[u8; 4]>,
    band: Band,
    negotiated: &Negotiated,
) -> Result<Option<ChannelSwitch>, Refusal> {
    let mode = negotiated.mode;
    let e = Elements::parse(elements, frame, mode);
    let wide40 = mode >= Mode::Ht && limit(negotiated.width) >= 40;
    let mut secondary = e.secondary.filter(|_| wide40);
    let wide = e.wide.filter(|_| wide40 && mode >= Mode::Vht);
    let ecsa = ecsa.or_else(|| e.ecsa.map(|b| b.try_into().unwrap()));
    let mut new_band = Ok(band);
    let mut class = None;
    let mut announced = None;
    if let Some([switch_mode, op_class, number, count]) = ecsa
        && let Some(found) = class_band(op_class)
    {
        new_band = found;
        class = Some(op_class);
        announced = Some((switch_mode, number, count));
    }
    if class.is_none()
        && let Some(csa) = e.csa
    {
        announced = Some((csa[0], csa[1], csa[2]));
    }
    let Some((switch_mode, number, count)) = announced else {
        return Ok(None);
    };
    let refuse = |error| Refusal {
        block_tx: switch_mode != 0,
        error,
    };
    let new_band = new_band.map_err(refuse)?;
    let control = Channel {
        band: new_band,
        number: u16::from(number),
        frequency_mhz: frequency(new_band, number)
            .map_err(|_| refuse(Error::Invalid("channel switch target")))?
            as u16,
    };
    if secondary.is_none() && mode >= Mode::Ht {
        // Without the offset the post-switch width is unknown: 20 MHz.
        secondary = Some(0);
    }
    let freq = u32::from(control.frequency_mhz);
    let mut oper = ChannelDefinition {
        control,
        width: Width::Mhz20,
        center1_mhz: freq,
        center2_mhz: None,
        punctured: 0,
    };
    match secondary {
        Some(1) => {
            oper.width = Width::Mhz40;
            oper.center1_mhz = freq + 10;
        }
        Some(3) => {
            oper.width = Width::Mhz40;
            oper.center1_mhz = freq - 10;
        }
        _ => {}
    }
    let mut ap = oper;
    let new = if let Some(b) = e.indication {
        eht_definition(&b[1..4], oper).map(|mut d| {
            if b[0] & 2 != 0 {
                d.punctured = u16::from_le_bytes([b[4], b[5]]);
            }
            d
        })
    } else {
        wide.and_then(|w| wide_definition(w, control))
            .or_else(|| class.and_then(|c| class_definition(c, control)))
            .or(Some(oper))
    };
    // A 6 GHz target is a band change here, which mac80211 disconnects for:
    // associations never run on 6 GHz, so its HE operation is not checked.
    let new = new
        .filter(|_| new_band != Band::Ghz6)
        .and_then(|d| ht_vht(&d, negotiated));
    if let Some(mut d) = new {
        ap = d;
        while limit(negotiated.width) < limit(d.width) && d.downgrade() {}
        if !compatible(&d, &oper) {
            return Err(refuse(Error::Incompatible("channel switch definitions")));
        }
        oper = d;
    }
    Ok(Some(ChannelSwitch {
        block_tx: switch_mode != 0,
        count,
        definition: oper,
        ap,
        max_switch_time: e
            .max_switch_time
            .map_or(0, |t| u32::from_le_bytes([t[0], t[1], t[2], 0])),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wifi::station::{
        Action, Station,
        tests::{LOCAL, beacon, configuration, ie, modern_join},
    };
    use alloc::vec::Vec;

    fn negotiated() -> Negotiated {
        let mut s = Station::new(LOCAL).unwrap();
        let j = modern_join();
        let Action::Configure {
            context: Some(context),
            ..
        } = configuration(&mut s, j.clone(), beacon(&j)).unwrap()
        else {
            panic!("modern context required")
        };
        context.negotiated().clone()
    }

    fn channel(number: u8) -> Channel {
        Channel {
            band: Band::Ghz5,
            number: u16::from(number),
            frequency_mhz: frequency(Band::Ghz5, number).unwrap() as u16,
        }
    }

    #[test]
    fn channel_switch_elements_follow_ieee80211_parse_ch_switch_ie() {
        let n = negotiated();
        assert_eq!(n.width, Width::Mhz80);
        assert_eq!(parse(&[], Frame::Beacon, None, Band::Ghz5, &n), Ok(None));
        // CSA to 44 below its secondary, an 80 MHz wrapper and a 1000 TU
        // maximum switch time.
        let mut e = Vec::new();
        ie(&mut e, 37, &[1, 44, 5]);
        ie(&mut e, 62, &[1]);
        let mut wrapper = Vec::new();
        ie(&mut wrapper, 194, &[1, 42, 0]);
        ie(&mut e, 196, &wrapper);
        ie(&mut e, 255, &[52, 0xe8, 3, 0]);
        let switch = parse(&e, Frame::Beacon, None, Band::Ghz5, &n)
            .unwrap()
            .unwrap();
        assert!(switch.block_tx);
        assert_eq!(switch.count, 5);
        assert_eq!(switch.max_switch_time, 1000);
        let eighty = ChannelDefinition {
            control: channel(44),
            width: Width::Mhz80,
            center1_mhz: 5210,
            center2_mhz: None,
            punctured: 0,
        };
        assert_eq!(switch.definition, eighty);
        // The wrapper is a beacon's: an action frame ignores it, leaving
        // the secondary channel offset's 40 MHz.
        let switch = parse(&e, Frame::Action, None, Band::Ghz5, &n)
            .unwrap()
            .unwrap();
        assert_eq!(switch.definition.width, Width::Mhz40);
        assert_eq!(switch.definition.center1_mhz, 5230);
        // A public action frame's ECSA names operating class 128 (80 MHz)
        // without a secondary offset.
        let switch = parse(&[], Frame::Action, Some([0, 128, 149, 2]), Band::Ghz5, &n)
            .unwrap()
            .unwrap();
        assert!(!switch.block_tx);
        assert_eq!(switch.definition.width, Width::Mhz80);
        assert_eq!(switch.definition.center1_mhz, 5775);
        // A wider AP is followed within the association's 80 MHz.
        let mut e = Vec::new();
        ie(&mut e, 37, &[0, 36, 1]);
        ie(&mut e, 62, &[1]);
        ie(&mut e, 194, &[1, 42, 50]);
        let switch = parse(&e, Frame::Action, None, Band::Ghz5, &n)
            .unwrap()
            .unwrap();
        assert_eq!(switch.ap.width, Width::Mhz160);
        assert_eq!(switch.ap.center1_mhz, 5250);
        assert_eq!(switch.definition.width, Width::Mhz80);
        assert_eq!(switch.definition.center1_mhz, 5210);
        // Channel 40 above its secondary is not the primary 40 MHz of the
        // 80 MHz around 42: mac80211 disconnects.
        let mut e = Vec::new();
        ie(&mut e, 37, &[0, 40, 1]);
        ie(&mut e, 62, &[1]);
        ie(&mut e, 194, &[1, 42, 0]);
        assert!(
            parse(&e, Frame::Action, None, Band::Ghz5, &n).is_err_and(|refusal| !refusal.block_tx)
        );
        // An unknown operating class falls back to the CSA element.
        let mut e = Vec::new();
        ie(&mut e, 37, &[0, 48, 3]);
        ie(&mut e, 60, &[0, 200, 52, 3]);
        let switch = parse(&e, Frame::Beacon, None, Band::Ghz5, &n)
            .unwrap()
            .unwrap();
        assert_eq!(switch.definition.control, channel(48));
        assert_eq!(switch.definition.width, Width::Mhz20);
    }
}
