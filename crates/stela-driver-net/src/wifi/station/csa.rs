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
use super::power_envelope::PowerEnvelope;
use crate::Mac;
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
    /// What the new channel limits, unfitted, `csa_tpe`.
    pub envelope: PowerEnvelope,
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
    envelope: Option<&'a [u8]>,
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
                    255 if e.envelope.is_none() && sub.first() == Some(&195) => {
                        e.envelope = Some(&sub[1..])
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
        mu_edca_count: None,
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
        envelope: e
            .envelope
            .map_or_else(PowerEnvelope::none, PowerEnvelope::single),
    }))
}

/// Where an announcement came from, `ieee80211_csa_source`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Beacon,
    Protected,
    Unprotected,
}

/// An action frame's announcement.
pub struct Announcement<'a> {
    pub elements: &'a [u8],
    /// The frame's own Extended Channel Switch fields.
    pub extended: Option<[u8; 4]>,
    pub source: Source,
}

impl<'a> Announcement<'a> {
    /// The announcement in a Spectrum Management or (Protected Dual of) Public
    /// action frame's `body`.
    pub fn of(body: &'a [u8]) -> Option<Self> {
        let (elements, extended, source) = match body {
            [0, 4, elements @ ..] => (elements, None, Source::Protected),
            [9, 4, a, b, c, d, elements @ ..] => {
                (elements, Some([*a, *b, *c, *d]), Source::Protected)
            }
            [4, 4, a, b, c, d, elements @ ..] => {
                (elements, Some([*a, *b, *c, *d]), Source::Unprotected)
            }
            _ => return None,
        };
        Some(Self {
            elements,
            extended,
            source,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    /// Whatever times the move has yet to hear of it.
    Announced,
    /// Firmware knows, and starts it when it is due.
    Scheduled,
    /// Firmware started it, and the link follows.
    Started,
    /// `csa.waiting_bcn`.
    Moved,
}

/// `link->conf->csa_active`, and iwlwifi's `csa_count` and `csa_misbehave`.
#[derive(Clone, Copy, Debug)]
pub struct Switch {
    pub ap: Mac,
    pub announced: ChannelSwitch,
    pub progress: Progress,
    pub tsf: u32,
    /// `link->u.mgd.csa.time`.
    pub due: u64,
    /// When `csa_work` gives up on a long silence.
    pub silence_ends: Option<u64>,
    /// A later beacon's count for firmware.
    pub recount: Option<ChannelSwitch>,
    pub misbehaved: bool,
}

/// What an announcement asks of the station.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Announced {
    Nothing,
    Begin(ChannelSwitch),
    Recount(ChannelSwitch),
}

/// The part of `ieee80211_sta_process_chanswitch` every driver shares.
#[derive(Default)]
pub struct Watch {
    pub switch: Option<Switch>,
    /// `csa.blocked_tx`.
    pub blocked_tx: bool,
    /// `csa_connection_drop_work`.
    pub dropped: bool,
    /// No `abort_channel_switch`: an AP that withdraws its switch is followed
    /// all the same.
    pub committed: bool,
}

impl Watch {
    /// A switch is under way.
    pub fn moving(&self) -> bool {
        self.switch.is_some()
    }

    /// The AP asked for silence.
    pub fn silent(&self) -> bool {
        self.blocked_tx
    }

    pub fn drop_connection(&mut self) {
        self.dropped = true;
    }

    /// What an announcement of `ap` settles, with the link on `current`.
    pub fn announced(
        &mut self,
        ap: Mac,
        parsed: Result<Option<ChannelSwitch>, Refusal>,
        source: Source,
        current: &ChannelDefinition,
    ) -> Announced {
        if self.switch.is_some_and(|active| active.ap != ap) {
            return Announced::Nothing;
        }
        let switch = match parsed {
            Ok(switch) => switch,
            // An unprotected frame is not trusted to disconnect.
            Err(_) if source == Source::Unprotected => return Announced::Nothing,
            Err(refusal) => {
                self.dropped = true;
                self.blocked_tx = refusal.block_tx;
                return Announced::Nothing;
            }
        };
        if let Some(active) = &self.switch {
            if source != Source::Beacon {
                return Announced::Nothing;
            }
            if active.progress == Progress::Moved {
                // ieee80211_chswitch_post_beacon; a switch still announced
                // afterwards is a new one.
                self.switch = None;
                self.blocked_tx = false;
            } else if let Some(switch) = switch {
                return Announced::Recount(switch);
            } else {
                // ieee80211_sta_abort_chanswitch: the AP withdrew it.
                if !self.committed {
                    self.switch = None;
                    self.blocked_tx = false;
                }
                return Announced::Nothing;
            }
        }
        let Some(switch) = switch else {
            self.blocked_tx = false;
            return Announced::Nothing;
        };
        // It only quiets the station until a beacon confirms or refutes it.
        if source == Source::Unprotected {
            self.blocked_tx |= switch.block_tx;
            return Announced::Nothing;
        }
        if switch.definition.control.band != current.control.band {
            self.dropped = true;
            self.blocked_tx = switch.block_tx;
            return Announced::Nothing;
        }
        if switch.definition == *current && (!switch.block_tx || source != Source::Beacon) {
            return Announced::Nothing;
        }
        Announced::Begin(switch)
    }

    /// `iwl_mvm_channel_switch_rx_beacon`: a later beacon's count for firmware
    /// that takes one, and the end of an AP that counts backwards twice.
    pub fn recounted(&mut self, modifies: bool) {
        let Some(active) = &mut self.switch else {
            return;
        };
        let Some(recount) = active.recount.filter(|_| modifies) else {
            active.recount = None;
            return;
        };
        if recount.count >= active.announced.count && recount.block_tx {
            if active.misbehaved {
                self.dropped = true;
                self.switch = None;
                return;
            }
            active.misbehaved = true;
        }
        active.announced.count = recount.count;
    }
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
        assert_eq!(switch.envelope, PowerEnvelope::none());
        let mut wrapper = Vec::new();
        ie(&mut wrapper, 255, &[195, 0, 40]);
        ie(&mut e, 196, &wrapper);
        let limited = parse(&e, Frame::Beacon, None, Band::Ghz5, &n)
            .unwrap()
            .unwrap();
        assert_eq!(limited.envelope.max_local[0].limit(0), 20);
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

#[cfg(test)]
mod watching {
    use super::*;

    const AP: Mac = Mac([2, 0, 0, 0, 0, 3]);

    fn definition(band: Band, number: u16, frequency_mhz: u16) -> ChannelDefinition {
        ChannelDefinition {
            control: Channel {
                band,
                number,
                frequency_mhz,
            },
            width: Width::Mhz20,
            center1_mhz: u32::from(frequency_mhz),
            center2_mhz: None,
            punctured: 0,
        }
    }

    fn switch(definition: ChannelDefinition, block_tx: bool, count: u8) -> ChannelSwitch {
        ChannelSwitch {
            block_tx,
            count,
            definition,
            ap: definition,
            max_switch_time: 0,
            envelope: PowerEnvelope::none(),
        }
    }

    #[test]
    fn an_unprotected_announcement_only_quiets_until_a_beacon_answers() {
        let current = definition(Band::Ghz5, 36, 5180);
        let mut tracking = Watch::default();
        let target = switch(definition(Band::Ghz5, 40, 5200), true, 5);
        assert_eq!(
            tracking.announced(AP, Ok(Some(target)), Source::Unprotected, &current),
            Announced::Nothing
        );
        assert!(tracking.silent());
        assert_eq!(
            tracking.announced(AP, Ok(None), Source::Beacon, &current),
            Announced::Nothing
        );
        assert!(!tracking.silent());
        let refusal = Refusal {
            block_tx: true,
            error: Error::Unsupported("test"),
        };
        tracking.announced(AP, Err(refusal), Source::Unprotected, &current);
        assert!(!tracking.dropped, "it may not end the association");
    }

    #[test]
    fn a_protected_announcement_begins_and_never_recounts() {
        let current = definition(Band::Ghz5, 36, 5180);
        let mut tracking = Watch::default();
        let target = switch(definition(Band::Ghz5, 40, 5200), false, 5);
        assert_eq!(
            tracking.announced(AP, Ok(Some(target)), Source::Protected, &current),
            Announced::Begin(target)
        );
        let mut running = running(target, Progress::Scheduled);
        assert_eq!(
            running.announced(AP, Ok(Some(target)), Source::Protected, &current),
            Announced::Nothing
        );
        let same = switch(current, true, 5);
        assert_eq!(
            Watch::default().announced(AP, Ok(Some(same)), Source::Protected, &current),
            Announced::Nothing,
            "only a beacon quiets the channel the link is on"
        );
    }

    fn running(announced: ChannelSwitch, progress: Progress) -> Watch {
        Watch {
            blocked_tx: announced.block_tx,
            switch: Some(Switch {
                ap: AP,
                announced,
                progress,
                tsf: 0,
                due: 0,
                silence_ends: None,
                recount: None,
                misbehaved: false,
            }),
            ..Watch::default()
        }
    }

    const fn here() -> (u16, u16) {
        (36, 5180)
    }

    #[test]
    fn a_beacon_begins_a_switch_and_a_later_one_counts_it_down() {
        let current = definition(Band::Ghz5, here().0, here().1);
        let target = definition(Band::Ghz5, 40, 5200);
        let mut tracking = Watch::default();
        assert_eq!(
            tracking.announced(
                AP,
                Ok(Some(switch(target, false, 5))),
                Source::Beacon,
                &current
            ),
            Announced::Begin(switch(target, false, 5))
        );
        let mut tracking = running(switch(target, false, 5), Progress::Scheduled);
        assert_eq!(
            tracking.announced(
                AP,
                Ok(Some(switch(target, false, 4))),
                Source::Beacon,
                &current
            ),
            Announced::Recount(switch(target, false, 4))
        );
        let other = Mac([2, 0, 0, 0, 0, 4]);
        assert_eq!(
            tracking.announced(
                other,
                Ok(Some(switch(target, false, 4))),
                Source::Beacon,
                &current
            ),
            Announced::Nothing,
            "one link at a time"
        );
    }

    #[test]
    fn silence_ends_with_the_ap_withdrawing_or_being_heard_after_the_move() {
        let current = definition(Band::Ghz5, here().0, here().1);
        let target = definition(Band::Ghz5, 40, 5200);
        let mut withdrawn = running(switch(target, true, 5), Progress::Scheduled);
        assert!(withdrawn.silent());
        assert_eq!(
            withdrawn.announced(AP, Ok(None), Source::Beacon, &current),
            Announced::Nothing
        );
        assert!(!withdrawn.silent() && !withdrawn.moving());
        let mut heard = running(switch(target, true, 1), Progress::Moved);
        assert_eq!(
            heard.announced(AP, Ok(None), Source::Beacon, &target),
            Announced::Nothing
        );
        assert!(!heard.silent() && !heard.moving());
    }

    #[test]
    fn a_switch_to_another_band_or_refused_drops_the_connection() {
        let current = definition(Band::Ghz5, here().0, here().1);
        let target = definition(Band::Ghz2, 1, 2412);
        let mut tracking = Watch::default();
        tracking.announced(
            AP,
            Ok(Some(switch(target, true, 5))),
            Source::Beacon,
            &current,
        );
        assert!(tracking.dropped && tracking.silent());
        let mut tracking = Watch::default();
        let refusal = Refusal {
            block_tx: false,
            error: Error::Unsupported("test"),
        };
        tracking.announced(AP, Err(refusal), Source::Beacon, &current);
        assert!(tracking.dropped && !tracking.silent());
    }

    #[test]
    fn a_switch_to_the_same_channel_matters_only_when_it_silences() {
        let current = definition(Band::Ghz5, here().0, here().1);
        let mut tracking = Watch::default();
        assert_eq!(
            tracking.announced(
                AP,
                Ok(Some(switch(current, false, 5))),
                Source::Beacon,
                &current
            ),
            Announced::Nothing
        );
        assert_eq!(
            tracking.announced(
                AP,
                Ok(Some(switch(current, true, 5))),
                Source::Beacon,
                &current
            ),
            Announced::Begin(switch(current, true, 5))
        );
    }

    #[test]
    fn an_ap_that_keeps_raising_a_quiet_count_is_given_up_on() {
        let target = definition(Band::Ghz5, 40, 5200);
        let mut tracking = running(switch(target, true, 5), Progress::Scheduled);
        let raised = |tracking: &mut Watch, count| {
            if let Some(active) = &mut tracking.switch {
                active.recount = Some(switch(target, true, count));
            }
            tracking.recounted(true);
        };
        raised(&mut tracking, 5);
        assert!(!tracking.dropped);
        raised(&mut tracking, 5);
        assert!(tracking.dropped);
    }

    #[test]
    fn a_committed_switch_outlives_its_withdrawal() {
        let current = definition(Band::Ghz5, here().0, here().1);
        let target = definition(Band::Ghz5, 40, 5200);
        let mut watch = running(switch(target, true, 5), Progress::Announced);
        watch.committed = true;
        watch.announced(AP, Ok(None), Source::Beacon, &current);
        assert!(watch.moving() && watch.silent());
    }
}
