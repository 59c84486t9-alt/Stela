//! The one mode the modeled DCP advertises for its fixed, connected SDR
//! monitor, in the forms the 26A434 AP reads: the EDID base block, the
//! `IOAVVideoTimingData` and `IOAVVideoColorData` records `A364
//! getVideoDataForIDs` returns, and the serialized `TimingElements` and
//! `ColorElements` arrays the coprocessor publishes on the IOMFB service with
//! `D126`..`D128 setDCPAVPropStart/Chunk/End`.
//!
//! Every layout and key is the exact build's (kernel fileset offsets; VA =
//! offset + 0xfffffe0007004000), from the IOAVFamily code that serializes
//! the same elements:
//!
//! - `IOAVVideoTimingElement::initWithDetailedTiming` (0x39671ac) decodes an
//!   EDID detailed timing into the 0x50-byte timing record (flags +0, the
//!   horizontal axis +0x4 and the vertical +0x24, each `{total, active, sync
//!   width, back porch, front porch, precise sync rate 16.16, sync polarity,
//!   pixel repetition}`, the pixel clock in Hz +0x44, the aspect ratio +0x48,
//!   the scan information +0x4c); `_IOAVVideoTimingSetPixelClock` (0x3973970)
//!   and `_IOAVVideoTimingUpdateSyncRates` (0x39739b0) derive both sync rates;
//!   `_IOAVVideoActiveFormatAspectRatio` (0x396fad4, table `arRef` 0xa52edc)
//!   picks the aspect-ratio code nearest the precise ratio.
//!   `restored_external`'s own `timing_data_struct` log reads the same
//!   offsets (active +0x28 / +0x8, interlaced +0 bit 0, clock +0x44, ratio
//!   +0x48, scan +0x4c).
//! - `IOAVVideoColorElement::withCapabilities` (0x3965c60) packs the 0x20-byte
//!   color record: depth (bits per component) +0, pixel encoding +4, dynamic
//!   range +8, colorimetry +0xc, EOTF +0x10, the supports-DSC byte +0x14.
//! - `IOAVElement::copyProperties` (0x39a31e4: `Score` 32-bit when not
//!   virtual, `ID` 64-bit, `IsVirtual`), `IOAVVideoTimingElement::
//!   copyProperties` (0x39acfec) with `IOAVVideoTimingAxisCopy` (0x3970928),
//!   and `IOAVVideoColorElement::copyProperties` (0x3966258) give the keys and
//!   their widths. The enumerations are the IOAV string tables
//!   (`_IOAVVideoPixelEncodingString` 0x396ed34 → 0 "RGB 4:4:4",
//!   `_IOAVVideoColorEOTFString` → 0 "Traditional gamma (SDR)",
//!   `_IOAVVideoColorDynamicRangeString` → 0 "Full", `_IOAVVideoColorimetryString`
//!   → 10 "sRGB", `_IOAVVideoTimingTypeString` → 3 "Detailed",
//!   `_IOAVStandardTypeString` → 1 "VESA", `_IOAVElementTypeString` → 0
//!   "Video Timing", 1 "Video Color").
//! - The scores follow `IOAVVideoTimingElement::setScoreOffsetMask` (0x3967004)
//!   with no offset bits and `__scoreColorData` (0x3965cc0, stored
//!   `* 1000 + 999` by `initWithData` 0x3965b2c). The firmware's own offset
//!   mask is not pinned; with one advertised timing the score only has to be
//!   positive, which `restored_external` requires (it keeps the timing whose
//!   `Score` exceeds the best so far, starting from 0).
//!
//! The timing's standard type (VESA, an EDID base-block timing without a CEA
//! extension), its being preferred and the color's sRGB colorimetry (the EDID
//! declares sRGB its default color space) are Inferred from the EDID the
//! model serves; docs/research/display-gpu.md section 8.6 is the row.
use super::super::scanout::Mode;
use crate::Result;
use alloc::string::String;
use core::fmt::Write;
use stela_contracts::refuse;

/// The timing element's ID. `IOMobileFramebufferShim::set_digital_out_mode`
/// (0x2a66aac) treats timing IDs in 500..=10027 as display-wall modes, so
/// the single-display ID lies outside them.
pub const TIMING_ID: u32 = 1;
/// The color element's ID (a separate namespace: `getVideoDataForIDs` takes
/// both).
pub const COLOR_ID: u32 = 2;
/// `sizeof(IOAVVideoTimingData)`: the `ElementData` restored copies and
/// `A364`'s first argument.
pub const TIMING_BYTES: usize = 0x50;
/// `sizeof(IOAVVideoColorData)`: `A364`'s second argument.
pub const COLOR_BYTES: usize = 0x20;
/// The refresh rate the EDID's detailed timing is built for.
const REFRESH: u32 = 60;

/// `IOAVVideoPixelEncoding` RGB 4:4:4.
const RGB_444: u32 = 0;
/// `IOAVVideoColorDynamicRange` full.
const FULL_RANGE: u32 = 0;
/// `IOAVVideoColorEOTF` traditional gamma (SDR).
const SDR: u32 = 0;
/// `IOAVVideoColorimetry` sRGB.
const SRGB: u32 = 10;
/// `IOAVStandardType` VESA.
const VESA: u32 = 1;
/// `IOAVVideoTimingType` detailed.
const DETAILED: u32 = 3;
/// `IOAVElementType` video timing and video color.
const TIMING_ELEMENT: u32 = 0;
const COLOR_ELEMENT: u32 = 1;
/// 8 bits per component.
const DEPTH: u32 = 8;

/// `IOAVVideoActiveFormatAspectRatio::arRef` (0xa52edc): each code's
/// width/height as 16.16, ascending.
const ASPECT_RATIOS: [(u32, u32); 18] = [
    (0x6c00, 1),
    (0x8700, 2),
    (0x9000, 3),
    (0x999a, 4),
    (0xa000, 5),
    (0xa492, 6),
    (0xc000, 7),
    (0xcccd, 8),
    (0x10000, 9),
    (0x14000, 10),
    (0x15555, 11),
    (0x18e39, 12),
    (0x1999a, 13),
    (0x1aaab, 14),
    (0x1c71c, 15),
    (0x1e574, 16),
    (0x25ed1, 17),
    (0x3097b, 0),
];

/// Nominal CVT-style blanking of the advertised timing.
const H_FRONT: u32 = 48;
const H_SYNC: u32 = 32;
const H_BLANK: u32 = 320;
const V_FRONT: u32 = 3;
const V_SYNC: u32 = 10;
const V_BLANK: u32 = 45;

/// An 18-byte EDID detailed timing descriptor for `mode` at 60 Hz, digital
/// separate sync, both polarities positive. A mode whose fields do not fit
/// the descriptor refuses rather than wraps.
pub fn detailed_timing(mode: Mode) -> Result<[u8; 18]> {
    let (w, h) = (mode.width, mode.height);
    if w == 0 || h == 0 || w > 0xfff || h > 0xfff {
        return Err(refuse!("DCP mode does not fit an EDID detailed timing"));
    }
    let clock = u64::from(w + H_BLANK) * u64::from(h + V_BLANK) * u64::from(REFRESH) / 10_000;
    let clock = u16::try_from(clock)
        .ok()
        .filter(|&clock| clock != 0)
        .ok_or(refuse!(
            "DCP mode's pixel clock does not fit an EDID detailed timing"
        ))?;
    let mut d = [0u8; 18];
    d[0..2].copy_from_slice(&clock.to_le_bytes());
    d[2] = w as u8;
    d[3] = H_BLANK as u8;
    d[4] = (((w >> 8) << 4) | (H_BLANK >> 8)) as u8;
    d[5] = h as u8;
    d[6] = V_BLANK as u8;
    d[7] = (((h >> 8) << 4) | (V_BLANK >> 8)) as u8;
    d[8] = H_FRONT as u8;
    d[9] = H_SYNC as u8;
    d[10] = ((V_FRONT << 4) | V_SYNC) as u8;
    d[11] = 0;
    // Image size in mm (nominal), no borders.
    d[12] = (w / 4) as u8;
    d[13] = (h / 4) as u8;
    d[14] = ((((w / 4) >> 8) << 4) | ((h / 4) >> 8)) as u8;
    // Digital separate sync (bits 4:3), vsync and hsync positive.
    d[17] = 0x1e;
    Ok(d)
}

/// A truthful EDID 1.4 base block whose one detailed timing is `mode`'s.
pub fn edid(mode: Mode) -> Result<[u8; 128]> {
    let mut e = [0u8; 128];
    e[0..8].copy_from_slice(&[0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00]);
    // Manufacturer "STE" (Stela), product 1, serial 1, week 1, year 2026.
    let man = ((b'S' as u16 - 64) << 10) | ((b'T' as u16 - 64) << 5) | (b'E' as u16 - 64);
    e[8..10].copy_from_slice(&man.to_be_bytes());
    e[10..12].copy_from_slice(&1u16.to_le_bytes());
    e[12..16].copy_from_slice(&1u32.to_le_bytes());
    e[16] = 1;
    e[17] = 2026u16.wrapping_sub(1990) as u8;
    e[18] = 1; // EDID 1.4
    e[19] = 4;
    // Digital input, 8 bpc, DisplayPort.
    e[20] = 0xa5;
    e[21] = (mode.width / 100).min(255) as u8;
    e[22] = (mode.height / 100).min(255) as u8;
    e[23] = 0x78; // gamma 2.2
    e[24] = 0x06; // RGB, sRGB default color space, preferred timing native
    e[25..35].copy_from_slice(&[0xee, 0x91, 0xa3, 0x54, 0x4c, 0x99, 0x26, 0x0f, 0x50, 0x54]);
    e[54..72].copy_from_slice(&detailed_timing(mode)?);
    e[75] = 0xfc; // display name
    e[77..77 + 6].copy_from_slice(b"Stela\n");
    e[93] = 0xfd; // range limits
    e[95..95 + 6].copy_from_slice(&[0x32, 0x4b, 0x1e, 0x50, 0x11, 0x00]);
    e[101] = 0x0a;
    e[111] = 0x10; // dummy descriptor
    let sum = e[0..127].iter().fold(0u8, |a, b| a.wrapping_add(*b));
    e[127] = 0u8.wrapping_sub(sum);
    Ok(e)
}

fn put(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn get(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(data[at..at + 4].try_into().expect("4 bytes"))
}

/// The `IOAVVideoTimingData` of an EDID detailed timing, decoded as
/// `IOAVVideoTimingElement::initWithDetailedTiming` does.
pub fn timing_data(d: &[u8; 18]) -> Result<[u8; TIMING_BYTES]> {
    let clock = u32::from(u16::from_le_bytes([d[0], d[1]]));
    let interlaced = u32::from(d[17] >> 7);
    let h_active = u32::from(d[2]) | u32::from(d[4] >> 4) << 8;
    let h_blank = u32::from(d[3]) | u32::from(d[4] & 0xf) << 8;
    let h_front = u32::from(d[8]) | u32::from(d[11] >> 6 & 3) << 8;
    let h_sync = u32::from(d[9]) | u32::from(d[11] >> 4 & 3) << 8;
    let h_back = h_blank.checked_sub(h_front + h_sync).ok_or(refuse!(
        "DCP detailed timing's horizontal porches exceed its blanking"
    ))?;
    let field = |lines: u32| {
        if interlaced != 0 {
            lines * 2 + 1
        } else {
            lines
        }
    };
    let v_active = (u32::from(d[5]) | u32::from(d[7] >> 4) << 8) << interlaced;
    let v_front = field(u32::from(d[10] >> 4) | u32::from(d[11] >> 2 & 3) << 4);
    let v_sync = (u32::from(d[10] & 0xf) | u32::from(d[11] & 3) << 4) << interlaced;
    let v_blank = field(u32::from(d[6]) | u32::from(d[7] & 0xf) << 8);
    let v_back = v_blank.checked_sub(v_front + v_sync).ok_or(refuse!(
        "DCP detailed timing's vertical porches exceed its blanking"
    ))?;
    let mut t = [0u8; TIMING_BYTES];
    put(&mut t, 0x00, interlaced);
    for (axis, [total, active, sync, back, front]) in [
        (
            0x04,
            [h_active + h_blank, h_active, h_sync, h_back, h_front],
        ),
        (
            0x24,
            [v_active + v_blank, v_active, v_sync, v_back, v_front],
        ),
    ] {
        put(&mut t, axis, total);
        put(&mut t, axis + 0x4, active);
        put(&mut t, axis + 0x8, sync);
        put(&mut t, axis + 0xc, back);
        put(&mut t, axis + 0x10, front);
    }
    // Digital sync: bit 3 separate (vsync polarity bit 2) or composite.
    if d[17] & 0x10 != 0 {
        let h = u32::from(d[17] >> 1 & 1);
        let v = if d[17] & 0x8 == 0 {
            h
        } else {
            u32::from(d[17] >> 2 & 1)
        };
        put(&mut t, 0x1c, h);
        put(&mut t, 0x3c, v);
    }
    // _IOAVVideoTimingSetPixelClock, then _IOAVVideoTimingUpdateSyncRates.
    let pixel_clock = clock * 10_000;
    put(&mut t, 0x44, pixel_clock);
    let line = u64::from(get(&t, 0x04)) * u64::from(get(&t, 0x20) + 1);
    let frame = u64::from(get(&t, 0x24)) * line;
    if line == 0 || frame == 0 {
        return Err(refuse!("DCP detailed timing has no blanking totals"));
    }
    let q16 = u64::from(pixel_clock) << 16;
    let h_rate = (q16 + line * 500) / (line * 1000);
    let mut v_rate = (q16 + frame / 2) / frame;
    if interlaced != 0 {
        v_rate *= 2;
    }
    put(&mut t, 0x18, h_rate as u32);
    put(&mut t, 0x38, v_rate as u32);
    if v_rate == 0 || h_active == 0 || v_active == 0 {
        return Err(refuse!("DCP detailed timing has no active area or refresh"));
    }
    let ratio = aspect_ratio(precise_aspect_ratio(&t));
    put(&mut t, 0x48, ratio);
    Ok(t)
}

/// `getPreciseAspectRatio`: horizontal over vertical active, 16.16.
fn precise_aspect_ratio(t: &[u8; TIMING_BYTES]) -> u32 {
    ((u64::from(get(t, 0x08)) << 16) / u64::from(get(t, 0x28))) as u32
}

/// `_IOAVVideoActiveFormatAspectRatio`: the code of the nearest ratio.
fn aspect_ratio(precise: u32) -> u32 {
    let distance = |ratio: u32| ratio.abs_diff(precise);
    let mut best = ASPECT_RATIOS.len() - 1;
    for (index, &(ratio, _)) in ASPECT_RATIOS.iter().enumerate() {
        if distance(ratio) < distance(ASPECT_RATIOS[best].0) {
            best = index;
        }
    }
    ASPECT_RATIOS[best].1
}

/// The `IOAVVideoColorData` of the one color mode: RGB 4:4:4, 8 bits per
/// component, full range, SDR, sRGB, no DSC.
pub fn color_data() -> [u8; COLOR_BYTES] {
    let mut c = [0u8; COLOR_BYTES];
    put(&mut c, 0x00, DEPTH);
    put(&mut c, 0x04, RGB_444);
    put(&mut c, 0x08, FULL_RANGE);
    put(&mut c, 0x0c, SRGB);
    put(&mut c, 0x10, SDR);
    c
}

/// `setScoreOffsetMask(0)`: the active pixel clock in MHz, rounded, plus
/// the vertical sync rate, rounded.
fn timing_score(t: &[u8; TIMING_BYTES]) -> u32 {
    let active =
        (u64::from(get(t, 0x08)) * u64::from(get(t, 0x28)) * u64::from(get(t, 0x38))) >> 16;
    let active = (active / u64::from(get(t, 0x20) + 1)) >> (get(t, 0) & 1);
    let megahertz = (active + 500_000) / 1_000_000;
    let refresh = (get(t, 0x38) + 0x8000) >> 16;
    megahertz as u32 + refresh
}

/// `__scoreColorData` for 8-bit RGB 4:4:4 sRGB (depth 200, encoding 40,
/// colorimetry 2), stored as `score * 1000 + 999`.
const COLOR_SCORE: u32 = (200 + 40 + 2) * 1000 + 999;

/// An OSUnserializeXML document under construction.
struct Xml(String);

impl Xml {
    fn key(&mut self, key: &str) -> &mut Self {
        let _ = write!(self.0, "<key>{key}</key>");
        self
    }
    fn int(&mut self, key: &str, value: u64, bits: u32) -> &mut Self {
        self.key(key);
        let _ = write!(self.0, "<integer size=\"{bits}\">{value}</integer>");
        self
    }
    fn bool(&mut self, key: &str, value: bool) -> &mut Self {
        self.key(key);
        self.0.push_str(if value { "<true/>" } else { "<false/>" });
        self
    }
    fn data(&mut self, key: &str, bytes: &[u8]) -> &mut Self {
        self.key(key);
        self.0.push_str("<data>");
        base64(&mut self.0, bytes);
        self.0.push_str("</data>");
        self
    }
    fn raw(&mut self, text: &str) -> &mut Self {
        self.0.push_str(text);
        self
    }
}

fn base64(out: &mut String, bytes: &[u8]) {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for chunk in bytes.chunks(3) {
        let word = u32::from(chunk[0]) << 16
            | u32::from(*chunk.get(1).unwrap_or(&0)) << 8
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for index in 0..4 {
            if index <= chunk.len() {
                out.push(ALPHABET[(word >> (18 - 6 * index) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
}

/// The one color element's properties (`IOAVVideoColorElement::
/// copyProperties`).
fn color_dict(xml: &mut Xml) {
    xml.raw("<dict>")
        .int("Score", u64::from(COLOR_SCORE), 32)
        .int("ID", u64::from(COLOR_ID), 64)
        .bool("IsVirtual", false)
        .int("ElementType", u64::from(COLOR_ELEMENT), 32)
        .data("ElementData", &color_data())
        .int("Depth", u64::from(DEPTH), 32)
        .int("PixelEncoding", u64::from(RGB_444), 32)
        .int("DynamicRange", u64::from(FULL_RANGE), 32)
        .int("EOTF", u64::from(SDR), 32)
        .int("Colorimetry", u64::from(SRGB), 32)
        .bool("SupportsDSC", false)
        .int("StandardType", u64::from(VESA), 32)
        .raw("</dict>");
}

/// One axis's attributes (`IOAVVideoTimingAxisCopy`).
fn axis_dict(xml: &mut Xml, t: &[u8; TIMING_BYTES], axis: usize) {
    let precise = get(t, axis + 0x14);
    xml.raw("<dict>")
        .int("Total", u64::from(get(t, axis)), 32)
        .int("FrontPorch", u64::from(get(t, axis + 0x10)), 32)
        .int("SyncWidth", u64::from(get(t, axis + 0x8)), 32)
        .int("BackPorch", u64::from(get(t, axis + 0xc)), 32)
        .int("Active", u64::from(get(t, axis + 0x4)), 32)
        .int("SyncRate", u64::from((precise + 0x8000) & 0xffff_0000), 32)
        .int("PreciseSyncRate", u64::from(precise), 32)
        .int("SyncPolarity", u64::from(get(t, axis + 0x18)), 32)
        .int("PixelRepetition", u64::from(get(t, axis + 0x1c)), 32)
        .raw("</dict>");
}

/// The advertised mode: its EDID, records and published properties.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advertised {
    pub edid: [u8; 128],
    pub timing: [u8; TIMING_BYTES],
    pub color: [u8; COLOR_BYTES],
}

impl Advertised {
    /// The one mode for the scanout's `mode`, or why it cannot be
    /// advertised.
    pub fn new(mode: Mode) -> Result<Self> {
        let edid = edid(mode)?;
        let dtd: [u8; 18] = edid[54..72].try_into().expect("18 bytes");
        Ok(Self {
            edid,
            timing: timing_data(&dtd)?,
            color: color_data(),
        })
    }

    /// The video records for `(timing, color)` IDs, when both are the
    /// advertised ones.
    pub fn video_data(&self, timing: u32, color: u32) -> Option<(&[u8], &[u8])> {
        (timing == TIMING_ID && color == COLOR_ID).then_some((&self.timing[..], &self.color[..]))
    }

    /// The `TimingElements` array (`IOAVVideoTimingElement::copyProperties`
    /// of the one timing, its `ColorModes` the one color element).
    pub fn timing_elements(&self) -> String {
        let t = &self.timing;
        let mut xml = Xml(String::new());
        xml.raw("<array><dict>")
            .int("Score", u64::from(timing_score(t)), 32)
            .int("ID", u64::from(TIMING_ID), 64)
            .bool("IsVirtual", false)
            .int("ElementType", u64::from(TIMING_ELEMENT), 32)
            .data("ElementData", t)
            .key("ColorModes")
            .raw("<array>");
        color_dict(&mut xml);
        xml.raw("</array>")
            .bool("IsInterlaced", get(t, 0) & 1 != 0)
            .bool("IsSplit", get(t, 0) & 2 != 0)
            .bool("IsOverscanned", get(t, 0x4c) == 1)
            .bool("IsPreferred", true)
            .bool("IsPromoted", false)
            .int("ScanInformation", u64::from(get(t, 0x4c)), 32)
            .int("ValidPixelEncodings", 1 << RGB_444, 32)
            .int("StandardType", u64::from(VESA), 32)
            .int("TimingType", u64::from(DETAILED), 32)
            .int("AspectRatio", u64::from(get(t, 0x48)), 32)
            .int("PreciseAspectRatio", u64::from(precise_aspect_ratio(t)), 32)
            .key("HorizontalAttributes");
        axis_dict(&mut xml, t, 0x04);
        xml.key("VerticalAttributes");
        axis_dict(&mut xml, t, 0x24);
        xml.raw("</dict></array>");
        xml.0
    }

    /// The `ColorElements` array: the one color element.
    pub fn color_elements(&self) -> String {
        let mut xml = Xml(String::from("<array>"));
        color_dict(&mut xml);
        xml.raw("</array>");
        xml.0
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::scanout::PixelFormat;
    use super::*;

    const FULL_HD: Mode = Mode {
        width: 1920,
        height: 1080,
        format: PixelFormat::Bgra8888,
    };

    #[test]
    fn the_edid_is_well_formed_for_the_mode() {
        let e = edid(FULL_HD).unwrap();
        assert_eq!(&e[0..8], &[0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0]);
        assert_eq!(e.iter().fold(0u8, |a, b| a.wrapping_add(*b)), 0, "checksum");
        let dtd = &e[54..72];
        assert_eq!(u32::from(dtd[2]) | (u32::from(dtd[4] >> 4) << 8), 1920);
        // A mode the descriptor cannot hold refuses rather than wraps.
        let huge = Mode {
            width: 5120,
            ..FULL_HD
        };
        assert!(edid(huge).is_err());
    }

    #[test]
    fn the_timing_record_is_the_ioav_decode_of_the_edid_timing() {
        let a = Advertised::new(FULL_HD).unwrap();
        let t = &a.timing;
        // 1920 + 320 by 1080 + 45 at 151.2 MHz: exactly 60 Hz, 67.5 kHz.
        assert_eq!(
            [
                get(t, 0x04),
                get(t, 0x08),
                get(t, 0x0c),
                get(t, 0x10),
                get(t, 0x14)
            ],
            [2240, 1920, 32, 240, 48]
        );
        assert_eq!(
            [
                get(t, 0x24),
                get(t, 0x28),
                get(t, 0x2c),
                get(t, 0x30),
                get(t, 0x34)
            ],
            [1125, 1080, 10, 32, 3]
        );
        assert_eq!(get(t, 0x44), 151_200_000);
        assert_eq!(get(t, 0x38), 60 << 16);
        assert_eq!(get(t, 0x18), 0x0043_8000);
        assert_eq!((get(t, 0x1c), get(t, 0x3c)), (1, 1));
        // 16:9 is code 15 (IOAV string table index 14 plus one).
        assert_eq!(get(t, 0x48), 15);
        assert_eq!(get(t, 0x4c), 0);
        // 124 MHz of active pixels at 60 Hz.
        assert_eq!(timing_score(t), 184);
    }

    #[test]
    fn the_color_record_packs_like_with_capabilities() {
        let c = color_data();
        assert_eq!(
            [
                get(&c, 0),
                get(&c, 4),
                get(&c, 8),
                get(&c, 0xc),
                get(&c, 0x10)
            ],
            [8, 0, 0, 10, 0]
        );
        assert!(c[0x14..].iter().all(|&byte| byte == 0));
    }

    #[test]
    fn video_data_answers_only_the_advertised_ids() {
        let a = Advertised::new(FULL_HD).unwrap();
        let (timing, color) = a.video_data(TIMING_ID, COLOR_ID).unwrap();
        assert_eq!((timing.len(), color.len()), (TIMING_BYTES, COLOR_BYTES));
        assert!(a.video_data(COLOR_ID, TIMING_ID).is_none());
        assert!(!(500..=10027).contains(&TIMING_ID));
    }

    #[test]
    fn the_properties_carry_the_keys_restore_reads() {
        let a = Advertised::new(FULL_HD).unwrap();
        let timings = a.timing_elements();
        for key in [
            "<key>ID</key><integer size=\"64\">1</integer>",
            "<key>Score</key><integer size=\"32\">184</integer>",
            "<key>ElementData</key><data>",
            "<key>ColorModes</key><array><dict>",
            "<key>Active</key><integer size=\"32\">1920</integer>",
            "<key>Active</key><integer size=\"32\">1080</integer>",
            "<key>SyncRate</key><integer size=\"32\">3932160</integer>",
            "<key>PixelEncoding</key><integer size=\"32\">0</integer>",
            "<key>Depth</key><integer size=\"32\">8</integer>",
            "<key>EOTF</key><integer size=\"32\">0</integer>",
            "<key>DynamicRange</key><integer size=\"32\">0</integer>",
        ] {
            assert!(timings.contains(key), "{key}");
        }
        assert!(timings.starts_with("<array><dict>") && timings.ends_with("</dict></array>"));
        let colors = a.color_elements();
        assert!(colors.contains("<key>ID</key><integer size=\"64\">2</integer>"));
        assert!(colors.contains("<key>Score</key><integer size=\"32\">242999</integer>"));
    }

    #[test]
    fn base64_pads_like_the_xml_data_element_expects() {
        let mut out = String::new();
        base64(&mut out, b"Man");
        base64(&mut out, b"Ma");
        base64(&mut out, b"M");
        assert_eq!(out, "TWFuTWE=TQ==");
    }
}
