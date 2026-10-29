//! `swap_submit_dcp`'s input and the surfaces it names.
//!
//! The layout is the exact build's (kernel fileset offsets, VA = offset +
//! 0xfffffe0007004000). `IOMobileFramebufferAP::swap_submit_dcp` (0x3d77298),
//! declared `(IOMFBSwapRec const*, IOSurface**, u64 const*, u64 const*,
//! IOSurface**, u64 const*, bool, double, u64, bool, unsigned int, bool*,
//! unsigned int const*, unsigned int*)`, zeroes its 0x1d30-byte input and
//! packs it with no interior alignment:
//!
//! | Offset | Field |
//! | --- | --- |
//! | 0x0 | `IOMFBSwapRec`, 0x6e0 bytes (one `memcpy`) |
//! | 0x6e0 | 4 `SurfaceContents`, 0x22c each (`SurfaceContents::from` 0x3dae3a4) |
//! | 0xf90 | the 4 surfaces' DVAs (u64) |
//! | 0xfb0 | 4 more u64, one per layer |
//! | 0xfd0 | 6 secondary `SurfaceContents` |
//! | 0x1cd8 | their 6 DVAs |
//! | 0x1d08 .. 0x1d22 | bool, double, u64, bool, u32, u32 |
//! | 0x1d22 | null flags: the record, the 4 surfaces (0x1d23), the 6 secondary surfaces (0x1d27), then the three scalar pointers |
//!
//! Its output (0xc) is the `bool*` and `unsigned int*` outs and the link
//! status `iomfb_status_from_link` (0x3d9cf30) converts.
//!
//! In the record (`IOMFB::swap_submit_with_tags` 0x3d71844 and the record
//! getters from 0x3dac62c): the swap id +0x98, the four surface IDs +0x9c,
//! the source rectangles +0xac and destination rectangles +0x10c (four
//! `IOMFBRect {x, y, width, height}`, the `src_*`/`dst_*` keys of
//! `writeLayerDebugInfo` 0x3daa058) and the enable mask +0x14c, whose bit
//! `i` selects layer `i` (the AP tests bits 0..3 only). These match m1n1's
//! 14.7 `IOMFBSwapRec` at every offset the AP touches; m1n1's background
//! color at +0x154 is not referenced by the 26A434 AP and is read only to
//! refuse a non-black background, and the Linux driver's
//! `DCP_REMOVE_LAYERS` (bit 31: layers outside the mask are removed) is
//! honored as Linux defines it.
//!
//! `SurfaceContents::from` (0x3dae3a4) fills each record from the IOSurface's
//! accessors (its calls resolve through the kext's stubs to the named
//! `IOSurface` methods):
//!
//! | Offset | Field | Source |
//! | --- | --- | --- |
//! | 0x0 | tiled (u8) | `isTiled` |
//! | 0x1 | tearing allowed (u8) | `isTearingAllowed` |
//! | 0x2 | premultiplied (u8) | a `getBulkAttachments` byte masked with 0xfd is zero (Linux `is_premultiplied`) |
//! | 0x3, 0x7 | plane count (u32, twice) | `getPlaneCount` |
//! | 0xb | pixel format (CoreVideo 4CC; `'BGRA'` stored as the bytes `"ARGB"`) | `getPixelFormat` |
//! | 0xf | YCbCr matrix (u32) | `getYCbCrMatrix` |
//! | 0x13, 0x14 | transfer function, colour space (u8) | `getBulkAttachments` |
//! | 0x15 | bytes per row | `getBytesPerRow` |
//! | 0x19, 0x1b, 0x1c | bytes per element (u16), element width, height (u8) | `getBytesPerElement`, `getElementWidth`/`Height` |
//! | 0x1d | base offset | `getBaseOffset` |
//! | 0x21, 0x25 | width, height | `getWidth`, `getHeight` |
//! | 0x29 | allocation size | `getAllocSize` |
//! | 0x2d | protection options (u64) | `getProtectionOptions` |
//! | 0x35 | surface ID | `getSurfaceID` |
//! | 0x39 + 8i | plane i's component count (u8) and up to 7 component types | `getNumberOfComponentsOfPlane`, `getTypeOfComponentOfPlane` |
//! | 0x59 + 0x50i | plane i: width, height, base, offset, bytes per row, size (u32 each), bytes per element (u16), element width, height (u8), address format (u8 at +0x29) | `getPlane*`, `getPlaneAddressFormat` |
//! | 0x149 | has plane info (u64) | |
//! | 0x151 + 0x34i | plane i's compression info, repacked from `getCompressedPlaneInfo` | |
//! | 0x1ed | has compression info (u64) | |
//!
//! The model presents linear single-plane surfaces in the 32-bit formats
//! [`PixelFormat`] names. Tiled and compressed surfaces refuse: the
//! address-format and compression-info encodings are IOSurface-private and
//! unrecorded. Multi-planar YCbCr surfaces refuse: the `getYCbCrMatrix`
//! enumeration is unrecorded. The DVAs are I/O addresses in the display
//! pipe's DART (`dart-dispext0` stream 0 on J473AP), not the DCP's. Zero is
//! one of them: that DART's `vm-base` is 0, and `surface_map` (0x3d66a00)
//! stores the first `IODMACommand` segment's address, so the first surface
//! the restore UI maps is at DVA 0. Only the null flags say a layer is
//! absent.
pub use super::super::scanout::Rect;
use super::super::scanout::{PixelFormat, Surface};
use crate::Result;
use stela_contracts::refuse;

/// One `SurfaceContents` record.
pub const SURFACE_BYTES: usize = 0x22c;
/// The primary layers a swap carries.
pub const LAYERS: usize = 4;
/// The secondary surfaces a swap carries.
pub const SECONDARY: usize = 6;
/// `sizeof(IOMFBSwapRec)` on this interface.
pub const RECORD_BYTES: usize = 0x6e0;
/// `swap_submit_dcp`'s input size.
pub const SUBMIT_BYTES: usize = 0x1d30;

/// Input offsets of the packed arguments.
pub const SURFACES: usize = RECORD_BYTES;
pub const DVAS: usize = SURFACES + LAYERS * SURFACE_BYTES;
#[cfg(test)]
const LAYER_VALUES: usize = DVAS + LAYERS * 8;
#[cfg(test)]
pub const SECONDARY_SURFACES: usize = LAYER_VALUES + LAYERS * 8;
#[cfg(test)]
const SECONDARY_DVAS: usize = SECONDARY_SURFACES + SECONDARY * SURFACE_BYTES;
const RECORD_NULL: usize = 0x1d22;
pub const SURFACE_NULL: usize = RECORD_NULL + 1;
pub const SECONDARY_NULL: usize = SURFACE_NULL + LAYERS;

/// Record offsets.
pub const SWAP_ID: usize = 0x98;
pub const SOURCE_RECTS: usize = 0xac;
pub const DESTINATION_RECTS: usize = 0x10c;
pub const ENABLED: usize = 0x14c;
pub const BACKGROUND: usize = 0x154;
/// Linux `DCP_REMOVE_LAYERS`.
pub const REMOVE_LAYERS: u32 = 1 << 31;

/// Field offsets in a `SurfaceContents` record.
const IS_TILED: usize = 0x0;
const PREMULTIPLIED: usize = 0x2;
const PLANE_COUNT: usize = 0x3;
const FORMAT: usize = 0xb;
const STRIDE: usize = 0x15;
const OFFSET: usize = 0x1d;
const WIDTH: usize = 0x21;
const HEIGHT: usize = 0x25;
const BUFFER_SIZE: usize = 0x29;
/// `has_compr_info` (a 64-bit bool) after the per-plane compression info.
const HAS_COMPRESSION: usize = 0x1ed;

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("4 bytes"))
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("8 bytes"))
}

/// One surface of a swap, as its record describes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record {
    pub tiled: bool,
    /// Whether the colour is premultiplied by alpha.
    pub premultiplied: bool,
    pub planes: u32,
    /// The CoreVideo fourcc as the record stores it.
    pub format: u32,
    pub stride: u32,
    pub offset: u32,
    pub width: u32,
    pub height: u32,
    pub buffer: u32,
    pub compressed: bool,
}

impl Record {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < SURFACE_BYTES {
            return Err(refuse!(
                "DCP SurfaceContents record is shorter than 0x22c bytes"
            ));
        }
        Ok(Self {
            tiled: bytes[IS_TILED] != 0,
            premultiplied: bytes[PREMULTIPLIED] != 0,
            planes: u32_at(bytes, PLANE_COUNT),
            format: u32_at(bytes, FORMAT),
            stride: u32_at(bytes, STRIDE),
            offset: u32_at(bytes, OFFSET),
            width: u32_at(bytes, WIDTH),
            height: u32_at(bytes, HEIGHT),
            buffer: u32_at(bytes, BUFFER_SIZE),
            compressed: u64_at(bytes, HAS_COMPRESSION) != 0,
        })
    }

    /// The linear 32-bit surface this record names at `dva`, or why the
    /// model cannot scan it out. Tiled, compressed, multi-planar and other
    /// formats refuse rather than present garbage.
    pub fn surface(&self, dva: u64) -> Result<Surface> {
        if self.tiled {
            return Err(refuse!(
                "DCP swap surface is tiled; the model scans out linear surfaces only"
            ));
        }
        if self.compressed {
            return Err(refuse!(
                "DCP swap surface is compressed; the model scans out uncompressed only"
            ));
        }
        if self.planes > 1 {
            return Err(refuse!(
                "DCP swap surface is multi-planar; the model scans out one plane"
            ));
        }
        let format = PixelFormat::from_fourcc(self.format)
            .ok_or(refuse!("DCP swap surface format is not BGRA, RGBA or l10r"))?;
        if self.width == 0 || self.height == 0 {
            return Err(refuse!("DCP swap surface has no size"));
        }
        let row = self
            .width
            .checked_mul(4)
            .ok_or(refuse!("DCP swap surface row overflows"))?;
        if self.stride < row
            || u64::from(self.stride) * u64::from(self.height) > u64::from(self.buffer)
        {
            return Err(refuse!("DCP swap surface stride or size is inconsistent"));
        }
        Ok(Surface {
            width: self.width,
            height: self.height,
            stride: self.stride,
            format,
            iova: dva
                .checked_add(u64::from(self.offset))
                .ok_or(refuse!("DCP swap surface address overflows"))?,
        })
    }
}

/// The `IOMFBRect` at `at`.
fn rect_at(bytes: &[u8], at: usize) -> Rect {
    Rect {
        x: u32_at(bytes, at),
        y: u32_at(bytes, at + 4),
        width: u32_at(bytes, at + 8),
        height: u32_at(bytes, at + 12),
    }
}

/// One layer a swap supplies: its surface record, DVA and placement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layer {
    pub record: Record,
    pub dva: u64,
    pub source: Rect,
    pub destination: Rect,
}

/// A parsed `swap_submit_dcp` input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Submission {
    /// The record's swap id.
    pub swap_id: u32,
    /// The enable mask: bit `i` updates layer `i`.
    pub enabled: u32,
    /// The background color (m1n1 14.7 `bg_color`).
    pub background: u32,
    /// Each layer's surface, when its pointer is not null.
    pub layers: [Option<Layer>; LAYERS],
}

impl Submission {
    /// Parse `input`, refusing a shape the model does not present: a missing
    /// record, a secondary surface, enable bits outside layers 0..3 and
    /// `DCP_REMOVE_LAYERS`.
    pub fn parse(input: &[u8]) -> Result<Self> {
        if input.len() != SUBMIT_BYTES {
            return Err(refuse!("DCP swap_submit_dcp input is not 0x1d30 bytes"));
        }
        if input[RECORD_NULL] != 0 {
            return Err(refuse!("DCP swap_submit_dcp carries no IOMFBSwapRec"));
        }
        if input[SECONDARY_NULL..SECONDARY_NULL + SECONDARY].contains(&0) {
            return Err(refuse!(
                "DCP swap carries a secondary surface, which the model does not compose"
            ));
        }
        let enabled = u32_at(input, ENABLED);
        if enabled & !(REMOVE_LAYERS | ((1 << LAYERS) - 1)) != 0 {
            return Err(refuse!(
                "DCP swap enables a layer outside the four the record carries"
            ));
        }
        let mut layers = [None; LAYERS];
        for (index, slot) in layers.iter_mut().enumerate() {
            if input[SURFACE_NULL + index] != 0 {
                continue;
            }
            let dva = u64_at(input, DVAS + index * 8);
            let at = SURFACES + index * SURFACE_BYTES;
            *slot = Some(Layer {
                record: Record::parse(&input[at..at + SURFACE_BYTES])?,
                dva,
                source: rect_at(input, SOURCE_RECTS + index * 16),
                destination: rect_at(input, DESTINATION_RECTS + index * 16),
            });
        }
        Ok(Self {
            swap_id: u32_at(input, SWAP_ID),
            enabled,
            background: u32_at(input, BACKGROUND),
            layers,
        })
    }

    /// The layer state after this swap, from the state before it: an
    /// enabled layer takes this swap's surface (or is removed when its
    /// pointer is null); with `DCP_REMOVE_LAYERS` the others are removed;
    /// otherwise they keep their surface.
    pub fn apply(&self, planes: &[Option<Layer>; LAYERS]) -> [Option<Layer>; LAYERS] {
        core::array::from_fn(|index| {
            if self.enabled & (1 << index) != 0 {
                self.layers[index]
            } else if self.enabled & REMOVE_LAYERS != 0 {
                None
            } else {
                planes[index]
            }
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use alloc::vec::Vec;

    pub fn record(width: u32, height: u32, format: PixelFormat) -> [u8; SURFACE_BYTES] {
        let mut bytes = [0u8; SURFACE_BYTES];
        bytes[PREMULTIPLIED] = 1;
        bytes[PLANE_COUNT..PLANE_COUNT + 4].copy_from_slice(&1u32.to_le_bytes());
        bytes[FORMAT..FORMAT + 4].copy_from_slice(&format.fourcc().to_le_bytes());
        bytes[STRIDE..STRIDE + 4].copy_from_slice(&(width * 4).to_le_bytes());
        bytes[WIDTH..WIDTH + 4].copy_from_slice(&width.to_le_bytes());
        bytes[HEIGHT..HEIGHT + 4].copy_from_slice(&height.to_le_bytes());
        bytes[BUFFER_SIZE..BUFFER_SIZE + 4].copy_from_slice(&(width * 4 * height).to_le_bytes());
        bytes
    }

    /// A `swap_submit_dcp` input as the AP packs it: every pointer null
    /// except the record and each `(layer, width, height, dva)`, whose
    /// rectangles cover the surface and a `screen` of the same size, all
    /// in the enable mask.
    pub fn submission(swap_id: u32, layers: &[(usize, u32, u32, u64)]) -> Vec<u8> {
        let mut input = alloc::vec![0u8; SUBMIT_BYTES];
        input[SWAP_ID..SWAP_ID + 4].copy_from_slice(&swap_id.to_le_bytes());
        input[SURFACE_NULL..SECONDARY_NULL + SECONDARY].fill(1);
        let mut enabled = 0u32;
        for &(layer, width, height, dva) in layers {
            enabled |= 1 << layer;
            input[SURFACE_NULL + layer] = 0;
            let at = SURFACES + layer * SURFACE_BYTES;
            input[at..at + SURFACE_BYTES].copy_from_slice(&record(
                width,
                height,
                PixelFormat::Bgra8888,
            ));
            input[DVAS + layer * 8..DVAS + layer * 8 + 8].copy_from_slice(&dva.to_le_bytes());
            for rects in [SOURCE_RECTS, DESTINATION_RECTS] {
                let at = rects + layer * 16;
                input[at + 8..at + 12].copy_from_slice(&width.to_le_bytes());
                input[at + 12..at + 16].copy_from_slice(&height.to_le_bytes());
            }
        }
        input[ENABLED..ENABLED + 4].copy_from_slice(&enabled.to_le_bytes());
        input
    }

    #[test]
    fn the_input_layout_adds_up_to_the_interface_size() {
        // The record, 4 surfaces, 4 + 4 u64, 6 surfaces, 6 DVAs, then
        // bool + double + u64 + bool + u32 + u32 = 0x1a bytes of scalars,
        // then 14 null flags: 0x1d30, A407's recorded input.
        assert_eq!(DVAS, 0xf90);
        assert_eq!(SECONDARY_SURFACES, 0xfd0);
        assert_eq!(SECONDARY_DVAS + SECONDARY * 8 + 0x1a, RECORD_NULL);
        assert_eq!(RECORD_NULL + 1 + LAYERS + SECONDARY + 3, SUBMIT_BYTES);
        assert_eq!(
            super::super::abi::method(b"A407").unwrap().input as usize,
            SUBMIT_BYTES
        );
    }

    #[test]
    fn the_surface_field_offsets_follow_surface_contents() {
        assert_eq!(FORMAT, 3 + 4 + 4);
        assert_eq!(HAS_COMPRESSION + 8, 0x1f5);
        let bytes = record(1920, 1080, PixelFormat::Bgra8888);
        // CoreVideo 'BGRA' stored little-endian reads "ARGB".
        assert_eq!(&bytes[FORMAT..FORMAT + 4], b"ARGB");
        let parsed = Record::parse(&bytes).unwrap();
        let surface = parsed.surface(0x4000).unwrap();
        assert_eq!(
            (surface.width, surface.stride, surface.iova),
            (1920, 7680, 0x4000)
        );
    }

    #[test]
    fn unsupported_surfaces_refuse() {
        let base = Record::parse(&record(8, 8, PixelFormat::Rgba8888)).unwrap();
        assert!(base.surface(0).is_ok());
        for bad in [
            Record {
                tiled: true,
                ..base
            },
            Record {
                compressed: true,
                ..base
            },
            Record { planes: 2, ..base },
            Record {
                format: u32::from_be_bytes(*b"420v"),
                ..base
            },
            Record { stride: 4, ..base },
            Record { buffer: 4, ..base },
            Record { width: 0, ..base },
        ] {
            assert!(bad.surface(0).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn layers_are_the_non_null_surfaces_with_their_rectangles() {
        let input = submission(7, &[(1, 4, 2, 0x8000)]);
        let parsed = Submission::parse(&input).unwrap();
        assert_eq!((parsed.swap_id, parsed.enabled), (7, 0b10));
        assert!(parsed.layers[0].is_none() && parsed.layers[2].is_none());
        let layer = parsed.layers[1].unwrap();
        assert_eq!((layer.record.width, layer.dva), (4, 0x8000));
        assert_eq!(layer.source, Rect::whole(4, 2));
        assert_eq!(layer.destination, Rect::whole(4, 2));
    }

    #[test]
    fn shapes_the_model_does_not_present_refuse() {
        let good = submission(1, &[(0, 4, 2, 0x8000)]);
        assert!(Submission::parse(&good).is_ok());
        assert!(Submission::parse(&good[..0x1000]).is_err());
        let mut no_record = good.clone();
        no_record[RECORD_NULL] = 1;
        assert!(Submission::parse(&no_record).is_err());
        let mut secondary = good.clone();
        secondary[SECONDARY_NULL + 2] = 0;
        assert!(Submission::parse(&secondary).is_err());
        let mut mask = good.clone();
        mask[ENABLED] = 0x10;
        assert!(Submission::parse(&mask).is_err());
        // DVA 0 is the first address of a DART whose vm-base is 0.
        let mut first = good;
        first[DVAS..DVAS + 8].fill(0);
        assert_eq!(Submission::parse(&first).unwrap().layers[0].unwrap().dva, 0);
    }

    #[test]
    fn the_mask_updates_removes_or_keeps_each_layer() {
        let first =
            Submission::parse(&submission(1, &[(0, 4, 2, 0x8000), (1, 4, 2, 0x9000)])).unwrap();
        let planes = first.apply(&[None; LAYERS]);
        assert!(planes[0].is_some() && planes[1].is_some());
        // Layer 0 only: layer 1 keeps its surface.
        let second = Submission::parse(&submission(2, &[(0, 4, 2, 0xa000)])).unwrap();
        let kept = second.apply(&planes);
        assert_eq!(kept[0].unwrap().dva, 0xa000);
        assert_eq!(kept[1].unwrap().dva, 0x9000);
        // Enabled with a null pointer removes; DCP_REMOVE_LAYERS removes the rest.
        let mut input = submission(3, &[(0, 4, 2, 0xb000)]);
        let mask = 0b11 | REMOVE_LAYERS;
        input[ENABLED..ENABLED + 4].copy_from_slice(&mask.to_le_bytes());
        let third = Submission::parse(&input).unwrap();
        let after = third.apply(&kept);
        assert_eq!(after[0].unwrap().dva, 0xb000);
        assert!(after[1].is_none() && after[2].is_none());
    }
}
