//! `swap_submit_dcp`'s input and the surfaces it names.
//!
//! Public layout (m1n1 `proxyclient/m1n1/fw/dcp/ipc.py`, `>= 14.7` branch of
//! `IOMobileFramebufferAP.swap_submit_dcp`; Asahi Linux
//! `drivers/gpu/drm/apple/iomfb_template.h` `dcp_swap_submit_req`): the
//! `IOMFBSwapRec`, four `IOSurface` records, their four DVAs, four more
//! 64-bit values, five further `IOSurface` records and their DVAs, then
//! scalars and the null flags. The surfaces' DVAs are I/O addresses in the
//! display pipe's DART (`dart-dispext0` stream 0 on J473AP), not the DCP's.
//!
//! The `IOSurface` record is 0x22c bytes from firmware 13.5 on (m1n1
//! `IOSurface`, Linux `dcp_surface` plus 47 bytes); this interface's
//! `A483 update_dfb(IOSurface*)` input, 0x230 = 0x22c plus its null byte
//! padded to 4, holds that size. The `IOMFBSwapRec` grew across releases
//! (0x468 bytes at 13.5, 0x508 at 14.7 in m1n1) and this interface's input
//! (0x1d30 bytes) matches neither, so [`SWAP_RECORD_BYTES`] stays unpinned
//! until a guest's own `swap_submit_dcp` payload, recorded in the display
//! log, pins it. Until then a submitted swap refuses by name.
use super::super::scanout::{PixelFormat, Surface};
use super::abi::Fields;

/// One `IOSurface` record (firmware >= 13.5).
pub const SURFACE_BYTES: usize = 0x22c;
/// The primary surfaces a swap carries (`SWAP_SURFACES`).
pub const LAYERS: usize = 4;

/// The `IOMFBSwapRec` size of interface 211, once pinned from an observed
/// payload (see the module comment).
pub const SWAP_RECORD_BYTES: Option<usize> = None;

/// Field offsets in an `IOSurface` record (m1n1 `IOSurface`): three bools,
/// `plane_cnt`, `plane_cnt2`, then the DCP fourcc of the format.
const IS_TILED: usize = 0x0;
const PLANE_COUNT: usize = 0x3;
const FORMAT: usize = 0xb;
const STRIDE: usize = 0x15;
const OFFSET: usize = 0x1d;
const WIDTH: usize = 0x21;
const HEIGHT: usize = 0x25;
const BUFFER_SIZE: usize = 0x29;
/// `has_compr_info` (a 64-bit bool) after the per-plane compression info.
const HAS_COMPRESSION: usize = 0x1ed;

/// One surface of a swap, as the record describes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record {
    pub tiled: bool,
    pub planes: u32,
    /// The DCP fourcc as the record stores it (Linux `DCP_FORMAT_BGRA` is
    /// the bytes `"ARGB"`, the `u32` `'BGRA'` big-endian).
    pub format: u32,
    pub stride: u32,
    pub offset: u32,
    pub width: u32,
    pub height: u32,
    pub buffer: u32,
    pub compressed: bool,
}

impl Record {
    pub fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < SURFACE_BYTES {
            return Err("DCP IOSurface record is shorter than 0x22c bytes");
        }
        let u32_at = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().expect("4 bytes"));
        Ok(Self {
            tiled: bytes[IS_TILED] != 0,
            planes: u32_at(PLANE_COUNT),
            format: u32_at(FORMAT),
            stride: u32_at(STRIDE),
            offset: u32_at(OFFSET),
            width: u32_at(WIDTH),
            height: u32_at(HEIGHT),
            buffer: u32_at(BUFFER_SIZE),
            compressed: u64::from_le_bytes(
                bytes[HAS_COMPRESSION..HAS_COMPRESSION + 8]
                    .try_into()
                    .expect("8 bytes"),
            ) != 0,
        })
    }

    /// The linear 32-bit surface this record names at `dva`, or why the
    /// model cannot scan it out. Tiled, compressed, multi-planar and other
    /// formats refuse rather than present garbage.
    pub fn surface(&self, dva: u64) -> Result<Surface, &'static str> {
        if self.tiled {
            return Err("DCP swap surface is tiled; the model scans out linear surfaces only");
        }
        if self.compressed {
            return Err("DCP swap surface is compressed; the model scans out uncompressed only");
        }
        if self.planes > 1 {
            return Err("DCP swap surface is multi-planar; the model scans out one plane");
        }
        let format = PixelFormat::from_fourcc(self.format)
            .ok_or("DCP swap surface format is not 32-bit BGRA or RGBA")?;
        if self.width == 0 || self.height == 0 {
            return Err("DCP swap surface has no size");
        }
        let row = self
            .width
            .checked_mul(4)
            .ok_or("DCP swap surface row overflows")?;
        if self.stride < row
            || u64::from(self.stride) * u64::from(self.height) > u64::from(self.buffer)
        {
            return Err("DCP swap surface stride or size is inconsistent");
        }
        Ok(Surface {
            width: self.width,
            height: self.height,
            stride: self.stride,
            format,
            iova: dva
                .checked_add(u64::from(self.offset))
                .ok_or("DCP swap surface address overflows")?,
        })
    }
}

/// The surfaces a `swap_submit_dcp` input enables, given the pinned
/// `IOMFBSwapRec` size: each primary layer whose DVA is nonzero, with its
/// record.
pub fn layers(
    input: &[u8],
    record: usize,
) -> Result<[Option<(Record, u64)>; LAYERS], &'static str> {
    let surfaces = record;
    let addresses = surfaces + LAYERS * SURFACE_BYTES;
    if addresses + LAYERS * 8 > input.len() {
        return Err("DCP swap_submit_dcp input is shorter than its surfaces");
    }
    let mut dvas = Fields::new(&input[addresses..]);
    let mut layers = [None; LAYERS];
    for (layer, slot) in layers.iter_mut().enumerate() {
        let dva = dvas.u64()?;
        if dva == 0 {
            continue;
        }
        let at = surfaces + layer * SURFACE_BYTES;
        *slot = Some((Record::parse(&input[at..at + SURFACE_BYTES])?, dva));
    }
    Ok(layers)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(width: u32, height: u32, format: PixelFormat) -> [u8; SURFACE_BYTES] {
        let mut bytes = [0u8; SURFACE_BYTES];
        bytes[PLANE_COUNT..PLANE_COUNT + 4].copy_from_slice(&1u32.to_le_bytes());
        bytes[FORMAT..FORMAT + 4].copy_from_slice(&format.fourcc().to_le_bytes());
        bytes[STRIDE..STRIDE + 4].copy_from_slice(&(width * 4).to_le_bytes());
        bytes[WIDTH..WIDTH + 4].copy_from_slice(&width.to_le_bytes());
        bytes[HEIGHT..HEIGHT + 4].copy_from_slice(&height.to_le_bytes());
        bytes[BUFFER_SIZE..BUFFER_SIZE + 4].copy_from_slice(&(width * 4 * height).to_le_bytes());
        bytes
    }

    #[test]
    fn the_surface_field_offsets_follow_the_public_record() {
        // Linux dcp_surface: 3 bools, plane_cnt, plane_cnt2, format, ...
        assert_eq!(FORMAT, 3 + 4 + 4);
        // m1n1 names the fields after has_compr_info unk_1f5/unk_1f9.
        assert_eq!(HAS_COMPRESSION + 8, 0x1f5);
        let bytes = record(1920, 1080, PixelFormat::Bgra8888);
        // DCP_FORMAT_BGRA is fourcc_code('A','R','G','B'): those bytes.
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
    fn layers_are_the_records_with_a_dva() {
        let record_bytes = 0x10;
        let mut input = alloc::vec![0u8; record_bytes + LAYERS * SURFACE_BYTES + LAYERS * 8];
        let second = record_bytes + SURFACE_BYTES;
        input[second..second + SURFACE_BYTES].copy_from_slice(&record(4, 2, PixelFormat::Bgra8888));
        let dvas = record_bytes + LAYERS * SURFACE_BYTES;
        input[dvas + 8..dvas + 16].copy_from_slice(&0x8000u64.to_le_bytes());
        let found = layers(&input, record_bytes).unwrap();
        assert!(found[0].is_none() && found[2].is_none());
        let (layer, dva) = found[1].unwrap();
        assert_eq!((layer.width, dva), (4, 0x8000));
        assert!(layers(&input[..dvas], record_bytes).is_err());
    }
}
