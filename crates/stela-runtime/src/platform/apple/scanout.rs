//! The host scanout a completed DCP swap is presented to: one fixed virtual
//! monitor whose pixels the boot crate copies to the UEFI GOP framebuffer
//! (`crates/stela-boot/src/engine/display.rs`).
//!
//! The DCP model terminates the J473AP display pipeline at the AP boundary:
//! it has no real display controller to scan a surface out of DRAM, so a
//! completed swap's front surface is read through its DART (dart-dispext0)
//! and handed to a [`Scanout`] the host implements. A swap completes only
//! after the scanout has consumed the pixels, so the guest never recycles a
//! surface the host is still reading (the DCP's own swap-complete contract).
//!
//! The model converts the surface's pixel format to the scanout's and honors
//! its row stride; a format the model cannot convert is refused explicitly
//! rather than presented as garbage.
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// A 32-bit surface pixel format the model converts from. The DCP driver's
/// default framebuffer is one of these at the GOP resolution; other formats
/// are refused (`IOMFB::getPixelDef`, `swap_submit_dcp` `SurfaceContents`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    /// 8:8:8:8 with blue in the low byte of the little-endian pixel
    /// (`'BGRA'`, XNU's x8r8g8b8 boot framebuffer order).
    Bgra8888,
    /// 8:8:8:8 with red in the low byte (`'RGBA'`).
    Rgba8888,
}

impl PixelFormat {
    /// The IOSurface pixel-format four-character code, as the driver's
    /// `SurfaceContents` carries it (big-endian 4CC in a host `u32`).
    pub const fn fourcc(self) -> u32 {
        match self {
            // 'BGRA' and 'RGBA', the codes `IOMFB::getPixelDef` maps for the
            // 32-bit default framebuffer.
            PixelFormat::Bgra8888 => u32::from_be_bytes(*b"BGRA"),
            PixelFormat::Rgba8888 => u32::from_be_bytes(*b"RGBA"),
        }
    }

    /// The format of a surface four-character code, or `None` when the model
    /// does not convert it.
    pub fn from_fourcc(code: u32) -> Option<Self> {
        [PixelFormat::Bgra8888, PixelFormat::Rgba8888]
            .into_iter()
            .find(|format| format.fourcc() == code)
    }
}

/// The host surface the scanout presents to: a fixed mode, 32 bits per pixel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mode {
    pub width: u32,
    pub height: u32,
    /// The scanout's own pixel order; converted-to from the surface's.
    pub format: PixelFormat,
}

/// The host's presentation sink. The boot crate implements it over the GOP
/// framebuffer; a swap is presented one row at a time.
pub trait Scanout {
    /// The fixed mode the one connected monitor runs. The model's EDID and
    /// mode answers are this mode; a swap of another size is refused.
    fn mode(&self) -> Mode;
    /// Present one completed frame: `rows` are its pixels top to bottom, each
    /// `width` pixels of the scanout's format, already converted and clipped
    /// to the mode. Called once per completed swap, before the swap completes.
    fn present(&mut self, rows: &[u8]) -> Result<(), &'static str>;
}

/// One surface plane the model reads pixels from: its format, size and the
/// DART I/O address (DVA) of its top-left pixel. Built from the driver's
/// `SurfaceContents` (`IOMFB::DCP::SurfaceContents::from`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Surface {
    pub width: u32,
    pub height: u32,
    /// Bytes between the starts of successive rows.
    pub stride: u32,
    pub format: PixelFormat,
    /// The I/O address of the first pixel, in dart-dispext0's space.
    pub iova: u64,
}

/// Why a surface could not be presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresentError {
    /// The surface's mode differs from the scanout's fixed mode.
    Mode,
    /// The surface's pixel format is one the model does not convert.
    Format,
    /// The scanout refused the frame.
    Scanout(&'static str),
}

/// Convert `source` (one surface row, `width` pixels of `from`) into `out`
/// (the same pixels in `to`), in place of a copy when the formats match.
pub fn convert_row(
    source: &[u8],
    width: usize,
    from: PixelFormat,
    to: PixelFormat,
    out: &mut [u8],
) {
    let pixels = width.min(source.len() / 4).min(out.len() / 4);
    for pixel in 0..pixels {
        let bytes = &source[pixel * 4..pixel * 4 + 4];
        let value = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let converted = if from == to {
            value
        } else {
            // The two formats differ only in red/blue order; swap them and
            // keep the green and alpha bytes.
            value & 0xff00_ff00 | (value & 0xff) << 16 | (value >> 16) & 0xff
        };
        out[pixel * 4..pixel * 4 + 4].copy_from_slice(&converted.to_le_bytes());
    }
}

/// A frame built from a front surface for one [`Scanout::present`]: the
/// scanout mode's rows, converted and clipped. `read` fills a byte range of
/// the surface from its DART (returning false when any byte is not reachable).
pub fn frame(
    surface: &Surface,
    mode: Mode,
    mut read: impl FnMut(u64, &mut [u8]) -> bool,
) -> Result<Vec<u8>, PresentError> {
    if surface.width != mode.width || surface.height != mode.height {
        return Err(PresentError::Mode);
    }
    let out_row = mode.width as usize * 4;
    let mut out = alloc::vec![0u8; out_row * mode.height as usize];
    let mut source = alloc::vec![0u8; surface.stride as usize];
    for y in 0..mode.height as u64 {
        let iova = surface
            .iova
            .checked_add(y * u64::from(surface.stride))
            .ok_or(PresentError::Mode)?;
        if !read(iova, &mut source) {
            return Err(PresentError::Scanout(
                "surface row is not reachable through its DART",
            ));
        }
        let row = &mut out[y as usize * out_row..][..out_row];
        convert_row(
            &source,
            mode.width as usize,
            surface.format,
            mode.format,
            row,
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fourcc_round_trips_the_two_known_formats() {
        for format in [PixelFormat::Bgra8888, PixelFormat::Rgba8888] {
            assert_eq!(PixelFormat::from_fourcc(format.fourcc()), Some(format));
        }
        assert_eq!(PixelFormat::from_fourcc(u32::from_be_bytes(*b"420f")), None);
    }

    #[test]
    fn convert_swaps_red_and_blue_only_across_formats() {
        let source = 0x11_22_33_44u32.to_le_bytes();
        let mut out = [0u8; 4];
        convert_row(
            &source,
            1,
            PixelFormat::Bgra8888,
            PixelFormat::Bgra8888,
            &mut out,
        );
        assert_eq!(out, source);
        convert_row(
            &source,
            1,
            PixelFormat::Bgra8888,
            PixelFormat::Rgba8888,
            &mut out,
        );
        // byte 0 (0x44, blue) and byte 2 (0x22, red) swap; green/alpha hold.
        assert_eq!(u32::from_le_bytes(out), 0x11_44_33_22);
    }

    #[test]
    fn frame_reads_rows_at_the_stride_and_refuses_a_wrong_mode() {
        let mode = Mode {
            width: 2,
            height: 2,
            format: PixelFormat::Bgra8888,
        };
        let surface = Surface {
            width: 2,
            height: 2,
            stride: 16,
            format: PixelFormat::Bgra8888,
            iova: 0x1000,
        };
        // Two rows of two pixels at a 16-byte stride (8 used, 8 padding).
        let mut memory = alloc::vec![0u8; 0x2000];
        for (i, byte) in memory[0x1000..0x1000 + 8].iter_mut().enumerate() {
            *byte = i as u8;
        }
        for (i, byte) in memory[0x1010..0x1010 + 8].iter_mut().enumerate() {
            *byte = 0x80 + i as u8;
        }
        let pixels = frame(&surface, mode, |iova, buf| {
            let start = iova as usize;
            buf.copy_from_slice(&memory[start..start + buf.len()]);
            true
        })
        .unwrap();
        assert_eq!(&pixels[0..8], &memory[0x1000..0x1008]);
        assert_eq!(&pixels[8..16], &memory[0x1010..0x1018]);

        let wrong = Surface {
            width: 3,
            ..surface
        };
        assert_eq!(frame(&wrong, mode, |_, _| true), Err(PresentError::Mode));
    }

    #[test]
    fn frame_refuses_an_unreachable_surface() {
        let mode = Mode {
            width: 1,
            height: 1,
            format: PixelFormat::Bgra8888,
        };
        let surface = Surface {
            width: 1,
            height: 1,
            stride: 4,
            format: PixelFormat::Bgra8888,
            iova: 0,
        };
        assert!(matches!(
            frame(&surface, mode, |_, _| false),
            Err(PresentError::Scanout(_))
        ));
    }
}
