//! The host scanout a completed DCP swap is presented to: one fixed virtual
//! monitor whose pixels the boot crate copies to the UEFI GOP framebuffer
//! (`crates/stela-boot/src/engine/display.rs`).
//!
//! The DCP model terminates the J473AP display pipeline at the AP boundary:
//! it has no real display controller to scan a surface out of DRAM, so a
//! completed swap's layers are read through their DART (dart-dispext0),
//! composed ([`compose`]) and handed to a [`Scanout`] the host implements. A swap completes only
//! after the scanout has consumed the pixels, so the guest never recycles a
//! surface the host is still reading (the DCP's own swap-complete contract).
//!
//! The model converts each surface's pixel format to the scanout's and honors
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
    /// mode answers are this mode; swaps are composed onto it.
    fn mode(&self) -> Mode;
    /// Present one completed frame: `rows` are its pixels top to bottom, each
    /// `width` pixels of the scanout's format, already composed and clipped
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

/// A rectangle in pixels (`IOMFBRect`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

impl Rect {
    /// The rectangle at the origin of a `width` by `height` area.
    pub fn whole(width: u32, height: u32) -> Self {
        Self {
            x: 0,
            y: 0,
            width,
            height,
        }
    }

    /// Whether this rectangle has an area and lies inside a `width` by
    /// `height` area.
    fn inside(&self, width: u32, height: u32) -> bool {
        self.width != 0
            && self.height != 0
            && u64::from(self.x) + u64::from(self.width) <= u64::from(width)
            && u64::from(self.y) + u64::from(self.height) <= u64::from(height)
    }
}

/// One layer of a composed frame: a source rectangle of a surface shown in
/// a destination rectangle of the screen, its colour premultiplied by its
/// alpha or not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layer {
    pub surface: Surface,
    pub source: Rect,
    pub destination: Rect,
    pub premultiplied: bool,
}

impl Layer {
    /// A layer, or why its rectangles cannot be shown: a source outside its
    /// surface, or an empty destination. A destination reaching past the
    /// screen is clipped when composed.
    pub fn new(
        surface: Surface,
        source: Rect,
        destination: Rect,
        premultiplied: bool,
    ) -> Result<Self, &'static str> {
        if !source.inside(surface.width, surface.height) {
            return Err("layer source rectangle is empty or outside its surface");
        }
        if destination.width == 0 || destination.height == 0 {
            return Err("layer destination rectangle is empty");
        }
        Ok(Self {
            surface,
            source,
            destination,
            premultiplied,
        })
    }
}

/// `value * weight / 255`, rounded.
fn scale(value: u32, weight: u32) -> u32 {
    (value * weight + 127) / 255
}

/// Compose `layers`, bottom to top, over opaque black on `mode`'s screen and
/// return the frame for one [`Scanout::present`]: the mode's rows in its
/// pixel order, alpha opaque. `read` fills a byte range of a surface from
/// its DART (false when any byte is not reachable).
///
/// Each destination pixel takes the source pixel under its centre (nearest
/// neighbour), so an unscaled layer is copied exactly; a layer is blended
/// source-over, its colour taken as premultiplied or multiplied by its
/// alpha first. Over the opaque black background a premultiplied layer
/// shows its colour whatever its alpha.
pub fn compose(
    layers: &[Layer],
    mode: Mode,
    mut read: impl FnMut(u64, &mut [u8]) -> bool,
) -> Result<Vec<u8>, &'static str> {
    let (width, height) = (mode.width as usize, mode.height as usize);
    // Red, green and blue per pixel; the background is opaque black.
    let mut canvas = alloc::vec![[0u32; 3]; width * height];
    let mut row = Vec::new();
    for layer in layers {
        let (surface, source, destination) = (layer.surface, layer.source, layer.destination);
        let x_end =
            (u64::from(destination.x) + u64::from(destination.width)).min(mode.width.into());
        let y_end =
            (u64::from(destination.y) + u64::from(destination.height)).min(mode.height.into());
        row.resize(source.width as usize * 4, 0);
        for y in u64::from(destination.y)..y_end {
            let from_y = (2 * (y - u64::from(destination.y)) + 1) * u64::from(source.height)
                / (2 * u64::from(destination.height));
            let iova = (u64::from(source.y) + from_y)
                .checked_mul(surface.stride.into())
                .and_then(|offset| offset.checked_add(u64::from(source.x) * 4))
                .and_then(|offset| surface.iova.checked_add(offset))
                .ok_or("layer row address overflows")?;
            if !read(iova, &mut row) {
                return Err("surface row is not reachable through its DART");
            }
            for x in u64::from(destination.x)..x_end {
                let from_x = (2 * (x - u64::from(destination.x)) + 1) * u64::from(source.width)
                    / (2 * u64::from(destination.width));
                let pixel = &row[from_x as usize * 4..][..4];
                let (red, blue) = match surface.format {
                    PixelFormat::Bgra8888 => (pixel[2], pixel[0]),
                    PixelFormat::Rgba8888 => (pixel[0], pixel[2]),
                };
                let alpha = u32::from(pixel[3]);
                let out = &mut canvas[y as usize * width + x as usize];
                for (channel, value) in out.iter_mut().zip([red, pixel[1], blue]) {
                    let value = u32::from(value);
                    let value = if layer.premultiplied {
                        value
                    } else {
                        scale(value, alpha)
                    };
                    *channel = (value + scale(*channel, 255 - alpha)).min(255);
                }
            }
        }
    }
    Ok(canvas
        .into_iter()
        .flat_map(|[red, green, blue]| {
            let (low, high) = match mode.format {
                PixelFormat::Bgra8888 => (blue, red),
                PixelFormat::Rgba8888 => (red, blue),
            };
            [low as u8, green as u8, high as u8, 0xff]
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODE: Mode = Mode {
        width: 4,
        height: 2,
        format: PixelFormat::Bgra8888,
    };

    fn surface(width: u32, height: u32, stride: u32, iova: u64) -> Surface {
        Surface {
            width,
            height,
            stride,
            format: PixelFormat::Bgra8888,
            iova,
        }
    }

    /// A reader over `memory` from address 0.
    fn reader(memory: &[u8]) -> impl FnMut(u64, &mut [u8]) -> bool + '_ {
        |iova, bytes| {
            let start = iova as usize;
            bytes.copy_from_slice(&memory[start..start + bytes.len()]);
            true
        }
    }

    #[test]
    fn fourcc_round_trips_the_two_known_formats() {
        for format in [PixelFormat::Bgra8888, PixelFormat::Rgba8888] {
            assert_eq!(PixelFormat::from_fourcc(format.fourcc()), Some(format));
        }
        assert_eq!(PixelFormat::from_fourcc(u32::from_be_bytes(*b"420f")), None);
    }

    #[test]
    fn an_unscaled_layer_is_read_at_its_stride_and_copied() {
        // Two rows of four pixels at a 32-byte stride (16 used, 16 padding).
        let mut memory = alloc::vec![0u8; 0x2000];
        for (i, byte) in memory[0x1000..0x1010].iter_mut().enumerate() {
            *byte = if i % 4 == 3 { 0xff } else { i as u8 };
        }
        for (i, byte) in memory[0x1020..0x1030].iter_mut().enumerate() {
            *byte = if i % 4 == 3 { 0xff } else { 0x80 + i as u8 };
        }
        let surface = surface(4, 2, 32, 0x1000);
        let layer = Layer::new(surface, Rect::whole(4, 2), Rect::whole(4, 2), false).unwrap();
        let frame = compose(&[layer], MODE, reader(&memory)).unwrap();
        assert_eq!(&frame[0..16], &memory[0x1000..0x1010]);
        assert_eq!(&frame[16..32], &memory[0x1020..0x1030]);
        // The RGBA scanout swaps red and blue.
        let rgba = Mode {
            format: PixelFormat::Rgba8888,
            ..MODE
        };
        let frame = compose(&[layer], rgba, reader(&memory)).unwrap();
        assert_eq!(&frame[0..4], &[2, 1, 0, 0xff]);
    }

    #[test]
    fn layers_crop_scale_place_and_blend_bottom_to_top() {
        // Surface A, 2x1: a red then a green opaque pixel (BGRA bytes).
        let mut memory = alloc::vec![0u8; 0x3000];
        memory[0x1000..0x1008].copy_from_slice(&[0, 0, 0xff, 0xff, 0, 0xff, 0, 0xff]);
        // Surface B, 1x1: blue at half alpha, premultiplied (0x80 of 0xff).
        memory[0x2000..0x2004].copy_from_slice(&[0x80, 0, 0, 0x80]);
        let a = surface(2, 1, 8, 0x1000);
        let b = surface(1, 1, 4, 0x2000);
        // A's green pixel alone, scaled up to the whole screen; B's pixel
        // in the last column, reaching past the screen's right edge.
        let crop = Rect {
            x: 1,
            ..Rect::whole(1, 1)
        };
        let bottom = Layer::new(a, crop, Rect::whole(4, 2), true).unwrap();
        let place = Rect {
            x: 3,
            ..Rect::whole(2, 2)
        };
        let top = Layer::new(b, Rect::whole(1, 1), place, true).unwrap();
        let frame = compose(&[bottom, top], MODE, reader(&memory)).unwrap();
        let green = [0, 0xff, 0, 0xff];
        // Blue 0x80 plus half of green: 0xff * 0x7f / 0xff = 0x7f.
        let blended = [0x80, 0x7f, 0, 0xff];
        for y in 0..2 {
            for x in 0..4 {
                let want = if x == 3 { blended } else { green };
                assert_eq!(&frame[(y * 4 + x) * 4..][..4], &want, "{x},{y}");
            }
        }
        // Straight alpha multiplies the colour first; a 2x downscale takes
        // the pixel under each centre.
        let straight = Layer::new(b, Rect::whole(1, 1), Rect::whole(1, 1), false).unwrap();
        let frame = compose(&[straight], MODE, reader(&memory)).unwrap();
        assert_eq!(&frame[0..4], &[0x40, 0, 0, 0xff]);
        let down = Layer::new(a, Rect::whole(2, 1), Rect::whole(1, 1), true).unwrap();
        let frame = compose(&[down], MODE, reader(&memory)).unwrap();
        assert_eq!(&frame[0..4], &green);
    }

    #[test]
    fn bad_rectangles_and_unreachable_surfaces_refuse() {
        let surface = surface(2, 2, 8, 0);
        let outside = Rect {
            x: 1,
            ..Rect::whole(2, 2)
        };
        assert!(Layer::new(surface, outside, Rect::whole(2, 2), true).is_err());
        assert!(Layer::new(surface, Rect::whole(0, 2), Rect::whole(2, 2), true).is_err());
        assert!(Layer::new(surface, Rect::whole(2, 2), Rect::whole(2, 0), true).is_err());
        let layer = Layer::new(surface, Rect::whole(2, 2), Rect::whole(2, 2), true).unwrap();
        assert!(compose(&[layer], MODE, |_, _| false).is_err());
        // No layer: opaque black.
        let frame = compose(&[], MODE, |_, _| panic!("no surface is read")).unwrap();
        assert!(frame.chunks(4).all(|pixel| pixel == [0, 0, 0, 0xff]));
    }
}
