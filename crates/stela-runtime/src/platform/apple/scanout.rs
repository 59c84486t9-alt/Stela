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

/// A 32-bit pixel format: the scanout's (an 8-bit one) or a surface's the
/// model converts from. The DCP driver's default framebuffer is 8-bit at the
/// GOP resolution; other formats are refused (`IOMFB::getPixelDef`,
/// `swap_submit_dcp` `SurfaceContents`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    /// 8:8:8:8 with blue in the low byte of the little-endian pixel
    /// (`'BGRA'`, XNU's x8r8g8b8 boot framebuffer order).
    Bgra8888,
    /// 8:8:8:8 with red in the low byte (`'RGBA'`).
    Rgba8888,
    /// 2:10:10:10 with blue in the low bits and alpha in the top two
    /// (`'l10r'`, CoreVideo's `ARGB2101010LEPacked`; Linux maps DRM's
    /// `ARGB2101010`, the same bits, to this DCP format).
    Argb2101010,
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
            PixelFormat::Argb2101010 => u32::from_be_bytes(*b"l10r"),
        }
    }

    /// The format of a surface four-character code, or `None` when the model
    /// does not convert it.
    pub fn from_fourcc(code: u32) -> Option<Self> {
        [
            PixelFormat::Bgra8888,
            PixelFormat::Rgba8888,
            PixelFormat::Argb2101010,
        ]
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
    /// An error leaves presentation uncommitted; the owner may retry the same
    /// swap. Validate fallible inputs before publishing host-visible pixels.
    fn present(&mut self, rows: &[u8]) -> Result<(), &'static str>;
}

/// A host framebuffer's 32-bit pixel given as one bit mask per channel: the
/// UEFI GOP `PixelBitMask` mode (UEFI 2.10 section 12.9,
/// `EFI_PIXEL_BITMASK`), whose reserved bits the display ignores. A
/// blue-low pixel is re-encoded through it, each 8-bit channel widened by
/// repeating its high bits or narrowed to its high bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelMasks {
    /// Each of red, green and blue: its lowest bit and its width. They are
    /// bytes so that the boot crate's framebuffer description stays small:
    /// it travels in the one-page loader handoff.
    channels: [(u8, u8); 3],
}

impl ChannelMasks {
    /// The layout of `red`, `green` and `blue`. Each mask must be one
    /// contiguous run of at most 16 bits, and no two masks may overlap.
    pub fn new(red: u32, green: u32, blue: u32) -> Result<Self, &'static str> {
        if red & green != 0 || red & blue != 0 || green & blue != 0 {
            return Err("framebuffer channel masks overlap");
        }
        let channel = |mask: u32| {
            let shift = mask.trailing_zeros();
            let width = mask.count_ones();
            if mask == 0 || width > 16 || (mask >> shift).trailing_ones() != width {
                Err("framebuffer channel mask is not one contiguous run of 1 to 16 bits")
            } else {
                Ok((shift as u8, width as u8))
            }
        };
        Ok(Self {
            channels: [channel(red)?, channel(green)?, channel(blue)?],
        })
    }

    /// The pixel of 8-bit `red`, `green` and `blue`, its reserved bits zero.
    pub fn encode(&self, red: u8, green: u8, blue: u8) -> u32 {
        [red, green, blue]
            .into_iter()
            .zip(self.channels)
            .map(|(value, (shift, width))| {
                let (value, shift, width) = (u32::from(value), u32::from(shift), u32::from(width));
                let scaled = if width >= 8 {
                    value << (width - 8) | value >> (16 - width)
                } else {
                    value >> (8 - width)
                };
                scaled << shift
            })
            .fold(0, |pixel, channel| pixel | channel)
    }
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
    #[cfg(test)]
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

impl PixelFormat {
    /// The byte offsets of red and blue in an 8-bit format's pixel.
    const fn red_blue(self) -> Option<(usize, usize)> {
        match self {
            PixelFormat::Bgra8888 => Some((2, 0)),
            PixelFormat::Rgba8888 => Some((0, 2)),
            PixelFormat::Argb2101010 => None,
        }
    }

    /// A pixel's red, green, blue and alpha as 8-bit values; 10-bit
    /// components and 2-bit alpha are rescaled, rounded.
    fn rgba(self, pixel: [u8; 4]) -> [u8; 4] {
        match self {
            PixelFormat::Bgra8888 => [pixel[2], pixel[1], pixel[0], pixel[3]],
            PixelFormat::Rgba8888 => pixel,
            PixelFormat::Argb2101010 => {
                let value = u32::from_le_bytes(pixel);
                let ten = |shift: u32| (((value >> shift & 0x3ff) * 255 + 511) / 1023) as u8;
                [ten(20), ten(10), ten(0), (value >> 30) as u8 * 85]
            }
        }
    }
}

/// The screen part of `rect` on a `width` by `height` screen, as half-open
/// pixel ranges, or `None` when nothing is on screen.
fn on_screen(rect: Rect, width: u32, height: u32) -> Option<([usize; 2], [usize; 2])> {
    let end = |start: u32, length: u32, limit: u32| {
        (u64::from(start) + u64::from(length)).min(limit.into()) as usize
    };
    let x = [rect.x as usize, end(rect.x, rect.width, width)];
    let y = [rect.y as usize, end(rect.y, rect.height, height)];
    (x[0] < x[1] && y[0] < y[1]).then_some((x, y))
}

/// Copy `source` pixels of `from` into `out` in `to`, alpha made opaque.
fn copy_opaque(source: &[u8], out: &mut [u8], from: PixelFormat, to: PixelFormat) {
    let source = source.as_chunks::<4>().0;
    let out = out.as_chunks_mut::<4>().0;
    for (out, &pixel) in out.iter_mut().zip(source) {
        let value = u32::from_le_bytes(pixel) | 0xff00_0000;
        let value = if from == to {
            value
        } else {
            // The formats differ only in red/blue order.
            value & 0xff00_ff00 | (value & 0xff) << 16 | (value >> 16) & 0xff
        };
        *out = value.to_le_bytes();
    }
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
///
/// The frame is built in the scanout's byte order. An unscaled row is
/// copied whole when blending cannot change it: every pixel opaque, or a
/// premultiplied layer over screen no lower layer has drawn on (still
/// black).
pub fn compose(
    layers: &[Layer],
    mode: Mode,
    mut read: impl FnMut(u64, &mut [u8]) -> bool,
) -> Result<Vec<u8>, &'static str> {
    let width = mode.width as usize;
    let mut frame = [0, 0, 0, 0xff].repeat(width * mode.height as usize);
    let (red, blue) = mode
        .format
        .red_blue()
        .ok_or("scanout mode is not an 8-bit format")?;
    let mut row = Vec::new();
    let mut drawn: Vec<([usize; 2], [usize; 2])> = Vec::new();
    for layer in layers {
        let (surface, source, destination) = (layer.surface, layer.source, layer.destination);
        let Some((xs, ys)) = on_screen(destination, mode.width, mode.height) else {
            continue;
        };
        let unscaled = (source.width, source.height) == (destination.width, destination.height);
        let over_black = !drawn
            .iter()
            .any(|(x, y)| x[0] < xs[1] && xs[0] < x[1] && y[0] < ys[1] && ys[0] < y[1]);
        let copies = surface.format.red_blue().is_some();
        row.resize(source.width as usize * 4, 0);
        for y in ys[0]..ys[1] {
            let from_y = (2 * (y as u64 - u64::from(destination.y)) + 1) * u64::from(source.height)
                / (2 * u64::from(destination.height));
            let iova = (u64::from(source.y) + from_y)
                .checked_mul(surface.stride.into())
                .and_then(|offset| offset.checked_add(u64::from(source.x) * 4))
                .and_then(|offset| surface.iova.checked_add(offset))
                .ok_or("layer row address overflows")?;
            if !read(iova, &mut row) {
                return Err("surface row is not reachable through its DART");
            }
            let out = &mut frame[(y * width + xs[0]) * 4..(y * width + xs[1]) * 4];
            if unscaled && copies {
                let start = (xs[0] - destination.x as usize) * 4;
                let pixels = &row[start..start + out.len()];
                if (layer.premultiplied && over_black)
                    || pixels.iter().skip(3).step_by(4).all(|&alpha| alpha == 0xff)
                {
                    copy_opaque(pixels, out, surface.format, mode.format);
                    continue;
                }
            }
            for (x, out) in (xs[0]..xs[1]).zip(out.as_chunks_mut::<4>().0) {
                let from_x = (2 * (x as u64 - u64::from(destination.x)) + 1)
                    * u64::from(source.width)
                    / (2 * u64::from(destination.width));
                let at = from_x as usize * 4;
                let pixel = surface
                    .format
                    .rgba([row[at], row[at + 1], row[at + 2], row[at + 3]]);
                let alpha = u32::from(pixel[3]);
                for (to, value) in [(red, pixel[0]), (1, pixel[1]), (blue, pixel[2])] {
                    let value = u32::from(value);
                    let value = if layer.premultiplied {
                        value
                    } else {
                        scale(value, alpha)
                    };
                    out[to] = (value + scale(u32::from(out[to]), 255 - alpha)).min(255) as u8;
                }
            }
        }
        drawn.push((xs, ys));
    }
    Ok(frame)
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
    fn channel_masks_encode_8_bit_channels_into_any_contiguous_layout() {
        // The masks of GOP's two fixed orders.
        let bgr = ChannelMasks::new(0xff_0000, 0xff00, 0xff).unwrap();
        assert_eq!(bgr.encode(0x12, 0x34, 0x56), 0x12_3456);
        let rgb = ChannelMasks::new(0xff, 0xff00, 0xff_0000).unwrap();
        assert_eq!(rgb.encode(0x12, 0x34, 0x56), 0x56_3412);
        // 10 bits widen by repeating the high bits; 5:6:5 narrows to them.
        let wide = ChannelMasks::new(0x3ff << 20, 0x3ff << 10, 0x3ff).unwrap();
        assert_eq!(wide.encode(0xff, 0x80, 0), 0x3ff << 20 | 0x202 << 10);
        let narrow = ChannelMasks::new(0xf800, 0x7e0, 0x1f).unwrap();
        assert_eq!(narrow.encode(0xff, 0x80, 0x08), 0xf800 | 0x20 << 5 | 1);
        // Gaps, overlaps, empty or over-wide channels refuse.
        assert!(ChannelMasks::new(0xf0f, 0xf000, 0xf0).is_err());
        assert!(ChannelMasks::new(0xff, 0x1ff, 0xff_0000).is_err());
        assert!(ChannelMasks::new(0, 0xff00, 0xff).is_err());
        assert!(ChannelMasks::new(0x1_ffff, 0xfe_0000, 0xff00_0000).is_err());
    }

    #[test]
    fn fourcc_round_trips_the_two_known_formats() {
        for format in [
            PixelFormat::Bgra8888,
            PixelFormat::Rgba8888,
            PixelFormat::Argb2101010,
        ] {
            assert_eq!(PixelFormat::from_fourcc(format.fourcc()), Some(format));
        }
        // 10-bit components round to 8 bits; 2-bit alpha spans 0..255.
        let l10r = (3u32 << 30 | 1023 << 20 | 512 << 10 | 3).to_le_bytes();
        assert_eq!(PixelFormat::Argb2101010.rgba(l10r), [255, 128, 1, 255]);
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

    /// The general path alone: every pixel blended through a red, green and
    /// blue canvas, as `compose` did before its fast paths.
    fn reference(layers: &[Layer], mode: Mode, memory: &[u8]) -> Vec<u8> {
        let (width, height) = (mode.width as usize, mode.height as usize);
        let mut canvas = alloc::vec![[0u32; 3]; width * height];
        for layer in layers {
            let (surface, source, destination) = (layer.surface, layer.source, layer.destination);
            let x_end =
                (u64::from(destination.x) + u64::from(destination.width)).min(mode.width.into());
            let y_end =
                (u64::from(destination.y) + u64::from(destination.height)).min(mode.height.into());
            for y in u64::from(destination.y)..y_end {
                let from_y = (2 * (y - u64::from(destination.y)) + 1) * u64::from(source.height)
                    / (2 * u64::from(destination.height));
                for x in u64::from(destination.x)..x_end {
                    let from_x = (2 * (x - u64::from(destination.x)) + 1) * u64::from(source.width)
                        / (2 * u64::from(destination.width));
                    let at = surface.iova
                        + (u64::from(source.y) + from_y) * u64::from(surface.stride)
                        + (u64::from(source.x) + from_x) * 4;
                    let at = at as usize;
                    let pixel = surface.format.rgba(memory[at..at + 4].try_into().unwrap());
                    let alpha = u32::from(pixel[3]);
                    let out = &mut canvas[y as usize * width + x as usize];
                    for (channel, value) in out.iter_mut().zip([pixel[0], pixel[1], pixel[2]]) {
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
        let (red, blue) = mode.format.red_blue().unwrap();
        canvas
            .into_iter()
            .flat_map(|rgb| {
                let mut pixel = [0, 0, 0, 0xff];
                pixel[red] = rgb[0] as u8;
                pixel[1] = rgb[1] as u8;
                pixel[blue] = rgb[2] as u8;
                pixel
            })
            .collect()
    }

    #[test]
    fn the_fast_paths_compose_the_frames_the_general_path_does() {
        // A seeded xorshift draws surfaces (some opaque, some with random
        // alpha) and layer stacks that mix unscaled and scaled, clipped and
        // overlapping, premultiplied and straight layers in both formats.
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move |bound: u32| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % u64::from(bound)) as u32
        };
        let mut memory = alloc::vec![0u8; 0x8000];
        for byte in memory.iter_mut() {
            *byte = next(256) as u8;
        }
        // Surfaces at 0x1000 steps; the even ones opaque.
        let formats = [
            PixelFormat::Bgra8888,
            PixelFormat::Rgba8888,
            PixelFormat::Argb2101010,
        ];
        let mut surfaces = Vec::new();
        for index in 0..6u32 {
            let (width, height) = (next(9) + 1, next(7) + 1);
            let iova = u64::from(0x1000 * (index + 1));
            let stride = width * 4 + next(3) * 4;
            if index % 2 == 0 {
                let base = iova as usize;
                for at in (base..base + (stride * height) as usize).skip(3).step_by(4) {
                    memory[at] = 0xff;
                }
            }
            surfaces.push(Surface {
                width,
                height,
                stride,
                format: formats[next(3) as usize],
                iova,
            });
        }
        for case in 0..200 {
            let mode = Mode {
                width: 12,
                height: 8,
                format: formats[case % 2],
            };
            let mut layers = Vec::new();
            for _ in 0..next(5) {
                let surface = surfaces[next(6) as usize];
                let (width, height) = (next(surface.width) + 1, next(surface.height) + 1);
                let source = Rect {
                    x: next(surface.width - width + 1),
                    y: next(surface.height - height + 1),
                    width,
                    height,
                };
                let size = if next(2) == 0 {
                    (width, height)
                } else {
                    (next(14) + 1, next(10) + 1)
                };
                let destination = Rect {
                    x: next(14),
                    y: next(10),
                    width: size.0,
                    height: size.1,
                };
                let premultiplied = next(2) == 0;
                layers.push(Layer::new(surface, source, destination, premultiplied).unwrap());
            }
            let fast = compose(&layers, mode, reader(&memory)).unwrap();
            assert_eq!(
                fast,
                reference(&layers, mode, &memory),
                "case {case}: {layers:?}"
            );
        }
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
