//! The host scanout a completed DCP swap is presented to: one fixed virtual
//! monitor. The boot crate implements it over the UEFI GOP framebuffer
//! (`crates/stela-boot/src/engine/display.rs`, two frames flipped through
//! QEMU's DISPI registers where the display has them) or, once a bound GPU
//! owns the display, over DRM mode setting
//! (`crates/stela-boot/src/engine/gpu/display.rs`, three dumb buffers in
//! video memory and page flips).
//!
//! The DCP model terminates the J473AP display pipeline at the AP boundary:
//! it has no real display controller to scan a surface out of DRAM, so the
//! CPU reads a swap's layers through their DART (dart-dispext0), composes
//! them a row at a time ([`compose`]) and hands the rows to a [`Scanout`].
//! A sink with a hidden buffer takes the rows straight from the composer, so
//! a frame is one pass from guest memory to the screen; any other is given
//! the whole frame, composed in the model's own storage. A present names the
//! rows that changed since the last one (its damage), and only those are
//! composed and copied again: a cursor move rewrites the rows its old and new
//! rectangles cover. A swap completes only after the scanout has consumed
//! the pixels, so the guest never recycles a surface the host is still
//! reading (the DCP's own swap-complete contract).
//!
//! The model converts each surface's pixel format to the scanout's and honors
//! its row stride; a format the model cannot convert is refused explicitly
//! rather than presented as garbage.
use crate::Result;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::ops::Range;
use stela_contracts::refuse;

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

/// The refresh of a scanout that reports none: 60 Hz, in millihertz.
pub const DEFAULT_REFRESH_MILLIHERTZ: u32 = 60_000;

/// The host's presentation sink. The boot crate implements it over the GOP
/// framebuffer; a swap is presented one row at a time.
pub trait Scanout {
    /// The fixed mode the one connected monitor runs. The model's EDID and
    /// mode answers are this mode; swaps are composed onto it.
    fn mode(&self) -> Mode;
    /// The monitor's refresh rate in millihertz, which the model advertises
    /// with the mode and paces the guest's display clients by.
    fn refresh_millihertz(&self) -> u32 {
        DEFAULT_REFRESH_MILLIHERTZ
    }
    /// The monitor's image size in millimetres, as its EDID reports it;
    /// `None` when unknown, and the model's EDID assumes a usual one
    /// (`dcp::modes::assumed_size_mm`).
    fn physical_size_mm(&self) -> Option<(u32, u32)> {
        None
    }
    /// Present one completed frame: `rows` are its pixels top to bottom, each
    /// `width` pixels of the scanout's format, already composed and clipped
    /// to the mode. Called once per completed swap, before the swap completes.
    /// An error leaves presentation uncommitted; the owner may retry the same
    /// swap. Validate fallible inputs before publishing host-visible pixels.
    fn present(&mut self, rows: &[u8]) -> Result<()>;

    /// Present a frame from a row producer, keeping its rows hidden until
    /// the whole frame is ready. `damage` names the rows that may differ
    /// from the last frame presented, `None` every row; the sink asks for
    /// those and for any others the buffer it fills lacks, as it last held
    /// an older frame. Call the producer with a row index and exactly
    /// `width * 4` bytes to fill, rows in increasing order, stopping on its
    /// first error; a later pass may ask for a row again. A sink without a
    /// hidden buffer declines without calling the producer.
    fn try_present_rows(
        &mut self,
        _damage: Option<Range<usize>>,
        _fill: &mut dyn FnMut(usize, &mut [u8]) -> Result<()>,
    ) -> Result<bool> {
        Ok(false)
    }

    /// Whether an earlier present left work only [`Self::flush`] finishes,
    /// such as a page flip whose request must wait for another processor.
    fn queued(&self) -> bool {
        false
    }

    /// Finish what an earlier present queued, as far as this processor may:
    /// what must wait for another processor stays queued for a later flush.
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

/// The smallest range of rows holding both `a` and `b`; an empty range adds
/// nothing.
pub fn union(a: Range<usize>, b: Range<usize>) -> Range<usize> {
    match (a.is_empty(), b.is_empty()) {
        (true, _) => b,
        (_, true) => a,
        _ => a.start.min(b.start)..a.end.max(b.end),
    }
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
    pub fn new(red: u32, green: u32, blue: u32) -> Result<Self> {
        if red & green != 0 || red & blue != 0 || green & blue != 0 {
            return Err(refuse!("framebuffer channel masks overlap"));
        }
        let channel = |mask: u32| {
            let shift = mask.trailing_zeros();
            let width = mask.count_ones();
            if mask == 0 || width > 16 || (mask >> shift).trailing_ones() != width {
                Err(refuse!(
                    "framebuffer channel mask is not one contiguous run of 1 to 16 bits"
                ))
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
    ) -> Result<Self> {
        if !source.inside(surface.width, surface.height) {
            return Err(refuse!(
                "layer source rectangle is empty or outside its surface"
            ));
        }
        if destination.width == 0 || destination.height == 0 {
            return Err(refuse!("layer destination rectangle is empty"));
        }
        Ok(Self {
            surface,
            source,
            destination,
            premultiplied,
        })
    }

    fn covers_mode(&self, mode: Mode) -> bool {
        self.surface.format == mode.format
            && self.source.width == mode.width
            && self.source.height == mode.height
            && self.destination
                == (Rect {
                    x: 0,
                    y: 0,
                    width: mode.width,
                    height: mode.height,
                })
    }

    fn read_row(
        &self,
        from_y: u64,
        out: &mut [u8],
        read: &mut impl FnMut(u64, &mut [u8]) -> bool,
    ) -> Result<()> {
        let iova = (u64::from(self.source.y) + from_y)
            .checked_mul(self.surface.stride.into())
            .and_then(|offset| offset.checked_add(u64::from(self.source.x) * 4))
            .and_then(|offset| self.surface.iova.checked_add(offset))
            .ok_or(refuse!("layer row address overflows"))?;
        if !read(iova, out) {
            return Err(refuse!("surface row is not reachable through its DART"));
        }
        Ok(())
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

/// Copy a same-format straight-alpha row over black without reading the
/// destination or calculating coordinates for individual pixels.
#[inline(never)]
fn copy_straight_over_black(pixels: &[u8], out: &mut [u8]) {
    for (out, pixel) in out
        .as_chunks_mut::<4>()
        .0
        .iter_mut()
        .zip(pixels.as_chunks::<4>().0)
    {
        *out = straight_over_black(*pixel);
    }
}

#[inline]
fn straight_over_black(pixel: [u8; 4]) -> [u8; 4] {
    let alpha = u32::from(pixel[3]);
    [
        scale(u32::from(pixel[0]), alpha) as u8,
        scale(u32::from(pixel[1]), alpha) as u8,
        scale(u32::from(pixel[2]), alpha) as u8,
        0xff,
    ]
}

/// Blend an unscaled row already in the scanout's channel order.
#[inline(never)]
fn blend_row(pixels: &[u8], out: &mut [u8], premultiplied: bool) {
    const LANES: u32 = 0x00ff_00ff;
    // Two independent 8-bit channels in 16-bit lanes. For products up to
    // 255², the shifts give the same rounded quotient as (product + 127) / 255.
    let scale = |lanes: u32, weight: u32| {
        let biased = lanes * weight + 0x0080_0080;
        ((biased + ((biased >> 8) & LANES)) >> 8) & LANES
    };
    for (out, pixel) in out
        .as_chunks_mut::<4>()
        .0
        .iter_mut()
        .zip(pixels.as_chunks::<4>().0)
    {
        let below = u32::from_le_bytes(*out);
        let source = u32::from_le_bytes(*pixel);
        let alpha = u32::from(pixel[3]);
        let blend = |source: u32, below: u32| {
            let source = source & LANES;
            let source = if premultiplied {
                source
            } else {
                scale(source, alpha)
            };
            let sum = source + scale(below & LANES, 255 - alpha);
            let overflow = (sum & 0x0100_0100) >> 8;
            (sum | (overflow * 255)) & LANES
        };
        let even = blend(source, below);
        let green = blend(source >> 8, below >> 8) & 0xff;
        *out = (even | (green << 8) | 0xff00_0000).to_le_bytes();
    }
}

/// The frame the model composed last, kept for the next: a frame is
/// megabytes, which a heap shared with the engine may not have in one piece
/// each time. While it holds what the scanout shows, a later present
/// recomposes only its damage in it.
#[derive(Debug, Default)]
pub struct Composed {
    rows: Vec<u8>,
    /// The rows are the frame the scanout shows.
    current: bool,
}

/// Present `layers` to `sink`, `damage` naming the rows that may differ
/// from the frame the sink shows (`None`: any row). A sink that can hide
/// unfinished rows takes them from the composer; any other gets the whole
/// frame, composed in `composed`. Rows that do not change are neither read
/// nor written, and no damage at all leaves the sink untouched.
pub(crate) fn present(
    sink: &mut dyn Scanout,
    layers: &[Layer],
    damage: Option<Range<usize>>,
    mut read: impl FnMut(u64, &mut [u8]) -> bool,
    composed: &mut Composed,
) -> Result<()> {
    let mode = sink.mode();
    let height = mode.height as usize;
    let damage = damage.map(|rows| rows.start.min(height)..rows.end.min(height));
    if damage.as_ref().is_some_and(Range::is_empty) {
        return Ok(());
    }
    let mut rows = Rows::new(layers, mode)?;
    if sink.try_present_rows(damage.clone(), &mut |y, row| {
        rows.compose(y, row, &mut read)
    })? {
        composed.current = false;
        return Ok(());
    }
    let lines = match damage {
        Some(lines) if composed.current => lines,
        _ => 0..height,
    };
    // A failure below leaves the storage between frames.
    composed.current = false;
    let row_bytes = mode.width as usize * 4;
    composed.rows.resize(row_bytes * height, 0);
    for y in lines {
        rows.compose(
            y,
            &mut composed.rows[y * row_bytes..][..row_bytes],
            &mut read,
        )?;
    }
    sink.present(&composed.rows)?;
    composed.current = true;
    Ok(())
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
/// The frame is built in the scanout's byte order, a row at a time. An
/// unscaled row is copied whole when blending cannot change it: every pixel
/// opaque, or a premultiplied layer over columns no lower layer has drawn
/// on in that row (still black).
pub fn compose(
    layers: &[Layer],
    mode: Mode,
    read: impl FnMut(u64, &mut [u8]) -> bool,
) -> Result<Vec<u8>> {
    let mut frame = Vec::new();
    compose_into(layers, mode, read, &mut frame)?;
    Ok(frame)
}

/// [`compose`] into `frame`, whatever it held.
pub fn compose_into(
    layers: &[Layer],
    mode: Mode,
    mut read: impl FnMut(u64, &mut [u8]) -> bool,
    frame: &mut Vec<u8>,
) -> Result<()> {
    let mut rows = Rows::new(layers, mode)?;
    let row_bytes = mode.width as usize * 4;
    frame.resize(row_bytes * mode.height as usize, 0);
    for (y, out) in frame.chunks_exact_mut(row_bytes.max(1)).enumerate() {
        rows.compose(y, out, &mut read)?;
    }
    Ok(())
}

/// The composer of one frame's rows, any row on its own.
struct Rows<'a> {
    layers: &'a [Layer],
    /// Each layer's on-screen columns and rows, `None` when off screen.
    placed: Vec<Option<([usize; 2], [usize; 2])>>,
    red: usize,
    blue: usize,
    format: PixelFormat,
    /// A matching bottom layer replaces every output pixel. Its DART rows
    /// are read into the output row without first filling opaque black or
    /// routing the pixels through the scratch row.
    direct_base: bool,
    /// The columns lower layers drew on in the row being composed.
    drawn: Vec<[usize; 2]>,
    scratch: Vec<u8>,
}

impl<'a> Rows<'a> {
    fn new(layers: &'a [Layer], mode: Mode) -> Result<Self> {
        let (red, blue) = mode
            .format
            .red_blue()
            .ok_or(refuse!("scanout mode is not an 8-bit format"))?;
        Ok(Self {
            layers,
            placed: layers
                .iter()
                .map(|layer| on_screen(layer.destination, mode.width, mode.height))
                .collect(),
            red,
            blue,
            format: mode.format,
            direct_base: layers.first().is_some_and(|layer| layer.covers_mode(mode)),
            drawn: Vec::new(),
            scratch: Vec::new(),
        })
    }

    /// Compose row `y` into `out`, the mode's width of pixels.
    fn compose(
        &mut self,
        y: usize,
        out: &mut [u8],
        read: &mut impl FnMut(u64, &mut [u8]) -> bool,
    ) -> Result<()> {
        if !self.direct_base {
            out.as_chunks_mut::<4>().0.fill([0, 0, 0, 0xff]);
        }
        self.drawn.clear();
        let layers = self.layers;
        for (index, layer) in layers.iter().enumerate() {
            let Some((xs, ys)) = self.placed[index] else {
                continue;
            };
            if !(ys[0]..ys[1]).contains(&y) {
                continue;
            }
            let (surface, source, destination) = (layer.surface, layer.source, layer.destination);
            let over_black = !self.drawn.iter().any(|x| x[0] < xs[1] && xs[0] < x[1]);
            self.drawn.push(xs);
            let from_y = (2 * (y as u64 - u64::from(destination.y)) + 1) * u64::from(source.height)
                / (2 * u64::from(destination.height));
            let out = &mut out[xs[0] * 4..xs[1] * 4];
            if index == 0 && self.direct_base {
                layer.read_row(from_y, out, read)?;
                make_opaque(out, layer.premultiplied);
                continue;
            }
            self.scratch.resize(source.width as usize * 4, 0);
            let row = &mut self.scratch[..];
            layer.read_row(from_y, row, read)?;
            let unscaled = (source.width, source.height) == (destination.width, destination.height);
            if unscaled && surface.format.red_blue().is_some() {
                let start = (xs[0] - destination.x as usize) * 4;
                let pixels = &row[start..start + out.len()];
                if (layer.premultiplied && over_black) || all_opaque(pixels) {
                    copy_opaque(pixels, out, surface.format, self.format);
                    continue;
                }
                if over_black && surface.format == self.format {
                    copy_straight_over_black(pixels, out);
                    continue;
                }
                if surface.format == self.format {
                    blend_row(pixels, out, layer.premultiplied);
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
                for (to, value) in [(self.red, pixel[0]), (1, pixel[1]), (self.blue, pixel[2])] {
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
        Ok(())
    }
}

/// Reject a translucent group at once while ignoring the colour bytes.
fn all_opaque(row: &[u8]) -> bool {
    const ALPHA: u64 = 0xff00_0000_ff00_0000;
    let (groups, tail) = row.as_chunks::<16>();
    groups.iter().all(|group| {
        let words = group.as_chunks::<8>().0;
        let combined = u64::from_le_bytes(words[0]) & u64::from_le_bytes(words[1]);
        combined & ALPHA == ALPHA
    }) && tail.iter().skip(3).step_by(4).all(|&alpha| alpha == 0xff)
}

fn make_opaque(row: &mut [u8], premultiplied: bool) {
    if !all_opaque(row) {
        opaque_over_black(row, premultiplied);
    }
}

/// The bottom layer covers this row. Alpha is opaque after composition
/// over black even if the source is translucent.
#[inline(never)]
fn opaque_over_black(row: &mut [u8], premultiplied: bool) {
    let pixels = row.as_chunks_mut::<4>().0;
    if premultiplied {
        for pixel in pixels {
            *pixel = (u32::from_le_bytes(*pixel) | 0xff00_0000).to_le_bytes();
        }
        return;
    }
    for pixel in pixels {
        *pixel = straight_over_black(*pixel);
    }
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
    fn the_opaque_check_reads_only_alpha_across_group_boundaries() {
        let mut bytes = [0; 41];
        for length in 0..=40 {
            for offset in 0..=1 {
                let row = &mut bytes[offset..][..length];
                row.fill(0);
                for alpha in row.iter_mut().skip(3).step_by(4) {
                    *alpha = 0xff;
                }
                assert!(all_opaque(row));
                for alpha in (3..row.len()).step_by(4) {
                    row[alpha] = 0xfe;
                    assert!(!all_opaque(row));
                    row[alpha] = 0xff;
                }
            }
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

    /// The last frame's storage, whatever it holds, composes the next
    /// frame as fresh storage does: over the screen a layer covers, and
    /// over opaque black elsewhere.
    #[test]
    fn a_frame_composed_in_the_last_ones_storage_is_the_same() {
        let mut memory = alloc::vec![0u8; 0x3000];
        memory[0x1000..0x1020].fill(0x40);
        memory[0x2000..0x2004].copy_from_slice(&[0x80, 0, 0, 0x80]);
        let whole = Layer::new(
            surface(4, 2, 16, 0x1000),
            Rect::whole(4, 2),
            Rect::whole(4, 2),
            false,
        )
        .unwrap();
        let corner = Layer::new(
            surface(1, 1, 4, 0x2000),
            Rect::whole(1, 1),
            Rect::whole(1, 1),
            true,
        )
        .unwrap();
        for layers in [&[whole][..], &[corner], &[whole, corner]] {
            let fresh = compose(layers, MODE, reader(&memory)).unwrap();
            for stale in [
                alloc::vec![0x5a; fresh.len()],
                alloc::vec![0x5a; 3],
                Vec::new(),
            ] {
                let mut frame = stale;
                compose_into(layers, MODE, reader(&memory), &mut frame).unwrap();
                assert_eq!(frame, fresh);
            }
        }
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
    fn overlapping_rows_round_and_saturate_each_channel_independently() {
        for premultiplied in [false, true] {
            for alpha in 0..=255 {
                for value in 0..=255 {
                    let source = [value, 255 - value, value ^ 0x55, alpha];
                    let below = [value ^ 0xaa, value, 255 - value, 0xff];
                    let mut actual = below;
                    blend_row(&source, &mut actual, premultiplied);
                    let alpha = u32::from(alpha);
                    let mut expected = below;
                    for (channel, (source, below)) in
                        source.into_iter().zip(below).take(3).enumerate()
                    {
                        let source = u32::from(source);
                        let source = if premultiplied {
                            source
                        } else {
                            scale(source, alpha)
                        };
                        expected[channel] =
                            (source + scale(u32::from(below), 255 - alpha)).min(255) as u8;
                    }
                    assert_eq!(actual, expected);
                }
            }
        }
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
    fn a_full_base_composes_over_black_and_preserves_row_dma_boundaries() {
        let base = Layer::new(
            surface(6, 3, 32, 8),
            Rect {
                x: 1,
                y: 1,
                ..Rect::whole(4, 2)
            },
            Rect::whole(4, 2),
            false,
        )
        .unwrap();
        let overlay = Layer::new(
            surface(2, 1, 8, 112),
            Rect::whole(2, 1),
            Rect {
                x: 3,
                y: 1,
                ..Rect::whole(2, 1)
            },
            true,
        )
        .unwrap();
        let mut memory = [0; 128];
        for (index, byte) in memory.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(37);
        }
        memory[47] = 0;
        memory[51] = 0xff;
        for premultiplied in [false, true] {
            let layers = [
                Layer {
                    premultiplied,
                    ..base
                },
                overlay,
            ];
            let mut reads = Vec::new();
            let mut outputs = Vec::new();
            let frame = compose(&layers, MODE, |iova, bytes| {
                reads.push((iova, bytes.len()));
                outputs.push(bytes.as_ptr());
                reader(&memory)(iova, bytes)
            })
            .unwrap();
            assert_eq!(reads, [(44, 16), (76, 16), (112, 8)]);
            assert_eq!(
                outputs[..2],
                [frame.as_ptr(), frame.as_ptr().wrapping_add(16)]
            );
            assert_eq!(frame, reference(&layers, MODE, &memory));
        }

        // An unreachable row leaves the frame unpublished and the later
        // overlay unread.
        let mut reads = Vec::new();
        assert!(
            compose(&[base, overlay], MODE, |iova, bytes| {
                reads.push(iova);
                bytes[0] = 99;
                iova != 76
            })
            .is_err()
        );
        assert_eq!(reads, [44, 76]);
    }

    /// A sink with a hidden buffer: it keeps the frame it shows, fills the
    /// rows a present asks for (every row when it names no damage) and
    /// shows them only once all are filled.
    #[derive(Default)]
    struct Hidden {
        mode: Option<Mode>,
        visible: Vec<u8>,
        streamed: usize,
        /// The rows each present asked the composer for.
        asked: Vec<Vec<usize>>,
    }

    impl Scanout for Hidden {
        fn mode(&self) -> Mode {
            self.mode.unwrap_or(MODE)
        }

        fn present(&mut self, rows: &[u8]) -> Result<()> {
            self.visible = rows.to_vec();
            Ok(())
        }

        fn try_present_rows(
            &mut self,
            damage: Option<Range<usize>>,
            fill: &mut dyn FnMut(usize, &mut [u8]) -> Result<()>,
        ) -> Result<bool> {
            let mode = self.mode();
            let row_bytes = mode.width as usize * 4;
            let mut rows = self.visible.clone();
            rows.resize(row_bytes * mode.height as usize, 0);
            let lines = damage.unwrap_or(0..mode.height as usize);
            self.asked.push(lines.clone().collect());
            for y in lines {
                fill(y, &mut rows[y * row_bytes..][..row_bytes])?;
            }
            self.streamed += 1;
            self.present(&rows)?;
            Ok(true)
        }
    }

    #[test]
    fn hidden_rows_preserve_fullscreen_dma_order_and_pixels() {
        let layer = Layer::new(
            surface(6, 3, 32, 8),
            Rect {
                x: 1,
                y: 1,
                ..Rect::whole(4, 2)
            },
            Rect::whole(4, 2),
            false,
        )
        .unwrap();
        let memory: Vec<u8> = (0..112).map(|i| (i as u8).wrapping_mul(37)).collect();
        let mut sink = Hidden::default();
        for premultiplied in [false, true] {
            let layers = [Layer {
                premultiplied,
                ..layer
            }];
            let old_visible = sink.visible.clone();
            let mut reads = Vec::new();
            assert!(
                present(
                    &mut sink,
                    &layers,
                    None,
                    |iova, row| {
                        reads.push((iova, row.len()));
                        reader(&memory)(iova, row) && iova != 76
                    },
                    &mut Composed::default()
                )
                .is_err()
            );
            assert_eq!(reads, [(44, 16), (76, 16)]);
            assert_eq!(sink.visible, old_visible);
            reads.clear();
            present(
                &mut sink,
                &layers,
                None,
                |iova, row| {
                    reads.push((iova, row.len()));
                    reader(&memory)(iova, row)
                },
                &mut Composed::default(),
            )
            .unwrap();
            assert_eq!(reads, [(44, 16), (76, 16)]);
            assert_eq!(sink.visible, reference(&layers, MODE, &memory));
        }
        assert_eq!(sink.streamed, 2);
        // A stack of layers streams its rows too: nothing is composed into
        // the model's own frame first.
        let mut composed = Composed::default();
        present(&mut sink, &[layer; 2], None, reader(&memory), &mut composed).unwrap();
        assert_eq!(sink.visible, reference(&[layer; 2], MODE, &memory));
        assert_eq!(sink.streamed, 3);
        assert!(composed.rows.is_empty());
    }

    /// A screen of eight rows: an opaque base layer and a 2x2 cursor.
    fn cursor_scene() -> (Mode, Vec<u8>, Layer, Layer) {
        let mode = Mode {
            width: 4,
            height: 8,
            format: PixelFormat::Bgra8888,
        };
        let mut memory = alloc::vec![0u8; 0x2000];
        for (index, byte) in memory[0x100..0x180].iter_mut().enumerate() {
            *byte = if index % 4 == 3 { 0xff } else { index as u8 };
        }
        // The cursor's four pixels, translucent and premultiplied.
        memory[0x1000..0x1010].copy_from_slice(&[0x40, 0x20, 0x10, 0x80].repeat(4));
        let base = Layer::new(
            surface(4, 8, 16, 0x100),
            Rect::whole(4, 8),
            Rect::whole(4, 8),
            true,
        )
        .unwrap();
        let cursor = Layer::new(
            surface(2, 2, 8, 0x1000),
            Rect::whole(2, 2),
            Rect::whole(2, 2),
            true,
        )
        .unwrap();
        (mode, memory, base, cursor)
    }

    fn at(cursor: Layer, x: u32, y: u32) -> Layer {
        Layer {
            destination: Rect {
                x,
                y,
                ..cursor.destination
            },
            ..cursor
        }
    }

    #[test]
    fn a_cursor_move_rewrites_only_the_rows_of_its_old_and_new_rectangles() {
        let (mode, memory, base, cursor) = cursor_scene();
        let mut sink = Hidden {
            mode: Some(mode),
            ..Hidden::default()
        };
        let mut composed = Composed::default();
        let first = [base, at(cursor, 1, 1)];
        present(&mut sink, &first, None, reader(&memory), &mut composed).unwrap();
        // The cursor moves from rows 1..3 to rows 4..6: the damage the model
        // names is their union, and only those rows are read and written.
        let moved = [base, at(cursor, 2, 4)];
        let mut reads = Vec::new();
        present(
            &mut sink,
            &moved,
            Some(1..6),
            |iova, bytes| {
                reads.push(iova);
                reader(&memory)(iova, bytes)
            },
            &mut composed,
        )
        .unwrap();
        assert_eq!(sink.asked[1], [1, 2, 3, 4, 5]);
        // Base rows 1..6, and the cursor's two rows after its base row.
        assert_eq!(reads, [0x110, 0x120, 0x130, 0x140, 0x1000, 0x150, 0x1008]);
        assert_eq!(
            sink.visible,
            compose(&moved, mode, reader(&memory)).unwrap()
        );
        // No damage leaves the sink alone.
        present(
            &mut sink,
            &moved,
            Some(3..3),
            |_, _| unreachable!(),
            &mut composed,
        )
        .unwrap();
        assert_eq!(sink.streamed, 2);
    }

    #[test]
    fn a_sink_without_hidden_rows_gets_the_kept_frame_with_only_its_damage_recomposed() {
        let (mode, memory, base, cursor) = cursor_scene();
        let screen = TestSink::new(mode);
        let mut sink = screen.clone();
        let mut composed = Composed::default();
        present(
            &mut sink,
            &[base, at(cursor, 0, 0)],
            None,
            reader(&memory),
            &mut composed,
        )
        .unwrap();
        let moved = [base, at(cursor, 2, 6)];
        let mut rows = Vec::new();
        present(
            &mut sink,
            &moved,
            Some(0..8),
            |iova, bytes| {
                if (0x100..0x180).contains(&iova) {
                    rows.push((iova - 0x100) / 16);
                }
                reader(&memory)(iova, bytes)
            },
            &mut composed,
        )
        .unwrap();
        assert_eq!(rows, (0..8).collect::<Vec<_>>());
        rows.clear();
        let back = [base, at(cursor, 2, 5)];
        present(
            &mut sink,
            &back,
            Some(5..8),
            |iova, bytes| {
                if (0x100..0x180).contains(&iova) {
                    rows.push((iova - 0x100) / 16);
                }
                reader(&memory)(iova, bytes)
            },
            &mut composed,
        )
        .unwrap();
        assert_eq!(rows, [5, 6, 7]);
        let frames = screen.0.borrow();
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[2], compose(&back, mode, reader(&memory)).unwrap());

        // A failed present leaves the kept frame between frames: the next
        // composes every row whatever its damage.
        drop(frames);
        assert!(present(&mut sink, &moved, Some(5..8), |_, _| false, &mut composed).is_err());
        rows.clear();
        present(
            &mut sink,
            &moved,
            Some(5..8),
            |iova, bytes| {
                if (0x100..0x180).contains(&iova) {
                    rows.push((iova - 0x100) / 16);
                }
                reader(&memory)(iova, bytes)
            },
            &mut composed,
        )
        .unwrap();
        assert_eq!(rows, (0..8).collect::<Vec<_>>());
        assert_eq!(
            screen.0.borrow().last().unwrap(),
            &compose(&moved, mode, reader(&memory)).unwrap()
        );
    }

    /// A sink that takes whole frames only, keeping each.
    #[derive(Clone)]
    struct TestSink(alloc::rc::Rc<core::cell::RefCell<Vec<Vec<u8>>>>, Mode);

    impl TestSink {
        fn new(mode: Mode) -> Self {
            Self(Default::default(), mode)
        }
    }

    impl Scanout for TestSink {
        fn mode(&self) -> Mode {
            self.1
        }

        fn present(&mut self, rows: &[u8]) -> Result<()> {
            self.0.borrow_mut().push(rows.to_vec());
            Ok(())
        }
    }

    #[test]
    fn damage_unions_into_one_range() {
        assert_eq!(union(0..0, 3..5), 3..5);
        assert_eq!(union(3..5, 7..7), 3..5);
        assert_eq!(union(3..5, 1..4), 1..5);
        assert_eq!(union(3..5, 8..9), 3..9);
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
