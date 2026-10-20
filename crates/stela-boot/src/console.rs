//! Text on the firmware's linear framebuffer, so a PC without a serial port
//! still shows the mount's output after boot services end.
//!
//! Glyphs are the public-domain 8x8 IBM PC set, scaled to the screen height.
//! When the screen fills, it clears and continues from the top: reading the
//! framebuffer back to scroll is too slow on uncached video memory.
use core::cell::UnsafeCell;
use font8x8::legacy::BASIC_LEGACY;
use stela_runtime::machine::apple::ScanoutMasks;
use uefi::{
    boot::{self, OpenProtocolAttributes, OpenProtocolParams},
    proto::console::gop::{GraphicsOutput, PixelFormat},
};

const GLYPH: usize = 8;
/// Two blank scaled rows between lines.
const LINE: usize = GLYPH + 2;
/// Scale so that at least this many lines fit.
const MIN_LINES: usize = 60;
const BYTES_PER_PIXEL: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Color {
    Text,
    Fatal,
}

/// How a GOP mode lays out a 32-bit pixel.
#[derive(Debug, Clone, Copy)]
enum Encoding {
    /// `PixelBlueGreenRedReserved8BitPerColor`: blue in the low byte, as the
    /// pixels Stela draws and presents already are.
    Bgr,
    /// `PixelRedGreenBlueReserved8BitPerColor`: red in the low byte.
    Rgb,
    /// `PixelBitMask`: the layout its channel masks give.
    Masks(ScanoutMasks),
}

impl Encoding {
    /// The mode's pixel for one with blue in the low byte.
    fn encode(self, pixel: u32) -> u32 {
        match self {
            Encoding::Bgr => pixel,
            Encoding::Rgb => pixel & 0xff00_ff00 | (pixel & 0xff) << 16 | (pixel >> 16) & 0xff,
            Encoding::Masks(masks) => {
                let [blue, green, red, _] = pixel.to_le_bytes();
                masks.encode(red, green, blue)
            }
        }
    }
}

/// The GOP mode in use when Stela takes over.
#[derive(Debug, Clone, Copy)]
pub struct Framebuffer {
    pub base: usize,
    pub bytes: usize,
    width: usize,
    height: usize,
    stride: usize,
    encoding: Encoding,
}

impl Framebuffer {
    /// The first GOP's current mode, when it is a linear 32-bit framebuffer:
    /// RGB, BGR or channel masks (`scanout::ChannelMasks`). A `PixelBltOnly`
    /// mode has no framebuffer to draw in once boot services end, so it gives
    /// none, as do masks that `ChannelMasks` refuses. Boot managers keep
    /// their own handle open, so this only reads the protocol rather than
    /// opening it exclusively.
    pub fn from_firmware() -> Option<Self> {
        let handle = boot::get_handle_for_protocol::<GraphicsOutput>().ok()?;
        // SAFETY: the protocol is only read, and only while boot services run.
        let mut gop = unsafe {
            boot::open_protocol::<GraphicsOutput>(
                OpenProtocolParams {
                    handle,
                    agent: boot::image_handle(),
                    controller: None,
                },
                OpenProtocolAttributes::GetProtocol,
            )
        }
        .ok()?;
        let mode = gop.current_mode_info();
        let encoding = match (mode.pixel_format(), mode.pixel_bitmask()) {
            (PixelFormat::Rgb, _) => Encoding::Rgb,
            (PixelFormat::Bgr, _) => Encoding::Bgr,
            (PixelFormat::Bitmask, Some(masks)) => {
                Encoding::Masks(ScanoutMasks::new(masks.red, masks.green, masks.blue).ok()?)
            }
            (PixelFormat::Bitmask | PixelFormat::BltOnly, _) => return None,
        };
        let (width, height) = mode.resolution();
        let mut buffer = gop.frame_buffer();
        let framebuffer = Self {
            base: buffer.as_mut_ptr() as usize,
            bytes: buffer.size(),
            width,
            height,
            stride: mode.stride(),
            encoding,
        };
        (framebuffer.stride * framebuffer.height * BYTES_PER_PIXEL <= framebuffer.bytes)
            .then_some(framebuffer)
    }

    /// The same mode reached at another address (the engine's physmap).
    pub fn relocated(self, base: usize) -> Self {
        Self { base, ..self }
    }

    /// Visible pixels across and down.
    pub fn resolution(&self) -> (usize, usize) {
        (self.width, self.height)
    }

    /// Row `y` from 32-bit pixels with blue in the low byte, as many as fit.
    pub fn show_row(&self, y: usize, pixels: &[u8]) {
        if y >= self.height {
            return;
        }
        let line = (self.base + y * self.stride * BYTES_PER_PIXEL) as *mut u32;
        let (pixels, _) = pixels.as_chunks::<BYTES_PER_PIXEL>();
        for (column, pixel) in pixels.iter().take(self.width).enumerate() {
            let value = self.encoding.encode(u32::from_le_bytes(*pixel));
            // SAFETY: `column < width` and `y < height`, inside the mode's
            // visible framebuffer.
            unsafe { line.add(column).write_volatile(value) };
        }
    }

    /// Pixels per row in memory, at least the width.
    pub fn stride(&self) -> usize {
        self.stride
    }

    /// The mode's pixel layout, as GOP names it.
    pub fn format(&self) -> &'static str {
        match self.encoding {
            Encoding::Bgr => "BGR",
            Encoding::Rgb => "RGB",
            Encoding::Masks(_) => "bitmask",
        }
    }

    /// The same mode with only its top `height` rows, so that text written
    /// to it leaves the rows below for something else.
    pub fn top(self, height: usize) -> Self {
        Self {
            height: height.min(self.height),
            ..self
        }
    }

    fn pixel(&self, color: Color) -> u32 {
        match color {
            Color::Text => self.rgb(0xe0, 0xe0, 0xe0),
            Color::Fatal => self.rgb(0xff, 0x50, 0x50),
        }
    }

    /// The pixel value of a colour in this mode's layout.
    pub fn rgb(&self, red: u8, green: u8, blue: u8) -> u32 {
        let (red, green, blue) = (u32::from(red), u32::from(green), u32::from(blue));
        self.encoding.encode((red << 16) | (green << 8) | blue)
    }

    fn fill(&self, x: usize, y: usize, size: usize, value: u32) {
        self.rectangle(x, y, size, size, value);
    }

    /// Fill `width` by `height` pixels from (`x`, `y`), cut to the mode's
    /// visible rows and columns.
    pub fn rectangle(&self, x: usize, y: usize, width: usize, height: usize, value: u32) {
        for row in y..(y + height).min(self.height) {
            let line = (self.base + row * self.stride * BYTES_PER_PIXEL) as *mut u32;
            for column in x..(x + width).min(self.width) {
                // SAFETY: inside the mode's visible framebuffer.
                unsafe { line.add(column).write_volatile(value) };
            }
        }
    }

    /// The pixel at (`x`, `y`), which is visible.
    pub fn read(&self, x: usize, y: usize) -> u32 {
        assert!(x < self.width && y < self.height, "pixel outside the mode");
        let line = (self.base + y * self.stride * BYTES_PER_PIXEL) as *const u32;
        // SAFETY: inside the mode's visible framebuffer, as checked.
        unsafe { line.add(x).read_volatile() }
    }

    fn clear(&self) {
        for row in 0..self.height {
            let line = (self.base + row * self.stride * BYTES_PER_PIXEL) as *mut u32;
            for column in 0..self.width {
                // SAFETY: inside the mode's visible framebuffer.
                unsafe { line.add(column).write_volatile(0) };
            }
        }
    }
}

struct Cursor {
    screen: Framebuffer,
    scale: usize,
    columns: usize,
    lines: usize,
    column: usize,
    line: usize,
}

impl Cursor {
    fn new(screen: Framebuffer) -> Option<Self> {
        let scale = (screen.height / (MIN_LINES * LINE)).max(1);
        let columns = screen.width / (GLYPH * scale);
        let lines = screen.height / (LINE * scale);
        (columns > 0 && lines > 0).then_some(Self {
            screen,
            scale,
            columns,
            lines,
            column: 0,
            line: 0,
        })
    }

    fn newline(&mut self) {
        self.column = 0;
        self.line += 1;
        if self.line == self.lines {
            self.screen.clear();
            self.line = 0;
        }
    }

    fn glyph(&mut self, byte: u8, color: Color) {
        if self.column == self.columns {
            self.newline();
        }
        let bits = BASIC_LEGACY[usize::from(byte & 0x7f)];
        let (x, y) = (
            self.column * GLYPH * self.scale,
            self.line * LINE * self.scale,
        );
        let (on, off) = (self.screen.pixel(color), 0);
        for (row, pattern) in bits.iter().enumerate() {
            for bit in 0..GLYPH {
                let value = if pattern & (1 << bit) != 0 { on } else { off };
                self.screen.fill(
                    x + bit * self.scale,
                    y + row * self.scale,
                    self.scale,
                    value,
                );
            }
        }
        self.column += 1;
    }

    fn write(&mut self, text: &str, color: Color) {
        for byte in text.bytes() {
            match byte {
                b'\n' => self.newline(),
                b'\r' => self.column = 0,
                byte if byte.is_ascii_graphic() || byte == b' ' => self.glyph(byte, color),
                _ => self.glyph(b'?', color),
            }
        }
    }
}

/// The boot processor is the only writer, with interrupts disabled.
struct Console(UnsafeCell<Option<Cursor>>);
// SAFETY: Stela runs on one CPU and never writes from an interrupt handler.
unsafe impl Sync for Console {}
static CONSOLE: Console = Console(UnsafeCell::new(None));

/// Clear the screen and send later output to it as well.
pub fn install(screen: Framebuffer) {
    screen.clear();
    // SAFETY: see `Console`; no reference to the cursor is live here.
    unsafe { *CONSOLE.0.get() = Cursor::new(screen) };
}

/// Stop drawing text: the screen now shows something else. Output still
/// reaches the UART.
pub fn release() {
    // SAFETY: see `Console`; no reference to the cursor is live here.
    unsafe { *CONSOLE.0.get() = None };
}

pub fn write(text: &str, color: Color) {
    // SAFETY: see `Console`; this is the only access, and it does not nest.
    if let Some(cursor) = unsafe { &mut *CONSOLE.0.get() } {
        cursor.write(text, color);
    }
}
