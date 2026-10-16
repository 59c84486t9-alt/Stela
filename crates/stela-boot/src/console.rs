//! Text on the firmware's linear framebuffer, so a PC without a serial port
//! still shows the mount's output after boot services end.
//!
//! Glyphs are the public-domain 8x8 IBM PC set, scaled to the screen height.
//! When the screen fills, it clears and continues from the top: reading the
//! framebuffer back to scroll is too slow on uncached video memory.
use core::cell::UnsafeCell;
use font8x8::legacy::BASIC_LEGACY;
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

/// The GOP mode in use when Stela takes over.
#[derive(Debug, Clone, Copy)]
pub struct Framebuffer {
    pub base: usize,
    pub bytes: usize,
    width: usize,
    height: usize,
    stride: usize,
    bgr: bool,
}

impl Framebuffer {
    /// The first GOP's current mode, when it is a 32-bit RGB or BGR
    /// framebuffer. Boot managers keep their own handle open, so this only
    /// reads the protocol rather than opening it exclusively.
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
        let bgr = match mode.pixel_format() {
            PixelFormat::Rgb => false,
            PixelFormat::Bgr => true,
            PixelFormat::Bitmask | PixelFormat::BltOnly => return None,
        };
        let (width, height) = mode.resolution();
        let mut buffer = gop.frame_buffer();
        let framebuffer = Self {
            base: buffer.as_mut_ptr() as usize,
            bytes: buffer.size(),
            width,
            height,
            stride: mode.stride(),
            bgr,
        };
        (framebuffer.stride * framebuffer.height * BYTES_PER_PIXEL <= framebuffer.bytes)
            .then_some(framebuffer)
    }

    fn pixel(&self, color: Color) -> u32 {
        let (red, green, blue) = match color {
            Color::Text => (0xe0, 0xe0, 0xe0),
            Color::Fatal => (0xff, 0x50, 0x50),
        };
        if self.bgr {
            (red << 16) | (green << 8) | blue
        } else {
            (blue << 16) | (green << 8) | red
        }
    }

    fn fill(&self, x: usize, y: usize, size: usize, value: u32) {
        for row in y..y + size {
            let line = (self.base + row * self.stride * BYTES_PER_PIXEL) as *mut u32;
            for column in x..x + size {
                // SAFETY: callers keep `x + size <= width` and
                // `y + size <= height`, inside the mode's framebuffer.
                unsafe { line.add(column).write_volatile(value) };
            }
        }
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

pub fn write(text: &str, color: Color) {
    // SAFETY: see `Console`; this is the only access, and it does not nest.
    if let Some(cursor) = unsafe { &mut *CONSOLE.0.get() } {
        cursor.write(text, color);
    }
}
