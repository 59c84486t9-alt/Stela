//! Text on the firmware's linear framebuffer, so a PC without a serial port
//! still shows the mount's progress, from the startup choice until the
//! guest's display takes the screen.
//!
//! Glyphs come from bitmap fonts drawn at their own resolution, in the size
//! the Linux console would choose for the screen ([`font::choose`]). The
//! text is a grid of cells kept in memory, and drawing writes only the cells
//! that changed: video memory is uncached and slow to read back, so
//! scrolling redraws from the grid instead of moving pixels.
mod font;

use alloc::{vec, vec::Vec};
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};
use font::Font;
use stela_runtime::machine::apple::ScanoutMasks;
use uefi::{
    boot::{self, OpenProtocolAttributes, OpenProtocolParams},
    proto::console::gop::{GraphicsOutput, PixelFormat},
};

const BYTES_PER_PIXEL: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Color {
    Text,
    Dim,
    Good,
    Warn,
    Fatal,
    Busy,
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
            Color::Text => self.rgb(0xd0, 0xd0, 0xd0),
            Color::Dim => self.rgb(0x80, 0x80, 0x80),
            Color::Good => self.rgb(0x5f, 0xd7, 0x5f),
            Color::Warn => self.rgb(0xff, 0xd7, 0x5f),
            Color::Fatal => self.rgb(0xff, 0x5f, 0x5f),
            Color::Busy => self.rgb(0xff, 0x5f, 0x5f),
        }
    }

    /// The pixel value of a colour in this mode's layout.
    pub fn rgb(&self, red: u8, green: u8, blue: u8) -> u32 {
        let (red, green, blue) = (u32::from(red), u32::from(green), u32::from(blue));
        self.encoding.encode((red << 16) | (green << 8) | blue)
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

#[derive(Clone, Copy, PartialEq, Eq)]
struct Cell {
    character: u8,
    color: Color,
}

const BLANK: Cell = Cell {
    character: b' ',
    color: Color::Text,
};

/// The text grid and what the screen shows of it.
struct Text {
    screen: Framebuffer,
    font: Font,
    columns: usize,
    rows: usize,
    cells: Vec<Cell>,
    shown: Vec<Cell>,
    column: usize,
    row: usize,
}

impl Text {
    fn new(screen: Framebuffer) -> Option<Self> {
        let (width, height) = screen.resolution();
        let font = font::choose(width, height)?;
        // A one-cell margin all round.
        let columns = (width / font.width).checked_sub(2)?;
        let rows = (height / font.height).checked_sub(2)?;
        (columns > 0 && rows > 0).then(|| Self {
            screen,
            font,
            columns,
            rows,
            cells: vec![BLANK; columns * rows],
            shown: vec![BLANK; columns * rows],
            column: 0,
            row: 0,
        })
    }

    fn newline(&mut self) {
        self.column = 0;
        if self.row + 1 < self.rows {
            self.row += 1;
            return;
        }
        self.cells.copy_within(self.columns.., 0);
        let last = self.cells.len() - self.columns;
        self.cells[last..].fill(BLANK);
    }

    fn put(&mut self, character: u8, color: Color) {
        match character {
            b'\n' => self.newline(),
            b'\r' => self.column = 0,
            _ => {
                if self.column == self.columns {
                    self.newline();
                }
                let character = match character {
                    b' '..=b'~' => character,
                    _ => b'?',
                };
                self.cells[self.row * self.columns + self.column] = Cell { character, color };
                self.column += 1;
            }
        }
    }

    /// Draw every cell that differs from what the screen shows.
    fn present(&mut self) {
        let (on_width, on_height) = (self.font.width, self.font.height);
        for index in 0..self.cells.len() {
            let cell = self.cells[index];
            if cell == self.shown[index] {
                continue;
            }
            self.shown[index] = cell;
            let x = (index % self.columns + 1) * on_width;
            let y = (index / self.columns + 1) * on_height;
            let (on, off) = (self.screen.pixel(cell.color), 0);
            for row in 0..on_height {
                let line = (self.screen.base + (y + row) * self.screen.stride * BYTES_PER_PIXEL)
                    as *mut u32;
                for column in 0..on_width {
                    let value = if self.font.pixel(cell.character, column, row) {
                        on
                    } else {
                        off
                    };
                    // SAFETY: the grid and its margin lie inside the mode's
                    // visible framebuffer.
                    unsafe { line.add(x + column).write_volatile(value) };
                }
            }
        }
    }
}

/// The boot processor is the only writer. While boot services run, the
/// firmware's timer may draw the running step from its callback, which
/// interrupts the boot processor; [`BUSY`] makes such a nested draw skip.
struct Console(UnsafeCell<Option<Text>>);
// SAFETY: Stela runs on one CPU, and `BUSY` keeps accesses from nesting.
unsafe impl Sync for Console {}
static CONSOLE: Console = Console(UnsafeCell::new(None));
/// The text [`release`] keeps, which [`reclaim`] shows again.
static PARKED: Console = Console(UnsafeCell::new(None));
static BUSY: AtomicBool = AtomicBool::new(false);

fn with<R>(f: impl FnOnce(&mut Text) -> R) -> Option<R> {
    if BUSY.swap(true, Ordering::Acquire) {
        return None;
    }
    // SAFETY: see `Console`; `BUSY` makes this the only live access.
    let result = unsafe { &mut *CONSOLE.0.get() }.as_mut().map(f);
    BUSY.store(false, Ordering::Release);
    result
}

/// Clear the screen and send later text to it.
pub fn install(screen: Framebuffer) {
    screen.clear();
    // SAFETY: see `Console`; no reference to the text is live here.
    unsafe { *CONSOLE.0.get() = Text::new(screen) };
}

/// Stop drawing text: the screen now shows something else. The text is
/// kept for [`reclaim`].
pub fn release() {
    // SAFETY: see `Console`; no reference to the text is live here.
    unsafe { *PARKED.0.get() = (*CONSOLE.0.get()).take() };
}

/// Take the screen back after [`release`] and draw the kept text again, so
/// a stop shows its reason instead of the guest's last frame.
pub fn reclaim() {
    // SAFETY: see `Console`; no reference to either text is live here.
    unsafe {
        if (*CONSOLE.0.get()).is_none()
            && let Some(mut text) = (*PARKED.0.get()).take()
        {
            text.screen.clear();
            text.shown.fill(BLANK);
            text.present();
            *CONSOLE.0.get() = Some(text);
        }
    }
}

/// Whether text reaches the screen.
pub fn active() -> bool {
    with(|_| ()).is_some()
}

/// Write `segments` at the cursor.
pub fn write(segments: &[(&str, Color)]) {
    with(|text| {
        for (part, color) in segments {
            for character in part.bytes() {
                text.put(character, *color);
            }
        }
        text.present();
    });
}

/// Replace the cursor's line with `segments`, cut to the line, and leave
/// the cursor on it, so that a line can change in place.
pub fn rewrite(segments: &[(&str, Color)]) {
    with(|text| {
        let start = text.row * text.columns;
        text.cells[start..start + text.columns].fill(BLANK);
        text.column = 0;
        for (part, color) in segments {
            for character in part.bytes().filter(|&c| c != b'\n') {
                if text.column == text.columns {
                    break;
                }
                text.put(character, *color);
            }
        }
        text.present();
    });
}
