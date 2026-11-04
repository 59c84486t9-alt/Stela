//! Text on the firmware's linear framebuffer, so a PC without a serial port
//! still shows the mount's progress, from the startup choice until the
//! guest's display takes the screen.
//!
//! The text sits under Stela's header ([`ui`]), in its colours. Glyphs come
//! from one 8x16 bitmap font drawn at the pages' [`ui::scale`]. The screen
//! runs in the panel's native mode where the firmware offers it ([`mode`]),
//! so each font pixel is whole panel pixels instead of ones the monitor
//! scales up, as in OpenCore's console. The text is a grid of cells kept in
//! memory, and drawing writes only the cells that changed: video memory is
//! write-combining and slow to read back, so scrolling redraws from the grid
//! instead of moving pixels.
pub(crate) mod font;
mod mode;

use crate::ui;
use alloc::{string::String, vec, vec::Vec};
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};
use font::Font;
use stela_boot_core::screen::{Access, Permit};
use stela_soc::machine::ScanoutMasks;
use uefi::{
    Handle,
    boot::{self, OpenProtocolAttributes, OpenProtocolParams, ScopedProtocol},
    proto::console::gop::{GraphicsOutput, ModeInfo, PixelFormat},
};

const BYTES_PER_PIXEL: usize = 4;
/// The most columns of text: wider than the pages' column, as log lines
/// are long.
const COLUMNS: usize = 140;

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

/// A mode's pixel layout, when Stela can draw in it.
fn encoding(mode: &ModeInfo) -> Option<Encoding> {
    match (mode.pixel_format(), mode.pixel_bitmask()) {
        (PixelFormat::Rgb, _) => Some(Encoding::Rgb),
        (PixelFormat::Bgr, _) => Some(Encoding::Bgr),
        (PixelFormat::Bitmask, Some(masks)) => {
            ScanoutMasks::new(masks.red, masks.green, masks.blue)
                .ok()
                .map(Encoding::Masks)
        }
        (PixelFormat::Bitmask | PixelFormat::BltOnly, _) => None,
    }
}

/// The first GOP, read-only (see [`Framebuffer::from_firmware`]), and its
/// handle.
fn gop() -> Option<(Handle, ScopedProtocol<GraphicsOutput>)> {
    let handle = boot::get_handle_for_protocol::<GraphicsOutput>().ok()?;
    // SAFETY: the protocol is only used while boot services run.
    let gop = unsafe {
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
    Some((handle, gop))
}

static FIRMWARE_ACCESS: Access = Access::new();

struct ScreenUse(Option<Permit<'static>>);

impl Drop for ScreenUse {
    fn drop(&mut self) {
        if self.0.is_some() {
            // SAFETY: SFENCE is available on x86-64. Complete this CPU's
            // write-combining stores before releasing its writer permit.
            unsafe { core::arch::asm!("sfence", options(nostack, preserves_flags)) };
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
    firmware: bool,
    pub(crate) pci_source: Option<crate::pci_io::FramebufferSource>,
}

impl Framebuffer {
    /// The first GOP's mode, when it is a linear 32-bit framebuffer: RGB,
    /// BGR or channel masks (`scanout::ChannelMasks`). The first call
    /// switches the GOP to the best mode ([`mode`]). A `PixelBltOnly` mode
    /// has no framebuffer to draw in once boot services end, so it
    /// gives none, as do masks that `ChannelMasks` refuses. Boot managers
    /// keep their own handle open, so this only reads the protocol rather
    /// than opening it exclusively.
    pub fn from_firmware() -> Option<Self> {
        Self::firmware_mode().map(|(_, screen)| screen)
    }

    fn firmware_mode() -> Option<(Handle, Self)> {
        let (handle, mut gop) = gop()?;
        mode::select(handle, &mut gop);
        Some((handle, Self::current(&mut gop)?))
    }

    /// Capture the original display function before the engine handoff.
    pub(crate) fn for_engine() -> crate::Result<Option<Self>> {
        let Some((handle, mut screen)) = Self::firmware_mode() else {
            return Ok(None);
        };
        match crate::pci_io::framebuffer_source(handle, screen.base as u64, screen.bytes as u64) {
            Ok(source) => screen.pci_source = source,
            Err(crate::pci_io::Error::Release(status)) => {
                return Err(
                    stela_contracts::refuse!("GOP PCI resource buffer remains retained: {status}", status = ?status),
                );
            }
            Err(error) => crate::output::arguments(format_args!(
                "GOP PCI source observation refused: {error}\n"
            )),
        }
        Ok(Some(screen))
    }

    /// `gop`'s current mode, when Stela can draw in it.
    fn current(gop: &mut GraphicsOutput) -> Option<Self> {
        let mode = gop.current_mode_info();
        let encoding = encoding(&mode)?;
        let (width, height) = mode.resolution();
        let mut buffer = gop.frame_buffer();
        let framebuffer = Self {
            base: buffer.as_mut_ptr() as usize,
            bytes: buffer.size(),
            width,
            height,
            stride: mode.stride(),
            encoding,
            firmware: true,
            pci_source: None,
        };
        (framebuffer.stride * framebuffer.height * BYTES_PER_PIXEL <= framebuffer.bytes)
            .then_some(framebuffer)
    }

    /// A blue-low `width` by `height` screen at `base`, `stride` pixels a row.
    #[cfg(feature = "nvk")]
    pub fn linear(base: usize, width: usize, height: usize, stride: usize) -> Self {
        Self {
            base,
            bytes: stride * height * BYTES_PER_PIXEL,
            width,
            height,
            stride,
            encoding: Encoding::Bgr,
            firmware: false,
            pci_source: None,
        }
    }

    /// The same mode reached at another address (the engine's physmap).
    pub fn relocated(self, base: usize) -> Self {
        Self { base, ..self }
    }

    /// Visible pixels across and down.
    pub fn resolution(&self) -> (usize, usize) {
        (self.width, self.height)
    }

    pub(crate) fn available(&self) -> bool {
        !self.firmware || !FIRMWARE_ACCESS.is_retired()
    }

    fn use_screen(&self) -> Option<ScreenUse> {
        if self.firmware {
            FIRMWARE_ACCESS
                .enter()
                .map(|permit| ScreenUse(Some(permit)))
        } else {
            Some(ScreenUse(None))
        }
    }

    /// Present one complete frame with a single permit, including the
    /// console's transfer to guest scanout.
    pub(crate) fn show_frame(&self, rows: &[u8], before: impl FnOnce() -> bool) -> bool {
        let Some(_access) = self.use_screen() else {
            return false;
        };
        let row_bytes = self.width * BYTES_PER_PIXEL;
        if row_bytes == 0 || !before() {
            return false;
        }
        for (y, pixels) in rows.chunks_exact(row_bytes).take(self.height).enumerate() {
            self.write_row(y, pixels);
        }
        true
    }

    /// Row `y` from 32-bit pixels with blue in the low byte, as many as fit.
    pub fn show_row(&self, y: usize, pixels: &[u8]) {
        if y >= self.height {
            return;
        }
        let Some(_access) = self.use_screen() else {
            return;
        };
        self.write_row(y, pixels);
    }

    fn write_row(&self, y: usize, pixels: &[u8]) {
        let line = (self.base + y * self.stride * BYTES_PER_PIXEL) as *mut u32;
        let (pixels, _) = pixels.as_chunks::<BYTES_PER_PIXEL>();
        let pixels = &pixels[..pixels.len().min(self.width)];
        for (column, pixel) in pixels.iter().enumerate() {
            let value = self.encoding.encode(u32::from_le_bytes(*pixel));
            // SAFETY: `column < width` and `y < height`, inside the mode's
            // visible framebuffer.
            unsafe { line.add(column).write_volatile(value) };
        }
    }

    /// Pixels per row in memory, at least the width.
    #[cfg(feature = "diagnostics")]
    pub fn stride(&self) -> usize {
        self.stride
    }

    /// The mode's pixel layout, as GOP names it.
    #[cfg(feature = "diagnostics")]
    pub fn format(&self) -> &'static str {
        match self.encoding {
            Encoding::Bgr => "BGR",
            Encoding::Rgb => "RGB",
            Encoding::Masks(_) => "bitmask",
        }
    }

    /// The same mode with only its top `height` rows, so that text written
    /// to it leaves the rows below for something else.
    #[cfg(feature = "diagnostics")]
    pub fn top(self, height: usize) -> Self {
        Self {
            height: height.min(self.height),
            ..self
        }
    }

    fn pixel(&self, color: Color) -> u32 {
        self.encoding.encode(match color {
            Color::Text => ui::TEXT,
            Color::Dim => ui::DIM,
            Color::Good => ui::BLUE,
            Color::Warn | Color::Busy => ui::ORANGE,
            Color::Fatal => ui::RED,
        })
    }

    /// The pixel value of a colour in this mode's layout.
    #[cfg(feature = "diagnostics")]
    pub fn rgb(&self, red: u8, green: u8, blue: u8) -> u32 {
        let (red, green, blue) = (u32::from(red), u32::from(green), u32::from(blue));
        self.encoding.encode((red << 16) | (green << 8) | blue)
    }

    /// Fill `width` by `height` pixels from (`x`, `y`), cut to the mode's
    /// visible rows and columns.
    pub fn rectangle(&self, x: usize, y: usize, width: usize, height: usize, value: u32) {
        let Some(_access) = self.use_screen() else {
            return;
        };
        for row in y..(y + height).min(self.height) {
            let line = (self.base + row * self.stride * BYTES_PER_PIXEL) as *mut u32;
            for column in x..(x + width).min(self.width) {
                // SAFETY: inside the mode's visible framebuffer.
                unsafe { line.add(column).write_volatile(value) };
            }
        }
    }

    /// The pixel at (`x`, `y`), which is visible.
    #[cfg(feature = "diagnostics")]
    pub fn read(&self, x: usize, y: usize) -> Option<u32> {
        assert!(x < self.width && y < self.height, "pixel outside the mode");
        let _access = self.use_screen()?;
        let line = (self.base + y * self.stride * BYTES_PER_PIXEL) as *const u32;
        // SAFETY: inside the mode's visible framebuffer, as checked.
        Some(unsafe { line.add(x).read_volatile() })
    }

    /// Stela's background under its header.
    fn clear(&self) {
        let background = self.encoding.encode(ui::BACKGROUND);
        self.rectangle(0, 0, self.width, self.height, background);
        if let Some(font) = font::console() {
            let mut header = ui::Canvas::header_band(*self, font);
            header.header();
            header.show();
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
    /// Screen pixels per font pixel.
    scale: usize,
    /// The screen pixel the grid starts at, across and down.
    left: usize,
    top: usize,
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
        let font = font::console()?;
        let scale = ui::scale(height);
        let top = ui::HEADER * scale;
        // A centred column, at least a cell from either side, over a margin
        // of a cell below.
        let columns = (width / (font.width * scale)).checked_sub(2)?.min(COLUMNS);
        let left = (width - columns * font.width * scale) / 2;
        let rows = (height.checked_sub(top)? / (font.height * scale)).checked_sub(1)?;
        (columns > 0 && rows > 0).then(|| Self {
            screen,
            font,
            scale,
            left,
            top,
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

    /// Carry on at `indent` on a blank row under the cursor's.
    fn wrap(&mut self, indent: usize) {
        self.newline();
        let start = self.row * self.columns;
        self.cells[start..start + self.columns].fill(BLANK);
        self.column = indent.min(self.columns - 1);
    }

    fn put(&mut self, character: u8, color: Color) {
        match character {
            b'\n' => self.newline(),
            b'\r' => self.column = 0,
            _ => {
                if self.column == self.columns {
                    self.newline();
                }
                self.cells[self.row * self.columns + self.column] = Cell {
                    character: printable(character),
                    color,
                };
                self.column += 1;
            }
        }
    }

    /// Draw every cell that differs from what the screen shows.
    fn present(&mut self) {
        let Some(_access) = self.screen.use_screen() else {
            return;
        };
        let s = self.scale;
        let (on_width, on_height) = (self.font.width * s, self.font.height * s);
        let off = self.screen.encoding.encode(ui::BACKGROUND);
        for index in 0..self.cells.len() {
            let cell = self.cells[index];
            if cell == self.shown[index] {
                continue;
            }
            self.shown[index] = cell;
            let x = self.left + index % self.columns * on_width;
            let y = self.top + index / self.columns * on_height;
            let on = self.screen.pixel(cell.color);
            for row in 0..on_height {
                let line = (self.screen.base + (y + row) * self.screen.stride * BYTES_PER_PIXEL)
                    as *mut u32;
                for column in 0..on_width {
                    let value = if self.font.pixel(cell.character, column / s, row / s) {
                        on
                    } else {
                        off
                    };
                    // SAFETY: the grid and its margins lie inside the mode's
                    // visible framebuffer.
                    unsafe { line.add(x + column).write_volatile(value) };
                }
            }
        }
    }
}

fn printable(character: u8) -> u8 {
    match character {
        b' '..=b'~' => character,
        _ => b'?',
    }
}

/// Firmware timer callbacks may interrupt the boot CPU. A nested operation
/// skips the console while its current owner holds BUSY.
struct Console(UnsafeCell<Option<Text>>);
// SAFETY: every access is exclusive through BUSY.
unsafe impl Sync for Console {}
static CONSOLE: Console = Console(UnsafeCell::new(None));
/// The text [`release`] keeps, which [`reclaim`] shows again.
static PARKED: Console = Console(UnsafeCell::new(None));
static BUSY: AtomicBool = AtomicBool::new(false);

fn with_consoles<R>(f: impl FnOnce(&mut Option<Text>, &mut Option<Text>) -> R) -> Option<R> {
    if BUSY.swap(true, Ordering::Acquire) {
        return None;
    }
    // SAFETY: BUSY makes these the only live references to either console.
    let result = unsafe { f(&mut *CONSOLE.0.get(), &mut *PARKED.0.get()) };
    BUSY.store(false, Ordering::Release);
    Some(result)
}

fn with<R>(f: impl FnOnce(&mut Text) -> R) -> Option<R> {
    with_consoles(|active, _| {
        active
            .as_mut()
            .filter(|text| text.screen.available())
            .map(f)
    })
    .flatten()
}

/// Clear the screen and send later text to it.
pub fn install(screen: Framebuffer) {
    with_consoles(|active, parked| {
        if screen.available() {
            screen.clear();
            *active = Text::new(screen);
            *parked = None;
        }
    });
}

/// Keep the text [`release`] kept for `screen`, which now shows.
#[cfg(feature = "nvk")]
pub fn parked_on(screen: Framebuffer) {
    with_consoles(|_, parked| {
        if let Some(text) = parked {
            text.screen = screen;
        }
    });
}

/// Stop drawing text: the screen now shows something else. The text is
/// kept for [`reclaim`]. False means another console operation was active.
pub fn release() -> bool {
    with_consoles(|active, parked| {
        if let Some(text) = active.take() {
            *parked = Some(text);
        }
    })
    .is_some()
}

/// Permanently stop the boot CPU and guest compositor from touching GOP.
/// Parked text can still be rebound to a native scanout.
pub(crate) fn retire_firmware() -> bool {
    with_consoles(|active, parked| {
        if !FIRMWARE_ACCESS.retire() {
            return false;
        }
        if active.as_ref().is_some_and(|text| text.screen.firmware) {
            *parked = active.take();
        }
        true
    })
    .unwrap_or(false)
}

/// Take the screen back after [`release`] and draw the kept text again, so
/// a stop shows its reason instead of the guest's last frame.
pub fn reclaim() {
    with_consoles(|active, parked| {
        if active.is_none()
            && parked.as_ref().is_some_and(|text| text.screen.available())
            && let Some(mut text) = parked.take()
        {
            text.screen.clear();
            text.shown.fill(BLANK);
            text.present();
            *active = Some(text);
        }
    });
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

/// Replace the cursor's line with `segments` and carry on under it: a word
/// that would pass the edge starts the next row, `indent` cells in. The
/// cursor ends on the last row.
pub fn rewrite_wrapped(segments: &[(&str, Color)], indent: usize) {
    with(|text| {
        let start = text.row * text.columns;
        text.cells[start..start + text.columns].fill(BLANK);
        text.column = 0;
        let room = text.columns.saturating_sub(indent);
        for (part, color) in segments {
            for word in part.split_inclusive(' ') {
                let length = word.trim_end().len();
                if text.column > indent && text.column + length > text.columns && length <= room {
                    text.wrap(indent);
                }
                for character in word.bytes().filter(|&c| c != b'\n') {
                    if text.column == text.columns {
                        if character == b' ' {
                            continue;
                        }
                        text.wrap(indent);
                    }
                    text.put(character, *color);
                }
            }
        }
        text.present();
    });
}

/// Show `lines` on the rows under the cursor's, `indent` cells in and each
/// wrapped onto as many rows as it takes, the last rows when not all fit,
/// and blank the rest; the cursor stays. An empty `lines` clears what an
/// earlier call showed.
pub fn below(lines: &[String], indent: usize, color: Color) {
    with(|text| {
        let width = text.columns.saturating_sub(indent).max(1);
        let rows_of = |line: &String| line.len().div_ceil(width).max(1);
        let first = text.row + 1;
        let total: usize = lines.iter().map(rows_of).sum();
        let skip = total.saturating_sub(text.rows - first);
        let mut pieces = lines.iter().flat_map(|line| {
            let bytes = line.as_bytes();
            let end = |k: usize| (k * width).min(bytes.len());
            (0..rows_of(line)).map(move |k| &bytes[end(k)..end(k + 1)])
        });
        for _ in 0..skip {
            pieces.next();
        }
        for row in first..text.rows {
            let cells = &mut text.cells[row * text.columns..(row + 1) * text.columns];
            cells.fill(BLANK);
            if let Some(piece) = pieces.next() {
                for (cell, &character) in cells.iter_mut().skip(indent).zip(piece) {
                    *cell = Cell {
                        character: printable(character),
                        color,
                    };
                }
            }
        }
        text.present();
    });
}
