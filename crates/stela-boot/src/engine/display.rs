//! The guest's display on the firmware's framebuffer.
//!
//! iBoot hands XNU a linear framebuffer through `boot_args.Video` and the
//! DeviceTree's `/vram`; XNU's boot console and verbose output draw into it.
//! The mount gives the guest one of the screen mode's size (the mode
//! `console::mode` chose, which the DCP model can advertise), 32 bits per
//! pixel, at the top of guest DRAM, outside the range the kernel manages
//! (`stela_runtime::boot_bundle::Machine`), and shows only the frames the
//! modeled DCP presents. XNU's 32-bit pixels are x8r8g8b8 with blue in the
//! low byte (public XNU `osfmk/console/video_console.c`), GOP's BGR order;
//! an RGB or channel-mask mode re-encodes each pixel.
use crate::console::{self, Framebuffer};
use crate::output;
use core::sync::atomic::{AtomicBool, Ordering};
use stela_runtime::boot_bundle;
use stela_runtime::machine::apple::{DisplayLog, Scanout, ScanoutFormat, ScanoutMode};

/// Whether the DCP model has presented a swap: the first one takes the
/// screen from Stela's console.
static DCP_PRESENTED: AtomicBool = AtomicBool::new(false);

/// The host scanout the modeled DCP presents completed swaps to: the UEFI GOP
/// framebuffer at its own mode. The DCP model composes each swap's layers in
/// this scanout's pixel order (blue-low, which `Framebuffer::show_row` writes,
/// re-encoding it for an RGB or channel-mask mode), so a frame arrives here
/// as rows ready for the firmware's mode.
pub struct GopScanout {
    screen: Framebuffer,
}

/// Print one display-log entry: what the guest sent the DCP model. Each
/// line starts `DCP `.
pub fn print_log(entry: &DisplayLog) {
    output::arguments(format_args!("{entry}\n"));
}

impl GopScanout {
    /// A scanout over `screen`, already relocated to the engine's physmap.
    pub fn new(screen: Framebuffer) -> Self {
        Self { screen }
    }
}

impl Scanout for GopScanout {
    fn mode(&self) -> ScanoutMode {
        let (width, height) = self.screen.resolution();
        ScanoutMode {
            width: width as u32,
            height: height as u32,
            // show_row takes blue-low pixels and re-encodes them for the mode.
            format: ScanoutFormat::Bgra8888,
        }
    }

    fn present(&mut self, rows: &[u8]) -> Result<(), &'static str> {
        let (width, height) = self.screen.resolution();
        let row_bytes = width * 4;
        if rows.len() < row_bytes * height {
            return Err("presented frame is smaller than the scanout mode");
        }
        if !DCP_PRESENTED.swap(true, Ordering::Relaxed) {
            console::release();
        }
        for y in 0..height {
            self.screen.show_row(y, &rows[y * row_bytes..][..row_bytes]);
        }
        Ok(())
    }
}

const BYTES_PER_PIXEL: u64 = 4;
/// The guest framebuffer is whole 16 KiB pages.
const PAGE: u64 = 0x4000;

/// The kernel's boot framebuffer for a `width` by `height` screen, ending at
/// `dram_end`. Nothing copies it to the screen: the kernel's boot console
/// and verbose text there reach the boot log through the debug UART, and
/// Stela's own console keeps the screen until the DCP presents macOS's
/// first frame ([`GopScanout`]).
pub fn boot_framebuffer(
    (width, height): (usize, usize),
    dram_end: u64,
) -> Option<boot_bundle::Framebuffer> {
    let (width, height) = (width as u64, height as u64);
    let row_bytes = width * BYTES_PER_PIXEL;
    let bytes = (row_bytes * height).next_multiple_of(PAGE);
    Some(boot_bundle::Framebuffer {
        guest_pa: dram_end.checked_sub(bytes)?,
        bytes,
        row_bytes,
        width,
        height,
        bits_per_pixel: BYTES_PER_PIXEL * 8,
    })
}
