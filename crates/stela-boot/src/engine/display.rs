//! The guest's display on the firmware's framebuffer.
//!
//! iBoot hands XNU a linear framebuffer through `boot_args.Video` and the
//! DeviceTree's `/vram`; XNU's boot console and verbose output draw into it.
//! The mount gives the guest one of the screen mode's size (the mode
//! `console::mode` chose, which the DCP model can advertise), 32 bits per
//! pixel, at the top of guest DRAM, outside the range the kernel manages
//! (`stela_formats::boot_bundle::Machine`), and shows only the frames the
//! modeled DCP presents. XNU's 32-bit pixels are x8r8g8b8 with blue in the
//! low byte (public XNU `osfmk/console/video_console.c`), GOP's BGR order;
//! an RGB or channel-mask mode re-encodes each pixel.
use crate::Result;
use crate::console::{self, Framebuffer};
use crate::output;
use alloc::{boxed::Box, vec};
use core::sync::atomic::{AtomicBool, Ordering};
use stela_contracts::refuse;
use stela_formats::boot_bundle;
use stela_soc::machine::{DisplayLog, Scanout, ScanoutFormat, ScanoutMode};

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

/// `--scanout-mirror`: any scanout, with its newest frame kept at one address
/// that the boot log names. A debugger reads it from there, as QEMU's `memsave`
/// does; a frame's rows are blue-low `width` pixels top to bottom.
pub struct MirroredScanout {
    scanout: Box<dyn Scanout>,
    frame: Box<[u8]>,
}

impl MirroredScanout {
    pub fn new(scanout: Box<dyn Scanout>) -> Self {
        Self {
            scanout,
            frame: Box::default(),
        }
    }
}

impl Scanout for MirroredScanout {
    fn mode(&self) -> ScanoutMode {
        self.scanout.mode()
    }

    fn refresh_millihertz(&self) -> u32 {
        self.scanout.refresh_millihertz()
    }

    fn present(&mut self, rows: &[u8]) -> Result<()> {
        if self.frame.len() != rows.len() {
            self.frame = vec![0; rows.len()].into_boxed_slice();
            let mode = self.mode();
            output::arguments(format_args!(
                "DISPLAY mirror address={:#x} bytes={:#x} mode={}x{}\n",
                self.frame.as_ptr() as usize,
                rows.len(),
                mode.width,
                mode.height,
            ));
        }
        self.frame.copy_from_slice(rows);
        self.scanout.present(rows)
    }
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

    fn refresh_millihertz(&self) -> u32 {
        self.screen.refresh_millihertz()
    }

    fn present(&mut self, rows: &[u8]) -> Result<()> {
        let (width, height) = self.screen.resolution();
        let row_bytes = width * 4;
        if rows.len() < row_bytes * height {
            return Err(refuse!("presented frame is smaller than the scanout mode"));
        }
        if !self.screen.show_frame(rows, || {
            if !DCP_PRESENTED.load(Ordering::Relaxed) {
                if !console::release() {
                    return false;
                }
                DCP_PRESENTED.store(true, Ordering::Relaxed);
            }
            true
        }) {
            return Err(refuse!("firmware framebuffer access was refused"));
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
