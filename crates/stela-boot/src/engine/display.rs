//! The guest's framebuffer, shown on the firmware's.
//!
//! iBoot hands XNU a linear framebuffer through `boot_args.Video` and the
//! DeviceTree's `/vram`; XNU's boot console and verbose output draw into it.
//! The mount gives the guest one of the firmware mode's size, 32 bits per
//! pixel, at the top of guest DRAM, outside the range the kernel manages
//! (`stela_runtime::boot_bundle::Machine`), and copies it to the firmware's
//! framebuffer between engine slices. XNU's 32-bit pixels are x8r8g8b8 with
//! blue in the low byte (public XNU `osfmk/console/video_console.c`), GOP's
//! BGR order; an RGB mode swaps red and blue.
use super::host::BareHost;
use crate::console::{self, Framebuffer};
use alloc::vec;
use stela_runtime::machine::apple::{Scanout, ScanoutFormat, ScanoutMode};
use stela_runtime::{boot_bundle, machine::Host};

/// The host scanout the modeled DCP presents completed swaps to: the UEFI GOP
/// framebuffer at its own mode. The DCP model converts each front surface to
/// this scanout's pixel order (blue-low, which `Framebuffer::show_row` writes,
/// swapping red and blue for an RGB panel) and honors its stride, so a frame
/// arrives here as rows ready for the firmware's mode.
pub struct GopScanout {
    screen: Framebuffer,
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
            // show_row takes blue-low pixels and swaps for an RGB panel.
            format: ScanoutFormat::Bgra8888,
        }
    }

    fn present(&mut self, rows: &[u8]) -> Result<(), &'static str> {
        let (width, height) = self.screen.resolution();
        let row_bytes = width * 4;
        if rows.len() < row_bytes * height {
            return Err("presented frame is smaller than the scanout mode");
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

pub struct Display {
    screen: Framebuffer,
    guest: boot_bundle::Framebuffer,
    shown: bool,
}

impl Display {
    /// A guest framebuffer the size of `screen`, ending at `dram_end`.
    pub fn new(screen: Framebuffer, dram_end: u64) -> Option<Self> {
        let (width, height) = screen.resolution();
        let (width, height) = (width as u64, height as u64);
        let row_bytes = width * BYTES_PER_PIXEL;
        let bytes = (row_bytes * height).next_multiple_of(PAGE);
        let guest_pa = dram_end.checked_sub(bytes)?;
        Some(Self {
            screen,
            guest: boot_bundle::Framebuffer {
                guest_pa,
                bytes,
                row_bytes,
                width,
                height,
                bits_per_pixel: BYTES_PER_PIXEL * 8,
            },
            shown: false,
        })
    }

    pub fn framebuffer(&self) -> boot_bundle::Framebuffer {
        self.guest
    }

    /// Copy the guest framebuffer to the screen. The first copy takes the
    /// screen from the mount's text console.
    pub fn show(&mut self, host: &mut BareHost) {
        if !self.shown {
            console::release();
            self.shown = true;
        }
        let mut row = vec![0; self.guest.row_bytes as usize];
        for y in 0..self.guest.height {
            let address = self.guest.guest_pa + y * self.guest.row_bytes;
            if !host.read_ram(address, &mut row) {
                return;
            }
            self.screen.show_row(y as usize, &row);
        }
    }
}
