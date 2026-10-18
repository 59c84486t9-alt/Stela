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
use stela_runtime::{boot_bundle, machine::Host};

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
