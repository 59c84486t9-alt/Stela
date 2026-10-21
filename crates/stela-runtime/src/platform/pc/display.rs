//! Which of the firmware's graphics modes the mount runs the screen in.
//!
//! A boot that keeps the mode the firmware left often runs below the
//! panel's resolution (QEMU's OVMF leaves 1280x800 whatever the display),
//! and the monitor scales that up into large, soft text. Boot managers
//! switch to a larger mode first, as OpenCore's `Resolution=Max` does, and
//! Linux's own display drivers set the panel's. The mount chooses once,
//! while boot services run, and keeps that mode for the whole boot: its
//! console and the guest's display share it, and the mode cannot change
//! after ExitBootServices.
//!
//! [`choose`] takes, among the modes Stela can draw in and the guest's
//! display can run, the panel's native resolution, the preferred timing of
//! its EDID ([`native`]), when the firmware offers it. It never takes a mode
//! larger than one the panel is known to show: without that mode it takes
//! the largest within it, and without an EDID it keeps the firmware's mode,
//! which the firmware set up on that panel, because a firmware may list
//! modes the panel cannot show (QEMU's OVMF lists 2048x2048 on any display).
//!
//! The guest's display caps the choice ([`guest_takes`]): the modeled DCP
//! advertises the screen's mode to macOS as an EDID detailed timing
//! (`platform::apple::dcp::modes`), which holds at most 4095 pixels on each
//! axis and a 655.35 MHz pixel clock at 60 Hz. 3840x2160 fits; a 5K or 6K
//! panel runs the largest smaller mode its firmware offers.
use super::super::apple::{
    dcp::modes::Advertised,
    scanout::{Mode as ScanoutMode, PixelFormat},
};
use core::{cmp::Reverse, fmt};

/// One of the firmware's graphics modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mode {
    /// The mode's number, which selects it.
    pub index: u32,
    pub width: u32,
    pub height: u32,
    /// Whether Stela can draw in it: a linear framebuffer of 32-bit pixels.
    pub drawable: bool,
}

impl Mode {
    fn pixels(&self) -> u64 {
        u64::from(self.width) * u64::from(self.height)
    }
}

/// Why [`choose`] took its mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The panel's EDID prefers its resolution.
    Native,
    /// The largest mode within the panel's native resolution, which no
    /// usable mode has.
    WithinNative,
    /// No EDID: the firmware's mode.
    Firmware,
    /// No EDID, and the guest cannot run the firmware's mode: the largest
    /// mode within it.
    WithinFirmware,
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Reason::Native => "the panel's native resolution",
            Reason::WithinNative => "the largest mode within the panel's native resolution",
            Reason::Firmware => "the firmware's mode, as no EDID names the panel's",
            Reason::WithinFirmware => "the largest mode within the firmware's",
        })
    }
}

/// The EDID base block's fixed header.
const EDID_HEADER: [u8; 8] = [0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00];
const EDID_BLOCK: usize = 128;
/// The first 18-byte detailed timing descriptor, the preferred timing
/// (VESA E-EDID 1.4, section 3.10.1; 1.3 requires it to be the
/// preferred one too).
const PREFERRED_TIMING: usize = 0x36;

/// The active width and height of an EDID's preferred timing: the panel's
/// native resolution. `None` for a block whose header or checksum is wrong,
/// or whose first descriptor is not a detailed timing (pixel clock 0).
pub fn native(edid: &[u8]) -> Option<(u32, u32)> {
    let block = edid.get(..EDID_BLOCK)?;
    if block[..8] != EDID_HEADER || block.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)) != 0 {
        return None;
    }
    let d = &block[PREFERRED_TIMING..PREFERRED_TIMING + 18];
    if d[0] == 0 && d[1] == 0 {
        return None;
    }
    let width = u32::from(d[2]) | u32::from(d[4] >> 4) << 8;
    let height = u32::from(d[5]) | u32::from(d[7] >> 4) << 8;
    (width != 0 && height != 0).then_some((width, height))
}

/// Whether the guest's display can run a `width` by `height` screen: the
/// DCP model can advertise it.
pub fn guest_takes(width: u32, height: u32) -> bool {
    Advertised::new(ScanoutMode {
        width,
        height,
        format: PixelFormat::Bgra8888,
    })
    .is_ok()
}

/// The mode to run among `modes`, given the one in use (`current`) and the
/// panel's native resolution when known: that resolution, else the
/// firmware's, or the largest mode within it. Among equals the current mode
/// wins, then the lowest number, so a firmware already in the best mode is
/// left alone. `None` when no such mode is drawable and fits the guest: the
/// caller keeps the current one.
pub fn choose(modes: &[Mode], current: u32, native: Option<(u32, u32)>) -> Option<(Mode, Reason)> {
    let (bound, exact, within) = match native {
        Some(native) => (native, Reason::Native, Reason::WithinNative),
        None => {
            let mode = modes.iter().find(|mode| mode.index == current)?;
            (
                (mode.width, mode.height),
                Reason::Firmware,
                Reason::WithinFirmware,
            )
        }
    };
    let usable = modes.iter().filter(|mode| {
        mode.drawable
            && mode.width <= bound.0
            && mode.height <= bound.1
            && guest_takes(mode.width, mode.height)
    });
    // Lower ranks first: the current mode, then the lowest number.
    let rank = |mode: &Mode| (mode.index != current, mode.index);
    let mode = usable.min_by_key(|mode| (Reverse(mode.pixels()), rank(mode)))?;
    let reason = if (mode.width, mode.height) == bound {
        exact
    } else {
        within
    };
    Some((*mode, reason))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode(index: u32, width: u32, height: u32) -> Mode {
        Mode {
            index,
            width,
            height,
            drawable: true,
        }
    }

    /// A base block whose preferred timing is `width` by `height`, built by
    /// the DCP model's own EDID encoder.
    fn edid(width: u32, height: u32) -> [u8; 128] {
        crate::platform::apple::dcp::modes::edid(ScanoutMode {
            width,
            height,
            format: PixelFormat::Bgra8888,
        })
        .unwrap()
    }

    #[test]
    fn the_native_resolution_is_the_preferred_timing() {
        assert_eq!(native(&edid(2560, 1440)), Some((2560, 1440)));
        assert_eq!(native(&edid(3840, 2160)), Some((3840, 2160)));
        let mut bad = edid(1920, 1080);
        bad[127] ^= 1;
        assert_eq!(native(&bad), None, "checksum");
        let mut bad = edid(1920, 1080);
        bad[0] = 1;
        assert_eq!(native(&bad), None, "header");
        let mut descriptor = edid(1920, 1080);
        descriptor[0x36..0x38].fill(0);
        assert_eq!(native(&descriptor), None, "display descriptor");
        assert_eq!(native(&edid(1920, 1080)[..127]), None, "short");
    }

    #[test]
    fn the_guest_takes_up_to_4k() {
        assert!(guest_takes(1920, 1080));
        assert!(guest_takes(3840, 2160));
        assert!(!guest_takes(4096, 2160));
        assert!(!guest_takes(5120, 2880));
        assert!(!guest_takes(0, 768));
    }

    #[test]
    fn the_native_mode_wins_and_nothing_larger_is_taken() {
        let modes = [mode(0, 800, 600), mode(1, 1920, 1080), mode(2, 2560, 1600)];
        assert_eq!(
            choose(&modes, 0, Some((1920, 1080))),
            Some((modes[1], Reason::Native))
        );
        // A native resolution the firmware does not offer.
        assert_eq!(
            choose(&modes, 0, Some((1366, 768))),
            Some((modes[0], Reason::WithinNative))
        );
        assert_eq!(choose(&modes, 0, Some((640, 480))), None);
    }

    #[test]
    fn without_an_edid_the_firmware_mode_stays() {
        let modes = [mode(0, 1280, 800), mode(1, 2048, 2048), mode(2, 1024, 768)];
        assert_eq!(choose(&modes, 0, None), Some((modes[0], Reason::Firmware)));
        // A firmware mode the guest cannot run gives way to one within it.
        let modes = [
            mode(0, 5120, 2880),
            mode(1, 3840, 2160),
            mode(2, 6016, 3384),
        ];
        assert_eq!(
            choose(&modes, 0, None),
            Some((modes[1], Reason::WithinFirmware))
        );
        // An unlisted firmware mode leaves the choice to the caller.
        assert_eq!(choose(&modes, 9, None), None);
    }

    #[test]
    fn modes_stela_cannot_draw_or_the_guest_cannot_run_are_skipped() {
        let blt_only = Mode {
            drawable: false,
            ..mode(1, 2560, 1440)
        };
        let modes = [mode(0, 1024, 768), blt_only, mode(2, 5120, 2880)];
        assert_eq!(
            choose(&modes, 0, Some((5120, 2880))),
            Some((modes[0], Reason::WithinNative))
        );
        assert_eq!(choose(&[blt_only], 1, None), None);
    }

    #[test]
    fn ties_keep_the_current_mode_then_the_lowest_number() {
        let modes = [
            mode(0, 1920, 1080),
            mode(1, 1080, 1920),
            mode(2, 1920, 1080),
        ];
        let native = Some((1920, 1080));
        assert_eq!(choose(&modes, 2, native), Some((modes[2], Reason::Native)));
        assert_eq!(choose(&modes, 1, native), Some((modes[0], Reason::Native)));
        assert_eq!(choose(&modes, 7, native), Some((modes[0], Reason::Native)));
        assert_eq!(
            choose(&modes, 1, Some((1920, 1920))),
            Some((modes[1], Reason::WithinNative))
        );
    }
}
