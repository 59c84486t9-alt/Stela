//! The guest's screen mode, which its boot framebuffer, the kernel's
//! `boot_args.Video` and the external display pipe's framebuffer geometry
//! in the device tree take: the firmware's screen, else the started GPU's
//! display, else [`DEFAULT`].
//!
//! A PC whose firmware shows no picture (a warm reset after which its GOP
//! drives nothing, a GPU whose firmware has no GOP mode, no monitor at the
//! firmware's handoff) still boots: the GPU's connected output gives its
//! mode, and without one the guest starts in [`DEFAULT`], which a display a
//! GPU detects later shows.
use alloc::{format, string::String};

/// The mode of a guest whose PC has neither a firmware screen nor a GPU
/// display: 1920x1080, the commonest monitor's native mode, at 60 Hz.
pub const DEFAULT: (usize, usize) = (1920, 1080);
/// [`DEFAULT`]'s refresh in millihertz.
pub const DEFAULT_REFRESH_MILLIHERTZ: u32 = 60_000;

/// Where the guest's screen mode came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Firmware,
    Gpu,
    Default,
}

/// The guest's screen mode from the `firmware` screen's and the started
/// GPU's display's, when they exist and have pixels.
pub fn choose(
    firmware: Option<(usize, usize)>,
    gpu: Option<(usize, usize)>,
) -> ((usize, usize), Source) {
    let shown = |size: Option<(usize, usize)>| size.filter(|&(width, height)| width * height != 0);
    match (shown(firmware), shown(gpu)) {
        (Some(size), _) => (size, Source::Firmware),
        (None, Some(size)) => (size, Source::Gpu),
        (None, None) => (DEFAULT, Source::Default),
    }
}

/// The log line that says where a mode not the firmware's came from; none
/// for the firmware's, which the `DISPLAY` lines already name.
pub fn line(((width, height), source): ((usize, usize), Source)) -> Option<String> {
    match source {
        Source::Firmware => None,
        Source::Gpu => Some(format!(
            "DISPLAY no firmware screen: the guest's screen is {width}x{height}, the GPU \
             display's mode\n"
        )),
        Source::Default => Some(format!(
            "DISPLAY no firmware screen and no GPU display: the guest's screen is \
             {width}x{height}, the default mode\n"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The firmware's screen wins; without it the GPU's display gives the
    /// mode, and without both the default does, each said in one line.
    #[test]
    fn the_guest_screen_follows_the_firmware_then_the_gpu_then_the_default() {
        let firmware = Some((2560, 1440));
        let gpu = Some((3440, 1440));
        assert_eq!(choose(firmware, gpu), ((2560, 1440), Source::Firmware));
        assert_eq!(line(choose(firmware, gpu)), None);
        assert_eq!(choose(None, gpu), ((3440, 1440), Source::Gpu));
        assert_eq!(
            line(choose(None, gpu)).as_deref(),
            Some(
                "DISPLAY no firmware screen: the guest's screen is 3440x1440, the GPU display's mode\n"
            )
        );
        // A size without pixels is no screen.
        assert_eq!(
            choose(Some((0, 0)), Some((0, 1080))),
            (DEFAULT, Source::Default)
        );
        assert_eq!(
            line(choose(None, None)).as_deref(),
            Some(
                "DISPLAY no firmware screen and no GPU display: the guest's screen is \
                 1920x1080, the default mode\n"
            )
        );
    }
}
