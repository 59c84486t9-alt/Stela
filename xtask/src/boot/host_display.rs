//! The emulated display's panel, matched to the host's monitor.
//!
//! QEMU's standard VGA reports an EDID whose preferred timing is its `xres`
//! by `yres` at `refresh_rate`, and OVMF starts its GOP in that mode when its
//! own mode table lists it. Stela runs the screen in the GOP's mode and
//! advertises the EDID's refresh to macOS, so a run on a monitor gets that
//! monitor's resolution and refresh rate: the window then shows the guest one
//! pixel to one when full screen. A host whose monitor reports no EDID, or
//! none connected, keeps QEMU's defaults.
use std::fs;
use std::path::Path;

/// A display mode: pixels across and down, and the refresh in millihertz.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Panel {
    pub width: u32,
    pub height: u32,
    pub refresh_millihertz: u32,
}

/// The resolutions OVMF's QEMU video driver lists (`QemuVideoDxe`'s
/// `QemuVideoBochsModes`), which bound the GOP modes a run can start in.
const FIRMWARE_MODES: [(u32, u32); 30] = [
    (640, 480),
    (800, 480),
    (800, 600),
    (832, 624),
    (960, 640),
    (1024, 600),
    (1024, 768),
    (1152, 864),
    (1152, 870),
    (1280, 720),
    (1280, 760),
    (1280, 768),
    (1280, 800),
    (1280, 960),
    (1280, 1024),
    (1360, 768),
    (1366, 768),
    (1400, 1050),
    (1440, 900),
    (1600, 900),
    (1600, 1200),
    (1680, 1050),
    (1920, 1080),
    (1920, 1200),
    (1920, 1440),
    (2000, 2000),
    (2048, 1536),
    (2048, 2048),
    (2560, 1440),
    (2560, 1600),
];

/// The preferred timing of an EDID base block: its first detailed timing
/// descriptor (VESA E-EDID 1.4, section 3.10.1). `None` for a bad header or
/// checksum, or a first descriptor that is not a timing.
pub fn preferred(edid: &[u8]) -> Option<Panel> {
    let block = edid.get(..128)?;
    let header = [0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00];
    if block[..8] != header || block.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)) != 0 {
        return None;
    }
    let d = &block[0x36..0x36 + 18];
    let clock = u64::from(u16::from_le_bytes([d[0], d[1]])) * 10_000;
    let width = u32::from(d[2]) | u32::from(d[4] >> 4) << 8;
    let h_blank = u32::from(d[3]) | u32::from(d[4] & 0xf) << 8;
    let height = u32::from(d[5]) | u32::from(d[7] >> 4) << 8;
    let v_blank = u32::from(d[6]) | u32::from(d[7] & 0xf) << 8;
    let total = u64::from(width + h_blank) * u64::from(height + v_blank);
    if clock == 0 || width == 0 || height == 0 || total == 0 {
        return None;
    }
    let refresh_millihertz = u32::try_from((clock * 1000 + total / 2) / total).ok()?;
    Some(Panel {
        width,
        height,
        refresh_millihertz,
    })
}

/// The panel to emulate for `native`: its resolution when the firmware
/// lists it, else the largest listed one within it of the same shape, else
/// the largest within it; always its refresh. `None` when nothing fits.
pub fn emulated(native: Panel) -> Option<Panel> {
    let within = |&&(width, height): &&(u32, u32)| width <= native.width && height <= native.height;
    let shape = |&&(width, height): &&(u32, u32)| {
        u64::from(width) * u64::from(native.height) == u64::from(height) * u64::from(native.width)
    };
    let area = |&&(width, height): &&(u32, u32)| u64::from(width) * u64::from(height);
    let (width, height) = *FIRMWARE_MODES
        .iter()
        .filter(within)
        .filter(shape)
        .max_by_key(area)
        .or_else(|| FIRMWARE_MODES.iter().filter(within).max_by_key(area))?;
    Some(Panel {
        width,
        height,
        refresh_millihertz: native.refresh_millihertz,
    })
}

/// The preferred timing of the first connected monitor DRM reports, in
/// connector order. Without one (or off Linux) `None`.
pub fn host() -> Option<Panel> {
    let mut connectors: Vec<_> = fs::read_dir(Path::new("/sys/class/drm"))
        .ok()?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.join("edid").exists())
        .collect();
    connectors.sort();
    connectors.into_iter().find_map(|path| {
        let connected = fs::read_to_string(path.join("status")).ok()?;
        (connected.trim() == "connected")
            .then(|| fs::read(path.join("edid")).ok())
            .flatten()
            .and_then(|edid| preferred(&edid))
    })
}

/// QEMU's `VGA` device for `panel`: its EDID's mode and refresh, and video
/// memory for two frames, so that the guest can show one while it fills
/// the other.
pub fn vga_device(panel: Option<Panel>) -> String {
    match panel {
        Some(panel) => {
            let frame = u64::from(panel.width) * u64::from(panel.height) * 4;
            let megabytes = (2 * frame).div_ceil(1 << 20).next_power_of_two().max(16);
            format!(
                "VGA,edid=on,xres={},yres={},refresh_rate={},vgamem_mb={megabytes}",
                panel.width, panel.height, panel.refresh_millihertz
            )
        }
        None => "VGA,edid=on,vgamem_mb=16".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An EDID base block whose preferred timing is `width` by `height`
    /// with the given blanking and pixel clock in 10 kHz units.
    fn edid(width: u32, height: u32, h_blank: u32, v_blank: u32, clock: u16) -> [u8; 128] {
        let mut e = [0u8; 128];
        e[..8].copy_from_slice(&[0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00]);
        let d = &mut e[0x36..0x36 + 18];
        d[..2].copy_from_slice(&clock.to_le_bytes());
        d[2] = width as u8;
        d[3] = h_blank as u8;
        d[4] = ((width >> 8) << 4 | h_blank >> 8) as u8;
        d[5] = height as u8;
        d[6] = v_blank as u8;
        d[7] = ((height >> 8) << 4 | v_blank >> 8) as u8;
        let sum = e[..127].iter().fold(0u8, |a, b| a.wrapping_add(*b));
        e[127] = 0u8.wrapping_sub(sum);
        e
    }

    #[test]
    fn the_preferred_timing_gives_the_mode_and_refresh() {
        // CEA 1080p60: 2200 by 1125 at 148.5 MHz.
        let panel = preferred(&edid(1920, 1080, 280, 45, 14850)).unwrap();
        assert_eq!(
            (panel.width, panel.height, panel.refresh_millihertz),
            (1920, 1080, 60000)
        );
        // 2560x1440 at 144 Hz, CVT reduced blanking: 2720 by 1525 at
        // 597.31 MHz.
        let fast = preferred(&edid(2560, 1440, 160, 85, 59731)).unwrap();
        assert_eq!(fast.refresh_millihertz, 144_000);
        let mut bad = edid(1920, 1080, 280, 45, 14850);
        bad[127] ^= 1;
        assert_eq!(preferred(&bad), None);
        assert_eq!(preferred(&edid(1920, 1080, 280, 45, 0)), None);
    }

    #[test]
    fn the_emulated_panel_is_the_largest_firmware_mode_within_the_monitor() {
        let panel = |width, height| Panel {
            width,
            height,
            refresh_millihertz: 144_000,
        };
        assert_eq!(emulated(panel(2560, 1440)), Some(panel(2560, 1440)));
        // A 4K monitor runs the largest 16:9 mode OVMF lists, at its refresh.
        assert_eq!(emulated(panel(3840, 2160)), Some(panel(2560, 1440)));
        // An ultrawide has no mode of its shape: the largest within it.
        assert_eq!(emulated(panel(3440, 1440)), Some(panel(2560, 1440)));
        assert_eq!(emulated(panel(320, 200)), None);
    }

    #[test]
    fn video_memory_holds_two_frames() {
        let panel = Panel {
            width: 2560,
            height: 1440,
            refresh_millihertz: 144_000,
        };
        assert_eq!(
            vga_device(Some(panel)),
            "VGA,edid=on,xres=2560,yres=1440,refresh_rate=144000,vgamem_mb=32"
        );
        assert_eq!(vga_device(None), "VGA,edid=on,vgamem_mb=16");
    }
}
