//! The IOMFB method answers of the modeled DCP for one fixed, connected SDR
//! monitor at the scanout's resolution: the truthful replies to the host-call
//! tags (`asig.txt`) the 26A434 normal boot path makes before and during a
//! swap, and a truthful EDID for the mode. Every other tag refuses explicitly,
//! named, so an unmodeled operation is a recorded gap, never a fake success.
//!
//! The tags are `IOMobileFramebufferAP` / `UnifiedPipeline2` / `UPPipe2` RPC
//! methods; their input and output byte sizes are the exact ones the kernel
//! passes to `rpc(tag, in, inlen, out, outlen)` (recovered per call site).
use super::super::scanout::Mode;
use super::link::Request;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// The reply to one host call: the output bytes to write back, or why the
/// call is refused.
pub type Reply = Result<Vec<u8>, &'static str>;

/// A boolean DCP reply (`IOReturn`-style success in the low bit).
fn ok_bool() -> Vec<u8> {
    1u32.to_le_bytes().to_vec()
}

/// Answer a non-DMA host call for the fixed `mode`, or refuse it by name.
/// Swap tags (A403/A406/A407…) are handled by the swap path, which needs the
/// surface DART, so they are not answered here.
pub fn answer(request: &Request, _input: &[u8], mode: Mode) -> Reply {
    let code = request.code();
    let out = request.output_len as usize;
    // A truthful reply must fill exactly the output the driver allocated.
    let sized = |bytes: Vec<u8>| -> Reply {
        if bytes.len() == out {
            Ok(bytes)
        } else {
            Err("DCP method output size differs from the driver's")
        }
    };
    match &code {
        // IOMobileFramebufferAP::start_signal / free_signal / stop_signal.
        b"A401" => sized(ok_bool()),
        // set_display_device(index): one external display, accepted.
        b"A411" => sized(ok_bool()),
        // is_main_display: the one connected display is main.
        b"A412" => sized(ok_bool()),
        // do_create_default_frame_buffer: the model creates it.
        b"A454" => sized(ok_bool()),
        // display_width / display_height.
        b"A451" => sized(mode.width.to_le_bytes().to_vec()),
        b"A452" => sized(mode.height.to_le_bytes().to_vec()),
        // get_display_size(w*, h*): width then height.
        b"A453" => {
            let mut bytes = mode.width.to_le_bytes().to_vec();
            bytes.extend_from_slice(&mode.height.to_le_bytes());
            sized(bytes)
        }
        // UnifiedPipeline2::displayHeight / displayWidth.
        b"A350" => sized(mode.height.to_le_bytes().to_vec()),
        b"A351" => sized(mode.width.to_le_bytes().to_vec()),
        // UnifiedPipeline2::is_external: the one display is external (HDMI).
        b"A379" => sized(ok_bool()),
        // UnifiedPipeline2::headless: not headless, a display is connected.
        b"A384" => sized(0u32.to_le_bytes().to_vec()),
        // setDisplayRefreshProperties / flush_supportsPower answer success.
        b"A475" | b"A478" => sized(if out == 0 { Vec::new() } else { ok_bool() }),
        _ => Err("DCP host-call tag is not modeled"),
    }
}

/// Whether a tag is a swap-path host call the DMA layer handles rather than
/// [`answer`].
pub fn is_swap(code: &[u8; 4]) -> bool {
    matches!(
        code,
        b"A403" | b"A404" | b"A406" | b"A407" | b"A408" | b"A409" | b"A410"
    )
}

/// A truthful EDID 1.4 base block for the fixed `mode` at 60 Hz: enough for
/// the driver to accept one connected SDR digital display of that size. The
/// pixel clock and blanking are nominal CVT-style values; the model advertises
/// exactly this one detailed timing.
pub fn edid(mode: Mode) -> [u8; 128] {
    let mut e = [0u8; 128];
    e[0..8].copy_from_slice(&[0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00]);
    // Manufacturer "STE" (Stela), product 1, serial 1, week 1, year 2026.
    let man = ((b'S' as u16 - 64) << 10) | ((b'T' as u16 - 64) << 5) | (b'E' as u16 - 64);
    e[8..10].copy_from_slice(&man.to_be_bytes());
    e[10..12].copy_from_slice(&1u16.to_le_bytes());
    e[12..16].copy_from_slice(&1u32.to_le_bytes());
    e[16] = 1;
    e[17] = 2026u16.wrapping_sub(1990) as u8;
    e[18] = 1; // EDID 1.4
    e[19] = 4;
    // Digital input, 8 bpc, DisplayPort; digital display.
    e[20] = 0xa5;
    e[21] = (mode.width / 100).min(255) as u8;
    e[22] = (mode.height / 100).min(255) as u8;
    e[23] = 0x78; // gamma 2.2
    e[24] = 0x06; // RGB, preferred-timing-is-native
    // Nominal chromaticity (sRGB-like); exact values are not load-bearing.
    e[25..35].copy_from_slice(&[0xee, 0x91, 0xa3, 0x54, 0x4c, 0x99, 0x26, 0x0f, 0x50, 0x54]);
    // Established/standard timings unused; the detailed timing is the mode.
    let dtd = detailed_timing(mode);
    e[54..72].copy_from_slice(&dtd);
    // Three display descriptors: name, range limits, blank.
    e[72] = 0x00;
    e[75] = 0xfc; // display name
    e[77..77 + 6].copy_from_slice(b"Stela\n");
    e[90] = 0x00;
    e[93] = 0xfd; // range limits
    e[95..95 + 6].copy_from_slice(&[0x32, 0x4b, 0x1e, 0x50, 0x11, 0x00]);
    e[101] = 0x0a;
    e[108] = 0x00;
    e[111] = 0x10; // dummy
    e[126] = 0; // one extension would go here; none
    let sum = e[0..127].iter().fold(0u8, |a, b| a.wrapping_add(*b));
    e[127] = 0u8.wrapping_sub(sum);
    e
}

/// An 18-byte detailed timing descriptor for `mode` at ~60 Hz with CVT-style
/// blanking (160 front/back horizontal, 45 vertical lines).
fn detailed_timing(mode: Mode) -> [u8; 18] {
    let w = mode.width;
    let h = mode.height;
    let hblank = 160u32 + 160;
    let vblank = 45u32;
    let clock = ((w + hblank) * (h + vblank) * 60 / 10_000).max(1);
    let mut d = [0u8; 18];
    d[0..2].copy_from_slice(&(clock as u16).to_le_bytes());
    d[2] = (w & 0xff) as u8;
    d[3] = (hblank & 0xff) as u8;
    d[4] = (((w >> 8) << 4) | (hblank >> 8)) as u8;
    d[5] = (h & 0xff) as u8;
    d[6] = (vblank & 0xff) as u8;
    d[7] = (((h >> 8) << 4) | (vblank >> 8)) as u8;
    d[8] = 48; // h front porch
    d[9] = 32; // h sync width
    d[10] = ((3 << 4) | 10) as u8; // v front porch / sync width low
    d[11] = 0;
    // Image size in mm (nominal), borders 0, digital separate sync +/+.
    d[12] = ((w / 4) & 0xff) as u8;
    d[13] = ((h / 4) & 0xff) as u8;
    d[14] = 0;
    d[15] = 0;
    d[16] = 0;
    d[17] = 0x1e;
    d
}

#[cfg(test)]
mod tests {
    use super::super::super::scanout::{Mode, PixelFormat};
    use super::*;

    const MODE: Mode = Mode {
        width: 1920,
        height: 1080,
        format: PixelFormat::Bgra8888,
    };

    fn request(code: &[u8; 4], input_len: u32, output_len: u32) -> Request {
        let [a, b, c, d] = *code;
        Request {
            tag: u32::from_le_bytes([d, c, b, a]),
            input_len,
            output_len,
        }
    }

    #[test]
    fn display_size_tags_report_the_fixed_mode() {
        assert_eq!(
            answer(&request(b"A451", 0, 4), &[], MODE).unwrap(),
            1920u32.to_le_bytes()
        );
        assert_eq!(
            answer(&request(b"A452", 0, 4), &[], MODE).unwrap(),
            1080u32.to_le_bytes()
        );
        let size = answer(&request(b"A453", 4, 8), &[0; 4], MODE).unwrap();
        assert_eq!(&size[0..4], &1920u32.to_le_bytes());
        assert_eq!(&size[4..8], &1080u32.to_le_bytes());
    }

    #[test]
    fn an_unmodeled_tag_refuses_and_a_wrong_output_size_refuses() {
        assert!(answer(&request(b"A999", 0, 4), &[], MODE).is_err());
        // start_signal with the wrong output size is refused, not faked.
        assert!(answer(&request(b"A401", 0, 8), &[], MODE).is_err());
        assert!(is_swap(b"A407"));
        assert!(!is_swap(b"A401"));
    }

    #[test]
    fn the_edid_is_well_formed_for_the_mode() {
        let e = edid(MODE);
        assert_eq!(&e[0..8], &[0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0]);
        assert_eq!(e.iter().fold(0u8, |a, b| a.wrapping_add(*b)), 0, "checksum");
        // The detailed timing's horizontal active is the mode width.
        let dtd = &e[54..72];
        let hactive = u32::from(dtd[2]) | (u32::from(dtd[4] >> 4) << 8);
        assert_eq!(hactive, 1920);
    }
}
