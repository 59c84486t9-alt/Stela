//! The IOMFB method service of the modeled DCP for one fixed, connected SDR
//! monitor: the truthful replies to the host-call tags the 26A434 normal boot
//! path makes, and the one callback that path provokes. Every tag outside the
//! verified fixed-monitor surface refuses explicitly, named, so an unmodeled
//! operation is a recorded gap, never a fake success.
//!
//! The tags are `IOMobileFramebufferAP` / `UnifiedPipeline2` / `UPPipeAP_H13P`
//! RPC methods; their input and output byte sizes are the exact ones the AP
//! passes to `rpc(tag, in, inlen, out, outlen)`, recovered per call site and
//! recorded in docs/research/display-gpu.md ("Verified method/callback
//! matrix"). The one callback the model makes is `D120 start_hardware_boot`,
//! nested inside the AP's `A401 start_signal`, exactly as the real firmware
//! does (`UnifiedPipeline2::start_hardware_boot`, kernel file 0x2a5d7cc, runs
//! as the AP's D120 handler and nests its own A-calls back, which re-enter
//! [`Methods::call`]).
//!
//! The model inherits the boot framebuffer rather than letting the DCP
//! allocate a new default one: `A454 do_create_default_frame_buffer` answers
//! false, which is exactly the branch (`start_hardware_boot` 0x2a5d804) that
//! skips the `A036`/`A037` default-framebuffer-info path. Swaps and the
//! coprocessor-initiated service/property callbacks stay refused by name
//! until the `dart-dispext0` surface path and the restore-boot callback
//! ordering are closed (see the doc's "Open" section).
use super::super::scanout::{Mode, Scanout};
use super::rpc::{Service, Step};
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// The IOMFB methods of the one connected display, presenting to a host
/// scanout.
pub struct Methods {
    scanout: Box<dyn Scanout>,
    /// Why the last call refused, kept so the device layer can name the exact
    /// tag in its refusal line.
    last_refusal: Option<String>,
}

impl Methods {
    pub fn new(scanout: Box<dyn Scanout>) -> Self {
        Self {
            scanout,
            last_refusal: None,
        }
    }

    /// The fixed mode the one connected display runs.
    pub fn mode(&self) -> Mode {
        self.scanout.mode()
    }

    /// The scanout, for the swap path once it is modeled.
    pub fn scanout_mut(&mut self) -> &mut dyn Scanout {
        &mut *self.scanout
    }
}

impl Service for Methods {
    fn call(
        &mut self,
        tag: [u8; 4],
        input: &[u8],
        output: u32,
    ) -> Result<Step<Self>, &'static str> {
        // A401 start_signal: the coprocessor nests D120 start_hardware_boot
        // back into the AP before answering. The AP's D120 handler nests its
        // own A-calls (A389/A454/A478/A475/size queries), which re-enter this
        // method and are answered by the table below; when the AP answers
        // D120 the continuation returns start_signal's success bool.
        if &tag == b"A401" {
            if output != 4 {
                return self.refuse(tag, "A401 start_signal output size differs from the AP's");
            }
            return Ok(Step::Call {
                tag: *b"D120",
                input: Vec::new(),
                output: 4,
                then: Box::new(|_methods, answer| {
                    // D120 start_hardware_boot returns a bool; start_signal
                    // reports success when the hardware boot succeeded.
                    let ok = answer.first().is_some_and(|byte| byte & 1 != 0);
                    Ok(Step::Return(bool_reply(ok)))
                }),
            });
        }
        if is_swap(&tag) {
            return self.refuse(
                tag,
                "swap host calls need the dart-dispext0 surface path, not yet modeled",
            );
        }
        match answer(&tag, input, output, self.mode()) {
            Ok(bytes) => Ok(Step::Return(bytes)),
            Err(reason) => self.refuse(tag, reason),
        }
    }
}

impl Methods {
    /// Record and return a named refusal for `tag`.
    fn refuse(&mut self, tag: [u8; 4], reason: &'static str) -> Result<Step<Self>, &'static str> {
        let name = core::str::from_utf8(&tag).unwrap_or("????");
        self.last_refusal = Some(format!("DCP IOMFB tag {name}: {reason}"));
        Err(reason)
    }

    /// The last refusal's full text, for the device layer's refusal line.
    pub fn last_refusal(&self) -> Option<&str> {
        self.last_refusal.as_deref()
    }
}

/// A boolean DCP reply (`IOReturn`-style success in the low bit). The AP maps
/// it through `iomfb_status_from_link`; the low bit set is success.
fn bool_reply(ok: bool) -> Vec<u8> {
    u32::from(ok).to_le_bytes().to_vec()
}

/// Answer a non-DMA, non-nesting host call for the fixed `mode`, or refuse it
/// by name. The output must be exactly the length the AP's header allocated
/// (the verified wire size); a mismatch refuses rather than truncates.
pub fn answer(
    code: &[u8; 4],
    _input: &[u8],
    output: u32,
    mode: Mode,
) -> Result<Vec<u8>, &'static str> {
    let out = output as usize;
    let sized = |bytes: Vec<u8>| -> Result<Vec<u8>, &'static str> {
        if bytes.len() == out {
            Ok(bytes)
        } else {
            Err("DCP method output size differs from the AP's header")
        }
    };
    let width = mode.width.to_le_bytes().to_vec();
    let height = mode.height.to_le_bytes().to_vec();
    match code {
        // IOMobileFramebufferAP display geometry (out=4 each).
        b"A451" => sized(width),
        b"A452" => sized(height),
        // UnifiedPipeline2 aliases: displayHeight (A350), displayWidth (A351).
        b"A350" => sized(height),
        b"A351" => sized(width),
        // get_display_size(flags) -> {width, height} (in=4, out=8).
        b"A453" => {
            let mut bytes = mode.width.to_le_bytes().to_vec();
            bytes.extend_from_slice(&mode.height.to_le_bytes());
            sized(bytes)
        }
        // is_external: the one HDMI display is external.
        b"A379" => sized(bool_reply(true)),
        // headless: a display is connected, so not headless (0).
        b"A384" => sized(bool_reply(false)),
        // is_main_display: the one connected display is main.
        b"A412" => sized(bool_reply(true)),
        // get_framebuffer_id: the single framebuffer's id.
        b"A405" => sized(1u32.to_le_bytes().to_vec()),
        // set_display_device(index): one display, accepted.
        b"A411" => sized(bool_reply(true)),
        // do_create_default_frame_buffer: the DCP does NOT create one; the
        // boot framebuffer is inherited, so this is false and the AP skips the
        // A036/A037 default-framebuffer-info path.
        b"A454" => sized(bool_reply(false)),
        // set_create_DFB / stop_signal / free_signal: no output.
        b"A389" | b"A402" | b"A400" => sized(Vec::new()),
        // flush_supportsPower(bool): no output.
        b"A478" => sized(Vec::new()),
        // setDisplayRefreshProperties: success (out=4).
        b"A475" => sized(bool_reply(true)),
        _ => Err("DCP host-call tag is not modeled for the one fixed monitor"),
    }
}

/// Whether a tag is a swap-path host call the surface/DMA layer handles rather
/// than [`answer`] (`swap_begin` A403, `swap_start_dcp` A406, `swap_submit_dcp`
/// A407 and the related submit/rotate tags).
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

    struct TestScreen(Mode);
    impl Scanout for TestScreen {
        fn mode(&self) -> Mode {
            self.0
        }
        fn present(&mut self, _rows: &[u8]) -> Result<(), &'static str> {
            Ok(())
        }
    }

    fn methods() -> Methods {
        Methods::new(Box::new(TestScreen(MODE)))
    }

    #[test]
    fn display_size_tags_report_the_fixed_mode_at_verified_sizes() {
        assert_eq!(
            answer(b"A451", &[], 4, MODE).unwrap(),
            1920u32.to_le_bytes()
        );
        assert_eq!(
            answer(b"A452", &[], 4, MODE).unwrap(),
            1080u32.to_le_bytes()
        );
        assert_eq!(
            answer(b"A351", &[], 4, MODE).unwrap(),
            1920u32.to_le_bytes()
        );
        assert_eq!(
            answer(b"A350", &[], 4, MODE).unwrap(),
            1080u32.to_le_bytes()
        );
        let size = answer(b"A453", &[0; 4], 8, MODE).unwrap();
        assert_eq!(&size[0..4], &1920u32.to_le_bytes());
        assert_eq!(&size[4..8], &1080u32.to_le_bytes());
    }

    #[test]
    fn connection_tags_describe_one_external_main_display() {
        assert_eq!(answer(b"A379", &[], 4, MODE).unwrap(), 1u32.to_le_bytes()); // external
        assert_eq!(answer(b"A384", &[], 4, MODE).unwrap(), 0u32.to_le_bytes()); // not headless
        assert_eq!(answer(b"A412", &[], 4, MODE).unwrap(), 1u32.to_le_bytes()); // main
    }

    #[test]
    fn the_boot_framebuffer_is_inherited_not_recreated() {
        // do_create_default_frame_buffer is false: the DCP inherits the boot
        // framebuffer, which is the branch that skips the A036/A037 DFB-info
        // path in start_hardware_boot.
        assert_eq!(answer(b"A454", &[], 4, MODE).unwrap(), 0u32.to_le_bytes());
        // set_create_DFB / flush_supportsPower carry no output (verified).
        assert!(answer(b"A389", &[], 0, MODE).unwrap().is_empty());
        assert!(answer(b"A478", &[0; 4], 0, MODE).unwrap().is_empty());
        assert_eq!(answer(b"A475", &[], 4, MODE).unwrap(), 1u32.to_le_bytes());
    }

    #[test]
    fn unmodeled_tags_and_wrong_sizes_refuse_by_name() {
        assert!(answer(b"A999", &[], 4, MODE).is_err());
        // start_signal with the wrong output size is refused, not faked.
        assert!(answer(b"A451", &[], 8, MODE).is_err());
        assert!(is_swap(b"A407"));
        assert!(!is_swap(b"A401"));
    }

    #[test]
    fn start_signal_nests_start_hardware_boot_and_reports_its_result() {
        let mut methods = methods();
        // A401 does not answer directly: it nests D120 start_hardware_boot.
        let step = methods.call(*b"A401", &[], 4).unwrap();
        let then = match step {
            Step::Call {
                tag, output, then, ..
            } => {
                assert_eq!(&tag, b"D120");
                assert_eq!(output, 4);
                then
            }
            Step::Return(_) => panic!("A401 must nest D120, not answer directly"),
        };
        // The AP answers D120 with success; start_signal then reports success.
        let step = then(&mut methods, &1u32.to_le_bytes()).unwrap();
        match step {
            Step::Return(bytes) => assert_eq!(bytes, 1u32.to_le_bytes()),
            Step::Call { .. } => panic!("the continuation returns start_signal's bool"),
        }
        // A wrong start_signal output size refuses by name.
        assert!(methods.call(*b"A401", &[], 8).is_err());
        assert!(methods.last_refusal().unwrap().contains("A401"));
    }

    #[test]
    fn swaps_refuse_by_name_until_the_surface_path_lands() {
        let mut methods = methods();
        assert!(methods.call(*b"A407", &[0; 16], 0xc).is_err());
        assert!(methods.last_refusal().unwrap().contains("A407"));
        assert!(methods.last_refusal().unwrap().contains("dispext0"));
    }

    #[test]
    fn the_edid_is_well_formed_for_the_mode() {
        let e = edid(MODE);
        assert_eq!(&e[0..8], &[0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0]);
        assert_eq!(e.iter().fold(0u8, |a, b| a.wrapping_add(*b)), 0, "checksum");
        let dtd = &e[54..72];
        let hactive = u32::from(dtd[2]) | (u32::from(dtd[4] >> 4) << 8);
        assert_eq!(hactive, 1920);
    }
}
