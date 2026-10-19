//! The IOMFB method service of the modeled DCP for one fixed, connected SDR
//! monitor: the replies to the methods the AP's IOMobileFramebuffer stack
//! calls during boot, power, mode set and swap, and the callbacks the
//! coprocessor makes. Every call is first checked against its interface row
//! ([`super::abi`]); a tag outside the interface, a call whose sizes differ
//! from its row and a method the model does not serve all refuse by name, so
//! an unmodeled operation is a recorded gap, never a fake success.
//!
//! The method semantics follow Asahi Linux's AP side of the same protocol
//! (`drivers/gpu/drm/apple/iomfb_template.c`: the boot sequence `boot_1` ..
//! `boot_done`, `iomfb_poweron`, `iomfb_modeset`, `iomfb_flush` and the swap
//! callbacks) and m1n1's method signatures (`proxyclient/m1n1/fw/dcp/ipc.py`),
//! with this interface's tags and sizes. docs/research/display-gpu.md
//! section 8 is the requirement matrix, row by row with its source.
//!
//! `A401 start_signal` nests `D120 start_hardware_boot` into the AP before it
//! answers, as the firmware does (Asahi `dcpep_cb_boot_1` is the AP's D120
//! handler; it calls `set_create_DFB`, `do_create_default_frame_buffer`,
//! `setup_video_limits`, `flush_supportsPower`, `late_init_signal` and
//! `setDisplayRefreshProperties` back, which re-enter [`Methods::call`]).
//! The model inherits the boot framebuffer rather than allocating a new
//! default one: `A454 do_create_default_frame_buffer` answers 0.
//!
//! A swap is `A406 swap_start_dcp` (the coprocessor assigns the swap id)
//! then `A407 swap_submit_dcp`. A submitted swap's surface is queued as a
//! [`Frame`]; the coprocessor reads its pixels through the display pipe's
//! DART, presents them and only then completes the swap with
//! `D594 swap_complete_ap_gated` ([`super::Coprocessor::present`]).
use super::super::scanout::{self, Mode, Scanout, Surface};
use super::Log;
use super::abi::{self, Fields, IO_RETURN_SUCCESS, Packed};
use super::rpc::{Callback, Service, Step};
use super::swap;
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// The most display-log entries kept between drains.
const LOG_CAPACITY: usize = 4096;
/// The leading call-input bytes a log entry keeps.
const LOGGED_INPUT: usize = 64;
/// How many `swap_submit_dcp` inputs are logged whole.
const DUMPED_SWAPS: u32 = 2;
/// `IOMFBPARAM_ADAPTIVE_SYNC` (Asahi `iomfb.h`).
const ADAPTIVE_SYNC: u32 = 14;
/// `D594 swap_complete_ap_gated`'s input: the swap id first (m1n1
/// `swap_complete_ap_gated(swap_id, ...)`); the rest of this interface's
/// record is zero (no timing statistics are reported).
const SWAP_COMPLETE: [u8; 4] = *b"D594";

/// A submitted swap waiting for its pixels: its id and its surface, or none
/// for a swap that only clears to the background.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame {
    pub swap_id: u32,
    pub surface: Option<Surface>,
}

/// The IOMFB methods of the one connected display, presenting to a host
/// scanout.
pub struct Methods {
    scanout: Box<dyn Scanout>,
    /// Why the last call refused, with the tag and its interface row.
    last_refusal: Option<String>,
    log: VecDeque<Log>,
    dropped: u64,
    /// The `IOMFBSwapRec` size submitted swaps are parsed with.
    record: Option<usize>,
    dumped: u32,
    /// The last `setPowerState`.
    powered: Option<bool>,
    /// Open IOMFB clients (`first_client_open` minus `last_client_close`).
    clients: u32,
    next_swap: u32,
    /// The swap `swap_start_dcp` opened, not yet submitted.
    open_swap: Option<u32>,
    frames: VecDeque<Frame>,
    /// Swaps presented, whose completion callback is due.
    completed: VecDeque<u32>,
}

impl Methods {
    pub fn new(scanout: Box<dyn Scanout>) -> Self {
        Self::with_record(scanout, swap::SWAP_RECORD_BYTES)
    }

    /// Methods that parse submitted swaps with an `IOMFBSwapRec` of `record`
    /// bytes, or refuse them when it is `None`.
    pub fn with_record(scanout: Box<dyn Scanout>, record: Option<usize>) -> Self {
        Self {
            scanout,
            last_refusal: None,
            log: VecDeque::new(),
            dropped: 0,
            record,
            dumped: 0,
            powered: None,
            clients: 0,
            next_swap: 1,
            open_swap: None,
            frames: VecDeque::new(),
            completed: VecDeque::new(),
        }
    }

    /// The fixed mode the one connected display runs.
    pub fn mode(&self) -> Mode {
        self.scanout.mode()
    }

    /// The last `setPowerState` the AP asked for.
    pub fn powered(&self) -> Option<bool> {
        self.powered
    }

    /// The last refusal's full text.
    pub fn last_refusal(&self) -> Option<&str> {
        self.last_refusal.as_deref()
    }

    /// The next display-log entry.
    pub fn take_log(&mut self) -> Option<Log> {
        self.log.pop_front().or_else(|| {
            (self.dropped != 0).then(|| Log::Dropped(core::mem::take(&mut self.dropped)))
        })
    }

    pub(super) fn record_log(&mut self, entry: Log) {
        if self.log.len() < LOG_CAPACITY {
            self.log.push_back(entry);
        } else {
            self.dropped += 1;
        }
    }

    /// The next submitted swap waiting for its pixels.
    pub fn frame_pending(&self) -> bool {
        !self.frames.is_empty()
    }

    /// Present the oldest submitted swap: read its surface through `read`
    /// (DVA, bytes; false when unreachable), hand the rows to the scanout and
    /// queue its completion. A swap is never completed before its pixels
    /// are consumed.
    pub fn present(
        &mut self,
        read: impl FnMut(u64, &mut [u8]) -> bool,
    ) -> Result<(), &'static str> {
        let Some(frame) = self.frames.pop_front() else {
            return Ok(());
        };
        let mode = self.mode();
        let rows = match frame.surface {
            Some(surface) => scanout::frame(&surface, mode, read).map_err(|error| match error {
                scanout::PresentError::Mode => "DCP swap surface differs from the fixed mode",
                scanout::PresentError::Format => "DCP swap surface format is not converted",
                scanout::PresentError::Scanout(reason) => reason,
            })?,
            // A background-only swap clears to opaque black.
            None => alloc::vec![0u8; mode.width as usize * mode.height as usize * 4],
        };
        self.scanout.present(&rows)?;
        self.record_log(Log::Presented {
            swap_id: frame.swap_id,
            surface: frame.surface,
        });
        self.completed.push_back(frame.swap_id);
        Ok(())
    }

    /// Record and return a named refusal for `tag`.
    fn refuse(&mut self, tag: [u8; 4], reason: &'static str) -> Result<Step<Self>, &'static str> {
        let row = abi::method(&tag)
            .map(|row| {
                format!(
                    " {}::{} (in {:#x}, out {:#x})",
                    row.class, row.name, row.input, row.output
                )
            })
            .unwrap_or_default();
        let text = format!("DCP IOMFB {}{row}: {reason}", abi::tag_str(&tag));
        self.record_log(Log::Refused(text.clone()));
        self.last_refusal = Some(text);
        Err(reason)
    }

    fn callback_log(&mut self, tag: [u8; 4], input: usize, output: u32) {
        self.record_log(Log::Callback { tag, input, output });
    }

    fn reply(
        &mut self,
        tag: [u8; 4],
        packed: Result<Vec<u8>, &'static str>,
    ) -> Result<Step<Self>, &'static str> {
        match packed {
            Ok(bytes) => Ok(Step::Return(bytes)),
            Err(reason) => self.refuse(tag, reason),
        }
    }
}

impl Service for Methods {
    fn call(
        &mut self,
        tag: [u8; 4],
        input: &[u8],
        output: u32,
    ) -> Result<Step<Self>, &'static str> {
        let Some(row) = abi::method(&tag) else {
            self.record_log(Log::Call {
                tag,
                input: input[..input.len().min(LOGGED_INPUT)].to_vec(),
                output,
            });
            return self.refuse(tag, "tag is not a method of this DCP interface");
        };
        self.record_log(Log::Call {
            tag,
            input: input[..input.len().min(LOGGED_INPUT)].to_vec(),
            output,
        });
        if row.input as usize != input.len() || row.output != output {
            return self.refuse(tag, "call sizes differ from the interface's record");
        }
        let mut fields = Fields::new(input);
        match &tag {
            // start_signal: nest D120 start_hardware_boot, then report its bool.
            b"A401" => {
                self.callback_log(*b"D120", 0, 4);
                Ok(Step::Call {
                    tag: *b"D120",
                    input: Vec::new(),
                    output: 4,
                    then: Box::new(|methods, answer| {
                        methods.record_log(Log::Answer {
                            tag: *b"D120",
                            output: answer.to_vec(),
                        });
                        let ok = answer.first().is_some_and(|byte| byte & 1 != 0);
                        Ok(Step::Return(bool_reply(ok)))
                    }),
                })
            }
            // late_init_signal(bool) -> bool (Asahi boot_4, true on >= 13.2).
            b"A000" => {
                let packed = Packed::new().bool(true).finish(output);
                self.reply(tag, packed)
            }
            // setup_video_limits(): the fixed mode has no limits to set up.
            b"A027" => Ok(Step::Return(Vec::new())),
            // set_parameter_dcp(param, value[4], count) -> u32. The one
            // parameter Asahi sets is adaptive sync, which a fixed 60 Hz
            // mode has off; any other parameter refuses.
            b"A450" => {
                let param = fields.u32()?;
                let mut values = [0u64; 4];
                for value in &mut values {
                    *value = fields.u64()?;
                }
                if param != ADAPTIVE_SYNC || values != [0; 4] {
                    return self.refuse(
                        tag,
                        "set_parameter_dcp sets a parameter the fixed mode does not have",
                    );
                }
                let packed = Packed::new().u32(IO_RETURN_SUCCESS).finish(output);
                self.reply(tag, packed)
            }
            // setPowerState(state, ...) -> {u32, u32 result}: 1 on, 0 off
            // (Asahi dcp_on_set_power_state / last_client_closed_poff).
            b"A484" => {
                let state = fields.u64()?;
                self.powered = Some(match state {
                    0 => false,
                    1 => true,
                    _ => {
                        return self
                            .refuse(tag, "setPowerState names a state other than off or on");
                    }
                });
                let packed = Packed::new().u32(0).u32(IO_RETURN_SUCCESS).finish(output);
                self.reply(tag, packed)
            }
            // set_digital_out_mode(color id, timing id): the model has not
            // advertised any TimingElements/ColorElements, so no id names
            // one of its modes.
            b"A413" => self.refuse(
                tag,
                "set_digital_out_mode names a mode the DCP never advertised",
            ),
            // first_client_open() / last_client_close_dcp(out u32).
            b"A466" => {
                self.clients += 1;
                Ok(Step::Return(Vec::new()))
            }
            b"A467" => {
                self.clients = self.clients.saturating_sub(1);
                let packed = Packed::new().u32(0).finish(output);
                self.reply(tag, packed)
            }
            // swap_begin(): no arguments and no result.
            b"A403" => Ok(Step::Return(Vec::new())),
            // swap_start_dcp(u32* swap_id, u64 client) -> {swap_id, u32}.
            b"A406" => {
                if self.open_swap.is_some() {
                    return self
                        .refuse(tag, "swap_start_dcp while a started swap is not submitted");
                }
                let id = self.next_swap;
                self.next_swap = self.next_swap.wrapping_add(1).max(1);
                self.open_swap = Some(id);
                let packed = Packed::new().u32(id).u32(IO_RETURN_SUCCESS).finish(output);
                self.reply(tag, packed)
            }
            b"A407" => self.submit(tag, input, output),
            // abort_swaps_dcp(client) -> u32: drop the open and queued swaps.
            b"A479" => {
                self.open_swap = None;
                self.frames.clear();
                let packed = Packed::new().u32(IO_RETURN_SUCCESS).finish(output);
                self.reply(tag, packed)
            }
            _ => match answer(&tag, input, output, self.mode()) {
                Ok(bytes) => Ok(Step::Return(bytes)),
                Err(reason) => self.refuse(tag, reason),
            },
        }
    }

    fn callback_pending(&self) -> bool {
        !self.completed.is_empty()
    }

    fn take_callback(&mut self) -> Option<Callback<Self>> {
        let swap_id = self.completed.pop_front()?;
        let length = abi::callback(&SWAP_COMPLETE)
            .and_then(|row| row.input)
            .expect("swap_complete_ap_gated's input size is recorded")
            as usize;
        let mut input = alloc::vec![0u8; length];
        input[0..4].copy_from_slice(&swap_id.to_le_bytes());
        self.callback_log(SWAP_COMPLETE, length, 0);
        Some(Callback {
            tag: SWAP_COMPLETE,
            input,
            output: 0,
            then: Box::new(|_, _| Ok(())),
        })
    }
}

impl Methods {
    /// `swap_submit_dcp`: queue the swap's one enabled layer (or none, a
    /// background clear) and answer `{bool, u32, u32 result}` (Linux
    /// `dcp_swap_submit_resp`).
    fn submit(
        &mut self,
        tag: [u8; 4],
        input: &[u8],
        output: u32,
    ) -> Result<Step<Self>, &'static str> {
        let Some(swap_id) = self.open_swap.take() else {
            return self.refuse(tag, "swap_submit_dcp without swap_start_dcp");
        };
        if self.dumped < DUMPED_SWAPS {
            self.dumped += 1;
            self.record_log(Log::Payload {
                tag,
                bytes: input.to_vec(),
            });
        }
        let Some(record) = self.record else {
            return self.refuse(
                tag,
                "the IOMFBSwapRec size of this interface is not pinned; the submitted input is in the display log",
            );
        };
        let layers = match swap::layers(input, record) {
            Ok(layers) => layers,
            Err(reason) => return self.refuse(tag, reason),
        };
        let mut enabled = layers.iter().flatten();
        let surface = match (enabled.next(), enabled.next()) {
            (None, _) => None,
            (Some((layer, dva)), None) => match layer.surface(*dva) {
                Ok(surface) => Some(surface),
                Err(reason) => return self.refuse(tag, reason),
            },
            (Some(_), Some(_)) => {
                return self.refuse(tag, "swap composes several layers; the model scans out one");
            }
        };
        let mode = self.mode();
        if surface
            .is_some_and(|surface| surface.width != mode.width || surface.height != mode.height)
        {
            return self.refuse(tag, "swap surface differs from the fixed mode");
        }
        self.frames.push_back(Frame { swap_id, surface });
        let packed = Packed::new()
            .bool(false)
            .u32(0)
            .u32(IO_RETURN_SUCCESS)
            .finish(output);
        self.reply(tag, packed)
    }
}

/// A boolean DCP reply (the low bit set is true).
fn bool_reply(ok: bool) -> Vec<u8> {
    u32::from(ok).to_le_bytes().to_vec()
}

/// Answer a stateless query for the fixed `mode`, or refuse it by name. The
/// output must be exactly the length the AP's header allocated (the
/// interface's size); a mismatch refuses rather than truncates.
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
        // boot framebuffer is inherited, so this is 0 and the AP skips the
        // A036/A037 default-framebuffer-info path.
        b"A454" => sized(bool_reply(false)),
        // set_create_DFB / stop_signal / free_signal: no output.
        b"A389" | b"A402" | b"A400" => sized(Vec::new()),
        // flush_supportsPower(bool): no output.
        b"A478" => sized(Vec::new()),
        // setDisplayRefreshProperties: success (out=4).
        b"A475" => sized(bool_reply(true)),
        _ => Err("DCP method is not modeled for the one fixed monitor"),
    }
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
    use alloc::rc::Rc;
    use core::cell::RefCell;

    const MODE: Mode = Mode {
        width: 4,
        height: 2,
        format: PixelFormat::Bgra8888,
    };
    const FULL_HD: Mode = Mode {
        width: 1920,
        height: 1080,
        format: PixelFormat::Bgra8888,
    };

    #[derive(Clone, Default)]
    struct TestScreen(Rc<RefCell<Vec<Vec<u8>>>>, Option<Mode>);
    impl Scanout for TestScreen {
        fn mode(&self) -> Mode {
            self.1.unwrap_or(FULL_HD)
        }
        fn present(&mut self, rows: &[u8]) -> Result<(), &'static str> {
            self.0.borrow_mut().push(rows.to_vec());
            Ok(())
        }
    }

    fn methods() -> Methods {
        Methods::new(Box::new(TestScreen::default()))
    }

    fn returned(step: Result<Step<Methods>, &'static str>) -> Vec<u8> {
        match step {
            Ok(Step::Return(bytes)) => bytes,
            Ok(Step::Call { .. }) => panic!("expected a return, got a callback"),
            Err(reason) => panic!("refused: {reason}"),
        }
    }

    #[test]
    fn display_size_tags_report_the_fixed_mode_at_verified_sizes() {
        assert_eq!(
            answer(b"A451", &[], 4, FULL_HD).unwrap(),
            1920u32.to_le_bytes()
        );
        assert_eq!(
            answer(b"A452", &[], 4, FULL_HD).unwrap(),
            1080u32.to_le_bytes()
        );
        assert_eq!(
            answer(b"A351", &[], 4, FULL_HD).unwrap(),
            1920u32.to_le_bytes()
        );
        assert_eq!(
            answer(b"A350", &[], 4, FULL_HD).unwrap(),
            1080u32.to_le_bytes()
        );
        let size = answer(b"A453", &[0; 4], 8, FULL_HD).unwrap();
        assert_eq!(&size[0..4], &1920u32.to_le_bytes());
        assert_eq!(&size[4..8], &1080u32.to_le_bytes());
    }

    #[test]
    fn connection_tags_describe_one_external_main_display() {
        assert_eq!(
            answer(b"A379", &[], 4, FULL_HD).unwrap(),
            1u32.to_le_bytes()
        );
        assert_eq!(
            answer(b"A384", &[], 4, FULL_HD).unwrap(),
            0u32.to_le_bytes()
        );
        assert_eq!(
            answer(b"A412", &[], 4, FULL_HD).unwrap(),
            1u32.to_le_bytes()
        );
    }

    #[test]
    fn the_boot_framebuffer_is_inherited_not_recreated() {
        assert_eq!(
            answer(b"A454", &[], 4, FULL_HD).unwrap(),
            0u32.to_le_bytes()
        );
        assert!(answer(b"A389", &[], 0, FULL_HD).unwrap().is_empty());
        assert!(answer(b"A478", &[0; 4], 0, FULL_HD).unwrap().is_empty());
        assert_eq!(
            answer(b"A475", &[], 4, FULL_HD).unwrap(),
            1u32.to_le_bytes()
        );
    }

    #[test]
    fn the_rest_of_asahis_boot_sequence_is_served() {
        let mut methods = methods();
        // late_init_signal(true) -> true; setup_video_limits() -> void.
        assert_eq!(
            returned(methods.call(*b"A000", &[1, 0, 0, 0], 4)),
            [1, 0, 0, 0]
        );
        assert!(returned(methods.call(*b"A027", &[], 0)).is_empty());
    }

    #[test]
    fn calls_off_the_interface_or_its_sizes_refuse_by_name() {
        let mut methods = methods();
        assert!(methods.call(*b"A999", &[], 4).is_err());
        assert!(methods.last_refusal().unwrap().contains("A999"));
        // display_width is (in 0, out 4): a different output refuses.
        assert!(methods.call(*b"A451", &[], 8).is_err());
        let refusal = methods.last_refusal().unwrap();
        assert!(refusal.contains("display_width") && refusal.contains("out 0x4"));
        // A method on the interface the model does not serve.
        assert!(methods.call(*b"A123", &[0; 0x18], 4).is_err());
        assert!(methods.last_refusal().unwrap().contains("start_task_dcp"));
        // Each call and refusal is in the display log.
        assert!(matches!(methods.take_log(), Some(Log::Call { tag, .. }) if &tag == b"A999"));
        assert!(matches!(methods.take_log(), Some(Log::Refused(_))));
    }

    #[test]
    fn start_signal_nests_start_hardware_boot_and_reports_its_result() {
        let mut methods = methods();
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
        let step = then(&mut methods, &1u32.to_le_bytes()).unwrap();
        match step {
            Step::Return(bytes) => assert_eq!(bytes, 1u32.to_le_bytes()),
            Step::Call { .. } => panic!("the continuation returns start_signal's bool"),
        }
        assert!(methods.call(*b"A401", &[], 8).is_err());
        assert!(methods.last_refusal().unwrap().contains("A401"));
    }

    #[test]
    fn power_and_parameters_follow_asahis_power_on() {
        let mut methods = methods();
        // set_parameter_dcp(ADAPTIVE_SYNC, 0, count 3) as Asahi sends it.
        let mut param = Packed::new().u32(ADAPTIVE_SYNC);
        for _ in 0..4 {
            param = param.u64(0);
        }
        let param = param.u32(3).finish(0x28).unwrap();
        assert_eq!(returned(methods.call(*b"A450", &param, 4)), [0; 4]);
        let mut vrr = param.clone();
        vrr[4] = 1;
        assert!(methods.call(*b"A450", &vrr, 4).is_err());
        // setPowerState(1) then (0).
        let on = Packed::new().u64(1).finish(0x10).unwrap();
        assert_eq!(returned(methods.call(*b"A484", &on, 8)), [0; 8]);
        assert_eq!(methods.powered(), Some(true));
        let off = Packed::new().u64(0).finish(0x10).unwrap();
        returned(methods.call(*b"A484", &off, 8));
        assert_eq!(methods.powered(), Some(false));
        let other = Packed::new().u64(2).finish(0x10).unwrap();
        assert!(methods.call(*b"A484", &other, 8).is_err());
        // No mode was advertised, so a mode set refuses.
        assert!(
            methods
                .call(*b"A413", &[1, 0, 0, 0, 1, 0, 0, 0], 4)
                .is_err()
        );
        // first_client_open / last_client_close_dcp.
        assert!(returned(methods.call(*b"A466", &[], 0)).is_empty());
        assert_eq!(returned(methods.call(*b"A467", &[0; 4], 4)), [0; 4]);
    }

    /// A swap_submit_dcp input with a 0x10-byte record and `layer` enabled.
    fn submission(surface: Option<(u32, u32)>) -> Vec<u8> {
        let mut input = alloc::vec![0u8; 0x1d30];
        if let Some((width, height)) = surface {
            let record = 0x10;
            let at = record;
            input[at + 3..at + 7].copy_from_slice(&1u32.to_le_bytes());
            input[at + 0xb..at + 0xf]
                .copy_from_slice(&PixelFormat::Bgra8888.fourcc().to_le_bytes());
            input[at + 0x15..at + 0x19].copy_from_slice(&(width * 4).to_le_bytes());
            input[at + 0x21..at + 0x25].copy_from_slice(&width.to_le_bytes());
            input[at + 0x25..at + 0x29].copy_from_slice(&height.to_le_bytes());
            input[at + 0x29..at + 0x2d].copy_from_slice(&(width * height * 4).to_le_bytes());
            let dvas = record + swap::LAYERS * swap::SURFACE_BYTES;
            input[dvas..dvas + 8].copy_from_slice(&0x1000u64.to_le_bytes());
        }
        input
    }

    #[test]
    fn a_swap_is_started_submitted_presented_then_completed() {
        let screen = TestScreen(Rc::default(), Some(MODE));
        let frames = screen.0.clone();
        let mut methods = Methods::with_record(Box::new(screen), Some(0x10));
        assert!(returned(methods.call(*b"A403", &[], 0)).is_empty());
        let start = Packed::new()
            .u32(0)
            .u64(0xfeed)
            .bool(false)
            .finish(0x10)
            .unwrap();
        let started = returned(methods.call(*b"A406", &start, 8));
        assert_eq!(started, [1, 0, 0, 0, 0, 0, 0, 0]);
        // A second start before the submit refuses.
        assert!(methods.call(*b"A406", &start, 8).is_err());
        let submitted = returned(methods.call(*b"A407", &submission(Some((4, 2))), 0xc));
        assert_eq!(submitted, [0; 12]);
        // Not complete until presented.
        assert!(!methods.callback_pending() && methods.frame_pending());
        methods
            .present(|dva, bytes| {
                assert!((0x1000..0x1020).contains(&dva));
                bytes.fill(0x5a);
                true
            })
            .unwrap();
        assert_eq!(frames.borrow()[0], [0x5a; 32]);
        let callback = methods.take_callback().unwrap();
        assert_eq!(&callback.tag, b"D594");
        assert_eq!(callback.input.len(), 0x730);
        assert_eq!(&callback.input[0..4], &1u32.to_le_bytes());
        // The record is logged whole the first times.
        let logged = core::iter::from_fn(|| methods.take_log())
            .any(|entry| matches!(entry, Log::Payload { bytes, .. } if bytes.len() == 0x1d30));
        assert!(logged);
    }

    #[test]
    fn a_background_swap_clears_and_bad_swaps_refuse() {
        let screen = TestScreen(Rc::default(), Some(MODE));
        let frames = screen.0.clone();
        let mut methods = Methods::with_record(Box::new(screen), Some(0x10));
        let start = Packed::new()
            .u32(0)
            .u64(0)
            .bool(false)
            .finish(0x10)
            .unwrap();
        // A submit without a start refuses.
        assert!(methods.call(*b"A407", &submission(None), 0xc).is_err());
        returned(methods.call(*b"A406", &start, 8));
        returned(methods.call(*b"A407", &submission(None), 0xc));
        methods
            .present(|_, _| panic!("a clear reads no surface"))
            .unwrap();
        assert_eq!(frames.borrow()[0], [0; 32]);
        // A surface of another size than the mode refuses.
        returned(methods.call(*b"A406", &start, 8));
        assert!(
            methods
                .call(*b"A407", &submission(Some((2, 2))), 0xc)
                .is_err()
        );
    }

    #[test]
    fn an_unpinned_record_refuses_the_submit_and_logs_it() {
        let mut methods = methods();
        let start = Packed::new()
            .u32(0)
            .u64(0)
            .bool(false)
            .finish(0x10)
            .unwrap();
        returned(methods.call(*b"A406", &start, 8));
        assert!(methods.call(*b"A407", &submission(None), 0xc).is_err());
        assert!(methods.last_refusal().unwrap().contains("not pinned"));
        let logged = core::iter::from_fn(|| methods.take_log())
            .any(|entry| matches!(entry, Log::Payload { .. }));
        assert!(logged);
    }

    #[test]
    fn the_edid_is_well_formed_for_the_mode() {
        let e = edid(FULL_HD);
        assert_eq!(&e[0..8], &[0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0]);
        assert_eq!(e.iter().fold(0u8, |a, b| a.wrapping_add(*b)), 0, "checksum");
        let dtd = &e[54..72];
        let hactive = u32::from(dtd[2]) | (u32::from(dtd[4] >> 4) << 8);
        assert_eq!(hactive, 1920);
    }
}
