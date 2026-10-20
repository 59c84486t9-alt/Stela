//! The IOMFB method service of the modeled DCP for one fixed, connected SDR
//! monitor: the replies to the methods the AP's IOMobileFramebuffer stack
//! calls during boot, power, mode set and swap, and the callbacks the
//! coprocessor makes. Every call is first checked against its interface row
//! ([`super::abi`]); a tag outside the interface, a call whose sizes differ
//! from its row and a method the model does not serve all refuse by name, so
//! an unmodeled operation is a recorded gap, never a fake success.
//!
//! The boot sequence follows Asahi Linux's AP side of the same protocol
//! (`drivers/gpu/drm/apple/iomfb_template.c`: `boot_1` .. `boot_done`,
//! `iomfb_poweron`, the swap callbacks) and m1n1's method signatures
//! (`proxyclient/m1n1/fw/dcp/ipc.py`), with this interface's tags and sizes.
//! The mode, hotplug and swap layouts are the 26A434 AP's own (kernel
//! fileset offsets, cited per method). docs/research/display-gpu.md section
//! 8 is the requirement matrix, row by row with its source.
//!
//! `A401 start_signal` nests `D120 start_hardware_boot` into the AP before it
//! answers, as the firmware does (the AP's D120 handler calls
//! `set_create_DFB`, `do_create_default_frame_buffer`, `setup_video_limits`,
//! `flush_supportsPower`, `late_init_signal` and `setDisplayRefreshProperties`
//! back, which re-enter [`Methods::call`]). The model inherits the boot
//! framebuffer rather than allocating a new default one: `A454
//! do_create_default_frame_buffer` answers 0.
//!
//! Once started, the coprocessor publishes its one mode on the IOMFB service
//! (`D126`..`D128 setDCPAVPropStart/Chunk/End` with the keys `TimingElements`
//! and `ColorElements`, [`super::modes`]) and then reports the monitor
//! connected (`D575 hotPlug_notify_gated`, state 1). Its callbacks leave one
//! at a time, each after the AP answered the previous one. The mode set is
//! `A364 getVideoDataForIDs` then `A413 set_digital_out_mode` with the
//! published IDs.
//!
//! A swap is `A406 swap_start_dcp` (the coprocessor assigns the swap id)
//! then `A407 swap_submit_dcp` ([`super::swap`]). The submitted layers
//! update the four layer slots; the visible layers are queued as a
//! [`Frame`]; the coprocessor reads their pixels through the display pipe's
//! DART, composes and presents them and only then completes the swap with
//! `D594 swap_complete_ap_gated` ([`super::Coprocessor::present`]).
//!
//! Composition (Inferred: the coprocessor's compositor is undocumented):
//! layers 0..3 stack bottom to top over opaque black, each a source
//! rectangle of its surface scaled nearest-neighbour into its destination
//! rectangle, clipped to the screen, and blended source-over with the
//! premultiplied flag the AP sets per surface. This agrees with Linux
//! (`plane.c`), which marks premultiplied only its formats without alpha
//! (XRGB, XBGR, XBGR2101010) and straight its ARGB ones: premultiplied over
//! black, an X byte of any value shows the colour unchanged.
use super::super::scanout::{self, Mode, Scanout};
use super::Log;
use super::abi::{self, Fields, IO_RETURN_SUCCESS, Packed};
use super::modes::{self, Advertised};
use super::rpc::{Callback, Service, Step};
use super::swap::{self, Layer, Submission};
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
/// The property-publishing callbacks (`UnifiedPipeline_RemoteCalls::
/// D126_callback__` 0x2a71628, `D127` 0x2a71730, `D128` 0x2a718b4).
const PROP_START: [u8; 4] = *b"D126";
const PROP_CHUNK: [u8; 4] = *b"D127";
const PROP_END: [u8; 4] = *b"D128";
/// `D127`'s chunk: `data[0x1000]` then `u32 offset`, `u32 length`.
const CHUNK_BYTES: usize = 0x1000;
/// `D128`'s key: `char[0x40]`, NUL-terminated by the AP.
const KEY_BYTES: usize = 0x40;
/// `IOMobileFramebuffer_RemoteCalls::D575_callback__` (0x3d88bb8):
/// `hotPlug_notify_gated(u64 state, IOMFB_TiledDisplayInfo* (0x4b bytes,
/// in-out), bool)`.
const HOTPLUG: [u8; 4] = *b"D575";
const TILED_DISPLAY_INFO: usize = 0x4b;
/// `hotPlug_notify_gated`'s plugged state (`IOMobileFramebufferShim::
/// hotPlug_notify_gated` 0x2a613c0 takes 0 as unplugged).
const PLUGGED: u64 = 1;
/// `get_digital_out_state`'s state for a connected display:
/// `restored_external` uses an external display only when it reads 1
/// ("Will use display %s").
const DIGITAL_OUT_CONNECTED: u32 = 1;

/// A submitted swap waiting for its pixels: its id and its layers, none for
/// a swap that only clears to the background.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub swap_id: u32,
    /// The visible layers, bottom to top.
    pub layers: Vec<scanout::Layer>,
}

/// A callback the coprocessor makes on its own initiative.
struct Outgoing {
    tag: [u8; 4],
    input: Vec<u8>,
    output: u32,
}

/// The IOMFB methods of the one connected display, presenting to a host
/// scanout.
pub struct Methods {
    scanout: Box<dyn Scanout>,
    /// The one mode, or why the scanout's mode cannot be advertised.
    advertised: Result<Advertised, &'static str>,
    /// Why the last call refused, with the tag and its interface row.
    last_refusal: Option<String>,
    log: VecDeque<Log>,
    dropped: u64,
    dumped: u32,
    /// The last `setPowerState`.
    powered: Option<bool>,
    /// Open IOMFB clients (`first_client_open` minus `last_client_close`).
    clients: u32,
    /// The mode set by `set_digital_out_mode`, `(color, timing)`.
    digital_out: Option<(u32, u32)>,
    next_swap: u32,
    /// The swap `swap_start_dcp` opened, not yet submitted.
    open_swap: Option<u32>,
    /// The four layer slots after the last submitted swap.
    planes: [Option<Layer>; swap::LAYERS],
    frames: VecDeque<Frame>,
    /// Callbacks to make, in order.
    outgoing: VecDeque<Outgoing>,
    /// Swaps presented, whose completion callback is due.
    completed: VecDeque<u32>,
    /// A callback is out and not answered yet.
    in_flight: bool,
}

impl Methods {
    pub fn new(scanout: Box<dyn Scanout>) -> Self {
        let advertised = Advertised::new(scanout.mode());
        Self {
            scanout,
            advertised,
            last_refusal: None,
            log: VecDeque::new(),
            dropped: 0,
            dumped: 0,
            powered: None,
            clients: 0,
            digital_out: None,
            next_swap: 1,
            open_swap: None,
            planes: [None; swap::LAYERS],
            frames: VecDeque::new(),
            outgoing: VecDeque::new(),
            completed: VecDeque::new(),
            in_flight: false,
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

    /// The `(color, timing)` IDs of the last `set_digital_out_mode`.
    pub fn digital_out(&self) -> Option<(u32, u32)> {
        self.digital_out
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

    /// Present the oldest submitted swap: read its layers through `read`
    /// (DVA, bytes; false when unreachable), hand the composed rows to the
    /// scanout and queue its completion. A swap is never completed before its pixels
    /// are consumed.
    pub fn present(
        &mut self,
        read: impl FnMut(u64, &mut [u8]) -> bool,
    ) -> Result<(), &'static str> {
        let Some(frame) = self.frames.pop_front() else {
            return Ok(());
        };
        let mode = self.mode();
        let rows = scanout::compose(&frame.layers, mode, read)?;
        self.scanout.present(&rows)?;
        self.record_log(Log::Presented {
            swap_id: frame.swap_id,
            surfaces: frame.layers.iter().map(|layer| layer.surface).collect(),
        });
        self.completed.push_back(frame.swap_id);
        Ok(())
    }

    fn refusal(&mut self, text: String) {
        self.record_log(Log::Refused(text.clone()));
        self.last_refusal = Some(text);
    }

    /// Record and return a named refusal for method `tag`.
    fn refuse(&mut self, tag: [u8; 4], reason: &'static str) -> Result<Step<Self>, &'static str> {
        let row = abi::method(&tag)
            .map(|row| {
                format!(
                    " {}::{} (in {:#x}, out {:#x})",
                    row.class, row.name, row.input, row.output
                )
            })
            .unwrap_or_default();
        self.refusal(format!("DCP IOMFB {}{row}: {reason}", abi::tag_str(&tag)));
        Err(reason)
    }

    /// Record and return a named refusal of the AP's answer to callback `tag`.
    fn refuse_answer(&mut self, tag: [u8; 4], reason: &'static str) -> Result<(), &'static str> {
        let name = abi::callback(&tag).map_or("", |row| row.name);
        self.refusal(format!(
            "DCP IOMFB callback {} {name}: {reason}",
            abi::tag_str(&tag)
        ));
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

    /// Queue a callback, sized by its interface row.
    fn queue(&mut self, tag: [u8; 4], input: Packed) -> Result<(), &'static str> {
        let row = abi::callback(&tag).ok_or("DCP callback is not on the interface")?;
        let (Some(length), Some(output)) = (row.input, row.output) else {
            return Err("DCP callback sizes are not recorded");
        };
        let input = input.finish(length)?;
        self.outgoing.push_back(Outgoing { tag, input, output });
        Ok(())
    }

    /// Publish the one mode's `TimingElements` and `ColorElements` on the
    /// IOMFB service, then report the monitor plugged.
    fn publish(&mut self) -> Result<(), &'static str> {
        let advertised = match &self.advertised {
            Ok(advertised) => advertised,
            Err(reason) => {
                let reason = *reason;
                return self.refuse_answer(PROP_START, reason);
            }
        };
        let properties = [
            ("TimingElements", advertised.timing_elements()),
            ("ColorElements", advertised.color_elements()),
        ];
        for (key, xml) in properties {
            // setDCPAVPropEnd NUL-terminates the buffer's last byte and
            // hands the whole buffer to OSUnserializeXML.
            let mut bytes = xml.into_bytes();
            bytes.push(0);
            let length = u32::try_from(bytes.len()).map_err(|_| "DCP property is too long")?;
            self.queue(PROP_START, Packed::new().u32(length))?;
            for (index, chunk) in bytes.chunks(CHUNK_BYTES).enumerate() {
                let mut data = [0u8; CHUNK_BYTES];
                data[..chunk.len()].copy_from_slice(chunk);
                self.queue(
                    PROP_CHUNK,
                    Packed::new()
                        .bytes(&data)
                        .u32((index * CHUNK_BYTES) as u32)
                        .u32(chunk.len() as u32),
                )?;
            }
            let mut name = [0u8; KEY_BYTES];
            name[..key.len()].copy_from_slice(key.as_bytes());
            self.queue(PROP_END, Packed::new().bytes(&name))?;
        }
        // A single, untiled display: a zero IOMFB_TiledDisplayInfo, present
        // (its null flag clear); the trailing bool is not read by
        // IOMobileFramebufferShim::hotPlug_notify_gated.
        self.queue(
            HOTPLUG,
            Packed::new()
                .u64(PLUGGED)
                .bytes(&[0; TILED_DISPLAY_INFO])
                .bool(false)
                .bool(false),
        )
    }
}

impl Service for Methods {
    fn call(
        &mut self,
        tag: [u8; 4],
        input: &[u8],
        output: u32,
    ) -> Result<Step<Self>, &'static str> {
        self.record_log(Log::Call {
            tag,
            input: input[..input.len().min(LOGGED_INPUT)].to_vec(),
            output,
        });
        let Some(row) = abi::method(&tag) else {
            return self.refuse(tag, "tag is not a method of this DCP interface");
        };
        if row.input as usize != input.len() || row.output != output {
            return self.refuse(tag, "call sizes differ from the interface's record");
        }
        let mut fields = Fields::new(input);
        match &tag {
            // start_signal: nest D120 start_hardware_boot, report its bool,
            // then publish the mode and the hotplug.
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
                        if ok {
                            methods.publish()?;
                        }
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
            // manage_properties(bool) (UnifiedPipeline2 0x2a52a8c; the
            // shim's HPD path passes "plugged"): the properties are the
            // ones already published; withdrawing them is not modeled.
            b"A363" => {
                if !fields.bool()? {
                    return self.refuse(
                        tag,
                        "manage_properties withdraws the published modes, which the fixed monitor never does",
                    );
                }
                Ok(Step::Return(Vec::new()))
            }
            // getVideoDataForIDs(IOAVVideoTimingData*, IOAVVideoColorData*,
            // u32 timing, u32 color, bool* dual pipe) -> bool (UnifiedPipeline2
            // 0x2a52ae4; the shim passes the timing ID before the color ID).
            b"A364" => {
                let timing_in = fields.bytes(modes::TIMING_BYTES)?;
                let color_in = fields.bytes(modes::COLOR_BYTES)?;
                let timing_id = fields.u32()?;
                let color_id = fields.u32()?;
                let found = self
                    .advertised
                    .as_ref()
                    .ok()
                    .and_then(|advertised| advertised.video_data(timing_id, color_id));
                let packed = match found {
                    Some((timing, color)) => Packed::new()
                        .bytes(timing)
                        .bytes(color)
                        .bool(false)
                        .bool(true),
                    // Unknown IDs: the records are left as passed, false.
                    None => Packed::new()
                        .bytes(timing_in)
                        .bytes(color_in)
                        .bool(false)
                        .bool(false),
                };
                let packed = packed.finish(output);
                self.reply(tag, packed)
            }
            // set_digital_out_mode(color id, timing id) -> link status
            // (IOMobileFramebufferAP 0x3d77a64).
            b"A413" => {
                let color = fields.u32()?;
                let timing = fields.u32()?;
                if (color, timing) != (modes::COLOR_ID, modes::TIMING_ID) {
                    return self.refuse(
                        tag,
                        "set_digital_out_mode names a mode the DCP never advertised",
                    );
                }
                self.digital_out = Some((color, timing));
                let packed = Packed::new().u32(IO_RETURN_SUCCESS).finish(output);
                self.reply(tag, packed)
            }
            // get_digital_out_state(u32* state) -> link status
            // (IOMobileFramebufferAP 0x3d77ad4): the monitor is connected.
            b"A414" => {
                let packed = Packed::new()
                    .u32(DIGITAL_OUT_CONNECTED)
                    .u32(IO_RETURN_SUCCESS)
                    .finish(output);
                self.reply(tag, packed)
            }
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
        !self.in_flight && !(self.outgoing.is_empty() && self.completed.is_empty())
    }

    fn take_callback(&mut self) -> Option<Callback<Self>> {
        if self.in_flight {
            return None;
        }
        if let Some(Outgoing { tag, input, output }) = self.outgoing.pop_front() {
            self.in_flight = true;
            self.callback_log(tag, input.len(), output);
            return Some(Callback {
                tag,
                input,
                output,
                then: Box::new(move |methods, answer| {
                    methods.in_flight = false;
                    methods.record_log(Log::Answer {
                        tag,
                        output: answer.to_vec(),
                    });
                    // The setDCPAVProp handlers answer a bool: false is
                    // "setDCPAVPropStart not called or failed", "invalid
                    // chunk requested", "OSUnserializeXML failed" or
                    // "setProperty failed".
                    if tag != HOTPLUG && !answer.first().is_some_and(|byte| byte & 1 != 0) {
                        methods.outgoing.clear();
                        return methods.refuse_answer(tag, "the AP refused the published mode");
                    }
                    Ok(())
                }),
            });
        }
        let swap_id = self.completed.pop_front()?;
        let length = abi::callback(&SWAP_COMPLETE)
            .and_then(|row| row.input)
            .expect("swap_complete_ap_gated's input size is recorded")
            as usize;
        let mut input = alloc::vec![0u8; length];
        input[0..4].copy_from_slice(&swap_id.to_le_bytes());
        self.in_flight = true;
        self.callback_log(SWAP_COMPLETE, length, 0);
        Some(Callback {
            tag: SWAP_COMPLETE,
            input,
            output: 0,
            then: Box::new(|methods, _| {
                methods.in_flight = false;
                Ok(())
            }),
        })
    }
}

impl Methods {
    /// `swap_submit_dcp`: update the layer slots, queue the visible layers
    /// (none is a background clear) and answer `{bool, u32, link status}`.
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
        let submission = match Submission::parse(input) {
            Ok(submission) => submission,
            Err(reason) => return self.refuse(tag, reason),
        };
        let planes = submission.apply(&self.planes);
        let layers = match visible(&planes, submission.background) {
            Ok(layers) => layers,
            Err(reason) => return self.refuse(tag, reason),
        };
        self.planes = planes;
        self.frames.push_back(Frame { swap_id, layers });
        let packed = Packed::new()
            .bool(false)
            .u32(0)
            .u32(IO_RETURN_SUCCESS)
            .finish(output);
        self.reply(tag, packed)
    }
}

/// The layers the slots show, bottom to top, over a black background. A
/// non-black background, or a layer whose surface or rectangles the model
/// cannot show, refuses by name.
fn visible(
    planes: &[Option<Layer>; swap::LAYERS],
    background: u32,
) -> Result<Vec<scanout::Layer>, &'static str> {
    if background != 0 {
        return Err("swap clears to a background color; the model presents black only");
    }
    planes
        .iter()
        .flatten()
        .map(|layer| {
            let surface = layer.record.surface(layer.dva)?;
            scanout::Layer::new(
                surface,
                layer.source,
                layer.destination,
                layer.record.premultiplied,
            )
        })
        .collect()
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

#[cfg(test)]
mod tests {
    use super::super::super::scanout::{Mode, PixelFormat};
    use super::super::swap::tests::submission;
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

    /// Start the display: A401, nesting D120, which the AP answers true.
    fn started(methods: &mut Methods) {
        let step = methods.call(*b"A401", &[], 4).unwrap();
        let Step::Call { then, .. } = step else {
            panic!("A401 must nest D120");
        };
        returned(then(methods, &1u32.to_le_bytes()));
    }

    /// Make every queued callback, answering each with `answer`; returns
    /// their tags and inputs.
    fn drain(methods: &mut Methods, answer: &[u8]) -> Vec<([u8; 4], Vec<u8>)> {
        let mut made = Vec::new();
        while let Some(callback) = methods.take_callback() {
            assert!(methods.take_callback().is_none(), "one callback at a time");
            made.push((callback.tag, callback.input.clone()));
            let mut output = alloc::vec![0u8; callback.output as usize];
            let n = output.len().min(answer.len());
            output[..n].copy_from_slice(&answer[..n]);
            (callback.then)(methods, &output).unwrap();
        }
        made
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
    fn a_failed_hardware_boot_publishes_nothing() {
        let mut methods = methods();
        let Ok(Step::Call { then, .. }) = methods.call(*b"A401", &[], 4) else {
            panic!("A401 must nest D120");
        };
        assert_eq!(returned(then(&mut methods, &[0; 4])), [0; 4]);
        assert!(!methods.callback_pending());
    }

    #[test]
    fn start_publishes_the_mode_then_reports_the_monitor_plugged() {
        let mut methods = methods();
        started(&mut methods);
        assert!(methods.callback_pending());
        let made = drain(&mut methods, &[1, 0, 0, 0]);
        let tags: Vec<&[u8; 4]> = made.iter().map(|(tag, _)| tag).collect();
        // Start, the chunks, End per key; then the hotplug.
        assert_eq!(tags.first(), Some(&&PROP_START));
        assert_eq!(tags.last(), Some(&&HOTPLUG));
        assert_eq!(tags.iter().filter(|tag| ***tag == PROP_END).count(), 2);
        let mut keys = Vec::new();
        let mut buffer = Vec::new();
        let mut expected = 0usize;
        for (tag, input) in &made {
            match tag {
                &PROP_START => {
                    assert_eq!(input.len(), 4);
                    expected = u32::from_le_bytes(input[0..4].try_into().unwrap()) as usize;
                    buffer = alloc::vec![0u8; expected];
                }
                &PROP_CHUNK => {
                    assert_eq!(input.len(), 0x1008);
                    let offset = u32::from_le_bytes(input[0x1000..0x1004].try_into().unwrap());
                    let length = u32::from_le_bytes(input[0x1004..0x1008].try_into().unwrap());
                    let (offset, length) = (offset as usize, length as usize);
                    assert!(length <= CHUNK_BYTES && offset + length <= expected);
                    buffer[offset..offset + length].copy_from_slice(&input[..length]);
                }
                &PROP_END => {
                    assert_eq!(input.len(), 0x40);
                    let key = input.split(|&byte| byte == 0).next().unwrap();
                    keys.push(String::from_utf8(key.to_vec()).unwrap());
                    // The buffer ends in the NUL setDCPAVPropEnd writes.
                    assert_eq!(buffer.last(), Some(&0));
                    let text = core::str::from_utf8(&buffer[..buffer.len() - 1]).unwrap();
                    assert!(text.starts_with("<array><dict>"));
                }
                &HOTPLUG => {
                    assert_eq!(input.len(), 0x58);
                    assert_eq!(&input[0..8], &1u64.to_le_bytes());
                    // The tiled-display info is present (null flag clear).
                    assert_eq!(input[0x54], 0);
                }
                other => panic!("unexpected callback {other:?}"),
            }
        }
        assert_eq!(keys, ["TimingElements", "ColorElements"]);
        assert!(!methods.callback_pending());
    }

    #[test]
    fn a_refused_property_stops_publishing_by_name() {
        let mut methods = methods();
        started(&mut methods);
        let callback = methods.take_callback().unwrap();
        assert_eq!(callback.tag, PROP_START);
        assert!((callback.then)(&mut methods, &[0; 4]).is_err());
        assert!(
            methods
                .last_refusal()
                .unwrap()
                .contains("setDCPAVPropStart")
        );
        assert!(!methods.callback_pending());
    }

    #[test]
    fn the_mode_set_uses_the_published_ids() {
        let mut methods = methods();
        started(&mut methods);
        drain(&mut methods, &[1, 0, 0, 0]);
        // get_digital_out_state: connected, success.
        let state = Packed::new().u32(0).bool(false).finish(8).unwrap();
        assert_eq!(
            returned(methods.call(*b"A414", &state, 8)),
            [1, 0, 0, 0, 0, 0, 0, 0]
        );
        // getVideoDataForIDs(timing, color): both records, no dual pipe, true.
        let query = |timing: u32, color: u32| {
            Packed::new()
                .bytes(&[0; modes::TIMING_BYTES])
                .bytes(&[0; modes::COLOR_BYTES])
                .u32(timing)
                .u32(color)
                .bool(false)
                .finish(0x7c)
                .unwrap()
        };
        let data =
            returned(methods.call(*b"A364", &query(modes::TIMING_ID, modes::COLOR_ID), 0x74));
        let advertised = Advertised::new(FULL_HD).unwrap();
        assert_eq!(&data[..0x50], &advertised.timing[..]);
        assert_eq!(&data[0x50..0x70], &advertised.color[..]);
        assert_eq!((data[0x70], data[0x71]), (0, 1));
        // Unknown IDs answer false.
        let data = returned(methods.call(*b"A364", &query(7, 7), 0x74));
        assert_eq!(data[0x71], 0);
        // set_digital_out_mode(color, timing).
        let set = Packed::new()
            .u32(modes::COLOR_ID)
            .u32(modes::TIMING_ID)
            .finish(8)
            .unwrap();
        assert_eq!(returned(methods.call(*b"A413", &set, 4)), [0; 4]);
        assert_eq!(
            methods.digital_out(),
            Some((modes::COLOR_ID, modes::TIMING_ID))
        );
        let swapped = Packed::new()
            .u32(modes::TIMING_ID)
            .u32(modes::COLOR_ID)
            .finish(8)
            .unwrap();
        assert!(methods.call(*b"A413", &swapped, 4).is_err());
        // manage_properties(true) keeps them; (false) refuses.
        assert!(returned(methods.call(*b"A363", &[1, 0, 0, 0], 0)).is_empty());
        assert!(methods.call(*b"A363", &[0; 4], 0).is_err());
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
        // first_client_open / last_client_close_dcp.
        assert!(returned(methods.call(*b"A466", &[], 0)).is_empty());
        assert_eq!(returned(methods.call(*b"A467", &[0; 4], 4)), [0; 4]);
    }

    fn start_swap(methods: &mut Methods) -> u32 {
        let start = Packed::new()
            .u32(0)
            .u64(0xfeed)
            .bool(false)
            .finish(0x10)
            .unwrap();
        let started = returned(methods.call(*b"A406", &start, 8));
        u32::from_le_bytes(started[0..4].try_into().unwrap())
    }

    #[test]
    fn a_swap_is_started_submitted_presented_then_completed() {
        let screen = TestScreen(Rc::default(), Some(MODE));
        let frames = screen.0.clone();
        let mut methods = Methods::new(Box::new(screen));
        assert!(returned(methods.call(*b"A403", &[], 0)).is_empty());
        assert_eq!(start_swap(&mut methods), 1);
        // A second start before the submit refuses.
        let start = Packed::new()
            .u32(0)
            .u64(0)
            .bool(false)
            .finish(0x10)
            .unwrap();
        assert!(methods.call(*b"A406", &start, 8).is_err());
        let submitted = returned(methods.call(*b"A407", &submission(1, &[(0, 4, 2, 0x1000)]), 0xc));
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
        assert_eq!(frames.borrow()[0], [0x5a, 0x5a, 0x5a, 0xff].repeat(8));
        let callback = methods.take_callback().unwrap();
        assert_eq!(&callback.tag, b"D594");
        assert_eq!(callback.input.len(), 0x730);
        assert_eq!(&callback.input[0..4], &1u32.to_le_bytes());
        (callback.then)(&mut methods, &[]).unwrap();
        // The record is logged whole the first times.
        let logged = core::iter::from_fn(|| methods.take_log())
            .any(|entry| matches!(entry, Log::Payload { bytes, .. } if bytes.len() == 0x1d30));
        assert!(logged);
    }

    #[test]
    fn a_layer_left_out_of_the_mask_keeps_showing() {
        let screen = TestScreen(Rc::default(), Some(MODE));
        let frames = screen.0.clone();
        let mut methods = Methods::new(Box::new(screen));
        start_swap(&mut methods);
        returned(methods.call(*b"A407", &submission(1, &[(2, 4, 2, 0x1000)]), 0xc));
        methods
            .present(|_, bytes| {
                bytes.fill(1);
                true
            })
            .unwrap();
        // A swap that enables no layer keeps layer 2.
        start_swap(&mut methods);
        returned(methods.call(*b"A407", &submission(2, &[]), 0xc));
        methods
            .present(|dva, bytes| {
                assert!((0x1000..0x1020).contains(&dva));
                bytes.fill(2);
                true
            })
            .unwrap();
        assert_eq!(frames.borrow()[1], [2, 2, 2, 0xff].repeat(8));
    }

    #[test]
    fn several_layers_are_composed_bottom_to_top() {
        let screen = TestScreen(Rc::default(), Some(MODE));
        let frames = screen.0.clone();
        let mut methods = Methods::new(Box::new(screen));
        start_swap(&mut methods);
        // Layer 0 covers the screen; layer 1, one pixel, sits at (3, 1).
        let mut two = submission(1, &[(0, 4, 2, 0x1000), (1, 1, 1, 0x2000)]);
        let at = swap::DESTINATION_RECTS + 16;
        two[at..at + 8].copy_from_slice(&[3, 0, 0, 0, 1, 0, 0, 0]);
        assert_eq!(returned(methods.call(*b"A407", &two, 0xc)), [0; 12]);
        methods
            .present(|dva, bytes| {
                bytes.fill(if dva >= 0x2000 { 0xff } else { 0x10 });
                true
            })
            .unwrap();
        let mut want = [0x10, 0x10, 0x10, 0xff].repeat(8);
        want[28..32].fill(0xff);
        assert_eq!(frames.borrow()[0], want);
    }

    #[test]
    fn a_background_swap_clears_and_bad_swaps_refuse() {
        let screen = TestScreen(Rc::default(), Some(MODE));
        let frames = screen.0.clone();
        let mut methods = Methods::new(Box::new(screen));
        // A submit without a start refuses.
        assert!(methods.call(*b"A407", &submission(0, &[]), 0xc).is_err());
        start_swap(&mut methods);
        returned(methods.call(*b"A407", &submission(1, &[]), 0xc));
        methods
            .present(|_, _| panic!("a clear reads no surface"))
            .unwrap();
        assert_eq!(frames.borrow()[0], [0, 0, 0, 0xff].repeat(8));
        // A source rectangle outside its surface refuses.
        start_swap(&mut methods);
        let mut outside = submission(2, &[(0, 4, 2, 0x1000)]);
        outside[swap::SOURCE_RECTS] = 1;
        assert!(methods.call(*b"A407", &outside, 0xc).is_err());
        assert!(
            methods
                .last_refusal()
                .unwrap()
                .contains("outside its surface")
        );
        // A non-black background refuses.
        start_swap(&mut methods);
        let mut red = submission(3, &[]);
        red[swap::BACKGROUND] = 0xff;
        assert!(methods.call(*b"A407", &red, 0xc).is_err());
    }
}
