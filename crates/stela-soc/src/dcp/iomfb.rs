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
//! answers, as the firmware does (the AP's D120 handler,
//! `UnifiedPipeline2::start_hardware_boot` 0x2a5d7cc, calls
//! `set_create_DFB`, `do_create_default_frame_buffer`, the config frame size
//! methods, `flush_supportsPower`, `apt_supported`, `late_init_signal`,
//! `headless` and `setDisplayRefreshProperties` back, which re-enter
//! [`Methods::call`]). The model inherits the boot framebuffer rather than
//! allocating a new default one: `A454 do_create_default_frame_buffer`
//! answers 0. The pipe's config frame size starts unset (`A103` answers
//! 0 x 0), so the AP's `start_hardware_boot` sets it to the display size
//! (`A104`) and programs it (`A105`).
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
use super::avipc::DisplayState;
use super::modes::{self, Advertised};
use super::rpc::{Callback, Service, Step};
use super::swap::{self, Layer, Submission};
use crate::Result;
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::format;
use alloc::rc::Rc;
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::cell::RefCell;
use stela_contracts::Refusal;
use stela_contracts::refuse;

/// The most display-log entries kept between drains.
const LOG_CAPACITY: usize = 4096;
/// The leading call-input bytes a log entry keeps.
const LOGGED_INPUT: usize = 64;
/// How many `swap_submit_dcp` inputs are logged whole.
const DUMPED_SWAPS: u32 = 2;
/// `IOMFBPARAM_ADAPTIVE_SYNC` (Asahi `iomfb.h`).
const ADAPTIVE_SYNC: u32 = 14;
/// `D594 swap_complete_ap_gated`'s input starts with the swap ID. Its
/// statistics pointer is absent. The fixed eight-blob storage remains zero
/// with count zero; the original dispatcher passes that array unconditionally
/// and has no independent blob-null flag. The sole null flag is at +0x72c;
/// +0x72d..+0x72f is padding in the complete 0x730-byte record.
const SWAP_COMPLETE: [u8; 4] = *b"D594";
/// Original T6000 `D594_callback__` (container file 0x3daec14) reads this
/// flag at VA 0xfffffe000adb2cec and passes nullptr for bit0=1. The AP
/// skips absent statistics at 0xfffffe000ad9cb68 and still completes the
/// presented swap. A present record copies its timestamp at +0x19.
const SWAP_COMPLETE_DATA_NULL: usize = 0x72c;
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
    advertised: Result<Advertised>,
    /// Why the last call refused, with the tag and its interface row.
    last_refusal: Option<String>,
    log: VecDeque<Log>,
    dropped: u64,
    dumped: u32,
    /// The monitor's power and sleep state, shared with its IOAV controller.
    display: Rc<RefCell<DisplayState>>,
    /// Open IOMFB clients (`first_client_open` minus `last_client_close`).
    clients: u32,
    /// The mode set by `set_digital_out_mode`, `(color, timing)`.
    digital_out: Option<(u32, u32)>,
    /// The pipe's config frame size, `(width, height)`; 0 x 0 until the AP
    /// sets it.
    config_frame: (u32, u32),
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
    /// The AP shut the link down (`link_shutdown_signal`).
    shut_down: bool,
}

impl Methods {
    pub(super) fn check_reset(&self) -> Result<()> {
        if self.open_swap.is_some()
            || !self.frames.is_empty()
            || !self.outgoing.is_empty()
            || !self.completed.is_empty()
            || self.in_flight
            || self.display.borrow().hotplug_pending()
        {
            return Err(refuse!(
                "DCP physical reset with owned scanout or callback work"
            ));
        }
        Ok(())
    }
    pub(super) fn reset(&mut self) {
        // The fixed physical monitor and host scanout survive a coprocessor
        // reset. Native clients/mode/layer state are volatile. The caller
        // preflights all frame and callback ownership before reaching here.
        self.clients = 0;
        self.digital_out = None;
        self.config_frame = (0, 0);
        self.next_swap = 1;
        self.open_swap = None;
        self.planes = [None; swap::LAYERS];
        self.shut_down = false;
    }
    /// Resume the link after the coprocessor's sleep-to-wake edge.
    /// Firmware 0x187658 clears its quiescence byte and releases stopped
    /// streams; the shared region, mode and client state remain allocated.
    /// No callbacks or swaps discarded by A500 are recreated here.
    pub(super) fn resume(&mut self) {
        self.shut_down = false;
    }

    pub fn new(scanout: Box<dyn Scanout>) -> Self {
        // Configured model power, not an observation of Apple's boot state.
        Self::with_display_state(scanout, Rc::new(RefCell::new(DisplayState::new(true))))
    }

    pub fn with_display_state(
        scanout: Box<dyn Scanout>,
        display: Rc<RefCell<DisplayState>>,
    ) -> Self {
        let advertised = Advertised::new(scanout.mode());
        Self {
            scanout,
            advertised,
            last_refusal: None,
            log: VecDeque::new(),
            dropped: 0,
            dumped: 0,
            display,
            clients: 0,
            digital_out: None,
            config_frame: (0, 0),
            next_swap: 1,
            open_swap: None,
            planes: [None; swap::LAYERS],
            frames: VecDeque::new(),
            outgoing: VecDeque::new(),
            completed: VecDeque::new(),
            in_flight: false,
            shut_down: false,
        }
    }

    pub(super) fn display_state(&self) -> Rc<RefCell<DisplayState>> {
        self.display.clone()
    }

    /// The fixed mode the one connected display runs.
    pub fn mode(&self) -> Mode {
        self.scanout.mode()
    }

    /// The last `setPowerState` the AP asked for.
    #[cfg(test)]
    pub fn powered(&self) -> Option<bool> {
        self.display.borrow().powered
    }

    /// The `(color, timing)` IDs of the last `set_digital_out_mode`.
    #[cfg(test)]
    pub fn digital_out(&self) -> Option<(u32, u32)> {
        self.digital_out
    }

    /// The last refusal's full text.
    #[cfg(test)]
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
    pub fn present(&mut self, read: impl FnMut(u64, &mut [u8]) -> bool) -> Result<()> {
        if !self.display.borrow().active() {
            return Ok(());
        }
        let Some(frame) = self.frames.front() else {
            return Ok(());
        };
        let mode = self.mode();
        let rows = scanout::compose(&frame.layers, mode, read)?;
        self.scanout.present(&rows)?;
        // Both the surface DMA and host sink can refuse. The submitted swap
        // owns its surfaces until presentation succeeds, or the AP explicitly
        // aborts/shuts down; neither failure consumes it or queues D594.
        let frame = self.frames.pop_front().expect("presented front frame");
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
    fn refuse(&mut self, tag: [u8; 4], reason: Refusal) -> Result<Step<Self>> {
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
    fn refuse_answer(&mut self, tag: [u8; 4], reason: Refusal) -> Result<()> {
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

    fn reply(&mut self, tag: [u8; 4], packed: Result<Vec<u8>>) -> Result<Step<Self>> {
        match packed {
            Ok(bytes) => Ok(Step::Return(bytes)),
            Err(reason) => self.refuse(tag, reason),
        }
    }

    /// Queue a callback, sized by its interface row.
    fn queue(&mut self, tag: [u8; 4], input: Packed) -> Result<()> {
        let row = abi::callback(&tag).ok_or(refuse!("DCP callback is not on the interface"))?;
        let (Some(length), Some(output)) = (row.input, row.output) else {
            return Err(refuse!("DCP callback sizes are not recorded"));
        };
        let input = input.finish(length)?;
        self.outgoing.push_back(Outgoing { tag, input, output });
        Ok(())
    }

    /// Publish the one mode's `TimingElements` and `ColorElements` on the
    /// IOMFB service, then report the monitor plugged.
    fn publish(&mut self) -> Result<()> {
        let advertised = match &self.advertised {
            Ok(advertised) => advertised,
            Err(reason) => {
                let reason = reason.clone();
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
            let length =
                u32::try_from(bytes.len()).map_err(|_| refuse!("DCP property is too long"))?;
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
        self.queue_hotplug()
    }

    fn queue_hotplug(&mut self) -> Result<()> {
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
    fn call(&mut self, tag: [u8; 4], input: &[u8], output: u32) -> Result<Step<Self>> {
        self.record_log(Log::Call {
            tag,
            input: input[..input.len().min(LOGGED_INPUT)].to_vec(),
            output,
        });
        let Some(row) = abi::method(&tag) else {
            return self.refuse(tag, refuse!("tag is not a method of this DCP interface"));
        };
        if row.input as usize != input.len() || row.output != output {
            return self.refuse(
                tag,
                refuse!("call sizes differ from the interface's record"),
            );
        }
        if self.shut_down {
            return self.refuse(
                tag,
                refuse!(
                    "the AP shut the DCP link down; an IOP sleep-to-wake transition is required"
                ),
            );
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
                        refuse!("set_parameter_dcp sets a parameter the fixed mode does not have"),
                    );
                }
                let packed = Packed::new().u32(IO_RETURN_SUCCESS).finish(output);
                self.reply(tag, packed)
            }
            // setPowerState(state, ...) -> {u32, u32 result}: 1 on, 0 off
            // (Asahi dcp_on_set_power_state / last_client_closed_poff).
            b"A484" => {
                let state = fields.u64()?;
                self.display.borrow_mut().powered = Some(match state {
                    0 => false,
                    1 => true,
                    _ => {
                        return self.refuse(
                            tag,
                            refuse!("setPowerState names a state other than off or on"),
                        );
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
                        refuse!("manage_properties withdraws the published modes, which the fixed monitor never does"),
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
                        refuse!("set_digital_out_mode names a mode the DCP never advertised"),
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
            // UPPipe2::get_config_frame_size(u32* width, u32* height)
            // (0x2a6b264): both values, then a null flag per pointer.
            // `UnifiedPipeline2::start_hardware_boot` (0x2a5d840) treats a
            // zero dimension as unset and configures the display size
            // (Inferred: a freshly started pipe has none configured).
            b"A103" => {
                fields.u32()?;
                fields.u32()?;
                let (width, height) = self.config_frame;
                let packed = Packed::new().u32(width).u32(height).finish(output);
                self.reply(tag, packed)
            }
            // set_config_frame_size(u32 width, u32 height) (0x2a6b33c).
            b"A104" => {
                self.config_frame = (fields.u32()?, fields.u32()?);
                Ok(Step::Return(Vec::new()))
            }
            // program_config_frame_size() (0x2a6b39c): the pipe scans out
            // the one mode, so only its size can be programmed.
            b"A105" => {
                let mode = self.mode();
                if self.config_frame != (mode.width, mode.height) {
                    return self.refuse(
                        tag,
                        refuse!(
                            "program_config_frame_size programs a frame size other than the mode's"
                        ),
                    );
                }
                Ok(Step::Return(Vec::new()))
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
                    return self.refuse(
                        tag,
                        refuse!("swap_start_dcp while a started swap is not submitted"),
                    );
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
            // link_shutdown_signal(bool hibernate, bool): the AP's
            // DCPPowerManager::set_power_state (0x3d852c0) sends it for
            // power state 0 once the link is idle, then waits for its own
            // streams and cuts the DCP's power and DART. Methods resume
            // only on the coprocessor's sleep-to-wake edge.
            // The firmware (restore 0x191390, normal 0x191594) reads only
            // the first byte. 1 also saves the pipe for hibernation
            // (0x191434, 0x1884a4). Otherwise it stops the pipe (0x27c99c),
            // tears its AP link down (0x1871f0) and answers nothing. The
            // model's pipe stops: no queued swap is presented or completed
            // and no callback follows.
            b"A500" => {
                if fields.u8()? == 1 {
                    return self.refuse(
                        tag,
                        refuse!("link_shutdown_signal saves the pipe for hibernation, which is not modeled"),
                    );
                }
                self.shut_down = true;
                self.open_swap = None;
                self.frames.clear();
                self.outgoing.clear();
                self.completed.clear();
                Ok(Step::Return(Vec::new()))
            }
            _ => match answer(&tag, input, output, self.mode()) {
                Ok(bytes) => Ok(Step::Return(bytes)),
                Err(reason) => self.refuse(tag, reason),
            },
        }
    }

    fn callback_pending(&self) -> bool {
        !self.in_flight
            && (!(self.outgoing.is_empty() && self.completed.is_empty())
                || (!self.shut_down && self.display.borrow().hotplug_pending()))
    }

    fn take_callback(&mut self) -> Option<Callback<Self>> {
        if self.in_flight {
            return None;
        }
        if !self.shut_down && self.display.borrow_mut().take_hotplug_request() {
            self.queue_hotplug()
                .expect("the recorded fixed-monitor HPD callback has a valid size");
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
                        return methods
                            .refuse_answer(tag, refuse!("the AP refused the published mode"));
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
        input[SWAP_COMPLETE_DATA_NULL] = 1;
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
    fn submit(&mut self, tag: [u8; 4], input: &[u8], output: u32) -> Result<Step<Self>> {
        let Some(swap_id) = self.open_swap else {
            return self.refuse(tag, refuse!("swap_submit_dcp without swap_start_dcp"));
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
        let packed = Packed::new()
            .bool(false)
            .u32(0)
            .u32(IO_RETURN_SUCCESS)
            .finish(output);
        let reply = self.reply(tag, packed)?;
        // Commit the accepted swap only after every fallible preflight succeeds.
        self.open_swap = None;
        self.planes = planes;
        self.frames.push_back(Frame { swap_id, layers });
        Ok(reply)
    }
}

/// The layers the slots show, bottom to top, over a black background. A
/// non-black background, or a layer whose surface or rectangles the model
/// cannot show, refuses by name.
fn visible(planes: &[Option<Layer>; swap::LAYERS], background: u32) -> Result<Vec<scanout::Layer>> {
    if background != 0 {
        return Err(refuse!(
            "swap clears to a background color; the model presents black only"
        ));
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
pub fn answer(code: &[u8; 4], input: &[u8], output: u32, mode: Mode) -> Result<Vec<u8>> {
    let out = output as usize;
    let sized = |bytes: Vec<u8>| -> Result<Vec<u8>> {
        if bytes.len() == out {
            Ok(bytes)
        } else {
            Err(refuse!(
                "DCP method output size differs from the AP's header"
            ))
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
        // set_display_device(index) -> link status, not bool. The AP
        // wrapper (0x3d77988) passes this word to iomfb_status_from_link
        // (0x3d9cf30): 0 succeeds; 1 maps to kIOReturnError (0xe00002bc).
        // Original T6000 restore FW 0x26aed0 ignores the index and returns
        // success for its external trait (+0x4305); init 0x256310..2563e8
        // sets that trait for types 2/3 and publishes "external".
        b"A411" => sized(IO_RETURN_SUCCESS.to_le_bytes().to_vec()),
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
        // apt_supported (UPPipeAP_H13P::late_init 0x2a4e98c): false. The
        // firmware answers pipe word +0x42c == 1 (restore 0x2bcad0, normal
        // 0x2bf884), which its init sets only to 3 or 0 (0x2c84b0, 0x2c8724).
        b"A035" => sized(bool_reply(false)),
        // setSharedEventMemBlockSize(u32, u32) (UnifiedPipeline2::start
        // 0x2a5e02c): no output; the firmware only records the sizes in its
        // shared-event block (restore 0x1becd8, normal 0x1bf20c).
        b"A465" => sized(Vec::new()),
        // isKeepOnScreen (swapping_client_did_start 0x3d67534): false, the
        // firmware's byte +0x4304, which nothing sets (restore 0x1c8f30).
        b"A485" => sized(bool_reply(false)),
        // get_shared_disp_state (get_ap_shared_disp_state 0x3d6247c, asked
        // once AppleClamshellState exists): false, the pipe's byte +0x2ba8,
        // which nothing sets (restore 0x2c01d0, normal 0x2c2fb4).
        b"A489" => sized(bool_reply(false)),
        // remove_gain_maps (0x3d7a6a8): this monitor creates no gain map, so
        // the client's record state in the first eight bytes returns as it
        // came, valid byte +5 included, with success in the word at +8, which
        // the AP returns.
        b"A480" => {
            let mut bytes = input.to_vec();
            if let Some(result) = bytes.get_mut(8..12) {
                result.copy_from_slice(&IO_RETURN_SUCCESS.to_le_bytes());
            }
            sized(bytes)
        }
        _ => Err(refuse!(
            "DCP method is not modeled for the one fixed monitor"
        )),
    }
}

#[cfg(test)]
mod tests;
