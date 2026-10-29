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
fn status_methods_succeed_under_the_ap_link_status_contract() {
    // The original AP maps link statuses 1..=18 to IOReturn errors
    // (0x3d9cf30, table 0xaf72f0). In particular a boolean true is
    // kIOReturnError, not success. Keep the consumer independent of
    // the reply builder so accidentally changing zero to true fails.
    fn ap_success(bytes: &[u8], offset: usize) -> bool {
        let status = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        !(1..=18).contains(&status)
    }
    assert!(!ap_success(&1u32.to_le_bytes(), 0));
    let mut methods = methods();
    let mut parameter = [0; 0x28];
    parameter[..4].copy_from_slice(&ADAPTIVE_SYNC.to_le_bytes());
    let mut power = [0; 0x10];
    power[..8].copy_from_slice(&1u64.to_le_bytes());
    let mode = [
        modes::COLOR_ID.to_le_bytes(),
        modes::TIMING_ID.to_le_bytes(),
    ]
    .concat();
    for (tag, input, output, status_offset) in [
        (*b"A411", 2u32.to_le_bytes().as_slice(), 4, 0),
        (*b"A450", parameter.as_slice(), 4, 0),
        (*b"A484", power.as_slice(), 8, 4),
        (*b"A413", mode.as_slice(), 4, 0),
        (*b"A414", [0; 8].as_slice(), 8, 4),
        (*b"A406", [0; 0x10].as_slice(), 8, 4),
        (*b"A479", [0; 8].as_slice(), 4, 0),
    ] {
        let reply = returned(methods.call(tag, input, output));
        assert!(ap_success(&reply, status_offset), "{tag:?}: {reply:?}");
        // Use canonical zero rather than an out-of-range value the
        // AP happens to accept.
        assert_eq!(&reply[status_offset..status_offset + 4], &[0; 4]);
    }
    start_swap(&mut methods);
    let reply = returned(methods.call(*b"A407", &submission(1, &[]), 0xc));
    assert!(ap_success(&reply, 8));
    assert_eq!(&reply[8..12], &[0; 4]);
    // setDisplayRefreshProperties is boolean: the AP at
    // 0x3d7a4e4 reads its low bit instead of mapping a link status.
    assert_eq!(returned(methods.call(*b"A475", &[], 4)), [1, 0, 0, 0]);
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
fn the_config_frame_size_starts_unset_and_programs_only_the_mode() {
    let mut methods = methods();
    // Values 0, both pointers present, the AP's 0xaa padding.
    let query = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa, 0xaa];
    assert_eq!(returned(methods.call(*b"A103", &query, 8)), [0; 8]);
    let mut size = 1920u32.to_le_bytes().to_vec();
    size.extend_from_slice(&1080u32.to_le_bytes());
    assert!(returned(methods.call(*b"A104", &size, 0)).is_empty());
    assert_eq!(returned(methods.call(*b"A103", &query, 8)), size);
    assert!(returned(methods.call(*b"A105", &[], 0)).is_empty());
    let mut other = 1280u32.to_le_bytes().to_vec();
    other.extend_from_slice(&720u32.to_le_bytes());
    returned(methods.call(*b"A104", &other, 0));
    assert!(methods.call(*b"A105", &[], 0).is_err());
    assert!(methods.last_refusal().unwrap().contains("A105"));
}

#[test]
fn the_pipe_start_up_queries_answer_as_the_j473_firmware_does() {
    let mut methods = methods();
    // apt_supported, isKeepOnScreen, get_shared_disp_state: false.
    for tag in [*b"A035", *b"A485", *b"A489"] {
        assert_eq!(returned(methods.call(tag, &[], 4)), [0; 4]);
    }
    // setSharedEventMemBlockSize(u32, u32): no output.
    let sizes = Packed::new().u32(0x4000).u32(0x40).finish(8).unwrap();
    assert!(returned(methods.call(*b"A465", &sizes, 0)).is_empty());
    assert!(methods.last_refusal().is_none());
}

#[test]
fn answers_fill_their_whole_output_past_a_callbacks_stale_bytes() {
    // A callback's output room keeps whatever the stream held before
    // (the firmware's rpc_caller_gated writes only the header and
    // input), and the AP writes just its bool. A401's answer, built
    // from that bool, still zeroes the rest of its own output.
    let mut methods = methods();
    let Step::Call { then, .. } = methods.call(*b"A401", &[], 4).unwrap() else {
        panic!("A401 must nest D120");
    };
    assert_eq!(
        returned(then(&mut methods, &[1, 0x3e, 0x49, 0x44])),
        [1, 0, 0, 0]
    );
    let made = drain(&mut methods, &[1, 0x6b, 0x65, 0x79]);
    assert_eq!(made.last().unwrap().0, HOTPLUG);
    assert!(methods.last_refusal().is_none());
}

#[test]
fn link_shutdown_stops_the_pipe_and_hibernation_refuses() {
    // Hibernation (first byte 1) refuses and leaves the link up.
    let mut hibernating = methods();
    assert!(hibernating.call(*b"A500", &[1, 1, 0xaa, 0xaa], 0).is_err());
    assert_eq!(returned(hibernating.call(*b"A035", &[], 4)), [0; 4]);
    // set_power_state's link_shutdown_signal(false, true), padded 0xaaaa,
    // with the published mode's callbacks still queued.
    let mut methods = methods();
    started(&mut methods);
    assert!(methods.callback_pending());
    assert!(returned(methods.call(*b"A500", &[0, 1, 0xaa, 0xaa], 0)).is_empty());
    assert!(!methods.callback_pending() && methods.take_callback().is_none());
    // The link is down: nothing more is served.
    assert!(methods.call(*b"A035", &[], 4).is_err());
    assert!(
        methods
            .last_refusal()
            .unwrap()
            .contains("shut the DCP link down")
    );
    methods.resume();
    assert_eq!(returned(methods.call(*b"A035", &[], 4)), [0; 4]);
    assert!(!methods.callback_pending() && methods.take_callback().is_none());
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
    let data = returned(methods.call(*b"A364", &query(modes::TIMING_ID, modes::COLOR_ID), 0x74));
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

#[test]
fn power_and_sleep_gate_scanout() {
    use super::super::avipc::{COMMAND_PACKET_TYPE, Controller};
    let display = Rc::new(RefCell::new(DisplayState::new(true)));
    let screen = TestScreen(Rc::default(), Some(MODE));
    let frames = screen.0.clone();
    let mut methods = Methods::with_display_state(Box::new(screen), Rc::clone(&display));
    let mut controller = Controller::new(display);
    let mut command = |index: u32, value: Option<u64>| {
        let size: u32 = if value.is_some() { 0x20 } else { 0x10 };
        let mut bytes = alloc::vec![0; 0x40 + size as usize];
        bytes[4..8].copy_from_slice(&index.to_le_bytes());
        bytes[8..12].copy_from_slice(&size.to_le_bytes());
        bytes[12..16].copy_from_slice(&0x6970_6378u32.to_le_bytes());
        if let Some(value) = value {
            bytes[0x50..0x58].copy_from_slice(&value.to_le_bytes());
        }
        let (status, reply) = controller.handle(COMMAND_PACKET_TYPE, &bytes).unwrap();
        assert_eq!(status, 0);
        assert_eq!(&reply[0x40..0x44], &[0; 4]);
        reply
    };
    start_swap(&mut methods);
    returned(methods.call(*b"A407", &submission(1, &[]), 0xc));
    command(6, Some(0));
    methods
        .present(|_, _| panic!("powered-off scanout reads no pixels"))
        .unwrap();
    assert!(methods.frame_pending() && !methods.callback_pending());
    assert!(frames.borrow().is_empty());
    command(6, Some(1));
    command(9, None);
    methods
        .present(|_, _| panic!("asleep scanout reads no pixels"))
        .unwrap();
    assert!(methods.frame_pending() && frames.borrow().is_empty());
    command(8, None);
    methods
        .present(|_, _| panic!("background clear has no surface"))
        .unwrap();
    assert_eq!(frames.borrow().len(), 1);
    assert!(!methods.frame_pending() && methods.callback_pending());
    let callback = methods.take_callback().unwrap();
    assert_eq!(callback.tag, SWAP_COMPLETE);
    (callback.then)(&mut methods, &[]).unwrap();
    // The opposite API observes the same power change.
    returned(methods.call(*b"A484", &[0; 0x10], 8));
    let power = command(7, Some(0));
    assert_eq!(&power[0x50..0x58], &[0; 8]);
    command(10, None);
    assert!(methods.callback_pending());
    let callback = methods.take_callback().unwrap();
    assert_eq!(callback.tag, HOTPLUG);
    assert_eq!(&callback.input[..8], &PLUGGED.to_le_bytes());
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

fn submit_refusal_keeps_accepted_swap(mutate: impl FnOnce(&mut [u8]), reason: &str) {
    let screen = TestScreen(Rc::default(), Some(MODE));
    let displayed = screen.0.clone();
    let mut methods = Methods::new(Box::new(screen));
    started(&mut methods);
    let completed = start_swap(&mut methods);
    returned(methods.call(*b"A407", &submission(completed, &[]), 0xc));
    methods
        .present(|_, _| panic!("background clear reads no surface"))
        .unwrap();
    let queued = start_swap(&mut methods);
    returned(methods.call(*b"A407", &submission(queued, &[(0, 4, 2, 0x1000)]), 0xc));
    let id = start_swap(&mut methods);
    let valid = submission(id, &[(0, 4, 2, 0x2000)]);
    let mut refused = valid.clone();
    mutate(&mut refused);
    let planes = methods.planes.to_vec();
    let frames = methods.frames.clone();
    let completions = methods.completed.clone();
    let error = methods
        .call(*b"A407", &refused, 0xc)
        .err()
        .expect("unsupported submission refused");
    assert!(error.contains(reason), "{error}");
    assert_eq!(methods.open_swap, Some(id));
    assert_eq!(methods.planes.as_slice(), planes);
    assert_eq!(methods.frames, frames);
    assert_eq!(methods.completed, completions);
    assert_eq!(displayed.borrow().len(), 1);
    assert_eq!(methods.call(*b"A407", &refused, 0xc).err(), Some(error));
    returned(methods.call(*b"A407", &valid, 0xc));
    assert_eq!(methods.open_swap, None);
    assert_eq!(methods.frames.len(), frames.len() + 1);
    assert_eq!(methods.frames.back().unwrap().swap_id, id);
    assert_eq!(methods.completed, completions);
}

#[test]
fn refused_swap_parse_preserves_started_swap_and_prior_frames() {
    submit_refusal_keeps_accepted_swap(
        |input| input[swap::SECONDARY_NULL] = 0,
        "secondary surface",
    );
}

#[test]
fn refused_tiled_surface_preserves_started_swap_and_prior_frames() {
    submit_refusal_keeps_accepted_swap(|input| input[swap::SURFACES] = 1, "tiled");
}

#[test]
fn refused_background_preserves_started_swap_and_prior_frames() {
    submit_refusal_keeps_accepted_swap(|input| input[swap::BACKGROUND] = 0xff, "background color");
}

#[test]
fn refused_submit_reply_preflight_preserves_started_swap() {
    let mut methods = methods();
    let id = start_swap(&mut methods);
    let input = submission(id, &[]);
    // Public RPC validates ABI output size before dispatch. The
    // submit method also prepares its fallible reply before committing.
    assert!(methods.submit(*b"A407", &input, 0).is_err());
    assert_eq!(methods.open_swap, Some(id));
    assert!(methods.frames.is_empty());
    returned(methods.call(*b"A407", &input, 0xc));
    assert_eq!(methods.frames.back().unwrap().swap_id, id);
}

#[test]
fn failed_presents_keep_swap_order_until_abort() {
    struct Sink {
        attempts: Rc<RefCell<usize>>,
        frames: Rc<RefCell<Vec<Vec<u8>>>>,
    }
    impl Scanout for Sink {
        fn mode(&self) -> Mode {
            MODE
        }
        fn present(&mut self, rows: &[u8]) -> Result<(), &'static str> {
            let mut attempts = self.attempts.borrow_mut();
            *attempts += 1;
            if *attempts == 1 {
                return Err("sink temporarily unavailable");
            }
            self.frames.borrow_mut().push(rows.to_vec());
            Ok(())
        }
    }
    let attempts = Rc::new(RefCell::new(0));
    let frames = Rc::new(RefCell::new(Vec::new()));
    let mut methods = Methods::new(Box::new(Sink {
        attempts: attempts.clone(),
        frames: frames.clone(),
    }));
    for (id, dva) in [(1, 0x1000), (2, 0x2000)] {
        assert_eq!(start_swap(&mut methods), id);
        returned(methods.call(*b"A407", &submission(id, &[(0, 4, 2, dva)]), 0xc));
    }
    let mut reads = 0;
    assert!(
        methods
            .present(|dva, bytes| {
                reads += 1;
                assert!((0x1000..0x1020).contains(&dva));
                bytes.fill(0x11);
                reads != 2
            })
            .is_err()
    );
    assert_eq!(*attempts.borrow(), 0);
    assert!(methods.frame_pending() && !methods.callback_pending());
    let read = |dva, bytes: &mut [u8]| {
        assert!((0x1000..0x1020).contains(&dva));
        bytes.fill(0x11);
        true
    };
    assert_eq!(methods.present(read), Err("sink temporarily unavailable"));
    assert!(methods.frame_pending() && !methods.callback_pending());
    assert!(frames.borrow().is_empty());
    methods.present(read).unwrap();
    assert_eq!(*attempts.borrow(), 2);
    assert_eq!(frames.borrow().len(), 1);
    let callback = methods.take_callback().unwrap();
    assert_eq!(callback.tag, SWAP_COMPLETE);
    assert_eq!(&callback.input[..4], &1u32.to_le_bytes());
    (callback.then)(&mut methods, &[]).unwrap();
    // The next submitted swap is still present, and an AP abort owns
    // its cancellation. It emits no invented successful completion.
    assert!(methods.frame_pending());
    returned(methods.call(*b"A479", &[0; 8], 4));
    assert!(!methods.frame_pending() && !methods.callback_pending());
    methods
        .present(|_, _| panic!("aborted swap has no DMA"))
        .unwrap();
    assert_eq!(*attempts.borrow(), 2);
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
    // The refused submission keeps its accepted start until explicit abort.
    returned(methods.call(*b"A479", &[0; 8], 4));
    // A non-black background refuses.
    start_swap(&mut methods);
    let mut red = submission(3, &[]);
    red[swap::BACKGROUND] = 0xff;
    assert!(methods.call(*b"A407", &red, 0xc).is_err());
}
