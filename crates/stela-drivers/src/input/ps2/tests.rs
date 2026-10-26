//! A controller/peripheral model with real output routing, IBF timing, device
//! state and negotiated packet size. The production controller issues commands;
//! tests inject ordinary input and independent framing/acknowledgement faults.
use super::*;
use alloc::{rc::Rc, vec};
use core::cell::{Cell, RefCell};
mod elantech_tests;
mod timing_tests;

#[test]
fn full_reply_side_queue_preserves_every_consumed_byte_and_leaves_further_hardware_unread() {
    let (mut c, h) = controller(Config::default());
    c.initialize().unwrap();
    let packet = [8, 1, 0, 0];
    let stream: Vec<_> = packet.into_iter().cycle().take(QUEUE_LIMIT + 8).collect();
    h.borrow_mut().inject_led = stream.iter().map(|byte| (Port::Mouse, *byte)).collect();
    let before = h.borrow().consumed;
    let error = c.set_leds(7).unwrap_err();
    assert_eq!(error.kind, ErrorKind::QueueFull);
    assert!(c.needs_reset());
    assert_eq!(
        h.borrow().consumed - before,
        QUEUE_LIMIT,
        "no extra hardware byte may be read merely to discover the software queue is full"
    );
    assert_eq!(
        c.retained_bytes()
            .map(|(port, data, _)| {
                assert_eq!(port, Port::Mouse);
                data
            })
            .collect::<Vec<_>>(),
        stream[..QUEUE_LIMIT]
    );
    assert!(h.borrow().output.len() >= 9);
    let writes = h.borrow().writes.len();
    assert_eq!(c.set_leds(7).unwrap_err().kind, ErrorKind::NeedsReset);
    assert_eq!(h.borrow().writes.len(), writes);
}
#[test]
fn full_side_queue_still_allows_actual_primary_ack_without_consuming_another_sibling_byte() {
    let (mut c, h) = controller(Config::default());
    c.initialize().unwrap();
    h.borrow_mut().inject_led = [8, 1, 0, 0]
        .into_iter()
        .cycle()
        .take(QUEUE_LIMIT)
        .map(|byte| (Port::Mouse, byte))
        .collect();
    c.set_leds(7).unwrap();
    assert_eq!(h.borrow().leds, 7);
    assert_eq!(c.retained_bytes().count(), QUEUE_LIMIT);
    assert!(c.is_ready());
    let inputs = c.poll().unwrap();
    assert_eq!(
        inputs
            .iter()
            .filter(|e| **e == Input::Motion { dx: 1, dy: 0 })
            .count(),
        16
    );
    assert_eq!(c.retained_bytes().count(), 0);
}
#[test]
fn consumed_framed_error_byte_survives_first_failure_even_with_full_side_queue() {
    for queued in [0, QUEUE_LIMIT] {
        let (mut c, h) = controller(Config::default());
        c.initialize().unwrap();
        for byte in [8, 1, 0, 0].into_iter().cycle().take(queued) {
            h.borrow_mut().output.push_back((Port::Mouse, byte, 0));
        }
        h.borrow_mut().output.push_back((Port::Mouse, 0x5a, 0x80));
        let error = c.set_leds(7).unwrap_err();
        assert!(matches!(error.kind,ErrorKind::Frame {port:Port::Mouse,status} if status&0x80!=0));
        assert_eq!(
            error.response,
            Some(ObservedResponse {
                port: Port::Mouse,
                data: 0x5a
            })
        );
        let retained: Vec<_> = c.retained_bytes().collect();
        assert!(retained.len() >= queued);
        assert!(
            retained
                .iter()
                .take(queued)
                .all(|(port, _, _)| *port == Port::Mouse)
        );
        if queued == 0 {
            assert!(
                retained
                    .iter()
                    .any(|(port, data, _)| *port == Port::Keyboard && *data == ACK)
            );
        }
        assert!(c.needs_reset());
    }
}
#[test]
fn original_and_containment_frame_failures_keep_their_distinct_actual_bytes() {
    let (mut c, h) = controller(Config::default());
    c.initialize().unwrap();
    for byte in [8, 1, 0, 0].into_iter().cycle().take(QUEUE_LIMIT) {
        h.borrow_mut().output.push_back((Port::Mouse, byte, 0));
    }
    h.borrow_mut()
        .output
        .extend([(Port::Mouse, 0x5a, 0x80), (Port::Mouse, 0x6b, 0x80)]);
    let error = c.set_leds(7).unwrap_err();
    assert!(matches!(
        error.kind,
        ErrorKind::Frame {
            port: Port::Mouse,
            ..
        }
    ));
    assert_eq!(
        error.response,
        Some(ObservedResponse {
            port: Port::Mouse,
            data: 0x5a
        })
    );
    assert!(matches!(
        error.recovery_error,
        Some(ErrorKind::Frame {
            port: Port::Mouse,
            ..
        })
    ));
    assert_eq!(
        error.recovery_response,
        Some(ObservedResponse {
            port: Port::Mouse,
            data: 0x6b
        })
    );
    assert_eq!(error.recovery, Recovery::Failed);
    assert_eq!(c.retained_bytes().count(), QUEUE_LIMIT);
}
mod synaptics_tests;

#[derive(Clone)]
struct Model(Rc<RefCell<Hardware>>);
struct Hardware {
    time: Rc<Cell<u64>>,
    status_delay_us: u64,
    busy_until: Option<u64>,
    output: VecDeque<(Port, u8, u8)>,
    config: u8,
    config_write: bool,
    mouse_write: bool,
    argument: [Option<u8>; 2],
    scanning: [bool; 2],
    scan: u8,
    leds: u8,
    rates: Vec<u8>,
    mouse_id: u8,
    wheel_capable: bool,
    explorer_capable: bool,
    no_id_ack: bool,
    force_id: Option<u8>,
    self_test: u8,
    keyboard_on_enable: Vec<u8>,
    after_self_test: Vec<u8>,
    interface_test: u8,
    translation_stuck: bool,
    busy_forever: bool,
    flood: bool,
    resend: Option<(Port, u8, usize)>,
    resend_inject: Vec<(Port, u8)>,
    no_ack: Option<(Port, u8)>,
    inject_led: Vec<(Port, u8)>,
    writes: Vec<(bool, u8)>,
    consumed: usize,
    synaptics: Option<synaptics_tests::Peripheral>,
    elantech: Option<elantech_tests::Peripheral>,
    delay_at_read: alloc::collections::BTreeMap<usize, u64>,
}
impl Hardware {
    fn new(time: Rc<Cell<u64>>) -> Self {
        Self {
            status_delay_us: 0,
            time,
            busy_until: None,
            output: VecDeque::new(),
            config: TRANSLATION | IRQ_BITS,
            config_write: false,
            mouse_write: false,
            argument: [None, None],
            scanning: [true; 2],
            scan: 2,
            leds: 0,
            rates: Vec::new(),
            mouse_id: 0,
            wheel_capable: true,
            explorer_capable: false,
            no_id_ack: false,
            force_id: None,
            self_test: 0x55,
            keyboard_on_enable: Vec::new(),
            after_self_test: Vec::new(),
            interface_test: 0,
            translation_stuck: false,
            busy_forever: false,
            flood: false,
            resend: None,
            resend_inject: Vec::new(),
            no_ack: None,
            inject_led: Vec::new(),
            writes: Vec::new(),
            consumed: 0,
            synaptics: None,
            elantech: None,
            delay_at_read: alloc::collections::BTreeMap::new(),
        }
    }
    fn emit(&mut self, port: Port, data: u8) {
        self.output.push_back((port, data, 0));
    }
    fn input_busy(&self) -> bool {
        self.busy_forever
            || self.busy_until.is_some_and(|deadline| {
                let remaining = deadline.wrapping_sub(self.time.get());
                remaining != 0 && remaining <= u64::MAX / 2
            })
    }
    fn index(port: Port) -> usize {
        if port == Port::Mouse { 1 } else { 0 }
    }
    fn device(&mut self, port: Port, data: u8) {
        if port == Port::Mouse
            && data == DISABLE_REPORTING
            && self.scanning[1]
            && let Some(e) = &mut self.elantech
        {
            let bytes = core::mem::take(&mut e.before_disable);
            for byte in bytes {
                self.emit(port, byte);
            }
        }
        if port == Port::Mouse
            && self.argument[1] == Some(SET_RATE)
            && let Some(s) = &mut self.synaptics
        {
            let records = if data == 0x28 {
                core::mem::take(&mut s.before_client_ack)
            } else if data == 0x14 {
                core::mem::take(&mut s.before_mode_ack)
            } else {
                Vec::new()
            };
            for record in records {
                for byte in record {
                    self.emit(port, byte);
                }
            }
        }
        if port == Port::Mouse
            && data == DISABLE_REPORTING
            && self.scanning[1]
            && let Some(s) = &mut self.synaptics
        {
            for byte in core::mem::take(&mut s.before_disable) {
                self.emit(port, byte);
            }
        }
        if let Some((p, b, ref mut attempts)) = self.resend
            && p == port
            && b == data
            && *attempts != 0
        {
            *attempts -= 1;
            let last = *attempts == 0;
            self.emit(port, RESEND);
            if last {
                for (port, byte) in core::mem::take(&mut self.resend_inject) {
                    self.emit(port, byte);
                }
            }
            return;
        }
        if port == Port::Keyboard && data == SET_LEDS && self.argument[0].is_none() {
            for (p, b) in core::mem::take(&mut self.inject_led) {
                self.emit(p, b);
            }
        }
        if port == Port::Mouse
            && self.argument[1].is_none()
            && let Some(action) = self.elantech.as_mut().and_then(|e| e.command(data))
        {
            if self.no_ack != Some((port, data)) {
                if action.late_ack {
                    self.delay_at_read
                        .insert(self.consumed + self.output.len() + 1, 101);
                }
                self.emit(port, ACK);
            }
            for (index, byte) in action.reply.iter().enumerate() {
                if action.late_byte == Some(index) {
                    self.delay_at_read
                        .insert(self.consumed + self.output.len() + 1, 101);
                }
                self.emit(port, *byte);
            }
            return;
        }
        let index = Self::index(port);
        if !(data == GET_ID && port == Port::Mouse && self.no_id_ack)
            && self.no_ack != Some((port, data))
        {
            self.emit(port, ACK);
        }
        if let Some(command) = self.argument[index].take() {
            match command {
                SET_SCAN if data == 0 => self.emit(port, self.scan),
                SET_SCAN => self.scan = data,
                SET_LEDS => self.leds = data,
                SET_RATE if port == Port::Mouse => {
                    if let Some(s) = &mut self.synaptics {
                        if data == 0x14 {
                            s.mode = Some(s.sliced);
                            if s.sliced == 0 {
                                s.advanced = false;
                                if s.busy_after_mode_zero {
                                    self.busy_forever = true;
                                }
                            }
                            if s.late_mode_ack {
                                s.read_delay_us = 101;
                            }
                        } else if data == 0x28 {
                            assert_ne!(s.queries[&2][2] & 0x80, 0);
                            s.client_writes.push(s.sliced);
                            if s.late_client_ack {
                                s.read_delay_us = 101;
                            }
                            let replies = s
                                .child
                                .as_mut()
                                .map_or_else(Vec::new, |c| c.write(s.sliced));
                            let late = s
                                .child
                                .as_ref()
                                .is_some_and(|c| c.late_response == Some(s.sliced));
                            let delay = if s.sliced == RESET { 201 } else { 101 };
                            let before_ack = s
                                .child
                                .as_ref()
                                .is_some_and(|c| c.replies_before_parent_ack);
                            let mut selected = Vec::new();
                            if let Some(child) = s.child.as_mut() {
                                for byte in replies {
                                    child.reply_number += 1;
                                    if child.omit_reply != Some(child.reply_number) {
                                        selected.push((
                                            byte,
                                            late || child.late_reply == Some(child.reply_number),
                                        ));
                                    }
                                }
                            }
                            let parent_ack = if before_ack {
                                self.output.pop_back()
                            } else {
                                None
                            };
                            if before_ack {
                                assert_eq!(parent_ack, Some((Port::Mouse, ACK, 0)));
                            }
                            for (byte, late) in selected {
                                if late {
                                    self.delay_at_read
                                        .insert(self.consumed + self.output.len() + 6, delay);
                                }
                                for field in [0x84, byte, 0, 0xc4, 0, 0] {
                                    self.emit(port, field);
                                }
                            }
                            if let Some(parent_ack) = parent_ack {
                                self.delay_at_read
                                    .insert(self.consumed + self.output.len() + 1, 1);
                                self.output.push_back(parent_ack);
                            }
                        } else {
                            assert_eq!(data, 0xc8);
                            assert_eq!(s.sliced, 3);
                            s.advanced = true;
                            if s.late_advanced_ack {
                                s.read_delay_us = 101;
                            }
                        }
                        return;
                    }
                    self.rates.push(data);
                    if self.wheel_capable && self.rates.ends_with(&[200, 100, 80]) {
                        self.mouse_id = 3;
                    }
                    if self.explorer_capable && self.rates.ends_with(&[200, 200, 80]) {
                        self.mouse_id = 4;
                    }
                }
                SET_RESOLUTION if port == Port::Mouse && self.synaptics.is_some() => {
                    let s = self.synaptics.as_mut().unwrap();
                    assert!(data < 4);
                    s.sliced = (s.sliced << 2) | data;
                }
                SET_RATE | SET_RESOLUTION => {}
                _ => panic!("model unknown argument command"),
            }
            return;
        }
        match data {
            RESET => {
                if let Some(s) = &mut self.synaptics {
                    s.mode = None;
                    s.advanced = false;
                }
                self.argument[index] = None;
                self.scanning[index] = false;
                if port == Port::Keyboard {
                    self.scan = 2;
                }
                self.emit(port, BAT_OK);
                if port == Port::Mouse {
                    self.mouse_id = 0;
                    self.emit(port, 0);
                }
            }
            DISABLE_REPORTING | DEFAULTS => {
                self.scanning[index] = false;
            }
            ENABLE_REPORTING => {
                self.scanning[index] = true;
            }
            SET_SCAN | SET_RATE | SET_LEDS | SET_RESOLUTION => self.argument[index] = Some(data),
            SCALE_ONE_TO_ONE => {
                if let Some(s) = &mut self.synaptics {
                    s.sliced = 0;
                }
            }
            0xe9 if port == Port::Mouse && self.synaptics.is_some() => {
                let s = self.synaptics.as_mut().unwrap();
                s.queried.push(s.sliced);
                s.query_reads_left = 4;
                let reply = *s
                    .queries
                    .get(&s.sliced)
                    .expect("actual query supported by peripheral");
                let take = s
                    .omit
                    .filter(|(id, _)| *id == s.sliced)
                    .map_or(3, |(_, count)| count);
                for &byte in &reply[..take] {
                    self.emit(port, byte);
                }
            }
            GET_ID if port == Port::Mouse => {
                self.emit(port, self.force_id.unwrap_or(self.mouse_id))
            }
            _ => panic!("unknown device command {data:x}"),
        }
    }
}
impl Registers for Model {
    fn status(&mut self) -> u8 {
        let h = self.0.borrow();
        h.time.set(h.time.get().wrapping_add(h.status_delay_us));
        let mut value = if h.input_busy() { INPUT_FULL } else { 0 };
        if let Some((port, _, error)) = h.output.front() {
            value |= OUTPUT_FULL | *error;
            if *port == Port::Mouse {
                value |= AUX_DATA;
            }
        } else if h.flood {
            value |= OUTPUT_FULL;
        }
        value
    }
    fn read_data(&mut self) -> u8 {
        let mut h = self.0.borrow_mut();
        h.consumed += 1;
        let consumed = h.consumed;
        if let Some(delay) = h.delay_at_read.remove(&consumed) {
            h.time.set(h.time.get().wrapping_add(delay));
        }
        match h.output.pop_front() {
            Some((port, data, _)) => {
                if port == Port::Mouse {
                    let mut delay = 0;
                    if let Some(s) = &mut h.synaptics {
                        delay = s.read_delay_us;
                        if s.query_reads_left != 0 {
                            if s.late_query_byte.is_some_and(|(id, index)| {
                                id == s.sliced && usize::from(s.query_reads_left) == 3 - index
                            }) {
                                delay = 101;
                            }
                            s.query_reads_left -= 1;
                        }
                    }
                    h.time.set(h.time.get().wrapping_add(delay));
                }
                data
            }
            None if h.flood => 0,
            None => panic!("read empty output"),
        }
    }
    fn write_command(&mut self, value: u8) {
        let mut h = self.0.borrow_mut();
        assert!(!h.input_busy(), "write with IBF set");
        h.busy_until = Some(h.time.get().wrapping_add(1));
        h.writes.push((true, value));
        match value {
            READ_CONFIG => {
                assert!(
                    h.config & KEYBOARD_DISABLED != 0 || !h.scanning[0],
                    "CTR reply lane is not owned while a keyboard can report"
                );
                let config = h.config;
                h.emit(Port::Keyboard, config);
            }
            WRITE_CONFIG => h.config_write = true,
            SELF_TEST => {
                let reply = h.self_test;
                h.config = TRANSLATION | IRQ_BITS;
                h.emit(Port::Keyboard, reply);
                for byte in core::mem::take(&mut h.after_self_test) {
                    h.emit(Port::Keyboard, byte);
                }
            }
            TEST_KEYBOARD | TEST_MOUSE => {
                let reply = h.interface_test;
                h.emit(Port::Keyboard, reply);
            }
            DISABLE_KEYBOARD => h.config |= KEYBOARD_DISABLED,
            DISABLE_MOUSE => h.config |= MOUSE_DISABLED,
            ENABLE_KEYBOARD => {
                h.config &= !KEYBOARD_DISABLED;
                if h.scanning[0] {
                    for byte in core::mem::take(&mut h.keyboard_on_enable) {
                        h.emit(Port::Keyboard, byte);
                    }
                }
            }
            ENABLE_MOUSE => h.config &= !MOUSE_DISABLED,
            SEND_MOUSE => h.mouse_write = true,
            _ => panic!("unknown controller command {value:x}"),
        }
    }
    fn write_data(&mut self, value: u8) {
        let mut h = self.0.borrow_mut();
        assert!(!h.input_busy(), "write with IBF set");
        h.busy_until = Some(h.time.get().wrapping_add(1));
        h.writes.push((false, value));
        if h.config_write {
            h.config_write = false;
            h.config = value | if h.translation_stuck { TRANSLATION } else { 0 };
        } else {
            let port = if core::mem::take(&mut h.mouse_write) {
                Port::Mouse
            } else {
                Port::Keyboard
            };
            let bit = if port == Port::Mouse {
                MOUSE_DISABLED
            } else {
                KEYBOARD_DISABLED
            };
            assert_eq!(h.config & bit, 0, "device command while clock disabled");
            assert_eq!(
                h.config & (IRQ_BITS | TRANSLATION),
                0,
                "IRQs/translation must be disabled"
            );
            h.device(port, value);
        }
    }
}
struct Time(Rc<Cell<u64>>);
impl Timer for Time {
    fn start(&self) -> u64 {
        !self.now_us().rotate_left(17)
    }
    fn elapsed_us(&self, marker: u64) -> u64 {
        self.now_us().wrapping_sub((!marker).rotate_right(17))
    }
    fn now_us(&self) -> u64 {
        self.0.get()
    }
    fn relax(&self) {
        self.0.set(self.0.get().wrapping_add(1));
    }
}
fn controller(config: Config) -> (Controller<Model, Time>, Rc<RefCell<Hardware>>) {
    let time = Rc::new(Cell::new(0));
    let h = Rc::new(RefCell::new(Hardware::new(time.clone())));
    let mut config = config;
    config.io_timeout_us = 50;
    config.command_timeout_us = 100;
    config.reset_timeout_us = 200;
    config.packet_timeout_us = 500;
    (
        Controller::new(Model(h.clone()), Time(time), config).unwrap(),
        h,
    )
}
fn ready() -> (Controller<Model, Time>, Rc<RefCell<Hardware>>) {
    let (mut c, h) = controller(Config::default());
    c.initialize().unwrap();
    (c, h)
}
fn emit(h: &Rc<RefCell<Hardware>>, port: Port, data: &[u8]) {
    for &byte in data {
        h.borrow_mut().emit(port, byte);
    }
}

#[test]
fn real_initialization_negotiates_devices_and_survives_controller_test_reset() {
    for (keyboard, mouse, wheel_capable) in [
        (true, true, true),
        (true, false, false),
        (false, true, true),
        (false, true, false),
    ] {
        let (mut c, h) = controller(Config {
            keyboard,
            mouse,
            ..Config::default()
        });
        h.borrow_mut().wheel_capable = wheel_capable;
        c.initialize().unwrap();
        assert!(c.is_ready());
        assert_eq!(c.has_wheel(), mouse && wheel_capable);
        assert_eq!(h.borrow().config & (IRQ_BITS | TRANSLATION), 0);
        // Unselected devices remain clock-inhibited; their pre-handoff
        // reporting state is not rewritten by this owner.
        assert_eq!(h.borrow().scanning, [true, true]);
        assert_eq!(h.borrow().config & KEYBOARD_DISABLED != 0, !keyboard);
        assert_eq!(h.borrow().config & MOUSE_DISABLED != 0, !mouse);
        assert_eq!(h.borrow().scan, 2);
        assert!(h.borrow().output.is_empty());
        c.stop().unwrap();
        assert_eq!(h.borrow().scanning, [!keyboard, !mouse]);
        assert_eq!(
            h.borrow().config & (KEYBOARD_DISABLED | MOUSE_DISABLED),
            KEYBOARD_DISABLED | MOUSE_DISABLED
        );
        c.initialize().unwrap();
        // Unselected devices remain clock-inhibited; their pre-handoff
        // reporting state is not rewritten by this owner.
        assert_eq!(h.borrow().scanning, [true, true]);
    }
}

#[test]
fn keyboard_make_break_repeat_extended_printscreen_pause_and_led_commands() {
    let (mut c, h) = ready();
    emit(
        &h,
        Port::Keyboard,
        &[
            0x1c, 0x1c, 0xf0, 0x1c, 0xe0, 0x14, 0xe0, 0xf0, 0x14, 0xe0, 0x12, 0xe0, 0x7c, 0xe0,
            0xf0, 0x7c, 0xe0, 0xf0, 0x12, 0xe1, 0x14, 0x77, 0xe1, 0xf0, 0x14, 0xf0, 0x77, 0x83,
            0xf0, 0x83,
        ],
    );
    let key = |usage, pressed| Input::Key { usage, pressed };
    assert_eq!(
        c.poll().unwrap(),
        vec![
            key(4, true),
            key(4, false),
            key(0xe4, true),
            key(0xe4, false),
            key(0x46, true),
            key(0x46, false),
            key(0x48, true),
            key(0x48, false),
            key(0x40, true),
            key(0x40, false)
        ]
    );
    c.set_leds(7).unwrap();
    assert_eq!(h.borrow().leds, 7);
    let writes = h.borrow().writes.len();
    assert_eq!(
        c.set_leds(8).unwrap_err().kind,
        ErrorKind::InvalidConfiguration
    );
    assert_eq!(h.borrow().writes.len(), writes);
}

#[test]
fn interleaved_ports_and_same_port_data_are_retained_during_led_ack() {
    let (mut c, h) = ready();
    h.borrow_mut().inject_led = vec![
        (Port::Keyboard, 0x1c),
        (Port::Mouse, 0x09),
        (Port::Mouse, 2),
        (Port::Mouse, 3),
        (Port::Mouse, 0),
    ];
    c.set_leds(3).unwrap();
    assert_eq!(
        c.poll().unwrap(),
        vec![
            Input::Key {
                usage: 4,
                pressed: true
            },
            Input::MouseButtons(1),
            Input::Motion { dx: 2, dy: -3 }
        ]
    );
    assert_eq!(h.borrow().leds, 3);
    assert_eq!(
        c.stop().unwrap(),
        vec![
            Input::Key {
                usage: 4,
                pressed: false
            },
            Input::MouseButtons(0)
        ]
    );
}

#[test]
fn ordinary_and_wheel_mouse_packets_preserve_nine_bit_motion_and_all_detents() {
    for wheel in [false, true] {
        let (mut c, h) = controller(Config {
            wheel,
            ..Config::default()
        });
        c.initialize().unwrap();
        let packet = if wheel {
            vec![0x39, 0xff, 0xff, 0x80]
        } else {
            vec![0x39, 0xff, 0xff]
        };
        emit(&h, Port::Mouse, &packet);
        let mut expected = vec![Input::MouseButtons(1), Input::Motion { dx: -1, dy: 1 }];
        if wheel {
            expected.extend([Input::MouseWheel(127), Input::MouseWheel(1)]);
        }
        assert_eq!(c.poll().unwrap(), expected);
        let packet = if wheel {
            vec![0x38, 0, 0, 1]
        } else {
            vec![0x38, 0, 0]
        };
        emit(&h, Port::Mouse, &packet);
        let mut expected = vec![Input::MouseButtons(0)];
        if wheel {
            expected.push(Input::MouseWheel(-1));
        }
        assert_eq!(c.poll().unwrap(), expected);
    }
}

#[test]
fn one_resend_retries_only_the_rejected_byte_but_exhaustion_quarantines() {
    let (mut c, h) = controller(Config::default());
    h.borrow_mut().resend = Some((Port::Keyboard, SET_SCAN, 1));
    c.initialize().unwrap();
    assert!(c.is_ready());
    h.borrow_mut().resend = Some((Port::Keyboard, SET_LEDS, 2));
    let error = c.set_leds(2).unwrap_err();
    assert_eq!(
        error.kind,
        ErrorKind::ResendLimit {
            port: Port::Keyboard,
            byte: SET_LEDS
        }
    );
    assert_eq!(error.recovery, Recovery::PortsDisabled);
    assert!(c.needs_reset());
    let writes = h.borrow().writes.len();
    assert_eq!(c.initialize().unwrap_err().kind, ErrorKind::NeedsReset);
    assert_eq!(c.set_leds(1).unwrap_err().kind, ErrorKind::NeedsReset);
    assert_eq!(h.borrow().writes.len(), writes);
}

#[test]
fn unacknowledged_command_never_publishes_ready_and_never_replays_automatically() {
    let (mut c, h) = controller(Config::default());
    h.borrow_mut().no_ack = Some((Port::Mouse, ENABLE_REPORTING));
    let error = c.initialize().unwrap_err();
    assert_eq!(error.kind, ErrorKind::Timeout(Phase::Response));
    assert_eq!(error.recovery, Recovery::PortsDisabled);
    assert!(!c.is_ready());
    assert!(c.needs_reset());
    let count = h
        .borrow()
        .writes
        .iter()
        .filter(|&&(command, byte)| !command && byte == ENABLE_REPORTING)
        .count();
    assert_eq!(count, 1);
    assert!(h.borrow().time.get() < 1000);
}

#[test]
fn unsupported_interface_or_controller_state_is_read_back_and_refused() {
    for mode in 0..4 {
        let (mut c, h) = controller(Config::default());
        match mode {
            0 => h.borrow_mut().self_test = 0xfc,
            1 => h.borrow_mut().interface_test = 1,
            2 => h.borrow_mut().translation_stuck = true,
            _ => h.borrow_mut().force_id = Some(5),
        }
        let error = c.initialize().unwrap_err();
        assert!(matches!(
            error.kind,
            ErrorKind::ControllerReply { .. } | ErrorKind::UnsupportedMouseId(5)
        ));
        assert!(!c.is_ready());
        assert!(c.needs_reset());
    }
}

#[test]
fn omitted_getid_ack_is_supported_without_confusing_regular_data() {
    let (mut c, h) = controller(Config::default());
    h.borrow_mut().no_id_ack = true;
    c.initialize().unwrap();
    assert!(c.has_wheel());
    assert!(h.borrow().output.is_empty());
}

#[test]
fn busy_controller_and_unbounded_stale_output_have_bounded_failures() {
    let (mut c, h) = controller(Config::default());
    h.borrow_mut().busy_forever = true;
    let error = c.initialize().unwrap_err();
    assert_eq!(error.kind, ErrorKind::Timeout(Phase::InputReady));
    assert_eq!(error.recovery, Recovery::Failed);
    assert!(h.borrow().writes.is_empty());
    assert!(h.borrow().time.get() <= 100);
    let (mut c, h) = controller(Config::default());
    h.borrow_mut().flood = true;
    assert_eq!(
        c.initialize().unwrap_err().kind,
        ErrorKind::Timeout(Phase::Drain)
    );
    // Initial draining and the independently bounded quiesce attempt each
    // consume at most one queue's worth; neither spins on perpetual OBF.
    assert!(h.borrow().consumed <= 2 * QUEUE_LIMIT);
    assert!(h.borrow().time.get() < 200);
}

#[test]
fn framed_input_error_retains_prior_events_and_requires_actual_owner_reset() {
    let (mut c, h) = ready();
    emit(&h, Port::Keyboard, &[0x1c]);
    h.borrow_mut().output.push_back((Port::Mouse, 0x08, 0x80));
    assert!(matches!(
        c.poll().unwrap_err().kind,
        ErrorKind::Frame {
            port: Port::Mouse,
            ..
        }
    ));
    assert_eq!(
        c.drain_events(),
        vec![Input::Key {
            usage: 4,
            pressed: true
        }]
    );
    assert_eq!(
        c.release_inputs(),
        vec![Input::Key {
            usage: 4,
            pressed: false
        }]
    );
    assert!(c.needs_reset());
}

#[test]
fn truncated_frames_and_spontaneous_device_reset_never_emit_invented_input() {
    for port in [Port::Keyboard, Port::Mouse] {
        let (mut c, h) = ready();
        emit(
            &h,
            port,
            if port == Port::Keyboard {
                &[0xe0]
            } else {
                &[0x08]
            },
        );
        assert!(c.poll().unwrap().is_empty());
        let time = h.borrow().time.clone();
        time.set(time.get() + 500);
        emit(&h, port, &[0x1c]);
        assert_eq!(c.poll().unwrap_err().kind, ErrorKind::PacketTimeout(port));
        assert!(c.drain_events().is_empty());
    }
    let (mut c, h) = ready();
    emit(&h, Port::Mouse, &[0xaa, 0]);
    assert_eq!(
        c.poll().unwrap_err().kind,
        ErrorKind::DeviceReset(Port::Mouse)
    );
    assert!(c.drain_events().is_empty());
}

#[test]
fn unsupported_keys_are_explicit_and_known_keys_can_continue() {
    let (mut c, h) = ready();
    emit(&h, Port::Keyboard, &[0x1c, 0xe0, 0x10, 0xf0, 0x1c]);
    assert!(matches!(
        c.poll().unwrap_err().kind,
        ErrorKind::UnsupportedScanCode(_)
    ));
    assert!(c.is_ready());
    assert_eq!(
        c.poll().unwrap(),
        vec![
            Input::Key {
                usage: 4,
                pressed: true
            },
            Input::Key {
                usage: 4,
                pressed: false
            }
        ]
    );
}

#[test]
fn pending_input_queue_is_bounded_and_preserves_the_supported_capacity() {
    let (mut c, h) = ready();
    h.borrow_mut().inject_led = vec![(Port::Keyboard, 0x1c); QUEUE_LIMIT];
    c.set_leds(1).unwrap();
    assert_eq!(
        c.poll().unwrap(),
        vec![Input::Key {
            usage: 4,
            pressed: true
        }]
    );
    h.borrow_mut().inject_led = vec![(Port::Keyboard, 0x32); QUEUE_LIMIT + 1];
    assert_eq!(c.set_leds(2).unwrap_err().kind, ErrorKind::QueueFull);
    assert!(c.needs_reset());
}

#[test]
fn stop_delivers_pending_input_before_releasing_and_ready_init_never_takes_over() {
    let (mut c, h) = ready();
    let writes = h.borrow().writes.len();
    assert_eq!(
        c.initialize().unwrap_err().kind,
        ErrorKind::AlreadyInitialized
    );
    assert_eq!(h.borrow().writes.len(), writes);
    h.borrow_mut().inject_led = vec![
        (Port::Keyboard, 0x1c),
        (Port::Keyboard, 0xf0),
        (Port::Keyboard, 0x1c),
    ];
    c.set_leds(1).unwrap();
    assert_eq!(
        c.stop().unwrap(),
        vec![
            Input::Key {
                usage: 4,
                pressed: true
            },
            Input::Key {
                usage: 4,
                pressed: false
            }
        ]
    );
    assert!(!c.is_ready());
    assert!(!c.needs_reset());
}

#[test]
fn rejected_led_argument_retries_only_that_argument() {
    let (mut c, h) = ready();
    let start = h.borrow().writes.len();
    h.borrow_mut().resend = Some((Port::Keyboard, 3, 1));
    c.set_leds(3).unwrap();
    assert_eq!(h.borrow().leds, 3);
    let data: Vec<u8> = h.borrow().writes[start..]
        .iter()
        .filter_map(|&(command, byte)| (!command).then_some(byte))
        .collect();
    assert_eq!(data, vec![SET_LEDS, 3, 3]);
}

#[test]
fn already_reporting_keyboard_cannot_alias_ctr_or_publish_old_scan_set_bytes() {
    let (mut c, h) = controller(Config::default());
    // Review regression: if make 0x0c aliases enabled CTR, real SYSF CTR0x04
    // would later decode as a phantom set2 F3 press. These are old unknown-mode
    // bytes; only acknowledged disable/reset establishes new input provenance.
    h.borrow_mut().config = 0x47;
    h.borrow_mut().keyboard_on_enable = vec![0x0c, 0x1e, 0xe0, 0xf0];
    h.borrow_mut().after_self_test = vec![0x0c];
    c.initialize().unwrap();
    assert_eq!(h.borrow().config, 4);
    assert!(c.poll().unwrap().is_empty());
    assert_eq!(c.discarded_before_start(), 5);
    // The first actually owned set2 input still decodes with fresh framing.
    emit(&h, Port::Keyboard, &[0x1c, 0xf0, 0x1c]);
    assert_eq!(
        c.poll().unwrap(),
        vec![
            Input::Key {
                usage: 4,
                pressed: true
            },
            Input::Key {
                usage: 4,
                pressed: false
            }
        ]
    );
}

#[test]
fn silent_partial_frames_expire_without_waiting_for_a_later_byte() {
    for (port, bytes) in [(Port::Keyboard, vec![0xe0]), (Port::Mouse, vec![0x08, 1])] {
        let (mut c, h) = ready();
        emit(&h, port, &bytes);
        assert!(c.poll().unwrap().is_empty());
        let time = h.borrow().time.clone();
        time.set(time.get() + 500);
        assert_eq!(c.poll().unwrap_err().kind, ErrorKind::PacketTimeout(port));
        assert!(c.needs_reset());
        assert!(c.drain_events().is_empty());
    }
}

#[test]
fn idle_expiration_does_not_preempt_a_complete_retained_frame() {
    let (mut c, h) = ready();
    h.borrow_mut().inject_led = vec![
        (Port::Keyboard, 0xe0),
        (Port::Keyboard, 0x14),
        (Port::Mouse, 0x08),
        (Port::Mouse, 1),
        (Port::Mouse, 2),
        (Port::Mouse, 0),
    ];
    c.set_leds(1).unwrap();
    let time = h.borrow().time.clone();
    time.set(time.get() + 500);
    assert_eq!(
        c.poll().unwrap(),
        vec![
            Input::Key {
                usage: 0xe4,
                pressed: true
            },
            Input::Motion { dx: 1, dy: -2 }
        ]
    );
}

#[test]
fn explorer_negotiates_both_actual_ids_and_retains_five_buttons_and_wheel() {
    for no_ack in [false, true] {
        let (mut c, h) = controller(Config::default());
        h.borrow_mut().explorer_capable = true;
        h.borrow_mut().no_id_ack = no_ack;
        c.initialize().unwrap();
        assert_eq!(c.mouse_protocol(), Some(MouseProtocol::Explorer));
        assert_eq!(h.borrow().rates, vec![200, 100, 80, 200, 200, 80, 100]);
        assert!(c.has_wheel());
        emit(&h, Port::Mouse, &[0x0f, 2, 3, 0x38]);
        assert_eq!(
            c.poll().unwrap(),
            vec![
                Input::MouseButtons(31),
                Input::Motion { dx: 2, dy: -3 },
                Input::MouseWheel(8)
            ]
        );
        assert_eq!(c.stop().unwrap(), vec![Input::MouseButtons(0)]);
    }
}

#[test]
fn explorer_all_wheel_nibbles_and_extra_button_bits_match_source_conversion() {
    for mode in [0, 0xc0] {
        for bits in [0, 0x10, 0x20, 0x30] {
            let (mut c, h) = controller(Config::default());
            h.borrow_mut().explorer_capable = true;
            c.initialize().unwrap();
            for raw in 0..16 {
                emit(&h, Port::Mouse, &[0x08, 0, 0, mode | bits | raw]);
                let events = c.poll().unwrap();
                let wheel = events
                    .iter()
                    .filter_map(|e| {
                        if let Input::MouseWheel(v) = e {
                            Some(i16::from(*v))
                        } else {
                            None
                        }
                    })
                    .sum::<i16>();
                let signed = if raw < 8 {
                    i16::from(raw)
                } else {
                    i16::from(raw) - 16
                };
                assert_eq!(wheel, -signed);
                if raw == 0 && bits != 0 {
                    assert_eq!(events, vec![Input::MouseButtons(bits >> 1)]);
                }
            }
        }
    }
}

#[test]
fn unnegotiated_explorer_enhanced_modes_never_masquerade_as_vertical_input() {
    for byte in [0x40, 0x80] {
        let (mut c, h) = controller(Config::default());
        h.borrow_mut().explorer_capable = true;
        c.initialize().unwrap();
        emit(&h, Port::Mouse, &[0x0f, 1, 2, byte]);
        assert_eq!(c.poll().unwrap_err().kind, ErrorKind::MousePacketMode(byte));
        assert!(c.needs_reset());
        assert!(c.drain_events().is_empty());
    }
}
