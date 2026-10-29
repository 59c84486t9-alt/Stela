use super::*;
use alloc::vec;

const VERSION: u64 = stela_formats::builds::DEFAULT.rtkit_version;

#[test]
fn a_physical_reset_clears_enumeration_without_reusing_boot_quiescence() {
    let mut kit = RtKit::new(
        vec![(0x20, Box::new(super::super::pmp::Pmp::default()))],
        stela_formats::builds::DEFAULT.rtkit_version,
    )
    .unwrap()
    .quiesced();
    let mut output = Vec::new();
    kit.start(&mut output).unwrap();
    assert!(output.is_empty());
    kit.check_reset().unwrap();
    kit.reset().unwrap();
    assert!(output.is_empty());
    kit.start(&mut output).unwrap();
    assert_eq!(output, [management(HELLO, VERSION | VERSION << 16)]);
    assert!(step(&mut kit, 0x20, 2 << 52).is_err());
    mgmt(&mut kit, HELLO_REPLY, VERSION | VERSION << 16).unwrap();
    mgmt(&mut kit, ROLL_CALL, 1).unwrap();
    mgmt(&mut kit, ROLL_CALL, ROLL_CALL_LAST | 1 << 32).unwrap();
    mgmt(&mut kit, ENDPOINT_CONTROL, 0x20 << 32 | ENABLE).unwrap();
    assert_eq!(
        step(&mut kit, 0x20, 2 << 52 | 123).unwrap()[0].payload,
        0x21 << 48 | 123
    );
}

/// Answers every payload with its complement.
struct Complement;
impl Endpoint for Complement {
    fn start(&mut self, outbox: &mut Vec<u64>) -> Result<(), &'static str> {
        outbox.push(0x5);
        Ok(())
    }
    fn receive(&mut self, payload: u64, outbox: &mut Vec<u64>) -> Result<(), &'static str> {
        outbox.push(!payload);
        Ok(())
    }
}

fn step(rtkit: &mut RtKit, endpoint: u8, payload: u64) -> Result<Vec<Message>, &'static str> {
    let mut outbox = Vec::new();
    rtkit.receive(Message { endpoint, payload }, &mut outbox)?;
    Ok(outbox)
}

fn mgmt(rtkit: &mut RtKit, kind: u64, fields: u64) -> Result<Vec<Message>, &'static str> {
    step(rtkit, 0, management(kind, fields).payload)
}

fn booted() -> RtKit {
    let mut rtkit = RtKit::new(
        vec![
            (0x20, Box::new(Complement) as Box<dyn Endpoint>),
            (0x41, Box::new(Complement)),
        ],
        stela_formats::builds::DEFAULT.rtkit_version,
    )
    .unwrap();
    let mut outbox = Vec::new();
    rtkit.start(&mut outbox).unwrap();
    assert_eq!(outbox, vec![management(HELLO, 12 | 12 << 16)]);
    rtkit
}

#[test]
fn cold_system_binding_keeps_the_started_session_and_precedes_roll_call() {
    let mut kit = RtKit::new(Vec::new(), stela_formats::builds::DEFAULT.rtkit_version).unwrap();
    let mut initial = Vec::new();
    kit.start(&mut initial).unwrap();
    kit.attach_cold_system_endpoints(SystemEndpoints {
        trace: Some(Box::new(Complement)),
        reporting: Some(Box::new(Complement)),
    })
    .unwrap();
    assert_eq!(initial, vec![management(HELLO, VERSION | VERSION << 16)]);
    assert_eq!(
        mgmt(&mut kit, HELLO_REPLY, VERSION | VERSION << 16).unwrap(),
        vec![management(
            ROLL_CALL,
            ROLL_CALL_LAST | 3 | 1 << KDEBUG | 1 << IOREPORTING,
        )]
    );
    mgmt(&mut kit, ROLL_CALL, ROLL_CALL_LAST).unwrap();
    assert!(
        kit.attach_cold_system_endpoints(SystemEndpoints::default())
            .is_err()
    );
    assert!(step(&mut kit, IOREPORTING, 7).is_err());
}

#[test]
fn late_or_duplicate_native_binding_refuses_before_changing_the_endpoint_map() {
    let mut kit = RtKit::new(Vec::new(), stela_formats::builds::DEFAULT.rtkit_version).unwrap();
    let mut initial = Vec::new();
    kit.start(&mut initial).unwrap();
    mgmt(&mut kit, HELLO_REPLY, VERSION | VERSION << 16).unwrap();
    assert!(
        kit.attach_cold_system_endpoints(SystemEndpoints {
            trace: Some(Box::new(Complement)),
            reporting: Some(Box::new(Complement)),
        })
        .is_err()
    );
    assert_eq!(kit.bitmap(0), 3);
    let mut kit = RtKit::with_system_endpoints(
        Vec::new(),
        SystemEndpoints {
            trace: Some(Box::new(Complement)),
            reporting: None,
        },
        stela_formats::builds::DEFAULT.rtkit_version,
    )
    .unwrap();
    assert!(
        kit.attach_cold_system_endpoints(SystemEndpoints {
            trace: None,
            reporting: Some(Box::new(Complement)),
        })
        .is_err()
    );
    assert_eq!(kit.bitmap(0), 3 | 1 << KDEBUG);
}

#[test]
fn explicit_system_owners_enumerate_and_receive_on_their_own_session() {
    let mut kit = RtKit::with_system_endpoints(
        Vec::new(),
        SystemEndpoints {
            trace: Some(Box::new(Complement)),
            reporting: Some(Box::new(Complement)),
        },
        stela_formats::builds::DEFAULT.rtkit_version,
    )
    .unwrap();
    let mut output = Vec::new();
    kit.start(&mut output).unwrap();
    assert_eq!(
        mgmt(&mut kit, HELLO_REPLY, VERSION | VERSION << 16).unwrap(),
        vec![management(
            ROLL_CALL,
            ROLL_CALL_LAST | 3 | 1 << KDEBUG | 1 << IOREPORTING
        )]
    );
    mgmt(&mut kit, ROLL_CALL, ROLL_CALL_LAST).unwrap();
    assert!(step(&mut kit, KDEBUG, 7).is_err());
    assert!(step(&mut kit, IOREPORTING, 7).is_err());
    for number in [KDEBUG, IOREPORTING] {
        assert_eq!(
            mgmt(&mut kit, ENDPOINT_CONTROL, u64::from(number) << 32 | ENABLE).unwrap(),
            vec![Message {
                endpoint: number,
                payload: 5
            }]
        );
        assert_eq!(
            step(&mut kit, number, 7).unwrap(),
            vec![Message {
                endpoint: number,
                payload: !7
            }]
        );
    }
    mgmt(
        &mut kit,
        ENDPOINT_CONTROL,
        u64::from(KDEBUG) << 32 | DISABLE,
    )
    .unwrap();
    assert!(step(&mut kit, KDEBUG, 7).is_err());
    assert!(step(&mut kit, IOREPORTING, 7).is_ok());
    assert!(step(&mut kit, FIRST_APPLICATION, 7).is_err());
    // Existing callers cannot smuggle a system service into the ordinary
    // application constructor or replace the reserved crashlog owner.
    assert!(
        RtKit::new(
            vec![(IOREPORTING, Box::new(Complement))],
            stela_formats::builds::DEFAULT.rtkit_version
        )
        .is_err()
    );
}

#[test]
fn the_coprocessor_says_hello_rolls_call_and_serves_its_endpoints() {
    let mut rtkit = booted();
    assert!(mgmt(&mut rtkit, HELLO_REPLY, 11 | 11 << 16).is_err());
    // Group 0 holds the management and crashlog endpoints.
    let call = mgmt(&mut rtkit, HELLO_REPLY, 1 << 32 | 12 | 12 << 16).unwrap();
    assert_eq!(call, vec![management(ROLL_CALL, 3)]);
    assert!(mgmt(&mut rtkit, ROLL_CALL, 1 << 32 | 1).is_err());
    // 0x20 is bit 0 of group 1, 0x41 bit 1 of group 2, the last.
    let call = mgmt(&mut rtkit, ROLL_CALL, 1).unwrap();
    assert_eq!(call, vec![management(ROLL_CALL, 1 << 32 | 1)]);
    let call = mgmt(&mut rtkit, ROLL_CALL, 1 << 32).unwrap();
    assert_eq!(
        call,
        vec![management(ROLL_CALL, ROLL_CALL_LAST | 2 << 32 | 2)]
    );
    assert!(step(&mut rtkit, 0x20, 1).is_err());
    assert_eq!(
        mgmt(&mut rtkit, ROLL_CALL, ROLL_CALL_LAST | 2 << 32).unwrap(),
        vec![management(IOP_POWER_ACK, POWER_ON)]
    );
    let started = mgmt(&mut rtkit, ENDPOINT_CONTROL, 0x20 << 32 | ENABLE).unwrap();
    assert_eq!(
        started,
        vec![Message {
            endpoint: 0x20,
            payload: 5
        }]
    );
    assert_eq!(
        step(&mut rtkit, 0x20, 0xf0).unwrap(),
        vec![Message {
            endpoint: 0x20,
            payload: !0xf0
        }]
    );
    assert!(step(&mut rtkit, 0x41, 1).is_err());
    assert!(
        mgmt(&mut rtkit, ENDPOINT_CONTROL, 0x20 << 32 | DISABLE)
            .unwrap()
            .is_empty()
    );
    assert!(step(&mut rtkit, 0x20, 1).is_err());
    assert!(mgmt(&mut rtkit, ENDPOINT_CONTROL, 0x21 << 32 | ENABLE).is_err());
    assert!(mgmt(&mut rtkit, ENDPOINT_CONTROL, 0x20 << 32 | 3).is_err());
}

#[test]
fn the_crashlog_endpoint_starts_silently_and_takes_no_ap_message() {
    let mut rtkit = booted();
    // Endpoint control before the roll call names anything refuses.
    assert!(mgmt(&mut rtkit, ENDPOINT_CONTROL, 1 << 32 | ENABLE).is_err());
    mgmt(&mut rtkit, HELLO_REPLY, 12 | 12 << 16).unwrap();
    // The AP starts the crashlog endpoint while answering group 0.
    assert!(
        mgmt(&mut rtkit, ENDPOINT_CONTROL, 1 << 32 | ENABLE)
            .unwrap()
            .is_empty()
    );
    mgmt(&mut rtkit, ROLL_CALL, 3).unwrap();
    mgmt(&mut rtkit, ROLL_CALL, 1 << 32).unwrap();
    mgmt(&mut rtkit, ROLL_CALL, ROLL_CALL_LAST | 2 << 32).unwrap();
    assert!(step(&mut rtkit, CRASHLOG, 1).is_err());
    // Enabling it requests no buffer; a buffer answer or any other AP
    // message refuses, enabled or not.
    let started = mgmt(&mut rtkit, ENDPOINT_CONTROL, 1 << 32 | ENABLE).unwrap();
    assert!(started.is_empty());
    let refusal = step(&mut rtkit, CRASHLOG, 0x1 << 52 | 0x8000).unwrap_err();
    assert!(refusal.contains("no buffer"), "{refusal}");
    assert!(mgmt(&mut rtkit, ENDPOINT_CONTROL, 1 << 32 | 3).is_err());
    assert!(
        mgmt(&mut rtkit, ENDPOINT_CONTROL, 1 << 32 | DISABLE)
            .unwrap()
            .is_empty()
    );
    // Other system endpoints stay absent.
    assert!(mgmt(&mut rtkit, ENDPOINT_CONTROL, 2 << 32 | ENABLE).is_err());
}

#[test]
fn power_pings_and_naps_are_answered_as_the_ap_expects() {
    let mut rtkit = booted();
    mgmt(&mut rtkit, HELLO_REPLY, 12 | 12 << 16).unwrap();
    mgmt(&mut rtkit, ROLL_CALL, 1).unwrap();
    mgmt(&mut rtkit, ROLL_CALL, 1 << 32).unwrap();
    // An ordinarily managed IOP announces power-on.
    assert_eq!(
        mgmt(&mut rtkit, ROLL_CALL, ROLL_CALL_LAST | 2 << 32 | 1).unwrap(),
        vec![management(IOP_POWER_ACK, POWER_ON)]
    );
    assert_eq!(
        mgmt(&mut rtkit, IOP_POWER, 0x220).unwrap(),
        vec![management(IOP_POWER_ACK, 0x220)]
    );
    assert_eq!(
        mgmt(&mut rtkit, AP_POWER, 0x201).unwrap(),
        vec![management(AP_POWER, 0x201)]
    );
    assert_eq!(
        mgmt(&mut rtkit, PING, 0x1234 << 32 | 21).unwrap(),
        vec![management(PING_ACK, 21)]
    );
    assert!(mgmt(&mut rtkit, POWER_NAP, 1).unwrap().is_empty());
    assert!(mgmt(&mut rtkit, IOP_POWER, 0x10).is_err());
    assert!(mgmt(&mut rtkit, AP_POWER, 0x202).is_err());
    assert!(mgmt(&mut rtkit, POWER_NAP, 2).is_err());
    assert!(mgmt(&mut rtkit, 0xf, 0).is_err());
}

#[test]
fn kept_cpu_halt_requires_sleep_and_resumes_without_enumeration() {
    for sleep in [0x201, 0x202] {
        let mut rtkit = booted();
        assert!(rtkit.stop().is_err()); // Incomplete protocol start.
        mgmt(&mut rtkit, HELLO_REPLY, 12 | 12 << 16).unwrap();
        mgmt(&mut rtkit, ROLL_CALL, 1).unwrap();
        mgmt(&mut rtkit, ROLL_CALL, 1 << 32).unwrap();
        mgmt(&mut rtkit, ROLL_CALL, ROLL_CALL_LAST | 2 << 32).unwrap();
        mgmt(&mut rtkit, ENDPOINT_CONTROL, 0x20 << 32 | ENABLE).unwrap();
        assert!(rtkit.stop().is_err()); // Awake, not kept sleep.
        mgmt(&mut rtkit, IOP_POWER, 0).unwrap();
        assert!(rtkit.stop().is_err()); // Memory-loss power state.
        mgmt(&mut rtkit, IOP_POWER, sleep).unwrap();
        rtkit.stop().unwrap();
        assert_eq!(rtkit.iop_power(), sleep);
        assert!(step(&mut rtkit, 0x20, 7).is_err());
        assert!(mgmt(&mut rtkit, IOP_POWER, WAKE).is_err());
        assert!(rtkit.start(&mut Vec::new()).is_err());
        let mut out = Vec::new();
        rtkit.resume(&mut out).unwrap();
        assert_eq!(out, [management(IOP_POWER_ACK, POWER_ON)]);
        assert_eq!(rtkit.iop_power(), POWER_ON);
        assert_eq!(rtkit.stage, Stage::Ready);
        assert!(rtkit.resume(&mut out).is_err());
        assert_eq!(out, [management(IOP_POWER_ACK, POWER_ON)]);
        assert_eq!(
            mgmt(&mut rtkit, IOP_POWER, WAKE).unwrap(),
            vec![management(IOP_POWER_ACK, WAKE)]
        );
        // The endpoint remains enabled and its existing native state serves
        // another request without a new endpoint control or roll call.
        assert_eq!(step(&mut rtkit, 0x20, 7).unwrap()[0].payload, !7u64);
    }
}

#[test]
fn the_restore_boot_pmp_handshake_ends_with_the_power_on_announcement() {
    // The AP's side of restore boot s25's PMP mailbox log, word for
    // word: the AP waited 20 s for running after its last answer.
    let mut rtkit = RtKit::new(
        vec![(0x20, Box::new(Complement) as Box<dyn Endpoint>)],
        stela_formats::builds::DEFAULT.rtkit_version,
    )
    .unwrap();
    let raw = |rtkit: &mut RtKit, payload| step(rtkit, 0, payload).unwrap();
    let mut outbox = Vec::new();
    rtkit.start(&mut outbox).unwrap();
    let payloads = |messages: Vec<Message>| -> Vec<u64> {
        messages
            .iter()
            .inspect(|message| assert_eq!(message.endpoint, 0))
            .map(|message| message.payload)
            .collect()
    };
    assert_eq!(payloads(outbox), [0x0010_0000_000c_000c]);
    // Group 0 now also lists the crashlog endpoint (bit 1), which s25's
    // coprocessor did not; the AP's answers are unchanged.
    assert_eq!(
        payloads(raw(&mut rtkit, 0x0020_0000_000c_000c)),
        [0x0080_0000_0000_0003]
    );
    assert_eq!(
        payloads(raw(&mut rtkit, 0x0080_0000_0000_0001)),
        [0x0088_0001_0000_0001]
    );
    assert_eq!(
        payloads(raw(&mut rtkit, 0x0088_0001_0000_0000)),
        [0x0070_0000_0000_0020]
    );
    // The client driver's STARTEP of 0x20 starts the endpoint.
    assert_eq!(
        raw(&mut rtkit, 0x0050_0020_0000_0002),
        [Message {
            endpoint: 0x20,
            payload: 5
        }]
    );
}

#[test]
fn a_quiesced_coprocessor_waits_for_its_wake_and_acks_it_after_enumeration() {
    let mut rtkit = RtKit::new(
        vec![(0x20, Box::new(Complement) as Box<dyn Endpoint>)],
        stela_formats::builds::DEFAULT.rtkit_version,
    )
    .unwrap()
    .quiesced();
    let mut outbox = Vec::new();
    rtkit.start(&mut outbox).unwrap();
    assert!(outbox.is_empty());
    assert!(mgmt(&mut rtkit, AP_POWER, POWER_ON).is_err());
    assert!(mgmt(&mut rtkit, HELLO_REPLY, 12 | 12 << 16).is_err());
    assert_eq!(
        mgmt(&mut rtkit, IOP_POWER, WAKE).unwrap(),
        vec![management(HELLO, 12 | 12 << 16)]
    );
    mgmt(&mut rtkit, HELLO_REPLY, 12 | 12 << 16).unwrap();
    // No ack before the last group is answered.
    assert_eq!(
        mgmt(&mut rtkit, ROLL_CALL, 1).unwrap(),
        vec![management(ROLL_CALL, ROLL_CALL_LAST | 1 << 32 | 1)]
    );
    assert_eq!(
        mgmt(&mut rtkit, ROLL_CALL, ROLL_CALL_LAST | 1 << 32).unwrap(),
        vec![management(IOP_POWER_ACK, WAKE)]
    );
}

/// Sends `pending` on its own and restarts the machine on any message.
#[derive(Default)]
struct Board {
    pending: Vec<u64>,
    restart: bool,
}
impl Endpoint for Board {
    fn start(&mut self, _outbox: &mut Vec<u64>) -> Result<(), &'static str> {
        Ok(())
    }
    fn receive(&mut self, _payload: u64, _outbox: &mut Vec<u64>) -> Result<(), &'static str> {
        self.restart = true;
        Ok(())
    }
    fn poll(&mut self, outbox: &mut Vec<u64>) -> Result<(), &'static str> {
        outbox.append(&mut self.pending);
        Ok(())
    }
    fn take_transition(&mut self) -> Option<TransitionRequest> {
        core::mem::take(&mut self.restart).then_some(TransitionRequest {
            device: "board",
            transition: super::super::bus::Transition::Restart,
            reason: "test",
        })
    }
}

#[test]
fn enabled_endpoints_send_board_events_and_carry_transitions() {
    let mut rtkit = RtKit::new(
        vec![(0x20, Box::new(Board::default()) as Box<dyn Endpoint>)],
        stela_formats::builds::DEFAULT.rtkit_version,
    )
    .unwrap();
    rtkit.start(&mut Vec::new()).unwrap();
    rtkit.endpoint_mut::<Board>(0x20).unwrap().pending.push(9);
    assert!(rtkit.endpoint_mut::<Complement>(0x20).is_none());
    assert!(rtkit.endpoint_mut::<Board>(0x21).is_none());
    // Nothing leaves before enumeration and the endpoint's enable.
    let mut outbox = Vec::new();
    Firmware::poll(&mut rtkit, &mut outbox).unwrap();
    assert!(outbox.is_empty());
    mgmt(&mut rtkit, HELLO_REPLY, 12 | 12 << 16).unwrap();
    mgmt(&mut rtkit, ROLL_CALL, 0).unwrap();
    mgmt(&mut rtkit, ROLL_CALL, ROLL_CALL_LAST | 1 << 32).unwrap();
    Firmware::poll(&mut rtkit, &mut outbox).unwrap();
    assert!(outbox.is_empty());
    mgmt(&mut rtkit, ENDPOINT_CONTROL, 0x20 << 32 | ENABLE).unwrap();
    Firmware::poll(&mut rtkit, &mut outbox).unwrap();
    assert_eq!(
        outbox,
        vec![Message {
            endpoint: 0x20,
            payload: 9
        }]
    );
    assert!(Firmware::take_transition(&mut rtkit).is_none());
    step(&mut rtkit, 0x20, 1).unwrap();
    let request = Firmware::take_transition(&mut rtkit).unwrap();
    assert_eq!(request.device, "board");
    assert!(Firmware::take_transition(&mut rtkit).is_none());
}

#[test]
fn endpoints_are_application_endpoints_once_each() {
    let one = || Box::new(Complement) as Box<dyn Endpoint>;
    assert!(
        RtKit::new(
            vec![(0x2, one())],
            stela_formats::builds::DEFAULT.rtkit_version
        )
        .is_err()
    );
    assert!(
        RtKit::new(
            vec![(0x20, one()), (0x20, one())],
            stela_formats::builds::DEFAULT.rtkit_version
        )
        .is_err()
    );
}
