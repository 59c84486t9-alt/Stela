extern crate std;
use super::*;
use crate::firmware::{Catalog, Provenance, Resource};
use alloc::{boxed::Box, rc::Rc, vec::Vec};
use core::cell::{Cell, RefCell};
use sha2::{Digest, Sha256};

struct Model {
    registers: Box<[[u8; 64]]>,
    lengths: [u8; 256],
    calls: usize,
    fail_at: usize,
    writes: Vec<(u8, Vec<u8>)>,
    commands: Vec<[u8; 4]>,
    patch: Vec<u8>,
    pending: Option<[u8; 4]>,
    busy: usize,
    hang: bool,
    invalid: bool,
    task_result: u8,
    second_result: u8,
    detach_during_sample: bool,
    patch_fail: Option<[u8; 4]>,
    role_changes: bool,
}
impl Model {
    fn new(hardware: u8, mode: [u8; 4]) -> Self {
        let mut this = Self {
            registers: vec![[0; 64]; 256].into_boxed_slice(),
            lengths: [64; 256],
            calls: 0,
            fail_at: usize::MAX,
            writes: Vec::new(),
            commands: Vec::new(),
            patch: Vec::new(),
            pending: None,
            busy: 0,
            hang: false,
            invalid: false,
            task_result: 0,
            second_result: 0,
            detach_during_sample: false,
            patch_fail: None,
            role_changes: true,
        };
        this.set32(0, 0x451);
        this.set32(0x0f, (u32::from(hardware) << 24) | 0x1234);
        this.registers[3][..4].copy_from_slice(&mode);
        this.set32(0x28, 5);
        this.set32(STATUS, 0xe1);
        this.set32(0x5f, (1 << 8) | (1 << 16) | (1 << 5));
        this.registers[0x3f][..2].copy_from_slice(&12u16.to_le_bytes());
        this.registers[0x48][..25].fill(0x5a);
        this
    }
    fn set32(&mut self, register: u8, value: u32) {
        self.registers[usize::from(register)][..4].copy_from_slice(&value.to_le_bytes());
    }
    fn value(&self, register: u8) -> u32 {
        u32::from_le_bytes(
            self.registers[usize::from(register)][..4]
                .try_into()
                .unwrap(),
        )
    }
    fn complete(&mut self) {
        let Some(command) = self.pending.take() else {
            return;
        };
        let mut status = self.value(STATUS);
        if self.role_changes && self.task_result == 0 {
            match &command {
                b"SWDF" => status |= 1 << 6,
                b"SWUF" => status &= !(1 << 6),
                b"SWSr" => status |= 1 << 5,
                b"SWSk" => status &= !(1 << 5),
                _ => {}
            }
        }
        if &command == b"PTCd" {
            let length = usize::from(self.lengths[usize::from(DATA)]);
            self.patch
                .extend_from_slice(&self.registers[usize::from(DATA)][..length]);
        }
        self.registers[usize::from(DATA)].fill(0);
        self.registers[usize::from(DATA)][0] = self.task_result;
        self.registers[usize::from(DATA)][1] = self.second_result;
        if self.patch_fail == Some(command) {
            match &command {
                b"PTCs" => self.registers[usize::from(DATA)][1] = 0x80,
                b"PTCd" => self.registers[usize::from(DATA)][2] = 9,
                b"PTCc" => self.registers[usize::from(DATA)][3] = 1,
                _ => {}
            }
        } else if &command == b"PTCc" {
            self.registers[3][..4].copy_from_slice(b"APP ");
        }
        self.lengths[usize::from(DATA)] = 64;
        self.set32(STATUS, status);
        self.set32(CMD, 0);
    }
}
#[derive(Clone)]
struct Device(Rc<RefCell<Model>>);
impl Bus for Device {
    fn transaction(
        &mut self,
        address: Address,
        operations: &mut [Operation<'_>],
    ) -> Result<(), i2c::Error> {
        assert_eq!(address, Address::SevenBit(0x38));
        let mut model = self.0.borrow_mut();
        model.calls += 1;
        if model.fail_at == model.calls {
            return Err(i2c::ErrorKind::Aborted {
                kind: i2c::AbortKind::DataNack,
                source: 0x4321,
            }
            .into());
        }
        match operations {
            [Operation::Write(request), Operation::Read(response)] => {
                assert_eq!(request.len(), 1);
                let register = request[0];
                assert!((2..=65).contains(&response.len()));
                if register == 0x5f && model.detach_during_sample {
                    model.detach_during_sample = false;
                    model.set32(STATUS, 0);
                    model.set32(0x5f, 0);
                    model.registers[0x3f][..2].fill(0);
                    model.registers[0x14][0] |= 8;
                }
                if register == CMD && model.pending.is_some() && !model.hang {
                    if model.invalid {
                        model.pending = None;
                        model.set32(CMD, INVALID_CMD);
                    } else if model.busy == 0 {
                        model.complete();
                    } else {
                        model.busy -= 1;
                    }
                }
                response[0] = model.lengths[usize::from(register)];
                let bytes = response.len() - 1;
                response[1..].copy_from_slice(&model.registers[usize::from(register)][..bytes]);
            }
            [Operation::Write(request)] => {
                assert!(request.len() >= 3);
                let register = request[0];
                let bytes = &request[2..];
                assert_eq!(usize::from(request[1]), bytes.len());
                model.writes.push((register, bytes.to_vec()));
                if register == 0x18 || register == 0x19 {
                    for (index, byte) in bytes.iter().enumerate() {
                        model.registers[usize::from(register - 4)][index] &= !byte;
                    }
                } else {
                    model.registers[usize::from(register)][..bytes.len()].copy_from_slice(bytes);
                    model.lengths[usize::from(register)] = bytes.len() as u8;
                }
                if register == CMD {
                    let command = bytes.try_into().unwrap();
                    model.commands.push(command);
                    model.pending = Some(command);
                    model.busy = 2;
                }
            }
            _ => panic!(
                "TI register protocol needs a length-prefixed single write or atomic repeated-start read"
            ),
        }
        Ok(())
    }
}
#[derive(Default)]
struct Time(Cell<u64>);
impl Timer for Time {
    fn now_us(&self) -> u64 {
        self.0.get()
    }
    fn delay_us(&self, us: u64) {
        self.0.set(self.0.get().wrapping_add(us));
    }
}
fn make_controller(hardware: u8, mode: [u8; 4]) -> (Tps6598x<Device, Time>, Rc<RefCell<Model>>) {
    let model = Rc::new(RefCell::new(Model::new(hardware, mode)));
    (
        Tps6598x::new(
            Device(model.clone()),
            Address::SevenBit(0x38),
            Time::default(),
        ),
        model,
    )
}
fn initialized(hardware: u8) -> (Tps6598x<Device, Time>, Rc<RefCell<Model>>) {
    let (mut controller, model) = make_controller(hardware, *b"APP ");
    controller.initialize(None, None).unwrap();
    (controller, model)
}
fn catalog(bytes: Vec<u8>, hardware: u8) -> Catalog {
    let revision = format!("{:08x}", (u32::from(hardware) << 24) | 0x1234);
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    Catalog::from_handoff(vec![Resource {
        name: "ti/board.bin",
        target: Target {
            driver: "typec-tps6598x",
            hardware: "vid-00000451",
            revision: &revision,
            board: Some("test-board"),
        },
        provenance: Provenance {
            source: "synthetic-stateful-model",
            revision: "1",
            member: "board.bin",
            license: "MIT",
        },
        expected_length: bytes.len(),
        expected_sha256: digest,
        bytes,
    }])
    .unwrap()
}

#[test]
fn supported_silicon_reports_pd_identity_and_connection() {
    for hardware in [0, 0xf7, 0xf9] {
        let (controller, model) = initialized(hardware);
        assert!(controller.ready());
        let identity = controller.identity().unwrap();
        assert_eq!(identity.event_bytes, if hardware == 0 { 8 } else { 11 });
        let snapshot = controller.snapshot().unwrap();
        assert!(snapshot.connected());
        assert!(snapshot.host());
        assert!(snapshot.source());
        assert!(snapshot.vconn_source());
        assert!(snapshot.pd());
        assert!(snapshot.displayport());
        assert!(snapshot.thunderbolt());
        assert_eq!(snapshot.partner_identity, Some([0x5a; 25]));
        assert_eq!(model.borrow().value(0x16), MASK as u32);
    }
}
#[test]
fn roles_are_verified_and_partner_rejection_does_not_poison_idle_controller() {
    let (mut controller, model) = initialized(0xf7);
    assert!(
        !controller
            .request_data_role(DataRole::Device)
            .unwrap()
            .host()
    );
    assert!(
        !controller
            .request_power_role(PowerRole::Sink)
            .unwrap()
            .source()
    );
    let old = controller.snapshot();
    model.borrow_mut().task_result = 3;
    assert_eq!(
        controller.request_power_role(PowerRole::Source),
        Err(Error::Rejected { command: *b"SWSr" })
    );
    assert_eq!(controller.snapshot(), old);
    assert!(controller.ready());
    model.borrow_mut().task_result = 0;
    model.borrow_mut().role_changes = false;
    assert!(matches!(
        controller.request_data_role(DataRole::Host),
        Err(Error::RoleMismatch { .. })
    ));
    assert!(controller.ready());
    assert!(!controller.snapshot().unwrap().host());
    model.borrow_mut().role_changes = true;
    assert!(controller.request_data_role(DataRole::Host).unwrap().host());
}
#[test]
fn firmware_upload_uses_verified_exact_resource_chunks_and_requires_app_mode() {
    for bytes in [vec![0x5a; 1], (0..=255).collect(), vec![0x91; 257]] {
        let (mut controller, model) = make_controller(0xf9, *b"PTCH");
        let catalog = catalog(bytes.clone(), 0xf9);
        controller
            .initialize(
                Some(&catalog),
                Some(FirmwareRequest {
                    name: "ti/board.bin",
                    board: "test-board",
                }),
            )
            .unwrap();
        drop(catalog);
        assert!(controller.ready());
        assert_eq!(model.borrow().patch, bytes);
        let receipt = controller.patch().unwrap();
        assert_eq!(receipt.length, bytes.len());
        assert_eq!(receipt.sha256, <[u8; 32]>::from(Sha256::digest(&bytes)));
        assert_eq!(receipt.name, "ti/board.bin");
        assert_eq!(receipt.target_board.as_deref(), Some("test-board"));
        let commands = &model.borrow().commands;
        assert_eq!(commands.first(), Some(b"PTCs"));
        assert_eq!(commands.last(), Some(b"PTCc"));
        assert_eq!(
            commands
                .iter()
                .filter(|command| *command == b"PTCd")
                .count(),
            bytes.len().div_ceil(64)
        );
        assert!(controller.timer.now_us() >= 1_000_000);
    }
}
#[test]
fn each_patch_protocol_failure_keeps_owned_evidence_and_refuses_retry() {
    for command in [*b"PTCs", *b"PTCd", *b"PTCc"] {
        let (mut controller, model) = make_controller(0, *b"PTCH");
        model.borrow_mut().patch_fail = Some(command);
        let catalog = catalog(vec![0x5a; 65], 0);
        assert!(matches!(
            controller.initialize(
                Some(&catalog),
                Some(FirmwareRequest {
                    name: "ti/board.bin",
                    board: "test-board"
                })
            ),
            Err(Error::PatchResponse { .. })
        ));
        drop(catalog);
        assert_eq!(controller.patch().unwrap().length, 65);
        assert!(!controller.ready());
        let calls = model.borrow().calls;
        assert_eq!(
            controller.initialize(None, None),
            Err(Error::NeedsPlatformReset)
        );
        assert_eq!(model.borrow().calls, calls);
    }
}
#[test]
fn missing_wrong_firmware_and_unsupported_silicon_or_modes_do_not_initialize() {
    let (mut controller, _) = make_controller(0, *b"PTCH");
    assert!(matches!(
        controller.initialize(None, None),
        Err(Error::FirmwareRequired { .. })
    ));
    let (mut controller, model) = make_controller(0, *b"PTCH");
    let catalog = catalog(vec![1], 0xf7);
    assert!(matches!(
        controller.initialize(
            Some(&catalog),
            Some(FirmwareRequest {
                name: "ti/board.bin",
                board: "test-board"
            })
        ),
        Err(Error::Firmware(_))
    ));
    assert!(model.borrow().commands.is_empty());
    for mode in [*b"BOOT", *b"BIST", *b"DISC", *b"XXXX"] {
        let (mut controller, _) = make_controller(0, mode);
        assert_eq!(controller.initialize(None, None), Err(Error::Mode(mode)));
    }
    let (mut controller, _) = make_controller(0x12, *b"APP ");
    assert!(matches!(
        controller.initialize(None, None),
        Err(Error::UnsupportedVersion(_))
    ));
}
#[test]
fn event_width_w1c_and_detach_publish_only_after_complete_observation() {
    for hardware in [0, 0xf7, 0xf9] {
        let (mut controller, model) = initialized(hardware);
        assert_eq!(controller.poll().unwrap(), None);
        {
            let mut model = model.borrow_mut();
            model.registers[0x14][0] = 8;
            model.registers[0x15][7] = 0x80;
            if hardware != 0 {
                model.registers[0x14][10] = 1;
            }
            model.set32(STATUS, 0);
            model.set32(0x5f, 0);
            model.registers[0x3f][..2].fill(0);
        }
        let event = controller.poll().unwrap().unwrap();
        assert!(!event.snapshot.connected());
        assert_eq!(event.snapshot.partner_identity, None);
        assert_eq!(event.first[0], 8);
        assert_eq!(event.second[7], 0x80);
        let model = model.borrow();
        let acks: Vec<_> = model
            .writes
            .iter()
            .filter(|(register, _)| matches!(register, 0x18 | 0x19))
            .collect();
        assert_eq!(acks.len(), 2);
        assert_eq!(acks[0].1.len(), usize::from(event.bytes));
        assert!(
            model.registers[0x14][..usize::from(event.bytes)]
                .iter()
                .all(|byte| *byte == 0)
        );
    }
}
#[test]
fn event_failures_keep_the_old_snapshot() {
    let (mut baseline, model) = initialized(0xf7);
    model.borrow_mut().registers[0x14][0] = 8;
    let first = model.borrow().calls + 1;
    baseline.poll().unwrap();
    let last = model.borrow().calls;
    for fail_at in first..=last {
        let (mut controller, model) = initialized(0xf7);
        let old = controller.snapshot();
        model.borrow_mut().registers[0x14][0] = 8;
        model.borrow_mut().fail_at = fail_at;
        assert!(matches!(controller.poll(), Err(Error::I2c { .. })));
        assert_eq!(controller.snapshot(), old);
        assert!(!controller.ready());
        let calls = model.borrow().calls;
        assert!(controller.poll().is_err());
        assert_eq!(model.borrow().calls, calls);
    }
}
#[test]
fn short_length_invalid_task_and_unresolved_task_are_explicit() {
    let (mut controller, model) = initialized(0);
    model.borrow_mut().lengths[usize::from(STATUS)] = 1;
    assert!(matches!(
        controller.request_data_role(DataRole::Device),
        Err(Error::InvalidLength { .. })
    ));
    assert!(!controller.ready());
    let (mut controller, model) = initialized(0);
    model.borrow_mut().invalid = true;
    assert_eq!(
        controller.request_data_role(DataRole::Device),
        Err(Error::InvalidCommand(*b"SWUF"))
    );
    assert!(controller.ready());
    let (mut controller, model) = initialized(0);
    model.borrow_mut().hang = true;
    assert_eq!(
        controller.request_data_role(DataRole::Device),
        Err(Error::Timeout { command: *b"SWUF" })
    );
    assert!(!controller.ready());
    let calls = model.borrow().calls;
    assert!(controller.request_data_role(DataRole::Device).is_err());
    assert_eq!(model.borrow().calls, calls);
}
#[test]
fn quiesce_disables_real_events_and_all_initialization_io_errors_are_explicit() {
    let (mut baseline, model) = initialized(0);
    let calls = model.borrow().calls;
    baseline.quiesce().unwrap();
    assert!(!baseline.ready());
    assert_eq!(model.borrow().value(0x16), 0);
    for fail_at in 1..=calls {
        let (mut controller, model) = make_controller(0, *b"APP ");
        model.borrow_mut().fail_at = fail_at;
        assert!(matches!(
            controller.initialize(None, None),
            Err(Error::I2c { .. })
        ));
        assert!(!controller.ready());
        let calls = model.borrow().calls;
        assert!(controller.initialize(None, None).is_err());
        assert_eq!(model.borrow().calls, calls);
    }
}

#[test]
fn unknown_task_results_and_failed_register_words_never_look_successful() {
    let (mut controller, model) = initialized(0);
    model.borrow_mut().task_result = 0xff;
    let old = controller.snapshot();
    assert_eq!(
        controller.request_data_role(DataRole::Device),
        Err(Error::TaskResult {
            command: *b"SWUF",
            status: 0xff
        })
    );
    assert_eq!(controller.snapshot(), old);
    assert!(controller.ready());
    let (mut controller, model) = make_controller(0, *b"APP ");
    model.borrow_mut().set32(STATUS, u32::MAX);
    assert_eq!(
        controller.initialize(None, None),
        Err(Error::InvalidRegister {
            register: STATUS,
            value: u32::MAX
        })
    );
    assert!(!controller.ready());
}
#[test]
fn every_role_io_failure_preserves_old_observation_and_blocks_uncertain_replay() {
    let (mut baseline, model) = initialized(0xf9);
    let first = model.borrow().calls + 1;
    baseline.request_data_role(DataRole::Device).unwrap();
    let last = model.borrow().calls;
    for fail_at in first..=last {
        let (mut controller, model) = initialized(0xf9);
        let old = controller.snapshot();
        model.borrow_mut().fail_at = fail_at;
        assert!(matches!(
            controller.request_data_role(DataRole::Device),
            Err(Error::I2c { .. })
        ));
        assert_eq!(controller.snapshot(), old);
        assert!(!controller.ready());
        let calls = model.borrow().calls;
        assert!(controller.request_data_role(DataRole::Device).is_err());
        assert_eq!(model.borrow().calls, calls);
    }
}

#[test]
fn same_plug_bit_reasserted_during_status_sampling_is_not_lost() {
    for hardware in [0, 0xf7, 0xf9] {
        let (mut controller, model) = initialized(hardware);
        model.borrow_mut().registers[0x14][0] = 8;
        model.borrow_mut().detach_during_sample = true;
        // STATUS is sampled before the peer detaches during DATA_STATUS.
        // The captured event was already ACKed, so its newly reasserted
        // same bit must survive this sample and trigger the next drain.
        assert!(controller.poll().unwrap().unwrap().snapshot.connected());
        assert_eq!(model.borrow().registers[0x14][0], 8);
        assert!(!controller.poll().unwrap().unwrap().snapshot.connected());
        assert_eq!(model.borrow().registers[0x14][0], 0);
        assert_eq!(controller.poll().unwrap(), None);
        assert!(!controller.snapshot().unwrap().connected());
    }
}
#[test]
#[ignore = "oracle: STELA_TYPEC_DISCRETE_ORACLE"]
fn unchanged_linux_tps_block_and_task_oracle() {
    let path = std::env::var("STELA_TYPEC_DISCRETE_ORACLE")
        .expect("STELA_TYPEC_DISCRETE_ORACLE trace path");
    let trace = std::fs::read_to_string(path).unwrap();
    let mut blocks = 0;
    let mut tasks = 0;
    for line in trace.lines() {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        match fields[0] {
            "B" => {
                let length: usize = fields[1].parse().unwrap();
                assert_eq!(fields[2], "0");
                assert_eq!(fields[3], "0");
                let (mut controller, model) = make_controller(0, *b"APP ");
                for (index, byte) in model.borrow_mut().registers[0x40].iter_mut().enumerate() {
                    *byte = index as u8;
                }
                let mut read = vec![0; length];
                controller.read(0x40, &mut read).unwrap();
                controller.write(0x40, &read).unwrap();
                let model = model.borrow();
                let wire = &model.writes.last().unwrap().1;
                assert_eq!(wire.len() + 1, fields[4].parse::<usize>().unwrap());
                assert_eq!(wire.len(), fields[5].parse::<usize>().unwrap());
                assert_eq!(read[length - 1], fields[6].parse::<u8>().unwrap());
                assert_eq!(wire[length - 1], fields[7].parse::<u8>().unwrap());
                blocks += 1;
            }
            "T" => {
                let kind: u8 = fields[1].parse().unwrap();
                let expected: i32 = fields[2].parse().unwrap();
                let (mut controller, model) = make_controller(0, *b"APP ");
                {
                    let mut model = model.borrow_mut();
                    model.second_result = 0x42;
                    match kind {
                        0 => {}
                        1 => model.set32(CMD, 0x12345678),
                        2 => model.invalid = true,
                        3 => model.hang = true,
                        4 => model.task_result = 1,
                        5 => model.task_result = 3,
                        _ => panic!("unknown task oracle case"),
                    }
                }
                let mut bytes = [0xaa; 2];
                let result = controller.task(*b"SWUF", &[1, 2, 3], &mut bytes);
                match (expected, result) {
                    (0, Ok(())) => {
                        assert_eq!(bytes[0], fields[5].parse::<u8>().unwrap());
                        assert_eq!(bytes[1], fields[6].parse::<u8>().unwrap());
                    }
                    (-16, Err(Error::Busy(_)))
                    | (-22, Err(Error::InvalidCommand(_)))
                    | (-110, Err(Error::Timeout { .. } | Error::TaskTimeout { .. }))
                    | (-1, Err(Error::Rejected { .. })) => assert_eq!(bytes, [0xaa; 2]),
                    (_, other) => panic!("Linux task {expected}, Stela {other:?}"),
                }
                let model = model.borrow();
                assert_eq!(model.commands.len(), fields[3].parse::<usize>().unwrap());
                assert_eq!(
                    model.writes.iter().filter(|write| write.0 == DATA).count(),
                    fields[4].parse::<usize>().unwrap()
                );
                tasks += 1;
            }
            "C" => {}
            _ => panic!("unknown oracle record"),
        }
    }
    assert_eq!(blocks, 64);
    assert_eq!(tasks, 6);
}
