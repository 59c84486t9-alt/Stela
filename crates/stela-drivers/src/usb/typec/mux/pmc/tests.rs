extern crate std;
use super::*;
use alloc::{collections::VecDeque, rc::Rc, vec::Vec};
use core::cell::{Cell, RefCell};
use scu::{RegisterError, Registers};

struct Hardware {
    words: [u32; 40],
    status: u32,
    pending: Option<(u32, Vec<u8>)>,
    polls: usize,
    stuck: bool,
    controller_error: u32,
    requests: Vec<Vec<u8>>,
    controls: Vec<u32>,
    responses: VecDeque<[u8; 4]>,
    iom: [u32; 15],
    irq_edges: usize,
    calls: usize,
    fail_at: usize,
    fail_after: bool,
    iom_reads: Vec<usize>,
    writes: Vec<(usize, u32)>,
}
impl Hardware {
    fn new() -> Self {
        Self {
            words: [0; 40],
            status: 0,
            pending: None,
            polls: 0,
            stuck: false,
            controller_error: 0,
            requests: Vec::new(),
            controls: Vec::new(),
            responses: VecDeque::new(),
            iom: [0; 15],
            irq_edges: 0,
            calls: 0,
            fail_at: usize::MAX,
            fail_after: false,
            iom_reads: Vec::new(),
            writes: Vec::new(),
        }
    }
    fn apply(&mut self, message: &[u8]) {
        let usage = message[0] & 15;
        let index = usize::from((message[0] >> 4) - 1);
        let old = self.iom[index];
        self.iom[index] = match usage {
            0 => (1 << 31) | (3 << 6) | (u32::from(message[1] & 16 != 0) << 10),
            1 => 0,
            2 => 4 << 6,
            3 => {
                let data = u32::from_le_bytes(message[4..8].try_into().unwrap());
                (1 << 31)
                    | (if message[1] == 0x10 { 5 } else { 7 } << 6)
                    | (u32::from(data & 8 != 0) << 10)
            }
            4 => {
                if message[1] & 32 != 0 {
                    assert!(
                        old & (1 << 12) != 0,
                        "IRQ requires prior HPD level publication"
                    );
                    self.irq_edges += 1;
                }
                (old & !(1 << 12)) | (u32::from(message[1] & 16 != 0) << 12)
            }
            _ => panic!("unsupported PMC usage"),
        };
    }
    fn complete(&mut self) {
        let (control, message) = self.pending.take().unwrap();
        let mut response = [0; 16];
        if control as u8 == 0xa7 {
            let reply = self.responses.pop_front().unwrap_or([0; 4]);
            response[..4].copy_from_slice(&reply);
            let status = reply[if message[0] & 15 < 2 { 2 } else { 1 }];
            if status & 1 == 0 && self.controller_error == 0 {
                self.apply(&message);
            }
        } else {
            for (index, byte) in response.iter_mut().enumerate() {
                *byte = 0xa0 + index as u8;
            }
        }
        for (index, bytes) in response.as_chunks::<4>().0.iter().enumerate() {
            self.words[0x90 / 4 + index] = u32::from_le_bytes(*bytes);
        }
        self.status = 4 | self.controller_error;
    }
}
#[derive(Clone)]
struct Ipc(Rc<RefCell<Hardware>>);
impl Registers for Ipc {
    fn read32(&mut self, offset: usize) -> Result<u32, RegisterError> {
        let mut hardware = self.0.borrow_mut();
        hardware.calls += 1;
        let fail = hardware.fail_at == hardware.calls;
        if fail && !hardware.fail_after {
            return Err(RegisterError::Io {
                offset,
                status: 0x42,
            });
        }
        let value = if offset == 4 {
            if hardware.pending.is_some() && !hardware.stuck {
                if hardware.polls == 0 {
                    hardware.complete();
                } else {
                    hardware.polls -= 1;
                }
            }
            hardware.status
        } else {
            hardware.words[offset / 4]
        };
        if fail {
            Err(RegisterError::Io {
                offset,
                status: 0x42,
            })
        } else {
            Ok(value)
        }
    }
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), RegisterError> {
        let mut hardware = self.0.borrow_mut();
        hardware.calls += 1;
        let fail = hardware.fail_at == hardware.calls;
        if fail && !hardware.fail_after {
            return Err(RegisterError::Io {
                offset,
                status: 0x42,
            });
        }
        hardware.writes.push((offset, value));
        match offset {
            0 => {
                assert_eq!(value & 0x100, 0x100);
                let length = ((value >> 16) & 255) as usize;
                assert!(length <= 16);
                let mut input = Vec::new();
                for index in 0..length.div_ceil(4) {
                    input.extend_from_slice(&hardware.words[0x80 / 4 + index].to_le_bytes());
                }
                input.truncate(length);
                hardware.requests.push(input.clone());
                hardware.controls.push(value);
                hardware.pending = Some((value, input));
                hardware.polls = 2;
                hardware.status = 1;
            }
            4 => {
                assert_eq!(value & 4, 4);
                hardware.status &= !4;
            }
            0x80..=0x8c => hardware.words[offset / 4] = value,
            _ => panic!("unexpected IPC write"),
        }
        if fail {
            Err(RegisterError::Io {
                offset,
                status: 0x42,
            })
        } else {
            Ok(())
        }
    }
}
struct Iom {
    hardware: Rc<RefCell<Hardware>>,
    kind: IomKind,
}
impl Registers for Iom {
    fn read32(&mut self, offset: usize) -> Result<u32, RegisterError> {
        let mut hardware = self.hardware.borrow_mut();
        hardware.calls += 1;
        hardware.iom_reads.push(offset);
        if hardware.calls == hardware.fail_at {
            return Err(RegisterError::Io {
                offset,
                status: 0x99,
            });
        }
        if offset < self.kind.status_offset()
            || !(offset - self.kind.status_offset()).is_multiple_of(self.kind.status_stride())
        {
            return Err(RegisterError::Bounds { offset });
        }
        let index = (offset - self.kind.status_offset()) / self.kind.status_stride();
        hardware
            .iom
            .get(index)
            .copied()
            .ok_or(RegisterError::Bounds { offset })
    }
    fn write32(&mut self, _offset: usize, _value: u32) -> Result<(), RegisterError> {
        panic!("IOM status is read-only")
    }
}
#[derive(Clone, Default)]
struct Time(Rc<Cell<u64>>);
impl Timer for Time {
    fn now_us(&self) -> u64 {
        self.0.get()
    }
    fn delay_us(&self, microseconds: u64) {
        self.0.set(self.0.get().wrapping_add(microseconds));
    }
}
fn make_hardware() -> Rc<RefCell<Hardware>> {
    Rc::new(RefCell::new(Hardware::new()))
}
fn configuration(usb3: u8) -> PortConfiguration {
    PortConfiguration {
        usb2: usb3,
        usb3,
        hsl_orientation: None,
        sbu_orientation: None,
    }
}
type TestController = Pmc<Native<Ipc, Iom, Time>>;
fn controller(kind: IomKind) -> (TestController, Rc<RefCell<Hardware>>) {
    let hardware = make_hardware();
    let native = Native::new(
        scu::Scu::new(Ipc(hardware.clone()), Time::default()),
        Iom {
            hardware: hardware.clone(),
            kind,
        },
        kind,
    );
    let mut controller = Pmc::new(native, &[configuration(1), configuration(3)]).unwrap();
    controller.initialize().unwrap();
    (controller, hardware)
}
fn dp(pin: Pin, status: u32, configuration: u32) -> Mode {
    Mode::DisplayPort(super::super::DisplayPort {
        pin,
        status,
        configuration,
    })
}

#[test]
fn scu_word_protocol_zero_padding_and_staged_responses_cover_all_lengths() {
    for input_length in 0usize..=16 {
        for output_length in 0..=16 {
            let hardware = make_hardware();
            let mut ipc = scu::Scu::new(Ipc(hardware.clone()), Time::default());
            let input: Vec<_> = (0..input_length as u8).collect();
            let mut output = vec![0x55; output_length];
            let receipt = ipc.command(0x5a, 3, &input, &mut output).unwrap();
            assert_eq!(
                receipt.command,
                ((input_length as u32) << 16) | (3 << 12) | 0x15a
            );
            assert_eq!(receipt.sequence, 1);
            assert_eq!(
                output,
                (0..output_length as u8)
                    .map(|byte| 0xa0 + byte)
                    .collect::<Vec<_>>()
            );
            let hardware = hardware.borrow();
            assert_eq!(hardware.requests, vec![input]);
            assert_eq!(hardware.status, 0);
            assert!(hardware.writes.contains(&(4, 4)));
            if !input_length.is_multiple_of(4) {
                let word = hardware.words[0x80 / 4 + input_length / 4].to_le_bytes();
                assert!(word[input_length % 4..].iter().all(|byte| *byte == 0));
            }
        }
    }
}
#[test]
fn scu_busy_timeout_controller_error_and_all_ones_status_remain_distinct() {
    let hardware = make_hardware();
    hardware.borrow_mut().status = 1;
    let mut ipc = scu::Scu::new(Ipc(hardware.clone()), Time::default());
    assert_eq!(ipc.command(0x5a, 0, &[], &mut []), Err(scu::Error::Busy(1)));
    assert!(hardware.borrow().writes.is_empty());
    assert_eq!(ipc.fault(), None);
    hardware.borrow_mut().status = u32::MAX;
    assert_eq!(
        ipc.command(0x5a, 0, &[], &mut []),
        Err(scu::Error::InvalidStatus(u32::MAX))
    );
    let hardware = make_hardware();
    hardware.borrow_mut().stuck = true;
    let timer = Time::default();
    timer.0.set(u64::MAX - 1000);
    let mut ipc = scu::Scu::new(Ipc(hardware.clone()), timer);
    assert_eq!(
        ipc.command(0x5a, 0, &[], &mut []),
        Err(scu::Error::Timeout(1))
    );
    let calls = hardware.borrow().calls;
    assert!(ipc.command(0x5a, 0, &[], &mut []).is_err());
    assert_eq!(hardware.borrow().calls, calls);
    let hardware = make_hardware();
    hardware.borrow_mut().controller_error = 0x1234_0002;
    let mut ipc = scu::Scu::new(Ipc(hardware.clone()), Time::default());
    let mut output = [0x55; 4];
    assert_eq!(
        ipc.command(0x5a, 0, &[], &mut output),
        Err(scu::Error::Controller(0x1234_0006))
    );
    assert_eq!(output, [0x55; 4]);
    assert_eq!(ipc.fault(), None);
    hardware.borrow_mut().controller_error = 0;
    assert!(ipc.command(0x5a, 0, &[], &mut output).is_ok());
}
#[test]
fn scu_every_register_failure_before_or_after_effect_blocks_replay_and_partial_output() {
    let hardware = make_hardware();
    let mut baseline = scu::Scu::new(Ipc(hardware.clone()), Time::default());
    baseline
        .command(0x5a, 1, &[1, 2, 3, 4, 5], &mut [0; 8])
        .unwrap();
    let calls = hardware.borrow().calls;
    for fail_after in [false, true] {
        for fail_at in 1..=calls {
            let hardware = make_hardware();
            hardware.borrow_mut().fail_at = fail_at;
            hardware.borrow_mut().fail_after = fail_after;
            let mut ipc = scu::Scu::new(Ipc(hardware.clone()), Time::default());
            let mut output = [0x55; 8];
            assert!(matches!(
                ipc.command(0x5a, 1, &[1, 2, 3, 4, 5], &mut output),
                Err(scu::Error::Register { .. })
            ));
            assert_eq!(output, [0x55; 8]);
            assert!(ipc.fault().is_some());
            assert_eq!(ipc.last_receipt(), None);
            let calls = hardware.borrow().calls;
            assert!(ipc.command(0x5a, 1, &[1, 2, 3, 4, 5], &mut output).is_err());
            assert_eq!(hardware.borrow().calls, calls);
        }
    }
}
#[test]
fn native_scalar_mmio_checks_alignment_bounds_and_words() {
    #[repr(C, align(4))]
    struct Region([u8; 0xa0]);
    let mut memory = Region([0; 0xa0]);
    let base = core::ptr::NonNull::new(memory.0.as_mut_ptr()).unwrap();
    // SAFETY: stable aligned exclusive fixture covers exactly this mapping.
    let mut mmio = unsafe { scu::Mmio::new(base, memory.0.len()) }.unwrap();
    mmio.write32(0x80, 0xa5c3_9f17).unwrap();
    assert_eq!(mmio.read32(0x80).unwrap(), 0xa5c3_9f17);
    assert_eq!(&memory.0[0x80..0x84], &[0x17, 0x9f, 0xc3, 0xa5]);
    assert!(mmio.read32(0x9d).is_err());
    assert!(mmio.read32(0xa0).is_err());
    // SAFETY: offset remains inside allocation; constructor must reject it.
    let unaligned = unsafe { core::ptr::NonNull::new_unchecked(base.as_ptr().add(1)) };
    assert!(matches!(
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        unsafe { scu::Mmio::new(unaligned, 0x90) },
        Err(RegisterError::Mapping)
    ));
}
#[test]
fn native_iom_layouts_use_real_source_offsets_stride_and_observed_roles() {
    for kind in [
        IomKind::TigerLake,
        IomKind::AlderLake,
        IomKind::MeteorLake,
        IomKind::LunarLake,
    ] {
        let (mut controller, hardware) = controller(kind);
        assert_eq!(
            &hardware.borrow().iom_reads[..2],
            &[
                kind.status_offset(),
                kind.status_offset() + 2 * kind.status_stride()
            ]
        );
        controller.set_orientation(0, Orientation::Reverse).unwrap();
        controller.set_role(0, Some(DataRole::Device)).unwrap();
        assert_eq!(hardware.borrow().requests, vec![vec![0x10, 0x71]]);
        let observed = controller.poll_status(0).unwrap();
        assert!(observed.connected());
        assert_eq!(observed.actual_role(), DataRole::Device);
        assert_eq!(observed.activity(), 3);
        controller.set_role(0, None).unwrap();
        assert_eq!(hardware.borrow().requests.last(), Some(&vec![0x11, 1]));
        assert!(!controller.poll_status(0).unwrap().connected());
    }
}
#[test]
fn firmware_busy_retries_only_three_and_fatal_errors_quarantine() {
    let (mut controller, hardware) = controller(IomKind::TigerLake);
    controller.set_orientation(0, Orientation::Normal).unwrap();
    hardware.borrow_mut().responses.extend([[0, 0, 1, 0]; 3]);
    assert!(matches!(
        controller.set_role(0, Some(DataRole::Host)),
        Err(Error::Firmware { fatal: false, .. })
    ));
    assert_eq!(hardware.borrow().requests.len(), 3);
    assert_eq!(controller.fault(), None);
    assert_eq!(controller.ports()[0].role, None);
    controller.set_role(0, Some(DataRole::Host)).unwrap();
    hardware.borrow_mut().responses.push_back([0, 3, 0, 0]);
    assert!(matches!(
        controller.set_mode(0, Mode::Safe),
        Err(Error::Firmware { fatal: true, .. })
    ));
    let calls = hardware.borrow().calls;
    assert!(controller.set_orientation(0, Orientation::Reverse).is_err());
    assert_eq!(hardware.borrow().calls, calls);
    assert_eq!(controller.last_reply().unwrap().response, [0, 3, 0, 0]);
}
#[test]
fn inherited_role_prevents_unknown_cache_from_hiding_a_required_swap() {
    let (mut controller, hardware) = controller(IomKind::AlderLake);
    hardware.borrow_mut().iom[0] = (1 << 31) | (3 << 6);
    controller.set_orientation(0, Orientation::Normal).unwrap();
    controller.set_role(0, Some(DataRole::Device)).unwrap();
    assert_eq!(
        hardware.borrow().requests,
        vec![vec![0x11, 1], vec![0x10, 0x11]]
    );
    assert_eq!(
        controller.poll_status(0).unwrap().actual_role(),
        DataRole::Device
    );
}
#[test]
fn dp_hpd_level_precedes_irq_and_clear_failure_never_becomes_disconnect_success() {
    let (mut controller, hardware) = controller(IomKind::MeteorLake);
    controller.set_orientation(0, Orientation::Normal).unwrap();
    controller.set_role(0, Some(DataRole::Host)).unwrap();
    hardware.borrow_mut().requests.clear();
    controller
        .set_mode(0, dp(Pin::D, 0x180, (3 << 2) | (1 << 28)))
        .unwrap();
    let requests = hardware.borrow().requests.clone();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].len(), 8);
    assert_eq!(&requests[1..], &[vec![0x14, 0x10], vec![0x14, 0x30]]);
    assert_eq!(hardware.borrow().irq_edges, 1);
    let observed = controller.poll_status(0).unwrap();
    assert!(observed.hpd());
    assert_eq!(observed.activity(), 5);
    hardware.borrow_mut().responses.extend([[0, 1, 0, 0]; 3]);
    let before = hardware.borrow().requests.len();
    assert!(matches!(
        controller.set_role(0, None),
        Err(Error::Firmware { fatal: false, .. })
    ));
    assert_eq!(hardware.borrow().requests.len(), before + 3);
    assert_eq!(controller.ports()[0].role, Some(DataRole::Host));
    assert!(
        hardware.borrow().requests[before..]
            .iter()
            .all(|request| request[0] & 15 == 4)
    );
}
#[test]
fn orientation_overrides_and_tbt_usb4_cable_data_are_real_wire_effects() {
    for kind in [IomKind::TigerLake, IomKind::MeteorLake] {
        let (mut controller, hardware) = controller(kind);
        controller.ports[0].configuration.hsl_orientation = Some(Orientation::Normal);
        controller.ports[0].configuration.sbu_orientation = Some(Orientation::Reverse);
        controller.set_orientation(0, Orientation::Normal).unwrap();
        controller.set_role(0, Some(DataRole::Host)).unwrap();
        assert_eq!(hardware.borrow().requests.last(), Some(&vec![0x10, 0x41]));
        controller
            .set_mode(
                0,
                Mode::Thunderbolt {
                    device_mode: 1 << 16,
                    cable_mode: (3 << 16) | (1 << 19) | (1 << 21) | (1 << 22) | (1 << 23),
                    enter_vdo: 1 << 24,
                },
            )
            .unwrap();
        let tbt = hardware.borrow().requests.last().unwrap().clone();
        let word = u32::from_le_bytes(tbt[4..8].try_into().unwrap());
        assert_ne!(word & 4, 0);
        assert_ne!(word & (1 << 17), 0);
        assert_ne!(word & (1 << 18), 0);
        assert_ne!(word & (1 << 20), 0);
        assert_eq!(word & (1 << 22) != 0, !kind.legacy_tbt());
        hardware.borrow_mut().iom[0] = (1 << 31) | (3 << 6);
        controller
            .set_mode(
                0,
                Mode::Usb4 {
                    enter_usb: (2 << 28) | (3 << 21) | (3 << 19),
                    active_link_training: true,
                },
            )
            .unwrap();
        let usb4 = hardware.borrow().requests.last().unwrap().clone();
        let word = u32::from_le_bytes(usb4[4..8].try_into().unwrap());
        assert_ne!(word & (1 << 23), 0);
        assert_ne!(word & (1 << 28), 0);
        assert_ne!(word & 4, 0);
        assert_eq!(word & (1 << 22) != 0, !kind.legacy_tbt());
    }
}
#[test]
fn invalid_configuration_missing_orientation_and_failed_iom_are_explicit() {
    let (mut controller, hardware) = controller(IomKind::LunarLake);
    assert_eq!(
        controller.set_role(0, Some(DataRole::Host)),
        Err(Error::NoOrientation)
    );
    assert!(hardware.borrow().requests.is_empty());
    assert_eq!(
        controller.set_mode(0, Mode::Usb3),
        Err(Error::NoOrientation)
    );
    let calls = hardware.borrow().calls;
    hardware.borrow_mut().fail_at = calls + 1;
    assert!(matches!(controller.poll_status(0), Err(Error::Iom(_))));
    let calls = hardware.borrow().calls;
    assert!(controller.set_orientation(0, Orientation::Normal).is_err());
    assert_eq!(hardware.borrow().calls, calls);
    assert_eq!(IomKind::from_hid("INTC10EA"), Some(IomKind::LunarLake));
    assert_eq!(IomKind::from_hid("UNKNOWN"), None);
    let hardware = make_hardware();
    let native = Native::new(
        scu::Scu::new(Ipc(hardware.clone()), Time::default()),
        Iom {
            hardware,
            kind: IomKind::TigerLake,
        },
        IomKind::TigerLake,
    );
    assert!(matches!(
        Pmc::new(native, &[configuration(0)]),
        Err(Error::InvalidConfiguration)
    ));
}
#[test]
fn native_rejects_invalid_pmc_frames_before_ipc_publication() {
    let (mut controller, hardware) = controller(IomKind::TigerLake);
    for bytes in [
        &[][..],
        &[0x10],
        &[0x00, 1],
        &[0x15, 0],
        &[0x12, 0],
        &[0x13, 0],
    ] {
        assert_eq!(
            controller.backend.command(bytes),
            Err(scu::Error::InvalidArgument)
        );
    }
    assert!(hardware.borrow().requests.is_empty());
}

#[test]
#[ignore = "oracle: STELA_INTEL_PMC_MUX_ORACLE"]
fn unchanged_linux_intel_pmc_packet_oracle() {
    let path = std::env::var("STELA_INTEL_PMC_MUX_ORACLE").unwrap();
    let trace = std::fs::read_to_string(path).unwrap();
    let kinds = [
        IomKind::TigerLake,
        IomKind::AlderLake,
        IomKind::MeteorLake,
        IomKind::LunarLake,
    ];
    let orientation = |value: u32| match value {
        0 => Orientation::None,
        1 => Orientation::Normal,
        2 => Orientation::Reverse,
        _ => panic!(),
    };
    let role = |value: u32| match value {
        0 => None,
        1 => Some(DataRole::Host),
        2 => Some(DataRole::Device),
        _ => panic!(),
    };
    let mut counts = [0; 7];
    for line in trace.lines() {
        let parts: Vec<_> = line.split_whitespace().collect();
        let dec = |index: usize| parts[index].parse::<u32>().unwrap();
        let hex = |index: usize| u32::from_str_radix(parts[index], 16).unwrap();
        let (kind, port, ori, cached_role, iom, result_index, group) = match parts[0] {
            "C" => (
                kinds[0],
                dec(1) as u8,
                orientation(dec(2)),
                role(dec(6)),
                hex(7),
                8,
                0,
            ),
            "D" => (
                kinds[dec(1) as usize],
                1,
                orientation(dec(2)),
                role(dec(3)),
                hex(7),
                8,
                1,
            ),
            "T" => (
                kinds[dec(1) as usize],
                1,
                orientation(dec(2)),
                role(dec(3)),
                hex(7),
                8,
                2,
            ),
            "U" => (
                kinds[dec(1) as usize],
                1,
                orientation(dec(2)),
                role(dec(3)),
                hex(6),
                7,
                3,
            ),
            "S" => (
                kinds[0],
                dec(1) as u8,
                Orientation::None,
                None,
                hex(2),
                3,
                4,
            ),
            "X" => (
                kinds[0],
                dec(1) as u8,
                Orientation::None,
                None,
                hex(2),
                3,
                5,
            ),
            "B" => (kinds[0], 1, Orientation::None, None, 0, 3, 6),
            _ => panic!("{line}"),
        };
        let (mut controller, hardware) = controller(kind);
        let index = usize::from(port == 3);
        controller.ports[index].orientation = ori;
        controller.ports[index].role = cached_role;
        hardware.borrow_mut().iom[usize::from(port - 1)] = iom;
        let result = match parts[0] {
            "C" => {
                controller.ports[index].configuration.hsl_orientation = Some(orientation(dec(4)));
                controller.ports[index].configuration.sbu_orientation = Some(orientation(dec(5)));
                controller.set_role(index, role(dec(3)))
            }
            "D" => controller.set_mode(
                index,
                dp(
                    [Pin::C, Pin::D, Pin::E, Pin::F][dec(4) as usize - 2],
                    hex(6),
                    hex(5),
                ),
            ),
            "T" => controller.set_mode(
                index,
                Mode::Thunderbolt {
                    device_mode: hex(4),
                    cable_mode: hex(5),
                    enter_vdo: hex(6),
                },
            ),
            "U" => controller.set_mode(
                index,
                Mode::Usb4 {
                    enter_usb: hex(4),
                    active_link_training: dec(5) != 0,
                },
            ),
            "S" => controller.set_mode(index, Mode::Safe),
            "X" => controller.set_role(index, None),
            "B" => {
                let requests: [&[u8]; 5] = [
                    &[0x10, 1],
                    &[0x11, 1],
                    &[0x12],
                    &[0x13, 0x10, 0, 0, 0, 0, 0, 0],
                    &[0x14, 0],
                ];
                let message = requests[dec(1) as usize];
                let mut response = [0; 4];
                response[if message[0] & 15 < 2 { 2 } else { 1 }] = if dec(2) == 3 { 3 } else { 1 };
                hardware.borrow_mut().responses.extend(core::iter::repeat_n(
                    response,
                    if dec(2) == 1 {
                        2
                    } else if dec(2) == 2 {
                        3
                    } else {
                        1
                    },
                ));
                controller.send(message)
            }
            _ => unreachable!(),
        };
        let expected_result = parts[result_index].parse::<i32>().unwrap();
        match expected_result {
            0 => assert_eq!(result, Ok(()), "{line}"),
            -16 => assert!(
                matches!(result, Err(Error::Firmware { fatal: false, .. })),
                "{line}: {result:?}"
            ),
            -5 => assert!(
                matches!(result, Err(Error::Firmware { fatal: true, .. })),
                "{line}: {result:?}"
            ),
            _ => panic!("{line}"),
        }
        let expected_count = dec(result_index + 1) as usize;
        let expected: Vec<Vec<u8>> = parts[result_index + 2..]
            .iter()
            .map(|message| {
                message
                    .as_bytes()
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| {
                        u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap()
                    })
                    .collect()
            })
            .collect();
        assert_eq!(expected.len(), expected_count, "{line}");
        assert_eq!(hardware.borrow().requests, expected, "{line}");
        counts[group] += 1;
    }
    assert_eq!(counts, [216, 3264, 3104, 544, 10, 10, 15]);
}
