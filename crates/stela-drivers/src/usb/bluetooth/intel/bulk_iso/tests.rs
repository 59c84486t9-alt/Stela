// SPDX-License-Identifier: MIT
//! Independent command peer plus actual native xHCI bulk ownership controls.
use super::*;
use crate::{
    block::BlockError,
    usb::{
        bluetooth::{Binding, Pipe},
        xhci,
    },
};
use alloc::{collections::VecDeque, vec, vec::Vec};
use core::cell::Cell;

fn cc(opcode: u16, credits: u8, returned: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x0e, (returned.len() + 3) as u8, credits];
    bytes.extend_from_slice(&opcode.to_le_bytes());
    bytes.extend_from_slice(returned);
    bytes
}
fn version(variant: u8) -> Vec<u8> {
    crate::bluetooth::intel::tests::tlv_version_variant(true, 0, variant)
}
fn device() -> xhci::Device {
    let mut device = crate::bluetooth::intel::tests::fixture().0;
    device.descriptor[10..12].copy_from_slice(&0x0032u16.to_le_bytes());
    device
}
fn binding(device: &xhci::Device) -> Binding {
    Binding::new(device, &xhci::interfaces(&device.configuration)[0]).unwrap()
}
fn initialize<B: Io>(hci: &mut Hci<B>) {
    let empty = crate::firmware::Catalog::from_handoff(vec![]).unwrap();
    hci.initialize_with_provider(&empty, super::super::PlatformInputs::default())
        .unwrap();
}
struct Model {
    script: VecDeque<(u16, Vec<Vec<u8>>)>,
    events: VecDeque<Vec<u8>>,
    acl: VecDeque<Vec<u8>>,
    sent: Vec<Vec<u8>>,
    commands: Vec<u16>,
    clock: Cell<u64>,
    step: u64,
    close_error: bool,
    close_count: usize,
    output_error: bool,
    reads: usize,
    deny_after_reset: bool,
    read_allowance: Option<usize>,
}
impl Model {
    fn new(variant: u8) -> Self {
        Self {
            script: [
                (0xfc05, vec![cc(0xfc05, 1, &version(variant))]),
                (0x1009, vec![cc(0x1009, 1, &[0, 1, 2, 3, 4, 5, 6])]),
                (0xfc05, vec![cc(0xfc05, 1, &version(variant))]),
            ]
            .into(),
            events: VecDeque::new(),
            acl: VecDeque::new(),
            sent: vec![],
            commands: vec![],
            clock: Cell::new(0),
            step: 1,
            close_error: false,
            close_count: 0,
            output_error: false,
            reads: 0,
            deny_after_reset: false,
            read_allowance: None,
        }
    }
    fn configuration(&mut self, feature: u8, credits: u8) {
        self.script.extend([
            (0x0c03, vec![cc(0x0c03, credits, &[0])]),
            (
                0x2003,
                vec![cc(0x2003, 1, &[0, 0, 0, 0, feature, 0, 0, 0, 0])],
            ),
            (0x2060, vec![cc(0x2060, 0, &[0, 0xfb, 0, 4, 0xfb, 0, 3])]),
        ]);
    }
}
impl Io for Model {
    fn validate(&self) -> Result<(), BlockError> {
        Ok(())
    }
    fn control(&mut self, setup: [u8; 8], packet: &[u8]) -> Result<(), BlockError> {
        assert_eq!(setup[0..6], [0x20, 0, 0, 0, 0, 0]);
        let opcode = u16::from_le_bytes([packet[0], packet[1]]);
        self.commands.push(opcode);
        if opcode == 0x0c03 && self.deny_after_reset {
            self.read_allowance = Some(2);
        }
        let (expected, replies) = self.script.pop_front().expect("unexpected real command");
        assert_eq!(opcode, expected);
        self.events.extend(replies);
        Ok(())
    }
    fn receive(&mut self, pipe: Pipe) -> Result<Option<Vec<u8>>, BlockError> {
        self.reads += 1;
        if let Some(left) = &mut self.read_allowance {
            if *left == 0 {
                return Err(BlockError::Timeout);
            }
            *left -= 1;
        }
        Ok(match pipe {
            Pipe::Event => self.events.pop_front(),
            Pipe::Acl => self.acl.pop_front(),
        })
    }
    fn write_acl(&mut self, packet: &[u8]) -> Result<(), BlockError> {
        self.sent.push(packet.to_vec());
        if self.output_error {
            Err(BlockError::Timeout)
        } else {
            Ok(())
        }
    }
    fn quiesce_bulk(&mut self) -> Result<(), BlockError> {
        Ok(())
    }
    fn close(&mut self) -> Result<(), BlockError> {
        self.close_count += 1;
        if self.close_error {
            Err(BlockError::Timeout)
        } else {
            Ok(())
        }
    }
    fn now_us(&self) -> u64 {
        let now = self.clock.get();
        self.clock.set(now.wrapping_add(self.step));
        now
    }
}
fn hci(variant: u8) -> Hci<Model> {
    let mut hci = Hci::from_io(binding(&device()), Model::new(variant));
    initialize(&mut hci);
    hci
}
fn session(variant: u8) -> Session<Model> {
    let mut hci = hci(variant);
    hci.io.configuration(0x10, 1);
    Session::start(hci, 1).unwrap()
}

#[test]
fn intel_bulk_iso_uses_actual_initialized_capabilities_and_retains_original_responses() {
    for variant in [0x18, 0x1c] {
        let owner = session(variant);
        assert_eq!(owner.report().hardware_variant, variant);
        assert_eq!(
            (
                owner.report().iso_mtu,
                owner.report().iso_packets,
                owner.report().command_credits
            ),
            (251, 3, 0)
        );
        assert_eq!(owner.report().received.len(), 3);
        assert_eq!(
            owner.hci.io.commands,
            [0xfc05, 0x1009, 0xfc05, 0x0c03, 0x2003, 0x2060]
        );
        assert!(matches!(
            owner.initialization().evidence,
            super::super::OwnedFirmwareEvidence::RunningUnknown
        ));
    }
    for variant in [0x17, 0x19, 0x1b, 0x1d, 0x1e, 0x22] {
        let mut h = hci(variant);
        assert!(matches!(profile(&h), Err(Error::Unsupported(_))));
        assert_eq!(h.io.commands.len(), 3);
        h.close().unwrap();
    }
    let raw = Hci::from_io(binding(&device()), Model::new(0x18));
    assert!(matches!(profile(&raw), Err(Error::Unsupported(_))));
    let mut changed = hci(0x18);
    changed.binding.device.descriptor[12] ^= 1;
    assert!(matches!(profile(&changed), Err(Error::Unsupported(_))));
    assert_eq!(changed.io.commands.len(), 3);
}

#[test]
fn intel_bulk_iso_matches_source_capability_handle_flags_and_preserves_bulk_framing() {
    let mut owner = session(0x18);
    // A complete timestamped packet retains its inner lost-SDU status. The
    // complete outer transport length remains8; no inner-status mask applies.
    let iso = vec![
        0x00, 0x49, 8, 0, 0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0, 0x80,
    ];
    let acl = vec![0xff, 0x38, 1, 0, 0x55];
    let mut chunks = acl.clone();
    chunks.extend(&iso);
    owner.hci.io.acl.extend([
        chunks[..3].to_vec(),
        chunks[3..9].to_vec(),
        chunks[9..].to_vec(),
    ]);
    assert!(owner.poll().unwrap().is_empty());
    assert_eq!(owner.poll().unwrap(), [Received::Acl(acl)]);
    assert_eq!(owner.poll().unwrap(), [Received::Iso(iso.clone())]);
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    let mut report = owner.report().clone();
    let mut records = 0;
    for feature in 0..=255u8 {
        report.features[3] = feature;
        for packet_type in 2..=5u8 {
            for flags in 0..16u16 {
                for handle in [0, 1, 0x8fe, 0x8ff, 0x900, 0x901, 0xeff, 0xfff] {
                    let raw = handle | (flags << 12);
                    let bytes = [raw as u8, (raw >> 8) as u8, 0, 0];
                    let iso = is_iso(&report, &bytes);
                    assert_eq!(iso, feature & 0x70 != 0 && handle >= 0x900);
                    digest.update([if packet_type == 2 && iso {
                        5
                    } else {
                        packet_type
                    }]);
                    records += 1;
                }
            }
        }
    }
    assert_eq!(records, 131072);
    // Complete unchanged original classifier/capability predicates, executed
    // with ASan/UBSan by tests/reference/intel_bulk_iso_oracle.py.
    assert_eq!(
        alloc::format!("{:x}", digest.finalize()),
        "61a04054588f89490df1e25c17c60ce04097c6f0704870a0f4c811a997e9d2d8"
    );
    let mut credits = 3;
    owner.submit_iso(&iso, &mut credits).unwrap();
    assert_eq!(credits, 2);
    assert_eq!(owner.hci.io.sent, [iso]);
    owner.submit_acl(&[1, 0x20, 1, 0, 0x42]).unwrap();
    assert_eq!(owner.hci.io.sent.len(), 2);
}

#[test]
fn intel_bulk_iso_validation_has_no_effects_and_delivery_failure_retains_debit_and_bytes() {
    let mut owner = session(0x18);
    let good = vec![0, 9, 1, 0, 0xaa];
    for (packet, mut credits) in [
        (vec![], 3),
        (vec![0, 9, 2, 0, 0xaa], 3),
        (vec![0, 8, 0, 0], 3),
        (good.clone(), 0),
        (good.clone(), 4),
    ] {
        let before = credits;
        assert!(owner.submit_iso(&packet, &mut credits).is_err());
        assert_eq!(credits, before);
    }
    let mut too_big = vec![0; 256];
    too_big[..4].copy_from_slice(&[0, 9, 252, 0]);
    let mut credits = 3;
    assert!(owner.submit_iso(&too_big, &mut credits).is_err());
    assert!(owner.submit_acl(&good).is_err());
    assert!(owner.hci.io.sent.is_empty());
    assert_eq!(credits, 3);
    owner.hci.io.output_error = true;
    owner.hci.io.close_error = true;
    let Error::Output { cause, packet } = owner.submit_iso(&good, &mut credits).unwrap_err() else {
        panic!()
    };
    assert_eq!(packet, good);
    assert_eq!(credits, 2);
    assert_eq!(cause.cleanup, Some(BlockError::Timeout));
    assert_eq!(owner.state(), State::Failed);
    let count = owner.hci.io.sent.len();
    assert!(owner.submit_iso(&good, &mut credits).is_err());
    assert_eq!(owner.hci.io.sent.len(), count);
    assert_eq!(credits, 2);
}

#[test]
fn intel_bulk_iso_zero_credits_require_actual_nop_and_complete_never_status_only() {
    let mut h = hci(0x18);
    h.io.configuration(0x20, 0);
    h.io.script[0].1.push(cc(0, 1, &[]));
    let owner = Session::start(h, 1).unwrap();
    assert_eq!(owner.report.iso_mtu, 251);
    for case in 0..8 {
        let mut h = hci(0x18);
        h.io.configuration(0x10, 1);
        h.io.step = 250_000;
        match case {
            0 => h.io.script[0].1 = vec![vec![0x0f, 4, 0, 1, 3, 0x0c]],
            1 => h.io.script[0].1 = vec![cc(0x0c03, 1, &[0x0c])],
            2 => h.io.script[0].1 = vec![cc(0x0c03, 1, &[0, 0])],
            3 => h.io.script[1].1 = vec![cc(0x2003, 1, &[0, 0, 0, 0, 0x80, 0, 0, 0, 0])],
            4 => h.io.script[2].1 = vec![cc(0x2060, 1, &[0, 0xfb, 0, 4, 0, 0, 3])],
            5 => h.io.script[2].1 = vec![cc(0x2060, 1, &[0, 0xfb, 0, 4, 0xfb, 0, 0])],
            6 => h.io.script[0].1 = vec![cc(0x2003, 1, &[0])],
            _ => {
                let cc = cc(0x0c03, 1, &[0]);
                let mut twice = cc.clone();
                twice.extend(cc);
                twice.extend([0xff, 1, 0x42]);
                h.io.script[0].1 = vec![twice];
            }
        }
        let Error::Failed {
            cause: _,
            attempt,
            cleanup: _,
        } = (match Session::start(h, 1) {
            Err(e) => e,
            Ok(_) => panic!("case{case}"),
        })
        else {
            panic!()
        };
        assert!(!attempt.submitted.is_empty());
        assert!(!attempt.received.is_empty());
        if case == 7 {
            assert_eq!(attempt.received.len(), 3);
            assert_eq!(attempt.received[2], Packet::Event(vec![0xff, 1, 0x42]));
        }
    }
}

#[test]
fn intel_bulk_iso_reset_reprobes_real_capability_and_partial_frames_refuse_before_commands() {
    let mut owner = session(0x18);
    assert!(owner.submit_command(&[3, 0x0c, 0]).is_err());
    assert!(owner.submit_command(&[1, 0xfc, 0]).is_err());
    owner.hci.io.configuration(0x40, 1);
    let report = owner.reset(1).unwrap();
    assert_eq!(report.features[3], 0x40);
    owner.hci.io.acl.push_back(vec![0, 9, 4]);
    assert!(owner.poll().unwrap().is_empty());
    let before = owner.hci.io.commands.len();
    assert!(owner.reset(1).is_err());
    assert_eq!(owner.hci.io.commands.len(), before);
    owner.close().unwrap();
    assert_eq!(owner.state(), State::Closed);
}

#[test]
fn intel_bulk_iso_uses_real_native_bulk_dma_and_retains_failed_short_transfer() {
    use crate::bus::dma::RegionAllocator;
    use alloc::rc::Rc;
    use core::cell::RefCell;
    for failed_retirement in [false, true] {
        let mut backing = vec![0u64; 64 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: exclusive aligned model DMA remains live through every owner.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (controller, model) = xhci::model::cancellation_controller(&mut dma);
        let controller = Rc::new(RefCell::new(controller));
        let mut d = device();
        d.id = controller.borrow().test_device_id(1).unwrap();
        model.borrow_mut().incoming_events.extend([
            cc(0xfc05, 1, &version(0x18)),
            cc(0x1009, 1, &[0, 1, 2, 3, 4, 5, 6]),
            cc(0xfc05, 1, &version(0x18)),
            cc(0x0c03, 1, &[0]),
            cc(0x2003, 1, &[0, 0, 0, 0, 0x10, 0, 0, 0, 0]),
            cc(0x2060, 1, &[0, 0xfb, 0, 4, 0xfb, 0, 3]),
        ]);
        let mut h = Hci::attach(controller, &d, binding(&d), &mut dma).unwrap();
        initialize(&mut h);
        let mut owner = Session::start(h, 1).unwrap();
        let iso = vec![0, 0x49, 8, 0, 0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0, 0x80];
        let mut credits = 3;
        owner.submit_iso(&iso, &mut credits).unwrap();
        assert_eq!(model.borrow().outgoing.last(), Some(&iso));
        assert_eq!(credits, 2);
        model
            .borrow_mut()
            .incoming_acl
            .extend([iso[..3].to_vec(), iso[3..].to_vec()]);
        assert!(owner.poll().unwrap().is_empty());
        assert_eq!(owner.poll().unwrap(), [Received::Iso(iso.clone())]);
        if failed_retirement {
            model.borrow_mut().short_bulk_out = true;
            model.borrow_mut().fail = Some((15, 19));
            let Error::Output { cause, packet } = owner.submit_iso(&iso, &mut credits).unwrap_err()
            else {
                panic!()
            };
            assert_eq!(packet, iso);
            assert!(cause.cleanup.is_some());
            assert_eq!(credits, 1);
            assert_eq!(owner.state(), State::Failed);
            let before = backing.clone();
            let sent = model.borrow().outgoing.len();
            assert!(owner.submit_iso(&iso, &mut credits).is_err());
            assert_eq!(backing, before);
            assert_eq!(model.borrow().outgoing.len(), sent);
            assert_eq!(credits, 1);
        } else {
            model
                .borrow_mut()
                .incoming_events
                .push_back(cc(0x0c03, 0, &[0]));
            let report = owner.shutdown(1).unwrap();
            assert!(report.transport_retired);
            assert_eq!(report.command_credits, 0);
            assert_eq!(report.received, [Packet::Event(cc(0x0c03, 0, &[0]))]);
        }
    }
}

#[test]
fn intel_shutdown_keeps_actual_zero_credit_reset_and_async_before_any_close_failure() {
    for failed_close in [false, true] {
        let mut owner = session(0x18);
        let before = owner.hci.io.reads;
        owner.hci.io.deny_after_reset = true;
        owner.hci.io.close_error = failed_close;
        let mut wire = vec![0xff, 1, 0x42];
        wire.extend(cc(0x0c03, 0, &[0]));
        wire.extend([0xff, 1, 0x43]);
        owner.hci.io.script.push_back((0x0c03, vec![wire]));
        assert_eq!(owner.shutdown(1).is_err(), failed_close);
        let report = owner.shutdown_report().unwrap();
        assert_eq!(report.command_credits, 0);
        assert_eq!(report.transport_retired, !failed_close);
        assert_eq!(
            report.received,
            [
                Packet::Event(vec![0xff, 1, 0x42]),
                Packet::Event(cc(0x0c03, 0, &[0])),
                Packet::Event(vec![0xff, 1, 0x43])
            ]
        );
        assert_eq!(owner.hci.io.reads, before + 2); // No destructive live postReset read.
        let commands = owner.hci.io.commands.len();
        assert!(owner.shutdown(1).is_err());
        assert_eq!(owner.hci.io.commands.len(), commands);
        assert!(owner.shutdown_report().is_some());
    }
}

#[test]
fn intel_shutdown_never_treats_status_or_failed_reset_as_successful_retirement() {
    for case in 0..3 {
        let mut owner = session(0x18);
        owner.hci.io.step = 250_000;
        let reply = match case {
            0 => vec![0x0f, 4, 0, 1, 3, 0x0c],
            1 => cc(0x0c03, 1, &[0x0c]),
            _ => cc(0x0c03, 1, &[0, 0]),
        };
        owner.hci.io.script.push_back((0x0c03, vec![reply.clone()]));
        let Error::Failed { attempt, .. } = owner.shutdown(1).unwrap_err() else {
            panic!()
        };
        assert_eq!(attempt.received, [Packet::Event(reply)]);
        assert_eq!(attempt.submitted, [0x0c03]);
        assert!(owner.shutdown_report().is_none());
        assert_ne!(owner.state(), State::Open);
    }
}
