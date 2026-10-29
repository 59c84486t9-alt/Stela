// SPDX-License-Identifier: MIT
//! Independent completed-transfer/voice model; initialization receipts come
//! from the existing real firmware-selection/download command model.
use super::*;
use crate::{
    block::BlockError,
    bus::dma::DmaBuffer,
    usb::{
        bluetooth::{Binding, Io, Packet, Pipe},
        xhci,
    },
};
use alloc::{boxed::Box, collections::VecDeque, rc::Rc, vec, vec::Vec};
use core::cell::{Cell, RefCell};
use shared::{Kind, Pair};

struct NoDma;
impl DmaAllocator for NoDma {
    fn allocate(&mut self, _: usize, _: usize) -> core::result::Result<DmaBuffer, BlockError> {
        panic!("logical model owns no DMA")
    }
}
#[derive(Default)]
struct Trace {
    pairs: Vec<(Option<Pair>, Option<Pair>)>,
    writes: Vec<Vec<u8>>,
    actions: Vec<&'static str>,
}
#[derive(Default)]
struct Model {
    trace: Rc<RefCell<Trace>>,
    events: VecDeque<Vec<u8>>,
    reads: VecDeque<Read>,
    time: Cell<u64>,
    invalid: bool,
    fail_replace: bool,
    fail_stop: bool,
    fail_write: bool,
    reset_event: Option<Vec<u8>>,
    queued: VecDeque<(u64, usize)>,
    receipts: VecDeque<OutputReceipt>,
    queue_sequence: u64,
    complete_output: bool,
    fail_queue: bool,
    fail_output: bool,
}
impl Io for Model {
    fn validate(&self) -> core::result::Result<(), BlockError> {
        if self.invalid {
            Err(BlockError::Unsupported("retired model owner"))
        } else {
            Ok(())
        }
    }
    fn control(&mut self, _: [u8; 8], bytes: &[u8]) -> core::result::Result<(), BlockError> {
        assert_eq!(bytes, [3, 0x0c, 0]);
        self.trace.borrow_mut().actions.push("hci-reset");
        self.events.push_back(
            self.reset_event
                .clone()
                .unwrap_or(vec![0x0e, 4, 0, 3, 0x0c, 0]),
        );
        Ok(())
    }
    fn receive(&mut self, pipe: Pipe) -> core::result::Result<Option<Vec<u8>>, BlockError> {
        Ok(if pipe == Pipe::Event {
            self.events.pop_front()
        } else {
            None
        })
    }
    fn write_acl(&mut self, _: &[u8]) -> core::result::Result<(), BlockError> {
        Ok(())
    }
    fn quiesce_bulk(&mut self) -> core::result::Result<(), BlockError> {
        Ok(())
    }
    fn close(&mut self) -> core::result::Result<(), BlockError> {
        self.trace.borrow_mut().actions.push("base-close");
        if self.fail_stop {
            Err(BlockError::Timeout)
        } else {
            Ok(())
        }
    }
    fn now_us(&self) -> u64 {
        let n = self.time.get();
        self.time.set(n + 1000);
        n
    }
}
impl MediaIo for Model {
    fn queue_sco(&mut self, bytes: &[u8]) -> Result<Option<u64>> {
        if self.queued.len() == 4 {
            return Ok(None);
        }
        if self.fail_queue {
            return Err(BlockError::Timeout.into());
        }
        self.queue_sequence += 1;
        self.queued.push_back((self.queue_sequence, bytes.len()));
        self.trace.borrow_mut().writes.push(bytes.to_vec());
        Ok(Some(self.queue_sequence))
    }
    fn poll_sco_output(&mut self) -> Result<Option<OutputReceipt>> {
        if let Some(receipt) = self.receipts.pop_front() {
            return Ok(Some(receipt));
        }
        if !self.complete_output {
            return Ok(None);
        }
        if self.fail_output {
            return Err(Error::QueuedOutput {
                sequence: self.queued.front().unwrap().0,
                cause: Box::new(BlockError::Timeout.into()),
            });
        }
        Ok(self
            .queued
            .pop_front()
            .map(|(sequence, packet_bytes)| OutputReceipt {
                sequence,
                packet_bytes,
                disposition: OutputDisposition::Completed,
            }))
    }
    fn start_iso(
        &mut self,
        _: Pair,
        _: &mut dyn DmaAllocator,
    ) -> core::result::Result<(), BlockError> {
        panic!("Realtek SCO must never configure MediaTek third interface")
    }
    fn replace_sco(
        &mut self,
        old: Option<Pair>,
        next: Option<Pair>,
        _: &mut dyn DmaAllocator,
    ) -> core::result::Result<(), BlockError> {
        self.trace.borrow_mut().pairs.push((old, next));
        if self.fail_replace {
            Err(BlockError::Timeout)
        } else {
            Ok(())
        }
    }
    fn read_media(&mut self, kind: Kind) -> core::result::Result<Option<Read>, BlockError> {
        assert_eq!(kind, Kind::Sco);
        Ok(self.reads.pop_front())
    }
    fn write_media(&mut self, kind: Kind, bytes: &[u8]) -> Result<()> {
        assert_eq!(kind, Kind::Sco);
        self.trace.borrow_mut().writes.push(bytes.to_vec());
        if self.fail_write {
            Err(BlockError::Timeout.into())
        } else {
            Ok(())
        }
    }
    fn quiesce_media(&mut self) -> core::result::Result<(), BlockError> {
        self.trace.borrow_mut().actions.push("quiesce");
        if self.fail_stop {
            Err(BlockError::Timeout)
        } else {
            self.receipts
                .extend(
                    self.queued
                        .drain(..)
                        .map(|(sequence, packet_bytes)| OutputReceipt {
                            sequence,
                            packet_bytes,
                            disposition: OutputDisposition::RetiredUnconfirmed,
                        }),
                );
            Ok(())
        }
    }
    fn reset_media_epoch(&mut self) -> core::result::Result<(), BlockError> {
        self.trace.borrow_mut().actions.push("voice-epoch-retired");
        self.reads.clear();
        if self.fail_stop {
            Err(BlockError::Timeout)
        } else {
            Ok(())
        }
    }
    fn resume_media(&mut self) -> core::result::Result<(), BlockError> {
        self.trace.borrow_mut().actions.push("resume");
        Ok(())
    }
    fn close_media(&mut self) -> core::result::Result<(), BlockError> {
        self.trace.borrow_mut().actions.push("media-close");
        if self.fail_stop {
            Err(BlockError::Timeout)
        } else {
            Ok(())
        }
    }
}
fn hci(project: super::super::Project, model: Model) -> Hci<Model> {
    let report = super::super::tests::initialized_report(project);
    let mut device = crate::usb::bluetooth::mediatek::media::tests::binding()
        .device()
        .clone();
    device.descriptor[8..10].copy_from_slice(&report.before.usb.vendor.to_le_bytes());
    device.descriptor[10..12].copy_from_slice(&report.before.usb.product.to_le_bytes());
    device.descriptor[12..14].copy_from_slice(&report.before.usb.revision.to_le_bytes());
    let binding = Binding::new(&device, &xhci::interfaces(&device.configuration)[0]).unwrap();
    let mut hci = Hci::from_io(binding, model);
    hci.initialization = Some(Box::new(Ok(InitializationReport::Realtek(report))));
    hci
}
fn voice(links: u8, setting: u16) -> Voice {
    Voice {
        connections: links,
        air_mode: AirMode::Cvsd,
        voice_setting: setting,
    }
}
fn session(model: Model) -> Session<Model> {
    Session::start(hci(super::super::Project::Rtl8761Bu, model)).unwrap()
}
fn wideband_hci(project: super::super::Project, model: Model, mask: u8) -> Hci<Model> {
    let mut h = hci(project, model);
    let raw = &h.binding.device.configuration;
    let mut next = Vec::new();
    let mut at = 0;
    let mut keep = true;
    let mut alt6 = false;
    while at < raw.len() {
        let n = usize::from(raw[at]);
        let mut descriptor = raw[at..at + n].to_vec();
        if descriptor[1] == 4 {
            keep = descriptor[2] != 1 || mask & (1 << descriptor[3]) != 0;
            alt6 = descriptor[2..4] == [1, 6];
        }
        if alt6 && descriptor[1] == 5 {
            descriptor[4..7].copy_from_slice(&[63, 0, 4]);
        }
        if keep {
            next.extend_from_slice(&descriptor);
        }
        at += n;
    }
    let len = next.len() as u16;
    next[2..4].copy_from_slice(&len.to_le_bytes());
    h.binding.device.configuration = next;
    h
}
#[test]
fn realtek_wideband_uses_observed_mtu_source_alternates_and_actual_capability() {
    for project in [
        super::super::Project::Rtl8761Bu,
        super::super::Project::Rtl8852Bu,
    ] {
        for (mask, mtu, expected) in [(127, 60, 6), (63, 71, 1), (63, 72, 3), (55, 255, 1)] {
            let mut s = Session::start(wideband_hci(project, Model::default(), mask)).unwrap();
            s.set_wideband_voice(1, mtu, &mut NoDma).unwrap();
            assert_eq!(
                s.0.hci
                    .io
                    .trace
                    .borrow()
                    .pairs
                    .last()
                    .unwrap()
                    .1
                    .unwrap()
                    .alternate,
                expected
            );
            assert!(s.submit_sco(&[1, 0, 0]).is_err()); // sync output cannot establish mSBC cadence
        }
    }
    let mut s = Session::start(wideband_hci(
        super::super::Project::Rtl8822B,
        Model::default(),
        127,
    ))
    .unwrap();
    assert!(s.set_wideband_voice(1, 72, &mut NoDma).is_err());
    assert!(s.0.hci.io.trace.borrow().pairs.is_empty());
    let mut h = wideband_hci(super::super::Project::Rtl8761Bu, Model::default(), 127);
    h.binding.device.descriptor[10..12].copy_from_slice(&0xa728u16.to_le_bytes());
    if let Some(Ok(InitializationReport::Realtek(r))) = h.initialization.as_deref_mut() {
        r.before.usb.product = 0xa728;
    }
    let mut s = Session::start(h).unwrap();
    assert!(s.set_wideband_voice(1, 72, &mut NoDma).is_err());
    // The same descriptor profile previously used only by CVSD models
    // advertises alt6 at 125us with 102 bytes; it cannot encode source 7/8ms WBS.
    let mut s = session(Model::default());
    assert!(s.set_wideband_voice(1, 60, &mut NoDma).is_err());
}
#[test]
fn realtek_wideband_acceptance_backpressure_completion_and_retirement_are_distinct() {
    let mut s = Session::start(wideband_hci(
        super::super::Project::Rtl8761Bu,
        Model::default(),
        127,
    ))
    .unwrap();
    s.set_wideband_voice(1, 60, &mut NoDma).unwrap();
    let mut packet = vec![0x5a; 63];
    packet[..3].copy_from_slice(&[1, 0, 60]);
    for seq in 1..=4 {
        assert_eq!(s.queue_sco(&packet).unwrap(), Some(seq));
    }
    assert_eq!(s.queue_sco(&packet).unwrap(), None);
    assert_eq!(s.lifecycle(), Lifecycle::Running);
    assert_eq!(s.poll_sco_output().unwrap(), None);
    s.0.hci.io.complete_output = true;
    assert_eq!(
        s.poll_sco_output().unwrap(),
        Some(OutputReceipt {
            sequence: 1,
            packet_bytes: 63,
            disposition: OutputDisposition::Completed
        })
    );
    s.quiesce().unwrap();
    for sequence in 2..=4 {
        assert_eq!(
            s.poll_sco_output().unwrap(),
            Some(OutputReceipt {
                sequence,
                packet_bytes: 63,
                disposition: OutputDisposition::RetiredUnconfirmed
            })
        );
    }
    s.resume().unwrap();
    packet.push(1);
    packet[2] = 61;
    assert!(s.queue_sco(&packet).is_err());
    assert_eq!(s.lifecycle(), Lifecycle::Running);
    s.set_voice(voice(1, 0), &mut NoDma).unwrap();
    s.submit_sco(&[1, 0, 0]).unwrap();
}
#[test]
fn realtek_wideband_partial_publication_and_failed_completion_remain_terminal() {
    for completion in [false, true] {
        let mut s = Session::start(wideband_hci(
            super::super::Project::Rtl8761Bu,
            Model::default(),
            127,
        ))
        .unwrap();
        s.set_wideband_voice(1, 60, &mut NoDma).unwrap();
        s.0.hci.io.fail_stop = true;
        let error = if completion {
            assert_eq!(s.queue_sco(&[1, 0, 0]).unwrap(), Some(1));
            s.0.hci.io.complete_output = true;
            s.0.hci.io.fail_output = true;
            s.poll_sco_output().unwrap_err()
        } else {
            s.0.hci.io.fail_queue = true;
            s.queue_sco(&[1, 0, 0]).unwrap_err()
        };
        assert!(matches!(
            error,
            Error::Cleanup {
                media: Some(BlockError::Timeout),
                base: Some(_),
                ..
            }
        ));
        assert_eq!(s.lifecycle(), Lifecycle::Failed);
        assert!(s.poll_sco_output().is_err());
        assert!(s.resume().is_err());
    }
}
#[test]
fn realtek_wideband_matches_292_unchanged_linux_selection_and_service_records() {
    let mut selections = 0;
    let mut packets = 0;
    for line in include_str!("../../../../../tests/reference/realtek-wideband.txt").lines() {
        let columns: Vec<_> = line.split_whitespace().collect();
        let values: Vec<usize> = columns[1..].iter().map(|v| v.parse().unwrap()).collect();
        match columns[0] {
            "W" => {
                let h = wideband_hci(
                    super::super::Project::Rtl8761Bu,
                    Model::default(),
                    values[0] as u8,
                );
                let b = shared::Bindings::realtek_sco(h.binding()).unwrap();
                let p = b.wideband_sco(values[2] as u8, values[1] as u16).unwrap();
                assert_eq!(p.map_or(0, |p| usize::from(p.alternate)), values[3]);
                selections += 1;
            }
            "P" => {
                let actual =
                    super::output_lengths(values[0], 63, Some(!values[1].is_multiple_of(2)))
                        .unwrap();
                assert_eq!(actual.len(), values[2]);
                assert_eq!(actual, values[3..]);
                packets += 1;
            }
            kind => panic!("unknown donor record {kind}"),
        }
    }
    assert_eq!((selections, packets), (48, 244));
}
#[test]
fn realtek_cvsd_matches_eight_unchanged_linux_voice_records() {
    let h = hci(super::super::Project::Rtl8761Bu, Model::default());
    let bindings = shared::Bindings::realtek_sco(h.binding()).unwrap();
    let mut count = 0;
    for line in include_str!("../../../../../tests/reference/realtek-sco.csv").lines() {
        let values: Vec<u16> = line.split(',').map(|v| v.parse().unwrap()).collect();
        let pair = bindings.sco(voice(values[1] as u8, values[0])).unwrap();
        assert_eq!(pair.map_or(0, |p| u16::from(p.alternate)), values[2]);
        count += 1;
    }
    assert_eq!(count, 8);
}
#[test]
fn realtek_all_initialized_profiles_select_source_cvsd_alternates_without_vendor_setup() {
    for project in [
        super::super::Project::Rtl8761Bu,
        super::super::Project::Rtl8822B,
        super::super::Project::Rtl8852Bu,
    ] {
        let mut session = Session::start(hci(project, Model::default())).unwrap();
        assert!(session.0.hci.io.trace.borrow().actions.is_empty());
        assert_eq!(session.initialization().before.project, project);
        for (links, bits, alternate) in [
            (1, 0, 1),
            (2, 0, 2),
            (3, 0, 3),
            (1, 0x20, 2),
            (2, 0x20, 4),
            (3, 0x20, 5),
        ] {
            session.set_voice(voice(links, bits), &mut NoDma).unwrap();
            assert_eq!(
                session
                    .0
                    .hci
                    .io
                    .trace
                    .borrow()
                    .pairs
                    .last()
                    .unwrap()
                    .1
                    .unwrap()
                    .alternate,
                alternate
            );
            session.submit_sco(&[1, 0, 2, 9, 8]).unwrap();
            assert_eq!(
                session.0.hci.io.trace.borrow().writes.last().unwrap(),
                &[1, 0, 2, 9, 8]
            );
        }
        session.set_voice(voice(0, 0), &mut NoDma).unwrap();
        assert!(session.submit_sco(&[1, 0, 0]).is_err());
        let before = session.0.hci.io.trace.borrow().pairs.len();
        assert!(
            session
                .set_voice(
                    Voice {
                        air_mode: AirMode::Transparent,
                        ..voice(1, 0)
                    },
                    &mut NoDma
                )
                .is_err()
        );
        assert!(session.set_voice(voice(4, 0), &mut NoDma).is_err());
        assert_eq!(session.0.hci.io.trace.borrow().pairs.len(), before);
        assert_eq!(session.lifecycle(), Lifecycle::Running);
    }
}
#[test]
fn realtek_split_coalesced_sco_and_loss_retain_hci_and_retire_partials() {
    let mut s = session(Model::default());
    s.set_voice(voice(1, 0), &mut NoDma).unwrap();
    s.0.hci.io.events.push_back(vec![0xff, 1, 0x55]);
    s.0.hci.io.reads.extend([
        Read::Data(vec![1, 0, 2, 7]),
        Read::Data(vec![8, 2, 0, 1, 9]),
    ]);
    assert_eq!(
        s.poll().unwrap(),
        [Received::Hci(Packet::Event(vec![0xff, 1, 0x55]))]
    );
    assert_eq!(
        s.poll().unwrap(),
        [
            Received::Sco(vec![1, 0, 2, 7, 8]),
            Received::Sco(vec![2, 0, 1, 9])
        ]
    );
    for loss in [
        Loss::MissedService,
        Loss::Transaction,
        Loss::Babble,
        Loss::Bandwidth,
        Loss::BufferOverrun,
    ] {
        s.0.hci.io.reads.extend([
            Read::Data(vec![1, 0, 5, 7]),
            Read::Loss(loss),
            Read::Data(vec![2, 0, 1, 9]),
        ]);
        assert!(s.poll().unwrap().is_empty());
        assert_eq!(s.poll().unwrap(), [Received::Loss(Kind::Sco, loss)]);
        assert_eq!(s.poll().unwrap(), [Received::Sco(vec![2, 0, 1, 9])]);
    }
    s.0.hci.io.reads.push_back(Read::Data(vec![1, 0, 4, 7]));
    s.poll().unwrap();
    s.quiesce().unwrap();
    assert!(s.poll().is_err());
    s.resume().unwrap();
    s.0.hci.io.reads.push_back(Read::Data(vec![2, 0, 1, 9]));
    assert_eq!(s.poll().unwrap(), [Received::Sco(vec![2, 0, 1, 9])]);
}
#[test]
fn realtek_reset_requires_real_completion_retires_voice_and_preserves_zero_credits() {
    let mut s = session(Model::default());
    s.set_voice(voice(1, 0), &mut NoDma).unwrap();
    s.0.hci.io.reads.push_back(Read::Data(vec![1, 0, 3, 9]));
    s.poll().unwrap();
    s.submit_command(&[3, 0x0c, 0]).unwrap();
    assert_eq!(s.last_reset().unwrap().command_credits, 0);
    assert_eq!(
        s.poll().unwrap(),
        [Received::Hci(Packet::Event(vec![0x0e, 4, 0, 3, 0x0c, 0]))]
    );
    assert!(s.submit_sco(&[1, 0, 0]).is_err());
    assert_eq!(
        s.0.hci.io.trace.borrow().actions,
        ["voice-epoch-retired", "hci-reset", "resume"]
    );
    for event in [
        vec![0x0f, 4, 0, 1, 3, 0x0c],
        vec![0x0e, 4, 1, 3, 0x0c, 0x0c],
        vec![0x0e, 3, 1, 3, 0x0c],
    ] {
        let mut s = session(Model {
            reset_event: Some(event),
            ..Model::default()
        });
        assert!(s.submit_command(&[3, 0x0c, 0]).is_err());
        assert_eq!(s.lifecycle(), Lifecycle::Failed);
        assert!(s.resume().is_err());
    }
}
#[test]
fn realtek_failure_keeps_first_error_cleanup_and_terminal_ownership() {
    for stage in 0..3 {
        let mut s = session(Model::default());
        s.set_voice(voice(1, 0), &mut NoDma).unwrap();
        s.0.hci.io.fail_stop = true;
        let error = match stage {
            0 => {
                s.0.hci.io.fail_replace = true;
                s.set_voice(voice(2, 0), &mut NoDma).unwrap_err()
            }
            1 => {
                s.0.hci.io.fail_write = true;
                s.submit_sco(&[1, 0, 1, 9]).unwrap_err()
            }
            _ => s.quiesce().unwrap_err(),
        };
        assert!(matches!(
            error,
            Error::Cleanup {
                media: Some(BlockError::Timeout),
                base: Some(_),
                ..
            }
        ));
        assert_eq!(s.lifecycle(), Lifecycle::Failed);
        assert!(s.resume().is_err());
        assert!(s.close().is_err());
        assert!(s.poll().is_err());
        assert!(
            s.0.hci
                .io
                .trace
                .borrow()
                .actions
                .ends_with(&["media-close", "base-close"])
        );
    }
}
#[test]
fn realtek_uninitialized_wrong_report_retired_and_aliased_descriptors_refuse() {
    let mut h = hci(super::super::Project::Rtl8761Bu, Model::default());
    h.initialization = None;
    let trace = h.io.trace.clone();
    assert!(Session::start(h).is_err());
    assert!(
        trace
            .borrow()
            .actions
            .ends_with(&["media-close", "base-close"])
    );
    let mut h = hci(super::super::Project::Rtl8761Bu, Model::default());
    if let Some(Ok(InitializationReport::Realtek(report))) = h.initialization.as_deref_mut() {
        report.before.usb.product ^= 1;
    }
    assert!(Session::start(h).is_err());
    let mut s = session(Model::default());
    s.0.hci.io.invalid = true;
    let before = s.0.hci.io.trace.borrow().actions.clone();
    assert!(s.set_voice(voice(1, 0), &mut NoDma).is_err());
    assert!(s.poll().is_err());
    assert!(s.close().is_err());
    assert_eq!(s.0.hci.io.trace.borrow().actions, before);
    let mut h = hci(super::super::Project::Rtl8761Bu, Model::default());
    // Mutate kept configuration: SCO endpoint 0x83 aliases the
    // unclaimed third interface, which must remain outside this driver's owner.
    let cfg = &mut h.binding.device.configuration;
    let i = cfg
        .windows(7)
        .position(|b| b == [7, 5, 0x85, 3, 0, 2, 1])
        .unwrap();
    cfg[i + 2] = 0x83;
    assert!(Session::start(h).is_err());
}
