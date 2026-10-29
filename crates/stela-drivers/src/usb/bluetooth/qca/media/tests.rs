// SPDX-License-Identifier: MIT
//! QCA live-report admission and source shutdown over an independent USB peer.
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
        panic!("logical QCA peer has no DMA")
    }
}
#[derive(Default)]
struct Trace {
    actions: Vec<&'static str>,
    pairs: Vec<Option<Pair>>,
    sco: Vec<Vec<u8>>,
}
#[derive(Default)]
struct Model {
    trace: Rc<RefCell<Trace>>,
    events: VecDeque<Vec<u8>>,
    reads: VecDeque<Read>,
    time: Cell<u64>,
    reset: Option<Vec<u8>>,
    fail_close: bool,
    queued: VecDeque<OutputReceipt>,
    sequence: u64,
    fail_post_reset_read: bool,
    reset_seen: bool,
    reset_batch_done: bool,
    reads_after_reset: usize,
    receipt_fail_after: Option<usize>,
    receipts_read: usize,
}
impl Io for Model {
    fn validate(&self) -> core::result::Result<(), BlockError> {
        Ok(())
    }
    fn control(&mut self, _: [u8; 8], bytes: &[u8]) -> core::result::Result<(), BlockError> {
        assert_eq!(bytes, [3, 0x0c, 0]);
        self.trace.borrow_mut().actions.push("reset");
        self.events
            .push_back(self.reset.clone().unwrap_or(vec![0x0e, 4, 0, 3, 0x0c, 0]));
        Ok(())
    }
    fn receive(&mut self, pipe: Pipe) -> core::result::Result<Option<Vec<u8>>, BlockError> {
        if self.fail_post_reset_read && self.reset_batch_done {
            self.reads_after_reset += 1;
            return Err(BlockError::Timeout);
        }
        Ok(if pipe == Pipe::Event {
            let packet = self.events.pop_front();
            if packet.as_ref().is_some_and(|bytes| {
                bytes.len() >= 5 && bytes[0] == 0x0e && bytes[3..5] == [3, 0x0c]
            }) {
                self.reset_seen = true;
            }
            packet
        } else {
            if self.reset_seen {
                self.reset_batch_done = true;
            }
            None
        })
    }
    fn write_acl(&mut self, _: &[u8]) -> core::result::Result<(), BlockError> {
        self.trace.borrow_mut().actions.push("acl");
        Ok(())
    }
    fn quiesce_bulk(&mut self) -> core::result::Result<(), BlockError> {
        Ok(())
    }
    fn close(&mut self) -> core::result::Result<(), BlockError> {
        self.trace.borrow_mut().actions.push("base-close");
        if self.fail_close {
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
    fn start_iso(
        &mut self,
        _: Pair,
        _: &mut dyn DmaAllocator,
    ) -> core::result::Result<(), BlockError> {
        panic!("QCA has no MT7925 third interface")
    }
    fn replace_sco(
        &mut self,
        _: Option<Pair>,
        next: Option<Pair>,
        _: &mut dyn DmaAllocator,
    ) -> core::result::Result<(), BlockError> {
        self.trace.borrow_mut().pairs.push(next);
        Ok(())
    }
    fn read_media(&mut self, kind: Kind) -> core::result::Result<Option<Read>, BlockError> {
        assert_eq!(kind, Kind::Sco);
        Ok(self.reads.pop_front())
    }
    fn write_media(&mut self, kind: Kind, bytes: &[u8]) -> Result<()> {
        assert_eq!(kind, Kind::Sco);
        self.trace.borrow_mut().sco.push(bytes.to_vec());
        Ok(())
    }
    fn queue_sco(&mut self, bytes: &[u8]) -> Result<Option<u64>> {
        self.sequence += 1;
        self.queued.push_back(OutputReceipt {
            sequence: self.sequence,
            packet_bytes: bytes.len(),
            disposition: OutputDisposition::Completed,
        });
        Ok(Some(self.sequence))
    }
    fn poll_sco_output(&mut self) -> Result<Option<OutputReceipt>> {
        if self.receipt_fail_after == Some(self.receipts_read) {
            return Err(BlockError::Timeout.into());
        }
        let receipt = self.queued.pop_front();
        if receipt.is_some() {
            self.receipts_read += 1;
        }
        Ok(receipt)
    }
    fn quiesce_media(&mut self) -> core::result::Result<(), BlockError> {
        self.trace.borrow_mut().actions.push("quiesce");
        Ok(())
    }
    fn reset_media_epoch(&mut self) -> core::result::Result<(), BlockError> {
        self.trace.borrow_mut().actions.push("retire-voice");
        self.reads.clear();
        for r in &mut self.queued {
            r.disposition = OutputDisposition::RetiredUnconfirmed;
        }
        Ok(())
    }
    fn resume_media(&mut self) -> core::result::Result<(), BlockError> {
        self.trace.borrow_mut().actions.push("resume");
        Ok(())
    }
    fn close_media(&mut self) -> core::result::Result<(), BlockError> {
        self.trace.borrow_mut().actions.push("media-close");
        if self.fail_close {
            Err(BlockError::Timeout)
        } else {
            Ok(())
        }
    }
}
fn hci(kind: super::super::Kind, model: Model, alt6: bool) -> Hci<Model> {
    let report = super::super::tests::initialized_media_report(kind);
    let mut device = crate::usb::bluetooth::mediatek::media::tests::binding()
        .device()
        .clone();
    device.descriptor[8..10].copy_from_slice(&report.usb.vendor.to_le_bytes());
    device.descriptor[10..12].copy_from_slice(&report.usb.product.to_le_bytes());
    device.descriptor[12..14].copy_from_slice(&report.usb.revision.to_le_bytes());
    let mut raw = Vec::new();
    let mut at = 0;
    let mut six = false;
    while at < device.configuration.len() {
        let n = usize::from(device.configuration[at]);
        let mut d = device.configuration[at..at + n].to_vec();
        if d[1] == 4 {
            six = d[2..4] == [1, 6];
        }
        if six && d[1] == 5 {
            d[4..7].copy_from_slice(&[63, 0, 4]);
        }
        if !six || alt6 {
            raw.extend_from_slice(&d);
        }
        at += n;
    }
    let len = raw.len() as u16;
    raw[2..4].copy_from_slice(&len.to_le_bytes());
    device.configuration = raw;
    let binding = Binding::new(&device, &xhci::interfaces(&device.configuration)[0]).unwrap();
    let mut h = Hci::from_io(binding, model);
    h.initialization = Some(Box::new(Ok(InitializationReport::Qualcomm(report))));
    h
}
fn voice() -> Voice {
    Voice {
        connections: 1,
        air_mode: AirMode::Cvsd,
        voice_setting: 0,
    }
}
#[test]
fn qca_initialized_rome_wcn_transport_owns_voice_media_and_source_wideband_fallback() {
    for kind in [super::super::Kind::Rome, super::super::Kind::Wcn] {
        for six in [false, true] {
            let mut s = Session::start(hci(kind, Model::default(), six)).unwrap();
            assert_eq!(s.initialization().kind, kind);
            s.set_voice(voice(), &mut NoDma).unwrap();
            s.submit_sco(&[1, 0, 1, 9]).unwrap();
            s.submit_acl(&[1, 0, 0, 0]).unwrap();
            s.0.hci.io.events.push_back(vec![0xff, 1, 8]);
            s.0.hci
                .io
                .reads
                .extend([Read::Data(vec![1, 0, 1]), Read::Data(vec![9])]);
            assert_eq!(
                s.poll().unwrap(),
                [Received::Hci(Packet::Event(vec![0xff, 1, 8]))]
            );
            assert_eq!(s.poll().unwrap(), [Received::Sco(vec![1, 0, 1, 9])]);
            s.set_wideband_voice(1, 255, &mut NoDma).unwrap();
            assert_eq!(
                s.0.hci
                    .io
                    .trace
                    .borrow()
                    .pairs
                    .last()
                    .unwrap()
                    .unwrap()
                    .alternate,
                if six { 6 } else { 1 }
            );
            assert_eq!(s.queue_sco(&[1, 0, 1, 9]).unwrap(), Some(1));
            assert_eq!(
                s.poll_sco_output().unwrap().unwrap().disposition,
                OutputDisposition::Completed
            );
        }
    }
}
#[test]
fn qca_shutdown_requires_real_credit_completion_and_acknowledged_terminal_retirement() {
    let mut s = Session::start(hci(super::super::Kind::Wcn, Model::default(), true)).unwrap();
    s.set_wideband_voice(1, 60, &mut NoDma).unwrap();
    s.queue_sco(&[1, 0, 0]).unwrap();
    assert!(s.shutdown(0).is_err());
    assert!(s.0.hci.io.trace.borrow().actions.is_empty());
    s.0.hci.io.events.push_back(vec![0xff, 1, 9]);
    let report = s.shutdown(1).unwrap();
    assert_eq!(report.completion.command_credits, 0);
    assert_eq!(
        report.asynchronous,
        [
            Received::Hci(Packet::Event(vec![0xff, 1, 9])),
            Received::Hci(Packet::Event(vec![0x0e, 4, 0, 3, 0x0c, 0]))
        ]
    );
    assert_eq!(
        report.output,
        [OutputReceipt {
            sequence: 1,
            packet_bytes: 3,
            disposition: OutputDisposition::RetiredUnconfirmed
        }]
    );
    assert_eq!(s.lifecycle(), Lifecycle::Closed);
    assert!(s.resume().is_err());
    assert!(s.shutdown(1).is_err());
    assert!(
        s.0.hci
            .io
            .trace
            .borrow()
            .actions
            .ends_with(&["media-close", "base-close"])
    );
}
#[test]
fn qca_shutdown_preserves_reset_packets_without_a_fallible_post_reset_live_read() {
    let mut s = Session::start(hci(
        super::super::Kind::Wcn,
        Model {
            fail_post_reset_read: true,
            ..Model::default()
        },
        true,
    ))
    .unwrap();
    s.0.hci.io.events.push_back(vec![0xff, 1, 9]);
    let report = s.shutdown(1).unwrap();
    assert!(report.transport_retired);
    assert_eq!(
        report.asynchronous,
        [
            Received::Hci(Packet::Event(vec![0xff, 1, 9])),
            Received::Hci(Packet::Event(vec![0x0e, 4, 0, 3, 0x0c, 0]))
        ]
    );
    assert!(s.0.hci.io.reset_batch_done);
    assert_eq!(s.0.hci.io.reads_after_reset, 0);
}
#[test]
fn qca_shutdown_later_receipt_failure_keeps_cc_async_and_prior_receipts() {
    let mut s = Session::start(hci(
        super::super::Kind::Wcn,
        Model {
            receipt_fail_after: Some(1),
            ..Model::default()
        },
        true,
    ))
    .unwrap();
    s.set_wideband_voice(1, 60, &mut NoDma).unwrap();
    for sequence in 1..=3 {
        assert_eq!(s.queue_sco(&[1, 0, 0]).unwrap(), Some(sequence));
    }
    s.0.hci.io.events.push_back(vec![0xff, 1, 9]);
    assert!(s.shutdown(1).is_err());
    let report = s.shutdown_report().unwrap();
    assert!(!report.transport_retired);
    assert_eq!(report.completion.completion, [0x0e, 4, 0, 3, 0x0c, 0]);
    assert_eq!(
        report.asynchronous,
        [
            Received::Hci(Packet::Event(vec![0xff, 1, 9])),
            Received::Hci(Packet::Event(vec![0x0e, 4, 0, 3, 0x0c, 0]))
        ]
    );
    assert_eq!(
        report.output,
        [OutputReceipt {
            sequence: 1,
            packet_bytes: 3,
            disposition: OutputDisposition::RetiredUnconfirmed
        }]
    );
    assert_eq!(s.0.hci.io.queued.len(), 2);
    assert_eq!(s.lifecycle(), Lifecycle::Failed);
}
#[test]
fn qca_shutdown_status_only_error_completion_or_failed_retirement_never_credit_success() {
    for (event, close) in [
        (vec![0x0f, 4, 0, 1, 3, 0x0c], false),
        (vec![0x0e, 4, 1, 3, 0x0c, 0x0c], false),
        (vec![0x0e, 4, 1, 3, 0x0c, 0], true),
    ] {
        let mut s = Session::start(hci(
            super::super::Kind::Rome,
            Model {
                reset: Some(event),
                fail_close: close,
                ..Model::default()
            },
            true,
        ))
        .unwrap();
        assert!(s.shutdown(1).is_err());
        if close {
            assert!(!s.shutdown_report().unwrap().transport_retired);
            assert_eq!(s.last_reset().unwrap().completion, [0x0e, 4, 1, 3, 0x0c, 0]);
        }
        assert_eq!(s.lifecycle(), Lifecycle::Failed);
        assert!(s.resume().is_err());
    }
}
#[test]
fn qca_media_refuses_uninitialized_or_foreign_kept_evidence() {
    let mut h = hci(super::super::Kind::Rome, Model::default(), true);
    h.initialization = None;
    assert!(Session::start(h).is_err());
    let mut h = hci(super::super::Kind::Rome, Model::default(), true);
    if let Some(Ok(InitializationReport::Qualcomm(r))) = h.initialization.as_deref_mut() {
        r.usb.product ^= 1;
    }
    assert!(Session::start(h).is_err());
}
#[test]
fn qca_matches_source_wideband_plans_and_all_75_exact_aliases_remain_descriptor_bound() {
    let mut selected = 0;
    let mut services = 0;
    for line in include_str!("../../../../../tests/reference/qca-wideband.txt").lines() {
        let words: Vec<_> = line.split_whitespace().collect();
        let values: Vec<usize> = words[1..].iter().map(|v| v.parse().unwrap()).collect();
        if words[0] == "P" {
            let lengths = crate::usb::bluetooth::realtek::media::output_lengths(
                values[0],
                63,
                Some(!values[1].is_multiple_of(2)),
            )
            .unwrap();
            assert_eq!(lengths.len(), values[2]);
            assert_eq!(lengths, values[3..]);
            services += 1;
        } else {
            assert_eq!(words[0], "W");
            let mut h = hci(
                super::super::Kind::Rome,
                Model::default(),
                values[0] & 64 != 0,
            );
            if values[0] & 8 == 0 {
                let raw = h.binding.device.configuration.clone();
                let mut output = Vec::new();
                let mut at = 0;
                let mut keep = true;
                while at < raw.len() {
                    let n = usize::from(raw[at]);
                    if raw[at + 1] == 4 {
                        keep = raw[at + 2] != 1 || raw[at + 3] != 3;
                    }
                    if keep {
                        output.extend_from_slice(&raw[at..at + n]);
                    }
                    at += n;
                }
                h.binding.device.configuration = output;
            }
            let b = shared::Bindings::qca_sco(h.binding()).unwrap();
            assert_eq!(
                b.wideband_sco(values[2] as u8, values[1] as u16)
                    .unwrap()
                    .map_or(0, |p| usize::from(p.alternate)),
                values[3]
            );
            selected += 1;
        }
    }
    assert_eq!((selected, services), (48, 244));
    let mut aliases = 0;
    for &(vendor, product, kind) in super::super::SOURCE_USB_IDS {
        let mut h = hci(kind, Model::default(), true);
        h.binding.device.descriptor[8..10].copy_from_slice(&vendor.to_le_bytes());
        h.binding.device.descriptor[10..12].copy_from_slice(&product.to_le_bytes());
        assert!(
            shared::Bindings::qca_sco(h.binding())
                .unwrap()
                .sco(voice())
                .unwrap()
                .is_some()
        );
        aliases += 1;
    }
    assert_eq!(aliases, 75);
}
