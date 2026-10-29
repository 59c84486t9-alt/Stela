// SPDX-License-Identifier: GPL-2.0-or-later
// Pinned Linux hid-multitouch.c reference and primary wire contracts:
// ../THIRD_PARTY.md. No vendor quirks or implicit contact releases are used.
//! Conservative, opt-in single-Finger hybrid report assembly.
use super::{BlockError, Poll, ReportType, UsbInput, descriptor::*, events};
use alloc::vec::Vec;

const CONTACT_ID: u32 = 0x000d_0051;
const CONTACT_COUNT: u32 = 0x000d_0054;
const CONTACT_MAX: u32 = 0x000d_0055;
const SCAN_TIME: u32 = 0x000d_0056;
const REQUIRED: [u32; 6] = [
    CONTACT_ID,
    0x000d_0042,
    0x0001_0030,
    0x0001_0031,
    CONTACT_COUNT,
    SCAN_TIME,
];
const MAX_CONTACTS: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TouchFrame {
    pub report: u8,
    pub application: usize,
    /// The device's unchanged scan token, not a host timestamp.
    pub scan_time: i64,
    pub contacts: Vec<events::Contact>,
    /// Every original input report contributing to this complete frame.
    pub reports: Vec<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TouchDiscard {
    Interrupted,
    InvalidValue,
    OrphanContinuation,
    ScanMismatch,
    DuplicateContact,
    RepeatedScan,
}

#[derive(Debug, Default)]
pub struct TouchPoll {
    pub hid: Poll,
    pub frames: Vec<TouchFrame>,
    pub discarded: Vec<TouchDiscard>,
}

#[derive(Clone)]
struct Scalar {
    field: usize,
    minimum: i64,
    maximum: i64,
}
impl Scalar {
    fn read(&self, frame: &Frame) -> Option<i64> {
        let sample = frame
            .samples
            .iter()
            .find(|s| s.field == self.field && s.element == 0)?;
        match sample.value {
            Value::Scalar(v) if !sample.null && (self.minimum..=self.maximum).contains(&v) => {
                Some(v)
            }
            _ => None,
        }
    }
}

pub(super) struct Profile {
    report: u8,
    application: usize,
    fields: Vec<Scalar>,
    feature_report: u8,
    feature: ReportField,
}

fn in_application(d: &Descriptor, mut collection: Option<usize>, app: usize) -> bool {
    while let Some(index) = collection {
        if index == app {
            return true;
        }
        let Some(c) = d.collections.get(index) else {
            return false;
        };
        // A nested Application is a separate owner.
        if c.kind == 1 {
            return false;
        }
        collection = c.parent;
    }
    false
}

fn scalar_field(field: &ReportField) -> bool {
    field.count == 1 && (1..=32).contains(&field.size) && field.flags & 7 == 2
}

impl Profile {
    fn select(d: &Descriptor, report: u8, app: usize) -> Option<Self> {
        let application = d.collections.get(app)?;
        if application.kind != 1 || !matches!(application.usage, 0x000d_0004 | 0x000d_0005) {
            return None;
        }
        let layout = d.layout(ReportType::Input, report)?;
        let fingers: Vec<_> = d
            .collections
            .iter()
            .enumerate()
            .filter(|(i, c)| {
                c.usage == 0x000d_0022 && c.kind == 2 && in_application(d, Some(*i), app)
            })
            .map(|(i, _)| i)
            .collect();
        let [finger] = fingers.as_slice() else {
            return None;
        };
        let mut fields = Vec::new();
        for (n, usage) in REQUIRED.iter().enumerate() {
            let mut matching =
                layout.fields.iter().enumerate().filter(|(_, f)| {
                    in_application(d, f.collection, app) && f.usages.contains(usage)
                });
            let (index, field) = matching.next()?;
            if matching.next().is_some()
                || !scalar_field(field)
                || field.usages.as_slice() != [*usage]
                || field.collection != Some(if n < 4 { *finger } else { app })
            {
                return None;
            }
            if n == 1 && (field.minimum != 0 || field.maximum != 1) {
                return None;
            }
            if matches!(n, 4 | 5) && field.minimum != 0 {
                return None;
            }
            fields.push(Scalar {
                field: index,
                minimum: field.minimum,
                maximum: field.maximum,
            });
        }
        let mut features = d
            .reports
            .iter()
            .filter(|l| l.kind == ReportType::Feature)
            .flat_map(|l| {
                l.fields
                    .iter()
                    .filter(move |f| f.collection == Some(app) && f.usages.contains(&CONTACT_MAX))
                    .map(move |f| (l.id, f))
            });
        let (feature_report, feature) = features.next()?;
        if features.next().is_some()
            || !scalar_field(feature)
            || feature.usages != [CONTACT_MAX]
            || feature.minimum < 0
        {
            return None;
        }
        Some(Self {
            report,
            application: app,
            fields,
            feature_report,
            feature: feature.clone(),
        })
    }

    fn maximum(&self, bytes: &[u8]) -> Option<usize> {
        let body = bytes.get(usize::from(self.feature_report != 0)..)?;
        let mut value = 0i64;
        for bit in 0..self.feature.size {
            let offset = self.feature.offset.checked_add(bit)?;
            value |= i64::from((body.get(offset / 8)? >> (offset % 8)) & 1) << bit;
        }
        if !(self.feature.minimum..=self.feature.maximum).contains(&value) {
            return None;
        }
        let value = usize::try_from(value).ok()?;
        (1..=MAX_CONTACTS).contains(&value).then_some(value)
    }
}

pub(super) struct Assembler {
    profile: Profile,
    maximum: usize,
    pending: Option<(usize, TouchFrame)>,
    last_scan: Option<i64>,
}
impl Assembler {
    #[cfg(test)]
    pub(super) fn pending_contacts(&self) -> usize {
        self.pending
            .as_ref()
            .map_or(0, |(_, frame)| frame.contacts.len())
    }
    pub(super) fn invalidate(&mut self) {
        self.pending = None;
        self.last_scan = None;
    }

    pub(super) fn update(
        &mut self,
        frame: &Frame,
        packet: &events::TouchPacket,
        out: &mut TouchPoll,
    ) {
        if frame.id != self.profile.report || packet.application != self.profile.application {
            return;
        }
        let values: Option<Vec<_>> = self.profile.fields.iter().map(|f| f.read(frame)).collect();
        let Some(v) = values else {
            self.pending = None;
            out.discarded.push(TouchDiscard::InvalidValue);
            return;
        };
        let count = usize::try_from(v[4]).ok().filter(|n| *n <= self.maximum);
        let Some(count) = count else {
            self.pending = None;
            out.discarded.push(TouchDiscard::InvalidValue);
            return;
        };
        let [contact] = packet.contacts.as_slice() else {
            self.pending = None;
            out.discarded.push(TouchDiscard::InvalidValue);
            return;
        };
        if count > 0 {
            if self.pending.take().is_some() {
                out.discarded.push(TouchDiscard::Interrupted);
            }
            if self.last_scan == Some(v[5]) {
                out.discarded.push(TouchDiscard::RepeatedScan);
                return;
            }
            self.last_scan = Some(v[5]);
            self.pending = Some((
                count,
                TouchFrame {
                    report: frame.id,
                    application: packet.application,
                    scan_time: v[5],
                    contacts: Vec::new(),
                    reports: Vec::new(),
                },
            ));
        }
        let Some((expected, pending)) = &mut self.pending else {
            out.discarded.push(TouchDiscard::OrphanContinuation);
            return;
        };
        if pending.scan_time != v[5] {
            self.pending = None;
            out.discarded.push(TouchDiscard::ScanMismatch);
            return;
        }
        if pending.contacts.iter().any(|c| c.id == Some(v[0])) {
            self.pending = None;
            out.discarded.push(TouchDiscard::DuplicateContact);
            return;
        }
        pending.contacts.push(contact.clone());
        pending.reports.push(frame.bytes.clone());
        if pending.contacts.len() == *expected {
            out.frames.push(self.pending.take().unwrap().1);
        }
    }
}

impl UsbInput {
    /// Enable only the descriptor's single-Finger scalar absolute profile.
    /// Device capacity comes from its acknowledged Feature GET_REPORT.
    /// Other layouts remain available unchanged as raw HID reports/events.
    /// A rejected enable keeps the previous selection; stale identity clears it.
    pub fn enable_touch_frames(
        &mut self,
        report: u8,
        application: usize,
    ) -> Result<(), BlockError> {
        if let Err(error) = self.controller.borrow().validate_device_id(self.id) {
            self.touch = None;
            return Err(error);
        }
        if self.state != super::State::Running {
            return Err(BlockError::Unsupported(
                "touch assembly requires running HID",
            ));
        }
        let profile = self.translator.descriptor().and_then(|d| Profile::select(d,report,application)).ok_or(BlockError::Unsupported("HID hybrid assembly requires one scalar Finger, count, scan time and maximum feature"))?;
        let bytes = self.get_report(ReportType::Feature, profile.feature_report)?;
        let maximum = profile.maximum(&bytes).ok_or(BlockError::Protocol(
            "invalid HID Contact Count Maximum; host limit is 64",
        ))?;
        self.controller.borrow().validate_device_id(self.id)?;
        self.touch = Some(Assembler {
            profile,
            maximum,
            pending: None,
            last_scan: None,
        });
        Ok(())
    }

    pub(super) fn invalidate_touch(&mut self) {
        if let Some(touch) = &mut self.touch {
            touch.invalidate();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::touch::SINGLE;
    use super::*;
    use alloc::vec;
    fn fixture() -> (Descriptor, events::Decoder, Assembler) {
        let descriptor = Descriptor::parse(SINGLE).unwrap();
        let profile = Profile::select(&descriptor, 1, 0).unwrap();
        assert_eq!(profile.maximum(&[2, 3]), Some(3));
        (
            descriptor,
            events::Decoder::default(),
            Assembler {
                profile,
                maximum: 3,
                pending: None,
                last_scan: None,
            },
        )
    }
    fn update(
        d: &Descriptor,
        decoder: &mut events::Decoder,
        a: &mut Assembler,
        bytes: &[u8],
    ) -> TouchPoll {
        let frame = d.decode(bytes).unwrap();
        let events = decoder.update(d, &frame);
        let mut out = TouchPoll::default();
        for event in events {
            if let events::Event::Touch(packet) = event {
                a.update(&frame, &packet, &mut out);
            }
        }
        out
    }
    fn raw(id: u8, tip: u8, count: u8, scan: u16) -> Vec<u8> {
        vec![
            1,
            id,
            tip,
            10,
            0,
            20,
            0,
            count,
            scan as u8,
            (scan >> 8) as u8,
        ]
    }
    #[test]
    fn duplicate_ids_discard_entire_pending_frame_and_do_not_mint_releases() {
        let (d, mut decoder, mut a) = fixture();
        assert!(
            update(&d, &mut decoder, &mut a, &raw(90, 1, 3, 8))
                .frames
                .is_empty()
        );
        let duplicate = update(&d, &mut decoder, &mut a, &raw(90, 0, 0, 8));
        assert_eq!(duplicate.discarded, [TouchDiscard::DuplicateContact]);
        assert!(duplicate.frames.is_empty());
        assert_eq!(
            update(&d, &mut decoder, &mut a, &raw(91, 1, 0, 8)).discarded,
            [TouchDiscard::OrphanContinuation]
        );
    }
    #[test]
    fn zero_orphans_new_positive_counts_and_scan_changes_never_complete_missing_contacts() {
        let (d, mut decoder, mut a) = fixture();
        assert_eq!(
            update(&d, &mut decoder, &mut a, &raw(1, 0, 0, 1)).discarded,
            [TouchDiscard::OrphanContinuation]
        );
        assert!(
            update(&d, &mut decoder, &mut a, &raw(1, 1, 3, 2))
                .frames
                .is_empty()
        );
        let replacement = update(&d, &mut decoder, &mut a, &raw(4, 0, 1, 3));
        assert_eq!(replacement.discarded, [TouchDiscard::Interrupted]);
        assert_eq!(replacement.frames[0].contacts[0].id, Some(4));
        assert!(
            update(&d, &mut decoder, &mut a, &raw(1, 1, 2, 4))
                .frames
                .is_empty()
        );
        assert_eq!(
            update(&d, &mut decoder, &mut a, &raw(2, 1, 0, 5)).discarded,
            [TouchDiscard::ScanMismatch]
        );
        assert_eq!(
            update(&d, &mut decoder, &mut a, &raw(3, 1, 0, 4)).discarded,
            [TouchDiscard::OrphanContinuation]
        );
    }
    #[test]
    fn descriptor_bounds_and_capacity_refuse_invalid_mandatory_values() {
        for (offset, value) in [(1, 128), (2, 2), (7, 4)] {
            let (d, mut decoder, mut a) = fixture();
            update(&d, &mut decoder, &mut a, &raw(1, 1, 2, 1));
            let mut invalid = raw(2, 1, 0, 1);
            invalid[offset] = value;
            assert_eq!(
                update(&d, &mut decoder, &mut a, &invalid).discarded,
                [TouchDiscard::InvalidValue]
            );
            assert_eq!(
                update(&d, &mut decoder, &mut a, &raw(3, 1, 0, 1)).discarded,
                [TouchDiscard::OrphanContinuation]
            );
        }
        let (d, mut decoder, mut a) = fixture();
        let mut invalid = raw(1, 1, 1, 7);
        invalid[4] = 0x80; // X=32778, outside logical maximum.
        assert_eq!(
            update(&d, &mut decoder, &mut a, &invalid).discarded,
            [TouchDiscard::InvalidValue]
        );
    }
    #[test]
    fn touch_frames_require_matching_identity_and_a_new_scan() {
        let (d, mut decoder, mut a) = fixture();
        let frame = d.decode(&raw(1, 1, 2, 7)).unwrap();
        let event = decoder.update(&d, &frame).remove(0);
        let events::Event::Touch(mut packet) = event else {
            panic!("touch")
        };
        let mut out = TouchPoll::default();
        a.update(&frame, &packet, &mut out);
        packet.application = 99;
        a.update(&frame, &packet, &mut out);
        assert!(out.frames.is_empty());
        let mut foreign = frame.clone();
        foreign.id = 2;
        packet.application = 0;
        a.update(&foreign, &packet, &mut out);
        assert!(out.frames.is_empty());
        assert_eq!(
            update(&d, &mut decoder, &mut a, &raw(2, 1, 0, 7)).frames[0]
                .contacts
                .len(),
            2
        );
        assert_eq!(
            update(&d, &mut decoder, &mut a, &raw(1, 1, 1, 7)).discarded,
            [TouchDiscard::RepeatedScan]
        );
        // No monotonic time requirement: 16-bit counter rollover works.
        assert_eq!(
            update(&d, &mut decoder, &mut a, &raw(1, 1, 1, 0))
                .frames
                .len(),
            1
        );
    }
    #[test]
    fn ambiguous_multi_slot_repeated_axes_and_missing_frame_metadata_are_not_admitted() {
        for usage in [CONTACT_COUNT, SCAN_TIME, CONTACT_MAX] {
            let mut bytes = SINGLE.to_vec();
            let low = usage as u8;
            let at = bytes.windows(2).position(|w| w == [9, low]).unwrap();
            bytes[at + 1] = 0x7f;
            assert!(Profile::select(&Descriptor::parse(&bytes).unwrap(), 1, 0).is_none());
        }
        let mut duplicate = SINGLE.to_vec();
        let at = duplicate
            .windows(4)
            .position(|w| w == [9, 0x31, 0x81, 2])
            .unwrap();
        duplicate.splice(at..at, [9, 0x30, 0x81, 2]);
        assert!(Profile::select(&Descriptor::parse(&duplicate).unwrap(), 1, 0).is_none());
        let mut slots = SINGLE.to_vec();
        let end = slots.iter().position(|v| *v == 0xc0).unwrap();
        slots.splice(end..end, [0xc0, 5, 0x0d, 9, 0x22, 0xa1, 2]);
        assert!(Profile::select(&Descriptor::parse(&slots).unwrap(), 1, 0).is_none());
    }
}
