// SPDX-License-Identifier: GPL-2.0-or-later
//! Scripted protocol contracts and real native EP0 transactions for scalar FUs.
extern crate std;
use super::*;
use crate::{block::BlockError, bus::dma::RegionAllocator, usb::xhci};
use alloc::{collections::VecDeque, rc::Rc, vec, vec::Vec};
use core::cell::RefCell;

struct Transaction {
    request: [u8; 8],
    out: Vec<u8>,
    result: Result<Vec<u8>, BlockError>,
}
#[derive(Default)]
struct Peer {
    expected: VecDeque<Transaction>,
    seen: Vec<([u8; 8], Vec<u8>)>,
}
impl Control for Peer {
    fn control(&mut self, request: [u8; 8], out: &[u8]) -> Result<Vec<u8>, BlockError> {
        let expected = self
            .expected
            .pop_front()
            .expect("unexpected control transaction");
        assert_eq!(request, expected.request);
        assert_eq!(out, expected.out);
        self.seen.push((request, out.to_vec()));
        expected.result
    }
    fn now_us(&self) -> u64 {
        0
    }
    fn relax(&mut self) {}
}
impl Peer {
    fn read(&mut self, selector: u8, channel: u8, request: u8, length: u16, reply: &[u8]) {
        self.expected.push_back(Transaction {
            request: xhci::setup(
                0xa1,
                request,
                u16::from(selector) << 8 | u16::from(channel),
                0x0203,
                length,
            ),
            out: Vec::new(),
            result: Ok(reply.to_vec()),
        });
    }
    fn send(&mut self, request: u8, selector: u8, channel: u8, bytes: &[u8]) {
        self.expected.push_back(Transaction {
            request: xhci::setup(
                0x21,
                request,
                u16::from(selector) << 8 | u16::from(channel),
                0x0203,
                bytes.len() as u16,
            ),
            out: bytes.to_vec(),
            result: Ok(Vec::new()),
        });
    }
    fn write(&mut self, selector: u8, channel: u8, bytes: &[u8]) {
        self.send(1, selector, channel, bytes);
    }
    /// The first RANGE triplet, read once each for MAX, MIN and RES.
    fn range(&mut self, selector: u8, raw: &[u8]) {
        for _ in 0..3 {
            self.read(selector, 0, 2, raw.len() as u16, raw);
        }
    }
}
fn graph(protocol: u8) -> Graph {
    let controls = (1..=13)
        .filter(|s| *s != 6)
        .fold(0u32, |bits, selector| bits | (3 << ((selector - 1) * 2)));
    Graph {
        protocol,
        control_interface: 3,
        entities: vec![
            super::super::Entity::Input {
                id: 1,
                terminal_type: 0x101,
                clock: 10,
                channels: 2,
                channel_config: 3,
            },
            super::super::Entity::Feature {
                id: 2,
                source: 1,
                controls: vec![controls; 3],
            },
        ],
    }
}
fn range(min: i64, max: i64, res: i64) -> MixerRange {
    MixerRange {
        min,
        max,
        res,
        db: None,
    }
}

#[test]
fn scalar_controls_use_linux_widths_and_write_without_readback() {
    use FeatureControl::*;
    use FeatureValue::{Enabled, GainDb256, Tone};
    for protocol in [UAC1, UAC2, UAC3] {
        let graph = graph(protocol);
        // audio_feature_info's value types.
        let mut cases = vec![
            (Bass, 3, Tone(-2), vec![0xfe]),
            (Mid, 4, Tone(2), vec![2]),
            (Treble, 5, Tone(-4), vec![0xfc]),
            (AutomaticGain, 7, Enabled(true), vec![1]),
            (BassBoost, 9, Enabled(false), vec![0]),
            (Loudness, 10, Enabled(true), vec![1]),
        ];
        if protocol == UAC1 {
            cases.push((Delay, 8, FeatureValue::Delay(48), vec![48, 0]));
        } else {
            cases.extend([
                (
                    Delay,
                    8,
                    FeatureValue::Delay(0x9000_0000),
                    vec![0, 0, 0, 0x90],
                ),
                (InputGain, 11, GainDb256(-512), vec![0, 0xfe]),
                (InputGainPad, 12, GainDb256(-4096), vec![0, 0xf0]),
                (PhaseInverter, 13, Enabled(true), vec![1]),
            ]);
        }
        let request = if protocol == UAC1 { 0x81 } else { 1 };
        for (feature, selector, value, bytes) in cases {
            for channel in [0, 1, 2] {
                let mut peer = Peer::default();
                peer.read(selector, channel, request, bytes.len() as u16, &bytes);
                assert_eq!(
                    graph.feature_value(&mut peer, 2, channel, feature),
                    Ok(value)
                );
                peer.write(selector, channel, &bytes);
                let wide = feature.has_range().then(|| range(-(1 << 40), 1 << 40, 1));
                graph
                    .set_feature_value(&mut peer, 2, channel, feature, wide, value)
                    .unwrap();
                assert!(peer.expected.is_empty());
            }
        }
        // get_relative_value then get_abs_value: down to a step, clamped.
        for (tone, written) in [(-3, 0xfc), (100, 8), (-100, 0xf8)] {
            let mut peer = Peer::default();
            peer.write(3, 0, &[written]);
            graph
                .set_feature_value(&mut peer, 2, 0, Bass, Some(range(-8, 8, 4)), Tone(tone))
                .unwrap();
            assert!(peer.expected.is_empty());
        }
        // Any nonzero boolean reads as set, as `!!val`.
        let mut peer = Peer::default();
        peer.read(7, 0, request, 1, &[2]);
        assert_eq!(
            graph.feature_value(&mut peer, 2, 0, AutomaticGain),
            Ok(Enabled(true))
        );
    }
}

#[test]
fn feature_admission_checks_type_access_channel_and_protocol_before_transactions() {
    let mut peer = Peer::default();
    let wide = Some(range(-128, 127, 1));
    for protocol in [UAC1, UAC2, UAC3] {
        let mut graph = graph(protocol);
        assert_eq!(
            graph.set_feature_value(
                &mut peer,
                2,
                0,
                FeatureControl::Bass,
                wide,
                FeatureValue::Enabled(true)
            ),
            Err(Error::Format)
        );
        assert_eq!(
            graph.set_feature_value(
                &mut peer,
                2,
                0,
                FeatureControl::Bass,
                None,
                FeatureValue::Tone(0)
            ),
            Err(Error::Format)
        );
        assert!(
            graph
                .feature_value(&mut peer, 2, 3, FeatureControl::Bass)
                .is_err()
        );
        assert!(
            graph
                .feature_value(&mut peer, 1, 0, FeatureControl::Bass)
                .is_err()
        );
        assert!(
            graph
                .feature_range(&mut peer, 2, 0, FeatureControl::AutomaticGain)
                .is_err()
        );
        if protocol == UAC1 {
            for feature in [
                FeatureControl::InputGain,
                FeatureControl::InputGainPad,
                FeatureControl::PhaseInverter,
            ] {
                assert!(graph.feature_value(&mut peer, 2, 0, feature).is_err());
            }
            assert_eq!(
                graph.set_feature_value(
                    &mut peer,
                    2,
                    0,
                    FeatureControl::Delay,
                    wide,
                    FeatureValue::Delay(65536)
                ),
                Err(Error::Format)
            );
        }
        let super::super::Entity::Feature { controls, .. } = &mut graph.entities[1] else {
            unreachable!()
        };
        controls[0] &= !(3 << 4); // absent Bass on master
        controls[1] = (controls[1] & !(3 << 4)) | (1 << 4); // read-only
        controls[2] = (controls[2] & !(3 << 4)) | (2 << 4); // reserved
        assert!(
            graph
                .feature_value(&mut peer, 2, 0, FeatureControl::Bass)
                .is_err()
        );
        assert!(
            graph
                .set_feature_value(
                    &mut peer,
                    2,
                    1,
                    FeatureControl::Bass,
                    wide,
                    FeatureValue::Tone(0)
                )
                .is_err()
        );
        assert!(
            graph
                .feature_value(&mut peer, 2, 2, FeatureControl::Bass)
                .is_err()
        );
    }
    assert!(peer.seen.is_empty());
}

#[test]
fn ranges_are_probed_like_get_min_max_with_quirks() {
    let uac2 = graph(UAC2);
    // RES doubles until a step past the current value reads back; the
    // current value is then restored.
    let mut peer = Peer::default();
    peer.range(3, &[1, 0, 0xf8, 8, 2]);
    peer.read(3, 0, 1, 1, &[0]);
    peer.write(3, 0, &[0xf8]);
    peer.read(3, 0, 1, 1, &[0xf8]);
    peer.write(3, 0, &[2]);
    peer.read(3, 0, 1, 1, &[0]);
    peer.write(3, 0, &[4]);
    peer.read(3, 0, 1, 1, &[4]);
    peer.write(3, 0, &[0]);
    assert_eq!(
        uac2.feature_range(&mut peer, 2, 0, FeatureControl::Bass),
        Ok(MixerRange {
            min: -8,
            max: 8,
            res: 4,
            db: Some((-3, 3))
        })
    );
    assert!(peer.expected.is_empty());

    // UAC1 asks SET_RES to halve RES while the device accepts.
    let uac1 = graph(UAC1);
    let mut peer = Peer::default();
    peer.read(8, 0, 0x83, 2, &[80, 0]);
    peer.read(8, 0, 0x82, 2, &[16, 0]);
    peer.read(8, 0, 0x84, 2, &[16, 0]);
    peer.send(4, 8, 0, &[8, 0]);
    peer.send(4, 8, 0, &[4, 0]);
    peer.expected[4].result = Err(BlockError::Timeout);
    peer.read(8, 0, 0x84, 2, &[8, 0]);
    peer.read(8, 0, 0x81, 2, &[48, 0]);
    peer.write(8, 0, &[16, 0]);
    peer.read(8, 0, 0x81, 2, &[16, 0]);
    peer.write(8, 0, &[56, 0]);
    peer.read(8, 0, 0x81, 2, &[56, 0]);
    peer.write(8, 0, &[48, 0]);
    assert_eq!(
        uac1.feature_range(&mut peer, 2, 0, FeatureControl::Delay),
        Ok(MixerRange {
            min: 16,
            max: 80,
            res: 8,
            db: Some((6, 31))
        })
    );
    assert!(peer.expected.is_empty());

    // A control that never follows SET_CUR is sticky: left at its maximum.
    let mut peer = Peer::default();
    peer.range(11, &[1, 0, 0, 0xf0, 0, 0, 0, 1]);
    peer.read(11, 0, 1, 2, &[0, 0xfe]);
    peer.write(11, 0, &[0, 0xf0]);
    peer.read(11, 0, 1, 2, &[0, 0xfe]);
    peer.write(11, 0, &[0, 0]);
    peer.read(11, 0, 1, 2, &[0, 0xfe]);
    peer.write(11, 0, &[0, 0]);
    assert_eq!(
        uac2.feature_range(&mut peer, 2, 0, FeatureControl::InputGain),
        Err(Error::Unsupported("sticky mixer values"))
    );
    assert!(peer.expected.is_empty());

    // A maximum at or below -96 dB disables dB; unsigned delays keep 32 bits.
    let mut peer = Peer::default();
    peer.range(11, &[1, 0, 0, 0xa0, 0, 0xa0, 0, 1]);
    assert_eq!(
        uac2.feature_range(&mut peer, 2, 0, FeatureControl::InputGain),
        Ok(range(-24576, -24576, 256))
    );
    let mut peer = Peer::default();
    peer.range(
        8,
        &[
            1, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0,
        ],
    );
    let delay = uac2
        .feature_range(&mut peer, 2, 0, FeatureControl::Delay)
        .unwrap();
    assert_eq!(
        (delay.min, delay.max, delay.res),
        (0xffff_ffff, 0xffff_ffff, 1)
    );

    // MAX and MIN must read; a RES that does not is 1.
    for failed in 0..3 {
        let mut peer = Peer::default();
        peer.range(3, &[1, 0, 0xf8, 0xf8, 2]);
        peer.expected[failed].result = Err(BlockError::Timeout);
        let result = uac2.feature_range(&mut peer, 2, 0, FeatureControl::Bass);
        if failed < 2 {
            assert_eq!(result, Err(Error::Transport(BlockError::Timeout)));
        } else {
            assert_eq!(result.map(|r| r.res), Ok(1));
        }
    }
    let mut peer = Peer::default();
    peer.read(3, 0, 2, 5, &[1, 0, 0xf8, 8]);
    assert_eq!(
        uac2.feature_range(&mut peer, 2, 0, FeatureControl::Bass),
        Err(Error::ControlLength)
    );
}

fn native(
    dma: &mut dyn crate::bus::dma::DmaAllocator,
) -> (
    super::super::UsbAudio,
    Rc<RefCell<xhci::model::CancelModel>>,
    xhci::Shared,
) {
    let mut raw = super::super::test_configuration();
    let at = raw
        .windows(5)
        .position(|v| v == [18, 0x24, 6, 2, 1])
        .unwrap();
    for channel in 0..3 {
        raw[at + 5 + channel * 4..at + 9 + channel * 4]
            .copy_from_slice(&0x03ff_ffffu32.to_le_bytes());
    }
    let (mut controller, model) = xhci::model::high_speed_media_controller(dma, &raw);
    controller.set_configuration(1, 1).unwrap();
    let shared = Rc::new(RefCell::new(controller));
    let device = xhci::Device {
        id: shared.borrow().test_device_id(1).unwrap(),
        slot: 1,
        speed: xhci::HIGH_SPEED,
        location: "descriptor-selected scalar feature native control peer".into(),
        descriptor: [18, 1, 0, 2, 0, 0, 0, 64, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1],
        configurations: vec![raw.clone()],
        configuration: raw.clone(),
        manufacturer: None,
        product: None,
        serial: None,
        language: None,
        vendor_ethernet_tcr: None,
        vendor_ethernet_revision: None,
    };
    let all = xhci::interfaces(&raw);
    let plan = super::super::Plan::parse(&all[0], &all, &raw, xhci::HIGH_SPEED).unwrap();
    let audio = super::super::UsbAudio::attach(shared.clone(), &device, plan, dma).unwrap();
    (audio, model, shared)
}
fn allocator(memory: &mut [u64]) -> RegionAllocator {
    let start = memory.as_mut_ptr() as u64;
    // SAFETY: each test keeps the original exclusive backing through owners.
    unsafe { RegionAllocator::new(start..start + memory.len() as u64 * 8) }
}

#[test]
fn native_ep0_probes_once_and_writes_exact_dma() {
    let mut backing = vec![0u64; 512 * 1024];
    let mut dma = allocator(&mut backing);
    let (mut audio, model, _) = native(&mut dma);
    for (feature, selector, value, bytes) in [
        (
            FeatureControl::Bass,
            3u8,
            FeatureValue::Tone(-2),
            vec![0xfe],
        ),
        (
            FeatureControl::Delay,
            8,
            FeatureValue::Delay(0x9000_0000),
            vec![0, 0, 0, 0x90],
        ),
    ] {
        // A one-value range needs no CUR probing.
        let address = u16::from(selector) << 8 | 2;
        let raw = [
            vec![1, 0],
            bytes.clone(),
            bytes.clone(),
            vec![1; bytes.len()],
        ]
        .concat();
        let probe = xhci::setup(0xa1, 2, address, 0x0200, raw.len() as u16);
        model.borrow_mut().control_replies.extend([
            (probe, raw.clone()),
            (probe, raw.clone()),
            (probe, raw),
        ]);
        for _ in 0..2 {
            audio.set_feature_value(2, 2, feature, value).unwrap();
        }
        assert!(model.borrow().control_replies.is_empty());
        let write = xhci::setup(0x21, 1, address, 0x0200, bytes.len() as u16);
        let writes = model
            .borrow()
            .setup
            .iter()
            .filter(|(r, payload)| *r == write && *payload == bytes)
            .count();
        assert_eq!(writes, 2);
    }
}

#[test]
fn native_ep0_short_range_and_stalled_set_propagate_failures() {
    for failure in 0..2 {
        let mut backing = vec![0u64; 512 * 1024];
        let mut dma = allocator(&mut backing);
        let (mut audio, model, _) = native(&mut dma);
        if failure == 0 {
            model
                .borrow_mut()
                .control_replies
                .push_back((xhci::setup(0xa1, 2, 3 << 8, 0x0200, 5), vec![1, 0, 0xf8, 8]));
            assert_eq!(
                audio.set_feature_value(2, 0, FeatureControl::Bass, FeatureValue::Tone(0)),
                Err(Error::ControlLength)
            );
            assert!(model.borrow().setup.iter().all(|(r, _)| r[0] != 0x21));
        } else {
            model.borrow_mut().stall_control = Some(1);
            let result = audio.set_feature_value(
                2,
                1,
                FeatureControl::AutomaticGain,
                FeatureValue::Enabled(true),
            );
            assert!(matches!(
                result,
                Err(Error::Transport(BlockError::Device { status: 6 }))
            ));
            assert!(model.borrow().seen.contains(&14)); // Reset Endpoint
            assert!(model.borrow().seen.contains(&16)); // Set Dequeue
            assert!(model.borrow().setup.iter().any(|(r, payload)| *r
                == xhci::setup(0x21, 1, 7 << 8 | 1, 0x0200, 1)
                && *payload == [1]));
        }
    }
}

#[test]
#[ignore = "oracle: STELA_USB_AUDIO_FEATURE_ORACLE"]
fn scalar_features_match_unchanged_linux_type_and_conversion_helpers() {
    use sha2::{Digest, Sha256};
    let path = std::env::var("STELA_USB_AUDIO_FEATURE_ORACLE")
        .expect("set STELA_USB_AUDIO_FEATURE_ORACLE to scalar source trace.txt");
    let trace = std::fs::read_to_string(path).unwrap();
    assert_eq!(
        alloc::format!("{:x}", Sha256::digest(trace.as_bytes())),
        "24344187c2a893ee4aefb6d5ffa7fa7aa32fa525f5bcb7b25b141af3e083953e"
    );
    let mut lines = trace.lines();
    assert_eq!(
        lines.next(),
        Some("linux cc9de5d4b5ab6459f5774946aa3195ad51236fa8")
    );
    let (mut layouts, mut values, mut u32_limits) = (0, 0, 0);
    for line in lines {
        let fields: Vec<_> = line.split_whitespace().collect();
        let numbers: Vec<i64> = fields[1..]
            .iter()
            .map(|value| value.parse().unwrap())
            .collect();
        let protocol = u8::try_from(numbers[0]).unwrap();
        let feature = FeatureControl::from_selector(u8::try_from(numbers[1]).unwrap()).unwrap();
        let layout = feature.layout(protocol).unwrap();
        let width = usize::try_from(numbers[3]).unwrap();
        assert_eq!(usize::from(layout.width().bytes), width);
        match fields[0] {
            "layout" => {
                assert_eq!(numbers.len(), 4);
                layouts += 1;
            }
            "value" => {
                assert_eq!(numbers.len(), 7);
                let raw = u32::try_from(numbers[4]).unwrap();
                let bytes = raw.to_le_bytes();
                let decoded = layout.decode(&bytes[..width]);
                match (numbers[2], decoded) {
                    (0, FeatureValue::Enabled(value)) => assert_eq!(i64::from(value), numbers[5]),
                    (2, FeatureValue::Tone(value)) => assert_eq!(i64::from(value), numbers[5]),
                    (4, FeatureValue::GainDb256(value)) => {
                        assert_eq!(i64::from(value), numbers[5])
                    }
                    (5, FeatureValue::Delay(value)) => assert_eq!(i64::from(value), numbers[5]),
                    (7, FeatureValue::Delay(value)) => {
                        assert_eq!(numbers[5] as u32, value); // original int preserves raw bits
                        assert_eq!(numbers[6], 0); // missing original U32 encode case
                        u32_limits += 1;
                    }
                    other => panic!("feature type differs from exact Linux table: {other:?}"),
                }
                let encoded = layout.width().encode(layout.numeric(decoded).unwrap());
                // `!!val` normalizes a nonzero boolean before it is written.
                if numbers[2] != 0 || raw <= 1 {
                    assert_eq!(encoded, &bytes[..width]);
                }
                if numbers[2] != 7 {
                    let mut word = [0; 4];
                    word[..width].copy_from_slice(&encoded);
                    assert_eq!(u32::from_le_bytes(word), numbers[6] as u32);
                }
                values += 1;
            }
            kind => panic!("unknown scalar source record {kind}"),
        }
    }
    assert_eq!((layouts, values, u32_limits), (27, 5175, 10));
}
