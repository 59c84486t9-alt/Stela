// SPDX-License-Identifier: GPL-2.0-or-later
//! Scripted protocol contracts and real native EP0 transactions for scalar FUs.
extern crate std;
use super::*;
use crate::{block::BlockError, bus::dma::RegionAllocator, usb::xhci};
use alloc::{collections::VecDeque, rc::Rc, vec};
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
    fn write(&mut self, selector: u8, channel: u8, bytes: &[u8]) {
        self.expected.push_back(Transaction {
            request: xhci::setup(
                0x21,
                1,
                u16::from(selector) << 8 | u16::from(channel),
                0x0203,
                bytes.len() as u16,
            ),
            out: bytes.to_vec(),
            result: Ok(Vec::new()),
        });
    }
    fn ranges(
        &mut self,
        protocol: u8,
        selector: u8,
        channel: u8,
        min: &[u8],
        max: &[u8],
        resolution: &[u8],
    ) {
        if protocol == UAC1 {
            for (request, value) in [(0x82, min), (0x83, max), (0x84, resolution)] {
                self.read(selector, channel, request, value.len() as u16, value);
            }
        } else {
            self.read(selector, channel, 2, 2, &[1, 0]);
            let raw = [b"\x01\x00".as_slice(), min, max, resolution].concat();
            self.read(selector, channel, 2, raw.len() as u16, &raw);
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

#[test]
fn all_scalar_controls_issue_exact_native_widths_requests_channels_and_readbacks() {
    use FeatureControl::*;
    use FeatureValue::{Enabled, GainDb256, Tone};
    for protocol in [UAC1, UAC2, UAC3] {
        let graph = graph(protocol);
        // Independent wire cases from Linux audio_feature_info's type table.
        let mut cases = vec![
            (Bass, 3, Tone(-2), vec![0xfe], vec![0xf8], vec![8], vec![2]),
            (Mid, 4, Tone(2), vec![2], vec![0xf8], vec![8], vec![2]),
            (
                Treble,
                5,
                Tone(-4),
                vec![0xfc],
                vec![0xf8],
                vec![8],
                vec![2],
            ),
            (
                AutomaticGain,
                7,
                Enabled(true),
                vec![1],
                vec![],
                vec![],
                vec![],
            ),
            (
                BassBoost,
                9,
                Enabled(false),
                vec![0],
                vec![],
                vec![],
                vec![],
            ),
            (Loudness, 10, Enabled(true), vec![1], vec![], vec![], vec![]),
        ];
        if protocol == UAC1 {
            cases.push((
                Delay,
                8,
                FeatureValue::Delay(48),
                vec![48, 0],
                vec![16, 0],
                vec![80, 0],
                vec![16, 0],
            ));
        } else {
            cases.push((
                Delay,
                8,
                FeatureValue::Delay(0x9000_0000),
                vec![0, 0, 0, 0x90],
                vec![0, 0, 0, 0x80],
                vec![0xff; 4],
                vec![0, 0, 0, 1],
            ));
            cases.push((
                InputGain,
                11,
                GainDb256(-512),
                vec![0, 0xfe],
                vec![0, 0xf0],
                vec![0, 0],
                vec![0, 1],
            ));
            cases.push((
                InputGainPad,
                12,
                GainDb256(-4096),
                vec![0, 0xf0],
                vec![0, 0xe0],
                vec![0, 0],
                vec![0, 1],
            ));
            cases.push((
                PhaseInverter,
                13,
                Enabled(true),
                vec![1],
                vec![],
                vec![],
                vec![],
            ));
        }
        for (feature, selector, value, bytes, min, max, resolution) in cases {
            for channel in [0, 1, 2] {
                let mut peer = Peer::default();
                let request = if protocol == UAC1 { 0x81 } else { 1 };
                peer.read(selector, channel, request, bytes.len() as u16, &bytes);
                assert_eq!(
                    graph.feature_value(&mut peer, 2, channel, feature),
                    Ok(value)
                );
                if !min.is_empty() {
                    peer.ranges(protocol, selector, channel, &min, &max, &resolution);
                }
                peer.write(selector, channel, &bytes);
                peer.read(selector, channel, request, bytes.len() as u16, &bytes);
                graph
                    .set_feature_value(&mut peer, 2, channel, feature, value)
                    .unwrap();
                assert!(peer.expected.is_empty());
            }
        }
    }
}

#[test]
fn feature_admission_checks_type_access_channel_and_protocol_before_transactions() {
    let mut peer = Peer::default();
    for protocol in [UAC1, UAC2, UAC3] {
        let mut graph = graph(protocol);
        assert_eq!(
            graph.set_feature_value(
                &mut peer,
                2,
                0,
                FeatureControl::Bass,
                FeatureValue::Enabled(true)
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
                .feature_ranges(&mut peer, 2, 0, FeatureControl::AutomaticGain)
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
                .set_feature_value(&mut peer, 2, 1, FeatureControl::Bass, FeatureValue::Tone(0))
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
fn numeric_ranges_preserve_disjoint_signed_intervals_fixed_values_and_unsigned_delay() {
    let graph = graph(UAC2);
    let mut peer = Peer::default();
    peer.read(3, 0, 2, 2, &[2, 0]);
    peer.read(3, 0, 2, 8, &[2, 0, 0x80, 0xf8, 8, 7, 7, 0]);
    assert_eq!(
        graph.feature_ranges(&mut peer, 2, 0, FeatureControl::Bass),
        Ok(vec![
            FeatureRange {
                min: -128,
                max: -8,
                resolution: 8
            },
            FeatureRange {
                min: 7,
                max: 7,
                resolution: 0
            },
        ])
    );
    let mut peer = Peer::default();
    peer.ranges(UAC2, 8, 0, &[0, 0, 0, 0x80], &[0xff; 4], &[1, 0, 0, 0]);
    assert_eq!(
        graph.feature_ranges(&mut peer, 2, 0, FeatureControl::Delay),
        Ok(vec![FeatureRange {
            min: 0x8000_0000,
            max: 0xffff_ffff,
            resolution: 1,
        }])
    );
    for value in [-127, -9, 0, 8] {
        let mut peer = Peer::default();
        peer.read(3, 0, 2, 2, &[2, 0]);
        peer.read(3, 0, 2, 8, &[2, 0, 0x80, 0xf8, 8, 7, 7, 0]);
        assert_eq!(
            graph.set_feature_value(
                &mut peer,
                2,
                0,
                FeatureControl::Bass,
                FeatureValue::Tone(value)
            ),
            Err(Error::Format)
        );
        assert!(peer.expected.is_empty());
        assert!(peer.seen.iter().all(|(r, _)| r[0] == 0xa1));
    }
}

#[test]
fn malformed_short_changed_and_failed_ranges_never_publish_a_set() {
    let graph = graph(UAC2);
    for count in [0u16, 65, u16::MAX] {
        let mut peer = Peer::default();
        peer.read(3, 0, 2, 2, &count.to_le_bytes());
        assert!(
            graph
                .set_feature_value(&mut peer, 2, 0, FeatureControl::Bass, FeatureValue::Tone(0))
                .is_err()
        );
        assert!(peer.expected.is_empty());
    }
    for raw in [
        vec![2, 0, 0, 8, 1],
        vec![1, 0, 8, 0, 1],
        vec![1, 0, 0, 8, 0],
        vec![1, 0, 0, 8],
    ] {
        let mut peer = Peer::default();
        peer.read(3, 0, 2, 2, &[1, 0]);
        peer.read(3, 0, 2, 5, &raw);
        assert!(
            graph
                .set_feature_value(&mut peer, 2, 0, FeatureControl::Bass, FeatureValue::Tone(0))
                .is_err()
        );
        assert!(peer.seen.iter().all(|(r, _)| r[0] == 0xa1));
    }
    for protocol in [UAC1, UAC2, UAC3] {
        let graph = self::graph(protocol);
        let mut template = Peer::default();
        template.ranges(protocol, 3, 0, &[0xf8], &[8], &[2]);
        let count = template.expected.len();
        for failed in 0..count {
            let mut peer = Peer::default();
            peer.ranges(protocol, 3, 0, &[0xf8], &[8], &[2]);
            peer.expected[failed].result = Err(BlockError::Timeout);
            assert_eq!(
                graph.set_feature_value(
                    &mut peer,
                    2,
                    0,
                    FeatureControl::Bass,
                    FeatureValue::Tone(0)
                ),
                Err(Error::Transport(BlockError::Timeout))
            );
            assert_eq!(peer.seen.len(), failed + 1);
            assert!(peer.seen.iter().all(|(r, _)| r[0] == 0xa1));
        }
    }
}

#[test]
fn boolean_false_readback_short_replies_and_failed_sets_are_never_success() {
    for protocol in [UAC1, UAC2, UAC3] {
        let graph = graph(protocol);
        let request = if protocol == UAC1 { 0x81 } else { 1 };
        for reply in [vec![], vec![0], vec![2], vec![1, 0]] {
            let mut peer = Peer::default();
            peer.write(7, 2, &[1]);
            peer.read(7, 2, request, 1, &reply);
            assert!(
                graph
                    .set_feature_value(
                        &mut peer,
                        2,
                        2,
                        FeatureControl::AutomaticGain,
                        FeatureValue::Enabled(true)
                    )
                    .is_err()
            );
            assert!(peer.expected.is_empty());
        }
        for result in [Err(BlockError::Timeout), Ok(vec![0])] {
            let mut peer = Peer::default();
            peer.write(7, 2, &[1]);
            peer.expected[0].result = result;
            assert!(
                graph
                    .set_feature_value(
                        &mut peer,
                        2,
                        2,
                        FeatureControl::AutomaticGain,
                        FeatureValue::Enabled(true)
                    )
                    .is_err()
            );
            assert_eq!(peer.seen.len(), 1);
        }
    }
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
    // SAFETY: each test retains the original exclusive backing through owners.
    unsafe { RegionAllocator::new(start..start + memory.len() as u64 * 8) }
}

#[test]
fn actual_native_ep0_tone_delay_and_gain_controls_consume_exact_dma_and_readback() {
    let mut backing = vec![0u64; 512 * 1024];
    let mut dma = allocator(&mut backing);
    let (mut audio, model, _) = native(&mut dma);
    for (feature, selector, value, bytes, range) in [
        (
            FeatureControl::Bass,
            3u8,
            FeatureValue::Tone(-2),
            vec![0xfe],
            vec![1, 0, 0xf8, 8, 2],
        ),
        (
            FeatureControl::InputGain,
            11,
            FeatureValue::GainDb256(-512),
            vec![0, 0xfe],
            vec![1, 0, 0, 0xf0, 0, 0, 0, 1],
        ),
        (
            FeatureControl::Delay,
            8,
            FeatureValue::Delay(0x9000_0000),
            vec![0, 0, 0, 0x90],
            vec![1, 0, 0, 0, 0, 0x80, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 1],
        ),
    ] {
        let address = u16::from(selector) << 8 | 2;
        model.borrow_mut().control_replies.extend([
            (xhci::setup(0xa1, 2, address, 0x0200, 2), vec![1, 0]),
            (
                xhci::setup(0xa1, 2, address, 0x0200, range.len() as u16),
                range,
            ),
            (
                xhci::setup(0xa1, 1, address, 0x0200, bytes.len() as u16),
                bytes.clone(),
            ),
        ]);
        audio.set_feature_value(2, 2, feature, value).unwrap();
        assert!(model.borrow().control_replies.is_empty());
        assert!(model.borrow().setup.iter().any(|(r, payload)| *r
            == xhci::setup(0x21, 1, address, 0x0200, bytes.len() as u16)
            && *payload == bytes));
    }
}

#[test]
fn actual_native_ep0_short_range_stalled_set_and_false_readback_propagate_failures() {
    for failure in 0..3 {
        let mut backing = vec![0u64; 512 * 1024];
        let mut dma = allocator(&mut backing);
        let (mut audio, model, _) = native(&mut dma);
        if failure == 0 {
            model.borrow_mut().control_replies.extend([
                (xhci::setup(0xa1, 2, 3 << 8, 0x0200, 2), vec![1, 0]),
                (xhci::setup(0xa1, 2, 3 << 8, 0x0200, 5), vec![1, 0, 0xf8, 8]),
            ]);
            assert_eq!(
                audio.set_feature_value(2, 0, FeatureControl::Bass, FeatureValue::Tone(0)),
                Err(Error::ControlLength)
            );
            assert!(model.borrow().setup.iter().all(|(r, _)| r[0] != 0x21));
        } else {
            if failure == 1 {
                model.borrow_mut().stall_control = Some(1);
            } else {
                model
                    .borrow_mut()
                    .control_replies
                    .push_back((xhci::setup(0xa1, 1, 7 << 8 | 1, 0x0200, 1), vec![0]));
            }
            let result = audio.set_feature_value(
                2,
                1,
                FeatureControl::AutomaticGain,
                FeatureValue::Enabled(true),
            );
            if failure == 1 {
                assert!(matches!(
                    result,
                    Err(Error::Transport(BlockError::Device { status: 6 }))
                ));
                assert!(model.borrow().seen.contains(&14)); // actual Reset Endpoint
                assert!(model.borrow().seen.contains(&16)); // actual Set Dequeue
            } else {
                assert_eq!(result, Err(Error::ControlReadback));
            }
            assert!(model.borrow().setup.iter().any(|(r, payload)| *r
                == xhci::setup(0x21, 1, 7 << 8 | 1, 0x0200, 1)
                && *payload == [1]));
        }
    }
}

#[test]
#[ignore = "requires unchanged-source Linux scalar feature oracle trace"]
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
        assert_eq!(layout.bytes(), width);
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
                if numbers[2] == 0 && raw > 1 {
                    // The source normalizes any nonzero boolean; native strict
                    // replies refuse reserved wire values instead.
                    assert_eq!(decoded, Err(Error::ControlReadback));
                } else {
                    let decoded = decoded.unwrap();
                    match (numbers[2], decoded) {
                        (0, FeatureValue::Enabled(value)) => {
                            assert_eq!(i64::from(value), numbers[5])
                        }
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
                    let (_, encoded) = layout.encode(decoded).unwrap();
                    assert_eq!(&encoded[..width], &bytes[..width]);
                    if numbers[2] != 7 {
                        assert_eq!(u32::from_le_bytes(encoded), numbers[6] as u32);
                    }
                }
                values += 1;
            }
            kind => panic!("unknown scalar source record {kind}"),
        }
    }
    assert_eq!((layouts, values, u32_limits), (27, 5175, 10));
}
