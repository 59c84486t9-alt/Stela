// SPDX-License-Identifier: GPL-2.0-only
//! A real UAC2 board codec configuration descriptor (string descriptors and
//! the device descriptor left out). Its playback path has an extension unit
//! hanging off a capture feature unit and an IEC 61937 Type III alternate.
use super::super::{AudioDevice, Completion, PacketStatus, Transport, UAC1};
use super::*;
use crate::{block::BlockError, bus::dma::TestRegion, usb::descriptor::interfaces};
use alloc::collections::BTreeMap;

pub(crate) fn board_codec() -> Vec<u8> {
    let hex: Vec<u8> = include_str!("../../../../tests/reference/uac2-board-codec.hex")
        .bytes()
        .filter(u8::is_ascii_hexdigit)
        .collect();
    hex.chunks(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn binding() -> Binding {
    let c = board_codec();
    let all = interfaces(&c);
    Binding::parse(&all[0], &all, &c, HIGH_SPEED).unwrap()
}

#[test]
fn board_codec_function_parses_with_its_extension_unit() {
    let c = board_codec();
    assert_eq!(c.len(), usize::from(le16(&c, 2)));
    let b = binding();
    // Only the IEC 61937 passthrough alternate stays out, with its reason.
    assert_eq!(b.unsupported, vec![(6, 11, "UAC2 non-Type-I signed PCM")]);
    // Three stereo capture streams of 8 alternates, 8-channel speaker (12),
    // headphones (21) and S/PDIF PCM (10).
    assert_eq!(b.formats.len(), 3 * 8 + 12 + 21 + 10);
    let count = |n: u8| b.formats.iter().filter(|f| f.interface == n).count();
    assert_eq!(
        [1, 2, 3, 4, 5, 6].map(count),
        [8, 8, 8, 12, 21, 10],
        "per-interface PCM alternates"
    );
    assert!(
        b.formats
            .iter()
            .all(|f| (f.direction == Direction::Capture) == (f.interface <= 3))
    );
    // The HID interface outside the association is not claimed.
    assert_eq!(
        b.settings(),
        vec![(0, 0), (1, 0), (2, 0), (3, 0), (4, 0), (5, 0), (6, 0)]
    );
    assert_eq!(b.graph.terminal_clock(13, Direction::Playback), Ok(5));
    assert_eq!(b.graph.terminal_clock(17, Direction::Capture), Ok(1));
    assert_eq!(
        b.graph.entity(33),
        Ok(&Entity::Processing {
            id: 33,
            subtype: 9,
            sources: vec![25],
            clocks: vec![],
            cluster: Some((2, 3)),
            controls: false,
        })
    );
    assert_eq!(b.graph.signal_cluster(33), Ok((2, 3)));
    assert_eq!(b.graph.signal_cluster(21), Ok((8, 0x63f)));
    let surround = b
        .formats
        .iter()
        .find(|f| f.interface == 4 && f.channels == 8 && f.bits == 24)
        .unwrap();
    assert_eq!((surround.subslot, surround.max_bytes), (3, 0x2e8));
    assert_eq!(surround.sync, Sync::Adaptive);
}

/// A device peer for any clock: one 48 kHz rate, valid, completions at once.
#[derive(Default)]
struct Peer {
    rates: BTreeMap<u8, u32>,
    alternates: Vec<(u8, u8)>,
    active: Vec<u8>,
    pending: BTreeMap<u64, (Endpoint, u64, usize)>,
    next: u64,
    output: Vec<u8>,
    time: u64,
}
impl Control for Peer {
    fn now_us(&self) -> u64 {
        self.time
    }
    fn relax(&mut self) {
        self.time += 1000;
    }
    fn control(&mut self, r: [u8; 8], out: &[u8]) -> Result<Vec<u8>, BlockError> {
        if r[0] == 1 && r[1] == 11 {
            self.alternates.push((r[4], r[2]));
            return Ok(Vec::new());
        }
        let (entity, selector, length) = (r[5], r[3], usize::from(le16(&r, 6)));
        assert_eq!(r[4], 0, "requests address the control interface");
        match (r[0], r[1], selector) {
            (0x21, 1, 1) => {
                self.rates
                    .insert(entity, u32::from_le_bytes(out.try_into().unwrap()));
                Ok(Vec::new())
            }
            (0xa1, 1, 1) => Ok(self
                .rates
                .get(&entity)
                .copied()
                .unwrap_or(44_100)
                .to_le_bytes()
                .to_vec()),
            (0xa1, 1, 2) => Ok(vec![1]),
            (0xa1, 2, 1) => {
                let mut v = 1u16.to_le_bytes().to_vec();
                for value in [48_000u32, 48_000, 0] {
                    v.extend_from_slice(&value.to_le_bytes());
                }
                v.truncate(length);
                Ok(v)
            }
            _ => panic!("unexpected request {r:?}"),
        }
    }
}
impl Transport for Peer {
    type Ticket = u64;
    fn validate(&self) -> Result<(), BlockError> {
        Ok(())
    }
    fn preflight(&mut self, _: &[Endpoint]) -> Result<(), BlockError> {
        Ok(())
    }
    fn configure(&mut self, _: Direction, eps: &[Endpoint]) -> Result<(), BlockError> {
        self.active.extend(eps.iter().map(|e| e.address));
        Ok(())
    }
    fn deconfigure(&mut self, _: Direction, eps: &[Endpoint]) -> Result<(), BlockError> {
        for e in eps {
            self.active.retain(|a| *a != e.address);
            self.pending.retain(|_, (ep, _, _)| ep.address != e.address);
        }
        Ok(())
    }
    fn submit(&mut self, e: &Endpoint, p: u64, n: usize) -> Result<u64, BlockError> {
        assert!(self.active.contains(&e.address));
        self.next += 1;
        self.pending.insert(self.next, (*e, p, n));
        Ok(self.next)
    }
    fn completed(&mut self, t: &u64) -> Option<Result<Completion, BlockError>> {
        let (e, p, n) = self.pending.remove(t)?;
        // SAFETY: the ticket owns this live DMA buffer until its completion.
        let data = unsafe { core::slice::from_raw_parts_mut(p as *mut u8, n) };
        if e.is_in() {
            data.fill(0x5a);
        } else {
            self.output.extend_from_slice(data);
        }
        Some(Ok(Completion {
            bytes: n,
            status: PacketStatus::Success,
        }))
    }
}

#[test]
fn board_codec_streams_surround_playback_and_capture() {
    let b = binding();
    let surround = b
        .formats
        .iter()
        .position(|f| f.interface == 4 && f.channels == 8 && f.bits == 24)
        .unwrap();
    let line_in = b.formats.iter().position(|f| f.interface == 2).unwrap();
    let mut dma = TestRegion::new(80 * 1024 * 8);
    let mut a = AudioDevice::new(Peer::default(), b, &mut dma).unwrap();
    let pcm: Vec<u8> = (0..8 * 3 * 4800).map(|i| (i * 7) as u8).collect();
    a.start_playback(surround, 48_000, &pcm, true).unwrap();
    a.start_capture(line_in, 48_000).unwrap();
    for _ in 0..400 {
        if a.poll().unwrap().playback_drained {
            break;
        }
    }
    assert!(a.progress().playback_drained);
    assert_eq!(a.generation_transport().output, pcm);
    assert_eq!(a.generation_transport().rates.get(&5), Some(&48_000));
    assert_eq!(a.generation_transport().rates.get(&3), Some(&48_000));
    let mut captured = [0u8; 64];
    assert!(a.read_capture(&mut captured).unwrap() > 0);
    a.shutdown().unwrap();
    assert!(a.generation_transport().alternates.contains(&(4, 0)));
    assert!(a.generation_transport().alternates.contains(&(2, 0)));
}

#[test]
fn processing_and_extension_units_pass_the_signal_through() {
    // UAC2 extension unit: one pin, declared stereo cluster, no controls.
    let extension = [16, 0x24, 9, 7, 0xda, 0x0b, 1, 3, 2, 3, 0, 0, 0, 0, 0, 0];
    assert_eq!(
        processing_unit(&extension, UAC2, true),
        Ok(Entity::Processing {
            id: 7,
            subtype: 9,
            sources: vec![3],
            clocks: vec![],
            cluster: Some((2, 3)),
            controls: false,
        })
    );
    assert!(processing_unit(&extension[..15], UAC2, true).is_err());
    let mut padded = extension.to_vec();
    padded.push(0);
    assert!(processing_unit(&padded, UAC2, true).is_err());
    // UAC2 up/down-mix processing unit: process-specific bytes follow and an
    // advertised enable control is reported, not hidden.
    let mix = [
        22, 0x24, 8, 8, 1, 0, 1, 3, 6, 0x3f, 0, 0, 0, 0, 1, 0, 0, 1, 0x3f, 0, 0, 0,
    ];
    let unit = processing_unit(&mix, UAC2, false).unwrap();
    assert!(matches!(
        unit,
        Entity::Processing {
            cluster: Some((6, 0x3f)),
            controls: true,
            ..
        }
    ));
    let graph = Graph {
        protocol: UAC2,
        control_interface: 0,
        entities: vec![unit],
    };
    assert!(unexposed_controls(&graph).is_some());
    // UAC1 extension unit with a one-byte control bitmap.
    let uac1 = [15, 0x24, 8, 4, 0, 0, 1, 2, 2, 3, 0, 0, 1, 0, 0];
    assert!(processing_unit(&uac1[..14], UAC1, true).is_err());
    assert_eq!(
        processing_unit(&uac1, UAC1, true),
        Ok(Entity::Processing {
            id: 4,
            subtype: 8,
            sources: vec![2],
            clocks: vec![],
            cluster: Some((2, 3)),
            controls: false,
        })
    );
}

#[test]
fn effect_units_and_rate_converters_keep_the_source_cluster() {
    let mut c = board_codec();
    // Turn the extension unit into an effect unit on feature unit 25,
    // keeping the descriptor length.
    let at = c.windows(4).position(|w| w == [16, 0x24, 9, 33]).unwrap();
    c[at..at + 16].copy_from_slice(&[16, 0x24, 7, 33, 1, 0, 25, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let all = interfaces(&c);
    let b = Binding::parse(&all[0], &all, &c, HIGH_SPEED).unwrap();
    assert!(matches!(
        b.graph.entity(33),
        Ok(Entity::Processing { cluster: None, .. })
    ));
    assert_eq!(b.graph.signal_cluster(33), Ok((2, 3)));
    // A dangling effect source is still a malformed graph.
    c[at + 6] = 99;
    let all = interfaces(&c);
    assert!(Binding::parse(&all[0], &all, &c, HIGH_SPEED).is_err());
}
