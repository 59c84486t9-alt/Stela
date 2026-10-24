// SPDX-License-Identifier: GPL-2.0-or-later
//! Full-protocol UAC3 device: high-capability requests have real mutable descriptor
//! replies; clock controls require observed D0, and PCM uses the DMA packet model.
use super::*;

fn configuration() -> Vec<u8> {
    let mut c = vec![9, 2, 0, 0, 3, 1, 0, 0x80, 50];
    append(&mut c, &[8, 11, 4, 3, 1, 1, 0x30, 0]);
    append(&mut c, &[9, 4, 4, 0, 0, 1, 1, 0x30, 0]);
    let h = c.len();
    append(&mut c, &[10, 0x24, 1, 1, 0, 0, 0, 0, 0, 0]);
    append(&mut c, &[12, 0x24, 11, 20, 3, 7, 0, 0, 0, 0, 0, 0]);
    for (input, feature, output, cluster, itype, otype) in [
        (1, 2, 3, 101, 0x0101u16, 0x0301u16),
        (4, 5, 6, 102, 0x0201, 0x0101),
    ] {
        let mut d = vec![
            20,
            0x24,
            2,
            input,
            itype as u8,
            (itype >> 8) as u8,
            0,
            20,
            0,
            0,
            0,
            0,
            cluster,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        append(&mut c, &d);
        d = vec![
            19, 0x24, 7, feature, input, 15, 0, 0, 0, 15, 0, 0, 0, 15, 0, 0, 0, 0, 0,
        ];
        append(&mut c, &d);
        append(
            &mut c,
            &[
                19,
                0x24,
                3,
                output,
                otype as u8,
                (otype >> 8) as u8,
                0,
                feature,
                20,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
        );
    }
    append(
        &mut c,
        &[15, 0x24, 16, 30, 0x58, 2, 0x70, 0x17, 4, 1, 2, 3, 20, 0, 0],
    );
    append(
        &mut c,
        &[14, 0x24, 16, 31, 0x58, 2, 0x70, 0x17, 3, 4, 5, 6, 0, 0],
    );
    let total = (c.len() - h) as u16;
    c[h + 4..h + 6].copy_from_slice(&total.to_le_bytes());
    for (interface, terminal, cluster, address, attrs) in [(5, 1, 101, 1, 13), (6, 6, 102, 0x82, 5)]
    {
        append(&mut c, &[9, 4, interface, 0, 0, 1, 2, 0x30, 0]);
        append(&mut c, &[9, 4, interface, 1, 1, 1, 2, 0x30, 0]);
        append(
            &mut c,
            &[
                23, 0x24, 1, terminal, 0, 0, 0, 0, cluster, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 16, 0, 0,
                0,
            ],
        );
        append(&mut c, &[7, 5, address, attrs, 0xc0, 0, 4]);
        append(&mut c, &[10, 0x25, 1, 0, 0, 0, 0, 0, 0, 0]);
    }
    total_length(&mut c);
    c
}
fn total_length(c: &mut [u8]) {
    let n = c.len() as u16;
    c[2..4].copy_from_slice(&n.to_le_bytes());
}
fn plan(c: &[u8]) -> Result<crate::usb::audio::Plan, Error> {
    let all = interfaces(c);
    crate::usb::audio::Plan::parse(&all[0], &all, c, 3)
}
fn cluster(id: u16) -> Vec<u8> {
    vec![
        19,
        0,
        0x26,
        0,
        id as u8,
        (id >> 8) as u8,
        2,
        6,
        0,
        0x20,
        1,
        2,
        0,
        6,
        0,
        0x20,
        1,
        3,
        0,
    ]
}
struct GeneralDevice {
    inner: Model,
    clusters: BTreeMap<u16, Vec<u8>>,
    queries: Vec<[u8; 8]>,
    states: [u8; 2],
    settle: [u64; 2],
    writes: Vec<(u8, u8)>,
    gains: BTreeMap<(u8, u8), i16>,
    mutes: BTreeMap<(u8, u8), bool>,
    hc_fault: u8,
    selectors: BTreeMap<u8, u8>,
    fail_idle: bool,
}
impl GeneralDevice {
    fn new() -> Self {
        Self {
            inner: Model::new(),
            clusters: BTreeMap::from([(101, cluster(101)), (102, cluster(102))]),
            queries: Vec::new(),
            states: [2, 1],
            settle: [0; 2],
            writes: Vec::new(),
            gains: BTreeMap::new(),
            mutes: BTreeMap::new(),
            hc_fault: 0,
            selectors: BTreeMap::new(),
            fail_idle: false,
        }
    }
    fn powered(&self, owner: Direction) {
        let d = usize::from(owner == Direction::Capture);
        assert_eq!(self.states[d], 0);
        assert!(self.inner.time >= self.settle[d]);
    }
}
impl Control for GeneralDevice {
    fn now_us(&self) -> u64 {
        self.inner.now_us()
    }
    fn relax(&mut self) {
        self.inner.relax();
    }
    fn control(&mut self, mut r: [u8; 8], out: &[u8]) -> Result<Vec<u8>, BlockError> {
        if r[1] == 6 {
            assert_eq!((r[0], r[4], r[5]), (0xa1, 4, 0));
            assert!(out.is_empty());
            self.queries.push(r);
            let id = u16::from_le_bytes([r[2], r[3]]);
            let n = usize::from(u16::from_le_bytes([r[6], r[7]]));
            let mut data = self.clusters[&id].clone();
            match self.hc_fault {
                1 if n == 6 => return Ok(data[..5].to_vec()),
                2 if n != 6 => return Ok(data[..data.len() - 1].to_vec()),
                3 if n != 6 => data[4] ^= 1,
                4 => data[2] = 0x24,
                5 => {
                    data[0] = 1;
                    data[1] = 0x10;
                }
                6 => data[7] = 0,
                7 => data[6] = 1,
                8 => return Err(BlockError::Timeout),
                _ => {}
            }
            return Ok(data[..n.min(data.len())].to_vec());
        }
        if r[0] == 1 && r[1] == 11 {
            let direction = if r[4] == 5 {
                Direction::Playback
            } else {
                assert_eq!(r[4], 6);
                Direction::Capture
            };
            if r[2] != 0 {
                self.powered(direction);
            }
            r[4] -= 4;
            return self.inner.control(r, out);
        }
        assert_eq!(r[4], 4);
        r[4] = 0;
        if matches!(r[5], 30 | 31) {
            assert_eq!((r[1], r[2], r[3], r[6], r[7]), (1, 0, 2, 1, 0));
            let d = usize::from(r[5] - 30);
            if r[0] == 0xa1 {
                return Ok(vec![self.states[d]]);
            }
            assert_eq!(r[0], 0x21);
            assert_eq!(out.len(), 1);
            self.writes.push((r[5], out[0]));
            if out[0] == 0 {
                let delay = match self.states[d] {
                    0 => 0,
                    1 => 30_000,
                    2 => 300_000,
                    _ => unreachable!(),
                };
                self.states[d] = 0;
                self.settle[d] = self.inner.time + delay;
            } else {
                assert_eq!(out[0], 1);
                let address = if d == 0 { 1 } else { 0x82 };
                assert!(!self.inner.active.contains(&address));
                assert!(
                    self.inner
                        .pending
                        .values()
                        .all(|(e, _, _)| e.address != address)
                );
                if self.fail_idle {
                    return Err(BlockError::Timeout);
                }
                self.states[d] = 1;
            }
            return Ok(Vec::new());
        }
        if matches!(r[5], 9 | 22) {
            assert_eq!((r[2], r[3], r[6], r[7]), (0, 1, 1, 0));
            if r[0] == 0x21 {
                self.selectors.insert(r[5], out[0]);
                return Ok(Vec::new());
            }
            return Ok(vec![self.selectors.get(&r[5]).copied().unwrap_or(1)]);
        }
        if r[5] == 23 {
            assert_eq!(r[0], 0xa1);
            assert!(matches!(r[3], 1 | 2));
            return Ok(1u16.to_le_bytes().to_vec());
        }
        if r[5] == 8 {
            assert!((1..=2).contains(&r[3]) && (1..=2).contains(&r[2]));
            let key = (8, r[3] * 16 + r[2]);
            if r[0] == 0x21 {
                self.gains
                    .insert(key, i16::from_le_bytes(out.try_into().unwrap()));
                return Ok(Vec::new());
            }
            let data = if r[1] == 2 {
                vec![1, 0, 0, 0xc0, 0, 0, 0, 1]
            } else {
                self.gains
                    .get(&key)
                    .copied()
                    .unwrap_or(0)
                    .to_le_bytes()
                    .to_vec()
            };
            let n = usize::from(u16::from_le_bytes([r[6], r[7]]));
            return Ok(data[..data.len().min(n)].to_vec());
        }
        if matches!(r[5], 20 | 21) {
            self.powered(Direction::Playback); // clock20 belongs to physical domain30
            r[5] = 10;
            return self.inner.control(r, out);
        }
        assert!(matches!(r[5], 2 | 5));
        assert!(r[2] <= 2);
        if r[3] == 1 {
            if r[0] == 0x21 {
                self.mutes.insert((r[5], r[2]), out[0] != 0);
                return Ok(Vec::new());
            }
            return Ok(vec![u8::from(
                *self.mutes.get(&(r[5], r[2])).unwrap_or(&false),
            )]);
        }
        assert_eq!(r[3], 2);
        if r[0] == 0x21 {
            self.gains
                .insert((r[5], r[2]), i16::from_le_bytes(out.try_into().unwrap()));
            return Ok(Vec::new());
        }
        let data = if r[1] == 2 {
            vec![1, 0, 0, 0xc0, 0, 0, 0, 1]
        } else {
            self.gains
                .get(&(r[5], r[2]))
                .copied()
                .unwrap_or(0)
                .to_le_bytes()
                .to_vec()
        };
        let n = usize::from(u16::from_le_bytes([r[6], r[7]]));
        Ok(data[..data.len().min(n)].to_vec())
    }
}
impl Transport for GeneralDevice {
    // Independent in-memory device peer; it owns no native attachment.
    fn validate(&self) -> Result<(), BlockError> {
        Ok(())
    }
    type Ticket = u64;
    fn preflight(&mut self, e: &[Endpoint]) -> Result<(), BlockError> {
        self.inner.preflight(e)
    }
    fn configure(&mut self, o: Direction, e: &[Endpoint]) -> Result<(), BlockError> {
        self.powered(o);
        self.inner.configure(o, e)
    }
    fn deconfigure(&mut self, o: Direction, e: &[Endpoint]) -> Result<(), BlockError> {
        self.inner.deconfigure(o, e)
    }
    fn submit(&mut self, e: &Endpoint, p: u64, n: usize) -> Result<u64, BlockError> {
        self.powered(if e.is_in() && e.attributes & 0x30 != 0x10 {
            Direction::Capture
        } else {
            Direction::Playback
        });
        self.inner.submit(e, p, n)
    }
    fn completed(&mut self, t: &u64) -> Option<Result<Completion, BlockError>> {
        self.inner.completed(t)
    }
}
fn run(c: Vec<u8>, f: impl FnOnce(&mut AudioDevice<GeneralDevice>)) {
    let mut memory = vec![0u64; 256 * 1024];
    let base = memory.as_mut_ptr() as u64;
    // SAFETY: exclusive model RAM outlives all retained DMA and device owners.
    let mut dma = unsafe { RegionAllocator::new(base..base + memory.len() as u64 * 8) };
    let mut transport = GeneralDevice::new();
    let binding = plan(&c).unwrap().discover(&mut transport).unwrap();
    let mut a = AudioDevice::new(transport, binding, &mut dma).unwrap();
    f(&mut a);
}
#[test]
fn uac3_pure_plan_requires_actual_stable_high_capability_replies_before_binding() {
    let c = configuration();
    let p = plan(&c).unwrap();
    assert!(matches!(p, crate::usb::audio::Plan::DiscoverUac3(_)));
    assert_eq!(p.settings(), vec![(4, 0), (5, 0), (6, 0)]);
    let mut transport = GeneralDevice::new();
    let b = p.discover(&mut transport).unwrap();
    assert_eq!(b.graph.protocol, UAC3);
    assert_eq!(b.basic_profile, None);
    assert_eq!(b.entity_clusters, vec![(1, 101), (4, 102)]);
    assert_eq!(b.clusters.len(), 2);
    assert_eq!(b.formats[0].cluster_id, Some(101));
    assert_eq!(b.formats[0].channels, 2);
    assert_eq!(b.formats[0].channel_config, 3);
    assert_eq!(
        transport.queries,
        vec![
            setup(0xa1, 6, 101, 4, 6),
            setup(0xa1, 6, 101, 4, 19),
            setup(0xa1, 6, 102, 4, 6),
            setup(0xa1, 6, 102, 4, 19)
        ]
    );
    assert!(transport.inner.alternates.is_empty());
    assert!(transport.inner.active.is_empty());
    assert!(transport.writes.is_empty());
    for fault in 1..=8 {
        let mut transport = GeneralDevice::new();
        transport.hc_fault = fault;
        assert!(
            plan(&c).unwrap().discover(&mut transport).is_err(),
            "accepted HCD fault {fault}"
        );
        assert!(transport.inner.alternates.is_empty());
        assert!(transport.inner.active.is_empty());
        assert!(transport.inner.submitted.is_empty());
        assert!(transport.writes.is_empty());
    }
}
#[test]
fn uac3_real_clocks_pcm_and_independent_feature_registers_observe_power_before_clock_io() {
    run(configuration(), |a| {
        a.set_mute(2, 0, true).unwrap();
        a.set_volume(2, 1, -512).unwrap();
        a.set_volume(5, 2, -256).unwrap();
        assert_eq!(a.transport.gains[&(2, 1)], -512);
        assert_eq!(a.transport.gains[&(5, 2)], -256);
        let pcm: Vec<_> = (0..12288).map(|i| i as u8).collect();
        a.start_playback(0, 48000, &pcm, true).unwrap();
        assert_eq!(a.transport.inner.time, 330_000);
        let pending = a.transport.inner.pending.len();
        let writes = a.transport.writes.clone();
        assert_eq!(a.start_capture(1, 44100), Err(Error::Busy));
        assert_eq!(a.transport.inner.pending.len(), pending);
        assert_eq!(a.transport.writes, writes);
        a.start_capture(1, 48000).unwrap();
        a.poll().unwrap();
        a.poll().unwrap();
        assert_eq!(a.transport.inner.output, pcm);
        assert!(a.progress.capture_frames > 0);
        a.transport.inner.cancel_fail = true;
        let pending = a.transport.inner.pending.len();
        assert_eq!(a.stop_capture(), Err(Error::Poisoned));
        assert_eq!(a.transport.inner.pending.len(), pending);
        assert_eq!(a.transport.states, [0, 0]);
        a.transport.inner.cancel_fail = false;
        a.transport.fail_idle = true;
        assert_eq!(a.shutdown(), Err(Error::Poisoned));
        assert!(!a.power_owners.is_empty());
        a.transport.fail_idle = false;
        a.shutdown().unwrap();
        assert_eq!(a.transport.states, [1, 1]);
    });
}
#[test]
fn uac3_discovery_validates_graph_power_domains_and_actual_cluster_relationships() {
    let base = configuration();
    for mode in 0..7 {
        let mut c = base.clone();
        match mode {
            0 => {
                let at = c.windows(4).position(|d| d == [20, 0x24, 2, 1]).unwrap();
                c[at + 7] = 99;
            }
            1 => {
                let at = c.windows(4).position(|d| d == [19, 0x24, 7, 2]).unwrap();
                c[at + 4] = 3;
            }
            2 => {
                let at = c.windows(4).position(|d| d == [14, 0x24, 16, 31]).unwrap();
                c[at + 9] = 1;
            }
            3 => {
                let at = c.windows(4).position(|d| d == [15, 0x24, 16, 30]).unwrap();
                c[at + 12] = 99;
            }
            4 => {
                let at = c.windows(4).position(|d| d == [23, 0x24, 1, 1]).unwrap();
                c[at + 8] = 103;
            }
            5 => {
                let at = c.windows(4).position(|d| d == [23, 0x24, 1, 1]).unwrap();
                c[at + 8] = 102;
            }
            6 => {
                let at = c.windows(4).position(|d| d == [10, 0x24, 1, 1]).unwrap();
                c[at + 4] -= 1;
            }
            _ => unreachable!(),
        }
        let mut transport = GeneralDevice::new();
        // A third cluster exists but has a different actual channel order.
        let mut wrong = cluster(103);
        wrong[11] = 3;
        wrong[17] = 2;
        transport.clusters.insert(103, wrong);
        if mode == 5 {
            transport.clusters.get_mut(&102).unwrap()[6] = 1;
            transport.clusters.get_mut(&102).unwrap().truncate(13);
            transport.clusters.get_mut(&102).unwrap()[0] = 13;
        }
        assert!(
            plan(&c).unwrap().discover(&mut transport).is_err(),
            "accepted graph fault {mode}"
        );
        assert!(transport.inner.submitted.is_empty());
        assert!(transport.writes.is_empty());
    }
    // Unknown channel relationships remain exact raw metadata and an explicit
    // unspecified legacy mask; discovery never invents a left/right mapping.
    let mut transport = GeneralDevice::new();
    transport.clusters.get_mut(&101).unwrap()[11] = 0x7f;
    let b = plan(&base).unwrap().discover(&mut transport).unwrap();
    assert_eq!(b.formats[0].channel_config, 0);
    assert_eq!(b.clusters[0].information[0].relationship, 0x7f);
}

fn graph_units() -> Vec<u8> {
    let mut c = configuration();
    let header = c.windows(4).position(|d| d == [10, 0x24, 1, 1]).unwrap();
    let total = u16::from_le_bytes([c[header + 4], c[header + 5]]);
    for (descriptor, clock_offset) in [
        ([20, 0x24, 2, 1], 7),
        ([20, 0x24, 2, 4], 7),
        ([19, 0x24, 3, 3], 8),
        ([19, 0x24, 3, 6], 8),
    ] {
        let at = c.windows(4).position(|d| d == descriptor).unwrap();
        c[at + clock_offset] = 23;
    }
    let feature = c.windows(4).position(|d| d == [19, 0x24, 7, 2]).unwrap();
    c[feature + 4] = 8;
    let feature = c.windows(4).position(|d| d == [19, 0x24, 7, 5]).unwrap();
    c[feature + 4] = 9;
    let domain = c.windows(4).position(|d| d == [15, 0x24, 16, 30]).unwrap();
    c[domain] = 20;
    c[domain + 8] = 9;
    c.splice(domain + 13..domain + 13, [8, 9, 21, 22, 23]);
    let stream = c
        .windows(9)
        .position(|d| d == [9, 4, 5, 0, 0, 1, 2, 0x30, 0])
        .unwrap();
    let units = [
        vec![15, 0x24, 5, 8, 1, 1, 101, 0, 0x90, 0, 0, 0, 0, 0, 0],
        vec![13, 0x24, 6, 9, 2, 4, 1, 3, 0, 0, 0, 0, 0],
        vec![12, 0x24, 11, 21, 3, 7, 0, 0, 0, 0, 0, 0],
        vec![13, 0x24, 12, 22, 2, 20, 21, 3, 0, 0, 0, 0, 0],
        vec![11, 0x24, 13, 23, 22, 5, 0, 0, 0, 0, 0],
    ];
    let added = units.iter().map(Vec::len).sum::<usize>() + 5;
    c.splice(stream..stream, units.into_iter().flatten());
    c[header + 4..header + 6].copy_from_slice(&(total + added as u16).to_le_bytes());
    total_length(&mut c);
    c
}
#[test]
fn uac3_mixer_signal_and_clock_selectors_and_multiplier_use_discovered_layouts() {
    run(graph_units(), |a| {
        assert_eq!(a.binding.graph.signal_cluster(8), Ok((2, 3)));
        assert!(a.binding.entity_clusters.contains(&(8, 101)));
        a.select_input(9, 2).unwrap();
        a.select_clock(22, 2).unwrap();
        assert_eq!(a.transport.selectors[&9], 2);
        assert_eq!(a.transport.selectors[&22], 2);
        a.set_mixer_volume(8, 1, 1, -512).unwrap();
        assert_eq!(a.mixer_volume(8, 1, 1), Ok(-512));
        assert!(a.set_mixer_volume(8, 1, 2, 0).is_err());
        let pcm = vec![0x4c; 6144];
        a.start_playback(0, 48000, &pcm, true).unwrap();
        assert!(matches!(
            a.playback.as_ref().unwrap().clock,
            StreamClock::Entity(ResolvedClock {
                source: 21,
                numerator: 1,
                denominator: 1
            })
        ));
        a.poll().unwrap();
        assert_eq!(a.transport.inner.output, pcm);
        a.shutdown().unwrap();
    });
    let mut transport = GeneralDevice::new();
    let c = transport.clusters.get_mut(&102).unwrap();
    c[11] = 3;
    c[17] = 2;
    assert!(
        plan(&graph_units())
            .unwrap()
            .discover(&mut transport)
            .is_err()
    );
}
#[test]
fn uac3_generic_implicit_feedback_uses_actual_capture_and_retires_both_power_domains() {
    let mut c = configuration();
    let output = c
        .windows(7)
        .position(|d| d == [7, 5, 1, 13, 0xc0, 0, 4])
        .unwrap();
    c[output + 3] = 5;
    let input = c
        .windows(7)
        .position(|d| d == [7, 5, 0x82, 5, 0xc0, 0, 4])
        .unwrap();
    c[input + 3] = 0x25;
    run(c, |a| {
        assert!(matches!(a.binding.formats[0].sync, Sync::Implicit { .. }));
        let pcm = vec![0x5d; 6144];
        a.start_playback(0, 48000, &pcm, true).unwrap();
        assert_eq!(a.progress.queued_playback, 0);
        for _ in 0..3 {
            a.poll().unwrap();
            if a.progress.playback_drained {
                break;
            }
        }
        assert_eq!(a.transport.inner.output, pcm);
        assert!(a.progress.feedback_updates > 0);
        assert!(a.transport.inner.pending.is_empty());
        assert_eq!(a.transport.states, [1, 1]);
    });
}
