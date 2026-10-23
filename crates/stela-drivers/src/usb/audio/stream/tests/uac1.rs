// SPDX-License-Identifier: GPL-2.0-or-later
//! A UAC1 device model layered on the existing independent DMA/packet transport.
//! Endpoint requests are checked against the real selected interface; no clock
//! source entity is manufactured to satisfy the UAC2 engine.
use super::*;

fn configuration() -> Vec<u8> {
    let mut v = vec![9, 2, 0, 0, 3, 1, 0, 0x80, 50];
    append(&mut v, &[9, 4, 0, 0, 0, 1, 1, 0, 0]);
    let start = v.len();
    append(&mut v, &[10, 0x24, 1, 0, 1, 0, 0, 2, 3, 7]);
    append(&mut v, &[12, 0x24, 2, 1, 1, 1, 0, 2, 3, 0, 0, 0]);
    append(&mut v, &[10, 0x24, 6, 2, 1, 1, 3, 3, 3, 0]);
    append(&mut v, &[9, 0x24, 3, 3, 1, 3, 0, 2, 0]);
    append(&mut v, &[12, 0x24, 2, 4, 1, 2, 0, 2, 3, 0, 0, 0]);
    append(&mut v, &[9, 0x24, 3, 5, 1, 1, 0, 4, 0]);
    let total = (v.len() - start) as u16;
    v[start + 5..start + 7].copy_from_slice(&total.to_le_bytes());
    for (interface, terminal, address, attrs) in [(3, 1, 1, 0x0d), (7, 5, 0x82, 0x05)] {
        append(&mut v, &[9, 4, interface, 0, 0, 1, 2, 0, 0]);
        append(&mut v, &[9, 4, interface, 1, 1, 1, 2, 0, 0]);
        append(&mut v, &[7, 0x24, 1, terminal, 1, 1, 0]);
        append(
            &mut v,
            &[14, 0x24, 2, 1, 2, 2, 16, 2, 0x44, 0xac, 0, 0x80, 0xbb, 0],
        );
        append(&mut v, &[9, 5, address, attrs, 0xc0, 0, 4, 0, 0]);
        append(&mut v, &[7, 0x25, 1, 1, 0, 0, 0]);
    }
    let n = v.len() as u16;
    v[2..4].copy_from_slice(&n.to_le_bytes());
    v
}
fn parse(bytes: &[u8]) -> Result<Binding, Error> {
    let all = interfaces(bytes);
    Binding::parse(&all[0], &all, bytes, 3)
}
struct LegacyModel {
    inner: Model,
    rates: BTreeMap<u8, u32>,
    endpoint_controls: Vec<[u8; 8]>,
    short_rate: bool,
    wrong_rate: bool,
    fail_rate: bool,
}
impl LegacyModel {
    fn new() -> Self {
        Self {
            inner: Model::new(),
            rates: BTreeMap::new(),
            endpoint_controls: Vec::new(),
            short_rate: false,
            wrong_rate: false,
            fail_rate: false,
        }
    }
}
impl Control for LegacyModel {
    fn now_us(&self) -> u64 {
        self.inner.now_us()
    }
    fn relax(&mut self) {
        self.inner.relax();
    }
    fn control(&mut self, mut r: [u8; 8], out: &[u8]) -> Result<Vec<u8>, BlockError> {
        if r[0] == 0x22 || r[0] == 0xa2 {
            self.endpoint_controls.push(r);
            assert_eq!(r[3], 1);
            assert_eq!((r[2], r[5], r[6], r[7]), (0, 0, 3, 0));
            let interface = if r[4] == 1 {
                3
            } else {
                assert_eq!(r[4], 0x82);
                7
            };
            assert_eq!(
                self.inner.alternates.last(),
                Some(&(interface, 1)),
                "rate request before real alternate ACK"
            );
            if r[0] == 0x22 {
                assert_eq!(r[1], 1);
                self.rates
                    .insert(r[4], u32::from_le_bytes([out[0], out[1], out[2], 0]));
                if self.fail_rate {
                    return Err(BlockError::Timeout);
                }
                return Ok(Vec::new());
            }
            assert_eq!(r[1], 0x81);
            let rate = if self.wrong_rate {
                32_000
            } else {
                self.rates[&r[4]]
            };
            return Ok(rate.to_le_bytes()[..if self.short_rate { 2 } else { 3 }].to_vec());
        }
        if r[0] == 0xa1 {
            match r[1] {
                0x81 => r[1] = 1,
                0x82 => return Ok((-16384_i16).to_le_bytes().to_vec()),
                0x83 => return Ok(0_i16.to_le_bytes().to_vec()),
                0x84 => return Ok(256_u16.to_le_bytes().to_vec()),
                _ => panic!("unexpected UAC1 interface request {r:?}"),
            }
        }
        // This representative unit gangs all three channel controls. The
        // original request still carries and validates the selected channel.
        if r[0] == 0xa1 || r[0] == 0x21 {
            assert!(r[2] <= 2);
            r[2] = 0;
        }
        self.inner.control(r, out)
    }
}
impl Transport for LegacyModel {
    type Ticket = u64;
    fn preflight(&mut self, endpoints: &[Endpoint]) -> Result<(), BlockError> {
        self.inner.preflight(endpoints)
    }
    fn configure(&mut self, owner: Direction, endpoints: &[Endpoint]) -> Result<(), BlockError> {
        self.inner.configure(owner, endpoints)
    }
    fn deconfigure(&mut self, owner: Direction, endpoints: &[Endpoint]) -> Result<(), BlockError> {
        self.inner.deconfigure(owner, endpoints)
    }
    fn submit(
        &mut self,
        endpoint: &Endpoint,
        physical: u64,
        bytes: usize,
    ) -> Result<u64, BlockError> {
        self.inner.submit(endpoint, physical, bytes)
    }
    fn completed(&mut self, ticket: &u64) -> Option<Result<Completion, BlockError>> {
        self.inner.completed(ticket)
    }
}
fn run(f: impl FnOnce(&mut AudioDevice<LegacyModel>)) {
    let mut memory = vec![0u64; 256 * 1024];
    let base = memory.as_mut_ptr() as u64;
    // SAFETY: exclusive test allocation outlives the transport and all its DMA.
    let mut dma = unsafe { RegionAllocator::new(base..base + memory.len() as u64 * 8) };
    let mut audio = AudioDevice::new(
        LegacyModel::new(),
        parse(&configuration()).unwrap(),
        &mut dma,
    )
    .unwrap();
    f(&mut audio);
}
#[test]
fn uac1_collection_and_actual_endpoint_rates_drive_duplex_pcm_and_controls() {
    run(|a| {
        assert_eq!(a.binding.graph.protocol, UAC1);
        assert_eq!(a.binding.formats[0].channel_config, 3);
        assert_eq!(a.binding.formats[1].channel_config, 3);
        assert_eq!(
            a.binding
                .formats
                .iter()
                .map(|f| f.interface)
                .collect::<Vec<_>>(),
            [3, 7]
        );
        assert!(
            !a.binding
                .graph
                .entities
                .iter()
                .any(|e| matches!(e, Entity::ClockSource { .. }))
        );
        a.set_mute(2, 0, true).unwrap();
        assert!(a.transport.inner.muted);
        a.set_volume(2, 1, -256).unwrap();
        assert_eq!(a.transport.inner.volume, -256);
        let pcm: Vec<u8> = (0..24000).map(|n| n as u8).collect();
        a.start_capture(1, 48_000).unwrap();
        a.start_playback(0, 48_000, &pcm, true).unwrap();
        for _ in 0..10 {
            a.poll().unwrap();
            if a.progress.playback_drained {
                break;
            }
        }
        assert!(a.progress.playback_drained);
        assert_eq!(a.transport.inner.output, pcm);
        assert!(a.progress.capture_frames > 0);
        let mut captured = vec![0; 192];
        assert_eq!(a.read_capture(&mut captured).unwrap(), 192);
        assert!(captured.iter().any(|v| *v != 0));
        assert_eq!(a.transport.rates.get(&1), Some(&48_000));
        assert_eq!(a.transport.rates.get(&0x82), Some(&48_000));
        assert_eq!(
            a.start_playback(0, 44_100, &[0; 1764], true),
            Err(Error::Busy)
        );
        a.shutdown().unwrap();
        assert!(a.transport.inner.active.is_empty());
        assert!(a.transport.inner.pending.is_empty());
    });
}
#[test]
fn uac1_rate_failure_and_readback_mismatch_never_start_or_release_uncertain_dma() {
    for fault in 0..3 {
        run(|a| {
            a.transport.fail_rate = fault == 0;
            a.transport.short_rate = fault == 1;
            a.transport.wrong_rate = fault == 2;
            let err = a.start_playback(0, 48_000, &[0; 192], true).unwrap_err();
            assert_eq!(
                err,
                match fault {
                    0 => Error::Transport(BlockError::Timeout),
                    1 => Error::ControlLength,
                    _ => Error::ControlReadback,
                }
            );
            assert!(a.transport.inner.submitted.is_empty());
            assert!(a.transport.inner.active.is_empty());
            assert_eq!(a.transport.inner.alternates.last(), Some(&(3, 0)));
        });
    }
    run(|a| {
        a.start_capture(1, 48_000).unwrap();
        a.transport.inner.cancel_fail = true;
        let before = a.transport.inner.pending.len();
        assert!(before > 0);
        assert_eq!(a.stop_capture(), Err(Error::Poisoned));
        assert_eq!(a.transport.inner.pending.len(), before);
        assert_eq!(a.start_capture(1, 48_000), Err(Error::Poisoned));
        a.transport.inner.cancel_fail = false;
        a.shutdown().unwrap();
        assert!(a.transport.inner.pending.is_empty());
    });
}
#[test]
fn uac1_unadvertised_rate_foreign_endpoint_and_invalid_controls_have_no_publication() {
    run(|a| {
        assert_eq!(
            a.start_playback(0, 32_000, &[0; 128], true),
            Err(Error::RateUnsupported)
        );
        assert!(a.transport.inner.alternates.is_empty());
        assert!(a.transport.endpoint_controls.is_empty());
        a.transport.inner.active.push(1);
        assert!(a.start_playback(0, 48_000, &[0; 192], true).is_err());
        assert!(a.transport.inner.alternates.is_empty());
        assert!(a.transport.endpoint_controls.is_empty());
        assert_eq!(a.set_volume(2, 0, -257), Err(Error::Format));
    });
}
#[test]
fn uac1_discrete_continuous_fixed_rate_and_collection_validation() {
    let mut c = configuration();
    let all = interfaces(&c);
    let f = &parse(&c).unwrap().formats[0];
    assert_eq!(f.endpoint_rates.as_ref().unwrap().ranges.len(), 2);
    let format_at = c.windows(4).position(|v| v == [14, 0x24, 2, 1]).unwrap();
    c[format_at + 7] = 0;
    c[format_at + 8..format_at + 11].copy_from_slice(&8000u32.to_le_bytes()[..3]);
    let b = parse(&c).unwrap();
    assert!(b.formats[0].endpoint_rates.as_ref().unwrap().ranges[0].contains(12345));
    assert!(!b.formats[0].endpoint_rates.as_ref().unwrap().ranges[0].contains(48001));
    for d in &mut c[format_at + 8..format_at + 11] {
        *d = 0;
    }
    assert!(parse(&c).is_err());
    let mut c = configuration();
    c[18 + 8] = 7; // duplicate collection interface
    assert!(parse(&c).is_err());
    let mut control = all[0].clone();
    control.extra[2][4] = 99; // dangling feature source
    assert!(Binding::parse(&control, &all, &configuration(), 3).is_err());
    let mut control = all[0].clone();
    control.extra[2][5] = 2; // inconsistent feature channel extent
    assert!(Binding::parse(&control, &all, &configuration(), 3).is_err());
}

#[test]
fn uac1_fixed_frequency_has_no_endpoint_request_and_standard_explicit_feedback_runs() {
    run(|a| {
        let rates = a.binding.formats[0].endpoint_rates.as_mut().unwrap();
        rates.frequency_control = false;
        rates.ranges = vec![RateRange {
            min: 48000,
            max: 48000,
            resolution: 0,
        }];
        a.start_playback(0, 48000, &[0x33; 192], true).unwrap();
        a.poll().unwrap();
        assert_eq!(a.transport.inner.output, [0x33; 192]);
        assert!(a.transport.endpoint_controls.is_empty());
    });
    let mut c = configuration();
    let alternate = c
        .windows(9)
        .position(|v| v == [9, 4, 3, 1, 1, 1, 2, 0, 0])
        .unwrap();
    c[alternate + 4] = 2;
    let endpoint = c.windows(4).position(|v| v == [9, 5, 1, 0x0d]).unwrap();
    c[endpoint + 3] = 5;
    c[endpoint + 8] = 0x83;
    c.splice(
        endpoint + 16..endpoint + 16,
        [9, 5, 0x83, 0x11, 4, 0, 4, 9, 0],
    );
    let n = c.len() as u16;
    c[2..4].copy_from_slice(&n.to_le_bytes());
    let binding = parse(&c).unwrap();
    assert!(matches!(
        binding.formats[0].sync,
        Sync::Explicit(Endpoint { address: 0x83, .. })
    ));
    if let Sync::Explicit(feedback) = binding.formats[0].sync {
        assert_eq!(feedback.interval, 10);
    }
    run(|a| {
        a.binding = binding;
        a.start_playback(0, 48000, &[0x44; 6144], true).unwrap();
        a.transport.inner.hold = true;
        a.transport.inner.time = 150_000;
        a.poll().unwrap(); // legal bRefresh=9 outlasts the default 100ms timeout
        a.transport.inner.hold = false;
        for _ in 0..3 {
            a.poll().unwrap();
            if a.progress.playback_drained {
                break;
            }
        }
        assert_eq!(a.transport.inner.output, [0x44; 6144]);
        assert!(a.progress.feedback_updates > 0);
        assert!(a.transport.inner.active.is_empty());
    });
}

#[test]
fn uac1_pitch_controls_and_shared_collection_aliases_are_checked() {
    struct Pitch {
        state: bool,
        writes: usize,
        wrong: bool,
    }
    impl Control for Pitch {
        fn now_us(&self) -> u64 {
            0
        }
        fn relax(&mut self) {}
        fn control(&mut self, r: [u8; 8], out: &[u8]) -> Result<Vec<u8>, BlockError> {
            assert_eq!(&r[2..], &[0, 2, 1, 0, 1, 0]);
            match (r[0], r[1]) {
                (0x22, 1) => {
                    assert_eq!(out, [1]);
                    self.state = true;
                    self.writes += 1;
                    Ok(Vec::new())
                }
                (0xa2, 0x81) => Ok(vec![u8::from(self.state && !self.wrong)]),
                _ => panic!("unexpected endpoint pitch request"),
            }
        }
    }
    let rates = EndpointRates {
        ranges: vec![RateRange {
            min: 48000,
            max: 48000,
            resolution: 0,
        }],
        frequency_control: false,
        pitch_control: true,
    };
    let mut io = Pitch {
        state: false,
        writes: 0,
        wrong: false,
    };
    rates.apply(&mut io, 1, 48000).unwrap();
    assert_eq!(io.writes, 1);
    io.wrong = true;
    assert_eq!(rates.apply(&mut io, 1, 48000), Err(Error::ControlReadback));
    let c = configuration();
    let mut all = interfaces(&c);
    let mut sibling = all[0].clone();
    sibling.number = 9;
    sibling.extra[0][8] = 3;
    all.push(sibling);
    assert!(Binding::parse(&all[0], &all, &c, 3).is_err());
    let mut all = interfaces(&c);
    let mut foreign = all[1].clone();
    foreign.number = 9;
    foreign.class = 3;
    foreign.endpoints = all[2].endpoints.clone();
    all.push(foreign);
    assert!(Binding::parse(&all[0], &all, &c, 3).is_err());
}

#[test]
fn uac1_full_speed_cadence_and_selector_unit_request_encoding() {
    let mut c = configuration();
    let mut at = 0;
    while at < c.len() {
        let n = usize::from(c[at]);
        if c[at + 1] == 5 {
            c[at + 6] = 1;
        }
        at += n;
    }
    let all = interfaces(&c);
    let binding = Binding::parse(&all[0], &all, &c, 1).unwrap();
    assert_eq!(binding.formats[0].service_microframes, 8);
    run(|a| {
        a.binding = binding;
        a.start_playback(0, 48000, &[0x22; 192], true).unwrap();
        a.poll().unwrap();
        assert_eq!(a.transport.inner.output, [0x22; 192]);
    });
    struct Selector(u8);
    impl Control for Selector {
        fn now_us(&self) -> u64 {
            0
        }
        fn relax(&mut self) {}
        fn control(&mut self, r: [u8; 8], out: &[u8]) -> Result<Vec<u8>, BlockError> {
            assert_eq!(&r[2..], &[0, 0, 0, 14, 1, 0]);
            match (r[0], r[1]) {
                (0x21, 1) => {
                    self.0 = out[0];
                    Ok(Vec::new())
                }
                (0xa1, 0x81) => Ok(vec![self.0]),
                _ => panic!("unexpected UAC1 selector request {r:?}"),
            }
        }
    }
    let mut graph = parse(&configuration()).unwrap().graph;
    graph.entities.push(Entity::Selector {
        id: 14,
        sources: vec![1, 4],
        controls: 3,
    });
    let mut io = Selector(1);
    graph.signal_selection(&mut io, 14, 2).unwrap();
    assert_eq!(io.0, 2);
}
