// SPDX-License-Identifier: GPL-2.0-only
use super::*;
use crate::{
    Clock,
    bus::thunderbolt::{
        config::{Encoded, PacketType},
        ring::{Direction, TX_DESCRIPTOR, model::*},
        router::Configured,
    },
};
use alloc::vec;
use core::sync::atomic::{AtomicBool, AtomicUsize};
struct Native {
    inventory: Inventory,
    current: AtomicBool,
    clock: Clock,
    router: Option<Configured>,
    dropped: Arc<AtomicUsize>,
}
// SAFETY: configured isolated model router and original native CM owner,
// independently of parsed data; one serialized real mapped-DMA channel.
unsafe impl Owner for Native {
    fn inventory(&self) -> &Inventory {
        &self.inventory
    }
    fn is_current(&self) -> bool {
        self.current.load(Ordering::Relaxed)
    }
    fn supports_duration(&self, us: u64) -> bool {
        self.clock.check_duration(us).is_ok()
    }
}
impl Drop for Native {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
        if let Some(r) = self.router.take() {
            // SAFETY: exact isolated configured router transfers to final kept model CM; quarantined owners never drop.
            unsafe { r.retire() };
        }
    }
}
struct Fixture {
    domain: Arc<Domain>,
    model: Arc<Model>,
    channel: Channel<Model>,
    owner: Arc<Native>,
    cursor: NativeCursor,
    router_dropped: Arc<AtomicUsize>,
}
fn fixture() -> Fixture {
    let LinkFixture {
        domain,
        model,
        channel,
        parent,
        child,
        cursor,
        dropped,
        ..
    } = link_fixture_with_protocol(1, false, 0x0e0101);
    let mut inventory = parent.retained_owner().target().clone();
    inventory.header = parent.header.clone();
    let owner = Arc::new(Native {
        inventory,
        current: AtomicBool::new(true),
        clock: Clock {
            ticks_per_microsecond: 1,
        },
        router: Some(parent),
        dropped: Arc::new(AtomicUsize::new(0)),
    });
    // SAFETY: isolated child setup transferred to kept model CM without a child command/tunnel publication.
    unsafe { child.retire() };
    Fixture {
        domain,
        model,
        channel,
        owner,
        cursor,
        router_dropped: dropped[0].clone(),
    }
}
fn rom(revision: u8) -> Vec<u8> {
    let mut bytes = vec![0; if revision == 1 { 22 } else { 16 }];
    bytes[1..9].copy_from_slice(&0x1122334455667788u64.to_le_bytes());
    bytes[13] = revision;
    if revision == 1 {
        bytes[16..20].copy_from_slice(&[0xbc, 0x9a, 0xf0, 0xde]);
    }
    let mut name = vec![68, 1];
    name.extend_from_slice(b"STELA\0");
    name.resize(68, b'V');
    bytes.extend(name);
    bytes.extend_from_slice(&[5, 2, b'D', b'P', 0, 8, 9, 0, 4, 0x34, 0x12, 0x78, 0x56]);
    bytes.extend_from_slice(&[8, 0x81, 0x90, 2, 0, 0, 0, 0]);
    bytes.extend_from_slice(&[2, 0xc2, 2, 0x87, 2, 0x86, 3, 5, 0xee]);
    seal(&mut bytes);
    bytes
}
fn seal(bytes: &mut [u8]) {
    let len = (bytes.len() - DATA_START) as u16;
    bytes[14..16].copy_from_slice(&len.to_le_bytes());
    bytes[0] = crc8(&bytes[1..9]);
    let crc = crc32(&bytes[13..]);
    bytes[9..13].copy_from_slice(&crc.to_le_bytes());
}
struct Peer {
    header: [u32; 5],
    uid: u64,
    rom: Vec<u8>,
    types: [u32; 64],
    upstream: u8,
    metadata: u32,
    command: u32,
    reads: usize,
    commands: Vec<u32>,
    writes: Vec<(u16, u32)>,
    ports: Vec<u8>,
    statuses: Vec<u8>,
    hold: bool,
    unsupported: bool,
    reject: Option<usize>,
}
impl Peer {
    fn new(f: &Fixture, rom: Vec<u8>) -> Self {
        let mut types = [0; 64];
        for a in &f.owner.inventory.adapters {
            if let AdapterObservation::Present { port, header, .. } = a {
                types[usize::from(*port)] = header.raw[2];
            }
        }
        Self {
            header: f.owner.inventory.header.raw,
            uid: 0x0123456789abcdef,
            rom,
            types,
            upstream: f.owner.inventory.upstream_port,
            metadata: 0,
            command: 0,
            reads: 0,
            commands: vec![],
            writes: vec![],
            ports: vec![],
            statuses: vec![],
            hold: false,
            unsupported: false,
            reject: None,
        }
    }
    fn respond(&mut self, domain: &Domain, model: &Model, index: usize) -> Encoded {
        let index = index % 10;
        let descriptor = domain.read32(model.descriptor_address(Direction::Tx, index) + 8);
        let kind = PacketType::try_from(((descriptor >> 12) & 15) as u8).unwrap();
        let frame = domain.data(
            model.frame_address(Direction::Tx, index),
            (descriptor & 0xfff) as usize,
        );
        let mut words: Vec<u32> = frame[..frame.len() - 4]
            .as_chunks::<4>()
            .0
            .iter()
            .map(|w| u32::from_be_bytes(*w))
            .collect();
        let address = words[2];
        let offset = (address & 8191) as u16;
        let count = ((address >> 13) & 63) as usize;
        let port = ((address >> 19) & 63) as u8;
        let space = (address >> 25) & 3;
        let writing = kind == PacketType::Write;
        let data = if space == 1 {
            assert!(!writing);
            assert_eq!((offset, count), (2, 1));
            self.ports.push(port);
            vec![self.types[usize::from(port)]]
        } else {
            assert_eq!((space, port), (2, 0));
            if writing {
                assert_eq!(count, 1);
                self.writes.push((offset, words[3]));
            }
            match offset {
                0 => {
                    assert!(!writing);
                    assert_eq!(count, 5);
                    self.header.to_vec()
                }
                7 => {
                    assert!(!writing);
                    assert_eq!(count, 2);
                    vec![self.uid as u32, (self.uid >> 32) as u32]
                }
                25 => {
                    assert_eq!(count, 1);
                    if writing {
                        self.metadata =
                            words[3] ^ u32::from(self.reject == Some(self.writes.len()));
                        vec![]
                    } else {
                        vec![self.metadata]
                    }
                }
                26 => {
                    assert_eq!(count, 1);
                    if writing {
                        assert_eq!(words[3], (1 << 31) | 0x24);
                        self.command = words[3];
                        self.reads = 0;
                        self.commands.push(self.metadata);
                        vec![]
                    } else {
                        if self.command & (1 << 31) != 0 {
                            self.reads += 1;
                            if self.reads >= 2 && !self.hold {
                                self.command &= !(1 << 31);
                                if self.unsupported {
                                    self.command |= 1 << 30;
                                } else {
                                    self.command |= u32::from(
                                        *self.statuses.get(self.commands.len() - 1).unwrap_or(&0),
                                    ) << 24;
                                }
                            }
                        }
                        vec![self.command]
                    }
                }
                9 => {
                    assert!(!writing);
                    let start = (self.metadata & 0x7ffc) as usize;
                    let requested = ((self.metadata >> 15) & 31) as usize;
                    assert_eq!(count, requested);
                    (0..count)
                        .map(|i| {
                            let mut bytes = [0; 4];
                            for (j, b) in bytes.iter_mut().enumerate() {
                                *b = *self.rom.get(start + i * 4 + j).unwrap_or(&0);
                            }
                            u32::from_le_bytes(bytes)
                        })
                        .collect()
                }
                _ => panic!("unexpected DROM frame offset"),
            }
        };
        words.truncate(3);
        words[0] |= 1 << 31;
        words[2] = (address & !(63 << 19)) | (u32::from(self.upstream) << 19);
        words.extend(data);
        incoming(kind, &words)
    }
}
fn step(
    peer: &mut Peer,
    domain: &Domain,
    model: &Model,
    cursor: &mut NativeCursor,
    read: &mut Read<Model>,
) -> Result<Option<Event>, Error> {
    if (model.read32(TX_DESCRIPTOR + 8) >> 16) as usize != cursor.tx % 10 {
        let reply = peer.respond(domain, model, cursor.tx);
        model.finish(Direction::Tx, cursor.tx % 10, &[], None);
        finish_rx(model, cursor.rx % 10, &reply);
        cursor.tx += 1;
        cursor.rx += 1;
    }
    cursor.now += 1;
    read.poll(cursor.now)
}
fn drive(
    peer: &mut Peer,
    domain: &Domain,
    model: &Model,
    cursor: &mut NativeCursor,
    read: &mut Read<Model>,
) -> Result<Acquired, Error> {
    read.poll(cursor.now)?;
    for _ in 0..4000 {
        if let Some(Event::Acquired(a)) = step(peer, domain, model, cursor, read)? {
            return Ok(a);
        }
    }
    panic!("actual DROM sequence did not complete")
}
#[test]
fn drom_frames_probe_chunks_crc_ports_names_and_original_owner() {
    for version in [1, 3] {
        for fallback in [false, true] {
            let f = fixture();
            let bytes = rom(version);
            let mut peer = Peer::new(&f, bytes.clone());
            if fallback {
                peer.uid = 0;
            }
            let Fixture {
                domain,
                model,
                channel,
                owner,
                mut cursor,
                router_dropped,
            } = f;
            // SAFETY: configured router/native CM source and same idle mapped-DMA channel.
            let mut read = unsafe { Read::new(channel, owner.clone(), cursor.now) }.unwrap();
            let acquired = drive(&mut peer, &domain, &model, &mut cursor, &mut read).unwrap();
            let mut channel = read.into_channel();
            assert_eq!(acquired.image.bytes, bytes);
            assert!(acquired.image.crc32.matches());
            assert_eq!(acquired.image.revision, version);
            assert_eq!(
                acquired.image.uid,
                if version == 1 && fallback {
                    0x1122334455667788
                } else {
                    peer.uid
                }
            );
            assert_eq!(
                acquired.image.uid_source,
                if version == 1 && fallback {
                    UidSource::V1DromFallback
                } else {
                    UidSource::Router
                }
            );
            assert_eq!(
                acquired.image.product,
                if version == 1 {
                    (0x9abc, 0xdef0)
                } else {
                    (0x1234, 0x5678)
                }
            );
            assert_eq!(acquired.image.vendor_name(), Some(&b"STELA"[..]));
            assert_eq!(acquired.image.device_name(), Some(&b"DP"[..]));
            assert_eq!(peer.ports, vec![1, 6]);
            assert_eq!(peer.commands[0], (1 << 15) | 12);
            assert_eq!(peer.commands[1], 16 << 15);
            assert!(peer.commands.len() >= 3);
            assert!(acquired.image.entries.iter().any(|e| e.index == 1
                && matches!(
                    e.kind,
                    Kind::Port {
                        lane: Some(Lane {
                            link_number: 1,
                            dual_port: Some(2)
                        }),
                        ..
                    }
                )));
            assert!(
                acquired
                    .image
                    .entries
                    .iter()
                    .any(|e| e.index == 7 && matches!(e.kind, Kind::Port { extra: true, .. }))
            );
            drop(owner);
            assert_eq!(router_dropped.load(Ordering::Relaxed), 0);
            // SAFETY: original native model CM takes the completed observed data/router before final drain.
            unsafe { acquired.retire() };
            assert_eq!(router_dropped.load(Ordering::Relaxed), 1);
            channel_release(&mut channel);
        }
    }
}
#[test]
fn source_crc32_mismatch_is_explicit_while_v1_uid_and_unknown_revision_fail() {
    for fault in 0..3 {
        let f = fixture();
        let mut bytes = rom(if fault == 2 {
            2
        } else if fault == 1 {
            1
        } else {
            3
        });
        if fault == 0 {
            bytes[9] ^= 1;
        }
        if fault == 1 {
            bytes[0] ^= 1;
        }
        let mut peer = Peer::new(&f, bytes);
        let Fixture {
            domain,
            model,
            channel,
            owner,
            mut cursor,
            router_dropped,
        } = f;
        // SAFETY: same model; received integrity/revision failures are never permission.
        let mut read = unsafe { Read::new(channel, owner.clone(), cursor.now) }.unwrap();
        let result = drive(&mut peer, &domain, &model, &mut cursor, &mut read);
        if fault == 0 {
            let acquired = result.expect("source warning continues");
            assert!(!acquired.image.crc32.matches());
            drop(acquired);
        } else {
            assert!(matches!(
                result,
                Err(Error::UidCrc { .. } | Error::UnsupportedRevision(2))
            ));
            assert!(matches!(read.poll(cursor.now + 1), Err(Error::Poisoned)));
            assert!(peer.ports.is_empty());
        }
        let mut channel = read.into_channel();
        drop(owner);
        assert_eq!(router_dropped.load(Ordering::Relaxed), 0);
        channel_release(&mut channel);
    }
}
#[test]
fn source_read_status_retry_budget_is_global_per_read_and_acked_status_only() {
    for exhausted in [false, true] {
        let f = fixture();
        let mut peer = Peer::new(&f, rom(3));
        peer.statuses = if exhausted {
            vec![0, 1, 0, 1, 1, 1]
        } else {
            vec![1, 0, 1, 0, 1, 1, 0]
        };
        let Fixture {
            domain,
            model,
            channel,
            owner,
            mut cursor,
            router_dropped,
        } = f;
        // SAFETY: native CM remains held through closed read-status retries.
        let mut read = unsafe { Read::new(channel, owner.clone(), cursor.now) }.unwrap();
        let result = drive(&mut peer, &domain, &model, &mut cursor, &mut read);
        if exhausted {
            assert!(matches!(
                result,
                Err(Error::Operation(operations::Error::ResourceStatus(1)))
            ));
            assert_eq!(peer.commands.len(), 6);
        } else {
            let acquired = result.expect("three full-body retries plus separate probe budget");
            assert!(acquired.image.crc32.matches());
            assert_eq!(peer.commands.len(), 7);
            // SAFETY: fully acknowledged model reads transfer to kept native CM.
            unsafe { acquired.retire() };
        }
        let mut channel = read.into_channel();
        drop(owner);
        assert_eq!(
            router_dropped.load(Ordering::Relaxed),
            usize::from(!exhausted)
        );
        channel_release(&mut channel);
    }
}

#[test]
fn every_drom_metadata_or_command_write_failure_keeps_original_cm_and_blocks_retry() {
    for target in 1..=6 {
        for fault in 0..3 {
            let f = fixture();
            let mut peer = Peer::new(&f, rom(3));
            if fault == 2 && target % 2 == 1 {
                peer.reject = Some(target);
            }
            let Fixture {
                domain,
                model,
                channel,
                owner,
                mut cursor,
                router_dropped,
            } = f;
            // SAFETY: native model CM and mapped-DMA configuration ownership.
            let mut read = unsafe { Read::new(channel, owner.clone(), cursor.now) }.unwrap();
            read.poll(cursor.now).unwrap();
            let mut failed = false;
            for _ in 0..2000 {
                if (model.read32(TX_DESCRIPTOR + 8) >> 16) as usize != cursor.tx % 10 {
                    let before = peer.writes.len();
                    let mut reply = peer.respond(&domain, &model, cursor.tx);
                    let selected = before != peer.writes.len() && peer.writes.len() == target;
                    if selected && fault == 1 {
                        reply = controller_error(&domain, &model, &cursor);
                    }
                    if selected && fault == 2 && target % 2 == 0 {
                        peer.hold = true;
                    }
                    model.finish(Direction::Tx, cursor.tx % 10, &[], None);
                    cursor.tx += 1;
                    cursor.now += 1;
                    if selected && fault == 0 {
                        cursor.now += 501;
                    } else {
                        finish_rx(&model, cursor.rx % 10, &reply);
                        cursor.rx += 1;
                    }
                } else {
                    cursor.now += 1;
                }
                if read.poll(cursor.now).is_err() {
                    failed = true;
                    break;
                }
            }
            assert!(failed);
            assert_eq!(peer.writes.len(), target);
            let writes = model.state.lock().unwrap().writes.len();
            assert!(matches!(read.poll(cursor.now + 1), Err(Error::Poisoned)));
            assert_eq!(writes, model.state.lock().unwrap().writes.len());
            let mut channel = read.into_channel();
            assert!(matches!(
                channel.poll(cursor.now + 1),
                Err(channel::Error::Poisoned)
            ));
            drop(owner);
            assert_eq!(router_dropped.load(Ordering::Relaxed), 0);
            channel_release(&mut channel);
        }
    }
}
#[test]
fn malformed_source_lengths_port_observations_and_guard_loss_never_publish_image() {
    for fault in 0..7 {
        let f = fixture();
        let mut bytes = rom(3);
        let mut peer = Peer::new(&f, bytes.clone());
        match fault {
            0 => bytes[15] |= 0x10,
            1 => {
                bytes[14] = 0;
                bytes[15] = 0;
            }
            2 => {
                bytes[16] = 1;
                seal(&mut bytes);
            }
            3 => {
                let at = 16 + 68 + 5;
                bytes[at] = 7;
                seal(&mut bytes);
            }
            4 => {
                let at = 16 + 68 + 5 + 8;
                bytes[at + 3] = 63;
                seal(&mut bytes);
            }
            5 => peer.types[1] = 0x100101,
            6 => {}
            _ => unreachable!(),
        }
        peer.rom = bytes;
        let Fixture {
            domain,
            model,
            channel,
            owner,
            mut cursor,
            router_dropped,
        } = f;
        // SAFETY: isolated router and source; malformed live data cannot grant native rights.
        let mut read = unsafe { Read::new(channel, owner.clone(), cursor.now) }.unwrap();
        read.poll(cursor.now).unwrap();
        let mut failed = false;
        for _ in 0..800 {
            if fault == 6 && !peer.writes.is_empty() {
                owner.current.store(false, Ordering::Relaxed);
            }
            match step(&mut peer, &domain, &model, &mut cursor, &mut read) {
                Err(_) => {
                    failed = true;
                    break;
                }
                Ok(Some(Event::Acquired(_))) => panic!("malformed/changed source published"),
                _ => {}
            }
        }
        assert!(failed);
        assert!(matches!(read.poll(cursor.now + 1), Err(Error::Poisoned)));
        let mut channel = read.into_channel();
        drop(owner);
        assert_eq!(router_dropped.load(Ordering::Relaxed), 0);
        channel_release(&mut channel);
    }
}
#[test]
fn native_drom_clock_admission_precedes_uid_or_any_router_operation() {
    for rate in [0, u64::MAX, ((1u64 << 63) - 1) / MAX_DURATION_US + 1] {
        let mut f = fixture();
        Arc::get_mut(&mut f.owner).unwrap().clock = Clock {
            ticks_per_microsecond: rate,
        };
        let before = f.model.state.lock().unwrap().writes.len();
        let Fixture {
            channel,
            owner,
            model,
            cursor,
            ..
        } = f;
        assert!(matches!(
            // SAFETY: same isolated native CM; invalid native clock budget must refuse
            // before I/O.
            unsafe { Read::new(channel, owner, cursor.now) },
            Err(Error::TimerBudget {
                microseconds: MAX_DURATION_US
            })
        ));
        assert_eq!(before, model.state.lock().unwrap().writes.len());
    }
}

#[test]
#[ignore = "oracle: STELA_THUNDERBOLT_DROM_ORACLE"]
fn unchanged_linux_drom_acquisition_crc_and_port_metadata_match_native_frames() {
    extern crate std;
    let trace = std::fs::read_to_string(
        std::env::var("STELA_THUNDERBOLT_DROM_ORACLE").expect("set DROM trace"),
    )
    .unwrap();
    let hex = |s: &str| {
        assert_eq!(s.len() % 2, 0);
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect::<Vec<_>>()
    };
    let mut cases = 0;
    for line in trace.lines() {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        let n = |i: usize| fields[i].parse::<u64>().unwrap();
        assert_eq!(fields[0], "D");
        let bytes = hex(fields[7]);
        let f = fixture();
        let mut peer = Peer::new(&f, bytes.clone());
        peer.uid = n(6);
        peer.statuses = match n(4) {
            0 => vec![],
            1 => vec![1, 0, 1, 0, 1, 1, 0],
            2 => vec![0, 1, 0, 1, 1, 1],
            _ => panic!("source retry mode"),
        };
        let Fixture {
            domain,
            model,
            channel,
            owner,
            mut cursor,
            router_dropped,
        } = f;
        // SAFETY: configured isolated router and original CM, source DROM input and real mapped-DMA channel.
        let mut read = unsafe { Read::new(channel, owner.clone(), cursor.now) }.unwrap();
        let result = drive(&mut peer, &domain, &model, &mut cursor, &mut read);
        let linux_ret = fields[8].parse::<i32>().unwrap();
        let count = n(9) as usize;
        assert_eq!(peer.writes.len(), count, "case {}", cases);
        let mut at = 10;
        for (offset, word) in &peer.writes {
            assert_eq!(u64::from(*offset), n(at));
            assert_eq!(u64::from(*word), n(at + 1));
            at += 2;
        }
        let ports = n(at) as usize;
        at += 1;
        assert_eq!(
            peer.ports,
            (at..at + ports).map(|i| n(i) as u8).collect::<Vec<_>>()
        );
        at += ports;
        if linux_ret == 0 {
            let acquired = result.expect("successful original source DROM");
            let image = &acquired.image;
            assert_eq!(image.bytes, bytes);
            assert_eq!(image.uid, n(at));
            assert_eq!(image.product, (n(at + 1) as u16, n(at + 2) as u16));
            assert_eq!(
                image.crc32,
                Crc32 {
                    expected: n(at + 3) as u32,
                    actual: n(at + 4) as u32
                }
            );
            assert_eq!(image.crc32.matches(), n(3) != 1);
            assert_eq!(image.revision, n(1) as u8);
            assert_eq!(
                image.uid_source,
                if n(1) == 1 && n(2) == 1 {
                    UidSource::V1DromFallback
                } else {
                    UidSource::Router
                }
            );
            at += 5;
            for port in 1..=6 {
                let observed = image.port(port);
                assert_eq!(u64::from(observed.is_some_and(|p| p.disabled)), n(at));
                let lane = observed.and_then(|p| p.lane);
                assert_eq!(u64::from(lane.map_or(0, |p| p.link_number)), n(at + 1));
                assert_eq!(
                    u64::from(lane.and_then(|p| p.dual_port).unwrap_or(64)),
                    n(at + 2)
                );
                at += 3;
            }
            let name = |s: &str| {
                if s == "-" {
                    None
                } else if s == "_" {
                    Some(vec![])
                } else {
                    Some(hex(s))
                }
            };
            assert_eq!(image.vendor_name(), name(fields[at]).as_deref());
            assert_eq!(image.device_name(), name(fields[at + 1]).as_deref());
            at += 2;
            assert!(image.port(7).is_none());
            assert_eq!(at, fields.len());
            let mut channel = read.into_channel();
            drop(owner);
            assert_eq!(router_dropped.load(Ordering::Relaxed), 0);
            // SAFETY: original model CM takes the fully read/parsed source observations and router through final native drain.
            unsafe { acquired.retire() };
            assert_eq!(router_dropped.load(Ordering::Relaxed), 1);
            channel_release(&mut channel);
        } else {
            assert_eq!(linux_ret, -5);
            let error = match result {
                Err(e) => e,
                _ => panic!("source failed but native published image"),
            };
            if n(4) == 2 {
                assert_eq!(
                    error,
                    Error::Operation(operations::Error::ResourceStatus(1))
                );
            } else {
                assert_eq!((n(1), n(3)), (1, 2));
                assert_eq!(
                    error,
                    Error::UidCrc {
                        expected: bytes[0],
                        actual: bytes[0] ^ 1
                    }
                );
            }
            assert!(matches!(read.poll(cursor.now + 1), Err(Error::Poisoned)));
            let mut channel = read.into_channel();
            drop(owner);
            assert_eq!(router_dropped.load(Ordering::Relaxed), 0);
            channel_release(&mut channel);
        }
        cases += 1;
    }
    assert_eq!(cases, 576);
}
