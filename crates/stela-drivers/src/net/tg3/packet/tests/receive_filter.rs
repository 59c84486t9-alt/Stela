// SPDX-License-Identifier: GPL-2.0-only
//! MAC/hash lookup, mapped frames and kept filter lifetimes.
use super::*;
use crate::net::tg3::ReceiveFilter;

// Independent nibble-table CRC peer, distinct from production bitwise CRC and
// original Linux byte-table generator used by the C reference.
fn physical_hash(mac: &[u8]) -> usize {
    const TABLE: [u32; 16] = [
        0, 0x1db71064, 0x3b6e20c8, 0x26d930ac, 0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c,
        0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c, 0x9b64c2b0, 0x86d3d2d4, 0xa00ae278,
        0xbdbdf21c,
    ];
    let mut crc = u32::MAX;
    for byte in mac {
        crc ^= u32::from(*byte);
        crc = (crc >> 4) ^ TABLE[(crc & 15) as usize];
        crc = (crc >> 4) ^ TABLE[(crc & 15) as usize];
    }
    (crc & 127) as usize
}
impl Device {
    pub(super) fn accepts_destination(&self, frame: &[u8]) -> bool {
        assert!(frame.len() >= 14);
        let destination = &frame[..6];
        if self.mac[&0x468] & 0x100 != 0 || destination == [0xff; 6] {
            return true;
        }
        if destination[0] & 1 != 0 {
            let bit = physical_hash(destination);
            return self.mac[&(0x470 + (bit / 32) as u32 * 4)] & (1 << (bit % 32)) != 0;
        }
        for slot in 0..4 {
            let high = self.mac[&(0x410 + slot * 8)];
            let low = self.mac[&(0x414 + slot * 8)];
            if destination
                == [
                    (high >> 8) as u8,
                    high as u8,
                    (low >> 24) as u8,
                    (low >> 16) as u8,
                    (low >> 8) as u8,
                    low as u8,
                ]
            {
                return true;
            }
        }
        false
    }
}
struct FilterTime {
    waits: Arc<Mutex<Vec<u64>>>,
    fail: Arc<AtomicBool>,
}
// SAFETY: explicit isolated timer only, never native calibration permission.
unsafe impl Delay for FilterTime {
    fn check(&self) -> Result<(), crate::bus::pci::power::Error> {
        Ok(())
    }
    fn wait_us(&self, us: u64) -> Result<(), crate::bus::pci::power::Error> {
        self.waits.lock().unwrap().push(us);
        if self.fail.load(Ordering::Relaxed) {
            Err(crate::bus::pci::power::Error::Clock)
        } else {
            Ok(())
        }
    }
}
struct Fixture {
    packet: Packet<Reg, FilterTime>,
    pages: Pages,
    domain: Arc<Domain>,
    peer: Arc<Mutex<Device>>,
    waits: Arc<Mutex<Vec<u64>>>,
    fail: Arc<AtomicBool>,
}
fn fixture(chip: u32) -> Fixture {
    let (mut previous, pages, domain, peer) = if chip == 0x0576_1000 {
        bcm5761::parts_5761(0x1680)
    } else {
        let parts = parts();
        if chip == 0x0576_2000 {
            *parts.3.lock().unwrap() = Device::new_5762();
        }
        parts
    };
    peer.lock().unwrap().match_receive_filter = true;
    let waits = Arc::new(Mutex::new(Vec::new()));
    let fail = Arc::new(AtomicBool::new(false));
    // SAFETY: transfer the same original isolated register owner and its model clock.
    let hardware = unsafe {
        Hardware::new(
            previous.release_registers(),
            FilterTime {
                waits: waits.clone(),
                fail: fail.clone(),
            },
        )
    };
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    let mut packet = match unsafe { Packet::attach(hardware, &pages, domain.clone()) } {
        Ok(packet) => packet,
        Err((error, _)) => panic!("filter attach {chip:x}: {error:?}"),
    };
    assert!(packet.carrier());
    Fixture {
        packet,
        pages,
        domain,
        peer,
        waits,
        fail,
    }
}
fn frame(destination: Mac, mark: u8) -> Vec<u8> {
    let mut frame = vec![mark; 60];
    frame[..6].copy_from_slice(&destination.0);
    frame[6..12].copy_from_slice(&[2, 9, 8, 7, 6, 5]);
    frame[12..14].copy_from_slice(&[8, 0]);
    frame
}
fn delivered(f: &mut Fixture, mac: Mac, expected: bool) {
    let frame = frame(mac, 0x76);
    let before = f.peer.lock().unwrap().dma_effects;
    f.peer.lock().unwrap().receive(&frame, 0, &f.domain);
    if !expected {
        assert_eq!(
            f.peer.lock().unwrap().dma_effects,
            before,
            "MAC drop before BD/payload DMA"
        );
    }
    assert_eq!(f.packet.receive().unwrap(), expected.then_some(frame));
}
fn selective() -> ReceiveFilter {
    ReceiveFilter {
        promiscuous: false,
        all_multicast: false,
        multicast: vec![Mac([1, 0, 0x5e, 0, 0, 1]), Mac([0x33, 0x33, 0, 0, 0, 0x16])],
        unicast: vec![
            Mac([0x0a, 0x77, 0x88, 0x99, 0xaa, 0xbb]),
            Mac([2, 0xfe, 0xdc, 0xba, 0x98, 0x76]),
        ],
    }
}

#[test]
fn real_station_multicast_hash_aliases_and_promiscuous_modes_control_dma_acceptance() {
    for chip in [0x0572_0000, 0x0576_1000, 0x0576_2000] {
        let mut f = fixture(chip);
        let own = f.packet.mac();
        let foreign = Mac([2, 3, 4, 5, 6, 7]);
        let selected = selective();
        let group = selected.multicast[0];
        let alias = selected.unicast[0];
        let excluded = (2..=255)
            .map(|n| Mac([1, 0, 0x5e, 0, 1, n]))
            .find(|mac| {
                !selected
                    .multicast
                    .iter()
                    .any(|entry| physical_hash(&entry.0) == physical_hash(&mac.0))
            })
            .unwrap();
        f.packet
            .set_receive_filter(ReceiveFilter {
                all_multicast: false,
                ..ReceiveFilter::default()
            })
            .unwrap();
        delivered(&mut f, own, true);
        delivered(&mut f, Mac::BROADCAST, true);
        delivered(&mut f, foreign, false);
        delivered(&mut f, group, false);
        f.packet.set_receive_filter(selected.clone()).unwrap();
        delivered(&mut f, group, true);
        delivered(&mut f, alias, true);
        delivered(&mut f, excluded, false);
        let collision = (2..=255)
            .map(|n| Mac([1, 0, 0x5e, 0, 2, n]))
            .find(|mac| physical_hash(&mac.0) == physical_hash(&group.0))
            .unwrap();
        delivered(&mut f, collision, true); // source hardware hashing is approximate.
        f.packet
            .set_receive_filter(ReceiveFilter::default())
            .unwrap();
        delivered(&mut f, excluded, true);
        delivered(&mut f, foreign, false);
        let mut fallback = selective();
        fallback
            .unicast
            .extend([Mac([2, 1, 2, 3, 4, 5]), Mac([2, 1, 2, 3, 4, 6])]);
        f.packet.set_receive_filter(fallback).unwrap();
        delivered(&mut f, foreign, true);
        f.packet
            .set_receive_filter(ReceiveFilter {
                promiscuous: true,
                ..ReceiveFilter::default()
            })
            .unwrap();
        delivered(&mut f, foreign, true);
        assert!(f.packet.retire().is_ok());
    }
}

#[test]
fn requested_filter_survives_real_rebuild_and_phy_resume_before_receive_engine_publication() {
    for chip in [0x0572_0000, 0x0576_1000, 0x0576_2000] {
        let mut f = fixture(chip);
        let policy = selective();
        f.packet.set_receive_filter(policy.clone()).unwrap();
        let maps = f
            .domain
            .maps
            .lock()
            .unwrap()
            .keys()
            .copied()
            .collect::<Vec<_>>();
        for phy in [false, true, false, true] {
            f.peer.lock().unwrap().access.clear();
            if phy {
                f.packet.suspend_phy().unwrap();
                f.packet.resume_phy().unwrap();
            } else {
                f.packet.restart().unwrap();
            }
            assert_eq!(f.packet.receive_filter(), &policy);
            assert!(f.packet.carrier());
            let p = f.peer.lock().unwrap();
            let enabled = p
                .access
                .iter()
                .position(|(write, at, value)| *write && *at == 0x468 && value & 2 != 0)
                .unwrap();
            for at in [0x470, 0x474, 0x478, 0x47c, 0x418, 0x41c, 0x420, 0x424] {
                assert!(
                    p.access[..enabled]
                        .iter()
                        .any(|(write, offset, _)| *write && *offset == at),
                    "filter{at:x} before RX enable"
                );
            }
            assert_eq!(
                p.mac[&0x468] & 0x03000502,
                if chip == 0x0576_2000 {
                    0x03000402
                } else {
                    0x01000402
                }
            );
            drop(p);
            assert_eq!(
                f.domain
                    .maps
                    .lock()
                    .unwrap()
                    .keys()
                    .copied()
                    .collect::<Vec<_>>(),
                maps
            );
            delivered(&mut f, policy.multicast[0], true);
            delivered(&mut f, policy.unicast[0], true);
            delivered(&mut f, Mac([2, 3, 4, 5, 6, 7]), false);
            assert_eq!(f.pages.drops.load(Ordering::Relaxed), 0);
        }
        assert!(f.packet.retire().is_ok());
    }
}

#[test]
fn all_hash_bits_and_source_unused_alias_and_previously_completed_frame_semantics_are_real() {
    for chip in [0x0572_0000, 0x0576_1000, 0x0576_2000] {
        let mut f = fixture(chip);
        let groups = (0..=255)
            .map(|n| Mac([1, 0, 0x5e, 0, 3, n]))
            .collect::<Vec<_>>();
        assert_eq!(
            groups
                .iter()
                .map(|mac| physical_hash(&mac.0))
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            128
        );
        f.packet
            .set_receive_filter(ReceiveFilter {
                all_multicast: false,
                multicast: groups.clone(),
                ..ReceiveFilter::default()
            })
            .unwrap();
        for at in [0x470, 0x474, 0x478, 0x47c] {
            assert_eq!(f.peer.lock().unwrap().mac[&at], u32::MAX);
        }
        for mac in groups {
            delivered(&mut f, mac, true);
        }
        let policy = selective();
        let alias = policy.unicast[0];
        f.packet.set_receive_filter(policy).unwrap();
        f.packet
            .set_receive_filter(ReceiveFilter {
                all_multicast: false,
                ..ReceiveFilter::default()
            })
            .unwrap();
        delivered(&mut f, alias, true); // pinned source leaves now-unused exact slots.
        f.packet.restart().unwrap();
        delivered(&mut f, alias, false);
        let foreign = Mac([2, 3, 4, 5, 6, 7]);
        f.packet
            .set_receive_filter(ReceiveFilter {
                promiscuous: true,
                ..ReceiveFilter::default()
            })
            .unwrap();
        let old = frame(foreign, 0x51);
        f.peer.lock().unwrap().receive(&old, 0, &f.domain);
        f.packet
            .set_receive_filter(ReceiveFilter {
                all_multicast: false,
                ..ReceiveFilter::default()
            })
            .unwrap();
        assert_eq!(f.packet.receive().unwrap(), Some(old)); // do not retract a real old-policy completion.
        delivered(&mut f, foreign, false);
        assert!(f.packet.retire().is_ok());
    }
}

#[test]
fn ignored_table_alias_mode_or_settling_wait_cannot_publish_a_policy_or_release_original_owners() {
    for chip in [0x0572_0000, 0x0576_1000, 0x0576_2000] {
        for fault in 0..4 {
            let mut f = fixture(chip);
            let before = f.packet.receive_filter().clone();
            let mut wanted = selective();
            match fault {
                0 => f.peer.lock().unwrap().ignore_write = Some(0x470),
                1 => f.peer.lock().unwrap().ignore_write = Some(0x418),
                2 => {
                    f.peer.lock().unwrap().ignore_write = Some(0x468);
                    wanted.promiscuous = true;
                }
                3 => {
                    f.fail.store(true, Ordering::Relaxed);
                    wanted.promiscuous = true;
                }
                _ => unreachable!(),
            }
            assert_eq!(
                f.packet.set_receive_filter(wanted),
                Err(if fault == 3 {
                    Error::Clock
                } else {
                    Error::ConfigDidNotLatch
                })
            );
            assert_eq!(f.packet.receive_filter(), &before);
            assert!(f.packet.hardware.failure().is_some());
            let effects = f.peer.lock().unwrap().dma_effects;
            assert!(f.packet.receive().is_err());
            assert!(f.packet.transmit(&frame(f.packet.mac(), 0x33)).is_err());
            assert_eq!(f.peer.lock().unwrap().dma_effects, effects);
            assert_eq!(f.domain.maps.lock().unwrap().len(), 6);
            drop(f.packet);
            assert_eq!(f.peer.lock().unwrap().drops, 0);
            assert_eq!(f.pages.drops.load(Ordering::Relaxed), 0);
        }
    }
}

#[test]
fn malformed_lists_and_stopped_or_phy_suspended_calls_refuse_before_any_filter_effect() {
    let mut f = fixture(0x0576_1000);
    let before = f.peer.lock().unwrap().access.len();
    for policy in [
        ReceiveFilter {
            multicast: vec![Mac([2, 1, 2, 3, 4, 5])],
            ..ReceiveFilter::default()
        },
        ReceiveFilter {
            unicast: vec![Mac::BROADCAST],
            ..ReceiveFilter::default()
        },
        ReceiveFilter {
            unicast: vec![Mac([0; 6])],
            ..ReceiveFilter::default()
        },
    ] {
        assert_eq!(f.packet.set_receive_filter(policy), Err(Error::InvalidMac));
        assert_eq!(f.peer.lock().unwrap().access.len(), before);
        assert_eq!(f.packet.failure(), None);
    }
    f.packet.stop().unwrap();
    let before = f.peer.lock().unwrap().access.len();
    assert_eq!(
        f.packet.set_receive_filter(selective()),
        Err(Error::Stopped)
    );
    assert_eq!(f.peer.lock().unwrap().access.len(), before);
    f.packet.restart().unwrap();
    f.packet.suspend_phy().unwrap();
    let before = f.peer.lock().unwrap().access.len();
    assert_eq!(
        f.packet.set_receive_filter(selective()),
        Err(Error::Stopped)
    );
    assert_eq!(f.peer.lock().unwrap().access.len(), before);
    f.packet.resume_phy().unwrap();
    assert!(f.packet.retire().is_ok());
}

fn source_policy(case: u32) -> ReceiveFilter {
    let mut policy = ReceiveFilter {
        promiscuous: case == 2 || case == 8,
        all_multicast: case == 1,
        multicast: Vec::new(),
        unicast: Vec::new(),
    };
    if case == 3 || case >= 5 {
        policy.multicast = selective().multicast;
    }
    if case == 4 {
        policy.multicast = (0..=255).map(|n| Mac([1, 0, 0x5e, 0, 3, n])).collect();
    }
    let aliases = [
        Mac([0x0a, 0x77, 0x88, 0x99, 0xaa, 0xbb]),
        Mac([2, 0xfe, 0xdc, 0xba, 0x98, 0x76]),
        Mac([2, 1, 0xff, 0xff, 0xff, 0xff]),
        Mac([2, 1, 2, 3, 4, 6]),
    ];
    let count = match case {
        5 => 1,
        6 | 8 => 3,
        7 => 4,
        _ => 0,
    };
    policy.unicast = aliases[..count].to_vec();
    policy
}

#[test]
#[ignore = "oracle: STELA_TG3_FILTER_ORACLE"]
fn unchanged_linux_complete_receive_policy_crc_hash_slots_writes_and_settling_match_native() {
    let trace = std::fs::read_to_string(
        std::env::var("STELA_TG3_FILTER_ORACLE").expect("fresh original filter trace required"),
    )
    .unwrap();
    let mut lines = trace.lines();
    assert_eq!(lines.next(), Some("TG3_FILTER_V1 108"));
    let hex = |s: &str| u32::from_str_radix(s, 16).unwrap();
    let mut count = 0;
    let mut seen = alloc::collections::BTreeSet::new();
    while let Some(line) = lines.next() {
        let head = line.split_whitespace().collect::<Vec<_>>();
        assert_eq!(head.len(), 4);
        assert_eq!(head[0], "CASE");
        let chip = hex(head[1]);
        let initial = hex(head[2]);
        let case = head[3].parse::<u32>().unwrap();
        assert!(case < 9 && seen.insert((chip, initial, case)));
        let mut expected_writes = Vec::new();
        let mut expected_waits = Vec::new();
        let state = loop {
            let row = lines
                .next()
                .expect("source effect/state")
                .split_whitespace()
                .collect::<Vec<_>>();
            match row[0] {
                "W" => {
                    assert_eq!(row.len(), 3);
                    expected_writes.push((hex(row[1]), hex(row[2])));
                }
                "D" => {
                    assert_eq!(row.len(), 2);
                    expected_waits.push(row[1].parse::<u64>().unwrap());
                }
                "STATE" => {
                    assert_eq!(row.len(), 12);
                    break row[1..].iter().map(|v| hex(v)).collect::<Vec<_>>();
                }
                other => panic!("unknown source row {other}"),
            }
        };
        assert_eq!(lines.next(), Some("END"));
        let mut f = fixture(chip);
        let policy = source_policy(case);
        {
            let mut peer = f.peer.lock().unwrap();
            peer.mac.insert(0x468, initial);
            for h in 0..4 {
                peer.mac.insert(0x470 + h * 4, 0x12340000 + h);
            }
            peer.access.clear();
        }
        f.waits.lock().unwrap().clear();
        f.packet.set_receive_filter(policy.clone()).unwrap();
        assert_eq!(f.packet.receive_filter(), &policy);
        {
            let peer = f.peer.lock().unwrap();
            let actual = peer
                .access
                .iter()
                .filter(|(write, _, _)| *write)
                .map(|(_, at, value)| (*at, *value))
                .collect::<Vec<_>>();
            assert_eq!(
                actual, expected_writes,
                "complete original writes {chip:x}/{initial:x}/{case}"
            );
            let registers = [
                0x468, 0x470, 0x474, 0x478, 0x47c, 0x418, 0x41c, 0x420, 0x424, 0x428, 0x42c,
            ];
            for (at, value) in registers.into_iter().zip(&state) {
                assert_eq!(peer.mac[&at], *value, "source state {at:x}");
            }
        }
        assert_eq!(
            *f.waits.lock().unwrap(),
            expected_waits,
            "original minimum settling requests"
        );
        let own = f.packet.mac();
        delivered(&mut f, own, true);
        delivered(&mut f, Mac([2, 3, 4, 5, 6, 7]), state[0] & 0x100 != 0);
        let group = Mac([1, 0, 0x5e, 0, 0, 1]);
        let bit = physical_hash(&group.0);
        delivered(
            &mut f,
            group,
            state[0] & 0x100 != 0 || state[1 + bit / 32] & (1 << (bit % 32)) != 0,
        );
        assert!(f.packet.retire().is_ok());
        count += 1;
    }
    assert_eq!(count, 108);
}

#[test]
fn all_ones_filter_data_requires_independent_pci_identity_and_mmio_liveness() {
    for chip in [0x0572_0000, 0x0576_1000, 0x0576_2000] {
        let mut f = fixture(chip);
        let alias = Mac([2, 1, 0xff, 0xff, 0xff, 0xff]);
        f.packet
            .set_receive_filter(ReceiveFilter {
                unicast: vec![alias],
                ..ReceiveFilter::default()
            })
            .unwrap();
        for at in [0x470, 0x474, 0x478, 0x47c, 0x41c] {
            assert_eq!(f.peer.lock().unwrap().mac[&at], u32::MAX);
        }
        delivered(&mut f, alias, true);
        assert!(f.packet.retire().is_ok());
        for fault in 0..3 {
            let mut f = fixture(chip);
            {
                let mut peer = f.peer.lock().unwrap();
                match fault {
                    0 => peer.removed_config_read = Some(0),
                    1 => peer.removed_read = Some(0x400),
                    2 => {
                        peer.config.insert(0, 0x123414e4);
                    }
                    _ => unreachable!(),
                }
            }
            assert_eq!(
                f.packet.set_receive_filter(ReceiveFilter::default()),
                Err(Error::Removed)
            );
            assert_eq!(f.packet.hardware.failure(), Some(Error::Removed));
            assert!(f.packet.receive().is_err());
            assert_eq!(f.domain.maps.lock().unwrap().len(), 6);
            drop(f.packet);
            assert_eq!(f.peer.lock().unwrap().drops, 0);
            assert_eq!(f.pages.drops.load(Ordering::Relaxed), 0);
        }
    }
}
