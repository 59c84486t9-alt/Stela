// SPDX-License-Identifier: GPL-2.0-only
//! Real per-speed endpoint WORD effects, source flag retention and native DMA.
use super::*;

fn parts_clock(
    chip: u32,
    initial: u16,
) -> (Hardware<Reg, Timer>, Pages, Arc<Domain>, Arc<Mutex<Device>>) {
    let parts = if chip == 0x0576_1000 {
        bcm5761::parts_5761(0x1680)
    } else {
        let parts = parts();
        if chip == 0x0576_2000 {
            *parts.3.lock().unwrap() = Device::new_5762();
        }
        parts
    };
    {
        let mut peer = parts.3.lock().unwrap();
        // Adjacent Link Status remains outside every narrow WORD store.
        peer.config.insert(0x50, 0xc3a5_0000 | u32::from(initial));
        peer.clkreq_bug = chip == 0x0576_1000 && initial & 0x100 != 0;
    }
    parts
}

#[test]
fn original_enabled_clkreq_uses_actual_negotiated_speed_before_raw_tx_and_rx() {
    for initial in [0x0343, 0x0243] {
        let (hardware, pages, domain, peer) = parts_clock(0x0576_1000, initial);
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        let mut packet = match unsafe { Packet::attach(hardware, &pages, domain.clone()) } {
            Ok(packet) => packet,
            Err((error, _)) => panic!("CLKREQ attach: {error:?}"),
        };
        for aux in [0x100, 0x200, 0x300, 0x500, 0x700, 0x100, 0x700] {
            peer.lock().unwrap().phy.insert(0x19, aux);
            assert!(packet.carrier());
            let expected = if initial & 0x100 == 0 {
                initial
            } else if aux == 0x700 {
                initial | 0x100
            } else {
                initial & !0x100
            };
            assert_eq!(
                peer.lock().unwrap().config[&0x50],
                0xc3a5_0000 | u32::from(expected)
            );
            packet.transmit(&[aux as u8; 60]).unwrap();
            peer.lock().unwrap().receive(&[0x39; 60], 0, &domain);
            assert_eq!(packet.receive().unwrap(), Some(vec![0x39; 60]));
        }
        assert!(packet.retire().is_ok());
    }
}

#[test]
fn original_clkreq_bug_survives_own_low_speed_clear_phy_suspend_and_full_rebuild() {
    let (hardware, pages, domain, peer) = parts_clock(0x0576_1000, 0x0343);
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    let mut packet = match unsafe { Packet::attach(hardware, &pages, domain.clone()) } {
        Ok(packet) => packet,
        Err((error, _)) => panic!("CLKREQ attach: {error:?}"),
    };
    let mappings: Vec<_> = domain.maps.lock().unwrap().keys().copied().collect();
    for _ in 0..3 {
        peer.lock().unwrap().phy.insert(0x19, 0x500);
        assert!(packet.carrier());
        assert_eq!(peer.lock().unwrap().config[&0x50], 0xc3a5_0243);
        packet.suspend_phy().unwrap();
        packet.resume_phy().unwrap();
        // The new observation is currently clear because of our own workaround;
        // it must not erase the source flag captured from the original owner.
        peer.lock().unwrap().phy.insert(0x19, 0x700);
        assert!(packet.carrier());
        assert_eq!(peer.lock().unwrap().config[&0x50], 0xc3a5_0343);
        assert_eq!(
            domain
                .maps
                .lock()
                .unwrap()
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            mappings
        );
        assert_eq!(pages.drops.load(Ordering::Relaxed), 0);
        packet.transmit(&[0x5a; 60]).unwrap();
    }
    assert!(packet.retire().is_ok());
}

#[test]
fn uncertain_actual_clkreq_read_store_or_acknowledgement_poison_and_retain_before_tx_dma() {
    for fault in 0..3 {
        let (hardware, pages, domain, peer) = parts_clock(0x0576_1000, 0x0343);
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        let mut packet = match unsafe { Packet::attach(hardware, &pages, domain.clone()) } {
            Ok(packet) => packet,
            Err((error, _)) => panic!("CLKREQ attach: {error:?}"),
        };
        {
            let mut peer = peer.lock().unwrap();
            peer.phy.insert(0x19, 0x500);
            match fault {
                0 => peer.removed_config_read = Some(0x50),
                1 => peer.fail_config_write = Some(0x50),
                2 => peer.ignore_config_write = Some(0x50),
                _ => unreachable!(),
            }
        }
        let effects = peer.lock().unwrap().dma_effects;
        assert!(!packet.carrier());
        assert_eq!(
            packet.failure(),
            Some(match fault {
                0 => Error::Removed,
                1 => Error::Access,
                _ => Error::ConfigDidNotLatch,
            })
        );
        assert!(packet.hardware.failure().is_some());
        assert!(packet.transmit(&[0x53; 60]).is_err());
        assert!(packet.receive().is_err());
        assert_eq!(peer.lock().unwrap().dma_effects, effects);
        assert_eq!(domain.maps.lock().unwrap().len(), 6);
        assert!(packet.restart().is_err());
        drop(packet);
        assert_eq!(domain.maps.lock().unwrap().len(), 6);
        assert_eq!(peer.lock().unwrap().drops, 0);
        assert_eq!(pages.drops.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn independent_tx_peer_rejects_clkreq_corruption_before_descriptor_or_payload_dma() {
    let (hardware, pages, domain, peer) = parts_clock(0x0576_1000, 0x0343);
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    let mut packet = match unsafe { Packet::attach(hardware, &pages, domain.clone()) } {
        Ok(packet) => packet,
        Err((error, _)) => panic!("CLKREQ attach: {error:?}"),
    };
    peer.lock().unwrap().phy.insert(0x19, 0x500);
    assert!(packet.carrier());
    {
        let mut peer = peer.lock().unwrap();
        peer.config.insert(0x50, 0xc3a5_0343);
        let before = peer.dma_effects;
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            peer.require_dma(DmaPath::Tx)
        }));
        assert!(caught.is_err());
        assert_eq!(peer.dma_effects, before);
        peer.config.insert(0x50, 0xc3a5_0243);
    }
    assert!(packet.retire().is_ok());
}

#[test]
#[ignore = "oracle: STELA_TG3_CLKREQ_ORACLE"]
fn unchanged_linux_clkreq_flag_and_complete_word_policy_match_actual_packet_owner() {
    let trace = std::fs::read_to_string(
        std::env::var("STELA_TG3_CLKREQ_ORACLE").expect("fresh original source trace required"),
    )
    .unwrap();
    let mut lines = trace.lines();
    assert_eq!(lines.next(), Some("TG3_CLKREQ_V1 36"));
    let hex = |s: &str| u32::from_str_radix(s, 16).unwrap();
    let mut cases = 0;
    let mut seen = alloc::collections::BTreeSet::new();
    for line in lines {
        let row: Vec<_> = line.split_whitespace().collect();
        assert_eq!(row.len(), 7);
        assert_eq!(row[0], "CASE");
        let chip = hex(row[1]);
        let initial = hex(row[2]) as u16;
        let speed = row[3].parse::<u32>().unwrap();
        let flag = row[4].parse::<u32>().unwrap();
        let expected = hex(row[5]);
        let writes = row[6].parse::<usize>().unwrap();
        assert!(seen.insert((chip, initial, speed)));
        assert_eq!(flag, u32::from(chip == 0x0576_1000 && initial & 0x100 != 0));
        let (hardware, pages, domain, peer) = parts_clock(chip, initial);
        peer.lock().unwrap().phy.insert(
            0x19,
            match speed {
                10 => 0x200,
                100 => 0x500,
                1000 => 0x700,
                _ => panic!("source speed {speed}"),
            },
        );
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        let mut packet = match unsafe { Packet::attach(hardware, &pages, domain.clone()) } {
            Ok(packet) => packet,
            Err((error, _)) => panic!("source CLKREQ {chip:x}/{initial:x}: {error:?}"),
        };
        assert!(packet.carrier());
        {
            let peer = peer.lock().unwrap();
            assert_eq!(peer.config[&0x50], 0xc3a5_0000 | expected);
            let actual: Vec<_> = peer
                .access
                .iter()
                .filter(|(write, at, _)| *write && *at == 0x10050)
                .collect();
            assert_eq!(actual.len(), writes);
            for (_, _, value) in actual {
                assert_eq!(*value, expected);
            }
        }
        packet.transmit(&[0x6d; 60]).unwrap();
        peer.lock().unwrap().receive(&[0x47; 60], 0, &domain);
        assert_eq!(packet.receive().unwrap(), Some(vec![0x47; 60]));
        assert!(packet.retire().is_ok());
        cases += 1;
    }
    assert_eq!(cases, 36);
}
