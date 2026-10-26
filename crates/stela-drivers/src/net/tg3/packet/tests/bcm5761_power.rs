// SPDX-License-Identifier: GPL-2.0-only
//! BCM5761 A0 held-D0 PHY power effects, including the actual source PLL write.
use super::*;

#[test]
fn actual_5761_phy_low_power_orders_clock_after_drain_and_restores_same_dma_for_traffic() {
    let (mut packet, pages, domain, peer) = bcm5761::attach_5761();
    let addresses = packet.memory.as_ref().unwrap().addresses().unwrap();
    for _ in 0..3 {
        assert!(packet.carrier());
        peer.lock().unwrap().hold_tx = true;
        packet.transmit(&[0xa1; 60]).unwrap();
        domain.defer.store(true, Ordering::Relaxed);
        peer.lock().unwrap().receive(&[0xb2; 60], 0, &domain);
        packet.suspend_phy().unwrap();
        let access = peer.lock().unwrap().access.len();
        assert!(packet.state == State::PhySuspended);
        assert_eq!(peer.lock().unwrap().mac[&0x360c], 0xa011_0000);
        assert_eq!(peer.lock().unwrap().phy[&0], 0x800);
        assert!(domain.posted.lock().unwrap().is_empty());
        assert!(!packet.carrier());
        assert_eq!(packet.receive().unwrap(), None);
        assert!(packet.transmit(&[0xc3; 60]).is_err());
        packet.suspend_phy().unwrap();
        assert_eq!(peer.lock().unwrap().access.len(), access);
        assert_eq!(domain.maps.lock().unwrap().len(), 6);
        assert_eq!(pages.drops.load(Ordering::Relaxed), 0);
        domain.defer.store(false, Ordering::Relaxed);
        peer.lock().unwrap().hold_tx = false;
        packet.resume_phy().unwrap();
        assert_eq!(peer.lock().unwrap().mac[&0x360c], 0xa000_0000);
        assert_eq!(
            packet.memory.as_ref().unwrap().addresses().unwrap(),
            addresses
        );
        assert_eq!(packet.receive().unwrap(), None);
        packet.transmit(&[0xd4; 60]).unwrap();
        peer.lock().unwrap().receive(&[0xe5; 60], 0, &domain);
        assert_eq!(packet.receive().unwrap(), Some(vec![0xe5; 60]));
    }
    assert_eq!(peer.lock().unwrap().sent, vec![vec![0xd4; 60]; 3]);
    assert!(packet.retire().is_ok());
    assert_eq!(pages.drops.load(Ordering::Relaxed), 6);
}

#[test]
fn actual_5761_unacknowledged_low_power_effects_poison_retains_all_original_owners() {
    for fault in 0..4 {
        let (mut packet, pages, domain, peer) = bcm5761::attach_5761();
        assert!(packet.carrier());
        {
            let mut p = peer.lock().unwrap();
            match fault {
                0 => p.ignore_write = Some(0x360c),
                1 => p.fail_write = Some(0x360c),
                2 => {
                    let next = p.read_counts[&0x360c] + 1;
                    p.fail_read_on = Some((0x360c, next));
                }
                _ => p.ignore_phy_write = Some((0, 0x800)),
            }
        }
        let start = peer.lock().unwrap().phy_writes.len();
        assert!(packet.suspend_phy().is_err());
        assert!(packet.state == State::Faulted);
        {
            let p = peer.lock().unwrap();
            assert_eq!(p.phy_writes[start..].contains(&(0, 0x800)), fault == 3);
            assert_eq!(p.phy[&0] & 0x800, 0);
        }
        assert_eq!(peer.lock().unwrap().config[&4] & 4, 0);
        assert!(domain.drained.load(Ordering::Relaxed));
        assert_eq!(domain.maps.lock().unwrap().len(), 6);
        assert_eq!(pages.drops.load(Ordering::Relaxed), 0);
        {
            let mut p = peer.lock().unwrap();
            p.ignore_write = None;
            p.fail_write = None;
            p.fail_read_on = None;
            p.ignore_phy_write = None;
        }
        assert_eq!(packet.stop(), Err(Error::Poisoned));
        assert!(packet.retire().is_err());
        assert_eq!(peer.lock().unwrap().drops, 0);
    }
}

#[test]
fn actual_5761_low_power_refuses_undrained_epoch_and_live_board_keep_link_policy() {
    for fault in 0..2 {
        let (mut packet, _, domain, peer) = bcm5761::attach_5761();
        assert!(packet.carrier());
        if fault == 0 {
            domain.fail_drain.store(true, Ordering::Relaxed);
        } else {
            peer.lock().unwrap().sram.insert(0xd3c, 0x400000);
        }
        let start = peer.lock().unwrap().phy_writes.len();
        let before = peer.lock().unwrap().access.len();
        assert!(packet.suspend_phy().is_err());
        assert_eq!(peer.lock().unwrap().phy_writes.len(), start);
        assert!(
            !peer.lock().unwrap().access[before..]
                .iter()
                .any(|(write, at, _)| *write && *at == 0x360c)
        );
        domain.fail_drain.store(false, Ordering::Relaxed);
        assert!(packet.retire().is_ok());
    }
}

#[test]
#[ignore = "set STELA_TG3_BCM5761_PHY_POWER_ORACLE from original tg3_phy_power_oracle.py bcm5761 mode"]
fn unchanged_linux_5761_phy_power_writes_match_actual_clock_and_retained_owner() {
    let trace = std::fs::read_to_string(
        std::env::var("STELA_TG3_BCM5761_PHY_POWER_ORACLE")
            .expect("fresh original C trace required"),
    )
    .unwrap();
    let mut lines = trace.lines();
    assert_eq!(lines.next(), Some("TG3_PHY_POWER_5761_V1 3"));
    let mut cases = 0;
    while let Some(line) = lines.next() {
        let header: Vec<_> = line.split_whitespace().collect();
        assert_eq!(header.len(), 2);
        assert_eq!(header[0], "CASE");
        let clock: u32 = header[1].parse().unwrap();
        let mut expected_phy = Vec::new();
        let mut expected_clock = Vec::new();
        loop {
            let row = lines.next().expect("truncated source case");
            if row == "END" {
                break;
            }
            let f: Vec<_> = row.split_whitespace().collect();
            assert_eq!(f.len(), 3);
            let (at, value) = (f[1].parse::<u32>().unwrap(), f[2].parse::<u32>().unwrap());
            match f[0] {
                "W" => expected_phy.push((at as u8, value as u16)),
                "M" => expected_clock.push((at, value)),
                _ => panic!("unexpected source row {row}"),
            }
        }
        let (mut packet, pages, domain, peer) = bcm5761::attach_5761();
        let (phy_start, access_start) = {
            let mut p = peer.lock().unwrap();
            // Selected original RMW inputs. No packet traffic is attempted
            // under these alternative source clock snapshots.
            p.mac.insert(0x360c, clock);
            (p.phy_writes.len(), p.access.len())
        };
        packet.suspend_phy().unwrap();
        {
            let p = peer.lock().unwrap();
            let actual_phy: Vec<_> = p.phy_writes[phy_start..]
                .iter()
                .copied()
                .filter(|(at, value)| !(*at == 0x18 && *value == 0x2007))
                .collect();
            let actual_clock: Vec<_> = p.access[access_start..]
                .iter()
                .filter(|(write, at, _)| *write && *at == 0x360c)
                .map(|(_, at, value)| (*at, *value))
                .collect();
            assert_eq!(actual_phy, expected_phy);
            assert_eq!(actual_clock, expected_clock);
            assert_eq!(expected_phy, [(0x10, 8), (0x18, 0x1b2), (0, 0x800)]);
            assert_eq!(expected_clock.len(), 1);
            assert_eq!(p.mac[&0x360c], expected_clock[0].1);
            assert_eq!(p.config[&4] & 4, 0);
        }
        assert!(domain.drained.load(Ordering::Relaxed));
        assert_eq!(domain.maps.lock().unwrap().len(), 6);
        assert_eq!(pages.drops.load(Ordering::Relaxed), 0);
        assert!(packet.retire().is_ok());
        cases += 1;
    }
    assert_eq!(cases, 3);
}
