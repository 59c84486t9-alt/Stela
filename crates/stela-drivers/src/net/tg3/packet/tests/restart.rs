// SPDX-License-Identifier: GPL-2.0-only
//! Held-D0 restart through the actual packet owner and independently modeled
//! device-visible DMA. These tests do not supply PCI power or reset authority.
use super::*;

fn attached(bcm5762: bool) -> (Packet<Reg, Timer>, Pages, Arc<Domain>, Arc<Mutex<Device>>) {
    if bcm5762 {
        bcm5762::attach_5762()
    } else {
        attach()
    }
}

fn resets(peer: &Arc<Mutex<Device>>) -> usize {
    peer.lock()
        .unwrap()
        .access
        .iter()
        .filter(|(write, at, value)| *write && *at == 0x6804 && value & 1 != 0)
        .count()
}

#[test]
fn restart_reuses_only_drained_rings_and_discards_old_uncompleted_frames() {
    for bcm5762 in [false, true] {
        let (mut packet, pages, domain, peer) = attached(bcm5762);
        let addresses = packet.memory.as_ref().unwrap().addresses().unwrap();
        for turn in 0..3 {
            assert!(packet.carrier());
            peer.lock().unwrap().hold_tx = true;
            packet.transmit(&[0xa1; 60]).unwrap();
            domain.defer.store(true, Ordering::Relaxed);
            peer.lock().unwrap().receive(&[0xb2; 60], 0, &domain);
            assert!(!domain.posted.lock().unwrap().is_empty());
            let before = resets(&peer);
            if turn == 1 {
                packet.stop().unwrap();
            }
            packet.restart().unwrap();
            assert_eq!(resets(&peer), before + 1);
            assert_eq!(domain.drains.load(Ordering::Relaxed), turn + 1);
            assert!(domain.posted.lock().unwrap().is_empty());
            assert_eq!(packet.failure(), None);
            assert!(!packet.carrier_up);
            assert_eq!(packet.tx_producer, 0);
            assert_eq!(packet.tx_consumer, 0);
            assert_eq!(packet.rx_producer, RX - 1);
            assert_eq!(packet.rx_consumer, 0);
            assert_eq!(
                packet.memory.as_ref().unwrap().addresses().unwrap(),
                addresses
            );
            assert_eq!(pages.allocated.get(), 6);
            assert_eq!(pages.drops.load(Ordering::Relaxed), 0);
            domain.defer.store(false, Ordering::Relaxed);
            peer.lock().unwrap().hold_tx = false;
            assert_eq!(
                packet.receive().unwrap(),
                None,
                "stale receive survived reset"
            );
            packet.transmit(&[0xc3; 60]).unwrap();
            peer.lock().unwrap().receive(&[0xd4; 60], 0, &domain);
            assert_eq!(packet.receive().unwrap(), Some(vec![0xd4; 60]));
        }
        assert_eq!(peer.lock().unwrap().sent, vec![vec![0xc3; 60]; 3]);
        assert!(packet.retire().is_ok());
        assert_eq!(pages.drops.load(Ordering::Relaxed), 6);
    }
}

#[test]
fn packet_completion_fault_is_cleared_only_by_successful_explicit_rebuild() {
    for bcm5762 in [false, true] {
        let (mut packet, _, domain, peer) = attached(bcm5762);
        let status = peer.lock().unwrap().status();
        domain.store(status + 16, &0x0001_0000u32.to_le_bytes());
        assert!(packet.receive().is_err());
        assert_eq!(packet.failure(), Some(Error::RingCorrupt));
        packet.restart().unwrap();
        assert_eq!(packet.failure(), None);
        assert!(packet.carrier());
        packet.transmit(&[0x68; 60]).unwrap();
        assert_eq!(peer.lock().unwrap().sent, vec![vec![0x68; 60]]);
        assert!(packet.retire().is_ok());
    }
}

#[test]
fn failed_restart_drain_never_resets_or_reuses_dma_and_can_retry_containment() {
    for bcm5762 in [false, true] {
        let (mut packet, pages, domain, peer) = attached(bcm5762);
        peer.lock().unwrap().hold_tx = true;
        packet.transmit(&[0x75; 60]).unwrap();
        domain.defer.store(true, Ordering::Relaxed);
        peer.lock().unwrap().receive(&[0x86; 60], 0, &domain);
        let before = resets(&peer);
        domain.fail_drain.store(true, Ordering::Relaxed);
        assert_eq!(
            packet.restart(),
            Err(Error::Dma(DmaError::DrainUnavailable))
        );
        assert_eq!(resets(&peer), before);
        assert!(packet.state == State::Faulted);
        assert_eq!(packet.tx_producer, 1);
        assert_eq!(domain.drains.load(Ordering::Relaxed), 0);
        assert!(!domain.posted.lock().unwrap().is_empty());
        assert_eq!(domain.maps.lock().unwrap().len(), 6);
        assert_eq!(pages.drops.load(Ordering::Relaxed), 0);
        assert!(!packet.carrier());
        assert!(packet.transmit(&[0x97; 60]).is_err());
        domain.fail_drain.store(false, Ordering::Relaxed);
        packet.restart().unwrap();
        assert_eq!(resets(&peer), before + 1);
        domain.defer.store(false, Ordering::Relaxed);
        peer.lock().unwrap().hold_tx = false;
        assert_eq!(packet.receive().unwrap(), None);
        packet.transmit(&[0xa8; 60]).unwrap();
        assert_eq!(peer.lock().unwrap().sent, vec![vec![0xa8; 60]]);
        assert!(packet.retire().is_ok());
    }
}

#[test]
fn failed_restart_engine_stop_never_drains_or_resets_the_live_epoch() {
    for bcm5762 in [false, true] {
        let (mut packet, pages, domain, peer) = attached(bcm5762);
        let before = resets(&peer);
        peer.lock().unwrap().stop_stuck = Some(0x4800);
        assert_eq!(packet.restart(), Err(Error::StopTimeout(0x4800)));
        assert_eq!(resets(&peer), before);
        assert_eq!(domain.drains.load(Ordering::Relaxed), 0);
        assert_eq!(pages.drops.load(Ordering::Relaxed), 0);
        assert!(packet.transmit(&[0x68; 60]).is_err());
        peer.lock().unwrap().stop_stuck = None;
        packet.restart().unwrap();
        assert_eq!(resets(&peer), before + 1);
        assert!(packet.retire().is_ok());
    }
}

#[test]
fn uncertain_firmware_reset_cannot_be_revived_by_another_restart() {
    for bcm5762 in [false, true] {
        let (mut packet, pages, domain, peer) = attached(bcm5762);
        peer.lock().unwrap().reset_ack = false;
        assert_eq!(packet.restart(), Err(Error::FirmwareTimeout));
        assert_eq!(packet.failure(), Some(Error::FirmwareTimeout));
        assert!(packet.state == State::Faulted);
        assert_eq!(pages.drops.load(Ordering::Relaxed), 0);
        assert_eq!(domain.maps.lock().unwrap().len(), 6);
        let before = resets(&peer);
        peer.lock().unwrap().reset_ack = true;
        assert_eq!(packet.restart(), Err(Error::Poisoned));
        assert_eq!(resets(&peer), before);
        assert!(!packet.carrier());
        assert!(packet.transmit(&[0x68; 60]).is_err());
        drop(packet);
        assert_eq!(pages.drops.load(Ordering::Relaxed), 0);
        assert_eq!(peer.lock().unwrap().drops, 0);
    }
}

#[test]
fn incomplete_attach_allocations_cannot_enter_restart() {
    for fail_after in [0, 3, 5] {
        let (hardware, mut pages, domain, peer) = parts();
        pages.fail_after = Some(fail_after);
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        let mut packet = match unsafe { Packet::attach(hardware, &pages, domain.clone()) } {
            Err((Error::Memory(MemoryError::OutOfMemory), packet)) => packet,
            _ => panic!("partial allocation must fail attachment"),
        };
        let before = resets(&peer);
        let accesses = peer.lock().unwrap().access.len();
        assert_eq!(packet.restart(), Err(Error::Stopped));
        assert_eq!(resets(&peer), before);
        assert_eq!(peer.lock().unwrap().access.len(), accesses);
        assert_eq!(domain.maps.lock().unwrap().len(), fail_after);
        assert!(packet.retire().is_ok());
        assert_eq!(pages.drops.load(Ordering::Relaxed), fail_after);
    }
}

#[test]
fn failed_mapping_retirement_permanently_refuses_packet_restart() {
    for bcm5762 in [false, true] {
        for fail_id in [1, 4] {
            let (packet, pages, domain, peer) = attached(bcm5762);
            domain.fail_unmap_id.store(fail_id, Ordering::Relaxed);
            let mut packet = match packet.retire() {
                Err((Error::Dma(DmaError::InvalidationFailed), packet)) => packet,
                _ => panic!("invalidation must refuse retirement"),
            };
            let accesses = peer.lock().unwrap().access.len();
            let before = resets(&peer);
            assert_eq!(packet.restart(), Err(Error::Stopped));
            assert_eq!(resets(&peer), before);
            assert_eq!(peer.lock().unwrap().access.len(), accesses);
            assert_eq!(domain.maps.lock().unwrap().len(), 7 - fail_id);
            assert_eq!(pages.drops.load(Ordering::Relaxed), 0);
            domain.fail_unmap_id.store(0, Ordering::Relaxed);
            assert_eq!(packet.restart(), Err(Error::Stopped));
            assert!(packet.retire().is_ok());
            assert_eq!(pages.drops.load(Ordering::Relaxed), 6);
        }
    }
}
