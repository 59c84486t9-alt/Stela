// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Stela contributors
//! Dma publication cases.
use super::*;

#[test]
fn descriptor_publication_is_high_before_low_and_own_before_enable() {
    use crate::bus::dma::RegionAllocator;
    let mut backing = vec![0u64; 200_000];
    let base = backing.as_mut_ptr() as u64;
    // SAFETY: backing outlives all descriptor use and has no other accesses.
    let mut dma = unsafe { RegionAllocator::new(base..base + (backing.len() * 8) as u64) };
    let mut rx = Ring::new(&mut dma, true).unwrap();
    let mut tx = Ring::new(&mut dma, true).unwrap();
    rx.initialize(true);
    tx.initialize(false);
    let time = Time::default();
    let model = Model::ready(&time);
    let hw = Hardware::new(&model, &time, revision(18), 0);
    publish(&hw, &rx, &tx, Mac([2, 3, 4, 5, 6, 7])).unwrap();
    let s = model.state.borrow();
    let at = |reg| s.writes.iter().position(|(r, _, _)| *r == reg).unwrap();
    assert!(at(TX_HIGH) < at(TX_LOW));
    assert!(at(RX_HIGH) < at(RX_LOW));
    assert!(at(RX_LOW) < at(COMMAND));
    for n in 0..DESCRIPTORS {
        assert_eq!(rx.descriptors.read::<u32>(n * DESCRIPTOR) & OWN, OWN);
    }
    drop(s);
    assert_eq!(model.read32(RX_CONFIG) & 0x3f, 0xe);
    assert_eq!(model.read16(INTERRUPT_MASK), 0);
}

#[test]
fn mac34_station_replaces_stale_exgmac_before_dma_and_relocks_on_failure() {
    use crate::bus::dma::RegionAllocator;
    for fault in [false, true] {
        let mut backing = vec![0u64; 200_000];
        let base = backing.as_mut_ptr() as u64;
        // SAFETY: backing outlives all descriptor use and has no other accesses.
        let mut dma = unsafe { RegionAllocator::new(base..base + (backing.len() * 8) as u64) };
        let mut rx = Ring::new(&mut dma, true).unwrap();
        let mut tx = Ring::new(&mut dma, true).unwrap();
        rx.initialize(true);
        tx.initialize(false);
        let time = Time::default();
        let mut model = Model::ready(&time);
        model.state.borrow_mut().eri.extend([
            (0xe0, u32::MAX),
            (0xe4, u32::MAX),
            (0xf0, u32::MAX),
            (0xf4, u32::MAX),
        ]);
        if fault {
            model.fault = Some(ERI_ADDRESS);
        }
        let hw = Hardware::new(&model, &time, revision(34), 0);
        let result = publish(&hw, &rx, &tx, Mac([2, 3, 4, 5, 6, 7]));
        let s = model.state.borrow();
        assert_eq!(s.bytes[CONFIG_LOCK], 0);
        let at = |reg| s.writes.iter().position(|(r, _, _)| *r == reg).unwrap();
        assert!(at(MAC4) < at(MAC0));
        assert!(at(MAC0) < at(ERI_ADDRESS));
        if fault {
            assert_eq!(result, Err(BlockError::Timeout));
            assert!(
                !s.writes
                    .iter()
                    .any(|(r, _, _)| matches!(*r, TX_HIGH | TX_LOW | RX_HIGH | RX_LOW | COMMAND))
            );
        } else {
            assert_eq!(result, Ok(()));
            assert_eq!(s.eri[&0xe0], 0x0504_0302);
            assert_eq!(s.eri[&0xe4], 0x0000_0706);
            assert_eq!(s.eri[&0xf0], 0x0302_0000);
            assert_eq!(s.eri[&0xf4], 0x0706_0504);
            let eri: Vec<_> = s
                .writes
                .iter()
                .enumerate()
                .filter(|(_, (r, _, _))| *r == ERI_ADDRESS)
                .map(|(i, (_, value, _))| (i, *value))
                .collect();
            assert_eq!(
                eri.iter().map(|(_, v)| *v).collect::<Vec<_>>(),
                [0x8000_f0e0, 0x8000_f0e4, 0x8000_f0f0, 0x8000_f0f4]
            );
            assert!(eri.last().unwrap().0 < at(TX_HIGH));
            assert!(at(RX_LOW) < at(COMMAND));
        }
    }
}

#[test]
fn dma_enable_readback_rejects_failed_bus_reads_and_missing_enable_bits() {
    use crate::bus::dma::RegionAllocator;
    for (command, expected) in [
        (u8::MAX, Err(BlockError::Device { status: 255 })),
        (0, Err(BlockError::Timeout)),
        (ENABLE, Ok(())),
    ] {
        let mut backing = vec![0u64; 200_000];
        let base = backing.as_mut_ptr() as u64;
        // SAFETY: backing outlives all descriptor use and has no other accesses.
        let mut dma = unsafe { RegionAllocator::new(base..base + (backing.len() * 8) as u64) };
        let mut rx = Ring::new(&mut dma, true).unwrap();
        let mut tx = Ring::new(&mut dma, true).unwrap();
        rx.initialize(true);
        tx.initialize(false);
        let time = Time::default();
        let mut model = Model::ready(&time);
        model.command_readback = Some(command);
        let hw = Hardware::new(&model, &time, revision(18), 0);
        assert_eq!(publish(&hw, &rx, &tx, Mac([2, 3, 4, 5, 6, 7])), expected);
    }
}
