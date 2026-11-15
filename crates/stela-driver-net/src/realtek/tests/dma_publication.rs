// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Stela contributors
//! Dma publication cases.
use super::*;

#[test]
fn descriptor_publication_is_high_before_low_and_own_before_enable() {
    use crate::bus::dma::TestRegion;
    let mut dma = TestRegion::new(200_000 * 8);
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
    use crate::bus::dma::TestRegion;
    for fault in [false, true] {
        let mut dma = TestRegion::new(200_000 * 8);
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
    use crate::bus::dma::TestRegion;
    for (command, expected) in [
        (u8::MAX, Err(BlockError::Device { status: 255 })),
        (0, Err(BlockError::Timeout)),
        (ENABLE, Ok(())),
    ] {
        let mut dma = TestRegion::new(200_000 * 8);
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

/// The failure report's line: registers, ring positions and ownership and
/// the receive events, after a publication on an RTL8168H, with the
/// station address never printed.
#[test]
fn the_diagnostic_line_names_registers_rings_and_events_without_the_address() {
    use crate::bus::dma::TestRegion;
    let mut dma = TestRegion::new(200_000 * 8);
    let mut rx = Ring::new(&mut dma, true).unwrap();
    let mut tx = Ring::new(&mut dma, true).unwrap();
    rx.initialize(true);
    tx.initialize(false);
    let time = Time::default();
    let model = Model::ready(&time);
    let hw = Hardware::new(&model, &time, revision(46), 0);
    let mac = Mac([2, 3, 4, 5, 6, 7]);
    publish(&hw, &rx, &tx, mac).unwrap();
    // One good frame and one with the error summary taken; one frame sent.
    rx.deliver(&[0x55; 60]);
    assert!(rx.receive().is_some());
    let index = rx.next();
    rx.descriptors
        .write(index * DESCRIPTOR, FIRST | LAST | RX_RES | 64);
    assert!(rx.receive().is_none());
    tx.transmit(&[0xab; 60]).unwrap();
    model.write16(INTERRUPT_STATUS, RX_OK | RX_DESCRIPTORS_EMPTY);
    let mut events = Events::default();
    events.note(RX_OK | RX_DESCRIPTORS_EMPTY | RX_FIFO_OVERFLOW);
    events.note(RX_DESCRIPTORS_EMPTY | LINK_CHANGE);
    let line = diagnostic_line(&model, revision(46), mac, &rx, &tx, events, true);
    for part in [
        "isr=0x11 ",
        "imr=0x0 ",
        "station=kept",
        "rx next=2 own=dddd taken=2 dropped=1 device_owned=256",
        "tx next=1 device_owned=1",
        "descriptors_empty=2 fifo_overflow=1 receive_error=0 link_change=1",
        "signalled=true",
    ] {
        assert!(line.contains(part), "{part} in {line}");
    }
    assert!(!line.contains("02:03:04"), "{line}");
    let other = Mac([2, 3, 4, 5, 6, 8]);
    let line = diagnostic_line(&model, revision(46), other, &rx, &tx, events, false);
    assert!(line.contains("station=differs"), "{line}");
}
