// SPDX-License-Identifier: GPL-2.0-only
//! Sparse MSI-X vectors, replay guards and live peer preservation.
use super::*;

#[test]
fn legacy_trace_parity() {
    for vectors in [1, 2, 65, 2048] {
        let (mut owner, m) = attach(fixture(vectors));
        let f = fixture(vectors);
        let (function, retained, bars) = f.owners;
        // SAFETY: The function and BARs are the fixture's Arc-backed peripheral owners.
        // There is no asynchronous source; invalid configuration returns owners before writes.
        let mut old = match unsafe { original::LegacyReference::new(function, retained, bars) } {
            Ok(owner) => owner,
            Err(_) => panic!("original attach"),
        };
        f.model.lock().unwrap().events.clear();
        let other = f.model;
        macro_rules! compare {
            ($new:expr, $old:expr) => {{
                assert_eq!($new, $old);
                let a = m.lock().unwrap();
                let b = other.lock().unwrap();
                assert_eq!(a.events, b.events);
                assert_eq!(a.config, b.config);
                assert_eq!(a.memory, b.memory);
                assert_eq!(a.emitted, b.emitted);
            }};
        }
        // SAFETY: The fixture keeps published ModelRoute callbacks. Emission is synchronous
        // under its mutex, including failures injected after a modeled hardware effect.
        compare!(unsafe { owner.unmask() }, unsafe { old.unmask() });
        let invalid = MsiMessage {
            address: 3,
            data: 0,
        };
        // SAFETY: Config and Bar keep the same mutex-protected peripheral. Live route
        // callbacks stay held; table writes and message emission run synchronously.
        compare!(unsafe { owner.program(invalid) }, unsafe {
            old.program(invalid)
        });
        // SAFETY: Config and Bar keep the same mutex-protected peripheral. Live route
        // callbacks stay held; table writes and message emission run synchronously.
        compare!(unsafe { owner.program(MESSAGE) }, unsafe {
            old.program(MESSAGE)
        });
        for model in [&m, &other] {
            let mut model = model.lock().unwrap();
            model.callback_published = true;
            model.pending = true;
        }
        // SAFETY: The fixture keeps published ModelRoute callbacks. Emission is synchronous
        // under its mutex, including failures injected after a modeled hardware effect.
        compare!(unsafe { owner.unmask() }, unsafe { old.unmask() });
        compare!(owner.mask(), old.mask());
        // SAFETY: Config and Bar keep the same mutex-protected peripheral. Live route
        // callbacks stay held; table writes and message emission run synchronously.
        compare!(unsafe { owner.program(message(1)) }, unsafe {
            old.program(message(1))
        });
        compare!(owner.disable(), old.disable());
        assert_eq!(owner.vectors(), old.vectors());
        assert_eq!(owner.needs_reset(), old.needs_reset());
        // SAFETY: All model deliveries finish synchronously while holding the peripheral
        // mutex. No hardware or background callback can race release of these owners.
        drop(unsafe { owner.release() }.unwrap());
        // SAFETY: All model deliveries finish synchronously while holding the peripheral
        // mutex. No hardware or background callback can race release of these owners.
        drop(unsafe { old.release() }.unwrap());
        assert_eq!(owner.address(), old.address());
        // SAFETY: The fixture keeps published ModelRoute callbacks. Emission is synchronous
        // under its mutex, including failures injected after a modeled hardware effect.
        compare!(unsafe { owner.unmask() }, unsafe { old.unmask() });
        // SAFETY: Config and Bar keep the same mutex-protected peripheral. Live route
        // callbacks stay held; table writes and message emission run synchronously.
        compare!(unsafe { owner.program(MESSAGE) }, unsafe {
            old.program(MESSAGE)
        });
        assert_eq!(owner.needs_reset(), old.needs_reset());
        compare!(owner.mask(), old.mask());
        assert_eq!(m.lock().unwrap().events, other.lock().unwrap().events);
    }
}

#[test]
fn sparse_indices_and_pending_delivery() {
    for vectors in [1, 2, 65, 66, 2048] {
        let (mut owner, m) = attach(fixture(vectors));
        let mut indices: Vec<u16> = [0, 1, 63, 64, 65, 2047]
            .into_iter()
            .filter(|index| *index < vectors)
            .collect();
        indices.push(vectors - 1);
        indices.sort_unstable();
        indices.dedup();
        let before = m.lock().unwrap().memory.clone();
        for &index in &indices {
            // SAFETY: Config and Bar keep the same mutex-protected peripheral. Live route
            // callbacks stay held; table writes and message emission run synchronously.
            unsafe { owner.program_indexed(index, message(index)) }.unwrap();
        }
        {
            let mut m = m.lock().unwrap();
            selected_masks(&m, &[]);
            for index in 0..vectors {
                let word = (TABLE / 4) as usize + usize::from(index) * 4;
                if indices.contains(&index) {
                    let expected = message(index);
                    assert_eq!(m.memory[word], expected.address as u32);
                    assert_eq!(m.memory[word + 1], (expected.address >> 32) as u32);
                    assert_eq!(m.memory[word + 2], expected.data);
                    m.publish(index);
                    m.queue(index);
                } else {
                    assert_eq!(m.memory[word..word + 3], before[word..word + 3]);
                }
            }
            assert!(m.emitted.is_empty());
        }
        // SAFETY: The fixture keeps published ModelRoute callbacks. Emission is synchronous
        // under its mutex, including failures injected after a modeled hardware effect.
        unsafe { owner.unmask_indices(&indices) }.unwrap();
        {
            let m = m.lock().unwrap();
            selected_masks(&m, &indices);
            assert_eq!(m.delivered_entries, indices);
            for &index in &indices {
                assert_eq!(
                    m.routes[usize::from(index)]
                        .as_ref()
                        .unwrap()
                        .calls
                        .load(Ordering::Relaxed),
                    1
                );
            }
            assert_eq!(
                m.emitted,
                indices.iter().copied().map(message).collect::<Vec<_>>()
            );
            assert!(
                m.memory
                    [(PBA / 4) as usize..(PBA / 4) as usize + usize::from(vectors).div_ceil(32)]
                    .iter()
                    .all(|word| *word == 0)
            );
            assert!(
                !m.events
                    .iter()
                    .any(|event| matches!(event, Event::BarWrite(offset, _) if *offset >= PBA))
            );
            assert!(
                matches!(m.events.iter().rev().find(|event| matches!(event, Event::ConfigWrite(..))), Some(Event::ConfigWrite(0x52, control)) if control & 0xc000 == 0x8000)
            );
        }
        // SAFETY: All model deliveries finish synchronously while holding the peripheral
        // mutex. No hardware or background callback can race release of these owners.
        drop(unsafe { owner.release() }.unwrap());
    }
}

#[test]
fn live_peer_preservation() {
    let (mut owner, m) = attach(fixture(66));
    for index in [0, 63, 64] {
        // SAFETY: Config and Bar keep the same mutex-protected peripheral. Live route
        // callbacks stay held; table writes and message emission run synchronously.
        unsafe { owner.program_indexed(index, message(index)) }.unwrap();
        m.lock().unwrap().publish(index);
    }
    // SAFETY: The fixture keeps published ModelRoute callbacks. Emission is synchronous
    // under its mutex, including failures injected after a modeled hardware effect.
    unsafe { owner.unmask_indices(&[0, 63, 64]) }.unwrap();
    let before = m.lock().unwrap().memory.clone();
    {
        let mut m = m.lock().unwrap();
        m.queue_on_guard.extend([0, 63, 64, 65]);
        // Target 65 has no published callback yet: it must never deliver while
        // its new message is being installed or peer delivery is restored.
    }
    let start = m.lock().unwrap().events.len();
    // SAFETY: Config and Bar keep the same mutex-protected peripheral. Live route
    // callbacks stay held; table writes and message emission run synchronously.
    unsafe { owner.program_indexed(65, message(65)) }.unwrap();
    {
        let m = m.lock().unwrap();
        selected_masks(&m, &[0, 63, 64]);
        assert_eq!(m.delivered_entries, [0, 63, 64]);
        assert_eq!(m.emitted, [message(0), message(63), message(64)]);
        for index in [0u16, 63, 64] {
            assert_eq!(
                m.routes[usize::from(index)]
                    .as_ref()
                    .unwrap()
                    .calls
                    .load(Ordering::Relaxed),
                1
            );
            let word = (TABLE / 4) as usize + usize::from(index) * 4;
            assert_eq!(m.memory[word..word + 3], before[word..word + 3]);
        }
        assert_eq!(m.memory[(PBA / 4) as usize + 2], 2); // pending entry65 survives
        assert!(m.pending_entries[65]);
        assert!(m.events[start..].iter().all(|event| match event {
            Event::BarWrite(offset, _) => (TABLE + 65 * 16..TABLE + 66 * 16).contains(offset),
            _ => true,
        }));
    }
    m.lock().unwrap().publish(65);
    // SAFETY: The fixture keeps published ModelRoute callbacks. Emission is synchronous
    // under its mutex, including failures injected after a modeled hardware effect.
    unsafe { owner.unmask_indices(&[0, 63, 64, 65]) }.unwrap();
    assert_eq!(m.lock().unwrap().delivered_entries, [0, 63, 64, 65]);
    owner.mask().unwrap();
    // SAFETY: Config and Bar keep the same mutex-protected peripheral. Live route
    // callbacks stay held; table writes and message emission run synchronously.
    unsafe { owner.program_indexed(65, message(65)) }.unwrap();
    assert_eq!(m.lock().unwrap().get(0x52, 2) & 0xc000, 0xc000);
    selected_masks(&m.lock().unwrap(), &[]);
    // Retarget a formerly live entry under an explicitly modeled stopped target;
    // the unrelated live peer remains enabled; no stale target request exists.
    // SAFETY: The fixture keeps published ModelRoute callbacks. Emission is synchronous
    // under its mutex, including failures injected after a modeled hardware effect.
    unsafe { owner.unmask_indices(&[0, 64]) }.unwrap();
    // SAFETY: Config and Bar keep the same mutex-protected peripheral. Live route
    // callbacks stay held; table writes and message emission run synchronously.
    unsafe { owner.program_indexed(64, message(64)) }.unwrap();
    selected_masks(&m.lock().unwrap(), &[0]);
    // SAFETY: All model deliveries finish synchronously while holding the peripheral
    // mutex. No hardware or background callback can race release of these owners.
    drop(unsafe { owner.release() }.unwrap());
}

#[test]
fn legacy_calls_invalidate_indexed_replay() {
    for use_program in [false, true] {
        let (mut owner, m) = attach(fixture(65));
        for index in [0, 64] {
            // SAFETY: Config and Bar keep the same mutex-protected peripheral. Live route
            // callbacks stay held; table writes and message emission run synchronously.
            unsafe { owner.program_indexed(index, message(index)) }.unwrap();
            m.lock().unwrap().publish(index);
        }
        // SAFETY: The fixture keeps published ModelRoute callbacks. Emission is synchronous
        // under its mutex, including failures injected after a modeled hardware effect.
        unsafe { owner.unmask_indices(&[0, 64]) }.unwrap();
        if use_program {
            // SAFETY: Config and Bar keep the same mutex-protected peripheral. Live route
            // callbacks stay held; table writes and message emission run synchronously.
            unsafe { owner.program(MESSAGE) }.unwrap();
            selected_masks(&m.lock().unwrap(), &[]);
            // SAFETY: The fixture keeps published ModelRoute callbacks. Emission is synchronous
            // under its mutex, including failures injected after a modeled hardware effect.
            unsafe { owner.unmask() }.unwrap();
        } else {
            // SAFETY: The fixture keeps published ModelRoute callbacks. Emission is synchronous
            // under its mutex, including failures injected after a modeled hardware effect.
            unsafe { owner.unmask() }.unwrap();
        }
        selected_masks(&m.lock().unwrap(), &[0]);
        let events = m.lock().unwrap().events.clone();
        assert_eq!(
            // SAFETY: The fixture keeps published ModelRoute callbacks. Emission is synchronous
            // under its mutex, including failures injected after a modeled hardware effect.
            unsafe { owner.unmask_indices(&[0, 64]) },
            Err(Error::NotProgrammed)
        );
        assert_eq!(m.lock().unwrap().events, events);
        assert!(!owner.needs_reset());
        // SAFETY: Config and Bar keep the same mutex-protected peripheral. Live route
        // callbacks stay held; table writes and message emission run synchronously.
        unsafe { owner.program_indexed(64, message(64)) }.unwrap();
        // SAFETY: The fixture keeps published ModelRoute callbacks. Emission is synchronous
        // under its mutex, including failures injected after a modeled hardware effect.
        unsafe { owner.unmask_indices(&[0, 64]) }.unwrap();
        selected_masks(&m.lock().unwrap(), &[0, 64]);
        // SAFETY: All model deliveries finish synchronously while holding the peripheral
        // mutex. No hardware or background callback can race release of these owners.
        drop(unsafe { owner.release() }.unwrap());
    }
}

#[test]
fn invalid_selection_is_transactional() {
    let (mut owner, m) = attach(fixture(65));
    for index in [0, 64] {
        // SAFETY: Config and Bar keep the same mutex-protected peripheral. Live route
        // callbacks stay held; table writes and message emission run synchronously.
        unsafe { owner.program_indexed(index, message(index)) }.unwrap();
        m.lock().unwrap().publish(index);
    }
    // SAFETY: The fixture keeps published ModelRoute callbacks. Emission is synchronous
    // under its mutex, including failures injected after a modeled hardware effect.
    unsafe { owner.unmask_indices(&[0, 64]) }.unwrap();
    let memory = m.lock().unwrap().memory.clone();
    let config = m.lock().unwrap().config;
    let events = m.lock().unwrap().events.clone();
    for indices in [&[][..], &[0, 0][..], &[65][..], &[0, 1][..]] {
        // SAFETY: The fixture keeps published ModelRoute callbacks. Emission is synchronous
        // under its mutex, including failures injected after a modeled hardware effect.
        assert!(unsafe { owner.unmask_indices(indices) }.is_err());
    }
    assert_eq!(
        // SAFETY: Config and Bar keep the same mutex-protected peripheral. Live route
        // callbacks stay held; table writes and message emission run synchronously.
        unsafe { owner.program_indexed(65, message(1)) },
        Err(Error::InvalidIndex)
    );
    assert_eq!(
        // SAFETY: Config and Bar keep the same mutex-protected peripheral. Live route
        // callbacks stay held; table writes and message emission run synchronously.
        unsafe { owner.program_indexed(u16::MAX, message(1)) },
        Err(Error::InvalidIndex)
    );
    assert_eq!(
        // SAFETY: Config and Bar keep the same mutex-protected peripheral. Live route
        // callbacks stay held; table writes and message emission run synchronously.
        unsafe {
            owner.program(MsiMessage {
                address: 3,
                data: 0,
            })
        },
        Err(Error::InvalidMessage)
    );
    assert_eq!(
        // SAFETY: Config and Bar keep the same mutex-protected peripheral. Live route
        // callbacks stay held; table writes and message emission run synchronously.
        unsafe {
            owner.program_indexed(
                64,
                MsiMessage {
                    address: 1,
                    data: 0,
                },
            )
        },
        Err(Error::InvalidMessage)
    );
    assert!(!owner.needs_reset());
    assert_eq!(m.lock().unwrap().memory, memory);
    assert_eq!(m.lock().unwrap().config, config);
    assert_eq!(m.lock().unwrap().events, events);
    selected_masks(&m.lock().unwrap(), &[0, 64]);
    // The checked arithmetic also refuses an impossible internal corrupt layout
    // without touching MMIO. This fixture does not admit such a hardware layout.
    let saved = owner.layout;
    owner.layout.table_offset = u64::MAX - 7;
    assert_eq!(
        // SAFETY: Config and Bar keep the same mutex-protected peripheral. Live route
        // callbacks stay held; table writes and message emission run synchronously.
        unsafe { owner.program_indexed(64, message(1)) },
        Err(Error::InvalidTable)
    );
    owner.layout = saved;
    assert_eq!(m.lock().unwrap().events, events);
    // SAFETY: All model deliveries finish synchronously while holding the peripheral
    // mutex. No hardware or background callback can race release of these owners.
    drop(unsafe { owner.release() }.unwrap());
}

#[test]
fn indexed_access_failure_quarantines() {
    let (mut baseline, m) = attach(fixture(3));
    for index in 0..3 {
        m.lock().unwrap().publish(index);
    }
    m.lock().unwrap().queue_on_guard.extend([0, 1]);
    indexed_sequence(&mut baseline).unwrap();
    let count = m.lock().unwrap().events.len();
    // SAFETY: All model deliveries finish synchronously while holding the peripheral
    // mutex. No hardware or background callback can race release of these owners.
    drop(unsafe { baseline.release() }.unwrap());
    for after_effect in [false, true] {
        for failure in 1..=count {
            let f = fixture(3);
            let drops = [
                f.config_drops.clone(),
                f.root_drops.clone(),
                f.bar_drops.clone(),
            ];
            let (mut owner, m) = attach(f);
            {
                let mut m = m.lock().unwrap();
                m.fail = Some(failure);
                m.after_effect = after_effect;
                for index in 0..3 {
                    m.publish(index);
                }
                m.queue_on_guard.extend([0, 1]);
            }
            assert!(
                indexed_sequence(&mut owner).is_err(),
                "unreached failure {failure}"
            );
            assert!(owner.needs_reset());
            assert!(owner.message.is_none() && owner.messages.iter().all(Option::is_none));
            for index in 0..3 {
                assert!(!owner.live.contains(index));
            }
            let events = m.lock().unwrap().events.len();
            assert_eq!(
                // SAFETY: The fixture keeps published ModelRoute callbacks. Emission is synchronous
                // under its mutex, including failures injected after a modeled hardware effect.
                unsafe { owner.unmask_indices(&[0, 1]) },
                Err(Error::Quarantined)
            );
            assert_eq!(
                // SAFETY: Config and Bar keep the same mutex-protected peripheral. Live route
                // callbacks stay held; table writes and message emission run synchronously.
                unsafe { owner.program_indexed(2, MESSAGE) },
                Err(Error::Quarantined)
            );
            // SAFETY: All model deliveries finish synchronously while holding the peripheral
            // mutex. No hardware or background callback can race release of these owners.
            assert_eq!(unsafe { owner.release() }.err(), Some(Error::Quarantined));
            assert_eq!(m.lock().unwrap().events.len(), events);
            drop(owner);
            assert!(drops.iter().all(|drop| drop.load(Ordering::Relaxed) == 0));
        }
    }
}

#[test]
fn peer_corruption_blocks_global_unmask() {
    for corrupt_peer in [false, true] {
        let (mut owner, m) = attach(fixture(3));
        for index in 0..3 {
            // SAFETY: Config and Bar keep the same mutex-protected peripheral. Live route
            // callbacks stay held; table writes and message emission run synchronously.
            unsafe { owner.program_indexed(index, message(index)) }.unwrap();
            m.lock().unwrap().publish(index);
        }
        // SAFETY: The fixture keeps published ModelRoute callbacks. Emission is synchronous
        // under its mutex, including failures injected after a modeled hardware effect.
        unsafe { owner.unmask_indices(&[0, 1]) }.unwrap();
        let word = (TABLE / 4) as usize + 4 + 2;
        m.lock().unwrap().memory[word] ^= 1;
        let start = m.lock().unwrap().events.len();
        let result = if corrupt_peer {
            // SAFETY: Config and Bar keep the same mutex-protected peripheral. Live route
            // callbacks stay held; table writes and message emission run synchronously.
            unsafe { owner.program_indexed(2, message(2)) }
        } else {
            // SAFETY: The fixture keeps published ModelRoute callbacks. Emission is synchronous
            // under its mutex, including failures injected after a modeled hardware effect.
            unsafe { owner.unmask_indices(&[0, 1, 2]) }
        };
        assert!(matches!(result, Err(Error::Readback { .. })));
        assert!(owner.needs_reset());
        let m = m.lock().unwrap();
        assert_eq!(m.get(0x52, 2) & 0xc000, 0xc000);
        assert!(!m.events[start..].iter().any(
            |event| matches!(event, Event::ConfigWrite(0x52, control) if control & 0xc000 == 0x8000)
        ));
        if !corrupt_peer {
            assert!(!m.events[start..].iter().any(
                |event| matches!(event, Event::BarWrite(offset, 0) if (*offset - TABLE) % 16 == 12)
            ));
        }
    }
}

#[test]
fn changed_layout_quarantines() {
    for case in 0..7 {
        let f = fixture(3);
        let drops = [
            f.config_drops.clone(),
            f.root_drops.clone(),
            f.bar_drops.clone(),
        ];
        let (mut owner, m) = attach(f);
        for index in 0..3 {
            // SAFETY: Config and Bar keep the same mutex-protected peripheral. Live route
            // callbacks stay held; table writes and message emission run synchronously.
            unsafe { owner.program_indexed(index, message(index)) }.unwrap();
            m.lock().unwrap().publish(index);
        }
        // SAFETY: The fixture keeps published ModelRoute callbacks. Emission is synchronous
        // under its mutex, including failures injected after a modeled hardware effect.
        unsafe { owner.unmask_indices(&[0, 1]) }.unwrap();
        {
            let mut m = m.lock().unwrap();
            match case {
                0 => m.put(0, 4, 0x9999_8086),
                1 => m.put(0x58, 4, (PBA + 8) as u32),
                2 => m.put(0x54, 4, (TABLE + 16) as u32),
                3 => m.put(0x52, 2, 0x8003),
                4 => m.put(4, 2, 0x505),
                5 => m.put(0x52, 2, 0xc002),
                _ => m.memory[(TABLE / 4) as usize + 4 + 3] = 1,
            }
        }
        let start = m.lock().unwrap().events.len();
        // SAFETY: Config and Bar keep the same mutex-protected peripheral. Live route
        // callbacks stay held; table writes and message emission run synchronously.
        assert!(unsafe { owner.program_indexed(2, message(2)) }.is_err());
        assert!(owner.needs_reset());
        if case < 6 {
            assert!(
                !m.lock().unwrap().events[start..]
                    .iter()
                    .any(|event| matches!(event, Event::BarRead(..) | Event::BarWrite(..)))
            );
        } else {
            assert_eq!(m.lock().unwrap().get(0x52, 2) & 0xc000, 0xc000);
        }
        // SAFETY: All model deliveries finish synchronously while holding the peripheral
        // mutex. No hardware or background callback can race release of these owners.
        assert_eq!(unsafe { owner.release() }.err(), Some(Error::Quarantined));
        drop(owner);
        assert!(drops.iter().all(|drop| drop.load(Ordering::Relaxed) == 0));
    }
}

#[test]
fn vector_zero_literal_trace() {
    // Exact immutable fixture layout: one 64-bit BAR, table/PBA in BAR0, one
    // capability. This sequence comes from the source contract, not new helpers.
    let discovery = [
        Event::ConfigRead(0, 4),
        Event::ConfigRead(0x0e, 1),
        Event::ConfigRead(4, 2),
        Event::ConfigRead(6, 2),
        Event::ConfigRead(0x34, 1),
        Event::ConfigRead(0x50, 2),
        Event::ConfigRead(0x52, 2),
        Event::ConfigRead(0x54, 4),
        Event::ConfigRead(0x58, 4),
        Event::ConfigRead(0x10, 4),
        Event::ConfigRead(0x14, 4),
        Event::ConfigRead(0x10, 4),
        Event::ConfigRead(0x14, 4),
    ];
    let prefix = || {
        let mut expected = discovery.to_vec();
        expected.extend([
            Event::ConfigRead(4, 2),
            Event::ConfigWrite(4, 0x507),
            Event::ConfigRead(4, 2),
            Event::ConfigWrite(0x52, 0xc001),
            Event::ConfigRead(0x52, 2),
            Event::BarWrite(0x10c, 1),
            Event::BarRead(0x10c),
            Event::BarWrite(0x11c, 1),
            Event::BarRead(0x11c),
        ]);
        expected
    };
    let (mut owner, m) = attach(fixture(2));
    // SAFETY: Config and Bar keep the same mutex-protected peripheral. Live route
    // callbacks stay held; table writes and message emission run synchronously.
    unsafe { owner.program(MESSAGE) }.unwrap();
    let mut expected = prefix();
    expected.extend([
        Event::BarWrite(0x100, 0xfee0_1000),
        Event::BarRead(0x100),
        Event::BarWrite(0x104, 0x1234_5678),
        Event::BarRead(0x104),
        Event::BarWrite(0x108, 0x8765_4321),
        Event::BarRead(0x108),
    ]);
    expected.extend(discovery);
    assert_eq!(m.lock().unwrap().events, expected);
    m.lock().unwrap().events.clear();
    m.lock().unwrap().publish(0);
    // SAFETY: The fixture keeps published ModelRoute callbacks. Emission is synchronous
    // under its mutex, including failures injected after a modeled hardware effect.
    unsafe { owner.unmask() }.unwrap();
    let mut expected = prefix();
    expected.extend([
        Event::BarRead(0x100),
        Event::BarRead(0x104),
        Event::BarRead(0x108),
        Event::BarWrite(0x10c, 0),
        Event::BarRead(0x10c),
    ]);
    expected.extend(discovery);
    expected.extend([Event::ConfigWrite(0x52, 0x8001), Event::ConfigRead(0x52, 2)]);
    assert_eq!(m.lock().unwrap().events, expected);
    // SAFETY: All model deliveries finish synchronously while holding the peripheral
    // mutex. No hardware or background callback can race release of these owners.
    drop(unsafe { owner.release() }.unwrap());
}

#[test]
fn missing_zero_preflight_preserves_peer() {
    let (mut owner, m) = attach(fixture(65));
    // SAFETY: Config and Bar keep the same mutex-protected peripheral. Live route
    // callbacks stay held; table writes and message emission run synchronously.
    unsafe { owner.program_indexed(64, message(64)) }.unwrap();
    m.lock().unwrap().publish(64);
    // SAFETY: The fixture keeps published ModelRoute callbacks. Emission is synchronous
    // under its mutex, including failures injected after a modeled hardware effect.
    unsafe { owner.unmask_indices(&[64]) }.unwrap();
    let events = m.lock().unwrap().events.clone();
    let memory = m.lock().unwrap().memory.clone();
    // SAFETY: The fixture keeps published ModelRoute callbacks. Emission is synchronous
    // under its mutex, including failures injected after a modeled hardware effect.
    assert_eq!(unsafe { owner.unmask() }, Err(Error::NotProgrammed));
    assert!(owner.live.contains(64));
    assert_eq!(owner.message_at(64), Some(message(64)));
    assert!(!owner.needs_reset());
    assert_eq!(m.lock().unwrap().events, events);
    assert_eq!(m.lock().unwrap().memory, memory);
    // SAFETY: The fixture keeps published ModelRoute callbacks. Emission is synchronous
    // under its mutex, including failures injected after a modeled hardware effect.
    unsafe { owner.unmask_indices(&[64]) }.unwrap();
    // SAFETY: All model deliveries finish synchronously while holding the peripheral
    // mutex. No hardware or background callback can race release of these owners.
    drop(unsafe { owner.release() }.unwrap());
}
