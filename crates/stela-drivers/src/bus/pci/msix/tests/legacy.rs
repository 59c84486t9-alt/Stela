// SPDX-License-Identifier: GPL-2.0-only
//! Vector-zero access ordering, ownership and failed operations.
use super::*;

#[test]
fn enable_order_and_pending_delivery() {
    for vectors in [1, 2, 65, 2048] {
        let (mut owner, m) = attach(fixture(vectors));
        // SAFETY: Config and Bar keep the same mutex-protected peripheral. Live route
        // callbacks stay held; table writes and message emission run synchronously.
        unsafe { owner.program(MESSAGE) }.unwrap();
        {
            let m = m.lock().unwrap();
            assert_eq!(m.get(4, 2), 0x507);
            assert_eq!(m.get(6, 2), 0xa510); // W1C never acknowledged.
            assert!(m.emitted.is_empty());
            assert_eq!(m.get(0x52, 2) & 0xc000, 0xc000);
            for vector in 1..vectors {
                let index = (TABLE / 4) as usize + usize::from(vector) * 4;
                assert_eq!(
                    &m.memory[index..index + 4],
                    &[0xabc0_0000 | u32::from(vector), 0x9876_0000, 0x55aa_0000, 1]
                );
            }
        }
        m.lock().unwrap().pending = true;
        m.lock().unwrap().callback_published = true;
        // SAFETY: The fixture keeps published ModelRoute callbacks. Emission is synchronous
        // under its mutex, including failures injected after a modeled hardware effect.
        unsafe { owner.unmask() }.unwrap();
        assert_eq!(m.lock().unwrap().emitted, [MESSAGE]);
        owner.mask().unwrap();
        assert_eq!(m.lock().unwrap().get(0x52, 2) & 0xc000, 0xc000);
        owner.disable().unwrap();
        assert_eq!(m.lock().unwrap().get(0x52, 2) & 0xc000, 0x4000);
        // SAFETY: All model deliveries finish synchronously while holding the peripheral
        // mutex. No hardware or background callback can race release of these owners.
        let owners = unsafe { owner.release() }.unwrap();
        assert_eq!(owner.address(), Err(Error::Released));
        drop(owners);
    }
}

#[test]
fn invalid_extents_return_owners() {
    for case in 0..12 {
        let f = fixture(2);
        {
            let mut m = f.model.lock().unwrap();
            match case {
                0 => m.put(0x52, 2, 0x8001),           // already active MSI-X
                1 => m.put(0x54, 4, TABLE as u32 | 6), // reserved BIR
                2 => m.put(0x54, 4, TABLE as u32 | 1), // high half of a wide BAR
                3 => m.put(0x58, 4, TABLE as u32 + 8), // overlaps table
                4 => m.put(0x54, 4, 0xfff8),           // outside BAR
                5 => m.put(4, 2, 1),                   // no memory decode
                6 => m.put(0x50, 2, 0x5011),           // capability cycle
                7 => m.put(0x50, 2, 0x5811),           // following capability inside current body
                8 => {
                    m.put(0x50, 2, 0x6011);
                    m.put(0x60, 2, 5);
                    m.put(0x62, 2, 1);
                } // active MSI
                9 => m.put(0x10, 4, (BASE as u32) | 1), // IO BAR
                10 => m.put(0x52, 2, 0x0801),          // reserved control bits
                _ => m.put(0, 4, 0x9999_8086),
            }
        }
        let (function, retained, bars) = f.owners;
        // SAFETY: The function and BARs are the fixture's Arc-backed peripheral owners.
        // There is no asynchronous source; invalid configuration returns owners before writes.
        let result = unsafe { MsixConfig::new(function, retained, bars) };
        let (_, owners) = match result {
            Err(error) => error,
            Ok(_) => panic!("accepted malformed case {case}"),
        };
        assert!(
            !f.model
                .lock()
                .unwrap()
                .events
                .iter()
                .any(|e| matches!(e, Event::ConfigWrite(..) | Event::BarWrite(..)))
        );
        drop(owners);
        assert_eq!(f.config_drops.load(Ordering::Relaxed), 1);
        assert_eq!(f.root_drops.load(Ordering::Relaxed), 1);
        assert_eq!(f.bar_drops.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn failed_access_poisoning() {
    let (mut baseline, m) = attach(fixture(2));
    m.lock().unwrap().callback_published = true;
    // SAFETY: Config and Bar keep the same mutex-protected peripheral. Live route
    // callbacks stay held; table writes and message emission run synchronously.
    unsafe { baseline.program(MESSAGE) }.unwrap();
    // SAFETY: The fixture keeps published ModelRoute callbacks. Emission is synchronous
    // under its mutex, including failures injected after a modeled hardware effect.
    unsafe { baseline.unmask() }.unwrap();
    baseline.disable().unwrap();
    let events = m.lock().unwrap().events.len();
    assert!(events > 100);
    for after_effect in [false, true] {
        for failure in 1..=events {
            let f = fixture(2);
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
                m.callback_published = true;
            }
            let result = (|| {
                // SAFETY: Config and Bar keep the same mutex-protected peripheral. Live route
                // callbacks stay held; table writes and message emission run synchronously.
                unsafe { owner.program(MESSAGE) }?;
                // SAFETY: The fixture keeps published ModelRoute callbacks. Emission is synchronous
                // under its mutex, including failures injected after a modeled hardware effect.
                unsafe { owner.unmask() }?;
                owner.disable()
            })();
            assert!(result.is_err(), "failure not exercised at {failure}");
            assert!(owner.needs_reset());
            let count = m.lock().unwrap().events.len();
            assert_eq!(owner.mask(), Err(Error::Quarantined));
            // SAFETY: The fixture keeps published ModelRoute callbacks. Emission is synchronous
            // under its mutex, including failures injected after a modeled hardware effect.
            assert_eq!(unsafe { owner.unmask() }, Err(Error::Quarantined));
            assert!(matches!(
                // SAFETY: All model deliveries finish synchronously while holding the peripheral
                // mutex. No hardware or background callback can race release of these owners.
                unsafe { owner.release() },
                Err(Error::Quarantined)
            ));
            assert_eq!(m.lock().unwrap().events.len(), count);
            drop(owner);
            assert!(drops.iter().all(|d| d.load(Ordering::Relaxed) == 0));
        }
    }
}

#[test]
fn changed_message_blocks_unmask() {
    let (mut owner, m) = attach(fixture(2));
    // SAFETY: The fixture keeps published ModelRoute callbacks. Emission is synchronous
    // under its mutex, including failures injected after a modeled hardware effect.
    assert_eq!(unsafe { owner.unmask() }, Err(Error::NotProgrammed));
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
    assert!(!owner.needs_reset());
    // SAFETY: Config and Bar keep the same mutex-protected peripheral. Live route
    // callbacks stay held; table writes and message emission run synchronously.
    unsafe { owner.program(MESSAGE) }.unwrap();
    m.lock().unwrap().memory[(TABLE / 4) as usize + 2] ^= 1;
    assert!(matches!(
        // SAFETY: The fixture keeps published ModelRoute callbacks. Emission is synchronous
        // under its mutex, including failures injected after a modeled hardware effect.
        unsafe { owner.unmask() },
        Err(Error::Readback { .. })
    ));
    assert!(owner.needs_reset());
    let (mut owner, m) = attach(fixture(2));
    // SAFETY: Config and Bar keep the same mutex-protected peripheral. Live route
    // callbacks stay held; table writes and message emission run synchronously.
    unsafe { owner.program(MESSAGE) }.unwrap();
    m.lock().unwrap().put(0x58, 4, (PBA + 8) as u32);
    // SAFETY: The fixture keeps published ModelRoute callbacks. Emission is synchronous
    // under its mutex, including failures injected after a modeled hardware effect.
    assert_eq!(unsafe { owner.unmask() }, Err(Error::CapabilityChanged));
    assert!(owner.needs_reset());
}
