// SPDX-License-Identifier: GPL-2.0-only
//! PCI MSI extents fixtures.
use super::*;

#[test]
fn standard_capability_extents() {
    for (id, flags, registers) in [
        (1u8, 3, 0),
        (2, 0, 0),
        (3, 0, 0),
        (4, 0, 0),
        (7, 0, 0),
        (7, 0x1000, 0),
        (7, 0x2000, 0),
        (9, 8, 0),
        (0x0d, 0, 0),
        (0x10, 1, 0),
        (0x10, 2, 0),
        (0x10, 0x91, 0),
        (0x10, 0x92, 0),
        (0x12, 0, 0),
        (0x12, 0, 15),
        (0x13, 0, 0),
        (0x7e, 0, 0),
    ] {
        let f = fixture(false, false);
        {
            let mut m = f.model.lock().unwrap();
            m.bytes.copy_within(0x50..0x5a, 0xc0);
            m.put(0x34, 1, 0x40);
            m.put(0x40, 2, 0xc000 | u32::from(id));
            m.put(0x42, 2, flags);
            m.put(0x44, 2, registers);
        }
        let (mut helper, _) = attach(f);
        // SAFETY: The accepted disjoint capability belongs to this exclusive RAM
        // Function; MESSAGE names its synthetic route and no source is in flight.
        unsafe { helper.program(MESSAGE) }.unwrap();
        drop(
            // SAFETY: Only synchronous RAM programming occurred; no DMA, posted vector,
            // callback or deferred user exists before releasing the owners.
            unsafe { helper.release() }.unwrap(),
        );
    }
}
#[test]
fn adjacent_extents_and_unknown_versions() {
    for reverse in [false, true] {
        let f = fixture(false, false);
        {
            let mut m = f.model.lock().unwrap();
            m.put(0x34, 1, if reverse { 0x50 } else { 0x48 });
            m.put(0x48, 2, if reverse { 1 } else { 0x5001 });
            m.put(0x4a, 2, 3);
            m.put(0x50, 2, if reverse { 0x4805 } else { 5 });
        }
        let (mut helper, model) = attach(f);
        // SAFETY: The adjacent bodies are backed by this exclusive RAM config;
        // MESSAGE belongs to its synthetic route and there is no asynchronous source.
        unsafe { helper.program(MESSAGE) }.unwrap();
        assert_eq!(model.lock().unwrap().get(0x4a, 2), 3);
        drop(
            // SAFETY: The model never starts a device or callback; all accesses are
            // synchronous and the original config/root guards may be returned.
            unsafe { helper.release() }.unwrap(),
        );
    }
    // Root-port and slot PCIe layouts are sized in full: the MSI header
    // at 0x50 lies inside their bodies.
    for (id, flags, expected) in [
        (7, 0x3000, MsiError::Unsupported),
        (0x10, 0, MsiError::Unsupported),
        (0x10, 3, MsiError::Unsupported),
        (0x10, 0x42, MsiError::MalformedCapability),
        (0x10, 0x102, MsiError::MalformedCapability),
    ] {
        let f = fixture(false, false);
        {
            let mut m = f.model.lock().unwrap();
            m.put(0x34, 1, 0x40);
            m.put(0x40, 2, 0x5000 | id);
            m.put(0x42, 2, flags);
        }
        let (error, owners) = match
        // SAFETY: Unknown versions are held in live RAM with the exact Function/root
        // guards kept. No physical delivery exists; admission must reject before
        // writes.
        unsafe { MsiConfig::new(f.function, f.root) } {
            Err(e) => e,
            Ok(_) => panic!("unknown capability format guessed"),
        };
        assert_eq!(error, expected);
        assert!(
            !f.model
                .lock()
                .unwrap()
                .events
                .iter()
                .any(|e| matches!(e, Event::Write(..)))
        );
        drop(owners);
    }
}
