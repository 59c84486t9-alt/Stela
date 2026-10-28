// SPDX-License-Identifier: GPL-2.0-only
//! PCI MSI aliases fixtures.
use super::*;

#[test]
fn pm_body_alias_preflight() {
    for reverse in [false, true] {
        let f = fixture(false, false);
        {
            let mut m = f.model.lock().unwrap();
            // Exact review repro: fake MSI54 aliases real PM50's PMCSR,
            // PPB extensions/data. Old program changed word56 0x5a→0x0a.
            m.bytes.copy_within(0x50..0x5a, 0x54);
            m.put(0x34, 1, if reverse { 0x54 } else { 0x50 });
            m.put(0x50, 2, if reverse { 1 } else { 0x5401 });
            m.put(0x52, 2, 3);
            m.put(0x54, 2, if reverse { 0x5005 } else { 5 });
            assert_eq!(m.get(0x56, 2), 0x5a);
        }
        let (error, owners) = match unsafe { MsiConfig::new(f.function, f.root) } {
            Err(e) => e,
            Ok(_) => panic!("PM body admitted as MSI"),
        };
        assert_eq!(error, MsiError::MalformedCapability);
        let m = f.model.lock().unwrap();
        assert_eq!(m.get(0x56, 2), 0x5a);
        assert!(!m.events.iter().any(|e| matches!(e, Event::Write(..))));
        drop(owners);
    }
}
#[test]
fn body_and_header_alias_preflight() {
    // All these known bodies can contain an aligned fake MSI header.
    for (id, flags) in [
        (1u8, 3),
        (2, 0),
        (3, 0),
        (7, 0),
        (7, 0x1000),
        (9, 8),
        (0x0d, 0),
        (0x10, 1),
        (0x10, 2),
        (0x10, 0x91),
        (0x10, 0x92),
        (0x12, 0),
        (0x13, 0),
    ] {
        for reverse in [false, true] {
            let f = fixture(false, false);
            {
                let mut m = f.model.lock().unwrap();
                m.bytes.copy_within(0x50..0x5a, 0x54);
                m.put(0x34, 1, if reverse { 0x54 } else { 0x50 });
                m.put(0x50, 2, u32::from(id) | if reverse { 0 } else { 0x5400 });
                m.put(0x52, 2, flags);
                m.put(0x54, 2, if reverse { 0x5005 } else { 5 });
            }
            let (error, owners) = match unsafe { MsiConfig::new(f.function, f.root) } {
                Err(e) => e,
                Ok(_) => panic!("body alias admitted id={id:#x} reverse={reverse}"),
            };
            assert_eq!(
                error,
                MsiError::MalformedCapability,
                "id={id:#x} reverse={reverse}"
            );
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
    // Unknown two-byte headers remain occupied even inside MSI data or
    // either actual per-vector Pending bitmap, in either list order.
    for (wide, mask, header) in [
        (false, false, 0x58),
        (false, true, 0x60),
        (true, true, 0x64),
    ] {
        for reverse in [false, true] {
            let f = fixture(wide, mask);
            {
                let mut m = f.model.lock().unwrap();
                m.put(0x34, 1, if reverse { header } else { 0x50 });
                m.put(0x50, 2, if reverse { 5 } else { (header << 8) | 5 });
                m.put(header as u16, 2, if reverse { 0x507e } else { 0x007e });
            }
            let (error, owners) = match unsafe { MsiConfig::new(f.function, f.root) } {
                Err(e) => e,
                Ok(_) => panic!("unknown header in MSI data/Pending body admitted"),
            };
            assert_eq!(error, MsiError::MalformedCapability);
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
}
#[test]
fn non_msi_alias_preflight() {
    for reverse in [false, true] {
        let f = fixture(false, false);
        {
            let mut m = f.model.lock().unwrap();
            m.bytes.copy_within(0x50..0x5a, 0x70);
            m.put(0x34, 1, if reverse { 0x44 } else { 0x40 });
            m.put(0x40, 2, if reverse { 0x7001 } else { 0x4401 });
            m.put(0x42, 2, 3);
            m.put(0x44, 2, if reverse { 0x4003 } else { 0x7003 });
        }
        let (error, owners) = match unsafe { MsiConfig::new(f.function, f.root) } {
            Err(e) => e,
            Ok(_) => panic!("PM/VPD body overlap admitted"),
        };
        assert_eq!(error, MsiError::MalformedCapability);
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
