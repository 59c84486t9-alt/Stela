// SPDX-License-Identifier: GPL-2.0-only
//! PCI MSI admission fixtures.
use super::*;

#[test]
fn malformed_duplicate_overlapping_or_live_capabilities_are_refused_without_writes() {
    for case in 0..11 {
        let f = fixture(false, false);
        let expected = {
            let mut m = f.model.lock().unwrap();
            match case {
                0 => {
                    m.put(0x34, 1, 0x51);
                    MsiError::MalformedCapability
                }
                1 => {
                    m.put(0x50, 2, 0x5005);
                    MsiError::MalformedCapability
                }
                2 => {
                    m.put(0x50, 2, 0x7005);
                    m.put(0x70, 2, 5);
                    MsiError::MalformedCapability
                }
                3 => {
                    m.put(0x34, 1, 0xfc);
                    m.put(0xfc, 2, 5);
                    MsiError::MalformedCapability
                }
                4 => {
                    m.put(0x50, 2, 0x5805);
                    m.put(0x58, 2, 0x10);
                    MsiError::MalformedCapability
                }
                5 => {
                    m.put(0x52, 2, 12);
                    MsiError::Unsupported
                }
                6 => {
                    m.put(0x52, 2, 1 << 4);
                    MsiError::Unsupported
                }
                7 => {
                    m.put(0x52, 2, 1);
                    MsiError::ActiveMsi
                }
                8 => {
                    m.put(0x50, 2, 0x8005);
                    m.put(0x80, 2, 0x11);
                    m.put(0x82, 2, 0x8000);
                    MsiError::ActiveMsix
                }
                10 => {
                    m.put(0x34, 1, 0x48);
                    m.put(0x48, 2, 0x5011);
                    MsiError::MalformedCapability
                }
                _ => {
                    m.put(0x52, 2, 1 << 9);
                    MsiError::Unsupported
                }
            }
        };
        let result = unsafe { MsiConfig::new(f.function, f.root) };
        let (e, (function, root)) = match result {
            Err(e) => e,
            Ok(_) => panic!("accepted case {case}"),
        };
        assert_eq!(e, expected, "case {case}");
        assert!(
            !f.model
                .lock()
                .unwrap()
                .events
                .iter()
                .any(|e| matches!(e, Event::Write(..)))
        );
        drop((function, root));
        assert_eq!(f.config_drops.load(Ordering::Relaxed), 1);
        assert_eq!(f.root_drops.load(Ordering::Relaxed), 1);
    }
}
#[test]
fn all_ones_admission_reads_do_not_mutate_or_consume_the_returned_owners() {
    for (offset, width) in [(0, 4), (STATUS, 2), (0x50, 2), (0x52, 2)] {
        let f = fixture(false, false);
        f.model.lock().unwrap().fail_read = Some((offset, width));
        let (error, owners) = match unsafe { MsiConfig::new(f.function, f.root) } {
            Err(e) => e,
            Ok(_) => panic!("failed config read admitted"),
        };
        assert_eq!(error, MsiError::FailedRead { offset });
        assert!(
            !f.model
                .lock()
                .unwrap()
                .events
                .iter()
                .any(|e| matches!(e, Event::Write(..)))
        );
        assert_eq!(f.config_drops.load(Ordering::Relaxed), 0);
        assert_eq!(f.root_drops.load(Ordering::Relaxed), 0);
        drop(owners);
        assert_eq!(f.config_drops.load(Ordering::Relaxed), 1);
        assert_eq!(f.root_drops.load(Ordering::Relaxed), 1);
    }
}
#[test]
fn each_real_capability_layout_has_a_checked_full_config_boundary() {
    for (wide, mask, offset, length) in [
        (false, false, 0xf4u16, 10usize),
        (true, false, 0xf0, 14),
        (false, true, 0xec, 20),
        (true, true, 0xe8, 24),
    ] {
        let f = fixture(wide, mask);
        {
            let mut m = f.model.lock().unwrap();
            m.bytes
                .copy_within(0x50..0x50 + length, usize::from(offset));
            m.put(0x34, 1, u32::from(offset));
        }
        let (mut helper, _) = attach(f);
        unsafe { helper.program(MESSAGE) }.unwrap();
        unsafe { helper.unmask() }.unwrap();
        drop(unsafe { helper.release() }.unwrap());
        let f = fixture(wide, mask);
        {
            let mut m = f.model.lock().unwrap();
            let too_far = offset + 4;
            m.put(0x34, 1, u32::from(too_far));
            m.put(too_far, 2, u32::from(MSI));
            let flags = m.get(0x52, 2);
            m.put(too_far + 2, 2, flags);
        }
        let (error, owners) = match unsafe { MsiConfig::new(f.function, f.root) } {
            Err(e) => e,
            Ok(_) => panic!("truncated layout admitted"),
        };
        assert_eq!(error, MsiError::MalformedCapability);
        drop(owners);
    }
}
