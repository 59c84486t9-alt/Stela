// SPDX-License-Identifier: GPL-2.0-only
//! PCI MSI failures fixtures.
use super::*;

#[test]
fn programming_faults_revoke_authorization() {
    for (offset, width) in [(COMMAND, 2), (0x52, 2), (0x54, 4), (0x58, 2)] {
        let (mut helper, model) = attach(fixture(false, false));
        model.lock().unwrap().fail_read = Some((offset, width));
        assert_eq!(
            unsafe { helper.program(MESSAGE) },
            Err(MsiError::FailedRead { offset })
        );
        assert_eq!(unsafe { helper.unmask() }, Err(MsiError::NotProgrammed));
        model.lock().unwrap().fail_read = None;
        drop(unsafe { helper.release() }.unwrap());
    }
    for (offset, width) in [(COMMAND, 2), (0x54, 4), (0x58, 2)] {
        let (mut helper, model) = attach(fixture(false, false));
        model.lock().unwrap().block_write = Some((offset, width));
        assert_eq!(
            unsafe { helper.program(MESSAGE) },
            Err(MsiError::Readback { offset })
        );
        assert_eq!(unsafe { helper.unmask() }, Err(MsiError::NotProgrammed));
        model.lock().unwrap().block_write = None;
        drop(unsafe { helper.release() }.unwrap());
    }
}
#[test]
fn enable_and_mask_faults_retain_owners() {
    let f = fixture(true, true);
    let cd = f.config_drops.clone();
    let rd = f.root_drops.clone();
    let weak = Arc::downgrade(&f.root);
    let (mut helper, model) = attach(f);
    unsafe { helper.program(MESSAGE) }.unwrap();
    model.lock().unwrap().block_write = Some((0x52, 2));
    assert_eq!(
        unsafe { helper.unmask() },
        Err(MsiError::Readback { offset: 0x52 })
    );
    model.lock().unwrap().block_write = None;
    model.lock().unwrap().fail_read = Some((COMMAND, 2));
    assert!(unsafe { helper.release() }.is_err());
    let count = quarantined_configurations();
    drop(helper);
    assert!(quarantined_configurations() >= count.saturating_add(1));
    assert_eq!(cd.load(Ordering::Relaxed), 0);
    assert_eq!(rd.load(Ordering::Relaxed), 0);
    assert!(weak.upgrade().is_some());
}
#[test]
fn unacknowledged_enable_quarantines() {
    let f = fixture(false, false);
    let config_drops = f.config_drops.clone();
    let root_drops = f.root_drops.clone();
    let (mut helper, model) = attach(f);
    unsafe { helper.program(MESSAGE) }.unwrap();
    model.lock().unwrap().fail_enable_ack = true;
    assert_eq!(
        unsafe { helper.unmask() },
        Err(MsiError::FailedRead { offset: 0x52 })
    );
    assert_eq!(model.lock().unwrap().get(0x52, 2) & 1, 1);
    drop(helper);
    assert_eq!(config_drops.load(Ordering::Relaxed), 0);
    assert_eq!(root_drops.load(Ordering::Relaxed), 0);
}
#[test]
fn changed_route_revokes_authorization() {
    for changed in [0, 0x52, 0x54] {
        let (mut helper, model) = attach(fixture(false, false));
        unsafe { helper.program(MESSAGE) }.unwrap();
        let old = {
            let mut m = model.lock().unwrap();
            let old = m.get(changed, if changed == 0x52 { 2 } else { 4 });
            m.put(
                changed,
                if changed == 0x52 { 2 } else { 4 },
                old ^ if changed == 0x52 { u32::from(WIDE) } else { 4 },
            );
            old
        };
        let expected = match changed {
            0 => MsiError::IdentityChanged,
            0x52 => MsiError::CapabilityChanged,
            _ => MsiError::Readback { offset: 0x54 },
        };
        assert_eq!(unsafe { helper.unmask() }, Err(expected));
        model
            .lock()
            .unwrap()
            .put(changed, if changed == 0x52 { 2 } else { 4 }, old);
        drop(unsafe { helper.release() }.unwrap());
    }
}
