// SPDX-License-Identifier: GPL-2.0-only
//! PCI MSI failures fixtures.
use super::*;

#[test]
fn programming_faults_revoke_authorization() {
    for (offset, width) in [(COMMAND, 2), (0x52, 2), (0x54, 4), (0x58, 2)] {
        let (mut helper, model) = attach(fixture(false, false));
        model.lock().unwrap().fail_read = Some((offset, width));
        assert_eq!(
            // SAFETY: The synthetic route and exact RAM config owners remain
            // kept; the injected read failure cannot start device work or
            // invalidate backing.
            unsafe { helper.program(MESSAGE) },
            Err(MsiError::FailedRead { offset })
        );
        assert_eq!(
            // SAFETY: The failed programming revoked authorization; the RAM config/root
            // owners remain live and rejected unmask must not enable delivery.
            unsafe { helper.unmask() },
            Err(MsiError::NotProgrammed)
        );
        model.lock().unwrap().fail_read = None;
        drop(
            // SAFETY: The read fault was cleared and all model activity is synchronous;
            // there are no DMA, IRQ, posted or deferred users before release.
            unsafe { helper.release() }.unwrap(),
        );
    }
    for (offset, width) in [(COMMAND, 2), (0x54, 4), (0x58, 2)] {
        let (mut helper, model) = attach(fixture(false, false));
        model.lock().unwrap().block_write = Some((offset, width));
        assert_eq!(
            // SAFETY: The rejected write targets live RAM owned by the fixture; no
            // source is active and the synthetic route/config guards stay held.
            unsafe { helper.program(MESSAGE) },
            Err(MsiError::Readback { offset })
        );
        assert_eq!(
            // SAFETY: The rejected write revoked authorization while keeping its model
            // owners; unmask must reject before publishing delivery.
            unsafe { helper.unmask() },
            Err(MsiError::NotProgrammed)
        );
        model.lock().unwrap().block_write = None;
        drop(
            // SAFETY: The blocked write was cleared. The model has no asynchronous
            // source, DMA or callbacks, so its original owners may be released.
            unsafe { helper.release() }.unwrap(),
        );
    }
}
#[test]
fn enable_and_mask_faults_retain_owners() {
    let f = fixture(true, true);
    let cd = f.config_drops.clone();
    let rd = f.root_drops.clone();
    let weak = Arc::downgrade(&f.root);
    let (mut helper, model) = attach(f);
    // SAFETY: This fresh fixture owns its synthetic MESSAGE route and RAM config; no
    // source or callback is active while programming.
    unsafe { helper.program(MESSAGE) }.unwrap();
    model.lock().unwrap().block_write = Some((0x52, 2));
    assert_eq!(
        // SAFETY: The route and backing owners remain held across the blocked
        // enable write; the RAM model has no physical interrupt delivery.
        unsafe { helper.unmask() },
        Err(MsiError::Readback { offset: 0x52 })
    );
    model.lock().unwrap().block_write = None;
    model.lock().unwrap().fail_read = Some((COMMAND, 2));
    assert!(
        // SAFETY: The isolated model has no async users or DMA; the injected read fault
        // makes release fail while keeping both owners.
        unsafe { helper.release() }.is_err()
    );
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
    // SAFETY: The fixture keeps the synthetic route and RAM config/root guards; no
    // source is active before the enable-ack fault is armed.
    unsafe { helper.program(MESSAGE) }.unwrap();
    model.lock().unwrap().fail_enable_ack = true;
    assert_eq!(
        // SAFETY: The programmed model route and owners remain held. A lost read
        // acknowledgement changes only RAM state and must quarantine the owner.
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
        // SAFETY: The fresh fixture owns the synthetic route and live RAM config;
        // deliberate stale-identity mutation occurs only after programming.
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
        assert_eq!(
            // SAFETY: All mutated fields remain in live RAM under its original owner. The
            // stale route must be rejected while no device or callback can run.
            unsafe { helper.unmask() },
            Err(expected)
        );
        model
            .lock()
            .unwrap()
            .put(changed, if changed == 0x52 { 2 } else { 4 }, old);
        drop(
            // SAFETY: The mutated field was restored; only synchronous RAM accesses
            // occurred, and no DMA, posted IRQ or deferred user exists before release.
            unsafe { helper.release() }.unwrap(),
        );
    }
}
