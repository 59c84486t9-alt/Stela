// SPDX-License-Identifier: GPL-2.0-only
//! PCI MSI retirement fixtures.
use super::*;
use crate::bus::pci::regs;

#[test]
fn terminal_stop_releases_original_owners() {
    for wide in [false, true] {
        for mask in [false, true] {
            let f = fixture(wide, mask);
            let configs = f.config_drops.clone();
            let roots = f.root_drops.clone();
            let (mut helper, model) = attach(f);
            // SAFETY: MESSAGE names the synthetic fixture route; its RAM config/root
            // guards are held and no device source or IRQ callback is active.
            unsafe { helper.program(MESSAGE) }.unwrap();
            // SAFETY: The synchronous RAM model keeps the programmed route and
            // owners; it has no device source or asynchronous callback to race
            // unmask.
            unsafe { helper.unmask() }.unwrap();
            // Ordinary admission masking remains reversible.
            helper.mask().unwrap();
            // SAFETY: Only reversible masking occurred; the same RAM route and owners
            // remain held, and no asynchronous source can restart.
            unsafe { helper.unmask() }.unwrap();
            let mut terminal = helper.begin_device_retirement().unwrap();
            assert_terminal(&mut helper, &model);
            assert_eq!(terminal.address().unwrap().device, 2);
            {
                let m = model.lock().unwrap();
                assert_eq!(m.get(0x52, 2) & u32::from(ENABLE), 0);
                assert_ne!(
                    m.get(regs::COMMAND, 2) & u32::from(regs::COMMAND_INTX_DISABLE),
                    0
                );
                assert_eq!(m.get(regs::STATUS, 2), 0xa510);
            }
            // SAFETY: synchronous config model, no device/IRQ users;
            // this is the single terminal stop, with no BM/MSI re-enable.
            let original = unsafe {
                terminal.with_device_stop(|config| {
                    let command = config.read16(regs::COMMAND);
                    config.write16(regs::COMMAND, command & !4);
                    command
                })
            }
            .unwrap();
            assert_ne!(original & 4, 0);
            assert_eq!(model.lock().unwrap().get(regs::COMMAND, 2) & 4, 0);
            // The original config transport can now be inaccessible.
            model.lock().unwrap().transport_dead = true;
            let before = model.lock().unwrap().events.len();
            // SAFETY: isolated fixture has no DMA/posted/IRQ/deferred users;
            // their empty completion is independent of BM-clear.
            let owners = unsafe { terminal.release_after_drain() }.unwrap();
            assert_eq!(model.lock().unwrap().events.len(), before);
            drop(owners);
            assert_eq!(configs.load(Ordering::Relaxed), 1);
            assert_eq!(roots.load(Ordering::Relaxed), 1);
            assert_eq!(terminal.address(), Err(MsiError::Released));
            assert!(matches!(
                // SAFETY: The fixture has no asynchronous users and its original
                // owners were already released; the repeated call must fail before
                // owner access.
                unsafe { terminal.release_after_drain() },
                Err(MsiError::Released)
            ));
        }
    }
}
#[test]
fn retirement_access_faults_keep_owners() {
    for wide in [false, true] {
        for mask in [false, true] {
            let (mut baseline, model) = attach(fixture(wide, mask));
            // SAFETY: The baseline RAM config owns this synthetic route; no device,
            // posted message or callback exists during programming.
            unsafe { baseline.program(MESSAGE) }.unwrap();
            // SAFETY: The baseline keeps the programmed route and backing Arc;
            // unmask changes only the mutex-protected RAM config.
            unsafe { baseline.unmask() }.unwrap();
            model.lock().unwrap().events.clear();
            let terminal = baseline.begin_device_retirement().unwrap();
            let count = model.lock().unwrap().events.len();
            drop(terminal); // live terminal abandonment keeps both real guards.
            for access in 1..=count {
                for after in [false, true] {
                    let f = fixture(wide, mask);
                    let configs = f.config_drops.clone();
                    let roots = f.root_drops.clone();
                    let (mut helper, model) = attach(f);
                    // SAFETY: This fresh fault fixture keeps its own config/root
                    // guards and has no source activity; fault injection begins only
                    // after setup.
                    unsafe { helper.program(MESSAGE) }.unwrap();
                    // SAFETY: The fresh fixture keeps its programmed route and
                    // owners; injected transport loss has not begun yet.
                    unsafe { helper.unmask() }.unwrap();
                    {
                        let mut m = model.lock().unwrap();
                        m.events.clear();
                        m.fault_at_access = Some((access, after));
                    }
                    let result = helper.begin_device_retirement();
                    assert!(model.lock().unwrap().transport_dead);
                    assert_terminal(&mut helper, &model);
                    // A successful final ACK followed by loss may transfer
                    // the original owner, but cannot create a stop proof.
                    drop(result);
                    drop(helper);
                    assert_eq!(
                        configs.load(Ordering::Relaxed),
                        0,
                        "config freed access={access},after={after}"
                    );
                    assert_eq!(
                        roots.load(Ordering::Relaxed),
                        0,
                        "root freed access={access},after={after}"
                    );
                }
            }
        }
    }
}
#[test]
fn stop_unwind_prevents_replay_and_release() {
    let f = fixture(true, true);
    let configs = f.config_drops.clone();
    let roots = f.root_drops.clone();
    let (mut helper, model) = attach(f);
    let mut terminal = helper.begin_device_retirement().unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: isolated config model, one terminal stop with a
        // deliberate post-effect unwind; no configuration escape/re-enable.
        unsafe {
            terminal.with_device_stop::<()>(|config| {
                config.write16(regs::COMMAND, regs::COMMAND_INTX_DISABLE);
                panic!("modeled caller unwind after actual stop effect");
            })
        }
    }));
    assert!(result.is_err());
    assert_eq!(
        model.lock().unwrap().get(regs::COMMAND, 2),
        u32::from(regs::COMMAND_INTX_DISABLE)
    );
    let before = model.lock().unwrap().events.len();
    assert_eq!(
        // SAFETY: The previous synchronous stop already unwound. The kept
        // terminal owner must reject this callback before invoking it.
        unsafe { terminal.with_device_stop::<()>(|_| panic!("replay after unwind")) },
        Err(MsiError::StopAlreadyAttempted)
    );
    assert_eq!(model.lock().unwrap().events.len(), before);
    drop(terminal);
    drop(helper);
    assert_eq!(configs.load(Ordering::Relaxed), 0);
    assert_eq!(roots.load(Ordering::Relaxed), 0);
}

#[test]
fn owned_mapping_retirement_and_abandonment() {
    use crate::bus::pci::owned::tests::fixture as owned_fixture;
    for abandon in [false, true] {
        let address = Address {
            segment: 7,
            bus: 3,
            device: 4,
            function: 1,
        };
        let (mut config, counters) = owned_fixture(address);
        config.write32(0, 0x1234_8086);
        config.write16(regs::COMMAND, 0x107);
        config.write16(regs::STATUS, regs::STATUS_CAP_LIST);
        config.write8(0x34, 0x50);
        config.write16(0x50, u16::from(MSI));
        config.write16(0x52, WIDE | MASK_CAPABLE);
        let function = Function::new(address, config).unwrap();
        let root_drops = Arc::new(AtomicU64::new(0));
        let root: RetainedOwner = Arc::new(Root(root_drops.clone()));
        // SAFETY: original isolated registry-owned RAM config epoch, no
        // device, IRQ delivery, worker or production validation exists.
        let mut helper = match unsafe { MsiConfig::new(function, root) } {
            Ok(helper) => helper,
            Err((error, _)) => panic!("valid actual owned transport: {error:?}"),
        };
        let mut terminal = helper.begin_device_retirement().unwrap();
        assert_eq!(terminal.address(), Ok(address));
        // SAFETY: single synchronous stop of this isolated owner.
        let stopped = unsafe {
            terminal.with_device_stop(|config| {
                let command = config.read16(regs::COMMAND);
                config.write16(regs::COMMAND, command & !4);
                config.read16(regs::COMMAND) & 4 == 0
            })
        }
        .unwrap();
        assert!(stopped);
        assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
        assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
        if abandon {
            drop(terminal);
            drop(helper);
            assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
            assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
            assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 0);
            assert_eq!(root_drops.load(Ordering::Relaxed), 0);
        } else {
            // SAFETY: the isolated real resource has no async users; empty
            // device/IRQ completion is known independently of config bits.
            let (function, root) = unsafe { terminal.release_after_drain() }.unwrap();
            let mut mapping = function.into_config().into_mapping();
            // SAFETY: original mapping, all synchronous users ended.
            unsafe { mapping.retire() }.unwrap();
            drop(root);
            assert_eq!(counters.unmaps.load(Ordering::Relaxed), 1);
            assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 1);
            assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 1);
            assert_eq!(root_drops.load(Ordering::Relaxed), 1);
        }
    }
}

#[test]
fn failed_stop_keeps_owners() {
    let f = fixture(true, true);
    let configs = f.config_drops.clone();
    let roots = f.root_drops.clone();
    let (mut helper, model) = attach(f);
    let mut terminal = helper.begin_device_retirement().unwrap();
    // SAFETY: one isolated model stop; its precise failure remains
    // caller-visible, and supplies no quiescence or release authorization.
    let original: Result<(), u32> = unsafe {
        terminal.with_device_stop(|config| {
            config.write16(regs::COMMAND, regs::COMMAND_INTX_DISABLE);
            Err(0x4377_00ff)
        })
    }
    .unwrap();
    assert_eq!(original, Err(0x4377_00ff));
    let before = model.lock().unwrap().events.len();
    assert_eq!(
        // SAFETY: The failed stop kept its terminal owner; this second callback
        // must be rejected without retrying the stop or touching config.
        unsafe { terminal.with_device_stop(|_| panic!("reset replay")) },
        Err::<(), _>(MsiError::StopAlreadyAttempted)
    );
    assert_eq!(model.lock().unwrap().events.len(), before);
    drop(terminal);
    drop(helper);
    assert_eq!(configs.load(Ordering::Relaxed), 0);
    assert_eq!(roots.load(Ordering::Relaxed), 0);
}
