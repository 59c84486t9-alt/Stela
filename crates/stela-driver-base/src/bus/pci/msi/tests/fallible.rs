use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

#[test]
fn constructor_unwind_keeps_both_original_owners_before_self_exists() {
    let f = fixture(true, true);
    let config = f.config_drops.clone();
    let root = f.root_drops.clone();
    f.model.lock().unwrap().panic_read = Some((0, 4));
    // SAFETY: actual isolated peer owns this configuration and root allocation;
    // the injected callback is not native admission or IRQ completion evidence.
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: the isolated same-owner peripheral and actual source
            // allocations stay retained; this deliberately tests unwind before
            // constructor publication, never native IRQ admission or drain.
            unsafe { MsiConfig::new(f.function, f.root) }
        }))
        .is_err()
    );
    assert_eq!(config.load(Ordering::Relaxed), 0);
    assert_eq!(root.load(Ordering::Relaxed), 0);
}
#[test]
fn interrupted_message_store_refuses_every_later_effect_and_drop_retains_graph() {
    let f = fixture(true, true);
    let config = f.config_drops.clone();
    let root = f.root_drops.clone();
    let (mut helper, model) = attach(f);
    model.lock().unwrap().panic_write = Some((0x54, 4));
    // SAFETY: synthetic message is authorized only for this isolated RAM peer.
    assert!(catch_unwind(AssertUnwindSafe(|| unsafe { helper.program(MESSAGE) })).is_err());
    let before = model.lock().unwrap().events.clone();
    assert_eq!(helper.mask(), Err(MsiError::Interrupted));
    assert_eq!(helper.disable(), Err(MsiError::Interrupted));
    // SAFETY: terminal control must reject before any modeled config effect.
    assert_eq!(
        // SAFETY: same isolated retained source/message; interrupted state
        // must reject this call before any new configuration effect.
        unsafe { helper.program(MESSAGE) },
        Err(MsiError::Interrupted)
    );
    // SAFETY: same retained isolated source/root; no new real route is admitted.
    assert_eq!(unsafe { helper.unmask() }, Err(MsiError::Interrupted));
    // SAFETY: no asynchronous model users; interrupted access must still refuse.
    assert!(matches!(
        // SAFETY: actual model users are synchronous and retained; the
        // interrupted operation must still refuse this attempted extraction.
        unsafe { helper.release() },
        Err(MsiError::Interrupted)
    ));
    drop(helper);
    assert_eq!(model.lock().unwrap().events, before);
    assert_eq!(config.load(Ordering::Relaxed), 0);
    assert_eq!(root.load(Ordering::Relaxed), 0);
}
