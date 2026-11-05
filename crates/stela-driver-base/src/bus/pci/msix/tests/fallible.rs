use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};
#[test]
#[expect(
    clippy::result_large_err,
    reason = "constructor refusal retains every original owner without allocation after failure"
)]
fn constructor_unwind_keeps_config_root_and_every_bar_before_self_exists() {
    let f = fixture(3);
    let config = f.config_drops.clone();
    let root = f.root_drops.clone();
    let bars = f.bar_drops.clone();
    f.model.lock().unwrap().panic_identity = true;
    let (function, retained, resources) = f.owners;
    // SAFETY: isolated same-owner RAM peripheral; no native route/grant exists.
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: the isolated same-owner peripheral and actual source
            // allocations stay retained; this deliberately tests unwind before
            // constructor publication, never native IRQ admission or drain.
            unsafe { MsixConfig::new(function, retained, resources) }
        }))
        .is_err()
    );
    assert_eq!(config.load(Ordering::Relaxed), 0);
    assert_eq!(root.load(Ordering::Relaxed), 0);
    assert_eq!(bars.load(Ordering::Relaxed), 0);
}
#[test]
fn interrupted_table_store_never_reopens_admission_or_retires_owners() {
    let f = fixture(3);
    let config = f.config_drops.clone();
    let root = f.root_drops.clone();
    let bars = f.bar_drops.clone();
    let (mut owner, model) = attach(f);
    model.lock().unwrap().panic_message = true;
    // SAFETY: synthetic message/entry belongs only to the retained RAM peer.
    assert!(catch_unwind(AssertUnwindSafe(|| unsafe { owner.program(MESSAGE) })).is_err());
    let effects = model.lock().unwrap().events.clone();
    assert_eq!(owner.mask(), Err(Error::Interrupted));
    assert_eq!(owner.disable(), Err(Error::Interrupted));
    // SAFETY: terminal model must refuse before accessing config or table.
    assert_eq!(unsafe { owner.program(MESSAGE) }, Err(Error::Interrupted));
    // SAFETY: retained model routes do not grant native IRQ admission.
    assert_eq!(unsafe { owner.unmask() }, Err(Error::Interrupted));
    // SAFETY: every model user is synchronous; uncertainty must still refuse.
    assert!(matches!(
        // SAFETY: actual model users are synchronous and retained; the
        // interrupted operation must still refuse this attempted extraction.
        unsafe { owner.release() },
        Err(Error::Interrupted)
    ));
    drop(owner);
    assert_eq!(model.lock().unwrap().events, effects);
    assert_eq!(config.load(Ordering::Relaxed), 0);
    assert_eq!(root.load(Ordering::Relaxed), 0);
    assert_eq!(bars.load(Ordering::Relaxed), 0);
}
