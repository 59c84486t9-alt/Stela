//! Callback-unwind controls keep grants even before their first hardware use.
use super::*;

struct PanicRoot(Arc<Checks>);
// SAFETY: isolated original whole-root peer; check deliberately unwinds without
// changing any hardware/context, testing retention rather than granting success.
unsafe impl RootOwner for PanicRoot {
    fn context(&self) -> Arc<dyn Context> {
        self.0.clone()
    }
    fn check(&self) -> Result<(), VtdError> {
        panic!("injected root check unwind")
    }
    fn generation(&self) -> u64 {
        17
    }
}
impl Drop for PanicRoot {
    fn drop(&mut self) {
        self.0.drops.fetch_add(1, Ordering::Relaxed);
    }
}
struct PanicSource {
    checks: Arc<Checks>,
    at: usize,
}
// SAFETY: exact isolated SID/epoch peer. The chosen check only unwinds; it
// performs no reset, config mutation or hardware access before doing so.
unsafe impl ExactSourceOwner for PanicSource {
    fn check(&self) -> Result<(), VtdError> {
        let count = self.checks.observations.fetch_add(1, Ordering::Relaxed) + 1;
        assert_ne!(count, self.at, "injected source check unwind");
        Ok(())
    }
    fn identity(&self) -> SourceIdentity {
        SourceIdentity {
            source_id: SID,
            configuration_epoch: 1,
            reset_epoch: 1,
        }
    }
}
impl Drop for PanicSource {
    fn drop(&mut self) {
        self.checks.drops.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn original_grant_callback_unwinds_never_run_final_owner_drop() {
    let f = Fixture::new(true);
    let root = Arc::new(Checks::default());
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: original isolated grant deliberately unwinds before exposure.
        unsafe {
            f.unit
                .enable_interrupt_remapping(Box::new(PanicRoot(root.clone())))
        }
    }));
    assert!(result.is_err());
    assert_eq!(root.drops.load(Ordering::Relaxed), 0);
    f.enable();
    for at in [1, 3] {
        let source = Arc::new(Checks::default());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // SAFETY: exact original symbolic source; chosen callback unwinds.
            unsafe {
                f.unit.allocate_interrupt_route(
                    Box::new(PanicSource {
                        checks: source.clone(),
                        at,
                    }),
                    RouteTarget::new(2, 0x51).unwrap(),
                )
            }
        }));
        assert!(result.is_err());
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
        let _guard = f.unit.lock();
        f.unit.with_interrupts(|slot| {
            let irq = slot.as_ref().unwrap();
            assert_eq!(irq.records.len(), usize::from(at == 3));
            assert_eq!(irq.poisoned, at == 3);
        });
    }
}
