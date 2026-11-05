//! Actual isolated hosted RAM/count controls, never native PCI permissions.
extern crate std;
use super::*;
use crate::{
    bus::{
        mmio::owned::{
            Error as MappingError,
            model::{MappingOwner, MappingRetention},
        },
        pci::assignment,
    },
    sync::{FirstFault, testing},
};
use alloc::boxed::Box;
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    thread::{self, ThreadId},
};

#[repr(C, align(4096))]
struct Ram {
    words: UnsafeCell<[u32; 1024]>,
    original_thread: ThreadId,
}
// SAFETY: only explicit bounded raw accesses below; no safe mutable RAM loan.
unsafe impl Send for Ram {}
// SAFETY: the owning test serializes all payload access and actual return tails.
unsafe impl Sync for Ram {}
fn context(ram: &Arc<Ram>) -> Result<(), assignment::Error> {
    if thread::current().id() != ram.original_thread
        || !(ram.words.get() as usize).is_multiple_of(4096)
    {
        Err(assignment::Error::Context)
    } else {
        Ok(())
    }
}
struct Validator {
    ram: MappingRetention<Arc<Ram>>,
    fault: FirstFault<ConfigError>,
    panic: AtomicBool,
    checks: AtomicUsize,
}
struct PublishInterrupted<'a> {
    validator: &'a Validator,
    done: bool,
}
impl Drop for PublishInterrupted<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.validator
                .fault
                .latch(ConfigError::before_effect(ConfigFailure::Interrupted));
        }
    }
}
// SAFETY: SAME actual isolated RAM/allocation and context; fault publication is
// only negative model data. No Source, native/driver/controller or map is built.
unsafe impl CompletionCheck for Validator {
    fn postvalidate(&self) -> Result<(), ConfigError> {
        let mut interrupted = PublishInterrupted {
            validator: self,
            done: false,
        };
        self.checks.fetch_add(1, Ordering::Relaxed);
        let result = self
            .ram
            .check_context()
            .map_err(|error| ConfigError::before_effect(ConfigFailure::Mapping(error)));
        assert!(
            !self.panic.swap(false, Ordering::Relaxed),
            "actual model completion callback interruption"
        );
        if let Err(error) = result
            && !error.is_observation()
        {
            self.fault.latch(error);
        }
        interrupted.done = true;
        result
    }
    fn failure(&self) -> FaultState<ConfigError> {
        self.fault.observe()
    }
}
type Model = (
    MappingOwner<Arc<Ram>>,
    MappingRetention<Arc<Ram>>,
    Arc<Validator>,
    Arc<Ram>,
);

fn setup() -> Model {
    let ram = Arc::new(Ram {
        words: UnsafeCell::new([0; 1024]),
        original_thread: thread::current().id(),
    });
    // SAFETY: actual private CPU allocation+pure original model thread guard;
    // no device, native root, source/controller or mapping exists.
    let owner = unsafe { MappingOwner::from_owned(ram.clone(), context) };
    let retained = owner.retention().unwrap();
    let validator = Arc::new(Validator {
        ram: retained.clone(),
        fault: FirstFault::new(),
        panic: AtomicBool::new(false),
        checks: AtomicUsize::new(0),
    });
    (owner, retained, validator, ram)
}
fn operation(retained: &MappingRetention<Arc<Ram>>, validator: &Arc<Validator>) -> ConfigOperation {
    let count = retained.begin_use(UseKind::Configuration).unwrap();
    // SAFETY: count and preowned validator retain the exact SAME RAM/epoch;
    // original custody keeps validator alive until every actual count ends.
    unsafe { ConfigOperation::new(count, validator.clone()) }
}
fn store(ram: &Ram, operation: &mut ConfigOperation, offset: u16, value: u32) {
    assert!(offset.is_multiple_of(4) && usize::from(offset) < 4096);
    // SAFETY: private real allocation, checked native width and actual count.
    unsafe {
        ram.words
            .get()
            .cast::<u32>()
            .add(usize::from(offset) / 4)
            .write_volatile(value.to_le())
    };
    // SAFETY: exact already-issued store, no intervening postcheck/callback.
    unsafe { operation.record_write(offset, 4) };
}
#[test]
fn caught_completion_unwind_keeps_same_box_prefix_cause_and_count() {
    let (mut owner, retained, validator, ram) = setup();
    // Preowned complete object, not merely leaked inner Arc storage.
    let mut operation = Box::new(operation(&retained, &validator));
    let address = (&*operation) as *const ConfigOperation;
    store(&ram, &mut operation, 0x44, 0x6d5c4b3a);
    validator.panic.store(true, Ordering::Relaxed);
    let caught = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: actual raw store/tail ended; same real model context.
        let _ = unsafe { operation.finish() };
    }));
    assert!(caught.is_err());
    assert_eq!((&*operation) as *const ConfigOperation, address);
    // SAFETY: isolated diagnostic read after caught operation; no other writer.
    let written = unsafe { ram.words.get().cast::<u32>().add(0x44 / 4).read_volatile() };
    assert_eq!(u32::from_le(written), 0x6d5c4b3a);
    assert_eq!(retained.uses(), 1);
    assert_eq!(
        operation.failure(),
        FaultState::Ready(ConfigError::write_may_have_applied(
            0x44,
            4,
            ConfigFailure::Interrupted
        ))
    );
    assert!(matches!(
        retained.begin_use(UseKind::Configuration),
        Err(MappingError::Assignment(assignment::Error::Closed))
    ));
    assert!(matches!(
        owner.close(),
        Err(MappingError::Assignment(assignment::Error::Busy {
            uses: 1,
            ..
        }))
    ));
}
#[test]
fn original_count_stays_parked_when_release_context_unwinds() {
    struct ReleaseContext(Arc<Ram>);
    // SAFETY: this test owns the actual isolated RAM and uses the same
    // thread guard. There are no native effects or extra control paths.
    unsafe impl assignment::PhysicalAssignment for ReleaseContext {
        fn parent(&self) -> Option<&assignment::Parent> {
            None
        }
        fn check_control(&self) -> Result<(), assignment::Error> {
            context(&self.0)?;
            panic!("original count release interrupted")
        }
    }
    struct Postcheck(Arc<Ram>);
    // SAFETY: keeps the same original CPU RAM and checks its thread context.
    unsafe impl CompletionCheck for Postcheck {
        fn postvalidate(&self) -> Result<(), ConfigError> {
            context(&self.0)
                .map_err(|error| ConfigError::before_effect(ConfigFailure::Ownership(error)))
        }
        fn failure(&self) -> FaultState<ConfigError> {
            FaultState::Empty
        }
    }
    let ram = Arc::new(Ram {
        words: UnsafeCell::new([0; 1024]),
        original_thread: thread::current().id(),
    });
    let owner = assignment::Assignment::from_owned(ReleaseContext(ram.clone()));
    let retained = owner.retain();
    let completion = Arc::new(Postcheck(ram.clone()));
    let count = retained.begin_use(UseKind::Configuration).unwrap().erase();
    // SAFETY: both actual owners retain the same private RAM and context.
    let mut operation = unsafe { ConfigOperation::new(count, completion.clone()) };
    store(&ram, &mut operation, 0x44, 0x6d5c4b3a);
    let caught = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: the actual isolated store and all raw users have ended.
        let _ = unsafe { operation.finish() };
    }));
    assert!(caught.is_err());
    assert!(operation.count.is_some());
    assert_eq!(retained.uses(), 1);
    assert!(matches!(
        retained.begin_use(UseKind::Configuration),
        Err(assignment::Error::Closed)
    ));
}

#[test]
fn same_actual_late_ready_preserves_store_prefix_without_hardware_retry() {
    let (_owner, retained, validator, ram) = setup();
    let mut operation = Box::new(operation(&retained, &validator));
    store(&ram, &mut operation, 0x88, 0xa1b2c3d4);
    assert!(testing::claim(&validator.fault));
    // SAFETY: actual access ended; observation refuses before any postcheck.
    let result = unsafe { operation.finish() };
    assert_eq!(
        result,
        Err(ConfigError::write_may_have_applied(
            0x88,
            4,
            ConfigFailure::FaultPublishing
        ))
    );
    assert_eq!(operation.failure(), FaultState::Publishing);
    assert_eq!(validator.checks.load(Ordering::Relaxed), 0);
    assert_eq!(retained.uses(), 1);
    let actual = ConfigError::before_effect(ConfigFailure::CommandAdmission);
    // SAFETY: sole claimed writer of this SAME real first-fault cell above.
    unsafe { testing::finish(&validator.fault, actual) };
    assert_eq!(
        operation.failure(),
        FaultState::Ready(ConfigError::write_may_have_applied(
            0x88,
            4,
            ConfigFailure::CommandAdmission
        ))
    );
    assert_eq!(validator.checks.load(Ordering::Relaxed), 0);
    assert!(
        !validator
            .fault
            .latch(ConfigError::before_effect(ConfigFailure::Interrupted))
    );
}
#[test]
fn accepted_operation_finishes_after_close_and_completed_observers_are_inert() {
    let (mut owner, retained, validator, _ram) = setup();
    let mut operation = operation(&retained, &validator);
    assert!(matches!(
        owner.close(),
        Err(MappingError::Assignment(assignment::Error::Busy {
            uses: 1,
            ..
        }))
    ));
    // SAFETY: no volatile/user was issued by this accepted readonly operation.
    unsafe { operation.finish() }.unwrap();
    assert_eq!(retained.uses(), 0);
    let calls = validator.checks.load(Ordering::Relaxed);
    assert_eq!(operation.failure(), FaultState::Empty);
    operation.close_metadata();
    // SAFETY: deliberately check the inert completed refusal before all fields.
    let result = unsafe { operation.finish() };
    assert_eq!(
        result,
        Err(ConfigError::before_effect(
            ConfigFailure::UnqualifiedControl
        ))
    );
    assert_eq!(validator.checks.load(Ordering::Relaxed), calls);
    drop(operation);
    drop(validator);
    drop(retained);
    // SAFETY: all model operations/raw tails/retentions ended, same source CPU.
    let _same_ram = unsafe { owner.retire() }.unwrap();
}
