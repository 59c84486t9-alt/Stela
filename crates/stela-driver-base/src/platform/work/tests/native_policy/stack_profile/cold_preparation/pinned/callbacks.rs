//! Pin acquisition and cancellation through real runtime continuations.
use super::*;
pub(super) unsafe extern "C" fn marker(pointer: *mut c_void) {
    // SAFETY: queue keeps this exact Scene/code until real completion.
    let f = unsafe { &*pointer.cast::<PinScene>() };
    f.marked.fetch_add(1, Ordering::Relaxed);
    if f.case == Case::Park {
        assert_eq!(f.entered.load(Ordering::Acquire), 0);
        let (binding, wake) = f.binding.lock().unwrap().as_ref().unwrap().clone();
        binding.blocked.store(false, Ordering::Release);
        wake.wake().unwrap();
    }
}
pub(super) unsafe extern "C" fn creator(pointer: *mut c_void) {
    // SAFETY: Scene, Foreground frame and all owners survive join.
    let f = unsafe { &*pointer.cast::<PinScene>() };
    let r = f.runtime();
    let authority = f.authority();
    let owner = r
        .reserve_unstarted_general(&authority, kernel())
        .unwrap()
        .into_owned()
        .unwrap();
    let cold = take_prepared(owner, &authority);
    if f.case == Case::Denied {
        f.active.store(false, Ordering::Release);
    }
    if f.case == Case::Closed {
        r.queue.close().unwrap();
    }
    let pinned = match cold.pin(&authority) {
        Ok(pin) => pin,
        Err((cold, error)) => {
            let expected = match f.case {
                Case::Missing => StackPinError::Memory(MemoryError::Unavailable),
                Case::Oom => StackPinError::Memory(MemoryError::OutOfMemory),
                Case::Logical => StackPinError::Memory(MemoryError::InvalidSize),
                Case::Subset | Case::Granule => StackPinError::Memory(MemoryError::InvalidPageList),
                Case::Other => StackPinError::Memory(MemoryError::OutsideReservation),
                Case::Denied | Case::PostStale => StackPinError::Work(WorkError::Unavailable),
                Case::Closed => StackPinError::Work(WorkError::Closed),
                _ => panic!("unexpected pin refusal {error:?}"),
            };
            assert_eq!(error, expected);
            assert_eq!(f.pins_dropped.load(Ordering::Relaxed), 0);
            assert_eq!(r.owned_escrows.get(), 1);
            f.active.store(true, Ordering::Release);
            drop(authority);
            let fresh = f.authority();
            let acquired = matches!(
                f.case,
                Case::Logical | Case::Subset | Case::Granule | Case::Other | Case::PostStale
            );
            let cold = if acquired {
                match cold.pin(&fresh) {
                    Err((cold, error)) => {
                        assert_eq!(error, StackPinError::Work(WorkError::Busy));
                        cold
                    }
                    Ok(_) => panic!("retry accumulated another actual pin"),
                }
            } else {
                cold
            };
            // SAFETY: no exported source user; fresh original authority retires held pins.
            unsafe { cold.cancel(&fresh) }.unwrap();
            assert_eq!(
                f.pins_dropped.load(Ordering::Relaxed),
                usize::from(acquired)
            );
            return;
        }
    };
    assert_eq!(f.exports.load(Ordering::Relaxed), 1);
    assert_eq!(f.pins_dropped.load(Ordering::Relaxed), 0);
    assert_eq!(r.owned_escrows.get(), 1);
    match f.case {
        Case::Drop => {
            drop(pinned);
        }
        Case::Stale => {
            f.active.store(false, Ordering::Release);
            assert_eq!(
                // SAFETY: no source user; stale authority must retain the pin.
                cancellation_error(unsafe { pinned.cancel(&authority) }),
                WorkError::Unavailable
            );
        }
        Case::Forget => {
            core::mem::forget(pinned);
        }
        Case::Park => {
            let binding = Arc::new(Binding {
                id: AtomicU64::new(0),
                blocked: AtomicBool::new(true),
            });
            let wake = r.bind_current(binding.clone()).unwrap();
            *f.binding.lock().unwrap() = Some((binding, wake));
            f.active.store(false, Ordering::Release);
            drop(authority);
            assert_eq!(r.park_if_blocked().unwrap(), ParkOutcome::Resumed);
            f.active.store(true, Ordering::Release);
            // SAFETY: original CPU resumed with no published source user.
            unsafe { pinned.cancel(&f.authority()) }.unwrap();
        }
        _ => {
            // SAFETY: pin remains unexposed; original authority can cancel it.
            unsafe { pinned.cancel(&authority) }.unwrap();
        }
    }
    if matches!(f.case, Case::Drop | Case::Stale | Case::Forget) {
        assert_eq!(f.pins_dropped.load(Ordering::Relaxed), 0);
        println!("STELA_COLD_PIN_OWNER_RETAINED {:?}", f.case);
        return;
    }
    assert_eq!(r.owned_escrows.get(), 0);
    assert_eq!(f.pins_dropped.load(Ordering::Relaxed), 1);
    if f.case == Case::Good {
        // SAFETY: original cold frame was reseeded/cancelled; this
        // finite marker fits the real kernel-sized owned worker and stays held.
        unsafe {
            r.queue
                .execute_general_with_requirement(kernel(), marker, pointer)
        }
        .unwrap();
    }
}
