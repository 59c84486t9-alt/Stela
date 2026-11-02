//! Cold preparation and cancellation through the real runtime callback.
use super::*;
pub(super) unsafe extern "C" fn creator(pointer: *mut c_void) {
    // SAFETY: queue owns Scene and this Foreground stack through join.
    let f = unsafe { &*pointer.cast::<Scene>() };
    let r = f.runtime();
    let authority = Authority::new(&f.cpu);
    if f.mode == Mode::Hot {
        let hot = f.hot.lock().unwrap().unwrap();
        let owner = r
            .reserve_general(&authority, kernel())
            .unwrap()
            .into_owned()
            .unwrap();
        let (index, _) = f.reserved();
        assert_eq!(
            // SAFETY: unbound idle reserved worker; no peer can mutate it.
            unsafe { (*r.task(index)).id },
            hot
        );
        // SAFETY: the prior marker returned through the native dispatcher;
        // no original C/page/alias user exists in this real-stack fixture.
        // Preserve history and require a NEW source allocation epoch.
        let prepared = match unsafe { owner.prepare_stack(&authority) } {
            Ok(prepared) => prepared,
            Err(_) => panic!("physically returned frame refused"),
        };
        assert!(prepared.epoch().is_some());
        // SAFETY: reservation excludes entry and this CPU owns the task array.
        assert!(unsafe { (*r.task(index)).ever_entered });
        // SAFETY: same excluded task, immutable history until reservation ends.
        let sequences = unsafe {
            (
                (*r.task(index)).completed_sequence,
                (*r.task(index)).returned_sequence,
            )
        };
        assert_eq!(sequences.0, sequences.1);
        // SAFETY: this fixture has no foreign C/descriptor/page/alias user.
        unsafe { prepared.cancel(&authority) }.unwrap();
        // SAFETY: this CPU still owns the task array; cancellation preserves history.
        assert!(unsafe { (*r.task(index)).ever_entered });
    }
    let owner = r
        .reserve_unstarted_general(&authority, kernel())
        .unwrap()
        .into_owned()
        .unwrap();
    let (index, range) = f.reserved();
    assert!(
        // SAFETY: worker is held/excluded/unbound. Private history
        // is written only by real entry, which cannot run while reserved.
        !unsafe { (*r.task(index)).ever_entered }
    );
    if f.mode == Mode::Hot {
        assert_ne!(
            // SAFETY: same excluded worker; only identity is read.
            unsafe { (*r.task(index)).id },
            f.hot.lock().unwrap().unwrap()
        );
    }
    if matches!(f.mode, Mode::Denied | Mode::Closed) {
        if f.mode == Mode::Denied {
            authority.active.set(false);
        } else {
            r.queue.close().unwrap();
        }
        // SAFETY: never-entered frame has no source user; inject admission refusal.
        let owner = match unsafe { owner.prepare_stack(&authority) } {
            Err((owner, error)) => {
                assert_eq!(
                    error,
                    if f.mode == Mode::Denied {
                        WorkError::Unavailable
                    } else {
                        WorkError::Closed
                    }
                );
                owner
            }
            _ => panic!("failed precheck mutated"),
        };
        authority.active.set(true);
        // SAFETY: same unexposed frame and restored original process authority.
        unsafe { owner.cancel(&authority) }.unwrap();
        return;
    }
    let top = range.end - 2 * size_of::<usize>();
    // SAFETY: never-entered kept range has only the constructor's
    // two bootstrap words. Copy those initialized words, then poison only the
    // other usable bytes; both PROT_NONE guards and bootstrap remain untouched.
    let before = unsafe {
        let words = (top as *const usize).read();
        let zero = ((top + size_of::<usize>()) as *const usize).read();
        core::ptr::write_bytes(range.start as *mut u8, 0xa7, top - range.start);
        (words, zero)
    };
    // SAFETY: exact excluded worker, immutable Task allocation; the
    // same-thread restore observer reads only its preparation state.
    let state = unsafe { core::ptr::addr_of!((*r.task(index)).state) };
    f.cpu.watch_state.store(state as u64, Ordering::Release);
    f.cpu.watch.store(range.start as u64, Ordering::Release);
    if f.mode == Mode::RestoreRefusal {
        // SAFETY: the real excluded mapping has no C/page/alias users. The
        // actual outer restore observer revokes this scope AFTER transfer.
        let prepared = match unsafe { owner.prepare_stack(&authority) } {
            Err((prepared, WorkError::Unavailable)) => prepared,
            _ => panic!("post-transfer refusal lost exact preparation owner"),
        };
        assert!(f.cpu.restored.load(Ordering::Acquire));
        assert_eq!(prepared.epoch(), Some(1));
        assert_eq!(f.cpu.model.flags(), 0x202);
        // SAFETY: exact excluded backing; the failed fresh scope must prevent
        // every destructive write, including native bootstrap words.
        unsafe {
            assert!(
                core::slice::from_raw_parts(range.start as *const u8, top - range.start)
                    .iter()
                    .all(|byte| *byte == 0xa7)
            );
            assert_eq!((top as *const usize).read(), before.0);
            assert_eq!(
                ((top + size_of::<usize>()) as *const usize).read(),
                before.1
            );
        }
        f.cpu.restored.store(false, Ordering::Release);
        // SAFETY: fresh scope regained; exact transferred owner has no pin or
        // published user, so cancellation must reseed and release only once.
        unsafe { prepared.cancel(&authority) }.unwrap();
        assert_eq!(r.owned_escrows.get(), 0);
        return;
    }
    let cold = take_prepared(owner, &authority);
    assert!(f.cpu.restored.load(Ordering::Acquire));
    assert_eq!(f.cpu.model.flags(), 0x202);
    assert!(
        // SAFETY: Preparing keeps/excludes this entire mapped usable
        // range. Production exposes no byte/address API; zeroing initialized it.
        unsafe { core::slice::from_raw_parts(range.start as *const u8, range.len()) }
            .iter()
            .all(|v| *v == 0)
    );
    match f.mode {
        Mode::Drop => {
            drop(cold);
            return;
        }
        Mode::Stale => {
            authority.active.set(false);
            assert_eq!(
                // SAFETY: no source users; stale authority must refuse cancellation.
                cancellation_error(unsafe { cold.cancel(&authority) }),
                WorkError::Unavailable
            );
            return;
        }
        Mode::Forget => {
            core::mem::forget(cold);
            return;
        }
        Mode::Park => {
            let binding = Arc::new(Binding {
                id: AtomicU64::new(0),
                blocked: AtomicBool::new(true),
            });
            let wake = r.bind_current(binding.clone()).unwrap();
            *f.binding.lock().unwrap() = Some((binding, wake));
            authority.active.set(false);
            drop(authority);
            assert_eq!(r.park_if_blocked().unwrap(), ParkOutcome::Resumed);
            // SAFETY: original CPU resumed; unexposed frame still has no source user.
            unsafe { cold.cancel(&Authority::new(&f.cpu)) }.unwrap();
        }
        _ => {
            // SAFETY: same unexposed frame has no C, page or alias user.
            unsafe { cold.cancel(&authority) }.unwrap();
        }
    }
    assert_eq!(r.owned_escrows.get(), 0);
    // SAFETY: exact cold frame is reseeded but still never entered. Reading its
    // two initialized bootstrap words and zeroed preceding bytes touches no guard.
    unsafe {
        assert_eq!((top as *const usize).read(), before.0);
        assert_eq!(
            ((top + size_of::<usize>()) as *const usize).read(),
            before.1
        );
        assert!(
            core::slice::from_raw_parts(range.start as *const u8, top - range.start)
                .iter()
                .all(|v| *v == 0)
        );
    }
    if f.mode != Mode::Park {
        // SAFETY: exact queue-kept marker fits real compiled kernel geometry;
        // after reseed/cancel the original entry frame must run normally.
        unsafe {
            r.queue
                .execute_general_with_requirement(kernel(), marker, pointer)
        }
        .unwrap();
    }
}
