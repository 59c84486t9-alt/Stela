//! Failure, refusal and finite-resource controls for independent VT-d peers.
use super::*;

#[test]
fn wrong_context_preflight_drop_retains_original_root_and_source() {
    let f = Fixture::new(true);
    f.root.fail.store(true, Ordering::Relaxed);
    let writes = f.registers.0.lock().unwrap().writes.len();
    {
        // SAFETY: intentionally refused original-context peer, no hardware exposure.
        let failed = unsafe {
            f.unit
                .enable_interrupt_remapping(Box::new(RootGrant(f.root.clone())))
        }
        .err()
        .unwrap();
        assert!(failed.returned.is_some());
    }
    assert_eq!(f.root.drops.load(Ordering::Relaxed), 0);
    assert_eq!(f.registers.0.lock().unwrap().writes.len(), writes);
    f.root.fail.store(false, Ordering::Relaxed);
    f.enable();
    let checks = Arc::new(Checks::default());
    checks.fail.store(true, Ordering::Relaxed);
    {
        // SAFETY: intentionally refused exact source peer with original owner kept.
        let failed = unsafe {
            f.unit.allocate_interrupt_route(
                Box::new(SourceGrant {
                    checks: checks.clone(),
                    epoch: 1,
                }),
                RouteTarget::new(2, 0x51).unwrap(),
            )
        }
        .err()
        .unwrap();
        assert!(failed.returned.is_some());
    }
    assert_eq!(checks.drops.load(Ordering::Relaxed), 0);
    let (route, _) = f.route(2, 0x51);
    assert_eq!(route.identity().index, 0);
}

#[test]
fn allocation_failure_and_unwind_keep_original_root_grant() {
    for panic in [false, true] {
        let f = Fixture::new(true);
        if panic {
            f.pool.panic_at.store(0x104000, Ordering::Relaxed)
        } else {
            f.pool.fail_at.store(0x104000, Ordering::Relaxed)
        }
        let writes = f.registers.0.lock().unwrap().writes.len();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // SAFETY: original isolated root; only the ordinary RAM allocator
            // fails or unwinds before any IRQ address reaches the hardware.
            unsafe {
                f.unit
                    .enable_interrupt_remapping(Box::new(RootGrant(f.root.clone())))
            }
        }));
        if panic {
            assert!(result.is_err())
        } else {
            let failed = result.unwrap().err().unwrap();
            assert_eq!(failed.error, VtdError::Memory);
            assert!(failed.returned.is_some());
        }
        assert_eq!(f.root.drops.load(Ordering::Relaxed), 0);
        assert_eq!(f.pool.released.load(Ordering::Relaxed), 2);
        assert_eq!(f.registers.0.lock().unwrap().writes.len(), writes);
    }
}

#[test]
fn every_uncertain_irq_enable_stage_keeps_all_root_targets() {
    for stage in [QUEUED_INVALIDATION, INTERRUPT_POINTER, INTERRUPT_REMAP] {
        let f = Fixture::new(true);
        f.registers.0.lock().unwrap().fail_enable = stage;
        // SAFETY: independent register peer deliberately withholds this stage.
        let failure = unsafe {
            f.unit
                .enable_interrupt_remapping(Box::new(RootGrant(f.root.clone())))
        }
        .err()
        .unwrap();
        assert!(failure.returned.is_none());
        // SAFETY: the model has no external sources; uncertainty still forbids shutdown.
        assert!(unsafe { f.unit.shut_down() }.is_err());
        drop(f.unit);
        assert_eq!(f.pool.released.load(Ordering::Relaxed), 0);
        assert_eq!(f.root.drops.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn tail_publication_unwind_retains_source_and_burned_index() {
    let f = Fixture::new(true);
    f.enable();
    f.registers.0.lock().unwrap().panic_tail = true;
    let source = Arc::new(Checks::default());
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: original symbolic source; peer unwinds after real tail publication.
        unsafe {
            f.unit.allocate_interrupt_route(
                Box::new(SourceGrant {
                    checks: source.clone(),
                    epoch: 1,
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
        assert!(irq.poisoned);
        assert_eq!(irq.records.len(), 1);
        assert_eq!(irq.records[0].identity.index, 0);
    });
}

#[test]
fn queue_head_alone_or_wrong_status_never_acknowledges_wait() {
    for wrong in [false, true] {
        let f = Fixture::new(true);
        f.enable();
        let (mut route, source) = f.route(1, 0x51);
        let mut h = f.registers.0.lock().unwrap();
        h.hold_status = !wrong;
        h.bad_status = wrong;
        drop(h);
        assert!(fence(&mut route).is_err());
        let h = f.registers.0.lock().unwrap();
        assert_eq!(h.values[&IQH], h.values[&IQT]);
        drop(h);
        drop(route);
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn payload_hold_does_not_become_interrupt_or_queue_completion() {
    let f = Fixture::new(true);
    f.enable();
    let mut h = f.registers.0.lock().unwrap();
    h.pending_payload = true;
    h.hold_payload = true;
    drop(h);
    assert_eq!(
        f.unit.drain_initial_requester(SID),
        Err(DmaError::InvalidationFailed)
    );
    assert!(f.registers.0.lock().unwrap().pending_payload);
}

#[test]
fn queue_ring_wrap_keeps_exact_logical_sequence() {
    let f = Fixture::new(true);
    f.enable();
    for _ in 0..260 {
        f.unit.drain_initial_requester(SID).unwrap()
    }
    let _guard = f.unit.lock();
    f.unit.with_interrupts(|slot| {
        let irq = slot.as_ref().unwrap();
        assert_eq!(irq.sequence, 261);
        assert!(irq.tail < PAGE);
        irq.quiescent(&f.unit).unwrap();
    });
}

#[test]
fn wire_token_reuse_requires_completed_queue_and_published_sentinel() {
    for coherent in [false, true] {
        let f = Fixture::new(coherent);
        f.enable();
        {
            let _guard = f.unit.lock();
            f.unit.with_interrupts(|slot| {
                let irq = slot.as_mut().unwrap();
                irq.sequence = u64::from(u32::MAX) - 1;
                irq.token = u32::MAX - 1;
                irq.status.write(0, u64::from(irq.token));
            });
        }
        for _ in 0..3 {
            f.unit.drain_initial_requester(SID).unwrap();
        }
        {
            let _guard = f.unit.lock();
            f.unit.with_interrupts(|slot| {
                let irq = slot.as_ref().unwrap();
                assert_eq!(irq.sequence, u64::from(u32::MAX) + 2);
                assert_eq!(irq.token, 2);
                irq.quiescent(&f.unit).unwrap();
            });
        }
        let h = f.registers.0.lock().unwrap();
        let tokens: Vec<_> = h
            .descriptors
            .iter()
            .filter(|words| words[0] & 15 == 5)
            .map(|words| (words[0] >> 32) as u32)
            .rev()
            .take(3)
            .collect();
        assert_eq!(tokens, [2, 1, u32::MAX]);
        assert!(h.status_at_tail.iter().all(|status| *status == 0));
    }
}

#[test]
fn stale_previous_status_after_publication_never_acknowledges_new_wait() {
    let f = Fixture::new(true);
    f.enable();
    let (mut route, source) = f.route(1, 0x51);
    let previous = {
        let _guard = f.unit.lock();
        f.unit.with_interrupts(|slot| slot.as_ref().unwrap().token)
    };
    {
        let mut h = f.registers.0.lock().unwrap();
        h.hold_fetch = true;
        h.status_on_tail = Some(previous);
    }
    assert_eq!(fence(&mut route), Err(VtdError::Invalidation));
    {
        let h = f.registers.0.lock().unwrap();
        assert_eq!(h.status_at_tail.last(), Some(&0));
        assert!(h.events.contains(&"injected-status"));
    }
    drop(route);
    assert_eq!(source.drops.load(Ordering::Relaxed), 0);
}

#[test]
fn delayed_status_after_timeout_cannot_reopen_the_poisoned_queue() {
    let f = Fixture::new(true);
    f.enable();
    let (mut route, source) = f.route(1, 0x51);
    f.registers.0.lock().unwrap().hold_status = true;
    assert_eq!(fence(&mut route), Err(VtdError::Timeout));
    let publications = {
        let mut h = f.registers.0.lock().unwrap();
        assert_eq!(h.values[&IQH], h.values[&IQT]);
        assert!(h.pending_status.is_some());
        h.release_status();
        h.hold_status = false;
        h.status_at_tail.len()
    };
    assert_eq!(fence(&mut route), Err(VtdError::Busy));
    assert_eq!(
        f.unit.drain_initial_requester(SID),
        Err(DmaError::InvalidationFailed)
    );
    assert_eq!(
        f.registers.0.lock().unwrap().status_at_tail.len(),
        publications
    );
    drop(route);
    assert_eq!(source.drops.load(Ordering::Relaxed), 0);
}

#[test]
fn logical_sequence_exhaustion_refuses_before_absent_table_mutation() {
    let f = Fixture::new(true);
    f.enable();
    let (mut route, _) = f.route(1, 0x51);
    {
        let _guard = f.unit.lock();
        f.unit.with_interrupts(|slot| {
            let irq = slot.as_mut().unwrap();
            irq.sequence = u64::MAX;
            irq.token = u32::MAX;
            irq.status.write(0, u64::from(u32::MAX));
        });
    }
    assert_eq!(fence(&mut route), Err(VtdError::Exhausted));
    let _guard = f.unit.lock();
    f.unit
        .with_interrupts(|slot| assert_ne!(slot.as_ref().unwrap().table.read(0) & 1, 0));
}

#[test]
fn full_index_epoch_never_recycles_even_explicitly_retired_routes() {
    let f = Fixture::new(true);
    f.enable();
    for epoch in 1..=ENTRIES as u64 {
        let (mut route, _) = f.route(epoch, 0x51);
        fence(&mut route).unwrap();
        assert_eq!(u64::from(route.identity().index), epoch - 1);
        // SAFETY: all users of this same symbolic endpoint epoch have retired.
        let ReleasedEndpoint { terminal, source } =
            unsafe { route.release_after_retirement() }.unwrap();
        drop(source);
        drop(terminal);
    }
    let source = Arc::new(Checks::default());
    {
        // SAFETY: next unpublished symbolic epoch, expected to refuse index exhaustion.
        let failed = unsafe {
            f.unit.allocate_interrupt_route(
                Box::new(SourceGrant {
                    checks: source.clone(),
                    epoch: 300,
                }),
                RouteTarget::new(2, 0x51).unwrap(),
            )
        }
        .err()
        .unwrap();
        assert_eq!(failed.error, VtdError::Exhausted);
        assert!(failed.returned.is_some());
    }
    assert_eq!(source.drops.load(Ordering::Relaxed), 0);
    // SAFETY: no endpoint active, but upstream index proof is still unresolved.
    assert_eq!(unsafe { f.unit.shut_down() }, Err(VtdError::Busy));
}

#[test]
fn missing_write_drain_stays_unavailable_and_queued_bits_match_capability() {
    let f = Fixture::with_cap_clear(true, CAP_WRITE_DRAIN);
    f.enable();
    assert_eq!(
        f.unit.drain_initial_requester(SID),
        Err(DmaError::DrainUnavailable)
    );
    let _guard = f.unit.lock();
    f.unit.invalidate(false).unwrap();
    let h = f.registers.0.lock().unwrap();
    let descriptor = h.descriptors.iter().rfind(|d| d[0] & 15 == 2).unwrap();
    assert_eq!(descriptor[0] & 0xc0, 0x80);
}

#[test]
fn changed_root_pointer_or_queue_fault_poisons_cached_fence() {
    for register in [IRTA, IQA, RTADDR, ECAP, FSTS] {
        let f = Fixture::new(true);
        f.enable();
        let (mut route, source) = f.route(1, 0x51);
        fence(&mut route).unwrap();
        let mut h = f.registers.0.lock().unwrap();
        *h.values.entry(register).or_default() ^= if register == FSTS { 1 << 4 } else { 0x1000 };
        drop(h);
        assert!(fence(&mut route).is_err());
        drop(route);
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn unused_irq_root_shuts_down_only_after_irq_and_dma_pointer_retirement() {
    let f = Fixture::new(true);
    f.enable();
    // SAFETY: no route was allocated and all symbolic requesters remain stopped.
    unsafe { f.unit.shut_down() }.unwrap();
    let h = f.registers.0.lock().unwrap();
    assert_eq!(h.values[&GSTS] as u32 & PERSISTENT, 0);
    assert_eq!((h.values[&IQA], h.values[&IRTA]), (0, 0));
    drop(h);
    drop(f.unit);
    assert_eq!(f.pool.released.load(Ordering::Relaxed), 5);
    assert_eq!(f.root.drops.load(Ordering::Relaxed), 1);
}
