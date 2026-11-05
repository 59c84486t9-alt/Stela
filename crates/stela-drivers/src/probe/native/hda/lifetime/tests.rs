//! Native ownership regression models. No physical controller/IRQ evidence.
extern crate std;
use super::super::RetirementError;
use super::*;
use core::sync::atomic::Ordering;
mod fixture;
use fixture::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

#[test]
fn cold_native_requires_original_irq_work_completion_even_when_intctl_is_masked() {
    let mut f = fixture(false);
    let failure = match Native::new(f.inputs.take().unwrap()) {
        Ok(_) => panic!("unproved original IRQ/work must refuse"),
        Err(f) => f,
    };
    assert_eq!(failure.error, RetirementError::OriginalUsersUnavailable);
    let s = lock(&f.state);
    assert!(s.events.contains(&Event::Write(0x20, 4, 0)));
    assert!(
        !s.events
            .iter()
            .any(|e| matches!(e, Event::OriginalDrain | Event::Bind | Event::Allocate))
    );
    assert_eq!(s.inherited, vec![0xa5; 8192]);
    drop(s);
    let before = snapshot(&f.state);
    drop(failure);
    assert_eq!(snapshot(&f.state), before);
    assert_eq!(f.config.unmaps.load(Ordering::Relaxed), 0);
}

#[test]
fn original_root_engine_drain_bind_new_ring_order_and_real_config_pin_retirement() {
    let mut f = fixture(true);
    let mut native = match Native::new(f.inputs.take().unwrap()) {
        Ok(n) => n,
        Err(e) => panic!("{:?}", e.error),
    };
    let events = lock(&f.state).events.clone();
    let drain = events
        .iter()
        .position(|e| *e == Event::OriginalDrain)
        .unwrap();
    let bind = events.iter().position(|e| *e == Event::Bind).unwrap();
    let allocate = events.iter().position(|e| *e == Event::Allocate).unwrap();
    assert!(drain < bind && bind < allocate);
    for offset in [0x80usize, 0xa0] {
        assert!(events[..drain].contains(&Event::Write(offset, 1, 0)));
    }
    assert_eq!(lock(&f.state).inherited, vec![0xa5; 8192]);
    assert_eq!(f.config.unmaps.load(Ordering::Relaxed), 0);
    // A genuine retained view of the same owned config remains pinned.
    let mut config_view = native.owner.resources().pci.as_ref().unwrap().borrow_mut();
    let pin = config_view.retain_config_epoch().unwrap();
    drop(pin);
    drop(config_view);
    native.close().unwrap();
    let events = lock(&f.state).events.clone();
    let payload = events
        .iter()
        .rposition(|e| *e == Event::PayloadDrain)
        .unwrap();
    let unmap = events
        .iter()
        .rposition(|e| matches!(e, Event::DmaUnmap(_)))
        .unwrap();
    let detach = events.iter().position(|e| *e == Event::Detach).unwrap();
    let bar = events.iter().position(|e| *e == Event::BarRetire).unwrap();
    assert!(payload < unmap && unmap < detach && detach < bar);
    assert!(lock(&f.state).live.is_empty());
    assert_eq!(f.config.unmaps.load(Ordering::Relaxed), 1);
    assert_eq!(lock(&f.state).page_drops, 2);
    let before = snapshot(&f.state);
    assert_eq!(native.close(), Err(RetirementError::Terminal));
    drop(native);
    assert_eq!(snapshot(&f.state), before);
}

#[test]
fn cold_and_constructor_failure_preserve_original_owner_and_never_retry_on_drop() {
    for fault in [
        Fault::Stop,
        Fault::OriginalDrain,
        Fault::Bind,
        Fault::Allocate(1),
        Fault::Allocate(2),
    ] {
        let mut f = fixture(true);
        lock(&f.state).fault = fault;
        let failure = match Native::new(f.inputs.take().unwrap()) {
            Ok(_) => panic!("fault {fault:?}"),
            Err(f) => f,
        };
        assert_eq!(f.config.unmaps.load(Ordering::Relaxed), 0);
        let before = snapshot(&f.state);
        drop(failure);
        assert_eq!(snapshot(&f.state), before);
        assert_eq!(lock(&f.state).page_drops, 0);
    }
}

#[test]
fn active_drop_performs_no_stop_reset_drain_unmap_or_detach() {
    let mut f = fixture(true);
    let native = match Native::new(f.inputs.take().unwrap()) {
        Ok(n) => n,
        Err(e) => panic!("{:?}", e.error),
    };
    let before = snapshot(&f.state);
    drop(native);
    assert_eq!(snapshot(&f.state), before);
    assert_eq!(f.config.unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(lock(&f.state).page_drops, 0);
}

#[test]
fn final_retirement_failure_is_sticky_and_blocks_all_reentry_after_partial_effects() {
    for fault in [
        Fault::Stop,
        Fault::Payload,
        Fault::Unmap,
        Fault::Detach,
        Fault::Bar,
        Fault::Config,
    ] {
        let mut f = fixture(true);
        let mut native = match Native::new(f.inputs.take().unwrap()) {
            Ok(n) => n,
            Err(e) => panic!("{:?}", e.error),
        };
        lock(&f.state).fault = fault;
        let error = native.close().unwrap_err();
        let before = snapshot(&f.state);
        assert_eq!(native.close(), Err(error));
        assert_eq!(native.discover_and_setup().err(), Some(error));
        drop(native);
        assert_eq!(snapshot(&f.state), before);
        assert_eq!(f.config.unmaps.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn panic_during_original_stop_root_drain_and_final_protocol_shutdown_keeps_graph_terminal() {
    for point in [0usize, 1, 2] {
        let mut f = fixture(true);
        if point < 2 {
            lock(&f.state).fault = if point == 0 {
                Fault::PanicStop
            } else {
                Fault::PanicOriginal
            };
            let result = catch_unwind(AssertUnwindSafe(|| Native::new(f.inputs.take().unwrap())));
            assert!(result.is_err());
        } else {
            let mut native = match Native::new(f.inputs.take().unwrap()) {
                Ok(n) => n,
                Err(e) => panic!("{:?}", e.error),
            };
            lock(&f.state).fault = Fault::PanicStop;
            assert!(catch_unwind(AssertUnwindSafe(|| native.close())).is_err());
            let before = snapshot(&f.state);
            assert_eq!(native.close(), Err(RetirementError::Terminal));
            assert_eq!(
                native.discover_and_setup().err(),
                Some(RetirementError::Terminal)
            );
            drop(native);
            assert_eq!(snapshot(&f.state), before);
        }
        assert_eq!(f.config.unmaps.load(Ordering::Relaxed), 0);
        assert_eq!(lock(&f.state).page_drops, 0);
    }
}

#[test]
fn real_external_config_retention_refuses_mapping_release_after_unique_detach_and_stays_terminal() {
    let mut f = fixture(true);
    let mut native = match Native::new(f.inputs.take().unwrap()) {
        Ok(n) => n,
        Err(e) => panic!("{:?}", e.error),
    };
    let pin = native
        .owner
        .resources()
        .pci
        .as_ref()
        .unwrap()
        .borrow_mut()
        .retain_config_epoch()
        .unwrap();
    let error = native.close().unwrap_err();
    assert_eq!(error, RetirementError::Mapping(MappingError::Busy));
    assert!(lock(&f.state).events.contains(&Event::Detach));
    assert_eq!(f.config.unmaps.load(Ordering::Relaxed), 0);
    drop(pin);
    let before = snapshot(&f.state);
    assert_eq!(native.close(), Err(error));
    drop(native);
    assert_eq!(snapshot(&f.state), before);
    assert_eq!(f.config.unmaps.load(Ordering::Relaxed), 0);
}

#[test]
fn unique_attachment_refuses_live_coherent_leases_before_bar_or_configuration_retirement() {
    let mut f = fixture(true);
    let mut native = match Native::new(f.inputs.take().unwrap()) {
        Ok(n) => n,
        Err(e) => panic!("{:?}", e.error),
    };
    let r = native.owner.resources();
    // SAFETY: this diagnostic manually observes current engine/source stop
    // with the original owner/IRQ/work exclusion; no new publication follows.
    hda::cold::stop_inherited(
        &mut *r.pci.as_ref().unwrap().borrow_mut(),
        &r.clock,
        &r.config.unwrap(),
    )
    .unwrap();
    // SAFETY: same stopped original register/Attachment graph.
    unsafe { r.pci.as_ref().unwrap().borrow_mut().set_bus_master(false) }.unwrap();
    // SAFETY: exact current payload source is stopped above; model independent
    // original IRQ/CPU/work capability remains kept in r.
    unsafe {
        r.attachment
            .as_ref()
            .unwrap()
            .domain()
            .drain_posted_writes()
    }
    .unwrap();
    // SAFETY: all users stopped/drained; remaining mapped leases intentionally
    // exercise mandatory metadata refusal without allowing actual detach.
    let error = match unsafe { r.attachment.as_mut().unwrap().detach() } {
        Err(error) => error,
        Ok(receipt) => {
            // An unexpected successful detach must not discard its affine
            // receipt while this deliberately retained graph still exists.
            core::mem::forget(receipt);
            panic!("detach unexpectedly accepted retained users");
        }
    };
    assert_eq!(error, DmaError::InvalidationFailed);
    assert!(
        !lock(&f.state)
            .events
            .iter()
            .any(|e| matches!(e, Event::Detach | Event::BarRetire))
    );
    assert_eq!(f.config.unmaps.load(Ordering::Relaxed), 0);
    let before = snapshot(&f.state);
    drop(native);
    assert_eq!(snapshot(&f.state), before);
}

#[test]
fn foreign_original_user_capability_refuses_before_any_hardware_or_dma_effect() {
    let mut original = fixture(true);
    let mut other = fixture(true);
    original.inputs.as_mut().unwrap().original_users =
        other.inputs.as_mut().unwrap().original_users.take();
    let error = match Native::new(original.inputs.take().unwrap()) {
        Ok(_) => panic!("foreign retained config accepted"),
        Err(f) => f,
    };
    assert_eq!(error.error, RetirementError::ForeignOriginalUsers);
    assert!(lock(&original.state).events.is_empty());
    assert_eq!(original.config.unmaps.load(Ordering::Relaxed), 0);
    let before = snapshot(&original.state);
    drop(error);
    assert_eq!(snapshot(&original.state), before);
}

#[test]
fn every_native_configuration_access_fault_keeps_original_graph_and_cannot_drop_retry() {
    let mut control = fixture(true);
    let before = control.config.contexts.load(Ordering::Relaxed);
    let owner = match Native::new(control.inputs.take().unwrap()) {
        Ok(n) => n,
        Err(e) => panic!("{:?}", e.error),
    };
    let accesses = control.config.contexts.load(Ordering::Relaxed) - before;
    assert!(accesses > 16);
    drop(owner);
    for index in 1..=accesses {
        let mut f = fixture(true);
        let at = f.config.contexts.load(Ordering::Relaxed) + index;
        f.config.fail_context_at.store(at, Ordering::Relaxed);
        let failure = match Native::new(f.inputs.take().unwrap()) {
            Ok(_) => panic!("configuration access {index} accepted"),
            Err(failure) => failure,
        };
        assert_eq!(
            f.config.unmaps.load(Ordering::Relaxed),
            0,
            "configuration access {index}"
        );
        let before = snapshot(&f.state);
        drop(failure);
        assert_eq!(snapshot(&f.state), before, "configuration access {index}");
    }
}

#[test]
fn constructor_unwind_after_private_ring_allocation_keeps_real_cpu_pa_iova_graph() {
    let mut f = fixture(true);
    lock(&f.state).fault = Fault::PanicNewRing;
    assert!(catch_unwind(AssertUnwindSafe(|| Native::new(f.inputs.take().unwrap()))).is_err());
    assert!(lock(&f.state).events.contains(&Event::Bind));
    assert_eq!(lock(&f.state).live.len(), 2);
    assert_eq!(lock(&f.state).page_drops, 0);
    assert_eq!(f.config.unmaps.load(Ordering::Relaxed), 0);
}
#[test]
fn payload_and_detach_unwind_never_reenter_service_or_retirement_after_catch() {
    for fault in [Fault::PanicPayload, Fault::PanicDetach] {
        let mut f = fixture(true);
        let mut native = match Native::new(f.inputs.take().unwrap()) {
            Ok(n) => n,
            Err(e) => panic!("{:?}", e.error),
        };
        lock(&f.state).fault = fault;
        assert!(catch_unwind(AssertUnwindSafe(|| native.close())).is_err());
        assert_eq!(f.config.unmaps.load(Ordering::Relaxed), 0);
        assert_eq!(
            lock(&f.state).page_drops,
            if fault == Fault::PanicPayload { 0 } else { 2 }
        );
        let before = snapshot(&f.state);
        assert_eq!(native.close(), Err(RetirementError::Terminal));
        assert_eq!(
            native.discover_and_setup().err(),
            Some(RetirementError::Terminal)
        );
        drop(native);
        assert_eq!(snapshot(&f.state), before);
    }
}

#[test]
fn late_minimum_failure_cannot_return_active_host_or_retry_close() {
    let mut f = fixture(true);
    let mut native = match Native::new(f.inputs.take().unwrap()) {
        Ok(native) => native,
        Err(failure) => panic!("{:?}", failure.error),
    };
    lock(&f.state).fault = Fault::Minimum;
    let before = snapshot(&f.state);
    let expected = Error::Controller(audio::Error::MinimumDelay(
        crate::bus::pci::power::Error::Clock,
    ));
    assert_eq!(native.discover_and_setup().err(), Some(expected));
    assert_eq!(native.close(), Err(expected));
    assert_eq!(snapshot(&f.state), before);
    core::mem::forget(native);
}
