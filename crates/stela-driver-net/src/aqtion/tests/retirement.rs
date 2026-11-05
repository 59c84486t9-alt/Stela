// SPDX-License-Identifier: GPL-2.0-only
//! Mapping-prefix retirement, never a caller-supplied stopped flag.
use super::*;
#[test]
fn every_unmap_failure_permanently_fences_rebuild_and_retries_original_retirement() {
    if crate::test_process::isolate_model() {
        return;
    }
    for device in [0x07b1, 0x04c0] {
        for failed in 1..=4 {
            let (mut owner, peer, domain, dropped) = setup(device);
            let pm = peer.native_pm.borrow().as_ref().unwrap().clone();
            owner.start().unwrap();
            if peer.profile.generation == Generation::Atlantic {
                peer.set(0x370, 0x100);
            } else {
                peer.set(0x13014, 0x830);
            }
            peer.tx_delay.set(true);
            domain.defer_writebacks.store(true, Ordering::Relaxed);
            owner.transmit(&[0x39; 60]).unwrap();
            assert_eq!(
                peer.pending_tx.get(),
                Some(1),
                "real submitted TX remains unfetched"
            );
            // Exercise a distinct posted DMA write as well as the
            // pending fetch. A held TX doorbell alone has not issued DMA.
            peer.receive(&[0x47; 60], 0, 3, 60);
            assert_ne!(domain.pending_dma.load(Ordering::Relaxed), 0);
            assert!(!domain.posted.lock().unwrap().is_empty());
            domain.fail_unmap_at.store(failed, Ordering::Relaxed);
            assert_eq!(
                owner.retire(),
                Err(Error::Dma(DmaError::InvalidationFailed))
            );
            assert_eq!(domain.unmap_calls.load(Ordering::Relaxed), failed);
            assert_eq!(domain.maps.lock().unwrap().len(), 5 - failed);
            assert_eq!(domain.pending_dma.load(Ordering::Relaxed), 0);
            assert!(domain.posted.lock().unwrap().is_empty());
            assert_eq!(domain.engines.load(Ordering::Relaxed), 0);
            assert_eq!(pm.command() & 4, 0);
            assert_eq!(owner.state(), State::Stopped);
            assert_eq!(dropped.load(Ordering::Relaxed), 0);
            let registers = (peer.reads.borrow().len(), peer.writes.borrow().len());
            let accesses = pm.accesses.lock().unwrap().len();
            let visibility = domain.visibility.lock().unwrap().len();
            assert_eq!(owner.restart(), Err(Error::Stopped));
            assert_eq!(
                (peer.reads.borrow().len(), peer.writes.borrow().len()),
                registers
            );
            assert_eq!(pm.accesses.lock().unwrap().len(), accesses);
            assert_eq!(domain.visibility.lock().unwrap().len(), visibility);
            assert_eq!(domain.engine_epoch.load(Ordering::Relaxed), 1);
            assert!(owner.transmit(&[0x51; 60]).is_err());
            domain.fail_unmap_at.store(0, Ordering::Relaxed);
            owner.retire().unwrap();
            assert!(domain.maps.lock().unwrap().is_empty());
            assert!(owner.memory.is_none());
            assert_eq!(domain.unmap_calls.load(Ordering::Relaxed), 5);
            assert_eq!(dropped.load(Ordering::Relaxed), 4);
            let accesses = pm.accesses.lock().unwrap().len();
            assert_eq!(owner.restart(), Err(Error::Stopped));
            assert_eq!(owner.resume_owned(), Err(Error::Stopped));
            assert_eq!(pm.accesses.lock().unwrap().len(), accesses);
        }
    }
}
#[test]
fn retiring_suspended_owner_refuses_pm_resume_before_configuration_or_mmio() {
    if crate::test_process::isolate_model() {
        return;
    }
    for device in [0x07b1, 0x04c0] {
        let (mut owner, peer, domain, dropped) = setup(device);
        let pm = peer.native_pm.borrow().as_ref().unwrap().clone();
        owner.start().unwrap();
        owner.suspend().unwrap();
        domain.fail_unmap_at.store(2, Ordering::Relaxed);
        assert_eq!(
            owner.retire(),
            Err(Error::Dma(DmaError::InvalidationFailed))
        );
        assert_eq!(domain.maps.lock().unwrap().len(), 3);
        assert_eq!(pm.actual_state.load(Ordering::Relaxed), 3);
        let registers = (peer.reads.borrow().len(), peer.writes.borrow().len());
        let accesses = pm.accesses.lock().unwrap().len();
        assert_eq!(owner.resume_owned(), Err(Error::Stopped));
        assert_eq!(
            (peer.reads.borrow().len(), peer.writes.borrow().len()),
            registers
        );
        assert_eq!(pm.accesses.lock().unwrap().len(), accesses);
        assert_eq!(pm.actual_state.load(Ordering::Relaxed), 3);
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        domain.fail_unmap_at.store(0, Ordering::Relaxed);
        owner.retire().unwrap();
        assert!(domain.maps.lock().unwrap().is_empty());
        assert_eq!(dropped.load(Ordering::Relaxed), 4);
    }
}
