//! Actual Provider + canonical Mapping + original native WOPCM RAM model only.
use super::*;
use intel::{firmware, wopcm};

fn catalog_for_device(device: &Device) -> crate::firmware::Catalog {
    let request = device.guc_firmware().unwrap();
    intel::catalog_for(&request, intel::bytes(request.wanted()))
}
pub(super) fn owned_wopcm_contract(authority: &Authority, platform: &Platform, next: &AtomicU64) {
    // Known missing older HuC prerequisites must not become zero-byte success.
    let (input, counts) = owner(next.fetch_add(BYTES as u64, Ordering::SeqCst), 0x9a49);
    let mut device = Device::open(authority, input, true).unwrap();
    let catalog = catalog_for_device(&device);
    assert!(matches!(
        device.prepare_wopcm(&catalog),
        Err(wopcm::Error::Device(Error::Awake))
    ));
    device.wake().unwrap();
    assert!(matches!(
        device.prepare_wopcm(&catalog),
        Err(wopcm::Error::Native {
            status: -95,
            writes: 0,
            ..
        })
    ));
    assert_eq!(counts.wopcm_reads.load(Ordering::SeqCst), 0);
    assert_eq!(counts.wopcm_writes.load(Ordering::SeqCst), 0);
    device.sleep().unwrap();
    device.retire().unwrap();

    // Actual owned BMG row with explicit synthetic runtime GMDID input; exact
    // real Provider target and original GuC image, not a production fact guess.
    for (device_id, graphics, name, total, guc_size) in [
        (0xe202, 2001, "xe/bmg_guc_70.bin", 0x800000, 0x7f3000),
        (0x56a0, 1255, "i915/dg2_guc_70.bin", 0x400000, 0x3f3000),
        (0x46d0, 1200, "i915/tgl_guc_70.bin", 0x200000, 0x1f3000),
    ] {
        for locked in [false, true] {
            let (offset, size) = if locked { (0x4001, 0x100001) } else { (0, 0) };
            let (input, counts) = owner_with_registers(
                next.fetch_add(BYTES as u64, Ordering::SeqCst),
                device_id,
                offset,
                size,
            );
            let mut device = Device::open(authority, input, true).unwrap();
            let catalog = catalog_for_device(&device);
            device.wake().unwrap();
            let empty = crate::firmware::Catalog::from_handoff(vec![]).unwrap();
            assert!(matches!(
                device.prepare_wopcm(&empty),
                Err(wopcm::Error::Firmware(firmware::Error::Provider(_)))
            ));
            assert_eq!(counts.wopcm_reads.load(Ordering::SeqCst), 0);
            // All real source/image/owner storage is ready BEFORE register effects.
            // An unexpected allocation fails for real; no production fault hook.
            allocation_failure::arm(0);
            {
                let prepared = device.prepare_wopcm(&catalog).unwrap();
                let no_allocation = allocation_failure::disarm();
                assert_eq!(no_allocation.attempts, 0);
                assert_eq!(prepared.image().name(), name);
                assert_eq!(prepared.identity().device, device_id);
                assert_eq!(prepared.facts().graphics_verx100, graphics);
                assert_eq!(prepared.metadata().upload_bytes, 144);
                assert_eq!(
                    prepared.layout().total_bytes,
                    if locked { 0x800000 } else { total }
                );
                assert_eq!(prepared.layout().guc_base, 0x4000);
                assert_eq!(
                    prepared.layout().guc_bytes,
                    if locked { 0x100000 } else { guc_size }
                );
                assert_eq!(prepared.writes(), if locked { 0 } else { 2 });
                assert_eq!(
                    prepared.observed_registers(),
                    if locked {
                        (offset, size)
                    } else {
                        (0x4001, guc_size | 1)
                    }
                );
                assert_ne!(prepared.diagnostics(), 0);
            } // no implicit sleep/reset/drain or lock rollback
            assert_eq!(counts.sleep_writes.load(Ordering::SeqCst), 0);
            let reads = counts.wopcm_reads.load(Ordering::SeqCst);
            assert!(matches!(
                device.prepare_wopcm(&catalog),
                Err(wopcm::Error::Native {
                    status: -114,
                    writes: 0,
                    ..
                })
            ));
            assert_eq!(counts.wopcm_reads.load(Ordering::SeqCst), reads);
            device.sleep().unwrap();
            device.retire().unwrap();
            assert_eq!(counts.finished.load(Ordering::SeqCst), 1);
            assert_eq!(counts.dropped.load(Ordering::SeqCst), 1);
        }
    }
    for device_id in [0xe202, 0x56a0, 0x46d0] {
        for fail_at in [1, 2] {
            let (input, counts) = owner(next.fetch_add(BYTES as u64, Ordering::SeqCst), device_id);
            let mut device = Device::open(authority, input, true).unwrap();
            let catalog = catalog_for_device(&device);
            device.wake().unwrap();
            counts.wopcm_fail_at.store(fail_at, Ordering::SeqCst);
            let quarantined = authority.status().unwrap().quarantined;
            let calls = platform.calls.lock().unwrap().len();
            allocation_failure::arm(0);
            let result = device.prepare_wopcm(&catalog);
            assert!(
                matches!(result, Err(wopcm::Error::Native { status: -22, writes, .. }) if writes == fail_at as u32)
            );
            let checks = counts.context_checks.load(Ordering::SeqCst);
            let reads = counts.wopcm_reads.load(Ordering::SeqCst);
            assert_eq!(device.facts(), Err(Error::Closing));
            assert!(matches!(
                device.guc_firmware(),
                Err(firmware::Error::Device(Error::Closing))
            ));
            assert!(matches!(
                device.prepare_wopcm(&catalog),
                Err(wopcm::Error::Device(Error::Closing))
            ));
            assert_eq!(device.wake(), Err(Error::Closing));
            assert_eq!(device.sleep(), Err(Error::Closing));
            assert_eq!(device.retire(), Err(Error::Awake));
            drop(device); // canonical quarantine + retained exact context/state
            assert_eq!(counts.context_checks.load(Ordering::SeqCst), checks);
            assert_eq!(counts.wopcm_reads.load(Ordering::SeqCst), reads);
            assert_eq!(counts.sleep_writes.load(Ordering::SeqCst), 0);
            assert_eq!(counts.finished.load(Ordering::SeqCst), 0);
            assert_eq!(counts.dropped.load(Ordering::SeqCst), 0);
            assert_eq!(counts.reservation_dropped.load(Ordering::SeqCst), 0);
            // Prove the actual allocator was still armed across failure+Drop.
            let layout = Layout::from_size_align(8, 8).unwrap();
            // SAFETY: intentional allocation-null probe, null is never dereferenced.
            let pointer = unsafe { std::alloc::alloc(layout) };
            let observed = allocation_failure::disarm();
            assert!(pointer.is_null() && observed.failed && observed.attempts == 1);
            assert_eq!(
                platform.calls.lock().unwrap().len(),
                calls,
                "no uncertain unmap attempt"
            );
            assert_eq!(authority.status().unwrap().quarantined, quarantined + 1);
        }
    }
}
