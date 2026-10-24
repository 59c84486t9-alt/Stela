use super::super::{
    Controls, Failure, MemoryStatus, Policy, flags,
    tests::{fixture, ordinary_transfer},
};
use super::*;
use crate::{
    machine::system::Register,
    memory::{RegisteredSystemRam, domain::MemoryThread},
};
use alloc::sync::Arc;

const VA: u64 = 0x4000;
const DATA: u64 = 0x14000;
const OTHER: u64 = 0x15000;
const LEAF: u64 = 0x13020;
const DESCRIPTOR: u64 = DATA | 3 | (1 << 10) | (3 << 8);

fn thread() -> (MemoryThread<Policy>, Arc<RegisteredSystemRam>) {
    let (cpu, profile, missing, ram) = fixture();
    let controls = Controls::capture(&cpu, profile.name, &missing).unwrap();
    let mut policy = Policy::new(controls.clone(), Arc::clone(&ram));
    policy.refresh(controls, 1);
    (ram.domain().thread(policy), ram)
}
fn publish(ram: &RegisteredSystemRam, physical: u64, bytes: &[u8]) {
    // SAFETY: the fixture retains actual canonical storage; no native entry
    // is live between these callback invocations. Use its canonical writer.
    unsafe { ram.publish_physical(physical, bytes) }.unwrap();
}
fn read(thread: &mut MemoryThread<Policy>) -> (MemoryStatus, u64) {
    let mut bytes = [0xa5; 8];
    let (status, _, _) = ordinary_transfer(thread, VA, &mut bytes, 0);
    (status, u64::from_le_bytes(bytes))
}
fn refresh(thread: &mut MemoryThread<Policy>, generation: u64) {
    let controls = thread.policy_mut().controls.clone();
    thread.policy_mut().refresh(controls, generation);
}

#[test]
fn authentic_tlb_retains_translation_until_epoch_but_always_reads_current_bytes() {
    let (mut thread, ram) = thread();
    publish(&ram, DATA, &7u64.to_le_bytes());
    publish(&ram, OTHER, &9u64.to_le_bytes());
    assert_eq!(read(&mut thread), (MemoryStatus::Success, 7));
    #[cfg(feature = "native-profile")]
    let before = thread.policy_mut().data_tlb_statistics();
    publish(&ram, DATA, &8u64.to_le_bytes());
    publish(&ram, LEAF, &(DESCRIPTOR + PAGE_BYTES).to_le_bytes());
    refresh(&mut thread, 1);
    assert_eq!(read(&mut thread), (MemoryStatus::Success, 8));
    #[cfg(feature = "native-profile")]
    {
        let after = thread.policy_mut().data_tlb_statistics();
        assert_eq!(after.hits, before.hits + 1);
        assert_eq!(after.descriptor_reads, before.descriptor_reads);
        assert_eq!(after.walks, before.walks);
        assert_eq!(after.cells, CELLS);
    }
    refresh(&mut thread, 2);
    assert_eq!(read(&mut thread), (MemoryStatus::Success, 9));
    // A previously valid TLB entry can likewise outlive a PTE becoming invalid.
    publish(&ram, LEAF, &0u64.to_le_bytes());
    assert_eq!(read(&mut thread), (MemoryStatus::Success, 9));
    refresh(&mut thread, 3);
    assert_eq!(read(&mut thread).0, MemoryStatus::Translation);
    // Faults never fill a negative entry: invalid -> valid needs no invalidation.
    publish(&ram, LEAF, &DESCRIPTOR.to_le_bytes());
    assert_eq!(read(&mut thread), (MemoryStatus::Success, 8));
}

#[test]
fn cached_readonly_rights_do_not_admit_stores_and_faults_keep_original_source() {
    let (mut thread, ram) = thread();
    publish(&ram, LEAF, &(DESCRIPTOR | (1 << 7)).to_le_bytes());
    publish(&ram, DATA, &7u64.to_le_bytes());
    assert_eq!(read(&mut thread), (MemoryStatus::Success, 7));
    let mut value = 9u64.to_le_bytes();
    assert_eq!(
        ordinary_transfer(&mut thread, VA, &mut value, flags::WRITE),
        (MemoryStatus::Permission, 0, VA)
    );
    assert!(matches!(
        thread.policy_mut().failure,
        Some(Failure::Fault {
            address: VA,
            fault: mmu::Fault {
                kind: mmu::FaultKind::Permission,
                level: 3,
                ..
            },
            ..
        })
    ));
    assert_eq!(read(&mut thread), (MemoryStatus::Success, 7));
    #[cfg(feature = "native-profile")]
    assert_eq!(
        thread.policy_mut().data_tlb_statistics().permission_misses,
        1
    );
}

#[test]
fn context_changes_cannot_revive_old_entries_and_helpers_disable_caching() {
    let (mut thread, ram) = thread();
    publish(&ram, DATA, &7u64.to_le_bytes());
    publish(&ram, OTHER, &9u64.to_le_bytes());
    assert_eq!(read(&mut thread), (MemoryStatus::Success, 7));
    publish(&ram, LEAF, &(DESCRIPTOR + PAGE_BYTES).to_le_bytes());
    let original = thread.policy_mut().controls.clone();
    let mut changed = original.clone();
    changed.requester.guarded = !changed.requester.guarded;
    thread.policy_mut().refresh(changed, 1);
    assert_eq!(read(&mut thread), (MemoryStatus::Success, 9));
    thread.policy_mut().refresh(original.clone(), 1);
    assert_eq!(read(&mut thread), (MemoryStatus::Success, 9));
    publish(&ram, LEAF, &DESCRIPTOR.to_le_bytes());
    thread.policy_mut().reset_controls(original);
    assert_eq!(read(&mut thread), (MemoryStatus::Success, 7));
    publish(&ram, LEAF, &(DESCRIPTOR + PAGE_BYTES).to_le_bytes());
    assert_eq!(read(&mut thread), (MemoryStatus::Success, 9));
}

#[test]
fn cached_page_does_not_authorize_a_later_split_page_or_unaligned_shape() {
    let (mut thread, ram) = thread();
    assert_eq!(read(&mut thread).0, MemoryStatus::Success);
    publish(&ram, DATA + PAGE_BYTES - 4, &[1, 2, 3, 4]);
    let mut bytes = [0xa5; 8];
    assert_eq!(
        ordinary_transfer(&mut thread, VA + PAGE_BYTES - 4, &mut bytes, 0),
        (MemoryStatus::Translation, 4, VA + PAGE_BYTES)
    );
    // Callback staging keeps its reached prefix; the compiler alone controls
    // whether a complete architectural destination may be committed.
    assert_eq!(bytes, [1, 2, 3, 4, 0xa5, 0xa5, 0xa5, 0xa5]);
    let mut controls = thread.policy_mut().controls.clone();
    controls.translation.sctlr |= mmu::alignment::SCTLR_A;
    thread.policy_mut().refresh(controls, 1);
    assert_eq!(
        ordinary_transfer(&mut thread, VA + 1, &mut bytes, 0),
        (MemoryStatus::Alignment, 0, VA + 1)
    );
}

#[test]
fn stage2_combined_entries_keep_real_rights_and_device_alignment_is_never_cached() {
    for device in [false, true] {
        let (mut cpu, profile, missing, ram) = fixture();
        // One level-1 block maps the descriptor IPAs and data IPA identically.
        // 39-bit IPA means one 4-KiB root, placed in the last fixture page.
        let attrs = if device { 0b0110 } else { 0b1111 };
        let block = 1u64 | (1 << 10) | (3 << 6) | (attrs << 2) | (3 << 8);
        publish(&ram, OTHER, &block.to_le_bytes());
        cpu.registers
            .set_raw(Register::HCR_EL2, 0, 1 | if device { 1 << 46 } else { 0 });
        cpu.registers
            .set_raw(Register::VTCR_EL2, 0, 25 | (1 << 6) | (5 << 16) | (1 << 31));
        cpu.registers.set_raw(Register::VTTBR_EL2, 0, OTHER);
        if device {
            cpu.registers.set_raw(Register::MAIR_EL1, 0, 0);
        }
        let controls = Controls::capture(&cpu, profile.name, &missing).unwrap();
        assert!(controls.translation.second_stage.is_some());
        let mut policy = Policy::new(controls.clone(), Arc::clone(&ram));
        policy.refresh(controls, 1);
        let mut thread = ram.domain().thread(policy);
        publish(&ram, DATA, &7u64.to_le_bytes());
        assert_eq!(read(&mut thread), (MemoryStatus::Success, 7));
        assert_eq!(read(&mut thread), (MemoryStatus::Success, 7));
        assert_eq!(
            thread.policy_mut().tlb.cells.iter().flatten().count(),
            usize::from(!device)
        );
        #[cfg(feature = "native-profile")]
        assert_eq!(
            thread.policy_mut().data_tlb_statistics().hits,
            u64::from(!device)
        );
        if device {
            let mut bytes = [0xa5; 8];
            assert_eq!(
                ordinary_transfer(&mut thread, VA + 1, &mut bytes, 0),
                (MemoryStatus::Alignment, 0, VA + 1)
            );
        }
    }
}

#[test]
fn terminal_physical_owner_failure_defeats_a_hot_translation() {
    use crate::memory::{
        backing::AccessKind,
        domain::{DataOperation, DataPolicy, DataRequest},
    };
    let (mut thread, ram) = thread();
    assert_eq!(read(&mut thread).0, MemoryStatus::Success);
    let service = ram.try_service().unwrap().unwrap();
    service.fail();
    drop(service);
    let request = DataRequest {
        address: VA,
        bytes: 8,
        flags: 0,
        pc: Some(0x18000),
        operation: DataOperation::Ordinary,
    };
    assert_eq!(
        thread.policy_mut().translate_part(
            request,
            DataPart {
                address: VA,
                bytes: 8,
                kind: AccessKind::Read
            }
        ),
        Err((MemoryStatus::Domain, VA))
    );
    assert_eq!(
        thread.prepare(Default::default()).err(),
        Some(MemoryStatus::Domain)
    );
}
