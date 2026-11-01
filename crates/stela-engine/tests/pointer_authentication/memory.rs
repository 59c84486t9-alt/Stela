//! Authenticated loads and their fault stops.
#![cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]

use anyhow::Result;
use std::{
    alloc::{Layout, alloc_zeroed, dealloc},
    ptr::NonNull,
    sync::Arc,
};
use stela_compiler::{
    GuestAddress, GuestState, TargetCpu,
    block::{BlockProfile, Features},
    context::memory::MemoryStatus,
};
use {
    stela_contracts::pauth::Key, stela_engine::blocks::BlockRuntime,
    stela_engine::blocks::StopReason, stela_engine::blocks::ThreadState,
    stela_engine::memory::backing::AccessPermissions, stela_engine::memory::backing::MemoryBacking,
    stela_engine::memory::backing::MemoryView, stela_engine::memory::domain::MappingAttributes,
    stela_engine::memory::domain::MemoryDomain, stela_engine::memory::domain::MemorySystem,
    stela_engine::memory::policy::LowerAddressProfile,
    stela_engine::memory::policy::MemoryControls, stela_engine::memory::policy::TagCheckFaultMode,
    stela_engine::memory::tags::AllocationTag, stela_engine::memory::tags::TAG_GRANULE_BYTES,
    stela_engine::pauth::Context, stela_engine::pauth::Keys, stela_engine::pauth::Version,
};

const ADDRESS_SPACE: u64 = 73;
const BASE: GuestAddress = GuestAddress(0x1000);
const GUEST_RAM: u64 = 0x4000;
const RAM_BYTES: usize = 64;
const RAM_ALIGNMENT: usize = 16;
const TAG: u8 = 7;
const OTHER_TAG: u8 = TAG + 1;
const VALUE: u64 = 0x8877_6655_4433_2211;
const KEY: [u64; 2] = [0x1122_3344_5566_7788, 0x99aa_bbcc_ddee_ff00];
const PROFILE: BlockProfile = BlockProfile::new(Features::POINTER_AUTHENTICATION);
const LDRAA_X1_X0: u32 = 0xf820_0401;
const LDRAA_X1_SP: u32 = 0xf820_07e1;
const LDRAA_X1_SP_WRITEBACK: u32 = 0xf820_0fe1;
const LDRAA_X0_X0_WRITEBACK: u32 = 0xf820_0c00;
const RIGHTS: AccessPermissions = AccessPermissions {
    readable: true,
    writable: true,
    executable: false,
};
const READ_ONLY: AccessPermissions = AccessPermissions {
    writable: false,
    ..RIGHTS
};

struct Storage {
    pointer: NonNull<u8>,
    layout: Layout,
}

// SAFETY: this owner pins raw RAM and exposes no byte references; native access
// and publication use the single machine memory domain.
unsafe impl Send for Storage {}
// SAFETY: sharing the lifetime owner does not read or write its native allocation.
unsafe impl Sync for Storage {}

impl Drop for Storage {
    fn drop(&mut self) {
        // SAFETY: the allocation and its layout are owned here.
        unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
    }
}

fn memory(allocation_tag: u8, mapped_bytes: usize, readable: bool) -> Result<Arc<MemoryDomain>> {
    let system = MemorySystem::new(RAM_ALIGNMENT as u64, 4).unwrap();
    let layout = Layout::from_size_align(RAM_BYTES, RAM_ALIGNMENT)?;
    // SAFETY: valid nonempty layout; owner keeps allocation until last backing.
    let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
    let storage = Arc::new(Storage { pointer, layout });
    // SAFETY: raw storage is pinned, coherent and disjoint from Rust byte references.
    let backing = unsafe { MemoryBacking::new(pointer, RAM_BYTES, RIGHTS, storage) }.unwrap();
    let mut initial = [0; RAM_BYTES];
    initial[..size_of::<u64>()].copy_from_slice(&VALUE.to_le_bytes());
    // SAFETY: private bytes and live writable RAM, before translated execution.
    unsafe { system.publish(&backing, 0, &initial) }.unwrap();
    for offset in (0..RAM_BYTES).step_by(TAG_GRANULE_BYTES) {
        backing
            .allocation_tags()
            .write(offset, AllocationTag::new(allocation_tag).unwrap())
            .unwrap();
    }
    let view = MemoryView::new(
        Arc::clone(&backing),
        GUEST_RAM,
        0,
        mapped_bytes,
        AccessPermissions {
            readable,
            ..READ_ONLY
        },
    )
    .unwrap();
    // Address-space binding constructor is finalized by the memory-domain owner.
    Ok(MemoryDomain::new_for_address_space(
        ADDRESS_SPACE,
        system,
        vec![(
            view,
            MappingAttributes {
                tagged: true,
                shareable: true,
            },
        )],
        TargetCpu::Baseline,
    )
    .unwrap())
}

fn controls() -> MemoryControls {
    MemoryControls::new(
        LowerAddressProfile::new(47, true).unwrap(),
        false,
        true,
        false,
        TagCheckFaultMode::Synchronous,
        false,
    )
}

fn context(version: Version) -> Context {
    Context::new_with_version(ADDRESS_SPACE, Keys::from_words(KEY, KEY, KEY, KEY), version)
}

fn tagged(address: u64) -> u64 {
    AllocationTag::new(TAG).unwrap().apply_to_address(address)
}

fn runtime(cache: &std::path::Path, word: u32) -> Result<BlockRuntime> {
    let mut runtime =
        BlockRuntime::new_for_target(ADDRESS_SPACE, cache.into(), PROFILE, TargetCpu::Baseline);
    runtime.register_code(BASE, word.to_le_bytes().to_vec())?;
    Ok(runtime)
}

fn state() -> ThreadState {
    ThreadState {
        pc: BASE,
        registers: GuestState {
            x: std::array::from_fn(|index| 0x0123_4567_89ab_cdefu64.rotate_left(index as u32)),
            sp: 0x2000,
            nzcv: 0xa000_0000,
            exclusive_bytes: 0xa5c3_9e71,
            exclusive_address: 0,
            exclusive_value: 0,
            daif: 0,
            pending: 0,
            v: std::array::from_fn(|index| [index as u64, !(index as u64)]),
            fpcr: 0x03c0_0000,
            fpsr: 0x0800_001f,
            ..Default::default()
        },
    }
}

#[test]
fn sp_offset_skips_tag_check_but_sp_writeback_checks_before_any_commit() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let domain = memory(OTHER_TAG, RAM_BYTES, true)?;
    let mut reader = domain.thread(controls());
    let context = context(Version::Classic);
    for (word, writeback) in [(LDRAA_X1_SP, false), (LDRAA_X1_SP_WRITEBACK, true)] {
        let mut runtime = runtime(cache.path(), word)?;
        let mut state = state();
        state.registers.sp = context.sign(Key::Da, tagged(GUEST_RAM), 0)?;
        let mut expected = state.registers.clone();
        // SAFETY: only the LDRA helper accesses memory, through the bound owned
        // RAM.
        let outcome = unsafe {
            runtime.run_with_pauth_memory(
                &mut state,
                None,
                1,
                &context,
                &mut reader,
                stela_engine::pauth::memory::Controls {
                    check_sp_alignment: true,
                    privileged: false,
                },
            )?
        };
        if writeback {
            assert!(
                matches!(outcome.reason, StopReason::PointerAuthenticationMemoryFault { fault, .. } if fault.status == MemoryStatus::TagCheck && fault.address == tagged(GUEST_RAM) && fault.pc == BASE.0)
            );
            assert_eq!(state.pc, BASE);
        } else {
            expected.x[1] = VALUE;
            assert_eq!(outcome.reason, StopReason::BudgetExhausted);
            assert_eq!(state.pc, GuestAddress(BASE.0 + 4));
        }
        assert_eq!(state.registers, expected);
    }
    Ok(())
}

#[test]
fn overlap_undefined_precedes_missing_data_key() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime = runtime(cache.path(), LDRAA_X0_X0_WRITEBACK)?;
    let mut state = state();
    let expected = state.registers.clone();
    let context = Context::new(ADDRESS_SPACE, Keys::from_ib_words(KEY[0], KEY[1]));
    // SAFETY: constrained-overlap helper stops before translation or data access.
    let outcome = unsafe { runtime.run_with_pauth(&mut state, None, 1, &context)? };
    assert!(matches!(
        outcome.reason,
        StopReason::PointerAuthenticationLoadUndefined { .. }
    ));
    assert_eq!(state.registers, expected);
    assert_eq!(state.pc, BASE);
    Ok(())
}

#[test]
fn fpaccombine_failure_precedes_misaligned_sp_and_unmapped_read() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime = runtime(cache.path(), LDRAA_X1_SP_WRITEBACK)?;
    let domain = memory(TAG, RAM_BYTES, true)?;
    let mut reader = domain.thread(controls());
    let context = context(Version::FaultingCombined);
    let mut state = state();
    state.registers.sp =
        context.sign(Key::Da, tagged(GUEST_RAM + RAM_BYTES as u64 + 1), 0)? ^ (1 << 47);
    let expected = state.registers.clone();
    // SAFETY: faulting helper authenticates before any RAM access.
    let outcome = unsafe {
        runtime.run_with_pauth_memory(
            &mut state,
            None,
            1,
            &context,
            &mut reader,
            stela_engine::pauth::memory::Controls {
                check_sp_alignment: true,
                privileged: false,
            },
        )?
    };
    assert!(matches!(
        outcome.reason,
        StopReason::PointerAuthenticationFailure { code: 2, .. }
    ));
    assert_eq!(state.registers, expected);
    assert_eq!(state.pc, BASE);
    Ok(())
}

#[test]
fn complete_read_fault_preserves_destination_and_authenticated_base() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let context = context(Version::Classic);
    for (mapped_bytes, readable, expected_status) in [
        (4, true, MemoryStatus::Translation),
        (RAM_BYTES, false, MemoryStatus::Permission),
    ] {
        let domain = memory(TAG, mapped_bytes, readable)?;
        let mut reader = domain.thread(controls());
        let mut runtime = runtime(cache.path(), LDRAA_X1_X0)?;
        let mut state = state();
        state.registers.x[0] = context.sign(Key::Da, tagged(GUEST_RAM), 0)?;
        let expected = state.registers.clone();
        // SAFETY: the checked reader validates each span in owned RAM.
        let outcome = unsafe {
            runtime.run_with_pauth_memory(
                &mut state,
                None,
                1,
                &context,
                &mut reader,
                stela_engine::pauth::memory::Controls {
                    check_sp_alignment: true,
                    privileged: false,
                },
            )?
        };
        assert!(
            matches!(outcome.reason, StopReason::PointerAuthenticationMemoryFault { fault, .. } if fault.status == expected_status && fault.pc == BASE.0)
        );
        assert_eq!(state.registers, expected);
        assert_eq!(state.pc, BASE);
    }
    Ok(())
}

#[test]
fn effective_cpu_alignment_control_selects_sp_fault_or_complete_read() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let domain = memory(TAG, RAM_BYTES, true)?;
    let mut reader = domain.thread(controls());
    let context = context(Version::Classic);
    for check_sp_alignment in [true, false] {
        let mut runtime = runtime(cache.path(), LDRAA_X1_SP)?;
        let mut state = state();
        // Eight-byte alignment satisfies the baseline reader, but SP still
        // violates SA0.
        state.registers.sp =
            context.sign(Key::Da, tagged(GUEST_RAM + size_of::<u64>() as u64), 0)?;
        let mut expected = state.registers.clone();
        // SAFETY: fixed EL0 controls and a reader for the same address space.
        let outcome = unsafe {
            runtime.run_with_pauth_memory(
                &mut state,
                None,
                1,
                &context,
                &mut reader,
                stela_engine::pauth::memory::Controls {
                    check_sp_alignment,
                    privileged: false,
                },
            )?
        };
        if check_sp_alignment {
            assert!(matches!(
                outcome.reason,
                StopReason::PointerAuthenticationStackAlignment { stack_pointer, .. }
                    if stack_pointer == expected.sp
            ));
            assert_eq!(state.pc, BASE);
        } else {
            // The second eight-byte slot was initialized to zero.
            expected.x[1] = 0;
            assert_eq!(outcome.reason, StopReason::BudgetExhausted);
            assert_eq!(state.pc, GuestAddress(BASE.0 + 4));
        }
        assert_eq!(state.registers, expected);
    }
    Ok(())
}

#[test]
fn mismatched_memory_privilege_is_rejected_before_dispatch() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let domain = memory(TAG, RAM_BYTES, true)?;
    let mut reader = domain.thread(controls());
    let context = context(Version::Classic);
    let mut runtime = runtime(cache.path(), LDRAA_X1_X0)?;
    let mut state = state();
    let expected = state.registers.clone();
    // SAFETY: the mismatched profile must fail entry before any native code or
    // data callback runs.
    let result = unsafe {
        runtime.run_with_pauth_memory(
            &mut state,
            None,
            1,
            &context,
            &mut reader,
            stela_engine::pauth::memory::Controls {
                check_sp_alignment: true,
                privileged: true,
            },
        )
    };
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("privilege profile unavailable")
    );
    assert_eq!(state.registers, expected);
    assert_eq!(state.pc, BASE);
    assert!(runtime.loaded_manifest(BASE).is_none());
    Ok(())
}
