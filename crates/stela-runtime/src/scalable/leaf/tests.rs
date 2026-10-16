use super::*;
use crate::memory::{
    backing::{AccessPermissions, MemoryBacking, MemoryView},
    domain::{MappingAttributes, MemoryDomain, MemorySystem},
    policy::{LowerAddressProfile, MemoryControls, TagCheckFaultMode},
};
use std::{
    alloc::{Layout, alloc_zeroed, dealloc},
    ptr::NonNull,
    sync::Arc,
};
use stela_compiler::{
    aarch64::scalable::{ScalableMode, VectorLength},
    context::{ScalableStateView, memory::MemoryImplementationProfile},
};

const RET_X30: u32 = 0xd65f_03c0;
const NOP: u32 = 0xd503_201f;
const MOV_X0_SEVEN: u32 = 0xd280_00e0;
// MOVZ XZR, #2 stages a Permission-shaped value in host RAX without changing
// any guest register. RET leaves that host return register unconstrained.
const MOV_XZR_PERMISSION: u32 = 0xd280_005f;
const LD1B_Z1_P0_X5: u32 = 0xa400_a0a1;
const LD1B_Z1_P0_SP: u32 = 0xa400_a3e1;
const LD1D_Z1_P0_X5: u32 = 0xa5e0_a0a1;
const GUEST_BASE: u64 = 0x1000;
const RAM_BASE: u64 = 0x1400_74000;
const RAM_BYTES: usize = 8192;
const GRANULE_BYTES: usize = 16;
const DESTINATION: u8 = 1;
const BASE_REGISTER: usize = 5;
const DECLARED_ADDRESS_BITS: u8 = 39;
const PERMISSIONS: AccessPermissions = AccessPermissions {
    readable: true,
    writable: true,
    executable: false,
};

struct Storage {
    pointer: NonNull<u8>,
    layout: Layout,
}
// SAFETY: bytes have no Rust references; tests access them only outside each
// serialized domain invocation, and the Arc owns their complete live extent.
unsafe impl Send for Storage {}
// SAFETY: sharing retains only raw storage metadata; no method accesses bytes
// concurrently with native execution or another domain writer.
unsafe impl Sync for Storage {}
impl Storage {
    fn new() -> Arc<Self> {
        let layout = Layout::from_size_align(RAM_BYTES, GRANULE_BYTES).unwrap();
        // SAFETY: valid initialized allocation; the matching owner deallocates it.
        let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
        for offset in 0..RAM_BYTES {
            // SAFETY: fresh exclusive initialized storage before publication.
            unsafe {
                pointer
                    .as_ptr()
                    .add(offset)
                    .write((offset & u8::MAX as usize) as u8);
            }
        }
        Arc::new(Self { pointer, layout })
    }

    fn bytes(&self) -> Vec<u8> {
        (0..RAM_BYTES)
            .map(|offset| {
                // SAFETY: every test calls this outside synchronous execution, with
                // no competing byte access; storage remains live through this Arc.
                unsafe { self.pointer.as_ptr().add(offset).read() }
            })
            .collect()
    }
}
impl Drop for Storage {
    fn drop(&mut self) {
        // SAFETY: the final Arc releases the exact original allocation/layout.
        unsafe {
            dealloc(self.pointer.as_ptr(), self.layout);
        }
    }
}

fn profile() -> ScalableProfile {
    ScalableProfile::new(
        VectorLength::from_bytes(GRANULE_BYTES).unwrap(),
        ScalableMode::new(true, false),
    )
}
fn words(input: &[u32]) -> Vec<u8> {
    input.iter().flat_map(|word| word.to_le_bytes()).collect()
}
fn unbound_controls(asynchronous: bool) -> MemoryControls {
    MemoryControls::new(
        LowerAddressProfile::new(DECLARED_ADDRESS_BITS, asynchronous).unwrap(),
        false,
        asynchronous,
        false,
        if asynchronous {
            TagCheckFaultMode::Asynchronous
        } else {
            TagCheckFaultMode::Ignore
        },
        false,
    )
}
fn raw_controls(asynchronous: bool) -> MemoryControls {
    unbound_controls(asynchronous).with_effective_sp_alignment(true)
}
fn controls(asynchronous: bool) -> MemoryControls {
    raw_controls(asynchronous)
        .with_implementation_profile(MemoryImplementationProfile::ScalableTagChecks)
}
fn owner(
    asynchronous: bool,
    split_permission: bool,
) -> (Arc<Storage>, MemoryThread<MemoryControls>) {
    let storage = Storage::new();
    // SAFETY: raw allocation remains owned, disjoint and RW; no byte references
    // exist, and all published accesses use this one serialized domain.
    let backing = unsafe {
        MemoryBacking::new(
            storage.pointer,
            RAM_BYTES,
            PERMISSIONS,
            Arc::clone(&storage),
        )
    }
    .unwrap();
    let views = if split_permission {
        vec![
            MemoryView::new(Arc::clone(&backing), RAM_BASE, 0, 1, PERMISSIONS).unwrap(),
            MemoryView::new(
                backing,
                RAM_BASE + 1,
                1,
                RAM_BYTES - 1,
                AccessPermissions {
                    readable: false,
                    writable: false,
                    executable: false,
                },
            )
            .unwrap(),
        ]
    } else {
        vec![MemoryView::new(backing, RAM_BASE, 0, RAM_BYTES, PERMISSIONS).unwrap()]
    };
    let views = views
        .into_iter()
        .map(|view| {
            (
                view,
                MappingAttributes {
                    tagged: false,
                    shareable: true,
                },
            )
        })
        .collect();
    let domain = MemoryDomain::new(
        MemorySystem::new(GRANULE_BYTES as u64, GRANULE_BYTES).unwrap(),
        views,
        TargetCpu::Baseline,
    )
    .unwrap();
    (storage, domain.thread(controls(asynchronous)))
}
fn state() -> (GuestState, ScalableState) {
    let mut registers = GuestState::default();
    let mut scalable = ScalableState::new(profile().vector_length(), true);
    scalable
        .apply_mode(&mut registers, profile().mode())
        .unwrap();
    registers.x[BASE_REGISTER] = RAM_BASE;
    scalable
        .write_z(&mut registers, DESTINATION, &[0xa5; GRANULE_BYTES])
        .unwrap();
    scalable.write_predicate(0, &[3, 0]).unwrap();
    (registers, scalable)
}
fn context() -> ExecutionContext {
    ExecutionContext {
        memory: std::ptr::dangling_mut::<u8>().cast(),
        scalable: std::ptr::dangling_mut::<ScalableStateView>(),
        system: std::ptr::dangling_mut::<u8>().cast(),
        ..ExecutionContext::default()
    }
}

#[test]
fn source_and_requirements_are_owned_not_caller_supplied() {
    let mut input = words(&[LD1B_Z1_P0_X5, RET_X30]);
    let leaf = PreparedScalableLeaf::prepare(
        &input,
        GuestAddress(GUEST_BASE),
        profile(),
        TargetCpu::Baseline,
    )
    .unwrap();
    let original = input.clone();
    input.fill(0);
    assert_eq!(leaf.source(), original);
    assert_eq!(leaf.identity().source_sha256, sha256(&original));
    assert_eq!(leaf.identity().abi, CONTEXT_LEAF_ABI);
    assert_eq!(
        leaf.identity().memory_implementation_profile,
        Some(MEMORY_IMPLEMENTATION_PROFILE_ID)
    );
    assert_eq!(leaf.identity().memory_requirements.required_host_caps, 0);
    assert_eq!(leaf.source_map()[0].0, GuestAddress(GUEST_BASE));
    assert!(leaf.native_bytes() > extended::CONTEXT_WRAPPER_BYTES);
}

#[test]
fn pure_ret_ignores_unconstrained_rax_and_restores_context() {
    let leaf = PreparedScalableLeaf::prepare(
        &words(&[NOP, MOV_XZR_PERMISSION, RET_X30]),
        GuestAddress(GUEST_BASE),
        profile(),
        TargetCpu::Baseline,
    )
    .unwrap();
    let (_storage, mut memory) = owner(false, false);
    *memory.policy_mut() = raw_controls(false);
    assert_eq!(leaf.identity().memory_implementation_profile, None);
    let (mut registers, mut scalable) = state();
    let before = registers.clone();
    let mut context = context();
    let pointers = (context.memory, context.scalable, context.system);
    // SAFETY: declared test CPU controls match this fixed profile; all owners
    // are disjoint and source is a finite NOP/MOVZ/RET leaf.
    let result =
        unsafe { leaf.execute(&mut registers, &mut scalable, &mut memory, &mut context) }.unwrap();
    assert_eq!(result, ScalableLeafExit::Returned);
    assert_eq!(registers, before);
    assert_eq!((context.memory, context.scalable, context.system), pointers);
}

#[test]
fn checked_async_preflight_precedes_the_gpr_prefix() {
    let leaf = PreparedScalableLeaf::prepare(
        &words(&[MOV_X0_SEVEN, LD1B_Z1_P0_X5, RET_X30]),
        GuestAddress(GUEST_BASE),
        profile(),
        TargetCpu::Baseline,
    )
    .unwrap();
    let (_storage, mut memory) = owner(true, false);
    let (mut registers, mut scalable) = state();
    let before = registers.clone();
    let mut context = context();
    let pointers = (context.memory, context.scalable, context.system);
    // SAFETY: owners are disjoint and the finite declared profile is explicit;
    // effective async controls must decline before invoking any native byte.
    let result =
        unsafe { leaf.execute(&mut registers, &mut scalable, &mut memory, &mut context) }.unwrap();
    assert_eq!(
        result,
        ScalableLeafExit::EntryDeclined(MemoryStatus::Unsupported)
    );
    assert_eq!(registers, before);
    assert_eq!((context.memory, context.scalable, context.system), pointers);
}

#[test]
fn missing_runtime_atomic_capability_precedes_the_gpr_prefix() {
    let leaf = PreparedScalableLeaf::prepare(
        &words(&[MOV_X0_SEVEN, LD1D_Z1_P0_X5, RET_X30]),
        GuestAddress(GUEST_BASE),
        profile(),
        TargetCpu::Baseline,
    )
    .unwrap();
    let (_storage, mut memory) = owner(false, false);
    let (mut registers, mut scalable) = state();
    let before = registers.clone();
    // SAFETY: a finite profile and disjoint owners; the baseline domain lacks
    // this body's source-derived generic multibyte AtomicLoad16 requirement.
    let result =
        unsafe { leaf.execute(&mut registers, &mut scalable, &mut memory, &mut context()) }
            .unwrap();
    assert_eq!(
        result,
        ScalableLeafExit::EntryDeclined(MemoryStatus::Unsupported)
    );
    assert_eq!(registers, before);
}

#[test]
fn later_memory_fault_retains_prefix_but_not_the_staged_destination() {
    let leaf = PreparedScalableLeaf::prepare(
        &words(&[MOV_X0_SEVEN, LD1B_Z1_P0_X5, RET_X30]),
        GuestAddress(GUEST_BASE),
        profile(),
        TargetCpu::Baseline,
    )
    .unwrap();
    for permission in [false, true] {
        let (storage, mut memory) = owner(false, permission);
        let ram_before = storage.bytes();
        let (mut registers, mut scalable) = state();
        registers.x[BASE_REGISTER] = if permission {
            RAM_BASE
        } else {
            RAM_BASE + RAM_BYTES as u64 - 1
        };
        let mut expected = registers.clone();
        expected.x[0] = 7;
        let mut context = context();
        let pointers = (context.memory, context.scalable, context.system);
        // SAFETY: disjoint pinned owners and finite fixed-profile source. The
        // controlled service fault returns normally through the inner wrapper.
        let result =
            unsafe { leaf.execute(&mut registers, &mut scalable, &mut memory, &mut context) }
                .unwrap();
        let status = if permission {
            MemoryStatus::Permission
        } else {
            MemoryStatus::Translation
        };
        let fault_address = if permission {
            RAM_BASE + 1
        } else {
            RAM_BASE + RAM_BYTES as u64
        };
        assert_eq!(
            result,
            ScalableLeafExit::MemoryFault(MemoryFault {
                status,
                address: GuestAddress(fault_address),
                pc: GuestAddress(GUEST_BASE + size_of::<u32>() as u64),
                completed_bytes: 1,
            })
        );
        assert_eq!(registers, expected);
        assert_eq!(storage.bytes(), ram_before);
        assert_eq!((context.memory, context.scalable, context.system), pointers);
    }
}

#[test]
fn checked_streaming_profile_is_validated_before_the_gpr_prefix() {
    let leaf = PreparedScalableLeaf::prepare(
        &words(&[MOV_X0_SEVEN, LD1B_Z1_P0_X5, RET_X30]),
        GuestAddress(GUEST_BASE),
        profile(),
        TargetCpu::Baseline,
    )
    .unwrap();
    for implementation in [
        None,
        Some(MemoryImplementationProfile::StreamingSveTagSuppression),
        Some(MemoryImplementationProfile::SmeTagSuppression),
        Some(MemoryImplementationProfile::ScalableTagChecks),
    ] {
        let (storage, mut memory) = owner(false, false);
        let policy = raw_controls(false);
        *memory.policy_mut() = match implementation {
            Some(implementation) => policy.with_implementation_profile(implementation),
            None => policy,
        };
        let ram_before = storage.bytes();
        let (mut registers, mut scalable) = state();
        let mut expected = registers.clone();
        let mut context = context();
        let pointers = (context.memory, context.scalable, context.system);
        // SAFETY: disjoint owned buffers and finite source. The strict named
        // artifact contract is independent of current ATA/TCO/TBI bypasses.
        let result =
            unsafe { leaf.execute(&mut registers, &mut scalable, &mut memory, &mut context) }
                .unwrap();
        if implementation == Some(MemoryImplementationProfile::ScalableTagChecks) {
            expected.x[0] = 7;
            expected.v[DESTINATION as usize] = [u64::from_le_bytes([0, 1, 0, 0, 0, 0, 0, 0]), 0];
            assert_eq!(result, ScalableLeafExit::Returned);
        } else {
            assert_eq!(
                result,
                ScalableLeafExit::EntryDeclined(MemoryStatus::Unsupported)
            );
        }
        assert_eq!(registers, expected);
        assert_eq!(storage.bytes(), ram_before);
        assert_eq!((context.memory, context.scalable, context.system), pointers);
    }
}

#[test]
fn unknown_or_disabled_sp_alignment_preflight_precedes_the_gpr_prefix() {
    let leaf = PreparedScalableLeaf::prepare(
        &words(&[MOV_X0_SEVEN, LD1B_Z1_P0_SP, RET_X30]),
        GuestAddress(GUEST_BASE),
        profile(),
        TargetCpu::Baseline,
    )
    .unwrap();
    for effective_sp_alignment in [None, Some(false)] {
        let (storage, mut memory) = owner(false, false);
        let policy = unbound_controls(false)
            .with_implementation_profile(MemoryImplementationProfile::ScalableTagChecks);
        *memory.policy_mut() = match effective_sp_alignment {
            Some(enabled) => policy.with_effective_sp_alignment(enabled),
            None => policy,
        };
        let ram_before = storage.bytes();
        let (mut registers, mut scalable) = state();
        registers.sp = RAM_BASE + 1;
        let before = registers.clone();
        let mut context = context();
        let pointers = (context.memory, context.scalable, context.system);
        // SAFETY: disjoint owners and finite source. Unknown or disabled SA0/SA
        // declines this Enabled specialization before MOV, local SP or RAM.
        let result =
            unsafe { leaf.execute(&mut registers, &mut scalable, &mut memory, &mut context) }
                .unwrap();
        assert_eq!(
            result,
            ScalableLeafExit::EntryDeclined(MemoryStatus::Unsupported)
        );
        assert_eq!(registers, before);
        assert_eq!(storage.bytes(), ram_before);
        assert_eq!((context.memory, context.scalable, context.system), pointers);
    }
}

#[test]
fn inactive_sp_fault_is_local_and_the_next_entry_clears_it() {
    let leaf = PreparedScalableLeaf::prepare(
        &words(&[MOV_X0_SEVEN, LD1B_Z1_P0_SP, RET_X30]),
        GuestAddress(GUEST_BASE),
        profile(),
        TargetCpu::Baseline,
    )
    .unwrap();
    let (storage, mut memory) = owner(false, false);
    let ram_before = storage.bytes();
    let (mut registers, mut scalable) = state();
    scalable.write_predicate(0, &[0, 0]).unwrap();
    registers.sp = RAM_BASE + 1;
    let mut expected = registers.clone();
    expected.x[0] = 7;
    let mut context = context();
    let pointers = (context.memory, context.scalable, context.system);
    // SAFETY: the finite body has disjoint owned buffers. The declared SA0 and
    // CHECKSPNONEACTIVE profile faults before issuing any memory request.
    let result =
        unsafe { leaf.execute(&mut registers, &mut scalable, &mut memory, &mut context) }.unwrap();
    assert_eq!(
        result,
        ScalableLeafExit::MemoryFault(MemoryFault {
            status: MemoryStatus::StackAlignment,
            address: GuestAddress(RAM_BASE + 1),
            pc: GuestAddress(GUEST_BASE + size_of::<u32>() as u64),
            completed_bytes: 0,
        })
    );
    assert_eq!(registers, expected);
    assert_eq!((context.memory, context.scalable, context.system), pointers);
    registers.sp = RAM_BASE;
    expected.sp = RAM_BASE;
    expected.v[DESTINATION as usize] = [0; 2];
    // SAFETY: identical owners and finite source; aligned inactive loads perform
    // no guest RAM access and commit their architectural zero destination.
    let result =
        unsafe { leaf.execute(&mut registers, &mut scalable, &mut memory, &mut context) }.unwrap();
    assert_eq!(result, ScalableLeafExit::Returned);
    assert_eq!(registers, expected);
    assert_eq!(storage.bytes(), ram_before);
    assert_eq!((context.memory, context.scalable, context.system), pointers);
}

#[test]
fn baseline_byte_load_preserves_enabled_vector_banks_at_every_length() {
    for bytes in [16, 32, 64, 128, 256] {
        let profile = ScalableProfile::new(
            VectorLength::from_bytes(bytes).unwrap(),
            ScalableMode::new(true, false),
        );
        let leaf = PreparedScalableLeaf::prepare(
            &words(&[LD1B_Z1_P0_X5, RET_X30]),
            GuestAddress(GUEST_BASE),
            profile,
            TargetCpu::Baseline,
        )
        .unwrap();
        let (storage, mut memory) = owner(false, false);
        let mut registers = GuestState::default();
        let mut scalable = ScalableState::new(profile.vector_length(), true);
        scalable.apply_mode(&mut registers, profile.mode()).unwrap();
        scalable.set_tpidr2_el0(0x1234_5678_9abc_def0);
        scalable.set_fpmr(0x2468_ace0);
        let controls_before = (scalable.tpidr2_el0(), scalable.fpmr(), scalable.mode());
        registers.x[BASE_REGISTER] = RAM_BASE;
        registers.nzcv = 0xa000_0000;
        registers.fpcr = 0x07c0_0000;
        registers.fpsr = 0x8800_009f;
        for register in 0..32 {
            scalable
                .write_z(&mut registers, register, &vec![register + 1; bytes])
                .unwrap();
        }
        for predicate in 0..16 {
            scalable
                .write_predicate(predicate, &vec![predicate.wrapping_mul(17); bytes / 8])
                .unwrap();
        }
        scalable.write_predicate(0, &vec![0x55; bytes / 8]).unwrap();
        scalable.write_ffr(&vec![0xa5; bytes / 8]).unwrap();
        let before = registers.clone();
        let ram = storage.bytes();
        // SAFETY: fixed declared CPU controls, disjoint pinned owners and finite
        // baseline byte accesses; caller-saved host values are not guest state.
        let result =
            unsafe { leaf.execute(&mut registers, &mut scalable, &mut memory, &mut context()) }
                .unwrap();
        assert_eq!(result, ScalableLeafExit::Returned);
        let output: Vec<u8> = (0..bytes)
            .map(|byte| if byte % 2 == 0 { ram[byte] } else { 0 })
            .collect();
        let mut expected = before;
        for (limb, value) in expected.v[DESTINATION as usize].iter_mut().zip(
            output[..GRANULE_BYTES]
                .as_chunks::<{ size_of::<u64>() }>()
                .0,
        ) {
            *limb = u64::from_le_bytes(*value);
        }
        assert_eq!(registers, expected);
        for register in 0..32 {
            let mut actual = vec![0; bytes];
            scalable.read_z(&registers, register, &mut actual).unwrap();
            assert_eq!(
                actual,
                if register == DESTINATION {
                    output.clone()
                } else {
                    vec![register + 1; bytes]
                }
            );
        }
        for predicate in 0..16 {
            let mut actual = vec![0; bytes / 8];
            scalable.read_predicate(predicate, &mut actual).unwrap();
            assert_eq!(
                actual,
                vec![
                    if predicate == 0 {
                        0x55
                    } else {
                        predicate.wrapping_mul(17)
                    };
                    bytes / 8
                ]
            );
        }
        let mut ffr = vec![0; bytes / 8];
        scalable.read_ffr(&mut ffr).unwrap();
        assert_eq!(ffr, vec![0xa5; bytes / 8]);
        assert_eq!(
            (scalable.tpidr2_el0(), scalable.fpmr(), scalable.mode()),
            controls_before
        );
        assert_eq!(storage.bytes(), ram);
    }
}

#[test]
fn invalid_owned_view_restores_pointers_before_returning_error() {
    let profile = ScalableProfile::new(
        VectorLength::from_bytes(GRANULE_BYTES).unwrap(),
        ScalableMode::new(true, true),
    );
    let leaf = PreparedScalableLeaf::prepare(
        &words(&[NOP, RET_X30]),
        GuestAddress(GUEST_BASE),
        profile,
        TargetCpu::Baseline,
    )
    .unwrap();
    let (_storage, mut memory) = owner(false, false);
    let mut registers = GuestState::default();
    let mut scalable = ScalableState::new(profile.vector_length(), false);
    scalable.apply_mode(&mut registers, profile.mode()).unwrap();
    let before = registers.clone();
    let mut context = context();
    let pointers = (context.memory, context.scalable, context.system);
    // SAFETY: no native call is allowed: the prepared SME2 ZA view requires ZT0,
    // while this explicit non-SME2 owner provides no ZT0 backing.
    let result = unsafe { leaf.execute(&mut registers, &mut scalable, &mut memory, &mut context) };
    assert!(result.is_err());
    assert_eq!(registers, before);
    assert_eq!((context.memory, context.scalable, context.system), pointers);
}
