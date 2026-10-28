//! Preparing and running a context-backed leaf with checked memory.
use alloc::rc::Rc;
#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, string::String};
use core::marker::PhantomData;

use crate::sha256;
use anyhow::{Context, Result, ensure};
use stela_compiler::{
    GuestAddress, GuestState, TargetCpu,
    aarch64::scalable::execution::{
        SCALABLE_EXECUTION_REQUIREMENTS_VERSION, ScalableExecutionRequirements,
    },
    context::{
        CONTEXT_LEAF_ABI, ExecutionContext,
        memory::{
            MEMORY_IMPLEMENTATION_PROFILE_ID, MemoryRequirements, MemoryStatus,
            profile_requirements,
        },
    },
    scalable_context::{self, ScalableProfile},
};

use super::{ScalableState, context::ContextLoan};
use crate::{
    execution::{MAX_NATIVE_BYTES, platform},
    memory::domain::{DataPolicy, MemoryThread},
};

/// Complete identity of the exact source and generated context leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScalableLeafIdentity {
    pub source_sha256: String,
    pub native_sha256: String,
    pub compiler_source_sha256: String,
    pub guest_base: GuestAddress,
    pub abi: &'static str,
    pub target_cpu: String,
    pub profile: ScalableProfile,
    pub memory_requirements: MemoryRequirements,
    pub execution_requirements_version: u32,
    pub execution_requirements: ScalableExecutionRequirements,
    /// Translation target identity, including the fixed CHECKSPNONEACTIVE choice.
    /// Runtime policy matching is required only by SCALABLE_TAG_CHECKS.
    pub memory_implementation_profile: Option<&'static str>,
}

/// Memory-service outcome after the still-faulting guest instruction returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryFault {
    pub status: MemoryStatus,
    pub address: GuestAddress,
    pub pc: GuestAddress,
    pub completed_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalableLeafExit {
    Returned,
    /// Effective controls or platform storage declined before native entry.
    EntryDeclined(MemoryStatus),
    /// Architectural faults and callback service failures.
    MemoryFault(MemoryFault),
    /// The body returned, but common fault settlement or domain health failed.
    /// Original architectural fault provenance remains distinct from this failure.
    FinalizationFailed {
        status: MemoryStatus,
        native_executed: bool,
        completed_bytes: u64,
        original_fault: Option<MemoryFault>,
    },
}

/// Immutable native code, its requirements and source bytes. Calls are
/// serialized.
#[derive(Debug)]
pub struct PreparedScalableLeaf {
    identity: ScalableLeafIdentity,
    source: Box<[u8]>,
    source_map: Box<[(GuestAddress, usize)]>,
    native_bytes: usize,
    target: TargetCpu,
    mapping: platform::Mapping,
    _serialized: PhantomData<Rc<()>>,
}

impl PreparedScalableLeaf {
    /// Compile a fixed context profile and bind its requirements to that exact
    /// source. Native bytes and caller-supplied requirements are never accepted.
    pub fn prepare(
        source: &[u8],
        base: GuestAddress,
        profile: ScalableProfile,
        target: TargetCpu,
    ) -> Result<Self> {
        ensure!(
            source.len() <= MAX_NATIVE_BYTES,
            "context leaf source exceeds the native preparation bound"
        );
        platform::ensure_supported()?;
        ensure!(
            crate::platform::cpu::admitted(target),
            "host lacks context-leaf CPU requirements"
        );
        let source: Box<[u8]> = source.into();
        let prepared = scalable_context::prepare_leaf(&source, base, profile, target)
            .context("prepare context leaf and source requirements")?;
        let native = prepared.native;
        let requirements = prepared.memory_requirements;
        ensure!(
            !native.x86_64_code.is_empty() && native.x86_64_code.len() <= MAX_NATIVE_BYTES,
            "generated context leaf exceeds the native preparation bound"
        );
        let identity = ScalableLeafIdentity {
            source_sha256: sha256(&source),
            native_sha256: sha256(&native.x86_64_code),
            compiler_source_sha256: stela_compiler::SOURCE_SHA256.into(),
            guest_base: base,
            abi: CONTEXT_LEAF_ABI,
            target_cpu: target.id(),
            profile,
            memory_requirements: requirements,
            execution_requirements_version: SCALABLE_EXECUTION_REQUIREMENTS_VERSION,
            execution_requirements: prepared.execution_requirements,
            memory_implementation_profile: (requirements.required_profile
                & profile_requirements::NATIVE_ACCESS
                != 0)
                .then_some(MEMORY_IMPLEMENTATION_PROFILE_ID),
        };
        let mapping = platform::Mapping::new(&native.x86_64_code)?;
        Ok(Self {
            identity,
            source,
            source_map: native.source_map.into_boxed_slice(),
            native_bytes: native.x86_64_code.len(),
            target,
            mapping,
            _serialized: PhantomData,
        })
    }

    pub fn identity(&self) -> &ScalableLeafIdentity {
        &self.identity
    }

    pub fn source(&self) -> &[u8] {
        &self.source
    }

    pub fn source_map(&self) -> &[(GuestAddress, usize)] {
        &self.source_map
    }

    pub fn native_bytes(&self) -> usize {
        self.native_bytes
    }

    /// Run after the memory preflight and view validation. Platform refusals
    /// leave guest state unchanged; faults keep the completed instructions and
    /// the memory service's reached prefix.
    ///
    /// # Safety
    /// The CPU owner must ensure the prepared feature and SMCR profile and
    /// `profile.required_dit()` match the effective controls, and that FP, SVE
    /// and SME access is enabled at the current EL (including CPACR and CPTR
    /// traps). Native memory access requires little-endian data, unenforced
    /// alignment and FEAT_CPA2 disabled; view validation does not check these,
    /// while the memory preflight checks SA/SA0 and the memory implementation
    /// profile. The source must be trusted to terminate. Guest memory must be
    /// disjoint from register storage, the native code, the context, the native
    /// stack and live Rust references, and its owners must keep host rights
    /// pinned. There is no signal recovery or unwinding through native code.
    pub unsafe fn execute<P: DataPolicy>(
        &self,
        registers: &mut GuestState,
        scalable: &mut ScalableState,
        memory: &mut MemoryThread<P>,
        context: &mut ExecutionContext,
    ) -> Result<ScalableLeafExit> {
        ensure!(
            context.has_supported_header(),
            "unsupported execution context"
        );
        ensure!(
            crate::platform::cpu::admitted(self.target),
            "context-leaf host requirements changed"
        );
        ensure!(
            scalable.vector_length() == self.identity.profile.vector_length()
                && scalable.mode() == self.identity.profile.mode(),
            "owned scalable state differs from prepared profile"
        );
        // SAFETY: the state owner keeps every register allocation; the guards
        // restore the service pointers before their borrows expire; the caller
        // supplies disjoint memory and terminating code.
        unsafe {
            scalable.with_view(|view| {
                let mut scalable_loan = ContextLoan::scalable(context, view);
                self.identity
                    .profile
                    .validate_view(scalable_loan.context(), view)?;
                let entry = match memory.prepare(self.identity.memory_requirements) {
                    Ok(entry) => entry,
                    Err(status) => return Ok(ScalableLeafExit::EntryDeclined(status)),
                };
                let mut native_executed = false;
                let mut completed_bytes = 0;
                let mut original_fault = None;
                let result = entry.with_checked_view(|memory_view| {
                    let mut memory_loan = ContextLoan::memory(scalable_loan.context(), memory_view);
                    self.mapping
                        .call_context(registers, memory_loan.context())?;
                    native_executed = true;
                    completed_bytes = memory_view.completed_bytes;
                    let status = memory_status(memory_view.fault_kind)?;
                    if status == MemoryStatus::Success {
                        return Ok(ScalableLeafExit::Returned);
                    }
                    let fault = MemoryFault {
                        status,
                        address: GuestAddress(memory_view.fault_address),
                        pc: GuestAddress(memory_view.fault_pc),
                        completed_bytes: memory_view.completed_bytes,
                    };
                    // Finalization can discard the callback result, so keep the
                    // fault before validating its PC.
                    original_fault = Some(fault);
                    ensure!(
                        self.source_map
                            .iter()
                            .any(|(address, _)| *address == fault.pc),
                        "memory service reported a PC outside the consumed source"
                    );
                    Ok(ScalableLeafExit::MemoryFault(fault))
                });
                match result {
                    Ok(exit) => exit,
                    Err(status) => Ok(ScalableLeafExit::FinalizationFailed {
                        status,
                        native_executed,
                        completed_bytes,
                        original_fault,
                    }),
                }
            })
        }
    }
}

fn memory_status(raw: u32) -> Result<MemoryStatus> {
    MemoryStatus::from_code(raw)
        .ok_or_else(|| anyhow::anyhow!("memory service returned an unknown status {raw}"))
}

#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
mod tests {
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
            // SAFETY: the last Arc frees the original allocation with its layout.
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
        // SAFETY: the allocation stays owned, disjoint and writable; no byte
        // references exist, and all accesses use this domain.
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
        assert!(leaf.native_bytes() > scalable_context::CONTEXT_WRAPPER_BYTES);
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
        // SAFETY: the test's controls match this profile, storage is disjoint, and
        // the source is NOP/MOVZ/RET.
        let result =
            unsafe { leaf.execute(&mut registers, &mut scalable, &mut memory, &mut context) }
                .unwrap();
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
        // SAFETY: disjoint storage and an explicit profile; the asynchronous
        // controls must refuse before any native code runs.
        let result =
            unsafe { leaf.execute(&mut registers, &mut scalable, &mut memory, &mut context) }
                .unwrap();
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
            // SAFETY: disjoint storage and terminating source; the artifact
            // contract does not depend on ATA, TCO or TBI.
            let result =
                unsafe { leaf.execute(&mut registers, &mut scalable, &mut memory, &mut context) }
                    .unwrap();
            if implementation == Some(MemoryImplementationProfile::ScalableTagChecks) {
                expected.x[0] = 7;
                expected.v[DESTINATION as usize] =
                    [u64::from_le_bytes([0, 1, 0, 0, 0, 0, 0, 0]), 0];
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
        // SAFETY: disjoint storage; the declared SA0 and CHECKSPNONEACTIVE profile
        // faults before any memory request.
        let result =
            unsafe { leaf.execute(&mut registers, &mut scalable, &mut memory, &mut context) }
                .unwrap();
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
            unsafe { leaf.execute(&mut registers, &mut scalable, &mut memory, &mut context) }
                .unwrap();
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
            // SAFETY: fixed controls, disjoint pinned storage and baseline byte
            // accesses.
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
        // SAFETY: no native call happens: the SME2 ZA view needs ZT0, which this
        // owner does not provide.
        let result =
            unsafe { leaf.execute(&mut registers, &mut scalable, &mut memory, &mut context) };
        assert!(result.is_err());
        assert_eq!(registers, before);
        assert_eq!((context.memory, context.scalable, context.system), pointers);
    }
}
