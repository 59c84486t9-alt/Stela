//! Qualified scalable entry through the same fixed process-memory authority.
//!
//! Source obligations belong to the prepared compiler identity. The scalable
//! control owner evaluates them while retaining its actual ID/control loan;
//! this child composes that loan with the existing same-thread policy guard.

use super::{FixedProcessMemoryControls, PolicyLoan, ProcessMemoryError};
use crate::{
    memory::{domain::MemoryThread, policy::MemoryControls},
    scalable::{
        ScalableState,
        leaf::{PreparedScalableLeaf, ScalableLeafExit},
    },
    system::{
        scalable_controls::{self, ScalableControlOwner, SourceAtomicity},
        state::SystemState,
    },
};
use stela_compiler::{
    GuestAddress, GuestState,
    aarch64::scalable::{
        ElementSize,
        execution::{GuestMemoryQuantity, SCALABLE_EXECUTION_REQUIREMENTS_VERSION},
    },
    context::{
        ExecutionContext,
        memory::{flags, profile_requirements},
    },
};

const SCALABLE_REQUEST_FLAGS: u32 =
    flags::WRITE | flags::TAG_CHECKED | flags::NON_TEMPORAL | flags::SME | flags::SVE_PREDICATED;

#[derive(Debug)]
pub enum ScalableExecutionError {
    MemoryAuthority {
        pc: GuestAddress,
        cause: ProcessMemoryError,
    },
    Control {
        entry_pc: GuestAddress,
        cause: scalable_controls::Error,
    },
    MissingIdentificationSnapshot {
        pc: GuestAddress,
    },
    WrongIdentificationSnapshot {
        pc: GuestAddress,
    },
    UnsupportedRequirementsVersion {
        pc: GuestAddress,
        version: u32,
    },
    UnsupportedSourceAtomicity {
        pc: GuestAddress,
        actual: SourceAtomicity,
    },
    UnsupportedMemoryClass {
        pc: GuestAddress,
        required_flags: u32,
    },
    UnqualifiedMemoryQuantity {
        pc: GuestAddress,
    },
    UnsupportedGuestQuantity {
        pc: GuestAddress,
        quantity: ElementSize,
    },
    Execution {
        entry_pc: GuestAddress,
        cause: anyhow::Error,
    },
}

impl FixedProcessMemoryControls {
    /// Execute one immutable compiler-prepared body under retained CPU controls.
    /// This source scope remains EL0/MTE-absent. The shared CPU owner checks
    /// each source helper and feature clause; the prepared leaf checks the
    /// actual domain's storage profile and read/write capabilities before entry.
    /// Native memory also requires an explicit SCA16 source implementation.
    /// Quadword requests retain their emitted architectural descriptor, so the
    /// canonical memory service owns their alignment, partition and fault order.
    /// Unsupported source facts and access controls decline before any prefix.
    ///
    /// # Safety
    /// Original source must return finitely. All raw guest backing must remain
    /// disjoint from these live state/context owners, this RX mapping and native
    /// stack; actual native rights and coherent storage remain pinned throughout
    /// invocation. No asynchronous reentry, host protection change or unwind /
    /// signal recovery through generated native code is permitted. Qualification
    /// establishes CPU/source authority, not these raw native-storage contracts.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn execute_scalable_leaf(
        &self,
        access: &ScalableControlOwner<'_>,
        prepared: &PreparedScalableLeaf,
        system: &mut SystemState,
        registers: &mut GuestState,
        scalable: &mut ScalableState,
        memory: &mut MemoryThread<MemoryControls>,
        context: &mut ExecutionContext,
    ) -> Result<ScalableLeafExit, ScalableExecutionError> {
        let identity = prepared.identity();
        let pc = identity.guest_base;
        let memory_error = |cause| ScalableExecutionError::MemoryAuthority { pc, cause };
        // Same ordered source-state checks as the GPR authority, including IL
        // before identification, source or service access.
        self.validate_source_state(system, registers)
            .map_err(memory_error)?;
        // Legacy raw-ID GPR controls carry no shared identification authority.
        // This MTE0-only provider must retain the same actual Snapshot allocation.
        let identification = self
            .identification_snapshot()
            .ok_or(ScalableExecutionError::MissingIdentificationSnapshot { pc })?;
        if !std::ptr::eq(identification, access.identification_snapshot()) {
            return Err(ScalableExecutionError::WrongIdentificationSnapshot { pc });
        }
        // Pin this actual domain before validating its source generation.
        // Retain the loan through native finalization and policy/control restore;
        // the actual PE owner separately retains its outer PC-settlement loan.
        let _execution_loan = memory
            .execution_loan()
            .map_err(ProcessMemoryError::Memory)
            .map_err(memory_error)?;
        if !self.source.matches(memory) {
            return Err(memory_error(ProcessMemoryError::WrongMemoryDomain));
        }
        if identity.execution_requirements_version != SCALABLE_EXECUTION_REQUIREMENTS_VERSION {
            return Err(ScalableExecutionError::UnsupportedRequirementsVersion {
                pc,
                version: identity.execution_requirements_version,
            });
        }
        if identity.memory_requirements.required_flags & !SCALABLE_REQUEST_FLAGS != 0 {
            return Err(ScalableExecutionError::UnsupportedMemoryClass {
                pc,
                required_flags: identity.memory_requirements.required_flags,
            });
        }
        for instruction in identity.execution_requirements.instructions() {
            match instruction.guest_memory_quantity() {
                GuestMemoryQuantity::None
                | GuestMemoryQuantity::Maximum(
                    ElementSize::Byte
                    | ElementSize::Halfword
                    | ElementSize::Word
                    | ElementSize::Doubleword
                    | ElementSize::Quadword,
                ) => {}
                GuestMemoryQuantity::Unqualified => {
                    return Err(ScalableExecutionError::UnqualifiedMemoryQuantity {
                        pc: instruction.pc(),
                    });
                }
            }
        }
        // Shared references to both actual fixed owners and SystemState remain
        // live for the callback. Guest/scalable mutable reborrows are its sole
        // subjects; no detached approval or conflicting immutable state survives.
        access
            .with_checked_execution(
                &identity.execution_requirements,
                identity.profile,
                system,
                registers,
                scalable,
                |effective, registers, scalable| {
                    if identity.memory_requirements.required_profile
                        & profile_requirements::NATIVE_ACCESS
                        != 0
                        && effective.source_atomicity() != SourceAtomicity::FixedSca16
                    {
                        return Err(ScalableExecutionError::UnsupportedSourceAtomicity {
                            pc,
                            actual: effective.source_atomicity(),
                        });
                    }
                    let policy = self
                        .memory_controls(system)
                        .with_implementation_profile(effective.implementation_profile());
                    let loan = PolicyLoan::new(memory, policy);
                    // SAFETY: all source/CPU qualification precedes this actual
                    // prepared mapping. The caller retains the raw backing contract.
                    // The existing leaf alone prepares complete-body requirements,
                    // publishes views, invokes native and settles checked finalization.
                    unsafe { prepared.execute(registers, scalable, loan.thread, context) }.map_err(
                        |cause| ScalableExecutionError::Execution {
                            entry_pc: pc,
                            cause,
                        },
                    )
                },
            )
            .map_err(|cause| ScalableExecutionError::Control {
                entry_pc: pc,
                cause,
            })?
    }
}

#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
#[path = "scalable/tests.rs"]
mod tests;
