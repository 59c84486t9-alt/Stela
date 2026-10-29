//! Scalable-code entry with checked memory.

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
        cause: crate::Error,
    },
}

/// A guest's general and FP registers with its scalable vector, predicate
/// and matrix state.
pub struct ScalableGuest<'a> {
    pub registers: &'a mut GuestState,
    pub scalable: &'a mut ScalableState,
}

impl FixedProcessMemoryControls {
    /// Run one compiler-prepared body under the held CPU controls. This scope
    /// is EL0 without MTE. The CPU owner checks every helper and feature clause
    /// from the source; the prepared leaf checks the domain's storage profile
    /// and read/write capabilities before entry. Native memory also needs
    /// 16-byte single-copy atomicity. Quadword requests keep their
    /// architectural descriptor, so the memory service decides their alignment,
    /// splitting and fault order. Unsupported facts or controls are refused
    /// before any prefix runs.
    ///
    /// # Safety
    /// The source must terminate. Raw guest memory must stay disjoint from the
    /// live state and context, this native code and the native stack, with host
    /// rights and coherent storage pinned throughout. No asynchronous re-entry,
    /// host protection change, unwinding or signal recovery through native code
    /// is allowed.
    pub unsafe fn execute_scalable_leaf(
        &self,
        access: &ScalableControlOwner<'_>,
        prepared: &PreparedScalableLeaf,
        system: &mut SystemState,
        guest: ScalableGuest<'_>,
        memory: &mut MemoryThread<MemoryControls>,
        context: &mut ExecutionContext,
    ) -> Result<ScalableLeafExit, ScalableExecutionError> {
        let ScalableGuest {
            registers,
            scalable,
        } = guest;
        let identity = prepared.identity();
        let pc = identity.guest_base;
        let memory_error = |cause| ScalableExecutionError::MemoryAuthority { pc, cause };
        // The same ordered source-state checks as the GPR path, including IL
        // before identification, source or service access.
        self.validate_source_state(system, registers)
            .map_err(memory_error)?;
        if self.features.cpa == super::pointer_checks::CpaFeature::Checked {
            return Err(ScalableExecutionError::MemoryAuthority {
                pc,
                cause: ProcessMemoryError::PointerChecks(
                    super::PointerChecksError::UnsupportedProfile,
                ),
            });
        }

        // Raw-ID GPR controls carry no identification snapshot; this MTE-free
        // provider must keep the same snapshot allocation.
        let identification = self
            .identification_snapshot()
            .ok_or(ScalableExecutionError::MissingIdentificationSnapshot { pc })?;
        if !core::ptr::eq(identification, access.identification_snapshot()) {
            return Err(ScalableExecutionError::WrongIdentificationSnapshot { pc });
        }
        // Pin the domain before validating its source generation, and keep the
        // borrow through native finalization and the policy and control
        // restore. The PE owner separately holds its outer borrow for PC
        // settlement.
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
        // Shared references to both fixed owners and the system state stay live
        // for the callback, whose only mutable subjects are the guest and
        // scalable state.
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
                    // SAFETY: all source and CPU checks precede this call, and
                    // the caller keeps the raw backing contract. The leaf
                    // prepares the requirements, publishes views, runs the
                    // native code and finalizes.
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
mod tests;
