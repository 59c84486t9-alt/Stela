//! Requirements of a prepared scalable body, checked against the live controls
//! immediately before native entry.

use super::{ElementSize, features::FeatureRequirement};
use crate::GuestAddress;
use alloc::boxed::Box;
use alloc::vec::Vec;

pub const SCALABLE_EXECUTION_REQUIREMENTS_VERSION: u32 = 2;

/// Source-derived helper obligation. Known sequences retain literal source
/// helper spelling; explicitly guarded specializations retain their reviewed
/// equivalent helper sequence under the named authoritative state guard.
/// Nested checks, their ordering and conditional semantics belong to the
/// shared source-control evaluator; they are never expanded into booleans here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScalableAccessCheck {
    SveEnabled,
    NonStreamingSveEnabled,
    StreamingSveEnabled,
    StreamingSveAndZaEnabled,
    SmeEnabled,
    SmeAndZaEnabled,
    SmeZt0Enabled,
}

/// Unknown source facts decline checked qualification. An empty known sequence
/// is reserved for an explicitly audited source that calls no scalable helper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScalableAccessRequirements {
    Known(Box<[ScalableAccessCheck]>),
    /// Reviewed equivalence specialized to actual FEAT_SME and actual SM=1.
    /// The consumer must validate both facts before evaluating any contained
    /// helper. Failure is a conservative Unsupported decline before effects,
    /// never an inferred source SM=0 trap. The same actual owners stay borrowed
    /// through the native body and checked finalization.
    StreamingSmeSpecialization(Box<[ScalableAccessCheck]>),
    Unqualified,
}

/// Maximum architectural guest memory quantity reached by this instruction.
/// Host read/RMW envelopes and total vector/block bytes are separate concepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestMemoryQuantity {
    None,
    Maximum(ElementSize),
    Unqualified,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstructionExecutionRequirements {
    pc: GuestAddress,
    /// Conjunction of the existing decoder's clauses. Each clause retains its
    /// own ALL and ANY sets; flattening ANY sets would change the condition.
    feature_clauses: Box<[FeatureRequirement]>,
    access: ScalableAccessRequirements,
    guest_memory_quantity: GuestMemoryQuantity,
}

impl InstructionExecutionRequirements {
    pub(crate) fn new(
        pc: GuestAddress,
        feature_clauses: Vec<FeatureRequirement>,
        access: ScalableAccessRequirements,
        guest_memory_quantity: GuestMemoryQuantity,
    ) -> Self {
        Self {
            pc,
            feature_clauses: feature_clauses.into_boxed_slice(),
            access,
            guest_memory_quantity,
        }
    }

    pub const fn pc(&self) -> GuestAddress {
        self.pc
    }

    pub fn feature_clauses(&self) -> &[FeatureRequirement] {
        &self.feature_clauses
    }

    pub fn access(&self) -> &ScalableAccessRequirements {
        &self.access
    }

    pub const fn guest_memory_quantity(&self) -> GuestMemoryQuantity {
        self.guest_memory_quantity
    }
}

/// Immutable source order, including prefixes and branches that the complete
/// prepared body may execute. This is independent of memory-service flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScalableExecutionRequirements {
    instructions: Box<[InstructionExecutionRequirements]>,
}

impl ScalableExecutionRequirements {
    pub(crate) fn new(instructions: Vec<InstructionExecutionRequirements>) -> Self {
        Self {
            instructions: instructions.into_boxed_slice(),
        }
    }

    pub fn instructions(&self) -> &[InstructionExecutionRequirements] {
        &self.instructions
    }
}
