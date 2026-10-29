//! Reconstruct fault permission from admitted source and a complete code template.
use super::{FaultRecovery, RecoveryBinding, RecoverySiteKind, RetirementPoint};
use crate::{
    CompileError, GuestAddress,
    block::{CompilationPlan, CompiledBlock},
};
use alloc::vec::Vec;

/// Persistable metadata; this carries no permission to project a guest fault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnqualifiedFaultRecovery {
    pub start: usize,
    pub end: usize,
    pub bindings: Vec<RecoveryBinding>,
    pub retirement: RetirementPoint,
    pub site: RecoverySiteKind,
}
impl From<&FaultRecovery> for UnqualifiedFaultRecovery {
    fn from(row: &FaultRecovery) -> Self {
        Self {
            start: row.start,
            end: row.end,
            bindings: row.bindings.clone(),
            retirement: row.retirement,
            site: row.site.kind(),
        }
    }
}
/// An immutable, unpatched template. The caller binds this to the installed
/// executable owner and validates every live chain redirection against its
/// patch plan. Mutated live code is never a substitute for this image.
pub struct RecoveryTemplate<'a> {
    pub code: &'a [u8],
    pub source_map: &'a [(GuestAddress, usize)],
    pub source_bytes: usize,
    pub direct_exits: &'a [crate::x86_64::chain::DirectExit],
    pub recovery: &'a [UnqualifiedFaultRecovery],
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryQualificationError {
    Compile(CompileError),
    SourceExtent,
    NativeCode,
    SourceMap,
    DirectExits,
    RecoveryPlan,
}
impl core::fmt::Display for RecoveryQualificationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Compile(error) => write!(f, "fault-plan recompilation failed: {error}"),
            Self::SourceExtent => f.write_str("fault-plan source extent differs"),
            Self::NativeCode => f.write_str("fault-plan native template differs"),
            Self::SourceMap => f.write_str("fault-plan source map differs"),
            Self::DirectExits => f.write_str("fault-plan chain patch sites differ"),
            Self::RecoveryPlan => f.write_str("fault-plan recovery metadata differs"),
        }
    }
}
impl core::error::Error for RecoveryQualificationError {}
impl CompilationPlan {
    /// Re-emit the admitted input/profile and mint a recovery plan only if the
    /// complete immutable template agrees. This allocates and must run in the
    /// dispatcher, never in an ISR. Legacy cached blocks may defer it until a
    /// fault, before publishing any architectural change. Spill/EGPR execution
    /// requires eager validation before invocation and capture-plan exposure.
    pub fn qualify_recovery(
        self,
        template: RecoveryTemplate<'_>,
    ) -> Result<CompiledBlock, RecoveryQualificationError> {
        let compiled = self
            .compile()
            .map_err(RecoveryQualificationError::Compile)?;
        if compiled.source_bytes != template.source_bytes {
            return Err(RecoveryQualificationError::SourceExtent);
        }
        if compiled.native.x86_64_code != template.code {
            return Err(RecoveryQualificationError::NativeCode);
        }
        if compiled.native.source_map != template.source_map {
            return Err(RecoveryQualificationError::SourceMap);
        }
        if compiled.direct_exits != template.direct_exits {
            return Err(RecoveryQualificationError::DirectExits);
        }
        if compiled.fault_recovery.len() != template.recovery.len()
            || !compiled
                .fault_recovery
                .iter()
                .zip(template.recovery)
                .all(|(minted, stored)| {
                    minted.start == stored.start
                        && minted.end == stored.end
                        && minted.bindings == stored.bindings
                        && minted.retirement == stored.retirement
                        && minted.site.kind() == stored.site
                })
        {
            return Err(RecoveryQualificationError::RecoveryPlan);
        }
        Ok(compiled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Options, TargetCpu,
        block::{BlockProfile, Features},
    };
    const BASE: GuestAddress = GuestAddress(0x1000);
    fn source() -> Vec<u8> {
        [0x91000400_u32, 0xf9400022, 0x14000000]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect()
    }
    fn options() -> Options {
        Options::new(
            BlockProfile::new(Features::SYSTEM_MODE),
            TargetCpu::Baseline,
        )
    }
    fn compile(source: &[u8]) -> CompiledBlock {
        CompilationPlan::new(source, BASE, &options())
            .unwrap()
            .compile()
            .unwrap()
    }
    fn template<'a>(
        block: &'a CompiledBlock,
        rows: &'a [UnqualifiedFaultRecovery],
    ) -> RecoveryTemplate<'a> {
        RecoveryTemplate {
            code: &block.native.x86_64_code,
            source_map: &block.native.source_map,
            source_bytes: block.source_bytes,
            direct_exits: &block.direct_exits,
            recovery: rows,
        }
    }
    #[test]
    fn full_plan_reconstruction_rejects_portable_guest_on_frame_and_code_mutants() {
        let source = source();
        let block = compile(&source);
        let rows: Vec<_> = block
            .fault_recovery
            .iter()
            .map(UnqualifiedFaultRecovery::from)
            .collect();
        assert!(
            rows.iter()
                .any(|row| row.site == RecoverySiteKind::GuestAccess)
        );
        let plan = || CompilationPlan::new(&source, BASE, &options()).unwrap();
        assert!(plan().qualify_recovery(template(&block, &rows)).is_ok());
        let mut forged = rows.clone();
        let frame = block.native.source_map[0].1;
        forged.push(UnqualifiedFaultRecovery {
            start: frame,
            end: frame + 1,
            bindings: Vec::new(),
            retirement: RetirementPoint::before(BASE, 0).unwrap(),
            site: RecoverySiteKind::GuestAccess,
        });
        assert!(matches!(
            plan().qualify_recovery(template(&block, &forged)),
            Err(RecoveryQualificationError::RecoveryPlan)
        ));
        let mut changed = block.clone();
        changed.native.x86_64_code[frame] ^= 1;
        assert!(matches!(
            plan().qualify_recovery(template(&changed, &rows)),
            Err(RecoveryQualificationError::NativeCode)
        ));
        let mut changed = block.clone();
        changed.native.source_map[0].1 += 1;
        assert!(matches!(
            plan().qualify_recovery(template(&changed, &rows)),
            Err(RecoveryQualificationError::SourceMap)
        ));
        let mut changed = block.clone();
        changed.source_bytes -= 4;
        assert!(matches!(
            plan().qualify_recovery(template(&changed, &rows)),
            Err(RecoveryQualificationError::SourceExtent)
        ));
        let mut changed = block.clone();
        changed.direct_exits[0].offset += 1;
        assert!(matches!(
            plan().qualify_recovery(template(&changed, &rows)),
            Err(RecoveryQualificationError::DirectExits)
        ));
        let mut changed_source = source.clone();
        changed_source[0..4].copy_from_slice(&0x91000800_u32.to_le_bytes());
        assert!(
            CompilationPlan::new(&changed_source, BASE, &options())
                .unwrap()
                .qualify_recovery(template(&block, &rows))
                .is_err()
        );
    }
}
