//! Snapshot-bound instruction authority for the checked shared-memory family.
use super::*;
use stela_compiler::context::memory::InstructionRequirements;
const SCTLR_NAA: u64 = 1 << 6;
const FEATURE_SHIFT: u32 = 20;
const LSE: u64 = 2;
const LSE128: u64 = 3;
const RCPC: u64 = 1;
const RCPC2: u64 = 2;
const RCPC3: u64 = 3;

pub(crate) struct SharedProcessMemoryAuthorization<'run> {
    system: &'run SystemState,
    controls: &'run FixedProcessMemoryControls,
    classes: u32,
    instructions: InstructionRequirements,
}
impl SharedProcessMemoryAuthorization<'_> {
    pub(crate) fn memory_controls(&self) -> MemoryControls {
        self.controls.memory_controls(self.system)
    }
    pub(crate) const fn classes(&self) -> u32 {
        self.classes
    }
    pub(crate) const fn instructions(&self) -> InstructionRequirements {
        self.instructions
    }
}
impl FixedProcessMemoryControls {
    pub(super) fn qualify_shared<'run>(
        &'run self,
        requirements: MemoryRequirements,
        system: &'run SystemState,
    ) -> Result<SharedProcessMemoryAuthorization<'run>, ProcessMemoryError> {
        let unsupported = || ProcessMemoryError::Memory(MemoryStatus::Unsupported);
        let required = requirements.required_instructions;
        if !required.valid() || required.contains(InstructionRequirements::LOR) {
            return Err(unsupported());
        }
        // A legacy raw-control constructor can never manufacture this authority.
        let identification = self.identification.as_deref().ok_or_else(unsupported)?;
        let field = |register| {
            identification
                .read(register)
                .map(|raw| (raw >> FEATURE_SHIFT) & ID_FIELD_MASK)
                .map_err(ProcessMemoryError::Identification)
        };
        let atomic = requirements.required_flags & flags::ATOMIC != 0;
        if atomic != required.contains(InstructionRequirements::LSE) {
            return Err(unsupported());
        }
        if atomic && !matches!(field(Register::IdAa64Isar0El1)?, LSE | LSE128) {
            return Err(unsupported());
        }
        if required.contains(InstructionRequirements::RCPC)
            || required.contains(InstructionRequirements::RCPC2)
        {
            if requirements.required_flags & flags::ORDERED == 0 {
                return Err(unsupported());
            }
            let rcpc = field(Register::IdAa64Isar1El1)?;
            if !matches!(rcpc, RCPC | RCPC2 | RCPC3)
                || required.contains(InstructionRequirements::RCPC2) && rcpc < RCPC2
            {
                return Err(unsupported());
            }
        }
        // nAA permits quantities crossing SCA16. This bounded service deliberately
        // has no such relaxation. A pure DMB body has no data requirement.
        if requirements.required_flags & flags::ORDERED != 0
            && requirements.required_profile & profile_requirements::NATIVE_ACCESS != 0
            && self.sctlr_el1 & SCTLR_NAA != 0
        {
            return Err(unsupported());
        }
        Ok(SharedProcessMemoryAuthorization {
            system,
            controls: self,
            classes: requirements.required_flags
                & (flags::ATOMIC | flags::ORDERED | flags::EXCLUSIVE),
            instructions: required,
        })
    }
}
