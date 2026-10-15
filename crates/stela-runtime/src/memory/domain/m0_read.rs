//! Source metadata and typed failures for a proposed M0 read boundary.
//!
//! These values grant no source, control, physical RAM, PE, ordering or entry
//! authority. The canonical parents must retain all those real loans through
//! translation, actual physical read, checked finalization and once-only commit.
//! This leaf owns no architectural bank, RAM, callback or monitor and performs
//! no memory access. It cannot replace PhysicalAddressSpace or read_descriptor.

use crate::memory::stage1;
use stela_compiler::{
    GuestAddress, GuestState, Lifter,
    aarch64::{
        AddressMode, Decoder, Instruction, MemoryTransfer, Operation, Register, Width, literal,
    },
    context::memory::{MemoryRequirements, SpAlignmentRequirement, flags, profile_requirements},
};

const INSTRUCTION_BYTES: u64 = size_of::<u32>() as u64;
const READ_BYTES: u8 = size_of::<u64>() as u8;
const READ_ALIGNMENT_MASK: u64 = READ_BYTES as u64 - 1;
#[cfg(test)]
const SCTLR_M: u64 = 1 << 0;
#[cfg(test)]
const SCTLR_EE: u64 = 1 << 25;

/// A metadata rejection only. Successful checking does not establish that the
/// snapshot is current, belongs to this PE, or remains stable through the read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(test)]
pub(crate) enum ControlMetadataFailure {
    Stage1Enabled,
    BigEndianEl1Data,
}

/// The real control owner must apply this to the same effective snapshot used
/// by canonical translation, before lending any physical access. Config's M0
/// branch does not validate EE. C/I do not change the M0 data memory type; E0E
/// selects EL0 endianness and cannot substitute for EL1's EE check here.
#[cfg(test)]
pub(crate) fn check_el1_m0_data_controls(
    controls: &stage1::Controls,
) -> Result<(), ControlMetadataFailure> {
    if controls.sctlr_el1 & SCTLR_M != 0 {
        return Err(ControlMetadataFailure::Stage1Enabled);
    }
    if controls.sctlr_el1 & SCTLR_EE != 0 {
        return Err(ControlMetadataFailure::BigEndianEl1Data);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceFailure {
    Decode,
    SourceMismatch,
    UnsupportedShape,
    ContinuationOverflow,
}

/// Typed source metadata, not a permission to issue a physical transaction.
#[derive(Debug)]
pub(crate) struct M0Read64Source {
    pc: GuestAddress,
    word: u32,
    next_pc: GuestAddress,
    destination: Register,
    address: ReadAddress,
}

#[derive(Debug)]
enum ReadAddress {
    Register { base: u8, displacement: i32 },
    Literal(u64),
}

impl M0Read64Source {
    /// Recheck against the common decoder; the real registered CodeRegion must
    /// separately establish that these bytes/PC belong to this actual source.
    pub(crate) fn from_source(instruction: &Instruction, word: u32) -> Result<Self, SourceFailure> {
        let decoded = Decoder
            .lift(instruction.pc, word)
            .map_err(|_| SourceFailure::Decode)?;
        if decoded != *instruction {
            return Err(SourceFailure::SourceMismatch);
        }
        let Operation::Memory {
            transfer:
                MemoryTransfer::Load {
                    signed: false,
                    width: Width::X64,
                },
            bytes: READ_BYTES,
            data,
            base: Register::X(base),
            displacement,
            mode: AddressMode::Offset,
        } = &instruction.operation
        else {
            return Err(SourceFailure::UnsupportedShape);
        };
        if *base >= 31
            || !matches!(data, Register::X(index) if *index < 31) && *data != Register::Zero
        {
            return Err(SourceFailure::UnsupportedShape);
        }
        let next_pc = GuestAddress(
            instruction
                .pc
                .0
                .checked_add(INSTRUCTION_BYTES)
                .ok_or(SourceFailure::ContinuationOverflow)?,
        );
        Ok(Self {
            pc: instruction.pc,
            word,
            next_pc,
            destination: *data,
            address: ReadAddress::Register {
                base: *base,
                displacement: *displacement,
            },
        })
    }

    pub(crate) fn from_el1_integer_source(
        instruction: &Instruction,
        word: u32,
    ) -> Result<Self, SourceFailure> {
        let decoded = Decoder
            .lift(instruction.pc, word)
            .map_err(|_| SourceFailure::Decode)?;
        if decoded != *instruction {
            return Err(SourceFailure::SourceMismatch);
        }
        let Operation::Literal(literal::Operand {
            address,
            transfer:
                literal::Transfer::Integer {
                    destination,
                    width: Width::X64,
                    signed: false,
                },
        }) = instruction.operation
        else {
            return Err(SourceFailure::UnsupportedShape);
        };
        if !matches!(destination, Register::X(index) if index < 31) && destination != Register::Zero
        {
            return Err(SourceFailure::UnsupportedShape);
        }
        Ok(Self {
            pc: instruction.pc,
            word,
            next_pc: GuestAddress(
                instruction
                    .pc
                    .0
                    .checked_add(INSTRUCTION_BYTES)
                    .ok_or(SourceFailure::ContinuationOverflow)?,
            ),
            destination,
            address: ReadAddress::Literal(address),
        })
    }

    pub(crate) fn requirements(&self) -> MemoryRequirements {
        MemoryRequirements {
            required_address_checks: Default::default(),
            required_pointer_arithmetic: None,
            required_flags: match self.address {
                ReadAddress::Register { .. } => flags::TAG_CHECKED,
                ReadAddress::Literal(_) => 0,
            },
            required_host_caps: 0,
            required_profile: profile_requirements::M0_DEVICE_RAM_READ64,
            required_sp_alignment: SpAlignmentRequirement::Any,
        }
    }

    /// Effective AddressAdd behavior requires the canonical profile to exclude
    /// CPA/other unsupported address operations. This computes metadata only.
    pub(crate) fn intent(&self, registers: &GuestState) -> M0Read64Intent {
        M0Read64Intent {
            source_pc: self.pc,
            source_word: self.word,
            next_pc: self.next_pc,
            raw_address: match self.address {
                ReadAddress::Register { base, displacement } => {
                    registers.x[usize::from(base)].wrapping_add_signed(i64::from(displacement))
                }
                ReadAddress::Literal(address) => address,
            },
            flags: self.requirements().required_flags,
            destination: self.destination,
        }
    }
}

/// No references or pointers to RAM or authority. Copying this cannot admit an
/// access; the actual CPU/source/physical parents requalify every reached use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct M0Read64Intent {
    pub(crate) source_pc: GuestAddress,
    pub(crate) source_word: u32,
    pub(crate) next_pc: GuestAddress,
    pub(crate) raw_address: u64,
    pub(crate) flags: u32,
    pub(crate) destination: Register,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MetadataFailure {
    UnalignedLocationNotAdmitted,
    WrongAccess,
    WrongAttributes,
    FabricatedWalkOrPermissions,
    IncompletePhysicalExtent,
}

impl M0Read64Intent {
    /// Compare metadata returned by canonical current-control translation.
    /// Success grants no current control, physical target, read or commit loan.
    pub(crate) fn check_translation(
        self,
        translation: &stage1::Translation,
    ) -> Result<(), MetadataFailure> {
        if self.raw_address & READ_ALIGNMENT_MASK != 0 {
            return Err(MetadataFailure::UnalignedLocationNotAdmitted);
        }
        let access = translation.access();
        if access.kind != stage1::AccessKind::Read
            || access.exception_level != stage1::ExceptionLevel::El1
            || access.raw_virtual_address != self.raw_address
            || access.source_pc != self.source_pc.0
            || !access.aligned
            || access.pan
            || access.uao
        {
            return Err(MetadataFailure::WrongAccess);
        }
        let attributes = translation.attributes();
        if attributes.origin != stage1::AttributeOrigin::MmuDisabled
            || attributes.memory_type != stage1::MemoryType::DeviceNgnrne
            || attributes.mair.is_some()
            || attributes.tagged
            || !attributes.xs
            || attributes.shareability != stage1::Shareability::Outer
            || attributes.guarded_page
        {
            return Err(MetadataFailure::WrongAttributes);
        }
        if translation.walk().is_some() || translation.permissions().is_some() {
            return Err(MetadataFailure::FabricatedWalkOrPermissions);
        }
        if translation.contiguous_bytes() < u64::from(READ_BYTES)
            || translation.physical_address() & READ_ALIGNMENT_MASK != 0
        {
            return Err(MetadataFailure::IncompletePhysicalExtent);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "m0_read/tests.rs"]
mod tests;

// Private implementation remains unregistered until actual producers close.
#[path = "m0_read/ram.rs"]
mod ram;
pub(crate) use ram::{M0RamReadPlatformError, M0RamReadPrepared, prepare_aligned_device_ram8};
