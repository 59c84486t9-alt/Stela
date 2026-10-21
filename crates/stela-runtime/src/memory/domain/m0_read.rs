//! Source metadata and failures of the M0 read.

pub(crate) mod pair;
mod pair_ram;
#[cfg(all(test, target_arch = "x86_64"))]
pub(crate) use pair_ram::tests as pair_read_fixtures;
pub(crate) use pair_ram::{
    M0RamPairReadPlatformError, M0RamPairReadPrepared, M0RamPairReadProgress,
    prepare_aligned_device_ram8_pair,
};

use crate::memory::stage1;
use stela_compiler::{
    GuestAddress, GuestState,
    aarch64::{AddressMode, Instruction, MemoryTransfer, Operation, Register, Width, literal},
    context::memory::{MemoryRequirements, SpAlignmentRequirement, flags, profile_requirements},
};

const INSTRUCTION_BYTES: u64 = size_of::<u32>() as u64;
const READ_BYTES: u8 = size_of::<u64>() as u8;
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

/// The control owner applies this to the same snapshot used for translation,
/// before any physical access. C and I do not change the M0 data memory type;
/// E0E selects EL0 endianness and does not replace EL1's EE check.
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
    SourceMismatch,
    UnsupportedShape,
    ContinuationOverflow,
}

/// Typed source metadata, not a permission to issue a physical transaction.
#[derive(Debug)]
pub(crate) struct M0ScalarReadSource {
    pc: GuestAddress,
    word: u32,
    next_pc: GuestAddress,
    destination: Register,
    address: ReadAddress,
}

#[derive(Debug)]
enum ReadAddress {
    Scalar(stela_compiler::block::el1_platform::ScalarLoad),
    Register { base: u8, displacement: i32 },
    Literal(u64),
}

impl M0ScalarReadSource {
    /// `instruction` is the common decoder's lift of `word`; the registered
    /// CodeRegion separately establishes that these bytes belong to the source.
    pub(crate) fn from_source(instruction: &Instruction, word: u32) -> Result<Self, SourceFailure> {
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
        if let ReadAddress::Scalar(load) = self.address {
            return load.requirements();
        }
        MemoryRequirements {
            required_address_checks: Default::default(),
            required_pointer_arithmetic: None,
            required_flags: match self.address {
                ReadAddress::Register { .. } => flags::TAG_CHECKED,
                ReadAddress::Literal(_) => 0,
                ReadAddress::Scalar(_) => unreachable!("scalar requirements returned above"),
            },
            required_host_caps: 0,
            required_profile: profile_requirements::M0_DEVICE_RAM_READ64,
            required_sp_alignment: SpAlignmentRequirement::Any,
            ..MemoryRequirements::default()
        }
    }

    /// AddressAdd behavior assumes the profile excludes FEAT_CPA and other
    /// unsupported address operations.
    pub(crate) fn intent(&self, registers: &GuestState) -> M0ScalarReadIntent {
        if let ReadAddress::Scalar(load) = self.address {
            return scalar::intent(load, self.word, registers);
        }
        M0ScalarReadIntent {
            source_pc: self.pc,
            source_word: self.word,
            next_pc: self.next_pc,
            raw_address: match self.address {
                ReadAddress::Register { base, displacement } => {
                    registers.x[usize::from(base)].wrapping_add_signed(i64::from(displacement))
                }
                ReadAddress::Literal(address) => address,
                ReadAddress::Scalar(_) => unreachable!("scalar intent returned above"),
            },
            flags: self.requirements().required_flags,
            destination: self.destination,
            bytes: READ_BYTES,
            stack_pointer: None,
            writeback: None,
        }
    }
}

/// Holds no references to RAM; the CPU, source and physical owners re-check
/// every use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct M0ScalarReadIntent {
    pub(crate) source_pc: GuestAddress,
    pub(crate) source_word: u32,
    pub(crate) next_pc: GuestAddress,
    pub(crate) raw_address: u64,
    pub(crate) flags: u32,
    pub(crate) destination: Register,
    pub(crate) bytes: u8,
    pub(crate) stack_pointer: Option<u64>,
    pub(crate) writeback: Option<(Register, u64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MetadataFailure {
    UnalignedLocationNotAdmitted,
    WrongAccess,
    WrongAttributes,
    FabricatedWalkOrPermissions,
    IncompletePhysicalExtent,
}

impl M0ScalarReadIntent {
    /// Compare with the metadata returned by translation under the current
    /// controls.
    pub(crate) fn check_translation(
        self,
        translation: &stage1::Translation,
    ) -> Result<(), MetadataFailure> {
        if !matches!(self.bytes, 1 | 2 | 4 | 8)
            || self.raw_address & (u64::from(self.bytes) - 1) != 0
        {
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
        if translation.contiguous_bytes() < u64::from(self.bytes)
            || translation.physical_address() & (u64::from(self.bytes) - 1) != 0
        {
            return Err(MetadataFailure::IncompletePhysicalExtent);
        }
        Ok(())
    }
}

mod ram;
pub(crate) use ram::{
    M0RamReadPlatformError, M0RamReadPrepared, prepare_aligned_device_ram_scalar,
};

mod scalar;

#[cfg(test)]
mod tests {
    use super::{ControlMetadataFailure, SCTLR_EE, SCTLR_M, check_el1_m0_data_controls};
    use crate::memory::stage1::Controls;

    const SCTLR_C: u64 = 1 << 2;
    const SCTLR_I: u64 = 1 << 12;
    const SCTLR_E0E: u64 = 1 << 24;

    fn snapshot(sctlr_el1: u64) -> Controls {
        Controls {
            ttbr0_el1: 0,
            ttbr1_el1: 0,
            tcr_el1: 0,
            sctlr_el1,
            mair_el1: 0,
        }
    }

    #[test]
    fn m0_el1_big_endian_metadata_is_refused_for_all_cache_controls() {
        for caches in [0, SCTLR_C, SCTLR_I, SCTLR_C | SCTLR_I] {
            assert_eq!(
                check_el1_m0_data_controls(&snapshot(caches | SCTLR_EE)),
                Err(ControlMetadataFailure::BigEndianEl1Data),
            );
            assert_eq!(check_el1_m0_data_controls(&snapshot(caches)), Ok(()));
            assert_eq!(
                check_el1_m0_data_controls(&snapshot(caches | SCTLR_E0E)),
                Ok(()),
            );
        }
    }

    #[test]
    fn enabled_stage1_cannot_enter_m0_metadata_profile() {
        assert_eq!(
            check_el1_m0_data_controls(&snapshot(SCTLR_M)),
            Err(ControlMetadataFailure::Stage1Enabled),
        );
    }
}
