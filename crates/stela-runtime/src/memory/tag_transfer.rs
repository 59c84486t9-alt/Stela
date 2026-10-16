//! Ordering and register commits of MTE tag loads and stores. On an abort the
//! sub-accesses complete sequentially, one of the outcomes Arm permits.
use super::tags::{AllocationTag, TAG_GRANULE_BYTES};
use stela_compiler::{
    GuestState,
    aarch64::{
        AddressMode, Register,
        tag_memory::{BulkKind, Operand, StoreKind},
    },
};

const TAG_GRANULE_BYTES_U32: u32 = TAG_GRANULE_BYTES as u32;
const TAG_GRANULE_MASK: u64 = (TAG_GRANULE_BYTES - 1) as u64;
const TAG_BITS: u32 = 4;
const TAG_COUNT: u32 = 1 << TAG_BITS;
const TAG_MASK: u64 = (TAG_COUNT - 1) as u64;
const REGISTER_31: u8 = 31;
const MAX_GMID_BYTES: u32 = TAG_GRANULE_BYTES_U32 * TAG_COUNT;
const BLOCK_SIZE_FIELD_BITS: u32 = 4;
const BLOCK_SIZE_WORD_BYTES: u32 = 4;
const MAX_DCZID_BYTES: u32 = BLOCK_SIZE_WORD_BYTES << ((1 << BLOCK_SIZE_FIELD_BITS) - 1);
const ZERO_DATA: [u8; TAG_GRANULE_BYTES] = [0; TAG_GRANULE_BYTES];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessKind {
    TagRead,
    TagWrite,
    DataWrite,
}

/// Architectural access inputs, before the backend translates the raw address.
/// Dedicated tag instructions generate unchecked accesses; this does not skip
/// translation, permission, attribute or alignment requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Access {
    pub address: u64,
    pub kind: AccessKind,
    pub privileged: bool,
    pub required_alignment: u8,
    pub pair: bool,
    pub zero_bulk: bool,
    pub data_registers: [Option<u8>; 2],
    pub tag_checked: bool,
}

pub trait Memory {
    type Error;

    fn read_tag(&mut self, access: Access) -> Result<AllocationTag, Self::Error>;
    fn write_tag(&mut self, access: Access, tag: AllocationTag) -> Result<(), Self::Error>;

    /// One aligned, single-copy atomic sixteen-byte Normal WB subaccess. The
    /// backend must not implement this as two independently visible u64 writes.
    fn write_data16(
        &mut self,
        access: Access,
        data: [u8; TAG_GRANULE_BYTES],
    ) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileError {
    GmidBlockSize,
    DczidBlockSize,
}

/// Effective controls supplied by the common CPU/memory context. Tag-access
/// enable and mapping attributes remain backend inputs; disabled ATA still
/// performs the instruction's applicable address and data accesses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile {
    privileged: bool,
    check_sp_alignment: bool,
    gmid_block_bytes: u32,
    dczid_block_bytes: u32,
}

impl Profile {
    pub const fn privileged(self) -> bool {
        self.privileged
    }

    pub const fn new(
        privileged: bool,
        check_sp_alignment: bool,
        gmid_block_bytes: u32,
        dczid_block_bytes: u32,
    ) -> Result<Self, ProfileError> {
        if !valid_block(gmid_block_bytes, MAX_GMID_BYTES) {
            return Err(ProfileError::GmidBlockSize);
        }
        if !valid_block(dczid_block_bytes, MAX_DCZID_BYTES) {
            return Err(ProfileError::DczidBlockSize);
        }
        Ok(Self {
            privileged,
            check_sp_alignment,
            gmid_block_bytes,
            dczid_block_bytes,
        })
    }
}

const fn valid_block(bytes: u32, maximum: u32) -> bool {
    bytes >= TAG_GRANULE_BYTES_U32 && bytes <= maximum && bytes.is_power_of_two()
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Progress {
    pub tag_reads: u32,
    pub tag_writes: u32,
    pub data_granules: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cause<E> {
    NotMemoryInstruction,
    UndefinedPrivilege,
    StackAlignment {
        stack_pointer: u64,
    },
    DataAlignment {
        address: u64,
    },
    Access {
        access: Access,
        error: E,
    },
    /// An unavailable backend requirement, before guest memory effects.
    Platform(E),
    InvalidOperands,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fault<E> {
    pub cause: Cause<E>,
    pub completed: Progress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Completion {
    pub effective_address: u64,
    pub completed: Progress,
}

struct Executor<'a, M: Memory> {
    memory: &'a mut M,
    profile: Profile,
    pair: bool,
    data_pair: bool,
    zero_bulk: bool,
    data_registers: [Option<u8>; 2],
    completed: Progress,
}

impl<M: Memory> Executor<'_, M> {
    fn fault(&self, cause: Cause<M::Error>) -> Fault<M::Error> {
        Fault {
            cause,
            completed: self.completed,
        }
    }

    fn descriptor(&self, address: u64, kind: AccessKind) -> Access {
        Access {
            address,
            kind,
            privileged: self.profile.privileged,
            required_alignment: TAG_GRANULE_BYTES as u8,
            pair: if kind == AccessKind::DataWrite {
                self.data_pair
            } else {
                self.pair
            },
            zero_bulk: self.zero_bulk,
            data_registers: self.data_registers,
            tag_checked: false,
        }
    }

    fn read_tag(&mut self, address: u64) -> Result<AllocationTag, Fault<M::Error>> {
        let access = self.descriptor(address, AccessKind::TagRead);
        let tag = self
            .memory
            .read_tag(access)
            .map_err(|error| self.fault(Cause::Access { access, error }))?;
        self.completed.tag_reads += 1;
        Ok(tag)
    }

    fn write_tag(&mut self, address: u64, tag: AllocationTag) -> Result<(), Fault<M::Error>> {
        let access = self.descriptor(address, AccessKind::TagWrite);
        self.memory
            .write_tag(access, tag)
            .map_err(|error| self.fault(Cause::Access { access, error }))?;
        self.completed.tag_writes += 1;
        Ok(())
    }

    fn write_data16(
        &mut self,
        address: u64,
        data: [u8; TAG_GRANULE_BYTES],
    ) -> Result<(), Fault<M::Error>> {
        let access = self.descriptor(address, AccessKind::DataWrite);
        self.memory
            .write_data16(access, data)
            .map_err(|error| self.fault(Cause::Access { access, error }))?;
        self.completed.data_granules += 1;
        Ok(())
    }

    fn base(&self, registers: &GuestState, base: Register) -> Result<u64, Fault<M::Error>> {
        let address = read(registers, base);
        if self.profile.check_sp_alignment
            && base == Register::Sp
            && address & TAG_GRANULE_MASK != 0
        {
            return Err(self.fault(Cause::StackAlignment {
                stack_pointer: address,
            }));
        }
        Ok(address)
    }

    fn aligned(&self, address: u64) -> Result<(), Fault<M::Error>> {
        if address & TAG_GRANULE_MASK != 0 {
            return Err(self.fault(Cause::DataAlignment { address }));
        }
        Ok(())
    }
}

/// Complete a memory-only MTE instruction. Successful earlier memory callbacks
/// remain observable after a later fault; no destination or writeback is committed
/// on that path. The backend may not probe future subaccesses on this helper's
/// behalf. This is an allowed deterministic implementation policy, not a claim
/// that Arm requires a completed prefix: DDI0487M.c RTNVSL permits UNKNOWN
/// outcomes for nonfaulting locations of an aborted multi-SCA instruction, and
/// RPJCWS does not order its separate data/tag MMU faults. Address-calculation
/// registers and undeclared state remain preserved on this helper's fault path.
pub fn complete<M: Memory>(
    operand: Operand,
    registers: &mut GuestState,
    profile: Profile,
    memory: &mut M,
) -> Result<Completion, Fault<M::Error>> {
    if !operand.is_valid() {
        return Err(Fault {
            cause: Cause::InvalidOperands,
            completed: Progress::default(),
        });
    }
    let (pair, data_pair, zero_bulk, data_registers) = match operand {
        Operand::RandomTag { .. } => {
            return Err(Fault {
                cause: Cause::NotMemoryInstruction,
                completed: Progress::default(),
            });
        }
        Operand::LoadTag { destination, .. } => {
            (false, false, false, [Some(index(destination)), None])
        }
        Operand::StoreTags { kind, source, .. } => {
            // STZ2G has an original pair descriptor with Rt == Rt2. Mem32
            // clears ispair for its two SCA16 data subaccesses; tags retain it.
            let pair = kind == StoreKind::ZeroTagPair;
            (
                pair,
                false,
                false,
                [
                    Some(index(source)),
                    if pair { Some(index(source)) } else { None },
                ],
            )
        }
        Operand::BulkTags { kind, data, .. } => (
            false,
            false,
            kind == BulkKind::StoreZero,
            [Some(index(data)), None],
        ),
        Operand::StorePair { data, .. } => (
            true,
            true,
            false,
            [Some(index(data[0])), Some(index(data[1]))],
        ),
    };
    let mut executor = Executor {
        memory,
        profile,
        pair,
        data_pair,
        zero_bulk,
        data_registers,
        completed: Progress::default(),
    };
    if operand.requires_privilege() && !profile.privileged {
        return Err(executor.fault(Cause::UndefinedPrivilege));
    }
    let effective_address = match operand {
        Operand::RandomTag { .. } => {
            unreachable!("random-tag operands return before memory execution")
        }
        Operand::LoadTag {
            destination,
            base,
            displacement,
        } => {
            let original = read(registers, destination);
            let address = executor
                .base(registers, base)?
                .wrapping_add_signed(i64::from(displacement))
                & !TAG_GRANULE_MASK;
            let tag = executor.read_tag(address)?;
            write(registers, destination, tag.apply_to_address(original));
            address
        }
        Operand::StoreTags {
            kind,
            source,
            base,
            displacement,
            mode,
        } => {
            let original_base = executor.base(registers, base)?;
            let tag = AllocationTag::from_address(read(registers, source));
            let address = effective(original_base, displacement, mode);
            executor.aligned(address)?;
            let paired = matches!(kind, StoreKind::TagPair | StoreKind::ZeroTagPair);
            if matches!(kind, StoreKind::ZeroTag | StoreKind::ZeroTagPair) {
                executor.write_data16(address, ZERO_DATA)?;
                if paired {
                    executor.write_data16(
                        address.wrapping_add(u64::from(TAG_GRANULE_BYTES_U32)),
                        ZERO_DATA,
                    )?;
                }
            }
            executor.write_tag(address, tag)?;
            if paired {
                executor.write_tag(address.wrapping_add(u64::from(TAG_GRANULE_BYTES_U32)), tag)?;
            }
            writeback(registers, base, original_base, displacement, mode);
            address
        }
        Operand::StorePair {
            data,
            base,
            displacement,
            mode,
        } => {
            let original_base = executor.base(registers, base)?;
            let first = read(registers, data[0]);
            let second = read(registers, data[1]);
            let address = effective(original_base, displacement, mode);
            executor.aligned(address)?;
            let packed = u128::from(first) | (u128::from(second) << u64::BITS);
            executor.write_data16(address, packed.to_le_bytes())?;
            executor.write_tag(address, AllocationTag::from_address(address))?;
            writeback(registers, base, original_base, displacement, mode);
            address
        }
        Operand::BulkTags { kind, data, base } => {
            let original_base = executor.base(registers, base)?;
            let source = read(registers, data);
            let bytes = if kind == BulkKind::StoreZero {
                profile.dczid_block_bytes
            } else {
                profile.gmid_block_bytes
            };
            let address = original_base & !u64::from(bytes - 1);
            let mut loaded = 0_u64;
            for offset in (0..bytes).step_by(TAG_GRANULE_BYTES) {
                let current = address.wrapping_add(u64::from(offset));
                let shift =
                    ((current / u64::from(TAG_GRANULE_BYTES_U32)) & TAG_MASK) as u32 * TAG_BITS;
                match kind {
                    BulkKind::Load => {
                        loaded |= u64::from(executor.read_tag(current)?.value()) << shift;
                    }
                    BulkKind::Store => {
                        let value = ((source >> shift) & TAG_MASK) as u8;
                        executor
                            .write_tag(current, AllocationTag::new(value).expect("masked tag"))?;
                    }
                    BulkKind::StoreZero => {
                        let value = (source & TAG_MASK) as u8;
                        executor
                            .write_tag(current, AllocationTag::new(value).expect("masked tag"))?;
                        executor.write_data16(current, ZERO_DATA)?;
                    }
                }
            }
            if kind == BulkKind::Load {
                write(registers, data, loaded);
            }
            address
        }
    };
    Ok(Completion {
        effective_address,
        completed: executor.completed,
    })
}

fn index(register: Register) -> u8 {
    match register {
        Register::X(index) => index,
        Register::Sp | Register::Zero => REGISTER_31,
    }
}

fn read(registers: &GuestState, register: Register) -> u64 {
    match register {
        Register::X(index) => registers.x[usize::from(index)],
        Register::Sp => registers.sp,
        Register::Zero => 0,
    }
}

fn write(registers: &mut GuestState, register: Register, value: u64) {
    match register {
        Register::X(index) => registers.x[usize::from(index)] = value,
        Register::Sp => registers.sp = value,
        Register::Zero => {}
    }
}

fn effective(base: u64, displacement: i32, mode: AddressMode) -> u64 {
    if mode == AddressMode::PostIndex {
        base
    } else {
        base.wrapping_add_signed(i64::from(displacement))
    }
}

fn writeback(
    registers: &mut GuestState,
    base: Register,
    original: u64,
    displacement: i32,
    mode: AddressMode,
) {
    if mode != AddressMode::Offset {
        write(
            registers,
            base,
            original.wrapping_add_signed(i64::from(displacement)),
        );
    }
}

#[cfg(test)]
mod tests;
