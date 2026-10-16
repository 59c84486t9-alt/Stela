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

/// Complete a memory-only MTE instruction. Memory callbacks that succeeded
/// before a later fault stay visible, and no destination or writeback is
/// committed on that path. The backend may not probe later sub-accesses. This
/// deterministic choice is allowed: the architecture leaves non-faulting
/// locations of an aborted multi-access instruction UNKNOWN (DDI0487 M.c
/// RTNVSL) and does not order its data and tag faults (RPJCWS). Address
/// registers and other state are preserved on the fault path.
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
            // STZ2G's descriptor is a pair with Rt == Rt2. Mem32 clears
            // `ispair` for its two 16-byte data accesses; the tag accesses keep
            // it.
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
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Effect {
        Read(Access),
        Tag(Access, AllocationTag),
        Data(Access, [u8; TAG_GRANULE_BYTES]),
    }

    #[derive(Default)]
    struct Observer {
        effects: Vec<Effect>,
        fault_at: Option<usize>,
    }

    impl Observer {
        fn record(&mut self, effect: Effect) -> Result<(), &'static str> {
            if self.fault_at == Some(self.effects.len()) {
                return Err("access fault");
            }
            self.effects.push(effect);
            Ok(())
        }
    }

    impl Memory for Observer {
        type Error = &'static str;

        fn read_tag(&mut self, access: Access) -> Result<AllocationTag, Self::Error> {
            self.record(Effect::Read(access))?;
            Ok(AllocationTag::new(((access.address >> TAG_BITS) & TAG_MASK) as u8).unwrap())
        }

        fn write_tag(&mut self, access: Access, tag: AllocationTag) -> Result<(), Self::Error> {
            self.record(Effect::Tag(access, tag))
        }

        fn write_data16(
            &mut self,
            access: Access,
            data: [u8; TAG_GRANULE_BYTES],
        ) -> Result<(), Self::Error> {
            self.record(Effect::Data(access, data))
        }
    }

    fn profile(privileged: bool, check_sp: bool) -> Profile {
        Profile::new(privileged, check_sp, 64, 64).unwrap()
    }

    fn state() -> GuestState {
        let mut state = GuestState::default();
        state.x.fill(0xa500_0000_0000_2000);
        state.sp = 0xb300_0000_0000_3040;
        state.nzcv = 0xf000_0000;
        state.reserved = 0xa5a5_5a5a;
        state.v.fill([0x1234_5678_9abc_def0, 0xfedc_ba98_7654_3210]);
        state.fpcr = 0x0300_0000;
        state.fpsr = 0x0800_009f;
        state
    }

    fn register(value: u8, sp: bool) -> Register {
        if value == REGISTER_31 {
            if sp { Register::Sp } else { Register::Zero }
        } else {
            Register::X(value)
        }
    }

    #[test]
    fn load_merges_old_destination_and_zero_still_accesses_memory() {
        for destination in [Register::X(0), Register::X(1), Register::Zero] {
            let mut registers = state();
            registers.x[1] = 0xc900_1234_5678_9abc;
            let initial = registers.clone();
            let mut observer = Observer::default();
            let result = complete(
                Operand::LoadTag {
                    destination,
                    base: Register::Sp,
                    displacement: -16,
                },
                &mut registers,
                profile(false, true),
                &mut observer,
            )
            .unwrap();
            assert_eq!(result.effective_address, initial.sp - 16);
            assert_eq!(result.completed.tag_reads, 1);
            let mut expected = initial.clone();
            let tag = AllocationTag::new(3).unwrap();
            write(
                &mut expected,
                destination,
                tag.apply_to_address(read(&initial, destination)),
            );
            assert_eq!(registers, expected);
            assert!(matches!(&observer.effects[..], [Effect::Read(access)]
            if access.address == initial.sp - 16 && !access.tag_checked));
        }
    }

    #[test]
    fn tag_store_all_register_aliases_stage_old_sources_before_writeback() {
        for source in 0..=REGISTER_31 {
            for base in 0..=REGISTER_31 {
                for mode in [
                    AddressMode::Offset,
                    AddressMode::PreIndex,
                    AddressMode::PostIndex,
                ] {
                    for kind in [
                        StoreKind::Tag,
                        StoreKind::TagPair,
                        StoreKind::ZeroTag,
                        StoreKind::ZeroTagPair,
                    ] {
                        let source = register(source, true);
                        let base = register(base, true);
                        let mut registers = state();
                        let initial = registers.clone();
                        let mut observer = Observer::default();
                        complete(
                            Operand::StoreTags {
                                kind,
                                source,
                                base,
                                displacement: -16,
                                mode,
                            },
                            &mut registers,
                            profile(false, true),
                            &mut observer,
                        )
                        .unwrap();
                        let mut expected = initial.clone();
                        writeback(&mut expected, base, read(&initial, base), -16, mode);
                        assert_eq!(registers, expected);
                        let expected_tag = AllocationTag::from_address(read(&initial, source));
                        for effect in &observer.effects {
                            if let Effect::Tag(access, tag) = effect {
                                assert_eq!(*tag, expected_tag);
                                assert_eq!(access.pair, kind == StoreKind::ZeroTagPair);
                                assert!(!access.zero_bulk);
                                assert_eq!(
                                    access.data_registers,
                                    [
                                        Some(index(source)),
                                        if kind == StoreKind::ZeroTagPair {
                                            Some(index(source))
                                        } else {
                                            None
                                        }
                                    ]
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn pair_uses_address_tag_and_snapshots_both_data_aliases() {
        for mode in [
            AddressMode::Offset,
            AddressMode::PreIndex,
            AddressMode::PostIndex,
        ] {
            for data in [
                [Register::X(0), Register::X(0)],
                [Register::X(0), Register::Zero],
                [Register::Zero, Register::X(0)],
            ] {
                let mut registers = state();
                let initial = registers.clone();
                let mut observer = Observer::default();
                complete(
                    Operand::StorePair {
                        data,
                        base: Register::X(0),
                        displacement: 16,
                        mode,
                    },
                    &mut registers,
                    profile(false, true),
                    &mut observer,
                )
                .unwrap();
                let address = effective(initial.x[0], 16, mode);
                let packed = u128::from(read(&initial, data[0]))
                    | (u128::from(read(&initial, data[1])) << u64::BITS);
                assert!(
                    matches!(&observer.effects[..], [Effect::Data(access, bytes), Effect::Tag(tag_access, tag)]
                if *bytes == packed.to_le_bytes() && access.address == address && access.pair
                && tag_access.address == address && *tag == AllocationTag::from_address(address))
                );
                let mut expected = initial.clone();
                writeback(&mut expected, Register::X(0), initial.x[0], 16, mode);
                assert_eq!(registers, expected);
            }
        }
    }

    #[test]
    fn faults_preserve_registers_and_report_actual_successful_callbacks() {
        for operand in [
            Operand::StoreTags {
                kind: StoreKind::ZeroTagPair,
                source: Register::X(0),
                base: Register::X(0),
                displacement: 16,
                mode: AddressMode::PreIndex,
            },
            Operand::StoreTags {
                kind: StoreKind::TagPair,
                source: Register::Sp,
                base: Register::Sp,
                displacement: -16,
                mode: AddressMode::PostIndex,
            },
            Operand::StorePair {
                data: [Register::X(0), Register::X(1)],
                base: Register::X(0),
                displacement: -16,
                mode: AddressMode::PreIndex,
            },
            Operand::BulkTags {
                kind: BulkKind::Load,
                data: Register::X(0),
                base: Register::X(0),
            },
            Operand::BulkTags {
                kind: BulkKind::StoreZero,
                data: Register::X(0),
                base: Register::Sp,
            },
        ] {
            let mut successful = Observer::default();
            complete(operand, &mut state(), profile(true, true), &mut successful).unwrap();
            for fault_at in 0..successful.effects.len() {
                let mut registers = state();
                let initial = registers.clone();
                let mut observer = Observer {
                    effects: Vec::new(),
                    fault_at: Some(fault_at),
                };
                let fault = complete(operand, &mut registers, profile(true, true), &mut observer)
                    .unwrap_err();
                assert_eq!(registers, initial);
                assert_eq!(observer.effects, successful.effects[..fault_at]);
                assert_eq!(
                    fault.completed.tag_reads as usize
                        + fault.completed.tag_writes as usize
                        + fault.completed.data_granules as usize,
                    fault_at
                );
                assert!(matches!(
                    fault.cause,
                    Cause::Access {
                        error: "access fault",
                        ..
                    }
                ));
            }
        }
    }

    #[test]
    fn bulk_load_places_nibbles_by_address_and_commits_after_all_reads() {
        for start in [0, 4, 8, 12] {
            let mut registers = state();
            registers.x[0] = 0xd700_0000_0000_2000 + start * u64::from(TAG_GRANULE_BYTES_U32);
            let initial = registers.clone();
            let mut observer = Observer::default();
            let completion = complete(
                Operand::BulkTags {
                    kind: BulkKind::Load,
                    data: Register::X(0),
                    base: Register::X(0),
                },
                &mut registers,
                profile(true, true),
                &mut observer,
            )
            .unwrap();
            let mut expected = initial;
            expected.x[0] =
                (start..start + 4).fold(0, |value, tag| value | tag << (tag as u32 * TAG_BITS));
            assert_eq!(registers, expected);
            assert_eq!(completion.completed.tag_reads, 4);
            assert_eq!(observer.effects.len(), 4);
        }
    }

    #[test]
    fn privilege_precedes_sp_and_profile_controls_alignment() {
        let mut registers = state();
        registers.sp |= 1;
        let initial = registers.clone();
        let bulk = Operand::BulkTags {
            kind: BulkKind::Load,
            data: Register::X(0),
            base: Register::Sp,
        };
        let mut observer = Observer::default();
        let fault =
            complete(bulk, &mut registers, profile(false, true), &mut observer).unwrap_err();
        assert_eq!(fault.cause, Cause::UndefinedPrivilege);
        let fault = complete(bulk, &mut registers, profile(true, true), &mut observer).unwrap_err();
        assert_eq!(
            fault.cause,
            Cause::StackAlignment {
                stack_pointer: initial.sp
            }
        );
        assert!(observer.effects.is_empty());
        assert_eq!(registers, initial);
        let load = Operand::LoadTag {
            destination: Register::Zero,
            base: Register::Sp,
            displacement: 0,
        };
        let result = complete(load, &mut registers, profile(false, false), &mut observer).unwrap();
        assert_eq!(result.effective_address, initial.sp & !TAG_GRANULE_MASK);
        assert_eq!(registers, initial);
    }

    #[test]
    fn malformed_blocks_are_profile_errors_and_random_tag_is_not_memory() {
        for bytes in [0, 4, 15, 17, 512] {
            assert_eq!(
                Profile::new(false, true, bytes, 64),
                Err(ProfileError::GmidBlockSize)
            );
        }
        for bytes in [0, 4, 15, 17, u32::MAX] {
            assert_eq!(
                Profile::new(false, true, 64, bytes),
                Err(ProfileError::DczidBlockSize)
            );
        }
        let mut registers = state();
        let initial = registers.clone();
        let mut observer = Observer::default();
        let result = complete(
            Operand::RandomTag {
                destination: Register::Sp,
                address: Register::Sp,
                mask: Register::Zero,
            },
            &mut registers,
            profile(false, true),
            &mut observer,
        );
        assert_eq!(result.unwrap_err().cause, Cause::NotMemoryInstruction);
        assert_eq!(registers, initial);
        assert!(observer.effects.is_empty());
    }

    #[test]
    fn malformed_public_operands_leave_every_state_and_callback_untouched() {
        let mut operands = vec![
            Operand::LoadTag {
                destination: Register::Sp,
                base: Register::Sp,
                displacement: 0,
            },
            Operand::StoreTags {
                kind: StoreKind::ZeroTagPair,
                source: Register::Zero,
                base: Register::Sp,
                displacement: 0,
                mode: AddressMode::PreIndex,
            },
            Operand::BulkTags {
                kind: BulkKind::StoreZero,
                data: Register::Sp,
                base: Register::Sp,
            },
            Operand::StorePair {
                data: [Register::Sp, Register::Zero],
                base: Register::Sp,
                displacement: 0,
                mode: AddressMode::PostIndex,
            },
            Operand::StorePair {
                data: [Register::Zero; 2],
                base: Register::Zero,
                displacement: 0,
                mode: AddressMode::Offset,
            },
        ];
        for invalid in REGISTER_31..=u8::MAX {
            operands.push(Operand::LoadTag {
                destination: Register::X(invalid),
                base: Register::Sp,
                displacement: 0,
            });
            operands.push(Operand::BulkTags {
                kind: BulkKind::StoreZero,
                data: Register::Zero,
                base: Register::X(invalid),
            });
        }
        for displacement in [i32::MIN, -1, 1, i32::MAX] {
            operands.push(Operand::LoadTag {
                destination: Register::Zero,
                base: Register::Sp,
                displacement,
            });
            operands.push(Operand::StorePair {
                data: [Register::Zero; 2],
                base: Register::Sp,
                displacement,
                mode: AddressMode::PreIndex,
            });
        }
        for operand in operands {
            let mut registers = state();
            let before = registers.clone();
            let mut observer = Observer::default();
            let fault =
                complete(operand, &mut registers, profile(false, true), &mut observer).unwrap_err();
            assert_eq!(fault.cause, Cause::InvalidOperands);
            assert_eq!(fault.completed, Progress::default());
            assert_eq!(registers, before);
            assert!(observer.effects.is_empty());
        }
    }

    #[test]
    fn zero_tag_pair_preserves_original_tag_descriptor_and_splits_data_pair() {
        let mut registers = state();
        let mut observer = Observer::default();
        complete(
            Operand::StoreTags {
                kind: StoreKind::ZeroTagPair,
                source: Register::Sp,
                base: Register::Sp,
                displacement: 0,
                mode: AddressMode::Offset,
            },
            &mut registers,
            profile(false, true),
            &mut observer,
        )
        .unwrap();
        assert_eq!(observer.effects.len(), 4);
        for (index, effect) in observer.effects.iter().enumerate() {
            let access = match effect {
                Effect::Data(access, _) | Effect::Tag(access, _) => access,
                Effect::Read(_) => panic!("STZ2G must not read tags"),
            };
            assert_eq!(access.pair, index >= 2);
            assert_eq!(access.data_registers, [Some(REGISTER_31); 2]);
        }
    }
}
