//! Checked LDP/LDPSW/STP/LDNP/STNP as one pair request to the memory service.
//! Load destinations and base writeback are written only after both elements
//! succeed.

use crate::{
    aarch64::{AddressMode, MemoryTransfer, Operation, Register, Width, non_temporal::Data},
    block::CheckedMemoryProfile,
    context::memory::{
        MemoryRequirements, SpAlignmentRequirement, flags, host_caps, profile_requirements,
    },
    x86_64::{
        load,
        memory_context::{self as memory, address},
        store,
    },
};
use alloc::vec::Vec;

const WORD_BYTES: u8 = size_of::<u32>() as u8;
const DOUBLEWORD_BYTES: u8 = size_of::<u64>() as u8;
const PAIR_MEMBERS: u8 = 2;
const DOUBLEWORD_PAIR_BYTES: u8 = PAIR_MEMBERS * DOUBLEWORD_BYTES;
const REGISTER_COUNT: u8 = 31;
const IMMEDIATE_MIN: i32 = -64;
const IMMEDIATE_MAX: i32 = 63;
const REQUEST_OFFSET: u32 = 0;
const DATA_OFFSET: u32 = crate::context::memory::MEMORY_REQUEST_BYTES as u32;
const WRITEBACK_OFFSET: u32 = DATA_OFFSET + (PAIR_MEMBERS * DOUBLEWORD_BYTES) as u32;
const STACK_ALIGNMENT_BYTES: u32 = 16;
const STACK_BYTES: u32 = (WRITEBACK_OFFSET + size_of::<u64>() as u32)
    .div_ceil(STACK_ALIGNMENT_BYTES)
    * STACK_ALIGNMENT_BYTES;
const SUB_RSP_IMM8: &[u8] = &[0x48, 0x83, 0xec];
const ADD_RSP_IMM8: &[u8] = &[0x48, 0x83, 0xc4];
const MOV_RSP_DISP8_EAX: &[u8] = &[0x89, 0x44, 0x24];
const MOV_RSP_DISP8_RAX: &[u8] = &[0x48, 0x89, 0x44, 0x24];
const MOV_RAX_RSP_DISP8: &[u8] = &[0x48, 0x8b, 0x44, 0x24];
const MOV_RSP_DISP8_RDX: &[u8] = &[0x48, 0x89, 0x54, 0x24];
const REX_W: u8 = 0x48;
const MOV_FROM_STAGING: u8 = 0x8b;
const MOVSXD_FROM_STAGING: u8 = 0x63;
const RAX_RSP_DISP8: &[u8] = &[0x44, 0x24];
const XOR_EAX_EAX: &[u8] = &[0x31, 0xc0];

/// Validated source operands, shared by temporal and non-temporal GPR pairs.
/// Source-permitted constrained NOP encodings are decoded as Operation::Nop
/// before this adapter; constructed overlapping writeback operands decline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Operand {
    profile: Profile,
    transfer: MemoryTransfer,
    bytes: u8,
    data: [Register; 2],
    base: Register,
    displacement: i32,
    mode: AddressMode,
    non_temporal: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Profile {
    NormalWb(CheckedMemoryProfile),
}

impl Operand {
    pub(crate) fn profile_success_traffic(&self) -> crate::block::profile::RegisterTraffic {
        let real_data = self
            .data
            .iter()
            .filter(|register| **register != Register::Zero)
            .count() as u64;
        crate::block::profile::RegisterTraffic {
            gpr_frame_loads: 1
                + u64::from(self.transfer == MemoryTransfer::Store) * real_data
                + u64::from(
                    self.base == Register::Sp
                        && matches!(self.profile,
                    Profile::NormalWb(profile) if profile.sp_requirement() == SpAlignmentRequirement::Enabled),
                ),
            gpr_direct_stores: u64::from(matches!(self.transfer, MemoryTransfer::Load { .. }))
                * real_data
                + u64::from(self.mode != AddressMode::Offset),
            ..Default::default()
        }
    }

    pub(crate) fn from_operation(
        operation: &Operation,
        profile: CheckedMemoryProfile,
    ) -> Option<Self> {
        let operand = match operation {
            Operation::MemoryPair {
                transfer,
                bytes,
                data,
                base,
                displacement,
                mode,
            } => Self {
                profile: Profile::NormalWb(profile),
                transfer: *transfer,
                bytes: *bytes,
                data: *data,
                base: *base,
                displacement: *displacement,
                mode: *mode,
                non_temporal: false,
            },
            Operation::MemoryNonTemporal(operand) => {
                let Data::Integer(data) = operand.data else {
                    return None;
                };
                Self {
                    profile: Profile::NormalWb(profile),
                    transfer: if operand.load {
                        MemoryTransfer::Load {
                            signed: false,
                            width: if operand.bytes == WORD_BYTES {
                                Width::W32
                            } else {
                                Width::X64
                            },
                        }
                    } else {
                        MemoryTransfer::Store
                    },
                    bytes: operand.bytes,
                    data,
                    base: operand.base,
                    displacement: operand.displacement,
                    mode: AddressMode::Offset,
                    non_temporal: true,
                }
            }
            _ => return None,
        };
        operand.is_valid().then_some(operand)
    }

    fn is_valid(self) -> bool {
        let data_valid = self.data.into_iter().all(|register| {
            matches!(register, Register::X(index) if index < REGISTER_COUNT)
                || register == Register::Zero
        });
        let base_valid = matches!(self.base, Register::X(index) if index < REGISTER_COUNT)
            || self.base == Register::Sp;
        let overlap = self.mode != AddressMode::Offset
            && self.base != Register::Sp
            && self.data.contains(&self.base);
        let transfer_valid = match self.transfer {
            MemoryTransfer::Store => true,
            MemoryTransfer::Load { signed, width } => {
                self.data[0] != self.data[1]
                    && matches!(
                        (self.bytes, signed, width),
                        (WORD_BYTES, false, Width::W32)
                            | (DOUBLEWORD_BYTES, false, Width::X64)
                            | (WORD_BYTES, true, Width::X64)
                    )
                    && !(self.non_temporal && signed)
            }
        };
        matches!(self.bytes, WORD_BYTES | DOUBLEWORD_BYTES)
            && transfer_valid
            && data_valid
            && base_valid
            && !overlap
            && self.displacement % i32::from(self.bytes) == 0
            && (IMMEDIATE_MIN..=IMMEDIATE_MAX)
                .contains(&(self.displacement / i32::from(self.bytes)))
    }

    fn flags(self) -> u32 {
        (if self.transfer == MemoryTransfer::Store {
            flags::WRITE
        } else {
            0
        }) | flags::PAIR
            | if self.mode != AddressMode::Offset || self.base != Register::Sp {
                flags::TAG_CHECKED
            } else {
                0
            }
            | if self.non_temporal {
                flags::NON_TEMPORAL
            } else {
                0
            }
    }
}

/// Loads conservatively require the 16-byte read-only snapshot. X-register pair
/// stores that may reach one 16-byte quantity need CMPXCHG16B first. With SP
/// alignment checked and an offset of 8 modulo 16, offset and pre-index forms
/// touch two separate 8-byte halves; post-index uses the unmodified SP. Without
/// SP checks every X pair needs CMPXCHG16B.
pub(crate) fn requirements(operand: &Operand) -> MemoryRequirements {
    let required_flags = operand.flags();
    let Profile::NormalWb(profile) = operand.profile;
    MemoryRequirements {
        required_pointer_arithmetic: None,
        required_address_checks: profile.address_requirements(false),
        required_flags,
        required_host_caps: if matches!(operand.transfer, MemoryTransfer::Load { .. }) {
            // Reads may cross an 8-byte boundary within a 16-byte quantity. The
            // read-only snapshot capability is separate from CMPXCHG16B.
            host_caps::ATOMIC_LOAD16
        } else if operand.bytes == DOUBLEWORD_BYTES
            && (operand.base != Register::Sp
                || profile.sp_requirement() == SpAlignmentRequirement::Disabled
                || operand.mode == AddressMode::PostIndex
                || operand.displacement % i32::from(DOUBLEWORD_PAIR_BYTES) == 0)
        {
            host_caps::CX16
        } else {
            0
        },
        required_profile: profile_requirements::NATIVE_ACCESS
            | if required_flags & flags::TAG_CHECKED != 0 {
                profile_requirements::TAG_GRANULES
            } else {
                0
            },
        required_sp_alignment: if operand.base == Register::Sp {
            profile.sp_requirement()
        } else {
            SpAlignmentRequirement::Any
        },
        ..MemoryRequirements::default()
    }
}

fn save_source(code: &mut Vec<u8>, register: Register, bytes: u8, destination: u32) {
    load(code, register);
    code.extend(if bytes == WORD_BYTES {
        MOV_RSP_DISP8_EAX
    } else {
        MOV_RSP_DISP8_RAX
    });
    code.push(u8::try_from(destination).expect("pair private staging fits disp8"));
}

/// Read the private callback output with the source extension semantics.
fn load_result(code: &mut Vec<u8>, bytes: u8, signed: bool, width: Width, source: u32) {
    if width == Width::X64 {
        code.push(REX_W);
    }
    code.push(if signed {
        MOVSXD_FROM_STAGING
    } else {
        MOV_FROM_STAGING
    });
    debug_assert!(matches!(
        (bytes, signed),
        (WORD_BYTES, true) | (WORD_BYTES | DOUBLEWORD_BYTES, false)
    ));
    code.extend(RAX_RSP_DISP8);
    code.push(u8::try_from(source).expect("pair private staging fits disp8"));
}

/// Emit an inner checked-context body. The caller has validated the descriptor,
/// memory profile, capabilities and effective SP-alignment controls. RDI points
/// to GuestState and R15 to ExecutionContext; callback failures leave completed
/// RAM prefixes visible and return through the enclosing context wrapper.
pub(crate) fn emit_context(code: &mut Vec<u8>, operand: &Operand, pc: u64) {
    debug_assert!(operand.is_valid());
    code.extend(SUB_RSP_IMM8);
    code.push(STACK_BYTES as u8);
    memory::begin(code);
    let sp_failure = if matches!(operand.profile, Profile::NormalWb(profile)
        if profile.sp_requirement() == SpAlignmentRequirement::Enabled)
    {
        address::check_sp(code, operand.base, pc)
    } else {
        None
    };

    if operand.transfer == MemoryTransfer::Store {
        for (member, register) in operand.data.into_iter().enumerate() {
            save_source(
                code,
                register,
                operand.bytes,
                DATA_OFFSET + member as u32 * u32::from(operand.bytes),
            );
        }
    }
    address::immediate_with_checks(
        code,
        operand.base,
        operand.displacement,
        operand.mode,
        match operand.profile {
            Profile::NormalWb(profile) => profile.address_checks(false),
        },
    );
    if operand.mode != AddressMode::Offset {
        code.extend(MOV_RSP_DISP8_RDX);
        code.push(WRITEBACK_OFFSET as u8);
    }
    memory::request(
        code,
        REQUEST_OFFSET,
        DATA_OFFSET,
        u32::from(operand.bytes * PAIR_MEMBERS),
        operand.flags(),
        pc,
    );
    memory::call(code, REQUEST_OFFSET);
    let callback_failure = memory::branch_failed(code);
    if let MemoryTransfer::Load { signed, width } = operand.transfer {
        for (member, register) in operand.data.into_iter().enumerate() {
            if register == Register::Zero {
                continue;
            }
            load_result(
                code,
                operand.bytes,
                signed,
                width,
                DATA_OFFSET + member as u32 * u32::from(operand.bytes),
            );
            store(code, register);
        }
    }
    if operand.mode != AddressMode::Offset {
        code.extend(MOV_RAX_RSP_DISP8);
        code.push(WRITEBACK_OFFSET as u8);
        // A validated base is never ZR; no source is re-read after callback.
        store(code, operand.base);
    }
    code.extend(XOR_EAX_EAX);
    let cleanup = code.len();
    memory::patch_branch(code, callback_failure, cleanup);
    if let Some(failure) = sp_failure {
        memory::patch_branch(code, failure, cleanup);
    }
    code.extend(ADD_RSP_IMM8);
    code.push(STACK_BYTES as u8);
    address::return_if_failed(code);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GuestAddress, Lifter, aarch64::Decoder};

    const TEST_PC: u64 = 0x1000;
    const STP_W_OFFSET: u32 = 0x2900_0000;
    const STP_W_PRE: u32 = 0x2980_0000;
    const STP_W_POST: u32 = 0x2880_0000;
    const STP_X_OFFSET: u32 = 0xa900_0000;
    const STP_X_PRE: u32 = 0xa980_0000;
    const STP_X_POST: u32 = 0xa880_0000;
    const STNP_W: u32 = 0x2800_0000;
    const STNP_X: u32 = 0xa800_0000;
    const REGISTER_MASK: u32 = 31;
    const BASE_SHIFT: u32 = 5;
    const SECOND_DATA_SHIFT: u32 = 10;
    const IMMEDIATE_SHIFT: u32 = 15;
    const IMMEDIATE_MASK: u32 = 127;
    const FORMS: [(u32, u8, AddressMode, bool); 8] = [
        (STP_W_OFFSET, WORD_BYTES, AddressMode::Offset, false),
        (STP_W_PRE, WORD_BYTES, AddressMode::PreIndex, false),
        (STP_W_POST, WORD_BYTES, AddressMode::PostIndex, false),
        (STP_X_OFFSET, DOUBLEWORD_BYTES, AddressMode::Offset, false),
        (STP_X_PRE, DOUBLEWORD_BYTES, AddressMode::PreIndex, false),
        (STP_X_POST, DOUBLEWORD_BYTES, AddressMode::PostIndex, false),
        (STNP_W, WORD_BYTES, AddressMode::Offset, true),
        (STNP_X, DOUBLEWORD_BYTES, AddressMode::Offset, true),
    ];

    fn word(form: u32, data: [u32; 2], base: u32, immediate: i32) -> u32 {
        form | data[0]
            | (base << BASE_SHIFT)
            | (data[1] << SECOND_DATA_SHIFT)
            | ((immediate as u32 & IMMEDIATE_MASK) << IMMEDIATE_SHIFT)
    }

    fn lifted(word: u32) -> Operation {
        Decoder.lift(GuestAddress(TEST_PC), word).unwrap().operation
    }

    #[test]
    fn allocated_pair_stores_retain_register_roles_and_descriptor_intent() {
        for (form, bytes, mode, non_temporal) in FORMS {
            for data in [
                [0, 1],
                [1, 1],
                [30, 0],
                [REGISTER_MASK, 0],
                [0, REGISTER_MASK],
                [REGISTER_MASK; 2],
            ] {
                for base in [2, 30, REGISTER_MASK] {
                    for immediate in [IMMEDIATE_MIN, -1, 0, 1, IMMEDIATE_MAX] {
                        let operation = lifted(word(form, data, base, immediate));
                        if mode != AddressMode::Offset
                            && base != REGISTER_MASK
                            && data.contains(&base)
                        {
                            assert_eq!(operation, Operation::Nop);
                            continue;
                        }
                        let operand = Operand::from_operation(
                            &operation,
                            CheckedMemoryProfile::SpAlignmentEnabled,
                        )
                        .unwrap();
                        assert_eq!(operand.bytes, bytes);
                        assert_eq!(operand.mode, mode);
                        assert_eq!(operand.non_temporal, non_temporal);
                        assert_eq!(operand.displacement, immediate * i32::from(bytes));
                        assert_eq!(operand.base == Register::Sp, base == REGISTER_MASK);
                        for (actual, encoded) in operand.data.into_iter().zip(data) {
                            assert_eq!(
                                actual,
                                if encoded == REGISTER_MASK {
                                    Register::Zero
                                } else {
                                    Register::X(encoded as u8)
                                }
                            );
                        }
                        let required = requirements(&operand);
                        assert_eq!(
                            required.required_flags & (flags::WRITE | flags::PAIR),
                            flags::WRITE | flags::PAIR
                        );
                        assert_eq!(
                            required.required_flags & flags::NON_TEMPORAL != 0,
                            non_temporal
                        );
                        assert_eq!(
                            required.required_flags & flags::TAG_CHECKED != 0,
                            mode != AddressMode::Offset || base != REGISTER_MASK
                        );
                        assert_eq!(
                            required.required_host_caps,
                            if bytes == DOUBLEWORD_BYTES
                                && (base != REGISTER_MASK
                                    || mode == AddressMode::PostIndex
                                    || immediate & 1 == 0)
                            {
                                host_caps::CX16
                            } else {
                                0
                            }
                        );
                        assert_eq!(
                            required.required_sp_alignment,
                            if base == REGISTER_MASK {
                                SpAlignmentRequirement::Enabled
                            } else {
                                SpAlignmentRequirement::Any
                            }
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn constrained_writeback_nops_never_enter_pair_service() {
        for form in [STP_W_PRE, STP_W_POST, STP_X_PRE, STP_X_POST] {
            for base in 0..REGISTER_MASK {
                for data in [[base, 0], [0, base], [base, base]] {
                    let operation = lifted(word(form, data, base, 1));
                    assert_eq!(operation, Operation::Nop);
                    assert_eq!(
                        Operand::from_operation(
                            &operation,
                            CheckedMemoryProfile::SpAlignmentEnabled
                        ),
                        None
                    );
                }
            }
        }
    }

    #[test]
    fn forged_store_descriptors_decline_before_emission() {
        let valid = Operand {
            profile: Profile::NormalWb(CheckedMemoryProfile::SpAlignmentEnabled),
            transfer: MemoryTransfer::Store,
            bytes: DOUBLEWORD_BYTES,
            data: [Register::X(0), Register::Zero],
            base: Register::X(2),
            displacement: 0,
            mode: AddressMode::PreIndex,
            non_temporal: false,
        };
        assert!(valid.is_valid());
        for invalid in [
            Operand { bytes: 0, ..valid },
            Operand {
                bytes: WORD_BYTES / 2,
                ..valid
            },
            Operand {
                data: [Register::Sp, Register::Zero],
                ..valid
            },
            Operand {
                data: [Register::X(REGISTER_COUNT), Register::Zero],
                ..valid
            },
            Operand {
                base: Register::Zero,
                ..valid
            },
            Operand {
                base: Register::X(REGISTER_COUNT),
                ..valid
            },
            Operand {
                base: Register::X(0),
                ..valid
            },
            Operand {
                displacement: 1,
                ..valid
            },
            Operand {
                displacement: (IMMEDIATE_MAX + 1) * i32::from(DOUBLEWORD_BYTES),
                ..valid
            },
            Operand {
                displacement: (IMMEDIATE_MIN - 1) * i32::from(DOUBLEWORD_BYTES),
                ..valid
            },
        ] {
            assert!(!invalid.is_valid(), "{invalid:?}");
        }
    }

    #[test]
    fn checked_sp_fixed_half_pairs_need_no_unused_quadword_capability() {
        for mode in [
            AddressMode::Offset,
            AddressMode::PreIndex,
            AddressMode::PostIndex,
        ] {
            for (displacement, fixed_half) in [
                (-512, false),
                (-8, true),
                (0, false),
                (8, true),
                (16, false),
                (504, true),
            ] {
                for base in [Register::Sp, Register::X(2)] {
                    let operand = Operand {
                        profile: Profile::NormalWb(CheckedMemoryProfile::SpAlignmentEnabled),
                        transfer: MemoryTransfer::Store,
                        bytes: DOUBLEWORD_BYTES,
                        data: [Register::X(0), Register::X(1)],
                        base,
                        displacement,
                        mode,
                        non_temporal: false,
                    };
                    assert!(operand.is_valid());
                    let required = requirements(&operand);
                    let expected =
                        if base == Register::Sp && mode != AddressMode::PostIndex && fixed_half {
                            0
                        } else {
                            host_caps::CX16
                        };
                    assert_eq!(required.required_host_caps, expected, "{operand:?}");
                    assert_eq!(
                        required.required_sp_alignment,
                        if base == Register::Sp {
                            SpAlignmentRequirement::Enabled
                        } else {
                            SpAlignmentRequirement::Any
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn disabled_sp_policy_never_borrows_enabled_alignment_proofs() {
        for (form, bytes, _, _) in FORMS {
            for base in [2, REGISTER_MASK] {
                for immediate in [IMMEDIATE_MIN, -1, 0, 1, IMMEDIATE_MAX] {
                    let operation = lifted(word(form, [0, 1], base, immediate));
                    let operand = Operand::from_operation(
                        &operation,
                        CheckedMemoryProfile::SpAlignmentDisabled,
                    )
                    .unwrap();
                    let required = requirements(&operand);
                    assert_eq!(
                        required.required_sp_alignment,
                        if base == REGISTER_MASK {
                            SpAlignmentRequirement::Disabled
                        } else {
                            SpAlignmentRequirement::Any
                        }
                    );
                    assert_eq!(
                        required.required_host_caps,
                        if bytes == DOUBLEWORD_BYTES {
                            host_caps::CX16
                        } else {
                            0
                        }
                    );
                }
            }
        }
    }

    const LOAD_FORMS: [(u32, u8, bool, Width); 11] = [
        (0x2940_0000, WORD_BYTES, false, Width::W32),
        (0x29c0_0000, WORD_BYTES, false, Width::W32),
        (0x28c0_0000, WORD_BYTES, false, Width::W32),
        (0xa940_0000, DOUBLEWORD_BYTES, false, Width::X64),
        (0xa9c0_0000, DOUBLEWORD_BYTES, false, Width::X64),
        (0xa8c0_0000, DOUBLEWORD_BYTES, false, Width::X64),
        (0x6940_0000, WORD_BYTES, true, Width::X64),
        (0x69c0_0000, WORD_BYTES, true, Width::X64),
        (0x68c0_0000, WORD_BYTES, true, Width::X64),
        (0x2840_0000, WORD_BYTES, false, Width::W32),
        (0xa840_0000, DOUBLEWORD_BYTES, false, Width::X64),
    ];

    #[test]
    fn allocated_load_pairs_keep_transfer_and_readonly_capability() {
        for (form, bytes, signed, width) in LOAD_FORMS {
            for profile in [
                CheckedMemoryProfile::SpAlignmentEnabled,
                CheckedMemoryProfile::SpAlignmentDisabled,
            ] {
                for data in [[0, 1], [REGISTER_MASK, 0], [0, REGISTER_MASK]] {
                    for base in [0, 1, 2, REGISTER_MASK] {
                        for immediate in [IMMEDIATE_MIN, -1, 0, 1, IMMEDIATE_MAX] {
                            let operation = lifted(word(form, data, base, immediate));
                            if operation == Operation::Nop {
                                continue;
                            }
                            let operand = Operand::from_operation(&operation, profile).unwrap();
                            assert_eq!(operand.transfer, MemoryTransfer::Load { signed, width });
                            assert_eq!(operand.bytes, bytes);
                            let required = requirements(&operand);
                            assert_eq!(
                                required.required_flags & (flags::WRITE | flags::PAIR),
                                flags::PAIR
                            );
                            assert_eq!(required.required_host_caps, host_caps::ATOMIC_LOAD16);
                            assert_eq!(
                                required.required_sp_alignment,
                                if base == REGISTER_MASK {
                                    profile.sp_requirement()
                                } else {
                                    SpAlignmentRequirement::Any
                                }
                            );
                            assert_eq!(
                                required.required_flags & flags::TAG_CHECKED != 0,
                                operand.mode != AddressMode::Offset || base != REGISTER_MASK
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn constructed_invalid_load_pairs_decline_and_constrained_encodings_stay_nop() {
        let valid = Operand::from_operation(
            &lifted(word(0xa940_0000, [0, 1], 2, 0)),
            CheckedMemoryProfile::SpAlignmentDisabled,
        )
        .unwrap();
        for invalid in [
            Operand {
                data: [Register::X(0); 2],
                ..valid
            },
            Operand {
                data: [Register::Zero; 2],
                ..valid
            },
            Operand {
                transfer: MemoryTransfer::Load {
                    signed: true,
                    width: Width::X64,
                },
                ..valid
            },
            Operand {
                transfer: MemoryTransfer::Load {
                    signed: false,
                    width: Width::W32,
                },
                ..valid
            },
            Operand {
                bytes: WORD_BYTES,
                transfer: MemoryTransfer::Load {
                    signed: true,
                    width: Width::W32,
                },
                ..valid
            },
            Operand {
                bytes: WORD_BYTES,
                non_temporal: true,
                transfer: MemoryTransfer::Load {
                    signed: true,
                    width: Width::X64,
                },
                ..valid
            },
            Operand {
                base: Register::X(0),
                mode: AddressMode::PostIndex,
                ..valid
            },
        ] {
            assert!(!invalid.is_valid(), "{invalid:?}");
        }
        for (form, _, _, _) in LOAD_FORMS {
            assert_eq!(lifted(word(form, [0, 0], 2, 0)), Operation::Nop);
            for base in [0, 1] {
                let operation = lifted(word(form, [0, 1], base, 1));
                if (form >> 23) & 3 == 1 || (form >> 23) & 3 == 3 {
                    assert_eq!(operation, Operation::Nop);
                }
            }
        }
    }
}
