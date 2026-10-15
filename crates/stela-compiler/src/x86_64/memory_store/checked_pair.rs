//! Checked GPR LDP/LDPSW/STP/LDNP/STNP through one source-correct pair request.
//!
//! Store inputs and load outputs live in private staging across the callback.
//! Load destinations and base writeback publish only after whole-pair success.
//! The memory owner decomposes the combined quantity and publishes reached
//! writes through the shared physical reservation domain. Legacy direct stores
//! remain in the parent module and retain their separate private-RAM profile.

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
    profile: CheckedMemoryProfile,
    transfer: MemoryTransfer,
    bytes: u8,
    data: [Register; 2],
    base: Register,
    displacement: i32,
    mode: AddressMode,
    non_temporal: bool,
}

impl Operand {
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
                profile,
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
                    profile,
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

/// Loads require the canonical readonly16 snapshot capability conservatively.
/// Variable X-pair stores can reach one 16-byte quantity and require CX16
/// before effects. With checked SP16 and a fixed offset of 8 modulo16, Offset
/// and PreIndex can only reach two 8-byte halves. PostIndex uses original SP.
/// Disabled SP checks supply no alignment proof: every X pair requires CX16.
pub(crate) fn requirements(operand: &Operand) -> MemoryRequirements {
    let required_flags = operand.flags();
    MemoryRequirements {
        required_pointer_arithmetic: None,
        required_address_checks: operand.profile.address_requirements(false),
        required_flags,
        required_host_caps: if matches!(operand.transfer, MemoryTransfer::Load { .. }) {
            // Dynamic read parts can cross aligned8 within SCA16. The canonical
            // readonly16 snapshot capability is independent of store CX16.
            host_caps::ATOMIC_LOAD16
        } else if operand.bytes == DOUBLEWORD_BYTES
            && (operand.base != Register::Sp
                || operand.profile.sp_requirement() == SpAlignmentRequirement::Disabled
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
            operand.profile.sp_requirement()
        } else {
            SpAlignmentRequirement::Any
        },
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
    let sp_failure = if operand.profile.sp_requirement() == SpAlignmentRequirement::Enabled {
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
        operand.profile.address_checks(false),
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
#[path = "checked_pair/tests.rs"]
mod tests;
