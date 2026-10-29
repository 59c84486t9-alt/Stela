//! Checked LDP/LDPSW/STP/LDNP/STNP as one pair request to the memory service.
//! Load destinations and base writeback are written only after both elements
//! succeed.
use crate::x86_64::asm::{Alu, Code, Gpr, Mem, Size};

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

/// The private staging slot at `offset`.
fn staging(offset: u32) -> Mem {
    Mem::base_disp8(
        Gpr::Rsp,
        i8::try_from(offset).expect("pair private staging fits disp8"),
    )
}

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

/// The operand size of a `bytes`-wide pair element.
fn size(bytes: u8) -> Size {
    Size::of(bytes == DOUBLEWORD_BYTES)
}

fn save_source(code: &mut Code, register: Register, bytes: u8, destination: u32) {
    load(code, register);
    code.asm()
        .mov_store(size(bytes), staging(destination), Gpr::Rax);
}

/// Read the private callback output with the source extension semantics.
fn load_result(code: &mut Code, bytes: u8, signed: bool, width: Width, source: u32) {
    debug_assert!(matches!(
        (bytes, signed),
        (WORD_BYTES, true) | (WORD_BYTES | DOUBLEWORD_BYTES, false)
    ));
    let mut asm = code.asm();
    if signed {
        debug_assert!(width == Width::X64);
        asm.movsxd(Gpr::Rax, staging(source));
    } else {
        asm.mov_load(Size::of(width == Width::X64), Gpr::Rax, staging(source));
    }
}

/// Emit an inner checked-context body. The caller has validated the descriptor,
/// memory profile, capabilities and effective SP-alignment controls. RDI points
/// to GuestState and R15 to ExecutionContext; callback failures leave completed
/// RAM prefixes visible and return through the enclosing context wrapper.
pub(crate) fn emit_context(code: &mut Code, operand: &Operand, pc: u64) {
    debug_assert!(operand.is_valid());
    code.asm()
        .alu_imm8(Alu::Sub, Size::Qword, Gpr::Rsp, STACK_BYTES as i8);
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
        code.asm()
            .mov_store(Size::Qword, staging(WRITEBACK_OFFSET), Gpr::Rdx);
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
        code.asm()
            .mov_load(Size::Qword, Gpr::Rax, staging(WRITEBACK_OFFSET));
        // A validated base is never ZR; no source is re-read after callback.
        store(code, operand.base);
    }
    code.asm().alu(Alu::Xor, Size::Dword, Gpr::Rax, Gpr::Rax);
    let cleanup = code.len();
    crate::x86_64::asm::resolve(code, callback_failure, cleanup);
    if let Some(failure) = sp_failure {
        crate::x86_64::asm::resolve(code, failure, cleanup);
    }
    code.asm()
        .alu_imm8(Alu::Add, Size::Qword, Gpr::Rsp, STACK_BYTES as i8);
    address::return_if_failed(code);
}

#[cfg(test)]
mod tests;
