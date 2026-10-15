//! Exact scalar baseline for complete-element shifts and data-only saturation.
use crate::aarch64::{
    scalable::ElementSize,
    sve::shifts::{Count, Kind},
};

const CHUNK_BYTES: usize = 16;
const BITS_PER_BYTE: u8 = 8;
const HOST_BITS: u8 = 64;
const SOURCE_SLOT: u8 = 0;
const COUNT_SLOT: u8 = 16;
const RESULT_SLOT: u8 = 32;
pub(super) const STACK_BYTES: u8 = 48;
const MOVDQU_STORE_RSP: [u8; 3] = [0xf3, 0x0f, 0x7f];
const MOVDQU_LOAD_RSP: [u8; 3] = [0xf3, 0x0f, 0x6f];
const MODRM_STACK_DISP8: u8 = 0x44;
const STACK_SIB: u8 = 0x24;
const MOVZX_EAX_BYTE_RSP: [u8; 3] = [0x0f, 0xb6, 0x44];
const MOVSX_RAX_BYTE_RSP: [u8; 4] = [0x48, 0x0f, 0xbe, 0x44];
const MOVZX_EAX_WORD_RSP: [u8; 3] = [0x0f, 0xb7, 0x44];
const MOVSX_RAX_WORD_RSP: [u8; 4] = [0x48, 0x0f, 0xbf, 0x44];
const MOV_EAX_DWORD_RSP: [u8; 2] = [0x8b, 0x44];
const MOVSXD_RAX_DWORD_RSP: [u8; 3] = [0x48, 0x63, 0x44];
const MOV_RAX_QWORD_RSP: [u8; 3] = [0x48, 0x8b, 0x44];
const MOV_ECX_IMM32: u8 = 0xb9;
const MOVABS_RAX: [u8; 2] = [0x48, 0xb8];
const MOVABS_RDX: [u8; 2] = [0x48, 0xba];
const MOV_RCX_RAX: [u8; 3] = [0x48, 0x89, 0xc1];
const MOV_RDX_RAX: [u8; 3] = [0x48, 0x89, 0xc2];
const MOV_R10_RAX: [u8; 3] = [0x49, 0x89, 0xc2];
const CMP_R10_RDX: [u8; 3] = [0x49, 0x39, 0xd2];
const CMP_RCX_RDX: [u8; 3] = [0x48, 0x39, 0xd1];
const CMOVG_RCX_RDX: [u8; 3] = [0x48, 0x0f, 0x4f];
const CMOVL_RCX_RDX: [u8; 3] = [0x48, 0x0f, 0x4c];
const CMP_ECX_IMM8: [u8; 2] = [0x83, 0xf9];
const TEST_RAX: [u8; 3] = [0x48, 0x85, 0xc0];
const TEST_RDX: [u8; 3] = [0x48, 0x85, 0xd2];
const TEST_RCX: [u8; 3] = [0x48, 0x85, 0xc9];
const NEG_RCX: [u8; 3] = [0x48, 0xf7, 0xd9];
const XOR_EAX: [u8; 2] = [0x31, 0xc0];
const ADC_RAX_ZERO: [u8; 4] = [0x48, 0x83, 0xd0, 0];
const ADD_RAX_RDX: [u8; 3] = [0x48, 0x01, 0xd0];
const CMOVNS_RDX_RCX: [u8; 4] = [0x48, 0x0f, 0x49, 0xd1];
const XOR_ECX: [u8; 2] = [0x31, 0xc9];
const MOV_BYTE_RSP_AL: [u8; 2] = [0x88, 0x44];
const MOV_WORD_RSP_AX: [u8; 3] = [0x66, 0x89, 0x44];
const MOV_DWORD_RSP_EAX: [u8; 2] = [0x89, 0x44];
const MOV_QWORD_RSP_RAX: [u8; 3] = [0x48, 0x89, 0x44];

fn stack_vector(code: &mut Vec<u8>, xmm: u8, slot: u8, store: bool) {
    code.extend(if store {
        MOVDQU_STORE_RSP
    } else {
        MOVDQU_LOAD_RSP
    });
    code.extend([MODRM_STACK_DISP8 | xmm << 3, STACK_SIB, slot]);
}

fn load_lane(code: &mut Vec<u8>, bytes: usize, signed: bool, slot: u8) {
    code.extend_from_slice(match (bytes, signed) {
        (1, false) => &MOVZX_EAX_BYTE_RSP,
        (1, true) => &MOVSX_RAX_BYTE_RSP,
        (2, false) => &MOVZX_EAX_WORD_RSP,
        (2, true) => &MOVSX_RAX_WORD_RSP,
        (4, false) => &MOV_EAX_DWORD_RSP,
        (4, true) => &MOVSXD_RAX_DWORD_RSP,
        (8, _) => &MOV_RAX_QWORD_RSP,
        _ => unreachable!("integer element width"),
    });
    code.extend([STACK_SIB, slot]);
}

fn store_lane(code: &mut Vec<u8>, bytes: usize, slot: u8) {
    code.extend_from_slice(match bytes {
        1 => &MOV_BYTE_RSP_AL,
        2 => &MOV_WORD_RSP_AX,
        4 => &MOV_DWORD_RSP_EAX,
        8 => &MOV_QWORD_RSP_RAX,
        _ => unreachable!("integer element width"),
    });
    code.extend([STACK_SIB, slot]);
}

#[derive(Clone, Copy)]
enum Branch {
    Always,
    Nonnegative,
    Equal,
    Above,
    AboveOrEqual,
}
fn branch(code: &mut Vec<u8>, condition: Branch) -> usize {
    match condition {
        Branch::Always => code.push(0xe9),
        Branch::Nonnegative => code.extend([0x0f, 0x89]),
        Branch::Equal => code.extend([0x0f, 0x84]),
        Branch::Above => code.extend([0x0f, 0x87]),
        Branch::AboveOrEqual => code.extend([0x0f, 0x83]),
    }
    let patch = code.len();
    code.extend([0; 4]);
    patch
}
fn resolve(code: &mut [u8], patch: usize) {
    let distance = i32::try_from(code.len() - patch - 4).expect("shift recipe branch span");
    code[patch..patch + 4].copy_from_slice(&distance.to_le_bytes());
}

#[derive(Clone, Copy)]
enum Shift {
    Left,
    LogicalRight,
    ArithmeticRight,
}
impl Shift {
    fn count(self, code: &mut Vec<u8>, temporary: bool) {
        let group = match self {
            Self::Left => 4,
            Self::LogicalRight => 5,
            Self::ArithmeticRight => 7,
        };
        code.extend([
            if temporary { 0x49 } else { 0x48 },
            0xd3,
            0xc0 | group << 3 | if temporary { 2 } else { 0 },
        ]);
    }
    fn immediate(self, code: &mut Vec<u8>, amount: u8) {
        let group = match self {
            Self::Left => 4,
            Self::LogicalRight => 5,
            Self::ArithmeticRight => 7,
        };
        code.extend([0x48, 0xc1, 0xc0 | group << 3, amount]);
    }
}

fn bound(code: &mut Vec<u8>, value: u64, rdx: bool) {
    code.extend(if rdx { MOVABS_RDX } else { MOVABS_RAX });
    code.extend(value.to_le_bytes());
}
fn normalize(code: &mut Vec<u8>, bits: u8, signed: bool) {
    if bits < HOST_BITS {
        Shift::Left.immediate(code, HOST_BITS - bits);
        if signed {
            Shift::ArithmeticRight
        } else {
            Shift::LogicalRight
        }
        .immediate(code, HOST_BITS - bits);
    }
}

/// Preloaded XMM0=data and XMM1=complete signed counts; result XMM0.
/// Preserves other XMMs and RDI/R15, clobbers RAX/RCX/RDX/R10, restores RSP.
/// Group instructions own source snapshots, group ordering and destination commit.
pub(crate) fn rounding_variable_chunk(code: &mut Vec<u8>, element_size: ElementSize, signed: bool) {
    super::adjust_stack(code, STACK_BYTES, true);
    chunk(
        code,
        if signed {
            Kind::RoundingSigned
        } else {
            Kind::RoundingUnsigned
        },
        element_size,
        Count::Elements(0),
    );
    super::adjust_stack(code, STACK_BYTES, false);
}

pub(super) fn chunk(code: &mut Vec<u8>, kind: Kind, element_size: ElementSize, count: Count) {
    stack_vector(code, 0, SOURCE_SLOT, true);
    if !matches!(count, Count::Immediate(_)) {
        stack_vector(code, 1, COUNT_SLOT, true);
    }
    let bytes = element_size.bytes();
    let bits = element_size.bits() as u8;
    let signed = matches!(
        kind,
        Kind::ArithmeticRight
            | Kind::DivideSigned
            | Kind::SaturatingSigned
            | Kind::SaturatingSignedToUnsigned
            | Kind::RoundingSigned
            | Kind::SaturatingRoundingSigned
    );
    for offset in (0..CHUNK_BYTES).step_by(bytes) {
        match count {
            Count::Immediate(amount) => {
                load_lane(code, bytes, signed, SOURCE_SLOT + offset as u8);
                if kind == Kind::DivideSigned {
                    divide_signed(code, bits, amount);
                } else {
                    code.push(MOV_ECX_IMM32);
                    code.extend(u32::from(amount).to_le_bytes());
                    left(code, bits, signed, kind != Kind::SaturatingSigned, true);
                }
            }
            Count::Elements(_) | Count::Doublewords(_) => {
                let bidirectional = !matches!(
                    kind,
                    Kind::ArithmeticRight | Kind::LogicalRight | Kind::LogicalLeft
                );
                let wide = matches!(count, Count::Doublewords(_));
                let count_bytes = if wide {
                    usize::from(HOST_BITS / BITS_PER_BYTE)
                } else {
                    bytes
                };
                let count_offset = if wide {
                    offset / count_bytes * count_bytes
                } else {
                    offset
                };
                load_lane(
                    code,
                    count_bytes,
                    bidirectional,
                    COUNT_SLOT + count_offset as u8,
                );
                code.extend(MOV_RCX_RAX);
                if bidirectional {
                    clamp_signed_count(code, bits);
                }
                load_lane(code, bytes, signed, SOURCE_SLOT + offset as u8);
                if bidirectional {
                    code.extend(TEST_RCX);
                    let positive = branch(code, Branch::Nonnegative);
                    code.extend(NEG_RCX);
                    right(
                        code,
                        signed,
                        matches!(
                            kind,
                            Kind::RoundingSigned
                                | Kind::RoundingUnsigned
                                | Kind::SaturatingRoundingSigned
                                | Kind::SaturatingRoundingUnsigned
                        ),
                    );
                    let done = branch(code, Branch::Always);
                    resolve(code, positive);
                    left(
                        code,
                        bits,
                        signed,
                        !signed,
                        matches!(
                            kind,
                            Kind::SaturatingSigned
                                | Kind::SaturatingUnsigned
                                | Kind::SaturatingRoundingSigned
                                | Kind::SaturatingRoundingUnsigned
                        ),
                    );
                    resolve(code, done);
                } else if kind == Kind::LogicalLeft {
                    // Full unsigned counts must not truncate to ECX/CL first.
                    clamp_unsigned_count(code, bits);
                    left(code, bits, false, true, false);
                } else {
                    clamp_unsigned_count(code, bits);
                    right(code, signed, false);
                }
            }
        }
        store_lane(code, bytes, RESULT_SLOT + offset as u8);
    }
    stack_vector(code, 0, RESULT_SLOT, false);
}

fn clamp_unsigned_count(code: &mut Vec<u8>, bits: u8) {
    // Compare the full count before x86 CL masking; source RAX remains intact.
    bound(code, u64::from(bits), true);
    code.extend(CMP_RCX_RDX);
    code.extend([0x48, 0x0f, 0x47, 0xca]); // cmova rcx,rdx
}
fn clamp_signed_count(code: &mut Vec<u8>, bits: u8) {
    let ceiling = i64::from(bits) + 1;
    bound(code, ceiling as u64, true);
    code.extend(CMP_RCX_RDX);
    code.extend(CMOVG_RCX_RDX);
    code.push(0xca);
    bound(code, (-ceiling) as u64, true);
    code.extend(CMP_RCX_RDX);
    code.extend(CMOVL_RCX_RDX);
    code.push(0xca);
}

fn divide_signed(code: &mut Vec<u8>, bits: u8, amount: u8) {
    if amount == bits {
        code.extend(XOR_EAX);
        return;
    }
    bound(code, (1_u64 << amount) - 1, true);
    code.extend(XOR_ECX);
    code.extend(TEST_RAX);
    code.extend(CMOVNS_RDX_RCX);
    code.extend(ADD_RAX_RDX);
    Shift::ArithmeticRight.immediate(code, amount);
}

fn right(code: &mut Vec<u8>, signed: bool, round: bool) {
    code.extend(CMP_ECX_IMM8);
    code.push(HOST_BITS);
    let large = branch(code, Branch::AboveOrEqual);
    if signed {
        Shift::ArithmeticRight
    } else {
        Shift::LogicalRight
    }
    .count(code, false);
    if round {
        code.extend(ADC_RAX_ZERO);
    }
    let done = branch(code, Branch::Always);
    resolve(code, large);
    if signed && !round {
        Shift::ArithmeticRight.immediate(code, HOST_BITS - 1);
    } else if !signed && round {
        let beyond = branch(code, Branch::Above);
        Shift::LogicalRight.immediate(code, HOST_BITS - 1);
        let end = branch(code, Branch::Always);
        resolve(code, beyond);
        code.extend(XOR_EAX);
        resolve(code, end);
    } else {
        code.extend(XOR_EAX);
    }
    resolve(code, done);
}

fn left(code: &mut Vec<u8>, bits: u8, signed: bool, unsigned_result: bool, saturating: bool) {
    let mut done = Vec::new();
    let mut negative = None;
    if saturating {
        code.extend(MOV_RDX_RAX);
    }
    if signed && unsigned_result {
        code.extend(TEST_RAX);
        let nonnegative = branch(code, Branch::Nonnegative);
        negative = Some(branch(code, Branch::Always));
        resolve(code, nonnegative);
    }
    code.extend(CMP_ECX_IMM8);
    code.push(bits);
    let large = branch(code, Branch::AboveOrEqual);
    Shift::Left.count(code, false);
    if saturating {
        normalize(code, bits, !unsigned_result);
        code.extend(MOV_R10_RAX);
        if unsigned_result {
            Shift::LogicalRight
        } else {
            Shift::ArithmeticRight
        }
        .count(code, true);
        code.extend(CMP_R10_RDX);
        done.push(branch(code, Branch::Equal));
        let overflow = branch(code, Branch::Always);
        resolve(code, large);
        code.extend(TEST_RAX);
        done.push(branch(code, Branch::Equal));
        resolve(code, overflow);
        if let Some(patch) = negative {
            resolve(code, patch);
        }
        let maximum = if unsigned_result {
            u64::MAX >> (HOST_BITS - bits)
        } else {
            (1_u64 << (bits - 1)) - 1
        };
        bound(code, maximum, false);
        if signed {
            code.extend(TEST_RDX);
            let nonnegative = branch(code, Branch::Nonnegative);
            bound(
                code,
                if unsigned_result {
                    0
                } else {
                    0_u64.wrapping_sub(1_u64 << (bits - 1))
                },
                false,
            );
            resolve(code, nonnegative);
        }
    } else {
        done.push(branch(code, Branch::Always));
        resolve(code, large);
        code.extend(XOR_EAX);
    }
    for patch in done {
        resolve(code, patch);
    }
}
