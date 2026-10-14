//! Scalar LSE updates: direct locked operations and one return-old retry engine.
//! RDX contains the checked address. Sources are staged before any guest commit;
//! only a completed atomic operation may publish its zero-extended old value.
use super::{ValueRegister, commit_rax, input_rax, input_rcx, locked_compare_exchange, read_rax};
use crate::aarch64::{
    Register,
    atomic::{Kind, Operand, Rmw},
};

const BYTE_BYTES: u8 = 1;
const HALFWORD_BYTES: u8 = 2;
const DWORD_BYTES: u8 = 4;
const QWORD_BYTES: u8 = 8;
const LOCK: u8 = 0xf0;
const OPERAND_SIZE_PREFIX: u8 = 0x66;
const REX_W_PREFIX: u8 = 0x48;
const REX_R_PREFIX: u8 = 0x44;
const REX_B_PREFIX: u8 = 0x41;
const REX_W_BIT: u8 = 0x08;
const OPCODE_ESCAPE: u8 = 0x0f;
const MODRM_RDX_RAX: u8 = 0x02;
const MODRM_RDX_RCX: u8 = 0x0a;
const MODRM_R8_RCX: u8 = 0xc1;
const ADD_BYTE: u8 = 0x00;
const ADD_WORD_OR_WIDER: u8 = 0x01;
const OR_BYTE: u8 = 0x08;
const OR_WORD_OR_WIDER: u8 = 0x09;
const AND_BYTE: u8 = 0x20;
const AND_WORD_OR_WIDER: u8 = 0x21;
const XOR_BYTE: u8 = 0x30;
const XOR_WORD_OR_WIDER: u8 = 0x31;
const CMP_BYTE: u8 = 0x38;
const CMP_WORD_OR_WIDER: u8 = 0x39;
const XCHG_BYTE: u8 = 0x86;
const XCHG_WORD_OR_WIDER: u8 = 0x87;
const XADD_BYTE: u8 = 0xc0;
const XADD_WORD_OR_WIDER: u8 = 0xc1;
const CMOVB: u8 = 0x42;
const CMOVA: u8 = 0x47;
const CMOVL: u8 = 0x4c;
const CMOVG: u8 = 0x4f;
const JNE_REL8: u8 = 0x75;
const MOV_R8_EAX_OPERANDS: &[u8] = &[0x89, 0xc0];
const NOT_ECX: &[u8] = &[0xf7, 0xd1];
const MODRM_EAX_ECX: u8 = 0xc8;

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand) {
    let Kind::ReadModifyWrite {
        operation,
        source,
        destination,
    } = operand.kind
    else {
        unreachable!("root dispatches only read-modify-write operands");
    };
    if matches!(operation, Rmw::Swap | Rmw::Add) {
        // The direct instruction returns old memory in its source register.
        // Stage RAX directly so committing old data needs no register copy.
        input_rax(code, operand.bytes, source);
        direct(
            code,
            operand.bytes,
            operation,
            destination == Register::Zero,
        );
        commit_rax(code, operand.bytes, destination);
        return;
    }
    input_rcx(code, operand.bytes, source);
    if operation == Rmw::Clear {
        wide_prefix(code, operand.bytes);
        code.extend(NOT_ECX);
    }
    if destination == Register::Zero && matches!(operation, Rmw::Clear | Rmw::Xor | Rmw::Set) {
        direct(code, operand.bytes, operation, true);
    } else {
        retry(code, operand.bytes, operation);
        commit_rax(code, operand.bytes, destination);
    }
}

fn wide_prefix(code: &mut Vec<u8>, bytes: u8) {
    if bytes == QWORD_BYTES {
        code.push(REX_W_PREFIX);
    }
}

fn width_prefix(code: &mut Vec<u8>, bytes: u8) {
    match bytes {
        HALFWORD_BYTES => code.push(OPERAND_SIZE_PREFIX),
        QWORD_BYTES => code.push(REX_W_PREFIX),
        BYTE_BYTES | DWORD_BYTES => {}
        _ => unreachable!("decoder validates scalar atomic width"),
    }
}

fn extended_prefix(code: &mut Vec<u8>, bytes: u8, extension: u8) {
    code.push(extension | if bytes == QWORD_BYTES { REX_W_BIT } else { 0 });
}

fn direct(code: &mut Vec<u8>, bytes: u8, operation: Rmw, discard: bool) {
    if operation != Rmw::Swap {
        code.push(LOCK);
    }
    width_prefix(code, bytes);
    let (byte, wider) = match operation {
        Rmw::Swap => (XCHG_BYTE, XCHG_WORD_OR_WIDER),
        Rmw::Add if !discard => {
            code.push(OPCODE_ESCAPE);
            (XADD_BYTE, XADD_WORD_OR_WIDER)
        }
        Rmw::Add => (ADD_BYTE, ADD_WORD_OR_WIDER),
        Rmw::Clear => (AND_BYTE, AND_WORD_OR_WIDER),
        Rmw::Xor => (XOR_BYTE, XOR_WORD_OR_WIDER),
        Rmw::Set => (OR_BYTE, OR_WORD_OR_WIDER),
        _ => unreachable!("min/max uses the shared compare-exchange retry"),
    };
    code.extend([
        if bytes == BYTE_BYTES { byte } else { wider },
        if matches!(operation, Rmw::Swap | Rmw::Add) {
            MODRM_RDX_RAX
        } else {
            MODRM_RDX_RCX
        },
    ]);
}

fn retry(code: &mut Vec<u8>, bytes: u8, operation: Rmw) {
    read_rax(code, bytes);
    let repeat = code.len();
    // Failed narrow CMPXCHG replaces AL/AX, retaining the zero upper bits from
    // the initial exact-width read. R8 holds proposed data; RAX stays old data.
    extended_prefix(code, bytes, REX_B_PREFIX);
    code.extend(MOV_R8_EAX_OPERANDS);
    match operation {
        Rmw::Clear | Rmw::Xor | Rmw::Set => {
            extended_prefix(code, bytes, REX_B_PREFIX);
            code.extend([
                match operation {
                    Rmw::Clear => AND_WORD_OR_WIDER,
                    Rmw::Xor => XOR_WORD_OR_WIDER,
                    Rmw::Set => OR_WORD_OR_WIDER,
                    _ => unreachable!(),
                },
                MODRM_EAX_ECX,
            ]);
        }
        Rmw::SignedMax | Rmw::SignedMin | Rmw::UnsignedMax | Rmw::UnsignedMin => {
            select_min_max(code, bytes, operation);
        }
        _ => unreachable!("direct instructions handle swap and addition"),
    }
    locked_compare_exchange(code, bytes, ValueRegister::R8);
    code.push(JNE_REL8);
    let displacement = i8::try_from(repeat as isize - (code.len() + size_of::<i8>()) as isize)
        .expect("bounded scalar atomic retry body");
    code.extend(displacement.to_le_bytes());
}

fn select_min_max(code: &mut Vec<u8>, bytes: u8, operation: Rmw) {
    width_prefix(code, bytes);
    code.extend([
        if bytes == BYTE_BYTES {
            CMP_BYTE
        } else {
            CMP_WORD_OR_WIDER
        },
        MODRM_EAX_ECX,
    ]);
    // Byte/halfword CMP supplies signed flags at the guest width. CMOV may use
    // 32 bits because CMPXCHG consumes only the selected low guest-width bits.
    extended_prefix(code, bytes, REX_R_PREFIX);
    code.extend([
        OPCODE_ESCAPE,
        match operation {
            Rmw::SignedMax => CMOVL,
            Rmw::SignedMin => CMOVG,
            Rmw::UnsignedMax => CMOVB,
            Rmw::UnsignedMin => CMOVA,
            _ => unreachable!("selector accepts only min/max operations"),
        },
        MODRM_R8_RCX,
    ]);
}
