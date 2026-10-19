//! LDADD-family atomics: direct LOCK operations where x86 has them, otherwise a
//! CMPXCHG retry loop. The old value is written only after the update succeeds.
//! For PSTATE.DIT they are a plain load, update and store ([`plain`]).
use super::{ValueRegister, commit_rax, input_rax, input_rcx, locked_compare_exchange, read_rax};
use crate::{
    TargetCpu,
    aarch64::{
        Register,
        atomic::{Kind, Operand, Rmw},
    },
};
use alloc::vec::Vec;

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
/// `[rdx], r8` under REX.R.
const MODRM_RDX_R8: u8 = 0x02;
const MOV_BYTE: u8 = 0x88;
const MOV_WORD_OR_WIDER: u8 = 0x89;
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

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand, target: TargetCpu) {
    let Kind::ReadModifyWrite {
        operation,
        source,
        destination,
    } = operand.kind
    else {
        unreachable!("root dispatches only read-modify-write operands");
    };
    if target.data_independent_timing() {
        plain(code, operand.bytes, operation, source, destination);
        return;
    }
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

/// The data-independent-timing lowering: load the old value into RAX, form
/// the new one in R8 with MOV, ADD, AND (of the inverted operand), XOR, OR,
/// or CMP and CMOVcc, store it, then commit the old value. Every instruction
/// is on Intel's data operand independent timing list and nothing branches.
///
/// The pair is atomic only while no other agent accesses guest memory, which
/// the mode requires ([`TargetCpu::data_independent_timing`]). The load comes
/// first, so an address a read would fault on faults there with WnR 0 and a
/// read-only one at the store with WnR 1, as Arm requires of an atomic that
/// both reads and writes; nothing is committed before the store completes.
fn plain(code: &mut Vec<u8>, bytes: u8, operation: Rmw, source: Register, destination: Register) {
    input_rcx(code, bytes, source);
    if operation == Rmw::Clear {
        wide_prefix(code, bytes);
        code.extend(NOT_ECX);
    }
    read_rax(code, bytes);
    extended_prefix(code, bytes, REX_B_PREFIX);
    code.extend(MOV_R8_EAX_OPERANDS);
    match operation {
        Rmw::SignedMax | Rmw::SignedMin | Rmw::UnsignedMax | Rmw::UnsignedMin => {
            select_min_max(code, bytes, operation);
        }
        Rmw::Swap | Rmw::Add | Rmw::Clear | Rmw::Xor | Rmw::Set => {
            extended_prefix(code, bytes, REX_B_PREFIX);
            code.extend([
                match operation {
                    Rmw::Swap => MOV_WORD_OR_WIDER,
                    Rmw::Add => ADD_WORD_OR_WIDER,
                    Rmw::Clear => AND_WORD_OR_WIDER,
                    Rmw::Xor => XOR_WORD_OR_WIDER,
                    _ => OR_WORD_OR_WIDER,
                },
                MODRM_EAX_ECX,
            ]);
        }
    }
    if bytes == HALFWORD_BYTES {
        code.push(OPERAND_SIZE_PREFIX);
    }
    extended_prefix(code, bytes, REX_R_PREFIX);
    code.extend([
        if bytes == BYTE_BYTES {
            MOV_BYTE
        } else {
            MOV_WORD_OR_WIDER
        },
        MODRM_RDX_R8,
    ]);
    commit_rax(code, bytes, destination);
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

#[cfg(test)]
mod tests {
    use super::*;

    const OPERATIONS: [Rmw; 9] = [
        Rmw::Add,
        Rmw::Clear,
        Rmw::Xor,
        Rmw::Set,
        Rmw::SignedMax,
        Rmw::SignedMin,
        Rmw::UnsignedMax,
        Rmw::UnsignedMin,
        Rmw::Swap,
    ];

    #[test]
    fn the_data_independent_timing_lowering_is_a_plain_load_update_and_store() {
        // mov eax,[rdx], or movzx eax,byte/word [rdx]: the old value.
        let loads = [
            (BYTE_BYTES, &[0x0f, 0xb6, 0x02][..]),
            (HALFWORD_BYTES, &[0x0f, 0xb7, 0x02]),
            (DWORD_BYTES, &[0x8b, 0x02]),
            (QWORD_BYTES, &[0x48, 0x8b, 0x02]),
        ];
        // mov [rdx],r8 at the access width.
        let stores = [
            (BYTE_BYTES, &[0x44, 0x88, 0x02][..]),
            (HALFWORD_BYTES, &[0x66, 0x44, 0x89, 0x02]),
            (DWORD_BYTES, &[0x44, 0x89, 0x02]),
            (QWORD_BYTES, &[0x4c, 0x89, 0x02]),
        ];
        // mov [rdi+16],rax: the old value's commit to X2.
        let commit = [0x48, 0x89, 0x87, 16, 0, 0, 0];
        let position = |code: &[u8], bytes: &[u8]| {
            code.windows(bytes.len()).position(|window| window == bytes)
        };
        for ((bytes, load), (_, store)) in loads.into_iter().zip(stores) {
            for operation in OPERATIONS {
                let mut code = Vec::new();
                plain(&mut code, bytes, operation, Register::X(1), Register::X(2));
                // X1 and X2 sit at frame offsets 8 and 16, so no other byte
                // is a LOCK prefix or a conditional jump.
                assert!(!code.contains(&LOCK), "{operation:?} {bytes}");
                assert!(!code.iter().any(|byte| (0x70..0x80).contains(byte)));
                let loaded = position(&code, load).expect("the load");
                let stored = position(&code, store).expect("the store");
                let committed = position(&code, &commit).expect("the commit");
                assert!(
                    loaded < stored && stored < committed,
                    "{operation:?} {bytes}"
                );
            }
        }
        // A ZR destination performs the access and commits nothing.
        let mut code = Vec::new();
        plain(
            &mut code,
            DWORD_BYTES,
            Rmw::Add,
            Register::X(1),
            Register::Zero,
        );
        assert!(code.ends_with(&[0x44, 0x89, 0x02]));
    }
}
