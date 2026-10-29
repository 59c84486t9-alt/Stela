//! LDADD-family atomics: direct LOCK operations where x86 has them, otherwise a
//! CMPXCHG retry loop. The old value is written only after the update succeeds.
//! For a single agent or PSTATE.DIT they are a plain load, update and store
//! ([`plain`]).
use super::{
    ADDRESS, QWORD_BYTES, commit_rax, input_rax, input_rcx, locked_compare_exchange, read_rax, size,
};
use crate::aarch64::{
    Register,
    atomic::{Kind, Operand, Rmw},
};
use crate::x86_64::asm::{Alu, Code, Cond, Gpr, Size, Unary, resolve};

pub(super) fn emit(code: &mut Code, operand: &Operand, plain_access: bool) {
    let Kind::ReadModifyWrite {
        operation,
        source,
        destination,
    } = operand.kind
    else {
        unreachable!("root dispatches only read-modify-write operands");
    };
    if plain_access {
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
        invert_rcx(code, operand.bytes);
    }
    if destination == Register::Zero && matches!(operation, Rmw::Clear | Rmw::Xor | Rmw::Set) {
        direct(code, operand.bytes, operation, true);
    } else {
        retry(code, operand.bytes, operation);
        commit_rax(code, operand.bytes, destination);
    }
}

/// The 32- or 64-bit size that holds a `bytes`-wide value.
const fn register_size(bytes: u8) -> Size {
    Size::of(bytes == QWORD_BYTES)
}

/// `not ecx` or `not rcx`: the operand LDCLR clears with.
fn invert_rcx(code: &mut Code, bytes: u8) {
    code.asm().unary(Unary::Not, register_size(bytes), Gpr::Rcx);
}

/// The single-agent and data-independent-timing lowering: load the old value
/// into RAX, form the new one in R8 with MOV, ADD, AND (of the inverted
/// operand), XOR, OR, or CMP and CMOVcc, store it, then commit the old value.
/// Every instruction is on Intel's data operand independent timing list and
/// nothing branches.
///
/// The pair is atomic only while no other agent accesses guest memory, which
/// both modes require ([`crate::TargetCpu::data_independent_timing`],
/// [`super::super::MemoryChecks::single_agent`]). The load comes
/// first, so an address a read would fault on faults there with WnR 0 and a
/// read-only one at the store with WnR 1, as Arm requires of an atomic that
/// both reads and writes; nothing is committed before the store completes.
fn plain(code: &mut Code, bytes: u8, operation: Rmw, source: Register, destination: Register) {
    input_rcx(code, bytes, source);
    if operation == Rmw::Clear {
        invert_rcx(code, bytes);
    }
    read_rax(code, bytes);
    let wide = register_size(bytes);
    code.asm().mov(wide, Gpr::R8, Gpr::Rax);
    match operation {
        Rmw::SignedMax | Rmw::SignedMin | Rmw::UnsignedMax | Rmw::UnsignedMin => {
            select_min_max(code, bytes, operation);
        }
        Rmw::Swap => code.asm().mov(wide, Gpr::R8, Gpr::Rcx),
        Rmw::Add | Rmw::Clear | Rmw::Xor | Rmw::Set => {
            code.asm().alu(alu(operation), wide, Gpr::R8, Gpr::Rcx);
        }
    }
    code.asm()
        .guest_access(|asm| asm.mov_store(size(bytes), ADDRESS, Gpr::R8));
    commit_rax(code, bytes, destination);
}

/// The x86 ALU operation of an LDADD, LDCLR (of the inverted operand), LDEOR
/// or LDSET.
fn alu(operation: Rmw) -> Alu {
    match operation {
        Rmw::Add => Alu::Add,
        Rmw::Clear => Alu::And,
        Rmw::Xor => Alu::Xor,
        Rmw::Set => Alu::Or,
        _ => unreachable!("swap and min/max have no ALU form"),
    }
}

fn direct(code: &mut Code, bytes: u8, operation: Rmw, discard: bool) {
    let size = size(bytes);
    let mut asm = code.asm();
    match operation {
        Rmw::Swap => asm.guest_access(|asm| asm.xchg(size, ADDRESS, Gpr::Rax)),
        Rmw::Add if !discard => {
            asm.guest_access(|asm| {
                asm.lock();
                asm.xadd(size, ADDRESS, Gpr::Rax)
            });
        }
        Rmw::Add => {
            asm.guest_access(|asm| {
                asm.lock();
                asm.alu(Alu::Add, size, ADDRESS, Gpr::Rax)
            });
        }
        Rmw::Clear | Rmw::Xor | Rmw::Set => {
            asm.guest_access(|asm| {
                asm.lock();
                asm.alu(alu(operation), size, ADDRESS, Gpr::Rcx)
            });
        }
        _ => unreachable!("min/max uses the shared compare-exchange retry"),
    }
}

fn retry(code: &mut Code, bytes: u8, operation: Rmw) {
    read_rax(code, bytes);
    let repeat = code.len();
    // Failed narrow CMPXCHG replaces AL/AX, retaining the zero upper bits from
    // the initial exact-width read. R8 holds proposed data; RAX stays old data.
    let wide = register_size(bytes);
    code.asm().mov(wide, Gpr::R8, Gpr::Rax);
    match operation {
        Rmw::Clear | Rmw::Xor | Rmw::Set => {
            code.asm().alu(alu(operation), wide, Gpr::R8, Gpr::Rcx);
        }
        Rmw::SignedMax | Rmw::SignedMin | Rmw::UnsignedMax | Rmw::UnsignedMin => {
            select_min_max(code, bytes, operation);
        }
        _ => unreachable!("direct instructions handle swap and addition"),
    }
    locked_compare_exchange(code, bytes, Gpr::R8);
    let again = code.asm().jcc8(Cond::Ne);
    resolve(code, again, repeat);
}

fn select_min_max(code: &mut Code, bytes: u8, operation: Rmw) {
    let mut asm = code.asm();
    asm.alu(Alu::Cmp, size(bytes), Gpr::Rax, Gpr::Rcx);
    // Byte/halfword CMP supplies signed flags at the guest width. CMOV may use
    // 32 bits because CMPXCHG consumes only the selected low guest-width bits.
    let keep = match operation {
        Rmw::SignedMax => Cond::L,
        Rmw::SignedMin => Cond::G,
        Rmw::UnsignedMax => Cond::B,
        Rmw::UnsignedMin => Cond::A,
        _ => unreachable!("selector accepts only min/max operations"),
    };
    asm.cmov(keep, register_size(bytes), Gpr::R8, Gpr::Rcx);
}

#[cfg(test)]
mod tests {
    use super::*;

    const BYTE_BYTES: u8 = 1;
    const HALFWORD_BYTES: u8 = 2;
    const DWORD_BYTES: u8 = 4;
    const LOCK: u8 = 0xf0;
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
                let mut code = Code::new();
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
        let mut code = Code::new();
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
