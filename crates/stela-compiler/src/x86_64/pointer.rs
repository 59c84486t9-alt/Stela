//! Native completion of PAC instructions for the system-mode engine.
//!
//! A PAC instruction ends its block with an exit to the engine, which
//! computes the result (Arm `AddPAC`, `Auth`) and remembers it in a memo of
//! [`MemoEntry`]s at a fixed host address: the operands, a tag and the
//! result. A [`thunk`] the engine installs over that exit first reads the
//! tag word `tags` holds for the instruction's key: zero, it takes the
//! original exit. Otherwise it looks the operands up in the memo and, on an
//! entry with that tag and the result's kind, completes the instruction
//! natively: it writes the result register and leaves through a direct exit
//! to the next instruction, or, for a branch, takes it through the exit the
//! branch form takes. On a memo miss it calls the engine's [`Service`]
//! routine, which computes the result under the same keys, version and
//! layout and remembers it ([`Completion`]); a result it does not complete
//! (an authentication that fails) takes the original exit.
//!
//! PACGA completes the same way under a tag word of its own, as a signing
//! with the generic key whose result goes to another register.
//!
//! A key whose SCTLR enable is clear has the tag word [`DISABLED`]: the
//! thunk completes with the pointer unchanged, as Arm `AddPAC` and `Auth`
//! return it, so BRA*, BLRA* and RETA* branch to it.
//!
//! The engine keeps a key's tag word zero while the key's result is not the
//! memo's to give (the key's use trapped, or the memo's keys,
//! PAC version or TCR stale), so no entry matches it and the service is
//! never asked: entry tags are at least [`tag`] of generation 1. A memo hit
//! clobbers RAX, RCX, RDX, R8, R9 and flags; a service call every register
//! the SysV ABI lets a call clobber, which no block keeps live across its
//! exit. The call aligns the stack to 16 bytes itself.
use crate::x86_64::asm::{Alu, Code, Cond, Gpr, Mem, ShiftOp, Size, resolve};
use crate::{
    Anchor, GuestAddress, Place,
    aarch64::Register,
    block::{
        ExitKind, PointerAuthenticationKey as Key, PointerAuthenticationModifier as Modifier,
        PointerAuthenticationOperation as Operation,
    },
};
use alloc::vec::Vec;

pub mod strip;

/// Entries in the memo.
pub const MEMO_ENTRIES: usize = 1 << 14;
/// The tag word of the generic key, after those of [`key_index`].
pub const GENERIC_KEY: u8 = 4;
/// The tag words, one for each key.
pub const TAG_WORDS: usize = 5;
/// The tag word of a key whose SCTLR enable is clear, so that every
/// signing and authentication with it returns its pointer unchanged (Arm
/// `AddPAC`, `Auth`, which test the enable before any trap): a thunk then
/// completes the instruction with the pointer itself, without the memo.
/// No open tag word, at least [`tag`] of generation 1, equals it.
pub const DISABLED: u64 = 1;
/// A signing result.
pub const SIGNED: u64 = 1;
/// A successful authentication, which answers both the plain and the
/// combined (branch and return) forms.
pub const AUTHENTICATED: u64 = 2;
/// [`Form::request`]: an authentication rather than a signing, and its
/// combined (branch and return) form; the key's tag word is bits 2:0.
pub const REQUEST_AUTHENTICATE: u32 = 1 << 3;
pub const REQUEST_COMBINED: u32 = 1 << 4;
const REQUEST_KEY: u32 = 7;

/// The engine's routine a thunk calls on a memo miss: [`Anchor::Pointer`],
/// [`Form::request`], the pointer and the modifier.
#[cfg(target_arch = "x86_64")]
pub type ServiceRoutine = extern "sysv64" fn(u64, u32, u64, u64) -> Completion;
/// Only x86-64 runs translated code; ARM hosts compile the type alone.
#[cfg(not(target_arch = "x86_64"))]
pub type ServiceRoutine = extern "C" fn(u64, u32, u64, u64) -> Completion;

/// What the service returns: `value` when `completed` is nonzero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Completion {
    pub completed: u64,
    pub value: u64,
}

/// Whether a [`Form::request`] is PACGA's, which [`requested`] does not name.
pub fn requests_generic_code(request: u32) -> bool {
    request & REQUEST_KEY == u32::from(GENERIC_KEY)
}

/// The key and operation of a [`Form::request`].
pub fn requested(request: u32) -> (Key, bool, bool) {
    let key = match request & REQUEST_KEY {
        0 => Key::Ia,
        1 => Key::Ib,
        2 => Key::Da,
        _ => Key::Db,
    };
    (
        key,
        request & REQUEST_AUTHENTICATE != 0,
        request & REQUEST_COMBINED != 0,
    )
}

/// One remembered result, as thunks read it.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemoEntry {
    pub pointer: u64,
    pub modifier: u64,
    /// [`tag`] of the memo generation, the key and the result's kind.
    pub tag: u64,
    pub value: u64,
}

const _: () = assert!(core::mem::size_of::<MemoEntry>() == 32);
const MODIFIER: i32 = core::mem::offset_of!(MemoEntry, modifier) as i32;
const TAG: i32 = core::mem::offset_of!(MemoEntry, tag) as i32;
const VALUE: i32 = core::mem::offset_of!(MemoEntry, value) as i32;
/// The multiplier and shift of [`slot`]: the top 14 bits index the memo.
const MIX: u64 = 0x9e37_79b9_7f4a_7c15;
const SLOT_SHIFT: u8 = 50;
const _: () = assert!(1 << (64 - SLOT_SHIFT) == MEMO_ENTRIES);

/// The memo slot of a PAC operation's operands, which never depends on a key.
pub fn slot(pointer: u64, modifier: u64) -> usize {
    ((pointer ^ modifier.rotate_left(29)).wrapping_mul(MIX) >> SLOT_SHIFT) as usize
}

/// The index of `key`'s word in the engine's tags.
pub fn key_index(key: Key) -> u8 {
    match key {
        Key::Ia => 0,
        Key::Ib => 1,
        Key::Da => 2,
        Key::Db => 3,
    }
}

/// The tag of a result of `kind` (below 16) with the key at `key` (below 4)
/// in memo `generation`; a key's tag word is `tag(generation, key, 0)`.
pub fn tag(generation: u64, key: u8, kind: u64) -> u64 {
    generation << 8 | u64::from(key) << 4 | kind
}

/// How a PAC instruction completes with its result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Finish {
    /// Into its register, then the next instruction.
    Register,
    /// RETA*: to the result.
    Return,
    /// BRA* and BLRA*: to the result, linking X30 first for BLRA*.
    Branch { link: bool },
}

/// What a thunk needs of a PAC instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Form {
    /// The key's tag word.
    key: u8,
    kind: u64,
    /// The register holding the pointer.
    pointer: u8,
    modifier: Modifier,
    /// The result's register for `Register`.
    result: u8,
    completion: Finish,
}

impl Form {
    /// What the service computes for this form: its key, and a signing,
    /// a plain authentication or, for RETA*, BRA* and BLRA*, a combined one.
    pub fn request(&self) -> u32 {
        let mut request = u32::from(self.key);
        if self.kind == AUTHENTICATED {
            request |= REQUEST_AUTHENTICATE;
            if self.completion != Finish::Register {
                request |= REQUEST_COMBINED;
            }
        }
        request
    }

    /// The form of `operation`, or `None` for the PAC instructions thunks do
    /// not complete: strips, loads, FEAT_PAuth_LR forms and register-31
    /// operands, but for PACGA's modifier, which is SP.
    pub fn of(operation: Operation) -> Option<Self> {
        if let Operation::GenericCode(code) = operation {
            let modifier = match code.modifier {
                31 => Modifier::StackPointer,
                register => Modifier::Register(register),
            };
            return (code.source < 31 && code.destination < 31).then_some(Self {
                key: GENERIC_KEY,
                kind: SIGNED,
                pointer: code.source,
                modifier,
                result: code.destination,
                completion: Finish::Register,
            });
        }
        let sp = Modifier::StackPointer;
        let x16 = Modifier::Register(16);
        let (key, kind, pointer, modifier, completion) = match operation {
            Operation::SignIbSp => (Key::Ib, SIGNED, 30, sp, Finish::Register),
            Operation::AuthenticateIbSp => (Key::Ib, AUTHENTICATED, 30, sp, Finish::Register),
            Operation::ReturnIbSp => (Key::Ib, AUTHENTICATED, 30, sp, Finish::Return),
            Operation::ReturnIaSp => (Key::Ia, AUTHENTICATED, 30, sp, Finish::Return),
            Operation::Sign1716 { key } => (key, SIGNED, 17, x16, Finish::Register),
            Operation::Authenticate1716 { key } => (key, AUTHENTICATED, 17, x16, Finish::Register),
            Operation::Sign {
                key,
                destination,
                modifier,
            } => (key, SIGNED, destination, modifier, Finish::Register),
            Operation::Authenticate {
                key,
                destination,
                modifier,
            } => (key, AUTHENTICATED, destination, modifier, Finish::Register),
            Operation::Branch {
                key,
                target,
                modifier,
                link,
            } => (
                key,
                AUTHENTICATED,
                target,
                modifier,
                Finish::Branch { link },
            ),
            _ => return None,
        };
        (pointer < 31 && modifier != Modifier::Register(31)).then_some(Self {
            key: key_index(key),
            kind,
            pointer,
            modifier,
            result: pointer,
            completion,
        })
    }
}

/// A [`thunk`] and the offset of the direct exit it takes after a register
/// completion, which the engine may chain like a block's, or of the exit to
/// the target in RAX after a return or branch completion
/// (`chain::dynamic_exit`), which the engine may redirect through a lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Thunk {
    pub code: Vec<u8>,
    pub next: Option<usize>,
    pub dynamic: Option<usize>,
}

/// The thunk completing the PAC instruction of `form` at `pc` from the memo
/// ([`Anchor::Memo`]) under the tag words at `tags`, or through `service`, a
/// [`ServiceRoutine`], else exiting at `pc` for the engine.
pub fn thunk(form: Form, pc: GuestAddress, tags: Place, service: u64) -> Thunk {
    use Gpr::{R8, R9, R11, Rax, Rcx, Rdi, Rdx, Rsi, Rsp};
    use Size::{Dword, Qword};
    let mut code = Code::pinned();
    let mut asm = code.asm();
    let mut exits = Vec::new();
    let pointer = asm.guest(Register::X(form.pointer)).expect("X0..X30");
    asm.mov_load(Qword, Rax, pointer);
    match form.modifier {
        Modifier::Register(register) => {
            let modifier = asm.guest(Register::X(register)).expect("X0..X30");
            asm.mov_load(Qword, Rdx, modifier);
        }
        Modifier::StackPointer => {
            let stack = asm.guest(Register::Sp).expect("SP has storage");
            asm.mov_load(Qword, Rdx, stack);
        }
        Modifier::Zero => asm.alu(Alu::Xor, Dword, Rdx, Rdx),
    }
    asm.place(
        R8,
        Place::new(tags.anchor, tags.offset + usize::from(form.key) * 8),
    );
    asm.mov_load(Qword, R8, Mem::base(R8, 0));
    asm.test(Qword, R8, R8);
    // The key is not open.
    exits.push(asm.jcc(Cond::E));
    // The result is the pointer in RAX.
    asm.alu_imm8(Alu::Cmp, Qword, R8, DISABLED as i8);
    let identity = asm.jcc(Cond::E);
    asm.mov(Qword, Rcx, Rdx);
    asm.shift_imm(ShiftOp::Rol, Qword, Rcx, 29);
    asm.alu(Alu::Xor, Qword, Rcx, Rax);
    asm.mov_imm64(R9, MIX);
    asm.imul(Qword, Rcx, R9);
    asm.shift_imm(ShiftOp::Shr, Qword, Rcx, SLOT_SHIFT);
    // 32-byte entries.
    asm.shift_imm(ShiftOp::Shl, Qword, Rcx, 5);
    asm.place(R9, Place::new(Anchor::Memo, 0));
    asm.alu(Alu::Add, Qword, Rcx, R9);
    let mut misses = Vec::new();
    asm.alu_load(Alu::Cmp, Qword, Rax, Mem::base(Rcx, 0));
    misses.push(asm.jcc(Cond::Ne));
    asm.alu_load(Alu::Cmp, Qword, Rdx, Mem::base(Rcx, MODIFIER));
    misses.push(asm.jcc(Cond::Ne));
    asm.alu_imm8(Alu::Or, Qword, R8, form.kind as i8);
    asm.alu_load(Alu::Cmp, Qword, R8, Mem::base(Rcx, TAG));
    misses.push(asm.jcc(Cond::Ne));
    asm.mov_load(Qword, Rax, Mem::base(Rcx, VALUE));
    asm.bind(identity);
    let complete = asm.len();
    let next_pc = GuestAddress(pc.0.wrapping_add(4));
    let mut next = None;
    let mut dynamic = None;
    match form.completion {
        Finish::Register => {
            let result = asm.guest(Register::X(form.result)).expect("X0..X30");
            asm.mov_store(Qword, result, Rax);
            next = Some(asm.len());
            super::block::direct_exit_with(&mut asm, next_pc, ExitKind::Fallthrough);
        }
        Finish::Return => {
            dynamic = Some(asm.len());
            super::block::exit_kind_with(&mut asm, ExitKind::Return);
        }
        Finish::Branch { link } => {
            if link {
                asm.mov_imm64(Rcx, next_pc.0);
                let storage = asm.guest(Register::X(30)).expect("X30 has storage");
                asm.mov_store(Qword, storage, Rcx);
            }
            dynamic = Some(asm.len());
            let kind = if link {
                ExitKind::Call
            } else {
                ExitKind::Indirect
            };
            super::block::exit_kind_with(&mut asm, kind);
        }
    }
    for miss in misses {
        asm.bind(miss);
    }
    // service(state, request, pointer, modifier) on a 16-byte aligned stack.
    asm.mov(Qword, R11, Rsp);
    asm.alu_imm8(Alu::And, Qword, Rsp, -16);
    asm.push(R11);
    asm.push(Rdi);
    // The one pinned register a call may change, and the alignment.
    asm.push(Rsi);
    asm.push(Rsi);
    asm.mov(Qword, Rcx, Rdx);
    asm.mov(Qword, Rdx, Rax);
    asm.mov_imm32(Rsi, form.request());
    asm.place(Rdi, Place::new(Anchor::Pointer, 0));
    asm.mov_imm64(Rax, service);
    asm.call_rm(Rax);
    asm.pop(Rsi);
    asm.pop(Rsi);
    asm.pop(Rdi);
    asm.pop(Rsp);
    asm.test(Qword, Rax, Rax);
    // Not completed.
    exits.push(asm.jcc(Cond::E));
    asm.mov(Qword, Rax, Rdx);
    let back = asm.jmp();
    for exit in exits {
        asm.bind(exit);
    }
    super::block::direct_exit_with(&mut asm, pc, ExitKind::PointerAuthentication);
    resolve(&mut code, back, complete);
    Thunk {
        code: code.into_bytes(),
        next,
        dynamic,
    }
}

#[cfg(test)]
mod tests;
