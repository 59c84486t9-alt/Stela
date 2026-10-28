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
    GuestAddress,
    block::{
        ExitKind, PointerAuthenticationKey as Key, PointerAuthenticationModifier as Modifier,
        PointerAuthenticationOperation as Operation,
    },
};
use alloc::vec::Vec;

pub mod strip;

/// Entries in the memo.
pub const MEMO_ENTRIES: usize = 1 << 14;
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
/// combined (branch and return) form; the key's index is bits 1:0.
pub const REQUEST_AUTHENTICATE: u32 = 1 << 2;
pub const REQUEST_COMBINED: u32 = 1 << 3;
const REQUEST_KEY: u32 = 3;

/// The engine's routine a thunk calls on a memo miss, and its argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Service {
    /// The first argument.
    pub state: u64,
    /// A `ServiceRoutine`.
    pub routine: u64,
}

/// The service's signature: its state, [`Form::request`], the pointer and
/// the modifier.
pub type ServiceRoutine = extern "sysv64" fn(u64, u32, u64, u64) -> Completion;

/// What the service returns: `value` when `completed` is nonzero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Completion {
    pub completed: u64,
    pub value: u64,
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
    key: Key,
    kind: u64,
    /// The register holding the pointer, and the result's for `Register`.
    pointer: u8,
    modifier: Modifier,
    completion: Finish,
}

impl Form {
    /// What the service computes for this form: its key, and a signing,
    /// a plain authentication or, for RETA*, BRA* and BLRA*, a combined one.
    pub fn request(&self) -> u32 {
        let mut request = u32::from(key_index(self.key));
        if self.kind == AUTHENTICATED {
            request |= REQUEST_AUTHENTICATE;
            if self.completion != Finish::Register {
                request |= REQUEST_COMBINED;
            }
        }
        request
    }

    /// The form of `operation`, or `None` for the PAC instructions thunks do
    /// not complete: strips, generic codes, loads, FEAT_PAuth_LR forms and
    /// register-31 operands.
    pub fn of(operation: Operation) -> Option<Self> {
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
            key,
            kind,
            pointer,
            modifier,
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
/// at `memo` under the tag words at `tags`, or through `service`, else
/// exiting at `pc` for the engine.
pub fn thunk(form: Form, pc: GuestAddress, memo: u64, tags: u64, service: Service) -> Thunk {
    use Gpr::{R8, R9, R11, Rax, Rcx, Rdi, Rdx, Rsi, Rsp};
    use Size::{Dword, Qword};
    let mut code = Code::new();
    let mut asm = code.asm();
    let mut exits = Vec::new();
    let pointer = frame(u32::from(form.pointer) * 8);
    asm.mov_load(Qword, Rax, pointer);
    match form.modifier {
        Modifier::Register(register) => {
            asm.mov_load(Qword, Rdx, frame(u32::from(register) * 8));
        }
        Modifier::StackPointer => asm.mov_load(Qword, Rdx, frame(STACK_POINTER)),
        Modifier::Zero => asm.alu(Alu::Xor, Dword, Rdx, Rdx),
    }
    asm.mov_imm64(R8, tags + u64::from(key_index(form.key)) * 8);
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
    asm.mov_imm64(R9, memo);
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
            asm.mov_store(Qword, pointer, Rax);
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
                asm.mov_store(Qword, frame(30 * 8), Rcx);
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
    asm.mov(Qword, Rcx, Rdx);
    asm.mov(Qword, Rdx, Rax);
    asm.mov_imm32(Rsi, form.request());
    asm.mov_imm64(Rdi, service.state);
    asm.mov_imm64(Rax, service.routine);
    asm.call_rm(Rax);
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

const STACK_POINTER: u32 = core::mem::offset_of!(crate::GuestState, sp) as u32;

/// `[rdi+offset]` with a 32-bit displacement: a field of the guest frame.
fn frame(offset: u32) -> Mem {
    Mem::base_disp32(Gpr::Rdi, offset as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forms_name_their_key_kind_operands_and_completion() {
        let form = Form::of(Operation::SignIbSp).unwrap();
        assert_eq!(
            (form.key, form.kind, form.pointer, form.modifier),
            (Key::Ib, SIGNED, 30, Modifier::StackPointer)
        );
        assert_eq!(requested(form.request()), (Key::Ib, false, false));
        let branch = Form::of(Operation::Branch {
            key: Key::Ia,
            target: 8,
            modifier: Modifier::Register(16),
            link: true,
        })
        .unwrap();
        assert_eq!(branch.completion, Finish::Branch { link: true });
        assert_eq!(branch.kind, AUTHENTICATED);
        assert_eq!(requested(branch.request()), (Key::Ia, true, true));
        let plain = Form::of(Operation::Authenticate {
            key: Key::Db,
            destination: 3,
            modifier: Modifier::Zero,
        })
        .unwrap();
        assert_eq!(requested(plain.request()), (Key::Db, true, false));
        let ret = Form::of(Operation::ReturnIbSp).unwrap();
        assert_eq!(requested(ret.request()), (Key::Ib, true, true));
        // Register 31 operands and the other PAC forms stay with the engine.
        assert!(
            Form::of(Operation::Sign {
                key: Key::Da,
                destination: 31,
                modifier: Modifier::Zero,
            })
            .is_none()
        );
        assert!(
            Form::of(Operation::Strip {
                data: true,
                destination: 0
            })
            .is_none()
        );
    }

    #[test]
    fn tags_keep_generation_key_and_kind_apart() {
        assert_eq!(tag(1, 3, AUTHENTICATED), 0x132);
        // A zero tag word matches no entry of any generation.
        assert!(tag(1, 0, SIGNED) > AUTHENTICATED);
        assert!(slot(u64::MAX, u64::MAX) < MEMO_ENTRIES);
    }

    /// Thunks run on the host: hits complete each form without the service,
    /// misses ask it on an aligned stack and complete what it completes, and
    /// a cleared tag word or a refusal exits with no write.
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn thunks_complete_hits_and_computed_misses_natively() {
        use crate::GuestState;
        use alloc::vec;
        use core::ffi::c_void;
        use core::sync::atomic::{AtomicU64, Ordering::SeqCst};
        unsafe extern "C" {
            fn mmap(
                address: *mut c_void,
                bytes: usize,
                protection: i32,
                flags: i32,
                fd: i32,
                offset: i64,
            ) -> *mut c_void;
            fn mprotect(address: *mut c_void, bytes: usize, protection: i32) -> i32;
            fn munmap(address: *mut c_void, bytes: usize) -> i32;
        }
        #[cfg(target_os = "macos")]
        const MAP_ANONYMOUS: i32 = 0x1000;
        #[cfg(target_os = "linux")]
        const MAP_ANONYMOUS: i32 = 0x20;
        const PAGE: usize = 4096;
        #[repr(C)]
        #[derive(Debug, PartialEq, Eq)]
        struct Exit {
            pc: u64,
            kind: u64,
        }
        // The service's calls, their last arguments, the stack alignment
        // they saw and the answer they give.
        static CALLS: AtomicU64 = AtomicU64::new(0);
        static STATE: AtomicU64 = AtomicU64::new(0);
        static REQUEST: AtomicU64 = AtomicU64::new(0);
        static OPERANDS: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
        static MISALIGNED: AtomicU64 = AtomicU64::new(0);
        static ANSWER: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
        extern "sysv64" fn service(
            state: u64,
            request: u32,
            pointer: u64,
            modifier: u64,
        ) -> Completion {
            // A u128 (16-byte aligned on x86-64) is at an aligned address
            // only in an aligned frame.
            const _: () = assert!(core::mem::align_of::<u128>() == 16);
            let local = core::hint::black_box(0u128);
            let address = core::hint::black_box(&raw const local) as u64;
            MISALIGNED.fetch_add(address & 15, SeqCst);
            CALLS.fetch_add(1, SeqCst);
            STATE.store(state, SeqCst);
            REQUEST.store(u64::from(request), SeqCst);
            OPERANDS[0].store(pointer, SeqCst);
            OPERANDS[1].store(modifier, SeqCst);
            Completion {
                completed: ANSWER[0].load(SeqCst),
                value: ANSWER[1].load(SeqCst),
            }
        }
        fn run(code: &[u8], state: &mut GuestState, misaligned: bool) -> Exit {
            // A misaligned run enters 8 bytes lower: Rust calls arrive with
            // RSP 8 mod 16, blocks run at 0 mod 16.
            let mut bytes = vec![];
            if misaligned {
                bytes.extend([0x48, 0x83, 0xec, 0x08]); // sub rsp,8
                bytes.push(0xe8); // call the thunk, after the next 5 bytes
                bytes.extend(5i32.to_le_bytes());
                bytes.extend([0x48, 0x83, 0xc4, 0x08, 0xc3]); // add rsp,8; ret
            }
            bytes.extend(code);
            // SAFETY: private anonymous memory, RX after the copy, unmapped
            // after the call; the thunk touches only `state`, the memo, the
            // tags and the stack, and calls `service`.
            unsafe {
                let page = mmap(core::ptr::null_mut(), PAGE, 3, 2 | MAP_ANONYMOUS, -1, 0);
                assert_ne!(page as usize, usize::MAX);
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), page.cast(), bytes.len());
                assert_eq!(mprotect(page, PAGE, 5), 0);
                let entry: unsafe extern "sysv64" fn(*mut GuestState) -> Exit =
                    core::mem::transmute(page);
                let exit = entry(state);
                assert_eq!(munmap(page, PAGE), 0);
                exit
            }
        }
        let pc = GuestAddress(0x4000);
        let (pointer, modifier, value) = (0xffff_fe00_1234_5678, 0xffff_fe00_0000_8000, 0xabcd);
        // Native code reads both through their addresses, so Rust writes
        // them through the same pointers.
        let mut memo = vec![MemoEntry::default(); MEMO_ENTRIES];
        let mut tags = [0u64; 4];
        let (memo, tags) = (memo.as_mut_ptr(), tags.as_mut_ptr());
        let address = (memo as u64, tags as u64);
        // SAFETY: key_index produces 0..4 and tags outlives these synchronous thunk calls.
        let set_tag = |key: u8, value: u64| unsafe { tags.add(usize::from(key)).write(value) };
        // SAFETY: slot masks into MEMO_ENTRIES; each returned borrow ends before native execution.
        let entry = |index: usize| unsafe { &mut *memo.add(index) };
        let routine: ServiceRoutine = service;
        let service = Service {
            state: 0x5e41,
            routine: routine as usize as u64,
        };
        let make = |operation| {
            thunk(
                Form::of(operation).unwrap(),
                pc,
                address.0,
                address.1,
                service,
            )
        };
        let mut state = GuestState::default();
        // PACIBSP: X30 signed with SP.
        let ib = key_index(Key::Ib);
        *entry(slot(pointer, modifier)) = MemoEntry {
            pointer,
            modifier,
            tag: tag(1, ib, SIGNED),
            value,
        };
        let sign = make(Operation::SignIbSp);
        state.x[30] = pointer;
        state.sp = modifier;
        let miss = Exit {
            pc: pc.0,
            kind: ExitKind::PointerAuthentication as u64,
        };
        assert_eq!(run(&sign.code, &mut state, false), miss, "a zero tag word");
        assert_eq!((state.x[30], CALLS.load(SeqCst)), (pointer, 0));
        set_tag(ib, tag(1, ib, 0));
        let next = Exit {
            pc: pc.0 + 4,
            kind: ExitKind::Fallthrough as u64,
        };
        assert_eq!(run(&sign.code, &mut state, false), next);
        assert_eq!((state.x[30], CALLS.load(SeqCst)), (value, 0));
        // Another modifier misses the memo: the service refuses, then
        // completes, on either stack alignment.
        state.x[30] = pointer;
        state.sp = modifier + 16;
        assert_eq!(run(&sign.code, &mut state, true), miss);
        assert_eq!(state.x[30], pointer);
        assert_eq!(
            (
                STATE.load(SeqCst),
                REQUEST.load(SeqCst),
                OPERANDS[0].load(SeqCst),
                OPERANDS[1].load(SeqCst)
            ),
            (0x5e41, u64::from(ib), pointer, modifier + 16)
        );
        ANSWER[0].store(1, SeqCst);
        ANSWER[1].store(0x1357, SeqCst);
        for misaligned in [false, true] {
            state.x[30] = pointer;
            assert_eq!(run(&sign.code, &mut state, misaligned), next);
            assert_eq!(state.x[30], 0x1357);
        }
        assert_eq!((CALLS.load(SeqCst), MISALIGNED.load(SeqCst)), (3, 0));
        // An authentication of the memo's signing operands misses too.
        state.x[30] = pointer;
        state.sp = modifier;
        let authenticate = make(Operation::AuthenticateIbSp);
        assert_eq!(run(&authenticate.code, &mut state, false), next);
        assert_eq!(
            REQUEST.load(SeqCst),
            u64::from(u32::from(ib) | REQUEST_AUTHENTICATE)
        );
        // BLRAA X8, X16 and RETAA take their branch with the result.
        let ia = key_index(Key::Ia);
        set_tag(ia, tag(1, ia, 0));
        entry(slot(pointer, modifier)).tag = tag(1, ia, AUTHENTICATED);
        let call = make(Operation::Branch {
            key: Key::Ia,
            target: 8,
            modifier: Modifier::Register(16),
            link: true,
        });
        state.x[8] = pointer;
        state.x[16] = modifier;
        let taken = |pc, kind: ExitKind| Exit {
            pc,
            kind: kind as u64,
        };
        let calls = CALLS.load(SeqCst);
        assert_eq!(
            run(&call.code, &mut state, false),
            taken(value, ExitKind::Call)
        );
        assert_eq!((state.x[8], state.x[30]), (pointer, pc.0 + 4));
        state.x[30] = pointer;
        let ret = make(Operation::ReturnIaSp);
        assert_eq!(
            run(&ret.code, &mut state, false),
            taken(value, ExitKind::Return)
        );
        assert_eq!((state.x[30], CALLS.load(SeqCst)), (pointer, calls));
        // A computed branch result, from a missed combined request.
        state.x[16] = modifier ^ 1;
        assert_eq!(
            run(&call.code, &mut state, false),
            taken(0x1357, ExitKind::Call)
        );
        assert_eq!(
            REQUEST.load(SeqCst),
            u64::from(u32::from(ia) | REQUEST_AUTHENTICATE | REQUEST_COMBINED)
        );
        // A disabled key returns every pointer unchanged, without the memo
        // or the service: PACIBSP leaves X30, BLRAA branches to X8 itself.
        let calls = CALLS.load(SeqCst);
        set_tag(ib, DISABLED);
        state.x[30] = pointer;
        state.sp = modifier + 32;
        assert_eq!(run(&sign.code, &mut state, false), next);
        assert_eq!(state.x[30], pointer);
        set_tag(ia, DISABLED);
        state.x[30] = 0;
        assert_eq!(
            run(&call.code, &mut state, false),
            taken(pointer, ExitKind::Call)
        );
        assert_eq!((state.x[8], state.x[30]), (pointer, pc.0 + 4));
        assert_eq!(CALLS.load(SeqCst), calls);
    }

    /// `mov [rdi+disp32],rax`.
    const REGISTER_WRITE_BYTES: usize = 7;
    /// The second opcode bytes of `jz` and `jnz` with a 32-bit displacement.
    const JZ: u8 = 0x84;
    const JNZ: u8 = 0x85;

    #[test]
    fn register_completions_chain_onward_and_misses_exit_unchanged() {
        let pc = GuestAddress(0x4000);
        let form = Form::of(Operation::SignIbSp).unwrap();
        let service = Service {
            state: 0x3000,
            routine: 0x4000,
        };
        let thunk = thunk(form, pc, 0x1000, 0x2000, service);
        let end = thunk.code.len();
        assert_eq!(
            thunk.code[end - 16..],
            super::super::chain::direct_exit(pc, ExitKind::PointerAuthentication)
        );
        let next = thunk.next.unwrap();
        assert_eq!(
            thunk.code[next..next + 16],
            super::super::chain::direct_exit(GuestAddress(0x4004), ExitKind::Fallthrough)
        );
        // The closed key and the refused service land on the exit; the
        // three memo misses on the service call, just after the completion.
        // The disabled key's identity lands on the completion's register write.
        let complete = next - REGISTER_WRITE_BYTES;
        let (mut exits, mut calls, mut identities) = (0, 0, 0);
        for at in 0..end - 6 {
            if thunk.code[at] == 0x0f && [JZ, JNZ].contains(&thunk.code[at + 1]) {
                let relative =
                    i32::from_le_bytes(thunk.code[at + 2..at + 6].try_into().unwrap()) as usize;
                match at + 6 + relative {
                    target if target == end - 16 => exits += 1,
                    target if target == next + 16 => calls += 1,
                    target if target == complete => identities += 1,
                    target => panic!("a jump to {target}"),
                }
            }
        }
        assert_eq!((exits, calls, identities), (2, 3, 1));
        assert_eq!(thunk.dynamic, None);
        // A return completes at its exit to the target in RAX, which the
        // service path reaches too.
        let ret = Form::of(Operation::ReturnIaSp).unwrap();
        let ret = super::thunk(ret, pc, 0, 0, service);
        assert_eq!(ret.next, None);
        let returns = ret.dynamic.unwrap();
        assert_eq!(
            ret.code[returns..returns + 6],
            super::super::chain::dynamic_exit(ExitKind::Return)
        );
        // The service path's `jmp complete` precedes the final exit.
        let back = ret.code.len() - 16 - 5;
        assert_eq!(ret.code[back], 0xe9);
        let relative = i32::from_le_bytes(ret.code[back + 1..back + 5].try_into().unwrap());
        assert_eq!((back as i64 + 5 + i64::from(relative)) as usize, returns);
    }
}
