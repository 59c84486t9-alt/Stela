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
//! The engine keeps a key's tag word zero while the key's result is not the
//! memo's to give (the key disabled or its use trapped, or the memo's keys,
//! PAC version or TCR stale), so no entry matches it and the service is
//! never asked: entry tags are at least [`tag`] of generation 1. A memo hit
//! clobbers RAX, RCX, RDX, R8, R9 and flags; a service call every register
//! the SysV ABI lets a call clobber, which no block keeps live across its
//! exit. The call aligns the stack to 16 bytes itself.
use crate::{
    GuestAddress,
    block::{
        ExitKind, PointerAuthenticationKey as Key, PointerAuthenticationModifier as Modifier,
        PointerAuthenticationOperation as Operation,
    },
};
use alloc::vec::Vec;

/// Entries in the memo.
pub const MEMO_ENTRIES: usize = 1 << 14;
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
const MODIFIER: u8 = core::mem::offset_of!(MemoEntry, modifier) as u8;
const TAG: u8 = core::mem::offset_of!(MemoEntry, tag) as u8;
const VALUE: u8 = core::mem::offset_of!(MemoEntry, value) as u8;
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
/// the target in RAX after a return completion
/// (`chain::dynamic_exit`), which the engine may redirect through a lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Thunk {
    pub code: Vec<u8>,
    pub next: Option<usize>,
    pub returns: Option<usize>,
}

/// The thunk completing the PAC instruction of `form` at `pc` from the memo
/// at `memo` under the tag words at `tags`, or through `service`, else
/// exiting at `pc` for the engine.
pub fn thunk(form: Form, pc: GuestAddress, memo: u64, tags: u64, service: Service) -> Thunk {
    let mut code = Vec::with_capacity(256);
    let mut exits = Vec::new();
    let pointer = u32::from(form.pointer) * 8;
    code.extend([0x48, 0x8b, 0x87]); // mov rax,[rdi+pointer]
    code.extend(pointer.to_le_bytes());
    match form.modifier {
        Modifier::Register(register) => {
            code.extend([0x48, 0x8b, 0x97]); // mov rdx,[rdi+modifier]
            code.extend((u32::from(register) * 8).to_le_bytes());
        }
        Modifier::StackPointer => {
            code.extend([0x48, 0x8b, 0x97]);
            code.extend(STACK_POINTER.to_le_bytes());
        }
        Modifier::Zero => code.extend([0x31, 0xd2]), // xor edx,edx
    }
    code.extend([0x49, 0xb8]); // movabs r8,&tags[key]
    code.extend((tags + u64::from(key_index(form.key)) * 8).to_le_bytes());
    code.extend([0x4d, 0x8b, 0x00]); // mov r8,[r8]
    code.extend([0x4d, 0x85, 0xc0]); // test r8,r8
    jump(&mut code, &mut exits, JZ); // jz: the key is not open
    code.extend([0x48, 0x89, 0xd1]); // mov rcx,rdx
    code.extend([0x48, 0xc1, 0xc1, 29]); // rol rcx,29
    code.extend([0x48, 0x31, 0xc1]); // xor rcx,rax
    code.extend([0x49, 0xb9]); // movabs r9,MIX
    code.extend(MIX.to_le_bytes());
    code.extend([0x49, 0x0f, 0xaf, 0xc9]); // imul rcx,r9
    code.extend([0x48, 0xc1, 0xe9, SLOT_SHIFT]); // shr rcx,50
    code.extend([0x48, 0xc1, 0xe1, 5]); // shl rcx,5: 32-byte entries
    code.extend([0x49, 0xb9]); // movabs r9,memo
    code.extend(memo.to_le_bytes());
    code.extend([0x4c, 0x01, 0xc9]); // add rcx,r9
    let mut misses = Vec::new();
    code.extend([0x48, 0x3b, 0x01]); // cmp rax,[rcx]
    jump(&mut code, &mut misses, JNZ);
    code.extend([0x48, 0x3b, 0x51, MODIFIER]); // cmp rdx,[rcx+modifier]
    jump(&mut code, &mut misses, JNZ);
    code.extend([0x49, 0x83, 0xc8, form.kind as u8]); // or r8,kind
    code.extend([0x4c, 0x3b, 0x41, TAG]); // cmp r8,[rcx+tag]
    jump(&mut code, &mut misses, JNZ);
    code.extend([0x48, 0x8b, 0x41, VALUE]); // mov rax,[rcx+value]
    let complete = code.len();
    let next_pc = GuestAddress(pc.0.wrapping_add(4));
    let mut next = None;
    let mut returns = None;
    match form.completion {
        Finish::Register => {
            code.extend([0x48, 0x89, 0x87]); // mov [rdi+pointer],rax
            code.extend(pointer.to_le_bytes());
            next = Some(code.len());
            code.extend(super::chain::direct_exit(next_pc, ExitKind::Fallthrough));
        }
        Finish::Return => {
            returns = Some(code.len());
            exit_kind(&mut code, ExitKind::Return);
        }
        Finish::Branch { link } => {
            if link {
                code.extend([0x48, 0xb9]); // movabs rcx,next_pc
                code.extend(next_pc.0.to_le_bytes());
                code.extend([0x48, 0x89, 0x8f]); // mov [rdi+x30],rcx
                code.extend((30u32 * 8).to_le_bytes());
            }
            exit_kind(
                &mut code,
                if link {
                    ExitKind::Call
                } else {
                    ExitKind::Indirect
                },
            );
        }
    }
    land(&mut code, &misses);
    // service(state, request, pointer, modifier) on a 16-byte aligned stack.
    code.extend([0x49, 0x89, 0xe3]); // mov r11,rsp
    code.extend([0x48, 0x83, 0xe4, 0xf0]); // and rsp,-16
    code.extend([0x41, 0x53, 0x57]); // push r11; push rdi
    code.extend([0x48, 0x89, 0xd1]); // mov rcx,rdx
    code.extend([0x48, 0x89, 0xc2]); // mov rdx,rax
    code.push(0xbe); // mov esi,request
    code.extend(form.request().to_le_bytes());
    code.extend([0x48, 0xbf]); // movabs rdi,state
    code.extend(service.state.to_le_bytes());
    code.extend([0x48, 0xb8]); // movabs rax,routine
    code.extend(service.routine.to_le_bytes());
    code.extend([0xff, 0xd0]); // call rax
    code.extend([0x5f, 0x5c]); // pop rdi; pop rsp
    code.extend([0x48, 0x85, 0xc0]); // test rax,rax
    jump(&mut code, &mut exits, JZ); // jz: not completed
    code.extend([0x48, 0x89, 0xd0]); // mov rax,rdx
    code.push(0xe9); // jmp complete
    let back = complete as i64 - (code.len() + 4) as i64;
    code.extend((back as i32).to_le_bytes());
    land(&mut code, &exits);
    code.extend(super::chain::direct_exit(
        pc,
        ExitKind::PointerAuthentication,
    ));
    Thunk {
        code,
        next,
        returns,
    }
}

/// The second opcode bytes of `jz` and `jnz` with a 32-bit displacement.
const JZ: u8 = 0x84;
const JNZ: u8 = 0x85;

const STACK_POINTER: u32 = core::mem::offset_of!(crate::GuestState, sp) as u32;

/// A `jcc` (`opcode` after 0x0f) whose displacement [`land`] fixes up.
fn jump(code: &mut Vec<u8>, fixups: &mut Vec<usize>, opcode: u8) {
    code.extend([0x0f, opcode]);
    fixups.push(code.len());
    code.extend([0; 4]);
}

/// Point the jumps at `fixups` here.
fn land(code: &mut [u8], fixups: &[usize]) {
    let here = code.len();
    for &fixup in fixups {
        let relative = (here - fixup - 4) as i32;
        code[fixup..fixup + 4].copy_from_slice(&relative.to_le_bytes());
    }
}

fn exit_kind(code: &mut Vec<u8>, kind: ExitKind) {
    code.push(0xba); // mov edx,kind
    code.extend((kind as u32).to_le_bytes());
    code.push(0xc3); // ret
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

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
        let set_tag = |key: u8, value: u64| unsafe { tags.add(usize::from(key)).write(value) };
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
    }

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
        let (mut exits, mut calls) = (0, 0);
        for at in 0..end - 6 {
            if thunk.code[at] == 0x0f && [JZ, JNZ].contains(&thunk.code[at + 1]) {
                let relative =
                    i32::from_le_bytes(thunk.code[at + 2..at + 6].try_into().unwrap()) as usize;
                match at + 6 + relative {
                    target if target == end - 16 => exits += 1,
                    target if target == next + 16 => calls += 1,
                    target => panic!("a jump to {target}"),
                }
            }
        }
        assert_eq!((exits, calls), (2, 3));
        assert_eq!(thunk.returns, None);
        // A return completes at its exit to the target in RAX, which the
        // service path reaches too.
        let ret = Form::of(Operation::ReturnIaSp).unwrap();
        let ret = super::thunk(ret, pc, 0, 0, service);
        assert_eq!(ret.next, None);
        let returns = ret.returns.unwrap();
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
