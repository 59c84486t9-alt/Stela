//! Native completion of remembered PAC results for the system-mode engine.
//!
//! A PAC instruction ends its block with an exit to the engine, which
//! computes the result (Arm `AddPAC`, `Auth`) and remembers it in a memo of
//! [`MemoEntry`]s at a fixed host address: the operands, a tag and the
//! result. A [`thunk`] the engine installs over that exit looks the operands
//! up in the memo and, when the entry's tag is the one `tags` holds for the
//! instruction's key and the result's kind, completes the instruction
//! natively: it writes the result register and leaves through a direct exit
//! to the next instruction, or, for a branch, takes it through the exit the
//! branch form takes. Anything else takes the original exit.
//!
//! The engine keeps a key's tag word zero while the key's result is not the
//! memo's to give (the key disabled or its use trapped, or the memo's keys,
//! PAC version or TCR stale), so no entry matches it: entry tags are at least
//! [`tag`] of generation 1. Thunks clobber only RAX, RCX, RDX, R8 and flags.
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
enum Completion {
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
    completion: Completion,
}

impl Form {
    /// The form of `operation`, or `None` for the PAC instructions thunks do
    /// not complete: strips, generic codes, loads, FEAT_PAuth_LR forms and
    /// register-31 operands.
    pub fn of(operation: Operation) -> Option<Self> {
        let sp = Modifier::StackPointer;
        let x16 = Modifier::Register(16);
        let (key, kind, pointer, modifier, completion) = match operation {
            Operation::SignIbSp => (Key::Ib, SIGNED, 30, sp, Completion::Register),
            Operation::AuthenticateIbSp => (Key::Ib, AUTHENTICATED, 30, sp, Completion::Register),
            Operation::ReturnIbSp => (Key::Ib, AUTHENTICATED, 30, sp, Completion::Return),
            Operation::ReturnIaSp => (Key::Ia, AUTHENTICATED, 30, sp, Completion::Return),
            Operation::Sign1716 { key } => (key, SIGNED, 17, x16, Completion::Register),
            Operation::Authenticate1716 { key } => {
                (key, AUTHENTICATED, 17, x16, Completion::Register)
            }
            Operation::Sign {
                key,
                destination,
                modifier,
            } => (key, SIGNED, destination, modifier, Completion::Register),
            Operation::Authenticate {
                key,
                destination,
                modifier,
            } => (
                key,
                AUTHENTICATED,
                destination,
                modifier,
                Completion::Register,
            ),
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
                Completion::Branch { link },
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
/// completion, which the engine may chain like a block's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Thunk {
    pub code: Vec<u8>,
    pub next: Option<usize>,
}

/// The thunk completing the PAC instruction of `form` at `pc` from the memo
/// at `memo` under the tag words at `tags`, else exiting at `pc` for the
/// engine.
pub fn thunk(form: Form, pc: GuestAddress, memo: u64, tags: u64) -> Thunk {
    let mut code = Vec::with_capacity(160);
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
    code.extend([0x48, 0x89, 0xd1]); // mov rcx,rdx
    code.extend([0x48, 0xc1, 0xc1, 29]); // rol rcx,29
    code.extend([0x48, 0x31, 0xc1]); // xor rcx,rax
    code.extend([0x49, 0xb8]); // movabs r8,MIX
    code.extend(MIX.to_le_bytes());
    code.extend([0x49, 0x0f, 0xaf, 0xc8]); // imul rcx,r8
    code.extend([0x48, 0xc1, 0xe9, SLOT_SHIFT]); // shr rcx,50
    code.extend([0x48, 0xc1, 0xe1, 5]); // shl rcx,5: 32-byte entries
    code.extend([0x49, 0xb8]); // movabs r8,memo
    code.extend(memo.to_le_bytes());
    code.extend([0x4c, 0x01, 0xc1]); // add rcx,r8
    let mut misses = Vec::new();
    code.extend([0x48, 0x3b, 0x01]); // cmp rax,[rcx]
    miss(&mut code, &mut misses);
    code.extend([0x48, 0x3b, 0x51, MODIFIER]); // cmp rdx,[rcx+modifier]
    miss(&mut code, &mut misses);
    code.extend([0x49, 0xb8]); // movabs r8,&tags[key]
    code.extend((tags + u64::from(key_index(form.key)) * 8).to_le_bytes());
    code.extend([0x49, 0x8b, 0x00]); // mov rax,[r8]
    code.extend([0x48, 0x83, 0xc8, form.kind as u8]); // or rax,kind
    code.extend([0x48, 0x3b, 0x41, TAG]); // cmp rax,[rcx+tag]
    miss(&mut code, &mut misses);
    code.extend([0x48, 0x8b, 0x41, VALUE]); // mov rax,[rcx+value]
    let next_pc = GuestAddress(pc.0.wrapping_add(4));
    let mut next = None;
    match form.completion {
        Completion::Register => {
            code.extend([0x48, 0x89, 0x87]); // mov [rdi+pointer],rax
            code.extend(pointer.to_le_bytes());
            next = Some(code.len());
            code.extend(super::chain::direct_exit(next_pc, ExitKind::Fallthrough));
        }
        Completion::Return => exit_kind(&mut code, ExitKind::Return),
        Completion::Branch { link } => {
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
    let exit = code.len();
    for fixup in misses {
        let relative = (exit - fixup - 4) as i32;
        code[fixup..fixup + 4].copy_from_slice(&relative.to_le_bytes());
    }
    code.extend(super::chain::direct_exit(
        pc,
        ExitKind::PointerAuthentication,
    ));
    Thunk { code, next }
}

const STACK_POINTER: u32 = core::mem::offset_of!(crate::GuestState, sp) as u32;

/// `jne` to the miss exit, its displacement recorded for fixing up.
fn miss(code: &mut Vec<u8>, misses: &mut Vec<usize>) {
    code.extend([0x0f, 0x85]);
    misses.push(code.len());
    code.extend([0; 4]);
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
        let branch = Form::of(Operation::Branch {
            key: Key::Ia,
            target: 8,
            modifier: Modifier::Register(16),
            link: true,
        })
        .unwrap();
        assert_eq!(branch.completion, Completion::Branch { link: true });
        assert_eq!(branch.kind, AUTHENTICATED);
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

    /// Thunks run on the host: hits complete each form, a cleared tag word
    /// or other operands miss to the original exit with no write.
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn thunks_complete_hits_natively_and_exit_on_misses() {
        use crate::GuestState;
        use core::ffi::c_void;
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
        fn run(code: &[u8], state: &mut GuestState) -> Exit {
            // SAFETY: private anonymous memory, RX after the copy, unmapped
            // after the call; the thunk touches only `state`, the memo and
            // the tags, which outlive it.
            unsafe {
                let page = mmap(core::ptr::null_mut(), PAGE, 3, 2 | MAP_ANONYMOUS, -1, 0);
                assert_ne!(page as usize, usize::MAX);
                core::ptr::copy_nonoverlapping(code.as_ptr(), page.cast(), code.len());
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
        let mut state = GuestState::default();
        // PACIBSP: X30 signed with SP.
        let ib = key_index(Key::Ib);
        *entry(slot(pointer, modifier)) = MemoEntry {
            pointer,
            modifier,
            tag: tag(1, ib, SIGNED),
            value,
        };
        let sign = thunk(
            Form::of(Operation::SignIbSp).unwrap(),
            pc,
            address.0,
            address.1,
        );
        state.x[30] = pointer;
        state.sp = modifier;
        let miss = Exit {
            pc: pc.0,
            kind: ExitKind::PointerAuthentication as u64,
        };
        assert_eq!(run(&sign.code, &mut state), miss, "a zero tag word");
        assert_eq!(state.x[30], pointer);
        set_tag(ib, tag(1, ib, 0));
        let next = Exit {
            pc: pc.0 + 4,
            kind: ExitKind::Fallthrough as u64,
        };
        assert_eq!(run(&sign.code, &mut state), next);
        assert_eq!(state.x[30], value);
        // Another modifier, or an authentication of the same operands, misses.
        state.x[30] = pointer;
        state.sp = modifier + 16;
        assert_eq!(run(&sign.code, &mut state), miss);
        state.sp = modifier;
        let authenticate = thunk(
            Form::of(Operation::AuthenticateIbSp).unwrap(),
            pc,
            address.0,
            address.1,
        );
        assert_eq!(run(&authenticate.code, &mut state), miss);
        assert_eq!(state.x[30], pointer);
        // BLRAA X8, X16 and RETAA take their branch with the result.
        let ia = key_index(Key::Ia);
        set_tag(ia, tag(1, ia, 0));
        entry(slot(pointer, modifier)).tag = tag(1, ia, AUTHENTICATED);
        let call = Operation::Branch {
            key: Key::Ia,
            target: 8,
            modifier: Modifier::Register(16),
            link: true,
        };
        state.x[8] = pointer;
        state.x[16] = modifier;
        let call = thunk(Form::of(call).unwrap(), pc, address.0, address.1);
        let taken = |kind: ExitKind| Exit {
            pc: value,
            kind: kind as u64,
        };
        assert_eq!(run(&call.code, &mut state), taken(ExitKind::Call));
        assert_eq!((state.x[8], state.x[30]), (pointer, pc.0 + 4));
        state.x[30] = pointer;
        let ret = thunk(
            Form::of(Operation::ReturnIaSp).unwrap(),
            pc,
            address.0,
            address.1,
        );
        assert_eq!(run(&ret.code, &mut state), taken(ExitKind::Return));
        assert_eq!(state.x[30], pointer);
    }

    #[test]
    fn register_completions_chain_onward_and_misses_exit_unchanged() {
        let pc = GuestAddress(0x4000);
        let form = Form::of(Operation::SignIbSp).unwrap();
        let thunk = thunk(form, pc, 0x1000, 0x2000);
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
        // Every jne lands on the miss exit.
        let mut jumps = 0;
        for at in 0..end - 6 {
            if thunk.code[at..at + 2] == [0x0f, 0x85] {
                let relative =
                    i32::from_le_bytes(thunk.code[at + 2..at + 6].try_into().unwrap()) as usize;
                assert_eq!(at + 6 + relative, end - 16);
                jumps += 1;
            }
        }
        assert_eq!(jumps, 3);
        let ret = Form::of(Operation::ReturnIaSp).unwrap();
        assert_eq!(super::thunk(ret, pc, 0, 0).next, None);
    }
}
