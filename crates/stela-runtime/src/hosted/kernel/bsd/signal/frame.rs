//! The arm64 signal frame (xnu `bsd/dev/arm/unix_signal.c`): the
//! `user_sigframe64` `sendsig` copies out below the interrupted stack, and
//! the thread-state conversions `sigreturn` reverses
//! (`osfmk/arm64/status.c`).
//!
//! For a process with user JOP the saved `pc` and `lr` are signed with IA
//! (discriminators "pc" and "lr"), `sp` and `fp` with DA ("sp", "fp"), and
//! the flags carry `KERNEL_SIGNED_PC`, `KERNEL_SIGNED_LR`, the thread's
//! sigreturn diversifier and two four-bit sigreturn tokens; an `lr` already
//! signed with IB round-trips as it is (`IB_SIGNED_LR`). Without user JOP
//! every pointer is raw and the flags are `NO_PTRAUTH`. Layouts are the
//! SDK's `struct __darwin_mcontext64`, `struct __darwin_ucontext` and
//! `siginfo_t` for LP64.
use crate::hosted::kernel::status;
use crate::pauth::{Context, Key};
use anyhow::Result;

/// `user64_siginfo_t`, `struct user_ucontext64` and `mcontext64_t`.
pub(super) const SIGINFO_BYTES: usize = 104;
pub(super) const UCONTEXT_BYTES: usize = 56;
pub(super) const MCONTEXT_BYTES: usize = 816;
/// `struct user_sigframe64`: siginfo, then ucontext, then mcontext.
pub(super) const FRAME_BYTES: u64 = (SIGINFO_BYTES + UCONTEXT_BYTES + MCONTEXT_BYTES) as u64;
const UCONTEXT_OFFSET: u64 = SIGINFO_BYTES as u64;
const MCONTEXT_OFFSET: u64 = (SIGINFO_BYTES + UCONTEXT_BYTES) as u64;
/// `C_64_REDZONE_LEN`.
const REDZONE: u64 = 128;
/// `UC_FLAVOR_SIZE64`: the only machine-context size `sigreturn` takes.
pub(super) const UC_FLAVOR_SIZE64: u64 = MCONTEXT_BYTES as u64;

/// `mcontext64` field offsets: exception state, thread state, NEON state.
const ES_FAR: usize = 0;
const ES_ESR: usize = 8;
const ES_EXCEPTION: usize = 12;
const SS: usize = 16;
const SS_FP: usize = SS + 232;
const SS_LR: usize = SS + 240;
const SS_SP: usize = SS + 248;
const SS_PC: usize = SS + 256;
const SS_CPSR: usize = SS + 264;
const SS_FLAGS: usize = SS + 268;
const NS: usize = 288;
const NS_FPSR: usize = NS + 512;
const NS_FPCR: usize = NS + 516;

/// `__DARWIN_ARM_THREAD_STATE64_FLAGS_*` and the flag fields
/// (`osfmk/mach/arm/_structs.h`).
pub(super) const FLAGS_NO_PTRAUTH: u32 = 0x1;
pub(super) const FLAGS_IB_SIGNED_LR: u32 = 0x2;
pub(super) const FLAGS_KERNEL_SIGNED_PC: u32 = 0x4;
pub(super) const FLAGS_KERNEL_SIGNED_LR: u32 = 0x8;
pub(super) const USER_DIVERSIFIER_MASK: u32 = 0xff00_0000;
pub(super) const SIGRETURN_PC_MASK: u32 = 0x000f_0000;
pub(super) const SIGRETURN_LR_MASK: u32 = 0x00f0_0000;

/// `ptrauth_string_discriminator` of "pc", "lr", "sp", "fp", "uctx" and
/// "nonce", as the arm64e compiler folds them.
const DISCRIMINATOR_PC: u64 = 0x7481;
const DISCRIMINATOR_LR: u64 = 0x77d3;
const DISCRIMINATOR_SP: u64 = 0xcbed;
const DISCRIMINATOR_FP: u64 = 0x4517;
const DISCRIMINATOR_UCTX: u64 = 0xd4a6;
const DISCRIMINATOR_NONCE: u64 = 0xb743;

/// `ptrauth_blend_discriminator(pointer, integer)`, which the compiler
/// lowers to a MOVK of the integer into bits 63:48.
fn blend(pointer: u64, integer: u64) -> u64 {
    (integer << 48) | (pointer & 0x0000_ffff_ffff_ffff)
}

/// `PSR64_NZCV_MASK` (`PSR64_USER_MASK`) and `PSR64_MODE_MASK`: setting a
/// user thread state copies NZCV, clears the mode (EL0t) and keeps the
/// rest (`thread_state64_to_saved_state`).
pub(super) const PSR64_NZCV_MASK: u32 = 0xf000_0000;
pub(super) const PSR64_MODE_MASK: u32 = 0x1f;

/// The CPSR a user thread state `requested` leaves on a thread whose
/// saved CPSR is `current`.
pub(super) fn user_cpsr(current: u32, requested: u32) -> u32 {
    (current & !(PSR64_NZCV_MASK | PSR64_MODE_MASK)) | (requested & PSR64_NZCV_MASK)
}

/// `arm_thread_state64_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct ThreadState {
    pub x: [u64; 29],
    pub fp: u64,
    pub lr: u64,
    pub sp: u64,
    pub pc: u64,
    pub cpsr: u32,
    pub flags: u32,
}

/// `mcontext64_t`: exception, thread and NEON state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct MachineContext {
    pub far: u64,
    pub esr: u32,
    pub exception: u32,
    pub ss: ThreadState,
    pub v: [[u64; 2]; 32],
    pub fpsr: u32,
    pub fpcr: u32,
}

fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn get64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("eight bytes"))
}

fn get32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes"))
}

impl MachineContext {
    pub(super) fn to_bytes(self) -> [u8; MCONTEXT_BYTES] {
        let mut bytes = [0u8; MCONTEXT_BYTES];
        put64(&mut bytes, ES_FAR, self.far);
        put32(&mut bytes, ES_ESR, self.esr);
        put32(&mut bytes, ES_EXCEPTION, self.exception);
        for (index, &value) in self.ss.x.iter().enumerate() {
            put64(&mut bytes, SS + index * 8, value);
        }
        put64(&mut bytes, SS_FP, self.ss.fp);
        put64(&mut bytes, SS_LR, self.ss.lr);
        put64(&mut bytes, SS_SP, self.ss.sp);
        put64(&mut bytes, SS_PC, self.ss.pc);
        put32(&mut bytes, SS_CPSR, self.ss.cpsr);
        put32(&mut bytes, SS_FLAGS, self.ss.flags);
        for (index, lane) in self.v.iter().enumerate() {
            put64(&mut bytes, NS + index * 16, lane[0]);
            put64(&mut bytes, NS + index * 16 + 8, lane[1]);
        }
        put32(&mut bytes, NS_FPSR, self.fpsr);
        put32(&mut bytes, NS_FPCR, self.fpcr);
        bytes
    }

    pub(super) fn from_bytes(bytes: &[u8]) -> Self {
        let mut ss = ThreadState::default();
        for (index, value) in ss.x.iter_mut().enumerate() {
            *value = get64(bytes, SS + index * 8);
        }
        ss.fp = get64(bytes, SS_FP);
        ss.lr = get64(bytes, SS_LR);
        ss.sp = get64(bytes, SS_SP);
        ss.pc = get64(bytes, SS_PC);
        ss.cpsr = get32(bytes, SS_CPSR);
        ss.flags = get32(bytes, SS_FLAGS);
        let mut v = [[0u64; 2]; 32];
        for (index, lane) in v.iter_mut().enumerate() {
            *lane = [
                get64(bytes, NS + index * 16),
                get64(bytes, NS + index * 16 + 8),
            ];
        }
        Self {
            far: get64(bytes, ES_FAR),
            esr: get32(bytes, ES_ESR),
            exception: get32(bytes, ES_EXCEPTION),
            ss,
            v,
            fpsr: get32(bytes, NS_FPSR),
            fpcr: get32(bytes, NS_FPCR),
        }
    }
}

/// `struct user_ucontext64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct UserContext {
    pub onstack: i32,
    pub sigmask: u32,
    pub stack_pointer: u64,
    pub stack_size: u64,
    pub stack_flags: u32,
    pub link: u64,
    pub mcsize: u64,
    pub mcontext: u64,
}

impl UserContext {
    pub(super) fn to_bytes(self) -> [u8; UCONTEXT_BYTES] {
        let mut bytes = [0u8; UCONTEXT_BYTES];
        put32(&mut bytes, 0, self.onstack as u32);
        put32(&mut bytes, 4, self.sigmask);
        put64(&mut bytes, 8, self.stack_pointer);
        put64(&mut bytes, 16, self.stack_size);
        put32(&mut bytes, 24, self.stack_flags);
        put64(&mut bytes, 32, self.link);
        put64(&mut bytes, 40, self.mcsize);
        put64(&mut bytes, 48, self.mcontext);
        bytes
    }

    pub(super) fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            onstack: get32(bytes, 0) as i32,
            sigmask: get32(bytes, 4),
            stack_pointer: get64(bytes, 8),
            stack_size: get64(bytes, 16),
            stack_flags: get32(bytes, 24),
            link: get64(bytes, 32),
            mcsize: get64(bytes, 40),
            mcontext: get64(bytes, 48),
        }
    }
}

/// `user64_siginfo_t`: the fields `sendsig` fills.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct Siginfo {
    pub signo: i32,
    pub code: i32,
    pub pid: i32,
    pub uid: u32,
    pub status: i32,
    pub addr: u64,
    /// `pad[0]`: the interrupted stack pointer.
    pub sp: u64,
}

impl Siginfo {
    pub(super) fn to_bytes(self) -> [u8; SIGINFO_BYTES] {
        let mut bytes = [0u8; SIGINFO_BYTES];
        put32(&mut bytes, 0, self.signo as u32);
        put32(&mut bytes, 8, self.code as u32);
        put32(&mut bytes, 12, self.pid as u32);
        put32(&mut bytes, 16, self.uid);
        put32(&mut bytes, 20, self.status as u32);
        put64(&mut bytes, 24, self.addr);
        put64(&mut bytes, 48, self.sp);
        bytes
    }
}

/// Where `sendsig` places the frame: below `top` with the red zone,
/// 16-byte aligned; the siginfo, ucontext and mcontext addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Placement {
    pub sp: u64,
    pub siginfo: u64,
    pub ucontext: u64,
    pub mcontext: u64,
}

impl Placement {
    pub(super) fn below(top: u64) -> Self {
        let sp = top.wrapping_sub(FRAME_BYTES + REDZONE) & !0xf;
        Self {
            sp,
            siginfo: sp,
            ucontext: sp + UCONTEXT_OFFSET,
            mcontext: sp + MCONTEXT_OFFSET,
        }
    }
}

/// A thread's sigreturn validation state (`uu_sigreturn_token`,
/// `uu_sigreturn_diversifier`, `uu_pending_sigreturn`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Sigreturn {
    pub token: u64,
    pub diversifier: u32,
    pub pending: u32,
}

impl Sigreturn {
    /// `sendsig`: a fresh random token and nonzero diversifier, each from
    /// `random`, when no sigreturn is pending; then one more pending.
    pub(super) fn arm(&mut self, mut random: impl FnMut() -> u64) {
        if self.pending == 0 {
            self.token = random();
            self.diversifier = loop {
                let diversifier = random() as u32 & USER_DIVERSIFIER_MASK;
                if diversifier != 0 {
                    break diversifier;
                }
            };
        }
        self.pending += 1;
    }

    /// `thread_generate_sigreturn_token`: the signed pointer XORed with the
    /// thread's token, signed with DA under "nonce", high word.
    fn token(&self, signer: &Context, pointer: u64) -> Result<u32> {
        let value = pointer ^ self.token;
        Ok((signer.sign(Key::Da, value, DISCRIMINATOR_NONCE)? >> 32) as u32)
    }
}

/// `machine_thread_siguctx_pointer_convert_to_user`: the ucontext pointer
/// signed with DA under "uctx", raw without user JOP.
pub(super) fn ucontext_pointer(signer: Option<&Context>, pointer: u64) -> Result<u64> {
    match signer {
        Some(signer) if pointer != 0 => signer.sign(Key::Da, pointer, DISCRIMINATOR_UCTX),
        _ => Ok(pointer),
    }
}

/// `machine_thread_state_convert_to_user` with `TSSF_STASH_SIGRETURN_TOKEN`
/// and `TSSF_THREAD_USER_DIV`, as `sendsig_get_state64` asks.
pub(super) fn to_user(
    ss: &mut ThreadState,
    signer: Option<&Context>,
    sigreturn: &Sigreturn,
) -> Result<()> {
    let Some(signer) = signer else {
        ss.flags = FLAGS_NO_PTRAUTH;
        return Ok(());
    };
    ss.flags = 0;
    // An lr signed with IB (strip changes it) round-trips as it is.
    if ss.lr != 0 && signer.strip(Key::Ib, ss.lr)? != ss.lr {
        ss.flags |= FLAGS_IB_SIGNED_LR;
    }
    ss.flags |= sigreturn.diversifier & USER_DIVERSIFIER_MASK;
    ss.flags |= FLAGS_KERNEL_SIGNED_PC | FLAGS_KERNEL_SIGNED_LR;
    if ss.pc != 0 {
        ss.pc = signer.sign(Key::Ia, ss.pc, DISCRIMINATOR_PC)?;
    }
    if ss.lr != 0 && ss.flags & FLAGS_IB_SIGNED_LR == 0 {
        ss.lr = signer.sign(Key::Ia, ss.lr, DISCRIMINATOR_LR)?;
    }
    if ss.sp != 0 {
        ss.sp = signer.sign(Key::Da, ss.sp, DISCRIMINATOR_SP)?;
    }
    if ss.fp != 0 {
        ss.fp = signer.sign(Key::Da, ss.fp, DISCRIMINATOR_FP)?;
    }
    // `__DARWIN_ARM_THREAD_STATE64_SET_SIGRETURN_TOKEN`: each token's own
    // bits under its mask.
    ss.flags |= sigreturn.token(signer, ss.pc)? & SIGRETURN_PC_MASK;
    ss.flags |= sigreturn.token(signer, ss.lr)? & SIGRETURN_LR_MASK;
    Ok(())
}

/// How `sigreturn` converts a returned thread state: with the process's
/// validation enabled (or still undecided) it checks the sigreturn tokens
/// (`TSSF_CHECK_SIGRETURN_TOKEN | TSSF_ALLOW_ONLY_MATCHING_TOKEN`) and
/// takes the thread's diversifier (`TSSF_THREAD_USER_DIV`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Validation {
    Tokens,
    None,
}

/// `machine_thread_state_convert_from_user`: the pointers authenticated
/// (a failure poisons them), or `false` when a token does not match
/// (`KERN_PROTECTION_FAILURE`).
pub(super) fn from_user(
    ss: &mut ThreadState,
    signer: Option<&Context>,
    sigreturn: &Sigreturn,
    validation: Validation,
) -> Result<bool> {
    let Some(signer) = signer else {
        ss.flags = FLAGS_NO_PTRAUTH;
        return Ok(true);
    };
    // A JOP-enabled thread takes no unsigned state: the flag is ignored and
    // the pointers authenticated (and poisoned) as signed ones.
    ss.flags &= !FLAGS_NO_PTRAUTH;
    if ss.flags & FLAGS_IB_SIGNED_LR != 0 && signer.strip(Key::Ib, ss.lr)? == ss.lr {
        // An unsigned lr does not pass through as it is.
        ss.flags &= !FLAGS_IB_SIGNED_LR;
    }
    let kernel_signed_pc = ss.flags & FLAGS_KERNEL_SIGNED_PC != 0;
    let kernel_signed_lr = ss.flags & FLAGS_KERNEL_SIGNED_LR != 0;
    if validation == Validation::Tokens {
        let matches = |pointer: u64, mask: u32| -> Result<bool> {
            Ok(ss.flags & mask == sigreturn.token(signer, pointer)? & mask)
        };
        if (kernel_signed_pc && !matches(ss.pc, SIGRETURN_PC_MASK)?)
            || (kernel_signed_lr && !matches(ss.lr, SIGRETURN_LR_MASK)?)
        {
            return Ok(false);
        }
    }
    let diversifier = match validation {
        Validation::Tokens => u64::from(sigreturn.diversifier & USER_DIVERSIFIER_MASK),
        Validation::None => 0,
    };
    let discriminator = |kernel_signed: bool, string: u64| {
        if !kernel_signed && diversifier != 0 {
            blend(diversifier, string)
        } else {
            string
        }
    };
    if ss.pc != 0 {
        ss.pc = status::authenticate(
            signer,
            Key::Ia,
            ss.pc,
            discriminator(kernel_signed_pc, DISCRIMINATOR_PC),
        )?;
    }
    if ss.lr != 0 && ss.flags & FLAGS_IB_SIGNED_LR == 0 {
        ss.lr = status::authenticate(
            signer,
            Key::Ia,
            ss.lr,
            discriminator(kernel_signed_lr, DISCRIMINATOR_LR),
        )?;
    }
    if ss.sp != 0 {
        ss.sp = status::authenticate(signer, Key::Da, ss.sp, DISCRIMINATOR_SP)?;
    }
    if ss.fp != 0 {
        ss.fp = status::authenticate(signer, Key::Da, ss.fp, DISCRIMINATOR_FP)?;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hosted::kernel::status::tests::signer;

    fn state() -> ThreadState {
        let mut x = [0u64; 29];
        for (index, value) in x.iter_mut().enumerate() {
            *value = index as u64 * 0x1111;
        }
        ThreadState {
            x,
            fp: 0x16fd_ff00,
            lr: 0x1_8000_4320,
            sp: 0x16fd_fe80,
            pc: 0x1_0000_4abc,
            cpsr: 0x6000_0000,
            flags: 0,
        }
    }

    /// `random` yielding `words` in turn.
    fn words(words: &[u64]) -> impl FnMut() -> u64 + '_ {
        let mut next = words.iter();
        move || *next.next().expect("enough words")
    }

    fn armed() -> Sigreturn {
        let mut sigreturn = Sigreturn::default();
        sigreturn.arm(words(&[0x0123_4567_89ab_cdef, 0x5a00_0000]));
        sigreturn
    }

    #[test]
    fn the_frame_lies_below_the_red_zone_in_xnus_order() {
        assert_eq!(FRAME_BYTES, 976);
        let placement = Placement::below(0x16fd_ff38);
        assert_eq!(placement.sp, (0x16fd_ff38 - 976 - 128) & !0xf);
        assert_eq!(placement.siginfo, placement.sp);
        assert_eq!(placement.ucontext, placement.sp + 104);
        assert_eq!(placement.mcontext, placement.sp + 160);
        assert_eq!(placement.mcontext % 16, 0);
    }

    #[test]
    fn contexts_round_trip_through_their_layouts() {
        let mut context = MachineContext {
            far: 0xdead_0000,
            esr: 0x5600_0080,
            exception: 0,
            ss: state(),
            v: [[0; 2]; 32],
            fpsr: 0x10,
            fpcr: 0x0300_0000,
        };
        context.v[31] = [1, 2];
        let bytes = context.to_bytes();
        assert_eq!(get64(&bytes, SS_PC), context.ss.pc);
        assert_eq!(get32(&bytes, NS_FPCR), 0x0300_0000);
        assert_eq!(MachineContext::from_bytes(&bytes), context);
        let user = UserContext {
            onstack: 1,
            sigmask: 0x2000,
            stack_pointer: 0x7000,
            stack_size: 0x8000,
            stack_flags: 1,
            link: 0,
            mcsize: UC_FLAVOR_SIZE64,
            mcontext: 0x7100,
        };
        assert_eq!(UserContext::from_bytes(&user.to_bytes()), user);
    }

    #[test]
    fn arming_keeps_the_token_while_a_sigreturn_is_pending() {
        let mut sigreturn = armed();
        assert_eq!(sigreturn.pending, 1);
        assert_eq!(sigreturn.diversifier, 0x5a00_0000);
        sigreturn.arm(words(&[]));
        assert_eq!(
            (sigreturn.token, sigreturn.pending),
            (0x0123_4567_89ab_cdef, 2)
        );
        // A zero diversifier is drawn again.
        let mut fresh = Sigreturn::default();
        fresh.arm(words(&[1, 0x00ff_ffff, 0x0300_0000]));
        assert_eq!(fresh.diversifier, 0x0300_0000);
    }

    #[test]
    fn a_delivered_state_returns_through_sigreturn() {
        let signer = signer();
        let sigreturn = armed();
        let original = state();
        let mut user = original;
        to_user(&mut user, Some(&signer), &sigreturn).unwrap();
        assert_eq!(
            user.flags & !(SIGRETURN_PC_MASK | SIGRETURN_LR_MASK),
            0x5a00_0000 | FLAGS_KERNEL_SIGNED_PC | FLAGS_KERNEL_SIGNED_LR
        );
        assert_eq!(user.pc, signer.sign(Key::Ia, original.pc, 0x7481).unwrap());
        assert_eq!(user.sp, signer.sign(Key::Da, original.sp, 0xcbed).unwrap());
        // `arm_thread_state64_get_pc` authenticates the saved pc.
        assert_eq!(
            signer
                .authenticate(Key::Ia, user.pc, 0x7481)
                .unwrap()
                .pointer,
            original.pc
        );
        let mut back = user;
        assert!(from_user(&mut back, Some(&signer), &sigreturn, Validation::Tokens).unwrap());
        assert_eq!(
            (back.pc, back.lr, back.sp, back.fp),
            (original.pc, original.lr, original.sp, original.fp)
        );
        assert_eq!(back.x, original.x);
    }

    #[test]
    fn a_handler_sets_a_new_pc_with_the_user_diversifier() {
        // `arm_thread_state64_set_pc_fptr`: signed with "pc" blended with
        // the diversifier, and KERNEL_SIGNED_PC cleared.
        let signer = signer();
        let sigreturn = armed();
        let mut user = state();
        to_user(&mut user, Some(&signer), &sigreturn).unwrap();
        let target = 0x1_0000_8000;
        user.pc = signer
            .sign(Key::Ia, target, blend(0x5a00_0000, DISCRIMINATOR_PC))
            .unwrap();
        user.flags &= !FLAGS_KERNEL_SIGNED_PC;
        assert!(from_user(&mut user, Some(&signer), &sigreturn, Validation::Tokens).unwrap());
        assert_eq!(user.pc, target);
    }

    #[test]
    fn a_tampered_state_is_refused_or_poisoned() {
        let signer = signer();
        let sigreturn = armed();
        let mut user = state();
        to_user(&mut user, Some(&signer), &sigreturn).unwrap();
        // A kernel-signed pc replaced: its token no longer matches.
        let mut replaced = user;
        replaced.pc = signer.sign(Key::Ia, 0x1_0000_9000, 0x7481).unwrap();
        assert!(!from_user(&mut replaced, Some(&signer), &sigreturn, Validation::Tokens).unwrap());
        // Without validation the same state is taken, its forged sp
        // poisoned rather than refused.
        let mut forged = user;
        forged.sp = 0x16fd_0000;
        assert!(from_user(&mut forged, Some(&signer), &sigreturn, Validation::None).unwrap());
        assert_eq!(forged.sp, status::poison(0x16fd_0000, Key::Da));
        // Another thread's token does not validate.
        let other = Sigreturn {
            token: 99,
            ..sigreturn
        };
        let mut stolen = user;
        assert!(!from_user(&mut stolen, Some(&signer), &other, Validation::Tokens).unwrap());
    }

    #[test]
    fn an_ib_signed_lr_round_trips_as_it_is() {
        let signer = signer();
        let sigreturn = armed();
        let mut user = state();
        let return_address = signer.sign(Key::Ib, user.lr, user.sp).unwrap();
        user.lr = return_address;
        to_user(&mut user, Some(&signer), &sigreturn).unwrap();
        assert_ne!(user.flags & FLAGS_IB_SIGNED_LR, 0);
        assert_eq!(user.lr, return_address);
        assert!(from_user(&mut user, Some(&signer), &sigreturn, Validation::Tokens).unwrap());
        assert_eq!(user.lr, return_address);
    }

    #[test]
    fn without_user_jop_the_state_is_raw() {
        let original = state();
        let mut user = original;
        to_user(&mut user, None, &armed()).unwrap();
        assert_eq!(user.flags, FLAGS_NO_PTRAUTH);
        assert_eq!((user.pc, user.lr), (original.pc, original.lr));
        assert!(from_user(&mut user, None, &armed(), Validation::Tokens).unwrap());
        assert_eq!(user.pc, original.pc);
        assert_eq!(ucontext_pointer(None, 0x7000).unwrap(), 0x7000);
    }

    #[test]
    fn the_cpsr_keeps_only_nzcv_from_the_user() {
        assert_eq!(user_cpsr(0x0000_1000, 0xf000_03c5), 0xf000_1000);
        assert_eq!(user_cpsr(0x6000_0000, 0), 0);
    }
}
