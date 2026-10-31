//! The PAC cipher of a system-mode guest, whose hardware's algorithm is
//! IMPLEMENTATION DEFINED on Apple silicon: six AES rounds of the pointer and modifier under the key, with
//! the block's halves folded into the code. AES-NI runs them in far less time
//! than QARMA5 takes in software, and like it indexes no memory with secret
//! data. Hosts without AES-NI use QARMA5.

use super::qarma;

/// One `compute` of `data` and `modifier` under `key`, the key's high word
/// first as [`qarma::compute`] takes it.
pub(super) fn compute(data: u64, modifier: u64, key: &[u64; 2]) -> u64 {
    #[cfg(target_arch = "x86_64")]
    if aes::available() {
        // SAFETY: CPUID reports AES-NI.
        return unsafe { aes::compute(data, modifier, key) };
    }
    qarma::compute(data, modifier, key)
}

#[cfg(target_arch = "x86_64")]
pub(super) mod aes {
    use core::sync::atomic::{AtomicU8, Ordering};

    /// CPUID.1:ECX.AESNI.
    const CPUID_AES: u32 = 1 << 25;
    const UNKNOWN: u8 = 0;
    const ABSENT: u8 = 1;
    const PRESENT: u8 = 2;
    static AES: AtomicU8 = AtomicU8::new(UNKNOWN);
    /// What sets each round's key apart from the others': the fractional
    /// digits of pi QARMA's round constants take, a nothing-up-my-sleeve
    /// choice.
    #[repr(C, align(16))]
    struct Constants([u64; 12]);
    static CONSTANTS: Constants = Constants([
        0x1319_8a2e_0370_7344,
        0xa409_3822_299f_31d0,
        0x082e_fa98_ec4e_6c89,
        0x4528_21e6_38d0_1377,
        0xbe54_66cf_34e9_0c6c,
        0xc0ac_29b7_c97c_50dd,
        0x3f84_d5b5_b547_0917,
        0x9216_d5d9_8979_fb1b,
        0xd131_0ba6_98df_b5ac,
        0x2ffd_72db_d01a_dfb7,
        0xb8e1_afed_6a26_7e96,
        0xba7c_9045_f12c_7f99,
    ]);

    pub(super) fn available() -> bool {
        match AES.load(Ordering::Relaxed) {
            UNKNOWN => {
                let present = core::arch::x86_64::__cpuid(1).ecx & CPUID_AES != 0;
                AES.store(if present { PRESENT } else { ABSENT }, Ordering::Relaxed);
                present
            }
            state => state == PRESENT,
        }
    }

    // XMM0 is the state, XMM1 the key and XMM2 its round's key.
    #[unsafe(naked)]
    unsafe extern "sysv64" fn rounds(data: u64, modifier: u64, key: *const [u64; 2]) -> u64 {
        core::arch::naked_asm!(
            ".macro keyed_round offset",
            "movdqa xmm2, xmm1",
            "pxor xmm2, xmmword ptr [rax + \\offset]",
            "aesenc xmm0, xmm2",
            ".endm",
            "lea rax, [rip + {constants}]",
            "movq xmm0, rdi",
            "movq xmm1, rsi",
            "punpcklqdq xmm0, xmm1",
            "movdqu xmm1, xmmword ptr [rdx]",
            "pxor xmm0, xmm1",
            "keyed_round 0",
            "keyed_round 16",
            "keyed_round 32",
            "keyed_round 48",
            "keyed_round 64",
            "pxor xmm1, xmmword ptr [rax + 80]",
            "aesenclast xmm0, xmm1",
            "movq rax, xmm0",
            "psrldq xmm0, 8",
            "movq rcx, xmm0",
            "xor rax, rcx",
            "ret",
            ".purgem keyed_round",
            constants = sym CONSTANTS,
        )
    }

    /// # Safety
    ///
    /// The processor implements AES-NI ([`available`]).
    pub(super) unsafe fn compute(data: u64, modifier: u64, key: &[u64; 2]) -> u64 {
        // SAFETY: the caller checked AES-NI; the routine reads only `key` and
        // the constants and clobbers only registers the ABI lets a call
        // clobber.
        unsafe { rounds(data, modifier, key) }
    }
}

#[cfg(test)]
mod tests {
    use super::compute;

    /// Each input bit moves about half of the code, so a guest learns nothing
    /// of one code from another's.
    #[test]
    fn each_input_moves_half_of_the_code() {
        const KEY: [u64; 2] = [0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210];
        let base = compute(0x1234_5678, 0x9abc_def0, &KEY);
        assert_eq!(base, compute(0x1234_5678, 0x9abc_def0, &KEY));
        let mut moved = 0;
        for bit in 0..64 {
            moved += (base ^ compute(0x1234_5678 ^ 1 << bit, 0x9abc_def0, &KEY)).count_ones();
            moved += (base ^ compute(0x1234_5678, 0x9abc_def0 ^ 1 << bit, &KEY)).count_ones();
            let mut key = KEY;
            key[bit % 2] ^= 1 << bit;
            moved += (base ^ compute(0x1234_5678, 0x9abc_def0, &key)).count_ones();
        }
        let flips = 3 * 64;
        assert!((flips * 28..flips * 36).contains(&moved), "{moved}");
    }
}
