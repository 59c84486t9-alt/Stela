//! Native atomic half-DTE replacement. No stack/red-zone or RBX corruption.
use core::ptr::NonNull;

pub(super) fn supported() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        // CPUID leaf one exists on the declared x86-64 baseline.
        core::arch::x86_64::__cpuid(1).ecx & (1 << 13) != 0
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// # Safety
/// CX16 is available on every CPU allowed to execute this call. `target`
/// covers aligned kept writable WB RAM, with every other software/hardware
/// writer excluded. `old` is the complete expected comparison image; it may
/// differ from current memory, in which case no new image is installed.
#[inline(never)]
pub(super) unsafe fn replace(target: NonNull<u64>, old: [u64; 2], new: [u64; 2]) -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        let replaced: u8;
        // SAFETY: the caller provides CX16, exclusion and the aligned live
        // 16-byte span. R8 temporarily holds RBX; the second exchange restores
        // RBX on both comparison outcomes. No stack or red-zone byte is touched.
        // RAX/RDX compare old; RBX/RCX install new. The memory/flags clobbers are
        // intentional and the LOCKed RMW is the atomic hardware store.
        unsafe {
            core::arch::asm!(
                "xchg rbx, r8",
                "lock cmpxchg16b [r11]",
                "setz r9b",
                "xchg rbx, r8",
                in("r11") target.as_ptr(),
                inout("rax") old[0] => _,
                inout("rdx") old[1] => _,
                inout("r8") new[0] => _,
                in("rcx") new[1],
                lateout("r9b") replaced,
                options(nostack),
            );
        }
        replaced != 0
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (target, old, new);
        // The public owner refuses unsupported architectures before calling.
        unreachable!("native DTE replacement requires x86-64 CX16")
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[repr(align(16))]
    struct Storage([u64; 8]);

    #[test]
    fn supported_cx16_replaces_only_the_aligned_half_and_reports_compare_failure() {
        if !supported() {
            // The public owner's fixtures assert UnsupportedAtomic on this
            // host; no software fallback pretends to execute CX16.
            std::println!("AMD_DTE_CX16 executed=false unsupported=true");
            return;
        }
        let old = [0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210];
        let new = [0x1357_9bdf_0246_8ace, 0xdead_beef_cafe_babe];
        let mut storage = Storage([
            0x1111_2222_3333_4444,
            0x5555_6666_7777_8888,
            old[0],
            old[1],
            0x9999_aaaa_bbbb_cccc,
            0xdddd_eeee_ffff_0000,
            0x1234_5678_9abc_def0,
            0xf0de_bc9a_7856_3412,
        ]);
        let original = storage.0;
        let target = NonNull::new(core::ptr::addr_of_mut!(storage.0[2])).unwrap();
        assert!((target.as_ptr() as usize).is_multiple_of(16));
        // SAFETY: this fixture uses the host OS process ISA contract and checks
        // local CX16. This thread exclusively owns aligned WB
        // stack RAM; no device or other writer can access the target.
        assert!(unsafe { replace(target, old, new) });
        let mut expected = original;
        expected[2..4].copy_from_slice(&new);
        assert_eq!(storage.0, expected, "only the exact16B target changes");
        // SAFETY: same live aligned exclusive RAM; stale compare
        // image must report false without changing any target or neighbor byte.
        assert!(!unsafe { replace(target, old, [u64::MAX, u64::MAX]) });
        assert_eq!(storage.0, expected);
        // SAFETY: the currently installed image is the next comparand.
        assert!(unsafe { replace(target, new, old) });
        assert_eq!(storage.0, original);
        std::println!("AMD_DTE_CX16 executed=true compare_failure=true neighbor_words=6");
    }
}
