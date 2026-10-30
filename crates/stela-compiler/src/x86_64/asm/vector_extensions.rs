//! Capability-checked packed bit operations (Intel SDM Vol. 2).
#[cfg(test)]
use super::Vex;
use super::{Code, Evex, Gpr, Map, Pp, Rm};
use crate::TargetCpu;
use crate::x86_64::isa::SimdOpcode as Host;

/// Reverse each byte in `destination`, using `scratch` and RAX for the
/// anti-diagonal affine matrix. The DIT profile keeps its reviewed recipe.
pub(crate) fn reverse_bytes(
    code: &mut Code,
    destination: u8,
    scratch: u8,
    target: TargetCpu,
) -> bool {
    if !target.supports(TargetCpu::Gfni) || target.data_independent_timing() {
        return false;
    }
    debug_assert_ne!(destination, scratch);
    let mut asm = code.asm();
    asm.mov_imm64(Gpr::Rax, 0x8040_2010_0804_0201);
    asm.movq_to_xmm(scratch, Gpr::Rax);
    asm.simd(
        Host::UnpackLowQword,
        scratch,
        Rm::Xmm(scratch),
        TargetCpu::Baseline,
    );
    asm.gf2p8affineqb(destination, Rm::Xmm(scratch), 0);
    true
}

/// EVEX.128 needs usable opmask/ZMM state and VL in addition to its lane
/// extension. The feature declarations are independent for explicit targets.
pub(crate) fn population_supported(lane_bytes: u8, target: TargetCpu) -> bool {
    let extension = match lane_bytes {
        1 | 2 => TargetCpu::Avx512bitalg,
        4 | 8 => TargetCpu::Avx512vpopcntdq,
        _ => return false,
    };
    target.supports(TargetCpu::Avx512f)
        && target.supports(TargetCpu::Avx512vl)
        && target.supports(extension)
        && !target.data_independent_timing()
}

/// EVEX.128 ternary logic needs F and VL. The DIT profile keeps its recipe.
pub(crate) fn merge_supported(target: TargetCpu) -> bool {
    target.supports(TargetCpu::Avx512f)
        && target.supports(TargetCpu::Avx512vl)
        && !target.data_independent_timing()
}

/// Select each bit from the new destination where mask is set, else from old.
/// VPTERNLOGD indexes imm8 with destination:old:mask, so this table is 0xe4.
/// k0 disables opmasking: byte/halfword predicates remain full bitwise masks.
pub(crate) fn merge(
    code: &mut Code,
    destination: u8,
    old: u8,
    mask: u8,
    target: TargetCpu,
) -> bool {
    if !merge_supported(target) {
        return false;
    }
    let mut asm = code.asm();
    asm.evex(
        Evex {
            map: Map::M0f3a,
            pp: Pp::P66,
            w: false,
            length: 0,
            mask: 0,
            zeroing: false,
            broadcast: false,
            scale: 16,
        },
        0x25,
        destination,
        old,
        Rm::Xmm(mask),
    );
    asm.data(&[0xe4]);
    true
}

/// VEX.128 VPBLENDVB needs AVX; the represented AVX2 target is sufficient.
/// Each mask byte must be 0 or255, as produced by the predicate expander.
/// Unlike the legacy form, the mask is explicit and cannot clobber XMM0.
#[cfg(test)]
pub(crate) fn blend_bytes(
    code: &mut Code,
    destination: u8,
    old: u8,
    mask: u8,
    target: TargetCpu,
) -> bool {
    if !target.supports(TargetCpu::Avx2) || target.data_independent_timing() {
        return false;
    }
    assert!(
        destination < 16 && old < 16 && mask < 16,
        "VEX blend uses legacy XMM register encodings"
    );
    let mut asm = code.asm();
    asm.vex(
        Vex {
            map: Map::M0f3a,
            pp: Pp::P66,
            w: false,
            l: false,
        },
        0x4c,
        destination,
        old,
        Rm::Xmm(destination),
    );
    asm.data(&[mask << 4]);
    true
}

/// Packed dword/qword leading-zero counts require CD in addition to F and VL.
pub(crate) fn leading_supported(lane_bytes: u8, target: TargetCpu) -> bool {
    matches!(lane_bytes, 4 | 8)
        && target.supports(TargetCpu::Avx512f)
        && target.supports(TargetCpu::Avx512vl)
        && target.supports(TargetCpu::Avx512cd)
        && !target.data_independent_timing()
}

/// Count leading zeros, including the architectural element width for zero.
pub(crate) fn leading_zeros(code: &mut Code, lane_bytes: u8, xmm: u8, target: TargetCpu) -> bool {
    if !leading_supported(lane_bytes, target) {
        return false;
    }
    code.asm().evex(
        Evex {
            map: Map::M0f38,
            pp: Pp::P66,
            w: lane_bytes == 8,
            length: 0,
            mask: 0,
            zeroing: false,
            broadcast: false,
            scale: 16,
        },
        0x44,
        xmm,
        0,
        Rm::Xmm(xmm),
    );
    true
}

/// Count set bits independently in each lane of `xmm`, without flags,
/// floating-point status or opmask state changes.
pub(crate) fn population_count(
    code: &mut Code,
    lane_bytes: u8,
    xmm: u8,
    target: TargetCpu,
) -> bool {
    if !population_supported(lane_bytes, target) {
        return false;
    }
    code.asm().evex(
        Evex {
            map: Map::M0f38,
            pp: Pp::P66,
            w: matches!(lane_bytes, 2 | 8),
            length: 0,
            mask: 0,
            zeroing: false,
            broadcast: false,
            scale: 16,
        },
        if lane_bytes <= 2 { 0x54 } else { 0x55 },
        xmm,
        0,
        Rm::Xmm(xmm),
    );
    true
}

#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
pub(crate) mod execution {
    use crate::{GuestState, context::ExecutionContext};
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
    pub(crate) struct Native {
        page: *mut c_void,
        bytes: usize,
    }
    impl Native {
        pub(crate) fn new(code: &[u8]) -> Self {
            #[cfg(target_os = "macos")]
            const ANONYMOUS: i32 = 0x1000;
            #[cfg(target_os = "linux")]
            const ANONYMOUS: i32 = 0x20;
            let bytes = code.len().next_multiple_of(4096);
            // SAFETY: private anonymous memory becomes RX after the copy and
            // remains mapped until this Native is dropped.
            let page = unsafe {
                let page = mmap(core::ptr::null_mut(), bytes, 3, 2 | ANONYMOUS, -1, 0);
                assert_ne!(page as usize, usize::MAX);
                core::ptr::copy_nonoverlapping(code.as_ptr(), page.cast(), code.len());
                assert_eq!(mprotect(page, bytes, 5), 0);
                page
            };
            Self { page, bytes }
        }
        pub(crate) fn run(&self, state: &mut GuestState, context: &mut ExecutionContext) {
            // SAFETY: callers supply a complete generated function using the
            // state/context ABI, with every requested host feature available.
            unsafe {
                let entry: unsafe extern "sysv64" fn(*mut GuestState, *mut ExecutionContext) =
                    core::mem::transmute(self.page);
                entry(state, context);
            }
        }
    }
    impl Drop for Native {
        fn drop(&mut self) {
            // SAFETY: this object owns the mapping returned by mmap.
            assert_eq!(unsafe { munmap(self.page, self.bytes) }, 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_blend_has_explicit_mask_and_refuses_missing_state_or_dit() {
        let target = TargetCpu::Avx2;
        for (destination, old, mask, expected) in [
            (0, 7, 6, [0xc4, 0xe3, 0x41, 0x4c, 0xc0, 0x60]),
            (8, 15, 14, [0xc4, 0x43, 0x01, 0x4c, 0xc0, 0xe0]),
        ] {
            let mut code = Code::new();
            assert!(blend_bytes(&mut code, destination, old, mask, target));
            assert_eq!(*code, expected);
            assert_eq!(code.instructions(), 1);
        }
        for target in [
            TargetCpu::Baseline,
            TargetCpu::Gfni,
            TargetCpu::Avx512f.with_avx512vl(),
            TargetCpu::Avx2.with_data_independent_timing(),
        ] {
            let mut code = Code::new();
            assert!(!blend_bytes(&mut code, 0, 7, 6, target));
            assert!(code.is_empty());
        }
    }

    #[test]
    fn merge_requires_vector_state_and_preserves_dit() {
        for target in [
            TargetCpu::Baseline,
            TargetCpu::Avx512f,
            TargetCpu::Avx512vl,
            TargetCpu::Avx512f
                .with_avx512vl()
                .with_data_independent_timing(),
        ] {
            let mut code = Code::new();
            assert!(!merge(&mut code, 0, 7, 6, target));
            assert!(code.is_empty());
        }
    }

    #[test]
    fn merge_truth_table_and_gnu_encodings() {
        let target = TargetCpu::Avx512f.with_avx512vl();
        for (destination, old, mask, expected) in [
            (0, 7, 6, [0x62, 0xf3, 0x45, 0x08, 0x25, 0xc6, 0xe4]),
            (8, 15, 14, [0x62, 0x53, 0x05, 0x08, 0x25, 0xc6, 0xe4]),
            (31, 30, 29, [0x62, 0x03, 0x0d, 0x00, 0x25, 0xfd, 0xe4]),
        ] {
            let mut code = Code::new();
            assert!(merge(&mut code, destination, old, mask, target));
            assert_eq!(*code, expected);
            assert_eq!(code.instructions(), 1);
        }
        for new in 0u8..2 {
            for old in 0u8..2 {
                for mask in 0u8..2 {
                    let index = (new << 2) | (old << 1) | mask;
                    assert_eq!((0xe4u8 >> index) & 1, (new & mask) | (old & (mask ^ 1)));
                }
            }
        }
    }

    #[test]
    fn leading_zero_count_requires_cd_and_uses_evex_128() {
        for lane in [4, 8] {
            for target in [
                TargetCpu::Avx512cd,
                TargetCpu::Avx512cd.with_avx512f(),
                TargetCpu::Avx512cd.with_avx512vl(),
                TargetCpu::Avx512f.with_avx512vl(),
                TargetCpu::Avx512f
                    .with_avx512vl()
                    .with_avx512cd()
                    .with_data_independent_timing(),
            ] {
                let mut code = Code::new();
                assert!(!leading_zeros(&mut code, lane, 0, target));
                assert!(code.is_empty());
            }
            let mut code = Code::new();
            assert!(leading_zeros(
                &mut code,
                lane,
                0,
                TargetCpu::Avx512f.with_avx512vl().with_avx512cd()
            ));
            assert_eq!(
                code.as_slice(),
                &[
                    0x62,
                    0xf2,
                    if lane == 8 { 0xfd } else { 0x7d },
                    0x08,
                    0x44,
                    0xc0
                ]
            );
            assert_eq!(code.instructions(), 1);
        }
    }

    #[test]
    fn population_count_checks_each_lane_extension_and_vector_state() {
        for lane in [1, 2, 4, 8] {
            let feature = if lane <= 2 {
                TargetCpu::Avx512bitalg
            } else {
                TargetCpu::Avx512vpopcntdq
            };
            for target in [
                TargetCpu::Baseline,
                feature,
                feature.with_avx512f(),
                feature.with_avx512vl(),
                TargetCpu::Avx512f.with_avx512vl(),
                feature
                    .with_avx512f()
                    .with_avx512vl()
                    .with_data_independent_timing(),
            ] {
                let mut code = Code::new();
                assert!(!population_count(&mut code, lane, 0, target));
                assert!(code.is_empty());
            }
            let target = feature.with_avx512f().with_avx512vl();
            let mut code = Code::new();
            assert!(population_count(&mut code, lane, 0, target));
            assert_eq!(
                code.as_slice(),
                &[
                    0x62,
                    0xf2,
                    if matches!(lane, 2 | 8) { 0xfd } else { 0x7d },
                    0x08,
                    if lane <= 2 { 0x54 } else { 0x55 },
                    0xc0
                ]
            );
            assert_eq!(code.instructions(), 1);
        }
    }

    #[test]
    fn byte_reversal_keeps_baseline_and_dit_paths_unchanged() {
        for target in [
            TargetCpu::Baseline,
            TargetCpu::Gfni.with_data_independent_timing(),
        ] {
            let mut code = Code::new();
            assert!(!reverse_bytes(&mut code, 0, 2, target));
            assert!(code.is_empty());
        }
        let mut code = Code::new();
        assert!(reverse_bytes(&mut code, 0, 2, TargetCpu::Gfni));
        assert_eq!(code.instructions(), 4);
        assert_eq!(&code[code.len() - 6..], &[0x66, 0x0f, 0x3a, 0xce, 0xc2, 0]);
    }
}
