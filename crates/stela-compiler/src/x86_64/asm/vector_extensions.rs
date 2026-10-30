//! Capability-checked packed bit operations (Intel SDM Vol. 2).
use super::{Code, Evex, Gpr, Map, Pp, Rm, Vex};
use crate::TargetCpu;
use crate::x86_64::isa::{ShiftOpcode as Shift, SimdOpcode as Host};

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

/// Byte dot products need AVX-VNNI-INT8, AVX-VNNI, or AVX-512 VNNI with F
/// and VL. The DIT profile keeps its reviewed recipe.
pub(crate) fn byte_dot_supported(target: TargetCpu) -> bool {
    (target.supports(TargetCpu::AvxVnniInt8)
        || target.supports(TargetCpu::AvxVnni)
        || target.supports(TargetCpu::Avx512f.with_avx512vl().with_avx512vnni()))
        && !target.data_independent_timing()
}

/// Set each dword of `sum` to the wrapping sum of the four products of the
/// bytes in that dword of each `[left, right]` pair, each operand's bytes
/// signed as `signed` says (SDOT, UDOT, USDOT, SUDOT and the matrix forms).
/// Callers add the old destination afterwards, so a chain of accumulations
/// waits on one PADDD rather than on the multiply. AVX-VNNI-INT8 has every
/// signedness. VPDPBUSD multiplies unsigned by signed bytes; for equal
/// signedness it flips the sign bit of one operand in place,
/// (a ^ 0x80) - 0x80 = a, and subtracts the 128-fold byte sum of the other,
/// collected in `scratch[1]` with the 0x80 bytes in `scratch[0]`.
pub(crate) fn byte_dot(
    code: &mut Code,
    sum: u8,
    pairs: &[[u8; 2]],
    signed: [bool; 2],
    scratch: [u8; 2],
    target: TargetCpu,
) -> bool {
    if !byte_dot_supported(target) {
        return false;
    }
    if target.supports(TargetCpu::AvxVnniInt8) {
        // VEX.pp names the signedness: VPDPBUUD, VPDPBSUD (signed first
        // source), VPDPBSSD.
        let pp = match signed {
            [false, false] => Pp::None,
            [true, true] => Pp::Pf2,
            _ => Pp::Pf3,
        };
        code.asm()
            .simd(Host::Xor, sum, Rm::Xmm(sum), TargetCpu::Baseline);
        for &[left, right] in pairs {
            let [first, second] = if signed == [false, true] {
                [right, left]
            } else {
                [left, right]
            };
            code.asm().vex(
                Vex {
                    map: Map::M0f38,
                    pp,
                    w: false,
                    l: false,
                },
                0x50,
                sum,
                first,
                Rm::Xmm(second),
            );
        }
        return true;
    }
    // VPDPBUSD: VEX.vvvv or EVEX.vvvv names the unsigned bytes.
    let unsigned_by_signed = |code: &mut Code, into: u8, unsigned: u8, signed: u8| {
        if target.supports(TargetCpu::AvxVnni) {
            code.asm().vex(
                Vex {
                    map: Map::M0f38,
                    pp: Pp::P66,
                    w: false,
                    l: false,
                },
                0x50,
                into,
                unsigned,
                Rm::Xmm(signed),
            );
        } else {
            code.asm().evex(
                Evex {
                    map: Map::M0f38,
                    pp: Pp::P66,
                    w: false,
                    length: 0,
                    mask: 0,
                    zeroing: false,
                    broadcast: false,
                    scale: 16,
                },
                0x50,
                into,
                unsigned,
                Rm::Xmm(signed),
            );
        }
    };
    let [bias, correction] = scratch;
    if signed[0] == signed[1] {
        // All-ones words shifted to 0x8000 saturate to 0x80 bytes.
        let mut asm = code.asm();
        asm.simd(Host::EqualByte, bias, Rm::Xmm(bias), TargetCpu::Baseline);
        Shift::LeftWord.emit(code, bias, 15);
        let mut asm = code.asm();
        asm.simd(
            Host::PackSignedWordToByte,
            bias,
            Rm::Xmm(bias),
            TargetCpu::Baseline,
        );
        asm.simd(
            Host::Xor,
            correction,
            Rm::Xmm(correction),
            TargetCpu::Baseline,
        );
    }
    code.asm()
        .simd(Host::Xor, sum, Rm::Xmm(sum), TargetCpu::Baseline);
    for &[left, right] in pairs {
        match signed {
            [false, true] => unsigned_by_signed(code, sum, left, right),
            [true, false] => unsigned_by_signed(code, sum, right, left),
            [true, true] => {
                // a·b = (a + 128)·b - 128·b.
                unsigned_by_signed(code, correction, bias, right);
                code.asm()
                    .simd(Host::Xor, left, Rm::Xmm(bias), TargetCpu::Baseline);
                unsigned_by_signed(code, sum, left, right);
            }
            [false, false] => {
                // a·b = a·(b - 128) + 128·a, and 0x80 is -128 signed.
                unsigned_by_signed(code, correction, left, bias);
                code.asm()
                    .simd(Host::Xor, right, Rm::Xmm(bias), TargetCpu::Baseline);
                unsigned_by_signed(code, sum, left, right);
            }
        }
    }
    if signed[0] == signed[1] {
        code.asm().simd(
            Host::SubDword,
            sum,
            Rm::Xmm(correction),
            TargetCpu::Baseline,
        );
    }
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
    fn byte_dot_checks_vector_state_and_encodes_each_signedness() {
        let vnni = TargetCpu::Avx512f.with_avx512vl().with_avx512vnni();
        for target in [
            TargetCpu::Baseline,
            TargetCpu::Avx512vnni,
            TargetCpu::Avx512f.with_avx512vnni(),
            TargetCpu::AvxVnni.with_data_independent_timing(),
            TargetCpu::AvxVnniInt8.with_data_independent_timing(),
            vnni.with_data_independent_timing(),
        ] {
            let mut code = Code::new();
            assert!(!byte_dot(
                &mut code,
                2,
                &[[0, 1]],
                [true; 2],
                [3, 4],
                target
            ));
            assert!(code.is_empty());
        }
        let encoded = |signed, target| {
            let mut code = Code::new();
            assert!(byte_dot(&mut code, 2, &[[0, 1]], signed, [3, 4], target));
            code.into_bytes()
        };
        const CLEAR_SUM: [u8; 4] = [0x66, 0x0f, 0xef, 0xd2];
        // GNU as: vpdpbuud, vpdpbsud and vpdpbssd xmm2, xmm0, xmm1;
        // vpdpbsud xmm2, xmm1, xmm0 for unsigned by signed.
        for (signed, product) in [
            ([false, false], [0xc4, 0xe2, 0x78, 0x50, 0xd1]),
            ([true, false], [0xc4, 0xe2, 0x7a, 0x50, 0xd1]),
            ([true, true], [0xc4, 0xe2, 0x7b, 0x50, 0xd1]),
            ([false, true], [0xc4, 0xe2, 0x72, 0x50, 0xd0]),
        ] {
            assert_eq!(
                encoded(signed, TargetCpu::AvxVnniInt8),
                [&CLEAR_SUM[..], &product].concat()
            );
        }
        // {vex} and {evex} vpdpbusd xmm2, xmm0, xmm1 multiply unsigned by
        // signed alone; signed by unsigned swaps the sources.
        for (target, prefix) in [
            (TargetCpu::AvxVnni, &[0xc4, 0xe2, 0x79][..]),
            (vnni, &[0x62, 0xf2, 0x7d, 0x08][..]),
        ] {
            let expected = [&CLEAR_SUM[..], prefix, &[0x50, 0xd1]].concat();
            assert_eq!(encoded([false, true], target), expected);
            let swapped = encoded([true, false], target);
            assert_eq!(swapped.len(), expected.len());
            assert_eq!(swapped[swapped.len() - 1], 0xd0);
            for signed in [[true, true], [false, false]] {
                let mut code = Code::new();
                assert!(byte_dot(&mut code, 2, &[[0, 1]], signed, [3, 4], target));
                // Bias, cleared correction and sum, the two products, the
                // flip and the subtraction.
                assert_eq!(code.instructions(), 9);
            }
        }
    }

    #[test]
    fn byte_dots_match_the_lane_model_on_each_host_form() {
        use crate::{GuestAddress, GuestState, context::ExecutionContext};
        use alloc::vec::Vec;
        use execution::Native;
        #[derive(Clone, Copy)]
        enum Form {
            Dot { index: Option<u8>, q: bool },
            Matrix,
        }
        let mut forms = Vec::new();
        for q in [false, true] {
            for (base, signed) in [
                (0x0e809400, [true, true]),
                (0x2e809400, [false, false]),
                (0x0e809c00, [false, true]),
            ] {
                forms.push((base, signed, Form::Dot { index: None, q }));
            }
            for (base, signed) in [
                (0x0f80e000, [true, true]),
                (0x2f80e000, [false, false]),
                (0x0f80f000, [false, true]),
                (0x0f00f000, [true, false]),
            ] {
                for index in 0..4 {
                    forms.push((
                        base,
                        signed,
                        Form::Dot {
                            index: Some(index),
                            q,
                        },
                    ));
                }
            }
        }
        for (base, signed) in [
            (0x4e80a400, [true, true]),
            (0x6e80a400, [false, false]),
            (0x4e80ac00, [false, true]),
        ] {
            forms.push((base, signed, Form::Matrix));
        }
        let host = TargetCpu::detect();
        let mut extended = 0;
        let mut random = 0x9e3779b97f4a7c15_u64;
        for target in [
            TargetCpu::X86_64_V3,
            TargetCpu::X86_64_V3.with_avx_vnni(),
            TargetCpu::X86_64_V3.with_avx_vnni_int8(),
            TargetCpu::Avx512f.with_avx512vl().with_avx512vnni(),
        ] {
            if !host.supports(target) {
                continue;
            }
            extended += usize::from(byte_dot_supported(target));
            for &(base, signed, form) in &forms {
                for (destination, left, right) in [(3u32, 1u32, 2u32), (4, 4, 4), (31, 17, 17)] {
                    let mut word = base | right << 16 | left << 5 | destination;
                    if let Form::Dot { index, q } = form {
                        word |= u32::from(q) << 30;
                        if let Some(index) = index {
                            word |= u32::from(index & 1) << 21 | u32::from(index >> 1) << 11;
                        }
                    }
                    let source: Vec<u8> = [word, 0xd65f03c0]
                        .into_iter()
                        .flat_map(u32::to_le_bytes)
                        .collect();
                    let block =
                        crate::testing::leaf_for(&source, GuestAddress(0x1000), target).unwrap();
                    let native = Native::new(&block.x86_64_code);
                    for sample in 0..16 {
                        let mut state = GuestState::default();
                        for vector in &mut state.v {
                            for limb in vector {
                                random ^= random << 13;
                                random ^= random >> 7;
                                random ^= random << 17;
                                *limb = match sample {
                                    0 => 0x8080_8080_8080_8080,
                                    1 => u64::MAX,
                                    2 => 0x7f80_7f80_ff01_8081,
                                    _ => random,
                                };
                            }
                        }
                        let value = |register: u32, at: usize, signed: bool| {
                            let vector = state.v[register as usize];
                            let byte = (vector[at / 8] >> (at % 8 * 8)) as u8;
                            if signed {
                                i64::from(byte as i8)
                            } else {
                                i64::from(byte)
                            }
                        };
                        let old = state.v[destination as usize];
                        let mut lanes: [u32; 4] =
                            core::array::from_fn(|i| (old[i / 2] >> (i % 2 * 32)) as u32);
                        let products = |left_at: usize, right_at: usize, count: usize| {
                            (0..count)
                                .map(|k| {
                                    value(left, left_at + k, signed[0])
                                        * value(right, right_at + k, signed[1])
                                })
                                .sum::<i64>() as u32
                        };
                        match form {
                            Form::Dot { index, q } => {
                                for (lane, sum) in lanes.iter_mut().enumerate() {
                                    *sum = if lane < 2 || q {
                                        let group = index.map_or(lane, usize::from);
                                        sum.wrapping_add(products(4 * lane, 4 * group, 4))
                                    } else {
                                        0
                                    };
                                }
                            }
                            Form::Matrix => {
                                for (lane, sum) in lanes.iter_mut().enumerate() {
                                    let row = lane / 2;
                                    let column = lane % 2;
                                    *sum = sum.wrapping_add(products(8 * row, 8 * column, 8));
                                }
                            }
                        }
                        let mut expected = state.clone();
                        expected.v[destination as usize] = [
                            u64::from(lanes[0]) | u64::from(lanes[1]) << 32,
                            u64::from(lanes[2]) | u64::from(lanes[3]) << 32,
                        ];
                        native.run(&mut state, &mut ExecutionContext::default());
                        assert_eq!(state, expected, "{target:?} {word:#010x} sample={sample}");
                    }
                }
            }
        }
        std::println!("BYTE_DOT_EXTENDED_TARGETS={extended}");
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
