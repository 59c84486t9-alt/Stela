//! Ahead-of-time native translation of supported Apple-silicon ARM64 semantics.
//! Unsupported instructions are errors; no interpreter fallback is emitted.

pub mod aarch64;
pub mod block;
pub mod context;
pub mod extended;
mod target;
pub mod x86_64;

pub use target::TargetCpu;

use serde::{Deserialize, Serialize};

/// Bind cached code and evidence to compiler implementation and dependencies.
pub const SOURCE_FINGERPRINT_MATERIAL: &str = concat!(
    include_str!("lib.rs"),
    include_str!("aarch64/sve/integer_comparison.rs"),
    include_str!("x86_64/sve/integer_comparison.rs"),
    include_str!("x86_64/sve/integer_comparison/wide.rs"),
    include_str!("context.rs"),
    include_str!("context/memory.rs"),
    include_str!("extended.rs"),
    include_str!("aarch64/scalable.rs"),
    include_str!("aarch64/scalable/features.rs"),
    include_str!("aarch64/scalable/profile.rs"),
    include_str!("aarch64/sve.rs"),
    include_str!("aarch64/sve/address.rs"),
    include_str!("aarch64/sve/dot.rs"),
    include_str!("aarch64/sve/floating_copy.rs"),
    include_str!("aarch64/sve/integer_arithmetic.rs"),
    include_str!("aarch64/sve/integer_logic.rs"),
    include_str!("aarch64/sve/integer_products.rs"),
    include_str!("aarch64/sve/integer_saturation.rs"),
    include_str!("aarch64/sve/predicate_generation.rs"),
    include_str!("aarch64/sve/predicate_logic.rs"),
    include_str!("aarch64/sve/rearrange.rs"),
    include_str!("aarch64/sve/rearrange_extract.rs"),
    include_str!("aarch64/sve/rearrange_widen.rs"),
    include_str!("aarch64/sve/reductions.rs"),
    include_str!("aarch64/sve/sign.rs"),
    include_str!("aarch64/sme.rs"),
    include_str!("aarch64/sme/integer_dots.rs"),
    include_str!("aarch64/sme/length.rs"),
    include_str!("x86_64/scalable.rs"),
    include_str!("x86_64/scalable/legacy.rs"),
    include_str!("x86_64/scalable/predicate.rs"),
    include_str!("x86_64/scalable_matrix.rs"),
    include_str!("x86_64/sve.rs"),
    include_str!("x86_64/sve/address.rs"),
    include_str!("x86_64/sve/predicate.rs"),
    include_str!("x86_64/sve/predicate/counter.rs"),
    include_str!("x86_64/sve/predicate/flags.rs"),
    include_str!("x86_64/sve/dot.rs"),
    include_str!("x86_64/sve/floating_copy.rs"),
    include_str!("x86_64/sve/integer_arithmetic.rs"),
    include_str!("x86_64/sve/integer_logic.rs"),
    include_str!("x86_64/sve/integer_products.rs"),
    include_str!("x86_64/sve/integer_products/complex.rs"),
    include_str!("x86_64/sve/integer_products/complex_wrapping.rs"),
    include_str!("x86_64/sve/integer_products/polynomial.rs"),
    include_str!("x86_64/sve/integer_products/saturating.rs"),
    include_str!("x86_64/sve/integer_products/widening.rs"),
    include_str!("x86_64/sve/integer_saturation.rs"),
    include_str!("x86_64/sve/predicate_generation.rs"),
    include_str!("x86_64/sve/predicate_logic.rs"),
    include_str!("x86_64/sve/rearrange.rs"),
    include_str!("x86_64/sve/rearrange/dynamic.rs"),
    include_str!("x86_64/sve/rearrange_extract.rs"),
    include_str!("x86_64/sve/rearrange_widen.rs"),
    include_str!("x86_64/sve/reductions.rs"),
    include_str!("x86_64/sve/sign.rs"),
    include_str!("x86_64/sme.rs"),
    include_str!("x86_64/sme/integer_dots.rs"),
    include_str!("x86_64/sme/integer_products.rs"),
    include_str!("x86_64/sme/length.rs"),
    include_str!("target.rs"),
    include_str!("aarch64.rs"),
    include_str!("aarch64/system.rs"),
    include_str!("aarch64/system/synchronization.rs"),
    include_str!("aarch64/constrained.rs"),
    include_str!("x86_64.rs"),
    include_str!("x86_64/system.rs"),
    include_str!("x86_64/system/synchronization.rs"),
    include_str!("block.rs"),
    include_str!("block/thread.rs"),
    include_str!("x86_64/block.rs"),
    include_str!("aarch64/bitfield.rs"),
    include_str!("x86_64/bitfield.rs"),
    include_str!("aarch64/conditional_select.rs"),
    include_str!("x86_64/conditional_select.rs"),
    include_str!("aarch64/crc.rs"),
    include_str!("x86_64/crc.rs"),
    include_str!("aarch64/flags.rs"),
    include_str!("x86_64/flags.rs"),
    include_str!("aarch64/floating.rs"),
    include_str!("aarch64/floating/comparison.rs"),
    include_str!("aarch64/floating/estimate.rs"),
    include_str!("aarch64/floating/minmax.rs"),
    include_str!("aarch64/floating/rounding.rs"),
    include_str!("aarch64/floating/sqrt.rs"),
    include_str!("aarch64/floating/fused.rs"),
    include_str!("aarch64/floating/widening.rs"),
    include_str!("aarch64/floating/bfloat16.rs"),
    include_str!("aarch64/floating/bfloat16/dot.rs"),
    include_str!("aarch64/floating/complex.rs"),
    include_str!("aarch64/floating/precision.rs"),
    include_str!("aarch64/floating/refinement.rs"),
    include_str!("aarch64/floating/integer.rs"),
    include_str!("aarch64/fp_register.rs"),
    include_str!("x86_64/fp_register.rs"),
    include_str!("aarch64/integer_math.rs"),
    include_str!("x86_64/integer_math.rs"),
    include_str!("aarch64/integer_unary.rs"),
    include_str!("x86_64/integer_unary.rs"),
    include_str!("aarch64/integer_minmax.rs"),
    include_str!("x86_64/integer_minmax.rs"),
    include_str!("aarch64/tag_arithmetic.rs"),
    include_str!("x86_64/tag_arithmetic.rs"),
    include_str!("aarch64/literal.rs"),
    include_str!("x86_64/literal.rs"),
    include_str!("aarch64/pc_relative.rs"),
    include_str!("x86_64/pc_relative.rs"),
    include_str!("aarch64/register_offset.rs"),
    include_str!("x86_64/register_offset.rs"),
    include_str!("x86_64/memory_store.rs"),
    include_str!("aarch64/atomic.rs"),
    include_str!("x86_64/atomic.rs"),
    include_str!("x86_64/atomic/compare_exchange.rs"),
    include_str!("x86_64/atomic/compare_exchange_pair.rs"),
    include_str!("x86_64/atomic/read_modify_write.rs"),
    include_str!("aarch64/ordered.rs"),
    include_str!("x86_64/ordered.rs"),
    include_str!("aarch64/non_temporal.rs"),
    include_str!("x86_64/non_temporal.rs"),
    include_str!("aarch64/unprivileged.rs"),
    include_str!("x86_64/unprivileged.rs"),
    include_str!("aarch64/prefetch.rs"),
    include_str!("x86_64/prefetch.rs"),
    include_str!("aarch64/simd.rs"),
    include_str!("x86_64/simd.rs"),
    include_str!("aarch64/simd/aes.rs"),
    include_str!("x86_64/simd/aes.rs"),
    include_str!("x86_64/simd/aes/sbox.rs"),
    include_str!("aarch64/simd/i8mm.rs"),
    include_str!("x86_64/simd/i8mm.rs"),
    include_str!("aarch64/simd/sha1.rs"),
    include_str!("x86_64/simd/sha1.rs"),
    include_str!("aarch64/simd/sha256.rs"),
    include_str!("x86_64/simd/sha256.rs"),
    include_str!("x86_64/simd/sha32.rs"),
    include_str!("aarch64/simd/sha3.rs"),
    include_str!("x86_64/simd/sha3.rs"),
    include_str!("aarch64/simd/sha512.rs"),
    include_str!("x86_64/simd/sha512.rs"),
    include_str!("aarch64/simd/memory.rs"),
    include_str!("x86_64/simd/memory.rs"),
    include_str!("aarch64/simd/structure_memory.rs"),
    include_str!("aarch64/simd/structure_memory/multiple.rs"),
    include_str!("aarch64/simd/structure_memory/single.rs"),
    include_str!("x86_64/simd/structure_memory.rs"),
    include_str!("x86_64/simd/structure_memory/multiple.rs"),
    include_str!("x86_64/simd/structure_memory/single.rs"),
    include_str!("aarch64/simd/floating.rs"),
    include_str!("x86_64/simd/floating.rs"),
    include_str!("aarch64/simd/arithmetic.rs"),
    include_str!("aarch64/simd/comparison.rs"),
    include_str!("aarch64/simd/estimate.rs"),
    include_str!("aarch64/simd/minmax.rs"),
    include_str!("aarch64/simd/rounding.rs"),
    include_str!("aarch64/simd/refinement.rs"),
    include_str!("aarch64/simd/sqrt.rs"),
    include_str!("x86_64/simd/arithmetic.rs"),
    include_str!("x86_64/simd/arithmetic/half.rs"),
    include_str!("x86_64/simd/arithmetic/half/product.rs"),
    include_str!("x86_64/simd/half.rs"),
    include_str!("x86_64/simd/comparison.rs"),
    include_str!("x86_64/simd/estimate.rs"),
    include_str!("x86_64/simd/minmax.rs"),
    include_str!("x86_64/simd/rounding.rs"),
    include_str!("x86_64/simd/refinement.rs"),
    include_str!("x86_64/simd/sqrt.rs"),
    include_str!("aarch64/simd/fused.rs"),
    include_str!("aarch64/simd/widening.rs"),
    include_str!("aarch64/simd/bfloat16.rs"),
    include_str!("aarch64/simd/complex.rs"),
    include_str!("aarch64/simd/conversion.rs"),
    include_str!("x86_64/simd/fused.rs"),
    include_str!("x86_64/simd/widening.rs"),
    include_str!("x86_64/simd/bfloat16.rs"),
    include_str!("x86_64/simd/bfloat16/conversion.rs"),
    include_str!("x86_64/simd/bfloat16/multiply.rs"),
    include_str!("x86_64/simd/bfloat16/dot.rs"),
    include_str!("x86_64/simd/complex.rs"),
    include_str!("x86_64/simd/complex/half.rs"),
    include_str!("x86_64/simd/precision.rs"),
    include_str!("x86_64/simd/integer_conversion.rs"),
    include_str!("x86_64/simd/numerical.rs"),
    include_str!("x86_64/simd/numerical/quantization.rs"),
    include_str!("x86_64/isa.rs"),
    include_str!("aarch64/simd/rearrange.rs"),
    include_str!("x86_64/simd/rearrange.rs"),
    include_str!("aarch64/simd/shifts.rs"),
    include_str!("x86_64/simd/shifts.rs"),
    include_str!("aarch64/simd/reductions.rs"),
    include_str!("x86_64/simd/reductions.rs"),
    include_str!("aarch64/simd/saturating.rs"),
    include_str!("x86_64/simd/saturating.rs"),
    include_str!("aarch64/simd/products.rs"),
    include_str!("x86_64/simd/products.rs"),
    include_str!("aarch64/simd/halving.rs"),
    include_str!("x86_64/simd/halving.rs"),
    include_str!("aarch64/simd/immediates.rs"),
    include_str!("x86_64/simd/immediates.rs"),
    include_str!("../Cargo.toml"),
    include_str!("../../../Cargo.lock"),
);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestAddress(pub u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnsupportedReason {
    HostCapabilityRequired {
        address: GuestAddress,
        required: TargetCpu,
    },
    NumericalRuntimeRequired {
        address: GuestAddress,
    },
    Instruction {
        address: GuestAddress,
        encoding: u32,
    },
    PrivilegedOperation {
        address: GuestAddress,
    },
    PointerAuthentication {
        address: GuestAddress,
    },
    UnresolvedIndirectTarget {
        address: GuestAddress,
    },
    UnresolvedDirectTarget {
        address: GuestAddress,
        target: GuestAddress,
    },
    RuntimeGeneratedCode,
}

/// A lifted instruction must describe architectural effects, not just syntax.
pub trait Lifter {
    type Instruction;
    fn lift(&self, pc: GuestAddress, encoding: u32)
    -> Result<Self::Instruction, UnsupportedReason>;
}

/// Emission must retain guest addresses for faults, debugging and evidence.
#[derive(Debug, Serialize, Deserialize)]
pub struct NativeBlock {
    pub x86_64_code: Vec<u8>,
    pub source_map: Vec<(GuestAddress, usize)>,
}

/// Native code requires the direct ordinary-RAM profile documented in compiler.md.
pub const NATIVE_ABI: &str = "x86_64-sysv-guest-state-v3-direct-ram";

/// Native ABI v3: System V x86-64 `void function(GuestState *state)`.
/// Registers are initially memory-backed; register allocation is future work.
/// Only NZCV bits 31:28 are modeled, not the complete PSTATE register.
/// V registers are little-endian low/high 64-bit limbs. Arithmetic preserves
/// unrelated FPCR/FPSR bits; architectural register accesses apply the declared
/// field masks. Saturating integer SIMD updates QC and numerical FP accumulates
/// exception status. The state layout itself grants no instruction support.
#[repr(C)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GuestState {
    pub x: [u64; 31],
    pub sp: u64,
    pub nzcv: u32,
    pub reserved: u32,
    pub v: [[u64; 2]; 32],
    pub fpcr: u32,
    pub fpsr: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileError(pub String);

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for CompileError {}

/// Compile one raw ARM64 leaf region ending in RET X30.
/// Input addresses are retained in the output map. No Mach-O loading, external
/// calls, PAC, privileged operations, or arbitrary RET targets.
pub fn compile(code: &[u8], base: GuestAddress) -> Result<NativeBlock, CompileError> {
    compile_for_target(code, base, TargetCpu::Baseline)
}
pub fn compile_for_target(
    code: &[u8],
    base: GuestAddress,
    target: TargetCpu,
) -> Result<NativeBlock, CompileError> {
    if code.is_empty() || !code.len().is_multiple_of(4) || !base.0.is_multiple_of(4) {
        return Err(CompileError(
            "input and guest base must be nonempty/aligned to 4 bytes".into(),
        ));
    }
    let mut instructions = vec![];
    for (index, bytes) in code.as_chunks::<4>().0.iter().enumerate() {
        let pc = GuestAddress(
            base.0
                .checked_add((index as u64) * 4)
                .ok_or_else(|| CompileError("guest address overflow".into()))?,
        );
        let encoding = u32::from_le_bytes(*bytes);
        let instruction = aarch64::Decoder
            .lift(pc, encoding)
            .map_err(|e| CompileError(format!("unsupported ARM64 semantics: {e:?}")))?;
        instructions.push(instruction);
    }
    if !matches!(
        instructions.last().unwrap().operation,
        aarch64::Operation::Return
    ) {
        return Err(CompileError("leaf region must end in RET X30".into()));
    }
    x86_64::Emitter
        .emit_for_target(&instructions, target)
        .map_err(|e| CompileError(format!("x86 emission failed: {e:?}")))
}

pub trait Backend<I> {
    fn emit(&self, instructions: &[I]) -> Result<NativeBlock, UnsupportedReason>;
}

/// Platform adaptation is separate from instruction translation.
pub mod platform {
    #[derive(Debug)]
    pub enum Requirement {
        MachTraps,
        BsdSyscalls,
        ThreadState,
        ExceptionDelivery,
        VirtualMemory,
        DynamicLinking,
        KernelBoot,
        Interrupts,
        Graphics,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn polynomial64_lowering_requires_independent_pclmul_and_selects_original_halves() {
        use x86_64::isa::SimdOpcode;
        let opcode = SimdOpcode::CarrylessMultiplyQword;
        assert_eq!(opcode.requires(), TargetCpu::Pclmulqdq);
        assert!(!TargetCpu::Sse42.supports(opcode.requires()));
        assert!(
            std::panic::catch_unwind(|| {
                opcode.register(&mut Vec::new(), 0, 1, TargetCpu::Sse42);
            })
            .is_err()
        );
        for (word, immediate) in [(0x0ee2e020u32, 0x00), (0x4ee2e020, 0x11)] {
            let source: Vec<_> = [word, 0xd65f03c0]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect();
            let baseline = compile(&source, GuestAddress(0x1000)).unwrap();
            let sse42 =
                compile_for_target(&source, GuestAddress(0x1000), TargetCpu::Sse42).unwrap();
            assert_eq!(baseline.x86_64_code, sse42.x86_64_code);
            let pclmul =
                compile_for_target(&source, GuestAddress(0x1000), TargetCpu::Pclmulqdq).unwrap();
            let combined = compile_for_target(
                &source,
                GuestAddress(0x1000),
                TargetCpu::Sse42.with_pclmulqdq(),
            )
            .unwrap();
            assert_eq!(pclmul.x86_64_code, combined.x86_64_code);
            assert!(
                pclmul
                    .x86_64_code
                    .windows(6)
                    .any(|bytes| bytes == [0x66, 0x0f, 0x3a, 0x44, 0xc1, immediate])
            );
            assert!(pclmul.x86_64_code.len() < baseline.x86_64_code.len());
            assert_eq!(pclmul.source_map.len(), baseline.source_map.len());
        }
        // Byte polynomial forms retain the lane-isolated SSE2 recipe.
        for word in [0x2e229c20u32, 0x0e22e020, 0x4e22e020] {
            let source: Vec<_> = [word, 0xd65f03c0]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect();
            assert_eq!(
                compile(&source, GuestAddress(0x1000)).unwrap().x86_64_code,
                compile_for_target(&source, GuestAddress(0x1000), TargetCpu::Pclmulqdq)
                    .unwrap()
                    .x86_64_code,
            );
        }
    }
    #[test]
    fn guest_state_layout_is_the_native_abi() {
        assert_eq!(std::mem::size_of::<GuestState>(), 784);
        assert_eq!(std::mem::align_of::<GuestState>(), 8);
        assert_eq!(std::mem::offset_of!(GuestState, x), 0);
        assert_eq!(std::mem::offset_of!(GuestState, sp), 248);
        assert_eq!(std::mem::offset_of!(GuestState, nzcv), 256);
        assert_eq!(std::mem::offset_of!(GuestState, reserved), 260);
        assert_eq!(std::mem::offset_of!(GuestState, v), 264);
        assert_eq!(std::mem::size_of::<[[u64; 2]; 32]>(), 512);
        assert_eq!(std::mem::offset_of!(GuestState, fpcr), 776);
        assert_eq!(std::mem::offset_of!(GuestState, fpsr), 780);
    }
    #[test]
    fn ordered_load_host_requirements_gate_leaf_and_block_before_output() {
        for word in [0xc8dffc20_u32, 0xf8bfc020] {
            let source: Vec<u8> = [word, 0xd65f03c0]
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect();
            assert!(
                compile(&source, GuestAddress(0))
                    .unwrap_err()
                    .0
                    .contains("HostCapabilityRequired")
            );
            assert!(compile_for_target(&source, GuestAddress(0), TargetCpu::AtomicLoad16).is_ok());
            let blocked = block::compile(&source, GuestAddress(0)).unwrap_err();
            assert!(blocked.0.contains("HostCapabilityRequired"));
            assert!(
                block::compile_for_target(
                    &source,
                    GuestAddress(0),
                    block::BlockProfile::default(),
                    TargetCpu::AtomicLoad16
                )
                .is_ok()
            );
        }
        for word in [0xc8dfffe0_u32, 0xf8bfc3e0, 0x08dffc20, 0xc89ffc20] {
            let source: Vec<u8> = [word, 0xd65f03c0]
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect();
            assert!(compile(&source, GuestAddress(0)).is_ok());
        }
    }

    #[test]
    fn pair_compare_exchange_requires_only_cx16_for_doubleword_pairs() {
        const CASP_WORD: u32 = 0x08207c82; // casp w0,w1,w2,w3,[x4]
        const CASP_DOUBLEWORD: u32 = 0x48207c82;
        const RET: u32 = 0xd65f03c0;
        for order in [0, 1 << 22, 1 << 15, (1 << 22) | (1 << 15)] {
            for (word, requires_cx16) in [(CASP_WORD, false), (CASP_DOUBLEWORD, true)] {
                let source: Vec<u8> = [word | order, RET]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect();
                for target in [
                    TargetCpu::Baseline,
                    TargetCpu::AtomicLoad16,
                    TargetCpu::Cx16,
                ] {
                    let permitted = !requires_cx16 || target.supports(TargetCpu::Cx16);
                    let leaf = compile_for_target(&source, GuestAddress(0), target);
                    let block = block::compile_for_target(
                        &source,
                        GuestAddress(0),
                        block::BlockProfile::default(),
                        target,
                    );
                    assert_eq!(leaf.is_ok(), permitted);
                    assert_eq!(block.is_ok(), permitted);
                    if !permitted {
                        assert!(leaf.unwrap_err().0.contains("HostCapabilityRequired"));
                        assert!(block.unwrap_err().0.contains("HostCapabilityRequired"));
                    } else {
                        const LOCK_CMPXCHG8B_R8: &[u8] = &[0xf0, 0x41, 0x0f, 0xc7, 0x08];
                        let uses_cx8 = leaf
                            .unwrap()
                            .x86_64_code
                            .windows(LOCK_CMPXCHG8B_R8.len())
                            .any(|body| body == LOCK_CMPXCHG8B_R8);
                        assert_eq!(uses_cx8, !requires_cx16 && target.supports(TargetCpu::Cx8));
                    }
                }
            }
        }
    }

    #[test]
    fn rejects_unknown_instructions_bad_boundaries_and_address_overflow() {
        for words in [
            vec![],
            vec![0xd503201fu32],
            vec![0x14000002, 0xd65f03c0], // branch falls outside the region
            vec![0xf8800800, 0xd65f03c0], // reserved unprivileged prefetch neighbor
            vec![0xd65f0000],
        ] {
            let bytes: Vec<_> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
            assert!(compile(&bytes, GuestAddress(0)).is_err());
        }
        assert!(compile(&[0, 0, 0], GuestAddress(0)).is_err());
        assert!(compile(&0xd65f03c0u32.to_le_bytes(), GuestAddress(1)).is_err());
        let code: Vec<_> = [0xd503201fu32, 0xd65f03c0]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        assert!(compile(&code, GuestAddress(u64::MAX - 3)).is_err());
    }
}
