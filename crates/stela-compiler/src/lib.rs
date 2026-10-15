//! Ahead-of-time native translation of supported Apple-silicon ARM64 semantics.
//! Unsupported instructions are errors; no interpreter fallback is emitted.

pub mod aarch64;
pub mod block;
pub mod context;
pub mod extended;
mod target;
pub mod x86_64;

pub use stela_state::{GuestState, NATIVE_ABI};
pub use target::TargetCpu;

use serde::{Deserialize, Serialize};

/// Bind cached code and evidence to compiler implementation and dependencies.
pub const SOURCE_FINGERPRINT_MATERIAL: &str = concat!(
    include_str!("x86_64/region.rs"),
    include_str!("x86_64/region/analysis.rs"),
    include_str!("x86_64/region/constant.rs"),
    include_str!("x86_64/region/encoding.rs"),
    include_str!("x86_64/region/recovery.rs"),
    include_str!("x86_64/region/tests.rs"),
    include_str!("lib.rs"),
    include_str!("aarch64/sme/fp_matrix.rs"),
    include_str!("aarch64/sme/fp_vector.rs"),
    include_str!("aarch64/floating/bfloat16/arithmetic.rs"),
    include_str!("aarch64/floating/bfloat16/extended_dot.rs"),
    include_str!("aarch64/floating/dot.rs"),
    include_str!("aarch64/floating/sign.rs"),
    include_str!("aarch64/floating/features.rs"),
    include_str!("aarch64/floating/fp8.rs"),
    include_str!("aarch64/simd/fp8_conversion.rs"),
    include_str!("aarch64/sme/fp8_conversion.rs"),
    include_str!("aarch64/sve/floating.rs"),
    include_str!("aarch64/sve/floating/arithmetic.rs"),
    include_str!("aarch64/sve/floating/arithmetic/encodings.rs"),
    include_str!("aarch64/sve/floating/comparison.rs"),
    include_str!("aarch64/sve/floating/control.rs"),
    include_str!("aarch64/sve/floating/conversion.rs"),
    include_str!("x86_64/scalable/numerical.rs"),
    include_str!("x86_64/simd/numerical/control.rs"),
    include_str!("x86_64/sve/floating.rs"),
    include_str!("x86_64/sve/floating/arithmetic.rs"),
    include_str!("x86_64/sve/floating/classify.rs"),
    include_str!("x86_64/sve/floating/comparison.rs"),
    include_str!("x86_64/sve/floating/conversion.rs"),
    include_str!("x86_64/sve/floating/conversion/widening.rs"),
    include_str!("block/scalable.rs"),
    include_str!("extended/block.rs"),
    include_str!("aarch64/sve/integer_comparison.rs"),
    include_str!("x86_64/sve/integer_comparison.rs"),
    include_str!("x86_64/sve/integer_comparison/wide.rs"),
    include_str!("context.rs"),
    include_str!("context/memory.rs"),
    include_str!("extended.rs"),
    include_str!("extended/prefix.rs"),
    include_str!("aarch64/scalable.rs"),
    include_str!("aarch64/scalable/features.rs"),
    include_str!("aarch64/scalable/profile.rs"),
    include_str!("aarch64/sve.rs"),
    include_str!("aarch64/sve/prefix.rs"),
    include_str!("aarch64/sve/address.rs"),
    include_str!("aarch64/sve/dot.rs"),
    include_str!("aarch64/sve/floating_copy.rs"),
    include_str!("aarch64/sve/integer_arithmetic.rs"),
    include_str!("aarch64/sve/integer_bits.rs"),
    include_str!("aarch64/sve/integer_logic.rs"),
    include_str!("aarch64/sve/integer_predicate_move.rs"),
    include_str!("aarch64/sve/integer_products.rs"),
    include_str!("aarch64/sve/integer_saturation.rs"),
    include_str!("aarch64/sve/predicate_generation.rs"),
    include_str!("aarch64/sve/predicate_logic.rs"),
    include_str!("aarch64/sve/rearrange.rs"),
    include_str!("aarch64/sve/rearrange_extract.rs"),
    include_str!("aarch64/sve/rearrange_widen.rs"),
    include_str!("aarch64/sve/reductions.rs"),
    include_str!("aarch64/sve/shifts.rs"),
    include_str!("aarch64/sve/shifts_narrow.rs"),
    include_str!("aarch64/sve/sign.rs"),
    include_str!("aarch64/sme.rs"),
    include_str!("aarch64/sme/integer_dots.rs"),
    include_str!("aarch64/sme/integer_matrix.rs"),
    include_str!("aarch64/sme/integer_vector.rs"),
    include_str!("aarch64/sme/length.rs"),
    include_str!("aarch64/sme/movement.rs"),
    include_str!("aarch64/sme/tables.rs"),
    include_str!("x86_64/scalable.rs"),
    include_str!("x86_64/scalable/legacy.rs"),
    include_str!("x86_64/scalable/predicate.rs"),
    include_str!("x86_64/scalable/routing.rs"),
    include_str!("x86_64/scalable_matrix.rs"),
    include_str!("x86_64/sve.rs"),
    include_str!("x86_64/sve/address.rs"),
    include_str!("x86_64/sve/predicate.rs"),
    include_str!("x86_64/sve/predicate/counter.rs"),
    include_str!("x86_64/sve/predicate/counter_mask.rs"),
    include_str!("x86_64/sve/predicate/flags.rs"),
    include_str!("x86_64/sve/dot.rs"),
    include_str!("x86_64/sve/floating_copy.rs"),
    include_str!("x86_64/sve/integer_arithmetic.rs"),
    include_str!("x86_64/sve/integer_bits.rs"),
    include_str!("x86_64/sve/integer_bits/scalar.rs"),
    include_str!("x86_64/sve/integer_logic.rs"),
    include_str!("x86_64/sve/integer_predicate_move.rs"),
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
    include_str!("x86_64/sve/shifts.rs"),
    include_str!("x86_64/sve/shifts/saturating.rs"),
    include_str!("x86_64/sve/shifts/scalar.rs"),
    include_str!("x86_64/sve/shifts/variable.rs"),
    include_str!("x86_64/sve/shifts_narrow.rs"),
    include_str!("x86_64/sve/sign.rs"),
    include_str!("x86_64/sme.rs"),
    include_str!("x86_64/sme/integer_dots.rs"),
    include_str!("x86_64/sme/integer_matrix.rs"),
    include_str!("x86_64/sme/integer_matrix/long.rs"),
    include_str!("x86_64/sme/integer_matrix/outer.rs"),
    include_str!("x86_64/sme/integer_products.rs"),
    include_str!("x86_64/sme/integer_vector.rs"),
    include_str!("x86_64/sme/length.rs"),
    include_str!("x86_64/sme/movement.rs"),
    include_str!("x86_64/sme/tables.rs"),
    include_str!("x86_64/sme/tables/lookup.rs"),
    include_str!("target.rs"),
    include_str!("context/memory/exclusive.rs"),
    include_str!("context/memory/operation.rs"),
    include_str!("aarch64/exclusive.rs"),
    include_str!("x86_64/exclusive.rs"),
    include_str!("x86_64/memory_context.rs"),
    include_str!("x86_64/memory_context/address.rs"),
    include_str!("x86_64/scalable/memory.rs"),
    include_str!("aarch64.rs"),
    include_str!("aarch64/system.rs"),
    include_str!("aarch64/system/exception.rs"),
    include_str!("aarch64/system/registers.rs"),
    include_str!("aarch64/tag_memory.rs"),
    include_str!("block/system.rs"),
    include_str!("aarch64/system/synchronization.rs"),
    include_str!("aarch64/constrained.rs"),
    include_str!("x86_64.rs"),
    include_str!("x86_64/system.rs"),
    include_str!("x86_64/system/synchronization.rs"),
    include_str!("block.rs"),
    include_str!("block/memory.rs"),
    include_str!("x86_64/block/checked_memory.rs"),
    include_str!("x86_64/memory_store/checked_scalar.rs"),
    include_str!("x86_64/memory_store/checked_pair.rs"),
    include_str!("x86_64/simd/memory_checked.rs"),
    include_str!("x86_64/simd/memory_checked/tests.rs"),
    include_str!("block/thread.rs"),
    include_str!("block/pauth_memory.rs"),
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
    include_str!("../../stela-state/src/lib.rs"),
    include_str!("../../stela-state/Cargo.toml"),
    include_str!("../Cargo.toml"),
    include_str!("../../../Cargo.lock"),
    include_str!("aarch64/floating/estimate/precision.rs"),
    include_str!("aarch64/floating/exponent.rs"),
    include_str!("aarch64/sve/floating/bfloat16.rs"),
    include_str!("x86_64/simd/half/kernel.rs"),
    include_str!("x86_64/sve/floating/add_reductions.rs"),
    include_str!("x86_64/sve/floating/arithmetic_dispatch.rs"),
    include_str!("x86_64/sve/floating/arithmetic_remaining.rs"),
    include_str!("x86_64/sve/floating/bfloat16.rs"),
    include_str!("x86_64/sve/floating/bfloat16/accumulation.rs"),
    include_str!("x86_64/sve/floating/bfloat16/accumulation/classic_dot.rs"),
    include_str!("x86_64/sve/floating/bfloat16/accumulation/enhanced_dot.rs"),
    include_str!("x86_64/sve/floating/bfloat16/accumulation/multiply_long.rs"),
    include_str!("x86_64/sve/floating/complex.rs"),
    include_str!("x86_64/sve/floating/estimate_exponent.rs"),
    include_str!("x86_64/sve/floating/floating_estimates.rs"),
    include_str!("x86_64/sve/floating/fused.rs"),
    include_str!("x86_64/sve/floating/half_dot.rs"),
    include_str!("x86_64/sve/floating/indexed_half.rs"),
    include_str!("x86_64/sve/floating/minmax.rs"),
    include_str!("x86_64/sve/floating/pairwise_clamp.rs"),
    include_str!("x86_64/sve/floating/reduction_minmax.rs"),
    include_str!("x86_64/sve/floating/refinement.rs"),
    include_str!("x86_64/sve/floating/scale.rs"),
    include_str!("x86_64/sve/floating/square_root.rs"),
    include_str!("x86_64/sve/floating/unsigned_estimates.rs"),
    include_str!("aarch64/sve/floating/rounding.rs"),
    include_str!("x86_64/simd/numerical/bfloat16.rs"),
    include_str!("x86_64/simd/rounding/kernel.rs"),
    include_str!("x86_64/sve/floating/bfloat16/arithmetic.rs"),
    include_str!("x86_64/sve/floating/bfloat16/arithmetic/binary.rs"),
    include_str!("x86_64/sve/floating/bfloat16/arithmetic/fused.rs"),
    include_str!("x86_64/sve/floating/bfloat16/arithmetic/selection.rs"),
    include_str!("x86_64/sve/floating/conversion/bfloat.rs"),
    include_str!("x86_64/sve/floating/conversion/double_narrowing.rs"),
    include_str!("x86_64/sve/floating/conversion/half_integer.rs"),
    include_str!("x86_64/sve/floating/conversion/half_narrowing.rs"),
    include_str!("x86_64/sve/floating/conversion/half_widening.rs"),
    include_str!("x86_64/sve/floating/conversion/integer.rs"),
    include_str!("x86_64/sve/floating/conversion/unsigned64.rs"),
    include_str!("x86_64/sve/floating/rounding.rs"),
    include_str!("aarch64/scalable/execution.rs"),
    include_str!("aarch64/sve/memory.rs"),
    include_str!("aarch64/sve/memory_load.rs"),
    include_str!("aarch64/sve/memory_multi.rs"),
    include_str!("aarch64/sve/memory_store.rs"),
    include_str!("aarch64/sve/memory_structure.rs"),
    include_str!("aarch64/sme/memory.rs"),
    include_str!("x86_64/sve/memory.rs"),
    include_str!("x86_64/sve/memory_load.rs"),
    include_str!("x86_64/sve/memory_multi.rs"),
    include_str!("x86_64/sve/memory_store.rs"),
    include_str!("x86_64/sve/memory_structure.rs"),
    include_str!("x86_64/sme/memory.rs"),
    include_str!("x86_64/sme/memory/za.rs"),
    include_str!("aarch64/floating/absolute_minmax.rs"),
    include_str!("aarch64/sve/floating/faminmax.rs"),
    include_str!("aarch64/sve/floating/fp8.rs"),
    include_str!("x86_64/simd/absolute_selection.rs"),
    include_str!("x86_64/sve/floating/faminmax.rs"),
    include_str!("aarch64/sve/tables.rs"),
    include_str!("x86_64/sve/tables.rs"),
    include_str!("x86_64/scalable/lut.rs"),
    include_str!("aarch64/simd/lut.rs"),
    include_str!("aarch64/sme/lut_v2.rs"),
    include_str!("x86_64/simd/lut.rs"),
    include_str!("x86_64/sme/tables/lookup/lut_v2.rs"),
    include_str!("aarch64/sme/fp8_matrix.rs"),
    include_str!("block/scalable/fp8_matrix_scope_tests.rs"),
    include_str!("aarch64/simd/extrema_scale.rs"),
    include_str!("x86_64/simd/extrema_scale.rs"),
    include_str!("aarch64/sme/extrema_scale.rs"),
    include_str!("x86_64/sme/extrema_scale.rs"),
    include_str!("x86_64/simd/exponent_scale.rs"),
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
    fn guest_state_reexport_is_the_shared_type() {
        let mut shared = stela_state::GuestState::default();
        let compiler: &mut GuestState = &mut shared;
        compiler.x[30] = 0x1234;
        let shared: &stela_state::GuestState = compiler;
        assert_eq!(shared.x[30], 0x1234);
        assert_eq!(NATIVE_ABI, stela_state::NATIVE_ABI);
        assert!(SOURCE_FINGERPRINT_MATERIAL.contains(include_str!("../../stela-state/src/lib.rs")));
        assert!(SOURCE_FINGERPRINT_MATERIAL.contains(include_str!("../../stela-state/Cargo.toml")));
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
