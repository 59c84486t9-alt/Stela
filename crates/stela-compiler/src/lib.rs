//! Ahead-of-time native translation of supported Apple-silicon ARM64 semantics.
//! Unsupported instructions are errors; no interpreter fallback is emitted.

pub mod aarch64;
pub mod block;
pub mod x86_64;

use serde::{Deserialize, Serialize};

/// Bind cached code and evidence to compiler implementation and dependencies.
pub const SOURCE_FINGERPRINT_MATERIAL: &str = concat!(
    include_str!("lib.rs"),
    include_str!("aarch64.rs"),
    include_str!("x86_64.rs"),
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
    include_str!("aarch64/integer_math.rs"),
    include_str!("x86_64/integer_math.rs"),
    include_str!("aarch64/literal.rs"),
    include_str!("x86_64/literal.rs"),
    include_str!("aarch64/pc_relative.rs"),
    include_str!("x86_64/pc_relative.rs"),
    include_str!("aarch64/register_offset.rs"),
    include_str!("x86_64/register_offset.rs"),
    include_str!("x86_64/memory_store.rs"),
    include_str!("aarch64/simd.rs"),
    include_str!("x86_64/simd.rs"),
    include_str!("aarch64/simd/memory.rs"),
    include_str!("x86_64/simd/memory.rs"),
    include_str!("aarch64/simd/floating.rs"),
    include_str!("x86_64/simd/floating.rs"),
    include_str!("aarch64/simd/arithmetic.rs"),
    include_str!("x86_64/simd/arithmetic.rs"),
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

/// Explicit host requirements bind generated code and persistent cache identity.
/// SSE tiers are nested; PCLMULQDQ is independent. No AVX/OSXSAVE assumption.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TargetCpu {
    tier: SseTier,
    pclmulqdq: bool,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SseTier {
    #[default]
    Baseline,
    Ssse3,
    Sse41,
    Sse42,
}

// Retain the established public tier names and their canonical cache identities.
#[allow(non_upper_case_globals)]
impl TargetCpu {
    pub const Baseline: Self = Self {
        tier: SseTier::Baseline,
        pclmulqdq: false,
    };
    pub const Ssse3: Self = Self {
        tier: SseTier::Ssse3,
        pclmulqdq: false,
    };
    pub const Sse41: Self = Self {
        tier: SseTier::Sse41,
        pclmulqdq: false,
    };
    pub const Sse42: Self = Self {
        tier: SseTier::Sse42,
        pclmulqdq: false,
    };
    /// Minimum requirements for legacy XMM PCLMULQDQ, independent of SSE tiers.
    pub const Pclmulqdq: Self = Self::Baseline.with_pclmulqdq();

    pub const fn with_pclmulqdq(self) -> Self {
        Self {
            pclmulqdq: true,
            ..self
        }
    }
    /// True only when every required feature is present in this target.
    pub fn supports(self, required: Self) -> bool {
        self.tier >= required.tier && (!required.pclmulqdq || self.pclmulqdq)
    }
    pub fn detect() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            Self::for_features(
                std::is_x86_feature_detected!("ssse3"),
                std::is_x86_feature_detected!("sse4.1"),
                std::is_x86_feature_detected!("sse4.2"),
                std::is_x86_feature_detected!("pclmulqdq"),
            )
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            Self::Baseline
        }
    }
    #[cfg(any(target_arch = "x86_64", test))]
    fn for_features(ssse3: bool, sse41: bool, sse42: bool, pclmulqdq: bool) -> Self {
        let tier = match (ssse3, sse41, sse42) {
            (false, _, _) => SseTier::Baseline,
            (true, false, _) => SseTier::Ssse3,
            (true, true, false) => SseTier::Sse41,
            (true, true, true) => SseTier::Sse42,
        };
        Self { tier, pclmulqdq }
    }
    pub fn id(self) -> &'static str {
        match (self.tier, self.pclmulqdq) {
            (SseTier::Baseline, false) => "x86_64-baseline",
            (SseTier::Ssse3, false) => "x86_64-baseline+ssse3",
            (SseTier::Sse41, false) => "x86_64-baseline+ssse3+sse4.1",
            (SseTier::Sse42, false) => "x86_64-baseline+ssse3+sse4.1+sse4.2",
            (SseTier::Baseline, true) => "x86_64-baseline+pclmulqdq",
            (SseTier::Ssse3, true) => "x86_64-baseline+ssse3+pclmulqdq",
            (SseTier::Sse41, true) => "x86_64-baseline+ssse3+sse4.1+pclmulqdq",
            (SseTier::Sse42, true) => "x86_64-baseline+ssse3+sse4.1+sse4.2+pclmulqdq",
        }
    }
    pub fn supported(self) -> bool {
        cfg!(target_arch = "x86_64") && Self::detect().supports(self)
    }
}

// Ordering means feature containment, not an arbitrary rank. In particular,
// baseline+PCLMUL and SSE4.2 without PCLMUL are incomparable requirements.
impl PartialOrd for TargetCpu {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match (self.supports(*other), other.supports(*self)) {
            (true, true) => Some(std::cmp::Ordering::Equal),
            (true, false) => Some(std::cmp::Ordering::Greater),
            (false, true) => Some(std::cmp::Ordering::Less),
            (false, false) => None,
        }
    }
}

impl std::str::FromStr for TargetCpu {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (tier_name, pclmulqdq) = match value.strip_suffix("+pclmulqdq") {
            Some(tier_name) => (tier_name, true),
            None => (value, false),
        };
        let tier = [Self::Baseline, Self::Ssse3, Self::Sse41, Self::Sse42]
            .into_iter()
            .zip(["baseline", "ssse3", "sse4.1", "sse4.2"])
            .find(|(target, alias)| target.id() == tier_name || *alias == tier_name)
            .map(|(target, _)| target)
            .ok_or_else(|| format!("unknown x86-64 CPU target {value}"))?;
        Ok(Self { pclmulqdq, ..tier })
    }
}

#[cfg(test)]
mod target_tests {
    use super::*;
    #[test]
    fn targets_require_every_feature_in_the_declared_tier() {
        for bits in 0..16 {
            let features = (bits & 1 != 0, bits & 2 != 0, bits & 4 != 0, bits & 8 != 0);
            let target = TargetCpu::for_features(features.0, features.1, features.2, features.3);
            assert_eq!(target >= TargetCpu::Ssse3, features.0);
            assert_eq!(target >= TargetCpu::Sse41, features.0 && features.1);
            assert_eq!(
                target >= TargetCpu::Sse42,
                features.0 && features.1 && features.2
            );
            assert_eq!(target.supports(TargetCpu::Pclmulqdq), features.3);
            assert_eq!(target >= TargetCpu::Pclmulqdq, features.3);
            assert_eq!(target.id().parse::<TargetCpu>().unwrap(), target);
        }
        assert!("x86_64-baseline+avx2".parse::<TargetCpu>().is_err());
        assert!("sse4.2+pclmulqdq+pclmulqdq".parse::<TargetCpu>().is_err());
        assert_eq!(
            "baseline+pclmulqdq".parse::<TargetCpu>().unwrap(),
            TargetCpu::Pclmulqdq
        );
        assert_eq!(
            "sse4.2+pclmulqdq".parse::<TargetCpu>().unwrap(),
            TargetCpu::Sse42.with_pclmulqdq()
        );
    }
    #[test]
    fn independent_features_require_full_containment() {
        for host_tier in [
            TargetCpu::Baseline,
            TargetCpu::Ssse3,
            TargetCpu::Sse41,
            TargetCpu::Sse42,
        ] {
            for required_tier in [
                TargetCpu::Baseline,
                TargetCpu::Ssse3,
                TargetCpu::Sse41,
                TargetCpu::Sse42,
            ] {
                for host_pclmul in [false, true] {
                    for required_pclmul in [false, true] {
                        let host = if host_pclmul {
                            host_tier.with_pclmulqdq()
                        } else {
                            host_tier
                        };
                        let required = if required_pclmul {
                            required_tier.with_pclmulqdq()
                        } else {
                            required_tier
                        };
                        let expected =
                            host_tier >= required_tier && (!required_pclmul || host_pclmul);
                        assert_eq!(host.supports(required), expected);
                        assert_eq!(host >= required, expected);
                    }
                }
            }
        }
        assert_eq!(TargetCpu::Sse42.partial_cmp(&TargetCpu::Pclmulqdq), None);
        assert!(!TargetCpu::Sse42.supports(TargetCpu::Pclmulqdq));
        assert!(!TargetCpu::Pclmulqdq.supports(TargetCpu::Ssse3));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestAddress(pub u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnsupportedReason {
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
/// V registers are little-endian low/high 64-bit limbs. FPCR and unimplemented FPSR bits
/// are preserved state. Saturating integer SIMD updates FPSR.QC; storage alone
/// does not implement floating-point arithmetic.
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
    fn rejects_unknown_instructions_bad_boundaries_and_address_overflow() {
        for words in [
            vec![],
            vec![0xd503201fu32],
            vec![0x14000002, 0xd65f03c0], // branch falls outside the region
            vec![0xf9800000, 0xd65f03c0], // PRFM is not a data load
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
