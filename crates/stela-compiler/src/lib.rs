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
    include_str!("x86_64/block.rs"),
    include_str!("aarch64/bitfield.rs"),
    include_str!("x86_64/bitfield.rs"),
    include_str!("aarch64/conditional_select.rs"),
    include_str!("x86_64/conditional_select.rs"),
    include_str!("aarch64/integer_math.rs"),
    include_str!("x86_64/integer_math.rs"),
    include_str!("aarch64/pc_relative.rs"),
    include_str!("x86_64/pc_relative.rs"),
    include_str!("aarch64/register_offset.rs"),
    include_str!("x86_64/register_offset.rs"),
    include_str!("aarch64/simd.rs"),
    include_str!("x86_64/simd.rs"),
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

/// Explicit feature tiers bind generated code and persistent cache identity.
/// Higher tiers require every lower-tier feature; no AVX/OSXSAVE assumption.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TargetCpu {
    #[default]
    Baseline,
    Ssse3,
    Sse41,
    Sse42,
}
impl TargetCpu {
    pub fn detect() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            Self::for_features(
                std::is_x86_feature_detected!("ssse3"),
                std::is_x86_feature_detected!("sse4.1"),
                std::is_x86_feature_detected!("sse4.2"),
            )
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            Self::Baseline
        }
    }
    #[cfg(any(target_arch = "x86_64", test))]
    fn for_features(ssse3: bool, sse41: bool, sse42: bool) -> Self {
        match (ssse3, sse41, sse42) {
            (false, _, _) => Self::Baseline,
            (true, false, _) => Self::Ssse3,
            (true, true, false) => Self::Sse41,
            (true, true, true) => Self::Sse42,
        }
    }
    pub fn id(self) -> &'static str {
        match self {
            Self::Baseline => "x86_64-baseline",
            Self::Ssse3 => "x86_64-baseline+ssse3",
            Self::Sse41 => "x86_64-baseline+ssse3+sse4.1",
            Self::Sse42 => "x86_64-baseline+ssse3+sse4.1+sse4.2",
        }
    }
    pub fn supported(self) -> bool {
        cfg!(target_arch = "x86_64") && self <= Self::detect()
    }
}

#[cfg(test)]
mod target_tests {
    use super::*;
    #[test]
    fn targets_require_every_feature_in_the_declared_tier() {
        for bits in 0..8 {
            let features = (bits & 1 != 0, bits & 2 != 0, bits & 4 != 0);
            let target = TargetCpu::for_features(features.0, features.1, features.2);
            assert_eq!(target >= TargetCpu::Ssse3, features.0);
            assert_eq!(target >= TargetCpu::Sse41, features.0 && features.1);
            assert_eq!(
                target >= TargetCpu::Sse42,
                features.0 && features.1 && features.2
            );
            assert_eq!(target.id().parse::<TargetCpu>().unwrap(), target);
        }
        assert!("x86_64-baseline+avx2".parse::<TargetCpu>().is_err());
    }
}
impl std::str::FromStr for TargetCpu {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        [Self::Baseline, Self::Ssse3, Self::Sse41, Self::Sse42]
            .into_iter()
            .find(|target| {
                target.id() == value
                    || match target {
                        Self::Baseline => value == "baseline",
                        Self::Ssse3 => value == "ssse3",
                        Self::Sse41 => value == "sse4.1",
                        Self::Sse42 => value == "sse4.2",
                    }
            })
            .ok_or_else(|| format!("unknown x86-64 CPU target {value}"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestAddress(pub u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnsupportedReason {
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
