//! Host-native paths for AMX operations, exact against [`super::model`].
//!
//! The reference model computes every lane with Stela's software Arm
//! evaluators, which costs microseconds for one matrix `fma32`. These paths
//! compute the same lanes with host vector instructions and return `false`
//! for any operand they do not cover, leaving the registers unchanged, so the
//! caller then runs the model: the model stays the definition and the
//! fallback for every rare mode.
//!
//! Covered, chosen once from the [`TargetCpu`] (`Native::select`):
//!
//! - `fma32`, `fms32`, `fma64` and `fms64` in matrix and vector shape,
//!   accumulating or product-only (bits 29:27 = 0 or 1), every lane-enable
//!   mode, and `fma32`'s even-f16 widening of X and Y (bits 61/60). Tiers:
//!   `Avx512` (EVEX.512, one ZMM per row, opmask lane enables; AVX-512F with
//!   OS-enabled opmask and ZMM state), `Fma` (VEX.256 with FMA3, two YMM
//!   halves per row, F16C for the widening, without which widening operands
//!   use the model), and below FMA3 the model: a multiply-add rounded once
//!   cannot be built exactly from SSE multiplies and adds.
//! - `vecfp` on IEEE f16 lanes, `z + x*y` and `z - x*y` (modes 0 and 1),
//!   with a broadcast Y lane or any lane-enable mode, one Z row, no shuffle,
//!   indexed load or multi-row form. F16C (VEX.128): the product of two f16
//!   values is exact in f32, the f32 sum is rounded to odd from its exact
//!   TwoSum error, and the conversion to f16 then rounds once correctly
//!   (24 >= 11 + 2 bits). Without F16C the model.
//!
//! The kernels are inline assembly, so they run in the boot, whose UEFI
//! target is soft-float (vector intrinsics would become software calls).
//!
//! Arithmetic runs under MXCSR 0x1F80 (round to nearest even, no DAZ/FTZ,
//! exceptions masked) and restores the caller's MXCSR, so host status flags
//! never escape. x86 and Arm agree on every non-NaN fused, product and sign
//! result in that mode, and a result is NaN on one exactly when it is on the
//! other; NaN results become the Arm default NaN, as the AMX environment
//! (FPCR.DN) gives.
use super::{AmxOperation, AmxRegisters, Generation, model::write_mask, state::ROW_BYTES};
use crate::TargetCpu;

const VECTOR: u64 = 1 << 63;
/// `fma16`/`fms16` bit 62: f32 accumulation into interleaved row pairs.
const WIDEN_16_32: u64 = 1 << 62;
const X_HALF: u64 = 1 << 61;
const Y_HALF: u64 = 1 << 60;

/// The widest host path that computes the covered operations exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tier {
    Model,
    Fma,
    Avx512,
}

impl Tier {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Model => "model",
            Self::Fma => "fma",
            Self::Avx512 => "avx512f",
        }
    }
}

/// The host paths one boot uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Native {
    /// The fused-multiply tier.
    tier: Tier,
    /// VEX F16C: `fma32`'s f16 widening on the `Fma` tier, and `vecfp` f16.
    f16c: bool,
}

impl Native {
    /// No host path: every operation uses the model.
    pub const MODEL: Self = Self {
        tier: Tier::Model,
        f16c: false,
    };

    /// The best paths `target` admits. AVX-512F has its own EVEX f16
    /// conversions; the VEX paths need F16C.
    pub const fn select(target: TargetCpu) -> Self {
        if !cfg!(target_arch = "x86_64") {
            return Self::MODEL;
        }
        let tier = if target.supports(TargetCpu::Avx512f) {
            Tier::Avx512
        } else if target.supports(TargetCpu::Fma) {
            Tier::Fma
        } else {
            Tier::Model
        };
        Self {
            tier,
            f16c: target.supports(TargetCpu::F16c),
        }
    }

    pub const fn tier(self) -> Tier {
        self.tier
    }

    /// Complete `operation` natively when a path covers `operand`, exactly as
    /// `model::execute_for(generation, ..)` would; `false` leaves the
    /// registers untouched for the model.
    pub fn execute(
        self,
        generation: Generation,
        registers: &mut AmxRegisters,
        operation: AmxOperation,
        operand: u64,
    ) -> bool {
        #[cfg(not(target_arch = "x86_64"))]
        let _ = (generation, registers, operand);
        match operation {
            #[cfg(target_arch = "x86_64")]
            AmxOperation::Fma32
            | AmxOperation::Fms32
            | AmxOperation::Fma64
            | AmxOperation::Fms64 => {
                self.tier != Tier::Model && x86::fused(self, registers, operation, operand)
            }
            #[cfg(target_arch = "x86_64")]
            AmxOperation::Fma16 | AmxOperation::Fms16 => {
                self.f16c && x86::fused_half(registers, operation, operand)
            }
            #[cfg(target_arch = "x86_64")]
            AmxOperation::VectorFloat => {
                self.f16c && x86::vector_half(generation, registers, operand)
            }
            _ => false,
        }
    }
}

/// The decoded form of a covered fused operation.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
struct Fused {
    vector: bool,
    z_row: usize,
    /// Per-byte lane enables (`write_mask`): lane i is on when bit
    /// `i * element bytes` is.
    x_enable: u64,
    y_enable: u64,
}

#[cfg(target_arch = "x86_64")]
mod x86 {
    //! The kernels are inline assembly with explicit registers: the UEFI
    //! target is soft-float, where vector intrinsics would become software
    //! calls. Each block is self-contained (no vector value lives across
    //! blocks) and declares the SysV clobbers, which on the soft-float
    //! target name registers its own code never uses.
    use super::{Fused, Native, ROW_BYTES, Tier, VECTOR, X_HALF, Y_HALF, write_mask};
    use crate::amx::{AmxOperation, AmxRegisters, Generation};
    use core::arch::asm;

    type Row = [u8; ROW_BYTES];

    static AMX_MXCSR: u32 = 0x1f80;
    static NAN_32: u32 = 0x7fc0_0000;
    static NAN_64: u64 = 0x7ff8_0000_0000_0000;
    static NEGATIVE_ZERO_32: u32 = 0x8000_0000;
    static NEGATIVE_ZERO_64: u64 = 0x8000_0000_0000_0000;

    /// The four fused forms.
    #[derive(Clone, Copy)]
    enum Form {
        /// `z + x*y`.
        Add,
        /// `z - x*y`.
        Subtract,
        /// `x*y`.
        Product,
        /// `-0 - x*y`: the negated product.
        NegatedProduct,
    }

    pub(super) fn fused(
        native: Native,
        registers: &mut AmxRegisters,
        operation: AmxOperation,
        operand: u64,
    ) -> bool {
        let (double, subtract) = match operation {
            AmxOperation::Fma32 => (false, false),
            AmxOperation::Fms32 => (false, true),
            AmxOperation::Fma64 => (true, false),
            AmxOperation::Fms64 => (true, true),
            _ => return false,
        };
        let product_only = match (operand >> 27) & 7 {
            0 => false,
            1 => true,
            _ => return false,
        };
        // Only fma32/fms32 read bits 61/60; f64 ignores them.
        let x_half = !double && operand & X_HALF != 0;
        let y_half = !double && operand & Y_HALF != 0;
        if (x_half || y_half) && native.tier == Tier::Fma && !native.f16c {
            return false;
        }
        let bytes = if double { 8 } else { 4 };
        let fused = Fused {
            vector: operand & VECTOR != 0,
            z_row: ((operand >> 20) & 63) as usize,
            x_enable: write_mask(operand >> 41, bytes, 7),
            y_enable: write_mask(operand >> 32, bytes, 7),
        };
        let form = match (product_only, subtract) {
            (false, false) => Form::Add,
            (false, true) => Form::Subtract,
            (true, false) => Form::Product,
            (true, true) => Form::NegatedProduct,
        };
        let mut x = registers.x_operand((operand >> 10) & 0x1ff);
        let mut y = registers.y_operand(operand & 0x1ff);
        let bytes = bytes as usize;
        let lanes = 64 / bytes;
        // Per-lane all-ones masks (VEX) or the opmask (EVEX) of X's lanes.
        let mut mask = [0u8; ROW_BYTES];
        let mut opmask = 0u32;
        for lane in 0..lanes {
            if on(fused.x_enable, lane, bytes) {
                mask[lane * bytes..lane * bytes + bytes].fill(0xff);
                opmask |= 1 << lane;
            }
        }
        // SAFETY: `select` chose the tier from a target whose features the
        // host admits, and F16C is checked above for VEX widening. Every
        // pointer is to a live 64-byte row; MXCSR is restored after.
        unsafe {
            let saved = enter();
            if x_half {
                x = widen(native.tier, &x);
            }
            if y_half {
                y = widen(native.tier, &y);
            }
            let mut row = |index: usize, y: &Row| {
                let z = registers.z[index].as_mut_ptr();
                match native.tier {
                    Tier::Avx512 => row_avx512(double, form, z, &x, y, opmask),
                    _ => row_fma(double, form, z, &x, y, &mask),
                }
            };
            if fused.vector {
                row(fused.z_row, &y);
            } else {
                // Y lane j into Z row j*g + z_row%g, g = 64/lanes, in one
                // kernel loop over the enabled Y lanes.
                let g = 64 / lanes;
                let rows = (0..lanes).fold(0u32, |rows, j| {
                    rows | u32::from(on(fused.y_enable, j, bytes)) << j
                });
                let matrix = Matrix {
                    z: registers.z[fused.z_row & (g - 1)].as_mut_ptr(),
                    stride: g * ROW_BYTES,
                    rows,
                    lanes,
                };
                match native.tier {
                    Tier::Avx512 => matrix_avx512(double, form, matrix, &x, &y, opmask),
                    _ => matrix_fma(double, form, matrix, &x, &y, &mask),
                }
            }
            leave(saved);
        }
        true
    }

    /// Save MXCSR and load the AMX environment.
    ///
    /// # Safety
    /// Pair with [`leave`].
    unsafe fn enter() -> u32 {
        let mut saved = 0u32;
        // SAFETY: stmxcsr/ldmxcsr of valid 4-byte locations.
        unsafe {
            asm!(
                "stmxcsr [{saved}]",
                "ldmxcsr [{amx}]",
                saved = in(reg) &raw mut saved,
                amx = in(reg) &raw const AMX_MXCSR,
                options(nostack, preserves_flags),
            );
        }
        saved
    }

    /// # Safety
    /// `saved` came from [`enter`].
    unsafe fn leave(saved: u32) {
        // SAFETY: ldmxcsr of the value stmxcsr produced.
        unsafe {
            asm!(
                "ldmxcsr [{saved}]",
                saved = in(reg) &raw const saved,
                options(nostack, preserves_flags, readonly),
            );
        }
    }

    /// Lane `lane` of `bytes`-byte lanes is on in a per-byte enable.
    fn on(enable: u64, lane: usize, bytes: usize) -> bool {
        (enable >> (lane * bytes)) & 1 != 0
    }

    /// The even f16 lanes of a row widened to f32, exactly; NaNs stay NaN
    /// (every covered result from a NaN input is the default NaN).
    ///
    /// # Safety
    /// The tier's instructions exist: F16C for `Fma`, AVX-512F for `Avx512`.
    unsafe fn widen(tier: Tier, row: &Row) -> Row {
        let mut out = [0u8; ROW_BYTES];
        let (source, destination) = (row.as_ptr(), out.as_mut_ptr());
        // SAFETY: 64-byte arrays, unaligned forms; the tier's instructions
        // exist as the caller guarantees.
        unsafe {
            if tier == Tier::Avx512 {
                asm!(
                    "vmovdqu32 zmm0, [{source}]",
                    "vpmovdw ymm0, zmm0",
                    "vcvtph2ps zmm0, ymm0",
                    "vmovups [{destination}], zmm0",
                    "vzeroupper",
                    source = in(reg) source,
                    destination = in(reg) destination,
                    clobber_abi("sysv64"),
                    options(nostack, preserves_flags),
                );
            } else {
                asm!(
                    "vpcmpeqd xmm4, xmm4, xmm4",
                    "vpsrld xmm4, xmm4, 16",
                    "vpand xmm0, xmm4, [{source}]",
                    "vpand xmm1, xmm4, [{source} + 16]",
                    "vpand xmm2, xmm4, [{source} + 32]",
                    "vpand xmm3, xmm4, [{source} + 48]",
                    "vpackusdw xmm0, xmm0, xmm1",
                    "vpackusdw xmm2, xmm2, xmm3",
                    "vcvtph2ps ymm0, xmm0",
                    "vcvtph2ps ymm2, xmm2",
                    "vmovups [{destination}], ymm0",
                    "vmovups [{destination} + 32], ymm2",
                    "vzeroupper",
                    source = in(reg) source,
                    destination = in(reg) destination,
                    clobber_abi("sysv64"),
                    options(nostack, preserves_flags),
                );
            }
        }
        out
    }

    /// One half-row (32 bytes at `$offset`) of a VEX.256 fused row:
    /// ymm3 = old Z, ymm2 = result, NaN results become the default NaN,
    /// disabled lanes keep the old Z.
    macro_rules! vex_half {
        ($s:literal, $offset:literal, $init:literal, $op:literal) => {
            concat!(
                "vmovups ymm0, ymmword ptr [{x} + ",
                $offset,
                "]\n",
                "vmovups ymm1, ymmword ptr [{y} + ",
                $offset,
                "]\n",
                "vmovups ymm3, ymmword ptr [{z} + ",
                $offset,
                "]\n",
                $init,
                "\n",
                $op,
                $s,
                " ymm2, ymm0, ymm1\n",
                "vcmpunord",
                $s,
                " ymm4, ymm2, ymm2\n",
                "vblendv",
                $s,
                " ymm2, ymm2, ymm7, ymm4\n",
                "vmovups ymm5, ymmword ptr [{mask} + ",
                $offset,
                "]\n",
                "vblendv",
                $s,
                " ymm2, ymm3, ymm2, ymm5\n",
                "vmovups ymmword ptr [{z} + ",
                $offset,
                "], ymm2\n",
            )
        };
    }

    /// A VEX.256 fused row: ymm6 = -0 and ymm7 = the default NaN in every
    /// lane, then both halves.
    macro_rules! vex_row {
        ($s:literal, $broadcast:literal, $init:literal, $op:literal, $z:expr, $x:expr, $y:expr, $mask:expr, $nan:expr, $zero:expr) => {
            asm!(
                concat!($broadcast, " ymm6, [{zero}]"),
                concat!($broadcast, " ymm7, [{nan}]"),
                vex_half!($s, "0", $init, $op),
                vex_half!($s, "32", $init, $op),
                "vzeroupper",
                x = in(reg) $x,
                y = in(reg) $y,
                z = in(reg) $z,
                mask = in(reg) $mask,
                nan = in(reg) $nan,
                zero = in(reg) $zero,
                clobber_abi("sysv64"),
                options(nostack, preserves_flags),
            )
        };
    }

    /// One Z row on the FMA3 tier.
    ///
    /// # Safety
    /// FMA3 and AVX exist; `z` is a 64-byte row.
    unsafe fn row_fma(double: bool, form: Form, z: *mut u8, x: &Row, y: &Row, mask: &Row) {
        let (x, y, mask) = (x.as_ptr(), y.as_ptr(), mask.as_ptr());
        // SAFETY: FMA3 exists as the caller guarantees; every pointer is to
        // 64 live bytes (or a constant), unaligned forms.
        unsafe {
            if double {
                let (nan, zero) = (&raw const NAN_64, &raw const NEGATIVE_ZERO_64);
                match form {
                    Form::Add => vex_row!(
                        "pd",
                        "vbroadcastsd",
                        "vmovapd ymm2, ymm3",
                        "vfmadd231",
                        z,
                        x,
                        y,
                        mask,
                        nan,
                        zero
                    ),
                    Form::Subtract => vex_row!(
                        "pd",
                        "vbroadcastsd",
                        "vmovapd ymm2, ymm3",
                        "vfnmadd231",
                        z,
                        x,
                        y,
                        mask,
                        nan,
                        zero
                    ),
                    Form::Product => {
                        vex_row!("pd", "vbroadcastsd", "", "vmul", z, x, y, mask, nan, zero)
                    }
                    Form::NegatedProduct => vex_row!(
                        "pd",
                        "vbroadcastsd",
                        "vmovapd ymm2, ymm6",
                        "vfnmadd231",
                        z,
                        x,
                        y,
                        mask,
                        nan,
                        zero
                    ),
                }
            } else {
                let (nan, zero) = (&raw const NAN_32, &raw const NEGATIVE_ZERO_32);
                match form {
                    Form::Add => vex_row!(
                        "ps",
                        "vbroadcastss",
                        "vmovaps ymm2, ymm3",
                        "vfmadd231",
                        z,
                        x,
                        y,
                        mask,
                        nan,
                        zero
                    ),
                    Form::Subtract => vex_row!(
                        "ps",
                        "vbroadcastss",
                        "vmovaps ymm2, ymm3",
                        "vfnmadd231",
                        z,
                        x,
                        y,
                        mask,
                        nan,
                        zero
                    ),
                    Form::Product => {
                        vex_row!("ps", "vbroadcastss", "", "vmul", z, x, y, mask, nan, zero)
                    }
                    Form::NegatedProduct => vex_row!(
                        "ps",
                        "vbroadcastss",
                        "vmovaps ymm2, ymm6",
                        "vfnmadd231",
                        z,
                        x,
                        y,
                        mask,
                        nan,
                        zero
                    ),
                }
            }
        }
    }

    macro_rules! evex_row {
        ($s:literal, $broadcast:literal, $init:literal, $op:literal, $z:expr, $x:expr, $y:expr, $opmask:expr, $nan:expr, $zero:expr) => {
            asm!(
                concat!($broadcast, " zmm6, [{zero}]"),
                "vmovups zmm0, zmmword ptr [{x}]",
                "vmovups zmm1, zmmword ptr [{y}]",
                "vmovups zmm3, zmmword ptr [{z}]",
                $init,
                concat!($op, $s, " zmm2, zmm0, zmm1"),
                concat!("vcmpunord", $s, " k1, zmm2, zmm2"),
                concat!($broadcast, " zmm2 {{k1}}, [{nan}]"),
                "kmovw k2, {opmask:e}",
                // The element width decides which lanes the opmask writes.
                concat!("vmovu", $s, " zmmword ptr [{z}] {{k2}}, zmm2"),
                "vzeroupper",
                x = in(reg) $x,
                y = in(reg) $y,
                z = in(reg) $z,
                opmask = in(reg) $opmask,
                nan = in(reg) $nan,
                zero = in(reg) $zero,
                clobber_abi("sysv64"),
                options(nostack, preserves_flags),
            )
        };
    }

    /// One Z row on the AVX-512F tier.
    ///
    /// # Safety
    /// AVX-512F exists with OS-enabled state; `z` is a 64-byte row.
    unsafe fn row_avx512(double: bool, form: Form, z: *mut u8, x: &Row, y: &Row, opmask: u32) {
        let (x, y) = (x.as_ptr(), y.as_ptr());
        // SAFETY: AVX-512F exists as the caller guarantees; every pointer is
        // to 64 live bytes (or a constant), unaligned forms.
        unsafe {
            if double {
                let (nan, zero) = (&raw const NAN_64, &raw const NEGATIVE_ZERO_64);
                match form {
                    Form::Add => evex_row!(
                        "pd",
                        "vbroadcastsd",
                        "vmovapd zmm2, zmm3",
                        "vfmadd231",
                        z,
                        x,
                        y,
                        opmask,
                        nan,
                        zero
                    ),
                    Form::Subtract => evex_row!(
                        "pd",
                        "vbroadcastsd",
                        "vmovapd zmm2, zmm3",
                        "vfnmadd231",
                        z,
                        x,
                        y,
                        opmask,
                        nan,
                        zero
                    ),
                    Form::Product => {
                        evex_row!("pd", "vbroadcastsd", "", "vmul", z, x, y, opmask, nan, zero)
                    }
                    Form::NegatedProduct => evex_row!(
                        "pd",
                        "vbroadcastsd",
                        "vmovapd zmm2, zmm6",
                        "vfnmadd231",
                        z,
                        x,
                        y,
                        opmask,
                        nan,
                        zero
                    ),
                }
            } else {
                let (nan, zero) = (&raw const NAN_32, &raw const NEGATIVE_ZERO_32);
                match form {
                    Form::Add => evex_row!(
                        "ps",
                        "vbroadcastss",
                        "vmovaps zmm2, zmm3",
                        "vfmadd231",
                        z,
                        x,
                        y,
                        opmask,
                        nan,
                        zero
                    ),
                    Form::Subtract => evex_row!(
                        "ps",
                        "vbroadcastss",
                        "vmovaps zmm2, zmm3",
                        "vfnmadd231",
                        z,
                        x,
                        y,
                        opmask,
                        nan,
                        zero
                    ),
                    Form::Product => {
                        evex_row!("ps", "vbroadcastss", "", "vmul", z, x, y, opmask, nan, zero)
                    }
                    Form::NegatedProduct => evex_row!(
                        "ps",
                        "vbroadcastss",
                        "vmovaps zmm2, zmm6",
                        "vfnmadd231",
                        z,
                        x,
                        y,
                        opmask,
                        nan,
                        zero
                    ),
                }
            }
        }
    }

    /// A matrix product's Z rows: the first, the step between them, the Y
    /// lanes whose rows are written (bit j) and the lane count.
    struct Matrix {
        z: *mut u8,
        stride: usize,
        rows: u32,
        lanes: usize,
    }

    /// One half of a VEX.256 matrix row: X in `$x`, its lane masks in
    /// `$mask`, the broadcast Y lane in ymm1.
    macro_rules! vex_matrix_half {
        ($s:literal, $offset:literal, $init:literal, $op:literal, $x:literal, $mask:literal) => {
            concat!(
                "vmovups ymm3, ymmword ptr [rdi + ",
                $offset,
                "]\n",
                $init,
                "\n",
                $op,
                $s,
                " ymm2, ",
                $x,
                ", ymm1\n",
                "vcmpunord",
                $s,
                " ymm4, ymm2, ymm2\n",
                "vblendv",
                $s,
                " ymm2, ymm2, ymm7, ymm4\n",
                "vblendv",
                $s,
                " ymm2, ymm3, ymm2, ",
                $mask,
                "\n",
                "vmovups ymmword ptr [rdi + ",
                $offset,
                "], ymm2\n",
            )
        };
    }

    /// A VEX.256 matrix product: ymm8/9 = X, ymm10/11 = its lane masks,
    /// ymm6 = -0, ymm7 = the default NaN; then each enabled Y lane.
    macro_rules! vex_matrix {
        ($s:literal, $broadcast:literal, $size:literal, $step:literal, $init:literal, $op:literal, $m:expr, $x:expr, $y:expr, $mask:expr, $nan:expr, $zero:expr) => {
            asm!(
                concat!($broadcast, " ymm6, [{zero}]"),
                concat!($broadcast, " ymm7, [{nan}]"),
                "vmovups ymm8, ymmword ptr [{x}]",
                "vmovups ymm9, ymmword ptr [{x} + 32]",
                "vmovups ymm10, ymmword ptr [{mask}]",
                "vmovups ymm11, ymmword ptr [{mask} + 32]",
                "2:",
                "test ecx, 1",
                "jz 3f",
                concat!($broadcast, " ymm1, ", $size, " ptr [rsi]"),
                vex_matrix_half!($s, "0", $init, $op, "ymm8", "ymm10"),
                vex_matrix_half!($s, "32", $init, $op, "ymm9", "ymm11"),
                "3:",
                concat!("add rsi, ", $step),
                "add rdi, {stride}",
                "shr ecx, 1",
                "dec rdx",
                "jnz 2b",
                "vzeroupper",
                inout("rsi") $y => _,
                inout("rdi") $m.z => _,
                inout("ecx") $m.rows => _,
                inout("rdx") $m.lanes => _,
                stride = in(reg) $m.stride,
                x = in(reg) $x,
                mask = in(reg) $mask,
                nan = in(reg) $nan,
                zero = in(reg) $zero,
                clobber_abi("sysv64"),
                options(nostack),
            )
        };
    }

    /// A matrix product on the FMA3 tier.
    ///
    /// # Safety
    /// FMA3 and AVX exist; `matrix` names rows of a live Z grid.
    unsafe fn matrix_fma(double: bool, form: Form, matrix: Matrix, x: &Row, y: &Row, mask: &Row) {
        let (x, y, mask) = (x.as_ptr(), y.as_ptr(), mask.as_ptr());
        // SAFETY: FMA3 exists as the caller guarantees; every row and
        // constant pointer is live, unaligned forms.
        unsafe {
            if double {
                let (nan, zero) = (&raw const NAN_64, &raw const NEGATIVE_ZERO_64);
                match form {
                    Form::Add => vex_matrix!(
                        "pd",
                        "vbroadcastsd",
                        "qword",
                        "8",
                        "vmovapd ymm2, ymm3",
                        "vfmadd231",
                        matrix,
                        x,
                        y,
                        mask,
                        nan,
                        zero
                    ),
                    Form::Subtract => vex_matrix!(
                        "pd",
                        "vbroadcastsd",
                        "qword",
                        "8",
                        "vmovapd ymm2, ymm3",
                        "vfnmadd231",
                        matrix,
                        x,
                        y,
                        mask,
                        nan,
                        zero
                    ),
                    Form::Product => vex_matrix!(
                        "pd",
                        "vbroadcastsd",
                        "qword",
                        "8",
                        "",
                        "vmul",
                        matrix,
                        x,
                        y,
                        mask,
                        nan,
                        zero
                    ),
                    Form::NegatedProduct => vex_matrix!(
                        "pd",
                        "vbroadcastsd",
                        "qword",
                        "8",
                        "vmovapd ymm2, ymm6",
                        "vfnmadd231",
                        matrix,
                        x,
                        y,
                        mask,
                        nan,
                        zero
                    ),
                }
            } else {
                let (nan, zero) = (&raw const NAN_32, &raw const NEGATIVE_ZERO_32);
                match form {
                    Form::Add => vex_matrix!(
                        "ps",
                        "vbroadcastss",
                        "dword",
                        "4",
                        "vmovaps ymm2, ymm3",
                        "vfmadd231",
                        matrix,
                        x,
                        y,
                        mask,
                        nan,
                        zero
                    ),
                    Form::Subtract => vex_matrix!(
                        "ps",
                        "vbroadcastss",
                        "dword",
                        "4",
                        "vmovaps ymm2, ymm3",
                        "vfnmadd231",
                        matrix,
                        x,
                        y,
                        mask,
                        nan,
                        zero
                    ),
                    Form::Product => vex_matrix!(
                        "ps",
                        "vbroadcastss",
                        "dword",
                        "4",
                        "",
                        "vmul",
                        matrix,
                        x,
                        y,
                        mask,
                        nan,
                        zero
                    ),
                    Form::NegatedProduct => vex_matrix!(
                        "ps",
                        "vbroadcastss",
                        "dword",
                        "4",
                        "vmovaps ymm2, ymm6",
                        "vfnmadd231",
                        matrix,
                        x,
                        y,
                        mask,
                        nan,
                        zero
                    ),
                }
            }
        }
    }

    /// An EVEX.512 matrix product: zmm8 = X, k2 = its lanes, zmm6 = -0;
    /// then each enabled Y lane.
    macro_rules! evex_matrix {
        ($s:literal, $broadcast:literal, $size:literal, $step:literal, $init:literal, $op:literal, $m:expr, $x:expr, $y:expr, $opmask:expr, $nan:expr, $zero:expr) => {
            asm!(
                concat!($broadcast, " zmm6, [{zero}]"),
                "vmovups zmm8, zmmword ptr [{x}]",
                "kmovw k2, {opmask:e}",
                "2:",
                "test ecx, 1",
                "jz 3f",
                concat!($broadcast, " zmm1, ", $size, " ptr [rsi]"),
                "vmovups zmm3, zmmword ptr [rdi]",
                $init,
                concat!($op, $s, " zmm2, zmm8, zmm1"),
                concat!("vcmpunord", $s, " k1, zmm2, zmm2"),
                concat!($broadcast, " zmm2 {{k1}}, [{nan}]"),
                concat!("vmovu", $s, " zmmword ptr [rdi] {{k2}}, zmm2"),
                "3:",
                concat!("add rsi, ", $step),
                "add rdi, {stride}",
                "shr ecx, 1",
                "dec rdx",
                "jnz 2b",
                "vzeroupper",
                inout("rsi") $y => _,
                inout("rdi") $m.z => _,
                inout("ecx") $m.rows => _,
                inout("rdx") $m.lanes => _,
                stride = in(reg) $m.stride,
                x = in(reg) $x,
                opmask = in(reg) $opmask,
                nan = in(reg) $nan,
                zero = in(reg) $zero,
                clobber_abi("sysv64"),
                options(nostack),
            )
        };
    }

    /// A matrix product on the AVX-512F tier.
    ///
    /// # Safety
    /// AVX-512F exists with OS-enabled state; `matrix` names rows of a live
    /// Z grid.
    unsafe fn matrix_avx512(
        double: bool,
        form: Form,
        matrix: Matrix,
        x: &Row,
        y: &Row,
        opmask: u32,
    ) {
        let (x, y) = (x.as_ptr(), y.as_ptr());
        // SAFETY: AVX-512F exists as the caller guarantees; every row and
        // constant pointer is live, unaligned forms.
        unsafe {
            if double {
                let (nan, zero) = (&raw const NAN_64, &raw const NEGATIVE_ZERO_64);
                match form {
                    Form::Add => evex_matrix!(
                        "pd",
                        "vbroadcastsd",
                        "qword",
                        "8",
                        "vmovapd zmm2, zmm3",
                        "vfmadd231",
                        matrix,
                        x,
                        y,
                        opmask,
                        nan,
                        zero
                    ),
                    Form::Subtract => evex_matrix!(
                        "pd",
                        "vbroadcastsd",
                        "qword",
                        "8",
                        "vmovapd zmm2, zmm3",
                        "vfnmadd231",
                        matrix,
                        x,
                        y,
                        opmask,
                        nan,
                        zero
                    ),
                    Form::Product => evex_matrix!(
                        "pd",
                        "vbroadcastsd",
                        "qword",
                        "8",
                        "",
                        "vmul",
                        matrix,
                        x,
                        y,
                        opmask,
                        nan,
                        zero
                    ),
                    Form::NegatedProduct => evex_matrix!(
                        "pd",
                        "vbroadcastsd",
                        "qword",
                        "8",
                        "vmovapd zmm2, zmm6",
                        "vfnmadd231",
                        matrix,
                        x,
                        y,
                        opmask,
                        nan,
                        zero
                    ),
                }
            } else {
                let (nan, zero) = (&raw const NAN_32, &raw const NEGATIVE_ZERO_32);
                match form {
                    Form::Add => evex_matrix!(
                        "ps",
                        "vbroadcastss",
                        "dword",
                        "4",
                        "vmovaps zmm2, zmm3",
                        "vfmadd231",
                        matrix,
                        x,
                        y,
                        opmask,
                        nan,
                        zero
                    ),
                    Form::Subtract => evex_matrix!(
                        "ps",
                        "vbroadcastss",
                        "dword",
                        "4",
                        "vmovaps zmm2, zmm3",
                        "vfnmadd231",
                        matrix,
                        x,
                        y,
                        opmask,
                        nan,
                        zero
                    ),
                    Form::Product => evex_matrix!(
                        "ps",
                        "vbroadcastss",
                        "dword",
                        "4",
                        "",
                        "vmul",
                        matrix,
                        x,
                        y,
                        opmask,
                        nan,
                        zero
                    ),
                    Form::NegatedProduct => evex_matrix!(
                        "ps",
                        "vbroadcastss",
                        "dword",
                        "4",
                        "vmovaps zmm2, zmm6",
                        "vfnmadd231",
                        matrix,
                        x,
                        y,
                        opmask,
                        nan,
                        zero
                    ),
                }
            }
        }
    }

    const VECFP_INDEXED_LOAD: u64 = 1 << 53;
    const VECFP_MULTIPLE_ROWS: u64 = 1 << 31;

    /// `vecfp` on f16 lanes, modes 0/1, in the covered forms; see the
    /// module documentation. `false` for any other operand.
    pub(super) fn vector_half(
        generation: Generation,
        registers: &mut AmxRegisters,
        operand: u64,
    ) -> bool {
        // The model ignores bit 37, which would otherwise join the lane field.
        let operand = operand & !(1 << 37);
        let mode = (operand >> 47) & 0x3f;
        let kind = (operand >> 42) & 0xf;
        let bf16_or_wider = matches!(kind, 3 | 4 | 7) || generation.m2_extensions() && kind <= 1;
        if (operand >> 54) & 7 != 0
            || operand & VECFP_INDEXED_LOAD != 0
            || mode > 1
            || bf16_or_wider
            || generation.m2_extensions() && operand & VECFP_MULTIPLE_ROWS != 0
            || (operand >> 27) & 0xf != 0
        {
            return false;
        }
        let field = (operand >> 38) & 7;
        let value = (operand >> 32) & 0x3f;
        if field == 0 && matches!(value, 3..=5) {
            return false;
        }
        let x = registers.x_operand((operand >> 10) & 0x1ff);
        let mut y = registers.y_operand(operand & 0x1ff);
        let enable = if field == 1 {
            // Y lane (bits 36:32) in every lane, every lane on.
            let lane = ((operand >> 32) & 31) as usize;
            let half = [y[2 * lane], y[2 * lane + 1]];
            for pair in y.as_chunks_mut::<2>().0 {
                pair.copy_from_slice(&half);
            }
            u64::MAX
        } else {
            write_mask(operand >> 32, 2, 9)
        };
        let row = &mut registers.z[((operand >> 20) & 63) as usize];
        let mut result = [0u8; ROW_BYTES];
        // SAFETY: the caller checked F16C (with OS-enabled AVX state); every
        // pointer is to a live 64-byte row; MXCSR is restored after.
        unsafe {
            let saved = enter();
            for group in 0..8 {
                fused_half4(
                    x.as_ptr().add(8 * group),
                    y.as_ptr().add(8 * group),
                    row.as_ptr().add(8 * group),
                    result.as_mut_ptr().add(8 * group),
                    mode == 1,
                );
            }
            leave(saved);
        }
        for lane in 0..32 {
            if on(enable, lane, 2) {
                row[2 * lane..2 * lane + 2].copy_from_slice(&result[2 * lane..2 * lane + 2]);
            }
        }
        true
    }

    /// `fma16`/`fms16` (`fma.c`) in the fused form (bits 29:27 clear): the
    /// vector shape and the f16 matrix row by row through [`fused_half4`],
    /// the bit-62 matrix into interleaved f32 row pairs through
    /// [`widened_rows`]. Every lane's f16 product is exact in f32.
    pub(super) fn fused_half(
        registers: &mut AmxRegisters,
        operation: AmxOperation,
        operand: u64,
    ) -> bool {
        let subtract = operation == AmxOperation::Fms16;
        if (operand >> 27) & 7 != 0 {
            return false;
        }
        let x = registers.x_operand((operand >> 10) & 0x1ff);
        let y = registers.y_operand(operand & 0x1ff);
        let x_enable = write_mask(operand >> 41, 2, 7);
        let y_enable = write_mask(operand >> 32, 2, 7);
        let z_row = ((operand >> 20) & 63) as usize;
        // SAFETY: the caller checked F16C (with OS-enabled AVX state); every
        // pointer is to a live row; MXCSR is restored after.
        unsafe {
            let saved = enter();
            if operand & VECTOR != 0 {
                half_row(&mut registers.z[z_row], &x, &y, x_enable, subtract);
            } else if operand & super::WIDEN_16_32 == 0 {
                for j in (0..32).filter(|&j| on(y_enable, j, 2)) {
                    let mut lane = [0u8; ROW_BYTES];
                    for pair in lane.as_chunks_mut::<2>().0 {
                        pair.copy_from_slice(&y[2 * j..2 * j + 2]);
                    }
                    let row = j * 2 + (z_row & 1);
                    half_row(&mut registers.z[row], &x, &lane, x_enable, subtract);
                }
            } else {
                widened_rows(registers, &x, &y, x_enable, y_enable, subtract);
            }
            leave(saved);
        }
        true
    }

    /// One f16 row: `z ± x*y` lane by lane where `enable` (per byte) is on.
    ///
    /// # Safety
    /// F16C and AVX exist; MXCSR holds the AMX environment.
    unsafe fn half_row(z: &mut Row, x: &Row, y: &Row, enable: u64, subtract: bool) {
        let mut result = [0u8; ROW_BYTES];
        for group in 0..8 {
            // SAFETY: 8-byte groups of live rows; the caller's contract.
            unsafe {
                fused_half4(
                    x.as_ptr().add(8 * group),
                    y.as_ptr().add(8 * group),
                    z.as_ptr().add(8 * group),
                    result.as_mut_ptr().add(8 * group),
                    subtract,
                );
            }
        }
        for lane in (0..32).filter(|&lane| on(enable, lane, 2)) {
            z[2 * lane..2 * lane + 2].copy_from_slice(&result[2 * lane..2 * lane + 2]);
        }
    }

    /// The bit-62 matrix: X lane i times Y lane j, widened to f32, into f32
    /// lane i/2 of Z row 2j + i%2. The product is exact in f32, so the
    /// fused result is one rounded f32 addition (or subtraction).
    ///
    /// # Safety
    /// F16C and AVX exist; MXCSR holds the AMX environment.
    unsafe fn widened_rows(
        registers: &mut AmxRegisters,
        x: &Row,
        y: &Row,
        x_enable: u64,
        y_enable: u64,
        subtract: bool,
    ) {
        // The even and the odd X lanes, each sixteen f16 in order.
        let mut halves = [[0u8; 32]; 2];
        for lane in 0..32 {
            halves[lane & 1][(lane >> 1) * 2..(lane >> 1) * 2 + 2]
                .copy_from_slice(&x[2 * lane..2 * lane + 2]);
        }
        let mut widened = [[0u8; ROW_BYTES]; 2];
        // All 32 Y lanes widened: 128 bytes.
        let mut y_wide = [0u8; 2 * ROW_BYTES];
        // SAFETY: F16C; 32-byte X halves into 64 bytes, 64 Y bytes into 128.
        unsafe {
            for (half, wide) in halves.iter().zip(widened.iter_mut()) {
                asm!(
                    "vcvtph2ps ymm0, xmmword ptr [{h}]",
                    "vcvtph2ps ymm1, xmmword ptr [{h} + 16]",
                    "vmovups ymmword ptr [{w}], ymm0",
                    "vmovups ymmword ptr [{w} + 32], ymm1",
                    "vzeroupper",
                    h = in(reg) half.as_ptr(),
                    w = in(reg) wide.as_mut_ptr(),
                    clobber_abi("sysv64"),
                    options(nostack),
                );
            }
            asm!(
                "vcvtph2ps ymm0, xmmword ptr [{h}]",
                "vcvtph2ps ymm1, xmmword ptr [{h} + 16]",
                "vcvtph2ps ymm2, xmmword ptr [{h} + 32]",
                "vcvtph2ps ymm3, xmmword ptr [{h} + 48]",
                "vmovups ymmword ptr [{w}], ymm0",
                "vmovups ymmword ptr [{w} + 32], ymm1",
                "vmovups ymmword ptr [{w} + 64], ymm2",
                "vmovups ymmword ptr [{w} + 96], ymm3",
                "vzeroupper",
                h = in(reg) y.as_ptr(),
                w = in(reg) y_wide.as_mut_ptr(),
                clobber_abi("sysv64"),
                options(nostack),
            );
        }
        // Per-lane all-ones masks of each parity's enabled X lanes.
        let mut masks = [[0u8; ROW_BYTES]; 2];
        for lane in (0..32).filter(|&lane| on(x_enable, lane, 2)) {
            masks[lane & 1][(lane >> 1) * 4..(lane >> 1) * 4 + 4].fill(0xff);
        }
        for j in (0..32).filter(|&j| on(y_enable, j, 2)) {
            for parity in 0..2 {
                let z = registers.z[2 * j + parity].as_mut_ptr();
                // SAFETY: live 64-byte rows; AVX; the caller's MXCSR.
                unsafe {
                    asm!(
                        "vbroadcastss xmm1, dword ptr [{y}]",
                        "vbroadcastss xmm7, dword ptr [{nan}]",
                        "xor eax, eax",
                        "2:",
                        "vmulps xmm0, xmm1, xmmword ptr [{x} + rax]",
                        "vmovups xmm2, xmmword ptr [{z} + rax]",
                        "test {subtract:e}, {subtract:e}",
                        "jz 3f",
                        "vsubps xmm3, xmm2, xmm0",
                        "jmp 4f",
                        "3:",
                        "vaddps xmm3, xmm2, xmm0",
                        "4:",
                        // NaN sums become the default NaN.
                        "vcmpps xmm4, xmm3, xmm3, 3",
                        "vblendvps xmm3, xmm3, xmm7, xmm4",
                        // Disabled lanes keep Z.
                        "vmovups xmm5, xmmword ptr [{m} + rax]",
                        "vblendvps xmm3, xmm2, xmm3, xmm5",
                        "vmovups xmmword ptr [{z} + rax], xmm3",
                        "add eax, 16",
                        "cmp eax, 64",
                        "jb 2b",
                        y = in(reg) y_wide.as_ptr().add(4 * j),
                        x = in(reg) widened[parity].as_ptr(),
                        z = in(reg) z,
                        m = in(reg) masks[parity].as_ptr(),
                        nan = in(reg) &raw const NAN_32,
                        subtract = in(reg) u32::from(subtract),
                        out("rax") _,
                        clobber_abi("sysv64"),
                        options(nostack),
                    );
                }
            }
        }
    }

    /// Four f16 lanes (8 bytes each at `x`, `y`, `z`) of `z ± x*y`, rounded
    /// once, to `out`: the f32 product is exact, the f32 sum is rounded to
    /// odd from its TwoSum error, then converted to f16 to nearest even.
    ///
    /// # Safety
    /// F16C and AVX exist; every pointer has 8 live bytes.
    unsafe fn fused_half4(x: *const u8, y: *const u8, z: *const u8, out: *mut u8, subtract: bool) {
        // SAFETY: as above.
        unsafe {
            asm!(
                "vcvtph2ps xmm0, qword ptr [{x}]",
                "vcvtph2ps xmm1, qword ptr [{y}]",
                "vcvtph2ps xmm2, qword ptr [{z}]",
                // p = x*y, exact; negated for z - x*y.
                "vmulps xmm3, xmm0, xmm1",
                "vpcmpeqd xmm10, xmm10, xmm10",
                "vpslld xmm11, xmm10, 31",
                "vpsrld xmm10, xmm10, 31",
                "test {subtract:e}, {subtract:e}",
                "jz 2f",
                "vxorps xmm3, xmm3, xmm11",
                "2:",
                // s = p + z and its TwoSum error e.
                "vaddps xmm4, xmm3, xmm2",
                "vsubps xmm5, xmm4, xmm3",
                "vsubps xmm6, xmm4, xmm5",
                "vsubps xmm6, xmm3, xmm6",
                "vsubps xmm7, xmm2, xmm5",
                "vaddps xmm6, xmm6, xmm7",
                // Inexact (ordered, nonzero e) and even: step toward s + e.
                "vxorps xmm7, xmm7, xmm7",
                "vcmpps xmm7, xmm6, xmm7, 12",
                "vpand xmm8, xmm4, xmm10",
                "vpxor xmm9, xmm9, xmm9",
                "vpcmpeqd xmm8, xmm8, xmm9",
                "vpand xmm7, xmm7, xmm8",
                "vpxor xmm9, xmm4, xmm6",
                "vpsrad xmm9, xmm9, 31",
                "vpor xmm9, xmm9, xmm10",
                "vpand xmm9, xmm9, xmm7",
                "vpaddd xmm4, xmm4, xmm9",
                // NaN sums become the default NaN.
                "vcmpps xmm7, xmm4, xmm4, 3",
                "vbroadcastss xmm8, dword ptr [{nan}]",
                "vblendvps xmm4, xmm4, xmm8, xmm7",
                "vcvtps2ph qword ptr [{out}], xmm4, 0",
                x = in(reg) x,
                y = in(reg) y,
                z = in(reg) z,
                out = in(reg) out,
                nan = in(reg) &raw const NAN_32,
                subtract = in(reg) u32::from(subtract),
                clobber_abi("sysv64"),
                options(nostack),
            );
        }
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;
    use crate::amx::{
        Generation,
        model::{self, AmxMemory, MemoryFault},
    };

    struct NoMemory;
    impl AmxMemory for NoMemory {
        fn read(&mut self, _: u64, _: &mut [u8]) -> Result<(), MemoryFault> {
            panic!("arithmetic must not read guest memory")
        }
        fn write(&mut self, _: u64, _: &[u8]) -> Result<(), MemoryFault> {
            panic!("arithmetic must not write guest memory")
        }
    }

    struct Random(u64);
    impl Random {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    /// Special f16 values in the low half of each 32-bit lane, and
    /// special f32 and f64 values, between random bits.
    fn fill(random: &mut Random) -> AmxRegisters {
        const SINGLES: [u32; 12] = [
            0,
            0x8000_0000,
            0x7f80_0000,
            0xff80_0000,
            0x7fc0_0000,
            0x7f80_0001,
            0x0000_0001,
            0x807f_ffff,
            0x3f80_0000,
            0x7f7f_ffff,
            0x0080_0000,
            0xffc1_2345,
        ];
        const DOUBLES: [u64; 10] = [
            0,
            1 << 63,
            0x7ff0_0000_0000_0000,
            0xfff0_0000_0000_0000,
            0x7ff8_0000_0000_0000,
            0x7ff0_0000_0000_0001,
            1,
            0x3ff0_0000_0000_0000,
            0x7fef_ffff_ffff_ffff,
            0x0010_0000_0000_0000,
        ];
        const HALVES: [u16; 9] = [
            0, 0x8000, 0x7c00, 0xfc00, 0x7c01, 0x7e00, 0x0001, 0x3c00, 0x7bff,
        ];
        let mut registers = AmxRegisters::zeroed();
        for lane in registers.as_bytes_mut().as_chunks_mut::<8>().0 {
            let value = random.next();
            *lane = match value % 8 {
                0 => {
                    let low = SINGLES[(value >> 8) as usize % SINGLES.len()];
                    let high = SINGLES[(value >> 16) as usize % SINGLES.len()];
                    u64::from(low) | u64::from(high) << 32
                }
                1 => DOUBLES[(value >> 8) as usize % DOUBLES.len()],
                2 => {
                    let half =
                        |shift: u32| u64::from(HALVES[(value >> shift) as usize % HALVES.len()]);
                    half(8) | half(16) << 32 | (value & 0xffff_0000_ffff_0000)
                }
                // Small exponents make cancellation, denormal and
                // tie results likely.
                3 => value & 0x83ff_ffff_83ff_ffff | 0x3c00_0000_3c00_0000,
                _ => random.next(),
            }
            .to_le_bytes();
        }
        registers
    }

    /// Operands over every field the fused operations read, with mode 0/1
    /// favoured and the lane-enable fields often all-on.
    fn operand(random: &mut Random) -> u64 {
        let mut operand = random.next();
        let choice = random.next();
        operand &= !(7 << 27);
        operand |= match choice % 8 {
            0..=3 => 0,
            4 | 5 => 1,
            mode => mode << 27,
        };
        if choice & 0x30 != 0 {
            operand &= !(0x7f << 41);
        }
        if choice & 0xc0 != 0 {
            operand &= !(0x7f << 32);
        }
        operand
    }

    /// Every tier and F16C choice this host can run, the reduced ones
    /// included: a lower tier's instructions all exist on a higher host.
    fn tiers() -> alloc::vec::Vec<Native> {
        let host = TargetCpu::detect();
        let f16c = host.supports(TargetCpu::F16c);
        let mut tiers = alloc::vec::Vec::new();
        for (tier, required) in [
            (Tier::Model, TargetCpu::Baseline),
            (Tier::Fma, TargetCpu::Fma),
            (Tier::Avx512, TargetCpu::Avx512f),
        ] {
            if host.supports(required) {
                tiers.push(Native { tier, f16c: false });
                if f16c {
                    tiers.push(Native { tier, f16c: true });
                }
            } else {
                std::eprintln!("AMX native tier {} skipped: host lacks it", tier.name());
            }
        }
        if !f16c {
            std::eprintln!("AMX native F16C paths skipped: host lacks F16C");
        }
        tiers
    }

    #[test]
    fn every_native_tier_matches_the_model_bit_for_bit() {
        let mut random = Random(0x9e37_79b9_7f4a_7c15);
        for native in tiers() {
            let mut covered = 0;
            for operation in [
                AmxOperation::Fma32,
                AmxOperation::Fms32,
                AmxOperation::Fma64,
                AmxOperation::Fms64,
            ] {
                for _ in 0..4000 {
                    let initial = fill(&mut random);
                    let operand = operand(&mut random);
                    let mut expected = initial.clone();
                    model::execute_for(
                        Generation::M2,
                        &mut expected,
                        operation,
                        operand,
                        &mut NoMemory,
                    )
                    .unwrap();
                    let mut actual = initial.clone();
                    if native.execute(Generation::M2, &mut actual, operation, operand) {
                        covered += 1;
                        assert!(
                            actual == expected,
                            "{native:?} {operation:?} operand {operand:#018x}"
                        );
                    } else {
                        assert!(actual == initial, "refused paths change nothing");
                        let mode = (operand >> 27) & 7;
                        let widened =
                            matches!(operation, AmxOperation::Fma32 | AmxOperation::Fms32)
                                && operand & (X_HALF | Y_HALF) != 0;
                        assert!(
                            native.tier == Tier::Model
                                || mode > 1
                                || widened && native.tier == Tier::Fma && !native.f16c,
                            "{operand:#x}"
                        );
                    }
                }
            }
            // Without F16C the VEX tier leaves f16-widening fma32 forms out.
            if native.tier != Tier::Model {
                assert!(covered > 5000, "{native:?} covered {covered}");
            }
        }
    }

    /// `vecfp` operands over the covered f16 forms, with some outside them.
    fn vector_operand(random: &mut Random) -> u64 {
        let mut operand = random.next();
        let choice = random.next();
        // Mostly no 54..56, no indexed load, no shuffle, mode 0 or 1.
        if choice & 7 != 0 {
            operand &= !(7 << 54 | 1 << 53 | 0xf << 27 | 0x3f << 47);
            operand |= (choice >> 3 & 1) << 47;
        }
        // Mostly f16 types (2, 5, 6, 8..15; 0/1 are f16 only on M1).
        if choice & 0x30 != 0 {
            operand &= !(0xf << 42);
            operand |= [2u64, 5, 6, 8, 9, 15, 0, 1][(choice >> 6) as usize & 7] << 42;
        }
        if choice & 0x300 != 0 {
            operand &= !(1 << 31);
        }
        // Broadcast Y lane often.
        if choice & 0xc00 != 0 {
            operand &= !(7 << 38);
            operand |= 1 << 38;
        }
        operand
    }

    #[test]
    fn vecfp_half_matches_the_model_bit_for_bit() {
        let mut random = Random(0x3c6e_f372_fe94_f82b);
        for native in tiers().into_iter().filter(|native| native.f16c) {
            for generation in [Generation::M1, Generation::M2, Generation::M4] {
                let mut covered = 0;
                for _ in 0..20000 {
                    let initial = fill(&mut random);
                    let operand = vector_operand(&mut random);
                    let mut expected = initial.clone();
                    model::execute_for(
                        generation,
                        &mut expected,
                        AmxOperation::VectorFloat,
                        operand,
                        &mut NoMemory,
                    )
                    .unwrap();
                    let mut actual = initial.clone();
                    if native.execute(generation, &mut actual, AmxOperation::VectorFloat, operand) {
                        covered += 1;
                        assert!(
                            actual == expected,
                            "{native:?} {generation:?} vecfp operand {operand:#018x}"
                        );
                    } else {
                        assert!(actual == initial, "refused paths change nothing");
                    }
                }
                assert!(covered > 2000, "{generation:?} covered {covered}");
            }
        }
    }

    /// Exhaustive-style f16 corner cases: every special pairing and values
    /// whose exact sums fall on, near and between f16 rounding points.
    /// fma16/fms16 in vector, f16 matrix and f32-widening matrix shapes,
    /// with all lanes on or random enables, bit for bit against the model.
    #[test]
    fn fma16_matches_the_model_bit_for_bit() {
        let mut random = Random(0x6a09_e667_f3bc_c908);
        for native in tiers().into_iter().filter(|native| native.f16c) {
            let mut covered = [0usize; 3];
            for operation in [AmxOperation::Fma16, AmxOperation::Fms16] {
                for _ in 0..3000 {
                    let initial = fill(&mut random);
                    let mut operand = operand(&mut random);
                    if !random.next().is_multiple_of(4) {
                        operand &= !(7 << 27);
                    }
                    let mut expected = initial.clone();
                    model::execute_for(
                        Generation::M2,
                        &mut expected,
                        operation,
                        operand,
                        &mut NoMemory,
                    )
                    .unwrap();
                    let mut actual = initial.clone();
                    if native.execute(Generation::M2, &mut actual, operation, operand) {
                        covered[if operand & VECTOR != 0 {
                            0
                        } else if operand & WIDEN_16_32 != 0 {
                            2
                        } else {
                            1
                        }] += 1;
                        assert!(
                            actual == expected,
                            "{native:?} {operation:?} operand {operand:#018x}"
                        );
                    } else {
                        assert!(actual == initial, "refused paths change nothing");
                        assert_ne!((operand >> 27) & 7, 0, "{operand:#x}");
                    }
                }
            }
            assert!(covered.iter().all(|&count| count > 500), "{covered:?}");
        }
    }

    #[test]
    fn vecfp_half_rounds_once_at_ties_and_extremes() {
        const HALVES: [u16; 24] = [
            0x0000, 0x8000, 0x0001, 0x8001, 0x03ff, 0x0400, 0x3c00, 0xbc00, 0x3c01, 0x3bff, 0x7bff,
            0xfbff, 0x7c00, 0xfc00, 0x7e00, 0x7c01, 0x1400, 0x1001, 0x5bff, 0x2400, 0x0200, 0x6800,
            0xe800, 0x0c00,
        ];
        for native in tiers().into_iter().filter(|native| native.f16c) {
            let mut registers = AmxRegisters::zeroed();
            for (index, &x) in HALVES.iter().enumerate() {
                for lane in 0..32 {
                    let y = HALVES[lane % HALVES.len()];
                    let z = HALVES[(lane * 7 + index) % HALVES.len()];
                    registers.x[0][2 * lane..2 * lane + 2].copy_from_slice(&x.to_le_bytes());
                    registers.y[0][2 * lane..2 * lane + 2].copy_from_slice(&y.to_le_bytes());
                    registers.z[3][2 * lane..2 * lane + 2].copy_from_slice(&z.to_le_bytes());
                }
                for mode in [0u64, 1] {
                    let operand = 2 << 42 | mode << 47 | 3 << 20;
                    let mut expected = registers.clone();
                    model::execute_for(
                        Generation::M2,
                        &mut expected,
                        AmxOperation::VectorFloat,
                        operand,
                        &mut NoMemory,
                    )
                    .unwrap();
                    let mut actual = registers.clone();
                    assert!(native.execute(
                        Generation::M2,
                        &mut actual,
                        AmxOperation::VectorFloat,
                        operand
                    ));
                    assert!(actual == expected, "x {x:#06x} mode {mode}");
                }
            }
        }
    }

    /// Cost per operation of the model and of each native tier on this
    /// host, for the hot BNNS forms (matrix fma32 with Y f16 widening,
    /// vector fma32, f16 vecfp with a broadcast Y lane):
    /// `cargo test -p stela-compiler --release amx::native -- --ignored --nocapture`.
    #[test]
    #[ignore = "manual: opt-in"]
    fn native_and_model_costs() {
        let mut random = Random(0x1234_5678_9abc_def1);
        let initial = fill(&mut random);
        let cases = [
            ("fma32 matrix f16-Y", AmxOperation::Fma32, Y_HALF | 1 << 20),
            ("fma32 vector", AmxOperation::Fma32, VECTOR | 5 << 20),
            ("fma64 matrix", AmxOperation::Fma64, 0),
            (
                "vecfp f16 broadcast",
                AmxOperation::VectorFloat,
                2 << 42 | 1 << 38 | 3 << 32 | 8 << 20,
            ),
        ];
        let rounds = 20_000u32;
        for (name, operation, operand) in cases {
            let mut registers = initial.clone();
            let start = std::time::Instant::now();
            for _ in 0..rounds {
                model::execute_for(
                    Generation::M2,
                    &mut registers,
                    operation,
                    operand,
                    &mut NoMemory,
                )
                .unwrap();
            }
            let model_ns = start.elapsed().as_nanos() / u128::from(rounds);
            std::eprint!("{name}: model {model_ns} ns");
            for native in tiers()
                .into_iter()
                .filter(|native| native.tier != Tier::Model && native.f16c)
            {
                let mut registers = initial.clone();
                let start = std::time::Instant::now();
                for _ in 0..rounds {
                    assert!(native.execute(Generation::M2, &mut registers, operation, operand));
                }
                let ns = start.elapsed().as_nanos() / u128::from(rounds);
                std::eprint!(", {} {ns} ns", native.tier.name());
            }
            std::eprintln!();
        }
    }

    #[test]
    fn the_model_tier_and_other_operations_are_left_to_the_model() {
        let mut registers = AmxRegisters::zeroed();
        assert_eq!(Native::select(TargetCpu::Sse42), Native::MODEL);
        assert!(!Native::MODEL.execute(Generation::M2, &mut registers, AmxOperation::Fma32, 0));
        for native in tiers() {
            for operation in [AmxOperation::Mac16, AmxOperation::LoadX] {
                assert!(!native.execute(Generation::M2, &mut registers, operation, 0));
            }
            // fma16 needs F16C; its other modes stay with the model.
            assert_eq!(
                native.execute(Generation::M2, &mut registers, AmxOperation::Fma16, 0),
                native.f16c
            );
            assert!(!native.execute(Generation::M2, &mut registers, AmxOperation::Fma16, 1 << 27));
        }
        assert_eq!(
            Native::select(TargetCpu::Sse42.with_fma().with_f16c()).tier(),
            Tier::Fma
        );
    }
}
