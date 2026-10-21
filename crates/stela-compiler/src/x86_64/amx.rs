//! Native x86 kernels for the hottest AMX forms in 26A434 Accelerate: `fma32`,
//! `fms32`, `fma64` and `fms64` with every X/Y lane enabled, in matrix or
//! vector shape, accumulating (`z ± x*y`) or product-only (bit 27).
//!
//! Exact fused results need FMA3 or AVX-512F. The kernels run under MXCSR
//! 0x1F80 (nearest even, no DAZ/FTZ, exceptions masked) and restore the
//! caller's MXCSR, so host status flags never escape. x86 and Arm agree on
//! every non-NaN fused, product and sign result in that mode; NaN results are
//! replaced by the Arm default NaN, matching the AMX environment of
//! [`crate::amx::model`]. Every other form, and every baseline host, uses the
//! model.
//!
//! ABI: `extern "sysv64" fn(z: *mut u8, x: *const u8, y: *const u8, row: u64)`
//! where `z` is the 4 KiB Z grid, `x`/`y` are the 64-byte operands after the
//! circular-pool wrap, and `row` is operand bits 25:20. The kernel writes only
//! the Z rows its shape selects.
mod encoding;

use crate::{TargetCpu, amx::AmxOperation};
use alloc::vec::Vec;
use encoding::{Gpr, Map, Operand, Prefix, at, evex, legacy_memory, vex};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Precision {
    Single,
    Double,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Shape {
    /// `z[j*g + row%g][i] ±= x[i]*y[j]` with g = 64/lanes: sixteen f32 rows
    /// or eight f64 rows.
    Matrix,
    /// `z[row][i] ±= x[i]*y[i]`.
    Vector,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Kernel {
    pub precision: Precision,
    pub shape: Shape,
    /// `fms`: `z - x*y`, or `-(x*y)` when product-only.
    pub subtract: bool,
    /// Bit 27: the Z input is skipped.
    pub product_only: bool,
}

impl Kernel {
    pub const ALL: [Self; 16] = {
        let mut all = [Self {
            precision: Precision::Single,
            shape: Shape::Matrix,
            subtract: false,
            product_only: false,
        }; 16];
        let mut index = 0;
        while index < 16 {
            all[index] = Self {
                precision: if index & 8 == 0 {
                    Precision::Single
                } else {
                    Precision::Double
                },
                shape: if index & 4 == 0 {
                    Shape::Matrix
                } else {
                    Shape::Vector
                },
                subtract: index & 2 != 0,
                product_only: index & 1 != 0,
            };
            index += 1;
        }
        all
    };

    /// The AMX operation this kernel computes.
    pub const fn operation(self) -> AmxOperation {
        match (self.precision, self.subtract) {
            (Precision::Single, false) => AmxOperation::Fma32,
            (Precision::Single, true) => AmxOperation::Fms32,
            (Precision::Double, false) => AmxOperation::Fma64,
            (Precision::Double, true) => AmxOperation::Fms64,
        }
    }

    const fn element_bytes(self) -> i32 {
        match self.precision {
            Precision::Single => 4,
            Precision::Double => 8,
        }
    }

    const fn lanes(self) -> i32 {
        64 / self.element_bytes()
    }

    fn index(self) -> usize {
        Self::ALL
            .iter()
            .position(|kernel| *kernel == self)
            .expect("every kernel is enumerated")
    }
}

/// A seven-bit lane-enable field that enables every lane: mode 0 with value
/// 0, or mode 2/3 with value 0 (corsix `parse_writemask`).
const fn all_lanes(field: u64) -> bool {
    let value = field & 0x1f;
    let mode = (field >> 5) & 3;
    value == 0 && mode != 1
}

/// The native kernel that computes this operation exactly, if any. Bits the
/// selected shape ignores stay ignored.
pub fn select(operation: AmxOperation, operand: u64) -> Option<Kernel> {
    let (precision, subtract) = match operation {
        AmxOperation::Fma32 => (Precision::Single, false),
        AmxOperation::Fms32 => (Precision::Single, true),
        AmxOperation::Fma64 => (Precision::Double, false),
        AmxOperation::Fms64 => (Precision::Double, true),
        _ => return None,
    };
    let product_only = match (operand >> 27) & 7 {
        0 => false,
        1 => true,
        _ => return None,
    };
    // fma32 bits 61/60 widen even f16 lanes; fma64 ignores them.
    if precision == Precision::Single && (operand >> 60) & 3 != 0 {
        return None;
    }
    let shape = if operand >> 63 != 0 {
        Shape::Vector
    } else {
        Shape::Matrix
    };
    if !all_lanes(operand >> 41) || shape == Shape::Matrix && !all_lanes(operand >> 32) {
        return None;
    }
    Some(Kernel {
        precision,
        shape,
        subtract,
        product_only,
    })
}

/// Host instruction tiers for the kernels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tier {
    /// VEX.256 with FMA3: two YMM halves per 64-byte row.
    Fma,
    /// EVEX.512: one ZMM per row, embedded broadcasts and opmask NaN fixes.
    Avx512,
}

impl Tier {
    pub const fn requires(self) -> TargetCpu {
        match self {
            Self::Fma => TargetCpu::Fma,
            Self::Avx512 => TargetCpu::Avx512f,
        }
    }

    /// The preferred tier the target supports; `None` leaves the model.
    pub fn for_target(target: TargetCpu) -> Option<Self> {
        [Self::Avx512, Self::Fma]
            .into_iter()
            .find(|tier| target.supports(tier.requires()))
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Fma => "fma",
            Self::Avx512 => "avx512f",
        }
    }
}

/// Every kernel of one tier in one image, each starting on a 64-byte boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Library {
    pub tier: Tier,
    pub code: Vec<u8>,
    offsets: [usize; 16],
}

impl Library {
    pub fn new(tier: Tier) -> Self {
        let mut code = Vec::new();
        let mut offsets = [0; 16];
        for (kernel, offset) in Kernel::ALL.into_iter().zip(&mut offsets) {
            code.resize(code.len().next_multiple_of(64), INT3);
            *offset = code.len();
            code.extend(emit(kernel, tier));
        }
        Self {
            tier,
            code,
            offsets,
        }
    }

    pub fn offset(&self, kernel: Kernel) -> usize {
        self.offsets[kernel.index()]
    }

    /// Bytes of one kernel, without alignment padding.
    pub fn kernel_bytes(&self, kernel: Kernel) -> usize {
        emit(kernel, self.tier).len()
    }
}

const INT3: u8 = 0xcc;
const MXCSR_ARM_ENVIRONMENT: u32 = 0x1f80;
const SINGLE_DEFAULT_NAN: u32 = 0x7fc0_0000;
const DOUBLE_DEFAULT_NAN: u64 = 0x7ff8_0000_0000_0000;
const CMP_UNORDERED: u8 = 3;
/// Register roles: X in 0 (and 1 for the YMM half), Y broadcast in 2, Z
/// halves in 3 and 4, the unordered mask in 5, the sign in 6 and the default
/// NaN in 7. EVEX rows rotate through ZMM16..19, so consecutive rows do not
/// wait on each other and no VEX-visible register holds a row.
const X: u8 = 0;
const Y: u8 = 2;
const Z_FIRST: u8 = 3;
const EVEX_Z_FIRST: u8 = 16;
const EVEX_Z_ROTATION: u8 = 4;
const UNORDERED: u8 = 5;
const SIGN: u8 = 6;
const DEFAULT_NAN: u8 = 7;
const OPMASK: u8 = 1;

/// Emit one kernel for one tier.
pub fn emit(kernel: Kernel, tier: Tier) -> Vec<u8> {
    let mut code = Vec::new();
    prologue(&mut code, kernel, tier);
    let rows = match kernel.shape {
        Shape::Matrix => kernel.lanes(),
        Shape::Vector => 1,
    };
    // A matrix touches one row from each group of 64/lanes rows.
    let stride = match (kernel.shape, kernel.precision) {
        (Shape::Matrix, Precision::Single) => 4 * 64,
        (Shape::Matrix, Precision::Double) => 8 * 64,
        (Shape::Vector, _) => 0,
    };
    for row in 0..rows {
        let offset = row * stride;
        match tier {
            Tier::Fma => vex_row(&mut code, kernel, row, offset),
            Tier::Avx512 => {
                let accumulator = EVEX_Z_FIRST + (row as u8 % EVEX_Z_ROTATION);
                evex_row(&mut code, kernel, row, offset, accumulator);
            }
        }
    }
    epilogue(&mut code);
    code
}

fn prologue(code: &mut Vec<u8>, kernel: Kernel, tier: Tier) {
    // sub rsp, 16: [rsp+4] caller MXCSR, [rsp] AMX MXCSR, [rsp+8] constants.
    code.extend([0x48, 0x83, 0xec, 0x10]);
    legacy_memory(code, &[0x0f, 0xae], 3, at(Gpr::Rsp, 4));
    code.extend([0xc7, 0x04, 0x24]);
    code.extend(MXCSR_ARM_ENVIRONMENT.to_le_bytes());
    legacy_memory(code, &[0x0f, 0xae], 2, at(Gpr::Rsp, 0));
    let double = kernel.precision == Precision::Double;
    let sign = if double { 1u64 << 63 } else { 1 << 31 };
    let constant = |code: &mut Vec<u8>, value: u64, register: u8| {
        // mov rax, imm64
        code.extend([0x48, 0xb8]);
        code.extend(value.to_le_bytes());
        match tier {
            Tier::Fma => {
                // mov [rsp+8], rax; vbroadcastss/sd ymm, [rsp+8]
                code.extend([0x48, 0x89, 0x44, 0x24, 0x08]);
                let opcode = if double { 0x19 } else { 0x18 };
                vex(
                    code,
                    Map::Escape38,
                    Prefix::OperandSize,
                    false,
                    true,
                    opcode,
                    register,
                    0,
                    Operand::Memory(at(Gpr::Rsp, 8)),
                );
            }
            // vpbroadcastd/q zmm, eax/rax
            Tier::Avx512 => evex(
                code,
                Map::Escape38,
                Prefix::OperandSize,
                double,
                0x7c,
                register,
                0,
                Operand::Register(Gpr::Rax as u8),
                false,
                0,
            ),
        }
    };
    constant(
        code,
        if double {
            DOUBLE_DEFAULT_NAN
        } else {
            u64::from(SINGLE_DEFAULT_NAN)
        },
        DEFAULT_NAN,
    );
    if kernel.subtract && kernel.product_only {
        constant(code, sign, SIGN);
    }
    // Select the Z row group: rdi += (row & (rows per group - 1)) * 64.
    let group_mask = match (kernel.shape, kernel.precision) {
        (Shape::Matrix, Precision::Single) => 3,
        (Shape::Matrix, Precision::Double) => 7,
        (Shape::Vector, _) => 63,
    };
    code.extend([0x83, 0xe1, group_mask]); // and ecx, mask
    code.extend([0xc1, 0xe1, 0x06]); // shl ecx, 6
    code.extend([0x48, 0x01, 0xcf]); // add rdi, rcx
    match tier {
        Tier::Fma => {
            for half in 0..2u8 {
                vmovups_load(code, X + half, at(Gpr::Rsi, i32::from(half) * 32));
            }
        }
        Tier::Avx512 => evex(
            code,
            Map::Primary,
            Prefix::None,
            false,
            0x10,
            X,
            0,
            Operand::Memory(at(Gpr::Rsi, 0)),
            false,
            0,
        ),
    }
}

fn epilogue(code: &mut Vec<u8>) {
    code.extend([0xc5, 0xf8, 0x77]); // vzeroupper
    legacy_memory(code, &[0x0f, 0xae], 2, at(Gpr::Rsp, 4));
    code.extend([0x48, 0x83, 0xc4, 0x10, 0xc3]); // add rsp, 16; ret
}

fn vmovups_load(code: &mut Vec<u8>, register: u8, memory: encoding::Memory) {
    vex(
        code,
        Map::Primary,
        Prefix::None,
        false,
        true,
        0x10,
        register,
        0,
        Operand::Memory(memory),
    );
}

fn vmovups_store(code: &mut Vec<u8>, register: u8, memory: encoding::Memory) {
    vex(
        code,
        Map::Primary,
        Prefix::None,
        false,
        true,
        0x11,
        register,
        0,
        Operand::Memory(memory),
    );
}

/// The packed-arithmetic prefix and W bit for the precision.
fn packed(kernel: Kernel) -> (Prefix, bool) {
    match kernel.precision {
        Precision::Single => (Prefix::None, false),
        Precision::Double => (Prefix::OperandSize, true),
    }
}

fn vex_row(code: &mut Vec<u8>, kernel: Kernel, row: i32, offset: i32) {
    let double = kernel.precision == Precision::Double;
    let (prefix, wide) = packed(kernel);
    match kernel.shape {
        Shape::Matrix => vex(
            code,
            Map::Escape38,
            Prefix::OperandSize,
            false,
            true,
            if double { 0x19 } else { 0x18 },
            Y,
            0,
            Operand::Memory(at(Gpr::Rdx, row * kernel.element_bytes())),
        ),
        Shape::Vector => {}
    }
    for half in 0..2u8 {
        let z = Z_FIRST + half;
        let memory = at(Gpr::Rdi, offset + i32::from(half) * 32);
        let y = match kernel.shape {
            Shape::Matrix => Y,
            Shape::Vector => {
                vmovups_load(code, Y, at(Gpr::Rdx, i32::from(half) * 32));
                Y
            }
        };
        if kernel.product_only {
            // vmulps/pd z, x, y
            vex(
                code,
                Map::Primary,
                prefix,
                false,
                true,
                0x59,
                z,
                X + half,
                Operand::Register(y),
            );
            if kernel.subtract {
                // vxorps/pd z, z, sign
                vex(
                    code,
                    Map::Primary,
                    prefix,
                    false,
                    true,
                    0x57,
                    z,
                    z,
                    Operand::Register(SIGN),
                );
            }
        } else {
            vmovups_load(code, z, memory);
            // vfmadd231 / vfnmadd231: z = ±(x*y) + z
            let opcode = if kernel.subtract { 0xbc } else { 0xb8 };
            vex(
                code,
                Map::Escape38,
                Prefix::OperandSize,
                wide,
                true,
                opcode,
                z,
                X + half,
                Operand::Register(y),
            );
        }
        // vcmpunordps/pd mask, z, z; vblendvps/pd z, z, nan, mask
        vex(
            code,
            Map::Primary,
            prefix,
            false,
            true,
            0xc2,
            UNORDERED,
            z,
            Operand::Register(z),
        );
        code.push(CMP_UNORDERED);
        vex(
            code,
            Map::Escape3a,
            Prefix::OperandSize,
            false,
            true,
            if double { 0x4b } else { 0x4a },
            z,
            z,
            Operand::Register(DEFAULT_NAN),
        );
        code.push(UNORDERED << 4);
        vmovups_store(code, z, memory);
    }
}

fn evex_row(code: &mut Vec<u8>, kernel: Kernel, row: i32, offset: i32, z: u8) {
    let (prefix, wide) = packed(kernel);
    let memory = at(Gpr::Rdi, offset);
    let (y, broadcast) = match kernel.shape {
        Shape::Matrix => (at(Gpr::Rdx, row * kernel.element_bytes()), true),
        Shape::Vector => (at(Gpr::Rdx, 0), false),
    };
    if kernel.product_only {
        // vmulps/pd z, x, y
        evex(
            code,
            Map::Primary,
            prefix,
            wide,
            0x59,
            z,
            X,
            Operand::Memory(y),
            broadcast,
            0,
        );
        if kernel.subtract {
            // vpxord/q z, z, sign
            evex(
                code,
                Map::Primary,
                Prefix::OperandSize,
                wide,
                0xef,
                z,
                z,
                Operand::Register(SIGN),
                false,
                0,
            );
        }
    } else {
        evex(
            code,
            Map::Primary,
            Prefix::None,
            false,
            0x10,
            z,
            0,
            Operand::Memory(memory),
            false,
            0,
        );
        let opcode = if kernel.subtract { 0xbc } else { 0xb8 };
        evex(
            code,
            Map::Escape38,
            Prefix::OperandSize,
            wide,
            opcode,
            z,
            X,
            Operand::Memory(y),
            broadcast,
            0,
        );
    }
    // vcmpunordps/pd k1, z, z; vmovaps/pd z{k1}, nan
    evex(
        code,
        Map::Primary,
        prefix,
        wide,
        0xc2,
        OPMASK,
        z,
        Operand::Register(z),
        false,
        0,
    );
    code.push(CMP_UNORDERED);
    evex(
        code,
        Map::Primary,
        prefix,
        wide,
        0x28,
        z,
        0,
        Operand::Register(DEFAULT_NAN),
        false,
        OPMASK,
    );
    evex(
        code,
        Map::Primary,
        Prefix::None,
        false,
        0x11,
        z,
        0,
        Operand::Memory(memory),
        false,
        0,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_covers_only_fully_enabled_fp32_fp64_forms() {
        let matrix = select(AmxOperation::Fma32, 0).unwrap();
        assert_eq!(matrix.shape, Shape::Matrix);
        assert!(!matrix.subtract && !matrix.product_only);
        let vector = select(AmxOperation::Fms64, (1 << 63) | (1 << 27) | (5 << 32)).unwrap();
        assert_eq!(vector.shape, Shape::Vector);
        assert!(vector.subtract && vector.product_only);
        // Y masks are ignored in vector mode only.
        assert_eq!(select(AmxOperation::Fma64, 5 << 32), None);
        // X masks: mode 1 selects one lane; mode 2/3 with zero enable all.
        assert_eq!(select(AmxOperation::Fma32, 1 << 46), None);
        assert!(select(AmxOperation::Fma32, 2 << 46).is_some());
        assert!(select(AmxOperation::Fma32, 3 << 46).is_some());
        assert_eq!(select(AmxOperation::Fma32, (2 << 46) | (1 << 41)), None);
        // Other skip modes, f16 widening and other operations use the model.
        assert_eq!(select(AmxOperation::Fma32, 2 << 27), None);
        assert_eq!(select(AmxOperation::Fma32, 1 << 60), None);
        assert!(select(AmxOperation::Fma64, 1 << 60).is_some());
        assert_eq!(select(AmxOperation::Fma16, 0), None);
        assert_eq!(select(AmxOperation::VectorFloat, 0), None);
    }

    #[test]
    fn kernel_operations_round_trip_through_selection() {
        for kernel in Kernel::ALL {
            let operand = (u64::from(kernel.shape == Shape::Vector) << 63)
                | (u64::from(kernel.product_only) << 27);
            assert_eq!(select(kernel.operation(), operand), Some(kernel));
        }
    }

    #[test]
    fn library_aligns_every_kernel() {
        for tier in [Tier::Fma, Tier::Avx512] {
            let library = Library::new(tier);
            for kernel in Kernel::ALL {
                let offset = library.offset(kernel);
                assert_eq!(offset % 64, 0);
                let bytes = library.kernel_bytes(kernel);
                assert_eq!(library.code[offset..offset + bytes], emit(kernel, tier));
                // Every kernel returns.
                assert_eq!(library.code[offset + bytes - 1], 0xc3);
            }
        }
    }

    /// Run every kernel of every tier this host supports against the model,
    /// from random registers rich in zeros, infinities, NaNs and subnormals,
    /// under a hostile caller MXCSR that the kernel must ignore and restore.
    #[cfg(all(target_arch = "x86_64", unix))]
    #[test]
    fn kernels_match_the_model_and_keep_the_caller_mxcsr() {
        use crate::amx::{AmxRegisters, model};
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
        const PROT_READ_WRITE: i32 = 3;
        const PROT_READ_EXECUTE: i32 = 5;
        const MAP_PRIVATE: i32 = 2;
        #[cfg(target_os = "macos")]
        const MAP_ANONYMOUS: i32 = 0x1000;
        #[cfg(target_os = "linux")]
        const MAP_ANONYMOUS: i32 = 0x20;
        /// Flush-to-zero, denormals-are-zero, round toward zero, all masked.
        const HOSTILE_MXCSR: u32 = 0xffc0;
        type Entry = unsafe extern "sysv64" fn(*mut u8, *const u8, *const u8, u64);

        struct NoMemory;
        impl model::AmxMemory for NoMemory {
            fn read(&mut self, address: u64, _: &mut [u8]) -> Result<(), model::MemoryFault> {
                Err(model::MemoryFault {
                    address,
                    write: false,
                })
            }
            fn write(&mut self, address: u64, _: &[u8]) -> Result<(), model::MemoryFault> {
                Err(model::MemoryFault {
                    address,
                    write: true,
                })
            }
        }

        fn next(seed: &mut u64) -> u64 {
            *seed ^= *seed << 13;
            *seed ^= *seed >> 7;
            *seed ^= *seed << 17;
            *seed
        }

        fn fill(bytes: &mut [u8], precision: Precision, seed: &mut u64) {
            const SINGLE: [u32; 10] = [
                0,
                0x8000_0000,
                0x7f80_0000,
                0xff80_0000,
                0x7fc0_1234,
                0x7f80_0001,
                1,
                0x8000_7fff,
                0x7f7f_ffff,
                0x3f80_0000,
            ];
            const DOUBLE: [u64; 10] = [
                0,
                1 << 63,
                0x7ff0 << 48,
                0xfff0 << 48,
                0x7ff8_0000_0000_1234,
                0x7ff0_0000_0000_0001,
                1,
                0x800f_ffff_ffff_ffff,
                0x7fef_ffff_ffff_ffff,
                0x3ff0 << 48,
            ];
            match precision {
                Precision::Single => {
                    for lane in bytes.as_chunks_mut::<4>().0 {
                        let random = next(seed);
                        let value = if random.is_multiple_of(4) {
                            SINGLE[(random >> 8) as usize % SINGLE.len()]
                        } else {
                            // Sign, an exponent near 1.0 and a random fraction.
                            ((random >> 32) as u32 & 0x8000_0000)
                                | ((100 + (random >> 40) as u32 % 56) << 23)
                                | (random as u32 & 0x7f_ffff)
                        };
                        lane.copy_from_slice(&value.to_le_bytes());
                    }
                }
                Precision::Double => {
                    for lane in bytes.as_chunks_mut::<8>().0 {
                        let random = next(seed);
                        let value = if random.is_multiple_of(4) {
                            DOUBLE[(random >> 8) as usize % DOUBLE.len()]
                        } else {
                            let fraction = next(seed) & ((1 << 52) - 1);
                            (random & (1 << 63)) | ((1000 + (random >> 40) % 48) << 52) | fraction
                        };
                        lane.copy_from_slice(&value.to_le_bytes());
                    }
                }
            }
        }

        fn mxcsr() -> u32 {
            let mut value = 0u32;
            // SAFETY: stores the four-byte MXCSR into a local.
            unsafe { core::arch::asm!("stmxcsr [{}]", in(reg) &mut value, options(nostack)) };
            value
        }

        fn set_mxcsr(value: u32) {
            // SAFETY: loads a valid MXCSR (reserved bits clear).
            unsafe { core::arch::asm!("ldmxcsr [{}]", in(reg) &value, options(nostack)) };
        }

        let host = crate::TargetCpu::detect();
        let tiers = [Tier::Fma, Tier::Avx512]
            .into_iter()
            .filter(|tier| host.supports(tier.requires()));
        for tier in tiers {
            let library = Library::new(tier);
            let length = library.code.len();
            // SAFETY: private anonymous memory becomes RX after an exact copy.
            let pointer = unsafe {
                mmap(
                    core::ptr::null_mut(),
                    length,
                    PROT_READ_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            assert_ne!(pointer as usize, usize::MAX);
            unsafe {
                core::ptr::copy_nonoverlapping(library.code.as_ptr(), pointer.cast(), length);
                assert_eq!(mprotect(pointer, length, PROT_READ_EXECUTE), 0);
            }
            let mut seed = 0x9e37_79b9_7f4a_7c15 ^ tier as u64;
            for kernel in Kernel::ALL {
                // SAFETY: the offset starts this kernel in the RX mapping.
                let entry: Entry = unsafe {
                    core::mem::transmute(pointer.cast::<u8>().add(library.offset(kernel)))
                };
                for _ in 0..256 {
                    let mut registers = AmxRegisters::zeroed();
                    fill(registers.as_bytes_mut(), kernel.precision, &mut seed);
                    let random = next(&mut seed);
                    // Random offsets and rows; mode-2/3 all-lane masks and
                    // ignored Y masks in vector shape stay on the fast path.
                    let mut operand = (random & 0x1ff)
                        | ((random >> 9) & 0x1ff) << 10
                        | ((random >> 18) & 63) << 20
                        | (u64::from(kernel.product_only) << 27)
                        | [0, 2, 3][(random >> 24) as usize % 3] << 46
                        | (u64::from(kernel.shape == Shape::Vector) << 63);
                    if kernel.shape == Shape::Vector {
                        operand |= ((random >> 25) & 0x7f) << 32;
                    }
                    assert_eq!(select(kernel.operation(), operand), Some(kernel));
                    let mut expected = registers.clone();
                    model::execute(&mut expected, kernel.operation(), operand, &mut NoMemory)
                        .unwrap();
                    // The pinned reference has identical fused arithmetic on
                    // M1–M4. Compare every model before testing unchanged
                    // native code against the shared expected result.
                    for generation in [
                        crate::amx::Generation::M1,
                        crate::amx::Generation::M3,
                        crate::amx::Generation::M4,
                    ] {
                        let mut other = registers.clone();
                        model::execute_for(
                            generation,
                            &mut other,
                            kernel.operation(),
                            operand,
                            &mut NoMemory,
                        )
                        .unwrap();
                        assert_eq!(
                            other, expected,
                            "{generation:?}/M2 fused semantics {kernel:?}"
                        );
                    }
                    let x = registers.x_operand((operand >> 10) & 0x1ff);
                    let y = registers.y_operand(operand & 0x1ff);
                    let caller = mxcsr();
                    set_mxcsr(HOSTILE_MXCSR);
                    // SAFETY: Z is 4 KiB, X and Y are 64 bytes each.
                    unsafe {
                        entry(
                            registers.z.as_mut_ptr().cast(),
                            x.as_ptr(),
                            y.as_ptr(),
                            (operand >> 20) & 63,
                        )
                    };
                    let after = mxcsr();
                    set_mxcsr(caller);
                    assert_eq!(after, HOSTILE_MXCSR, "{kernel:?} {}", tier.name());
                    for (row, (actual, wanted)) in registers.z.iter().zip(&expected.z).enumerate() {
                        assert_eq!(
                            actual,
                            wanted,
                            "{kernel:?} {} operand {operand:#x} row {row}",
                            tier.name()
                        );
                    }
                }
            }
            assert_eq!(unsafe { munmap(pointer, length) }, 0);
        }
    }
}
