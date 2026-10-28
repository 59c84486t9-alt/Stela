//! SVE conversions between single/double and integers.
use crate::x86_64::asm::Code;

use super::{half_integer, unsigned64};
use alloc::vec::Vec;

use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{
        floating::{
            Format, INEXACT,
            features::NumericalFeatures,
            integer::{IntegerFormat, IntegerWidth},
        },
        scalable::{ElementSize, VECTOR_CHUNK_BYTES, VectorLength},
        sve::floating::conversion::{Kind, Operand},
    },
    x86_64::{
        isa::{ShiftOpcode, SimdOpcode as Host},
        scalable::{
            load_z_chunk,
            numerical::{self, Environment, Output},
            read_predicate_mask,
        },
        simd::numerical::rounding_control,
        sve::floating::classify::{
            guard_active_exception_enables, guard_normal_zero_or_infinity, prepare_classification,
        },
    },
};

const INTEGER30_LONG_VECTOR_BYTES: usize = 4 * VECTOR_CHUNK_BYTES;
const SCALAR: u8 = 0;
const SOURCE: u8 = 1;
const OLD_DESTINATION: u8 = 2;
const RESULT: u8 = 3;
const ACTIVE: u8 = 6;
const PACK: u8 = 7;
const CLASSIFICATION_CONSTANTS: [u8; 2] = [4, 5];
const CLASSIFICATION_SCRATCH: [u8; 3] = [OLD_DESTINATION, RESULT, PACK];
const HALF_ACTIVE: u8 = 5;
const HALF_MASK_SCRATCH: u8 = 6;
const HALF_OLD_DESTINATION: u8 = 1;
const HALF_PACK_SCRATCH: u8 = 5;
const OUTPUT_SLOT: usize = 0;
const HALFWORD_BYTES: u8 = size_of::<u16>() as u8;
const DWORD_BYTES: u8 = size_of::<u32>() as u8;
const QWORD_BYTES: u8 = size_of::<u64>() as u8;
const SECOND_HALF_GROUP_BYTES: u8 = QWORD_BYTES;
const SIGNED_HALF_SIGN_MASK: u8 = 4;
const SIGNED_HALFWORD_SIGN_SHIFT: u8 = u16::BITS as u8 - 1;
const SIGNED_DWORD_SIGN_SHIFT: u8 = u32::BITS as u8 - 1;
const UNSIGNED_HALF_PACK_BIAS: u32 = 1 << (u16::BITS - 1);
const UNSIGNED_HALF_PACK_SIGN_BITS: u32 =
    UNSIGNED_HALF_PACK_BIAS | (UNSIGNED_HALF_PACK_BIAS << u16::BITS);
const MODRM_REGISTER: u8 = 0xc0;
const MODRM_REGISTER_SHIFT: u8 = 3;
const SSE_ESCAPE: u8 = 0x0f;
const SINGLE_PREFIX: u8 = 0xf3;
const DOUBLE_PREFIX: u8 = 0xf2;
const REX_W: u8 = 0x48;
const CVTSI_TO_FLOAT: u8 = 0x2a;
const CVTT_TO_INTEGER: u8 = 0x2c;
const CVTDQ2PD: &[u8] = &[0xf3, 0x0f, 0xe6];
const CVTTPS2DQ: &[u8] = &[0xf3, 0x0f, 0x5b];
const MOVD_XMM_EAX: &[u8] = &[0x66, 0x0f, 0x6e];
const MOVD_EAX_XMM: &[u8] = &[0x66, 0x0f, 0x7e];
const MOVQ_RAX_XMM: &[u8] = &[0x66, 0x48, 0x0f, 0x7e];
const MOVSXD_RAX_EAX: &[u8] = &[0x48, 0x63, 0xc0];
const MOV_RDX_RAX: &[u8] = &[0x48, 0x89, 0xc2];
const SHR_RDX_IMMEDIATE: &[u8] = &[0x48, 0xc1, 0xea];
const TEST_EDX_EDX: &[u8] = &[0x85, 0xd2];
const MOV_EAX_ECX: &[u8] = &[0x89, 0xc8];
const MOV_ECX_IMMEDIATE: &[u8] = &[0xb9];
const MOVQ_R8_XMM0: &[u8] = &[0x66, 0x49, 0x0f, 0x7e, 0xc0];
const MOVQ_XMM7_R8: &[u8] = &[0x66, 0x49, 0x0f, 0x6e, 0xf8];
const XOR_R10D_R10D: &[u8] = &[0x45, 0x31, 0xd2];
const OR_EAX_R10D: &[u8] = &[0x44, 0x09, 0xd0];
const GPR_RCX: u8 = 1;
const GPR_RAX: u8 = 0;
const REPEAT_LOW_DWORD: u8 = 0;
const XOR_EAX_EAX: &[u8] = &[0x31, 0xc0];
const SHR_EAX_IMMEDIATE: &[u8] = &[0xc1, 0xe8];
const AND_EAX_IMMEDIATE: u8 = 0x25;
const TEST_ECX_IMMEDIATE: &[u8] = &[0xf7, 0xc1];
const JNZ_REL32: &[u8] = &[0x0f, 0x85];
const MXCSR_PRECISION: u32 = 1 << 5;
const MXCSR_OTHER_STATUS: u32 = MXCSR_PRECISION - 1;
const MXCSR_TO_FPSR_PRECISION_SHIFT: u8 = 1;
const LOW_DWORDS_FROM_QWORDS: u8 = 0b10_00_10_00;

/// Production mappings selected from measured typed shapes and usable host features.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mapping {
    Scalar,
    PackedSignedDword,
    PackedSignedHalf,
    F16c,
    UnsignedHalfPack,
    F16cUnsignedHalfPack,
}

impl Mapping {
    fn select(conversion: Conversion, length: VectorLength, target: TargetCpu) -> Self {
        let short_vector = length.bytes() == VECTOR_CHUNK_BYTES;
        let long_vector = length.bytes() == INTEGER30_LONG_VECTOR_BYTES;
        let f16c = target.supports(TargetCpu::F16c);
        if conversion.signed_half_input() && f16c {
            return if short_vector {
                Self::F16c
            } else {
                Self::PackedSignedHalf
            };
        }
        if !short_vector && !long_vector {
            return Self::Scalar;
        }
        if conversion.float == Format::Half {
            if conversion.unsigned_half_output() {
                return match (f16c, target.supports(TargetCpu::Sse41)) {
                    (true, true) => Self::F16cUnsignedHalfPack,
                    (false, true) => Self::UnsignedHalfPack,
                    _ => Self::Scalar,
                };
            }
            let checked_half = match (
                conversion.direction,
                conversion.integer.signed,
                conversion.integer.width,
            ) {
                (Direction::ToInteger, true, IntegerWidth::Bits16) => true,
                (Direction::ToInteger, true, IntegerWidth::Bits32) => short_vector,
                (Direction::ToInteger, false, IntegerWidth::Bits64) => true,
                (Direction::FromInteger, true, IntegerWidth::Bits32) => long_vector,
                (Direction::FromInteger, true, IntegerWidth::Bits64) => true,
                (Direction::FromInteger, false, _) => long_vector,
                _ => false,
            };
            return if f16c && checked_half {
                Self::F16c
            } else {
                Self::Scalar
            };
        }
        if conversion.packed() && (conversion.float == Format::Double || short_vector) {
            Self::PackedSignedDword
        } else {
            Self::Scalar
        }
    }

    fn half_f16c(self) -> bool {
        matches!(
            self,
            Self::F16c | Self::F16cUnsignedHalfPack | Self::PackedSignedHalf
        )
    }

    fn unsigned_half_pack(self) -> bool {
        matches!(self, Self::UnsignedHalfPack | Self::F16cUnsignedHalfPack)
    }
}

#[derive(Clone, Copy)]
enum Direction {
    FromInteger,
    ToInteger,
}

#[derive(Clone, Copy)]
struct Conversion {
    direction: Direction,
    float: Format,
    integer: IntegerFormat,
}

impl Conversion {
    fn decode(kind: Kind) -> Option<Self> {
        let conversion = match kind {
            Kind::FromInteger {
                source,
                destination,
            } => Self {
                direction: Direction::FromInteger,
                float: destination,
                integer: source,
            },
            Kind::ToInteger {
                source,
                destination,
            } => Self {
                direction: Direction::ToInteger,
                float: source,
                integer: destination,
            },
            _ => return None,
        };
        // Canonical Half pairs with H/W/X; S/D pairs only with W/X. Do not
        // synthesize the unallocated integer-H↔S/D shapes from generic types.
        if conversion.float != Format::Half && conversion.integer.width == IntegerWidth::Bits16 {
            return None;
        }
        Some(conversion)
    }

    fn packed(self) -> bool {
        self.integer.signed
            && self.integer.width == IntegerWidth::Bits32
            && (matches!(self.direction, Direction::FromInteger) || self.float == Format::Single)
    }

    fn signed_half_input(self) -> bool {
        matches!(self.direction, Direction::FromInteger)
            && self.float == Format::Half
            && self.integer.signed
            && self.integer.width == IntegerWidth::Bits16
    }

    fn host_wide(self) -> bool {
        self.integer.width == IntegerWidth::Bits64 || !self.integer.signed
    }

    fn unsigned_x(self) -> bool {
        !self.integer.signed && self.integer.width == IntegerWidth::Bits64
    }

    fn unsigned_half_output(self) -> bool {
        self.float == Format::Half
            && matches!(self.direction, Direction::ToInteger)
            && !self.integer.signed
            && self.integer.width == IntegerWidth::Bits16
    }

    fn manual_inexact(self, mapping: Mapping) -> bool {
        self.float == Format::Half
            && matches!(self.direction, Direction::FromInteger)
            && !mapping.half_f16c()
    }
}

fn reject(code: &mut Code, failures: &mut Vec<usize>) {
    code.extend(JNZ_REL32);
    failures.push(code.len());
    code.extend(0_i32.to_le_bytes());
}

fn scalar_opcode(code: &mut Code, conversion: Conversion, opcode: u8) {
    code.push(match conversion.float {
        Format::Single => SINGLE_PREFIX,
        Format::Double => DOUBLE_PREFIX,
        Format::Half => unreachable!("Half conversion belongs to its compute leaf"),
    });
    if conversion.host_wide() {
        code.push(REX_W);
    }
    // Both directions use XMM0 and RAX/EAX, with the appropriate ModRM role.
    code.extend([SSE_ESCAPE, opcode, MODRM_REGISTER]);
}

fn scalar_chunk(
    code: &mut Code,
    conversion: Conversion,
    slot_bytes: u8,
    failures: &mut Vec<usize>,
    target: TargetCpu,
    mapping: Mapping,
) {
    Host::Xor.register(code, RESULT, RESULT, target);
    for offset in (0..VECTOR_CHUNK_BYTES).step_by(usize::from(slot_bytes)) {
        Host::MoveAligned.register(code, SCALAR, SOURCE, target);
        if offset != 0 {
            ShiftOpcode::RightBytes.emit(code, SCALAR, offset as u8);
        }
        match conversion.direction {
            Direction::FromInteger => {
                code.extend(if conversion.integer.width == IntegerWidth::Bits64 {
                    MOVQ_RAX_XMM
                } else {
                    MOVD_EAX_XMM
                });
                code.push(MODRM_REGISTER | (GPR_RAX << MODRM_REGISTER_SHIFT) | SCALAR);
                // MOVD writes EAX and zero-extends unsigned W before CVTSI64.
                // Reset all scalar upper bits so X→S zero-fills its full slot.
                Host::Xor.register(code, SCALAR, SCALAR, target);
                if conversion.float == Format::Half {
                    half_integer::from_integer_lane(
                        code,
                        conversion.integer,
                        mapping.half_f16c(),
                        failures,
                        target,
                    );
                    pack_integer(code, slot_bytes, target);
                } else {
                    if conversion.unsigned_x() {
                        unsigned64::from_integer(code, conversion.float);
                    } else {
                        scalar_opcode(code, conversion, CVTSI_TO_FLOAT);
                    }
                    Host::MoveAligned.register(code, PACK, SCALAR, target);
                }
            }
            Direction::ToInteger => {
                if conversion.unsigned_x() {
                    unsigned64::to_integer(code, conversion.float, failures);
                } else {
                    scalar_opcode(code, conversion, CVTT_TO_INTEGER);
                }
                if !conversion.integer.signed && !conversion.unsigned_x() {
                    // CVTT64 admits unsigned W only when high32 is zero.
                    // Negative fractions truncating to zero are valid too.
                    code.extend(MOV_RDX_RAX);
                    code.extend(SHR_RDX_IMMEDIATE);
                    code.push(u32::BITS as u8);
                    code.extend(TEST_EDX_EDX);
                    reject(code, failures);
                } else if slot_bytes == QWORD_BYTES
                    && conversion.integer.width == IntegerWidth::Bits32
                {
                    code.extend(MOVSXD_RAX_EAX);
                }
                pack_integer(code, slot_bytes, target);
            }
        }
        if offset != 0 {
            ShiftOpcode::LeftBytes.emit(code, PACK, offset as u8);
        }
        Host::Or.register(code, RESULT, PACK, target);
    }
}

/// MOVD/MOVQ clear all unused packed bits. A returned raw Half also clears the
/// rest of its H/W/X slot, so the shift/OR assembly cannot contaminate a neighbor.
fn pack_integer(code: &mut Code, slot_bytes: u8, target: TargetCpu) {
    if slot_bytes == QWORD_BYTES {
        Host::MoveGprQword.append(code, target);
    } else {
        code.extend(MOVD_XMM_EAX);
    }
    code.push(MODRM_REGISTER | (PACK << MODRM_REGISTER_SHIFT) | GPR_RAX);
}

/// Compile-time access bookkeeping for the single instruction frame. No guest
/// sources are written or copied into an additional architectural output.
#[derive(Clone, Copy)]
struct ChunkAccess {
    operand: Operand,
    length: VectorLength,
    element: ElementSize,
    features: NumericalFeatures,
    target: TargetCpu,
}

impl ChunkAccess {
    fn mask(self, code: &mut Code, chunk: usize, destination: u8, scratch: u8) {
        read_predicate_mask(
            code,
            self.operand.governing,
            chunk,
            self.element,
            destination,
            scratch,
            self.length,
            self.target,
        );
    }

    fn source(self, code: &mut Code, chunk: usize, destination: u8) {
        load_z_chunk(
            code,
            self.operand.source,
            chunk,
            destination,
            self.length,
            self.target,
        );
    }
}

fn broadcast_dword(code: &mut Code, register: u8, value: u32, target: TargetCpu) {
    code.extend(MOV_ECX_IMMEDIATE);
    code.extend(value.to_le_bytes());
    Host::MoveGprQword.append(code, target);
    code.push(MODRM_REGISTER | (register << MODRM_REGISTER_SHIFT) | GPR_RCX);
    Host::ShuffleDword.register(code, register, register, target);
    code.push(REPEAT_LOW_DWORD);
}

fn half_forward_group(
    code: &mut Code,
    access: ChunkAccess,
    chunk: usize,
    integer: IntegerFormat,
    mapping: Mapping,
    upper: bool,
    failures: &mut Vec<usize>,
) {
    // The compute leaf destroys mask/source scratch. Reload for each H group;
    // R8 and invariant constants XMM2/3/4 survive both access and computation.
    access.mask(code, chunk, HALF_ACTIVE, HALF_MASK_SCRATCH);
    if !upper {
        guard_active_exception_enables(code, HALF_ACTIVE, access.features, failures, access.target);
    }
    access.source(code, chunk, SCALAR);
    Host::And.register(code, SCALAR, HALF_ACTIVE, access.target);
    match integer.width {
        IntegerWidth::Bits16 => {
            if upper {
                ShiftOpcode::RightBytes.emit(code, SCALAR, SECOND_HALF_GROUP_BYTES);
            }
            Host::Xor.register(code, HALF_MASK_SCRATCH, HALF_MASK_SCRATCH, access.target);
            Host::UnpackLowWord.register(code, SCALAR, HALF_MASK_SCRATCH, access.target);
        }
        IntegerWidth::Bits32 => {
            // Each max-width dword already contains its selected low Half.
        }
        IntegerWidth::Bits64 => {
            // Half0/Half4 are the only architectural operands. Duplicate them
            // in internal extra dwords rather than reading Half2/Half6 poison.
            Host::ShuffleDword.register(code, SCALAR, SCALAR, access.target);
            code.push(LOW_DWORDS_FROM_QWORDS);
        }
    }
    half_integer::to_integer_words(code, integer, mapping.half_f16c(), failures, access.target);
}

/// Every selected H result is in range before these lossless integer packs.
fn pack_half_results(code: &mut Code, integer: IntegerFormat, mapping: Mapping, target: TargetCpu) {
    if integer.signed {
        Host::PackSignedDwordToWord.register(code, SCALAR, SCALAR, target);
    } else if mapping.unsigned_half_pack() {
        Host::PackUnsignedDwordToWord.register(code, SCALAR, SCALAR, target);
    } else {
        // 0..65504 maps to -32768..32736, so PACKSSDW cannot saturate.
        broadcast_dword(code, HALF_PACK_SCRATCH, UNSIGNED_HALF_PACK_BIAS, target);
        Host::SubDword.register(code, SCALAR, HALF_PACK_SCRATCH, target);
        Host::PackSignedDwordToWord.register(code, SCALAR, SCALAR, target);
        broadcast_dword(
            code,
            HALF_PACK_SCRATCH,
            UNSIGNED_HALF_PACK_SIGN_BITS,
            target,
        );
        Host::Xor.register(code, SCALAR, HALF_PACK_SCRATCH, target);
    }
}

/// Return the complete converted chunk register, preserving constants2/3/4.
fn half_forward_chunk(
    code: &mut Code,
    access: ChunkAccess,
    chunk: usize,
    integer: IntegerFormat,
    mapping: Mapping,
    failures: &mut Vec<usize>,
) -> u8 {
    half_forward_group(code, access, chunk, integer, mapping, false, failures);
    match integer.width {
        IntegerWidth::Bits16 => {
            pack_half_results(code, integer, mapping, access.target);
            code.extend(MOVQ_R8_XMM0);
            half_forward_group(code, access, chunk, integer, mapping, true, failures);
            pack_half_results(code, integer, mapping, access.target);
            // RDX cannot hold group one: the Z and P reloads clobber it.
            code.extend(MOVQ_XMM7_R8);
            Host::UnpackLowQword.register(code, PACK, SCALAR, access.target);
            PACK
        }
        IntegerWidth::Bits32 => SCALAR,
        IntegerWidth::Bits64 => {
            if integer.signed {
                Host::MoveAligned.register(code, HALF_PACK_SCRATCH, SCALAR, access.target);
                ShiftOpcode::ArithmeticDword.emit(code, HALF_PACK_SCRATCH, SIGNED_DWORD_SIGN_SHIFT);
            } else {
                Host::Xor.register(code, HALF_PACK_SCRATCH, HALF_PACK_SCRATCH, access.target);
            }
            Host::UnpackLowDword.register(code, SCALAR, HALF_PACK_SCRATCH, access.target);
            SCALAR
        }
    }
}

/// Convert eight sanitized signed H lanes into eight IEEE Half lanes.
/// Every signed16 value is exact in Single, so only VCVTPS2PH can raise PE.
/// The caller owns RC installation, active-trap guards and whole-state commit.
/// Input SOURCE1 is read-only; RESULT3 is output; SCALAR0 and XMM4 are scratch.
/// Preserves ACTIVE6, all other XMMs, GPRs, EFLAGS and pending status channels.
fn packed_signed_half_chunk(code: &mut Code, target: TargetCpu) {
    Host::MoveAligned.register(code, RESULT, SOURCE, target);
    Host::MoveAligned.register(code, SCALAR, SOURCE, target);
    Host::MoveAligned.register(code, SIGNED_HALF_SIGN_MASK, SOURCE, target);
    ShiftOpcode::ArithmeticWord.emit(code, SIGNED_HALF_SIGN_MASK, SIGNED_HALFWORD_SIGN_SHIFT);
    Host::UnpackLowWord.register(code, RESULT, SIGNED_HALF_SIGN_MASK, target);
    Host::UnpackHighWord.register(code, SCALAR, SIGNED_HALF_SIGN_MASK, target);
    Host::ConvertPackedDwordToSingle.register(code, RESULT, RESULT, target);
    Host::ConvertPackedDwordToSingle.register(code, SCALAR, SCALAR, target);
    // This instruction's ModRM.reg is the Single source, r/m the Half result.
    Host::ConvertSingleToHalf.register(code, RESULT, RESULT, target);
    code.push(half_integer::USE_MXCSR_ROUNDING);
    Host::ConvertSingleToHalf.register(code, SCALAR, SCALAR, target);
    code.push(half_integer::USE_MXCSR_ROUNDING);
    Host::UnpackLowQword.register(code, RESULT, SCALAR, target);
}

fn packed_chunk(code: &mut Code, conversion: Conversion, target: TargetCpu) {
    Host::MoveAligned.register(code, RESULT, SOURCE, target);
    match (conversion.direction, conversion.float) {
        (Direction::FromInteger, Format::Single) => {
            Host::ConvertPackedDwordToSingle.register(code, RESULT, RESULT, target);
        }
        (Direction::FromInteger, Format::Double) => {
            // W→D selects each qword's low dword, not adjacent packed W lanes.
            Host::ShuffleDword.register(code, RESULT, RESULT, target);
            code.push(LOW_DWORDS_FROM_QWORDS);
            code.extend(CVTDQ2PD);
            code.push(MODRM_REGISTER | (RESULT << MODRM_REGISTER_SHIFT) | RESULT);
        }
        (Direction::ToInteger, Format::Single) => {
            code.extend(CVTTPS2DQ);
            code.push(MODRM_REGISTER | (RESULT << MODRM_REGISTER_SHIFT) | RESULT);
        }
        _ => unreachable!("packed mapping was checked before emission"),
    }
}

/// Caller retains instruction availability and the streaming entry guard.
/// Unsupported forms leave `code` unchanged. No guest state is changed
/// until numerical::finish, including when source aliases destination.
pub(in crate::x86_64) fn emit(
    code: &mut Code,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    let Some(conversion) = Conversion::decode(operand.kind) else {
        return Ok(false);
    };
    let mapping = Mapping::select(conversion, length, target);
    let slot_bytes = operand.kind.slot_bytes();
    let element = match slot_bytes {
        HALFWORD_BYTES => ElementSize::Halfword,
        DWORD_BYTES => ElementSize::Word,
        QWORD_BYTES => ElementSize::Doubleword,
        _ => unreachable!("admitted conversions use H/W/X slots"),
    };
    let access = ChunkAccess {
        operand,
        length,
        element,
        features,
        target,
    };
    let half_forward =
        conversion.float == Format::Half && matches!(conversion.direction, Direction::ToInteger);
    let half_reverse =
        conversion.float == Format::Half && matches!(conversion.direction, Direction::FromInteger);
    let manual_inexact = conversion.manual_inexact(mapping);
    let frame = numerical::begin(
        code,
        length,
        &[Output::Z(operand.destination)],
        Environment::PrivateMxcsr,
    )?;
    match conversion.direction {
        Direction::FromInteger => rounding_control(code),
        Direction::ToInteger => code.extend(XOR_EAX_EAX), // CVTT ignores RC.
    }
    numerical::install_mxcsr(code, &frame);
    if manual_inexact {
        // This is an approved guest-IXC bitmask, not a Boolean or host status.
        code.extend(XOR_R10D_R10D);
    }
    if half_forward {
        half_integer::prepare_to_integer(code, target);
    }
    let classification = (matches!(conversion.direction, Direction::ToInteger)
        && conversion.float != Format::Half)
        .then(|| prepare_classification(code, conversion.float, CLASSIFICATION_CONSTANTS, target));
    let mut failures = Vec::new();
    for chunk in 0..length.chunks() {
        let (result, active, old_destination) = if half_forward {
            let result = half_forward_chunk(
                code,
                access,
                chunk,
                conversion.integer,
                mapping,
                &mut failures,
            );
            access.mask(code, chunk, HALF_ACTIVE, HALF_MASK_SCRATCH);
            (result, HALF_ACTIVE, HALF_OLD_DESTINATION)
        } else {
            access.mask(code, chunk, ACTIVE, OLD_DESTINATION);
            guard_active_exception_enables(code, ACTIVE, features, &mut failures, target);
            access.source(code, chunk, SOURCE);
            Host::And.register(code, SOURCE, ACTIVE, target);
            if let Some(classification) = classification {
                if conversion.float == Format::Single && slot_bytes == QWORD_BYTES {
                    // Ignore the unused high Single in every S→X source slot.
                    ShiftOpcode::LeftQword.emit(code, SOURCE, u32::BITS as u8);
                    ShiftOpcode::RightQword.emit(code, SOURCE, u32::BITS as u8);
                }
                guard_normal_zero_or_infinity(
                    code,
                    classification,
                    SOURCE,
                    CLASSIFICATION_SCRATCH,
                    &mut failures,
                    target,
                );
            }
            if mapping == Mapping::PackedSignedDword {
                packed_chunk(code, conversion, target);
            } else if mapping == Mapping::PackedSignedHalf {
                packed_signed_half_chunk(code, target);
            } else {
                scalar_chunk(code, conversion, slot_bytes, &mut failures, target, mapping);
            }
            if half_reverse && mapping != Mapping::PackedSignedHalf {
                // Every reverse Half lane destroys XMM6, but SOURCE1/RESULT3
                // remain live. Reconstruct activity once before the merge.
                access.mask(code, chunk, ACTIVE, OLD_DESTINATION);
            }
            (RESULT, ACTIVE, OLD_DESTINATION)
        };
        load_z_chunk(
            code,
            operand.destination,
            chunk,
            old_destination,
            length,
            target,
        );
        Host::AndNot.register(code, active, old_destination, target);
        Host::Or.register(code, result, active, target);
        numerical::stage_vector_chunk(code, &frame, OUTPUT_SLOT, chunk, result, target);
    }
    // Private host invalid/range failures never become architectural effects.
    // All admitted conversions can raise only guest IXC. Earlier chunks and
    // caller MXCSR remain untouched if any later lane needs exact completion.
    numerical::capture_status(code, &frame);
    code.extend(TEST_ECX_IMMEDIATE);
    code.extend(MXCSR_OTHER_STATUS.to_le_bytes());
    reject(code, &mut failures);
    code.extend(MOV_EAX_ECX);
    code.push(AND_EAX_IMMEDIATE);
    code.extend(MXCSR_PRECISION.to_le_bytes());
    code.extend(SHR_EAX_IMMEDIATE);
    code.push(MXCSR_TO_FPSR_PRECISION_SHIFT);
    if manual_inexact {
        code.extend(OR_EAX_R10D);
        code.push(AND_EAX_IMMEDIATE);
        code.extend(INEXACT.to_le_bytes());
    }
    numerical::add_fpsr(code, &frame);
    numerical::finish(code, &frame, &failures, pc, target);
    Ok(true)
}
