//! Named x86 SIMD output encodings and their minimum feature requirements.
//! Intel SDM instruction entries define these SSE/VEX forms. Operand fields
//! (ModRM, displacement and immediates) are supplied separately by the emitter.
use crate::TargetCpu;

macro_rules! catalog {
    ($($name:ident => ($mnemonic:literal, $cpu:ident, [$($byte:expr),+])),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum SimdOpcode { $($name),+ }
        impl SimdOpcode {
            pub const ALL: &'static [Self] = &[$(Self::$name),+];
            pub fn mnemonic(self) -> &'static str { match self { $(Self::$name => $mnemonic),+ } }
            pub fn requires(self) -> TargetCpu { match self { $(Self::$name => TargetCpu::$cpu),+ } }
            pub fn encoding(self) -> &'static [u8] { match self { $(Self::$name => &[$($byte),+]),+ } }
        }
    };
}
catalog! {
    And => ("pand", Baseline, [0x66,0x0f,0xdb]),
    AndNot => ("pandn", Baseline, [0x66,0x0f,0xdf]),
    Or => ("por", Baseline, [0x66,0x0f,0xeb]),
    Xor => ("pxor", Baseline, [0x66,0x0f,0xef]),
    EqualByte => ("pcmpeqb", Baseline, [0x66,0x0f,0x74]),
    EqualWord => ("pcmpeqw", Baseline, [0x66,0x0f,0x75]),
    EqualDword => ("pcmpeqd", Baseline, [0x66,0x0f,0x76]),
    EqualQword => ("pcmpeqq", Sse41, [0x66,0x0f,0x38,0x29]),
    GreaterByte => ("pcmpgtb", Baseline, [0x66,0x0f,0x64]),
    GreaterWord => ("pcmpgtw", Baseline, [0x66,0x0f,0x65]),
    GreaterDword => ("pcmpgtd", Baseline, [0x66,0x0f,0x66]),
    GreaterQword => ("pcmpgtq", Sse42, [0x66,0x0f,0x38,0x37]),
    AddByte => ("paddb", Baseline, [0x66,0x0f,0xfc]),
    AddWord => ("paddw", Baseline, [0x66,0x0f,0xfd]),
    AddDword => ("paddd", Baseline, [0x66,0x0f,0xfe]),
    AddQword => ("paddq", Baseline, [0x66,0x0f,0xd4]),
    SubByte => ("psubb", Baseline, [0x66,0x0f,0xf8]),
    SubWord => ("psubw", Baseline, [0x66,0x0f,0xf9]),
    SubDword => ("psubd", Baseline, [0x66,0x0f,0xfa]),
    SubQword => ("psubq", Baseline, [0x66,0x0f,0xfb]),
    AbsByte => ("pabsb", Ssse3, [0x66,0x0f,0x38,0x1c]),
    AbsWord => ("pabsw", Ssse3, [0x66,0x0f,0x38,0x1d]),
    AbsDword => ("pabsd", Ssse3, [0x66,0x0f,0x38,0x1e]),
    UnpackLowQword => ("punpcklqdq", Baseline, [0x66,0x0f,0x6c]),
    UnpackLowByte => ("punpcklbw", Baseline, [0x66,0x0f,0x60]),
    UnpackLowWord => ("punpcklwd", Baseline, [0x66,0x0f,0x61]),
    UnpackLowDword => ("punpckldq", Baseline, [0x66,0x0f,0x62]),
    PackUnsignedWordToByte => ("packuswb", Baseline, [0x66,0x0f,0x67]),
    PackSignedDwordToWord => ("packssdw", Baseline, [0x66,0x0f,0x6b]),
    UnpackHighByte => ("punpckhbw", Baseline, [0x66,0x0f,0x68]),
    UnpackHighWord => ("punpckhwd", Baseline, [0x66,0x0f,0x69]),
    UnpackHighDword => ("punpckhdq", Baseline, [0x66,0x0f,0x6a]),
    UnpackHighQword => ("punpckhqdq", Baseline, [0x66,0x0f,0x6d]),
    MinUnsignedByte => ("pminub", Baseline, [0x66,0x0f,0xda]),
    MaxUnsignedByte => ("pmaxub", Baseline, [0x66,0x0f,0xde]),
    MinSignedWord => ("pminsw", Baseline, [0x66,0x0f,0xea]),
    MaxSignedWord => ("pmaxsw", Baseline, [0x66,0x0f,0xee]),
    MinSignedByte => ("pminsb", Sse41, [0x66,0x0f,0x38,0x38]),
    MaxSignedByte => ("pmaxsb", Sse41, [0x66,0x0f,0x38,0x3c]),
    MinUnsignedWord => ("pminuw", Sse41, [0x66,0x0f,0x38,0x3a]),
    MaxUnsignedWord => ("pmaxuw", Sse41, [0x66,0x0f,0x38,0x3e]),
    MinSignedDword => ("pminsd", Sse41, [0x66,0x0f,0x38,0x39]),
    MaxSignedDword => ("pmaxsd", Sse41, [0x66,0x0f,0x38,0x3d]),
    MinUnsignedDword => ("pminud", Sse41, [0x66,0x0f,0x38,0x3b]),
    MaxUnsignedDword => ("pmaxud", Sse41, [0x66,0x0f,0x38,0x3f]),
    AddSignedSaturatingByte => ("paddsb", Baseline, [0x66,0x0f,0xec]),
    AddSignedSaturatingWord => ("paddsw", Baseline, [0x66,0x0f,0xed]),
    AddUnsignedSaturatingByte => ("paddusb", Baseline, [0x66,0x0f,0xdc]),
    AddUnsignedSaturatingWord => ("paddusw", Baseline, [0x66,0x0f,0xdd]),
    SubSignedSaturatingByte => ("psubsb", Baseline, [0x66,0x0f,0xe8]),
    SubSignedSaturatingWord => ("psubsw", Baseline, [0x66,0x0f,0xe9]),
    SubUnsignedSaturatingByte => ("psubusb", Baseline, [0x66,0x0f,0xd8]),
    SubUnsignedSaturatingWord => ("psubusw", Baseline, [0x66,0x0f,0xd9]),
    PackSignedWordToByte => ("packsswb", Baseline, [0x66,0x0f,0x63]),
    PackUnsignedDwordToWord => ("packusdw", Sse41, [0x66,0x0f,0x38,0x2b]),
    ByteSignMask => ("pmovmskb", Baseline, [0x66,0x0f,0xd7]),
    DwordSignMask => ("movmskps", Baseline, [0x0f,0x50]),
    MultiplyLowWord => ("pmullw", Baseline, [0x66,0x0f,0xd5]),
    MultiplyHighSignedWord => ("pmulhw", Baseline, [0x66,0x0f,0xe5]),
    MultiplyHighUnsignedWord => ("pmulhuw", Baseline, [0x66,0x0f,0xe4]),
    MultiplyHighRoundedScaledWord => ("pmulhrsw", Ssse3, [0x66,0x0f,0x38,0x0b]),
    MultiplyUnsignedDword => ("pmuludq", Baseline, [0x66,0x0f,0xf4]),
    MultiplyLowDword => ("pmulld", Sse41, [0x66,0x0f,0x38,0x40]),
    MultiplySignedDword => ("pmuldq", Sse41, [0x66,0x0f,0x38,0x28]),
    CarrylessMultiplyQword => ("pclmulqdq", Pclmulqdq, [0x66,0x0f,0x3a,0x44]),
    AverageByte => ("pavgb", Baseline, [0x66,0x0f,0xe0]),
    AverageWord => ("pavgw", Baseline, [0x66,0x0f,0xe3]),
    MultiplyAddWords => ("pmaddwd", Baseline, [0x66,0x0f,0xf5]),
    MultiplyAddUnsignedBytes => ("pmaddubsw", Ssse3, [0x66,0x0f,0x38,0x04]),
    SignExtendWordToDword => ("pmovsxwd", Sse41, [0x66,0x0f,0x38,0x23]),
    ZeroExtendWordToDword => ("pmovzxwd", Sse41, [0x66,0x0f,0x38,0x33]),
    SignExtendDwordToQword => ("pmovsxdq", Sse41, [0x66,0x0f,0x38,0x25]),
    ZeroExtendDwordToQword => ("pmovzxdq", Sse41, [0x66,0x0f,0x38,0x35]),
    RoundPackedSingle => ("roundps", Sse41, [0x66,0x0f,0x3a,0x08]),
    RoundPackedDouble => ("roundpd", Sse41, [0x66,0x0f,0x3a,0x09]),
    RoundScalarSingle => ("roundss", Sse41, [0x66,0x0f,0x3a,0x0a]),
    RoundScalarDouble => ("roundsd", Sse41, [0x66,0x0f,0x3a,0x0b]),
    SquareRootPackedSingle => ("sqrtps", Baseline, [0x0f,0x51]),
    SquareRootPackedDouble => ("sqrtpd", Baseline, [0x66,0x0f,0x51]),
    SquareRootScalarSingle => ("sqrtss", Baseline, [0xf3,0x0f,0x51]),
    SquareRootScalarDouble => ("sqrtsd", Baseline, [0xf2,0x0f,0x51]),
    ReciprocalPackedSingle => ("rcpps", Baseline, [0x0f,0x53]),
    ConvertPackedDwordToSingle => ("cvtdq2ps", Baseline, [0x0f,0x5b]),
    ConvertPackedSingleToDword => ("cvtps2dq", Baseline, [0x66,0x0f,0x5b]),
    ConvertHalfToSingle => ("vcvtph2ps", F16c, [0xc4,0xe2,0x79,0x13]),
    ConvertSingleToHalf => ("vcvtps2ph", F16c, [0xc4,0xe3,0x79,0x1d]),
    MoveGprQword => ("movq", Baseline, [0x66,0x48,0x0f,0x6e]),
    MoveAligned => ("movdqa", Baseline, [0x66,0x0f,0x6f]),
    ShuffleDword => ("pshufd", Baseline, [0x66,0x0f,0x70]),
    ShuffleLowWord => ("pshuflw", Baseline, [0xf2,0x0f,0x70]),
    ShuffleHighWord => ("pshufhw", Baseline, [0xf3,0x0f,0x70]),
    LoadUnaligned => ("movdqu", Baseline, [0xf3,0x0f,0x6f]),
    StoreUnaligned => ("movdqu", Baseline, [0xf3,0x0f,0x7f]),
    MoveQword => ("movq", Baseline, [0xf3,0x0f,0x7e]),
    ByteShuffle => ("pshufb", Ssse3, [0x66,0x0f,0x38,0x00]),
}

/// Packed immediate shifts use an opcode group, rather than a source ModRM field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShiftOpcode {
    LeftWord,
    LeftDword,
    LeftQword,
    RightWord,
    RightDword,
    RightQword,
    ArithmeticWord,
    ArithmeticDword,
    RightBytes,
}
impl ShiftOpcode {
    pub const ALL: &'static [Self] = &[
        Self::LeftWord,
        Self::LeftDword,
        Self::LeftQword,
        Self::RightWord,
        Self::RightDword,
        Self::RightQword,
        Self::ArithmeticWord,
        Self::ArithmeticDword,
        Self::RightBytes,
    ];
    pub fn mnemonic(self) -> &'static str {
        self.facts().0
    }
    pub fn opcode(self) -> u8 {
        self.facts().1
    }
    pub fn group(self) -> u8 {
        self.facts().2
    }
    fn facts(self) -> (&'static str, u8, u8) {
        match self {
            Self::LeftWord => ("psllw", 0x71, 6),
            Self::LeftDword => ("pslld", 0x72, 6),
            Self::LeftQword => ("psllq", 0x73, 6),
            Self::RightWord => ("psrlw", 0x71, 2),
            Self::RightDword => ("psrld", 0x72, 2),
            Self::RightQword => ("psrlq", 0x73, 2),
            Self::ArithmeticWord => ("psraw", 0x71, 4),
            Self::ArithmeticDword => ("psrad", 0x72, 4),
            Self::RightBytes => ("psrldq", 0x73, 3),
        }
    }
    pub(crate) fn emit(self, code: &mut Vec<u8>, register: u8, amount: u8) {
        assert!(register < 8, "legacy SIMD register needs REX encoding");
        code.extend([
            0x66,
            0x0f,
            self.opcode(),
            0xc0 | (self.group() << 3) | register,
            amount,
        ]);
    }
}
impl SimdOpcode {
    pub(crate) fn append(self, code: &mut Vec<u8>, target: TargetCpu) {
        assert!(
            target.supports(self.requires()),
            "selected CPU requirements cannot emit {}",
            self.mnemonic()
        );
        code.extend(self.encoding());
    }
    pub(crate) fn register(
        self,
        code: &mut Vec<u8>,
        destination: u8,
        source: u8,
        target: TargetCpu,
    ) {
        assert!(
            destination < 8 && source < 8,
            "legacy SIMD register needs REX encoding"
        );
        self.append(code, target);
        code.push(0xc0 | (destination << 3) | source);
    }
}

/// SSE4.2 CRC32 computes Castagnoli, never the IEEE polynomial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CrcOpcode {
    Byte,
    Halfword,
    Word,
    Doubleword,
}
impl CrcOpcode {
    pub(crate) fn for_bytes(bytes: u8) -> Self {
        match bytes {
            1 => Self::Byte,
            2 => Self::Halfword,
            4 => Self::Word,
            8 => Self::Doubleword,
            _ => unreachable!("decoder validates CRC data size"),
        }
    }
    /// Accumulator RAX, data RCX; every form zero-extends its 32-bit remainder.
    pub(crate) fn emit(self, code: &mut Vec<u8>, target: TargetCpu) {
        assert!(target.supports(TargetCpu::Sse42));
        code.push(0xf2);
        match self {
            Self::Halfword => code.push(0x66),
            Self::Doubleword => code.push(0x48),
            _ => {}
        }
        code.extend([
            0x0f,
            0x38,
            if self == Self::Byte { 0xf0 } else { 0xf1 },
            0xc1,
        ]);
    }
}

/// Fixed caller-saved register recipe primitives for scalar CRC table lowering.
/// RAX is the W accumulator, RCX is original data, RDX the table index,
/// and R8 the immutable RIP-relative table base. GuestState remains in RDI.
#[derive(Debug, Clone, Copy)]
pub(crate) enum CrcTableInstruction {
    TruncateByteData,
    TruncateHalfwordData,
    TableBaseRip,
    MergeWordData,
    SelectHighDataWord,
    IndexLowByte,
    ShiftAccumulatorByte,
    XorTableEntry,
    JumpOverTable,
    Discard,
}
impl CrcTableInstruction {
    pub(crate) fn emit(self, code: &mut Vec<u8>) {
        code.extend(match self {
            Self::TruncateByteData => &[0x0f, 0xb6, 0xc9][..], // movzx ecx,cl
            Self::TruncateHalfwordData => &[0x0f, 0xb7, 0xc9], // movzx ecx,cx
            Self::TableBaseRip => &[0x4c, 0x8d, 0x05],         // lea r8,[rip+disp32]
            Self::MergeWordData => &[0x31, 0xc8],              // xor eax,ecx
            Self::SelectHighDataWord => &[0x48, 0xc1, 0xe9, 32], // shr rcx,32
            Self::IndexLowByte => &[0x0f, 0xb6, 0xd0],         // movzx edx,al
            Self::ShiftAccumulatorByte => &[0xc1, 0xe8, 8],    // shr eax,8
            Self::XorTableEntry => &[0x41, 0x33, 0x04, 0x90],  // xor eax,[r8+rdx*4]
            Self::JumpOverTable => &[0xe9],                    // jmp rel32
            Self::Discard => &[0x90],                          // nop, nonempty source-map interval
        });
    }
}
