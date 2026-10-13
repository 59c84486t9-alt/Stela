//! Named x86 SIMD output encodings and their minimum feature requirements.
//! Intel SDM instruction entries define these legacy SSE forms. Operand fields
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
    MultiplyLowWord => ("pmullw", Baseline, [0x66,0x0f,0xd5]),
    MultiplyUnsignedDword => ("pmuludq", Baseline, [0x66,0x0f,0xf4]),
    MultiplyLowDword => ("pmulld", Sse41, [0x66,0x0f,0x38,0x40]),
    MultiplySignedDword => ("pmuldq", Sse41, [0x66,0x0f,0x38,0x28]),
    MoveGprQword => ("movq", Baseline, [0x66,0x48,0x0f,0x6e]),
    MoveAligned => ("movdqa", Baseline, [0x66,0x0f,0x6f]),
    ShuffleDword => ("pshufd", Baseline, [0x66,0x0f,0x70]),
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
            target >= self.requires(),
            "selected CPU tier cannot emit {}",
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
