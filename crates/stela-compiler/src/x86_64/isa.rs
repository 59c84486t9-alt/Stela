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
    MoveGprQword => ("movq", Baseline, [0x66,0x48,0x0f,0x6e]),
    MoveAligned => ("movdqa", Baseline, [0x66,0x0f,0x6f]),
    ShuffleDword => ("pshufd", Baseline, [0x66,0x0f,0x70]),
    LoadUnaligned => ("movdqu", Baseline, [0xf3,0x0f,0x6f]),
    StoreUnaligned => ("movdqu", Baseline, [0xf3,0x0f,0x7f]),
    MoveQword => ("movq", Baseline, [0xf3,0x0f,0x7e]),
    ByteShuffle => ("pshufb", Ssse3, [0x66,0x0f,0x38,0x00]),
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
