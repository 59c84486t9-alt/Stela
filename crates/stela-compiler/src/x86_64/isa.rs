//! x86 SIMD opcodes and their minimum CPU features, emitted through the
//! typed encoder with the emitter's register, memory and immediate operands.
use crate::TargetCpu;
use crate::x86_64::asm::{Asm, Code, Gpr, Map, Mem, Pp, Rm, Size, Vex};
use crate::x86_64::simd::encode::gpr;

/// How a catalog opcode is encoded.
#[derive(Debug, Clone, Copy)]
enum Form {
    /// Legacy SSE: an optional mandatory prefix and the opcode bytes.
    Sse(Option<u8>, &'static [u8]),
    /// Legacy SSE with REX.W, whose r/m operand is a general register.
    Wide(Option<u8>, &'static [u8]),
    /// VEX.128.W0 with no VEX.vvvv operand.
    Vex(Pp, Map, u8),
}

macro_rules! legacy_prefix {
    (P66) => {
        0x66
    };
    (Pf3) => {
        0xf3
    };
    (Pf2) => {
        0xf2
    };
}

macro_rules! form {
    (form [$($opcode:literal),+]) => {
        Form::Sse(None, &[$($opcode),+])
    };
    (form $prefix:ident [$($opcode:literal),+]) => {
        Form::Sse(Some(legacy_prefix!($prefix)), &[$($opcode),+])
    };
    (form $prefix:ident W [$($opcode:literal),+]) => {
        Form::Wide(Some(legacy_prefix!($prefix)), &[$($opcode),+])
    };
    (form Vex $pp:ident $map:ident $opcode:literal) => {
        Form::Vex(Pp::$pp, Map::$map, $opcode)
    };
    (bytes [$($opcode:literal),+]) => {
        &[$($opcode),+]
    };
    (bytes $prefix:ident [$($opcode:literal),+]) => {
        &[legacy_prefix!($prefix), $($opcode),+]
    };
    (bytes $prefix:ident W [$($opcode:literal),+]) => {
        &[legacy_prefix!($prefix), 0x48, $($opcode),+]
    };
    (bytes Vex $pp:ident $map:ident $opcode:literal) => {{
        const BYTES: &[u8] = &[0xc4, 0xe0 | Map::$map as u8, 0x78 | Pp::$pp as u8, $opcode];
        BYTES
    }};
}

macro_rules! catalog {
    ($($name:ident => ($mnemonic:literal, $cpu:ident, $($form:tt)+)),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum SimdOpcode { $($name),+ }
        impl SimdOpcode {
            pub const ALL: &'static [Self] = &[$(Self::$name),+];
            pub fn mnemonic(self) -> &'static str { match self { $(Self::$name => $mnemonic),+ } }
            pub fn requires(self) -> TargetCpu { match self { $(Self::$name => TargetCpu::$cpu),+ } }
            /// The prefix and opcode bytes with registers 0 to 7: the
            /// mandatory prefix, any REX.W or VEX prefix, and the opcode.
            pub fn encoding(self) -> &'static [u8] { match self { $(Self::$name => form!(bytes $($form)+)),+ } }
            fn form(self) -> Form { match self { $(Self::$name => form!(form $($form)+)),+ } }
        }
    };
}
catalog! {
    AesEncryptRound => ("aesenc", Aes, P66 [0x0f, 0x38, 0xdc]),
    AesEncryptLast => ("aesenclast", Aes, P66 [0x0f, 0x38, 0xdd]),
    AesDecryptRound => ("aesdec", Aes, P66 [0x0f, 0x38, 0xde]),
    AesDecryptLast => ("aesdeclast", Aes, P66 [0x0f, 0x38, 0xdf]),
    AesInverseMixColumns => ("aesimc", Aes, P66 [0x0f, 0x38, 0xdb]),
    HorizontalAddDword => ("phaddd", Ssse3, P66 [0x0f, 0x38, 0x02]),
    Sha1Rounds4 => ("sha1rnds4", Sha, [0x0f, 0x3a, 0xcc]),
    Sha1Message2 => ("sha1msg2", Sha, [0x0f, 0x38, 0xca]),
    Sha256Rounds2 => ("sha256rnds2", Sha, [0x0f, 0x38, 0xcb]),
    Sha256Message1 => ("sha256msg1", Sha, [0x0f, 0x38, 0xcc]),
    Sha256Message2 => ("sha256msg2", Sha, [0x0f, 0x38, 0xcd]),
    And => ("pand", Baseline, P66 [0x0f, 0xdb]),
    AndNot => ("pandn", Baseline, P66 [0x0f, 0xdf]),
    Or => ("por", Baseline, P66 [0x0f, 0xeb]),
    Xor => ("pxor", Baseline, P66 [0x0f, 0xef]),
    EqualByte => ("pcmpeqb", Baseline, P66 [0x0f, 0x74]),
    EqualWord => ("pcmpeqw", Baseline, P66 [0x0f, 0x75]),
    EqualDword => ("pcmpeqd", Baseline, P66 [0x0f, 0x76]),
    EqualQword => ("pcmpeqq", Sse41, P66 [0x0f, 0x38, 0x29]),
    GreaterByte => ("pcmpgtb", Baseline, P66 [0x0f, 0x64]),
    GreaterWord => ("pcmpgtw", Baseline, P66 [0x0f, 0x65]),
    GreaterDword => ("pcmpgtd", Baseline, P66 [0x0f, 0x66]),
    GreaterQword => ("pcmpgtq", Sse42, P66 [0x0f, 0x38, 0x37]),
    AddByte => ("paddb", Baseline, P66 [0x0f, 0xfc]),
    AddWord => ("paddw", Baseline, P66 [0x0f, 0xfd]),
    AddDword => ("paddd", Baseline, P66 [0x0f, 0xfe]),
    AddQword => ("paddq", Baseline, P66 [0x0f, 0xd4]),
    SubByte => ("psubb", Baseline, P66 [0x0f, 0xf8]),
    SubWord => ("psubw", Baseline, P66 [0x0f, 0xf9]),
    SubDword => ("psubd", Baseline, P66 [0x0f, 0xfa]),
    SubQword => ("psubq", Baseline, P66 [0x0f, 0xfb]),
    AbsByte => ("pabsb", Ssse3, P66 [0x0f, 0x38, 0x1c]),
    AbsWord => ("pabsw", Ssse3, P66 [0x0f, 0x38, 0x1d]),
    AbsDword => ("pabsd", Ssse3, P66 [0x0f, 0x38, 0x1e]),
    UnpackLowQword => ("punpcklqdq", Baseline, P66 [0x0f, 0x6c]),
    UnpackLowByte => ("punpcklbw", Baseline, P66 [0x0f, 0x60]),
    UnpackLowWord => ("punpcklwd", Baseline, P66 [0x0f, 0x61]),
    UnpackLowDword => ("punpckldq", Baseline, P66 [0x0f, 0x62]),
    PackUnsignedWordToByte => ("packuswb", Baseline, P66 [0x0f, 0x67]),
    PackSignedDwordToWord => ("packssdw", Baseline, P66 [0x0f, 0x6b]),
    UnpackHighByte => ("punpckhbw", Baseline, P66 [0x0f, 0x68]),
    UnpackHighWord => ("punpckhwd", Baseline, P66 [0x0f, 0x69]),
    UnpackHighDword => ("punpckhdq", Baseline, P66 [0x0f, 0x6a]),
    UnpackHighQword => ("punpckhqdq", Baseline, P66 [0x0f, 0x6d]),
    MinUnsignedByte => ("pminub", Baseline, P66 [0x0f, 0xda]),
    MaxUnsignedByte => ("pmaxub", Baseline, P66 [0x0f, 0xde]),
    MinSignedWord => ("pminsw", Baseline, P66 [0x0f, 0xea]),
    MaxSignedWord => ("pmaxsw", Baseline, P66 [0x0f, 0xee]),
    MinSignedByte => ("pminsb", Sse41, P66 [0x0f, 0x38, 0x38]),
    MaxSignedByte => ("pmaxsb", Sse41, P66 [0x0f, 0x38, 0x3c]),
    MinUnsignedWord => ("pminuw", Sse41, P66 [0x0f, 0x38, 0x3a]),
    MaxUnsignedWord => ("pmaxuw", Sse41, P66 [0x0f, 0x38, 0x3e]),
    MinSignedDword => ("pminsd", Sse41, P66 [0x0f, 0x38, 0x39]),
    MaxSignedDword => ("pmaxsd", Sse41, P66 [0x0f, 0x38, 0x3d]),
    MinUnsignedDword => ("pminud", Sse41, P66 [0x0f, 0x38, 0x3b]),
    MaxUnsignedDword => ("pmaxud", Sse41, P66 [0x0f, 0x38, 0x3f]),
    AddSignedSaturatingByte => ("paddsb", Baseline, P66 [0x0f, 0xec]),
    AddSignedSaturatingWord => ("paddsw", Baseline, P66 [0x0f, 0xed]),
    AddUnsignedSaturatingByte => ("paddusb", Baseline, P66 [0x0f, 0xdc]),
    AddUnsignedSaturatingWord => ("paddusw", Baseline, P66 [0x0f, 0xdd]),
    SubSignedSaturatingByte => ("psubsb", Baseline, P66 [0x0f, 0xe8]),
    SubSignedSaturatingWord => ("psubsw", Baseline, P66 [0x0f, 0xe9]),
    SubUnsignedSaturatingByte => ("psubusb", Baseline, P66 [0x0f, 0xd8]),
    SubUnsignedSaturatingWord => ("psubusw", Baseline, P66 [0x0f, 0xd9]),
    PackSignedWordToByte => ("packsswb", Baseline, P66 [0x0f, 0x63]),
    PackUnsignedDwordToWord => ("packusdw", Sse41, P66 [0x0f, 0x38, 0x2b]),
    ByteSignMask => ("pmovmskb", Baseline, P66 [0x0f, 0xd7]),
    DwordSignMask => ("movmskps", Baseline, [0x0f, 0x50]),
    MultiplyLowWord => ("pmullw", Baseline, P66 [0x0f, 0xd5]),
    MultiplyHighSignedWord => ("pmulhw", Baseline, P66 [0x0f, 0xe5]),
    MultiplyHighUnsignedWord => ("pmulhuw", Baseline, P66 [0x0f, 0xe4]),
    MultiplyHighRoundedScaledWord => ("pmulhrsw", Ssse3, P66 [0x0f, 0x38, 0x0b]),
    MultiplyUnsignedDword => ("pmuludq", Baseline, P66 [0x0f, 0xf4]),
    MultiplyLowDword => ("pmulld", Sse41, P66 [0x0f, 0x38, 0x40]),
    MultiplySignedDword => ("pmuldq", Sse41, P66 [0x0f, 0x38, 0x28]),
    CarrylessMultiplyQword => ("pclmulqdq", Pclmulqdq, P66 [0x0f, 0x3a, 0x44]),
    AverageByte => ("pavgb", Baseline, P66 [0x0f, 0xe0]),
    AverageWord => ("pavgw", Baseline, P66 [0x0f, 0xe3]),
    MultiplyAddWords => ("pmaddwd", Baseline, P66 [0x0f, 0xf5]),
    MultiplyAddUnsignedBytes => ("pmaddubsw", Ssse3, P66 [0x0f, 0x38, 0x04]),
    SignExtendByteToWord => ("pmovsxbw", Sse41, P66 [0x0f, 0x38, 0x20]),
    ZeroExtendByteToWord => ("pmovzxbw", Sse41, P66 [0x0f, 0x38, 0x30]),
    MinimumPositionWord => ("phminposuw", Sse41, P66 [0x0f, 0x38, 0x41]),
    SignExtendWordToDword => ("pmovsxwd", Sse41, P66 [0x0f, 0x38, 0x23]),
    ZeroExtendWordToDword => ("pmovzxwd", Sse41, P66 [0x0f, 0x38, 0x33]),
    SignExtendWordToQword => ("pmovsxwq", Sse41, P66 [0x0f, 0x38, 0x24]),
    ZeroExtendWordToQword => ("pmovzxwq", Sse41, P66 [0x0f, 0x38, 0x34]),
    SignExtendDwordToQword => ("pmovsxdq", Sse41, P66 [0x0f, 0x38, 0x25]),
    ZeroExtendDwordToQword => ("pmovzxdq", Sse41, P66 [0x0f, 0x38, 0x35]),
    RoundPackedSingle => ("roundps", Sse41, P66 [0x0f, 0x3a, 0x08]),
    RoundPackedDouble => ("roundpd", Sse41, P66 [0x0f, 0x3a, 0x09]),
    RoundScalarSingle => ("roundss", Sse41, P66 [0x0f, 0x3a, 0x0a]),
    RoundScalarDouble => ("roundsd", Sse41, P66 [0x0f, 0x3a, 0x0b]),
    InsertSingle => ("insertps", Sse41, P66 [0x0f, 0x3a, 0x21]),
    SquareRootPackedSingle => ("sqrtps", Baseline, [0x0f, 0x51]),
    SquareRootPackedDouble => ("sqrtpd", Baseline, P66 [0x0f, 0x51]),
    SquareRootScalarSingle => ("sqrtss", Baseline, Pf3 [0x0f, 0x51]),
    SquareRootScalarDouble => ("sqrtsd", Baseline, Pf2 [0x0f, 0x51]),
    ReciprocalPackedSingle => ("rcpps", Baseline, [0x0f, 0x53]),
    ConvertPackedDwordToSingle => ("cvtdq2ps", Baseline, [0x0f, 0x5b]),
    ConvertPackedSingleToDword => ("cvtps2dq", Baseline, P66 [0x0f, 0x5b]),
    ConvertHalfToSingle => ("vcvtph2ps", F16c, Vex P66 M0f38 0x13),
    ConvertSingleToHalf => ("vcvtps2ph", F16c, Vex P66 M0f3a 0x1d),
    MoveGprQword => ("movq", Baseline, P66 W [0x0f, 0x6e]),
    MoveAligned => ("movdqa", Baseline, P66 [0x0f, 0x6f]),
    ShuffleDword => ("pshufd", Baseline, P66 [0x0f, 0x70]),
    ShuffleLowWord => ("pshuflw", Baseline, Pf2 [0x0f, 0x70]),
    ShuffleHighWord => ("pshufhw", Baseline, Pf3 [0x0f, 0x70]),
    LoadUnaligned => ("movdqu", Baseline, Pf3 [0x0f, 0x6f]),
    StoreUnaligned => ("movdqu", Baseline, Pf3 [0x0f, 0x7f]),
    MoveQword => ("movq", Baseline, Pf3 [0x0f, 0x7e]),
    MoveScalarSingle => ("movss", Baseline, Pf3 [0x0f, 0x10]),
    MoveScalarDouble => ("movsd", Baseline, Pf2 [0x0f, 0x10]),
    ByteShuffle => ("pshufb", Ssse3, P66 [0x0f, 0x38, 0x00]),
    AlignBytes => ("palignr", Ssse3, P66 [0x0f, 0x3a, 0x0f]),
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
    LeftBytes,
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
        Self::LeftBytes,
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
            Self::LeftBytes => ("pslldq", 0x73, 7),
            Self::RightBytes => ("psrldq", 0x73, 3),
        }
    }
    /// Shift XMM `register` by `amount`.
    pub(crate) fn emit(self, code: &mut Code, register: u8, amount: u8) {
        code.asm().sse_imm(
            Some(0x66),
            &[0x0f, self.opcode()],
            self.group(),
            Rm::Xmm(register),
            amount,
        );
    }
}
impl SimdOpcode {
    fn check(self, target: TargetCpu) {
        assert!(
            target.supports(self.requires()),
            "selected CPU requirements cannot emit {}",
            self.mnemonic()
        );
    }
    /// This opcode with ModRM.reg `register` and r/m `rm`.
    pub(crate) fn emit(self, code: &mut Code, register: u8, rm: impl Into<Rm>, target: TargetCpu) {
        code.asm().simd(self, register, rm, target);
    }
    /// [`Self::emit`] with an 8-bit immediate.
    pub(crate) fn emit_imm(
        self,
        code: &mut Code,
        register: u8,
        rm: impl Into<Rm>,
        immediate: u8,
        target: TargetCpu,
    ) {
        self.emit(code, register, rm, target);
        code.asm().data(&[immediate]);
    }
    /// This opcode on registers: XMM `destination` and XMM `source`, or the
    /// general register numbered `source` for [`Self::MoveGprQword`].
    pub(crate) fn register(self, code: &mut Code, destination: u8, source: u8, target: TargetCpu) {
        let source = match self.form() {
            Form::Wide(..) => Rm::Reg(gpr(source)),
            _ => Rm::Xmm(source),
        };
        self.emit(code, destination, source, target);
    }
    /// [`Self::register`] with an 8-bit immediate.
    pub(crate) fn register_imm(
        self,
        code: &mut Code,
        destination: u8,
        source: u8,
        immediate: u8,
        target: TargetCpu,
    ) {
        self.register(code, destination, source, target);
        code.asm().data(&[immediate]);
    }
}

impl Asm<'_> {
    /// The catalog instruction `opcode` with ModRM.reg `register` and r/m
    /// `rm`; the selected CPU must provide its features.
    pub(crate) fn simd(
        &mut self,
        opcode: SimdOpcode,
        register: u8,
        rm: impl Into<Rm>,
        target: TargetCpu,
    ) {
        opcode.check(target);
        match opcode.form() {
            Form::Sse(prefix, bytes) => self.sse(prefix, bytes, register, rm),
            Form::Wide(prefix, bytes) => {
                self.legacy(Size::Qword, prefix, bytes, register, false, rm.into());
            }
            Form::Vex(pp, map, byte) => self.vex(
                Vex {
                    map,
                    pp,
                    w: false,
                    l: false,
                },
                byte,
                register,
                0,
                rm.into(),
            ),
        }
    }
    /// The catalog instruction `opcode` writing general-purpose
    /// `destination` from `xmm` (PMOVMSKB, MOVMSKPS).
    pub(crate) fn simd_to_gpr(
        &mut self,
        opcode: SimdOpcode,
        destination: Gpr,
        xmm: u8,
        target: TargetCpu,
    ) {
        self.simd(opcode, destination as u8, Rm::Xmm(xmm), target);
    }
    /// [`Self::simd`] with an 8-bit immediate.
    pub(crate) fn simd_imm(
        &mut self,
        opcode: SimdOpcode,
        register: u8,
        rm: impl Into<Rm>,
        immediate: u8,
        target: TargetCpu,
    ) {
        self.simd(opcode, register, rm, target);
        self.data(&[immediate]);
    }
}

/// AVX2 per-element shifts used by fixed 128-bit scalable chunks. The full
/// unsigned dword/qword count is consumed; logical overflow zeroes the lane and
/// arithmetic dword overflow sign-fills it. No EFLAGS or MXCSR effects occur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VexShiftOpcode {
    LeftDword,
    RightDword,
    ArithmeticDword,
    LeftQword,
    RightQword,
}

impl VexShiftOpcode {
    pub(crate) fn register(
        self,
        code: &mut Code,
        destination: u8,
        source: u8,
        counts: u8,
        target: TargetCpu,
    ) {
        assert!(
            target.supports(TargetCpu::Avx2),
            "AVX2 shifts require usable AVX2 state"
        );
        let (opcode, w) = match self {
            Self::LeftDword => (0x47, false),
            Self::RightDword => (0x45, false),
            Self::ArithmeticDword => (0x46, false),
            Self::LeftQword => (0x47, true),
            Self::RightQword => (0x45, true),
        };
        // VEX.vvvv names the data source, ModRM.rm the per-element counts.
        code.asm().vex(
            Vex {
                map: Map::M0f38,
                pp: Pp::P66,
                w,
                l: false,
            },
            opcode,
            destination,
            source,
            Rm::Xmm(counts),
        );
    }
}

/// Clear caller-volatile upper vector state before an AVX2 body starts mixing
/// VEX128 arithmetic with its legacy SSE state-access and predication wrapper.
pub(crate) fn clear_upper_vector_state(code: &mut Code, target: TargetCpu) {
    assert!(
        target.supports(TargetCpu::Avx2),
        "VZEROUPPER requires usable AVX state"
    );
    code.asm().vzeroupper();
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
    pub(crate) fn emit(self, code: &mut Code, target: TargetCpu) {
        assert!(target.supports(TargetCpu::Sse42));
        let (size, opcode) = match self {
            Self::Byte => (Size::Byte, 0xf0),
            Self::Halfword => (Size::Word, 0xf1),
            Self::Word => (Size::Dword, 0xf1),
            Self::Doubleword => (Size::Qword, 0xf1),
        };
        // F2 ahead of the operand-size prefix, as the SDM lists CRC32.
        let mut asm = code.asm();
        asm.prefix(0xf2);
        asm.legacy(
            size,
            None,
            &[0x0f, 0x38, opcode],
            0,
            false,
            Rm::Reg(Gpr::Rcx),
        );
    }
}

/// Register recipe for the table-driven CRC: RAX is the W accumulator, RCX the
/// data, RDX the table index and R8 the RIP-relative table base, which the
/// caller loads. RDI holds GuestState.
#[derive(Debug, Clone, Copy)]
pub(crate) enum CrcTableInstruction {
    TruncateByteData,
    TruncateHalfwordData,
    MergeWordData,
    SelectHighDataWord,
    IndexLowByte,
    ShiftAccumulatorByte,
    XorTableEntry,
    Discard,
}
impl CrcTableInstruction {
    /// Emit this step.
    pub(crate) fn emit(self, code: &mut Code) {
        use crate::x86_64::asm::{Alu, ShiftOp};
        use Gpr::{R8, Rax, Rcx, Rdx};
        let mut asm = code.asm();
        match self {
            Self::TruncateByteData => asm.movzx(Size::Dword, Rcx, Size::Byte, Rcx),
            Self::TruncateHalfwordData => asm.movzx(Size::Dword, Rcx, Size::Word, Rcx),
            Self::MergeWordData => asm.alu(Alu::Xor, Size::Dword, Rax, Rcx),
            Self::SelectHighDataWord => asm.shift_imm(ShiftOp::Shr, Size::Qword, Rcx, 32),
            Self::IndexLowByte => asm.movzx(Size::Dword, Rdx, Size::Byte, Rax),
            Self::ShiftAccumulatorByte => asm.shift_imm(ShiftOp::Shr, Size::Dword, Rax, 8),
            Self::XorTableEntry => {
                asm.alu_load(Alu::Xor, Size::Dword, Rax, Mem::indexed(R8, Rdx, 4, 0));
            }
            // A nonempty source-map interval.
            Self::Discard => asm.nop(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn avx2_shift_encodings_keep_data_count_and_destination_fields_distinct() {
        for (opcode, operation, width) in [
            (VexShiftOpcode::LeftDword, 0x47, 0),
            (VexShiftOpcode::RightDword, 0x45, 0),
            (VexShiftOpcode::ArithmeticDword, 0x46, 0),
            (VexShiftOpcode::LeftQword, 0x47, 0x80),
            (VexShiftOpcode::RightQword, 0x45, 0x80),
        ] {
            let mut code = Code::new();
            opcode.register(&mut code, 3, 6, 7, TargetCpu::Avx2);
            assert_eq!(code, [0xc4, 0xe2, width | 0x49, operation, 0xdf]);
            for target in [TargetCpu::Baseline, TargetCpu::Sse42, TargetCpu::Fma] {
                code.clear();
                let declined = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    opcode.register(&mut code, 0, 0, 1, target);
                }));
                assert!(declined.is_err());
                assert!(code.is_empty());
            }
        }
    }

    #[test]
    fn word_to_qword_widening_requires_checked_sse41() {
        for (opcode, mnemonic, encoding) in [
            (
                SimdOpcode::SignExtendWordToQword,
                "pmovsxwq",
                [0x66, 0x0f, 0x38, 0x24],
            ),
            (
                SimdOpcode::ZeroExtendWordToQword,
                "pmovzxwq",
                [0x66, 0x0f, 0x38, 0x34],
            ),
        ] {
            assert_eq!(opcode.mnemonic(), mnemonic);
            assert_eq!(opcode.encoding(), encoding);
            assert_eq!(opcode.requires(), TargetCpu::Sse41);
            for target in [TargetCpu::Baseline, TargetCpu::Ssse3] {
                let mut code = Code::new();
                let declined = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    opcode.register(&mut code, 0, 1, target)
                }));
                assert!(declined.is_err());
                assert!(code.is_empty());
            }
            for target in [TargetCpu::Sse41, TargetCpu::Sse42] {
                let mut code = Code::new();
                opcode.register(&mut code, 0, 1, target);
                assert_eq!(code, [&encoding[..], &[0xc1]].concat());
            }
        }
    }

    #[test]
    fn signed_byte_widening_requires_checked_sse41() {
        let opcode = SimdOpcode::SignExtendByteToWord;
        let encoding = [0x66, 0x0f, 0x38, 0x20];
        assert_eq!(opcode.mnemonic(), "pmovsxbw");
        assert_eq!(opcode.encoding(), encoding);
        assert_eq!(opcode.requires(), TargetCpu::Sse41);
        for target in [TargetCpu::Baseline, TargetCpu::Ssse3] {
            let mut code = Code::new();
            let declined = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                opcode.register(&mut code, 0, 1, target);
            }));
            assert!(declined.is_err());
            assert!(code.is_empty());
        }
        for target in [TargetCpu::Sse41, TargetCpu::Sse42] {
            let mut code = Code::new();
            opcode.register(&mut code, 0, 1, target);
            assert_eq!(code, [&encoding[..], &[0xc1]].concat());
        }
    }

    #[test]
    fn catalog_forms_match_their_encodings() {
        use Gpr::*;
        let one = |build: &dyn Fn(&mut Asm)| {
            let mut code = Code::new();
            build(&mut code.asm());
            assert_eq!(code.instructions(), 1);
            code
        };
        let v3 = TargetCpu::X86_64_V3;
        for (expected, code) in [
            (
                &[0x66, 0x0f, 0xdb, 0xca][..],
                one(&|a| a.simd(SimdOpcode::And, 1, Rm::Xmm(2), v3)),
            ),
            (
                &[0x66, 0x48, 0x0f, 0x6e, 0xf8],
                one(&|a| a.simd(SimdOpcode::MoveGprQword, 7, Rax, v3)),
            ),
            (
                &[0x0f, 0x50, 0xc1],
                one(&|a| a.simd_to_gpr(SimdOpcode::DwordSignMask, Rax, 1, v3)),
            ),
            (
                &[0x66, 0x0f, 0x70, 0xc1, 0x1b],
                one(&|a| a.simd_imm(SimdOpcode::ShuffleDword, 0, Rm::Xmm(1), 0x1b, v3)),
            ),
            (
                &[0xf3, 0x0f, 0x6f, 0x87, 8, 1, 0, 0],
                one(&|a| {
                    a.simd(
                        SimdOpcode::LoadUnaligned,
                        0,
                        Mem::base_disp32(Rdi, 0x108),
                        v3,
                    )
                }),
            ),
            (
                &[0xc4, 0xe2, 0x79, 0x13, 0xc1],
                one(&|a| a.simd(SimdOpcode::ConvertHalfToSingle, 0, Rm::Xmm(1), v3)),
            ),
            (
                &[0xc4, 0xe3, 0x79, 0x1d, 0xc8, 4],
                one(&|a| a.simd_imm(SimdOpcode::ConvertSingleToHalf, 1, Rm::Xmm(0), 4, v3)),
            ),
        ] {
            assert_eq!(code, expected);
        }
    }

    #[test]
    #[should_panic(expected = "selected CPU requirements cannot emit pmulld")]
    fn catalog_forms_require_their_features() {
        Code::new().asm().simd(
            SimdOpcode::MultiplyLowDword,
            0,
            Rm::Xmm(1),
            TargetCpu::Baseline,
        );
    }
}
