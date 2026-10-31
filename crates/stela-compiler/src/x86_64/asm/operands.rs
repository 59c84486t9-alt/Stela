//! Typed x86 register, memory, opcode and branch operands.
/// General-purpose registers by encoding number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Gpr {
    Rax,
    Rcx,
    Rdx,
    Rbx,
    Rsp,
    Rbp,
    Rsi,
    Rdi,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    R16,
    R17,
    R18,
    R19,
    R20,
    R21,
    R22,
    R23,
    R24,
    R25,
    R26,
    R27,
    R28,
    R29,
    R30,
    R31,
}

impl Gpr {
    /// Checked architectural encoding, including the APX extended bank.
    pub(crate) const fn from_encoding(number: u8) -> Self {
        use Gpr::*;
        const REGISTERS: [Gpr; 32] = [
            Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi, R8, R9, R10, R11, R12, R13, R14, R15, R16, R17,
            R18, R19, R20, R21, R22, R23, R24, R25, R26, R27, R28, R29, R30, R31,
        ];
        assert!(number < 32, "GPR encoding must be in zero through31");
        REGISTERS[number as usize]
    }
    pub(crate) const fn number(self) -> u8 {
        self as u8
    }
    pub(super) const fn low(self) -> u8 {
        self as u8 & 7
    }
    pub(super) const fn high(self) -> bool {
        self as u8 & 8 != 0
    }
}

/// Operand sizes of integer instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Size {
    Byte,
    Word,
    Dword,
    Qword,
}

impl Size {
    /// The 32- or 64-bit size of an A64 W or X register operation.
    pub(crate) const fn of(wide: bool) -> Self {
        if wide { Self::Qword } else { Self::Dword }
    }
    pub(crate) const fn bits(self) -> u32 {
        match self {
            Self::Byte => 8,
            Self::Word => 16,
            Self::Dword => 32,
            Self::Qword => 64,
        }
    }
}

/// `[base + index * scale + displacement]`, or `[rip + displacement]` when
/// `base` is `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Mem {
    pub base: Option<Gpr>,
    pub index: Option<(Gpr, u8)>,
    pub displacement: i32,
    pub width: Disp,
}

/// How a base register's displacement is encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Disp {
    /// The shortest form: none for zero (but RBP and R13), else 8 or 32 bits.
    Auto,
    /// An 8-bit field, even for zero.
    Byte,
    /// A 32-bit field, even when 8 bits would do.
    Dword,
}

impl Mem {
    pub(crate) const fn base(base: Gpr, displacement: i32) -> Self {
        Self {
            base: Some(base),
            index: None,
            displacement,
            width: Disp::Auto,
        }
    }
    /// `[base + displacement]` with a 32-bit displacement field.
    pub(crate) const fn base_disp32(base: Gpr, displacement: i32) -> Self {
        Self {
            width: Disp::Dword,
            ..Self::base(base, displacement)
        }
    }
    /// `[base + displacement]` with an 8-bit displacement field.
    pub(crate) const fn base_disp8(base: Gpr, displacement: i8) -> Self {
        Self {
            width: Disp::Byte,
            ..Self::base(base, displacement as i32)
        }
    }
    /// This operand with its displacement field `width`.
    pub(crate) const fn with_width(self, width: Disp) -> Self {
        Self { width, ..self }
    }
    /// `[rip + displacement]`.
    pub(crate) const fn rip(displacement: i32) -> Self {
        Self {
            base: None,
            index: None,
            displacement,
            width: Disp::Dword,
        }
    }
    pub(crate) const fn indexed(base: Gpr, index: Gpr, scale: u8, displacement: i32) -> Self {
        Self {
            base: Some(base),
            index: Some((index, scale)),
            displacement,
            width: Disp::Auto,
        }
    }
}

/// A register or memory operand (the ModRM r/m field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rm {
    Reg(Gpr),
    Xmm(u8),
    Mem(Mem),
}

impl From<Gpr> for Rm {
    fn from(register: Gpr) -> Self {
        Self::Reg(register)
    }
}

impl From<Mem> for Rm {
    fn from(memory: Mem) -> Self {
        Self::Mem(memory)
    }
}

impl Rm {
    /// REX.X and REX.B.
    pub(super) fn extensions(self) -> (bool, bool) {
        match self {
            Self::Reg(register) => (false, register.high()),
            Self::Xmm(register) => (false, register & 8 != 0),
            Self::Mem(memory) => (
                memory.index.is_some_and(|(index, _)| index.high()),
                memory.base.is_some_and(Gpr::high),
            ),
        }
    }
    /// Fifth index/base bits for the APX general-purpose register bank.
    pub(super) fn extended_extensions(self) -> (bool, bool) {
        match self {
            Self::Reg(register) => (false, register.number() & 16 != 0),
            Self::Xmm(_) => (false, false),
            Self::Mem(memory) => (
                memory
                    .index
                    .is_some_and(|(index, _)| index.number() & 16 != 0),
                memory.base.is_some_and(|base| base.number() & 16 != 0),
            ),
        }
    }
    /// Whether a byte-sized access to this operand needs a REX prefix to
    /// name SPL, BPL, SIL or DIL.
    pub(super) fn needs_byte_rex(self) -> bool {
        matches!(self, Self::Reg(register) if (4..8).contains(&register.number()))
    }
}

/// Two-operand ALU operations, numbered by their ModRM reg digit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Alu {
    Add,
    Or,
    Adc,
    Sbb,
    And,
    Sub,
    Xor,
    Cmp,
}

/// Group 2 rotate and shift operations, numbered by their ModRM reg digit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum ShiftOp {
    Rol = 0,
    Ror = 1,
    Shl = 4,
    Shr = 5,
    Sar = 7,
}

/// Condition codes, numbered as in Jcc, SETcc and CMOVcc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Cond {
    O,
    No,
    B,
    Ae,
    E,
    Ne,
    Be,
    A,
    S,
    Ns,
    P,
    Np,
    L,
    Ge,
    Le,
    G,
}

impl Cond {
    /// The condition that holds exactly when this one does not.
    pub(crate) const fn negate(self) -> Self {
        use Cond::*;
        match self {
            O => No,
            No => O,
            B => Ae,
            Ae => B,
            E => Ne,
            Ne => E,
            Be => A,
            A => Be,
            S => Ns,
            Ns => S,
            P => Np,
            Np => P,
            L => Ge,
            Ge => L,
            Le => G,
            G => Le,
        }
    }
}

/// Group 3 unary operations, numbered by their ModRM reg digit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Unary {
    Not = 2,
    Neg = 3,
    Mul = 4,
    Imul = 5,
    Div = 6,
    Idiv = 7,
}

/// The VEX opcode maps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Map {
    M0f = 1,
    M0f38 = 2,
    M0f3a = 3,
    /// EVEX only: AVX512-FP16's maps 5 and 6.
    M5 = 5,
    M6 = 6,
}

/// VEX implied mandatory prefixes (VEX.pp).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Pp {
    None = 0,
    P66 = 1,
    Pf3 = 2,
    Pf2 = 3,
}

/// The fields of a VEX prefix besides its registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Vex {
    pub(crate) map: Map,
    pub(crate) pp: Pp,
    /// VEX.W: a 64-bit general-purpose operand size.
    pub(crate) w: bool,
    /// VEX.L: 256-bit vectors.
    pub(crate) l: bool,
}

/// The displacement field of a rel8 or rel32 branch, resolved by
/// [`super::Asm::bind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub(crate) struct Patch {
    pub(super) at: usize,
    pub(super) short: bool,
}

impl Patch {
    /// The offset of the displacement field in the code.
    pub(crate) const fn offset(self) -> usize {
        self.at
    }
    /// The offset just past the branch, which its displacement counts from.
    pub(crate) const fn end(self) -> usize {
        self.at + if self.short { 1 } else { 4 }
    }
}

/// The fields of an EVEX prefix besides its registers (SDM Vol. 2A 2.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Evex {
    pub(crate) map: Map,
    pub(crate) pp: Pp,
    pub(crate) w: bool,
    /// EVEX.L'L: 0, 1 and 2 for 128, 256 and 512 bits.
    pub(crate) length: u8,
    /// EVEX.aaa: the opmask register, zero for none.
    pub(crate) mask: u8,
    /// EVEX.z: zero masked elements instead of merging.
    pub(crate) zeroing: bool,
    /// EVEX.b: embedded broadcast for memory, or rounding control.
    pub(crate) broadcast: bool,
    /// N of the compressed disp8*N displacement (SDM 2.7.5).
    pub(crate) scale: u8,
}
