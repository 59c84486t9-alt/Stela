//! A typed x86-64 encoder (Intel SDM Vol. 2, chapter 2). Operands are typed
//! registers and memory; operand-size prefixes, REX, VEX, ModRM, SIB and
//! displacements are derived from them, and [`Asm`] counts every instruction
//! it emits.
//!
//! Emitters take a [`Code`], which carries the instruction count across
//! every [`Asm`] built over it.
//!
use alloc::vec::Vec;

pub(crate) mod control;
mod integer;
pub(crate) mod memory;
mod sse;
pub(crate) mod vector_extensions;
pub(crate) use integer::BitTest;
pub(crate) use sse::{FloatLanes, FloatOp};

/// Emitted bytes and the number of instructions among them.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Code {
    bytes: Vec<u8>,
    instructions: usize,
}

/// A byte and instruction position captured at an emission boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Checkpoint {
    bytes: usize,
    instructions: usize,
}

impl Checkpoint {
    pub(crate) const fn offset(self) -> usize {
        self.bytes
    }
}

impl Code {
    pub(crate) const fn new() -> Self {
        Self {
            bytes: Vec::new(),
            instructions: 0,
        }
    }
    /// An encoder that appends here and adds to this count.
    pub(crate) fn asm(&mut self) -> Asm<'_> {
        Asm {
            code: &mut self.bytes,
            instructions: 0,
            shared: Some(&mut self.instructions),
        }
    }
    /// The instructions emitted through [`Self::asm`].
    pub(crate) const fn instructions(&self) -> usize {
        self.instructions
    }
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
    /// Append `other`'s bytes and instructions.
    pub(crate) fn append(&mut self, other: Code) {
        self.bytes.extend(other.bytes);
        self.instructions += other.instructions;
    }
    /// The current emission boundary, for splitting or truncating this buffer.
    pub(crate) fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            bytes: self.bytes.len(),
            instructions: self.instructions,
        }
    }
    /// Move the instructions emitted after `at` into a separate buffer.
    pub(crate) fn split_off(&mut self, at: Checkpoint) -> Self {
        assert!(at.bytes <= self.bytes.len() && at.instructions <= self.instructions);
        let tail = Self {
            bytes: self.bytes.split_off(at.bytes),
            instructions: self.instructions - at.instructions,
        };
        self.instructions = at.instructions;
        tail
    }
    /// Discard the instructions emitted after `at`.
    pub(crate) fn truncate(&mut self, at: Checkpoint) {
        assert!(at.bytes <= self.bytes.len() && at.instructions <= self.instructions);
        self.bytes.truncate(at.bytes);
        self.instructions = at.instructions;
    }
    /// Remove one complete instruction whose bytes the caller identified.
    pub(crate) fn remove_instruction(&mut self, range: core::ops::Range<usize>) {
        assert!(!range.is_empty());
        self.bytes.drain(range);
        self.instructions = self
            .instructions
            .checked_sub(1)
            .expect("counted instruction");
    }
    /// Remove every byte and instruction.
    #[cfg(test)]
    pub(crate) fn clear(&mut self) {
        self.bytes.clear();
        self.instructions = 0;
    }
}

impl From<Vec<u8>> for Code {
    fn from(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            instructions: 0,
        }
    }
}

impl PartialEq<[u8]> for Code {
    fn eq(&self, other: &[u8]) -> bool {
        self.bytes == other
    }
}

impl PartialEq<Vec<u8>> for Code {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.bytes == *other
    }
}

impl<const N: usize> PartialEq<[u8; N]> for Code {
    fn eq(&self, other: &[u8; N]) -> bool {
        self.bytes == other
    }
}

impl PartialEq<&[u8]> for Code {
    fn eq(&self, other: &&[u8]) -> bool {
        self.bytes == *other
    }
}

impl PartialEq<Code> for [u8] {
    fn eq(&self, other: &Code) -> bool {
        self == other.bytes
    }
}

impl PartialEq<Code> for &[u8] {
    fn eq(&self, other: &Code) -> bool {
        *self == other.bytes
    }
}

impl PartialEq<Code> for Vec<u8> {
    fn eq(&self, other: &Code) -> bool {
        *self == other.bytes
    }
}

impl<const N: usize> PartialEq<Code> for [u8; N] {
    fn eq(&self, other: &Code) -> bool {
        self[..] == other.bytes
    }
}

impl From<Code> for Vec<u8> {
    fn from(code: Code) -> Self {
        code.bytes
    }
}

impl<const N: usize> TryFrom<Code> for [u8; N] {
    type Error = Vec<u8>;
    fn try_from(code: Code) -> Result<Self, Vec<u8>> {
        code.bytes.try_into()
    }
}

impl<'a> IntoIterator for &'a Code {
    type Item = &'a u8;
    type IntoIter = core::slice::Iter<'a, u8>;
    fn into_iter(self) -> Self::IntoIter {
        self.bytes.iter()
    }
}

impl IntoIterator for Code {
    type Item = u8;
    type IntoIter = alloc::vec::IntoIter<u8>;
    fn into_iter(self) -> Self::IntoIter {
        self.bytes.into_iter()
    }
}

impl core::ops::Deref for Code {
    type Target = Vec<u8>;
    fn deref(&self) -> &Vec<u8> {
        &self.bytes
    }
}

impl core::ops::DerefMut for Code {
    fn deref_mut(&mut self) -> &mut Vec<u8> {
        &mut self.bytes
    }
}

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
}

impl Gpr {
    const fn number(self) -> u8 {
        self as u8
    }
    const fn low(self) -> u8 {
        self as u8 & 7
    }
    const fn high(self) -> bool {
        self as u8 >= 8
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
    fn extensions(self) -> (bool, bool) {
        match self {
            Self::Reg(register) => (false, register.high()),
            Self::Xmm(register) => (false, register & 8 != 0),
            Self::Mem(memory) => (
                memory.index.is_some_and(|(index, _)| index.high()),
                memory.base.is_some_and(Gpr::high),
            ),
        }
    }
    /// Whether a byte-sized access to this operand needs a REX prefix to
    /// name SPL, BPL, SIL or DIL.
    fn needs_byte_rex(self) -> bool {
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
/// [`Asm::bind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub(crate) struct Patch {
    at: usize,
    short: bool,
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

/// An encoder that appends to `code` and counts the instructions it emits,
/// into the [`Code`] it was built over as well.
pub(crate) struct Asm<'a> {
    code: &'a mut Vec<u8>,
    instructions: usize,
    shared: Option<&'a mut usize>,
}

impl<'a> Asm<'a> {
    pub(crate) fn new(code: &'a mut Vec<u8>) -> Self {
        Self {
            code,
            instructions: 0,
            shared: None,
        }
    }
    fn count(&mut self) {
        self.instructions += 1;
        if let Some(shared) = self.shared.as_deref_mut() {
            *shared += 1;
        }
    }
    /// The number of instructions emitted through this encoder.
    #[cfg(test)]
    pub(crate) const fn instructions(&self) -> usize {
        self.instructions
    }
    /// The code length, the offset of the next instruction.
    pub(crate) fn len(&self) -> usize {
        self.code.len()
    }
    /// A prefix byte (LOCK, REP, a segment override) of the next
    /// instruction, which counts it.
    pub(crate) fn prefix(&mut self, byte: u8) {
        self.code.push(byte);
    }
    /// `lock` for the next instruction.
    pub(crate) fn lock(&mut self) {
        self.prefix(0xf0);
    }
    /// Data or immediates that belong to the instruction just emitted.
    pub(crate) fn data(&mut self, bytes: &[u8]) {
        self.code.extend(bytes);
    }

    fn modrm(&mut self, reg: u8, rm: Rm) {
        self.modrm_scaled(reg, rm, 1);
    }

    /// ModRM, SIB and displacement, with an 8-bit displacement counted in
    /// units of `scale` bytes (EVEX disp8*N; 1 elsewhere).
    fn modrm_scaled(&mut self, reg: u8, rm: Rm, scale: u8) {
        let reg = (reg & 7) << 3;
        match rm {
            Rm::Reg(register) => self.code.push(0xc0 | reg | register.low()),
            Rm::Xmm(register) => self.code.push(0xc0 | reg | (register & 7)),
            Rm::Mem(Mem {
                base: None,
                index,
                displacement,
                ..
            }) => {
                debug_assert!(index.is_none(), "RIP-relative addressing has no index");
                self.code.push(reg | 5);
                self.code.extend(displacement.to_le_bytes());
            }
            Rm::Mem(Mem {
                base: Some(base),
                index,
                displacement,
                width,
            }) => {
                // RBP and R13 have no mod-00 form; RSP and R12 need a SIB.
                let scale = i32::from(scale);
                let short = displacement % scale == 0 && i8::try_from(displacement / scale).is_ok();
                let mode = match width {
                    Disp::Dword => 2,
                    Disp::Byte => {
                        debug_assert!(short, "displacement fits its 8-bit field");
                        1
                    }
                    Disp::Auto if displacement == 0 && base.low() != 5 => 0,
                    Disp::Auto if short => 1,
                    Disp::Auto => 2,
                };
                match index {
                    None if base.low() != 4 => self.code.push(mode << 6 | reg | base.low()),
                    None => self.code.extend([mode << 6 | reg | 4, 0x24]),
                    Some((index, scale)) => {
                        debug_assert!(index != Gpr::Rsp, "RSP cannot be an index");
                        let scale = match scale {
                            1 => 0,
                            2 => 1,
                            4 => 2,
                            8 => 3,
                            _ => unreachable!("scale of 1, 2, 4 or 8"),
                        };
                        self.code.extend([
                            mode << 6 | reg | 4,
                            scale << 6 | index.low() << 3 | base.low(),
                        ]);
                    }
                }
                match mode {
                    1 => self.code.push((displacement / scale) as u8),
                    2 => self.code.extend(displacement.to_le_bytes()),
                    _ => {}
                }
            }
        }
    }

    /// A legacy-encoded instruction: the operand-size prefix for words, the
    /// mandatory `prefix`, REX when any field needs it, `opcode` and ModRM.
    pub(crate) fn legacy(
        &mut self,
        size: Size,
        prefix: Option<u8>,
        opcode: &[u8],
        reg: u8,
        reg_byte: bool,
        rm: Rm,
    ) {
        if size == Size::Word {
            self.code.push(0x66);
        }
        if let Some(prefix) = prefix {
            self.code.push(prefix);
        }
        let (x, b) = rm.extensions();
        let w = size == Size::Qword;
        let r = reg & 8 != 0;
        let byte_rex =
            size == Size::Byte && (rm.needs_byte_rex() || (reg_byte && (4..8).contains(&reg)));
        if w || r || x || b || byte_rex {
            self.code
                .push(0x40 | u8::from(w) << 3 | u8::from(r) << 2 | u8::from(x) << 1 | u8::from(b));
        }
        self.code.extend(opcode);
        self.modrm(reg, rm);
        self.count();
    }

    /// A VEX-encoded instruction: two-byte C5 when the fields allow it,
    /// otherwise three-byte C4.
    pub(crate) fn vex(&mut self, prefix: Vex, opcode: u8, reg: u8, vvvv: u8, rm: Rm) {
        let Vex { map, pp, w, l } = prefix;
        let (x, b) = rm.extensions();
        let r = reg & 8 != 0;
        let tail = u8::from(l) << 2 | pp as u8 | (!vvvv & 15) << 3;
        if map == Map::M0f && !w && !x && !b {
            self.code.extend([0xc5, u8::from(!r) << 7 | tail]);
        } else {
            self.code.extend([
                0xc4,
                u8::from(!r) << 7 | u8::from(!x) << 6 | u8::from(!b) << 5 | map as u8,
                u8::from(w) << 7 | tail,
            ]);
        }
        self.code.push(opcode);
        self.modrm(reg, rm);
        self.count();
    }

    /// An EVEX-encoded instruction. Registers number 0 to 31; `rm` names
    /// an XMM register or memory.
    pub(crate) fn evex(&mut self, prefix: Evex, opcode: u8, reg: u8, vvvv: u8, rm: Rm) {
        let Evex {
            map,
            pp,
            w,
            length,
            mask,
            zeroing,
            broadcast,
            scale,
        } = prefix;
        let (x, b) = match rm {
            // EVEX.X extends a register r/m to 32 registers.
            Rm::Xmm(register) => (register & 16 != 0, register & 8 != 0),
            other => other.extensions(),
        };
        let r = reg & 8 != 0;
        let r2 = reg & 16 != 0;
        let v2 = vvvv & 16 != 0;
        self.code.extend([
            0x62,
            u8::from(!r) << 7
                | u8::from(!x) << 6
                | u8::from(!b) << 5
                | u8::from(!r2) << 4
                | map as u8,
            u8::from(w) << 7 | (!vvvv & 15) << 3 | 4 | pp as u8,
            u8::from(zeroing) << 7
                | (length & 3) << 5
                | u8::from(broadcast) << 4
                | u8::from(!v2) << 3
                | (mask & 7),
            opcode,
        ]);
        let scale = if matches!(rm, Rm::Mem(_)) {
            scale.max(1)
        } else {
            1
        };
        self.modrm_scaled(reg, rm, scale);
        self.count();
    }

    /// A legacy SSE instruction on XMM registers: the mandatory `prefix`,
    /// REX when a register needs it, `opcode` and ModRM.
    pub(crate) fn sse(&mut self, prefix: Option<u8>, opcode: &[u8], xmm: u8, rm: impl Into<Rm>) {
        self.legacy(Size::Dword, prefix, opcode, xmm, false, rm.into());
    }
    /// [`Self::sse`] with an 8-bit immediate.
    pub(crate) fn sse_imm(
        &mut self,
        prefix: Option<u8>,
        opcode: &[u8],
        xmm: u8,
        rm: impl Into<Rm>,
        immediate: u8,
    ) {
        self.sse(prefix, opcode, xmm, rm);
        self.code.push(immediate);
    }
    /// An opcode that names its register in its low three bits (`+r`).
    pub(crate) fn opcode_reg(&mut self, size: Size, opcode: u8, register: Gpr) {
        if size == Size::Word {
            self.code.push(0x66);
        }
        let w = size == Size::Qword;
        if w || register.high() {
            self.code
                .push(0x40 | u8::from(w) << 3 | u8::from(register.high()));
        }
        self.code.push(opcode | register.low());
        self.count();
    }
    /// An instruction of fixed bytes and no operands (`ret`, `ud2`, `mfence`).
    pub(crate) fn fixed(&mut self, bytes: &[u8]) {
        self.code.extend(bytes);
        self.count();
    }

    // Stack and control transfer.

    /// `push r64`.
    pub(crate) fn push(&mut self, register: Gpr) {
        self.opcode_reg(Size::Dword, 0x50, register);
    }
    /// `pop r64`.
    pub(crate) fn pop(&mut self, register: Gpr) {
        self.opcode_reg(Size::Dword, 0x58, register);
    }
    /// `ret`.
    pub(crate) fn ret(&mut self) {
        self.fixed(&[0xc3]);
    }
    /// `call rm64`.
    pub(crate) fn call_rm(&mut self, rm: impl Into<Rm>) {
        self.legacy(Size::Dword, None, &[0xff], 2, false, rm.into());
    }
    /// `jmp rm64`.
    pub(crate) fn jmp_rm(&mut self, rm: impl Into<Rm>) {
        self.legacy(Size::Dword, None, &[0xff], 4, false, rm.into());
    }
    /// `call rel32`, resolved later by [`Self::bind`] or [`resolve`].
    pub(crate) fn call(&mut self) -> Patch {
        self.code.push(0xe8);
        self.patch()
    }

    // Moves.

    /// `mov rm, src`.
    pub(crate) fn mov_store(&mut self, size: Size, rm: impl Into<Rm>, source: Gpr) {
        let opcode = if size == Size::Byte { 0x88 } else { 0x89 };
        self.legacy(size, None, &[opcode], source.number(), true, rm.into());
    }
    /// `mov dst, rm`.
    pub(crate) fn mov_load(&mut self, size: Size, destination: Gpr, rm: impl Into<Rm>) {
        let opcode = if size == Size::Byte { 0x8a } else { 0x8b };
        self.legacy(size, None, &[opcode], destination.number(), true, rm.into());
    }
    /// `mov dst, src` in the 89 direction (`mov rm, reg`).
    pub(crate) fn mov(&mut self, size: Size, destination: Gpr, source: Gpr) {
        self.mov_store(size, destination, source);
    }
    /// `mov r32, imm32` (B8+r), which zero-extends to 64 bits.
    pub(crate) fn mov_imm32(&mut self, destination: Gpr, value: u32) {
        if destination.high() {
            self.code.push(0x41);
        }
        self.code.push(0xb8 | destination.low());
        self.code.extend(value.to_le_bytes());
        self.count();
    }
    /// `movabs r64, imm64` (REX.W B8+r).
    pub(crate) fn mov_imm64(&mut self, destination: Gpr, value: u64) {
        self.code.push(0x48 | u8::from(destination.high()));
        self.code.push(0xb8 | destination.low());
        self.code.extend(value.to_le_bytes());
        self.count();
    }
    /// `mov rm, imm32` (C7 /0), sign-extended for a quadword.
    pub(crate) fn mov_rm_imm32(&mut self, size: Size, rm: impl Into<Rm>, value: i32) {
        debug_assert!(size != Size::Byte && size != Size::Word);
        self.legacy(size, None, &[0xc7], 0, false, rm.into());
        self.code.extend(value.to_le_bytes());
    }
    /// `movzx dst, rm8/rm16`.
    pub(crate) fn movzx(&mut self, size: Size, destination: Gpr, from: Size, rm: impl Into<Rm>) {
        let opcode = if from == Size::Byte { 0xb6 } else { 0xb7 };
        let rm = rm.into();
        let byte_rex = from == Size::Byte && rm.needs_byte_rex();
        self.extended(
            size,
            byte_rex,
            None,
            &[0x0f, opcode],
            destination.number(),
            rm,
        );
    }
    /// `movsx dst, rm8/rm16`.
    pub(crate) fn movsx(&mut self, size: Size, destination: Gpr, from: Size, rm: impl Into<Rm>) {
        let opcode = if from == Size::Byte { 0xbe } else { 0xbf };
        let rm = rm.into();
        let byte_rex = from == Size::Byte && rm.needs_byte_rex();
        self.extended(
            size,
            byte_rex,
            None,
            &[0x0f, opcode],
            destination.number(),
            rm,
        );
    }
    /// `movsxd r64, rm32`.
    pub(crate) fn movsxd(&mut self, destination: Gpr, rm: impl Into<Rm>) {
        self.legacy(
            Size::Qword,
            None,
            &[0x63],
            destination.number(),
            false,
            rm.into(),
        );
    }
    /// `lea dst, [mem]`.
    pub(crate) fn lea(&mut self, size: Size, destination: Gpr, memory: Mem) {
        self.legacy(
            size,
            None,
            &[0x8d],
            destination.number(),
            false,
            Rm::Mem(memory),
        );
    }

    /// A legacy instruction whose operand size is `size` but whose REX also
    /// carries `byte_rex` for a byte-sized r/m source (MOVZX, MOVSX).
    fn extended(
        &mut self,
        size: Size,
        byte_rex: bool,
        prefix: Option<u8>,
        opcode: &[u8],
        reg: u8,
        rm: Rm,
    ) {
        if byte_rex && size != Size::Qword && reg & 8 == 0 && rm.extensions() == (false, false) {
            if size == Size::Word {
                self.code.push(0x66);
            }
            if let Some(prefix) = prefix {
                self.code.push(prefix);
            }
            self.code.push(0x40);
            self.code.extend(opcode);
            self.modrm(reg, rm);
            self.count();
        } else {
            self.legacy(size, prefix, opcode, reg, false, rm);
        }
    }

    // Arithmetic.

    /// `op rm, src` (the 01-direction ALU forms).
    pub(crate) fn alu(&mut self, op: Alu, size: Size, rm: impl Into<Rm>, source: Gpr) {
        let opcode = (op as u8) << 3 | u8::from(size != Size::Byte);
        self.legacy(size, None, &[opcode], source.number(), true, rm.into());
    }
    /// `op dst, rm` (the 03-direction ALU forms).
    pub(crate) fn alu_load(&mut self, op: Alu, size: Size, destination: Gpr, rm: impl Into<Rm>) {
        let opcode = (op as u8) << 3 | 2 | u8::from(size != Size::Byte);
        self.legacy(size, None, &[opcode], destination.number(), true, rm.into());
    }
    /// `op rm, imm8` sign-extended (83 /digit).
    pub(crate) fn alu_imm8(&mut self, op: Alu, size: Size, rm: impl Into<Rm>, value: i8) {
        debug_assert!(size != Size::Byte);
        self.legacy(size, None, &[0x83], op as u8, false, rm.into());
        self.code.push(value as u8);
    }
    /// `op rm, imm32` (81 /digit), sign-extended for a quadword.
    pub(crate) fn alu_imm32(&mut self, op: Alu, size: Size, rm: impl Into<Rm>, value: i32) {
        debug_assert!(size == Size::Dword || size == Size::Qword);
        self.legacy(size, None, &[0x81], op as u8, false, rm.into());
        self.code.extend(value.to_le_bytes());
    }
    /// `op eax/rax, imm32`, the accumulator short form.
    pub(crate) fn alu_accumulator_imm32(&mut self, op: Alu, size: Size, value: i32) {
        debug_assert!(size == Size::Dword || size == Size::Qword);
        if size == Size::Qword {
            self.code.push(0x48);
        }
        self.code.push((op as u8) << 3 | 5);
        self.code.extend(value.to_le_bytes());
        self.count();
    }
    /// `op rm, imm`: the sign-extended imm8 form when it fits, else imm32.
    pub(crate) fn alu_imm(&mut self, op: Alu, size: Size, rm: impl Into<Rm>, value: i32) {
        match i8::try_from(value) {
            Ok(short) => self.alu_imm8(op, size, rm, short),
            Err(_) => self.alu_imm32(op, size, rm, value),
        }
    }
    /// `test rm, src`.
    pub(crate) fn test(&mut self, size: Size, rm: impl Into<Rm>, source: Gpr) {
        let opcode = if size == Size::Byte { 0x84 } else { 0x85 };
        self.legacy(size, None, &[opcode], source.number(), true, rm.into());
    }
    /// Group 3 `op rm`: NOT, NEG, MUL, IMUL, DIV, IDIV.
    pub(crate) fn unary(&mut self, op: Unary, size: Size, rm: impl Into<Rm>) {
        let opcode = if size == Size::Byte { 0xf6 } else { 0xf7 };
        self.legacy(size, None, &[opcode], op as u8, false, rm.into());
    }
    /// `imul dst, rm`.
    pub(crate) fn imul(&mut self, size: Size, destination: Gpr, rm: impl Into<Rm>) {
        self.legacy(
            size,
            None,
            &[0x0f, 0xaf],
            destination.number(),
            false,
            rm.into(),
        );
    }
    /// `cdq` or `cqo`: sign-extend EAX/RAX into EDX/RDX.
    pub(crate) fn sign_extend_accumulator(&mut self, size: Size) {
        if size == Size::Qword {
            self.code.push(0x48);
        }
        self.code.push(0x99);
        self.count();
    }
    /// A group 2 shift or rotate by CL.
    pub(crate) fn shift_cl(&mut self, op: ShiftOp, size: Size, rm: impl Into<Rm>) {
        let opcode = if size == Size::Byte { 0xd2 } else { 0xd3 };
        self.legacy(size, None, &[opcode], op as u8, false, rm.into());
    }
    /// A group 2 shift or rotate by one (D1 /digit).
    pub(crate) fn shift_one(&mut self, op: ShiftOp, size: Size, rm: impl Into<Rm>) {
        let opcode = if size == Size::Byte { 0xd0 } else { 0xd1 };
        self.legacy(size, None, &[opcode], op as u8, false, rm.into());
    }
    /// `imul dst, rm, imm32`.
    pub(crate) fn imul_imm32(
        &mut self,
        size: Size,
        destination: Gpr,
        rm: impl Into<Rm>,
        value: i32,
    ) {
        self.legacy(size, None, &[0x69], destination.number(), false, rm.into());
        self.code.extend(value.to_le_bytes());
    }
    /// `nop`.
    pub(crate) fn nop(&mut self) {
        self.code.push(0x90);
        self.count();
    }
    /// A group 2 shift or rotate by an immediate (C1 /digit ib).
    pub(crate) fn shift_imm(&mut self, op: ShiftOp, size: Size, rm: impl Into<Rm>, amount: u8) {
        let opcode = if size == Size::Byte { 0xc0 } else { 0xc1 };
        self.legacy(size, None, &[opcode], op as u8, false, rm.into());
        self.code.push(amount);
    }
    /// `shrd rm, src, imm8`.
    pub(crate) fn shrd_imm(&mut self, size: Size, rm: impl Into<Rm>, source: Gpr, amount: u8) {
        self.legacy(size, None, &[0x0f, 0xac], source.number(), false, rm.into());
        self.code.push(amount);
    }

    // Bit operations.

    /// `bsr dst, rm`.
    pub(crate) fn bsr(&mut self, size: Size, destination: Gpr, rm: impl Into<Rm>) {
        self.legacy(
            size,
            None,
            &[0x0f, 0xbd],
            destination.number(),
            false,
            rm.into(),
        );
    }
    /// `bsf dst, rm`.
    pub(crate) fn bsf(&mut self, size: Size, destination: Gpr, rm: impl Into<Rm>) {
        self.legacy(
            size,
            None,
            &[0x0f, 0xbc],
            destination.number(),
            false,
            rm.into(),
        );
    }
    /// `lzcnt dst, rm` (LZCNT; ABM on AMD).
    pub(crate) fn lzcnt(&mut self, size: Size, destination: Gpr, rm: impl Into<Rm>) {
        self.legacy(
            size,
            Some(0xf3),
            &[0x0f, 0xbd],
            destination.number(),
            false,
            rm.into(),
        );
    }
    /// `tzcnt dst, rm` (BMI1).
    pub(crate) fn tzcnt(&mut self, size: Size, destination: Gpr, rm: impl Into<Rm>) {
        self.legacy(
            size,
            Some(0xf3),
            &[0x0f, 0xbc],
            destination.number(),
            false,
            rm.into(),
        );
    }
    /// `popcnt dst, rm`.
    pub(crate) fn popcnt(&mut self, size: Size, destination: Gpr, rm: impl Into<Rm>) {
        self.legacy(
            size,
            Some(0xf3),
            &[0x0f, 0xb8],
            destination.number(),
            false,
            rm.into(),
        );
    }
    /// `bswap reg`.
    pub(crate) fn bswap(&mut self, size: Size, register: Gpr) {
        debug_assert!(size == Size::Dword || size == Size::Qword);
        if size == Size::Qword || register.high() {
            self.code
                .push(0x40 | u8::from(size == Size::Qword) << 3 | u8::from(register.high()));
        }
        self.code.extend([0x0f, 0xc8 | register.low()]);
        self.count();
    }
    /// `cmovcc dst, rm`.
    pub(crate) fn cmov(&mut self, cond: Cond, size: Size, destination: Gpr, rm: impl Into<Rm>) {
        self.legacy(
            size,
            None,
            &[0x0f, 0x40 | cond as u8],
            destination.number(),
            false,
            rm.into(),
        );
    }
    /// `setcc rm8`.
    pub(crate) fn setcc(&mut self, cond: Cond, rm: impl Into<Rm>) {
        self.legacy(
            Size::Byte,
            None,
            &[0x0f, 0x90 | cond as u8],
            0,
            false,
            rm.into(),
        );
    }

    // SSE moves and GFNI.

    /// `movq xmm, r64`.
    pub(crate) fn movq_to_xmm(&mut self, xmm: u8, source: Gpr) {
        self.legacy(
            Size::Qword,
            Some(0x66),
            &[0x0f, 0x6e],
            xmm,
            false,
            Rm::Reg(source),
        );
    }
    /// `movq r64, xmm`.
    pub(crate) fn movq_from_xmm(&mut self, destination: Gpr, xmm: u8) {
        self.legacy(
            Size::Qword,
            Some(0x66),
            &[0x0f, 0x7e],
            xmm,
            false,
            Rm::Reg(destination),
        );
    }
    /// `gf2p8affineqb xmm, xmm/m128, imm8`: each byte of `xmm` becomes the
    /// GF(2) affine transform by the matching qword's 8x8 bit matrix in
    /// `matrix`, XOR `constant` (GFNI).
    pub(crate) fn gf2p8affineqb(&mut self, xmm: u8, matrix: Rm, constant: u8) {
        self.legacy(
            Size::Dword,
            Some(0x66),
            &[0x0f, 0x3a, 0xce],
            xmm,
            false,
            matrix,
        );
        self.code.push(constant);
    }

    // BMI2 (VEX-encoded general-purpose forms).

    /// `shlx`, `shrx` or `sarx dst, rm, count`: a shift by the count register
    /// modulo the operand width, without flags (BMI2).
    pub(crate) fn shift_x(
        &mut self,
        op: ShiftOp,
        size: Size,
        destination: Gpr,
        rm: impl Into<Rm>,
        count: Gpr,
    ) {
        let pp = match op {
            ShiftOp::Shl => Pp::P66,
            ShiftOp::Shr => Pp::Pf2,
            ShiftOp::Sar => Pp::Pf3,
            _ => unreachable!("SHLX, SHRX and SARX only"),
        };
        self.vex(
            Vex {
                map: Map::M0f38,
                pp,
                w: size == Size::Qword,
                l: false,
            },
            0xf7,
            destination.number(),
            count.number(),
            rm.into(),
        );
    }
    /// `rorx dst, rm, imm8`: rotate right without flags (BMI2).
    #[cfg(test)]
    pub(crate) fn rorx(&mut self, size: Size, destination: Gpr, rm: impl Into<Rm>, amount: u8) {
        self.vex(
            Vex {
                map: Map::M0f3a,
                pp: Pp::Pf2,
                w: size == Size::Qword,
                l: false,
            },
            0xf0,
            destination.number(),
            0,
            rm.into(),
        );
        self.code.push(amount);
    }

    // Control flow.

    /// `jmp rel32`, resolved later by [`Self::bind`].
    pub(crate) fn jmp(&mut self) -> Patch {
        self.code.push(0xe9);
        self.patch()
    }
    /// `jcc rel32`, resolved later by [`Self::bind`].
    pub(crate) fn jcc(&mut self, cond: Cond) -> Patch {
        self.code.extend([0x0f, 0x80 | cond as u8]);
        self.patch()
    }
    /// `jmp rel8`, resolved later by [`Self::bind`].
    pub(crate) fn jmp8(&mut self) -> Patch {
        self.code.push(0xeb);
        self.short_patch()
    }
    /// `jcc rel8`, resolved later by [`Self::bind`].
    pub(crate) fn jcc8(&mut self, cond: Cond) -> Patch {
        self.code.push(0x70 | cond as u8);
        self.short_patch()
    }
    fn patch(&mut self) -> Patch {
        let at = self.code.len();
        self.code.extend([0; 4]);
        self.count();
        Patch { at, short: false }
    }
    fn short_patch(&mut self) -> Patch {
        let at = self.code.len();
        self.code.push(0);
        self.count();
        Patch { at, short: true }
    }
    /// Point `patch` at the current position.
    pub(crate) fn bind(&mut self, patch: Patch) {
        let target = self.code.len();
        resolve(self.code, patch, target);
    }
}

/// Point `patch` in `code` at `target`.
pub(crate) fn resolve(code: &mut [u8], patch: Patch, target: usize) {
    let distance = target as i64 - patch.end() as i64;
    if patch.short {
        code[patch.at] = i8::try_from(distance).expect("rel8 branch in range") as u8;
    } else {
        let distance = i32::try_from(distance).expect("rel32 branch in range");
        code[patch.at..patch.at + 4].copy_from_slice(&distance.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn bytes(build: impl FnOnce(&mut Asm)) -> (Vec<u8>, usize) {
        let mut code = vec![];
        let mut asm = Asm::new(&mut code);
        build(&mut asm);
        let count = asm.instructions();
        (code, count)
    }

    #[test]
    fn integer_forms_match_the_sdm_encodings() {
        use Gpr::*;
        use Size::*;
        for (expected, build) in [
            (
                &[0x89, 0xc1][..],
                (|a: &mut Asm| a.mov(Dword, Rcx, Rax)) as fn(&mut Asm),
            ),
            (&[0x48, 0x89, 0xc1], |a| a.mov(Qword, Rcx, Rax)),
            (&[0x4d, 0x89, 0xc8], |a| a.mov(Qword, R8, R9)),
            (&[0x48, 0x8b, 0x47, 0x08], |a| {
                a.mov_load(Qword, Rax, Mem::base(Rdi, 8))
            }),
            (&[0x48, 0x8b, 0x87, 0x00, 0x01, 0, 0], |a| {
                a.mov_load(Qword, Rax, Mem::base(Rdi, 256))
            }),
            (&[0x48, 0x89, 0x87, 0x08, 0, 0, 0], |a| {
                a.mov_store(Qword, Mem::base_disp32(Rdi, 8), Rax)
            }),
            (&[0x48, 0x8b, 0x04, 0x24], |a| {
                a.mov_load(Qword, Rax, Mem::base(Rsp, 0))
            }),
            (&[0x49, 0x8b, 0x45, 0x00], |a| {
                a.mov_load(Qword, Rax, Mem::base(R13, 0))
            }),
            (&[0x41, 0x33, 0x04, 0x90], |a| {
                a.alu_load(Alu::Xor, Dword, Rax, Mem::indexed(R8, Rdx, 4, 0))
            }),
            (&[0x40, 0x88, 0xf0], |a| a.mov_store(Byte, Rax, Rsi)),
            (&[0x0f, 0xb6, 0xc9], |a| a.movzx(Dword, Rcx, Byte, Rcx)),
            (&[0x40, 0x0f, 0xb6, 0xc6], |a| {
                a.movzx(Dword, Rax, Byte, Rsi)
            }),
            (&[0x48, 0x63, 0xc0], |a| a.movsxd(Rax, Rax)),
            (&[0x48, 0x0f, 0xbd, 0xc0], |a| a.bsr(Qword, Rax, Rax)),
            (&[0xf3, 0x48, 0x0f, 0xbd, 0xc0], |a| {
                a.lzcnt(Qword, Rax, Rax)
            }),
            (&[0x0f, 0xc8], |a| a.bswap(Dword, Rax)),
            (&[0x49, 0x0f, 0xc9], |a| a.bswap(Qword, R9)),
            (&[0x48, 0x0f, 0x44, 0xc1], |a| {
                a.cmov(Cond::E, Qword, Rax, Rcx)
            }),
            (&[0x83, 0xf0, 0x1f], |a| {
                a.alu_imm8(Alu::Xor, Dword, Rax, 31)
            }),
            (&[0x81, 0xe1, 0x55, 0x55, 0x55, 0x55], |a| {
                a.alu_imm32(Alu::And, Dword, Rcx, 0x5555_5555)
            }),
            (&[0x25, 0x55, 0x55, 0x55, 0x55], |a| {
                a.alu_accumulator_imm32(Alu::And, Dword, 0x5555_5555)
            }),
            (&[0x48, 0xd3, 0xf8], |a| {
                a.shift_cl(ShiftOp::Sar, Qword, Rax)
            }),
            (&[0xc1, 0xc8, 0x10], |a| {
                a.shift_imm(ShiftOp::Ror, Dword, Rax, 16)
            }),
            (&[0x48, 0x0f, 0xac, 0xc1, 0x07], |a| {
                a.shrd_imm(Qword, Rcx, Rax, 7)
            }),
            (&[0x48, 0xf7, 0xe9], |a| a.unary(Unary::Imul, Qword, Rcx)),
            (&[0x48, 0x99], |a| a.sign_extend_accumulator(Qword)),
            (&[0xb9, 0x3f, 0, 0, 0], |a| a.mov_imm32(Rcx, 63)),
            (&[0x48, 0xba, 1, 2, 3, 4, 5, 6, 7, 8], |a| {
                a.mov_imm64(Rdx, 0x0807_0605_0403_0201)
            }),
            (&[0x4c, 0x8d, 0x05, 0, 0, 0, 0], |a| {
                a.lea(Qword, R8, Mem::rip(0))
            }),
            (&[0xc4, 0xe2, 0xf1, 0xf7, 0xc0], |a| {
                a.shift_x(ShiftOp::Shl, Qword, Rax, Rax, Rcx)
            }),
            (&[0xc4, 0xe2, 0x72, 0xf7, 0xc0], |a| {
                a.shift_x(ShiftOp::Sar, Dword, Rax, Rax, Rcx)
            }),
            (&[0xc4, 0xe2, 0x73, 0xf7, 0xc0], |a| {
                a.shift_x(ShiftOp::Shr, Dword, Rax, Rax, Rcx)
            }),
            (&[0xc4, 0xe3, 0xfb, 0xf0, 0xc0, 0x05], |a| {
                a.rorx(Qword, Rax, Rax, 5)
            }),
            (&[0x66, 0x48, 0x0f, 0x6e, 0xc0], |a| a.movq_to_xmm(0, Rax)),
            (&[0x66, 0x48, 0x0f, 0x7e, 0xc8], |a| a.movq_from_xmm(Rax, 1)),
            (&[0x66, 0x49, 0x0f, 0x6e, 0xca], |a| a.movq_to_xmm(1, R10)),
            (&[0x66, 0x0f, 0x3a, 0xce, 0xc1, 0x00], |a| {
                a.gf2p8affineqb(0, Rm::Xmm(1), 0)
            }),
            (&[0x66, 0x44, 0x0f, 0x3a, 0xce, 0xc1, 0x00], |a| {
                a.gf2p8affineqb(8, Rm::Xmm(1), 0)
            }),
        ] {
            let (code, count) = bytes(build);
            assert_eq!(code, expected);
            assert_eq!(count, 1);
        }
    }

    #[test]
    fn core_forms_match_the_sdm_encodings() {
        use Gpr::*;
        for (expected, build) in [
            (
                &[0x48, 0x8b, 0x47, 0x00][..],
                (|a: &mut Asm| a.mov_load(Size::Qword, Rax, Mem::base_disp8(Rdi, 0)))
                    as fn(&mut Asm),
            ),
            (&[0x41, 0x57], |a| a.push(R15)),
            (&[0x5d], |a| a.pop(Rbp)),
            (&[0xff, 0xd0], |a| a.call_rm(Rax)),
            (&[0x41, 0xff, 0xe3], |a| a.jmp_rm(R11)),
            (&[0x66, 0x0f, 0xef, 0xc1], |a| {
                a.sse(Some(0x66), &[0x0f, 0xef], 0, Rm::Xmm(1))
            }),
            (&[0x66, 0x45, 0x0f, 0xef, 0xc1], |a| {
                a.sse(Some(0x66), &[0x0f, 0xef], 8, Rm::Xmm(9))
            }),
            (&[0x66, 0x0f, 0x70, 0xc1, 0x1b], |a| {
                a.sse_imm(Some(0x66), &[0x0f, 0x70], 0, Rm::Xmm(1), 0x1b)
            }),
            (&[0x0f, 0xae, 0xf0], |a| a.fixed(&[0x0f, 0xae, 0xf0])),
            // vpaddd zmm0{k1}, zmm1, zmm2
            (&[0x62, 0xf1, 0x75, 0x49, 0xfe, 0xc2], |a| {
                a.evex(
                    Evex {
                        map: Map::M0f,
                        pp: Pp::P66,
                        w: false,
                        length: 2,
                        mask: 1,
                        zeroing: false,
                        broadcast: false,
                        scale: 64,
                    },
                    0xfe,
                    0,
                    1,
                    Rm::Xmm(2),
                )
            }),
            // vpaddd zmm16, zmm17, [rdi+0x40]: disp8*64 = 1.
            (&[0x62, 0xe1, 0x75, 0x40, 0xfe, 0x47, 0x01], |a| {
                a.evex(
                    Evex {
                        map: Map::M0f,
                        pp: Pp::P66,
                        w: false,
                        length: 2,
                        mask: 0,
                        zeroing: false,
                        broadcast: false,
                        scale: 64,
                    },
                    0xfe,
                    16,
                    17,
                    Rm::Mem(Mem::base(Rdi, 0x40)),
                )
            }),
        ] {
            let (code, count) = bytes(build);
            assert_eq!(code, expected);
            assert_eq!(count, 1);
        }
    }

    #[test]
    fn checkpoints_preserve_counts_when_moving_cold_code() {
        let mut code = Code::new();
        code.asm().mov_imm64(Gpr::Rax, 0x1234);
        let hot = code.checkpoint();
        let skip = code.asm().jmp();
        let cold = code.checkpoint();
        resolve(&mut code, skip, cold.offset());
        code.asm().mov_imm32(Gpr::Rcx, 1);
        code.asm().ret();
        let tail = code.split_off(cold);
        assert_eq!(tail.instructions(), 2);
        assert_eq!(code.instructions(), 2);
        code.truncate(hot);
        assert_eq!(code.instructions(), 1);
        let bytes = code.len();
        code.append(tail);
        assert_eq!(code.instructions(), 3);
        code.remove_instruction(0..bytes);
        assert_eq!(code.instructions(), 2);
        assert_eq!(*code, [0xb9, 1, 0, 0, 0, 0xc3]);
    }

    #[test]
    fn code_counts_across_encoders_and_prefixes_join_their_instruction() {
        let mut code = Code::new();
        code.asm().mov(Size::Dword, Gpr::Rax, Gpr::Rcx);
        let mut asm = code.asm();
        asm.lock();
        asm.alu(Alu::Add, Size::Dword, Mem::base(Gpr::Rdi, 0), Gpr::Rax);
        assert_eq!(code.instructions(), 2);
        assert_eq!(*code, [0x89, 0xc8, 0xf0, 0x01, 0x07]);
        code.clear();
        assert_eq!((code.len(), code.instructions()), (0, 0));
    }

    #[test]
    fn short_branches_resolve_relative_to_the_next_instruction() {
        let (code, count) = bytes(|a| {
            let forward = a.jcc8(Cond::Ne);
            a.mov(Size::Dword, Gpr::Rax, Gpr::Rax);
            a.bind(forward);
            let back = a.jmp8();
            resolve(a.code, back, 0);
        });
        assert_eq!(code, [0x75, 2, 0x89, 0xc0, 0xeb, 0xfa]);
        assert_eq!(count, 3);
    }

    #[test]
    fn branches_resolve_relative_to_the_next_instruction() {
        let (code, count) = bytes(|a| {
            let forward = a.jcc(Cond::E);
            a.mov(Size::Dword, Gpr::Rax, Gpr::Rax);
            a.bind(forward);
            let back = a.jmp();
            resolve(a.code, back, 0);
        });
        assert_eq!(
            code,
            [
                0x0f, 0x84, 2, 0, 0, 0, 0x89, 0xc0, 0xe9, 0xf3, 0xff, 0xff, 0xff
            ]
        );
        assert_eq!(count, 3);
    }
}
