//! A typed x86-64 encoder (Intel SDM Vol. 2, chapter 2). Operands are typed
//! registers and memory; operand-size prefixes, REX, VEX, ModRM, SIB and
//! displacements are derived from them, and [`Asm`] counts every instruction
//! it emits.
//!
//! The scalar integer families emit through it; the rest still emit bytes
//! directly, so some operand kinds and forms wait for their first user.
#![allow(dead_code)]
use alloc::vec::Vec;

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
    /// Encode the displacement in 32 bits even when it fits 8.
    pub disp32: bool,
}

impl Mem {
    pub(crate) const fn base(base: Gpr, displacement: i32) -> Self {
        Self {
            base: Some(base),
            index: None,
            displacement,
            disp32: false,
        }
    }
    /// `[base + displacement]` with a 32-bit displacement field.
    pub(crate) const fn base_disp32(base: Gpr, displacement: i32) -> Self {
        Self {
            disp32: true,
            ..Self::base(base, displacement)
        }
    }
    /// `[rip + displacement]`.
    pub(crate) const fn rip(displacement: i32) -> Self {
        Self {
            base: None,
            index: None,
            displacement,
            disp32: true,
        }
    }
    pub(crate) const fn indexed(base: Gpr, index: Gpr, scale: u8, displacement: i32) -> Self {
        Self {
            base: Some(base),
            index: Some((index, scale)),
            displacement,
            disp32: false,
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
    Rol,
    Ror,
    Rcl,
    Rcr,
    Shl,
    Shr,
    Sal,
    Sar,
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

/// The displacement field of a rel32 branch, resolved by [`Asm::bind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub(crate) struct Patch(usize);

impl Patch {
    /// The offset of the 4-byte displacement in the code.
    pub(crate) const fn offset(self) -> usize {
        self.0
    }
}

/// An encoder that appends to `code` and counts the instructions it emits.
pub(crate) struct Asm<'a> {
    code: &'a mut Vec<u8>,
    instructions: usize,
}

impl<'a> Asm<'a> {
    pub(crate) fn new(code: &'a mut Vec<u8>) -> Self {
        Self {
            code,
            instructions: 0,
        }
    }
    /// The number of instructions emitted through this encoder.
    pub(crate) const fn instructions(&self) -> usize {
        self.instructions
    }
    /// The code length, the offset of the next instruction.
    pub(crate) fn len(&self) -> usize {
        self.code.len()
    }
    /// Instruction bytes this encoder does not model, counted as
    /// `instructions` instructions.
    pub(crate) fn raw(&mut self, bytes: &[u8], instructions: usize) {
        self.code.extend(bytes);
        self.instructions += instructions;
    }
    /// Data or immediates that belong to the instruction just emitted.
    pub(crate) fn data(&mut self, bytes: &[u8]) {
        self.code.extend(bytes);
    }

    fn modrm(&mut self, reg: u8, rm: Rm) {
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
                disp32,
            }) => {
                // RBP and R13 have no mod-00 form; RSP and R12 need a SIB.
                let mode = if disp32 {
                    2
                } else if displacement == 0 && base.low() != 5 {
                    0
                } else if i8::try_from(displacement).is_ok() {
                    1
                } else {
                    2
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
                    1 => self.code.push(displacement as u8),
                    2 => self.code.extend(displacement.to_le_bytes()),
                    _ => {}
                }
            }
        }
    }

    /// A legacy-encoded instruction: the operand-size prefix for words, the
    /// mandatory `prefix`, REX when any field needs it, `opcode` and ModRM.
    fn legacy(
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
        self.instructions += 1;
    }

    /// A VEX-encoded instruction: two-byte C5 when the fields allow it,
    /// otherwise three-byte C4.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn vex(
        &mut self,
        map: Map,
        pp: Pp,
        w: bool,
        l: bool,
        opcode: u8,
        reg: u8,
        vvvv: u8,
        rm: Rm,
    ) {
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
        self.instructions += 1;
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
        self.instructions += 1;
    }
    /// `movabs r64, imm64` (REX.W B8+r).
    pub(crate) fn mov_imm64(&mut self, destination: Gpr, value: u64) {
        self.code.push(0x48 | u8::from(destination.high()));
        self.code.push(0xb8 | destination.low());
        self.code.extend(value.to_le_bytes());
        self.instructions += 1;
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
            self.instructions += 1;
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
        self.instructions += 1;
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
        self.instructions += 1;
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
        self.instructions += 1;
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
        self.instructions += 1;
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
            ShiftOp::Shl | ShiftOp::Sal => Pp::P66,
            ShiftOp::Shr => Pp::Pf2,
            ShiftOp::Sar => Pp::Pf3,
            _ => unreachable!("SHLX, SHRX and SARX only"),
        };
        self.vex(
            Map::M0f38,
            pp,
            size == Size::Qword,
            false,
            0xf7,
            destination.number(),
            count.number(),
            rm.into(),
        );
    }
    /// `rorx dst, rm, imm8`: rotate right without flags (BMI2).
    pub(crate) fn rorx(&mut self, size: Size, destination: Gpr, rm: impl Into<Rm>, amount: u8) {
        self.vex(
            Map::M0f3a,
            Pp::Pf2,
            size == Size::Qword,
            false,
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
    fn patch(&mut self) -> Patch {
        let at = self.code.len();
        self.code.extend([0; 4]);
        self.instructions += 1;
        Patch(at)
    }
    /// Point `patch` at the current position.
    pub(crate) fn bind(&mut self, patch: Patch) {
        let target = self.code.len();
        resolve(self.code, patch, target);
    }
}

/// Point `patch` in `code` at `target`.
pub(crate) fn resolve(code: &mut [u8], patch: Patch, target: usize) {
    let next = patch.0 as i64 + 4;
    let distance = i32::try_from(target as i64 - next).expect("rel32 branch in range");
    code[patch.0..patch.0 + 4].copy_from_slice(&distance.to_le_bytes());
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
