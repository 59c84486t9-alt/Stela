//! Native x86-64 emitter. Guest state pointer remains in RDI throughout.
use crate::{
    Backend, GuestAddress, NativeBlock, UnsupportedReason,
    aarch64::{
        AddressMode, Instruction, Logical, MemoryTransfer, Operation, Register, RegisterExtend,
        Shift, WideMove, Width,
    },
};

pub struct Emitter;
mod bitfield;
pub(crate) mod block;
mod conditional_select;
mod crc;
mod flags;
mod fp_register;
mod integer_math;
mod integer_minmax;
mod integer_unary;
pub mod isa;
mod literal;
mod memory_store;
mod pc_relative;
mod register_offset;
mod simd;

fn offset(register: Register) -> Option<u32> {
    match register {
        Register::X(index) => Some(u32::from(index) * 8),
        Register::Sp => Some(248),
        Register::Zero => None,
    }
}

/// Backend policy shared by block parsing and emission. Terminal numerical
/// mappings consume only their own word; conditional mappings retain a suffix.
pub(crate) fn numerical_always_exits(operation: &crate::aarch64::FloatingPointOperation) -> bool {
    simd::numerical_always_exits(operation)
}

fn load(code: &mut Vec<u8>, register: Register) {
    if let Some(offset) = offset(register) {
        code.extend([0x48, 0x8b, 0x87]); // mov rax,[rdi+disp32]
        code.extend(offset.to_le_bytes());
    } else {
        code.extend([0x31, 0xc0]);
    }
}

fn store(code: &mut Vec<u8>, register: Register) {
    if let Some(offset) = offset(register) {
        code.extend([0x48, 0x89, 0x87]); // mov [rdi+disp32],rax
        code.extend(offset.to_le_bytes());
    }
}

/// Direct ordinary-RAM profile. Guest virtual addresses equal native addresses;
/// the caller keeps code/state separate from guest mappings. Guest NZCV is untouched.
fn memory(
    code: &mut Vec<u8>,
    transfer: MemoryTransfer,
    bytes: u8,
    data: Register,
    base: Register,
    displacement: i32,
    mode: AddressMode,
) {
    memory_address(code, base, displacement, mode);
    match transfer {
        MemoryTransfer::Store => {
            right_operand(code, data, Width::X64, Shift::Lsl, 0);
            memory_store::emit(
                code,
                bytes,
                0,
                memory_store::Source::Rcx,
                memory_store::aligned_immediate(base, displacement, mode, bytes),
            );
        }
        MemoryTransfer::Load { signed, width } => {
            if width == Width::X64 {
                code.push(0x48);
            }
            match (bytes, signed) {
                (1, false) => code.extend([0x0f, 0xb6, 0x08]),
                (2, false) => code.extend([0x0f, 0xb7, 0x08]),
                (1, true) => code.extend([0x0f, 0xbe, 0x08]),
                (2, true) => code.extend([0x0f, 0xbf, 0x08]),
                (4, true) => code.extend([0x63, 0x08]), // movsxd rcx,[rax]
                (4 | 8, false) => code.extend([0x8b, 0x08]),
                _ => unreachable!("decoder validates signed scalar size"),
            }
            // Even a discarded load performs the memory access and can fault.
            if let Some(offset) = offset(data) {
                code.extend([0x48, 0x89, 0x8f]); // mov [rdi+disp32],rcx
                code.extend(offset.to_le_bytes());
            }
        }
    }
    // A failed native memory instruction cannot update the base register.
    memory_writeback(code, base, mode);
}

fn memory_address(code: &mut Vec<u8>, base: Register, displacement: i32, mode: AddressMode) {
    load(code, base);
    if base == Register::Sp {
        // The profile enables ARM SP alignment checks, before address addition.
        // A native UD2 is a mapped fault boundary, not guest exception delivery.
        code.extend([0xa8, 15, 0x74, 2, 0x0f, 0x0b]); // test al,15; jz +2; ud2
    }
    code.extend([0x48, 0x8d, 0x90]); // lea rdx,[rax+disp32]: potential writeback
    code.extend(displacement.to_le_bytes());
    if mode != AddressMode::PostIndex {
        code.extend([0x48, 0x89, 0xd0]); // mov rax,rdx: effective address
    }
}

fn memory_writeback(code: &mut Vec<u8>, base: Register, mode: AddressMode) {
    if mode != AddressMode::Offset {
        code.extend([0x48, 0x89, 0x97]); // mov [rdi+disp32],rdx
        code.extend(
            offset(base)
                .expect("memory base cannot be ZR")
                .to_le_bytes(),
        );
    }
}

/// Pair loads stage both values before committing either guest destination.
/// Pair stores expose completed first-element writes if the second access faults.
/// Concurrent/128-bit single-copy atomic semantics are outside this RAM profile.
fn memory_pair(
    code: &mut Vec<u8>,
    transfer: MemoryTransfer,
    bytes: u8,
    data: [Register; 2],
    base: Register,
    displacement: i32,
    mode: AddressMode,
) {
    memory_address(code, base, displacement, mode);
    match transfer {
        MemoryTransfer::Store => {
            right_operand(code, data[0], Width::X64, Shift::Lsl, 0);
            if let Some(offset) = offset(data[1]) {
                code.extend([0x4c, 0x8b, 0x87]); // mov r8,[rdi+disp32]
                code.extend(offset.to_le_bytes());
            } else {
                code.extend([0x45, 0x31, 0xc0]); // xor r8d,r8d
            }
            let aligned = memory_store::aligned_immediate(base, displacement, mode, bytes);
            memory_store::emit(code, bytes, 0, memory_store::Source::Rcx, aligned);
            memory_store::emit(code, bytes, bytes, memory_store::Source::R8, aligned);
        }
        MemoryTransfer::Load { signed, width } => {
            if width == Width::X64 {
                code.push(0x48);
            }
            code.extend([if signed { 0x63 } else { 0x8b }, 0x08]);
            code.extend([
                if width == Width::X64 { 0x4c } else { 0x44 },
                if signed { 0x63 } else { 0x8b },
                0x40,
                bytes,
            ]);
            // Commit only after both loads succeeded, including discarded/ZR
            // destinations. RAX/RDX retain address and potential writeback.
            for (register, rex, modrm) in [(data[0], 0x48, 0x8f), (data[1], 0x4c, 0x87)] {
                if let Some(offset) = offset(register) {
                    code.extend([rex, 0x89, modrm]);
                    code.extend(offset.to_le_bytes());
                }
            }
        }
    }
    memory_writeback(code, base, mode);
}

fn right_operand(code: &mut Vec<u8>, register: Register, width: Width, shift: Shift, amount: u8) {
    if let Some(offset) = offset(register) {
        code.extend([0x48, 0x8b, 0x8f]);
        code.extend(offset.to_le_bytes());
    } else {
        code.extend([0x31, 0xc9]);
    }
    if amount != 0 {
        if width == Width::X64 {
            code.push(0x48);
        }
        code.extend([
            0xc1,
            match shift {
                Shift::Lsl => 0xe1,
                Shift::Lsr => 0xe9,
                Shift::Asr => 0xf9,
                Shift::Ror => 0xc9,
            },
            amount,
        ]);
    }
}

fn jump(
    code: &mut Vec<u8>,
    opcode: Option<u8>,
    pc: GuestAddress,
    target: GuestAddress,
    fixups: &mut Vec<(GuestAddress, GuestAddress, usize)>,
) {
    if let Some(opcode) = opcode {
        code.extend([0x0f, opcode]);
    } else {
        code.push(0xe9);
    }
    fixups.push((pc, target, code.len()));
    code.extend([0; 4]);
}

/// Evaluate ARM conditions from saved NZCV, independent of incidental host flags.
fn condition(code: &mut Vec<u8>, condition: u8) -> Option<u8> {
    if condition >= 14 {
        return None;
    } // AL and NV both satisfy ConditionHolds.
    code.extend([0x8b, 0x87, 0, 1, 0, 0]); // mov eax,[rdi+256]
    let positive = match condition / 2 {
        0..=3 => {
            let bit = [30, 29, 31, 28][usize::from(condition / 2)];
            code.push(0xa9);
            code.extend((1u32 << bit).to_le_bytes());
            0x85 // flag set -> JNZ
        }
        4 => {
            code.push(0x25);
            code.extend(0x60000000u32.to_le_bytes());
            code.push(0x3d);
            code.extend(0x20000000u32.to_le_bytes());
            0x84 // C && !Z
        }
        5 => {
            code.extend([0x89, 0xc1, 0xc1, 0xe9, 3, 0x31, 0xc8, 0xa9]);
            code.extend(0x10000000u32.to_le_bytes());
            0x84 // N == V
        }
        _ => {
            code.extend([0x89, 0xc1, 0xc1, 0xe9, 3, 0x31, 0xc1, 0x81, 0xe1]);
            code.extend(0x10000000u32.to_le_bytes());
            code.push(0x25);
            code.extend(0x40000000u32.to_le_bytes());
            code.extend([0x09, 0xc8]);
            0x84 // !Z && N == V
        }
    };
    Some(positive ^ (condition & 1))
}

fn immediate(code: &mut Vec<u8>, value: u64) {
    code.extend([0x48, 0xb8]); // movabs rax,imm64
    code.extend(value.to_le_bytes());
}

fn nzcv(code: &mut Vec<u8>, subtract: bool) {
    code.extend([0x9c, 0x5a]); // pushfq; pop rdx, before any flag-clobbering work
    // N <- SF. Z <- ZF. C <- CF for ADD, !CF (no borrow) for SUB. V <- OF.
    code.extend([
        0x48, 0x89, 0xd0, 0x48, 0xc1, 0xe8, 7, 0x83, 0xe0, 1, 0xc1, 0xe0, 31,
    ]);
    for (source_shift, destination_shift, invert) in
        [(6, 30, false), (0, 29, subtract), (11, 28, false)]
    {
        code.extend([0x48, 0x89, 0xd1]);
        if source_shift != 0 {
            code.extend([0x48, 0xc1, 0xe9, source_shift]);
        }
        code.extend([0x83, 0xe1, 1]);
        if invert {
            code.extend([0x83, 0xf1, 1]);
        }
        code.extend([0xc1, 0xe1, destination_shift, 0x09, 0xc8]);
    }
    code.extend([0x89, 0x87, 0, 1, 0, 0]); // mov dword [rdi+256],eax
}

/// Shared semantic emission. Block compilation handles control transfers itself.
fn emit_instruction(
    code: &mut Vec<u8>,
    instruction: &Instruction,
    fixups: &mut Vec<(GuestAddress, GuestAddress, usize)>,
    target: crate::TargetCpu,
) {
    match instruction.operation {
        Operation::FloatingPoint(_) => {
            unreachable!("numerical instructions require block emission")
        }
        Operation::FloatingPointRegister(operand) => fp_register::emit(code, &operand),
        Operation::Simd(operand) => simd::emit_for_target(code, &operand, target),
        Operation::Bitfield(operand) => bitfield::emit(code, &operand),
        Operation::PcRelative(operand) => pc_relative::emit(code, &operand),
        Operation::ConditionalSelect(operand) => conditional_select::emit(code, &operand),
        Operation::ConditionalCompare(operand) => conditional_select::emit_compare(code, &operand),
        Operation::Crc(operand) => crc::emit(code, &operand, target),
        Operation::Flags(operand) => flags::emit(code, &operand),
        Operation::IntegerMath(operand) => integer_math::emit(code, &operand),
        Operation::IntegerMinMax(operand) => integer_minmax::emit(code, &operand),
        Operation::IntegerUnary(operand) => integer_unary::emit(code, &operand, target),
        Operation::Literal(operand) => literal::emit(code, &operand),
        Operation::MemoryPair {
            transfer,
            bytes,
            data,
            base,
            displacement,
            mode,
        } => {
            memory_pair(code, transfer, bytes, data, base, displacement, mode);
        }
        Operation::Memory {
            transfer,
            bytes,
            data,
            base,
            displacement,
            mode,
        } => {
            memory(code, transfer, bytes, data, base, displacement, mode);
        }
        Operation::Branch { target } => jump(code, None, instruction.pc, target, fixups),
        Operation::BranchCondition {
            target,
            condition: cond,
        } => {
            let opcode = condition(code, cond);
            jump(code, opcode, instruction.pc, target, fixups);
        }
        Operation::BranchZero {
            target,
            source,
            width,
            nonzero,
        } => {
            load(code, source);
            if width == Width::X64 {
                code.push(0x48);
            }
            code.extend([0x85, 0xc0]);
            jump(
                code,
                Some(if nonzero { 0x85 } else { 0x84 }),
                instruction.pc,
                target,
                fixups,
            );
        }
        Operation::BranchBit {
            target,
            source,
            bit,
            nonzero,
        } => {
            load(code, source);
            code.extend([0x48, 0x0f, 0xba, 0xe0, bit]); // bt rax,imm8
            jump(
                code,
                Some(if nonzero { 0x82 } else { 0x83 }),
                instruction.pc,
                target,
                fixups,
            );
        }
        Operation::AddSubCarry {
            width,
            subtract,
            flags,
            destination,
            left,
            right,
        } => {
            load(code, left);
            right_operand(code, right, width, Shift::Lsl, 0);
            // Recover guest C after operand loads, including XOR-based
            // ZR loads that clobber host flags. SBC consumes !C as borrow.
            code.extend([0x0f, 0xba, 0xa7, 0, 1, 0, 0, 29]); // bt [rdi+256],29
            if subtract {
                code.push(0xf5); // cmc: ARM no-borrow -> x86 borrow
            }
            if width == Width::X64 {
                code.push(0x48);
            }
            code.extend([if subtract { 0x19 } else { 0x11 }, 0xc8]); // sbb/adc (e/r)ax,(e/r)cx
            store(code, destination);
            if flags {
                nzcv(code, subtract);
            }
        }
        Operation::AddSubRegister {
            width,
            subtract,
            flags,
            destination,
            left,
            right,
            shift,
            amount,
        } => {
            load(code, left);
            right_operand(code, right, width, shift, amount);
            if width == Width::X64 {
                code.push(0x48);
            }
            code.extend([if subtract { 0x29 } else { 0x01 }, 0xc8]);
            store(code, destination);
            if flags {
                nzcv(code, subtract);
            }
        }
        Operation::AddSubExtended {
            width,
            subtract,
            flags,
            destination,
            left,
            right,
            extend,
            amount,
        } => {
            // Read both operands before a possibly overlapping destination/SP write.
            load(code, left);
            right_operand(code, right, Width::X64, Shift::Lsl, 0);
            match extend {
                RegisterExtend::Uxtb => code.extend([0x0f, 0xb6, 0xc9]), // movzx ecx,cl
                RegisterExtend::Uxth => code.extend([0x0f, 0xb7, 0xc9]), // movzx ecx,cx
                RegisterExtend::Uxtw => code.extend([0x89, 0xc9]),       // mov ecx,ecx
                RegisterExtend::Sxtb => code.extend([0x48, 0x0f, 0xbe, 0xc9]),
                RegisterExtend::Sxth => code.extend([0x48, 0x0f, 0xbf, 0xc9]),
                RegisterExtend::Sxtw => code.extend([0x48, 0x63, 0xc9]),
                RegisterExtend::Uxtx | RegisterExtend::Sxtx => {}
            }
            if amount != 0 {
                code.extend([0x48, 0xc1, 0xe1, amount]);
            }
            if width == Width::X64 {
                code.push(0x48);
            }
            // W32 arithmetic truncates both operands and zero-extends even WSP.
            code.extend([if subtract { 0x29 } else { 0x01 }, 0xc8]);
            store(code, destination);
            if flags {
                nzcv(code, subtract);
            }
        }
        Operation::MemoryRegisterOffset(operand) => register_offset::emit(code, &operand),
        Operation::LogicalImmediate {
            width,
            kind,
            flags,
            destination,
            source,
            immediate,
        } => {
            load(code, source);
            code.extend([0x48, 0xb9]); // movabs rcx,logical bitmask
            code.extend(immediate.to_le_bytes());
            if width == Width::X64 {
                code.push(0x48);
            }
            code.extend([
                match kind {
                    Logical::And => 0x21,
                    Logical::Or => 0x09,
                    Logical::Xor => 0x31,
                },
                0xc8,
            ]);
            store(code, destination); // MOV preserves the logical result flags.
            if flags {
                nzcv(code, false); // AND clears CF/OF, matching ARM C/V=0.
            }
        }
        Operation::LogicalRegister {
            width,
            kind,
            invert,
            flags,
            destination,
            left,
            right,
            shift,
            amount,
        } => {
            load(code, left);
            right_operand(code, right, width, shift, amount);
            if invert {
                if width == Width::X64 {
                    code.push(0x48);
                }
                code.extend([0xf7, 0xd1]);
            }
            if width == Width::X64 {
                code.push(0x48);
            }
            code.extend([
                match kind {
                    Logical::And => 0x21,
                    Logical::Or => 0x09,
                    Logical::Xor => 0x31,
                },
                0xc8,
            ]);
            store(code, destination);
            if flags {
                nzcv(code, false);
            } // AND clears host CF/OF, matching ARM C/V=0.
        }
        Operation::Return => code.push(0xc3),
        Operation::Nop => code.push(0x90),
        Operation::MoveWide {
            width,
            kind,
            destination,
            immediate: value,
            shift,
        } => {
            let value = u64::from(value) << shift;
            match kind {
                WideMove::Zero => immediate(code, value),
                WideMove::Not => immediate(code, !value),
                WideMove::Keep => {
                    load(code, destination);
                    code.extend([0x48, 0xb9]); // movabs rcx,mask
                    code.extend((!(0xffffu64 << shift)).to_le_bytes());
                    code.extend([0x48, 0x21, 0xc8, 0x48, 0xb9]); // and rax,rcx; movabs rcx,value
                    code.extend(value.to_le_bytes());
                    code.extend([0x48, 0x09, 0xc8]);
                }
            }
            if width == Width::W32 {
                code.extend([0x89, 0xc0]);
            } // mov eax,eax: zero-extend
            store(code, destination);
        }
        Operation::AddSub {
            width,
            subtract,
            flags,
            destination,
            source,
            immediate,
        } => {
            load(code, source);
            if width == Width::X64 {
                code.push(0x48);
            }
            code.extend([0x81, if subtract { 0xe8 } else { 0xc0 }]);
            code.extend(immediate.to_le_bytes());
            store(code, destination); // MOV leaves arithmetic flags unchanged.
            if flags {
                nzcv(code, subtract);
            }
        }
    }
}

impl Backend<Instruction> for Emitter {
    fn emit(&self, instructions: &[Instruction]) -> Result<NativeBlock, UnsupportedReason> {
        self.emit_for_target(instructions, crate::TargetCpu::Baseline)
    }
}
impl Emitter {
    pub fn emit_for_target(
        &self,
        instructions: &[Instruction],
        target: crate::TargetCpu,
    ) -> Result<NativeBlock, UnsupportedReason> {
        let mut block = NativeBlock {
            x86_64_code: vec![],
            source_map: vec![],
        };
        let code = &mut block.x86_64_code;
        let mut fixups = vec![];
        for instruction in instructions {
            if matches!(instruction.operation, Operation::FloatingPoint(_)) {
                return Err(UnsupportedReason::NumericalRuntimeRequired {
                    address: instruction.pc,
                });
            }
            block.source_map.push((instruction.pc, code.len()));
            emit_instruction(code, instruction, &mut fixups, target);
        }
        let offsets: std::collections::BTreeMap<_, _> = block
            .source_map
            .iter()
            .map(|(pc, offset)| (pc.0, *offset))
            .collect();
        for (pc, target, displacement) in fixups {
            let error = || UnsupportedReason::UnresolvedDirectTarget {
                address: pc,
                target,
            };
            let destination = *offsets.get(&target.0).ok_or_else(error)?;
            let relative = destination as i128 - (displacement + 4) as i128;
            let relative = i32::try_from(relative).map_err(|_| error())?;
            code[displacement..displacement + 4].copy_from_slice(&relative.to_le_bytes());
        }
        Ok(block)
    }
}
