//! Native x86-64 emitter. Guest state pointer remains in RDI throughout.
use crate::{
    Backend, GuestAddress, NativeBlock, UnsupportedReason,
    aarch64::{Instruction, Logical, Operation, Register, Shift, WideMove, Width},
};

pub struct Emitter;

fn offset(register: Register) -> Option<u32> {
    match register {
        Register::X(index) => Some(u32::from(index) * 8),
        Register::Sp => Some(248),
        Register::Zero => None,
    }
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

impl Backend<Instruction> for Emitter {
    fn emit(&self, instructions: &[Instruction]) -> Result<NativeBlock, UnsupportedReason> {
        let mut block = NativeBlock {
            x86_64_code: vec![],
            source_map: vec![],
        };
        let code = &mut block.x86_64_code;
        let mut fixups = vec![];
        for instruction in instructions {
            block.source_map.push((instruction.pc, code.len()));
            match instruction.operation {
                Operation::Branch { target } => {
                    jump(code, None, instruction.pc, target, &mut fixups)
                }
                Operation::BranchCondition {
                    target,
                    condition: cond,
                } => {
                    let opcode = condition(code, cond);
                    jump(code, opcode, instruction.pc, target, &mut fixups);
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
                        &mut fixups,
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
                        &mut fixups,
                    );
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
