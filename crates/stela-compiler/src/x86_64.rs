//! Native x86-64 emitter. Guest state pointer remains in RDI throughout.
use crate::{
    Backend, NativeBlock, UnsupportedReason,
    aarch64::{Instruction, Operation, Register, WideMove, Width},
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
        for instruction in instructions {
            block.source_map.push((instruction.pc, code.len()));
            match instruction.operation {
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
        Ok(block)
    }
}
