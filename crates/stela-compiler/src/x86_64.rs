//! Native x86-64 emitter. Guest state pointer remains in RDI throughout.
use crate::{
    Backend, GuestAddress, NativeBlock, UnsupportedReason,
    aarch64::{
        AddressMode, Instruction, Logical, MemoryTransfer, Operation, Register, RegisterExtend,
        Shift, WideMove, Width,
    },
};
use alloc::vec;
use alloc::vec::Vec;

pub struct Emitter;

/// Check semantic host requirements before either leaf or block emission.
pub(crate) fn validate_target(
    instruction: &Instruction,
    target: crate::TargetCpu,
) -> Result<(), UnsupportedReason> {
    if matches!(
        instruction.operation,
        Operation::Exclusive(_) | Operation::CheckedPointer(_)
    ) {
        return Err(UnsupportedReason::PrivilegedOperation {
            address: instruction.pc,
        });
    }
    if let Operation::Synchronization(operation) = &instruction.operation
        && !matches!(
            operation,
            crate::aarch64::system::synchronization::Operation::Yield
                | crate::aarch64::system::synchronization::Operation::ConsumptionBarrier
                | crate::aarch64::system::synchronization::Operation::SpeculationBarrier
        )
    {
        return Err(UnsupportedReason::PrivilegedOperation {
            address: instruction.pc,
        });
    }
    if let Operation::Ordered(operand) = &instruction.operation
        && ordered::requires_atomic_load16(operand)
        && !target.supports(crate::TargetCpu::AtomicLoad16)
    {
        return Err(UnsupportedReason::HostCapabilityRequired {
            address: instruction.pc,
            required: crate::TargetCpu::AtomicLoad16,
        });
    }
    if let Operation::Atomic(operand) = &instruction.operation
        && atomic::requires_cx16(operand)
        && !target.supports(crate::TargetCpu::Cx16)
    {
        return Err(UnsupportedReason::HostCapabilityRequired {
            address: instruction.pc,
            required: crate::TargetCpu::Cx16,
        });
    }
    Ok(())
}
mod atomic;
mod bitfield;
pub(crate) mod block;
pub(crate) mod checked_pointer;
mod conditional_select;
mod crc;
pub(crate) mod exclusive;
mod flags;
mod fp_register;
mod integer_math;
mod integer_minmax;
mod integer_unary;
pub mod isa;
mod literal;
pub(crate) mod memory_context;
pub(crate) mod memory_store;
mod non_temporal;
mod ordered;
mod pc_relative;
mod pointer_checks;
mod prefetch;
mod region;
mod register_offset;
mod scalable;
mod scalable_matrix;
mod simd;
pub(crate) use simd::memory_checked::CheckedOperand as CheckedFixedMemoryOperand;
pub(crate) mod sme;
pub(crate) mod sve;
mod system;
mod tag_arithmetic;
mod unprivileged;

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
    const HOST_SIGN_BIT: u8 = 7;
    const HOST_ZERO_BIT: u8 = 6;
    const HOST_OVERFLOW_BIT: u8 = 11;
    const ARM_NEGATIVE_BIT: u8 = 31;
    const ARM_ZERO_BIT: u8 = 30;
    const ARM_CARRY_BIT: u8 = 29;
    const ARM_OVERFLOW_BIT: u8 = 28;
    const NEGATIVE_ZERO_MASK: u32 = (1 << ARM_NEGATIVE_BIT) | (1 << ARM_ZERO_BIT);
    const STATE_NZCV_OFFSET: u32 = core::mem::offset_of!(crate::GuestState, nzcv) as u32;
    const SIGN_ZERO_SHIFT: u8 = ARM_NEGATIVE_BIT - HOST_SIGN_BIT;
    const _: () = assert!(SIGN_ZERO_SHIFT == ARM_ZERO_BIT - HOST_ZERO_BIT);

    code.extend([0x9c, 0x5a]); // pushfq; pop rdx: capture before modifying flags.
    code.extend([0x89, 0xd0]); // mov eax,edx
    code.extend([0xc1, 0xe0, SIGN_ZERO_SHIFT]); // shl eax,24: SF/ZF together.
    code.push(0x25); // and eax,imm32: retain ARM N/Z only.
    code.extend(NEGATIVE_ZERO_MASK.to_le_bytes());

    code.extend([0x89, 0xd1, 0x83, 0xe1, 1]); // mov ecx,edx; and ecx,1: CF.
    if subtract {
        code.extend([0x83, 0xf1, 1]); // xor ecx,1: ARM subtraction has no-borrow C.
    }
    code.extend([0xc1, 0xe1, ARM_CARRY_BIT, 0x09, 0xc8]); // shl ecx,29; or eax,ecx

    code.extend([0xc1, 0xea, HOST_OVERFLOW_BIT, 0x83, 0xe2, 1]); // shr edx,11; and edx,1
    code.extend([0xc1, 0xe2, ARM_OVERFLOW_BIT, 0x09, 0xd0]); // shl edx,28; or eax,edx
    code.extend([0x89, 0x87]); // mov dword [rdi+GuestState.nzcv],eax
    code.extend(STATE_NZCV_OFFSET.to_le_bytes());
}

/// Shared semantic emission. Block compilation handles control transfers itself.
pub(crate) fn emit_instruction(
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
        Operation::Synchronization(operand) => system::synchronization::emit(code, &operand)
            .expect("decoder admits only context-independent synchronization"),
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
        Operation::MemoryNonTemporal(operand) => non_temporal::emit(code, &operand),
        Operation::MemoryUnprivileged(operand) => unprivileged::emit(code, &operand),
        Operation::TagArithmetic(operand) => tag_arithmetic::emit(code, &operand),
        Operation::Atomic(operand) => atomic::emit(code, &operand, target),
        Operation::Ordered(operand) => ordered::emit(code, &operand, target),
        Operation::Prefetch(operand) => prefetch::emit(code, &operand),
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
        Operation::Exclusive(_) => unreachable!("exclusive requires checked context emitter"),
        Operation::CheckedPointer(_) => {
            unreachable!("CPA arithmetic requires checked context emitter")
        }
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
            validate_target(instruction, target)?;
            if matches!(instruction.operation, Operation::FloatingPoint(_)) {
                return Err(UnsupportedReason::NumericalRuntimeRequired {
                    address: instruction.pc,
                });
            }
            block.source_map.push((instruction.pc, code.len()));
            emit_instruction(code, instruction, &mut fixups, target);
        }
        let offsets: alloc::collections::BTreeMap<_, _> = block
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

#[cfg(test)]
mod synchronization_tests {
    use super::*;
    use crate::aarch64::system::synchronization::{
        Operation as Synchronization, Requirement, Scope, WaitKind,
    };

    #[test]
    fn constructed_context_operations_return_an_explicit_error() {
        const BARRIER_OPTION_OSH: u8 = 3;
        const BARRIER_OPTION_SY: u8 = 15;
        const BTI_JC_TARGETS: u8 = 3;
        const RESERVED_HINT_IMMEDIATE: u8 = 127;
        let pc = GuestAddress(0x1000);
        for operation in [
            Synchronization::DataCompletion {
                option: BARRIER_OPTION_OSH,
                scope: Scope::OuterShareable,
                requirement: Requirement::All,
                nxs: false,
            },
            Synchronization::InstructionSynchronization {
                option: BARRIER_OPTION_SY,
            },
            Synchronization::StoreBypassBarrier { physical: false },
            Synchronization::StoreBypassBarrier { physical: true },
            Synchronization::BranchTarget {
                targets: BTI_JC_TARGETS,
            },
            Synchronization::Wait {
                kind: WaitKind::Event,
                timeout_register: None,
            },
            Synchronization::SendEvent { local: false },
            Synchronization::ErrorSynchronization,
            Synchronization::TraceSynchronization,
            Synchronization::OtherHint {
                immediate: RESERVED_HINT_IMMEDIATE,
            },
        ] {
            let instructions = [
                Instruction {
                    pc,
                    operation: Operation::Nop,
                },
                Instruction {
                    pc: GuestAddress(pc.0 + size_of::<u32>() as u64),
                    operation: Operation::Synchronization(operation),
                },
            ];
            assert!(
                matches!(Emitter.emit_for_target(&instructions, crate::TargetCpu::Baseline),
                Err(UnsupportedReason::PrivilegedOperation { address }) if address == instructions[1].pc)
            );
        }
    }
}
