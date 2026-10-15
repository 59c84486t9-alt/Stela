//! Integer host-flag provenance inside nonfaulting resident loops.
//! Every admitted exit is still defined by the final complete subtraction.
use super::{Effects, Emitter, RegionError, analysis, encoding};
use crate::aarch64::{
    Instruction, Logical, Operation, Register, Width,
    conditional_select::{Operand, Otherwise},
};
use encoding::{NativeCondition, RESULT, RIGHT};

const ARM_CS: u8 = 0b0010;
const ARM_CC: u8 = 0b0011;
const ARM_HI: u8 = 0b1000;
const ARM_LS: u8 = 0b1001;
const ARM_AL: u8 = 0b1110;
const ARM_NV: u8 = 0b1111;

#[derive(Debug, Clone, Copy)]
pub(super) enum Carry {
    Native,
    Inverted,
    Zero,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum Step {
    Ordinary,
    Define,
    Select(Carry),
}

pub(super) fn analyze(
    operation: &Operation,
    provenance: &mut Option<Carry>,
) -> Option<(Effects, Step)> {
    let mut lowered = operation.clone();
    let defined = match &mut lowered {
        Operation::AddSub {
            flags: true,
            subtract,
            ..
        }
        | Operation::AddSubRegister {
            flags: true,
            subtract,
            ..
        } => Some(if *subtract {
            Carry::Inverted
        } else {
            Carry::Native
        }),
        Operation::LogicalImmediate {
            flags: true,
            kind: Logical::And,
            ..
        }
        | Operation::LogicalRegister {
            flags: true,
            kind: Logical::And,
            ..
        } => Some(Carry::Zero),
        _ => None,
    };
    if let Some(carry) = defined {
        remove_flag_capture(&mut lowered);
        let effects = analysis::effects(&lowered)?;
        *provenance = Some(carry);
        return Some((effects, Step::Define));
    }
    if let Operation::ConditionalSelect(operand) = operation {
        if operand.condition > ARM_NV
            || [operand.destination, operand.left, operand.right]
                .iter()
                .any(|register| matches!(register, Register::Sp | Register::X(31..)))
        {
            return None;
        }
        // AL/NV do not read flags. This value only selects a constant predicate;
        // it never establishes new host-flag provenance for a later consumer.
        let carry = if operand.condition >= ARM_AL {
            Carry::Zero
        } else {
            (*provenance)?
        };
        let bit = |register| analysis::slot(register).map_or(0, |slot| 1 << slot);
        return Some((
            Effects {
                reads: bit(operand.left) | bit(operand.right),
                writes: bit(operand.destination),
            },
            Step::Select(carry),
        ));
    }
    let effects = analysis::effects(operation)?;
    // Conservatively decline a later read after ordinary arithmetic or constant
    // recipes may overwrite host flags. NOP is the only proven neutral shape here.
    if !matches!(operation, Operation::Nop) {
        *provenance = None;
    }
    Some((effects, Step::Ordinary))
}

fn remove_flag_capture(operation: &mut Operation) {
    match operation {
        Operation::AddSub { flags, .. }
        | Operation::AddSubRegister { flags, .. }
        | Operation::LogicalImmediate { flags, .. }
        | Operation::LogicalRegister { flags, .. } => *flags = false,
        _ => unreachable!("analyzed complete integer flag producer"),
    }
}

pub(super) fn emit(
    emitter: &mut Emitter<'_>,
    instruction: &Instruction,
    step: Step,
) -> Result<(), RegionError> {
    match step {
        Step::Ordinary => emitter.instruction(instruction),
        Step::Define => {
            let mut lowered = instruction.clone();
            remove_flag_capture(&mut lowered.operation);
            // Existing register arithmetic defines the actual host flags; its
            // register copies and zero-destination NOP preserve those flags.
            emitter.instruction_defining_flags(&lowered)
        }
        Step::Select(carry) => {
            let Operation::ConditionalSelect(operand) = instruction.operation else {
                unreachable!("analyzed conditional select")
            };
            emit_select(emitter, instruction.pc, operand, carry);
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Predicate {
    Constant(bool),
    One(NativeCondition),
    All(NativeCondition, NativeCondition),
    Any(NativeCondition, NativeCondition),
}

fn predicate(condition: u8, carry: Carry) -> Predicate {
    use NativeCondition::{AboveEqual, Below, Equal, NotEqual};
    match (condition, carry) {
        (ARM_AL..=ARM_NV, _) => Predicate::Constant(true),
        (ARM_CS, Carry::Native) => Predicate::One(Below),
        (ARM_CC, Carry::Native) => Predicate::One(AboveEqual),
        (ARM_HI, Carry::Native) => Predicate::All(Below, NotEqual),
        (ARM_LS, Carry::Native) => Predicate::Any(AboveEqual, Equal),
        (ARM_CS | ARM_HI, Carry::Zero) => Predicate::Constant(false),
        (ARM_CC | ARM_LS, Carry::Zero) => Predicate::Constant(true),
        _ => Predicate::One(encoding::SUBTRACTION_CONDITIONS[usize::from(condition)]),
    }
}

fn emit_select(emitter: &mut Emitter<'_>, pc: crate::GuestAddress, operand: Operand, carry: Carry) {
    emitter.pinned_hosts = 0;
    emitter.constants.clear();
    emitter
        .output
        .source_map
        .push((pc, emitter.output.code.len()));
    emitter.read(operand.left, RESULT);
    if operand.width == Width::W32 {
        emitter.emit(|code| encoding::copy(code, RESULT, RESULT, Width::W32));
    }
    if operand.condition >= ARM_AL {
        emitter.commit(operand.destination, operand.width);
        return;
    }
    emitter.read(operand.right, RIGHT);
    if operand.width == Width::W32 {
        emitter.emit(|code| encoding::copy(code, RIGHT, RIGHT, Width::W32));
    }
    emitter.emit(|code| match operand.otherwise {
        Otherwise::Unchanged => {}
        Otherwise::Increment => encoding::increment_preserving_flags(code, RIGHT, operand.width),
        Otherwise::Invert => encoding::invert(code, operand.width),
        Otherwise::Negate => {
            encoding::invert(code, operand.width);
            encoding::increment_preserving_flags(code, RIGHT, operand.width);
        }
    });
    emitter.emit(|code| match predicate(operand.condition, carry) {
        Predicate::Constant(true) => {}
        Predicate::Constant(false) => encoding::copy(code, RESULT, RIGHT, operand.width),
        Predicate::One(condition) => {
            encoding::conditional_copy(code, RESULT, RIGHT, condition.inverse(), operand.width)
        }
        Predicate::All(first, second) => {
            encoding::conditional_copy(code, RESULT, RIGHT, first.inverse(), operand.width);
            encoding::conditional_copy(code, RESULT, RIGHT, second.inverse(), operand.width);
        }
        Predicate::Any(first, second) => {
            let keep_first = encoding::conditional_jump(code, first);
            let keep_second = encoding::conditional_jump(code, second);
            encoding::copy(code, RESULT, RIGHT, operand.width);
            let end = code.len();
            encoding::patch_relative(code, keep_first, end);
            encoding::patch_relative(code, keep_second, end);
        }
    });
    emitter.commit(operand.destination, operand.width);
}
