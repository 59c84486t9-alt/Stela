//! Keeping NZCV in host flags across non-faulting spans and self-loops; it is
//! written back at each exit.
use super::{
    Effects, Emitter, RegionError,
    allocation::{Value, ValueEffects},
    analysis, encoding,
};
use crate::aarch64::{
    Instruction, Logical, Operation, Register, Shift, Width,
    conditional_select::{Operand, Otherwise},
    flags::{NZCV_C, NZCV_N, NZCV_V, NZCV_Z},
};
use crate::x86_64::asm::Code;
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
            // The register arithmetic sets the host flags; the following
            // register copies and ZR NOP preserve them.
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
    match operand.otherwise {
        Otherwise::Unchanged => {}
        Otherwise::Increment => {
            emitter.emit(|code| encoding::increment_preserving_flags(code, RIGHT, operand.width))
        }
        Otherwise::Invert => emitter.emit(|code| encoding::invert(code, operand.width)),
        Otherwise::Negate => {
            emitter.emit(|code| encoding::invert(code, operand.width));
            emitter.emit(|code| encoding::increment_preserving_flags(code, RIGHT, operand.width));
        }
    }
    emit_predicate(emitter, predicate(operand.condition, carry), operand.width);
    emitter.commit(operand.destination, operand.width);
}

/// NZCV is tracked by the same allocator as GPR values. The frame copy is
/// current only at entry or after a write-back.
#[derive(Debug, Clone, Copy)]
pub(super) enum Location {
    Frame,
    Native(Carry),
    Packed,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum ValueStep {
    Ordinary,
    Define(Carry),
    Select,
}

pub(super) fn analyze_value(operation: &Operation) -> Option<(Effects, ValueEffects, ValueStep)> {
    // A placeholder carry source that permits every condition; the real
    // producer is chosen at emission.
    let mut provenance = Some(Carry::Native);
    let (gprs, step) = analyze(operation, &mut provenance)?;
    let (reads_flags, writes_flags, step) = match step {
        Step::Ordinary => (false, false, ValueStep::Ordinary),
        Step::Define => (false, true, ValueStep::Define(provenance.unwrap())),
        Step::Select(_) => {
            let Operation::ConditionalSelect(operand) = operation else {
                unreachable!()
            };
            (operand.condition < ARM_AL, false, ValueStep::Select)
        }
    };
    Some((
        gprs,
        ValueEffects::new(gprs, reads_flags, writes_flags),
        step,
    ))
}

const ARM_OVERFLOW_BIT: u8 = NZCV_V.trailing_zeros() as u8;
const _: () = assert!(matches!(RESULT, encoding::HostGpr::Rax));
const _: () = assert!(matches!(RIGHT, encoding::HostGpr::Rdx));

/// The two-scratch SETcc capture into RESULT (EAX), clobbering RIGHT (RDX).
/// RCX (a live value or budget) is intact.
fn pack_native(code: &mut Code, carry: Carry) {
    crate::x86_64::capture_nzcv(code, matches!(carry, Carry::Inverted));
}

impl Emitter<'_> {
    fn preserve_native_flags(&mut self) {
        let Location::Native(carry) = self.flag_location else {
            return;
        };
        if !self
            .allocation
            .as_ref()
            .unwrap()
            .requires_after(self.current, Value::NZCV)
        {
            self.flag_location = Location::Frame;
            self.output.stats.dead_versions += 1;
            return;
        }
        self.emit(|code| pack_native(code, carry));
        let index = self.allocate_value(Value::NZCV);
        let host = encoding::pool_host(index);
        self.emit(|code| encoding::copy(code, host, RESULT, Width::W32));
        self.resident[index] = Some(super::Resident {
            guest: Value::NZCV.slot(),
            dirty: true,
        });
        self.flag_location = Location::Packed;
    }

    pub(super) fn settle_value_flags(&mut self) {
        if let Location::Native(carry) = self.flag_location {
            self.emit(|code| pack_native(code, carry));
            self.emit(|code| encoding::store_nzcv(code, RESULT));
            self.output.stats.flag_stores += 1;
            self.flag_location = Location::Frame;
        }
    }

    fn packed_flags(&mut self) -> encoding::HostGpr {
        if let Some(index) = self.value_index(Value::NZCV) {
            return encoding::pool_host(index);
        }
        let index = self.allocate_value(Value::NZCV);
        let host = encoding::pool_host(index);
        self.emit(|code| encoding::load_nzcv(code, host));
        self.output.stats.flag_loads += 1;
        self.flag_location = Location::Packed;
        host
    }

    pub(super) fn value_instruction(
        &mut self,
        instruction: &Instruction,
        step: ValueStep,
    ) -> Result<(), RegionError> {
        let source_start = self.output.code.len();
        match step {
            ValueStep::Ordinary => {
                // MOV-immediate/PC and NOP are neutral; all other supported
                // ordinary recipes conservatively preserve the live flag bank.
                if !matches!(
                    instruction.operation,
                    Operation::Nop
                        | Operation::PcRelative(_)
                        | Operation::MoveWide {
                            kind: crate::aarch64::WideMove::Zero | crate::aarch64::WideMove::Not,
                            ..
                        }
                ) {
                    self.preserve_native_flags();
                }
                let result = self.instruction(instruction);
                if let Some((_, offset)) = self.output.source_map.last_mut() {
                    *offset = source_start;
                }
                result
            }
            ValueStep::Define(carry) => {
                if let Some(index) = self.value_index(Value::NZCV) {
                    self.forget_value(index);
                }
                self.flag_location = Location::Frame;
                let mut lowered = instruction.clone();
                remove_flag_capture(&mut lowered.operation);
                self.instruction_defining_flags(&lowered)?;
                self.flag_location = Location::Native(carry);
                if let Some((_, offset)) = self.output.source_map.last_mut() {
                    *offset = source_start;
                }
                Ok(())
            }
            ValueStep::Select => {
                let Operation::ConditionalSelect(operand) = instruction.operation else {
                    unreachable!()
                };
                self.pinned_hosts = 0;
                self.coalesced = None;
                self.output
                    .source_map
                    .push((instruction.pc, self.output.code.len()));
                let selected = if operand.condition >= ARM_AL {
                    Predicate::Constant(true)
                } else if let Location::Native(carry) = self.flag_location {
                    predicate(operand.condition, carry)
                } else {
                    let host = self.packed_flags();
                    self.emit(|code| encoding::copy(code, RESULT, host, Width::W32));
                    packed_predicate(self, operand.condition)
                };
                self.read(operand.left, RESULT);
                if operand.width == Width::W32 {
                    self.emit(|code| encoding::copy(code, RESULT, RESULT, Width::W32));
                }
                if operand.condition >= ARM_AL {
                    self.commit(operand.destination, operand.width);
                    return Ok(());
                }
                self.read(operand.right, RIGHT);
                if operand.width == Width::W32 {
                    self.emit(|code| encoding::copy(code, RIGHT, RIGHT, Width::W32));
                }
                match operand.otherwise {
                    Otherwise::Unchanged => {}
                    Otherwise::Increment => self.emit(|code| {
                        encoding::increment_preserving_flags(code, RIGHT, operand.width)
                    }),
                    Otherwise::Invert => self.emit(|code| encoding::invert(code, operand.width)),
                    Otherwise::Negate => {
                        self.emit(|code| encoding::invert(code, operand.width));
                        self.emit(|code| {
                            encoding::increment_preserving_flags(code, RIGHT, operand.width)
                        });
                    }
                }
                emit_predicate(self, selected, operand.width);
                self.commit(operand.destination, operand.width);
                Ok(())
            }
        }
    }
}

fn emit_predicate(emitter: &mut Emitter<'_>, selected: Predicate, width: Width) {
    match selected {
        Predicate::Constant(true) => {}
        Predicate::Constant(false) => {
            emitter.emit(|code| encoding::copy(code, RESULT, RIGHT, width))
        }
        Predicate::One(condition) => emitter.emit(|code| {
            encoding::conditional_copy(code, RESULT, RIGHT, condition.inverse(), width)
        }),
        Predicate::All(first, second) => {
            emitter.emit(|code| {
                encoding::conditional_copy(code, RESULT, RIGHT, first.inverse(), width)
            });
            emitter.emit(|code| {
                encoding::conditional_copy(code, RESULT, RIGHT, second.inverse(), width)
            });
        }
        Predicate::Any(first, second) => emitter.emit(|code| {
            let keep_first = encoding::conditional_jump(code, first);
            let keep_second = encoding::conditional_jump(code, second);
            encoding::copy(code, RESULT, RIGHT, width);
            let end = code.len();
            encoding::patch_relative(code, keep_first, end);
            encoding::patch_relative(code, keep_second, end);
        }),
    }
}

const ARM_NIBBLE_SHIFT: u8 = ARM_OVERFLOW_BIT;
const NIBBLE_N: u32 = NZCV_N >> ARM_NIBBLE_SHIFT;
const NIBBLE_Z: u32 = NZCV_Z >> ARM_NIBBLE_SHIFT;
const NIBBLE_C: u32 = NZCV_C >> ARM_NIBBLE_SHIFT;
const NIBBLE_V: u32 = NZCV_V >> ARM_NIBBLE_SHIFT;
const NIBBLE_N_TO_V_SHIFT: u8 = (NZCV_N.trailing_zeros() - NZCV_V.trailing_zeros()) as u8;

/// Produce a host predicate from the packed bank before loading scratch operands.
/// The architectural flag value stays packed and is not replaced by this TEST.
fn packed_predicate(emitter: &mut Emitter<'_>, condition: u8) -> Predicate {
    use encoding::ImmediateExtension::{And, Compare};
    emitter.emit(|code| {
        encoding::shift_register(code, RESULT, Shift::Lsr, ARM_NIBBLE_SHIFT, Width::W32)
    });
    let positive = condition & 1 == 0;
    let (mask, expected) = match condition >> 1 {
        0 => (NIBBLE_Z, NIBBLE_Z),
        1 => (NIBBLE_C, NIBBLE_C),
        2 => (NIBBLE_N, NIBBLE_N),
        3 => (NIBBLE_V, NIBBLE_V),
        4 => (NIBBLE_C | NIBBLE_Z, NIBBLE_C),
        group @ (5 | 6) => {
            emitter.emit(|code| encoding::copy(code, RIGHT, RESULT, Width::W32));
            emitter.emit(|code| {
                encoding::shift_register(code, RIGHT, Shift::Lsr, NIBBLE_N_TO_V_SHIFT, Width::W32)
            });
            emitter.emit(|code| {
                encoding::binary(code, RIGHT, RESULT, encoding::Binary::Xor, Width::W32)
            });
            emitter
                .emit(|code| encoding::integer_immediate(code, RIGHT, And, NIBBLE_V, Width::W32));
            emitter.emit(|code| {
                encoding::integer_immediate(
                    code,
                    RESULT,
                    And,
                    if group == 6 { NIBBLE_Z } else { 0 },
                    Width::W32,
                )
            });
            emitter.emit(|code| {
                encoding::binary(code, RESULT, RIGHT, encoding::Binary::Or, Width::W32)
            });
            (NIBBLE_Z | NIBBLE_V, 0)
        }
        _ => unreachable!("AL/NV handled without reading flags"),
    };
    emitter.emit(|code| encoding::integer_immediate(code, RESULT, And, mask, Width::W32));
    emitter.emit(|code| encoding::integer_immediate(code, RESULT, Compare, expected, Width::W32));
    Predicate::One(if positive {
        NativeCondition::Equal
    } else {
        NativeCondition::NotEqual
    })
}

/// Complete exit capture after all native-resident GPR outputs have been stored.
pub(super) fn settle_native_exit(code: &mut Code, carry: Carry) {
    pack_native(code, carry);
    encoding::store_nzcv(code, RESULT);
}
