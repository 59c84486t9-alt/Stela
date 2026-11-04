//! Branchless conditional select from the saved guest NZCV.
use super::{capture_nzcv, condition_holds, flag_word, load, right_operand, store, store_nzcv};
use crate::aarch64::{
    Register, Shift, Width,
    conditional_select::{CompareOperand, CompareRight, Operand, Otherwise},
};
use crate::x86_64::asm::{
    Alu, Asm, Code, Cond,
    Gpr::{R8, Rax, Rcx, Rdx},
    Rm, Size, Unary,
};

const NZCV_SHIFT: u8 = 28;

/// The comparison runs on both arms and a CMOV picks its flags or the
/// fallback, so the timing depends on neither the condition nor the data.
pub(super) fn emit_compare(code: &mut Code, operand: &CompareOperand) {
    let predicate = condition_holds(code, operand.condition, false);
    if let Some(cond) = predicate {
        // R8 is scratch under the native leaf ABI.
        code.asm().setcc(cond, R8);
    }
    load(code, operand.left);
    match operand.right {
        CompareRight::Register(register) => {
            right_operand(code, register, operand.width, Shift::Lsl, 0)
        }
        CompareRight::Immediate(value) => code.asm().mov_imm32(Rcx, u32::from(value)),
    }
    let op = if operand.subtract { Alu::Sub } else { Alu::Add };
    code.asm()
        .alu(op, Size::of(operand.width == Width::X64), Rax, Rcx);
    let pinned = code.is_pinned();
    if pinned {
        flag_word::capture_in_rax(code, operand.subtract);
    } else {
        capture_nzcv(code, operand.subtract);
    }
    let fallback = flag_word::constant(code, u32::from(operand.fallback) << NZCV_SHIFT);
    let mut asm = code.asm();
    if predicate.is_some() {
        // The fallback NZCV word where the condition fails.
        asm.mov_imm32(Rdx, fallback);
        asm.test(Size::Byte, R8, R8);
        asm.cmov(Cond::E, Size::Dword, Rax, Rdx);
    }
    if pinned {
        flag_word::store(&mut asm, Rax);
    } else {
        store_nzcv(&mut asm);
    }
}

pub(super) fn emit(code: &mut Code, operand: &Operand, live_nzcv: bool) {
    let size = Size::of(operand.width == Width::X64);
    let destination = code.host(operand.destination);
    let output = destination.unwrap_or(Rax);
    if operand.left == Register::Zero
        && operand.right == Register::Zero
        && matches!(operand.otherwise, Otherwise::Increment | Otherwise::Invert)
        && let Some(predicate) = condition_holds(code, operand.condition, live_nzcv)
    {
        // CSET and CSETM materialize the condition as a bit or a mask.
        let mut asm = code.asm();
        asm.setcc(predicate.negate(), output);
        asm.movzx(Size::Dword, output, Size::Byte, output);
        if operand.otherwise == Otherwise::Invert {
            asm.unary(Unary::Neg, size, output);
        }
        if destination.is_none() {
            store(code, operand.destination);
        }
        return;
    }
    let otherwise = if operand.condition >= 14 {
        // AL and NV always select Rn.
        None
    } else if operand.otherwise == Otherwise::Unchanged
        && let Some(source) = code.asm().guest(operand.right)
    {
        Some(source)
    } else {
        // Prepare the false arm before the predicate. R8 survives predicate
        // emission, and the true arm is a MOV that leaves host flags intact.
        let mut asm = code.asm();
        select_input(&mut asm, R8, size, operand.right);
        match operand.otherwise {
            Otherwise::Increment => asm.inc(size, R8),
            Otherwise::Invert => asm.unary(Unary::Not, size, R8),
            Otherwise::Negate => asm.unary(Unary::Neg, size, R8),
            Otherwise::Unchanged => {}
        }
        Some(Rm::Reg(R8))
    };
    // If the unchanged false arm already lives in the result register,
    // keep it there and conditionally move the true arm instead.
    let keep_false = operand.left != operand.destination
        && matches!(otherwise, Some(Rm::Reg(source)) if source == output);
    let (initial, alternate) = if keep_false {
        let mut asm = code.asm();
        let source = asm.guest(operand.left).unwrap_or_else(|| {
            asm.mov_imm32(R8, 0);
            Rm::Reg(R8)
        });
        (operand.destination, Some(source))
    } else {
        (operand.left, otherwise)
    };
    let predicate = condition_holds(code, operand.condition, live_nzcv);
    let mut asm = code.asm();
    let selected = predicate.zip(alternate);
    let already_placed = destination.is_some() && initial == operand.destination;
    // CMOVcc r32 in 64-bit mode clears the upper half even when its
    // predicate is false (Intel SDM, CMOVcc).
    if selected.is_none() || !already_placed {
        select_input(&mut asm, output, size, initial);
    }
    if let Some((predicate, alternate)) = selected {
        let take_alternate = if keep_false {
            predicate
        } else {
            predicate.negate()
        };
        asm.cmov(take_alternate, size, output, alternate);
    }
    if destination.is_none() {
        store(code, operand.destination);
    }
}

/// A W source is zero-extended by the sized MOV. XZR uses an immediate
/// instead of XOR so it can be loaded after the predicate.
fn select_input(asm: &mut Asm, host: crate::x86_64::asm::Gpr, size: Size, guest: Register) {
    if let Some(source) = asm.guest(guest) {
        asm.mov_load(size, host, source);
    } else {
        asm.mov_imm32(host, 0);
    }
}

#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
mod tests {
    use super::*;
    use crate::GuestState;

    #[test]
    fn selects_preserve_nzcv_and_zero_extend_w_results() {
        const LEFT: u64 = 0x1234_5678_9abc_def0;
        const RIGHT: u64 = 0xfedc_ba98_7654_3210;
        let cases = [Width::W32, Width::X64]
            .into_iter()
            .flat_map(|width| [1, 2, 8].map(|destination| (width, destination)));
        for (width, destination) in cases {
            for (left, lhs) in [(Register::X(1), LEFT), (Register::Zero, 0)] {
                for (right, rhs) in [(Register::X(8), RIGHT), (Register::Zero, 0)] {
                    for (otherwise, alternate) in [
                        (Otherwise::Unchanged, rhs),
                        (Otherwise::Increment, rhs.wrapping_add(1)),
                        (Otherwise::Invert, !rhs),
                        (Otherwise::Negate, rhs.wrapping_neg()),
                    ] {
                        for condition in [0, 1, 10, 12, 14, 15] {
                            let operand = Operand {
                                width,
                                destination: Register::X(destination),
                                left,
                                right,
                                condition,
                                otherwise,
                            };
                            let mut frame = Code::new();
                            let mut pinned = Code::pinned();
                            emit(&mut frame, &operand, false);
                            emit(&mut pinned, &operand, false);
                            pinned.asm().ret();
                            let pinned = super::super::pinned::entered(&pinned);
                            for flags in 0..16 {
                                let n = flags & 8 != 0;
                                let z = flags & 4 != 0;
                                let v = flags & 1 != 0;
                                let select_left = match condition {
                                    0 => z,
                                    1 => !z,
                                    10 => n == v,
                                    12 => n == v && !z,
                                    _ => true,
                                };
                                let expected = if select_left { lhs } else { alternate };
                                let expected = if width == Width::W32 {
                                    u64::from(expected as u32)
                                } else {
                                    expected
                                };
                                for code in [&frame[..], &pinned] {
                                    let mut state = GuestState {
                                        nzcv: flags << 28,
                                        ..Default::default()
                                    };
                                    state.x[1] = LEFT;
                                    state.x[8] = RIGHT;
                                    super::super::native::run(code, &mut state);
                                    let mut expected_registers = [0; 31];
                                    expected_registers[1] = LEFT;
                                    expected_registers[8] = RIGHT;
                                    expected_registers[usize::from(destination)] = expected;
                                    assert_eq!(state.x, expected_registers, "{operand:?}");
                                    assert_eq!(state.nzcv, flags << 28);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
