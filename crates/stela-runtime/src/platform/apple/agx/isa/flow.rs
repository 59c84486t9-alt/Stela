//! Control flow: the nesting-counter instructions, jumps, calls, stops,
//! barriers and waits.
//!
//! The nesting counter `r0l` (Public: Mesa compiler README, `agx_compile.c`
//! `emit_if`/`emit_loop`, `agx_lower_pseudo.c`) gives each thread how many
//! `pop_exec` levels it is below; a thread runs iff it is zero. With `n` the
//! `nest` immediate and `v` a present thread's counter:
//! - `if cond`: `v != 0` → `v += n`; else `!cond` → `v = 1`.
//! - `else cond`: `v == 0` → `v = n`; else `v == 1` → `v = cond ? 0 : 1`.
//! - `while cond`: `v < n` → `v = cond ? 0 : n` (Mesa lowers `break_if` with
//!   nest 1 to it).
//! - `pop_exec n`: `v = max(v - n, 0)`.
//! - `update_exec` re-evaluates the mask and changes no counter (its fields
//!   decode as `if 0.0, 0.0, 0, feq`).
//!
//! Mesa's `push_exec n` (`if 0.0, 0.0, n, feq`), `break` (`r0l = n;
//! pop_exec 0`) and the `if`/`else`/`pop_exec 1` and loop
//! `push_exec 1 .. jmp_exec_any .. pop_exec 1` shapes all follow from these.
//!
//! Jumps are relative to the jump instruction's own address (Mesa
//! `agx_pack.c` patches `target - offset`). `r1` is the link register (Mesa
//! README): `call` writes the following instruction's offset from the code
//! base into it and `ret`/`call r` jump to the code base plus a register; an
//! indirect target must be the same in every active thread (Inferred: the
//! program counter is shared, so a divergent target has no meaning).
//!
//! No caches or reordering are modeled (memory is coherent and every access
//! completes in order), so the memory and image barriers, `wait` and the
//! pixel `pixwait`/`pixrel` ordering are complete as no-ops. `barrier` ends
//! the run so the dispatcher can rendezvous the threadgroup. The helper
//! program's `doorbell`, `jmp_if_skipping_doorbell` and `map`/`unmap` and
//! the fragment `jmp_incomplete` refuse by name.

use super::alu::{fcompare, icompare, size};
use super::decode::Instr;
use super::generated::{Imm, Mod, Op};
use super::machine::{Env, Error, Exit, SimdGroup, Step, lanes};

/// `r1`, the link register, in halves.
const LINK_REGISTER: usize = 2;

impl SimdGroup {
    pub(super) fn flow(&mut self, instr: &Instr, _env: &mut dyn Env) -> Result<Step, Error> {
        use Op::*;
        let pc = self.pc;
        let next = pc + instr.len as u64;
        let offset = instr.immediate(Imm::Offset).unwrap_or(0);
        let nest = instr.immediate(Imm::Nest).unwrap_or(0) as u16;
        match instr.op() {
            Stop => Ok(Step::Exit(Exit::Stopped)),
            Trap => Err(Error::Trap),
            Barrier => Ok(Step::Exit(Exit::Barrier)),
            JmpAny => Ok(if self.active() != 0 {
                Step::Jump(pc.wrapping_add(offset as u64))
            } else {
                Step::Next
            }),
            JmpNone => Ok(if self.active() == 0 {
                Step::Jump(pc.wrapping_add(offset as u64))
            } else {
                Step::Next
            }),
            Call => {
                self.link(next);
                Ok(Step::Jump(pc.wrapping_add(offset as u64)))
            }
            CallReg => {
                let target = self.indirect(instr)?;
                self.link(next);
                Ok(Step::Jump(target))
            }
            Ret => Ok(Step::Jump(self.indirect(instr)?)),
            PopExec => {
                for lane in lanes(self.present) {
                    let v = self.half(lane, 0);
                    self.set_half(lane, 0, v.saturating_sub(nest));
                }
                Ok(Step::Next)
            }
            UpdateExec => Ok(Step::Next),
            IfIcmp | ElseIcmp | WhileIcmp | IfFcmp | ElseFcmp | WhileFcmp => {
                self.nesting(instr, nest)?;
                Ok(Step::Next)
            }
            Wait | Pixwait | Pixrel | MemoryBarrier | ImageBarrier1 | ImageBarrier2
            | ImageBarrier3 | ImageBarrier4 | FlushMemoryToTexture | MemoryBarrier2
            | MemoryBarrier3 | UnknownBarrier1 | UnknownBarrier2 | DeviceBarrier1
            | DeviceBarrier2 => Ok(Step::Next),
            JmpIncomplete => Err(Error::Refused(
                "jmp_incomplete: the partial-tile resume is not modeled",
            )),
            Doorbell | JmpIfSkippingDoorbell => Err(Error::Refused(
                "the helper program's firmware doorbell is not modeled",
            )),
            Map | Unmap => Err(Error::Refused(
                "the helper program's stack map and unmap are not modeled",
            )),
            other => unreachable!("{other:?} is not a control-flow instruction"),
        }
    }

    /// Update every present thread's nesting counter for `if`, `else` or
    /// `while`.
    fn nesting(&mut self, instr: &Instr, nest: u16) -> Result<(), Error> {
        use Op::*;
        let cond = instr.modifier(Mod::Cond).unwrap_or(0);
        let float = matches!(instr.op(), IfFcmp | ElseFcmp | WhileFcmp);
        let (a, b) = (instr.source(0), instr.source(1));
        for lane in lanes(self.present) {
            let v = self.half(lane, 0);
            // The condition is read only where the counter rule consults it.
            let condition = || -> Result<bool, Error> {
                Ok(if float {
                    fcompare(cond, self.float(lane, &a)?, self.float(lane, &b)?)
                } else {
                    icompare(
                        cond,
                        self.bits(lane, &a, 0)?,
                        size(&a),
                        self.bits(lane, &b, 0)?,
                        size(&b),
                    )
                })
            };
            let updated = match instr.op() {
                IfIcmp | IfFcmp => {
                    if v != 0 {
                        v.saturating_add(nest)
                    } else if !condition()? {
                        1
                    } else {
                        0
                    }
                }
                ElseIcmp | ElseFcmp => match v {
                    0 => nest,
                    1 => u16::from(!condition()?),
                    _ => v,
                },
                _ => {
                    if v < nest {
                        if condition()? { 0 } else { nest }
                    } else {
                        v
                    }
                }
            };
            self.set_half(lane, 0, updated);
        }
        Ok(())
    }

    /// Write the return offset into every present thread's link register.
    fn link(&mut self, next: u64) {
        let value = next.wrapping_sub(self.code_base) as u32;
        for lane in lanes(self.present) {
            self.set_reg32(lane, LINK_REGISTER, value);
        }
    }

    /// The target of `ret`/`call r`: the code base plus the register, the
    /// same in every active thread.
    fn indirect(&self, instr: &Instr) -> Result<u64, Error> {
        let source = instr.source(0);
        let threads = if self.active() != 0 {
            self.active()
        } else {
            self.present
        };
        let mut target = None;
        for lane in lanes(threads) {
            let value = self.bits(lane, &source, 0)?;
            match target {
                None => target = Some(value),
                Some(seen) if seen != value => {
                    return Err(Error::Refused("an indirect branch whose target diverges"));
                }
                _ => {}
            }
        }
        let value = target.ok_or(Error::Refused("an indirect branch with no threads"))?;
        Ok(self.code_base.wrapping_add(value & 0xffff_ffff))
    }
}

#[cfg(test)]
mod tests {
    use super::super::assemble::line;
    use super::super::machine::tests::{CODE, finish, setup};
    use super::super::machine::{ExecError, Exit};
    use super::*;

    #[test]
    fn if_else_and_pop_select_threads() {
        // r2 = lane parity; then-branch writes 1, else-branch writes 2.
        let (mut memory, mut group) = setup(
            "if r2, 0, 1, ine\n\
             mov r4, 1\n\
             else 0.0, 0.0, 1, feq\n\
             mov r4, 2\n\
             pop_exec 1\n\
             mov r6, 3\n\
             stop",
            4,
        );
        for lane in 0..4 {
            group.set_reg32(lane, 4, lane as u32 & 1);
        }
        assert_eq!(finish(&mut group, &mut memory), Ok(Exit::Stopped));
        for lane in 0..4 {
            let expected = if lane & 1 != 0 { 1 } else { 2 };
            assert_eq!(group.reg32(lane, 8), expected, "lane {lane}");
            assert_eq!(group.reg32(lane, 12), 3);
            assert_eq!(group.half(lane, 0), 0);
        }
    }

    #[test]
    fn loops_break_with_while_and_jump_back_while_any_thread_runs() {
        // Count r4 up to the lane index: while (r4 < lane) r4++.
        let body = ["while r4, r2, 1, ult", "iadd r4, r4, 1"];
        let back: usize = body.iter().map(|text| line(text).unwrap().len()).sum();
        let (mut memory, mut group) = setup(
            &alloc::format!(
                "if 0.0, 0.0, 1, feq\n{}\n{}\njmp_any -{back}\npop_exec 1\nstop",
                body[0],
                body[1]
            ),
            4,
        );
        for lane in 0..4 {
            group.set_reg32(lane, 4, lane as u32);
        }
        assert_eq!(finish(&mut group, &mut memory), Ok(Exit::Stopped));
        for lane in 0..4 {
            assert_eq!(group.reg32(lane, 8), lane as u32, "lane {lane}");
            assert_eq!(group.half(lane, 0), 0);
        }
    }

    #[test]
    fn calls_link_through_r1() {
        let (mut memory, mut group) = setup(
            "call 8\n\
             stop\n\
             mov r4, 7\n\
             ret r1",
            2,
        );
        assert_eq!(finish(&mut group, &mut memory), Ok(Exit::Stopped));
        assert_eq!(group.reg32(0, 8), 7);
        assert_eq!(group.reg32(1, LINK_REGISTER), 6);
        assert_eq!(group.pc, CODE + 8);
    }

    #[test]
    fn barriers_yield_and_the_helper_program_refuses() {
        let (mut memory, mut group) = setup("barrier\nstop", 1);
        assert_eq!(finish(&mut group, &mut memory), Ok(Exit::Barrier));
        assert_eq!(finish(&mut group, &mut memory), Ok(Exit::Stopped));
        let (mut memory, mut group) = setup("doorbell 32", 1);
        assert!(matches!(
            finish(&mut group, &mut memory),
            Err(ExecError::Refused {
                op: Op::Doorbell,
                ..
            })
        ));
        let (mut memory, mut group) = setup("trap", 1);
        assert_eq!(
            finish(&mut group, &mut memory),
            Err(ExecError::Trap { pc: CODE })
        );
    }
}
