//! Instruction fetch: lookup contexts, translation, branch-target and FP access
//! checks.

use super::*;

impl<H: Host, D: Devices> Machine<H, D> {
    /// Arm `BranchTargetCheck`: the Branch Target exception (EC 0x0D)
    /// reports BTYPE in ISS and leaves it set for SPSR.
    pub(super) fn branch_target_exception(&self, pc: u64, word: u32) -> Option<Exception> {
        let btype = self.cpu.pstate.btype;
        (!self.branch_target_compatible(word))
            .then(|| Exception::synchronous(Class::BranchTarget, u32::from(btype), pc))
    }

    /// An instruction whose FP, SVE, SME and FPMR access checks the engine
    /// applies before it runs: after a Branch Target exception, the first
    /// check that fails traps, or is UNDEFINED (`CheckFPMREnabled`). One
    /// that passes runs on its own: the AdvSIMD FP8 conversions here
    /// ([`Self::fp8_conversion`]), SVE and SME forms through [`scalable`],
    /// and scalar FP in streaming mode as a block that then zeroes the upper
    /// Z bits it wrote.
    #[cold]
    pub(super) fn checked_instruction(&mut self, pc: u64, word: u32) -> Step {
        if self.cpu.pstate.btype != 0
            && self.fetch_guarded(pc)
            && let Some(exception) = self.branch_target_exception(pc, word)
        {
            self.cpu.step_advance = false;
            self.take(exception);
            return Ok(());
        }
        let checks = self.profile.chip.checks(word);
        let exception = match streaming::check(&self.cpu, checks) {
            Err(Denial::FloatingPoint(el)) => {
                Exception::synchronous(Class::FloatingPointAccess, TRAPPED_AARCH64, pc).to(el)
            }
            Err(Denial::Sme { el, smtc }) => {
                Exception::synchronous(Class::SmeAccess, smtc, pc).to(el)
            }
            Err(Denial::Undefined) => return self.undefined(),
            Err(Denial::Unimplemented(feature)) => {
                return Err(self.unsupported(RequirementKind::Instruction {
                    word,
                    detail: format!("its access check needs {feature}, which the engine lacks"),
                }));
            }
            Ok(()) if let Some(operand) = fp8_conversion::decode(word) => {
                return self.fp8_conversion(word, &operand);
            }
            Ok(()) if checks.iter().all(|check| *check == Check::Fp) => {
                return self.streaming_scalar(pc, word);
            }
            Ok(()) => return self.scalable_instruction(pc, word),
        };
        self.cpu.step_advance = false;
        // Arm decodes before it checks access: an SVE or SME word UNDEFINED
        // on this chip takes that instead of the trap.
        if checks.iter().any(|check| *check != Check::Fp) && self.scalable_undefined(pc, word) {
            return self.undefined();
        }
        self.take(exception);
        Ok(())
    }

    /// F1CVTL, F2CVTL, BF1CVTL, BF2CVTL and FCVTN (FP8) and their upper
    /// forms, after their checks passed: the shared FP8 conversion with
    /// FPMR's formats and scales and FPCR, the cumulative exceptions ORed
    /// into FPSR. In streaming mode the V write zeroes the upper Z bits.
    pub(super) fn fp8_conversion(&mut self, word: u32, operand: &fp8_conversion::Operand) -> Step {
        let Some(fpmr) = self.cpu.scalable.as_ref().map(ScalableState::fpmr) else {
            return Err(self.unsupported(RequirementKind::Instruction {
                word,
                detail: "an FP8 conversion on a PE without FPMR".into(),
            }));
        };
        let fpcr = self.cpu.state.fpcr;
        let register = |index: u8| self.cpu.state.v[usize::from(index)];
        let converted = crate::floating::scalable::fixed_fp8_conversion(
            operand,
            register(operand.source),
            register(operand.second_source),
            register(operand.destination),
            fpcr,
            fpmr,
        );
        let Ok((value, exceptions)) = converted else {
            return Err(self.unsupported(RequirementKind::Instruction {
                word,
                detail: format!("FPCR {fpcr:#x} enables a trapped FP exception"),
            }));
        };
        let scalable = self.cpu.scalable.as_mut().expect("checked above");
        if let Err(error) = scalable.write_v(&mut self.cpu.state, operand.destination, value) {
            return Err(self.unsupported(RequirementKind::Instruction {
                word,
                detail: format!("its FP8 result cannot be written: {error}"),
            }));
        }
        self.cpu.state.fpsr |= exceptions;
        self.next()
    }

    /// The number of the context a fetch in `half` runs in now: the EL with
    /// the guarded level, the variant, the code generation and the half's
    /// translation inputs ([`Space`]). Lookup entries name it.
    pub(super) fn context(&mut self, el: u8, variant: Variant, half: usize) -> u64 {
        let generations = (self.translation_generation, self.code_generation);
        if let Some(recent) = self.recent[half].iter().flatten().find(|recent| {
            (recent.el, recent.variant, recent.generations) == (el, variant, generations)
        }) {
            return recent.number;
        }
        let inputs = self.half_inputs(half, el);
        let spaces = &mut self.spaces[half];
        spaces.retain(|space| space.code == generations.1);
        let found = spaces
            .iter()
            .position(|space| space.el == el && space.variant == variant && space.inputs == inputs);
        let space = match found {
            Some(at) => spaces.remove(at),
            None => {
                if spaces.len() == SPACES {
                    spaces.remove(0);
                }
                let number = self.next_context;
                self.next_context += 1;
                Space {
                    inputs,
                    el,
                    variant,
                    code: generations.1,
                    number,
                }
            }
        };
        self.spaces[half].push(space);
        self.recent[half].rotate_right(1);
        self.recent[half][0] = Some(Recent {
            el,
            variant,
            generations,
            number: space.number,
        });
        space.number
    }

    /// Both halves' contexts at `el` in `variant`.
    pub(super) fn contexts(&mut self, el: u8, variant: Variant) -> [u64; 2] {
        [0, 1].map(|half| self.context(el, variant, half))
    }

    /// What decides how a fetch of `half` at `el` (with the guarded level in
    /// bit 4) translates besides the tables' contents: the controls of the
    /// regime it walks and HCR_EL2, which selects that regime (Arm
    /// `S1TranslationRegime`; E2H is RES1). Of SPRR's permissions a fetch
    /// reads only its own level's register, SPRR_PERM_EL0 at EL0 and
    /// SPRR_PERM_EL1 above, and neither PAN nor the unlock fields
    /// (`mmu::sprr::permissions`), so the kernel's contexts outlive the
    /// SPRR_PERM_EL0 writes XNU makes at every thread switch. The upper
    /// half's leave out TTBR0's table address, which it never walks, and
    /// keep TTBR0's ASID field only while TCR.A1 selects it and a fetch of
    /// the upper half since its contexts were last forgotten was
    /// non-global: the ASID selects nothing else of it, so a kernel's
    /// global text keeps one context across every process's ASID.
    pub(super) fn half_inputs(&self, half: usize, el: u8) -> (mmu::Controls, u64) {
        const TCR_A1: u64 = 1 << 22;
        const TTBR_ASID: u64 = 0xffff << 48;
        use crate::machine::cpu::TranslationRegime;
        let el = el & 3;
        let regime = if el == 2 || el == 0 && self.cpu.in_host() {
            TranslationRegime::El20
        } else {
            TranslationRegime::El10
        };
        let mut controls = self.cpu.controls(regime);
        if el == 0 {
            controls.sprr.el1 = 0;
        } else {
            controls.sprr.el0 = 0;
        }
        controls.sprr.fields = [0; 2];
        if half == 1 {
            controls.ttbr0 &= if self.private_fetches[1] && controls.tcr & TCR_A1 == 0 {
                TTBR_ASID
            } else {
                0
            };
        }
        (controls, self.cpu.read(SystemRegister::HCR_EL2))
    }

    /// The checks before an instruction executes, in Arm's priority after PC
    /// alignment: an Instruction Abort of its fetch, a breakpoint (Arm
    /// `AArch64_CheckBreakpoint`), then the Illegal Execution state (Arm
    /// `AArch64_CheckIllegalState`).
    #[cold]
    pub(super) fn instruction_checks(
        &mut self,
        pc: u64,
        breakpoints: bool,
    ) -> Result<Option<Exception>, Stop> {
        match self.fetch_physical(pc) {
            Ok(_) => {}
            Err(Ok(exception)) => return Ok(Some(exception)),
            Err(Err(stop)) => return Err(stop),
        }
        if breakpoints && debug::breakpoint(&self.cpu, pc) {
            return Ok(Some(self.debug_exception(
                Class::BreakpointLower,
                Class::BreakpointSame,
                0x22,
                pc,
            )));
        }
        Ok(self
            .cpu
            .pstate
            .il
            .then(|| Exception::synchronous(Class::IllegalExecution, 0, pc)))
    }

    /// Translate a PC for execution at the current EL.
    pub(super) fn fetch_physical(&mut self, pc: u64) -> Result<u64, Result<Exception, Stop>> {
        let page = pc & !(FETCH_PAGE - 1);
        let slot = (page / FETCH_PAGE) as usize % FETCH_CACHE;
        // The cache key folds the guarded level in with the EL.
        let el = self.cpu.pstate.el | u8::from(self.cpu.pstate.guarded) << 4;
        if let Some(entry) = self.fetch[slot]
            && entry.page == page
            && entry.el == el
            && entry.generation == self.translation_generation
        {
            return Ok(entry.physical | (pc & (FETCH_PAGE - 1)));
        }
        let requester = self.cpu.requester();
        let controls = self.cpu.controls(self.cpu.regime());
        let mut tables = RamTables(&mut self.host);
        match mmu::translate(&controls, pc, Access::Execute, requester, &mut tables) {
            Translated::Mapped(_) if !self.host.fetch_permitted(pc) => {
                let fault =
                    mmu::Fault::stage1(mmu::FaultKind::Permission, HOST_REFUSED_FETCH_LEVEL);
                Err(Ok(self.abort(
                    fault,
                    [Class::InstructionAbortLower, Class::InstructionAbortSame],
                    fault.instruction_syndrome(),
                    pc,
                    pc,
                )))
            }
            Translated::Mapped(translation) => {
                let half = chain::half(pc);
                self.fetched_through(half, translation.size, translation.global);
                let physical = translation.physical & !(FETCH_PAGE - 1);
                self.fetch[slot] = Some(FetchEntry {
                    page,
                    physical,
                    guarded: translation.guarded,
                    el,
                    generation: self.translation_generation,
                });
                Ok(translation.physical)
            }
            Translated::Fault(fault)
                if fault.kind == mmu::FaultKind::Permission
                    && requester.el != 0
                    && !requester.guarded
                    && controls.sprr.enabled()
                    && matches!(
                        mmu::translate(
                            &controls,
                            pc,
                            Access::Execute,
                            mmu::Requester {
                                guarded: true,
                                ..requester
                            },
                            &mut RamTables(&mut self.host),
                        ),
                        Translated::Mapped(_)
                    ) =>
            {
                // On hardware an EL fetch of GL-only code enters GL at
                // GXF_ABORT_EL1 (Sven Peter, for GL2); the saved state is
                // not documented.
                Err(Err(self.unsupported(RequirementKind::Native(
                    "kernel-level fetch of guarded-only code (GXF abort entry)",
                ))))
            }
            Translated::Fault(fault) => Err(Ok(self.abort(
                fault,
                [Class::InstructionAbortLower, Class::InstructionAbortSame],
                fault.instruction_syndrome(),
                pc,
                pc,
            ))),
            Translated::Unsupported(unsupported) => Err(Err(
                self.unsupported(RequirementKind::Translation(unsupported))
            )),
        }
    }

    /// Whether the page of `pc`, which executes at the current EL, is guarded
    /// (Arm `InGuardedPage`).
    pub(super) fn fetch_guarded(&mut self, pc: u64) -> bool {
        if self.fetch_physical(pc).is_err() {
            return false;
        }
        let page = pc & !(FETCH_PAGE - 1);
        let slot = (page / FETCH_PAGE) as usize % FETCH_CACHE;
        self.fetch[slot].is_some_and(|entry| entry.page == page && entry.guarded)
    }

    /// FEAT_BTI's BTYPE after an indirect branch at `pc` through `register`
    /// (Arm BR, BLR, BRA* and BLRA*): BLR forms give 0b10; BR forms give
    /// 0b01 through X16 or X17 or from an unguarded page, else 0b11.
    pub(super) fn indirect_branch_type(&mut self, pc: u64, register: u8, link: bool) -> u8 {
        if link {
            0b10
        } else if register == 16 || register == 17 || !self.fetch_guarded(pc) {
            0b01
        } else {
            0b11
        }
    }

    /// Whether the first instruction of a guarded-page target is compatible
    /// with PSTATE.BTYPE (Arm `BTypeCompatible_BTI`, `BTypeCompatible_PAC`):
    /// BTI with a matching target, PACIASP and PACIBSP unless BTYPE is 0b11
    /// and SCTLR_ELx.BT0 (EL0) or BT1 forbids it, BRK and HLT.
    pub(super) fn branch_target_compatible(&self, word: u32) -> bool {
        self.branch_target_accepts(word, self.cpu.pstate.btype)
    }

    /// [`Self::branch_target_compatible`] for BTYPE `btype`.
    pub(super) fn branch_target_accepts(&self, word: u32, btype: u8) -> bool {
        const PACIASP: u32 = 0xd503_233f;
        const PACIBSP: u32 = 0xd503_237f;
        const SCTLR_BT0: u64 = 1 << 35;
        const SCTLR_BT1: u64 = 1 << 36;
        if word & 0xffff_ff3f == 0xd503_241f {
            return match (word >> 6) & 3 {
                0b00 => btype == 0,
                0b01 => btype != 0b11,
                0b10 => btype != 0b10,
                _ => true,
            };
        }
        if word == PACIASP || word == PACIBSP || block::pauth_lr::signs_with_implicit_bti(word) {
            let sctlr = self.cpu.regime_sctlr();
            let forbid = if self.cpu.pstate.el == 0 {
                SCTLR_BT0
            } else {
                SCTLR_BT1
            };
            return btype != 0b11 || sctlr & forbid == 0;
        }
        // BRK and HLT.
        matches!(word & 0xffe0_001f, 0xd420_0000 | 0xd440_0000)
    }

    /// The EL an FP/SIMD access traps to, if it traps (Arm
    /// `AArch64_CheckFPEnabled`): CPACR_EL1.FPEN at EL0 and EL1 outside the
    /// host, then CPTR_EL2.FPEN, which has the CPACR layout because
    /// HCR_EL2.E2H is RES1.
    pub(super) fn floating_point_trap(&mut self) -> Option<u8> {
        *self
            .floating_point
            .get_or_insert_with(|| self.cpu.floating_point_trap())
    }

    pub(super) fn floating_point_enabled(&mut self) -> bool {
        self.floating_point_trap().is_none()
    }

    pub(super) fn floating_point_exception(&mut self, pc: u64) -> Exception {
        let exception = Exception::synchronous(Class::FloatingPointAccess, TRAPPED_AARCH64, pc);
        match self.floating_point_trap() {
            Some(el) => exception.to(el),
            None => exception,
        }
    }

    /// BTYPE after a block that a native branch or fallthrough ended: BR and
    /// BLR set it, every other instruction clears it.
    pub(super) fn native_branch_type(
        &mut self,
        index: usize,
        kind: Result<ExitKind, stela_compiler::block::InvalidExitKind>,
    ) -> Result<u8, Stop> {
        const REGISTER_BRANCH: u32 = 0xffff_fc1f;
        const BR: u32 = 0xd61f_0000;
        const BLR: u32 = 0xd63f_0000;
        if !matches!(kind, Ok(ExitKind::Indirect | ExitKind::Call)) {
            return Ok(0);
        }
        let Some(&(terminal, _)) = self.blocks[index].source_map.last() else {
            return Ok(0);
        };
        let word = self.word(index, terminal)?;
        let register = ((word >> 5) & 31) as u8;
        Ok(match word & REGISTER_BRANCH {
            BR => self.indirect_branch_type(terminal, register, false),
            BLR => self.indirect_branch_type(terminal, register, true),
            // BRA* and BLRA* that a PAC thunk completed.
            _ => match block::decode_pointer_authentication(GuestAddress(terminal), word) {
                Ok(Some(instruction)) => self.pointer_branch_type(terminal, instruction.operation),
                _ => 0,
            },
        })
    }

    /// Both FP service boundaries share the same sole semantic completion.
    #[inline]
    pub(super) fn complete_floating_point(
        &mut self,
        word: u32,
        operation: &FloatingPointOperation,
    ) -> Result<(), stela_compiler::aarch64::floating::UnsupportedControl> {
        #[cfg(all(feature = "std", feature = "native-profile"))]
        if let Some(profile) = &mut self.floating_profile
            && profile.tick()
        {
            return profile.complete_at(&mut self.cpu, word, operation);
        }
        #[cfg(not(all(feature = "std", feature = "native-profile")))]
        let _ = word;
        crate::floating::complete(&mut self.cpu.state, operation)
    }
}
