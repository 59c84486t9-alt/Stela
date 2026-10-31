//! Pointer authentication with the guest's own keys, completed by the engine.

use super::*;

/// The APCTL bit that keeps the keys on above EL0 whatever SCTLR says. SPTM
/// 26A434 sets it at boot (`__text+0xb790`), and its context switch for a
/// process without JOP keys then clears SCTLR's enables (`__text+0x4a264`)
/// with signed returns of its own and the kernel's still to come, so those
/// enables can govern only EL0. SPTM clears the bit on entry, setting all
/// four enables instead (`__text+0x20e0`).
const APCTL_KERNEL_KEYS: u64 = 1 << 4;

impl<H: Host, D: Devices> Machine<H, D> {
    /// Whether a PAC key is on at the current EL: the current regime's SCTLR
    /// enables it (EnIA 31, EnIB 30, EnDA 27, EnDB 13), or above EL0 APCTL
    /// does.
    pub(super) fn key_enabled(&self, key: PointerAuthenticationKey) -> bool {
        let bit = match key {
            PointerAuthenticationKey::Ia => 31,
            PointerAuthenticationKey::Ib => 30,
            PointerAuthenticationKey::Da => 27,
            PointerAuthenticationKey::Db => 13,
        };
        let control = match self.cpu.pstate.el {
            1 => self.cpu.apple.apctl[0],
            2 => self.cpu.apple.apctl[1],
            _ => 0,
        };
        self.cpu.regime_sctlr() & (1 << bit) != 0 || control & APCTL_KERNEL_KEYS != 0
    }

    /// The PAC keys as (low, high) words in APIA, APIB, APDA, APDB, APGA order.
    pub(super) fn pointer_keys(&self) -> [Option<[u64; 2]>; 5] {
        // The original T6000 LLB initializes C13/C14 keys and consumes them
        // at EL2. They are not aliases of the architectural lower bank. EL0
        // in the host shares them, as the architectural keys serve every EL:
        // 26A434 XNU at EL2 loads each thread's B keys there on a context
        // switch (0xfffffe000bb9bd14) for its EL0 to use.
        if self.cpu.pstate.el == 2 || self.cpu.pstate.el == 0 && self.cpu.in_host() {
            return self.cpu.apple.pointer_keys.pairs();
        }
        use SystemRegister as R;
        let pair = |low, high| Some([self.cpu.read(low), self.cpu.read(high)]);
        [
            pair(R::APIAKeyLo_EL1, R::APIAKeyHi_EL1),
            pair(R::APIBKeyLo_EL1, R::APIBKeyHi_EL1),
            pair(R::APDAKeyLo_EL1, R::APDAKeyHi_EL1),
            pair(R::APDBKeyLo_EL1, R::APDBKeyHi_EL1),
            pair(R::APGAKeyLo_EL1, R::APGAKeyHi_EL1),
        ]
    }

    /// The PAC algorithm version of the PE: FEAT_FPACCOMBINE, FEAT_FPAC,
    /// FEAT_PAuth2 or the classic FEAT_PAuth insertion and error code (the
    /// M1). A feature the PE has and the engine does not implement yet stops.
    pub(super) fn pointer_version(&self) -> Result<pauth::Version, Stop> {
        let has = |feature| {
            self.cpu
                .registers
                .implemented(feature)
                .map_err(|reason| self.unsupported(RequirementKind::Native(reason)))
        };
        Ok(if has(Feature::FEAT_FPACCOMBINE)? {
            pauth::Version::FaultingCombined
        } else if has(Feature::FEAT_FPAC)? {
            pauth::Version::Faulting
        } else if has(Feature::FEAT_PAuth2)? {
            pauth::Version::Enhanced
        } else {
            pauth::Version::Classic
        })
    }

    /// The guest's PAC keys and the current regime's TCR layout, with the
    /// chip's PAC version.
    pub(super) fn pointer_context(&self) -> Result<pauth::Context, Stop> {
        let [ia, ib, da, db, generic] = self.pointer_keys();
        let mut keys = pauth::Keys::from_optional_words([ia, ib, da, db]);
        if let Some(generic) = generic {
            keys = keys.with_generic_words(generic);
        }
        Ok(
            pauth::Context::new_with_version(0, keys, self.pointer_version()?)
                .with_translation_regime(self.cpu.regime_tcr())
                .with_implementation_defined_cipher(),
        )
    }

    /// Whether HCR_EL2.API clear traps the use of an enabled key, or PACGA,
    /// to EL2: from EL1, and from EL0 outside the host (Arm
    /// `IsAPIAKeyEnabled` and the other key checks, `AddPACGA`).
    pub(super) fn pointer_authentication_trapped(&self) -> bool {
        let el = self.cpu.pstate.el;
        (el == 1 || (el == 0 && !self.cpu.in_host())) && !self.cpu.hcr(HCR_API)
    }

    /// Arm `TrapPACUse(EL2)`: EC 0x09 with ISS 0 at the instruction.
    pub(super) fn pointer_authentication_trap(&mut self) -> Step {
        let pc = self.cpu.pc;
        self.take(Exception::synchronous(Class::PointerAuthenticationTrap, 0, pc).to(2));
        Ok(())
    }

    /// Complete one PAC instruction with the guest's own keys, laid out for
    /// the current TCR. The algorithm is the software QARMA5 service as
    /// FEAT_PAuth2 with FEAT_FPAC; Apple's hardware algorithm and AppleMode
    /// diversification are not reproduced, so values are self-consistent
    /// rather than equal to hardware's. A failed standalone AUT* takes the
    /// PAC Fail exception (EC 0x1C) to the current EL, or from EL0 to EL1 or
    /// the host's EL2 (Arm `AArch64_PACFailException`).
    pub(super) fn pointer_authentication(&mut self, word: u32) -> Step {
        if let Some(step) = self.implicit_pointer_authentication(word) {
            return step;
        }
        let pc = self.cpu.pc;
        let refuse = |machine: &Self, detail: String| {
            Err(machine.unsupported(RequirementKind::Instruction { word, detail }))
        };
        let instruction = match block::decode_pointer_authentication(GuestAddress(pc), word) {
            Ok(Some(instruction)) => instruction,
            _ => return refuse(self, "PAC exit at a word that is not PAC".into()),
        };
        let link_register = self
            .cpu
            .registers
            .implemented(Feature::FEAT_PAuth_LR)
            .map_err(|reason| self.unsupported(RequirementKind::Native(reason)))?;
        // Without FEAT_PAuth_LR its hint-space form (PACM) is a NOP and the
        // others are UNDEFINED.
        if let PointerAuthenticationOperation::LinkRegister(form) = instruction.operation {
            if !link_register {
                return if word & 0xffff_f01f == 0xd503_201f {
                    self.next()
                } else {
                    self.undefined()
                };
            }
            if form == block::pauth_lr::Instruction::Pacm {
                self.cpu.pstate.pacm = self.cpu.pacm_enabled();
                self.pacm_written = true;
                return self.next();
            }
            let staged = pauth::lr_instruction::stage(
                form,
                pc,
                self.cpu.state.x[..31].try_into().expect("31 registers"),
                self.cpu.state.sp,
            );
            return match staged {
                Ok(pauth::lr_instruction::Staged::Pointer(operands)) => {
                    self.two_modifier_authentication(word, instruction, operands)
                }
                _ => refuse(self, "FEAT_PAuth_LR operands".into()),
            };
        }
        if link_register && self.cpu.pstate.pacm {
            let operands = self.pacm_operands(instruction).map_err(|error| {
                self.unsupported(RequirementKind::Instruction {
                    word,
                    detail: alloc::format!("invalid PACM operands: {error:?}"),
                })
            })?;
            if let Some(operands) = operands {
                return self.two_modifier_authentication(word, instruction, operands);
            }
        }
        let uses_key = match instruction.operation.required_key() {
            Some(key) if !self.key_enabled(key) => {
                return self.disabled_pointer_authentication(word, instruction);
            }
            Some(_) => true,
            None => matches!(
                instruction.operation,
                PointerAuthenticationOperation::GenericCode(_)
            ),
        };
        if uses_key && self.pointer_authentication_trapped() {
            return self.pointer_authentication_trap();
        }
        if let Some(step) = self.register_pointer_authentication(instruction) {
            return step;
        }
        let context = self.pointer_context()?;
        if let PointerAuthenticationOperation::Strip { data, .. } = instruction.operation {
            self.pointer.open_stripping(&context, data);
        }
        if let PointerAuthenticationOperation::Load(load) = instruction.operation {
            return self.authenticated_load(word, Some(&context), load);
        }
        match crate::blocks::services::complete_pauth_with_memory(
            &context,
            &instruction,
            &mut self.cpu.state,
            None,
        ) {
            Ok((next, _)) => {
                self.cpu.pstate.btype = self.pointer_branch_type(pc, instruction.operation);
                self.cpu.pc = next.0;
                Ok(())
            }
            Err(crate::blocks::services::PauthFault::Authentication(
                pauth::AuthenticationError::Failure { code },
            )) => {
                self.take(Exception::synchronous(
                    Class::PointerAuthenticationFailure,
                    u32::from(code),
                    pc,
                ));
                Ok(())
            }
            Err(fault) => refuse(self, fault.to_string()),
        }
    }

    /// PACIASP, PACIBSP, AUTIASP, AUTIBSP, RETAA, RETAB and the HINT-space
    /// *1716 forms, whose operands are implicit (X30 and SP, or X17 and X16):
    /// the kernel's prologues and epilogues. With the key enabled and its use
    /// not trapped, each completes as the general path does (Arm `AddPAC`,
    /// `Auth`; RETA* branches to the authenticated pointer and keeps X30
    /// signed) through [`Self::pointer_result`]. `None` leaves every other
    /// case, and every form under PSTATE.PACM, to the general path.
    pub(super) fn implicit_pointer_authentication(&mut self, word: u32) -> Option<Step> {
        use PointerAuthenticationKey as Block;
        use stela_contracts::pauth::Key;
        #[derive(PartialEq)]
        enum Form {
            Sign,
            Authenticate,
            Return,
        }
        let (form, key, block_key, stack) = match word {
            0xd503_233f => (Form::Sign, Key::Ia, Block::Ia, true),
            0xd503_237f => (Form::Sign, Key::Ib, Block::Ib, true),
            0xd503_23bf => (Form::Authenticate, Key::Ia, Block::Ia, true),
            0xd503_23ff => (Form::Authenticate, Key::Ib, Block::Ib, true),
            0xd65f_0bff => (Form::Return, Key::Ia, Block::Ia, true),
            0xd65f_0fff => (Form::Return, Key::Ib, Block::Ib, true),
            0xd503_211f => (Form::Sign, Key::Ia, Block::Ia, false),
            0xd503_215f => (Form::Sign, Key::Ib, Block::Ib, false),
            0xd503_219f => (Form::Authenticate, Key::Ia, Block::Ia, false),
            0xd503_21df => (Form::Authenticate, Key::Ib, Block::Ib, false),
            _ => return None,
        };
        if self.cpu.pstate.pacm
            || !self.key_enabled(block_key)
            || self.pointer_authentication_trapped()
        {
            return None;
        }
        let (register, modifier) = if stack {
            (30, self.cpu.state.sp)
        } else {
            (17, self.cpu.state.x[16])
        };
        let operation = match form {
            Form::Sign => PointerOperation::Sign,
            Form::Authenticate => PointerOperation::Authenticate { combined: false },
            Form::Return => PointerOperation::Authenticate { combined: true },
        };
        let pointer = self.cpu.state.x[register];
        let result = match self.pointer_result(operation, key, pointer, modifier) {
            Ok(result) => result,
            Err(stop) => return Some(Err(stop)),
        };
        let pc = self.cpu.pc;
        match result {
            Ok((target, _)) if form == Form::Return => {
                self.cpu.pstate.btype = 0;
                self.cpu.pc = target;
            }
            Ok((value, _)) => {
                self.cpu.pstate.btype = 0;
                self.cpu.state.x[register] = value;
                self.cpu.pc = pc + INSTRUCTION;
            }
            Err(code) => self.take(Exception::synchronous(
                Class::PointerAuthenticationFailure,
                u32::from(code),
                pc,
            )),
        }
        Some(Ok(()))
    }

    /// PAC*, AUT*, BRA* and BLRA* with register, SP or zero modifiers, once
    /// their key is known enabled and untrapped: each completes as the
    /// general path does (Arm `AddPAC`, `Auth`; a branch authenticates as a
    /// combined form, then links and branches) through
    /// [`Self::pointer_result`], and PACGA through the same service. `None`
    /// leaves forms naming register 31 to the general path.
    pub(super) fn register_pointer_authentication(
        &mut self,
        instruction: PointerAuthentication,
    ) -> Option<Step> {
        use PointerAuthenticationModifier as Modifier;
        use PointerAuthenticationOperation as Operation;
        if let Operation::GenericCode(code) = instruction.operation {
            return self.generic_pointer_code(code, instruction.next_pc.0);
        }
        let (operation, key, register, modifier) = match instruction.operation {
            Operation::Sign {
                key,
                destination,
                modifier,
            } => (PointerOperation::Sign, key, destination, modifier),
            Operation::Authenticate {
                key,
                destination,
                modifier,
            } => (
                PointerOperation::Authenticate { combined: false },
                key,
                destination,
                modifier,
            ),
            Operation::Branch {
                key,
                target,
                modifier,
                ..
            } => (
                PointerOperation::Authenticate { combined: true },
                key,
                target,
                modifier,
            ),
            _ => return None,
        };
        let modifier = match modifier {
            Modifier::Register(31) => return None,
            Modifier::Register(register) => self.cpu.state.x[usize::from(register)],
            Modifier::StackPointer => self.cpu.state.sp,
            Modifier::Zero => 0,
        };
        if register == 31 {
            return None;
        }
        let key = match key {
            PointerAuthenticationKey::Ia => stela_contracts::pauth::Key::Ia,
            PointerAuthenticationKey::Ib => stela_contracts::pauth::Key::Ib,
            PointerAuthenticationKey::Da => stela_contracts::pauth::Key::Da,
            PointerAuthenticationKey::Db => stela_contracts::pauth::Key::Db,
        };
        let pc = self.cpu.pc;
        let pointer = self.cpu.state.x[usize::from(register)];
        let result = match self.pointer_result(operation, key, pointer, modifier) {
            Ok(result) => result,
            Err(stop) => return Some(Err(stop)),
        };
        match result {
            Ok((value, _)) => {
                self.cpu.pstate.btype = self.pointer_branch_type(pc, instruction.operation);
                if let Operation::Branch { link, .. } = instruction.operation {
                    if link {
                        self.cpu.state.x[30] = instruction.next_pc.0;
                    }
                    self.cpu.pc = value;
                } else {
                    self.cpu.state.x[usize::from(register)] = value;
                    self.cpu.pc = instruction.next_pc.0;
                }
            }
            Err(code) => self.take(Exception::synchronous(
                Class::PointerAuthenticationFailure,
                u32::from(code),
                pc,
            )),
        }
        Some(Ok(()))
    }

    /// PACGA, known untrapped, through the service, which opens the generic
    /// key's tag word for thunks. `None` leaves an XZR source or destination
    /// to the general path.
    fn generic_pointer_code(
        &mut self,
        code: stela_compiler::block::pauth_memory::GenericCode,
        next: u64,
    ) -> Option<Step> {
        if code.source == 31 || code.destination == 31 {
            return None;
        }
        if let Err(stop) = self.open_pointers() {
            return Some(Err(stop));
        }
        let data = self.cpu.state.x[usize::from(code.source)];
        let modifier = match code.modifier {
            31 => self.cpu.state.sp,
            register => self.cpu.state.x[usize::from(register)],
        };
        let Some(value) = self.pointer.generic_code(data, modifier) else {
            return Some(Err(self.unsupported(RequirementKind::Native(
                "PAC generic key unavailable",
            ))));
        };
        self.cpu.pstate.btype = 0;
        self.cpu.state.x[usize::from(code.destination)] = value;
        self.cpu.pc = next;
        Some(Ok(()))
    }

    /// Open the service with the current keys, version and layout.
    fn open_pointers(&mut self) -> Result<(), Stop> {
        if !self.pointer.is_open() {
            let inputs = PointerInputs {
                keys: self.pointer_keys(),
                version: self.pointer_version()?,
                tcr: self.cpu.regime_tcr(),
            };
            self.pointer.open(inputs);
        }
        Ok(())
    }

    /// One signing or authentication with the current keys, version and
    /// layout (`pointer::PointerService::result`), the key known enabled
    /// and untrapped.
    pub(super) fn pointer_result(
        &mut self,
        operation: PointerOperation,
        key: stela_contracts::pauth::Key,
        pointer: u64,
        modifier: u64,
    ) -> Result<PointerResult, Stop> {
        self.open_pointers()?;
        self.pointer
            .result(operation, key, pointer, modifier)
            .ok_or_else(|| {
                self.unsupported(RequirementKind::Native(match operation {
                    PointerOperation::Sign => "PAC key unavailable for signing",
                    PointerOperation::Authenticate { .. } => {
                        "PAC key unavailable for authentication"
                    }
                }))
            })
    }

    /// The two-modifier operation PSTATE.PACM makes of a PAC*SP, AUT*SP,
    /// RETA* or HINT-space *1716 instruction (Arm PACIA, AUTIA and RETAA
    /// under FEAT_PAuth_LR): the signing forms take the instruction's PC as
    /// the second modifier, the authenticating forms X16, and the *1716
    /// forms X15.
    pub(super) fn pacm_operands(
        &self,
        instruction: PointerAuthentication,
    ) -> Result<Option<pauth::lr_instruction::Operands>, pauth::lr_instruction::StageError> {
        let staged = pauth::conditional::stage(
            instruction.operation,
            instruction.instruction_pc.0,
            self.cpu.state.x[..31]
                .try_into()
                .expect("31 architectural registers"),
            self.cpu.state.sp,
            crate::system::state::Pacm::One,
        )?;
        Ok(staged.map(|operands| pauth::lr_instruction::Operands {
            key: operands.key,
            action: operands.action,
            pointer: operands.pointer,
            modifier1: operands.first,
            modifier2: operands
                .second
                .expect("PACM one selects the second modifier"),
            destination: operands.destination,
            implicit_bti: false,
            instruction_pc: instruction.instruction_pc.0,
        }))
    }

    /// Arm AddPACIA2, AddPACIB2, AuthIA2 and AuthIB2 with the guest's keys:
    /// with the key's SCTLR enable clear the pointer is unchanged, HCR_EL2.API
    /// clear traps the use, a failed AUT* takes the PAC Fail exception
    /// (FEAT_FPAC) and so does a failed RETA* (FEAT_FPACCOMBINE).
    pub(super) fn two_modifier_authentication(
        &mut self,
        word: u32,
        instruction: PointerAuthentication,
        operands: pauth::lr_instruction::Operands,
    ) -> Step {
        use pauth::lr_instruction::{Action, Key};
        let pc = self.cpu.pc;
        let (key, runtime_key) = match operands.key {
            Key::Ia => (
                PointerAuthenticationKey::Ia,
                stela_contracts::pauth::Key::Ia,
            ),
            Key::Ib => (
                PointerAuthenticationKey::Ib,
                stela_contracts::pauth::Key::Ib,
            ),
        };
        if !self.key_enabled(key) {
            return self.disabled_pointer_authentication(word, instruction);
        }
        if self.pointer_authentication_trapped() {
            return self.pointer_authentication_trap();
        }
        let context = self.pointer_context()?;
        let refuse = |machine: &Self, detail: String| {
            Err(machine.unsupported(RequirementKind::Instruction { word, detail }))
        };
        let (pointer, m1, m2) = (operands.pointer, operands.modifier1, operands.modifier2);
        let result = match operands.action {
            Action::Sign => match context.sign_two_modifiers(runtime_key, pointer, m1, m2) {
                Ok(signed) => Ok(signed),
                Err(error) => return refuse(self, format!("{error:?}")),
            },
            Action::Authenticate | Action::Return => {
                let combined = operands.action == Action::Return;
                match context.authenticate_two_modifiers(runtime_key, pointer, m1, m2, combined) {
                    Ok(Ok(result)) => Ok(result.pointer),
                    Ok(Err(pauth::AuthenticationError::Failure { code })) => Err(code),
                    Ok(Err(error)) => return refuse(self, format!("{error:?}")),
                    Err(error) => return refuse(self, format!("{error:?}")),
                }
            }
        };
        let value = match result {
            Ok(value) => value,
            Err(code) => {
                self.take(Exception::synchronous(
                    Class::PointerAuthenticationFailure,
                    u32::from(code),
                    pc,
                ));
                return Ok(());
            }
        };
        self.cpu.pstate.btype = 0;
        match operands.destination {
            Some(31) => self.cpu.pc = instruction.next_pc.0,
            Some(destination) => {
                self.cpu.state.x[usize::from(destination)] = value;
                self.cpu.pc = instruction.next_pc.0;
            }
            None => self.cpu.pc = value,
        }
        Ok(())
    }

    /// BTYPE after a completed PAC instruction at `pc`: BRA* and BLRA* set it
    /// as BR and BLR do, every other form clears it.
    pub(super) fn pointer_branch_type(
        &mut self,
        pc: u64,
        operation: PointerAuthenticationOperation,
    ) -> u8 {
        match operation {
            PointerAuthenticationOperation::Branch { target, link, .. } => {
                self.indirect_branch_type(pc, target, link)
            }
            _ => 0,
        }
    }

    /// With the key's SCTLR enable clear, AddPAC and Auth return the pointer
    /// unchanged (Arm ARM `AddPAC`, `Auth`). Until derived state changes,
    /// the key's tag word lets PAC thunks complete its instructions the
    /// same way (`x86_64::pointer::DISABLED`).
    pub(super) fn disabled_pointer_authentication(
        &mut self,
        word: u32,
        instruction: PointerAuthentication,
    ) -> Step {
        use PointerAuthenticationOperation as Operation;
        if let Some(key) = instruction.operation.required_key() {
            self.pointer.tags[usize::from(x86_64_pointer::key_index(key))] =
                x86_64_pointer::DISABLED;
        }
        let next = instruction.next_pc.0;
        self.cpu.pstate.btype = self.pointer_branch_type(self.cpu.pc, instruction.operation);
        match instruction.operation {
            Operation::Sign1716 { .. }
            | Operation::Authenticate1716 { .. }
            | Operation::SignIbSp
            | Operation::AuthenticateIbSp
            | Operation::Sign { .. }
            | Operation::Authenticate { .. } => self.cpu.pc = next,
            Operation::ReturnIbSp | Operation::ReturnIaSp => self.cpu.pc = self.cpu.state.x[30],
            Operation::LinkRegister(form) if form.is_return() => {
                self.cpu.pc = self.cpu.state.x[30];
            }
            Operation::LinkRegister(_) => self.cpu.pc = next,
            Operation::Branch { target, link, .. } => {
                let destination = if target == 31 {
                    0
                } else {
                    self.cpu.state.x[usize::from(target)]
                };
                if link {
                    self.cpu.state.x[30] = next;
                }
                self.cpu.pc = destination;
            }
            Operation::Load(load) => return self.authenticated_load(word, None, load),
            Operation::Strip { .. } | Operation::GenericCode(_) => {
                unreachable!("XPAC and PACGA use no key that SCTLR disables")
            }
        }
        Ok(())
    }

    /// LDRAA/LDRAB: authenticate the base, then read through the guest's
    /// translation like any data load. Without a context the key is
    /// disabled, and AuthDA/AuthDB return the base unchanged (Arm `Auth`).
    pub(super) fn authenticated_load(
        &mut self,
        word: u32,
        context: Option<&pauth::Context>,
        load: stela_compiler::block::pauth_memory::Load,
    ) -> Step {
        let pc = self.cpu.pc;
        let controls = self.cpu.controls(self.cpu.regime());
        let requester = self.cpu.requester();
        let sctlr = controls.sctlr;
        let memory_controls = pauth::memory::Controls {
            check_sp_alignment: if requester.el == 0 {
                sctlr & (1 << 4) != 0
            } else {
                sctlr & (1 << 3) != 0
            },
            privileged: requester.el != 0,
        };
        enum LoadStop {
            Alignment,
            Fault(mmu::Fault),
            Unsupported(mmu::Unsupported),
            Device(u64),
        }
        // A RAM read has no side effects: the load is made, then checked
        // against the watchpoints, and undone if one matches.
        let before = self.cpu.state.clone();
        let loaded = core::cell::Cell::new(None);
        let host = &mut self.host;
        let result = pauth::memory::complete(
            load,
            memory_controls,
            &mut self.cpu.state,
            |key, pointer| {
                let key = match key {
                    stela_compiler::block::pauth_memory::DataKey::A => {
                        stela_contracts::pauth::Key::Da
                    }
                    stela_compiler::block::pauth_memory::DataKey::B => {
                        stela_contracts::pauth::Key::Db
                    }
                };
                match context {
                    Some(context) => context
                        .authenticate_operation(key, pointer, 0, true)
                        .map(|result| result.pointer),
                    None => Ok(pointer),
                }
            },
            |address| {
                let shape = mmu::alignment::Shape {
                    kind: mmu::alignment::Kind::Plain,
                    bytes: 8,
                    pair: false,
                };
                if mmu::alignment::before_translation(sctlr, address, shape) {
                    return Err(LoadStop::Alignment);
                }
                let translation = match mmu::translate(
                    &controls,
                    address,
                    Access::Read,
                    requester,
                    &mut RamTables(host),
                ) {
                    Translated::Mapped(translation) => translation,
                    Translated::Fault(fault) => return Err(LoadStop::Fault(fault)),
                    Translated::Unsupported(unsupported) => {
                        return Err(LoadStop::Unsupported(unsupported));
                    }
                };
                let mut bytes = [0; 8];
                if (address & (FETCH_PAGE - 1)) > FETCH_PAGE - 8 {
                    return Err(LoadStop::Device(translation.physical));
                }
                loaded.set(Some(address));
                if !host.read_ram(translation.physical, &mut bytes) {
                    return Err(LoadStop::Device(translation.physical));
                }
                Ok(u64::from_le_bytes(bytes))
            },
        );
        match result {
            Ok(_) => {
                let access = loaded.get().map(|address| debug::Access {
                    address,
                    size: 8,
                    read: true,
                    write: false,
                    maintenance: false,
                    el: requester.el,
                });
                if let Some(exception) =
                    access.and_then(|access| self.watchpoint_exception(&access, pc))
                {
                    self.cpu.state = before;
                    self.take(exception);
                    return Ok(());
                }
                // Tag checked with writeback or a base other than SP
                // (FEAT_MTE2), after the watchpoint.
                if let Some(access) = access
                    && (load.writeback || load.base != 31)
                    && let tags::TagCheck::Failed(exception) =
                        self.tag_check(&access, requester, None)?
                {
                    self.cpu.state = before;
                    self.take(exception);
                    return Ok(());
                }
                self.cpu.pc = pc;
                self.next()
            }
            Err(pauth::memory::Fault::Read {
                address,
                error: LoadStop::Fault(fault),
            }) => self.data_abort(address, fault, false, false),
            Err(pauth::memory::Fault::Read {
                address,
                error: LoadStop::Alignment,
            }) => self.alignment_fault(address, false),
            Err(pauth::memory::Fault::Read {
                error: LoadStop::Unsupported(unsupported),
                ..
            }) => Err(self.unsupported(RequirementKind::Translation(unsupported))),
            Err(pauth::memory::Fault::StackAlignment { .. }) => {
                self.take(Exception::synchronous(Class::SpAlignment, 0, pc));
                Ok(())
            }
            // FEAT_FPACCOMBINE: a failed authentication of the base faults
            // as a standalone AUT does.
            Err(pauth::memory::Fault::Authentication(pauth::AuthenticationError::Failure {
                code,
            })) => {
                self.take(Exception::synchronous(
                    Class::PointerAuthenticationFailure,
                    u32::from(code),
                    pc,
                ));
                Ok(())
            }
            Err(other) => Err(self.unsupported(RequirementKind::Instruction {
                word,
                detail: match other {
                    pauth::memory::Fault::Read {
                        error: LoadStop::Device(physical),
                        ..
                    } => format!("LDRA from non-RAM or page-crossing address (PA {physical:#x})"),
                    _ => "LDRA operands or authentication".into(),
                },
            })),
        }
    }

    /// `pointer` without its PAC, laid out as an instruction address in the
    /// current regime (Arm `XPACI`), for diagnostics such as return
    /// addresses in frame records; unchanged without a PAC layout.
    pub fn strip_instruction_pointer(&self, pointer: u64) -> u64 {
        self.pointer_context()
            .ok()
            .map(|context| context.strip(stela_contracts::pauth::Key::Ia, pointer))
            .unwrap_or(pointer)
    }

    /// ADDPT, SUBPT, MADDPT and MSUBPT (FEAT_CPA), UNDEFINED on a chip
    /// without it. No Apple chip has FEAT_CPA2, so `EffectiveCPTA` and
    /// `EffectiveCPTM` are 0 and `PointerAddCheck` and
    /// `PointerMultiplyAddCheck` return the plain sum.
    pub(super) fn checked_pointer(
        &mut self,
        operand: stela_compiler::aarch64::checked_pointer::Operand,
    ) -> Step {
        use stela_compiler::aarch64::checked_pointer::Kind;
        match self.cpu.registers.implemented(Feature::FEAT_CPA) {
            Ok(true) => {}
            Ok(false) => return self.undefined(),
            Err(reason) => return Err(self.unsupported(RequirementKind::Native(reason))),
        }
        let (base, change, subtract) = match operand.kind {
            Kind::Offset {
                base,
                offset,
                amount,
                subtract,
            } => (base, self.read_register(offset) << amount, subtract),
            Kind::Product {
                left,
                right,
                base,
                subtract,
            } => (
                base,
                self.read_register(left)
                    .wrapping_mul(self.read_register(right)),
                subtract,
            ),
        };
        let base = self.read_register(base);
        let result = if subtract {
            base.wrapping_sub(change)
        } else {
            base.wrapping_add(change)
        };
        self.write_register(operand.destination, result);
        self.next()
    }
}
