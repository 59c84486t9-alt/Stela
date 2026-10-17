//! MRS, MSR and System instructions through the generated AARCHMRS accessors
//! (`machine::system`): this module is the [`Context`] they run against.
//!
//! - Identification registers hold the CPU profile's values; one without a
//!   value stops the read (`RequirementKind::SystemRegister`).
//! - SP_ELx are the banked stack pointers, CNTx_CTL compute ISTATUS, ISR_EL1
//!   reports the pending lines, and FPCR/FPSR live in the guest state.
//! - Writes the engine cannot honor stop: SCTLR alignment checking, debug
//!   exceptions and breakpoints, and Apple VMSA_LOCK. SCTLR_ELx.EE and E0E
//!   are RES0 because the profile has no FEAT_MixedEnd.
use super::{
    Devices, Host, Machine, RequirementKind, Step, Stop,
    mmu::{self, Access as MemoryAccess, Outcome as Translated},
};
use crate::machine::{
    cpu::{Exception, HCR_AMO, HCR_FMO, HCR_IMO, HCR_VF, HCR_VI, HCR_VSE, TranslationRegime},
    exception::{Class, DAIF_A, DAIF_D, DAIF_F, DAIF_I, Pstate as PstateBits},
    registers::{Lines, Refusal, trap_iss},
    system::{
        ACCESSORS, AtAccess, CacheOp, CacheScope, Context, Effect, ErrorRecord, Limit, Operation,
        Pstate, Register, Stage,
    },
    timer::Channel,
};
use core::cell::Cell;
use stela_compiler::aarch64::system::registers::{Encoding, RegisterAccess};

/// The FPCR fields of the profile: AHP, DN, FZ, RMode and FZ16 (FEAT_FP16).
/// The trap enables IOE, DZE, OFE, UFE, IXE and IDE are RAZ/WI because the M2
/// does not trap FP exceptions (inferred: macOS on Apple silicon cannot
/// enable FP traps); FEAT_AFP, FEAT_EBF16 and AArch32's Len and Stride are not
/// in the profile.
const FPCR_FIELDS: u32 = 0x07c8_0000;

/// Registers whose value is the CPU profile's, read-only to software.
pub(super) fn identification(register: Register) -> bool {
    let name = register.name();
    name.starts_with("ID_")
        || matches!(
            register,
            Register::MIDR_EL1
                | Register::MPIDR_EL1
                | Register::REVIDR_EL1
                | Register::AIDR_EL1
                | Register::CTR_EL0
                | Register::DCZID_EL0
                | Register::CLIDR_EL1
                | Register::CCSIDR_EL1
                | Register::MVFR0_EL1
                | Register::MVFR1_EL1
                | Register::MVFR2_EL1
                | Register::LORID_EL1
                | Register::MPAMIDR_EL1
                | Register::ERRIDR_EL1
                | Register::AMCFGR_EL0
                | Register::AMCGCR_EL0
                | Register::AMCG1IDR_EL0
                | Register::DBGAUTHSTATUS_EL1
                | Register::MDRAR_EL1
                | Register::RVBAR_EL2
        )
}

/// The MRS encoding of a register, from its generated accessor.
pub(super) fn encoding_of(register: Register) -> Option<Encoding> {
    let name = alloc::format!("MRS {}", register.name());
    let accessor = ACCESSORS
        .iter()
        .find(|accessor| accessor.name == name && accessor.index.is_empty())?;
    let key = accessor.value;
    Some(Encoding::new(
        (key >> 14) as u8,
        ((key >> 11) & 7) as u8,
        ((key >> 7) & 15) as u8,
        ((key >> 3) & 15) as u8,
        (key & 7) as u8,
    ))
}

/// Writes that change translation: shadow roots and fetch translations go.
fn translates(register: Register) -> bool {
    matches!(
        register,
        Register::SCTLR_EL1
            | Register::SCTLR_EL2
            | Register::TCR_EL1
            | Register::TCR_EL2
            | Register::TTBR0_EL1
            | Register::TTBR0_EL2
            | Register::TTBR1_EL1
            | Register::TTBR1_EL2
            | Register::MAIR_EL1
            | Register::MAIR_EL2
            | Register::HCR_EL2
            | Register::VTCR_EL2
            | Register::VTTBR_EL2
    )
}

const SCTLR_A: u64 = 1 << 1;
const MDSCR_SS: u64 = 1 << 0;
const MDSCR_KDE: u64 = 1 << 13;
const MDSCR_MDE: u64 = 1 << 15;
const DBG_ENABLE: u64 = 1;
const ISR_A: u64 = 1 << 8;
const ISR_I: u64 = 1 << 7;
const ISR_F: u64 = 1 << 6;

/// One MRS, MSR, SYS or SYSL in progress.
pub(super) struct Access<'a, H: Host, D: Devices> {
    machine: &'a mut Machine<H, D>,
    rt: u8,
    /// The interrupt lines and the system counter when the access started.
    lines: Lines,
    now: u64,
    result: Option<u64>,
    translation: bool,
    regime: bool,
    code: bool,
    refusal: Cell<Option<&'static str>>,
}

impl<H: Host, D: Devices> Access<'_, H, D> {
    fn refuse(&self, reason: &'static str) {
        if self.refusal.get().is_none() {
            self.refusal.set(Some(reason));
        }
    }
}

impl<H: Host, D: Devices> Context for Access<'_, H, D> {
    fn el(&self) -> u64 {
        u64::from(self.machine.cpu.pstate.el)
    }

    fn pstate(&self, field: Pstate) -> u64 {
        let cpu = &self.machine.cpu;
        let state = cpu.pstate;
        let nzcv = u64::from(cpu.state.nzcv >> 28);
        let daif = u64::from(state.daif);
        match field {
            Pstate::N => nzcv >> 3 & 1,
            Pstate::Z => nzcv >> 2 & 1,
            Pstate::C => nzcv >> 1 & 1,
            Pstate::V => nzcv & 1,
            Pstate::D => u64::from(daif & u64::from(DAIF_D) != 0),
            Pstate::A => u64::from(daif & u64::from(DAIF_A) != 0),
            Pstate::I => u64::from(daif & u64::from(DAIF_I) != 0),
            Pstate::F => u64::from(daif & u64::from(DAIF_F) != 0),
            Pstate::SP => u64::from(state.sp),
            Pstate::PAN => u64::from(state.pan),
            Pstate::UAO => u64::from(state.uao),
            Pstate::DIT => u64::from(state.dit),
            Pstate::SSBS => u64::from(state.ssbs),
        }
    }

    fn set_pstate(&mut self, field: Pstate, value: u64) {
        let cpu = &mut self.machine.cpu;
        let bit = value & 1 != 0;
        let flag = |shift: u32| 1u32 << (28 + shift);
        let mut next: PstateBits = cpu.pstate;
        let daif = |next: &mut PstateBits, mask: u8| {
            if bit {
                next.daif |= mask;
            } else {
                next.daif &= !mask;
            }
        };
        match field {
            Pstate::N | Pstate::Z | Pstate::C | Pstate::V => {
                let shift = match field {
                    Pstate::N => 3,
                    Pstate::Z => 2,
                    Pstate::C => 1,
                    _ => 0,
                };
                if bit {
                    cpu.state.nzcv |= flag(shift);
                } else {
                    cpu.state.nzcv &= !flag(shift);
                }
                return;
            }
            Pstate::D => daif(&mut next, DAIF_D),
            Pstate::A => daif(&mut next, DAIF_A),
            Pstate::I => daif(&mut next, DAIF_I),
            Pstate::F => daif(&mut next, DAIF_F),
            Pstate::SP => {
                next.sp = bit;
                self.regime = true;
            }
            Pstate::PAN => {
                next.pan = bit;
                self.regime = true;
            }
            Pstate::UAO => next.uao = bit,
            Pstate::DIT => next.dit = bit,
            Pstate::SSBS => next.ssbs = bit,
        }
        cpu.set_pstate(next);
    }

    fn x(&self) -> u64 {
        if self.rt == 31 {
            0
        } else {
            self.machine.cpu.state.x[usize::from(self.rt)]
        }
    }

    fn set_x(&mut self, value: u64) {
        self.result = Some(value);
    }

    fn read(&self, register: Register, index: u64) -> u64 {
        let machine = &*self.machine;
        let cpu = &machine.cpu;
        if machine.profile_missing.contains(&register) {
            self.refuse("identification register without a profile value");
            return 0;
        }
        match register {
            Register::SP_EL0 => cpu.sp(0),
            Register::SP_EL1 => cpu.sp(1),
            Register::SP_EL2 => cpu.sp(2),
            Register::FPCR => u64::from(cpu.state.fpcr),
            Register::FPSR => u64::from(cpu.state.fpsr),
            Register::ISR_EL1 => self.pending(),
            _ => match Channel::by_control(register) {
                Some(channel) => channel.read_control(cpu, self.now),
                None => cpu.registers.get(register, index),
            },
        }
    }

    fn write(&mut self, register: Register, index: u64, value: u64) -> Result<(), Effect> {
        let cpu = &mut self.machine.cpu;
        if let Some(reason) = crate::machine::registers::vmsa_locked(cpu, register, value) {
            return Err(Effect::Refused(reason));
        }
        match register {
            Register::SCTLR_EL1 | Register::SCTLR_EL2 if value & SCTLR_A != 0 => {
                return Err(Effect::Refused("SCTLR alignment checking"));
            }
            Register::MDSCR_EL1 if value & (MDSCR_SS | MDSCR_KDE | MDSCR_MDE) != 0 => {
                return Err(Effect::Refused(
                    "MDSCR_EL1 software step or debug exceptions",
                ));
            }
            Register::DBGBCR_EL1 | Register::DBGWCR_EL1 if value & DBG_ENABLE != 0 => {
                return Err(Effect::Refused("enabled breakpoint or watchpoint"));
            }
            // Once GXF is enabled HCR_EL2 is writable only from GL2 (m1n1
            // `gxf.c`, `exception_asm.S`); what a write from EL2 does then is
            // not documented.
            Register::HCR_EL2 if cpu.guarded_enabled() && !cpu.pstate.guarded => {
                return Err(Effect::Refused(
                    "HCR_EL2 write outside GL2 with GXF enabled",
                ));
            }
            Register::SP_EL0 | Register::SP_EL1 | Register::SP_EL2 => {
                let el = match register {
                    Register::SP_EL0 => 0,
                    Register::SP_EL1 => 1,
                    _ => 2,
                };
                cpu.set_sp(el, value);
                return Ok(());
            }
            Register::FPCR => {
                cpu.state.fpcr = value as u32 & FPCR_FIELDS;
                return Ok(());
            }
            Register::FPSR => {
                cpu.state.fpsr = value as u32;
                return Ok(());
            }
            _ => {}
        }
        cpu.registers.set(register, index, value);
        self.machine.derived_changed();
        self.machine
            .profile_missing
            .retain(|missing| *missing != register);
        if translates(register) {
            self.translation = true;
        }
        Ok(())
    }

    fn physical_count(&self) -> u64 {
        self.now
    }

    fn nv_mem(&mut self, _offset: u64) -> Result<u64, Effect> {
        Err(Effect::Refused("FEAT_NV2 is not in the profile"))
    }

    fn set_nv_mem(&mut self, _offset: u64, _value: u64) -> Result<(), Effect> {
        Err(Effect::Refused("FEAT_NV2 is not in the profile"))
    }

    fn operation(&mut self, operation: Operation) -> Result<(), Effect> {
        match operation {
            // Every TLB maintenance operation discards all translations, a
            // superset of what any scope or level requires.
            Operation::Tlbi(_) => {
                self.translation = true;
                Ok(())
            }
            Operation::At {
                stage,
                el,
                access,
                address,
            } => self.address_translation(stage, el, access, address),
            Operation::Dc {
                op, scope, operand, ..
            } => {
                if scope == CacheScope::SetWay {
                    return Ok(());
                }
                // The host is coherent: maintenance by VA only checks that
                // the address translates, as a write for invalidation.
                let write = op == CacheOp::Invalidate;
                self.check_maintenance(operand, write)
            }
            Operation::Ic { scope, operand } => {
                if scope == CacheScope::PoU {
                    self.check_maintenance(operand, false)?;
                }
                self.code = true;
                Ok(())
            }
            Operation::ZeroBlock { address, .. } => self.zero_block(address),
            // No speculation to restrict.
            Operation::RestrictPrediction { .. } => Ok(()),
        }
    }

    fn implementation_defined(&mut self, _read: bool) -> Result<Effect, Effect> {
        Err(Effect::Refused(
            "the IMPLEMENTATION DEFINED space is handled by machine::registers",
        ))
    }

    fn read_dbgdtr(&mut self) -> u64 {
        self.refuse("the debug communications channel is not modeled");
        0
    }

    fn write_dbgdtr(&mut self, _value: u64) -> Result<(), Effect> {
        Err(Effect::Refused(
            "the debug communications channel is not modeled",
        ))
    }

    /// The profile has no error records (ERRIDR_EL1.NUM is 0), so the
    /// ERX*_EL1 window reads as zero and ignores writes.
    fn error_record(&self, _register: ErrorRecord, _index: u64) -> u64 {
        0
    }

    fn set_error_record(
        &mut self,
        _register: ErrorRecord,
        _index: u64,
        _value: u64,
    ) -> Result<(), Effect> {
        Ok(())
    }

    fn auxiliary_monitor(&self, _index: u64) -> bool {
        false
    }

    fn limit(&self, limit: Limit) -> u64 {
        let dfr0 = self.machine.cpu.read(Register::ID_AA64DFR0_EL1);
        match limit {
            Limit::Breakpoints => (dfr0 >> 12 & 0xf) + 1,
            Limit::Watchpoints => (dfr0 >> 20 & 0xf) + 1,
            Limit::AuxiliaryMonitors => 0,
        }
    }
}

impl<H: Host, D: Devices> Access<'_, H, D> {
    /// ISR_EL1: virtual interrupts while routed to EL2 from EL1 or EL0
    /// outside the host, physical lines otherwise.
    fn pending(&self) -> u64 {
        let cpu = &self.machine.cpu;
        let lines = self.lines;
        let guest = cpu.pstate.el != 2 && !cpu.in_host();
        let line = |routing: u32, virtual_bit: u32, physical: bool| {
            if guest && cpu.hcr(routing) {
                cpu.hcr(virtual_bit)
            } else {
                physical
            }
        };
        (if line(HCR_IMO, HCR_VI, lines.irq) {
            ISR_I
        } else {
            0
        }) | (if line(HCR_FMO, HCR_VF, lines.fiq) {
            ISR_F
        } else {
            0
        }) | (if line(HCR_AMO, HCR_VSE, false) {
            ISR_A
        } else {
            0
        })
    }

    fn translate(
        &mut self,
        regime: TranslationRegime,
        requester: mmu::Requester,
        address: u64,
        access: MemoryAccess,
    ) -> Translated {
        let controls = self.machine.cpu.controls(regime);
        mmu::translate(
            &controls,
            address,
            access,
            requester,
            &mut super::RamTables(&mut self.machine.host),
        )
    }

    fn check_maintenance(&mut self, address: u64, write: bool) -> Result<(), Effect> {
        let regime = self.machine.cpu.regime();
        let requester = self.machine.cpu.requester();
        let access = if write {
            MemoryAccess::Write
        } else {
            MemoryAccess::Read
        };
        match self.translate(regime, requester, address, access) {
            Translated::Mapped(_) => Ok(()),
            Translated::Fault(fault) => Err(Effect::Exception(
                self.machine
                    .data_abort_exception(address, fault, true, true),
            )),
            Translated::Unsupported(_) => Err(Effect::Refused(
                "cache maintenance address needs an unsupported translation",
            )),
        }
    }

    fn zero_block(&mut self, address: u64) -> Result<(), Effect> {
        let dczid = self.machine.cpu.read(Register::DCZID_EL0);
        if self.machine.profile_missing.contains(&Register::DCZID_EL0) {
            return Err(Effect::Refused("DC ZVA without a profile DCZID_EL0"));
        }
        let bytes = 4u64 << (dczid & 0xf);
        let start = address & !(bytes - 1);
        let regime = self.machine.cpu.regime();
        let requester = self.machine.cpu.requester();
        match self.translate(regime, requester, start, MemoryAccess::Write) {
            Translated::Mapped(translation) => {
                let zero = alloc::vec![0u8; bytes as usize];
                if self.machine.host.write_ram(translation.physical, &zero) {
                    Ok(())
                } else {
                    Err(Effect::Refused("DC ZVA outside RAM"))
                }
            }
            Translated::Fault(fault) => Err(Effect::Exception(
                self.machine
                    .data_abort_exception(address, fault, true, false),
            )),
            Translated::Unsupported(_) => Err(Effect::Refused(
                "DC ZVA address needs an unsupported translation",
            )),
        }
    }

    /// `AArch64_AT`: S1E1 from the host becomes S1E2; S1E0 translates as
    /// unprivileged and S1E1R/W ignore PAN, S1E1RP/WP honor it. PAR_EL1 takes
    /// the result.
    fn address_translation(
        &mut self,
        stage: Stage,
        el: u64,
        access: AtAccess,
        address: u64,
    ) -> Result<(), Effect> {
        if stage == Stage::S12 && self.machine.cpu.stage2(TranslationRegime::El10) {
            return Err(Effect::Refused("AT S12 with stage 2 enabled"));
        }
        let cpu = &self.machine.cpu;
        let el = if el == 1 && cpu.in_host() && stage == Stage::S1 {
            2
        } else {
            el
        };
        let regime = if el == 2 || (el == 0 && cpu.in_host()) {
            TranslationRegime::El20
        } else {
            TranslationRegime::El10
        };
        let requester = mmu::Requester {
            el: if el == 0 { 1 } else { el as u8 },
            pan: matches!(access, AtAccess::ReadPAN | AtAccess::WritePAN) && cpu.pstate.pan,
            unprivileged: el == 0,
            guarded: cpu.pstate.guarded,
        };
        let memory = if matches!(access, AtAccess::Write | AtAccess::WritePAN) {
            MemoryAccess::Write
        } else {
            MemoryAccess::Read
        };
        let outcome = self.translate(regime, requester, address, memory);
        let Some(par) = mmu::par(&outcome) else {
            return Err(Effect::Refused("AT needs an unsupported translation"));
        };
        self.machine.cpu.registers.set(Register::PAR_EL1, 0, par);
        Ok(())
    }
}

impl<H: Host, D: Devices> Machine<H, D> {
    /// Execute MRS, MSR, SYS or SYSL through the generated accessor for its
    /// encoding. `None` when no architectural accessor matches.
    pub(super) fn system_access(&mut self, word: u32, access: RegisterAccess) -> Option<Step> {
        let read =
            access.direction() == stela_compiler::aarch64::system::registers::Direction::Read;
        let (accessor, index) = self.lookup.find(access.encoding(), read)?;
        let lines = self.lines();
        let now = self.host.counter();
        let mut context = Access {
            machine: self,
            rt: access.rt(),
            lines,
            now,
            result: None,
            translation: false,
            regime: false,
            code: false,
            refusal: Cell::new(None),
        };
        let effect = match (accessor.run)(&mut context, index) {
            Ok(effect) | Err(effect) => effect,
        };
        let Access {
            result,
            translation,
            regime,
            code,
            refusal,
            ..
        } = context;
        let refusal = refusal.into_inner().or(match effect {
            Effect::Refused(reason) => Some(reason),
            _ => None,
        });
        if let Some(reason) = refusal {
            let mut requirement = self.requirement(RequirementKind::SystemRegister {
                word,
                refusal: Refusal::UnsupportedSetting(reason),
            });
            requirement.syndrome = Some(super::super::exception::syndrome(
                Class::SystemRegister,
                trap_iss(access),
            ));
            return Some(Err(Stop::Unsupported(requirement)));
        }
        if translation {
            self.translations_changed();
        } else if regime {
            self.sync_regime();
        }
        if code {
            self.discard_code();
        }
        Some(match effect {
            Effect::Done => {
                if let Some(value) = result
                    && access.rt() != 31
                {
                    self.cpu.state.x[usize::from(access.rt())] = value;
                }
                self.next()
            }
            Effect::Undefined => self.undefined(),
            Effect::Trap { el, ec } => {
                let iss = if ec == Class::SystemRegister as u64 {
                    trap_iss(access)
                } else {
                    super::TRAPPED_AARCH64
                };
                let exception = Exception {
                    syndrome: (ec << 26) | (1 << 25) | u64::from(iss),
                    ..Exception::synchronous(Class::Unknown, 0, self.cpu.pc)
                }
                .to(el);
                self.take(exception);
                Ok(())
            }
            Effect::Exception(exception) => {
                self.take(exception);
                Ok(())
            }
            Effect::Refused(_) => unreachable!("handled above"),
        })
    }

    /// Fill the identification registers from the CPU profile and hand
    /// VPIDR_EL2 and VMPIDR_EL2 the physical values, as boot firmware does.
    pub(super) fn load_profile(&mut self) {
        self.cpu
            .registers
            .set_raw(Register::CNTFRQ_EL0, 0, self.profile.counter_frequency);
        for register in Register::ALL {
            if !identification(register) {
                continue;
            }
            let value = encoding_of(register).and_then(|encoding| {
                self.profile
                    .fixed
                    .iter()
                    .find(|(candidate, _)| *candidate == encoding)
                    .map(|(_, value)| *value)
            });
            match value {
                Some(value) => self.cpu.registers.set_raw(register, 0, value),
                None => self.profile_missing.push(register),
            }
        }
        for (virtual_register, physical) in [
            (Register::VPIDR_EL2, Register::MIDR_EL1),
            (Register::VMPIDR_EL2, Register::MPIDR_EL1),
        ] {
            if self.profile_missing.contains(&physical) {
                self.profile_missing.push(virtual_register);
            } else {
                let value = self.cpu.read(physical);
                self.cpu.registers.set_raw(virtual_register, 0, value);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{BASE, machine};
    use crate::machine::{
        cpu::{HCR_HCD, HCR_TGE, HCR_TSC},
        exception::{Pstate, Vector},
        system::Register,
    };
    use stela_compiler::aarch64::system::registers::Encoding;

    fn access(read: bool, encoding: Encoding, rt: u32) -> u32 {
        0xd510_0000
            | u32::from(read) << 21
            | u32::from(encoding.op0() & 1) << 19
            | u32::from(encoding.op1()) << 16
            | u32::from(encoding.crn()) << 12
            | u32::from(encoding.crm()) << 8
            | u32::from(encoding.op2()) << 5
            | rt
    }

    const SCTLR_EL1: Encoding = Encoding::new(3, 0, 1, 0, 0);
    const SCTLR_EL12: Encoding = Encoding::new(3, 5, 1, 0, 0);
    const CNTKCTL_EL1: Encoding = Encoding::new(3, 0, 14, 1, 0);
    const CNTVCT_EL0: Encoding = Encoding::new(3, 3, 14, 0, 2);
    const ID_AA64PFR0_EL1: Encoding = Encoding::new(3, 0, 0, 4, 0);
    const MIDR_EL1: Encoding = Encoding::new(3, 0, 0, 0, 0);
    const TLBI_VMALLE1: u32 = 0xd508_871f;
    const HVC: u32 = 0xd400_0002;
    const SMC: u32 = 0xd400_0003;
    const WFI: u32 = 0xd503_207f;
    const HCR_TVM: u64 = 1 << 26;
    const HCR_TRVM: u64 = 1 << 30;
    const HCR_TID3: u64 = 1 << 18;
    const HCR_TTLB: u64 = 1 << 25;
    const HCR_TWI: u64 = 1 << 13;

    type TestMachine =
        super::super::Machine<super::super::tests::FakeHost, super::super::NoDevices>;

    fn el2_trap(machine: &mut TestMachine, word: u32) -> u64 {
        machine.cpu.pc = BASE;
        machine.cpu.pstate = Pstate::reset(1);
        machine.cpu.registers.set(Register::VBAR_EL2, 0, 0x4_0000);
        machine.system_instruction(word).unwrap();
        // From EL1, a lower EL: the lower-EL AArch64 synchronous vector.
        assert_eq!(
            (machine.cpu.pstate.el, machine.cpu.pc),
            (2, 0x4_0400),
            "{word:#x}"
        );
        machine.cpu.read(Register::ESR_EL2)
    }

    #[test]
    fn hcr_el2_traps_route_el1_accesses_to_el2_with_their_syndromes() {
        let mut machine = machine(&[]);
        for (hcr, word) in [
            (HCR_TVM, access(false, SCTLR_EL1, 1)),
            (HCR_TRVM, access(true, SCTLR_EL1, 1)),
            (HCR_TID3, access(true, ID_AA64PFR0_EL1, 1)),
            (HCR_TTLB, TLBI_VMALLE1),
        ] {
            machine.cpu.registers.set(Register::HCR_EL2, 0, hcr);
            let esr = el2_trap(&mut machine, word);
            assert_eq!(esr >> 26, 0x18, "{word:#x}");
            // ISS: Op0, Op2, Op1, CRn, Rt, CRm and the direction (read = 1).
            assert_eq!(esr & 1, u64::from(word >> 21 & 1), "{word:#x}");
            assert_eq!(esr >> 10 & 0xf, u64::from(word >> 12 & 0xf), "{word:#x}");
        }
        // Without the trap the EL1 write reaches SCTLR_EL1.
        machine.cpu.registers.set(Register::HCR_EL2, 0, 0);
        machine.cpu.pstate = Pstate::reset(1);
        machine.cpu.state.x[1] = 0x1005;
        machine
            .system_instruction(access(false, SCTLR_EL1, 1))
            .unwrap();
        assert_eq!(machine.cpu.read(Register::SCTLR_EL1) & 0xffff, 0x1985);
        // HCR_EL2.TWI traps WFI and TSC traps SMC from EL1 to EL2.
        machine.cpu.registers.set(Register::HCR_EL2, 0, HCR_TWI);
        assert_eq!(el2_trap(&mut machine, WFI) >> 26, 0x01);
        machine
            .cpu
            .registers
            .set(Register::HCR_EL2, 0, 1 << HCR_TSC);
        assert_eq!(el2_trap(&mut machine, SMC) >> 26, 0x17);
        // HVC goes to EL2 unless HCR_EL2.HCD disables it.
        machine.cpu.registers.set(Register::HCR_EL2, 0, 0);
        assert_eq!(el2_trap(&mut machine, HVC) >> 26, 0x16);
        machine
            .cpu
            .registers
            .set(Register::HCR_EL2, 0, 1 << HCR_HCD);
        machine.cpu.pc = BASE;
        machine.cpu.pstate = Pstate::reset(1);
        machine.system_instruction(HVC).unwrap();
        assert_eq!(
            machine.cpu.read(Register::ESR_EL1) >> 26,
            0,
            "UNDEFINED at EL1"
        );
    }

    #[test]
    fn a_vhe_host_redirects_el1_names_and_reaches_el1_through_el12() {
        let mut machine = machine(&[]);
        machine.cpu.pstate = Pstate::reset(2);
        machine.cpu.state.x[1] = 0x1005;
        machine
            .system_instruction(access(false, SCTLR_EL1, 1))
            .unwrap();
        assert_eq!(machine.cpu.read(Register::SCTLR_EL2) & 1, 1);
        assert_eq!(machine.cpu.read(Register::SCTLR_EL1) & 1, 0);
        machine.cpu.state.x[2] = 1;
        machine
            .system_instruction(access(false, SCTLR_EL12, 2))
            .unwrap();
        assert_eq!(machine.cpu.read(Register::SCTLR_EL1) & 1, 1);
        machine.cpu.registers.set(Register::CNTHCTL_EL2, 0, 0x3);
        machine
            .system_instruction(access(true, CNTKCTL_EL1, 3))
            .unwrap();
        assert_eq!(
            machine.cpu.state.x[3] & 3,
            3,
            "CNTKCTL_EL1 names CNTHCTL_EL2"
        );
    }

    #[test]
    fn el0_counter_traps_follow_cntkctl_or_cnthctl_in_the_host() {
        let mut machine = machine(&[]);
        let user = Pstate {
            el: 0,
            sp: false,
            daif: 0,
            ..Pstate::reset(1)
        };
        machine.cpu.registers.set(Register::VBAR_EL1, 0, 0x1_0000);
        machine.cpu.registers.set(Register::VBAR_EL2, 0, 0x4_0000);
        machine.cpu.pstate = user;
        machine
            .system_instruction(access(true, CNTVCT_EL0, 0))
            .unwrap();
        assert_eq!((machine.cpu.pstate.el, machine.cpu.pc), (1, 0x1_0400));
        // In the host the trap goes to EL2 and CNTHCTL_EL2 governs it.
        machine
            .cpu
            .registers
            .set(Register::HCR_EL2, 0, 1 << HCR_TGE);
        machine.cpu.pstate = user;
        machine.cpu.pc = BASE;
        machine
            .system_instruction(access(true, CNTVCT_EL0, 0))
            .unwrap();
        assert_eq!((machine.cpu.pstate.el, machine.cpu.pc), (2, 0x4_0400));
        machine.cpu.registers.set(Register::CNTHCTL_EL2, 0, 1 << 1);
        machine.cpu.pstate = user;
        machine.cpu.pc = BASE;
        machine.host.now = 77;
        machine
            .system_instruction(access(true, CNTVCT_EL0, 4))
            .unwrap();
        assert_eq!((machine.cpu.state.x[4], machine.cpu.pstate.el), (77, 0));
    }

    #[test]
    fn identification_reads_come_from_the_profile_or_refuse() {
        let mut machine = machine(&[]);
        // The test profile has no MIDR_EL1: the read, through VPIDR_EL2 at
        // EL1, refuses rather than reading zero.
        assert!(matches!(
            machine.system_instruction(access(true, MIDR_EL1, 0)),
            Err(super::Stop::Unsupported(_))
        ));
        // A value written to VPIDR_EL2 at EL2 is what EL1 then reads.
        machine.cpu.pstate = Pstate::reset(2);
        machine.cpu.state.x[1] = 0x611f_0320;
        machine
            .system_instruction(access(false, Encoding::new(3, 4, 0, 0, 0), 1))
            .unwrap();
        machine.cpu.pstate = Pstate::reset(1);
        machine
            .system_instruction(access(true, MIDR_EL1, 2))
            .unwrap();
        assert_eq!(machine.cpu.state.x[2], 0x611f_0320);
    }

    #[test]
    fn interrupts_route_by_hcr_el2_and_virtual_interrupts_reach_el1() {
        let mut machine = machine(&[]);
        machine.cpu.registers.set(Register::VBAR_EL1, 0, 0x1_0000);
        machine.cpu.registers.set(Register::VBAR_EL2, 0, 0x4_0000);
        // A virtual IRQ (HCR_EL2.IMO and VI) is taken at EL1 under PSTATE.I.
        machine
            .cpu
            .registers
            .set(Register::HCR_EL2, 0, 1 << 4 | 1 << 7);
        machine.cpu.pstate = Pstate {
            daif: 0,
            ..Pstate::reset(1)
        };
        machine.derived_changed();
        assert!(machine.deliver_interrupts());
        assert_eq!((machine.cpu.pstate.el, machine.cpu.pc), (1, 0x1_0280));
        // Physical IRQs go to EL2 while IMO is set.
        assert_eq!(machine.cpu.interrupt_target(Vector::Irq), 2);
    }

    #[test]
    fn sctlr_endianness_bits_are_res0_and_alignment_checking_stops() {
        let mut machine = machine(&[]);
        // SCTLR_EL1.EE and E0E are RES0 without FEAT_MixedEnd.
        machine.cpu.state.x[0] = 3 << 24;
        machine.system_instruction(0xd518_1000).unwrap(); // msr sctlr_el1, x0
        assert_eq!(machine.cpu.read(Register::SCTLR_EL1) & 3 << 24, 0);
        machine.cpu.state.x[0] = 1 << 1;
        assert!(matches!(
            machine.system_instruction(0xd518_1000),
            Err(super::super::Stop::Unsupported(_))
        ));
    }
}
