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
    CpuProfile,
    cpu::{Cpu, Exception, HCR_AMO, HCR_FMO, HCR_IMO, HCR_VF, HCR_VI, HCR_VSE, TranslationRegime},
    debug::{self, DCC_FULL},
    exception::{Class, DAIF_A, DAIF_D, DAIF_F, DAIF_I, Pstate as PstateBits},
    registers::{Lines, Refusal, trap_iss},
    system::{
        ACCESSORS, AtAccess, CacheOp, CacheScope, Context, Effect, ErrorRecord, Limit, Operation,
        Pstate, Register, Stage,
    },
    timer::Channel,
};
use alloc::vec::Vec;
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

/// FEAT_AMUv1 is in the declared profile only through Apple clang's Armv8.4
/// implication, and the engine counts no activity: every AMU register access
/// stops instead of reading or storing counter values that never count.
const AMU_REFUSAL: &str = "activity monitors (FEAT_AMUv1) do not count";

fn activity_monitor(register: Register) -> bool {
    let name = register.name();
    name.starts_with("AMC") || name.starts_with("AMEV") || name.starts_with("AMUSERENR")
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

/// DataCacheWatchpointSize: the block a DC IVAC is watched as.
const DC_WATCH_BYTES: u64 = 64;

/// Writes that change which pages watchpoints keep out of the shadow tables
/// (`machine::debug::watched`).
fn watches(register: Register) -> bool {
    matches!(
        register,
        Register::DBGWCR_EL1
            | Register::DBGWVR_EL1
            | Register::MDSCR_EL1
            | Register::MDCR_EL2
            | Register::OSLSR_EL1
    )
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
/// Whether the LORegion registers are RES0: LORID_EL1.LD (bits 23:16)
/// reports no LORegion descriptor.
fn no_lor_descriptors(cpu: &crate::machine::cpu::Cpu) -> bool {
    cpu.field(Register::LORID_EL1, 16, 8) == 0
}

fn lor_region(register: Register) -> bool {
    matches!(
        register,
        Register::LORC_EL1 | Register::LORSA_EL1 | Register::LOREA_EL1 | Register::LORN_EL1
    )
}

/// MPAMn_ELx.MPAMEN. Without EL3, MPAM2_EL2's is read/write and MPAM1_EL1's
/// reads it and ignores writes.
const MPAMEN: u64 = 1 << 63;
/// RMR_EL2.RR, the Warm reset request.
const RMR_RR: u64 = 1 << 1;
const SCTLR_DZE: u32 = 14;
const HCR_TDZ: u32 = 28;
const DCZID_DZP: u64 = 1 << 4;

/// Whether DC ZVA traps at the current EL, which DCZID_EL0.DZP reports:
/// SCTLR_EL1.DZE and HCR_EL2.TDZ at EL0 outside the host, SCTLR_EL2.DZE in
/// it, and HCR_EL2.TDZ at EL1.
fn zero_block_prohibited(cpu: &crate::machine::cpu::Cpu) -> bool {
    match cpu.pstate.el {
        0 if cpu.in_host() => cpu.field(Register::SCTLR_EL2, SCTLR_DZE, 1) == 0,
        0 => cpu.field(Register::SCTLR_EL1, SCTLR_DZE, 1) == 0 || cpu.hcr(HCR_TDZ),
        1 => cpu.hcr(HCR_TDZ),
        _ => false,
    }
}
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
        if field == Pstate::D {
            // PSTATE.D masks same-EL debug exceptions, watchpoints included.
            self.regime = true;
        }
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
        if activity_monitor(register) {
            self.refuse(AMU_REFUSAL);
            return 0;
        }
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
            register if lor_region(register) && no_lor_descriptors(cpu) => 0,
            Register::MPAM1_EL1 => {
                cpu.registers.get(register, 0) & !MPAMEN
                    | cpu.registers.get(Register::MPAM2_EL2, 0) & MPAMEN
            }
            Register::DCZID_EL0 => {
                cpu.registers.get(register, 0) & !DCZID_DZP
                    | if zero_block_prohibited(cpu) {
                        DCZID_DZP
                    } else {
                        0
                    }
            }
            // RXfull and TXfull mirror the debug communications channel.
            Register::MDCCSR_EL0 => cpu.dcc.status(),
            Register::MDSCR_EL1 => cpu.registers.get(register, 0) & !DCC_FULL | cpu.dcc.status(),
            // Every claim tag is implemented; DBGCLAIMCLR reads the claim.
            Register::DBGCLAIMSET_EL1 => debug::CLAIM_TAGS,
            Register::DBGCLAIMCLR_EL1 => u64::from(cpu.claim),
            Register::OSDTRRX_EL1 => u64::from(cpu.dcc.rx),
            Register::OSDTRTX_EL1 => u64::from(cpu.dcc.tx),
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
        if activity_monitor(register) {
            return Err(Effect::Refused(AMU_REFUSAL));
        }
        let value = if register == Register::MPAM1_EL1 {
            value & !MPAMEN
        } else {
            value
        };
        // Without LORegion descriptors the LORegion registers are RAZ/WI.
        if lor_region(register) && no_lor_descriptors(cpu) {
            return Ok(());
        }
        match register {
            Register::SCTLR_EL1 | Register::SCTLR_EL2 if value & SCTLR_A != 0 => {
                return Err(Effect::Refused("SCTLR alignment checking"));
            }
            // RMR_EL2.RR requests a Warm reset into the reset vector, which
            // has no profile value (see RVBAR_EL2).
            Register::RMR_EL2 if value & RMR_RR != 0 => {
                return Err(Effect::Refused("RMR_EL2.RR Warm reset request"));
            }
            // OSLAR_EL1.OSLK locks and unlocks the OS lock (OSLSR_EL1.OSLK).
            Register::OSLAR_EL1 => {
                let oslsr = cpu.read(Register::OSLSR_EL1) & !0b10 | (value & 1) << 1;
                cpu.registers.set_raw(Register::OSLSR_EL1, 0, oslsr);
                self.regime = true;
                return Ok(());
            }
            // RXfull and TXfull are writable only while the OS lock is set,
            // for saving and restoring the channel.
            Register::MDSCR_EL1 if cpu.field(Register::OSLSR_EL1, 1, 1) != 0 => {
                cpu.dcc.tx_full = value >> 29 & 1 != 0;
                cpu.dcc.rx_full = value >> 30 & 1 != 0;
            }
            Register::OSDTRRX_EL1 => {
                cpu.dcc.rx = value as u32;
                return Ok(());
            }
            Register::DBGCLAIMSET_EL1 => {
                cpu.claim |= (value & debug::CLAIM_TAGS) as u8;
                return Ok(());
            }
            Register::DBGCLAIMCLR_EL1 => {
                cpu.claim &= !((value & debug::CLAIM_TAGS) as u8);
                return Ok(());
            }
            Register::OSDTRTX_EL1 => {
                cpu.dcc.tx = value as u32;
                return Ok(());
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
            // Without AArch32, FPSR keeps only QC and the cumulative flags.
            Register::FPSR => {
                cpu.state.fpsr = (value & !Register::FPSR.res0()) as u32;
                return Ok(());
            }
            _ => {}
        }
        if matches!(
            register,
            Register::CNTKCTL_EL1
                | Register::CNTHCTL_EL2
                | Register::CNTVOFF_EL2
                | Register::HCR_EL2
        ) {
            self.machine.sample_events(self.now);
        }
        let cpu = &mut self.machine.cpu;
        cpu.registers.set(register, index, value);
        self.machine.derived_changed();
        self.machine
            .profile_missing
            .retain(|missing| *missing != register);
        if translates(register) {
            self.translation = true;
        }
        if watches(register) {
            self.regime = true;
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
                self.check_maintenance(operand, write)?;
                // DC IVAC is watched as a write of the DataCacheWatchpointSize
                // block around it (64 bytes, CTR_EL0's line: Stela's choice).
                if write && scope == CacheScope::PoC {
                    let access = debug::Access {
                        address: operand & !(DC_WATCH_BYTES - 1),
                        size: DC_WATCH_BYTES,
                        read: false,
                        write: false,
                        maintenance: true,
                        el: self.machine.cpu.pstate.el,
                    };
                    if let Some(exception) = self
                        .machine
                        .watchpoint_exception(&access, self.machine.cpu.pc)
                    {
                        return Err(Effect::Exception(exception));
                    }
                }
                Ok(())
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

    fn read_dbgdtr(&mut self, width: u32) -> u64 {
        self.machine.cpu.dcc.read(width)
    }

    fn write_dbgdtr(&mut self, width: u32, value: u64) -> Result<(), Effect> {
        self.machine.cpu.dcc.write(width, value);
        Ok(())
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
                let access = debug::Access {
                    address: start,
                    size: bytes,
                    read: false,
                    write: true,
                    maintenance: false,
                    el: self.machine.cpu.pstate.el,
                };
                if let Some(exception) = self
                    .machine
                    .watchpoint_exception(&access, self.machine.cpu.pc)
                {
                    return Err(Effect::Exception(exception));
                }
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
    /// unprivileged and S1E1R/W ignore PAN, S1E1RP/WP honor it. S1E* stops at
    /// the IPA, though its walk goes through stage 2; S12E* translates both
    /// stages. PAR_EL1 takes the result, except that an external abort, or a
    /// stage-2 fault on the walk of an AT executed at EL1, is taken as a
    /// Data Abort with CM set.
    fn address_translation(
        &mut self,
        stage: Stage,
        el: u64,
        access: AtAccess,
        address: u64,
    ) -> Result<(), Effect> {
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
        let controls = self.machine.cpu.controls(regime);
        let tables = &mut super::RamTables(&mut self.machine.host);
        let outcome = match stage {
            Stage::S1 => mmu::translate_stage1(&controls, address, memory, requester, tables),
            Stage::S12 => mmu::translate(&controls, address, memory, requester, tables),
        };
        if let Translated::Fault(fault) = outcome {
            let walk = fault.second_stage.is_some_and(|second| second.walk);
            if fault.kind == mmu::FaultKind::ExternalOnWalk
                || walk && self.machine.cpu.pstate.el == 1
            {
                return Err(Effect::Exception(
                    self.machine
                        .data_abort_exception(address, fault, true, true),
                ));
            }
        }
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

    /// Fill the identification registers of the running PE from the CPU
    /// profile.
    pub(super) fn load_profile(&mut self) {
        identify(
            &self.profile,
            self.current,
            &mut self.cpu,
            &mut self.profile_missing,
        );
    }
}

/// Fill `cpu`'s identification registers with the profile's values for PE
/// number `pe` and hand VPIDR_EL2 and VMPIDR_EL2 the physical values, as boot
/// firmware does. `missing` collects the registers the profile has no value
/// for.
pub(super) fn identify(
    profile: &CpuProfile,
    pe: usize,
    cpu: &mut Cpu,
    missing: &mut Vec<Register>,
) {
    cpu.registers
        .set_raw(Register::CNTFRQ_EL0, 0, profile.counter_frequency);
    let own = profile.processors.get(pe);
    for register in Register::ALL {
        if !identification(register) {
            continue;
        }
        let value = match (register, own) {
            (Register::MIDR_EL1, Some(identity)) => Some(identity.midr),
            (Register::MPIDR_EL1, Some(identity)) => Some(identity.mpidr),
            _ => encoding_of(register).and_then(|encoding| {
                profile
                    .fixed
                    .iter()
                    .find(|(candidate, _)| *candidate == encoding)
                    .map(|(_, value)| *value)
            }),
        };
        match value {
            Some(value) => cpu.registers.set_raw(register, 0, value),
            // A layout the profile reserves entirely, such as the AArch32
            // ID registers without FEAT_AA32, has one value.
            None if register.res0() | register.res1() == u64::MAX => {
                cpu.registers.set_raw(register, 0, register.res1());
            }
            None => missing.push(register),
        }
    }
    for (virtual_register, physical) in [
        (Register::VPIDR_EL2, Register::MIDR_EL1),
        (Register::VMPIDR_EL2, Register::MPIDR_EL1),
    ] {
        if missing.contains(&physical) {
            missing.push(virtual_register);
        } else {
            let value = cpu.read(physical);
            cpu.registers.set_raw(virtual_register, 0, value);
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
    fn sctlr_el0_controls_trap_to_el1_or_to_el2_in_the_host_and_set_dzp() {
        const CTR_EL0: Encoding = Encoding::new(3, 3, 0, 0, 1);
        const DCZID_EL0: Encoding = Encoding::new(3, 3, 0, 0, 7);
        const DC_CVAC_X0: u32 = 0xd50b_7a20;
        const IC_IVAU_X0: u32 = 0xd50b_7520;
        const DC_ZVA_X0: u32 = 0xd50b_7420;
        const UCT: u64 = 1 << 15;
        const DZE: u64 = 1 << 14;
        const UCI: u64 = 1 << 26;
        const TDZ: u64 = 1 << 28;
        let mut machine = machine(&[]);
        let user = Pstate {
            el: 0,
            sp: false,
            daif: 0,
            ..Pstate::reset(1)
        };
        machine.cpu.registers.set(Register::VBAR_EL1, 0, 0x1_0000);
        machine.cpu.registers.set(Register::VBAR_EL2, 0, 0x4_0000);
        let sctlr = machine.cpu.read(Register::SCTLR_EL1) & !(UCT | DZE | UCI);
        machine.cpu.registers.set(Register::SCTLR_EL1, 0, sctlr);
        let run = |machine: &mut TestMachine, pstate: Pstate, word: u32| {
            machine.cpu.pstate = pstate;
            machine.cpu.pc = BASE;
            machine.cpu.state.x[0] = BASE + 0x100;
            machine.system_instruction(word).unwrap();
            (machine.cpu.pstate.el, machine.cpu.pc)
        };
        // With UCT, UCI and DZE clear, EL0 traps to EL1 with EC 0x18 and the
        // instruction's own Op0, Op2, Op1, CRn, Rt, CRm and direction.
        for (word, iss) in [
            (access(true, CTR_EL0, 0), 0x32_c001),
            (DC_CVAC_X0, 0x12_dc14),
            (IC_IVAU_X0, 0x12_dc0a),
            (DC_ZVA_X0, 0x12_dc08),
        ] {
            assert_eq!(run(&mut machine, user, word), (1, 0x1_0400), "{word:#x}");
            assert_eq!(
                machine.cpu.read(Register::ESR_EL1),
                0x18 << 26 | 1 << 25 | iss,
                "{word:#x}"
            );
        }
        // DCZID_EL0.DZP reports the DC ZVA trap; BS is the profile's 4.
        let dczid = access(true, DCZID_EL0, 1);
        assert_eq!(run(&mut machine, user, dczid), (0, BASE + 4));
        assert_eq!(machine.cpu.state.x[1], 0x14);
        machine
            .cpu
            .registers
            .set(Register::SCTLR_EL1, 0, sctlr | UCT | DZE | UCI);
        // With UCT set the read reaches CTR_EL0, which this machine's profile
        // does not give.
        machine.cpu.pstate = user;
        assert!(
            machine
                .system_instruction(access(true, CTR_EL0, 1))
                .is_err()
        );
        for word in [DC_CVAC_X0, IC_IVAU_X0] {
            assert_eq!(run(&mut machine, user, word), (0, BASE + 4), "{word:#x}");
        }
        machine.host.ram[0x100..0x140].fill(0xaa);
        assert_eq!(run(&mut machine, user, DC_ZVA_X0), (0, BASE + 4));
        assert!(machine.host.ram[0x100..0x140].iter().all(|&b| b == 0));
        run(&mut machine, user, dczid);
        assert_eq!(machine.cpu.state.x[1], 0x4);
        // HCR_EL2.TDZ prohibits DC ZVA at EL0 and EL1, trapping to EL2.
        machine.cpu.registers.set(Register::HCR_EL2, 0, TDZ);
        for pstate in [user, Pstate::reset(1)] {
            run(&mut machine, pstate, dczid);
            assert_eq!(machine.cpu.state.x[1], 0x14);
            assert_eq!(run(&mut machine, pstate, DC_ZVA_X0), (2, 0x4_0400));
        }
        // In the host SCTLR_EL2 governs EL0, trapping to EL2 (WFI and WFE
        // through nTWI and nTWE), and EL2 is never prohibited DC ZVA.
        machine
            .cpu
            .registers
            .set(Register::HCR_EL2, 0, 1 << HCR_TGE | 1 << 34);
        const NTWI: u64 = 1 << 16;
        const NTWE: u64 = 1 << 18;
        let sctlr2 = machine.cpu.read(Register::SCTLR_EL2) & !(UCT | DZE | UCI | NTWI | NTWE);
        machine.cpu.registers.set(Register::SCTLR_EL2, 0, sctlr2);
        run(&mut machine, user, dczid);
        assert_eq!(machine.cpu.state.x[1], 0x14);
        machine.cpu.event = false;
        for (word, esr) in [
            (access(true, CTR_EL0, 0), 0x18 << 26 | 1 << 25 | 0x32_c001),
            (DC_CVAC_X0, 0x18 << 26 | 1 << 25 | 0x12_dc14),
            (DC_ZVA_X0, 0x18 << 26 | 1 << 25 | 0x12_dc08),
            (WFI, 0x01 << 26 | 1 << 25 | 1 << 24 | 0xe << 20),
            (0xd503_205f, 0x01 << 26 | 1 << 25 | 1 << 24 | 0xe << 20 | 1),
        ] {
            assert_eq!(run(&mut machine, user, word), (2, 0x4_0400), "{word:#x}");
            assert_eq!(machine.cpu.read(Register::ESR_EL2), esr, "{word:#x}");
        }
        machine
            .cpu
            .registers
            .set(Register::SCTLR_EL2, 0, sctlr2 | UCI | DZE);
        run(&mut machine, user, dczid);
        assert_eq!(machine.cpu.state.x[1], 0x4);
        for word in [DC_CVAC_X0, DC_ZVA_X0] {
            assert_eq!(run(&mut machine, user, word), (0, BASE + 4), "{word:#x}");
        }
        machine.cpu.registers.set(Register::SCTLR_EL2, 0, sctlr2);
        run(&mut machine, Pstate::reset(2), dczid);
        assert_eq!(machine.cpu.state.x[1], 0x4);
    }

    #[test]
    fn rmr_el2_resets_into_aarch64_and_refuses_a_warm_reset_request() {
        const RMR_EL2: Encoding = Encoding::new(3, 4, 12, 0, 2);
        let mut machine = machine(&[]);
        machine.cpu.pstate = Pstate::reset(2);
        // Without AArch32, AA64 is RAO/WI and bits 63:2 are RES0.
        machine.cpu.state.x[0] = !0b11;
        machine
            .system_instruction(access(false, RMR_EL2, 0))
            .unwrap();
        machine
            .system_instruction(access(true, RMR_EL2, 1))
            .unwrap();
        assert_eq!(machine.cpu.state.x[1], 1);
        machine.cpu.state.x[0] = 0b10;
        assert!(matches!(
            machine.system_instruction(access(false, RMR_EL2, 0)),
            Err(super::Stop::Unsupported(_))
        ));
        assert_eq!(machine.cpu.registers.get(Register::RMR_EL2, 0), 1);
    }

    #[test]
    fn el1_reads_vmpidr_el2_as_mpidr_el1_and_el2_the_physical_value() {
        const MPIDR_EL1: Encoding = Encoding::new(3, 0, 0, 0, 5);
        const VMPIDR_EL2: Encoding = Encoding::new(3, 4, 0, 0, 5);
        let mut machine = machine(&[]);
        let physical = 0x8000_0103;
        machine.cpu.registers.set(Register::MPIDR_EL1, 0, physical);
        machine
            .profile_missing
            .retain(|register| *register != Register::MPIDR_EL1);
        let read = |machine: &mut TestMachine, el: u8, encoding: Encoding| {
            machine.cpu.pstate = Pstate::reset(el);
            machine.cpu.state.x[1] = 0x5a5a;
            machine
                .system_instruction(access(true, encoding, 1))
                .unwrap();
            machine.cpu.state.x[1]
        };
        assert_eq!(read(&mut machine, 2, MPIDR_EL1), physical);
        // VMPIDR_EL2 keeps Aff3..Aff0, U and MT; bit 31 is RES1 and the
        // rest RES0.
        machine.cpu.pstate = Pstate::reset(2);
        machine.cpu.state.x[0] = u64::MAX;
        machine
            .system_instruction(access(false, VMPIDR_EL2, 0))
            .unwrap();
        let virtual_mpidr = 0xff_c1ff_ffff;
        assert_eq!(read(&mut machine, 2, VMPIDR_EL2), virtual_mpidr);
        assert_eq!(read(&mut machine, 1, MPIDR_EL1), virtual_mpidr);
        assert_eq!(read(&mut machine, 2, MPIDR_EL1), physical);
    }

    #[test]
    fn fields_without_aarch32_or_lpa2_are_reserved() {
        const SCTLR_EL2: Encoding = Encoding::new(3, 4, 1, 0, 0);
        const TCR_EL1: Encoding = Encoding::new(3, 0, 2, 0, 2);
        const TCR_EL2: Encoding = Encoding::new(3, 4, 2, 0, 2);
        let mut machine = machine(&[]);
        let round_trip = |machine: &mut TestMachine, encoding: Encoding, value: u64| {
            machine.cpu.pstate = Pstate::reset(2);
            machine.cpu.state.x[0] = value;
            machine
                .system_instruction(access(false, encoding, 0))
                .unwrap();
            machine
                .system_instruction(access(true, encoding, 1))
                .unwrap();
            machine.cpu.state.x[1]
        };
        // With E2H set and no AArch32 at EL0, SCTLR_EL2.SED (bit 8) and bit 7
        // are RES1 and CP15BEN (bit 5) is RES0, as in SCTLR_EL1.
        let sed = 1 << 8;
        let cp15ben = 1 << 5;
        let res1 = sed | 1 << 7;
        assert_eq!(
            round_trip(&mut machine, SCTLR_EL2, cp15ben) & (res1 | cp15ben),
            res1
        );
        assert_eq!(
            machine.cpu.registers.get(Register::SCTLR_EL2, 0) & cp15ben,
            0
        );
        // Without FEAT_LPA2 the DS bit of either TCR is RES0.
        for tcr in [TCR_EL1, TCR_EL2] {
            assert_eq!(round_trip(&mut machine, tcr, 1 << 59 | 0x19), 0x19);
        }
    }

    #[test]
    fn special_purpose_and_coprocessor_registers_keep_only_their_fields() {
        const NZCV: Encoding = Encoding::new(3, 3, 4, 2, 0);
        const DAIF: Encoding = Encoding::new(3, 3, 4, 2, 1);
        const CURRENT_EL: Encoding = Encoding::new(3, 0, 4, 2, 2);
        const FPSR: Encoding = Encoding::new(3, 3, 4, 4, 1);
        const CPACR_EL1: Encoding = Encoding::new(3, 0, 1, 0, 2);
        const CPTR_EL2: Encoding = Encoding::new(3, 4, 1, 1, 2);
        let mut machine = machine(&[]);
        let round_trip_value = |machine: &mut TestMachine, encoding: Encoding, value: u64| {
            machine.cpu.pstate = Pstate::reset(2);
            machine.cpu.state.x[0] = value;
            machine
                .system_instruction(access(false, encoding, 0))
                .unwrap();
            machine
                .system_instruction(access(true, encoding, 1))
                .unwrap();
            machine.cpu.state.x[1]
        };
        let round_trip = |machine: &mut TestMachine, el: u8, encoding: Encoding| {
            machine.cpu.pstate = Pstate::reset(el);
            machine.cpu.pc = BASE;
            machine.cpu.state.x[0] = u64::MAX;
            machine
                .system_instruction(access(false, encoding, 0))
                .unwrap();
            machine.cpu.state.x[1] = 0x5a5a;
            machine
                .system_instruction(access(true, encoding, 1))
                .unwrap();
            assert_eq!(machine.cpu.pc, BASE + 8);
            machine.cpu.state.x[1]
        };
        // CPTR_EL2 has its E2H layout: FPEN, TAM and TCPAC; CPACR_EL1 keeps
        // FPEN alone.
        assert_eq!(round_trip(&mut machine, 2, CPTR_EL2), 0xc030_0000);
        machine.cpu.registers.set(Register::CPTR_EL2, 0, 0b11 << 20);
        machine.derived_changed();
        assert_eq!(round_trip(&mut machine, 1, CPACR_EL1), 0x0030_0000);
        // NZCV, DAIF and FPSR hold their flags, masks and cumulative bits.
        assert_eq!(round_trip(&mut machine, 1, NZCV), 0xf000_0000);
        assert_eq!(machine.cpu.state.nzcv, 0xf000_0000);
        assert_eq!(round_trip(&mut machine, 1, DAIF), 0x3c0);
        assert_eq!(machine.cpu.pstate.daif, 0xf);
        assert_eq!(round_trip(&mut machine, 1, FPSR), 0x0800_009f);
        // CurrentEL reads the EL at bits 3:2.
        for el in [1, 2] {
            machine.cpu.pstate = Pstate::reset(el);
            machine
                .system_instruction(access(true, CURRENT_EL, 2))
                .unwrap();
            assert_eq!(machine.cpu.state.x[2], u64::from(el) << 2);
        }
        // HCR_EL2.BSU and SWIO are stored (one PE runs at a time and no cache
        // is visible, so neither has an effect); bits 39:38 are RES0 and RW
        // reads as one.
        const HCR_EL2: Encoding = Encoding::new(3, 4, 1, 1, 0);
        let hcr = 0b11 << 10 | 1 << 1 | 1 << 34;
        assert_eq!(
            round_trip_value(&mut machine, HCR_EL2, hcr | 0b11 << 38),
            hcr | 1 << 31
        );
        machine.cpu.registers.set(Register::HCR_EL2, 0, 1 << 34);
        // CPTR_EL2.TCPAC traps EL1 CPACR_EL1 accesses to EL2.
        machine
            .cpu
            .registers
            .set(Register::CPTR_EL2, 0, 1 << 31 | 0b11 << 20);
        let esr = el2_trap(&mut machine, access(true, CPACR_EL1, 1));
        assert_eq!(esr >> 26, 0x18);
    }

    #[test]
    fn pstate_fields_vector_bases_and_context_ids_keep_only_their_bits() {
        const SPSEL: Encoding = Encoding::new(3, 0, 4, 2, 0);
        const PAN: Encoding = Encoding::new(3, 0, 4, 2, 3);
        const SSBS: Encoding = Encoding::new(3, 3, 4, 2, 6);
        const VBAR_EL1: Encoding = Encoding::new(3, 0, 12, 0, 0);
        const VBAR_EL2: Encoding = Encoding::new(3, 4, 12, 0, 0);
        const CONTEXTIDR_EL1: Encoding = Encoding::new(3, 0, 13, 0, 1);
        const CONTEXTIDR_EL2: Encoding = Encoding::new(3, 4, 13, 0, 1);
        const SCTLR_EL2: Encoding = Encoding::new(3, 4, 1, 0, 0);
        let mut machine = machine(&[]);
        let write_read = |machine: &mut TestMachine, el: u8, encoding: Encoding, value: u64| {
            machine.cpu.pstate = Pstate::reset(el);
            machine.cpu.pc = BASE;
            machine.cpu.state.x[0] = value;
            machine
                .system_instruction(access(false, encoding, 0))
                .unwrap();
            machine
                .system_instruction(access(true, encoding, 1))
                .unwrap();
            assert_eq!(machine.cpu.pc, BASE + 8, "{encoding:?}");
            machine.cpu.state.x[1]
        };
        // PSTATE.SP, PAN and SSBS at bits 0, 22 and 12.
        assert_eq!(write_read(&mut machine, 1, SPSEL, u64::MAX), 1);
        assert_eq!(write_read(&mut machine, 1, PAN, u64::MAX), 1 << 22);
        assert!(machine.cpu.pstate.pan);
        assert_eq!(write_read(&mut machine, 1, SSBS, u64::MAX), 1 << 12);
        assert!(machine.cpu.pstate.ssbs);
        // Vector bases are 2 KiB aligned; CONTEXTIDR holds a 32-bit PROCID.
        assert_eq!(write_read(&mut machine, 1, VBAR_EL1, u64::MAX), !0x7ff);
        assert_eq!(write_read(&mut machine, 2, VBAR_EL2, u64::MAX), !0x7ff);
        assert_eq!(
            write_read(&mut machine, 1, CONTEXTIDR_EL1, u64::MAX),
            0xffff_ffff
        );
        assert_eq!(
            write_read(&mut machine, 2, CONTEXTIDR_EL2, u64::MAX),
            0xffff_ffff
        );
        // SCTLR bits 17, 24, 25 and 53:50 are RES0 in both registers.
        let reserved = 1 << 17 | 3 << 24 | 0xf << 50;
        assert_eq!(
            write_read(&mut machine, 1, SCTLR_EL1, reserved) & reserved,
            0
        );
        assert_eq!(
            write_read(&mut machine, 2, SCTLR_EL2, reserved) & reserved,
            0
        );
        // HCR_EL2.TWE traps EL1 WFE to EL2 when no event is pending.
        machine.cpu.event = false;
        machine.cpu.registers.set(Register::HCR_EL2, 0, 1 << 14);
        let esr = el2_trap(&mut machine, 0xd503_205f);
        assert_eq!(esr, 0x01 << 26 | 1 << 25 | 1 << 24 | 0xe << 20 | 1);
    }

    #[test]
    fn whole_register_state_holds_what_software_writes() {
        const STATE: &[(u8, Encoding)] = &[
            (1, Encoding::new(3, 3, 13, 0, 2)), // TPIDR_EL0
            (1, Encoding::new(3, 3, 13, 0, 3)), // TPIDRRO_EL0
            (1, Encoding::new(3, 0, 13, 0, 4)), // TPIDR_EL1
            (2, Encoding::new(3, 4, 13, 0, 2)), // TPIDR_EL2
            (1, Encoding::new(3, 0, 4, 0, 1)),  // ELR_EL1
            (2, Encoding::new(3, 4, 4, 0, 1)),  // ELR_EL2
            (1, Encoding::new(3, 0, 6, 0, 0)),  // FAR_EL1
            (2, Encoding::new(3, 4, 6, 0, 0)),  // FAR_EL2
            (1, Encoding::new(3, 0, 4, 1, 0)),  // SP_EL0
            (2, Encoding::new(3, 4, 4, 1, 0)),  // SP_EL1
            (2, Encoding::new(3, 3, 13, 0, 7)), // SCXTNUM_EL0
            (2, Encoding::new(3, 4, 13, 0, 7)), // SCXTNUM_EL2
        ];
        let mut machine = machine(&[]);
        // HCR_EL2.APK lets EL1 reach the keys.
        machine.cpu.registers.set(Register::HCR_EL2, 0, 1 << 40);
        let value = 0xfedc_ba98_7654_3210;
        // The PAC keys: APIA and APIB (CRm 1), APDA and APDB (CRm 2) and
        // APGA (CRm 3), Lo then Hi.
        let keys = [(1, 0..4), (2, 0..4), (3, 0..2)]
            .into_iter()
            .flat_map(|(crm, op2s)| op2s.map(move |op2| (1, Encoding::new(3, 0, 2, crm, op2))));
        for (el, encoding) in STATE.iter().copied().chain(keys) {
            machine.cpu.pstate = Pstate::reset(el);
            machine.cpu.pc = BASE;
            machine.cpu.state.x[0] = value;
            machine
                .system_instruction(access(false, encoding, 0))
                .unwrap();
            machine.cpu.state.x[1] = 0;
            machine
                .system_instruction(access(true, encoding, 1))
                .unwrap();
            assert_eq!(
                (machine.cpu.state.x[1], machine.cpu.pc),
                (value, BASE + 8),
                "{encoding:?}"
            );
        }
        // HSTR_EL2, which traps AArch32 EL1, is RES0; MVFR0-2, REVIDR_EL1 and
        // the debug-state DLR_EL0 and DSPSR_EL0 behave as the profile says:
        // AArch32 media features and revisions read 0, and outside Debug
        // state DLR and DSPSR are UNDEFINED.
        machine.cpu.pstate = Pstate::reset(2);
        machine.cpu.state.x[0] = u64::MAX;
        let hstr = Encoding::new(3, 4, 1, 1, 3);
        machine.system_instruction(access(false, hstr, 0)).unwrap();
        machine.system_instruction(access(true, hstr, 1)).unwrap();
        assert_eq!(machine.cpu.state.x[1], 0);
        for op2 in 0..3 {
            machine.cpu.pstate = Pstate::reset(1);
            machine.cpu.state.x[1] = 1;
            machine
                .system_instruction(access(true, Encoding::new(3, 0, 0, 3, op2), 1))
                .unwrap();
            assert_eq!(machine.cpu.state.x[1], 0, "MVFR{op2}_EL1");
        }
        machine.cpu.registers.set(Register::VBAR_EL1, 0, 0x1_0000);
        for encoding in [Encoding::new(3, 3, 4, 5, 0), Encoding::new(3, 3, 4, 5, 1)] {
            machine.cpu.pstate = Pstate::reset(1);
            machine
                .system_instruction(access(true, encoding, 1))
                .unwrap();
            assert_eq!(
                machine.cpu.read(Register::ESR_EL1),
                0x0200_0000,
                "{encoding:?}"
            );
        }
    }

    #[test]
    fn aarch32_banked_spsrs_are_res0_at_el2_and_undefined_at_el1() {
        let mut machine = machine(&[]);
        // Without AArch32 at EL1, SPSR_irq, SPSR_abt, SPSR_und and SPSR_fiq
        // are RES0 from EL2.
        for op2 in 0..4 {
            let spsr = Encoding::new(3, 4, 4, 3, op2);
            machine.cpu.pstate = Pstate::reset(2);
            machine.cpu.pc = BASE;
            machine.cpu.state.x[0] = u64::MAX;
            machine.system_instruction(access(false, spsr, 0)).unwrap();
            machine.cpu.state.x[1] = u64::MAX;
            machine.system_instruction(access(true, spsr, 1)).unwrap();
            assert_eq!(
                (machine.cpu.state.x[1], machine.cpu.pc),
                (0, BASE + 8),
                "{op2}"
            );
            machine.cpu.pstate = Pstate::reset(1);
            machine.cpu.registers.set(Register::VBAR_EL1, 0, 0x1_0000);
            machine.system_instruction(access(true, spsr, 1)).unwrap();
            assert_eq!(machine.cpu.read(Register::ESR_EL1), 0x0200_0000, "{op2}");
        }
    }

    #[test]
    fn ecv_self_synchronized_counts_and_el1_virtual_counter_traps() {
        const CNTPCTSS_EL0: Encoding = Encoding::new(3, 3, 14, 0, 5);
        const CNTVCTSS_EL0: Encoding = Encoding::new(3, 3, 14, 0, 6);
        const CNTV_CTL_EL0: Encoding = Encoding::new(3, 3, 14, 3, 1);
        const EL1PCTEN: u64 = 1 << 10;
        let mut machine = machine(&[]);
        let kernel = machine.cpu.pstate;
        machine.cpu.registers.set(Register::VBAR_EL2, 0, 0x4_0000);
        machine.cpu.registers.set(Register::CNTVOFF_EL2, 0, 100);
        machine
            .cpu
            .registers
            .set(Register::CNTHCTL_EL2, 0, EL1PCTEN);
        machine.host.now = 1000;
        machine
            .system_instruction(access(true, CNTPCTSS_EL0, 1))
            .unwrap();
        machine
            .system_instruction(access(true, CNTVCTSS_EL0, 2))
            .unwrap();
        assert_eq!(
            (machine.cpu.state.x[1], machine.cpu.state.x[2]),
            (1000, 900)
        );
        // CNTHCTL_EL2.EL1TVCT traps EL1 reads of the virtual count and
        // EL1TVT the virtual timer registers to EL2 with EC 0x18.
        for (bit, encoding) in [(14, CNTVCTSS_EL0), (14, CNTVCT_EL0), (13, CNTV_CTL_EL0)] {
            machine
                .cpu
                .registers
                .set(Register::CNTHCTL_EL2, 0, EL1PCTEN | 1 << bit);
            machine.cpu.pstate = kernel;
            machine.cpu.pc = BASE;
            machine
                .system_instruction(access(true, encoding, 3))
                .unwrap();
            assert_eq!(
                (machine.cpu.pstate.el, machine.cpu.pc),
                (2, 0x4_0400),
                "{encoding:?}"
            );
            assert_eq!(machine.cpu.read(Register::ESR_EL2) >> 26, 0x18);
        }
    }

    /// For every generated accessor at every index, run at EL1 on a fresh
    /// machine that `configure` prepares, whether it traps to EL2 with EC
    /// 0x18.
    fn el1_traps_to_el2(
        configure: impl FnOnce(
            &mut super::Machine<super::super::tests::FakeHost, super::super::NoDevices>,
        ),
    ) -> alloc::vec::Vec<bool> {
        use super::{ACCESSORS, Access, Cell, Effect, Host};
        let mut machine = machine(&[]);
        configure(&mut machine);
        ACCESSORS
            .iter()
            .flat_map(|accessor| (0..1u64 << accessor.index.len()).map(move |m| (accessor, m)))
            .map(|(accessor, m)| {
                let lines = machine.lines();
                let now = machine.host.counter();
                let mut context = Access {
                    machine: &mut machine,
                    rt: 0,
                    lines,
                    now,
                    result: None,
                    translation: false,
                    regime: false,
                    code: false,
                    refusal: Cell::new(None),
                };
                let effect = match (accessor.run)(&mut context, m) {
                    Ok(effect) | Err(effect) => effect,
                };
                matches!(effect, Effect::Trap { el: 2, ec: 0x18 })
            })
            .collect()
    }

    /// HCR_EL2's APK, FIEN and EnSCXT set, so that their coarse traps do not
    /// pre-empt the controls under test.
    const HCR_ENABLES: u64 = 1 << 40 | 1 << 47 | 1 << 53;

    /// Every FEAT_FGT control the profile implements changes whether some
    /// EL1 access traps to EL2 with EC 0x18. HFGITR_EL2.ERET, SVC_EL0 and
    /// SVC_EL1 trap instructions without accessors and are tested in
    /// engine.rs. HAFGRTR_EL2 is left out: every activity monitor access is
    /// refused.
    #[test]
    fn every_fine_grained_trap_control_traps_an_el1_access() {
        const CONTROLS: [Register; 5] = [
            Register::HFGRTR_EL2,
            Register::HFGWTR_EL2,
            Register::HFGITR_EL2,
            Register::HDFGRTR_EL2,
            Register::HDFGWTR_EL2,
        ];
        const INSTRUCTIONS: u64 = 0b111 << 51;
        let enable = |machine: &mut super::Machine<_, _>| {
            let hcr = machine.cpu.read(Register::HCR_EL2) | HCR_ENABLES;
            machine.cpu.registers.set(Register::HCR_EL2, 0, hcr);
        };
        let baseline = el1_traps_to_el2(enable);
        let mut inert = alloc::vec::Vec::new();
        for register in CONTROLS {
            let mut fields = !(register.res0() | register.res1());
            if register == Register::HFGITR_EL2 {
                fields &= !INSTRUCTIONS;
            }
            for bit in (0..64).filter(|bit| fields >> bit & 1 != 0) {
                let traps = el1_traps_to_el2(|machine| {
                    enable(machine);
                    let value = machine.cpu.read(register) ^ 1 << bit;
                    machine.cpu.registers.set(register, 0, value);
                });
                if traps == baseline {
                    inert.push(alloc::format!("{}[{bit}]", register.name()));
                }
            }
        }
        assert!(inert.is_empty(), "controls that trap nothing: {inert:?}");
    }

    /// Every HCR_EL2 control that traps System register and System
    /// instruction accesses changes whether some EL1 access traps to EL2:
    /// TID1-4, TACR, TSW, TPCP, TPU, TTLB, TVM, TRVM, TDZ, TLOR and TERR,
    /// FEAT_EVT's TICAB and TOCU, FEAT_EVT2's TTLBIS and TTLBOS, and APK,
    /// FIEN and EnSCXT, which trap while clear.
    #[test]
    fn every_hcr_el2_access_trap_control_traps_an_el1_access() {
        const CONTROLS: [(&str, u32); 21] = [
            ("TID1", 16),
            ("TID2", 17),
            ("TID3", 18),
            ("TACR", 21),
            ("TSW", 22),
            ("TPCP", 23),
            ("TPU", 24),
            ("TTLB", 25),
            ("TVM", 26),
            ("TDZ", 28),
            ("TRVM", 30),
            ("TLOR", 35),
            ("TERR", 36),
            ("APK", 40),
            ("FIEN", 47),
            ("TID4", 49),
            ("TICAB", 50),
            ("TOCU", 52),
            ("EnSCXT", 53),
            ("TTLBIS", 54),
            ("TTLBOS", 55),
        ];
        let hcr = |value: u64| {
            move |machine: &mut super::Machine<_, _>| {
                machine.cpu.registers.set(Register::HCR_EL2, 0, value);
            }
        };
        let baseline = el1_traps_to_el2(hcr(HCR_ENABLES));
        let inert: alloc::vec::Vec<_> = CONTROLS
            .into_iter()
            .filter(|&(_, bit)| el1_traps_to_el2(hcr(HCR_ENABLES ^ 1 << bit)) == baseline)
            .map(|(name, _)| name)
            .collect();
        assert!(inert.is_empty(), "controls that trap nothing: {inert:?}");
    }

    #[test]
    fn reserved_and_absent_id_registers_follow_feat_idst() {
        const RESERVED: Encoding = Encoding::new(3, 0, 0, 4, 3);
        const GMID_EL1: Encoding = Encoding::new(3, 1, 0, 0, 4);
        const HCR_TID3: u64 = 1 << 18;
        let mut machine = machine(&[]);
        machine.cpu.registers.set(Register::VBAR_EL1, 0, 0x1_0000);
        machine.cpu.registers.set(Register::VBAR_EL2, 0, 0x4_0000);
        let kernel = machine.cpu.pstate;
        let class = |machine: &super::Machine<_, _>, register| machine.cpu.read(register) >> 26;
        // RES0 from EL1.
        machine.cpu.state.x[3] = 1;
        machine
            .system_instruction(access(true, RESERVED, 3))
            .unwrap();
        assert_eq!((machine.cpu.state.x[3], machine.cpu.pc), (0, BASE + 4));
        // HCR_EL2.TID3 traps EL1 reads to EL2.
        machine.cpu.registers.set(Register::HCR_EL2, 0, HCR_TID3);
        machine.cpu.pc = BASE;
        machine
            .system_instruction(access(true, RESERVED, 3))
            .unwrap();
        assert_eq!((machine.cpu.pstate.el, machine.cpu.pc), (2, 0x4_0400));
        assert_eq!(class(&machine, Register::ESR_EL2), 0x18);
        machine.cpu.registers.set(Register::HCR_EL2, 0, 0);
        // FEAT_IDST: an EL0 read traps to EL1 with EC 0x18.
        machine.cpu.pstate = Pstate {
            el: 0,
            sp: false,
            ..kernel
        };
        machine.cpu.pc = BASE;
        machine
            .system_instruction(access(true, RESERVED, 3))
            .unwrap();
        assert_eq!((machine.cpu.pstate.el, machine.cpu.pc), (1, 0x1_0400));
        assert_eq!(class(&machine, Register::ESR_EL1), 0x18);
        // A write is UNDEFINED.
        machine.cpu.pstate = kernel;
        machine.cpu.pc = BASE;
        machine
            .system_instruction(access(false, RESERVED, 3))
            .unwrap();
        assert_eq!(
            (machine.cpu.pc, class(&machine, Register::ESR_EL1)),
            (0x1_0200, 0)
        );
        // GMID_EL1 without FEAT_MTE2 is an unimplemented ID register: EC
        // 0x18 at the current EL.
        machine.cpu.pstate = kernel;
        machine.cpu.pc = BASE;
        machine
            .system_instruction(access(true, GMID_EL1, 3))
            .unwrap();
        assert_eq!(
            (machine.cpu.pc, class(&machine, Register::ESR_EL1)),
            (0x1_0200, 0x18)
        );
    }

    #[test]
    fn cntfrq_reads_the_profile_counter_frequency() {
        const CNTFRQ_EL0: Encoding = Encoding::new(3, 3, 14, 0, 0);
        let mut machine = machine(&[]);
        machine
            .system_instruction(access(true, CNTFRQ_EL0, 5))
            .unwrap();
        assert_eq!(machine.cpu.state.x[5], machine.profile.counter_frequency);
    }

    #[test]
    fn identification_reads_come_from_the_profile_or_refuse() {
        let mut machine = machine(&[]);
        // Without FEAT_AA32 the AArch32 ID registers are entirely reserved,
        // so they read their one value with no profile entry.
        for (index, encoding) in [Encoding::new(3, 0, 0, 2, 0), Encoding::new(3, 0, 0, 3, 0)]
            .into_iter()
            .enumerate()
        {
            machine.cpu.state.x[3] = 1;
            machine
                .system_instruction(access(true, encoding, 3))
                .unwrap_or_else(|stop| panic!("{index}: {stop:?}"));
            assert_eq!(machine.cpu.state.x[3], 0);
        }
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
        // ISR_EL1 shows the virtual lines while they are routed to EL2: VI,
        // VF and VSE as I, F and A at bits 7, 6 and 8.
        const ISR_EL1: Encoding = Encoding::new(3, 0, 12, 1, 0);
        for (hcr, isr) in [
            (1 << 4 | 1 << 7, 1 << 7),
            (1 << 3 | 1 << 6, 1 << 6),
            (1 << 5 | 1 << 8, 1 << 8),
            (1 << 4 | 1 << 3 | 1 << 5, 0),
        ] {
            machine.cpu.registers.set(Register::HCR_EL2, 0, hcr);
            machine.cpu.pstate = Pstate::reset(1);
            machine
                .system_instruction(access(true, ISR_EL1, 1))
                .unwrap();
            assert_eq!(machine.cpu.state.x[1], isr, "{hcr:#x}");
        }
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

    #[test]
    fn mpam_enable_is_mpam2s_and_the_vpm_and_el3_registers_are_undefined() {
        const MPAM0_EL1: Encoding = Encoding::new(3, 0, 10, 5, 1);
        const MPAM1_EL1: Encoding = Encoding::new(3, 0, 10, 5, 0);
        const MPAM2_EL2: Encoding = Encoding::new(3, 4, 10, 5, 0);
        let mut machine = machine(&[]);
        // The profile's MPAMIDR_EL1: PARTID 0 and PMG 0 only, no HCR.
        machine
            .profile_missing
            .retain(|register| *register != Register::MPAMIDR_EL1);
        machine.cpu.registers.set(Register::MPAMIDR_EL1, 0, 0);
        machine.cpu.registers.set(Register::VBAR_EL1, 0, 0x1_0000);
        machine.cpu.registers.set(Register::VBAR_EL2, 0, 0x4_0000);
        let access_at = |machine: &mut TestMachine, el: u8, read: bool, encoding, value| {
            machine.cpu.pstate = Pstate::reset(el);
            machine.cpu.pc = BASE;
            machine.cpu.state.x[1] = value;
            machine
                .system_instruction(access(read, encoding, 1))
                .unwrap();
            (machine.cpu.pc, machine.cpu.state.x[1])
        };
        // EL2 sets MPAMEN and clears the reset traps on MPAM0_EL1 and
        // MPAM1_EL1; without EL3, MPAM1_EL1.MPAMEN reads MPAM2_EL2's and
        // ignores writes.
        let partitions = 0x0000_0506_0007_0008;
        for (enable, expected) in [(1u64 << 63, 1u64 << 63), (0, 0)] {
            access_at(&mut machine, 2, false, MPAM2_EL2, enable | partitions);
            assert_eq!(
                access_at(&mut machine, 2, true, MPAM2_EL2, 0),
                (BASE + 4, enable | partitions)
            );
            access_at(
                &mut machine,
                1,
                false,
                MPAM1_EL1,
                !enable & 1 << 63 | partitions,
            );
            assert_eq!(
                access_at(&mut machine, 1, true, MPAM1_EL1, 0),
                (BASE + 4, expected | partitions)
            );
        }
        // MPAM0_EL1 has no MPAMEN.
        access_at(&mut machine, 1, false, MPAM0_EL1, u64::MAX);
        assert_eq!(
            access_at(&mut machine, 1, true, MPAM0_EL1, 0).1,
            0x0000_ffff_ffff_ffff
        );
        // MPAMIDR_EL1.HAS_HCR is 0, so MPAMHCR_EL2, MPAMVPM<n>_EL2 and
        // MPAMVPMV_EL2 are UNDEFINED; without EL3 so is MPAM3_EL3.
        for encoding in [
            Encoding::new(3, 4, 10, 4, 0),
            Encoding::new(3, 4, 10, 6, 0),
            Encoding::new(3, 4, 10, 6, 7),
            Encoding::new(3, 4, 10, 4, 1),
            Encoding::new(3, 6, 10, 5, 0),
        ] {
            assert_eq!(
                access_at(&mut machine, 2, true, encoding, 0).0,
                0x4_0200,
                "{encoding:?}"
            );
            assert_eq!(machine.cpu.read(Register::ESR_EL2), 0x0200_0000);
        }
    }

    #[test]
    fn disr_el1_is_stored_and_reads_vdisr_el2_while_amo_routes_serrors() {
        const DISR_EL1: Encoding = Encoding::new(3, 0, 12, 1, 1);
        let mut machine = machine(&[]);
        let access_at = |machine: &mut TestMachine, el: u8, read: bool, value| {
            machine.cpu.pstate = Pstate::reset(el);
            machine.cpu.state.x[1] = value;
            machine
                .system_instruction(access(read, DISR_EL1, 1))
                .unwrap();
            machine.cpu.state.x[1]
        };
        // A, IDS, AET, EA and DFSC hold what EL2 writes; the rest is RES0.
        access_at(&mut machine, 2, false, u64::MAX);
        let disr = access_at(&mut machine, 2, true, 0);
        assert_eq!(disr, !Register::DISR_EL1.res0());
        assert_eq!(disr & (1 << 31 | 1 << 24), 1 << 31 | 1 << 24);
        // With HCR_EL2.AMO, EL1 reads and writes VDISR_EL2 instead.
        machine.cpu.registers.set(Register::HCR_EL2, 0, 1 << 5);
        machine
            .cpu
            .registers
            .set(Register::VDISR_EL2, 0, 0x8000_0011);
        assert_eq!(access_at(&mut machine, 1, true, 0), 0x8000_0011);
        access_at(&mut machine, 1, false, 0);
        assert_eq!(machine.cpu.read(Register::VDISR_EL2), 0);
        assert_eq!(machine.cpu.read(Register::DISR_EL1), disr);
        // Without AMO, EL1 reaches DISR_EL1 itself.
        machine.cpu.registers.set(Register::HCR_EL2, 0, 0);
        assert_eq!(access_at(&mut machine, 1, true, 0), disr);
    }

    #[test]
    fn mpam_ras_lor_and_scxtnum_follow_their_minimal_configurations() {
        let mut machine = machine(&[]);
        // HCR_EL2.EnSCXT lets EL1 reach SCXTNUM_EL1, and clearing the reset
        // traps of MPAM2_EL2 (TRAPMPAM0EL1, TRAPMPAM1EL1) lets it reach
        // MPAM1_EL1.
        machine.cpu.registers.set(Register::HCR_EL2, 0, 1 << 53);
        machine.cpu.registers.set(Register::MPAM2_EL2, 0, 0);
        let write = |machine: &mut super::super::Machine<_, _>, encoding, value| {
            machine.cpu.state.x[1] = value;
            machine
                .system_instruction(access(false, encoding, 1))
                .unwrap();
        };
        let read = |machine: &mut super::super::Machine<_, _>, encoding| {
            machine
                .system_instruction(access(true, encoding, 2))
                .unwrap();
            machine.cpu.state.x[2]
        };
        // MPAM1_EL1 and SCXTNUM_EL1 hold what EL1 writes.
        for (encoding, value) in [
            (Encoding::new(3, 0, 10, 5, 0), 0x0001_0002_0003),
            (Encoding::new(3, 0, 13, 0, 7), 0x1234_5678),
        ] {
            write(&mut machine, encoding, value);
            assert_eq!(read(&mut machine, encoding), value, "{encoding:?}");
        }
        // With no LORegion descriptor (LORID_EL1 0), LORSA_EL1, LOREA_EL1,
        // LORN_EL1 and LORC_EL1 are RES0: RAZ/WI.
        machine
            .profile_missing
            .retain(|register| *register != Register::LORID_EL1);
        machine.cpu.registers.set(Register::LORID_EL1, 0, 0);
        for op2 in 0..4 {
            let encoding = Encoding::new(3, 0, 10, 4, op2);
            write(&mut machine, encoding, 0x8000_0001);
            assert_eq!(read(&mut machine, encoding), 0, "{encoding:?}");
        }
        // No error record: ERX* read 0 and ignore writes, whatever ERRSELR
        // selects.
        write(&mut machine, Encoding::new(3, 0, 5, 3, 1), 3);
        write(&mut machine, Encoding::new(3, 0, 5, 4, 1), u64::MAX);
        assert_eq!(read(&mut machine, Encoding::new(3, 0, 5, 4, 1)), 0);
        assert_eq!(read(&mut machine, Encoding::new(3, 0, 5, 4, 2)), 0);
        // An AMU access stops: its counters would never count.
        let Err(super::super::Stop::Unsupported(requirement)) =
            machine.system_instruction(access(true, Encoding::new(3, 3, 13, 2, 0), 2))
        else {
            panic!("AMCR_EL0 read")
        };
        assert!(format!("{:?}", requirement.kind).contains("activity monitors"));
    }
}
