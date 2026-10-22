//! The architectural state of one PE: `GuestState` for the registers native
//! blocks use, plus PC, PSTATE, the System register file and Apple's state.
//!
//! EL0, EL1 and EL2 exist; EL2 is a VHE host (HCR_EL2.E2H is RES1). Every
//! exception is routed to its target EL as Arm's pseudocode routes it, and
//! entry and return use that EL's ELR, SPSR, ESR, FAR, VBAR and SP (Arm
//! `AArch64_TakeException`, `AArch64_ExceptionReturn`).
use super::{
    exception::{self, Class, IllegalReturn, Pstate, Vector},
    mmu::{self, Controls, Sprr},
    system::{
        Feature, File, Register,
        helpers::{bits, effective_nvx},
    },
};
use crate::scalable::ScalableState;
use alloc::rc::Rc;
use core::cell::RefCell;
use stela_compiler::{
    GuestState,
    aarch64::scalable::{ScalableMode, VectorLength},
};

pub const HCR_VM: u32 = 0;
pub const HCR_FMO: u32 = 3;
pub const HCR_IMO: u32 = 4;
pub const HCR_AMO: u32 = 5;
pub const HCR_VF: u32 = 6;
pub const HCR_VI: u32 = 7;
pub const HCR_VSE: u32 = 8;
pub const HCR_TSC: u32 = 19;
pub const HCR_TGE: u32 = 27;
pub const HCR_HCD: u32 = 29;
pub const HCR_TEA: u32 = 37;
pub const HCR_API: u32 = 41;
/// HCR_EL2.ATA: EL0 and EL1 outside the host may access Allocation Tags.
pub const HCR_ATA: u32 = 56;
/// SCTLR_ELx.ATA0, ATA, TCF0 and TCF (FEAT_MTE2).
const SCTLR_ATA0: u32 = 42;
const SCTLR_ATA: u32 = 43;
const SCTLR_TCF0: u32 = 38;
const SCTLR_TCF: u32 = 40;
/// TCF 0b01: Tag Check faults are synchronous.
const TCF_SYNC: u64 = 0b01;
const TCR_TBI0: u64 = 1 << 37;
const TCR_TBI1: u64 = 1 << 38;
const TCR_TCMA0: u64 = 1 << 57;
const TCR_TCMA1: u64 = 1 << 58;

/// The streaming vector length of a chip with FEAT_SME: 512 bits, the M4's.
/// It is the only length implemented (Arm `SupportedPowerTwoSVL`), so
/// `ImplementedSMEVectorLength` selects it for every SMCR_ELx.LEN.
pub const STREAMING_VECTOR_BYTES: usize = 64;
/// CPACR_EL1.FPEN, and CPTR_EL2.FPEN in its CPACR layout.
const FPEN: u32 = 20;
const CPACR_SMEN: u32 = 24;
const CPTR_SMEN: u32 = 24;

/// CTR_EL0.ERG = 4: sixteen words.
pub const RESERVATION_GRANULE: u64 = 64;

/// An Exclusives reservation: the physical reservation granule an exclusive
/// load marked, with the bytes it held then. One PE runs at a time, so
/// another observer's write can only break the reservation between runs;
/// the granule's bytes changing is how it shows (`engine::processors`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reservation {
    pub granule: u64,
    pub bytes: [u8; RESERVATION_GRANULE as usize],
}

/// Apple GXF state of one guarded level: GL1 beside EL1, GL2 beside EL2
/// (Asahi Linux "SPRR and GXF"; m1n1 `cpu_regs.h`, `gxf.c` and `gxf_asm.S`).
#[derive(Debug, Clone, Default)]
pub struct GuardedBank {
    /// GXF_ENTER_ELx: where GENTER continues.
    pub enter: u64,
    /// GXF_ABORT_ELx.
    pub abort: u64,
    /// SP_GLx when it is not the current stack pointer.
    pub sp: u64,
    pub tpidr: u64,
    pub vbar: u64,
    pub spsr: u64,
    /// ASPSR_GLx; bit 0 makes GEXIT return to the guarded level.
    pub aspsr: u64,
    pub esr: u64,
    pub elr: u64,
    pub far: u64,
}

pub const GXF_CONFIG_EN: u64 = 1;
/// GXF_CONFIG bits without public meaning that SPTM 26A434 sets in EL2's
/// configuration once its GL2 entry, abort and vector addresses are in
/// place (`__text+0xbf6c` to `__text+0xbf9c`): bits 1, 2, 3 and 5 always,
/// and bit 6 when it also clears EL1's configuration, entry and abort
/// (`GXF_CONFIG_EL12`, `GXF_ENTER_EL12`, `GXF_ABORT_EL12`). As with
/// SPRR_CONFIG's undocumented bits, they are taken as locks that bind
/// outside the guarded level: bits 1 to 5 of EL2's own GXF registers, which
/// only SPTM writes, and bit 6 of EL1's enable (inference).
pub const GXF_CONFIG_LOCKS: u64 = 0b10_1110;
pub const GXF_CONFIG_EL1_LOCK: u64 = 1 << 6;
pub const ASPSR_GUARDED: u64 = 1;
/// The ISS GENTER leaves in ESR_GLx under EC 0x3f, with its immediate in
/// bits 4:0: m1n1 `hv_sprr.h` `HV_GXF_ESR_GENTER` (0xfe010000, "EC 0x3f")
/// ORed with the immediate; Asahi Linux "Apple Proprietary Instructions":
/// "imm5 stored in ESR_GLx".
const GENTER_ISS: u32 = 0x1_0000;

/// Apple's implementation-defined state (machine::registers dispatches its
/// encodings).
#[derive(Debug, Clone)]
pub struct AppleState {
    /// SPRR_CONFIG_EL1.
    pub sprr_config: u64,
    /// SPRR permissions: EL0 of the EL1&0 regime, EL1, EL0 of the EL2&0
    /// regime, EL2.
    pub sprr_perm: [u64; 4],
    /// `S3_6_C15_C3_0` and `S3_6_C15_C3_1` (`mmu::Sprr::fields`).
    pub sprr_fields: [u64; 2],
    /// GXF_CONFIG of EL1 and EL2.
    pub gxf_config: [u64; 2],
    /// GL1 and GL2.
    pub guarded: [GuardedBank; 2],
    /// APCTL_EL1 and APCTL_EL2.
    pub apctl: [u64; 2],
    /// KERNELKEYLO/HI_EL1.
    pub kernel_key: [u64; 2],
    /// Distinct source-qualified Apple EL2 PAC bank; unknown until written.
    pub pointer_keys: super::pointer_keys::Bank,
    /// VMSA_LOCK_EL1 and the EL whose translation registers it locks.
    pub vmsa_lock: u64,
    pub vmsa_lock_el: u8,
    /// VM_TMR_FIQ_ENA_EL2: bit 0 lets the EL1 virtual timer, bit 1 the EL1
    /// physical timer, signal FIQ.
    pub vm_timer_fiq: u64,
    /// SPR_LOCKDOWN_EL2 and SPR_LOCKDOWN_EL1, and the bits of
    /// `S3_4_C15_C12_5` that commit them (`registers::SprLockdown`).
    pub spr_lockdown: [u64; 2],
    pub spr_commit: u64,
    /// CYC_OVRD (`registers::CYC_OVRD`), 0 from reset (inference).
    pub cyc_ovrd: u64,
    /// The Apple generic timer's own registers (`timer::agt`).
    pub generic_timer: super::timer::agt::State,
    /// Implementation-defined registers without architectural effect here.
    pub impdef: super::impdef::Registers,
}

/// SPRR_PERM indexes into [`AppleState::sprr_perm`].
pub const PERM_EL0_10: usize = 0;
pub const PERM_EL1: usize = 1;
pub const PERM_EL0_20: usize = 2;
pub const PERM_EL2: usize = 3;
pub const VM_TIMER_FIQ_VIRTUAL: u64 = 1;
pub const VM_TIMER_FIQ_PHYSICAL: u64 = 2;

impl Default for AppleState {
    fn default() -> Self {
        Self {
            sprr_config: 0,
            sprr_perm: [0; 4],
            sprr_fields: [0; 2],
            gxf_config: [0; 2],
            guarded: [GuardedBank::default(), GuardedBank::default()],
            apctl: [0; 2],
            kernel_key: [0; 2],
            pointer_keys: super::pointer_keys::Bank::default(),
            vmsa_lock: 0,
            vmsa_lock_el: 1,
            // Both EL1 timers signal FIQ until EL2 software says otherwise
            // (inference: m1n1 and SPTM program it explicitly).
            vm_timer_fiq: VM_TIMER_FIQ_VIRTUAL | VM_TIMER_FIQ_PHYSICAL,
            spr_lockdown: [0; 2],
            spr_commit: 0,
            cyc_ovrd: 0,
            generic_timer: super::timer::agt::State::new(super::Chip::DEFAULT),
            impdef: super::impdef::Registers::default(),
        }
    }
}

/// A translation regime of the profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranslationRegime {
    /// EL1&0, through stage 1 and, with HCR_EL2.VM, stage 2.
    El10,
    /// EL2&0, the VHE host.
    El20,
}

/// Which stack pointer a PSTATE selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stack {
    El0,
    El1,
    El2,
    /// SP_GL1 or SP_GL2.
    Guarded(usize),
}

fn stack(pstate: Pstate) -> Stack {
    match (pstate.el, pstate.sp, pstate.guarded) {
        (0, _, _) | (_, false, _) => Stack::El0,
        (el, true, true) => Stack::Guarded(usize::from(el) - 1),
        (1, true, false) => Stack::El1,
        (_, true, false) => Stack::El2,
    }
}

/// Why a GXF instruction cannot run here; each is UNDEFINED.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardedRefusal {
    /// GENTER at EL0 or GL0, or with GXF or SPRR disabled.
    Enter,
    /// GEXIT outside the guarded level.
    Exit,
}

#[derive(Debug)]
pub struct Cpu {
    pub state: GuestState,
    pub pc: u64,
    pub pstate: Pstate,
    /// The architectural System registers.
    pub registers: File,
    pub apple: AppleState,
    /// The serial lane's event storage. Converted PEs use the linear canonical
    /// endpoint; observers must use event_is_set, not this inactive scalar.
    pub event: bool,
    /// Arm `ShouldAdvanceSS`: the instruction being stepped advances the
    /// software step state machine when it completes; ERET cancels that.
    pub step_advance: bool,
    /// The debug communications channel.
    pub dcc: super::debug::Dcc,
    /// The claim tags (DBGCLAIMSET_EL1, DBGCLAIMCLR_EL1), clear at reset.
    pub claim: u8,
    /// The caches CLIDR_EL1 and CCSIDR_EL1 describe, where the board's
    /// identity gives them (`machine::caches`).
    pub caches: Option<super::caches::Caches>,
    /// The serial lane's byte-observed reservation (`engine::exclusive`).
    /// Converted PEs retain their actual monitor in canonical_memory.
    pub monitor: Option<Reservation>,
    /// Linear canonical monitor/event owner after shared-system conversion.
    /// The legacy fields above grant no authority while this owner is present.
    pub(in crate::machine) canonical_memory: Option<super::engine::SharedMemory>,
    /// The PE's Apple AMX unit (`machine::amx`).
    pub amx: super::amx::Unit,
    /// The GICv3 virtual CPU interface (`machine::vgic`).
    pub vgic: super::vgic::CpuInterface,
    /// On a chip with FEAT_SME: PSTATE.SM and ZA, ZA itself, ZT0 with
    /// FEAT_SME2, and the Z, P and FFR state beyond `state.v`
    /// (`crate::scalable`).
    pub scalable: Option<ScalableState>,
    /// Apple's core performance monitor (`machine::pmu`), on the PEs whose
    /// chip and core clock the profile declares.
    pub pmu: Option<super::pmu::Pmu>,
    /// The activity monitors (`machine::amu`), on a chip with FEAT_AMUv1.
    pub amu: Option<super::amu::Amu>,
    /// The instructions this PE has retired (`machine::pmu`).
    pub retired: u64,
    /// The CTRR registers of this PE's cluster, shared with its other PEs
    /// (`machine::ctrr`).
    pub ctrr: Rc<RefCell<super::ctrr::Cluster>>,
    /// This PE's own CTRR registers on the M4 and later.
    pub ctrr_core: super::ctrr::Core,
    /// What iBoot left in the core lock registers, which every PE and
    /// cluster starts from.
    pub core_locks: Rc<super::ctrr::Handoff>,
    /// The region the memory controller has locked against writes, first
    /// and last byte, as the engine last read it from the devices.
    pub memory_lock: super::mmu::MemoryLocks,
    /// System registers answered as storage after their model refused an
    /// access outside strict mode, by encoding selector: each reads the
    /// value last written to it until its model accepts a write
    /// (`engine::Machine::set_strict`).
    pub degraded: alloc::collections::BTreeMap<u16, u64>,
}

/// What an exception entry needs beyond the vector kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exception {
    pub vector: Vector,
    pub syndrome: u64,
    pub fault_address: Option<u64>,
    /// ELR_ELx: the preferred return address.
    pub return_address: u64,
    /// The EL it is taken to; `None` routes it as an exception that targets
    /// EL1 by default (to EL2 from EL2, or from EL0 with HCR_EL2.TGE).
    pub target: Option<u8>,
}

impl Exception {
    pub fn synchronous(class: Class, iss: u32, return_address: u64) -> Self {
        Self {
            vector: Vector::Synchronous,
            syndrome: exception::syndrome(class, iss),
            fault_address: None,
            return_address,
            target: None,
        }
    }

    pub fn undefined(pc: u64) -> Self {
        Self::synchronous(Class::Unknown, 0, pc)
    }

    pub fn to(self, el: u8) -> Self {
        Self {
            target: Some(el),
            ..self
        }
    }
}

/// The banked exception registers of one EL.
struct Bank {
    elr: Register,
    spsr: Register,
    esr: Register,
    far: Register,
    vbar: Register,
    sctlr: Register,
}

fn bank(el: u8) -> Bank {
    if el == 2 {
        Bank {
            elr: Register::ELR_EL2,
            spsr: Register::SPSR_EL2,
            esr: Register::ESR_EL2,
            far: Register::FAR_EL2,
            vbar: Register::VBAR_EL2,
            sctlr: Register::SCTLR_EL2,
        }
    } else {
        Bank {
            elr: Register::ELR_EL1,
            spsr: Register::SPSR_EL1,
            esr: Register::ESR_EL1,
            far: Register::FAR_EL1,
            vbar: Register::VBAR_EL1,
            sctlr: Register::SCTLR_EL1,
        }
    }
}

/// A consuming borrow of this exact local monitor. Preparation can fail before
/// CPU/controller effects; dropping it leaves the reservation unchanged.
pub(crate) enum PreparedExclusiveClear<'a> {
    Legacy(&'a mut Option<Reservation>),
    Canonical(crate::memory::domain::PreparedLocalClear<'a>),
}
impl PreparedExclusiveClear<'_> {
    pub(crate) fn commit(self) {
        match self {
            Self::Legacy(monitor) => *monitor = None,
            Self::Canonical(clear) => clear.commit(),
        }
    }
}

impl Cpu {
    /// A PE of the chip the tests run on ([`super::test_chip`]).
    #[cfg(test)]
    pub fn new(pc: u64, pstate: Pstate) -> Self {
        Self::of(super::test_chip(), pc, pstate)
    }

    /// A PE of `chip`, its registers at their Cold reset values under the
    /// chip's profile.
    pub fn of(chip: super::Chip, pc: u64, pstate: Pstate) -> Self {
        let mut registers = File::new(chip);
        // OSLSR_EL1.OSLM = 0b10 (bits 3 and 0): the OS lock is implemented.
        // OSLK, set at Cold reset, comes with the reset value.
        let oslsr = registers.get(Register::OSLSR_EL1, 0);
        registers.set_raw(Register::OSLSR_EL1, 0, oslsr | 0b1000);
        // CPTR_EL2.FPEN (E2H being RES1) leaves reset at 0b11, FP/SIMD not
        // trapped, where Arm leaves it UNKNOWN: SPTM 26A434 (T8112) uses
        // FP/SIMD on its cold entry and on its warm reset path (`ldr q0` at
        // `__text+0x3f74c`, reached from the RVBAR page) before it ever
        // writes CPTR_EL2, and nothing runs before it on a core leaving
        // reset.
        registers.set_raw(Register::CPTR_EL2, 0, 0b11 << FPEN);
        Self {
            state: GuestState::default(),
            pc,
            pstate,
            registers,
            apple: AppleState {
                generic_timer: super::timer::agt::State::new(chip),
                ..AppleState::default()
            },
            event: false,
            step_advance: false,
            dcc: super::debug::Dcc::default(),
            claim: 0,
            caches: None,
            monitor: None,
            canonical_memory: None,
            amx: super::amx::Unit::on(chip),
            vgic: super::vgic::CpuInterface::default(),
            scalable: (chip.implemented(Feature::FEAT_SME) == Ok(true)).then(|| {
                let length = VectorLength::from_bytes(STREAMING_VECTOR_BYTES)
                    .expect("a 512-bit vector length");
                ScalableState::new(length, Feature::FEAT_SME2.on(chip))
            }),
            pmu: None,
            amu: None,
            retired: 0,
            ctrr: Rc::default(),
            ctrr_core: super::ctrr::Core::default(),
            core_locks: Rc::default(),
            memory_lock: [None; 4],
            degraded: alloc::collections::BTreeMap::new(),
        }
    }

    /// The actual event register; converted PEs read their canonical endpoint.
    pub fn event_is_set(&self) -> bool {
        self.canonical_memory
            .as_ref()
            .map_or(self.event, |memory| memory.event_endpoint().is_set())
    }
    /// Publish an event to this PE, coalescing with concurrent monitor signals.
    pub fn signal_event(&mut self) {
        if let Some(memory) = &self.canonical_memory {
            memory.event_endpoint().signal_local();
        } else {
            self.event = true;
        }
    }
    /// Consume at most the currently published event; no copied bit is cleared.
    pub fn consume_event(&mut self) -> bool {
        if let Some(memory) = &self.canonical_memory {
            memory.event_endpoint().consume_if_set()
        } else {
            core::mem::take(&mut self.event)
        }
    }
    /// CLREX and legal exception return clear the same local reservation as
    /// checked native stores. The physical global mark retains its own lifetime.
    pub(crate) fn prepare_clear_exclusive(
        &mut self,
    ) -> Result<PreparedExclusiveClear<'_>, stela_compiler::context::memory::MemoryStatus> {
        if let Some(memory) = &mut self.canonical_memory {
            Ok(PreparedExclusiveClear::Canonical(
                memory.prepare_clear_reservation()?,
            ))
        } else {
            Ok(PreparedExclusiveClear::Legacy(&mut self.monitor))
        }
    }
    pub fn clear_exclusive(&mut self) -> Result<(), stela_compiler::context::memory::MemoryStatus> {
        self.prepare_clear_exclusive()?.commit();
        Ok(())
    }
    pub fn has_canonical_memory(&self) -> bool {
        self.canonical_memory.is_some()
    }

    /// Present an identification that withholds the chip's features in
    /// `withheld` (`identification::withheld`): the PE treats them as
    /// absent, and without FEAT_SME (or FEAT_SME2) keeps no SME state (or
    /// ZT0) for them.
    pub fn present(&mut self, withheld: u64) {
        self.registers.withhold(withheld);
        let sme = self.registers.has(Feature::FEAT_SME);
        let sme2 = self.registers.has(Feature::FEAT_SME2);
        match &self.scalable {
            Some(scalable) if sme && scalable.has_zt0_storage() == sme2 => {}
            None if !sme => {}
            _ => {
                self.scalable = sme.then(|| {
                    let length = VectorLength::from_bytes(STREAMING_VECTOR_BYTES)
                        .expect("a 512-bit vector length");
                    ScalableState::new(length, sme2)
                });
            }
        }
    }

    /// SVCR: PSTATE.SM at bit 0 and PSTATE.ZA at bit 1.
    pub fn svcr(&self) -> u64 {
        self.scalable.as_ref().map_or(0, |scalable| {
            let mode = scalable.mode();
            u64::from(mode.streaming()) | u64::from(mode.za_enabled()) << 1
        })
    }

    /// Arm `SetPSTATE_SM`, then `SetPSTATE_ZA`: a change of SM resets the
    /// Z, P and FFR registers, FPSR (to 0x0800009F) and FPMR, and enabling
    /// ZA zeroes ZA and ZT0. The engine applies the access checks streaming
    /// mode changes to each instruction ([`super::streaming`]).
    pub fn set_svcr(&mut self, streaming: bool, za: bool) -> Result<(), &'static str> {
        let scalable = self
            .scalable
            .as_mut()
            .ok_or("SVCR on a PE without SME state")?;
        scalable
            .apply_mode(&mut self.state, ScalableMode::new(streaming, za))
            .map_err(|_| "cannot allocate the SME register state")
    }

    /// The EL an FP/SIMD access traps to, if it traps (Arm
    /// `AArch64_CheckFPEnabled`): CPACR_EL1.FPEN at EL0 and EL1 outside the
    /// host, then CPTR_EL2.FPEN, which has the CPACR layout because HCR_EL2.E2H
    /// is RES1.
    pub fn floating_point_trap(&self) -> Option<u8> {
        let el = self.pstate.el;
        let in_host = el == 2 || (el == 0 && self.in_host());
        if el != 2 && !in_host {
            match self.field(Register::CPACR_EL1, FPEN, 2) {
                0b11 => {}
                0b01 if el != 0 => {}
                _ => return Some(1),
            }
        }
        match self.field(Register::CPTR_EL2, FPEN, 2) {
            0b11 => None,
            0b01 if !(el == 0 && self.in_host()) => None,
            _ => Some(2),
        }
    }

    /// Arm `CheckSMEAccess` without EL3: the EL an SME access trap is taken
    /// to, if CPACR_EL1.SMEN (at EL0 and EL1 outside the host) or
    /// CPTR_EL2.SMEN (E2H being RES1) disables it.
    pub fn sme_access_trap(&self) -> Option<u8> {
        let el = self.pstate.el;
        if el <= 1 && !self.in_host() {
            let smen = self.field(Register::CPACR_EL1, CPACR_SMEN, 2);
            if smen & 1 == 0 || (smen == 0b01 && el == 0) {
                return Some(1);
            }
        }
        let smen = self.field(Register::CPTR_EL2, CPTR_SMEN, 2);
        if smen & 1 == 0 || (smen == 0b01 && el == 0 && self.in_host()) {
            return Some(2);
        }
        None
    }

    pub fn read(&self, register: Register) -> u64 {
        self.registers.get(register, 0)
    }

    pub fn field(&self, register: Register, low: u32, width: u32) -> u64 {
        bits(self.read(register), u64::from(low), u64::from(width))
    }

    pub fn hcr(&self, bit: u32) -> bool {
        self.field(Register::HCR_EL2, bit, 1) == 1
    }

    /// Arm `EffectiveHCR_EL2_NVx` (`helpers::effective_nvx`): '000' on a chip
    /// without FEAT_NV.
    pub fn nested(&self) -> u64 {
        effective_nvx(
            self.read(Register::HCR_EL2),
            self.registers.has(Feature::FEAT_NV),
            self.registers.has(Feature::FEAT_NV2),
        )
    }

    fn bank_sp(&mut self, which: Stack) -> &mut u64 {
        match which {
            Stack::Guarded(level) => &mut self.apple.guarded[level].sp,
            Stack::El0 | Stack::El1 | Stack::El2 => unreachable!("SP_ELx live in the file"),
        }
    }

    fn sp_register(which: Stack) -> Option<Register> {
        match which {
            Stack::El0 => Some(Register::SP_EL0),
            Stack::El1 => Some(Register::SP_EL1),
            Stack::El2 => Some(Register::SP_EL2),
            Stack::Guarded(_) => None,
        }
    }

    fn store_sp(&mut self, which: Stack, value: u64) {
        match Self::sp_register(which) {
            Some(register) => self.registers.set_raw(register, 0, value),
            None => *self.bank_sp(which) = value,
        }
    }

    fn load_sp(&mut self, which: Stack) -> u64 {
        match Self::sp_register(which) {
            Some(register) => self.registers.get(register, 0),
            None => *self.bank_sp(which),
        }
    }

    /// Switch PSTATE, moving the current stack pointer to its bank and
    /// loading the newly selected one.
    pub fn set_pstate(&mut self, next: Pstate) {
        let (was, will) = (stack(self.pstate), stack(next));
        if was != will {
            let current = self.state.sp;
            self.store_sp(was, current);
            self.state.sp = self.load_sp(will);
        }
        self.pstate = next;
    }

    /// A banked stack pointer, current or not.
    pub fn sp(&self, el: u8) -> u64 {
        let which = match el {
            0 => Stack::El0,
            1 => Stack::El1,
            _ => Stack::El2,
        };
        if stack(self.pstate) == which {
            self.state.sp
        } else {
            Self::sp_register(which).map_or(0, |register| self.registers.get(register, 0))
        }
    }

    pub fn set_sp(&mut self, el: u8, value: u64) {
        let which = match el {
            0 => Stack::El0,
            1 => Stack::El1,
            _ => Stack::El2,
        };
        if stack(self.pstate) == which {
            self.state.sp = value;
        } else {
            self.store_sp(which, value);
        }
    }

    /// HCR_EL2.TGE: EL0 runs in the EL2&0 host regime.
    pub fn in_host(&self) -> bool {
        self.hcr(HCR_TGE)
    }

    /// What the vGIC's accessors read of this PE for an MRS or, with
    /// `write`, an MSR: with FEAT_FGT, HFGRTR_EL2 or HFGWTR_EL2's
    /// ICC_IGRPENn_EL1 trap.
    pub fn vgic_context(&self, write: bool) -> super::vgic::Context {
        const HFGXTR_ICC_IGRPENN: u32 = 39;
        let fine_grained = if write {
            Register::HFGWTR_EL2
        } else {
            Register::HFGRTR_EL2
        };
        super::vgic::Context {
            el: self.pstate.el,
            hcr: self.read(Register::HCR_EL2),
            nested: self.nested() & 1 != 0,
            fine_grained_trap: self.registers.implemented(Feature::FEAT_FGT) == Ok(true)
                && self.field(fine_grained, HFGXTR_ICC_IGRPENN, 1) == 1,
        }
    }

    /// A virtual IRQ (`HCR_VI`) or FIQ (`HCR_VF`) pending for EL1 and EL0:
    /// the HCR_EL2 bit, or the vGIC CPU interface's signal, which Arm ORs
    /// with it. A virtual SError (`HCR_VSE`) has only its bit.
    pub fn virtual_pending(&self, virtual_bit: u32) -> bool {
        let signals = self.vgic.signals();
        self.hcr(virtual_bit)
            || match virtual_bit {
                HCR_VI => signals.irq,
                HCR_VF => signals.fiq,
                _ => false,
            }
    }

    /// Arm `IsPACMEnabled` for the current PSTATE: PACM sets PSTATE.PACM
    /// only on a chip with FEAT_PAuth_LR, with HCRX_EL2.PACMEn set for EL0
    /// and EL1 outside the host, and with the regime's SCTLR2_ELx.EnPACM
    /// (EnPACM0 at EL0), SCTLR2_EL1 counting only under HCRX_EL2.SCTLR2En
    /// (`IsSCTLR2EL1Enabled`; EL2 is always enabled and there is no EL3).
    /// The PE's PACM is not trivial.
    pub fn pacm_enabled(&self) -> bool {
        const HCRX_SCTLR2EN: u32 = 15;
        const HCRX_PACMEN: u32 = 24;
        const SCTLR2_ENPACM: u32 = 7;
        const SCTLR2_ENPACM0: u32 = 8;
        if !self.registers.has(Feature::FEAT_PAuth_LR) {
            return false;
        }
        let hcrx = |bit| bits(self.read(Register::HCRX_EL2), u64::from(bit), 1) == 1;
        let el = self.pstate.el;
        let host = self.in_host();
        if el < 2 && !host && !hcrx(HCRX_PACMEN) {
            return false;
        }
        let sctlr2 = |register, bit: u32| bits(self.read(register), u64::from(bit), 1) == 1;
        let el1 = |bit| hcrx(HCRX_SCTLR2EN) && sctlr2(Register::SCTLR2_EL1, bit);
        match el {
            2 => sctlr2(Register::SCTLR2_EL2, SCTLR2_ENPACM),
            1 => el1(SCTLR2_ENPACM),
            _ if host => sctlr2(Register::SCTLR2_EL2, SCTLR2_ENPACM0),
            _ => el1(SCTLR2_ENPACM0),
        }
    }

    /// The regime the current PSTATE translates in.
    pub fn regime(&self) -> TranslationRegime {
        if self.pstate.el == 2 || (self.pstate.el == 0 && self.in_host()) {
            TranslationRegime::El20
        } else {
            TranslationRegime::El10
        }
    }

    /// SCTLR_ELx of the current regime, without the rest of [`Self::controls`].
    pub fn regime_sctlr(&self) -> u64 {
        self.read(match self.regime() {
            TranslationRegime::El10 => Register::SCTLR_EL1,
            TranslationRegime::El20 => Register::SCTLR_EL2,
        })
    }

    /// TCR_ELx of the current regime, without the rest of [`Self::controls`].
    pub fn regime_tcr(&self) -> u64 {
        self.read(match self.regime() {
            TranslationRegime::El10 => Register::TCR_EL1,
            TranslationRegime::El20 => Register::TCR_EL2,
        })
    }

    /// The PE has FEAT_MTE: exception entry sets PSTATE.TCO, and return
    /// restores it.
    pub fn mte(&self) -> bool {
        self.registers.has(Feature::FEAT_MTE)
    }

    /// SCTLR_ELx of `el`'s translation regime: SCTLR_EL2 at EL2 and at EL0
    /// in the host.
    fn sctlr_of(&self, el: u8) -> u64 {
        self.read(if el == 2 || el == 0 && self.in_host() {
            Register::SCTLR_EL2
        } else {
            Register::SCTLR_EL1
        })
    }

    /// Arm `IsMTEEnabled(el)`: the chip implements FEAT_MTE2, HCR_EL2.ATA
    /// is set for EL0 and EL1 outside the host, and SCTLR_ELx.ATA (ATA0 for
    /// EL0) of `el`'s regime enables Allocation Tag access.
    pub fn allocation_tags(&self, el: u8) -> bool {
        if self.registers.implemented(Feature::FEAT_MTE2) != Ok(true) {
            return false;
        }
        if el < 2 && !self.in_host() && !self.hcr(HCR_ATA) {
            return false;
        }
        let enable = if el == 0 { SCTLR_ATA0 } else { SCTLR_ATA };
        self.sctlr_of(el) >> enable & 1 != 0
    }

    /// Whether a tag-checked data access by `el` to `address` takes a
    /// synchronous Tag Check fault on a mismatch (Arm
    /// `AArch64_AccessIsTagChecked` and `AArch64_EffectiveTCF`): Allocation
    /// Tag access is enabled at `el`, PSTATE.TCO is clear, SCTLR_ELx.TCF
    /// (TCF0 for EL0) is 0b01, and the current regime has TBI for the
    /// address's half without a TCMA match (bits 59:55 all clear or all
    /// set). Without FEAT_MTE_ASYNC and FEAT_MTE_ASYM_FAULT, TCF 0b10 leaves
    /// a mismatch without effect, as the reserved 0b11 does too
    /// (Unpredictable_RESTCF: Stela takes 0b00).
    pub fn tag_checked(&self, el: u8, address: u64) -> bool {
        if !self.allocation_tags(el) || self.pstate.tco {
            return false;
        }
        let shift = if el == 0 { SCTLR_TCF0 } else { SCTLR_TCF };
        if self.sctlr_of(el) >> shift & 0b11 != TCF_SYNC {
            return false;
        }
        let tcr = self.regime_tcr();
        let (tbi, tcma) = if address & (1 << 55) != 0 {
            (TCR_TBI1, TCR_TCMA1)
        } else {
            (TCR_TBI0, TCR_TCMA0)
        };
        let top = address >> 55 & 0x1f;
        tcr & tbi != 0 && !(tcr & tcma != 0 && (top == 0 || top == 0x1f))
    }

    /// For each half of the current regime, lower then upper, whether the
    /// current EL's tag-checked accesses through untagged pointers (logical
    /// tag 0 below, 0xf above) are checked: the shadow tables then keep
    /// Tagged memory of that half out (`engine::Regime::tag_checks`).
    pub fn tag_checks(&self) -> [bool; 2] {
        [0, u64::MAX].map(|address| self.tag_checked(self.pstate.el, address))
    }

    /// Translation controls of a regime: its stage-1 registers and, for
    /// EL1&0, the stage-2 registers that `mmu` applies under HCR_EL2.VM or DC.
    pub fn controls(&self, regime: TranslationRegime) -> Controls {
        let (sctlr, tcr, ttbr0, ttbr1, mair, kernel, user) = match regime {
            TranslationRegime::El10 => (
                Register::SCTLR_EL1,
                Register::TCR_EL1,
                Register::TTBR0_EL1,
                Register::TTBR1_EL1,
                Register::MAIR_EL1,
                PERM_EL1,
                PERM_EL0_10,
            ),
            TranslationRegime::El20 => (
                Register::SCTLR_EL2,
                Register::TCR_EL2,
                Register::TTBR0_EL2,
                Register::TTBR1_EL2,
                Register::MAIR_EL2,
                PERM_EL2,
                PERM_EL0_20,
            ),
        };
        Controls {
            sctlr: self.read(sctlr),
            tcr: self.read(tcr),
            ttbr0: self.read(ttbr0),
            ttbr1: self.read(ttbr1),
            mair: self.read(mair),
            xs: self.registers.has(Feature::FEAT_XS),
            tagged: self.registers.has(Feature::FEAT_MTE2),
            sprr: Sprr {
                config: self.apple.sprr_config,
                el1: self.apple.sprr_perm[kernel],
                el0: self.apple.sprr_perm[user],
                fields: self.apple.sprr_fields,
            },
            ctrr: mmu::Ctrr {
                privileged: super::ctrr::protection(
                    self.registers.chip(),
                    &self.ctrr.borrow(),
                    &self.ctrr_core,
                    regime == TranslationRegime::El20,
                    self.read(sctlr) & mmu::SCTLR_M != 0,
                ),
                memory: self.memory_lock,
            },
            stage2: self.stage2(regime),
            second_stage: (regime == TranslationRegime::El10).then(|| mmu::Stage2 {
                hcr: self.read(Register::HCR_EL2),
                vtcr: self.read(Register::VTCR_EL2),
                vttbr: self.read(Register::VTTBR_EL2),
                xs: self.registers.has(Feature::FEAT_XS),
            }),
            regime: match regime {
                TranslationRegime::El10 => mmu::Regime::El10,
                TranslationRegime::El20 => mmu::Regime::El20,
            },
        }
    }

    /// Whether the EL1&0 regime translates through stage 2.
    pub fn stage2(&self, regime: TranslationRegime) -> bool {
        regime == TranslationRegime::El10 && self.hcr(HCR_VM)
    }

    /// GXF is usable when both SPRR and the current EL's GXF are enabled
    /// (m1n1 `gxf.c` `gxf_enabled`).
    pub fn guarded_enabled(&self) -> bool {
        let level = usize::from(self.pstate.el.max(1)) - 1;
        self.apple.sprr_config & mmu::SPRR_CONFIG_EN != 0
            && self.apple.gxf_config[level] & GXF_CONFIG_EN != 0
    }

    /// GENTER at EL1 or EL2, or at GL1 or GL2: bank the return state and
    /// `immediate` in that GL's registers and continue at GXF_ENTER_ELx on
    /// the GL stack with every exception masked (m1n1 `hv_sprr.c`
    /// `hv_gxf_genter`: SPSR and ELR from the link state, ESR_GL1
    /// 0xfe010000 | imm, DAIF set, EL1h). From a GL it stays guarded and
    /// sets ASPSR bit 0, so GEXIT returns to the GL ("genter from GL is
    /// weird but allowed"); the outer return state in the bank is replaced.
    /// m1n1 is an emulator, so this is evidence, not silicon proof. SPTM
    /// 26A434 needs IRQ and FIQ masked: the kernel enters with them unmasked
    /// and SPTM's GL2 SP_ELx interrupt vectors park (`__exc+0x280`).
    pub fn guarded_enter(&mut self, immediate: u8) -> Result<(), GuardedRefusal> {
        if self.pstate.el == 0 || !self.guarded_enabled() {
            return Err(GuardedRefusal::Enter);
        }
        // GENTER completes, returning to the next instruction, so the saved
        // state and the guarded level both start with BTYPE clear.
        let from = Pstate {
            btype: 0,
            ..self.pstate
        };
        let level = usize::from(from.el) - 1;
        let spsr = from.to_spsr(self.state.nzcv);
        let bank = &mut self.apple.guarded[level];
        bank.spsr = spsr;
        bank.elr = self.pc.wrapping_add(4);
        bank.esr = exception::syndrome(
            Class::ImplementationDefined,
            GENTER_ISS | u32::from(immediate & 0x1f),
        );
        bank.aspsr = if from.guarded { ASPSR_GUARDED } else { 0 };
        let enter = bank.enter;
        self.set_pstate(Pstate {
            sp: true,
            daif: exception::DAIF_ALL,
            guarded: true,
            ..from
        });
        self.pc = enter;
        Ok(())
    }

    /// GEXIT at GL1 or GL2: restore PSTATE from SPSR_GLx and continue at
    /// ELR_GLx, guarded when ASPSR_GLx says so.
    pub fn guarded_exit(&mut self) -> Result<Result<(), IllegalReturn>, GuardedRefusal> {
        if !self.pstate.guarded || self.pstate.el == 0 {
            return Err(GuardedRefusal::Exit);
        }
        let level = usize::from(self.pstate.el) - 1;
        let bank = &self.apple.guarded[level];
        let (spsr, elr, aspsr) = (bank.spsr, bank.elr, bank.aspsr);
        if let Some(illegal) = self.illegal_return(spsr) {
            return Ok(Err(illegal));
        }
        let (mut next, nzcv) = exception::restore(self.pstate, spsr, false, self.mte());
        next.guarded = aspsr & ASPSR_GUARDED != 0;
        // GL0 is reachable from a guarded level: SPTM 26A434 resumes saved
        // contexts with their ASPSR_GL (`__text+0x44e0`), TXM's at GL0
        // among them. A guarded return to another level stops.
        if next.guarded && next.el != self.pstate.el && next.el != 0 {
            return Ok(Err(IllegalReturn::Mode(0)));
        }
        self.state.nzcv = nzcv;
        self.set_pstate(next);
        self.pstate.pacm &= self.pacm_enabled();
        self.pc = elr;
        Ok(Ok(()))
    }

    pub fn requester(&self) -> mmu::Requester {
        mmu::Requester {
            el: self.pstate.el,
            pan: self.pstate.pan,
            unprivileged: false,
            guarded: self.pstate.guarded,
        }
    }

    /// The EL an exception targeting EL1 by default is taken to.
    pub fn route(&self) -> u8 {
        match self.pstate.el {
            2 => 2,
            0 if self.in_host() => 2,
            _ => 1,
        }
    }

    /// The EL a physical interrupt is routed to (Arm
    /// `AArch64_TakePhysicalIRQException` and FIQ): EL2 from EL2, or from EL0
    /// and EL1 with HCR_EL2.TGE or the IMO/FMO routing bit.
    pub fn interrupt_target(&self, vector: Vector) -> u8 {
        let routing = match vector {
            Vector::Irq => HCR_IMO,
            Vector::Fiq => HCR_FMO,
            _ => HCR_AMO,
        };
        if self.pstate.el == 2 || self.in_host() || self.hcr(routing) {
            2
        } else {
            1
        }
    }

    /// The guarded level GL0 takes its exceptions to: GL2 while EL2's GXF is
    /// enabled, else GL1. SPTM 26A434 enters TXM at GL0 with HCR_EL2.TGE set
    /// (`__text+0xb0c0`) and handles its SVCs in VBAR_GL2's lower-EL vector
    /// (`__exc+0x400`, reading ESR_GL), with EL1's GXF disabled; the GL1 case
    /// has no public description (inference).
    fn guarded_el0_target(&self) -> u8 {
        if self.apple.gxf_config[1] & GXF_CONFIG_EN != 0 {
            2
        } else {
            1
        }
    }

    /// Take an exception and continue at its vector. At a guarded level it
    /// stays guarded, through VBAR_GLx and the GL bank; GL0 enters the
    /// guarded level that owns it.
    pub fn take(&mut self, exception: Exception) {
        let from = self.pstate;
        let mut target = exception.target.unwrap_or_else(|| self.route());
        if from.guarded && from.el == 0 {
            target = self.guarded_el0_target();
        }
        if from.guarded && (target == from.el || from.el == 0) {
            let level = usize::from(target) - 1;
            let spsr = from.to_spsr(self.state.nzcv);
            let bank = &mut self.apple.guarded[level];
            bank.spsr = spsr;
            bank.elr = exception.return_address;
            bank.aspsr = ASPSR_GUARDED;
            if exception.vector == Vector::Synchronous {
                bank.esr = exception.syndrome;
            }
            if let Some(address) = exception.fault_address {
                bank.far = address;
            }
            let vbar = bank.vbar;
            let sctlr = self.read(bank_sctlr(target));
            let entry = exception::entry_pstate(from, sctlr, target, self.in_host(), self.mte());
            self.set_pstate(Pstate {
                guarded: true,
                ..entry
            });
            self.pc = vbar.wrapping_add(exception::vector_offset(from, target, exception.vector));
            return;
        }
        let bank = bank(target);
        let mut spsr = from.to_spsr(self.state.nzcv);
        // From EL1 to EL1 under HCR_EL2.NV (with NV1 RAZ, NVx 'x01'),
        // SPSR_EL1.M[3:2] records EL2, the level the guest hypervisor
        // believes it runs at (Arm `AArch64_TakeException`).
        if from.el == 1 && target == 1 && self.nested() & 0b011 == 0b001 {
            spsr = spsr & !0b1100 | 0b1000;
        }
        self.registers.set_raw(bank.spsr, 0, spsr);
        self.registers
            .set_raw(bank.elr, 0, exception.return_address);
        if exception.vector == Vector::Synchronous || exception.vector == Vector::SError {
            self.registers.set_raw(bank.esr, 0, exception.syndrome);
        }
        if let Some(address) = exception.fault_address {
            self.registers.set_raw(bank.far, 0, address);
        }
        let sctlr = self.read(bank.sctlr);
        self.set_pstate(Pstate {
            guarded: false,
            ..exception::entry_pstate(from, sctlr, target, self.in_host(), self.mte())
        });
        let vbar = self.read(bank.vbar) & !0x7ff;
        self.pc = vbar.wrapping_add(exception::vector_offset(from, target, exception.vector));
    }

    /// Why a return from the current EL to `spsr` is illegal, if it is
    /// (Arm `IllegalExceptionReturn`): an invalid or AArch32 mode, a higher
    /// EL, or EL1 while HCR_EL2.TGE is set.
    pub fn illegal_return(&self, spsr: u64) -> Option<IllegalReturn> {
        match exception::spsr_target(spsr) {
            Err(illegal) => Some(illegal),
            Ok((el, _)) if el > self.pstate.el => Some(IllegalReturn::Mode(el << 2)),
            Ok((1, _)) if self.hcr(HCR_TGE) => Some(IllegalReturn::Host),
            Ok(_) => None,
        }
    }

    /// ELR_ELx of the current EL, or ELR_GLx at a guarded level.
    pub fn exception_link(&self) -> u64 {
        match self.pstate.guarded {
            true => self.apple.guarded[usize::from(self.pstate.el) - 1].elr,
            false => self.read(bank(self.pstate.el).elr),
        }
    }

    /// SPSR_ELx of the current EL, or SPSR_GLx at a guarded level.
    pub(crate) fn exception_state(&self) -> u64 {
        match self.pstate.guarded {
            true => self.apple.guarded[usize::from(self.pstate.el) - 1].spsr,
            false => self.read(bank(self.pstate.el).spsr),
        }
    }

    /// An instruction address with its tag removed for the current EL (Arm
    /// `AArch64_BranchAddr`): with TBI and not TBID for the half that bit 55
    /// selects, bits 63:56 copy bit 55. Every EL here uses two VA ranges
    /// (EL1&0, or EL2&0 because HCR_EL2.E2H is RES1), so the address is sign
    /// extended.
    pub fn branch_address(&self, address: u64) -> u64 {
        let tcr = self.controls(self.regime()).tcr;
        let (tbi, tbid) = if address & (1 << 55) != 0 {
            (38, 52)
        } else {
            (37, 51)
        };
        if tcr & (1 << tbi) != 0 && tcr & (1 << tbid) == 0 {
            exception::sign_extend_55(address)
        } else {
            address
        }
    }

    /// ERET, ERETAA or ERETAB from EL1 or EL2 to `target`, the current ELR
    /// after any authentication (Arm `AArch64_ExceptionReturn`). An illegal
    /// return sets PSTATE.IL instead of changing EL; after one to AArch32 the
    /// ARBITRARY PC bits 63:32 and 1:0 read 0. EL0 ERET is UNDEFINED and must
    /// not reach here.
    ///
    /// At a guarded level ERET returns through SPSR_GLx and ELR_GLx and stays
    /// guarded: SPTM 26A434 enters TXM at GL0 that way (`__text+0x2b1c`,
    /// SPSR_GL M=EL0t), and leaves for unguarded code only through GEXIT
    /// with ASPSR_GL bit 0 clear (inference; no public description).
    pub fn exception_return(
        &mut self,
        target: u64,
    ) -> Result<(), stela_compiler::context::memory::MemoryStatus> {
        // Preflight/clear before any architectural CPU effect. A failed domain
        // cannot appear to complete ERET with a stale local reservation.
        self.clear_exclusive()?;
        let guarded = self.pstate.guarded;
        let spsr = self.exception_state();
        let illegal = self.illegal_return(spsr).is_some();
        let destination = match exception::spsr_target(spsr) {
            Ok((el, _)) if !illegal => el,
            _ => self.pstate.el,
        };
        let ss = super::debug::return_ss(self, spsr, destination);
        let (mut next, nzcv) = exception::restore(self.pstate, spsr, illegal, self.mte());
        next.ss = ss;
        next.guarded = guarded;
        self.step_advance = false;
        self.state.nzcv = nzcv;
        self.set_pstate(next);
        // SetPSTATEFromPSR: IsPACMEnabled at the EL returned to.
        self.pstate.pacm &= self.pacm_enabled();
        self.pc = if illegal && spsr & (1 << 4) != 0 {
            target & 0xffff_fffc
        } else {
            self.branch_address(target)
        };
        // ERET clears the local exclusive monitor and sets the event register.
        self.signal_event();
        Ok(())
    }
}

fn bank_sctlr(el: u8) -> Register {
    bank(el).sctlr
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::exception::{DAIF_ALL, DAIF_I};

    const HCR_E2H_TGE: u64 = 1 << 34 | 1 << 27;

    #[test]
    fn exception_entry_and_return_bank_stack_pointers() {
        let user = Pstate {
            el: 0,
            sp: false,
            daif: 0,
            ..Pstate::reset(1)
        };
        let mut cpu = Cpu::new(0x4000, user);
        cpu.state.sp = 0x7000;
        cpu.state.nzcv = 0x6000_0000;
        cpu.registers.set_raw(Register::SP_EL1, 0, 0xffff_0000);
        cpu.registers.set(Register::VBAR_EL1, 0, 0xffff_8000);
        cpu.take(Exception::synchronous(Class::SupervisorCall, 7, 0x4004));
        assert_eq!(cpu.pc, 0xffff_8400);
        assert_eq!(cpu.state.sp, 0xffff_0000);
        assert_eq!(cpu.sp(0), 0x7000);
        assert_eq!(cpu.read(Register::ELR_EL1), 0x4004);
        assert_eq!(cpu.read(Register::SPSR_EL1), 0x6000_0000);
        assert_eq!(cpu.read(Register::ESR_EL1), 0x5600_0007);
        assert_eq!(cpu.pstate.daif, DAIF_ALL);
        assert!(cpu.pstate.pan);
        cpu.state.sp = 0xffff_0100;
        cpu.registers.set(Register::SPSR_EL1, 0, DAIF_I as u64 * 64); // EL0t with IRQs masked
        cpu.exception_return(cpu.exception_link()).unwrap();
        assert_eq!(
            (cpu.pc, cpu.state.sp, cpu.sp(1)),
            (0x4004, 0x7000, 0xffff_0100)
        );
        assert_eq!(cpu.pstate.el, 0);
        assert_eq!(cpu.pstate.daif, DAIF_I);
        assert_eq!(cpu.state.nzcv, 0);
    }

    #[test]
    fn interrupts_from_el1h_use_the_current_el_spx_group() {
        let mut cpu = Cpu::new(0x8000, Pstate::reset(1));
        cpu.registers.set(Register::VBAR_EL1, 0, 0x1_0000);
        cpu.registers.set(Register::ESR_EL1, 0, 0x1234);
        cpu.take(Exception {
            vector: Vector::Fiq,
            syndrome: 0,
            fault_address: None,
            return_address: 0x8000,
            target: Some(1),
        });
        assert_eq!(cpu.pc, 0x1_0300);
        assert_eq!(
            cpu.read(Register::ESR_EL1),
            0x1234,
            "interrupts leave ESR unchanged"
        );
    }

    #[test]
    fn routing_follows_tge_and_el2_uses_its_own_registers() {
        let mut cpu = Cpu::new(0x8000, Pstate::reset(2));
        cpu.registers.set(Register::HCR_EL2, 0, HCR_E2H_TGE);
        cpu.registers.set(Register::VBAR_EL2, 0, 0x1_0000);
        cpu.state.sp = 0xa000;
        cpu.take(Exception::synchronous(Class::HypervisorCall, 3, 0x8004).to(2));
        assert_eq!((cpu.pc, cpu.pstate.el), (0x1_0200, 2));
        assert_eq!(cpu.read(Register::SPSR_EL2) & 0xf, 0b1001, "EL2h");
        assert_eq!(cpu.read(Register::ESR_EL2), 0x5a00_0003);
        cpu.exception_return(cpu.exception_link()).unwrap();
        assert_eq!((cpu.pc, cpu.pstate.el), (0x8004, 2));
        // EL0 in the host: exceptions go to EL2.
        cpu.registers.set(Register::SPSR_EL2, 0, 0);
        cpu.exception_return(cpu.exception_link()).unwrap();
        assert_eq!((cpu.pstate.el, cpu.regime()), (0, TranslationRegime::El20));
        cpu.take(Exception::synchronous(Class::SupervisorCall, 0, 0x8008));
        assert_eq!((cpu.pc, cpu.pstate.el), (0x1_0400, 2));
        // A return to EL1 under TGE is illegal: EL2 stays and sets IL.
        cpu.registers.set(Register::SPSR_EL2, 0, 0b0101);
        assert_eq!(cpu.illegal_return(0b0101), Some(IllegalReturn::Host));
        cpu.exception_return(0x9000).unwrap();
        assert_eq!((cpu.pc, cpu.pstate.el, cpu.pstate.il), (0x9000, 2, true));
        // Without TGE it enters a guest.
        cpu.registers.set(Register::HCR_EL2, 0, 0);
        cpu.exception_return(cpu.exception_link()).unwrap();
        assert!(!cpu.pstate.il);
        assert_eq!((cpu.pstate.el, cpu.regime()), (1, TranslationRegime::El10));
        assert_eq!(cpu.route(), 1);
        assert_eq!(cpu.interrupt_target(Vector::Irq), 1);
        cpu.registers.set(Register::HCR_EL2, 0, 1 << HCR_IMO);
        assert_eq!(cpu.interrupt_target(Vector::Irq), 2);
    }
}
