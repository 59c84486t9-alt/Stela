//! System-mode engine lane: run a case's words on `stela_runtime::machine` at
//! EL0 under the harness's EL1 controls, so exception outcomes (ESR, ELR, FAR)
//! compare with QEMU as well as completions. EL1 cases run at EL1t with every
//! exception masked until their first exception, as the harness runs them:
//! the zero words after the case are UDF, and SPSR then holds PSTATE.
//!
//! The engine translates through a copy of the harness's own tables
//! (`build_tables` in `harness.S`), so instruction fetch, AT, cache
//! maintenance and their faults walk what QEMU walks. Every SCTLR_EL1 trap
//! control the harness clears (nTWI, nTWE, UCI, UCT, DZE, UMA) is clear here
//! too, CPACR_EL1 enables FP/SIMD, and the CPU profile is the engine's M2
//! identification without EL2, like the harness's QEMU machine.
//!
//! A case with [`Case::hypervisor`] mirrors the `virtualization=on` harness
//! instead: the M2 identification with EL2, the harness's HCR_EL2 with the
//! case's additions, its VTCR_EL2 and VTTBR_EL2, and a copy of its stage-2
//! tables with the case's descriptors. Exceptions are then read from the EL
//! they were taken to, with HPFAR_EL2 at EL2, and level-2 cases run at EL2t.
use super::{
    CODE_PAGE, CODE_REGION, CODE_REGION_BYTES, Case, DATA_BYTES, DATA_WINDOW, Exception, HCR_BASE,
    Hypervisor, Outcome, STAGE2_NORMAL,
    native::{Executable, windows},
};
use anyhow::{Result, bail};
use stela_compiler::{GuestState, TargetCpu};
use stela_runtime::hosted::host::{HostFault, NativeRunner};
use stela_runtime::machine::{
    Chip, Cpu, FaultCause, Host, InstallError, Machine, NativeCode, NativeExit, NoDevices, Regime,
    Stop,
    cpu::HCR_HCD,
    exception::Pstate,
    identification,
    mmu::{self, Access, Outcome as Translated, TableMemory},
    registers::{
        CpuProfile,
        encodings::{DCZID_EL0, MIDR_EL1, MPIDR_EL1},
    },
    system::Register,
};

/// The harness's SCTLR_EL1: MMU and caches on, every EL0 trap control clear.
const SCTLR_VALUE: u64 = 0x30d0_0801 | (1 << 2) | (1 << 12) | (1 << 42) | (1 << 60);
/// The harness's TCR_EL1: T0SZ=25, 4 KiB granule, TTBR1 walks off, 48-bit PA.
const TCR_VALUE: u64 = 25 | (1 << 8) | (1 << 10) | (3 << 12) | (1 << 23) | (5 << 32);
/// MAIR_EL1 attribute 0: Normal write-back.
const MAIR_VALUE: u64 = 0xff;
/// CPACR_EL1.FPEN = 0b11.
const CPACR_FP: u64 = 3 << 20;
/// DCZID_EL0 of the Apple profile: 64-byte blocks.
const DCZID: u64 = 4;
const VECTOR_BASE: u64 = 0;
/// MDSCR_EL1.SS, which the harness sets for stepping EL0 cases.
const MDSCR_SS: u64 = 1;
/// SPSR_EL1 the harness's ERET consumed: EL1t or EL0t with DAIF masked.
const SPSR_EL1T_MASKED: u64 = 0x3c4;
/// SPSR_EL2 of the EL2 harness's entry to an EL2 case: EL2t, DAIF masked.
const SPSR_EL2T_MASKED: u64 = 0x3c8;
const SPSR_EL0T_STEPPED: u64 = 0x3c0 | 1 << 21;
/// ESR_EL1 of UDF #0: EC 0 with IL set.
const UDF_SYNDROME: u64 = 1 << 25;

// The harness's translation tables and the memory they map.
const RAM: u64 = 0x4000_0000;
const L1_TABLE: u64 = 0x4011_0000;
const L2_TABLE: u64 = 0x4011_1000;
const L3_DATA: u64 = 0x4011_3000;
const L2_CASE_TABLE: u64 = 0x4011_4000;
// The EL2 harness's stage-2 tables (`build_stage2`).
const S2_L1_TABLE: u64 = 0x4012_0000;
const S2_L2_RAM: u64 = 0x4012_1000;
const S2_L3_HARNESS: u64 = 0x4012_2000;
const S2_L2_CASE: u64 = 0x4012_3000;
const S2_L3_DATA: u64 = 0x4012_4000;
/// Both stages' tables, from `L1_TABLE` to the end of `S2_L3_DATA`.
const TABLE_BYTES: usize = 0x1_5000;
/// The EL2 harness's controls: VTCR_EL2 (T0SZ=25 from level 1, 4 KiB,
/// 48-bit PA), SCTLR_EL2 (EL2&0 MMU off, caches on, TSCXT clear) and the E2H
/// layouts of CPTR_EL2 and CNTHCTL_EL2 the EL1 lane also uses.
const VTCR_VALUE: u64 = 25 | (1 << 6) | (1 << 8) | (1 << 10) | (3 << 12) | (5 << 16) | (1 << 31);
const SCTLR_EL2_VALUE: u64 = 0x30c0_0800 | (1 << 2) | (1 << 12);
const CASE_REGION: u64 = 0x2_0000_0000;
const CODE_ALIAS: u64 = 0x2_0040_0000;
const L2_ENTRIES: u64 = 512;
const BLOCK_1G: u64 = 0x4000_0000;
const BLOCK_2M: u64 = 0x20_0000;
const PAGE_BYTES: u64 = 0x1000;
const DESC_TABLE: u64 = 3;
const DESC_BLOCK: u64 = 1;
const DESC_PAGE: u64 = 3;
/// AF, Inner Shareable, AttrIndx 0.
const DESC_NORMAL: u64 = (1 << 10) | (3 << 8);
const DESC_EL0_RW: u64 = 1 << 6;
const DESC_READ_ONLY: u64 = 3 << 6;
const DESC_PXN: u64 = 1 << 53;
const DESC_UXN: u64 = 1 << 54;

/// The descriptors `build_tables` writes, as bytes from `L1_TABLE`, and
/// under a hypervisor those of `build_stage2` with the case's descriptors.
fn harness_tables(hypervisor: Option<&Hypervisor>) -> Vec<u8> {
    let mut tables = vec![0u8; TABLE_BYTES];
    let mut set = |address: u64, descriptor: u64| {
        let offset = (address - L1_TABLE) as usize;
        tables[offset..offset + 8].copy_from_slice(&descriptor.to_le_bytes());
    };
    set(L1_TABLE + RAM / BLOCK_1G * 8, L2_TABLE | DESC_TABLE);
    set(
        L1_TABLE + CASE_REGION / BLOCK_1G * 8,
        L2_CASE_TABLE | DESC_TABLE,
    );
    for entry in 0..L2_ENTRIES {
        let block = RAM + entry * BLOCK_2M;
        set(
            L2_TABLE + entry * 8,
            block | DESC_NORMAL | DESC_BLOCK | DESC_UXN,
        );
    }
    let case = |address: u64| L2_CASE_TABLE + (address - CASE_REGION) / BLOCK_2M * 8;
    set(
        case(CASE_REGION),
        CASE_REGION | DESC_NORMAL | DESC_BLOCK | DESC_READ_ONLY | DESC_PXN | DESC_UXN,
    );
    set(
        case(CODE_PAGE),
        CODE_PAGE | DESC_NORMAL | DESC_BLOCK | DESC_READ_ONLY,
    );
    set(
        case(CODE_ALIAS),
        CODE_PAGE | DESC_NORMAL | DESC_BLOCK | DESC_PXN | DESC_UXN,
    );
    set(case(DATA_WINDOW), L3_DATA | DESC_TABLE);
    for page in 0..DATA_BYTES as u64 / PAGE_BYTES {
        let address = DATA_WINDOW + page * PAGE_BYTES;
        set(
            L3_DATA + page * 8,
            address | DESC_NORMAL | DESC_PAGE | DESC_EL0_RW | DESC_PXN | DESC_UXN,
        );
    }
    let Some(hypervisor) = hypervisor else {
        return tables;
    };
    set(S2_L1_TABLE + RAM / BLOCK_1G * 8, S2_L2_RAM | DESC_TABLE);
    set(
        S2_L1_TABLE + CASE_REGION / BLOCK_1G * 8,
        S2_L2_CASE | DESC_TABLE,
    );
    set(S2_L2_RAM, S2_L3_HARNESS | DESC_TABLE);
    for entry in 1..L2_ENTRIES {
        let block = RAM + entry * BLOCK_2M;
        set(S2_L2_RAM + entry * 8, block | STAGE2_NORMAL | DESC_BLOCK);
    }
    for entry in 0..L2_ENTRIES {
        let page = RAM + entry * PAGE_BYTES;
        set(S2_L3_HARNESS + entry * 8, page | STAGE2_NORMAL | DESC_PAGE);
    }
    set(
        S2_L3_HARNESS + (L3_DATA - RAM) / PAGE_BYTES * 8,
        hypervisor.table,
    );
    let case = |address: u64| S2_L2_CASE + (address - CASE_REGION) / BLOCK_2M * 8;
    set(case(CASE_REGION), CASE_REGION | STAGE2_NORMAL | DESC_BLOCK);
    set(case(CODE_PAGE), hypervisor.code);
    set(case(DATA_WINDOW), S2_L3_DATA | DESC_TABLE);
    for (page, descriptor) in hypervisor.data.iter().enumerate() {
        set(S2_L3_DATA + page as u64 * 8, *descriptor);
    }
    tables
}

/// Guest RAM is the oracle's code region and data window at their guest
/// addresses; installed native code lives in owned executable mappings.
struct OracleHost {
    code: *const u8,
    data: *mut u8,
    /// The harness's translation tables, read-only.
    tables: Vec<u8>,
    installed: Vec<Executable>,
    runner: NativeRunner,
    /// The translation regime the engine runs under, which classifies a
    /// native page fault.
    regime: Option<Regime>,
}

/// The harness's tables, as the guest's translation walks them.
struct HarnessTables<'a>(&'a mut OracleHost);

impl TableMemory for HarnessTables<'_> {
    fn read_descriptor(&mut self, physical: u64) -> Option<u64> {
        let mut bytes = [0u8; 8];
        self.0
            .read_ram(physical, &mut bytes)
            .then(|| u64::from_le_bytes(bytes))
    }

    fn update_descriptor(&mut self, _: u64, _: u64, _: u64) -> Option<bool> {
        None
    }
}

impl OracleHost {
    /// A native fault's cause: a check's own, or for a page fault what the
    /// guest's translation of the address gives. A page the guest maps but
    /// the host has no memory at is a device access, which the lane has
    /// none of, so the engine refuses it.
    fn cause(&mut self, fault: &HostFault) -> FaultCause {
        if let Some(cause) = fault.check_cause() {
            return cause;
        }
        let Some(regime) = self.regime else {
            return FaultCause::Device {
                physical: fault.address,
            };
        };
        let access = if fault.write {
            Access::Write
        } else {
            Access::Read
        };
        match mmu::translate(
            &regime.controls,
            fault.address,
            access,
            regime.requester,
            &mut HarnessTables(self),
        ) {
            Translated::Fault(fault) => FaultCause::Guest(fault),
            Translated::Unsupported(unsupported) => FaultCause::Translation(unsupported),
            Translated::Mapped(translation) => FaultCause::Device {
                physical: translation.physical,
            },
        }
    }
}

impl OracleHost {
    fn range(&self, physical: u64, bytes: usize) -> Option<(*mut u8, bool)> {
        let end = physical.checked_add(bytes as u64)?;
        if physical >= CODE_REGION && end <= CODE_REGION + CODE_REGION_BYTES as u64 {
            // SAFETY: inside the owned code mapping.
            let pointer = unsafe { self.code.add((physical - CODE_REGION) as usize) };
            return Some((pointer.cast_mut(), false));
        }
        if physical >= DATA_WINDOW && end <= DATA_WINDOW + DATA_BYTES as u64 {
            // SAFETY: inside the owned data mapping.
            let pointer = unsafe { self.data.add((physical - DATA_WINDOW) as usize) };
            return Some((pointer, true));
        }
        if physical >= L1_TABLE && end <= L1_TABLE + TABLE_BYTES as u64 {
            let pointer = self.tables[(physical - L1_TABLE) as usize..].as_ptr();
            return Some((pointer.cast_mut(), false));
        }
        None
    }
}

impl Host for OracleHost {
    fn read_ram(&mut self, physical: u64, buffer: &mut [u8]) -> bool {
        let Some((pointer, _)) = self.range(physical, buffer.len()) else {
            return false;
        };
        // SAFETY: `range` checked the whole span against an owned mapping.
        unsafe { std::ptr::copy_nonoverlapping(pointer, buffer.as_mut_ptr(), buffer.len()) };
        true
    }

    fn write_ram(&mut self, physical: u64, data: &[u8]) -> bool {
        match self.range(physical, data.len()) {
            Some((pointer, true)) => {
                // SAFETY: as for `read_ram`, in the writable data window.
                unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), pointer, data.len()) };
                true
            }
            _ => false,
        }
    }

    fn install(&mut self, code: &[u8]) -> Result<NativeCode, InstallError> {
        let executable = Executable::new(code).map_err(|_| InstallError::Full)?;
        let address = executable.address();
        self.installed.push(executable);
        Ok(NativeCode(address))
    }

    fn patch(&mut self, code: NativeCode, bytes: &[u8]) {
        self.installed
            .iter_mut()
            .find(|executable| executable.contains(code.0))
            .expect("a patch of installed code")
            .patch(code.0, bytes)
            .expect("a writable native mapping");
    }

    fn discard_code(&mut self) {
        self.installed.clear();
    }

    unsafe fn execute(&mut self, code: NativeCode, state: &mut GuestState) -> NativeExit {
        self.runner
            .set_ranges(self.installed.iter().map(Executable::range).collect());
        // SAFETY: the engine passes code it installed for the system-mode
        // block ABI. Its accesses reach the windows, mapped at their guest
        // addresses, or fault, which ends the run at the faulting
        // instruction.
        match unsafe { self.runner.run(code.0, state) } {
            Ok(exit) => NativeExit::Exit {
                next_pc: exit.next_pc,
                kind: exit.kind,
            },
            Err(fault) => {
                let cause = self.cause(&fault);
                NativeExit::Fault(
                    fault.native(fault.rip.wrapping_sub(code.0 as u64) as usize, cause),
                )
            }
        }
    }

    fn context_entry(&mut self, code: NativeCode) -> Option<usize> {
        // Installed code is callable where it lies, in its executable mapping.
        Some(code.0)
    }

    fn set_regime(&mut self, regime: &Regime) {
        self.regime = Some(*regime);
    }

    fn invalidate_translations(&mut self) {}

    fn counter(&mut self) -> u64 {
        0
    }

    fn arm_timer(&mut self, _: Option<u64>) {}

    fn wait_for_interrupt(&mut self) {}
}

const HCR_APK: u32 = 40;
const HCR_API: u32 = 41;
const HCR_FIEN: u32 = 47;
const HCR_ENSCXT: u32 = 53;

/// The engine's M2 profile, with EL2 only when the oracle machine has it.
fn profile(target: TargetCpu, el2: bool) -> CpuProfile {
    // The oracle's host isolates no predictions: no speculation guarantee.
    let mut fixed = identification::derive(
        Chip::DEFAULT,
        target,
        el2,
        identification::Speculation::NONE,
    );
    fixed.push((DCZID_EL0, DCZID));
    // J473AP cpu0's MIDR and MPIDR, as the bundle profile gives them; only
    // the access outcome of an MRS is compared.
    fixed.extend([(MIDR_EL1, 0x611f_0320), (MPIDR_EL1, 0x8000_0000)]);
    CpuProfile {
        chip: Chip::DEFAULT,
        name: if el2 {
            "oracle-m2-el2"
        } else {
            "oracle-m2-el0"
        },
        counter_frequency: 24_000_000,
        fixed,
        processors: Vec::new(),
    }
}

/// Run `case`'s first word at EL0 on the engine and report it as the harness
/// would: registers, SP_EL0, NZCV, the data window and any exception.
///
/// # Safety
/// The case's native memory accesses must reach the windows or fault, as
/// System instructions and the region lane's sequences do.
pub unsafe fn run(case: &Case, target: TargetCpu) -> Result<Outcome> {
    let windows = windows()?.lock().expect("native windows lock");
    // SAFETY: the windows are owned mappings; the code page is installed below.
    unsafe { super::native::install_case(&windows, case)? };
    let hypervisor = case.hypervisor.as_ref();
    let mut pstate = Pstate::reset(case.el);
    // EL1 and EL2 cases run on SP_EL0 (EL1t, EL2t), as the harness keeps
    // SP_EL1 and SP_EL2 for itself.
    pstate.sp = false;
    let mut cpu = Cpu::of(Chip::DEFAULT, CODE_PAGE, pstate);
    cpu.state = case.state.clone();
    // The rest of the EL1 state the harness leaves for the case.
    let nzcv = u64::from(case.state.nzcv) & 0xf000_0000;
    let spsr = nzcv
        | if case.el != 0 {
            SPSR_EL1T_MASKED
        } else {
            SPSR_EL0T_STEPPED
        };
    for (register, value) in [
        (Register::ELR_EL1, CODE_PAGE),
        (Register::SPSR_EL1, spsr),
        (Register::TPIDR_EL1, case.steps as u64),
        (Register::MDSCR_EL1, MDSCR_SS),
        (Register::SCTLR_EL1, SCTLR_VALUE),
        (Register::TCR_EL1, TCR_VALUE),
        (Register::TTBR0_EL1, L1_TABLE),
        (Register::MAIR_EL1, MAIR_VALUE),
        (Register::CPACR_EL1, CPACR_FP),
        (Register::VBAR_EL1, VECTOR_BASE),
        // Without a hypervisor the oracle machine has no EL2, so the
        // engine's EL2 stays out of the way: HVC is UNDEFINED; PAC keys,
        // SCXTNUM and the RAS error record controls are not trapped
        // (HCR_EL2.APK, API, EnSCXT, FIEN); and FP/SIMD and the EL1 counter
        // and timer are not trapped to EL2. The EL2 harness sets the same
        // controls without HCD, with E2H, RW and VM and the case's additions.
        (
            Register::HCR_EL2,
            match hypervisor {
                Some(hypervisor) => HCR_BASE | hypervisor.hcr,
                None => {
                    1 << HCR_HCD | 1 << HCR_APK | 1 << HCR_API | 1 << HCR_ENSCXT | 1 << HCR_FIEN
                }
            },
        ),
        (Register::CPTR_EL2, 0b11 << 20),
        (Register::CNTHCTL_EL2, 1 << 10 | 1 << 11),
    ] {
        cpu.registers.set(register, 0, value);
    }
    if hypervisor.is_some() {
        for (register, value) in [
            (Register::VTCR_EL2, VTCR_VALUE),
            (Register::VTTBR_EL2, S2_L1_TABLE),
            (Register::SCTLR_EL2, SCTLR_EL2_VALUE),
            (Register::VBAR_EL2, VECTOR_BASE),
            // An EL2 case is entered by the EL2 harness's ERET.
            (Register::ELR_EL2, CODE_PAGE),
            (Register::SPSR_EL2, nzcv | SPSR_EL2T_MASKED),
        ] {
            cpu.registers.set(register, 0, value);
        }
    }
    // The harness enters each case by ERET, which sets the event register.
    cpu.event = true;
    let host = OracleHost {
        code: windows.code_pointer(),
        data: windows.data_pointer(),
        tables: harness_tables(hypervisor),
        installed: Vec::new(),
        runner: NativeRunner::new(Vec::new()),
        regime: None,
    };
    let profile = profile(target, hypervisor.is_some());
    let mut machine = Machine::new(cpu, host, NoDevices, profile, target);
    // An EL1 or EL2 case runs its words, one block each, and the UDF after
    // them.
    let blocks = if case.el != 0 {
        case.code.len() as u64 + 1
    } else {
        1
    };
    let saved = super::native::mxcsr();
    let mut stop = Stop::Budget;
    for budget in 1..=blocks {
        stop = machine.run(budget);
        if machine.statistics.exceptions != 0 {
            break;
        }
    }
    super::native::set_mxcsr(saved);
    // The harness ends a case at its first exception; the engine may run on
    // to its vector (an exception on fetch takes no budget), which the case
    // does not include.
    match stop {
        _ if machine.statistics.exceptions != 0 => {}
        Stop::Budget => {}
        Stop::Unsupported(requirement) => bail!("engine refused: {requirement}"),
        other => bail!("engine stopped: {other:?}"),
    }
    let cpu = &machine.cpu;
    let mut state = cpu.state.clone();
    // A stepped EL0 case completes after its words, but the engine runs on
    // into the zero words after them: their UDF #0 marks completion.
    let end = CODE_PAGE + 4 * case.code.len() as u64;
    // The exception's registers are those of the EL it was taken to.
    let level = cpu.pstate.el;
    let (esr, elr, far, spsr) = if level == 2 {
        (
            Register::ESR_EL2,
            Register::ELR_EL2,
            Register::FAR_EL2,
            Register::SPSR_EL2,
        )
    } else {
        (
            Register::ESR_EL1,
            Register::ELR_EL1,
            Register::FAR_EL1,
            Register::SPSR_EL1,
        )
    };
    let fell_through = case.el == 0
        && machine.statistics.exceptions != 0
        && level == 1
        && cpu.read(esr) == UDF_SYNDROME
        && cpu.read(elr) == end;
    let (next_pc, exception) = if fell_through {
        state.sp = cpu.sp(0);
        (end, None)
    } else if machine.statistics.exceptions != 0 {
        state.sp = cpu.sp(0);
        let exception = Exception {
            syndrome: cpu.read(esr),
            address: cpu.read(elr),
            fault_address: cpu.read(far),
            level,
            hpfar: if level == 2 {
                cpu.read(Register::HPFAR_EL2)
            } else {
                0
            },
        };
        (cpu.read(elr), Some(exception))
    } else {
        (cpu.pc, None)
    };
    // SAFETY: the data window stays mapped while the lock is held.
    let data = unsafe { std::slice::from_raw_parts(windows.data_pointer(), DATA_BYTES) }.into();
    Ok(Outcome {
        state,
        next_pc,
        data,
        scalable: None,
        exception,
        spsr: (case.el != 0).then_some(cpu.read(spsr)),
    })
}
