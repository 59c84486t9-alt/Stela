//! System-mode engine lane: run a case's words on `stela_runtime::machine` at
//! EL0 under the harness's EL1 controls, so exception outcomes (ESR, ELR, FAR)
//! compare with QEMU as well as completions. EL1 cases run at EL1t with every
//! exception masked until their first exception, as the harness runs them:
//! the zero words after the case are UDF, and SPSR then holds PSTATE.
//!
//! The engine runs with its MMU off: EL0 sees the code region and data window
//! at their own addresses, as the harness maps them. Every SCTLR_EL1 trap
//! control the harness clears (nTWI, nTWE, UCI, UCT, DZE, UMA) is clear here
//! too, CPACR_EL1 enables FP/SIMD, and the CPU profile is the engine's M2
//! identification without EL2, like the harness's QEMU machine.
use super::{
    CODE_PAGE, CODE_REGION, CODE_REGION_BYTES, Case, DATA_BYTES, DATA_WINDOW, Exception, Outcome,
    native::{Executable, windows},
};
use anyhow::{Result, bail};
use stela_compiler::{GuestState, TargetCpu};
use stela_runtime::machine::{
    Cpu, Host, InstallError, Machine, NativeCode, NativeExit, NoDevices, Regime, Stop,
    exception::Pstate,
    identification,
    registers::{CpuProfile, encodings::DCZID_EL0},
};

/// The harness's SCTLR_EL1 without M: every EL0 trap control clear.
const SCTLR_VALUE: u64 = (0x30d0_0801 | (1 << 42) | (1 << 60)) & !1;
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
const SPSR_EL0T_STEPPED: u64 = 0x3c0 | 1 << 21;
/// Blocks an EL1 case may run before its first exception: the case word and
/// the UDF after it.
const EL1_BLOCKS: u64 = 2;

/// The native block exit in RAX:RDX.
#[repr(C)]
struct BlockExit {
    next_pc: u64,
    kind: u64,
}

/// Guest RAM is the oracle's code region and data window at their guest
/// addresses; installed native code lives in owned executable mappings.
struct OracleHost {
    code: *const u8,
    data: *mut u8,
    installed: Vec<Executable>,
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

    fn discard_code(&mut self) {
        self.installed.clear();
    }

    unsafe fn execute(&mut self, code: NativeCode, state: &mut GuestState) -> NativeExit {
        // SAFETY: the engine passes code it installed for the system-mode
        // block ABI; the lane admits only words whose blocks exit at once.
        let block: extern "sysv64" fn(*mut GuestState) -> BlockExit =
            unsafe { std::mem::transmute(code.0) };
        let exit = block(state);
        NativeExit::Exit {
            next_pc: exit.next_pc,
            kind: exit.kind,
        }
    }

    fn set_regime(&mut self, _: &Regime) {}

    fn invalidate_translations(&mut self) {}

    fn counter(&mut self) -> u64 {
        0
    }

    fn arm_timer(&mut self, _: Option<u64>) {}

    fn wait_for_interrupt(&mut self) {}
}

/// The engine's M2 profile without EL2, as the oracle machine has none.
fn profile(target: TargetCpu) -> CpuProfile {
    let mut fixed = identification::derive(target, false);
    fixed.push((DCZID_EL0, DCZID));
    CpuProfile {
        name: "oracle-m2-el0",
        counter_frequency: 24_000_000,
        fixed,
    }
}

/// Run `case`'s first word at EL0 on the engine and report it as the harness
/// would: registers, SP_EL0, NZCV, the data window and any exception.
///
/// # Safety
/// The case's words must compile to blocks that exit before any native memory
/// access, as System instructions do in the system-mode profile.
pub unsafe fn run(case: &Case, target: TargetCpu) -> Result<Outcome> {
    let windows = windows()?.lock().expect("native windows lock");
    // SAFETY: the windows are owned mappings; the code page is installed below.
    unsafe { super::native::install_case(&windows, case)? };
    let mut pstate = Pstate::reset(if case.el1 { 1 } else { 0 });
    // EL1 cases run on SP_EL0 (EL1t), as the harness keeps SP_EL1 for itself.
    pstate.sp_el1 = false;
    let mut cpu = Cpu::new(CODE_PAGE, pstate);
    cpu.state = case.state.clone();
    // The rest of the EL1 state the harness leaves for the case.
    let nzcv = u64::from(case.state.nzcv) & 0xf000_0000;
    cpu.system.elr = CODE_PAGE;
    cpu.system.spsr = nzcv
        | if case.el1 {
            SPSR_EL1T_MASKED
        } else {
            SPSR_EL0T_STEPPED
        };
    cpu.system.tpidr_el1 = case.steps as u64;
    cpu.system.mdscr = MDSCR_SS;
    cpu.system.translation.sctlr = SCTLR_VALUE;
    cpu.system.translation.tcr = TCR_VALUE;
    cpu.system.translation.mair = MAIR_VALUE;
    cpu.system.cpacr = CPACR_FP;
    cpu.system.vbar = VECTOR_BASE;
    // The harness enters each case by ERET, which sets the event register.
    cpu.system.event = true;
    let host = OracleHost {
        code: windows.code_pointer(),
        data: windows.data_pointer(),
        installed: Vec::new(),
    };
    let mut machine = Machine::new(cpu, host, NoDevices, profile(target), target);
    let blocks = if case.el1 { EL1_BLOCKS } else { 1 };
    let saved = super::native::mxcsr();
    let mut stop = Stop::Budget;
    for budget in 1..=blocks {
        stop = machine.run(budget);
        if machine.statistics.exceptions != 0 {
            break;
        }
    }
    super::native::set_mxcsr(saved);
    match stop {
        Stop::Budget => {}
        Stop::Unsupported(requirement) => bail!("engine refused: {requirement}"),
        other => bail!("engine stopped: {other:?}"),
    }
    let cpu = &machine.cpu;
    let mut state = cpu.state.clone();
    let (next_pc, exception) = if machine.statistics.exceptions != 0 {
        state.sp = cpu.system.sp_el0;
        let exception = Exception {
            syndrome: cpu.system.esr,
            address: cpu.system.elr,
            fault_address: cpu.system.far,
        };
        (cpu.system.elr, Some(exception))
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
        spsr: case.el1.then_some(cpu.system.spsr),
    })
}
