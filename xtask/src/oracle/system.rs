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
use super::{
    CODE_PAGE, CODE_REGION, CODE_REGION_BYTES, Case, DATA_BYTES, DATA_WINDOW, Exception, Outcome,
    native::{Executable, windows},
};
use anyhow::{Result, bail};
use stela_compiler::{GuestState, TargetCpu};
use stela_runtime::machine::{
    Cpu, Host, InstallError, Machine, NativeCode, NativeExit, NoDevices, Regime, Stop,
    cpu::HCR_HCD,
    exception::Pstate,
    identification,
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
const SPSR_EL0T_STEPPED: u64 = 0x3c0 | 1 << 21;
/// ESR_EL1 of UDF #0: EC 0 with IL set.
const UDF_SYNDROME: u64 = 1 << 25;

// The harness's translation tables and the memory they map.
const RAM: u64 = 0x4000_0000;
const L1_TABLE: u64 = 0x4011_0000;
const L2_TABLE: u64 = 0x4011_1000;
const L3_DATA: u64 = 0x4011_3000;
const L2_CASE_TABLE: u64 = 0x4011_4000;
const TABLE_BYTES: usize = 0x5000;
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

/// The descriptors `build_tables` writes, as bytes from `L1_TABLE`.
fn harness_tables() -> Vec<u8> {
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
    tables
}

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
    /// The harness's translation tables, read-only.
    tables: Vec<u8>,
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

const HCR_APK: u32 = 40;
const HCR_API: u32 = 41;
const HCR_FIEN: u32 = 47;
const HCR_ENSCXT: u32 = 53;

/// The engine's M2 profile without EL2, as the oracle machine has none.
fn profile(target: TargetCpu) -> CpuProfile {
    let mut fixed = identification::derive(target, false);
    fixed.push((DCZID_EL0, DCZID));
    // J473AP cpu0's MIDR and MPIDR, as the bundle profile gives them; only
    // the access outcome of an MRS is compared.
    fixed.extend([(MIDR_EL1, 0x611f_0320), (MPIDR_EL1, 0x8000_0000)]);
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
    pstate.sp = false;
    let mut cpu = Cpu::new(CODE_PAGE, pstate);
    cpu.state = case.state.clone();
    // The rest of the EL1 state the harness leaves for the case.
    let nzcv = u64::from(case.state.nzcv) & 0xf000_0000;
    let spsr = nzcv
        | if case.el1 {
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
        // The oracle machine has no EL2, so the engine's EL2 stays out of
        // the way: HVC is UNDEFINED; PAC keys, SCXTNUM and the RAS error
        // record controls are not trapped (HCR_EL2.APK, API, EnSCXT, FIEN);
        // and FP/SIMD and the EL1 counter and timer are not trapped to EL2.
        (
            Register::HCR_EL2,
            1 << HCR_HCD | 1 << HCR_APK | 1 << HCR_API | 1 << HCR_ENSCXT | 1 << HCR_FIEN,
        ),
        (Register::CPTR_EL2, 0b11 << 20),
        (Register::CNTHCTL_EL2, 1 << 10 | 1 << 11),
    ] {
        cpu.registers.set(register, 0, value);
    }
    // The harness enters each case by ERET, which sets the event register.
    cpu.event = true;
    let host = OracleHost {
        code: windows.code_pointer(),
        data: windows.data_pointer(),
        tables: harness_tables(),
        installed: Vec::new(),
    };
    let mut machine = Machine::new(cpu, host, NoDevices, profile(target), target);
    // An EL1 case runs its words, one block each, and the UDF after them.
    let blocks = if case.el1 {
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
    match stop {
        Stop::Budget => {}
        Stop::Unsupported(requirement) => bail!("engine refused: {requirement}"),
        other => bail!("engine stopped: {other:?}"),
    }
    let cpu = &machine.cpu;
    let mut state = cpu.state.clone();
    // A stepped EL0 case completes after its words, but the engine runs on
    // into the zero words after them: their UDF #0 marks completion.
    let end = CODE_PAGE + 4 * case.code.len() as u64;
    let fell_through = !case.el1
        && machine.statistics.exceptions != 0
        && cpu.read(Register::ESR_EL1) == UDF_SYNDROME
        && cpu.read(Register::ELR_EL1) == end;
    let (next_pc, exception) = if fell_through {
        state.sp = cpu.sp(0);
        (end, None)
    } else if machine.statistics.exceptions != 0 {
        state.sp = cpu.sp(0);
        let exception = Exception {
            syndrome: cpu.read(Register::ESR_EL1),
            address: cpu.read(Register::ELR_EL1),
            fault_address: cpu.read(Register::FAR_EL1),
        };
        (cpu.read(Register::ELR_EL1), Some(exception))
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
        spsr: case.el1.then_some(cpu.read(Register::SPSR_EL1)),
    })
}
