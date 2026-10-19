//! Apple implementation-defined registers of the T8112 (M2) that the 26A434
//! kernelcache, SPTM and TXM access, each listed with its consumer and the
//! behavior that consumer needs (the census is in
//! `docs/research/j473-kernel.md#system-registers`). Registers with an
//! architectural or modeled effect have their own owners (`machine::registers`,
//! `pmu`, `amx`, `ctrr` and the board's fast-IPI registers); every encoding
//! neither lists refuses.
//!
//! - `Storage`: software saves and restores the register around its own
//!   changes, or writes it and never reads it, so reads must return the last
//!   value written. A read before the first write refuses, because the reset
//!   value is unknown.
//! - `Tuning`: a core tuning ("chicken bit") register, named by m1n1
//!   `cpu_regs.h` or used only in the same boot-time pattern, or a
//!   performance hint to the core's predictors. Software reads it, sets or
//!   clears bits and writes it back, or saves and restores it.
//!   The reset value is unknown and taken as 0 (inference). No bit has an
//!   effect here.
//! - `Scratch`: a register software keeps its own records in, with no
//!   hardware effect. Reads return the last value written, 0 from cold
//!   reset (inference).
//! - `Control`: a control register whose bits select features or events
//!   this machine does not model. It reads 0 from reset (inference) and
//!   takes only the entry's permitted bits (none for most); any other set
//!   bit stops, as for ACTLR_EL1.
//! - `Status`: the status of an event this machine never raises (an error,
//!   an uncore interrupt). It reads 0, and the writes software uses to
//!   clear it (write-one-to-clear) change nothing.
//! - `Record`: information about such an event. It reads 0, and since no
//!   consumer writes it, a write stops.
//! - `Counter`: an event counter whose controls (`Control` entries) accept
//!   only their disabled value here, so it never counts. It holds what
//!   software writes, 0 from reset (inference).
//! - `Guest`: a VM's copy of Apple EL1 state, which the kernel's hypervisor
//!   loads before it runs a vCPU and saves afterwards. It is stored like
//!   `Storage`, but this machine applies none of it to a guest, so entering
//!   an EL1&0 guest of the EL2 host while one holds a nonzero value must
//!   stop. `Registers::guest_state` finds such a value, which the engine's
//!   ERET and GEXIT check before entering such a guest.
//! - `Unsupported`: its consumer relies on an effect this machine cannot
//!   provide; every access stops with the evidence as the reason.
//!
//! `Scope::Cluster` entries are one register per cluster, shared by its PEs
//! (`Registers::join`); the others are per PE. `el2` entries are UNDEFINED
//! below EL2. Every entry is hardware-unverified ([`VERIFICATION`]): no M2
//! has enumerated the space, so neither an encoding's existence nor its reset
//! value is observed. The run reports every entry the guest used, so none of
//! these is silent.
use alloc::{collections::BTreeMap, rc::Rc};
use core::cell::RefCell;
use stela_compiler::aarch64::system::registers::Encoding;

/// The verification state of every entry.
pub const VERIFICATION: &str =
    "hardware-unverified until an M2 enumeration observes the encoding and its reset value";

/// The CRn of Apple's registers (op0 3); no 26A434 component uses CRn 11.
const IMPDEF_CRN: u8 = 15;

macro_rules! encodings {
    ($($name:ident = $op1:literal, $crm:literal, $op2:literal;)*) => {
        $(pub const $name: Encoding = Encoding::new(3, $op1, IMPDEF_CRN, $crm, $op2);)*
    };
}

// Names from m1n1 `cpu_regs.h` where it has one, from XNU where its strings
// or headers give one, else the encoding.
encodings! {
    EHID0 = 0, 0, 1;
    HID26 = 0, 0, 3;
    HID27 = 0, 0, 4;
    HID1 = 0, 1, 0;
    HID21 = 0, 1, 3;
    HID3 = 0, 3, 0;
    HID4 = 0, 4, 0;
    EHID4 = 0, 4, 1;
    HID5 = 0, 5, 0;
    HID7 = 0, 7, 0;
    HID9 = 0, 9, 0;
    EHID9 = 0, 9, 1;
    HID10 = 0, 10, 0;
    EHID10 = 0, 10, 1;
    HID11 = 0, 11, 0;
    HID18 = 0, 11, 2;
    EHID18 = 0, 11, 3;
    HID13 = 0, 14, 0;
    HID14 = 0, 15, 0;
    HID16 = 0, 15, 2;
    MEM_STALL_SELECT_0 = 1, 0, 3;
    MEM_STALL_SELECT_1 = 1, 1, 3;
    VM_CONTEXT = 1, 8, 2;
    MEM_STALL_COUNTER_0 = 1, 8, 3;
    MEM_STALL_COUNTER_1 = 1, 9, 3;
    MEM_STALL_COUNTER_2 = 1, 10, 3;
    MEM_STALL_COUNTER_3 = 1, 11, 3;
    LSU_ERR_STS = 3, 0, 0;
    E_LSU_ERR_STS = 3, 2, 0;
    L2C_ERR_STS = 3, 8, 0;
    L2C_ERR_ADR = 3, 9, 0;
    L2C_ERR_INF = 3, 10, 0;
    FED_ERR_STS = 4, 0, 0;
    CORE_TUNING_1 = 4, 0, 1;
    E_FED_ERR_STS = 4, 0, 2;
    CORE_TUNING_3 = 4, 0, 3;
    GUEST_C2_6 = 4, 2, 6;
    AMX_CTX_EL1 = 4, 5, 0;
    GUEST_C8_0 = 4, 8, 0;
    GUEST_C8_1 = 4, 8, 1;
    GUEST_C8_2 = 4, 8, 2;
    GUEST_C8_3 = 4, 8, 3;
    GUEST_C9_0 = 4, 9, 0;
    GUEST_C9_1 = 4, 9, 1;
    GUEST_C9_2 = 4, 9, 2;
    GUEST_C9_3 = 4, 9, 3;
    GUEST_C9_4 = 4, 9, 4;
    GUEST_C9_5 = 4, 9, 5;
    SPTM_KEY_0 = 4, 10, 0;
    SPTM_KEY_1 = 4, 10, 1;
    SPTM_KEY_2 = 4, 10, 2;
    SPTM_KEY_3 = 4, 10, 3;
    SIQ_CFG_EL1 = 4, 10, 4;
    NESTED_PAGE = 4, 10, 7;
    THREAD_CONTROL = 4, 12, 0;
    THREAD_KEY_0 = 4, 13, 6;
    THREAD_KEY_1 = 4, 13, 7;
    GUEST_C14_0 = 4, 14, 0;
    GUEST_C14_1 = 4, 14, 1;
    GUEST_C14_2 = 4, 14, 2;
    GUEST_C14_3 = 4, 14, 3;
    GUEST_RANGE_COMMAND = 4, 15, 1;
    GUEST_C15_2 = 4, 15, 2;
    SPTM_CONTEXT = 4, 15, 4;
    GUEST_C15_5 = 4, 15, 5;
    THREAD_PERMISSIONS = 4, 15, 6;
    DPC_ERR_STS = 5, 0, 5;
    GUEST_VGIC = 5, 1, 2;
    SWITCH_CLEARED = 5, 1, 4;
    WATCHDOG_DIAG0 = 5, 2, 6;
    ACC_CFG = 5, 4, 0;
    ACC_OVRD = 5, 6, 0;
    TRACE_CLEARED = 5, 10, 1;
    MMU_ERR_STS = 6, 0, 0;
    GUARDED_AFSR1 = 6, 0, 2;
    GUEST_AFSR1 = 6, 0, 3;
    BP_OBJC_ADR_EL1 = 6, 0, 4;
    BP_OBJC_CTL_EL1 = 6, 0, 5;
    GUARDED_HPFAR = 6, 1, 1;
    E_MMU_ERR_STS = 6, 2, 0;
    GUEST_KEY_C2_1 = 6, 2, 1;
    GUEST_KEY_C2_2 = 6, 2, 2;
    GUEST_KEY_C2_3 = 6, 2, 3;
    GUEST_KEY_C2_4 = 6, 2, 4;
    TSO_THREAD_CONTROL = 6, 2, 5;
    GUEST_SPRR_C6_0 = 6, 6, 0;
    GUEST_SPRR_C6_1 = 6, 6, 1;
    GUEST_SPRR_C6_2 = 6, 6, 2;
    GUEST_SPRR_C6_3 = 6, 6, 3;
    GUEST_KEY_C7_0 = 6, 7, 0;
    GUEST_KEY_C7_1 = 6, 7, 1;
    GUEST_KEY_C7_2 = 6, 7, 2;
    GUEST_KEY_C7_3 = 6, 7, 3;
    GUEST_KEY_C7_4 = 6, 7, 4;
    GUEST_KEY_C7_5 = 6, 7, 5;
    GUEST_KEY_C7_6 = 6, 7, 6;
    GUEST_KEY_C7_7 = 6, 7, 7;
    TSO_THREAD_FLAGS = 6, 8, 3;
    GXF_MASK = 6, 8, 5;
    GUEST_C12_7 = 6, 12, 7;
    APVMKEYLO_EL2 = 6, 14, 4;
    APVMKEYHI_EL2 = 6, 14, 5;
    APSTS_EL12 = 6, 14, 7;
    GUEST_SPRR_C15_4 = 6, 15, 4;
    GUEST_SPRR_C15_5 = 6, 15, 5;
    CLUSTER_COUNTER_C0 = 7, 0, 2;
    AON_COUNTER_0 = 7, 0, 3;
    UPMCR0 = 7, 0, 4;
    UPMC8 = 7, 0, 5;
    CORE_NRG_ACC_DAT = 7, 1, 1;
    AON_SELECT_0 = 7, 1, 3;
    UPMESR0_EL1 = 7, 1, 4;
    UPMC9 = 7, 1, 5;
    CLUSTER_COUNTER_C2 = 7, 2, 2;
    AON_COUNTER_1 = 7, 2, 3;
    UPMC10 = 7, 2, 5;
    CORE_SRM_NRG_ACC_DAT = 7, 3, 1;
    AON_SELECT_1 = 7, 3, 3;
    UPMECM0_EL1 = 7, 3, 4;
    UPMC11 = 7, 3, 5;
    CLUSTER_COUNTER_C4 = 7, 4, 2;
    AON_COUNTER_2 = 7, 4, 3;
    UPMECM1_EL1 = 7, 4, 4;
    UPMC12 = 7, 4, 5;
    AON_ENABLE = 7, 5, 0;
    AON_SELECT_2 = 7, 5, 3;
    UPMPCM_EL1 = 7, 5, 4;
    UPMC13 = 7, 5, 5;
    CLUSTER_COUNTER_C6 = 7, 6, 2;
    UPMSR = 7, 6, 4;
    UPMC14 = 7, 6, 5;
    UPMC0 = 7, 7, 4;
    UPMC15 = 7, 7, 5;
    CLUSTER_COUNTER_C8 = 7, 8, 2;
    UPMC1 = 7, 8, 4;
    UPMECM2_EL1 = 7, 8, 5;
    UPMC2 = 7, 9, 4;
    UPMECM3_EL1 = 7, 9, 5;
    CLUSTER_COUNTER_C10 = 7, 10, 2;
    UPMC3 = 7, 10, 4;
    UPMC4 = 7, 11, 4;
    UPMESR1_EL1 = 7, 11, 5;
    CLUSTER_COUNTER_C12 = 7, 12, 2;
    UPMC5 = 7, 12, 4;
    UPMC6 = 7, 13, 4;
    UPMC7 = 7, 14, 4;
}

/// UPMCR0's interrupt mode 4 (FIQ, bits 16-18) and per-counter PMI enables
/// (bits 20-35): m1n1 `UPMCR0_IMODE_T8020`, `UPMCR0_IMODE_FIQ` and
/// `UPMCR0_PMI_SHIFT_T8020`, for 16 counters. Its counter enables (bits
/// 0-15) and other interrupt modes are not permitted.
const UPMCR0_IMODE_FIQ: u64 = 4 << 16;
const UPMCR0_PMI_ENABLES: u64 = 0xffff << 20;
const UPMCR0_PERMITTED: u64 = UPMCR0_IMODE_FIQ | UPMCR0_PMI_ENABLES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Storage,
    Tuning,
    Scratch,
    Control,
    Status,
    Record,
    Counter,
    Guest,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Pe,
    Cluster,
}

pub struct Entry {
    pub encoding: Encoding,
    pub name: &'static str,
    pub class: Class,
    pub evidence: &'static str,
    pub scope: Scope,
    /// UNDEFINED below EL2.
    pub el2: bool,
    /// The bits a `Control` entry takes.
    pub permitted: u64,
}

const fn entry(
    encoding: Encoding,
    name: &'static str,
    class: Class,
    evidence: &'static str,
) -> Entry {
    Entry {
        encoding,
        name,
        class,
        evidence,
        scope: Scope::Pe,
        el2: false,
        permitted: 0,
    }
}

impl Entry {
    const fn cluster(self) -> Self {
        Self {
            scope: Scope::Cluster,
            ..self
        }
    }

    const fn el2(self) -> Self {
        Self { el2: true, ..self }
    }

    const fn permitting(self, permitted: u64) -> Self {
        Self { permitted, ..self }
    }
}

const SPTM_CONTEXT_EVIDENCE: &str = "SPTM 26A434 saves and restores it with SCTLR_EL1 and TCR_EL1 \
    (__text+0x2120, __text+0x28e8)";

const SPTM_KEY_WRITES: &str = "SPTM 26A434 writes it once per CPU with a PAC-key-derived \
    value after the architectural PAC keys and reads it nowhere; TXM and the kernel never touch it";

const M1N1_TUNING: &str = "m1n1 cpu_regs.h names it a core tuning (HID) register; SPTM 26A434 \
    sets or clears bits with read-modify-write at boot";

const XNU_THREAD_CONTROL: &str = "26A434 XNU saves it in every exception frame and \
    restores it on return (0xfffffe000bb9da44, 0xfffffe000bb9db48), SPTM 26A434 keeps it in \
    each context it resumes (__text+0x44a8), and CPU initialization clears bit 1 \
    (0xfffffe000bd80ed8) unless a patch alternative sets it, the bit ACTLR_EL1 names EnTSO; \
    AIDR_EL1 here advertises no TSO";

const XNU_AMX_CONTEXT: &str = "26A434 XNU CPU initialization writes MPIDR.Aff0 to it \
    under one boot configuration (0xfffffe000bd80f44) and reads it nowhere; named AMX_CTX_EL1 \
    beside AMX_CTL_EL1 (docs/research/amx.md)";

const SPTM_CORE_TUNING: &str = "no public name; SPTM 26A434 clears one bit with \
    read-modify-write at boot, selected by MPIDR core type next to its HID writes \
    (__text+0xb9a8, __text+0xb9d0), and AppleARM64ErrorHandler::_fedErrorHandler reads it \
    only after a front-end error (0xfffffe0009495114), which this machine never raises";

const SPTM_GXF_MASK: &str = "SPTM 26A434 writes it once per CPU at boot with the value it \
    writes to S3_1_C15_C8_2 (0x30300 or 0x3_0300_00ff_ff00, __text+0x1bebc) and reads it \
    nowhere; TXM and the kernel never touch it";

const VM_CONTEXT_EVIDENCE: &str = "SPTM 26A434 writes it once per CPU at boot (__text+0x1bec8); \
    the 26A434 kernel only saves and restores it with a VM's GL12 registers \
    (0xfffffe000bd9eddc, 0xfffffe000bda2bb4)";

const ACC_CFG_EVIDENCE: &str = "m1n1 cpu_regs.h names it, with the branch-predictor sleep field \
    ACC_CFG_BP_SLEEP (bits 2-3), which 26A434 XNU sets with read-modify-write \
    (0xfffffe000bb9c8e0); the engine keeps no predictor state to retain";

const ACC_OVRD_EVIDENCE: &str = "m1n1 cpu_regs.h names it; XNU xnu-12377.121.6 \
    machine_routines_asm.s sets its deep-sleep fields (xnu-6153.141.1 arm64_common.h \
    ARM64_REG_ACC_OVRD_*) before a deep-sleep power-down, which acts only when the cluster \
    powers down, and core power-down stops (CYC_OVRD)";

const SIQ_CFG: &str = "m1n1 cpu_regs.h names it SIQ_CFG_EL1; 26A434 XNU sets bits 0-1 to a \
    per-thread mode with read-modify-write at context switch (0xfffffe000bd7c388) and before \
    a power-down, and clears it elsewhere (0xfffffe000bd70b74); no field is described, and \
    the HID1 and EHID20 chicken bits m1n1 names after the SIQ tune speculation only";

const XNU_THREAD_KEYS: &str = "26A434 XNU's context switch writes it with the thread's \
    APIBKey value plus 4 or 5, after APIBKey and APDBKey (0xfffffe000bb9bd38), and reads it \
    nowhere; the software PAC function, like for the Apple PAC controls, uses only the \
    architectural keys";

const WATCHDOG_DIAG: &str = "XNU xnu-12377.121.6 debug.c names it WATCHDOG_DIAG0, which the \
    Apple watchdog logging ORs its flags into (awl_set_scratch_reg_hv_bit)";

const OBJC_BRANCH_HINT: &str = "the objc_msgSend branch-predictor helper: public XNU \
    apple_arm64_regs.h describes BP_OBJC_ADR_EL1 and BP_OBJC_CTL_EL1 under HAS_OBJC_BP_HELPER, \
    and 26A434 XNU's objc_bp_assist_cfg_np(adr, ctl) (syscall 535) checks its two values \
    against those fields, writes them to S3_6_C15_C0_4 and S3_6_C15_C0_5 on every CPU \
    (0xfffffe000bda59b4) and saves both per thread; SPTM 26A434 clears C0_5 around TXM \
    (__text+0x2aec); a prediction hint has no architectural effect";

const XNU_SWITCH_CLEARS: &str = "26A434 XNU writes 0 to it at every context switch \
    (0xfffffe000bd8393c, beside S3_5_C15_C10_1) and reads it nowhere; SPTM and TXM never \
    touch it. Writing 0 can only clear state this machine does not have (inference)";

const XNU_TRACE_CLEARS: &str = "26A434 XNU writes 0 to it at every context switch \
    (0xfffffe000bd83940) and after appending a timestamp record to a per-CPU trace ring \
    (0xfffffe000bd7b0e0), and reads it nowhere; SPTM and TXM never touch it. Writing 0 can \
    only clear state this machine does not have (inference)";

const XNU_THREAD_PERMISSIONS: &str = "26A434 XNU swaps a per-thread value through it at \
    context switch (0xfffffe000bd83950) and elsewhere reads it beside SPRR_PERM_EL0, treating \
    the thread as unrestricted when bits 14-15 are clear and SPRR_PERM_EL0 holds its default \
    (0xfffffe000bd787cc). Those bits relate to EL0 permissions this machine does not \
    implement for them, so only 0 is accepted (inference)";

const ERROR_STATUS: &str = "an error status register (m1n1 cpu_regs.h names it; the E_ form \
    is the E-core's): 26A434 XNU's panic for an unhandled implementation-specific error \
    prints it (0xfffffe000c52dab8), and AppleARM64ErrorHandler::_platformErrorHandler reads \
    the form for the MPIDR core type and tests its valid bit 56 (0xfffffe0009494970). Both \
    run only after an SError or implementation-defined error exception, which this machine \
    never raises, so it reads 0: no error recorded";

const DPC_ERROR_STATUS: &str = "no m1n1 name; 26A434 XNU's panic for an unhandled \
    implementation-specific error prints it as dpc_err_sts (0xfffffe000c52dabc), and \
    AppleARM64ErrorHandler::_platformErrorHandler reads it on both core types and tests its \
    valid bit 56 (0xfffffe000949497c). Both run only after an SError or \
    implementation-defined error exception, which this machine never raises, so it reads 0: \
    no error recorded";

const L2C_ERROR_STATUS: &str = "m1n1 cpu_regs.h names it, with L2C_ERR_STS_ENABLE_W1C; \
    26A434 XNU's error panic and AppleARM64ErrorHandler read it (0xfffffe000c52dad8, \
    0xfffffe00094949bc), _llcErrorHandler writes back the status bit it handled \
    (0xfffffe0009494ecc, 0xfffffe0009494f3c), write-one-to-clear, and _llcErrorClear writes \
    its argument (0xfffffe0009494e98); SPTM 26A434 reads it with L2C_ERR_ADR and L2C_ERR_INF \
    (__text+0x5ab90). No error exception is ever raised here, so it reads 0 and the clearing \
    writes change nothing";

const L2C_ERROR_RECORD: &str = "m1n1 cpu_regs.h names it; 26A434 XNU's error panic, \
    AppleARM64ErrorHandler::_platformErrorHandler (0xfffffe00094949c0) and SPTM 26A434 \
    (__text+0x5ab94) read it with L2C_ERR_STS to describe a recorded L2 error. None is ever \
    recorded here, so it reads 0; no consumer writes it";

const UNCORE_CONTROL: &str = "m1n1 cpu_regs.h UPMCR0 (T8020 layout: counter enables in bits \
    0-15, interrupt mode in bits 16-18 with 4 for FIQ, PMI enables from bit 20); 26A434 XNU's \
    uncore monitor writes 0xf_fff4_0000, every PMI enabled in FIQ mode, at CPU initialization \
    and when it resets the counters (0xfffffe000bd8bec8, 0xfffffe000bd8c314), adding counter \
    enables only while uncore counting is configured (0xfffffe000bd8bebc). Uncore events \
    are not modeled, so a counter enable or another interrupt mode stops. One per cluster";

const UNCORE_SELECT: &str = "m1n1 cpu_regs.h names this uncore monitor selection (event \
    numbers, core masks or the PMI core mask); 26A434 XNU writes it from its uncore \
    configuration at CPU initialization (0xfffffe000bd8bea0 to 0xfffffe000bd8bf14) and never \
    reads it. No uncore counter counts here, so the selection has no effect. One per cluster";

const UNCORE_STATUS: &str = "m1n1 cpu_regs.h UPMSR (bit 0 an uncore PMI is active, bits \
    2-17 the counters' overflow); 26A434 XNU's FIQ handler reads bit 0 to recognize an \
    uncore PMI (0xfffffe000bd7b400) and writes 0 after resetting the counters \
    (0xfffffe000bd8c450). No uncore counter counts here, so it reads 0. One per cluster";

const UNCORE_COUNTER: &str = "m1n1 cpu_regs.h names this uncore counter; 26A434 XNU's \
    uncore monitor zeroes, reads and restores it (0xfffffe000bd8c2b0, 0xfffffe000bd8bb3c, \
    0xfffffe000bd8d020). It counts only under a UPMCR0 counter enable, which stops here, so \
    it holds what software writes, 0 from reset (inference). One per cluster";

const AON_ENABLE_EVIDENCE: &str = "no public name; AppleT8112CLPC's \
    CorePerfSampler::readAONCounterEnable and writeAONCounterEnable read and write it \
    (0xfffffe0009f40a3c, 0xfffffe0009f40a48), and enableCore sets it after selecting three \
    core counters' events in S3_7_C15_C1_3, C3_3 and C5_3 (0xfffffe0009f40b14). What those \
    counters count is not documented, so only 0 (disabled) is accepted";

const AON_SELECT_EVIDENCE: &str = "no public name; AppleT8112CLPC's \
    CorePerfSampler::enableCore writes the selectors 0x8000, 0x8100 and 0x8700 to \
    S3_7_C15_C1_3, C3_3 and C5_3 before setting S3_7_C15_C5_0 (0xfffffe0009f40afc) and never \
    reads them; they act only once that enable is set, which stops here";

const AON_COUNTER_EVIDENCE: &str = "no public name; AppleT8112CLPC's CorePerfSampler::sample \
    and SchedulerInterface::contextSwitch read it as a wrapping 32-bit count \
    (0xfffffe0009f39778, 0xfffffe0009f382ac). It counts only under S3_7_C15_C5_0, which \
    accepts only 0 here, so it holds what software wrote, 0 from reset (inference)";

const MEM_STALL_SELECT_EVIDENCE: &str = "no public name; AppleT8112CLPC's \
    CoreMemStallSampler::enableCore writes two 32-bit selectors into each of S3_1_C15_C0_3 \
    and C1_3 (0x801 and 0x805, 0x807 and 0x3) with read-modify-write to start four \
    memory-stall counters, and 0 to stop them (0xfffffe0009f41790). The events are not \
    documented, so only 0 is accepted";

const MEM_STALL_COUNTER_EVIDENCE: &str = "no public name; AppleT8112CLPC's \
    CoreMemStallSampler::sample reads it as a 48-bit count whose bit 47 is its overflow, \
    which it clears by writing 0 (0xfffffe0009f41878). It counts only under the \
    S3_1_C15_C0_3 and C1_3 selectors, which accept only 0 here, so it holds what software \
    wrote, 0 from reset (inference)";

const CLUSTER_COUNTER_EVIDENCE: &str = "refused: AppleT8112CLPC's ClusterPerfSampler::sample \
    reads seven 48-bit counters of the PE's own cluster through S3_7_C15_C0_2 to C12_2 \
    (0xfffffe0009f68a8c), the other clusters' through MMIO, and rewrites them on overflow; \
    what they count and what enables them is not documented, so no count can be given";

const ENERGY_EVIDENCE: &str = "refused: m1n1 cpu_regs.h names this core energy accumulator; \
    AppleT8112CLPC's context switch adds CORE_NRG_ACC_DAT and CORE_SRM_NRG_ACC_DAT and panics \
    if the sum ever decreases (0xfffffe0009f38328, 0xfffffe0009f38374), and AppleT8112PMGR \
    reports them (0xfffffe0009fa45d4, 0xfffffe0009fa8ad0); this machine models no core power, \
    so it has no energy to accumulate";

const TSO_THREAD_EVIDENCE: &str = "no public name; 26A434 XNU saves S3_6_C15_C8_3 (bits 1-2) \
    and S3_6_C15_C2_5 in the exception frame of a thread that runs with ACTLR_EL1's EnTSO and \
    EnAPFLG and restores them on return (0xfffffe000bb9ad7c, 0xfffffe000bb9b96c), swaps a \
    VM's values at guest exit and entry (0xfffffe000bb9da34, 0xfffffe000bb9b794), and SPTM \
    26A434 restores S3_6_C15_C2_5 with each context it resumes (__text+0x44a0). Such \
    threads need the TSO and APFLG features AIDR_EL1 here does not advertise, so only 0 is \
    accepted (inference)";

const NESTED_PAGE_EVIDENCE: &str = "no public name; SPTM 26A434 reads and writes it through \
    accessors beside VNCR_EL2's (__text+0x593b0, __text+0x593c8), stores a page's physical \
    address in it with VNCR_EL2's when HCR_EL2.NV2 is set (__text+0x58f28, __text+0x59e4c) \
    and clears it before entering EL1 (__text+0x49edc). The M2 has no FEAT_NV2, so only 0 \
    is accepted (inference: a companion of VNCR_EL2)";

const GUEST_RANGE_EVIDENCE: &str = "refused: no public name; 26A434 XNU's hypervisor writes \
    an address-and-size encoding to it followed by ISB (0xfffffe000bda5670) and never reads \
    it, a command whose effect is not documented";

const GUARDED_HPFAR_EVIDENCE: &str = "no public name; SPTM 26A434 copies it to HPFAR_EL2, \
    as it copies the GL bank's ESR and FAR to EL1's, when it reflects a guarded-level \
    exception to the kernel (__text+0x27c8); inference: the guarded level's HPFAR. No \
    stage-2 fault is taken at a guarded level while HCR_EL2.VM is clear, so it reads 0, and \
    with VM set a read stops (machine::registers); no consumer writes it";

const GUARDED_AFSR1_EVIDENCE: &str = "no public name; SPTM 26A434 copies it to AFSR1_EL2 \
    when it reflects a guarded-level exception to the kernel (__text+0x27d0); inference: \
    the guarded level's AFSR1, whose contents are implementation defined. As for \
    AFSRn_ELx, this machine records nothing in it, so it reads 0; no consumer writes it";

const GUEST_AFSR1_EVIDENCE: &str = "no public name; 26A434 XNU's hypervisor saves and \
    restores it with a vCPU's GL12 registers (0xfffffe000bd9ede4, 0xfffffe000bda2bbc); \
    inference: GL1's AFSR1 reached from EL2. As for AFSRn_ELx, it takes only 0";

const VM_KEY_EVIDENCE: &str = "m1n1 cpu_regs.h names it; SPTM 26A434 clears it before \
    entering EL1 (__text+0x49ecc) and 26A434 XNU's hypervisor loads each VM's key into it \
    before running a vCPU (0xfffffe000bda2488). Like KERNELKEYLO/HI_EL1 it is stored: the \
    software PAC function uses only the architectural keys, so a guest's PACs stay \
    self-consistent but differ from hardware";

const VM_STATUS_EVIDENCE: &str = "m1n1 cpu_regs.h names it APSTS_EL12; SPTM 26A434 clears it \
    before entering EL1 (__text+0x49ed4) and 26A434 XNU's hypervisor loads a VM's value \
    before running a vCPU (0xfffffe000bda2498). A guest's APSTS_EL1 reads MKEYVld as the \
    host's does, so the value is only stored";

const GUEST_EVIDENCE: &str = "no public name; 26A434 XNU's hypervisor saves it with a vCPU's \
    EL12, GL12, SPRR, PAC or vGIC state after the guest runs (0xfffffe000bd9ea30) and loads \
    it before running one (0xfffffe000bd9fdc8), and SPTM 26A434 loads it from a saved \
    context before entering EL1, saves it on return and clears the PAC-group ones \
    (__text+0x49e80, __text+0x4a824, __text+0x4a120). A VM's copy of Apple EL1 state this \
    machine does not apply to a guest: stored; entering an EL1&0 guest while it is \
    nonzero stops at the ERET or GEXIT";

pub const TABLE: &[Entry] = &[
    entry(
        SWITCH_CLEARED,
        "S3_5_C15_C1_4 (unnamed)",
        Class::Control,
        XNU_SWITCH_CLEARS,
    ),
    entry(
        TRACE_CLEARED,
        "S3_5_C15_C10_1 (unnamed)",
        Class::Control,
        XNU_TRACE_CLEARS,
    ),
    entry(
        THREAD_PERMISSIONS,
        "S3_4_C15_C15_6 (unnamed)",
        Class::Control,
        XNU_THREAD_PERMISSIONS,
    ),
    entry(
        BP_OBJC_ADR_EL1,
        "BP_OBJC_ADR_EL1",
        Class::Tuning,
        OBJC_BRANCH_HINT,
    ),
    entry(
        BP_OBJC_CTL_EL1,
        "BP_OBJC_CTL_EL1",
        Class::Tuning,
        OBJC_BRANCH_HINT,
    ),
    entry(ACC_CFG, "ACC_CFG", Class::Tuning, ACC_CFG_EVIDENCE),
    entry(ACC_OVRD, "ACC_OVRD", Class::Tuning, ACC_OVRD_EVIDENCE),
    entry(SIQ_CFG_EL1, "SIQ_CFG_EL1", Class::Tuning, SIQ_CFG),
    entry(
        THREAD_KEY_0,
        "S3_4_C15_C13_6 (unnamed)",
        Class::Storage,
        XNU_THREAD_KEYS,
    ),
    entry(
        THREAD_KEY_1,
        "S3_4_C15_C13_7 (unnamed)",
        Class::Storage,
        XNU_THREAD_KEYS,
    ),
    entry(
        WATCHDOG_DIAG0,
        "WATCHDOG_DIAG0",
        Class::Scratch,
        WATCHDOG_DIAG,
    ),
    entry(
        THREAD_CONTROL,
        "S3_4_C15_C12_0 (unnamed)",
        Class::Control,
        XNU_THREAD_CONTROL,
    ),
    entry(
        CORE_TUNING_1,
        "S3_4_C15_C0_1 (unnamed)",
        Class::Tuning,
        SPTM_CORE_TUNING,
    ),
    entry(
        CORE_TUNING_3,
        "S3_4_C15_C0_3 (unnamed)",
        Class::Tuning,
        SPTM_CORE_TUNING,
    ),
    entry(EHID0, "EHID0", Class::Tuning, M1N1_TUNING),
    entry(HID26, "HID26", Class::Tuning, M1N1_TUNING),
    entry(HID27, "HID27", Class::Tuning, M1N1_TUNING),
    entry(HID1, "HID1", Class::Tuning, M1N1_TUNING),
    entry(HID21, "HID21", Class::Tuning, M1N1_TUNING),
    entry(HID3, "HID3", Class::Tuning, M1N1_TUNING),
    entry(HID4, "HID4", Class::Tuning, M1N1_TUNING),
    entry(EHID4, "EHID4", Class::Tuning, M1N1_TUNING),
    entry(HID5, "HID5", Class::Tuning, M1N1_TUNING),
    entry(HID7, "HID7", Class::Tuning, M1N1_TUNING),
    entry(HID9, "HID9", Class::Tuning, M1N1_TUNING),
    entry(EHID9, "EHID9", Class::Tuning, M1N1_TUNING),
    entry(HID10, "HID10", Class::Tuning, M1N1_TUNING),
    entry(EHID10, "EHID10", Class::Tuning, M1N1_TUNING),
    entry(HID11, "HID11", Class::Tuning, M1N1_TUNING),
    entry(HID18, "HID18", Class::Tuning, M1N1_TUNING),
    entry(EHID18, "EHID18", Class::Tuning, M1N1_TUNING),
    entry(HID13, "HID13", Class::Tuning, M1N1_TUNING),
    entry(HID14, "HID14", Class::Tuning, M1N1_TUNING),
    entry(HID16, "HID16", Class::Tuning, M1N1_TUNING),
    entry(
        SPTM_CONTEXT,
        "S3_4_C15_C15_4 (unnamed)",
        Class::Storage,
        SPTM_CONTEXT_EVIDENCE,
    ),
    entry(
        SPTM_KEY_0,
        "S3_4_C15_C10_0 (unnamed)",
        Class::Storage,
        SPTM_KEY_WRITES,
    ),
    entry(
        SPTM_KEY_1,
        "S3_4_C15_C10_1 (unnamed)",
        Class::Storage,
        SPTM_KEY_WRITES,
    ),
    entry(
        SPTM_KEY_2,
        "S3_4_C15_C10_2 (unnamed)",
        Class::Storage,
        SPTM_KEY_WRITES,
    ),
    entry(
        SPTM_KEY_3,
        "S3_4_C15_C10_3 (unnamed)",
        Class::Storage,
        SPTM_KEY_WRITES,
    ),
    entry(AMX_CTX_EL1, "AMX_CTX_EL1", Class::Storage, XNU_AMX_CONTEXT),
    entry(
        GXF_MASK,
        "S3_6_C15_C8_5 (unnamed)",
        Class::Storage,
        SPTM_GXF_MASK,
    ),
    entry(
        VM_CONTEXT,
        "S3_1_C15_C8_2 (unnamed)",
        Class::Storage,
        VM_CONTEXT_EVIDENCE,
    ),
    // Error records.
    entry(LSU_ERR_STS, "LSU_ERR_STS", Class::Status, ERROR_STATUS),
    entry(E_LSU_ERR_STS, "E_LSU_ERR_STS", Class::Status, ERROR_STATUS),
    entry(FED_ERR_STS, "FED_ERR_STS", Class::Status, ERROR_STATUS),
    entry(E_FED_ERR_STS, "E_FED_ERR_STS", Class::Status, ERROR_STATUS),
    entry(MMU_ERR_STS, "MMU_ERR_STS", Class::Status, ERROR_STATUS),
    entry(E_MMU_ERR_STS, "E_MMU_ERR_STS", Class::Status, ERROR_STATUS),
    entry(
        DPC_ERR_STS,
        "S3_5_C15_C0_5 (XNU dpc_err_sts)",
        Class::Status,
        DPC_ERROR_STATUS,
    ),
    entry(L2C_ERR_STS, "L2C_ERR_STS", Class::Status, L2C_ERROR_STATUS),
    entry(L2C_ERR_ADR, "L2C_ERR_ADR", Class::Record, L2C_ERROR_RECORD),
    entry(L2C_ERR_INF, "L2C_ERR_INF", Class::Record, L2C_ERROR_RECORD),
    // The uncore performance monitor, one per cluster.
    entry(UPMCR0, "UPMCR0", Class::Control, UNCORE_CONTROL)
        .cluster()
        .permitting(UPMCR0_PERMITTED),
    entry(UPMESR0_EL1, "UPMESR0_EL1", Class::Storage, UNCORE_SELECT).cluster(),
    entry(UPMESR1_EL1, "UPMESR1_EL1", Class::Storage, UNCORE_SELECT).cluster(),
    entry(UPMECM0_EL1, "UPMECM0_EL1", Class::Storage, UNCORE_SELECT).cluster(),
    entry(UPMECM1_EL1, "UPMECM1_EL1", Class::Storage, UNCORE_SELECT).cluster(),
    entry(UPMECM2_EL1, "UPMECM2_EL1", Class::Storage, UNCORE_SELECT).cluster(),
    entry(UPMECM3_EL1, "UPMECM3_EL1", Class::Storage, UNCORE_SELECT).cluster(),
    entry(UPMPCM_EL1, "UPMPCM_EL1", Class::Storage, UNCORE_SELECT).cluster(),
    entry(UPMSR, "UPMSR", Class::Status, UNCORE_STATUS).cluster(),
    entry(UPMC0, "UPMC0", Class::Counter, UNCORE_COUNTER).cluster(),
    entry(UPMC1, "UPMC1", Class::Counter, UNCORE_COUNTER).cluster(),
    entry(UPMC2, "UPMC2", Class::Counter, UNCORE_COUNTER).cluster(),
    entry(UPMC3, "UPMC3", Class::Counter, UNCORE_COUNTER).cluster(),
    entry(UPMC4, "UPMC4", Class::Counter, UNCORE_COUNTER).cluster(),
    entry(UPMC5, "UPMC5", Class::Counter, UNCORE_COUNTER).cluster(),
    entry(UPMC6, "UPMC6", Class::Counter, UNCORE_COUNTER).cluster(),
    entry(UPMC7, "UPMC7", Class::Counter, UNCORE_COUNTER).cluster(),
    entry(UPMC8, "UPMC8", Class::Counter, UNCORE_COUNTER).cluster(),
    entry(UPMC9, "UPMC9", Class::Counter, UNCORE_COUNTER).cluster(),
    entry(UPMC10, "UPMC10", Class::Counter, UNCORE_COUNTER).cluster(),
    entry(UPMC11, "UPMC11", Class::Counter, UNCORE_COUNTER).cluster(),
    entry(UPMC12, "UPMC12", Class::Counter, UNCORE_COUNTER).cluster(),
    entry(UPMC13, "UPMC13", Class::Counter, UNCORE_COUNTER).cluster(),
    entry(UPMC14, "UPMC14", Class::Counter, UNCORE_COUNTER).cluster(),
    entry(UPMC15, "UPMC15", Class::Counter, UNCORE_COUNTER).cluster(),
    // AppleT8112CLPC's core, memory-stall and cluster samplers and the
    // energy accumulators.
    entry(
        AON_ENABLE,
        "S3_7_C15_C5_0 (unnamed)",
        Class::Control,
        AON_ENABLE_EVIDENCE,
    ),
    entry(
        AON_SELECT_0,
        "S3_7_C15_C1_3 (unnamed)",
        Class::Storage,
        AON_SELECT_EVIDENCE,
    ),
    entry(
        AON_SELECT_1,
        "S3_7_C15_C3_3 (unnamed)",
        Class::Storage,
        AON_SELECT_EVIDENCE,
    ),
    entry(
        AON_SELECT_2,
        "S3_7_C15_C5_3 (unnamed)",
        Class::Storage,
        AON_SELECT_EVIDENCE,
    ),
    entry(
        AON_COUNTER_0,
        "S3_7_C15_C0_3 (unnamed)",
        Class::Counter,
        AON_COUNTER_EVIDENCE,
    ),
    entry(
        AON_COUNTER_1,
        "S3_7_C15_C2_3 (unnamed)",
        Class::Counter,
        AON_COUNTER_EVIDENCE,
    ),
    entry(
        AON_COUNTER_2,
        "S3_7_C15_C4_3 (unnamed)",
        Class::Counter,
        AON_COUNTER_EVIDENCE,
    ),
    entry(
        MEM_STALL_SELECT_0,
        "S3_1_C15_C0_3 (unnamed)",
        Class::Control,
        MEM_STALL_SELECT_EVIDENCE,
    ),
    entry(
        MEM_STALL_SELECT_1,
        "S3_1_C15_C1_3 (unnamed)",
        Class::Control,
        MEM_STALL_SELECT_EVIDENCE,
    ),
    entry(
        MEM_STALL_COUNTER_0,
        "S3_1_C15_C8_3 (unnamed)",
        Class::Counter,
        MEM_STALL_COUNTER_EVIDENCE,
    ),
    entry(
        MEM_STALL_COUNTER_1,
        "S3_1_C15_C9_3 (unnamed)",
        Class::Counter,
        MEM_STALL_COUNTER_EVIDENCE,
    ),
    entry(
        MEM_STALL_COUNTER_2,
        "S3_1_C15_C10_3 (unnamed)",
        Class::Counter,
        MEM_STALL_COUNTER_EVIDENCE,
    ),
    entry(
        MEM_STALL_COUNTER_3,
        "S3_1_C15_C11_3 (unnamed)",
        Class::Counter,
        MEM_STALL_COUNTER_EVIDENCE,
    ),
    entry(
        CLUSTER_COUNTER_C0,
        "S3_7_C15_C0_2 (unnamed)",
        Class::Unsupported,
        CLUSTER_COUNTER_EVIDENCE,
    ),
    entry(
        CLUSTER_COUNTER_C2,
        "S3_7_C15_C2_2 (unnamed)",
        Class::Unsupported,
        CLUSTER_COUNTER_EVIDENCE,
    ),
    entry(
        CLUSTER_COUNTER_C4,
        "S3_7_C15_C4_2 (unnamed)",
        Class::Unsupported,
        CLUSTER_COUNTER_EVIDENCE,
    ),
    entry(
        CLUSTER_COUNTER_C6,
        "S3_7_C15_C6_2 (unnamed)",
        Class::Unsupported,
        CLUSTER_COUNTER_EVIDENCE,
    ),
    entry(
        CLUSTER_COUNTER_C8,
        "S3_7_C15_C8_2 (unnamed)",
        Class::Unsupported,
        CLUSTER_COUNTER_EVIDENCE,
    ),
    entry(
        CLUSTER_COUNTER_C10,
        "S3_7_C15_C10_2 (unnamed)",
        Class::Unsupported,
        CLUSTER_COUNTER_EVIDENCE,
    ),
    entry(
        CLUSTER_COUNTER_C12,
        "S3_7_C15_C12_2 (unnamed)",
        Class::Unsupported,
        CLUSTER_COUNTER_EVIDENCE,
    ),
    entry(
        CORE_NRG_ACC_DAT,
        "CORE_NRG_ACC_DAT",
        Class::Unsupported,
        ENERGY_EVIDENCE,
    ),
    entry(
        CORE_SRM_NRG_ACC_DAT,
        "CORE_SRM_NRG_ACC_DAT",
        Class::Unsupported,
        ENERGY_EVIDENCE,
    ),
    // Per-thread Rosetta (TSO) state, nested-virtualization and
    // guarded-level syndromes.
    entry(
        TSO_THREAD_FLAGS,
        "S3_6_C15_C8_3 (unnamed)",
        Class::Control,
        TSO_THREAD_EVIDENCE,
    ),
    entry(
        TSO_THREAD_CONTROL,
        "S3_6_C15_C2_5 (unnamed)",
        Class::Control,
        TSO_THREAD_EVIDENCE,
    ),
    entry(
        NESTED_PAGE,
        "S3_4_C15_C10_7 (unnamed)",
        Class::Control,
        NESTED_PAGE_EVIDENCE,
    )
    .el2(),
    entry(
        GUARDED_HPFAR,
        "S3_6_C15_C1_1 (unnamed)",
        Class::Record,
        GUARDED_HPFAR_EVIDENCE,
    )
    .el2(),
    entry(
        GUARDED_AFSR1,
        "S3_6_C15_C0_2 (unnamed)",
        Class::Record,
        GUARDED_AFSR1_EVIDENCE,
    )
    .el2(),
    entry(
        GUEST_AFSR1,
        "S3_6_C15_C0_3 (unnamed)",
        Class::Control,
        GUEST_AFSR1_EVIDENCE,
    )
    .el2(),
    // The hypervisor's VM state.
    entry(
        APVMKEYLO_EL2,
        "APVMKEYLO_EL2",
        Class::Storage,
        VM_KEY_EVIDENCE,
    )
    .el2(),
    entry(
        APVMKEYHI_EL2,
        "APVMKEYHI_EL2",
        Class::Storage,
        VM_KEY_EVIDENCE,
    )
    .el2(),
    entry(APSTS_EL12, "APSTS_EL12", Class::Storage, VM_STATUS_EVIDENCE).el2(),
    entry(
        GUEST_RANGE_COMMAND,
        "S3_4_C15_C15_1 (unnamed)",
        Class::Unsupported,
        GUEST_RANGE_EVIDENCE,
    )
    .el2(),
    guest(GUEST_C2_6, "S3_4_C15_C2_6 (unnamed)"),
    guest(GUEST_C8_0, "S3_4_C15_C8_0 (unnamed)"),
    guest(GUEST_C8_1, "S3_4_C15_C8_1 (unnamed)"),
    guest(GUEST_C8_2, "S3_4_C15_C8_2 (unnamed)"),
    guest(GUEST_C8_3, "S3_4_C15_C8_3 (unnamed)"),
    guest(GUEST_C9_0, "S3_4_C15_C9_0 (unnamed)"),
    guest(GUEST_C9_1, "S3_4_C15_C9_1 (unnamed)"),
    guest(GUEST_C9_2, "S3_4_C15_C9_2 (unnamed)"),
    guest(GUEST_C9_3, "S3_4_C15_C9_3 (unnamed)"),
    guest(GUEST_C9_4, "S3_4_C15_C9_4 (unnamed)"),
    guest(GUEST_C9_5, "S3_4_C15_C9_5 (unnamed)"),
    guest(GUEST_C14_0, "S3_4_C15_C14_0 (unnamed)"),
    guest(GUEST_C14_1, "S3_4_C15_C14_1 (unnamed)"),
    guest(GUEST_C14_2, "S3_4_C15_C14_2 (unnamed)"),
    guest(GUEST_C14_3, "S3_4_C15_C14_3 (unnamed)"),
    guest(GUEST_C15_2, "S3_4_C15_C15_2 (unnamed)"),
    guest(GUEST_C15_5, "S3_4_C15_C15_5 (unnamed)"),
    guest(GUEST_VGIC, "S3_5_C15_C1_2 (unnamed)"),
    guest(GUEST_KEY_C2_1, "S3_6_C15_C2_1 (unnamed)"),
    guest(GUEST_KEY_C2_2, "S3_6_C15_C2_2 (unnamed)"),
    guest(GUEST_KEY_C2_3, "S3_6_C15_C2_3 (unnamed)"),
    guest(GUEST_KEY_C2_4, "S3_6_C15_C2_4 (unnamed)"),
    guest(GUEST_SPRR_C6_0, "S3_6_C15_C6_0 (unnamed)"),
    guest(GUEST_SPRR_C6_1, "S3_6_C15_C6_1 (unnamed)"),
    guest(GUEST_SPRR_C6_2, "S3_6_C15_C6_2 (unnamed)"),
    guest(GUEST_SPRR_C6_3, "S3_6_C15_C6_3 (unnamed)"),
    guest(GUEST_KEY_C7_0, "S3_6_C15_C7_0 (unnamed)"),
    guest(GUEST_KEY_C7_1, "S3_6_C15_C7_1 (unnamed)"),
    guest(GUEST_KEY_C7_2, "S3_6_C15_C7_2 (unnamed)"),
    guest(GUEST_KEY_C7_3, "S3_6_C15_C7_3 (unnamed)"),
    guest(GUEST_KEY_C7_4, "S3_6_C15_C7_4 (unnamed)"),
    guest(GUEST_KEY_C7_5, "S3_6_C15_C7_5 (unnamed)"),
    guest(GUEST_KEY_C7_6, "S3_6_C15_C7_6 (unnamed)"),
    guest(GUEST_KEY_C7_7, "S3_6_C15_C7_7 (unnamed)"),
    guest(GUEST_C12_7, "S3_6_C15_C12_7 (unnamed)"),
    guest(GUEST_SPRR_C15_4, "S3_6_C15_C15_4 (unnamed)"),
    guest(GUEST_SPRR_C15_5, "S3_6_C15_C15_5 (unnamed)"),
];

const fn guest(encoding: Encoding, name: &'static str) -> Entry {
    entry(encoding, name, Class::Guest, GUEST_EVIDENCE).el2()
}

pub fn lookup(encoding: Encoding) -> Option<&'static Entry> {
    TABLE.iter().find(|entry| entry.encoding == encoding)
}

/// Values and use counts of the table's registers.
#[derive(Debug, Clone, Default)]
pub struct Registers {
    values: BTreeMap<u16, u64>,
    /// The `Scope::Cluster` values, shared with the cluster's other PEs.
    cluster: Rc<RefCell<BTreeMap<u16, u64>>>,
    pub reads: BTreeMap<u16, u64>,
    pub writes: BTreeMap<u16, u64>,
}

impl Registers {
    /// Share `other`'s cluster registers: a PE starting in a cluster that
    /// already has a powered PE.
    pub fn join(&mut self, other: &Self) {
        self.cluster = other.cluster.clone();
    }

    fn stored(&self, entry: &Entry) -> Option<u64> {
        let key = entry.encoding.selector();
        match entry.scope {
            Scope::Pe => self.values.get(&key).copied(),
            Scope::Cluster => self.cluster.borrow().get(&key).copied(),
        }
    }

    /// A read, or why it cannot complete.
    pub fn read(&mut self, entry: &Entry) -> Result<u64, &'static str> {
        if entry.class == Class::Unsupported {
            return Err(entry.evidence);
        }
        let key = entry.encoding.selector();
        *self.reads.entry(key).or_default() += 1;
        match (self.stored(entry), entry.class) {
            (_, Class::Status | Class::Record) => Ok(0),
            (Some(value), _) => Ok(value),
            (None, Class::Storage | Class::Guest) => {
                Err("read of an implementation-defined storage register before its first write")
            }
            (None, _) => Ok(0),
        }
    }

    /// A write, or why it cannot complete.
    pub fn write(&mut self, entry: &Entry, value: u64) -> Result<(), &'static str> {
        match entry.class {
            Class::Unsupported => return Err(entry.evidence),
            Class::Record => {
                return Err("write of an implementation-defined record no consumer writes");
            }
            Class::Control if value & !entry.permitted != 0 => {
                return Err(
                    "implementation-defined control bit for a feature or event this machine \
                     does not model",
                );
            }
            _ => {}
        }
        let key = entry.encoding.selector();
        *self.writes.entry(key).or_default() += 1;
        // A status register records nothing, so a clearing write leaves it 0.
        if entry.class != Class::Status {
            match entry.scope {
                Scope::Pe => self.values.insert(key, value),
                Scope::Cluster => self.cluster.borrow_mut().insert(key, value),
            };
        }
        Ok(())
    }

    /// The first `Guest` register holding a nonzero value: state an EL1&0
    /// guest would run without.
    pub fn guest_state(&self) -> Option<&'static Entry> {
        TABLE.iter().find(|entry| {
            entry.class == Class::Guest && self.stored(entry).is_some_and(|value| value != 0)
        })
    }

    /// (entry, reads, writes) for every register the guest touched.
    pub fn used(&self) -> impl Iterator<Item = (&'static Entry, u64, u64)> + '_ {
        TABLE.iter().filter_map(|entry| {
            let key = entry.encoding.selector();
            let reads = self.reads.get(&key).copied().unwrap_or(0);
            let writes = self.writes.get(&key).copied().unwrap_or(0);
            (reads + writes > 0).then_some((entry, reads, writes))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeSet;

    #[test]
    fn storage_refuses_reads_before_writes_and_tuning_starts_at_zero() {
        let mut registers = Registers::default();
        let storage = lookup(SPTM_CONTEXT).unwrap();
        assert!(registers.read(storage).is_err());
        registers.write(storage, 2).unwrap();
        assert_eq!(registers.read(storage), Ok(2));
        let control = lookup(THREAD_CONTROL).unwrap();
        assert_eq!(registers.read(control), Ok(0));
        registers.write(control, 0).unwrap();
        assert!(registers.write(control, 2).is_err());
        let tuning = entry(
            Encoding::new(3, 0, IMPDEF_CRN, 0, 0),
            "HID0",
            Class::Tuning,
            "test",
        );
        assert_eq!(registers.read(&tuning), Ok(0));
        assert_eq!(
            registers.used().count(),
            2,
            "only table entries are reported"
        );
    }

    #[test]
    fn every_entry_is_a_distinct_crn_15_encoding_with_evidence() {
        let mut seen = BTreeSet::new();
        for entry in TABLE {
            assert_eq!(entry.encoding.op0(), 3);
            assert_eq!(entry.encoding.crn(), IMPDEF_CRN);
            assert!(!entry.evidence.is_empty());
            assert!(seen.insert(entry.encoding.selector()), "{}", entry.name);
            assert!(entry.permitted == 0 || entry.class == Class::Control);
        }
    }

    /// Error records report no error and take their clearing writes; the
    /// information registers refuse writes.
    #[test]
    fn error_records_read_zero_and_clearing_writes_change_nothing() {
        let mut registers = Registers::default();
        let status = lookup(L2C_ERR_STS).unwrap();
        // _llcErrorHandler's write-one-to-clear of the bit it handled.
        registers.write(status, 1).unwrap();
        assert_eq!(registers.read(status), Ok(0));
        for encoding in [LSU_ERR_STS, E_FED_ERR_STS, MMU_ERR_STS, DPC_ERR_STS] {
            assert_eq!(registers.read(lookup(encoding).unwrap()), Ok(0));
        }
        let record = lookup(L2C_ERR_ADR).unwrap();
        assert_eq!(registers.read(record), Ok(0));
        assert!(registers.write(record, 0).is_err());
    }

    /// XNU's uncore initialization value is taken; counting is not. The
    /// counters and selections are one per cluster.
    #[test]
    fn the_uncore_monitor_takes_xnus_initialization_and_shares_a_cluster() {
        const XNU_UPMCR0: u64 = 0xf_fff4_0000;
        let mut first = Registers::default();
        let control = lookup(UPMCR0).unwrap();
        first.write(control, XNU_UPMCR0).unwrap();
        assert_eq!(first.read(control), Ok(XNU_UPMCR0));
        // A counter enable, or AIC interrupt mode 2.
        assert!(first.write(control, XNU_UPMCR0 | 1).is_err());
        assert!(first.write(control, 2 << 16).is_err());
        let counter = lookup(UPMC3).unwrap();
        assert_eq!(first.read(counter), Ok(0));
        first.write(counter, 0x1234).unwrap();
        let mut second = Registers::default();
        second.join(&first);
        assert_eq!(second.read(counter), Ok(0x1234));
        let status = lookup(UPMSR).unwrap();
        second.write(status, 0).unwrap();
        assert_eq!(second.read(status), Ok(0));
        // A PE of another cluster has its own.
        let mut other = Registers::default();
        assert_eq!(other.read(counter), Ok(0));
    }

    /// CLPC's samplers can only be disabled; their counters hold what
    /// software writes. Cluster counters and energy refuse.
    #[test]
    fn clpc_counters_stay_disabled_and_energy_refuses() {
        let mut registers = Registers::default();
        let enable = lookup(AON_ENABLE).unwrap();
        registers.write(enable, 0).unwrap();
        assert!(registers.write(enable, 1).is_err());
        registers
            .write(lookup(AON_SELECT_0).unwrap(), 0x8000)
            .unwrap();
        let select = lookup(MEM_STALL_SELECT_0).unwrap();
        assert!(registers.write(select, 0x801).is_err());
        let counter = lookup(MEM_STALL_COUNTER_2).unwrap();
        assert_eq!(registers.read(counter), Ok(0));
        registers.write(counter, 0).unwrap();
        for encoding in [CORE_NRG_ACC_DAT, CORE_SRM_NRG_ACC_DAT, CLUSTER_COUNTER_C6] {
            let entry = lookup(encoding).unwrap();
            assert_eq!(registers.read(entry), Err(entry.evidence));
            assert!(registers.write(entry, 0).is_err());
        }
    }

    #[test]
    fn nonzero_guest_state_is_reported() {
        let mut registers = Registers::default();
        assert!(registers.guest_state().is_none());
        let guest = lookup(GUEST_SPRR_C15_4).unwrap();
        assert!(guest.el2);
        // SPTM's host-restore clears and the hypervisor's zero loads.
        registers.write(guest, 0).unwrap();
        assert!(registers.guest_state().is_none());
        registers.write(guest, 0x3b).unwrap();
        assert_eq!(
            registers.guest_state().map(|entry| entry.encoding),
            Some(GUEST_SPRR_C15_4)
        );
        // The VM keys follow the PAC regime: stored, not guest state.
        registers.write(lookup(APVMKEYLO_EL2).unwrap(), 5).unwrap();
        registers.write(guest, 0).unwrap();
        assert!(registers.guest_state().is_none());
    }
}
