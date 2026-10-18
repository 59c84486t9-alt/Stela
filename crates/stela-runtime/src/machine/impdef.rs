//! Apple implementation-defined registers that have no architectural effect
//! this machine models, each listed with its evidence. Every other
//! implementation-defined encoding still refuses.
//!
//! - `Storage`: software saves and restores the register around its own
//!   changes, so reads must return the last value written. A read before the
//!   first write refuses, because the reset value is unknown.
//! - `Tuning`: a core tuning ("chicken bit") register, named by m1n1
//!   `cpu_regs.h` or used only in the same boot-time pattern, or a
//!   performance hint to the core's predictors. Software reads it, sets or
//!   clears bits and writes it back, or saves and restores it.
//!   The reset value is unknown and taken as 0 (inference). No bit has an
//!   effect here.
//! - `Scratch`: a register software keeps its own records in, with no
//!   hardware effect. Reads return the last value written, 0 from cold
//!   reset (inference).
//! - `Control`: a control register whose bits select features this machine
//!   does not advertise. It reads 0 from reset (inference) and takes only
//!   values with no bit set; any set bit stops, as for ACTLR_EL1.
//!
//! The run reports every entry the guest used, so none of these is silent.
use alloc::collections::BTreeMap;
use stela_compiler::aarch64::system::registers::Encoding;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Storage,
    Tuning,
    Scratch,
    Control,
}

pub struct Entry {
    pub encoding: Encoding,
    pub name: &'static str,
    pub class: Class,
    pub evidence: &'static str,
}

const fn entry(
    op1: u8,
    crn: u8,
    crm: u8,
    op2: u8,
    name: &'static str,
    class: Class,
    evidence: &'static str,
) -> Entry {
    Entry {
        encoding: Encoding::new(3, op1, crn, crm, op2),
        name,
        class,
        evidence,
    }
}

const SPTM_CONTEXT: &str = "SPTM 26A434 saves and restores it with SCTLR_EL1 and TCR_EL1 \
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
    read-modify-write at boot, selected by MPIDR core type next to its HID writes";

const SPTM_GXF_MASK: &str = "SPTM 26A434 writes it once per CPU at boot with the value it \
    writes to S3_1_C15_C8_2 (0x30300 or 0x3_0300_00ff_ff00, __text+0x1bebc) and reads it \
    nowhere; TXM and the kernel never touch it";

const VM_CONTEXT: &str = "SPTM 26A434 writes it once per CPU at boot (__text+0x1bec8); the \
    26A434 kernel only saves and restores it with a VM's GL12 registers \
    (0xfffffe000bd9eddc, 0xfffffe000bda2bb4)";

const ACC_CFG: &str = "m1n1 cpu_regs.h names it, with the branch-predictor sleep field \
    ACC_CFG_BP_SLEEP (bits 2-3), which 26A434 XNU sets with read-modify-write \
    (0xfffffe000bb9c8e0); the engine keeps no predictor state to retain";

const ACC_OVRD: &str = "m1n1 cpu_regs.h names it; XNU xnu-12377.121.6 machine_routines_asm.s \
    sets its deep-sleep fields (xnu-6153.141.1 arm64_common.h ARM64_REG_ACC_OVRD_*) before a \
    deep-sleep power-down, which acts only when the cluster powers down, and core power-down \
    stops (CYC_OVRD)";

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

pub const TABLE: &[Entry] = &[
    entry(
        5,
        15,
        1,
        4,
        "S3_5_C15_C1_4 (unnamed)",
        Class::Control,
        XNU_SWITCH_CLEARS,
    ),
    entry(
        5,
        15,
        10,
        1,
        "S3_5_C15_C10_1 (unnamed)",
        Class::Control,
        XNU_TRACE_CLEARS,
    ),
    entry(
        4,
        15,
        15,
        6,
        "S3_4_C15_C15_6 (unnamed)",
        Class::Control,
        XNU_THREAD_PERMISSIONS,
    ),
    entry(
        6,
        15,
        0,
        4,
        "BP_OBJC_ADR_EL1",
        Class::Tuning,
        OBJC_BRANCH_HINT,
    ),
    entry(
        6,
        15,
        0,
        5,
        "BP_OBJC_CTL_EL1",
        Class::Tuning,
        OBJC_BRANCH_HINT,
    ),
    entry(5, 15, 4, 0, "ACC_CFG", Class::Tuning, ACC_CFG),
    entry(5, 15, 6, 0, "ACC_OVRD", Class::Tuning, ACC_OVRD),
    entry(4, 15, 10, 4, "SIQ_CFG_EL1", Class::Tuning, SIQ_CFG),
    entry(
        4,
        15,
        13,
        6,
        "S3_4_C15_C13_6 (unnamed)",
        Class::Storage,
        XNU_THREAD_KEYS,
    ),
    entry(
        4,
        15,
        13,
        7,
        "S3_4_C15_C13_7 (unnamed)",
        Class::Storage,
        XNU_THREAD_KEYS,
    ),
    entry(5, 15, 2, 6, "WATCHDOG_DIAG0", Class::Scratch, WATCHDOG_DIAG),
    entry(
        4,
        15,
        12,
        0,
        "S3_4_C15_C12_0 (unnamed)",
        Class::Control,
        XNU_THREAD_CONTROL,
    ),
    entry(
        4,
        15,
        0,
        1,
        "S3_4_C15_C0_1 (unnamed)",
        Class::Tuning,
        SPTM_CORE_TUNING,
    ),
    entry(
        4,
        15,
        0,
        3,
        "S3_4_C15_C0_3 (unnamed)",
        Class::Tuning,
        SPTM_CORE_TUNING,
    ),
    entry(0, 15, 0, 1, "EHID0", Class::Tuning, M1N1_TUNING),
    entry(0, 15, 0, 3, "HID26", Class::Tuning, M1N1_TUNING),
    entry(0, 15, 0, 4, "HID27", Class::Tuning, M1N1_TUNING),
    entry(0, 15, 1, 0, "HID1", Class::Tuning, M1N1_TUNING),
    entry(0, 15, 1, 3, "HID21", Class::Tuning, M1N1_TUNING),
    entry(0, 15, 3, 0, "HID3", Class::Tuning, M1N1_TUNING),
    entry(0, 15, 4, 0, "HID4", Class::Tuning, M1N1_TUNING),
    entry(0, 15, 4, 1, "EHID4", Class::Tuning, M1N1_TUNING),
    entry(0, 15, 5, 0, "HID5", Class::Tuning, M1N1_TUNING),
    entry(0, 15, 7, 0, "HID7", Class::Tuning, M1N1_TUNING),
    entry(0, 15, 9, 0, "HID9", Class::Tuning, M1N1_TUNING),
    entry(0, 15, 9, 1, "EHID9", Class::Tuning, M1N1_TUNING),
    entry(0, 15, 10, 0, "HID10", Class::Tuning, M1N1_TUNING),
    entry(0, 15, 10, 1, "EHID10", Class::Tuning, M1N1_TUNING),
    entry(0, 15, 11, 0, "HID11", Class::Tuning, M1N1_TUNING),
    entry(0, 15, 11, 2, "HID18", Class::Tuning, M1N1_TUNING),
    entry(0, 15, 11, 3, "EHID18", Class::Tuning, M1N1_TUNING),
    entry(0, 15, 14, 0, "HID13", Class::Tuning, M1N1_TUNING),
    entry(0, 15, 15, 0, "HID14", Class::Tuning, M1N1_TUNING),
    entry(0, 15, 15, 2, "HID16", Class::Tuning, M1N1_TUNING),
    entry(
        4,
        15,
        15,
        4,
        "S3_4_C15_C15_4 (unnamed)",
        Class::Storage,
        SPTM_CONTEXT,
    ),
    entry(
        4,
        15,
        10,
        0,
        "S3_4_C15_C10_0 (unnamed)",
        Class::Storage,
        SPTM_KEY_WRITES,
    ),
    entry(
        4,
        15,
        10,
        1,
        "S3_4_C15_C10_1 (unnamed)",
        Class::Storage,
        SPTM_KEY_WRITES,
    ),
    entry(
        4,
        15,
        10,
        2,
        "S3_4_C15_C10_2 (unnamed)",
        Class::Storage,
        SPTM_KEY_WRITES,
    ),
    entry(
        4,
        15,
        10,
        3,
        "S3_4_C15_C10_3 (unnamed)",
        Class::Storage,
        SPTM_KEY_WRITES,
    ),
    entry(4, 15, 5, 0, "AMX_CTX_EL1", Class::Storage, XNU_AMX_CONTEXT),
    entry(
        6,
        15,
        8,
        5,
        "S3_6_C15_C8_5 (unnamed)",
        Class::Storage,
        SPTM_GXF_MASK,
    ),
    entry(
        1,
        15,
        8,
        2,
        "S3_1_C15_C8_2 (unnamed)",
        Class::Storage,
        VM_CONTEXT,
    ),
];

pub fn lookup(encoding: Encoding) -> Option<&'static Entry> {
    TABLE.iter().find(|entry| entry.encoding == encoding)
}

/// Values and use counts of the table's registers.
#[derive(Debug, Clone, Default)]
pub struct Registers {
    values: BTreeMap<u16, u64>,
    pub reads: BTreeMap<u16, u64>,
    pub writes: BTreeMap<u16, u64>,
}

impl Registers {
    /// `None` when a storage register is read before its first write.
    pub fn read(&mut self, entry: &Entry) -> Option<u64> {
        let key = entry.encoding.selector();
        *self.reads.entry(key).or_default() += 1;
        match (self.values.get(&key), entry.class) {
            (Some(value), _) => Some(*value),
            (None, Class::Tuning | Class::Scratch | Class::Control) => Some(0),
            (None, Class::Storage) => None,
        }
    }

    /// A write, or why it cannot complete.
    pub fn write(&mut self, entry: &Entry, value: u64) -> Result<(), &'static str> {
        if entry.class == Class::Control && value != 0 {
            return Err(
                "implementation-defined control bit for a feature this machine does not advertise",
            );
        }
        let key = entry.encoding.selector();
        *self.writes.entry(key).or_default() += 1;
        self.values.insert(key, value);
        Ok(())
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

    #[test]
    fn storage_refuses_reads_before_writes_and_tuning_starts_at_zero() {
        let mut registers = Registers::default();
        let storage = lookup(Encoding::new(3, 4, 15, 15, 4)).unwrap();
        assert_eq!(registers.read(storage), None);
        registers.write(storage, 2).unwrap();
        assert_eq!(registers.read(storage), Some(2));
        let control = lookup(Encoding::new(3, 4, 15, 12, 0)).unwrap();
        assert_eq!(registers.read(control), Some(0));
        registers.write(control, 0).unwrap();
        assert!(registers.write(control, 2).is_err());
        let tuning = Entry {
            encoding: Encoding::new(3, 0, 15, 0, 0),
            name: "HID0",
            class: Class::Tuning,
            evidence: "test",
        };
        assert_eq!(registers.read(&tuning), Some(0));
        assert_eq!(
            registers.used().count(),
            2,
            "only table entries are reported"
        );
        for entry in TABLE {
            assert_eq!(entry.encoding.op0(), 3);
            assert_eq!(entry.encoding.crn(), 15);
            assert!(!entry.evidence.is_empty());
        }
    }
}
