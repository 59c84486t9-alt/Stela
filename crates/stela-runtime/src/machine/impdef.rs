//! Apple implementation-defined registers that have no architectural effect
//! this machine models, each listed with its evidence. Every other
//! implementation-defined encoding still refuses.
//!
//! - `Storage`: software saves and restores the register around its own
//!   changes, so reads must return the last value written. A read before the
//!   first write refuses, because the reset value is unknown.
//! - `Tuning`: a core tuning ("chicken bit") register, named by m1n1
//!   `cpu_regs.h` or used only in the same boot-time pattern. Software reads
//!   it, sets or clears bits and writes it back.
//!   The reset value is unknown and taken as 0 (inference). No bit has an
//!   effect here.
//!
//! The run reports every entry the guest used, so none of these is silent.
use alloc::collections::BTreeMap;
use stela_compiler::aarch64::system::registers::Encoding;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Storage,
    Tuning,
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

const XNU_AMX_CONTEXT: &str = "26A434 XNU CPU initialization writes MPIDR.Aff0 to it \
    under one boot configuration (0xfffffe000bd80f44) and reads it nowhere; named AMX_CTX_EL1 \
    beside AMX_CTL_EL1 (docs/research/amx.md)";

const SPTM_CORE_TUNING: &str = "no public name; SPTM 26A434 clears one bit with \
    read-modify-write at boot, selected by MPIDR core type next to its HID writes";

pub const TABLE: &[Entry] = &[
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
            (None, Class::Tuning) => Some(0),
            (None, Class::Storage) => None,
        }
    }

    pub fn write(&mut self, entry: &Entry, value: u64) {
        let key = entry.encoding.selector();
        *self.writes.entry(key).or_default() += 1;
        self.values.insert(key, value);
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
        registers.write(storage, 2);
        assert_eq!(registers.read(storage), Some(2));
        let tuning = Entry {
            encoding: Encoding::new(3, 0, 15, 0, 0),
            name: "HID0",
            class: Class::Tuning,
            evidence: "test",
        };
        assert_eq!(registers.read(&tuning), Some(0));
        assert_eq!(
            registers.used().count(),
            1,
            "only table entries are reported"
        );
        for entry in TABLE {
            assert_eq!(entry.encoding.op0(), 3);
            assert_eq!(entry.encoding.crn(), 15);
            assert!(!entry.evidence.is_empty());
        }
    }
}
