//! The pinned Mach-trap catalog: index, routine name, argument count and
//! port-return flag for every negative-`x16` Mach trap.
//!
//! The rows in [`generated`] come from xnu's `osfmk/kern/syscall_sw.c`
//! `mach_trap_table`. A userspace Mach trap passes `x16 = -index`; the kernel
//! (`mach_syscall`) indexes the table by that positive index and reads the
//! row's argument count of 64-bit registers on the arm64 path. Rows whose
//! routine is `kern_invalid` are reserved slots the kernel refuses.
//!
//! Provenance matches the [BSD catalog](crate::darwin::catalog): the newest
//! public xnu (`xnu-12377.121.6`). The pinned 26A434 kernel is
//! `xnu-13432.1.9`; the Mach-trap indices libSystem startup uses are stable.
use super::Request;

mod generated;

/// A `kern_invalid` slot: a real index with no routine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reserved {
    No,
    Yes,
}

/// One row of the Mach-trap table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MachTrapEntry {
    pub index: u32,
    pub name: &'static str,
    pub argument_count: usize,
    pub returns_port: bool,
    pub reserved: Reserved,
}

/// The kernel distribution the catalog was generated from.
pub const SOURCE: &str = "xnu-12377.121.6 osfmk/kern/syscall_sw.c";

/// The catalog row for a Mach-trap index, implemented or reserved; `None`
/// past the table's end.
pub fn entry(index: u32) -> Option<&'static MachTrapEntry> {
    generated::CATALOG.get(index as usize)
}

/// The routine name of a Mach-trap index, reserved or not; `None` past the
/// table's end.
pub fn name(index: u32) -> Option<&'static str> {
    entry(index).map(|entry| entry.name)
}

/// The number of 64-bit argument registers an implemented Mach trap reads;
/// `None` for a reserved index or one past the table.
pub fn argument_count(index: u32) -> Option<usize> {
    entry(index)
        .filter(|entry| entry.reserved == Reserved::No)
        .map(|entry| entry.argument_count)
}

impl Request {
    /// Whether this captured trap's number and argument count agree with the
    /// pinned Mach-trap table.
    pub fn matches_catalog(&self) -> bool {
        argument_count(self.number) == Some(self.arguments.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_the_full_dense_trap_table() {
        let catalog = generated::CATALOG;
        // The table is MACH_TRAP_TABLE_COUNT entries, dense from zero.
        assert_eq!(catalog.len(), 128);
        for (index, entry) in catalog.iter().enumerate() {
            assert_eq!(entry.index as usize, index);
        }
    }

    #[test]
    fn bootstrap_port_traps_match_the_pinned_table() {
        for (index, name) in [
            (super::super::REPLY_PORT_TRAP, "mach_reply_port"),
            (super::super::THREAD_SELF_TRAP, "thread_self_trap"),
            (super::super::TASK_SELF_TRAP, "task_self_trap"),
            (super::super::HOST_SELF_TRAP, "host_self_trap"),
        ] {
            let entry = entry(index).unwrap();
            assert_eq!(entry.name, name);
            assert_eq!(entry.reserved, Reserved::No);
            assert!(entry.returns_port, "{name} returns a port");
            assert_eq!(entry.argument_count, 0);
            assert_eq!(argument_count(index), Some(0));
        }
    }

    #[test]
    fn argument_counts_follow_the_arm64_branch() {
        // mach_msg2_trap (47) takes the __arm64__ branch: eight arguments.
        assert_eq!(entry(47).unwrap().name, "mach_msg2_trap");
        assert_eq!(argument_count(47), Some(8));
        // mach_msg_trap (31) takes seven.
        assert_eq!(argument_count(31), Some(7));
        // mach_vm_allocate (10) takes four and returns no port.
        let allocate = entry(10).unwrap();
        assert_eq!(allocate.argument_count, 4);
        assert!(!allocate.returns_port);
    }

    #[test]
    fn invalid_slots_are_reserved_and_absent_past_the_end() {
        // Index 0 and the 1xx tail are kern_invalid.
        assert_eq!(entry(0).unwrap().reserved, Reserved::Yes);
        assert!(argument_count(0).is_none());
        assert_eq!(entry(30).unwrap().reserved, Reserved::Yes);
        assert!(entry(128).is_none());
        assert!(name(128).is_none());
        assert!(argument_count(128).is_none());
    }
}
