//! The pinned BSD system-call catalog: number, name, argument count and
//! return-register munging for every `SVC #0x80` BSD call.
//!
//! The rows in [`generated`] are produced from xnu's
//! `bsd/kern/syscalls.master` exactly as `makesyscalls.sh` derives the
//! `sysent` table: the argument count is the number of C parameters, each one
//! 64-bit register slot under the arm64 LP64 ABI (`void` is zero), and the
//! return type is the same `sy_return_type` munging. Services derive and
//! check their prototypes against this one table instead of hand-copying
//! numbers, and the dispatcher can name an unimplemented or reserved call
//! rather than treating it as absent.
//!
//! Provenance: the newest public xnu
//! (`xnu-12377.121.6`, `bsd/kern/syscalls.master`). The pinned 26A434 kernel
//! is `xnu-13432.1.9`, which Apple has not yet open-sourced; BSD syscall
//! numbers are append-only stable ABI, so the entries libSystem startup uses
//! are identical. A later open-source drop refreshes [`generated`] and
//! extends the high end.
use super::{BsdPrototype, BsdReturnType};

mod generated;

/// A reserved (`enosys`/`nosys`) number is a real ABI slot with no call. The
/// kernel returns ENOSYS for it; the catalog keeps the row so the dispatcher
/// can name it rather than treat the number as unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reserved {
    No,
    Yes,
}

/// One row of the catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatalogEntry {
    pub number: u16,
    pub name: &'static str,
    pub argument_count: usize,
    pub return_type: BsdReturnType,
    pub reserved: Reserved,
}

impl CatalogEntry {
    /// The calling-convention prototype of an implemented call. Reserved
    /// numbers have none: the kernel answers them with ENOSYS.
    pub const fn prototype(&self) -> Option<BsdPrototype> {
        match self.reserved {
            Reserved::No => Some(BsdPrototype {
                argument_count: self.argument_count,
                return_type: self.return_type,
            }),
            Reserved::Yes => None,
        }
    }
}

/// The kernel distribution the catalog was generated from.
pub const SOURCE: &str = "xnu-12377.121.6 bsd/kern/syscalls.master";

/// The catalog row for a BSD call number, implemented or reserved.
pub fn entry(number: u16) -> Option<&'static CatalogEntry> {
    generated::CATALOG
        .binary_search_by_key(&number, |entry| entry.number)
        .ok()
        .map(|index| &generated::CATALOG[index])
}

/// The call's name, whatever its status; `None` for a number past the
/// catalog's end.
pub fn name(number: u16) -> Option<&'static str> {
    entry(number).map(|entry| entry.name)
}

/// The prototype of an implemented BSD call; `None` for a reserved number or
/// one past the catalog's end.
pub fn prototype(number: u16) -> Option<BsdPrototype> {
    entry(number).and_then(CatalogEntry::prototype)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_ascending_unique_and_contiguous_from_zero() {
        let catalog = generated::CATALOG;
        assert!(!catalog.is_empty());
        assert_eq!(catalog[0].number, 0);
        for pair in catalog.windows(2) {
            // Strictly ascending (so `binary_search_by_key` is valid) and,
            // for this append-only table, with no gaps.
            assert_eq!(
                pair[1].number,
                pair[0].number + 1,
                "catalog is not contiguous at {}",
                pair[0].number
            );
        }
    }

    #[test]
    fn known_entries_match_the_pinned_master() {
        // getpid: no arguments, signed int result, implemented.
        let getpid = entry(20).unwrap();
        assert_eq!(getpid.name, "getpid");
        assert_eq!(getpid.reserved, Reserved::No);
        assert_eq!(
            getpid.prototype().unwrap(),
            BsdPrototype {
                argument_count: 0,
                return_type: BsdReturnType::Int,
            }
        );
        // read: three arguments, signed-size result.
        assert_eq!(
            prototype(3).unwrap(),
            BsdPrototype {
                argument_count: 3,
                return_type: BsdReturnType::SignedSize,
            }
        );
        // mmap returns an address.
        assert_eq!(entry(197).unwrap().name, "mmap");
        assert_eq!(entry(197).unwrap().return_type, BsdReturnType::Address);
        // lseek returns an offset.
        assert_eq!(entry(199).unwrap().return_type, BsdReturnType::Offset);
        // exit never returns a value.
        assert_eq!(entry(1).unwrap().name, "exit");
        assert_eq!(entry(1).unwrap().return_type, BsdReturnType::None);
    }

    #[test]
    fn reserved_numbers_are_named_but_have_no_prototype() {
        // Number 0 is the indirect-call `nosys` slot, reserved.
        let zero = entry(0).unwrap();
        assert_eq!(zero.name, "nosys");
        assert_eq!(zero.reserved, Reserved::Yes);
        assert!(zero.prototype().is_none());
        assert!(prototype(0).is_none());
        // A number past the end is unknown entirely.
        let past = generated::CATALOG.last().unwrap().number + 1;
        assert!(entry(past).is_none());
        assert!(name(past).is_none());
        assert!(prototype(past).is_none());
    }

    /// Every BSD call Stela services today agrees with the pinned catalog, so
    /// the hand-written service prototypes cannot drift from the kernel ABI.
    #[test]
    fn serviced_calls_match_their_catalog_prototypes() {
        for (number, argument_count, return_type) in [
            (
                crate::darwin::process::SYSCALL_NUMBER,
                0,
                BsdReturnType::Int,
            ),
            (
                crate::darwin::crossarch::SYSCALL_NUMBER,
                1,
                BsdReturnType::Int,
            ),
            // mprotect is serviced inline by `service_data_mprotect`.
            (74, 3, BsdReturnType::Int),
            (
                crate::darwin::shared_region::SYSCALL_NUMBER,
                1,
                BsdReturnType::Int,
            ),
            (crate::darwin::csr::SYSCALL_NUMBER, 3, BsdReturnType::Int),
            (
                crate::darwin::entropy::SYSCALL_NUMBER,
                2,
                BsdReturnType::Int,
            ),
        ] {
            let entry = entry(number).unwrap_or_else(|| panic!("catalog lacks {number}"));
            assert_eq!(entry.reserved, Reserved::No, "{number} is reserved");
            assert_eq!(
                entry.prototype().unwrap(),
                BsdPrototype {
                    argument_count,
                    return_type,
                },
                "service {} ({number}) disagrees with the catalog",
                entry.name
            );
        }
    }
}
