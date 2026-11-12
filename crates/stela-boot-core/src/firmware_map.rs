//! How the UEFI memory map's entry types and attributes bound native device
//! ranges and the identity map of the firmware's runtime regions.
//!
//! EFI_MEMORY_RUNTIME says the OS must keep a region mapped for the runtime
//! services; it does not take the range from the OS. EDK2-derived firmware
//! lists MMIO in its map only with that attribute (DxeCore CoreGetMemoryMap),
//! so the MCFG window, IOAPICs and HPET of real PCs often carry it. Linux
//! uses an MCFG window that its map reserves whatever the attribute.

/// EfiReservedMemoryType.
pub const RESERVED: u32 = 0;
/// EfiRuntimeServicesCode.
pub const RUNTIME_SERVICES_CODE: u32 = 5;
/// EfiMemoryMappedIO.
pub const MMIO: u32 = 11;
/// EfiMemoryMappedIOPortSpace.
pub const MMIO_PORT_SPACE: u32 = 12;
/// EfiPalCode.
pub const PAL_CODE: u32 = 13;

/// EFI_MEMORY_WB: the region supports write-back caching.
pub const MEMORY_WB: u64 = 1 << 3;
/// EFI_MEMORY_RUNTIME.
pub const MEMORY_RUNTIME: u64 = 1 << 63;

/// Whether an entry of `kind` leaves its range to devices: reserved or
/// MMIO, never memory the firmware or the loader can hand out. The
/// attributes, EFI_MEMORY_RUNTIME included, do not change this.
pub const fn leaves_to_devices(kind: u32) -> bool {
    matches!(kind, RESERVED | MMIO)
}

/// The first entry of `entries` (start, end, kind) that overlaps
/// `first..end` and does not leave it to devices. Ranges no entry covers
/// are outside the map's memory and do not conflict.
pub fn first_conflict(
    entries: impl IntoIterator<Item = (u64, u64, u32)>,
    first: u64,
    end: u64,
) -> Option<(u64, u64, u32)> {
    entries
        .into_iter()
        .find(|&(start, stop, kind)| start < end && first < stop && !leaves_to_devices(kind))
}

/// Whether every entry of `entries` that overlaps `first..end` leaves the
/// range to devices.
pub fn excludes_memory(
    entries: impl IntoIterator<Item = (u64, u64, u32)>,
    first: u64,
    end: u64,
) -> bool {
    first_conflict(entries, first, end).is_none()
}

/// The UEFI name of a memory type, for the boot log.
pub const fn kind_name(kind: u32) -> &'static str {
    match kind {
        0 => "reserved",
        1 => "loader code",
        2 => "loader data",
        3 => "boot services code",
        4 => "boot services data",
        5 => "runtime services code",
        6 => "runtime services data",
        7 => "conventional memory",
        8 => "unusable memory",
        9 => "ACPI reclaim memory",
        10 => "ACPI NVS",
        11 => "MMIO",
        12 => "MMIO port space",
        13 => "PAL code",
        14 => "persistent memory",
        15 => "unaccepted memory",
        _ => "an unknown type",
    }
}

/// The identity mapping of one runtime region.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeMapping {
    /// Runtime code: write-back and executable.
    Code,
    /// Write-back data, not executable.
    WriteBack,
    /// Uncached, not executable.
    Uncached,
}

/// Map MMIO uncached and code executable; map other runtime regions
/// write-back only when the firmware says they support it, as Linux's
/// efi_map_region does. A reserved runtime region without EFI_MEMORY_WB is
/// often device registers such as an ECAM window, and a write-back alias of
/// those would conflict with their uncached native mapping.
pub const fn runtime_mapping(kind: u32, attributes: u64) -> RuntimeMapping {
    match kind {
        MMIO | MMIO_PORT_SPACE => RuntimeMapping::Uncached,
        RUNTIME_SERVICES_CODE | PAL_CODE => RuntimeMapping::Code,
        _ if attributes & MEMORY_WB != 0 => RuntimeMapping::WriteBack,
        _ => RuntimeMapping::Uncached,
    }
}

/// Why the final memory map cannot be kept as the native inventory, with
/// the entries and numbers that decide it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealError {
    /// The map has more entries than the inventory keeps.
    Capacity { entries: usize, capacity: usize },
    /// An entry does not start on a 4 KiB page.
    Unaligned { index: usize, start: u64 },
    /// An entry's pages pass the top of the address space.
    Wraps {
        index: usize,
        start: u64,
        pages: u64,
    },
    /// Entry `index` covers memory an earlier entry covers.
    Overlap {
        index: usize,
        range: (u64, u64),
        earlier: (u64, u64),
    },
}

impl core::fmt::Display for SealError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Capacity { entries, capacity } => write!(
                f,
                "the firmware's final memory map has {entries} entries, more than the \
                 {capacity} Stela keeps"
            ),
            Self::Unaligned { index, start } => write!(
                f,
                "final memory map entry {index} starts at {start:#x}, not on a 4 KiB page"
            ),
            Self::Wraps {
                index,
                start,
                pages,
            } => write!(
                f,
                "final memory map entry {index} at {start:#x} has {pages:#x} pages, past the \
                 top of the address space"
            ),
            Self::Overlap {
                index,
                range,
                earlier,
            } => write!(
                f,
                "final memory map entry {index} ({:#x}..{:#x}) overlaps an earlier entry \
                 ({:#x}..{:#x})",
                range.0, range.1, earlier.0, earlier.1
            ),
        }
    }
}

/// The entries the native inventory keeps of the final memory map. A
/// fragmented map of a PC with many firmware drivers can pass 512 entries;
/// the firmware SMBIOS reader bounds a map at the same 4096.
pub const INVENTORY_ENTRIES: usize = 4096;

/// One kept memory map entry: its range and UEFI memory type.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Entry {
    pub start: u64,
    pub end: u64,
    pub kind: u32,
}

/// What [`seal`] kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sealed {
    /// Entries written to the inventory.
    pub kept: usize,
    /// Entries without pages, which describe no memory and are left out.
    pub empty: usize,
}

/// Copy the memory map's `entries` (start, pages, kind) into `inventory`
/// as (start, end, kind). An entry without pages describes no memory:
/// firmware does list some, and Linux prunes them too, so they are left
/// out and counted. Every other entry must start on a page, end below the
/// top of the address space and overlap no other entry. Refusals name the
/// entry by its index in `entries`.
pub fn seal(
    entries: impl IntoIterator<Item = (u64, u64, u32)>,
    inventory: &mut [Entry],
) -> Result<Sealed, SealError> {
    const PAGE: u64 = 4096;
    let mut sealed = Sealed { kept: 0, empty: 0 };
    // Each entry's index in the firmware's map, for a refusal.
    let mut entries = entries.into_iter().enumerate();
    while let Some((index, (start, pages, kind))) = entries.next() {
        if pages == 0 {
            sealed.empty += 1;
            continue;
        }
        if !start.is_multiple_of(PAGE) {
            return Err(SealError::Unaligned { index, start });
        }
        let end = pages
            .checked_mul(PAGE)
            .and_then(|bytes| start.checked_add(bytes))
            .ok_or(SealError::Wraps {
                index,
                start,
                pages,
            })?;
        if let Some(earlier) = inventory[..sealed.kept]
            .iter()
            .find(|earlier| earlier.start < end && start < earlier.end)
        {
            return Err(SealError::Overlap {
                index,
                range: (start, end),
                earlier: (earlier.start, earlier.end),
            });
        }
        let Some(slot) = inventory.get_mut(sealed.kept) else {
            let rest = entries.filter(|&(_, (_, pages, _))| pages != 0).count();
            return Err(SealError::Capacity {
                entries: sealed.kept + 1 + rest,
                capacity: inventory.len(),
            });
        };
        *slot = Entry { start, end, kind };
        sealed.kept += 1;
    }
    Ok(sealed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_keeps_entries_and_leaves_out_empty_ones() {
        let mut inventory = [Entry::default(); 4];
        let map = [(0, 0x9f, 7), (0x10_0000, 0, 4), (0x20_0000, 0x10, 2)];
        assert_eq!(seal(map, &mut inventory), Ok(Sealed { kept: 2, empty: 1 }));
        assert_eq!(
            inventory[..2],
            [
                Entry {
                    start: 0,
                    end: 0x9f000,
                    kind: 7
                },
                Entry {
                    start: 0x20_0000,
                    end: 0x21_0000,
                    kind: 2
                }
            ]
        );
    }

    #[test]
    fn seal_names_the_count_of_a_map_larger_than_the_inventory() {
        let mut inventory = [Entry::default(); 512];
        // A fragmented map of 700 one-page entries, an empty one after each.
        let map =
            (0..700u64).flat_map(|page| [(page * 0x2000, 1, 2), (page * 0x2000 + 0x1000, 0, 7)]);
        let error = seal(map, &mut inventory).unwrap_err();
        assert_eq!(
            error,
            SealError::Capacity {
                entries: 700,
                capacity: 512
            }
        );
        assert_eq!(
            alloc::format!("{error}"),
            "the firmware's final memory map has 700 entries, more than the 512 Stela keeps"
        );
    }

    #[test]
    fn seal_refuses_unaligned_wrapping_and_overlapping_entries() {
        let mut inventory = [Entry::default(); 8];
        assert_eq!(
            seal([(0x1000, 1, 7), (0x2800, 1, 7)], &mut inventory),
            Err(SealError::Unaligned {
                index: 1,
                start: 0x2800
            })
        );
        assert_eq!(
            seal([(0xffff_ffff_ffff_f000, 2, 0)], &mut inventory),
            Err(SealError::Wraps {
                index: 0,
                start: 0xffff_ffff_ffff_f000,
                pages: 2
            })
        );
        let error = seal(
            [(0, 0x10, 7), (0x10_0000, 0, 7), (0x8000, 0x10, 4)],
            &mut inventory,
        )
        .unwrap_err();
        assert_eq!(
            error,
            SealError::Overlap {
                index: 2,
                range: (0x8000, 0x18000),
                earlier: (0, 0x10000)
            }
        );
        assert_eq!(
            alloc::format!("{error}"),
            "final memory map entry 2 (0x8000..0x18000) overlaps an earlier entry (0x0..0x10000)"
        );
    }

    const ECAM: (u64, u64) = (0xe000_0000, 0xf000_0000);

    #[test]
    fn runtime_reserved_or_mmio_entries_leave_an_ecam_window_to_devices() {
        for kind in [RESERVED, MMIO] {
            assert!(excludes_memory([(ECAM.0, ECAM.1, kind)], ECAM.0, ECAM.1));
            assert!(excludes_memory(
                [(ECAM.0 - 0x1000, ECAM.1 + 0x1000, kind)],
                ECAM.0,
                ECAM.0 + 0x10_0000
            ));
        }
        assert!(excludes_memory([], ECAM.0, ECAM.1));
    }

    #[test]
    fn ram_loader_or_firmware_memory_over_an_ecam_window_refuses() {
        // Loader code/data, boot services, conventional memory, ACPI
        // tables and NVS, runtime services code and data, persistent memory.
        for kind in [1, 2, 3, 4, 5, 6, 7, 9, 10, 13, 14] {
            assert!(!excludes_memory(
                [
                    (ECAM.0, ECAM.0 + 0x1000, MMIO),
                    (ECAM.0 + 0x1000, ECAM.1, kind)
                ],
                ECAM.0,
                ECAM.1
            ));
        }
        assert_eq!(
            first_conflict(
                [
                    (ECAM.0, ECAM.0 + 0x1000, MMIO),
                    (ECAM.0 + 0x1000, ECAM.1, 7)
                ],
                ECAM.0,
                ECAM.1
            ),
            Some((ECAM.0 + 0x1000, ECAM.1, 7))
        );
        assert_eq!(kind_name(7), "conventional memory");
        // Entries that end at or start after the range do not count.
        assert!(excludes_memory(
            [(0, ECAM.0, 7), (ECAM.1, ECAM.1 + 0x1000, 7)],
            ECAM.0,
            ECAM.1
        ));
    }

    #[test]
    fn runtime_regions_map_write_back_only_when_the_firmware_allows_it() {
        let uc = 1;
        assert_eq!(
            runtime_mapping(MMIO, MEMORY_WB | uc),
            RuntimeMapping::Uncached
        );
        assert_eq!(
            runtime_mapping(MMIO_PORT_SPACE, 0),
            RuntimeMapping::Uncached
        );
        assert_eq!(
            runtime_mapping(RUNTIME_SERVICES_CODE, MEMORY_WB),
            RuntimeMapping::Code
        );
        assert_eq!(runtime_mapping(PAL_CODE, MEMORY_WB), RuntimeMapping::Code);
        assert_eq!(
            runtime_mapping(6, MEMORY_WB | uc),
            RuntimeMapping::WriteBack
        );
        assert_eq!(
            runtime_mapping(RESERVED, MEMORY_RUNTIME | uc),
            RuntimeMapping::Uncached
        );
        assert_eq!(
            runtime_mapping(RESERVED, MEMORY_RUNTIME | MEMORY_WB),
            RuntimeMapping::WriteBack
        );
    }
}
