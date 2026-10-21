//! Cache identification: CLIDR_EL1 and the CCSIDR_EL1 that each CSSELR_EL1
//! selection reads, for a PE whose caches its SoC row and DeviceTree
//! describe (Arm ARM D23.2: CLIDR_EL1, CCSIDR_EL1 without FEAT_CCIDX,
//! CSSELR_EL1).
//!
//! The engine keeps no cache: memory is coherent, and CTR_EL0.IDC and DIC
//! hold. The registers still report the hierarchy, because software sizes
//! its data structures by it. 26A434 XNU's `do_cacheid` (kernel
//! 0xfffffe000bd74a74) takes `cache_line_size` from the level 1 data
//! cache's CCSIDR_EL1.LineSize. `vm_page_init_local_q` aligns each CPU's
//! local page queue to it (`vm_resident.c`), and the queue's packed
//! pointers need 64-byte alignment (`vm_page.h`
//! `VM_PAGE_PACKED_PTR_ALIGNMENT`). A queue head on a 16-byte line unpacks
//! to its neighbour, which corrupts the queues of a multiprocessor
//! ("vm_page_reactivate_local: found vm_page_t with wrong cpuid").
//!
//! CLIDR_EL1's LoUIS, LoC and LoUU are 0, as without caches: no level needs
//! maintenance for coherence, which holds on this engine. ICB is 0 (not
//! disclosed), and the levels beyond those described are absent.
//! CCSIDR_EL1 reads 0 for a selection without a cache, one of the UNKNOWN
//! values the architecture permits.

pub mod cram;

/// CLIDR_EL1.Ctype values.
const SEPARATE: u64 = 0b011;
const UNIFIED: u64 = 0b100;
/// The CSSELR_EL1 Level and InD fields, which select a CCSIDR_EL1.
const SELECTION: u64 = 0xf;
/// CCSIDR_EL1 field positions and limits without FEAT_CCIDX.
const ASSOCIATIVITY: u32 = 3;
const NUM_SETS: u32 = 13;
const MAX_WAYS: u32 = 1 << 10;
const MAX_SETS: u32 = 1 << 15;

/// One cache's capacity, associativity and line length in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cache {
    pub bytes: u32,
    pub ways: u32,
    pub line: u32,
}

impl Cache {
    /// Its CCSIDR_EL1, or why the geometry has no encoding.
    fn ccsidr(self) -> Result<u32, &'static str> {
        if !self.line.is_power_of_two() || !(16..=2048).contains(&self.line) {
            return Err("cache line length has no CCSIDR_EL1 LineSize");
        }
        let way_bytes = self.ways.checked_mul(self.line).filter(|&bytes| bytes != 0);
        let sets = way_bytes
            .filter(|&bytes| self.bytes.is_multiple_of(bytes))
            .map(|bytes| self.bytes / bytes)
            .filter(|&sets| sets != 0)
            .ok_or("cache capacity is not a whole number of sets")?;
        if self.ways > MAX_WAYS || sets > MAX_SETS {
            return Err("cache geometry exceeds CCSIDR_EL1's fields");
        }
        let line_size = self.line.trailing_zeros() - 4;
        Ok((sets - 1) << NUM_SETS | (self.ways - 1) << ASSOCIATIVITY | line_size)
    }
}

/// A PE's cache identification registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caches {
    clidr: u64,
    /// By CSSELR_EL1 Level and InD.
    ccsidr: [u32; SELECTION as usize + 1],
}

impl Caches {
    /// Separate level 1 instruction and data caches and a unified level 2,
    /// the hierarchy of every Apple core.
    pub fn split_unified(
        instruction: Cache,
        data: Cache,
        unified: Cache,
    ) -> Result<Self, &'static str> {
        let mut ccsidr = [0; SELECTION as usize + 1];
        // CSSELR_EL1: Level 1 data, Level 1 instruction, Level 2.
        ccsidr[0b000] = data.ccsidr()?;
        ccsidr[0b001] = instruction.ccsidr()?;
        ccsidr[0b010] = unified.ccsidr()?;
        Ok(Self {
            clidr: SEPARATE | UNIFIED << 3,
            ccsidr,
        })
    }

    pub fn clidr(&self) -> u64 {
        self.clidr
    }

    /// The CCSIDR_EL1 the CSSELR_EL1 value `csselr` selects.
    pub fn ccsidr(&self, csselr: u64) -> u64 {
        u64::from(self.ccsidr[(csselr & SELECTION) as usize])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn cache(bytes: u32, ways: u32) -> Cache {
        Cache {
            bytes,
            ways,
            line: 128,
        }
    }

    #[test]
    fn selections_read_their_geometry_as_xnu_decodes_it() {
        let caches = Caches::split_unified(
            cache(192 << 10, 6),
            cache(128 << 10, 8),
            cache(16 << 20, 16),
        )
        .unwrap();
        assert_eq!(caches.clidr(), 0b100_011);
        // do_cacheid: line 16 << LineSize, sets NumSets + 1, ways
        // Associativity + 1.
        let decode = |value: u64| {
            (
                16u64 << (value & 7),
                (value >> NUM_SETS & 0x7fff) + 1,
                (value >> ASSOCIATIVITY & 0x3ff) + 1,
            )
        };
        assert_eq!(decode(caches.ccsidr(0)), (128, 128, 8));
        assert_eq!(decode(caches.ccsidr(1)), (128, 256, 6));
        assert_eq!(decode(caches.ccsidr(2)), (128, 8192, 16));
        // TnD is outside the selection; absent caches read 0.
        assert_eq!(caches.ccsidr(0x10), caches.ccsidr(0));
        assert_eq!(caches.ccsidr(3), 0);
        assert_eq!(caches.ccsidr(4), 0);
        for wrong in [
            cache(100, 1),
            cache(128 << 10, 0),
            Cache {
                line: 96,
                ..cache(96 << 10, 8)
            },
            cache(1 << 30, 1),
        ] {
            assert!(wrong.ccsidr().is_err(), "{wrong:?}");
        }
    }
}
