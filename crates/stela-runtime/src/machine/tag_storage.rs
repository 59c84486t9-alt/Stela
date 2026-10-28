//! TAG_OFFSET_EL2: where the M5 and later keep memory tags in DRAM.
//!
//! Public XNU `xnu-12377.121.6` names it (`osfmk/arm64/proc_reg.h:3407-3421`):
//! `MTE_TAG_OFFSET_EL2` `S3_0_C11_C9_0`, "the start of the stolen DRAM memory
//! that contains MTE tags metadata", a physically contiguous array aligned to
//! 1 MiB, its address in bits 41:20; one tag page covers 32 pages
//! (`MTE_PAGES_PER_TAG_PAGE`). iBoot programs and locks it: M5 iBoot
//! (`iBoot.j813` `0x31854..0x318dc`) requires it to read 0, sizes its tag
//! carveout (region 0xda) at DRAM size / 32 with 1 MiB alignment
//! (`0x38194`), and writes the carveout's base with bit 63 set, reading it
//! back. SPTM 26A434 only reads it (T8142 `0xfffffff0270bed98..0x...bedcc`;
//! T6050 and T8152 alike, the T8132 and T8140 never): it takes `/chosen
//! dram-size` >> 19 as the 16 KiB tag pages, requires bits 62:0 to equal
//! `physBase + memSize - tag bytes` rounded down to 1 MiB and bit 63 to be
//! set, and types that range `MTE_TAG_STORAGE` at the top of the range it
//! hands XNU (XNU's `vm_mteinfo.c`: iBoot places the tag storage "at the
//! end of the managed address space"). [`stela_contracts::tag_storage::hand_off`] gives that value.
//!
//! The tags themselves stay in `machine::tags`, apart from RAM. XNU moves
//! tags only with the tag instructions (its compressor and tag copy use
//! `LDGM`/`STGM`, `osfmk/arm64/mte.c`, `mte_xnu.h:191-198`), and uses a tag
//! storage page as ordinary memory only while it stores no tags (its
//! `CLAIMED` state, `osfmk/vm/vm_mteinfo.c`), so those paths observe the
//! same values. What differs: a tag storage page's DRAM bytes are not the
//! tags of the pages it covers, so a tag read after activation without a
//! tag write returns the last tags (0 from reset) instead of stale bytes,
//! and a DRAM image of active tag storage (a hibernation image) does not
//! carry tags.
use super::identification;
use super::registers::encodings::Encoding;
use stela_contracts::Chip;

pub const TAG_OFFSET_EL2: Encoding = Encoding::new(3, 0, 11, 9, 0);

/// Whether the declared chip owns this implementation-defined register.
pub fn owns(chip: Chip, encoding: Encoding) -> bool {
    encoding == TAG_OFFSET_EL2 && identification::memory_tagging(chip)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_memory_tagging_chips_own_the_tag_storage_register() {
        assert!(owns(Chip::AppleM5, TAG_OFFSET_EL2) && owns(Chip::AppleM6, TAG_OFFSET_EL2));
        assert!(!owns(Chip::AppleM4, TAG_OFFSET_EL2));
    }
}
