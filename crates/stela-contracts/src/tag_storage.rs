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
//! end of the managed address space"). [`hand_off`] gives that value.
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
/// Bit 63 locks the register.
pub const LOCK: u64 = 1 << 63;
/// Bits 41:20: the tag storage's physical base.
pub const BASE_MASK: u64 = 0x3f_ffff << ALIGNMENT_SHIFT;
const ALIGNMENT_SHIFT: u32 = 20;
/// DRAM bytes one tag storage byte covers: two 4-bit tags of 16 bytes.
pub const COVERAGE: u64 = 32;

/// The tag storage's bytes for `dram_size` bytes of DRAM.
pub const fn bytes(dram_size: u64) -> u64 {
    dram_size / COVERAGE
}

/// The locked value iBoot leaves for the managed range `phys_base` to
/// `phys_base + mem_size` in `dram_size` bytes of DRAM, or `None` when its
/// base does not fit the register.
pub fn hand_off(phys_base: u64, mem_size: u64, dram_size: u64) -> Option<u64> {
    let end = phys_base.checked_add(mem_size)?;
    let base = end.checked_sub(bytes(dram_size))? >> ALIGNMENT_SHIFT << ALIGNMENT_SHIFT;
    (base & !BASE_MASK == 0).then_some(base | LOCK)
}

/// The tag storage's first byte in a TAG_OFFSET_EL2 value.
pub const fn base(value: u64) -> u64 {
    value & BASE_MASK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_handoff_matches_what_sptm_checks() {
        // The J813 qemu-sptm trace: 8 GiB at 0x100_0000_0000 with a 31/32
        // memSize reads 0x80000101e0000000.
        let dram = 0x2_0000_0000;
        assert_eq!(
            hand_off(0x100_0000_0000, dram / 32 * 31, dram),
            Some(0x8000_0101_e000_0000)
        );
        // The managed range to the end of DRAM puts it in DRAM's last 1/32.
        let value = hand_off(0x100_0200_0000, dram - 0x200_0000, dram).unwrap();
        assert_eq!(base(value), 0x100_0000_0000 + dram - bytes(dram));
        assert_ne!(value & LOCK, 0);
        // An unaligned end rounds down to 1 MiB; bases above bit 41 do not fit.
        assert_eq!(
            hand_off(0x100_0000_0000, dram - 0x4000, dram).map(base),
            Some(0x101_eff0_0000)
        );
        assert_eq!(hand_off(1 << 42, dram, dram), None);
    }
}
