//! Linear queue geometry shared by the AP and SPTM, independent of SoC name.
//!
//! Original 26A434 mac13j (SHA256 5109fca5209bdbb89cec29e3241cc42a90418cb737d65e31962b059b9879af90)
//! AppleANS3CGv2 GetMaxPendingCommands at VA 0xfffffe000ade1f64 returns 256;
//! GetNVMeSPTMQueueEntries at ade1f70 subtracts 1 from the parent's bounded
//! ring size. T6000 SPTM (SHA256 dda6be8f5aa266b2a9505269d7152e870e2b610114185a2f60a587782d2af082)
//! INIT at 0xfffffff0270d4b28 checks that handoff count; MAP_PAGES at d52d0
//! bounds tag by that same count. ENABLE_CG at d5a48 writes 0x28100=63 even
//! with J314s handoff 253. That control is not the software tag bound.
const MAX_TAG_SLOTS: u16 = 256;
const TAGS_PER_STATUS_WORD: u16 = 8;
const STATUS_WORD_BYTES: u64 = 4;
const VDMA_ENTRY_BYTES: u64 = 32;
/// The only source-checked NVMMU control encoding. The engine keeps no
/// translation cache after a synchronous command; no alternate encoding's
/// effect is inferred from the control's historical name/count interpretation.
pub const NVMMU_CONTROL: u16 = 63;
/// NVMe CAP bits shared by these declared dies: contiguous queues, timeout 1,
/// NVM command set, 4K minimum and 16K maximum memory pages.
const CAP_FIXED: u64 = (1 << 16) | (1 << 24) | (1 << 37) | (2 << 52);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueGeometry {
    handoff: u16,
}
impl QueueGeometry {
    /// Historic J473/M2 declaration; no observed silicon value is implied.
    pub const DEFAULT: Self = Self { handoff: 64 };
    /// The AP's min(CAP.MQES+1,257)-1 and 8-bit TCB ID bound this complete
    /// linear contract to 1..256 software slots. This is an explicit emulated
    /// resource declaration, not a generation-dependent hardware default.
    pub fn linear(handoff: u32) -> Result<Self, &'static str> {
        if handoff == 0 || handoff > u32::from(MAX_TAG_SLOTS) {
            return Err("ANS linear handoff entries must be in 1..=256");
        }
        Ok(Self {
            handoff: handoff as u16,
        })
    }
    pub const fn handoff_entries(self) -> u16 {
        self.handoff
    }
    pub const fn ring_entries(self) -> u16 {
        self.handoff + 1
    }
    pub const fn tag_slots(self) -> u16 {
        self.handoff
    }
    pub const fn capabilities(self) -> u64 {
        CAP_FIXED | self.handoff as u64
    }
    pub const fn status_bytes(self) -> u64 {
        self.handoff.div_ceil(TAGS_PER_STATUS_WORD) as u64 * STATUS_WORD_BYTES
    }
    pub const fn vdma_bytes(self) -> u64 {
        self.handoff as u64 * VDMA_ENTRY_BYTES
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn handoff_ring_tags_and_control_are_distinct_at_all_boundaries() {
        for value in [1, 63, 64, 65, 253, 254, 255, 256] {
            let g = QueueGeometry::linear(value).unwrap();
            assert_eq!(u32::from(g.tag_slots()), value);
            assert_eq!(u32::from(g.ring_entries()), value + 1);
            assert_eq!((g.capabilities() & 0xffff) + 1, u64::from(value) + 1);
            assert_eq!(
                ((g.capabilities() & 0xffff) + 1).min(257) - 1,
                u64::from(value)
            );
            assert_eq!(g.status_bytes(), u64::from(value.div_ceil(8)) * 4);
            assert_eq!(g.vdma_bytes(), u64::from(value) * 32);
            assert_eq!(NVMMU_CONTROL, 63);
        }
        for bad in [0, 257, u32::MAX] {
            assert!(QueueGeometry::linear(bad).is_err());
        }
    }
}
