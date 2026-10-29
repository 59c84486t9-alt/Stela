//! Source-checked per-core sampler register-window geometry.
//! Counter storage, selector effects and System-register decoding are owned
//! by the architectural/device execution layers.
/// The core performance counters' slots: eight 0x10 apart, then the
/// T6050's two more 8 apart.
pub const AON: u64 = 0x4000;
/// The core performance counters' slots: eight 0x10 apart, then the
/// T6050's two more 8 apart.
pub const AON_STRIDE: u64 = 0x10;
/// The core performance counters' slots: eight 0x10 apart, then the
/// T6050's two more 8 apart.
pub const AON_SLOTS: usize = 8;
/// The core performance counters' slots: eight 0x10 apart, then the
/// T6050's two more 8 apart.
pub const AON_EXTRA: u64 = 0x3fc0;
pub const EXTRA_STRIDE: u64 = 8;
/// The memory-stall counters' slots.
pub const STALL: u64 = 0x6030;
/// The memory-stall counters' slots.
pub const STALL_STRIDE: u64 = 8;
/// The memory-stall counters' slots.
pub const STALL_SLOTS: usize = 8;
pub const EXTRA_SLOTS: usize = 2;
pub const MAX_AON: usize = AON_SLOTS + EXTRA_SLOTS;

/// The source-checked counter slots exposed by both views of a SoC's cores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    aon: u8,
    stall: u8,
}

/// The counters of the SoC with `chip_id`: the System registers its CLPC's
/// `CorePerfSampler::sample` and `CoreMemStallSampler::sample` read (and,
/// on the Ultras and the T6050, the second CLPC's two more memory-stall
/// counters, S3_1_C15_C14_3 and C15_3: kernelcache.release.mac14j
/// 0xfffffe0009f7c420).
pub fn layout(chip_id: u32) -> Option<Layout> {
    let (aon, stall) = match chip_id {
        0x8103 | 0x8112 => (3, 4),
        0x6000 | 0x6001 | 0x6020 | 0x6021 => (4, 6),
        0x6002 | 0x6022 => (4, 8),
        // AppleT8140CLPC in 26A434 kernelcache.release.mac17p reads
        // AON0..2 (file 0x2b61478, 0x2b61460, 0x2b62cd0) and
        // stall0..4 (0x2b6aff8..0x2b6b0a8). Its config methods at
        // 0x2b71a64/0x2b71aac use the same 0x4000/0x6010 bases.
        // The A18 Pro uses an M4 ISA profile but has its own sampler row.
        0x8122 | 0x8140 => (3, 5),
        0x6030 => (4, 5),
        0x6031 | 0x6034 | 0x6040 | 0x6041 => (5, 6),
        0x6032 => (5, 8),
        0x8132 | 0x8142 | 0x8152 => (5, 5),
        0x6050 => (10, 8),
        _ => return None,
    };
    Some(Layout { aon, stall })
}

impl Layout {
    /// The window ranges a block of this layout maps, as (offset, bytes):
    /// each kind's described slots, from the first to the last.
    pub fn windows(self) -> impl Iterator<Item = (u64, u64)> {
        let aon = usize::from(self.aon);
        [
            (AON, aon.min(AON_SLOTS) as u64 * AON_STRIDE),
            (
                AON_EXTRA,
                aon.saturating_sub(AON_SLOTS) as u64 * EXTRA_STRIDE,
            ),
            (STALL, u64::from(self.stall) * STALL_STRIDE),
        ]
        .into_iter()
        .filter(|&(_, bytes)| bytes != 0)
    }
}

impl Layout {
    pub fn aon_slots(self) -> usize {
        usize::from(self.aon)
    }
    pub fn stall_slots(self) -> usize {
        usize::from(self.stall)
    }
}
