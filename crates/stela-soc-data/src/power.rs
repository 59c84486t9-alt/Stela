//! Source-checked SOC power register families and their word offsets.
//! Configuration layout never establishes physical readiness or progression.
use alloc::vec::Vec;
pub const STATUS: u64 = 0x24;
pub const CHANNEL: core::ops::Range<u64> = 0x30..0x50;
pub const MASK: u64 = 0x3f8;
pub const FINAL: u64 = 0x3fc;
pub const MARKER: u64 = 0x17ffc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Volman,
    Marker,
    Gpce,
    /// T8112 original RegMap0x63/reg41: both CIO reconfiguration words.
    Cio,
    /// LLB's source GPCE0 finalizer auxiliary controls, not a native PC/status bank.
    GpceFinalize,
    /// Exact T8112 native sequence/table configuration words, placed at their
    /// physical-address offsets. No status, trigger or SRAM aperture is implied.
    NubBindings,
    Gating,
    Tvm,
}

impl Kind {
    pub fn offsets(self) -> Vec<u64> {
        match self {
            Self::Volman => [
                alloc::vec![STATUS, MASK, FINAL],
                CHANNEL.step_by(4).collect(),
            ]
            .concat(),
            Self::Marker => alloc::vec![MARKER],
            Self::Gpce => alloc::vec![0, 4],
            Self::Cio => alloc::vec![0x4000, 0x8000],
            Self::GpceFinalize => alloc::vec![0x2008, 0x200c],
            Self::NubBindings => {
                let mut offsets = alloc::vec![
                    0x23d2d0200,
                    0x23d2d0300,
                    0x23b781000,
                    0x23b78d000,
                    0x23b781004,
                    0x23b781008,
                    0x23b78d004
                ];
                for base in [0x23d2d0200, 0x23d2d0300] {
                    offsets.extend((4..=0x18).step_by(4).map(|offset| base + offset));
                }
                offsets
            }
            Self::Gating => alloc::vec![0, 0x40, 0x80, 0x88],
            Self::Tvm => [0, 0x400, 0x800, 0xc00]
                .into_iter()
                .flat_map(|o| [o, o + 0x3e0])
                .collect(),
        }
    }
}
