//! The MPIDR_EL1 identity of an Apple PE, the same on every SoC. XNU
//! xnu-12377.121.6 apple_arm64_regs.h:102–107 defines MPIDR_CORETYPE at
//! bits 18:16 (E=0, P=1, M=4); Aff1 and Aff0 are the DeviceTree `reg`'s
//! physical cluster and core, so core type never creates another cluster.

/// The `reg` bits MPIDR_EL1 carries: Aff1 and Aff0.
pub const CLUSTER_CORE: u32 = 0xffff;
pub const CORETYPE_MASK: u8 = 7;
pub const CORETYPE_SHIFT: u32 = 16;
const RES1: u64 = 1 << 31;

/// The MPIDR_EL1 of core type `coretype` at `reg`, or `None` for an
/// out-of-field core type or undeclared `reg` bits.
pub const fn compose(coretype: u8, reg: u32) -> Option<u64> {
    if coretype & !CORETYPE_MASK != 0 || reg & !CLUSTER_CORE != 0 {
        return None;
    }
    Some(RES1 | (coretype as u64) << CORETYPE_SHIFT | reg as u64)
}

/// MPIDR_EL1's core type.
pub const fn coretype(mpidr: u64) -> u8 {
    (mpidr >> CORETYPE_SHIFT) as u8 & CORETYPE_MASK
}
