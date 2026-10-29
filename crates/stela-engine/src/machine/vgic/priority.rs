//! Virtual interrupt priorities (Arm GICv3 architecture, "Interrupt
//! prioritization" and "Preemption"): the group priority a binary point
//! leaves, the binary point minima, and the active priorities the
//! ICH_AP0R0_EL2 and ICH_AP1R0_EL2 bits record.
//!
//! The interface implements five priority and five preemption bits
//! (ICH_VTR_EL2.PRIbits and PREbits 4), the architectural minimum: priority
//! bits 2:0 are RES0, there are 32 preemption levels and one active-priority
//! register per group.

/// Implemented priority bits.
pub const PRIORITY_BITS: u32 = 5;
/// Implemented preemption bits.
pub const PREEMPTION_BITS: u32 = 5;
/// The implemented bits of an 8-bit priority.
pub const PRIORITY_MASK: u8 = !((1 << (8 - PRIORITY_BITS)) - 1);
/// Group 0's smallest binary point: its group priority keeps every
/// preemption bit.
pub const BPR0_MIN: u8 = (7 - PREEMPTION_BITS) as u8;
/// Group 1's smallest binary point (Non-secure: one more than group 0's).
pub const BPR1_MIN: u8 = BPR0_MIN + 1;
/// The largest binary point.
pub const BPR_MAX: u8 = 7;
/// The running priority with no interrupt active.
pub const IDLE: u8 = 0xff;
/// The active-priority bit of a group priority is its preemption bits.
const ACTIVE_SHIFT: u32 = 8 - PREEMPTION_BITS;

/// The group priority of `priority` under binary point `point`, where the
/// group priority field is bits 7:point+1 (Arm `GroupBits` for group 0 and
/// a group 1 sharing BPR0).
pub const fn group_bits(priority: u8, point: u8) -> u8 {
    priority & ((0xff_u32 << (point as u32 + 1)) as u8)
}

/// The active-priority register bit of a group priority.
pub const fn active_bit(group_priority: u8) -> u32 {
    (group_priority as u32) >> ACTIVE_SHIFT
}

/// The running priority: the highest active priority across both groups'
/// active-priority registers, or [`IDLE`] when none is set.
pub fn running(active: [u64; 2]) -> u8 {
    let all = (active[0] | active[1]) as u32;
    if all == 0 {
        IDLE
    } else {
        (all.trailing_zeros() << ACTIVE_SHIFT) as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn five_preemption_bits_give_32_levels_and_the_binary_point_minima() {
        assert_eq!(PRIORITY_MASK, 0xf8);
        assert_eq!((BPR0_MIN, BPR1_MIN), (2, 3));
        // BPR0 2 keeps bits 7:3, every implemented bit; BPR0 7 keeps none.
        assert_eq!(group_bits(0xa8, BPR0_MIN), 0xa8);
        assert_eq!(group_bits(0xa8, 4), 0xa0);
        assert_eq!(group_bits(0xa8, BPR_MAX), 0);
        assert_eq!(active_bit(0xf8), 31);
        assert_eq!(active_bit(0x08), 1);
        assert_eq!(running([0, 0]), IDLE);
        // The lowest set bit across both groups is the highest priority.
        assert_eq!(running([1 << 20, 1 << 4]), 0x20);
        assert_eq!(running([1 << 0, 0]), 0);
    }
}
