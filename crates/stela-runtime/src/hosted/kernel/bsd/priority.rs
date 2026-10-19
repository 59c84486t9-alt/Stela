//! `pthread_priority_t`, the QoS encoding libpthread, libdispatch and the
//! kernel exchange (xnu `bsd/pthread/priority_private.h`), and the thread
//! QoS tiers it encodes (`osfmk/mach/thread_policy.h`).

/// `THREAD_QOS_*`.
pub(crate) const THREAD_QOS_UNSPECIFIED: u8 = 0;
pub(crate) const THREAD_QOS_MAINTENANCE: u8 = 1;
pub(crate) const THREAD_QOS_BACKGROUND: u8 = 2;
pub(crate) const THREAD_QOS_LEGACY: u8 = 4;
pub(crate) const THREAD_QOS_USER_INITIATED: u8 = 5;
#[cfg(test)]
pub(crate) const THREAD_QOS_USER_INTERACTIVE: u8 = 6;
/// `THREAD_QOS_LAST`: one past the highest tier.
pub(crate) const THREAD_QOS_LAST: u8 = 7;
/// `THREAD_QOS_MIN_TIER_IMPORTANCE`: the lowest relative priority.
pub(crate) const MIN_TIER_IMPORTANCE: i32 = -15;

pub(crate) const OVERCOMMIT_FLAG: u64 = 0x8000_0000;
pub(crate) const SCHED_PRI_FLAG: u64 = 0x2000_0000;
pub(crate) const COOPERATIVE_FLAG: u64 = 0x0800_0000;
pub(crate) const EVENT_MANAGER_FLAG: u64 = 0x0200_0000;
pub(crate) const OVERRIDE_QOS_FLAG: u64 = 0x0080_0000;
pub(crate) const FLAGS_MASK: u64 = 0xff00_0000;
const VALID_QOS_CLASS_MASK: u64 = 0x0000_3f00;
const VALID_OVERRIDE_QOS_MASK: u64 = 0x003f_c000;
const QOS_CLASS_SHIFT: u32 = 8;
const PRIORITY_MASK: u64 = 0xff;
pub(crate) const SCHED_PRI_MASK: u64 = PRIORITY_MASK;

/// `_pthread_priority_has_qos`.
pub(crate) fn has_qos(priority: u64) -> bool {
    priority & (SCHED_PRI_FLAG | EVENT_MANAGER_FLAG) == 0 && priority & VALID_QOS_CLASS_MASK != 0
}

/// `_pthread_priority_thread_qos`: the lowest encoded tier, or
/// unspecified.
pub(crate) fn thread_qos(priority: u64) -> u8 {
    if !has_qos(priority) {
        return THREAD_QOS_UNSPECIFIED;
    }
    let bits = (priority & VALID_QOS_CLASS_MASK) >> QOS_CLASS_SHIFT;
    bits.trailing_zeros() as u8 + 1
}

/// `_pthread_priority_relpri`: the relative priority, 0 down to -15.
pub(crate) fn relative_priority(priority: u64) -> i32 {
    i32::from((priority & PRIORITY_MASK) as u8 as i8) + 1
}

/// `_pthread_priority_has_override_qos`.
pub(crate) fn has_override_qos(priority: u64) -> bool {
    priority & (SCHED_PRI_FLAG | EVENT_MANAGER_FLAG) == 0
        && priority & OVERRIDE_QOS_FLAG != 0
        && priority & VALID_OVERRIDE_QOS_MASK != 0
}

/// `_pthread_priority_make_from_thread_qos(qos, relpri, flags)`.
pub(crate) fn from_thread_qos(qos: u8, relative: i32, flags: u64) -> u64 {
    let mut priority = flags & FLAGS_MASK;
    if qos != THREAD_QOS_UNSPECIFIED && qos < THREAD_QOS_LAST {
        priority |= 1 << (QOS_CLASS_SHIFT + u32::from(qos) - 1);
        priority |= u64::from((relative as u8).wrapping_sub(1)) & PRIORITY_MASK;
    }
    priority
}

/// `_pthread_priority_to_policy`: a valid QoS tier and relative priority.
pub(crate) fn to_policy(priority: u64) -> Option<(u8, i32)> {
    let (qos, relative) = (thread_qos(priority), relative_priority(priority));
    (qos != THREAD_QOS_UNSPECIFIED && (MIN_TIER_IMPORTANCE..=0).contains(&relative))
        .then_some((qos, relative))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodings_round_trip_as_libpthread_builds_them() {
        // `_pthread_priority_make_from_thread_qos(THREAD_QOS_LEGACY, 0, 0)`.
        let legacy = from_thread_qos(THREAD_QOS_LEGACY, 0, 0);
        assert_eq!(legacy, 0x8ff);
        assert_eq!(thread_qos(legacy), THREAD_QOS_LEGACY);
        assert_eq!(relative_priority(legacy), 0);
        assert_eq!(to_policy(legacy), Some((THREAD_QOS_LEGACY, 0)));
        let low = from_thread_qos(THREAD_QOS_USER_INTERACTIVE, -15, OVERCOMMIT_FLAG);
        assert_eq!(low, 0x8000_20f0);
        assert_eq!(to_policy(low), Some((THREAD_QOS_USER_INTERACTIVE, -15)));
        assert_eq!(
            thread_qos(EVENT_MANAGER_FLAG | 0x100),
            THREAD_QOS_UNSPECIFIED
        );
        assert_eq!(to_policy(0x1ff), Some((THREAD_QOS_MAINTENANCE, 0)));
        assert_eq!(to_policy(0x100), None, "relative priority +1");
        assert!(!has_override_qos(legacy));
    }
}
