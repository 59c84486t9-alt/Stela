//! XNU machine timeouts as boot-args give them.
//!
//! An `ml-timeout-NAME=VALUE` boot-arg is in picoseconds, whatever unit the
//! timeout is stored in (`osfmk/kern/startup.h`, "Machine Timeouts are
//! ALWAYS in picoseconds in the device tree or boot-args"). XNU converts an
//! overriding value to the stored unit, timebase ticks for `debug-ack`, and
//! keeps a default as it is: 26B123's `debug-ack` default is 1,440,000
//! ticks, 60 ms at 24 MHz.

//!
//! XNU also multiplies each timeout, its default or an override, by
//! `ml-timeout-NAME-scale` and by `ml-timeout-global-scale` (integers,
//! default 1; a product that overflows saturates), or by `NAME-scale` and
//! `global-scale` in `/machine-timeouts` or `/chosen/machine-timeouts`.
//! 26B123's kernel declares these timeouts: `lock` (6,000,000 ticks,
//! 250 ms), `ticket-lock` (3,000,000, 125 ms), `lock-panic` (12,582,912,
//! the mutex interlock's 0.5 s), `debug-ack`, `dtrace-spin-threshold` and
//! four `report-`/`trace-phy-read`/`write-delay` (default 0, off). Its
//! RELEASE build has no interrupt-masked or preemption-disable timeout.

use alloc::{format, string::String};

const PICOSECONDS_PER_SECOND: u64 = 1_000_000_000_000;

/// `seconds` as a machine timeout boot-arg's value.
pub const fn picoseconds(seconds: u64) -> u64 {
    seconds.saturating_mul(PICOSECONDS_PER_SECOND)
}

/// The timeouts by which one core times another's lock hold.
pub const LOCK_TIMEOUTS: [&str; 3] = ["ticket-lock", "lock", "lock-panic"];

/// The modeled chips' performance core clock: Apple M2's (and M2 Ultra's)
/// 3.49 GHz, the speed XNU's lock timeouts assume of a holder.
pub const MODELED_CORE_HZ: u64 = 3_490_000_000;

/// The largest scale: 1 s for a ticket spinlock.
pub const MAX_LOCK_SCALE: u64 = 8;

/// The factor the lock timeouts get on a host whose cores run at
/// `host_hz`, as measured: how many times slower than the modeled chip's
/// they are, rounded up, so 1 on a host at least as fast. A translated
/// holder runs its critical section that much slower; a holder the host
/// stops is the count's to hold (`stela_engine` `clock`). An unmeasured
/// rate changes nothing.
pub fn lock_scale(host_hz: u64) -> u64 {
    if host_hz == 0 {
        return 1;
    }
    MODELED_CORE_HZ.div_ceil(host_hz).clamp(1, MAX_LOCK_SCALE)
}

/// The boot-args that scale the lock timeouts by `scale`, each with a
/// leading space; none at 1, which leaves XNU's defaults.
pub fn lock_scale_arguments(scale: u64) -> String {
    if scale <= 1 {
        return String::new();
    }
    LOCK_TIMEOUTS
        .iter()
        .map(|name| format!(" ml-timeout-{name}-scale={scale}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_host_at_least_as_fast_as_the_modeled_chip_keeps_the_timeouts() {
        assert_eq!(lock_scale(4_700_041_194), 1);
        assert_eq!(lock_scale(MODELED_CORE_HZ), 1);
        assert_eq!(lock_scale_arguments(1), "");
        // Unmeasured: unchanged.
        assert_eq!(lock_scale(0), 1);
    }

    #[test]
    fn a_slower_host_scales_the_lock_timeouts_by_its_deficit_rounded_up() {
        assert_eq!(lock_scale(3_000_000_000), 2);
        assert_eq!(lock_scale(1_100_000_000), 4);
        assert_eq!(lock_scale(100_000_000), MAX_LOCK_SCALE);
        assert_eq!(
            lock_scale_arguments(2),
            " ml-timeout-ticket-lock-scale=2 ml-timeout-lock-scale=2 \
             ml-timeout-lock-panic-scale=2"
        );
    }

    #[test]
    fn a_boot_arg_timeout_is_in_picoseconds() {
        assert_eq!(picoseconds(10), 10_000_000_000_000);
        // What 24 MHz ticks XNU makes of it: 10 s.
        assert_eq!(picoseconds(10) / 1_000_000 * 24, 240_000_000);
    }

    #[test]
    fn the_old_tick_count_was_240_microseconds() {
        // 240,000,000 read as picoseconds, which XNU does.
        assert_eq!(240_000_000 * 24_000_000 / PICOSECONDS_PER_SECOND, 5_760);
    }

    #[test]
    fn a_timeout_too_long_saturates() {
        assert_eq!(picoseconds(u64::MAX), u64::MAX);
    }
}
