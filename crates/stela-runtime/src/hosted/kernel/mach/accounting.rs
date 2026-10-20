//! Machine accounting in the profile's terms (the machine-accounting
//! contract of `docs/research/hosted-requirements.md`): the host machine's
//! load and CPU ticks, which are the hosted machine's, restated over the
//! selected profile's processors.
//!
//! The Mach factor is XNU's (`osfmk/kern/sched_average.c`,
//! `compute_averages`) applied to a load average over the profile's
//! processor count. Per-processor ticks fold the host's processors onto the
//! profile's: with at least as many host processors as profile ones, host
//! processor `i` counts for profile processor `i mod N`; with fewer, profile
//! processor `j` stands for host processor `j mod H`, which spreads its
//! ticks evenly over the profile processors standing for it. Either way
//! every tick counts exactly once.

/// `LOAD_SCALE` (`osfmk/mach/processor_info.h`): loads and Mach factors are
/// fixed point in thousandths.
pub(super) const LOAD_SCALE: u32 = 1000;

/// `CPU_STATE_MAX`: user, system, idle and nice ticks.
pub(super) const CPU_STATES: usize = 4;

/// The Mach factor of `cpus` processors under the load average `load`
/// (runnable threads in thousandths): the processors left idle, or, past
/// one runnable thread per processor, the share each thread gets
/// (`compute_averages`'s `factor_now`).
pub(super) fn mach_factor(load: u32, cpus: u32) -> u32 {
    let capacity = u64::from(cpus) * u64::from(LOAD_SCALE);
    let load = u64::from(load);
    let factor = if load > capacity {
        capacity * u64::from(LOAD_SCALE) / (load + u64::from(LOAD_SCALE))
    } else {
        capacity - load
    };
    factor as u32
}

/// The host processors' ticks folded onto `cpus` profile processors.
pub(super) fn fold(host: &[[u32; CPU_STATES]], cpus: usize) -> Vec<[u32; CPU_STATES]> {
    let mut profile = vec![[0u32; CPU_STATES]; cpus];
    if host.is_empty() || cpus == 0 {
        return profile;
    }
    if host.len() >= cpus {
        for (index, ticks) in host.iter().enumerate() {
            for (sum, &tick) in profile[index % cpus].iter_mut().zip(ticks) {
                *sum = sum.wrapping_add(tick);
            }
        }
        return profile;
    }
    let hosts = host.len();
    for (index, ticks) in profile.iter_mut().enumerate() {
        let source = index % hosts;
        // The profile processors standing for `source`, and this one's
        // place among them.
        let shares = (cpus - source).div_ceil(hosts) as u32;
        let place = (index / hosts) as u32;
        for (tick, &total) in ticks.iter_mut().zip(&host[source]) {
            // An even share, the remainder one each to the first places:
            // each share grows with the host's count.
            *tick = total / shares + u32::from(place < total % shares);
        }
    }
    profile
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mach_factor_follows_compute_averages() {
        // Whole runnable threads, as `compute_averages` samples them.
        for cpus in [1u32, 4, 8, 24] {
            for threads in 0..40u32 {
                let expected = if threads > cpus {
                    cpus * LOAD_SCALE / (threads + 1)
                } else {
                    (cpus - threads) * LOAD_SCALE
                };
                assert_eq!(mach_factor(threads * LOAD_SCALE, cpus), expected);
            }
        }
        // Averages in between.
        assert_eq!(mach_factor(2_500, 8), 5_500);
        assert_eq!(mach_factor(9_000, 8), 800);
    }

    fn total(ticks: &[[u32; CPU_STATES]]) -> [u64; CPU_STATES] {
        let mut sums = [0u64; CPU_STATES];
        for row in ticks {
            for (sum, &tick) in sums.iter_mut().zip(row) {
                *sum += u64::from(tick);
            }
        }
        sums
    }

    #[test]
    fn more_host_processors_fold_by_index() {
        let host: Vec<[u32; CPU_STATES]> = (0..12u32)
            .map(|cpu| [cpu, 10 * cpu, 100 + cpu, 1])
            .collect();
        let profile = fold(&host, 8);
        assert_eq!(profile[0], [8, 80, 208, 2]);
        assert_eq!(profile[3], [3 + 11, 30 + 110, 214, 2]);
        assert_eq!(profile[7], [7, 70, 107, 1]);
        assert_eq!(total(&profile), total(&host));
        assert_eq!(fold(&host[..8], 8), host[..8]);
    }

    #[test]
    fn fewer_host_processors_spread_evenly() {
        let host = [[10u32, 7, 1_000, 0], [3, 0, 999, 5], [8, 8, 8, 8]];
        let profile = fold(&host, 8);
        // Host 0 stands for profile 0, 3 and 6; host 1 for 1, 4 and 7;
        // host 2 for 2 and 5.
        assert_eq!(profile[0], [4, 3, 334, 0]);
        assert_eq!(profile[3], [3, 2, 333, 0]);
        assert_eq!(profile[6], [3, 2, 333, 0]);
        assert_eq!(profile[1], [1, 0, 333, 2]);
        assert_eq!(profile[7], [1, 0, 333, 1]);
        assert_eq!(profile[2], [4, 4, 4, 4]);
        assert_eq!(profile[5], [4, 4, 4, 4]);
        assert_eq!(total(&profile), total(&host));
        // Every share stays monotonic as the host's counter grows.
        let mut last = [0u32; 3];
        for count in 0..50u32 {
            let shares = fold(&[[count, 0, 0, 0]], 3);
            let now = [shares[0][0], shares[1][0], shares[2][0]];
            assert!(now.iter().zip(&last).all(|(now, last)| now >= last));
            last = now;
        }
    }
}
