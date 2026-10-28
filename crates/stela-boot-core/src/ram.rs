//! Copy admission over immutable, guest-address-sorted RAM ranges. A refused
//! physical transfer must not modify either RAM or the caller's read buffer.

/// Guest DRAM backed by one contiguous host physical range.
#[derive(Debug, Clone, Copy)]
pub struct RamRange {
    pub guest: u64,
    pub host: u64,
    pub bytes: u64,
}

/// Lay `ram` out end to end in guest physical memory from `base`, in order,
/// keeping each range's host backing.
pub fn place(ram: &mut [RamRange], base: u64) {
    let mut guest = base;
    for range in ram {
        range.guest = guest;
        guest += range.bytes;
    }
}

/// The longest RAM run starting at `guest`, as (host physical, bytes).
pub fn run(ram: &[RamRange], guest: u64) -> Option<(u64, u64)> {
    let index = ram.partition_point(|range| range.guest <= guest);
    let range = ram.get(index.checked_sub(1)?)?;
    let offset = guest - range.guest;
    if offset >= range.bytes {
        return None;
    }
    Some((range.host.checked_add(offset)?, range.bytes - offset))
}

/// The immutable map and all host backing remain owned by the caller through
/// both passes. `action` is infallible and receives only complete admitted
/// chunks. UAT/DART page-by-page prefix semantics belong to their outer owner.
pub fn copy(
    ram: &[RamRange],
    guest: u64,
    length: usize,
    mut action: impl FnMut(u64, usize, usize),
) -> bool {
    if length == 0 {
        return true;
    }
    let Ok(bytes) = u64::try_from(length) else {
        return false;
    };
    if guest.checked_add(bytes - 1).is_none() {
        return false;
    }
    let Some((host, available)) = run(ram, guest) else {
        return false;
    };
    // The common one-run transfer needs one lookup and no replay.
    if bytes <= available {
        if host.checked_add(bytes - 1).is_none() {
            return false;
        }
        action(host, 0, length);
        return true;
    }
    if !walk(ram, guest, length, |_, _, _| {}) {
        return false;
    }
    // The map is immutably borrowed and unchanged, so the same walk cannot
    // discover a new hole after an earlier chunk has had an effect.
    walk(ram, guest, length, action)
}

fn walk(
    ram: &[RamRange],
    guest: u64,
    length: usize,
    mut action: impl FnMut(u64, usize, usize),
) -> bool {
    let mut done = 0;
    while done < length {
        let Some((host, available)) = run(ram, guest + done as u64) else {
            return false;
        };
        let chunk = usize::try_from(available)
            .unwrap_or(usize::MAX)
            .min(length - done);
        if host.checked_add(chunk as u64 - 1).is_none() {
            return false;
        }
        action(host, done, chunk);
        done += chunk;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holes_and_outer_boundaries_refuse_without_read_or_write_prefixes() {
        let ram = [
            RamRange {
                guest: 8,
                host: 0,
                bytes: 8,
            },
            RamRange {
                guest: 16,
                host: 24,
                bytes: 8,
            },
            RamRange {
                guest: 32,
                host: 8,
                bytes: 8,
            },
        ];
        for start in 0..=48u64 {
            for length in 0..=49usize {
                let admitted = (start..start + length as u64)
                    .all(|byte| (8..24).contains(&byte) || (32..40).contains(&byte));
                let mut host = [0xa5u8; 40];
                let mut output = [0x5au8; 49];
                let mut calls = 0;
                assert_eq!(
                    copy(&ram, start, length, |physical, done, chunk| {
                        calls += 1;
                        host[physical as usize..physical as usize + chunk].fill(0x33);
                        output[done..done + chunk].fill(0x77);
                    }),
                    admitted,
                    "start={start} length={length}"
                );
                if !admitted || length == 0 {
                    assert_eq!(calls, 0);
                    assert_eq!(host, [0xa5; 40]);
                    assert_eq!(output, [0x5a; 49]);
                } else {
                    assert!(output[..length].iter().all(|byte| *byte == 0x77));
                    assert!(output[length..].iter().all(|byte| *byte == 0x5a));
                }
            }
        }
    }

    #[test]
    fn adjacent_guest_ranges_keep_their_distinct_host_offsets() {
        let ram = [
            RamRange {
                guest: 8,
                host: 0x1000,
                bytes: 8,
            },
            RamRange {
                guest: 16,
                host: 0x9000,
                bytes: 8,
            },
            RamRange {
                guest: 24,
                host: 0x4000,
                bytes: 8,
            },
        ];
        let mut chunks = std::vec::Vec::new();
        assert!(copy(&ram, 12, 16, |host, done, bytes| chunks
            .push((host, done, bytes))));
        assert_eq!(chunks, [(0x1004, 0, 4), (0x9000, 4, 8), (0x4000, 12, 4)]);
        assert_eq!(run(&ram, 32), None);
    }

    #[test]
    fn placing_moves_guest_addresses_and_keeps_host_backing() {
        let mut ram = [
            RamRange {
                guest: 0,
                host: 0x9000,
                bytes: 0x2000,
            },
            RamRange {
                guest: 0x2000,
                host: 0x1000,
                bytes: 0x1000,
            },
        ];
        place(&mut ram, 0x8_0000_0000);
        assert_eq!(run(&ram, 0x8_0000_0000), Some((0x9000, 0x2000)));
        assert_eq!(run(&ram, 0x8_0000_2800), Some((0x1800, 0x800)));
        assert_eq!(run(&ram, 0x2000), None);
    }

    #[test]
    fn address_wrap_refuses_before_effects_and_last_address_is_representable() {
        let ram = [RamRange {
            guest: u64::MAX - 7,
            host: 0x1000,
            bytes: 8,
        }];
        let mut calls = 0;
        assert!(!copy(&ram, u64::MAX - 3, 5, |_, _, _| calls += 1));
        assert_eq!(calls, 0);
        assert!(copy(&ram, u64::MAX - 3, 4, |host, done, bytes| {
            assert_eq!((host, done, bytes), (0x1004, 0, 4));
            calls += 1;
        }));
        assert_eq!(calls, 1);
        let ram = [
            RamRange {
                guest: 0,
                host: 0x1000,
                bytes: 4,
            },
            RamRange {
                guest: 4,
                host: u64::MAX - 1,
                bytes: 4,
            },
        ];
        assert!(!copy(&ram, 0, 8, |_, _, _| calls += 1));
        assert_eq!(
            calls, 1,
            "a later host overflow cannot transfer an earlier chunk"
        );
        assert_eq!(run(&ram, 7), None);
    }
}
