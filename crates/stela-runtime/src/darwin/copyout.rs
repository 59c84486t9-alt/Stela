//! Copying service results into guest memory in source order (XNU
//! `osfmk/arm64/copyio.c`). A fault keeps the completed store prefix.

use crate::memory::{DIRECT_RAM_USER_END, OwnedMemory};
use anyhow::{Result, bail, ensure};

const MAX_COPYOUT_BYTES: usize = 256;
const STP_PAIR_BYTES: usize = 2 * size_of::<u64>();
const STRB_BYTES: usize = size_of::<u8>();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Completion {
    Copied,
    Fault { completed: usize },
}

/// Copy only into serialized private ordinary memory. The cold fault path plans
/// every reached store before publishing: an unsupported partly writable pair
/// leaves all destination bytes unchanged, including earlier valid pairs.
pub(crate) fn copyout(memory: &mut OwnedMemory, address: u64, bytes: &[u8]) -> Result<Completion> {
    ensure!(memory.is_usable(), "guest address space is unusable");
    ensure!(
        bytes.len() <= MAX_COPYOUT_BYTES,
        "copyout exceeds the bounded source profile"
    );
    if bytes.is_empty() {
        return Ok(Completion::Copied);
    }
    // copy_validate checks the entire user range before the assembly copy.
    // This lower-VA47 profile's minimum is zero, so only overflow/max need tests.
    if address
        .checked_add(bytes.len() as u64)
        .is_none_or(|end| end > DIRECT_RAM_USER_END)
    {
        return Ok(Completion::Fault { completed: 0 });
    }
    if memory.write(address, bytes).is_ok() {
        return Ok(Completion::Copied);
    }

    let pair_bytes = bytes.len() / STP_PAIR_BYTES * STP_PAIR_BYTES;
    let mut completed = 0;
    while completed < pair_bytes {
        let destination = address + completed as u64;
        if memory.validate_write(destination, STP_PAIR_BYTES).is_ok() {
            completed += STP_PAIR_BYTES;
            continue;
        }
        if (0..STP_PAIR_BYTES).any(|offset| {
            memory
                .validate_write(destination + offset as u64, STRB_BYTES)
                .is_ok()
        }) {
            bail!(
                "copyout fault within a partly writable STP requires a reviewed pair-fault profile"
            );
        }
        return publish_prefix(memory, address, bytes, completed);
    }
    while completed < bytes.len() {
        if memory
            .validate_write(address + completed as u64, STRB_BYTES)
            .is_err()
        {
            return publish_prefix(memory, address, bytes, completed);
        }
        completed += STRB_BYTES;
    }
    // The failed initial whole-range check and the identical successful store
    // plan cannot disagree under this serialized owner. Do not fabricate a fault.
    bail!("copyout permissions changed during serialized preflight")
}

fn publish_prefix(
    memory: &mut OwnedMemory,
    address: u64,
    bytes: &[u8],
    completed: usize,
) -> Result<Completion> {
    // Coalescing stores that were already validated is unobservable here: there
    // is no concurrent execution, device memory or observer.
    memory.write(address, &bytes[..completed])?;
    Ok(Completion::Fault { completed })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{MemoryRegionSpec, host_page_size};

    const TEST_BASE: u64 = 0x6b000000000;
    const ADDRESS_ATTEMPTS: u64 = 32;
    const CANARY: u8 = 0xa5;
    const COPIED: u8 = 0x3c;

    fn memory(first_writable: bool, second_writable: Option<bool>) -> OwnedMemory {
        let page = host_page_size().unwrap() as u64;
        for attempt in 0..ADDRESS_ATTEMPTS {
            let base = TEST_BASE + attempt * page * 4;
            let region = |address, writable| MemoryRegionSpec {
                guest_address: address,
                virtual_bytes: page,
                initial_bytes: vec![CANARY; page as usize],
                readable: true,
                writable,
                executable: false,
            };
            let mut regions = vec![region(base, first_writable)];
            if let Some(writable) = second_writable {
                regions.push(region(base + page, writable));
            }
            if let Ok(memory) = OwnedMemory::map(regions) {
                return memory;
            }
        }
        panic!("cannot allocate copyout fixture mapping");
    }

    #[test]
    fn complete_copies_preserve_canaries_across_pairs_tails_and_adjacent_regions() {
        let mut memory = memory(true, Some(true));
        let base = memory.regions()[0].guest_address;
        let page = memory.regions()[0].virtual_bytes as usize;
        for size in [0, 1, 4, 8, 15, 16, 17, 128, 255, MAX_COPYOUT_BYTES] {
            let address = base + page as u64 - 3;
            memory
                .write(address - 1, &[CANARY; MAX_COPYOUT_BYTES + 2])
                .unwrap();
            assert_eq!(
                copyout(&mut memory, address, &vec![COPIED; size]).unwrap(),
                Completion::Copied
            );
            let mut expected = vec![CANARY; MAX_COPYOUT_BYTES + 2];
            expected[1..1 + size].fill(COPIED);
            assert_eq!(
                memory.read_snapshot(address - 1, expected.len()).unwrap(),
                expected
            );
        }
        assert_eq!(
            copyout(&mut memory, u64::MAX, &[]).unwrap(),
            Completion::Copied
        );
    }

    #[test]
    fn source_recipe_faults_retain_only_proven_prefixes() {
        let mut memory = memory(true, Some(false));
        let base = memory.regions()[0].guest_address;
        let page = memory.regions()[0].virtual_bytes as usize;
        for size in [
            1,
            4,
            8,
            15,
            16,
            17,
            31,
            32,
            33,
            127,
            128,
            129,
            255,
            MAX_COPYOUT_BYTES,
        ] {
            for prefix in [0, 1, 3, 4, 7, 8, 15, 16, 17, 24, 31, 32, 127, 128, 255] {
                if prefix >= size {
                    continue;
                }
                memory.write(base, &vec![CANARY; page]).unwrap();
                let address = base + (page - prefix) as u64;
                let result = copyout(&mut memory, address, &vec![COPIED; size]);
                let bulk = size / STP_PAIR_BYTES * STP_PAIR_BYTES;
                let unsupported = prefix < bulk && prefix % STP_PAIR_BYTES != 0;
                if unsupported {
                    assert!(result.is_err(), "size={size} prefix={prefix}");
                } else {
                    assert_eq!(result.unwrap(), Completion::Fault { completed: prefix });
                }
                let mut expected = vec![CANARY; page];
                if !unsupported {
                    expected[page - prefix..].fill(COPIED);
                }
                assert_eq!(memory.read_snapshot(base, page).unwrap(), expected);
                assert_eq!(
                    memory.read_snapshot(base + page as u64, page).unwrap(),
                    vec![CANARY; page]
                );
            }
        }
    }

    #[test]
    fn mixed_pair_declines_even_when_first_store_is_unwritable() {
        let mut memory = memory(false, Some(true));
        let base = memory.regions()[0].guest_address;
        let page = memory.regions()[0].virtual_bytes as usize;
        let address = base + page as u64 - STP_PAIR_BYTES as u64 / 2;
        assert!(copyout(&mut memory, address, &[COPIED; STP_PAIR_BYTES]).is_err());
        assert_eq!(
            memory.read_snapshot(base, 2 * page).unwrap(),
            vec![CANARY; 2 * page]
        );
    }

    #[test]
    fn entirely_unwritable_first_pair_stops_before_later_writable_pair() {
        let mut memory = memory(false, Some(true));
        let base = memory.regions()[0].guest_address;
        let page = memory.regions()[0].virtual_bytes as usize;
        let address = base + page as u64 - STP_PAIR_BYTES as u64;
        assert_eq!(
            copyout(&mut memory, address, &[COPIED; 2 * STP_PAIR_BYTES]).unwrap(),
            Completion::Fault { completed: 0 }
        );
        assert_eq!(
            memory.read_snapshot(base, 2 * page).unwrap(),
            vec![CANARY; 2 * page]
        );
    }

    #[test]
    fn unmapped_gaps_follow_the_same_byte_and_pair_policy() {
        let mut memory = memory(true, None);
        let base = memory.regions()[0].guest_address;
        let page = memory.regions()[0].virtual_bytes as usize;
        for (size, prefix, unsupported) in [(8, 4, false), (32, 16, false), (32, 24, true)] {
            memory.write(base, &vec![CANARY; page]).unwrap();
            let result = copyout(
                &mut memory,
                base + (page - prefix) as u64,
                &vec![COPIED; size],
            );
            if unsupported {
                assert!(result.is_err());
            } else {
                assert_eq!(result.unwrap(), Completion::Fault { completed: prefix });
            }
            let mut expected = vec![CANARY; page];
            if !unsupported {
                expected[page - prefix..].fill(COPIED);
            }
            assert_eq!(memory.read_snapshot(base, page).unwrap(), expected);
        }
    }

    #[test]
    fn range_wrap_high_tag_and_maximum_fault_before_any_copy() {
        let mut memory = memory(true, None);
        let base = memory.regions()[0].guest_address;
        for address in [
            u64::MAX,
            DIRECT_RAM_USER_END,
            DIRECT_RAM_USER_END - 1,
            (1_u64 << 56) | base,
        ] {
            assert_eq!(
                copyout(&mut memory, address, &[COPIED; 2]).unwrap(),
                Completion::Fault { completed: 0 }
            );
        }
        assert_eq!(
            memory.read_snapshot(base, MAX_COPYOUT_BYTES).unwrap(),
            vec![CANARY; MAX_COPYOUT_BYTES]
        );
        assert!(copyout(&mut memory, base, &[COPIED; MAX_COPYOUT_BYTES + 1]).is_err());
        assert_eq!(
            memory.read_snapshot(base, MAX_COPYOUT_BYTES).unwrap(),
            vec![CANARY; MAX_COPYOUT_BYTES]
        );
    }
}
