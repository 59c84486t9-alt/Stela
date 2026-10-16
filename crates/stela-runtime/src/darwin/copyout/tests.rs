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
