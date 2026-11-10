use super::*;
use alloc::string::ToString;

/// Free RAM a PC of `installed` GiB shows Stela: firmware keeps about 3 %.
fn free(installed: u64) -> u64 {
    installed * GIB / 32 * 31
}

#[test]
fn every_host_size_keeps_the_parts_in_bounds_and_the_guest_above_its_floor() {
    for (installed, runners) in [
        (8, 2),
        (8, 4),
        (8, 8),
        (16, 8),
        (32, 8),
        (128, 8),
        (128, 64),
        (2048, 8),
        (2048, 64),
    ] {
        let free = free(installed);
        let sizes = sizes(free, runners, runners).unwrap();
        assert!((HEAP_FLOOR..=HEAP_CEILING).contains(&sizes.heap));
        assert!(sizes.guest >= GUEST_FLOOR);
        assert_eq!(
            sizes.heap + sizes.code.bytes + sizes.pool + sizes.guest,
            free
        );
        // The pool maps each sharer's guest DRAM once, up to its cap.
        let sharers = (runners as u64).min(POOL_SHARERS);
        let wanted = sharers * sizes.guest / POOL_SHARE;
        let cap = sharers * POOL_PER_RUNNER;
        let floor = POOL_FLOOR.max(runners as u64 * POOL_RUNNER_FLOOR);
        assert!(
            sizes.pool == cap || sizes.pool + ALIGNMENT * 2 >= wanted,
            "{installed} GiB"
        );
        assert!(sizes.pool <= wanted.max(floor) || sizes.pool == cap);
    }
}

#[test]
fn an_8_gib_host_gives_the_guest_what_the_parts_leave() {
    let sizes = sizes(free(8), 8, 8).unwrap();
    assert_eq!(sizes.heap, HEAP_FLOOR);
    assert_eq!(sizes.code.bytes, 512 * MIB);
    // 8 runners' sixty-fourths of the guest's 4 GiB, not of all 7.75 GiB.
    assert_eq!(sizes.pool, 512 * MIB);
    assert_eq!(sizes.guest, 4096 * MIB);
}

#[test]
fn a_16_gib_host_sizes_the_heap_from_its_window_and_one_shared_code_window() {
    let sizes = sizes(free(16), 8, 8).unwrap();
    // A twelfth, 3 bytes per byte of the 512 MiB window and 16 MiB per PE.
    assert_eq!(sizes.heap, 2986 * MIB);
    // 64 MiB of window per runner, and each executor's 2 MiB of its own.
    assert_eq!(sizes.code.bytes, 528 * MIB);
    assert!(sizes.guest > 10 * GIB);
}

#[test]
fn a_128_gib_host_grows_the_heap_with_its_share_window_and_pes() {
    let sizes = sizes(free(128), 8, 8).unwrap();
    let heap = free(128) / HEAP_SHARE + HEAP_PER_WINDOW * 512 * MIB + 8 * PE_HEAP;
    assert_eq!(sizes.heap, heap / ALIGNMENT * ALIGNMENT);
    assert!(HEAP_FLOOR < sizes.heap && sizes.heap < HEAP_CEILING);
    assert_eq!(sizes.code.bytes, 528 * MIB);
    assert_eq!(sizes.pool, 8 * POOL_PER_RUNNER);
    assert!(sizes.guest > 100 * GIB);
}

/// Heap, code, pool and guest MiB for `runners` PEs at `free` GiB, or None
/// when the guest's floor does not fit.
#[test]
fn stelas_share_stops_growing_per_pe_past_what_each_pe_takes() {
    for (runners, free, expected) in [
        (2, 4, None),
        (2, 8, Some([2816, 132, 158, 5086])),
        (2, 16, Some([2816, 132, 406, 13030])),
        (2, 30, Some([2976, 132, 836, 26776])),
        (2, 128, Some([11338, 132, 2048, 117554])),
        (8, 4, None),
        (8, 8, Some([2816, 528, 538, 4310])),
        (8, 16, Some([3028, 528, 1424, 11404])),
        (8, 30, Some([4224, 528, 2884, 23084])),
        (8, 128, Some([12586, 528, 8192, 109766])),
        (24, 4, None),
        (24, 8, Some([2816, 560, 768, 4048])),
        (24, 16, Some([4820, 1072, 1164, 9328])),
        (24, 30, Some([7552, 1584, 2398, 19186])),
        (24, 128, Some([15914, 1584, 8192, 105382])),
        (64, 4, None),
        (64, 8, None),
        (64, 16, Some([5460, 1152, 2048, 7724])),
        (64, 30, Some([9344, 2048, 2146, 17182])),
        (64, 128, Some([16384, 2176, 8192, 104320])),
    ] {
        let actual = sizes(free * GIB, runners, runners)
            .ok()
            .map(|sizes| [sizes.heap, sizes.code.bytes, sizes.pool, sizes.guest].map(|b| b / MIB));
        assert_eq!(actual, expected, "{runners} PEs, {free} GiB");
        if let Some([_, _, pool, guest]) = actual {
            // The pool's total stays within an eighth of the guest, or each
            // runner's floor, whatever the PE count.
            assert!(
                pool <= (guest / 8).max(runners as u64 * 32),
                "{runners} {free}"
            );
        }
    }
}

#[test]
fn the_test_bench_keeps_its_guest() {
    // `HOST MEMORY free=7354M heap=2816M code=464M pool=452M guest=3622M`.
    let sizes = sizes(7354 * MIB, 8, 8).unwrap();
    assert_eq!(
        [sizes.heap, sizes.code.bytes, sizes.pool, sizes.guest].map(|b| b / MIB),
        [2816, 464, 452, 3622]
    );
}

#[test]
fn a_2_tib_host_caps_every_part() {
    let sizes = sizes(free(2048), 8, 8).unwrap();
    assert_eq!(sizes.heap, HEAP_CEILING);
    assert_eq!(sizes.code.bytes, 528 * MIB);
    assert_eq!(sizes.pool, 8 * POOL_PER_RUNNER);
    assert_eq!(sizes.guest, free(2048) - 24 * GIB - 528 * MIB);
}

#[test]
fn the_heap_grows_with_the_host_between_its_bounds() {
    let small = sizes(free(32), 8, 8).unwrap().heap;
    let large = sizes(free(64), 8, 8).unwrap().heap;
    assert!(HEAP_FLOOR < small && small < large && large < HEAP_CEILING);
}

#[test]
fn too_little_ram_says_how_much_is_needed() {
    let refusal = sizes(4 * GIB, 8, 8).unwrap_err();
    assert_eq!(
        refusal.to_string(),
        "this PC has 4.0 GB of RAM free; Stela needs at least 7 GB free: \
         3 GB for macOS and the rest for its own memory"
    );
    let two_cores = sizes(5 * GIB, 2, 2).unwrap_err();
    assert!(
        two_cores.to_string().contains("at least 6 GB"),
        "{two_cores}"
    );
    assert!(sizes(6 * GIB, 2, 2).is_ok());
    assert!(sizes(free(8), 2, 2).is_ok());
}

#[test]
fn parked_executors_add_only_their_reserves() {
    let parked = sizes(free(16), 12, 8).unwrap();
    let rest = free(16) - parked.heap - parked.code.bytes;
    let running = 8 * rest / (POOL_SHARE + 8) / ALIGNMENT * ALIGNMENT;
    assert_eq!(parked.pool, running + 4 * 4 * MIB);
}

/// The free RAM an 8 GB VM showed the loader with no pack read, as
/// `HOST MEMORY free=7544M` (run 20261109-163216, eight cores).
const VM_8_GB: u64 = 7544 * MIB;

#[test]
fn an_8_gb_pc_keeps_a_sixteenth_for_the_pack() {
    let budget = pack_budget(VM_8_GB, 8, 8);
    assert_eq!(budget, 470 * MIB);
    // The 845 MB pack that stopped this VM's boots no longer fits whole,
    // and what is read of it leaves the parts and the guest's floor.
    assert!(budget < 845_496_619);
    let sizes = sizes(VM_8_GB - budget - PACK_MARGIN, 8, 8).unwrap();
    assert!(sizes.guest > GUEST_FLOOR + 200 * MIB, "{sizes:?}");
    assert_eq!(pack_budget(free(8), 8, 8), 496 * MIB);
}

#[test]
fn a_16_gb_pc_keeps_about_a_gigabyte_for_the_pack() {
    assert_eq!(pack_budget(free(16), 8, 8), 992 * MIB);
}

#[test]
fn a_128_gb_pc_keeps_more_for_the_pack() {
    let budget = pack_budget(free(128), 16, 16);
    assert_eq!(budget, 7936 * MIB);
    let sizes = sizes(free(128) - budget - PACK_MARGIN, 16, 16).unwrap();
    assert!(sizes.guest > 72 * GIB, "{sizes:?}");
}

#[test]
fn the_pack_gets_only_what_the_parts_and_the_guest_leave() {
    // Just above what eight cores need, the pack gets the rest, not its
    // share; below it, nothing, and the boot goes on without a pack.
    let needed = (6000..7200)
        .map(|mib| mib * MIB)
        .find(|&free| sizes(free, 8, 8).is_ok())
        .unwrap();
    assert_eq!(pack_budget(needed, 8, 8), 0);
    // 100 MiB more leaves the pack about that much, less the margin: the
    // most that still fits.
    let budget = pack_budget(needed + 100 * MIB, 8, 8);
    assert!((PACK_FLOOR..=100 * MIB).contains(&budget), "{budget}");
    assert!(sizes(needed + 100 * MIB - budget - PACK_MARGIN, 8, 8).is_ok());
    assert!(sizes(needed + 100 * MIB - budget - ALIGNMENT - PACK_MARGIN, 8, 8).is_err());
    assert_eq!(pack_budget(4 * GIB, 8, 8), 0);
    for cores in [1, 2, 4, 8, 16, 64] {
        for free in (2 * GIB..40 * GIB).step_by(37 * MIB as usize) {
            let budget = pack_budget(free, cores, cores);
            assert!(budget.is_multiple_of(ALIGNMENT));
            assert!(budget <= free / PACK_SHARE);
            if budget != 0 {
                assert!(budget >= PACK_FLOOR);
                let left = free - budget - PACK_MARGIN;
                assert!(sizes(left, cores, cores).is_ok(), "{free} {cores}");
            }
        }
    }
}
