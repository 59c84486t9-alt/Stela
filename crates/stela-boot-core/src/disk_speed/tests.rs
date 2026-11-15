use super::*;
use core::cell::Cell;

/// A disk whose reads take `seek` microseconds to start and `per_mib` per
/// MiB moved, on a clock only its reads advance.
fn run(blocks: u64, block_bytes: u64, seek: u64, per_mib: u64) -> (Option<Speed>, Vec<(u64, u64)>) {
    let clock = Cell::new(0u64);
    let mut reads = Vec::new();
    let speed = measure(
        blocks,
        block_bytes,
        7,
        |lba, count| {
            assert!(lba + count <= blocks, "read past the disk's end");
            reads.push((lba, count));
            clock.set(clock.get() + seek + count * block_bytes * per_mib / (1 << 20));
            true
        },
        || clock.get(),
    );
    (speed, reads)
}

#[test]
fn the_thresholds_follow_the_boot_logs() {
    assert_eq!(SLOWEST_READ_US, 2000);
    assert_eq!(SLOWEST_SEQUENTIAL_KIB_S, 12_288);
}

#[test]
fn an_ssd_is_fast_and_a_spinning_disk_is_slow_within_the_bounds() {
    // An SSD: 0.1 ms a read, 500 MB/s.
    let (ssd, reads) = run(1 << 30, 512, 100, 2000);
    let ssd = ssd.unwrap();
    assert_eq!(ssd.random_us, 100 + 8 * 2000 / 2048);
    assert!(ssd.sequential_kib_s > 400_000, "{ssd:?}");
    assert_eq!(reads.len(), RANDOM_READS + SEQUENTIAL_READS);
    assert_eq!(caution(Rotation::Unreported, Some(ssd)), None);
    // A disk with 20 ms seeks, as a 5400 rpm disk across its whole span.
    let (hdd, reads) = run(1 << 30, 512, 20_000, 10_000);
    let hdd = hdd.unwrap();
    assert!(hdd.random_us >= 20_000);
    // The random phase stopped at its time bound, not its count.
    let random = reads.iter().filter(|(_, count)| *count == 8).count();
    assert_eq!(random, (RANDOM_MICROS / hdd.random_us + 1) as usize);
    assert_eq!(
        caution(Rotation::Unreported, Some(hdd)).as_deref(),
        Some("Slow disk (20.0 ms a read): macOS may be too slow to start")
    );
    // Measured, the speed decides, whatever the disk reports.
    assert_eq!(
        caution(Rotation::from_nominal(5400), Some(hdd)).as_deref(),
        Some("Slow disk (20.0 ms a read): macOS may be too slow to start")
    );
}

#[test]
fn reads_are_aligned_spread_and_read_only_the_disk() {
    let (_, reads) = run(1 << 24, 512, 50, 1000);
    let random: Vec<_> = reads.iter().filter(|(_, count)| *count == 8).collect();
    assert!(random.iter().all(|(lba, _)| lba % 8 == 0));
    // Spread: not all in one tenth of the disk.
    let low = random
        .iter()
        .filter(|(lba, _)| *lba < (1 << 24) / 10)
        .count();
    assert!(low < random.len() / 2, "{low} of {}", random.len());
    // The sequential reads follow one another.
    let sequential: Vec<_> = reads.iter().filter(|(_, count)| *count == 2048).collect();
    assert!(
        sequential
            .windows(2)
            .all(|pair| pair[1].0 == pair[0].0 + 2048)
    );
    // A 4 KiB-block disk reads one block a random read.
    let (_, reads) = run(1 << 22, 4096, 50, 1000);
    assert!(reads.iter().any(|&(_, count)| count == 1));
}

#[test]
fn a_slow_stream_is_cautioned_and_odd_disks_are_not_measured() {
    // Fast seeks but 4 MB/s.
    let (slow, _) = run(1 << 30, 512, 300, 250_000);
    let slow = slow.unwrap();
    assert!(slow.random_us <= SLOWEST_READ_US);
    assert_eq!(
        caution(Rotation::None, Some(slow)).as_deref(),
        Some("Slow disk (4 MB/s): macOS may be too slow to start")
    );
    // Too small for the reads, an unusual block size, a failed read.
    assert_eq!(run(1000, 512, 1, 1).0, None);
    assert_eq!(measure(1 << 30, 520, 1, |_, _| true, || 0), None);
    assert_eq!(measure(1 << 30, 8192, 1, |_, _| true, || 0), None);
    assert_eq!(measure(1 << 30, 512, 1, |_, _| false, || 0), None);
}

#[test]
fn unmeasured_a_spinning_disk_keeps_its_caution() {
    assert_eq!(
        caution(Rotation::from_nominal(5400), None).as_deref(),
        Some("Spinning disk (5400 rpm): macOS may be too slow to start")
    );
    assert_eq!(caution(Rotation::None, None), None);
    assert_eq!(caution(Rotation::Unreported, None), None);
}

#[test]
fn the_check_in_stall_on_a_slow_disk_names_it() {
    const PANIC: &str = "IOKit Daemon (kernelmanagerd) stall[0], (60s): registry root held \
                         busy, kernelmanagerd has not checked in @IOService.cpp:6140";
    // #132's disk at the panic: busy 126145 ms over 21549 commands.
    let micros = service_us(21_549, 126_145_000);
    assert_eq!(micros, Some(5853));
    assert_eq!(
        stop_note(PANIC, "ST980811AS", micros).as_deref(),
        Some(
            "the macOS disk ST980811AS took 5.8 ms a read, too slow for macOS to start in time \
             (it needs under 2.0 ms): install macOS on a faster disk, such as an SSD"
        )
    );
    // #138's SSD: busy 47% at 790 reads a second.
    assert_eq!(stop_note(PANIC, "SSD", service_us(7920, 4_700_000)), None);
    // Another panic, or too few commands to judge, says nothing more.
    assert_eq!(stop_note("watchdog timeout", "ST980811AS", micros), None);
    assert_eq!(service_us(999, 100_000_000), None);
    assert_eq!(stop_note(PANIC, "ST980811AS", None), None);
}
