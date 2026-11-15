// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright 2004-2005 Red Hat, Inc.
//! Error handling a step per look: each case runs once with the error
//! handling run to its end in place, as every caller that waits gets it,
//! and once through the block device's start and finish, a step per look.
//! Both end with the same result, the same register writes in the same
//! order and the same disk state, and no step waits.
use super::*;

/// The fixtures' virtual clock, one tick per microsecond, on which each
/// counter read costs 100 µs.
const VIRTUAL: Clock = Clock {
    ticks_per_microsecond: 1,
};

/// The longest a look may take on the virtual clock: 20 counter reads and
/// no wait. A step that waited for a minimum delay, a debounce or a
/// command would take that wait's whole length.
const STEP_BOUND_US: u64 = 2_000;

/// What runs on a guest processor between two looks, on the virtual clock.
const BETWEEN_LOOKS_US: u64 = 1_000;

/// What one run of a command left: its result, every register write and
/// command issue on the link, and the disk state error handling changes.
#[derive(Debug, PartialEq)]
struct Outcome {
    result: Finished,
    writes: Vec<(usize, u32)>,
    issued: usize,
    fault: Option<BlockError>,
    speed_limit: u32,
    speed: u32,
    mode: u8,
    udma_mask: u32,
    pio_mask: u32,
    errors: usize,
    /// What the block device says after the command: its depth and room,
    /// and whether it takes another.
    depth: usize,
    room: bool,
    next: Result<(), BlockError>,
}

/// How a stepped run went: its looks, those while error handling ran, and
/// the longest look.
#[derive(Debug, Default)]
struct Steps {
    looks: usize,
    recovering: usize,
    longest_us: u64,
}

fn outcome(disk: &mut AhciDisk, link: &Link, result: Finished) -> Outcome {
    Outcome {
        result,
        writes: link.writes.borrow().clone(),
        issued: link.issued.get(),
        fault: disk.fault.clone(),
        speed_limit: disk.speed_limit,
        speed: disk.speed,
        mode: disk.mode,
        udma_mask: disk.udma_mask,
        pio_mask: disk.pio_mask,
        errors: disk.errors.newest().count(),
        depth: disk.depth(),
        room: disk.room(),
        next: disk.begin(Command::Flush).map(|_| ()),
    }
}

fn write() -> Command {
    Command::Write {
        lba: 9,
        data: vec![0x44; 512],
        fua: false,
    }
}

/// `command` on `disk`, its error handling run to its end in place within
/// each run of the started commands: what every caller that waits gets.
fn in_place(disk: &mut AhciDisk, link: &Link, command: Command) -> Outcome {
    let tag = disk.begin(command).unwrap();
    let result = loop {
        disk.run(link);
        if let Some(index) = disk
            .running
            .iter()
            .position(|running| running.tag == tag && running.result.is_some())
        {
            let running = disk.running.remove(index);
            disk.release(running.slot);
            break running.result.unwrap();
        }
    };
    outcome(disk, link, result)
}

/// `command` on `disk` through the block device's start and finish, a
/// look every [`BETWEEN_LOOKS_US`], each timed on the virtual clock.
fn stepped(disk: &mut AhciDisk, link: &Rc<Link>, command: Command) -> (Outcome, Steps) {
    let mut steps = Steps::default();
    let timed = |steps: &mut Steps, look: &mut dyn FnMut() -> Option<Finished>| {
        let before = VIRTUAL.now_us();
        let finished = look();
        steps.longest_us = steps.longest_us.max(VIRTUAL.now_us() - before);
        steps.looks += 1;
        finished
    };
    let mut tag = None;
    timed(&mut steps, &mut || {
        tag = Some(disk.start_on(link, command.clone()).unwrap());
        None
    });
    let tag = tag.unwrap();
    let result = loop {
        crate::test_clock::advance(VIRTUAL, BETWEEN_LOOKS_US);
        let was = disk.recovering();
        if let Some(finished) = timed(&mut steps, &mut || disk.finish_on(link, tag)) {
            break finished;
        }
        if disk.recovering() {
            steps.recovering += 1;
            // The port takes no other command meanwhile, and says so.
            assert!(!disk.room());
            assert_eq!(disk.depth(), 1);
            // After a step that found it waiting, the next look is due a
            // millisecond on.
            assert!(!was || !disk.posted());
        }
        assert!(steps.looks < 1_000_000, "error handling ends");
    };
    (outcome(disk, link, result), steps)
}

/// A disk identified from `identify_page`, with its controller's timer
/// model, whose blocking waits and begun intervals show which a run used.
fn timed() -> (Fixture, crate::test_clock::Guard, Rc<MinimumModel>) {
    let timer = Rc::new(MinimumModel::default());
    let (fixture, clock) =
        recovering_on(identify_page("S1", 1024), 0, Control::model(timer.clone()));
    (fixture, clock, timer)
}

#[test]
fn a_hard_reset_runs_in_bounded_steps_and_ends_as_in_place() {
    // Reference: ata_eh_reset with ahci_hardreset, ata_eh_revalidate_and_attach.
    let (mut reference, _clock, timer) = timed();
    let link = Link::new(&[Fault::Interface]);
    let expected = in_place(&mut reference.disk, &link, write());
    assert_eq!(expected.result, Ok(None));
    // In place, COMRESET's hold, the resume's settle and each debounce
    // interval are waited in.
    assert_eq!(
        timer.waits.borrow()[..2],
        [COMRESET_HOLD_US, RESUME_SETTLE_US]
    );
    assert!(timer.intervals.borrow().is_empty());
    // The write, the revalidating IDENTIFY, SET FEATURES with UDMA 6 and
    // its IDENTIFY, and the write again, after COMRESET.
    assert_eq!(expected.issued, 5);
    let controls: Vec<u32> = link
        .writes_to(PORT_SATA_CONTROL)
        .iter()
        .map(|control| control & 0xf0f)
        .collect();
    assert_eq!(controls, [0x301, 0x300]);

    let (mut fixture, _clock, timer) = timed();
    let link = Rc::new(Link::new(&[Fault::Interface]));
    let (found, steps) = stepped(&mut fixture.disk, &link, write());
    assert_eq!(found, expected);
    assert!(steps.longest_us <= STEP_BOUND_US, "{steps:?}");
    // Stepped, the same delays are looked at across many looks, none of
    // them waiting.
    assert!(timer.waits.borrow().is_empty());
    assert_eq!(
        timer.intervals.borrow()[..2],
        [COMRESET_HOLD_US, RESUME_SETTLE_US]
    );
    assert!(steps.recovering > 100, "{steps:?}");
    assert!(!fixture.disk.recovering());
}

#[test]
fn a_disk_that_never_comes_ready_fails_in_bounded_steps_as_in_place() {
    // Reference: ata_eh_reset_timeouts, ata_wait_ready.
    let start = VIRTUAL.now_us();
    let (mut reference, _clock) = recovering(identify_page("S1", 1024));
    let link = Link::new(&[Fault::Timeout]);
    link.stuck.set(true);
    let expected = in_place(&mut reference.disk, &link, write());
    // Four hard resets, each waiting its whole timeout for BSY to clear:
    // 10, 10, 35 and 5 s.
    assert_eq!(expected.result, Err(BlockError::Timeout));
    assert_eq!(expected.fault, Some(BlockError::Timeout));
    let resets = link
        .writes_to(PORT_SATA_CONTROL)
        .iter()
        .filter(|control| *control & 0xf == SATA_CONTROL_RESET)
        .count();
    assert_eq!(resets, RESET_TIMEOUTS_US.len());
    assert!(VIRTUAL.now_us() - start >= 60_000_000);
    // A disabled disk runs nothing more, its error kept.
    assert_eq!((expected.depth, expected.room), (0, false));
    assert_eq!(expected.next, Err(BlockError::Timeout));

    let (mut fixture, _clock) = recovering(identify_page("S1", 1024));
    let link = Rc::new(Link::new(&[Fault::Timeout]));
    link.stuck.set(true);
    let start = VIRTUAL.now_us();
    let (found, steps) = stepped(&mut fixture.disk, &link, write());
    assert_eq!(found, expected);
    assert!(VIRTUAL.now_us() - start >= 60_000_000);
    assert!(steps.longest_us <= STEP_BOUND_US, "{steps:?}");
    assert!(steps.recovering > 10_000, "{steps:?}");
}

#[test]
fn a_disk_that_fails_during_recovery_is_disabled_in_bounded_steps_as_in_place() {
    // Reference: ata_eh_recover with ata_eh_handle_dev_fail: each failed
    // revalidation costs a try, the last at a lower link speed and PIO
    // limit, and the third disables the disk.
    let faults = [
        Fault::Interface,
        Fault::TaskFile(0x0451),
        Fault::TaskFile(0x0451),
        Fault::TaskFile(0x0451),
    ];
    let (mut reference, _clock) = recovering(identify_page("S1", 1024));
    let link = Link::new(&faults);
    let expected = in_place(&mut reference.disk, &link, write());
    assert_eq!(expected.result, Err(BlockError::Device { status: 0x0451 }));
    assert_eq!(expected.fault, Some(BlockError::Device { status: 0x0451 }));
    assert_eq!(expected.issued, 4);
    let resets = link
        .writes_to(PORT_SATA_CONTROL)
        .iter()
        .filter(|control| *control & 0xf == SATA_CONTROL_RESET)
        .count();
    assert_eq!(resets, DEVICE_TRIES);
    assert_eq!(expected.speed_limit, 0b1);
    assert_eq!(expected.next, Err(BlockError::Device { status: 0x0451 }));

    let (mut fixture, _clock) = recovering(identify_page("S1", 1024));
    let link = Rc::new(Link::new(&faults));
    let (found, steps) = stepped(&mut fixture.disk, &link, write());
    assert_eq!(found, expected);
    assert!(steps.longest_us <= STEP_BOUND_US, "{steps:?}");
}

#[test]
fn a_look_after_a_waiting_step_says_it_would_find_more_a_millisecond_on() {
    let (mut fixture, _clock) = recovering(identify_page("S1", 1024));
    let link = Rc::new(Link::new(&[Fault::Interface]));
    let tag = fixture.disk.start_on(&link, write()).unwrap();
    // The failure is seen at a look; the next look starts error handling.
    while !fixture.disk.recovering() {
        assert_eq!(fixture.disk.finish_on(&link, tag), None);
    }
    assert!(fixture.disk.posted(), "its first step is due");
    assert_eq!(fixture.disk.finish_on(&link, tag), None);
    assert!(fixture.disk.recovering());
    assert!(!fixture.disk.posted());
    crate::test_clock::advance(VIRTUAL, 1_000);
    assert!(fixture.disk.posted());
    // A caller that waits runs the rest to its end in place, and the write
    // completes at its next look.
    fixture.disk.settled();
    assert!(!fixture.disk.recovering());
    assert_eq!(fixture.disk.finish_on(&link, tag), Some(Ok(None)));
    assert_eq!(link.issued.get(), 5);
}
