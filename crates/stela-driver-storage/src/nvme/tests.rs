use super::*;
use crate::bus::{dma::RegionAllocator, mmio::Mmio};
use alloc::boxed::Box;

struct Fixture {
    disk: Namespace,
    // The real driver uses volatile MMIO/DMA accesses to these owned,
    // stable allocations. This fixture advances completions explicitly;
    // it is not a physical NVMe model or a reset validation.
    _registers: Box<[u64]>,
    _memory: Vec<u64>,
}

impl Fixture {
    fn new() -> Self {
        let mut registers = vec![0u64; 1024].into_boxed_slice();
        let mut memory = vec![0u64; 65536];
        let start = memory.as_mut_ptr() as u64;
        // SAFETY: this fixture owns both stable allocations until after
        // all controller operations; no device accesses them.
        let (mmio, mut dma) = unsafe {
            (
                Mmio::new(registers.as_mut_ptr() as u64),
                RegionAllocator::new(start..start + (memory.len() * 8) as u64),
            )
        };
        let slots = (1..DEPTH)
            .map(|_| Slot {
                bounce: Buffer::Legacy(dma.allocate(4 * PAGE, PAGE).unwrap()),
                prp_list: Buffer::Legacy(dma.allocate(PAGE, PAGE).unwrap()),
            })
            .collect();
        let controller = Controller {
            registers: RegisterIo::Legacy(mmio),
            doorbell_stride: 4,
            admin: Queue::new(0, ADMIN_ENTRIES, &mut dma).unwrap(),
            io: Queue::new(1, IO_ENTRIES, &mut dma).unwrap(),
            bounce: Buffer::Legacy(dma.allocate(BOUNCE_BYTES, PAGE).unwrap()),
            prp_list: Buffer::Legacy(dma.allocate(PAGE, PAGE).unwrap()),
            slots,
            prp_pages: [1; DEPTH],
            tags: (0..DEPTH).map(|_| Tag::Free).collect(),
            recovery: None,
            signalled: false,
            max_transfer: BOUNCE_BYTES,
            max_command_bytes: MAX_COMMAND_BYTES,
            shutdown_timeout_us: 1000,
            shut_down: false,
            command_id: 0,
            // Exercise a real finite deadline with a short captured test
            // policy; native attachment keeps its thirty-second policy.
            clock: Clock {
                ticks_per_microsecond: 1000,
            },
            command_timeout_us: 1000,
            admin_timeout_us: 1000,
            fault: None,
            owned: None,
            teardown: owned::Teardown::Unprepared,
            ready_timeout_us: 500_000,
            configuration: CONFIGURATION_VALUE & !ENABLE,
            independent_identify: false,
            version: 0,
            commands: 0,
            scans: 0,
            retry_delays: [0; 3],
            host_memory: None,
            host_memory_enabled: false,
            events: Events::default(),
            aborts: Vec::new(),
            limits: Limits::default(),
        };
        Self {
            _registers: registers,
            _memory: memory,
            disk: Namespace {
                controller: Rc::new(RefCell::new(controller)),
                namespace: 1,
                ids: Ids::default(),
                scanned: 0,
                removed: None,
                identity: Identity {
                    transport: Transport::Nvme,
                    location: "fixture".into(),
                    model: "fixture".into(),
                    serial: "fixture".into(),
                    blocks: 1024,
                    block_size: 512,
                    read_only: false,
                    features: Features {
                        write_cache: true,
                        fua: true,
                        max_transfer: BOUNCE_BYTES,
                        ..Features::default()
                    },
                },
            },
        }
    }
}

#[test]
fn a_timeout_aborts_then_a_controller_that_stays_down_poisons_its_siblings() {
    let _clock = crate::test_clock::virtualize();
    let mut fixture = Fixture::new();
    fixture.disk.controller.borrow_mut().clock = Clock {
        ticks_per_microsecond: 1,
    };
    // Nothing answers: the write times out, its abort goes unanswered,
    // and the controller never reports ready again after its reset.
    assert_eq!(
        fixture.disk.write(0, &[0x31; 512]),
        Err(BlockError::Timeout)
    );
    let mut sibling = Namespace {
        controller: fixture.disk.controller.clone(),
        namespace: 2,
        identity: fixture.disk.identity.clone(),
        ids: Ids::default(),
        scanned: 0,
        removed: None,
    };
    {
        let c = fixture.disk.controller.borrow();
        // The abort names the write's command and queue.
        let abort = &c.admin.submissions.bytes()[..64];
        assert_eq!(abort[0], ADMIN_ABORT);
        assert_eq!(
            u32::from_le_bytes(abort[40..44].try_into().unwrap()),
            1 << 16 | 1
        );
        // The reset re-enabled the controller with the admin queue.
        assert_eq!(
            c.registers.read32(CONFIGURATION).unwrap(),
            CONFIGURATION_VALUE
        );
        assert_eq!(c.fault, Some(BlockError::Timeout));
        assert_eq!(c.command_id, 2);
    }
    let mut output = vec![0x55; 512];
    assert_eq!(sibling.read(0, &mut output), Err(BlockError::Timeout));
    assert!(output.iter().all(|byte| *byte == 0x55));
    assert_eq!(sibling.flush(), Err(BlockError::Timeout));
    assert_eq!(fixture.disk.controller.borrow().command_id, 2);
}

#[test]
fn unrelated_or_malformed_completions_do_not_retire_our_command() {
    for (cid, sqid, head) in [
        (2u32, 1u32, 1u32),
        (1, 2, 1),
        (1, 1, 16),
        (1, 1, 0),
        (1, 1, 2),
    ] {
        let mut fixture = Fixture::new();
        {
            let mut c = fixture.disk.controller.borrow_mut();
            c.io.completions.write(8, sqid << 16 | head);
            c.io.completions.write(12, 1u32 << 16 | cid);
        }
        let error = BlockError::Device { status: 0xffff };
        assert_eq!(fixture.disk.flush(), Err(error.clone()));
        assert_eq!(fixture.disk.write(0, &[0x71; 512]), Err(error));
        let c = fixture.disk.controller.borrow();
        assert_eq!(c.io.head, 0);
        assert_eq!(c.registers.read32(DOORBELLS + 12).unwrap(), 0);
        assert!(c.bounce.bytes().iter().all(|byte| *byte == 0));
    }
}

#[test]
fn sq_head_validation_preserves_wrap_and_rejects_stale_or_ahead_heads() {
    let stale = u32::from(IO_ENTRIES - 1);
    for invalid_head in [None, Some(stale), Some(1)] {
        let mut fixture = Fixture::new();
        for next in 1..IO_ENTRIES {
            {
                let mut c = fixture.disk.controller.borrow_mut();
                let offset = usize::from(next - 1) * 16;
                c.io.completions
                    .write(offset + 8, 1u32 << 16 | u32::from(next));
                c.io.completions
                    .write(offset + 12, 1u32 << 16 | u32::from(next));
            }
            fixture.disk.flush().unwrap();
        }
        {
            let mut c = fixture.disk.controller.borrow_mut();
            let last = usize::from(IO_ENTRIES - 1) * 16;
            c.io.completions
                .write(last + 8, 1u32 << 16 | invalid_head.unwrap_or(0));
            c.io.completions
                .write(last + 12, 1u32 << 16 | u32::from(IO_ENTRIES));
        }
        let result = fixture.disk.flush();
        let mut c = fixture.disk.controller.borrow_mut();
        assert_eq!(c.io.tail, 0);
        match invalid_head {
            Some(_) => {
                assert_eq!(result, Err(BlockError::Device { status: 0xffff }));
                assert_eq!(c.io.head, IO_ENTRIES - 1);
                assert!(c.io.phase);
            }
            None => {
                assert_eq!(result, Ok(()));
                assert_eq!(c.io.head, 0);
                assert!(!c.io.phase);
                c.io.completions.write(8, 1u32 << 16 | 1);
                c.io.completions.write(12, u32::from(IO_ENTRIES) + 1); // New phase is zero.
                drop(c);
                fixture.disk.flush().unwrap();
            }
        }
    }
}

#[test]
fn completed_command_error_is_distinct_from_unresolved_dma() {
    let mut fixture = Fixture::new();
    {
        let mut c = fixture.disk.controller.borrow_mut();
        c.io.completions.write(8, 1u32 << 16 | 1);
        // Invalid Field, with Do Not Retry.
        c.io.completions
            .write(12, (STATUS_DO_NOT_RETRY | 2) << 17 | 1 << 16 | 1);
    }
    assert_eq!(
        fixture.disk.flush(),
        Err(BlockError::Device {
            status: STATUS_DO_NOT_RETRY | 2
        })
    );
    {
        let mut c = fixture.disk.controller.borrow_mut();
        assert!(c.fault.is_none());
        assert_eq!(c.io.head, 1);
        c.io.completions.write(16 + 8, 1u32 << 16 | 2);
        c.io.completions.write(16 + 12, 1u32 << 16 | 2);
    }
    assert_eq!(fixture.disk.flush(), Ok(()));
    assert_eq!(fixture.disk.controller.borrow().io.head, 2);
}

#[test]
fn a_fatal_controller_is_reset_first_and_poisons_when_it_stays_fatal() {
    let mut fixture = Fixture::new();
    fixture
        .disk
        .controller
        .borrow()
        .registers
        .write32(STATUS, FATAL)
        .unwrap();
    let error = BlockError::Device { status: FATAL };
    assert_eq!(fixture.disk.write(0, &[0xa9; 512]), Err(error.clone()));
    fixture
        .disk
        .controller
        .borrow()
        .registers
        .write32(STATUS, 0)
        .unwrap();
    assert_eq!(fixture.disk.flush(), Err(error));
    let c = fixture.disk.controller.borrow();
    // Nothing was submitted to the fatal controller, whose reset found
    // it fatal again.
    assert_eq!(
        c.registers.read32(CONFIGURATION).unwrap(),
        CONFIGURATION_VALUE
    );
    assert_eq!((c.command_id, c.io.tail, c.io.head), (0, 0, 0));
    assert!(c.io.submissions.bytes().iter().all(|byte| *byte == 0));
    assert!(c.bounce.bytes().iter().all(|byte| *byte == 0));
    assert_eq!(c.registers.read32(DOORBELLS + 8).unwrap(), 0);
}

fn namespace(blocks: u64, flbas: u8, formats: &[(usize, u32)], attributes: u8) -> Vec<u8> {
    let mut page = vec![0u8; PAGE];
    page[NAMESPACE_SIZE].copy_from_slice(&blocks.to_le_bytes());
    page[NAMESPACE_FORMAT] = flbas;
    page[NAMESPACE_ATTRIBUTES] = attributes;
    for &(index, descriptor) in formats {
        page[NAMESPACE_FORMATS + 4 * index..][..4].copy_from_slice(&descriptor.to_le_bytes());
    }
    page
}

#[test]
fn namespace_formats_use_both_flbas_index_fields_and_write_protection() {
    // Format 17 (index bits 0001 and 01) holds 4 KiB blocks.
    let page = namespace(64, 1 | 1 << 5, &[(17, 12 << 16)], NAMESPACE_WRITE_PROTECTED);
    let format = plain_format(&page, BOUNCE_BYTES).unwrap().unwrap();
    assert_eq!((format.blocks, format.block_size), (64, 4096));
    assert!(format.read_only);
    assert!(
        plain_format(&namespace(0, 0, &[], 0), BOUNCE_BYTES)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        plain_format(&namespace(8, 0, &[(0, 8 | 9 << 16)], 0), BOUNCE_BYTES).err(),
        Some(BlockError::Unsupported("NVMe format with metadata"))
    );
    // A 64 KiB block cannot fit an 8 KiB maximum transfer.
    assert_eq!(
        plain_format(&namespace(8, 0, &[(0, 16 << 16)], 0), 2 * PAGE).err(),
        Some(BlockError::Unsupported("NVMe logical block size"))
    );
}

#[test]
fn shutdown_waits_follow_the_rtd3_entry_latency_within_linux_bounds() {
    assert_eq!(shutdown_timeout_us(0), SHUTDOWN_MINIMUM_US);
    assert_eq!(shutdown_timeout_us(8_000_001), 9 * MICROSECONDS_PER_SECOND);
    assert_eq!(shutdown_timeout_us(u64::MAX), SHUTDOWN_MAXIMUM_US);
}

/// Post, at the I/O queue's head, the completion of the command `id`,
/// with every submission up to the tail consumed.
fn post(controller: &mut Controller, id: u16, status: u32) {
    let entry = usize::from(controller.io.head) * 16;
    let tail = u32::from(controller.io.tail);
    let phase = u32::from(controller.io.phase) << 16;
    controller
        .io
        .completions
        .write(entry + 8, 1u32 << 16 | tail);
    controller
        .io
        .completions
        .write(entry + 12, status << 17 | phase | u32::from(id));
}

/// Post, at the admin queue's head, the completion of the command `id`.
fn post_admin(controller: &mut Controller, id: u16, status: u32) {
    let entry = usize::from(controller.admin.head) * 16;
    let tail = u32::from(controller.admin.tail);
    let phase = u32::from(controller.admin.phase) << 16;
    controller.admin.completions.write(entry + 8, tail);
    controller
        .admin
        .completions
        .write(entry + 12, status << 17 | phase | u32::from(id));
}

fn running_id(controller: &Controller, tag: u32) -> u16 {
    match controller.tags[tag as usize] {
        Tag::Running { id, .. } => id,
        _ => panic!("tag {tag} runs nothing"),
    }
}

#[test]
fn prp_list_prefixes_follow_each_bounce_mapping_and_only_grow() {
    let mut fixture = Fixture::new();
    let disk = &mut fixture.disk;
    let submit = |disk: &mut Namespace, pages| {
        disk.start(Command::Read {
            lba: 0,
            bytes: pages * PAGE,
        })
        .unwrap()
    };
    let check = |disk: &Namespace, tag: u32, pages| {
        let mut controller = disk.controller.borrow_mut();
        let tag = tag as usize;
        assert_eq!(controller.prp_pages[tag], pages);
        let (bounce, list) = controller.slot(tag);
        let base = bounce.address().unwrap();
        for page in 1..=pages {
            let start = (page - 1) * 8;
            let entry = u64::from_le_bytes(list.bytes()[start..start + 8].try_into().unwrap());
            let expected = if page < pages {
                base + (page * PAGE) as u64
            } else {
                0
            };
            assert_eq!(entry, expected);
        }
        base
    };
    let complete = |disk: &mut Namespace, tag| {
        {
            let mut controller = disk.controller.borrow_mut();
            let id = running_id(&controller, tag);
            post(&mut controller, id, 0);
        }
        assert!(matches!(disk.finish(tag), Some(Ok(Some(_)))));
    };
    let first = submit(disk, 3);
    let second = submit(disk, 4);
    let base = check(disk, first, 3);
    assert_ne!(check(disk, second, 4), base);
    complete(disk, first);
    assert_eq!(submit(disk, 2), first);
    assert_eq!(check(disk, first, 3), base);
    complete(disk, first);
    assert_eq!(submit(disk, 5), first);
    assert_eq!(check(disk, first, 5), base);
    complete(disk, second);
    complete(disk, first);
}

#[test]
fn queued_commands_run_together_and_complete_in_any_order() {
    let mut fixture = Fixture::new();
    let disk = &mut fixture.disk;
    assert_eq!(disk.depth(), DEPTH);
    let read = disk.start(Command::Read { lba: 0, bytes: 512 }).unwrap();
    let write = disk
        .start(Command::Write {
            lba: 1,
            data: vec![7; 512],
            fua: true,
        })
        .unwrap();
    assert_ne!(read, write);
    assert_eq!(
        disk.controller.borrow().io.tail,
        2,
        "both submitted at once"
    );
    assert_eq!(disk.finish(read), None, "not complete yet");
    {
        let mut controller = disk.controller.borrow_mut();
        // The write carries Force Unit Access.
        let words = controller.io.submissions.bytes()[64 + 48..64 + 52].to_vec();
        assert_eq!(
            u32::from_le_bytes(words.try_into().unwrap()),
            FORCE_UNIT_ACCESS
        );
        // The write completes first.
        let id = running_id(&controller, write);
        post(&mut controller, id, 0);
    }
    assert_eq!(disk.finish(write), Some(Ok(None)));
    assert_eq!(disk.finish(read), None);
    {
        let mut controller = disk.controller.borrow_mut();
        let tag = read as usize;
        controller.slot(tag).0.bytes_mut()[..512].fill(0x42);
        let id = running_id(&controller, read);
        post(&mut controller, id, 0);
    }
    assert_eq!(disk.finish(read), Some(Ok(Some(vec![0x42; 512]))));
    assert_eq!(disk.controller.borrow().io.head, 2);
    // Every tag in use leaves no room.
    for _ in 0..DEPTH {
        disk.start(Command::Flush).unwrap();
    }
    assert!(!disk.room());
    assert!(disk.start(Command::Flush).is_err());
}

#[test]
fn delayed_read_completes_after_submission_ring_wraps() {
    let _clock = crate::test_clock::virtualize();
    for turns in [1, 2] {
        let mut fixture = Fixture::new();
        let disk = &mut fixture.disk;
        let delayed = disk.start(Command::Read { lba: 0, bytes: 512 }).unwrap();
        let delayed_id = running_id(&disk.controller.borrow(), delayed);
        for _ in 1..usize::from(IO_ENTRIES) * turns {
            let read = disk.start(Command::Read { lba: 1, bytes: 512 }).unwrap();
            {
                let mut controller = disk.controller.borrow_mut();
                controller.slot(read as usize).0.bytes_mut()[..512].fill(0x71);
                let id = running_id(&controller, read);
                post(&mut controller, id, 0);
            }
            assert_eq!(disk.finish(read), Some(Ok(Some(vec![0x71; 512]))));
            assert_eq!(disk.finish(delayed), None);
        }
        {
            let mut controller = disk.controller.borrow_mut();
            assert_eq!(controller.io.tail, 0);
            assert_eq!(controller.io.consumed, 0);
            controller.slot(delayed as usize).0.bytes_mut()[..512].fill(0x42);
            post(&mut controller, delayed_id, 0);
        }
        assert_eq!(disk.finish(delayed), Some(Ok(Some(vec![0x42; 512]))));
        assert!(disk.controller.borrow().fault.is_none());
    }
}

#[test]
fn reused_tag_requires_its_new_submission_to_be_fetched() {
    let _clock = crate::test_clock::virtualize();
    let mut fixture = Fixture::new();
    let disk = &mut fixture.disk;
    let first = disk.start(Command::Read { lba: 0, bytes: 512 }).unwrap();
    {
        let mut controller = disk.controller.borrow_mut();
        let id = running_id(&controller, first);
        post(&mut controller, id, 0);
    }
    assert!(disk.finish(first).unwrap().is_ok());
    let second = disk.start(Command::Read { lba: 1, bytes: 512 }).unwrap();
    assert_eq!(first, second);
    {
        let mut controller = disk.controller.borrow_mut();
        let id = running_id(&controller, second);
        let entry = usize::from(controller.io.head) * 16;
        let consumed = u32::from(controller.io.consumed);
        let phase = u32::from(controller.io.phase) << 16;
        controller
            .io
            .completions
            .write(entry + 8, 1u32 << 16 | consumed);
        controller
            .io
            .completions
            .write(entry + 12, phase | u32::from(id));
    }
    assert_eq!(
        disk.finish(second),
        Some(Err(BlockError::Device { status: 0xffff }))
    );
    assert_eq!(disk.controller.borrow().io.head, 1);
}

#[test]
fn deallocate_and_write_zeroes_carry_their_ranges() {
    let mut fixture = Fixture::new();
    let disk = &mut fixture.disk;
    let discard = disk
        .start(Command::Discard {
            extents: vec![
                crate::block::Extent { lba: 9, blocks: 3 },
                crate::block::Extent { lba: 40, blocks: 2 },
            ],
        })
        .unwrap();
    let zeroes = disk
        .start(Command::WriteZeroes {
            lba: 20,
            blocks: 4,
            unmap: true,
        })
        .unwrap();
    let mut controller = disk.controller.borrow_mut();
    let word = |controller: &Controller, entry: usize, index: usize| {
        let bytes = &controller.io.submissions.bytes()[entry * 64 + 4 * index..][..4];
        u32::from_le_bytes(bytes.try_into().unwrap())
    };
    assert_eq!(
        word(&controller, 0, 0) & 0xff,
        u32::from(IO_DATASET_MANAGEMENT)
    );
    assert_eq!(word(&controller, 0, 10), 1);
    assert_eq!(word(&controller, 0, 11), ATTRIBUTE_DEALLOCATE);
    let range = controller.slot(discard as usize).0.bytes()[..32].to_vec();
    assert_eq!(range[4..8], 3u32.to_le_bytes());
    assert_eq!(range[8..16], 9u64.to_le_bytes());
    assert_eq!(range[20..24], 2u32.to_le_bytes());
    assert_eq!(range[24..32], 40u64.to_le_bytes());
    assert_eq!(word(&controller, 1, 0) & 0xff, u32::from(IO_WRITE_ZEROES));
    assert_eq!(word(&controller, 1, 10), 20);
    assert_eq!(word(&controller, 1, 12), 3 | DEALLOCATE);
    let _ = zeroes;
}

#[test]
fn a_command_past_its_deadline_is_aborted_then_resets_the_controller_and_runs_again() {
    let _clock = crate::test_clock::virtualize();
    let mut fixture = Fixture::new();
    let disk = &mut fixture.disk;
    let read = disk.start(Command::Read { lba: 0, bytes: 512 }).unwrap();
    let read_id = running_id(&disk.controller.borrow(), read);
    let wait = |disk: &mut Namespace| {
        let clock = disk.controller.borrow().clock;
        let started = clock.try_start().unwrap();
        while clock.try_elapsed_us(started).unwrap() < 1000 {
            core::hint::spin_loop();
        }
    };
    // The deadline passes: the read is aborted and given another.
    wait(disk);
    assert_eq!(disk.finish(read), None);
    {
        let mut controller = disk.controller.borrow_mut();
        let abort = &controller.admin.submissions.bytes()[..64];
        assert_eq!(abort[0], ADMIN_ABORT);
        assert_eq!(abort[40..44], (u32::from(read_id) << 16 | 1).to_le_bytes());
        // The controller reports it not aborted.
        let id = controller.aborts[0];
        post_admin(&mut controller, id, 0);
    }
    assert_eq!(disk.finish(read), None);
    assert!(disk.controller.borrow().aborts.is_empty());
    // The second deadline passes: the controller, not ready, is disabled.
    wait(disk);
    assert_eq!(disk.finish(read), None);
    {
        let controller = disk.controller.borrow();
        assert!(matches!(controller.recovery, Some(Recovery::Disabling(_))));
        assert_eq!(controller.registers.read32(CONFIGURATION).unwrap(), 0);
        assert!(!disk.room());
    }
    // CSTS.RDY is clear: it is enabled again.
    assert_eq!(disk.finish(read), None);
    {
        let controller = disk.controller.borrow();
        assert!(matches!(controller.recovery, Some(Recovery::Enabling(_))));
        controller.registers.write32(STATUS, READY).unwrap();
    }
    // Ready: identified, then the I/O queues created again, completion
    // queue first.
    for opcode in [
        ADMIN_IDENTIFY,
        ADMIN_CREATE_COMPLETION,
        ADMIN_CREATE_SUBMISSION,
    ] {
        assert_eq!(disk.finish(read), None);
        let mut controller = disk.controller.borrow_mut();
        let Some(Recovery::Admin { id, .. }) = controller.recovery else {
            panic!("no bring-up command");
        };
        let offset = usize::from(controller.admin.tail - 1) * 64;
        assert_eq!(controller.admin.submissions.bytes()[offset], opcode);
        post_admin(&mut controller, id, 0);
    }
    // The interrupted read runs again on the empty queue.
    assert_eq!(disk.finish(read), None);
    let mut controller = disk.controller.borrow_mut();
    assert!(controller.recovery.is_none());
    assert_eq!(controller.scans, 1);
    assert_eq!((controller.io.tail, controller.io.head), (1, 0));
    let id = running_id(&controller, read);
    controller.bounce.bytes_mut()[..512].fill(0x5a);
    post(&mut controller, id, 0);
    drop(controller);
    assert_eq!(disk.finish(read), Some(Ok(Some(vec![0x5a; 512]))));
}

#[test]
fn errors_without_do_not_retry_run_again_after_their_retry_delay() {
    let _clock = crate::test_clock::virtualize();
    let mut fixture = Fixture::new();
    let disk = &mut fixture.disk;
    disk.controller.borrow_mut().clock = Clock {
        ticks_per_microsecond: 1,
    };
    disk.controller.borrow_mut().retry_delays = [1, 0, 0];
    let flush = disk.start(Command::Flush).unwrap();
    {
        let mut controller = disk.controller.borrow_mut();
        let id = running_id(&controller, flush);
        // Namespace Not Ready with CRD 1: 100 ms.
        post(&mut controller, id, 0x82 | 1 << 11);
    }
    assert_eq!(disk.finish(flush), None);
    assert!(matches!(
        disk.controller.borrow().tags[flush as usize],
        Tag::Delayed { retries: 1, .. }
    ));
    let clock = disk.controller.borrow().clock;
    let started = clock.try_start().unwrap();
    while disk.controller.borrow().io.tail == 1 {
        assert_eq!(disk.finish(flush), None);
    }
    assert!(clock.try_elapsed_us(started).unwrap() >= 100_000);
    {
        let mut controller = disk.controller.borrow_mut();
        let id = running_id(&controller, flush);
        post(&mut controller, id, 0);
    }
    assert_eq!(disk.finish(flush), Some(Ok(None)));
}

/// Each state idles into the deepest usable non-operational state below
/// it, one per latency tolerance, as Linux `nvme_configure_apst`.
#[test]
fn apst_follows_linux_tolerances_from_the_deepest_state_up() {
    let mut identify = vec![0u8; PAGE];
    assert_eq!(apst_table(&identify), None, "no APST support");
    identify[CONTROLLER_APST] = 1;
    identify[CONTROLLER_POWER_STATES] = 5;
    // (state, entry us, exit us): PS5's exit is past the latency limit.
    for (state, entry, exit) in [
        (2, 500, 500),
        (3, 2_000, 2_000),
        (4, 4_000, 30_000),
        (5, 0, 200_000),
    ] {
        let descriptor = &mut identify[CONTROLLER_POWER_DESCRIPTORS + 32 * state..][..32];
        descriptor[3] = POWER_NON_OPERATIONAL;
        descriptor[4..8].copy_from_slice(&u32::to_le_bytes(entry));
        descriptor[8..12].copy_from_slice(&u32::to_le_bytes(exit));
    }
    let table = apst_table(&identify).unwrap();
    let primary = 3 << 3 | APST_PRIMARY_TIMEOUT_MS << 8;
    let secondary = 4 << 3 | APST_SECONDARY_TIMEOUT_MS << 8;
    assert_eq!(table[..6], [primary, primary, primary, secondary, 0, 0]);
    assert!(table[6..].iter().all(|&entry| entry == 0));
}

/// A signalled controller's I/O completion queue raises vector 0, and
/// a posted completion shows in memory before the namespace takes it.
#[test]
fn completions_are_signalled_and_posted_in_memory() {
    let mut fixture = Fixture::new();
    let disk = &mut fixture.disk;
    assert_eq!(disk.controller.borrow().create_queue(false).unwrap()[11], 1);
    disk.controller.borrow_mut().signalled = true;
    assert!(disk.signals());
    assert_eq!(
        disk.controller.borrow().create_queue(false).unwrap()[11],
        0b11
    );
    assert!(!disk.posted(), "nothing runs");
    let read = disk.start(Command::Read { lba: 0, bytes: 512 }).unwrap();
    assert!(!disk.posted());
    {
        let mut controller = disk.controller.borrow_mut();
        let id = running_id(&controller, read);
        post(&mut controller, id, 0);
    }
    assert!(disk.posted());
    assert!(disk.finish(read).is_some());
    assert!(!disk.posted());
}

#[test]
fn a_removed_controller_fails_its_commands_without_a_reset() {
    let mut fixture = Fixture::new();
    let disk = &mut fixture.disk;
    let read = disk.start(Command::Read { lba: 0, bytes: 512 }).unwrap();
    disk.controller
        .borrow()
        .registers
        .write32(STATUS, REMOVED)
        .unwrap();
    disk.controller.borrow_mut().reset();
    assert_eq!(disk.finish(read), Some(Err(removed())));
    assert!(disk.controller.borrow().recovery.is_none());
    assert_eq!(disk.read(0, &mut [0; 512]), Err(removed()));
}

#[test]
fn only_a_controller_with_a_volatile_write_cache_is_sent_flushes() {
    let mut fixture = Fixture::new();
    fixture.disk.identity.features.write_cache = false;
    assert_eq!(fixture.disk.flush(), Ok(()));
    assert_eq!(fixture.disk.controller.borrow().io.tail, 0);
    // With a cache the flush is submitted; this fixture never completes
    // it, nor its abort.
    fixture.disk.identity.features.write_cache = true;
    assert_eq!(fixture.disk.flush(), Err(BlockError::Timeout));
    let controller = fixture.disk.controller.borrow();
    assert_eq!(controller.io.submissions.bytes()[0], IO_FLUSH);
    assert_eq!(controller.admin.submissions.bytes()[0], ADMIN_ABORT);
}

#[test]
fn identification_descriptors_parse_like_nvme_identify_ns_descs() {
    let mut page = vec![0u8; PAGE];
    let mut at = 0;
    for (kind, value) in [
        (DESCRIPTOR_EUI64, &[1u8; 8][..]),
        (9, &[7; 5][..]),
        (DESCRIPTOR_UUID, &[3; 16][..]),
        (DESCRIPTOR_CSI, &[2][..]),
    ] {
        page[at] = kind;
        page[at + 1] = value.len() as u8;
        page[at + 4..at + 4 + value.len()].copy_from_slice(value);
        at += 4 + value.len();
    }
    let ids = Ids::from_descriptors(&page);
    assert_eq!(
        ids,
        Ids {
            eui64: [1; 8],
            nguid: [0; 16],
            uuid: [3; 16],
            csi: 2
        }
    );
    // A wrong length ends the list; Identify Namespace then fills EUI64
    // from 1.1 and NGUID from 1.2.
    page[1] = 9;
    let mut ids = Ids::from_descriptors(&page);
    assert_eq!(ids, Ids::default());
    let mut data = vec![0u8; PAGE];
    data[NAMESPACE_EUI64].fill(5);
    data[NAMESPACE_NGUID].fill(6);
    ids.fill(VERSION_1_1, &data);
    assert_eq!((ids.eui64, ids.nguid), ([5; 8], [0; 16]));
    ids.fill(VERSION_1_2, &data);
    assert_eq!(ids.nguid, [6; 16]);
}

#[test]
fn a_controller_shuts_down_once_and_then_refuses_commands() {
    let fixture = Fixture::new();
    let mut controller = fixture.disk.controller.borrow_mut();
    controller
        .registers
        .write32(CONFIGURATION, CONFIGURATION_VALUE)
        .unwrap();
    controller
        .registers
        .write32(STATUS, READY | SHUTDOWN_COMPLETE)
        .unwrap();
    // The I/O submission queue's deletion is refused (Invalid Queue
    // Identifier); its completion queue's succeeds.
    let completion = |c: &mut Controller, slot: usize, id: u32, status: u32| {
        c.admin.completions.write(16 * slot + 8, id);
        c.admin
            .completions
            .write(16 * slot + 12, status << 17 | 1 << 16 | id);
    };
    completion(&mut controller, 0, 1, 1);
    completion(&mut controller, 1, 2, 0);
    controller.shutdown().unwrap();
    let submitted = controller.admin.submissions.bytes();
    for (slot, opcode) in [(0, ADMIN_DELETE_SUBMISSION), (1, ADMIN_DELETE_COMPLETION)] {
        let entry = &submitted[64 * slot..64 * slot + 64];
        assert_eq!(entry[0], opcode);
        assert_eq!(u32::from_le_bytes(entry[40..44].try_into().unwrap()), 1);
    }
    assert_eq!(
        controller.registers.read32(CONFIGURATION).unwrap(),
        CONFIGURATION_VALUE | SHUTDOWN_NORMAL
    );
    controller.registers.write32(CONFIGURATION, 0).unwrap();
    controller.shutdown().unwrap();
    assert_eq!(controller.registers.read32(CONFIGURATION).unwrap(), 0);
    assert_eq!(
        controller.ready(),
        Err(BlockError::Unsupported("NVMe controller is shut down"))
    );
}
