//! Native wire controls. All use xHC DMA rings, events and stop/dequeue.
use super::*;
use crate::usb::xhci::{HIGH_SPEED, SUPER_SPEED, model};
use alloc::{rc::Rc, vec};
use core::cell::RefCell;

type Fixture = (
    Host,
    Rc<RefCell<model::ResetHardware>>,
    crate::bus::dma::RegionAllocator,
);
const LUN: [u8; 8] = [0, 3, 0, 0, 0, 0, 0, 0];
const READ: [u8; 10] = [0x28, 0, 0, 0, 0, 7, 0, 0, 1, 0];
const WRITE: [u8; 10] = [0x2a, 0, 0, 0, 0, 7, 0, 0, 1, 0];
fn fixture(memory: &mut [u64], speed: u8, context: usize, streams: u16) -> Fixture {
    let (controller, device, hardware, mut dma) = model::reset_fixture(memory, speed, context, 1);
    controller
        .borrow_mut()
        .device(device.id)
        .unwrap()
        .set_configuration(1)
        .unwrap();
    let interface = crate::usb::xhci::interfaces(&device.configuration).remove(0);
    let binding = Binding::new(&device, &interface).unwrap();
    let host = if speed == SUPER_SPEED && streams == 1 {
        let endpoints = binding.endpoints();
        let actual = controller
            .borrow_mut()
            .device(device.id)
            .unwrap()
            .configure_streams(&endpoints, &binding.stream_endpoints(), 1, &mut dma)
            .unwrap();
        assert_eq!(actual, 1);
        Host {
            engine: Engine::new(
                Native {
                    controller,
                    id: device.id,
                    endpoints,
                    streams: Some(actual),
                },
                &mut dma,
            )
            .unwrap(),
            flags: binding.flags,
            device,
            binding,
        }
    } else {
        // SAFETY: this fixture exclusively owns the interface/endpoints.
        unsafe { Host::new(controller, &device, binding, &mut dma) }.unwrap()
    };
    (host, hardware, dma)
}
fn geometry(host: &Host) -> [(u64, usize); 3] {
    [&host.engine.command, &host.engine.status, &host.engine.data].map(|b| (b.physical(), b.len()))
}
fn contents(host: &Host) -> [Vec<u8>; 3] {
    [&host.engine.command, &host.engine.status, &host.engine.data].map(|b| b.bytes().to_vec())
}
fn fenced(host: &mut Host, hardware: &Rc<RefCell<model::ResetHardware>>, native_quarantine: bool) {
    assert!(host.requires_rebind());
    let snapshot = contents(host);
    let accesses = hardware.borrow().accesses;
    hardware.borrow_mut().trap_mmio = true;
    assert!(host.command(LUN, &READ, Data::In(512)).is_err());
    let again = host.command_with_abort_timeout(LUN, &READ, Data::In(512), 1);
    assert!(again.command.is_err());
    assert!(
        again.abort.is_none(),
        "a second TMF/tag reuse must never occur"
    );
    assert_eq!(
        host.engine
            .io
            .controller
            .borrow_mut()
            .device(host.device.id)
            .is_err(),
        native_quarantine
    );
    hardware.borrow_mut().trap_mmio = false;
    assert_eq!(hardware.borrow().accesses, accesses);
    assert_eq!(contents(host), snapshot);
}
#[test]
fn native_abort_task_requires_response_and_separate_pending_data_retirement() {
    for speed in [HIGH_SPEED, SUPER_SPEED] {
        for context in [32, 64] {
            for input in [false, true] {
                let mut memory = vec![0u64; 512 * 1024];
                let (mut host, hardware, dma) = fixture(&mut memory, speed, context, 2);
                let original = geometry(&host);
                let remaining = dma.remaining();
                hardware.borrow_mut().hang_next = true;
                let result = host.command_with_abort_timeout(
                    LUN,
                    if input { &READ } else { &WRITE },
                    if input {
                        Data::In(512)
                    } else {
                        Data::Out(&[0xb7; 512])
                    },
                    100_000,
                );
                assert_eq!(result.command, Err(BlockError::Timeout));
                assert_eq!(
                    result.abort,
                    Some(AbortTaskOutcome::Acknowledged { retirement: Ok(()) })
                );
                assert_eq!(geometry(&host), original);
                assert_eq!(dma.remaining(), remaining);
                assert!(host.engine.pending.iter().all(Option::is_none));
                let peer = hardware.borrow();
                assert_eq!(
                    peer.uas_abort_requests(),
                    &[task_iu(TaskTag(2), TaskTag(1), LUN).to_vec()]
                );
                assert_eq!(peer.uas_abort_pending_observations(), (&[1][..], &[1][..]));
                assert_eq!(peer.uas_pending_data(), 0);
                assert!(!peer.device_task);
                for dci in [5, if input { 7 } else { 8 }] {
                    assert!(
                        peer.commands_seen
                            .iter()
                            .any(|&(kind, _, endpoint)| kind == 15 && endpoint == dci)
                    );
                    assert!(
                        peer.commands_seen
                            .iter()
                            .any(|&(kind, _, endpoint)| kind == 16 && endpoint == dci)
                    );
                }
                drop(peer);
                assert_eq!(
                    &host.engine.data.bytes()[..512],
                    if input { &[0; 512] } else { &[0xb7; 512] }
                );
                fenced(&mut host, &hardware, false);
            }
        }
    }
}
#[test]
fn native_abort_task_negative_short_old_tag_and_missing_responses_keep_original_dma() {
    use model::UasAbortFault as F;
    for speed in [HIGH_SPEED, SUPER_SPEED] {
        for fault in [
            F::Response(2),
            F::Response(4),
            F::Response(5),
            F::Response(8),
            F::Response(9),
            F::Response(10),
            F::ShortResponse,
            F::WrongTag,
            F::OldStatus,
            F::Timeout,
            F::ShortCommand,
        ] {
            let mut memory = vec![0u64; 512 * 1024];
            let (mut host, hardware, dma) = fixture(&mut memory, speed, 64, 2);
            let original = geometry(&host);
            let remaining = dma.remaining();
            hardware.borrow_mut().hang_next = true;
            hardware.borrow_mut().uas_abort_fault(fault);
            let result =
                host.command_with_abort_timeout(LUN, &WRITE, Data::Out(&[0xb7; 512]), 100_000);
            assert_eq!(result.command, Err(BlockError::Timeout));
            assert!(
                matches!(result.abort, Some(AbortTaskOutcome::NotAcknowledged(_))),
                "{speed}/{fault:?}"
            );
            assert_eq!(geometry(&host), original);
            assert_eq!(dma.remaining(), remaining);
            assert!(host.engine.pending[Pipe::Output.index()].is_some());
            assert_eq!(&host.engine.data.bytes()[..512], &[0xb7; 512]);
            assert_eq!(hardware.borrow().uas_pending_data(), 1);
            assert!(hardware.borrow().device_task);
            assert_eq!(
                hardware.borrow().uas_abort_requests(),
                &[task_iu(TaskTag(2), TaskTag(1), LUN).to_vec()]
            );
            fenced(&mut host, &hardware, true);
        }
    }
}
#[test]
fn native_abort_device_ack_does_not_hide_failed_host_data_stop_or_dequeue() {
    for speed in [HIGH_SPEED, SUPER_SPEED] {
        for fault in [model::ResetFault::Stop(8), model::ResetFault::Dequeue(8)] {
            let mut memory = vec![0u64; 512 * 1024];
            let (mut host, hardware, dma) = fixture(&mut memory, speed, 32, 2);
            let original = geometry(&host);
            let remaining = dma.remaining();
            hardware.borrow_mut().hang_next = true;
            hardware.borrow_mut().fault = fault;
            let result =
                host.command_with_abort_timeout(LUN, &WRITE, Data::Out(&[0xb7; 512]), 100_000);
            assert_eq!(result.command, Err(BlockError::Timeout));
            assert!(matches!(
                result.abort,
                Some(AbortTaskOutcome::Acknowledged { retirement: Err(_) })
            ));
            assert!(host.engine.pending[Pipe::Output.index()].is_some());
            assert_eq!(geometry(&host), original);
            assert_eq!(dma.remaining(), remaining);
            assert_eq!(&host.engine.data.bytes()[..512], &[0xb7; 512]);
            assert!(!hardware.borrow().device_task);
            assert_eq!(
                hardware.borrow().uas_abort_pending_observations(),
                (&[1][..], &[1][..])
            );
            fenced(&mut host, &hardware, true);
        }
    }
}
#[test]
fn native_abort_refuses_before_tmf_when_original_command_receipt_is_missing() {
    for speed in [HIGH_SPEED, SUPER_SPEED] {
        let mut memory = vec![0u64; 512 * 1024];
        let (mut host, hardware, _) = fixture(&mut memory, speed, 64, 2);
        hardware.borrow_mut().hang_next = true;
        hardware.borrow_mut().uas_hold_command_event();
        let result = host.command_with_abort_timeout(LUN, &WRITE, Data::Out(&[0xb7; 512]), 100_000);
        assert!(matches!(
            result.abort,
            Some(AbortTaskOutcome::NotAcknowledged(_))
        ));
        assert!(hardware.borrow().uas_abort_requests().is_empty());
        assert!(host.engine.pending[Pipe::Command.index()].is_some());
        assert_eq!(host.engine.command.bytes()[0], COMMAND_IU);
        assert!(
            !hardware
                .borrow()
                .commands_seen
                .iter()
                .any(|&(kind, _, endpoint)| kind == 15 && endpoint == 5)
        );
        fenced(&mut host, &hardware, true);
    }
}
#[test]
fn native_abort_uses_distinct_allocated_stream_and_fences_all_later_tag_reuse() {
    for streams in [1, 2] {
        let mut memory = vec![0u64; 512 * 1024];
        let (mut host, hardware, _) = fixture(&mut memory, SUPER_SPEED, 64, streams);
        // With two streams an ordinary completed command first consumes
        // tag1; the outstanding CDB then uses2 and the TMF must use free stream1.
        if streams == 2 {
            assert!(host.command(LUN, &[0; 6], Data::None).is_ok());
        }
        hardware.borrow_mut().hang_next = true;
        let result = host.command_with_abort_timeout(LUN, &READ, Data::In(512), 100_000);
        if streams == 1 {
            assert!(matches!(
                result.abort,
                Some(AbortTaskOutcome::NotAcknowledged(_))
            ));
            assert!(hardware.borrow().uas_abort_requests().is_empty());
        } else {
            assert_eq!(
                result.abort,
                Some(AbortTaskOutcome::Acknowledged { retirement: Ok(()) })
            );
            assert_eq!(
                hardware.borrow().uas_abort_requests(),
                &[task_iu(TaskTag(1), TaskTag(2), LUN).to_vec()]
            );
        }
        fenced(&mut host, &hardware, streams == 1);
    }
}
#[test]
fn native_abort_invalid_deadline_and_ordinary_success_have_no_recovery_effects() {
    let mut memory = vec![0u64; 512 * 1024];
    let (mut host, hardware, _) = fixture(&mut memory, SUPER_SPEED, 32, 2);
    let before = contents(&host);
    let accesses = hardware.borrow().accesses;
    for timeout in [0, TIMEOUT_US + 1] {
        let result = host.command_with_abort_timeout(LUN, &READ, Data::In(512), timeout);
        assert!(result.command.is_err());
        assert!(result.abort.is_none());
    }
    assert_eq!(contents(&host), before);
    assert_eq!(hardware.borrow().accesses, accesses);
    let result = host.command_with_abort_timeout(LUN, &READ, Data::In(512), TIMEOUT_US);
    assert_eq!(result.command, Ok(vec![0x6d; 512]));
    assert!(result.abort.is_none());
    assert!(!host.requires_rebind());
    assert!(hardware.borrow().uas_abort_requests().is_empty());
}

/// Construct native outstanding IO up to the same Command/READY receipts
/// as the production command loop; stop before its deadline to snapshot owners.
fn outstanding(host: &mut Host, hardware: &Rc<RefCell<model::ResetHardware>>) {
    hardware.borrow_mut().hang_next = true;
    let engine = &mut host.engine;
    engine.io.ready().unwrap();
    engine.tag = 1;
    let iu = command_iu(1, LUN, &WRITE);
    engine.command.bytes_mut()[..iu.len()].copy_from_slice(&iu);
    engine.status.bytes_mut().fill(0);
    engine.data.bytes_mut()[..512].fill(0xb7);
    engine
        .post(Pipe::Status, engine.status.physical(), IU_BUFFER_BYTES)
        .unwrap();
    if engine.io.streams().is_some() {
        engine
            .post(Pipe::Output, engine.data.physical(), 512)
            .unwrap();
    }
    engine
        .post(Pipe::Command, engine.command.physical(), iu.len())
        .unwrap();
    let command = engine.pending[Pipe::Command.index()].as_ref().unwrap();
    assert_eq!(engine.io.completed(command), Some(Ok(iu.len())));
    engine.pending[Pipe::Command.index()] = None;
    if engine.io.streams().is_none() {
        let status = engine.pending[Pipe::Status.index()].as_ref().unwrap();
        assert_eq!(engine.io.completed(status), Some(Ok(4)));
        assert_eq!(&engine.status.bytes()[..4], &[WRITE_READY_IU, 0, 0, 1]);
        engine.pending[Pipe::Status.index()] = None;
        engine
            .post(Pipe::Status, engine.status.physical(), IU_BUFFER_BYTES)
            .unwrap();
        engine
            .post(Pipe::Output, engine.data.physical(), 512)
            .unwrap();
    }
    assert_eq!(hardware.borrow().uas_pending_data(), 1);
    let data = engine.pending[Pipe::Output.index()].as_ref().unwrap();
    assert_eq!(engine.io.completed(data), None);
    engine.poisoned = true;
}
#[test]
fn native_abort_status_drain_failure_preserves_both_iu_buffers_and_original_data() {
    for speed in [HIGH_SPEED, SUPER_SPEED] {
        for fault in [model::ResetFault::Stop(5), model::ResetFault::Dequeue(5)] {
            let mut memory = vec![0u64; 512 * 1024];
            let (mut host, hardware, dma) = fixture(&mut memory, speed, 64, 2);
            outstanding(&mut host, &hardware);
            let before = contents(&host);
            let original = geometry(&host);
            let remaining = dma.remaining();
            hardware.borrow_mut().fault = fault;
            assert!(matches!(
                host.engine.abort_task(LUN),
                AbortTaskOutcome::NotAcknowledged(_)
            ));
            assert_eq!(contents(&host), before);
            assert_eq!(geometry(&host), original);
            assert_eq!(dma.remaining(), remaining);
            assert!(host.engine.pending[Pipe::Status.index()].is_some());
            assert!(host.engine.pending[Pipe::Output.index()].is_some());
            assert_eq!(hardware.borrow().uas_pending_data(), 1);
            assert!(hardware.borrow().uas_abort_requests().is_empty());
            host.quarantine();
            fenced(&mut host, &hardware, true);
        }
    }
}
#[test]
fn native_abort_stale_generation_refuses_before_mmio_and_dma_rewrite() {
    let mut memory = vec![0u64; 512 * 1024];
    let (mut host, hardware, mut dma) = fixture(&mut memory, SUPER_SPEED, 64, 2);
    outstanding(&mut host, &hardware);
    let controller = host.engine.io.controller.clone();
    // SAFETY: this fixture owns the sole UAS interface and all its DCIs.
    let fresh = unsafe {
        controller.borrow_mut().reset_and_reuse_root(
            &host.device,
            &host.binding.endpoints(),
            &mut dma,
        )
    }
    .unwrap();
    assert_ne!(fresh.id, host.device.id);
    let snapshot = contents(&host);
    let accesses = hardware.borrow().accesses;
    hardware.borrow_mut().trap_mmio = true;
    assert!(matches!(
        host.engine.abort_task(LUN),
        AbortTaskOutcome::NotAcknowledged(_)
    ));
    hardware.borrow_mut().trap_mmio = false;
    assert_eq!(hardware.borrow().accesses, accesses);
    assert_eq!(contents(&host), snapshot);
    assert!(hardware.borrow().uas_abort_requests().is_empty());
    assert!(host.engine.pending[Pipe::Output.index()].is_some());
}
#[test]
fn native_abort_foreign_controller_identity_refuses_before_mmio_and_dma_rewrite() {
    let mut memory = vec![0u64; 512 * 1024];
    let (mut host, hardware, _) = fixture(&mut memory, HIGH_SPEED, 32, 2);
    outstanding(&mut host, &hardware);
    let mut foreign_memory = vec![0u64; 512 * 1024];
    let (foreign, _, _) = fixture(&mut foreign_memory, HIGH_SPEED, 32, 2);
    // This is another native controller's opaque identity, not a forged
    // numeric slot or caller-supplied generation.
    host.engine.io.id = foreign.device.id;
    let snapshot = contents(&host);
    let accesses = hardware.borrow().accesses;
    hardware.borrow_mut().trap_mmio = true;
    assert!(matches!(
        host.engine.abort_task(LUN),
        AbortTaskOutcome::NotAcknowledged(_)
    ));
    hardware.borrow_mut().trap_mmio = false;
    assert_eq!(hardware.borrow().accesses, accesses);
    assert_eq!(contents(&host), snapshot);
    assert!(hardware.borrow().uas_abort_requests().is_empty());
    assert!(host.engine.pending[Pipe::Output.index()].is_some());
}

#[test]
fn native_abort_wrong_original_lun_refuses_before_status_drain_or_dma_rewrite() {
    let mut memory = vec![0u64; 512 * 1024];
    let (mut host, hardware, _) = fixture(&mut memory, HIGH_SPEED, 64, 2);
    outstanding(&mut host, &hardware);
    let snapshot = contents(&host);
    let commands = hardware.borrow().commands_seen.clone();
    let mut wrong = LUN;
    wrong[1] += 1;
    assert_eq!(
        host.engine.abort_task(wrong),
        AbortTaskOutcome::NotAcknowledged(BlockError::Unsupported(
            "UAS abort original task identity"
        ))
    );
    assert_eq!(contents(&host), snapshot);
    assert_eq!(hardware.borrow().commands_seen, commands);
    assert!(hardware.borrow().uas_abort_requests().is_empty());
    assert!(host.engine.pending[Pipe::Status.index()].is_some());
    assert!(host.engine.pending[Pipe::Output.index()].is_some());
}

#[test]
fn native_acknowledged_abort_rebinds_only_after_whole_device_reset_and_fresh_identity() {
    for speed in [HIGH_SPEED, SUPER_SPEED] {
        for context in [32, 64] {
            let mut memory = vec![0u64; 512 * 1024];
            let (mut host, hardware, _) = fixture(&mut memory, speed, context, 2);
            let original = geometry(&host);
            let id = host.device.id;
            let controller = host.engine.io.controller.clone();
            let original_controller = controller.borrow().reset_allocation_geometry(id).unwrap();
            hardware.borrow_mut().hang_next = true;
            let result =
                host.command_with_abort_timeout(LUN, &WRITE, Data::Out(&[0xb7; 512]), 100_000);
            assert_eq!(result.command, Err(BlockError::Timeout));
            assert_eq!(
                result.abort,
                Some(AbortTaskOutcome::Acknowledged { retirement: Ok(()) })
            );
            fenced(&mut host, &hardware, false);
            struct NoAllocation;
            impl DmaAllocator for NoAllocation {
                fn allocate(&mut self, _: usize, _: usize) -> Result<DmaBuffer, BlockError> {
                    panic!("abort rebind allocated new DMA")
                }
            }
            let mut fresh = host.reset_and_rebind(&mut NoAllocation).unwrap();
            assert_eq!(hardware.borrow().resets, 1);
            assert_ne!(fresh.device.id, id);
            assert_eq!(geometry(&fresh), original);
            assert_eq!(
                controller
                    .borrow()
                    .reset_allocation_geometry(fresh.device.id)
                    .unwrap(),
                original_controller
            );
            assert!(!host.engine.buffers_present());
            assert!(host.requires_rebind());
            let current_bytes = contents(&fresh);
            let accesses = hardware.borrow().accesses;
            hardware.borrow_mut().trap_mmio = true;
            assert!(host.command(LUN, &READ, Data::In(512)).is_err());
            assert!(host.engine.io.ready().is_err());
            hardware.borrow_mut().trap_mmio = false;
            assert_eq!(hardware.borrow().accesses, accesses);
            assert_eq!(contents(&fresh), current_bytes);
            assert!(!fresh.requires_rebind());
            fresh.command(LUN, &WRITE, Data::Out(&[0x39; 512])).unwrap();
            assert_eq!(
                fresh.command(LUN, &READ, Data::In(512)),
                Ok(vec![0x39; 512])
            );
        }
    }
}
