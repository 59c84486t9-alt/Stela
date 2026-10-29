// SPDX-License-Identifier: GPL-2.0-only
//! Real DMA/command/event reset cycles. No generation or return token is injected.
use super::*;

pub(super) fn iso_configuration(speed: u8) -> Vec<u8> {
    let mut raw = vec![
        9, 2, 0, 0, 1, 1, 0, 0x80, 0, 9, 4, 0, 0, 1, 0xff, 0, 0, 0, 7, 5, 0x81, 1, 0, 4, 1,
    ];
    if speed >= SUPER_SPEED {
        raw.extend_from_slice(&[6, 48, 0, 0, 0, 4]);
    }
    let length = raw.len() as u16;
    raw[2..4].copy_from_slice(&length.to_le_bytes());
    raw
}
fn geometry(c: &Controller, slot: u8) -> Vec<(u64, usize)> {
    let state = c.slots[usize::from(slot)].as_ref().unwrap();
    let mut all = vec![
        (state.input.physical(), state.input.len()),
        (state._output.physical(), state._output.len()),
        (state.control.physical(), state.control.len()),
    ];
    for transfer in state.endpoints.iter().flatten() {
        all.push((transfer.ring.buffer.physical(), transfer.ring.buffer.len()));
        if let Some(streams) = &transfer.streams {
            all.extend(streams.allocation_geometry());
        }
    }
    for ring in state.retired_rings.iter().flatten() {
        all.push((ring.buffer.physical(), ring.buffer.len()));
    }
    all.sort_unstable();
    all
}
fn selected(mut fresh: Device, previous: &Device) -> Device {
    fresh.configuration = fresh
        .configurations
        .iter()
        .find(|raw| raw.get(5) == Some(&previous.configuration_value()))
        .unwrap()
        .clone();
    fresh
}
fn configure(
    c: &mut Controller,
    device: &Device,
    endpoints: &[Endpoint],
    dma: &mut dyn DmaAllocator,
) {
    let mut owner = c.device(device.id).unwrap();
    owner
        .set_configuration(device.configuration_value())
        .unwrap();
    if device.speed >= SUPER_SPEED {
        owner
            .configure_streams(endpoints, &[0x82, 0x83, 4], 2, dma)
            .unwrap();
    } else {
        owner.configure(endpoints, None, dma).unwrap();
    }
}
fn read_block(
    c: &mut Controller,
    device: &Device,
    command: &mut DmaBuffer,
    data: &DmaBuffer,
    status: &DmaBuffer,
) -> transfer::TransferTicket {
    command.bytes_mut().fill(0);
    command.bytes_mut()[0] = 1;
    command.bytes_mut()[3] = 1;
    command.bytes_mut()[16] = 0x28;
    command.bytes_mut()[24] = 1;
    let mut owner = c.device(device.id).unwrap();
    let ticket = owner.submit_ticket(2, command.physical(), 32).unwrap();
    if device.speed >= SUPER_SPEED {
        let payload = owner.submit_stream(7, 1, data.physical(), 512).unwrap();
        let finish = owner.submit_stream(5, 1, status.physical(), 64).unwrap();
        assert_eq!(owner.completed_stream(&payload), Some(Ok(512)));
        assert_eq!(owner.completed_stream(&finish), Some(Ok(16)));
    } else {
        let ready = owner.submit_ticket(5, status.physical(), 64).unwrap();
        assert_eq!(owner.completed_ticket(&ready), Some(Ok(4)));
        let payload = owner.submit_ticket(7, data.physical(), 512).unwrap();
        let finish = owner.submit_ticket(5, status.physical(), 64).unwrap();
        assert_eq!(owner.completed_ticket(&payload), Some(Ok(512)));
        assert_eq!(owner.completed_ticket(&finish), Some(Ok(16)));
    }
    assert_eq!(&data.bytes()[..512], &[0x6d; 512]);
    ticket
}

#[test]
fn published_root_pool_reuses_all_ordinary_and_stream_dma_across_96_real_lifetimes() {
    for speed in [HIGH_SPEED, SUPER_SPEED] {
        for context in [32, 64] {
            for profile in [dma::Profile::SPEC, dma::Profile::pci(0x1d17, 0x9202)] {
                let mut memory = vec![0u64; 512 * 1024];
                let (shared, mut old, hardware, mut dma) =
                    fixture_profile(&mut memory, speed, context, 1, (false, false, profile));
                let endpoints = interfaces(&old.configuration)[0].endpoints.clone();
                configure(&mut shared.borrow_mut(), &old, &endpoints, &mut dma);
                let mut command = dma.allocate(512, 512).unwrap();
                let data = dma.allocate(512, 65536).unwrap();
                let status = dma.allocate(512, 512).unwrap();
                let original = geometry(&shared.borrow(), old.slot);
                let remaining = dma.remaining();
                let mut identities = vec![old.id];
                // Force the specified stopped event even for every empty ring;
                // Disable checks the event was consumed before storage returns.
                hardware.borrow_mut().force_idle_stop = true;
                for cycle in 1..=96 {
                    let mut c = shared.borrow_mut();
                    let retired = read_block(&mut c, &old, &mut command, &data, &status);
                    if cycle % 2 == 0 {
                        assert_eq!(c.completed_ticket(&retired), Some(Ok(32)));
                    }
                    // SAFETY: fixture exclusively owns every configured
                    // endpoint; aliases are exercised only to prove refusal.
                    let fresh = selected(
                        unsafe { c.reset_and_reuse_root(&old, &endpoints, &mut dma) }.unwrap(),
                        &old,
                    );
                    assert_eq!(fresh.slot, old.slot);
                    assert!(!identities.contains(&fresh.id));
                    configure(&mut c, &fresh, &endpoints, &mut dma);
                    let current = read_block(&mut c, &fresh, &mut command, &data, &status);
                    let before = hardware.borrow().accesses;
                    let event_bytes = c.events.bytes().to_vec();
                    let current_dma: Vec<_> = geometry(&c, fresh.slot)
                        .into_iter()
                        .map(|(at, len)| (at, bytes(at, len)))
                        .collect();
                    for id in &identities {
                        assert!(c.device(*id).is_err());
                    }
                    assert!(c.completed_ticket(&retired).unwrap().is_err());
                    assert!(
                        c.control(old.slot, setup(0x80, GET_DESCRIPTOR, 1 << 8, 0, 18), &[])
                            .is_err()
                    );
                    assert_eq!(hardware.borrow().accesses, before);
                    assert_eq!(c.events.bytes(), event_bytes);
                    for (at, contents) in current_dma {
                        assert_eq!(bytes(at, contents.len()), contents);
                    }
                    assert_eq!(c.completed_ticket(&current), Some(Ok(32)));
                    assert_eq!(geometry(&c, fresh.slot), original);
                    assert_eq!(
                        dma.remaining(),
                        remaining,
                        "published reset allocated fresh DMA"
                    );
                    assert_eq!(hardware.borrow().reset_writes, cycle);
                    assert!(hardware.borrow().forced_idle_events >= 5 * cycle);
                    identities.push(fresh.id);
                    old = fresh;
                }
            }
        }
    }
}

#[test]
fn published_pool_follows_actual_different_enable_slot_without_allocating_another_set() {
    for context in [32, 64] {
        let mut memory = vec![0u64; 512 * 1024];
        let (shared, mut old, _, hardware, mut dma) =
            prepared(&mut memory, SUPER_SPEED, context, 3);
        let endpoints = interfaces(&old.configuration)[0].endpoints.clone();
        let original = geometry(&shared.borrow(), old.slot);
        let remaining = dma.remaining();
        for cycle in 0..96 {
            hardware.borrow_mut().preferred_slot = Some(if old.slot == 1 { 2 } else { 1 });
            let mut c = shared.borrow_mut();
            // SAFETY: the one root leaf's complete inventory is exclusive.
            let fresh = selected(
                unsafe { c.reset_and_reuse_root(&old, &endpoints, &mut dma) }.unwrap(),
                &old,
            );
            assert_ne!(old.slot, fresh.slot);
            configure(&mut c, &fresh, &endpoints, &mut dma);
            assert_eq!(geometry(&c, fresh.slot), original);
            assert_eq!(dma.remaining(), remaining);
            let accesses = hardware.borrow().accesses;
            assert!(c.device(old.id).is_err());
            assert_eq!(hardware.borrow().accesses, accesses);
            assert_eq!(hardware.borrow().resets, cycle + 1);
            old = fresh;
        }
    }
}

#[test]
fn published_iso_pool_reuses_real_queued_service_and_rejects_old_tickets_for_96_resets() {
    for speed in [HIGH_SPEED, SUPER_SPEED] {
        for context in [32, 64] {
            let mut memory = vec![0u64; 512 * 1024];
            let (shared, mut old, hardware, mut dma) = fixture_profile(
                &mut memory,
                speed,
                context,
                1,
                (false, true, dma::Profile::SPEC),
            );
            let endpoints = interfaces(&old.configuration)[0].endpoints.clone();
            shared
                .borrow_mut()
                .device(old.id)
                .unwrap()
                .configure(&endpoints, None, &mut dma)
                .unwrap();
            let payload = dma.allocate(4096, 4096).unwrap();
            let original = geometry(&shared.borrow(), old.slot);
            let remaining = dma.remaining();
            for cycle in 1..=96 {
                let mut c = shared.borrow_mut();
                let retired = c
                    .device(old.id)
                    .unwrap()
                    .submit_iso(3, payload.physical(), 64)
                    .unwrap();
                // The peer has consumed the Isoch TRB into pending. Its
                // stopped event must precede Stop ACK; Disable checks full ERDP.
                assert!(hardware.borrow().pending.contains_key(&(old.slot, 3, 0)));
                let fresh = selected(
                    // SAFETY: the model device is stopped and drained, so nothing still uses what
                    // this releases.
                    unsafe { c.reset_and_reuse_root(&old, &endpoints, &mut dma) }.unwrap(),
                    &old,
                );
                c.device(fresh.id).unwrap().set_configuration(1).unwrap();
                c.device(fresh.id)
                    .unwrap()
                    .configure(&endpoints, None, &mut dma)
                    .unwrap();
                let current = c
                    .device(fresh.id)
                    .unwrap()
                    .submit_iso(3, payload.physical(), 64)
                    .unwrap();
                let mut h = hardware.borrow_mut();
                let td = h.pending.remove(&(fresh.slot, 3, 0)).unwrap();
                copy(td.buffer, &vec![0x5a; td.length]);
                h.event(td.trb, SUCCESS << 24, TRANSFER_EVENT, fresh.slot, 3);
                drop(h);
                let before = hardware.borrow().accesses;
                let event_bytes = c.events.bytes().to_vec();
                let ring_bytes = c.slots[usize::from(fresh.slot)].as_ref().unwrap().endpoints[3]
                    .as_ref()
                    .unwrap()
                    .ring
                    .buffer
                    .bytes()
                    .to_vec();
                assert!(c.completed_iso(&retired).unwrap().is_err());
                assert!(c.device(old.id).is_err());
                assert_eq!(hardware.borrow().accesses, before);
                assert_eq!(c.events.bytes(), event_bytes);
                assert_eq!(
                    c.slots[usize::from(fresh.slot)].as_ref().unwrap().endpoints[3]
                        .as_ref()
                        .unwrap()
                        .ring
                        .buffer
                        .bytes(),
                    ring_bytes
                );
                assert_eq!(
                    c.completed_iso(&current),
                    Some(Ok(iso::IsoCompletion {
                        bytes: 64,
                        status: iso::IsoStatus::Success
                    }))
                );
                assert_eq!(&payload.bytes()[..64], &[0x5a; 64]);
                assert_eq!(geometry(&c, fresh.slot), original);
                assert_eq!(dma.remaining(), remaining);
                assert_eq!(hardware.borrow().resets, cycle);
                old = fresh;
            }
        }
    }
}

#[test]
fn uncertain_published_retirement_or_settled_reset_keeps_original_storage_quarantined() {
    for fault in [
        Fault::Stop(1),
        Fault::SilentStop(2),
        Fault::Dequeue(7),
        Fault::Disable,
        Fault::WrongDisableSlot,
        Fault::SilentDisable,
        Fault::NoResetChange,
        Fault::NoPortEvent,
        Fault::BadLink,
        Fault::FatalAfterReset,
        Fault::ChangeAfterReset,
    ] {
        let mut memory = vec![0u64; 512 * 1024];
        let (shared, old, _, hardware, mut dma) = prepared(&mut memory, SUPER_SPEED, 64, 1);
        let endpoints = interfaces(&old.configuration)[0].endpoints.clone();
        let original = geometry(&shared.borrow(), old.slot);
        let output = shared.borrow().slots[usize::from(old.slot)]
            .as_ref()
            .unwrap()
            ._output
            .physical();
        let contents: Vec<_> = original
            .iter()
            .map(|(at, len)| (*at, bytes(*at, *len)))
            .collect();
        let remaining = dma.remaining();
        hardware.borrow_mut().fault = fault;
        let mut c = shared.borrow_mut();
        assert!(
            // SAFETY: the model device is stopped and drained, so nothing still uses what this
            // releases.
            unsafe { c.reset_and_reuse_root(&old, &endpoints, &mut dma) }.is_err(),
            "{fault:?}"
        );
        assert_eq!(geometry(&c, old.slot), original);
        assert_eq!(dma.remaining(), remaining);
        assert!(c.slots[usize::from(old.slot)].as_ref().unwrap().retiring);
        // Context state/producer pointers may change only through the
        // retirement commands; data segments and their padding are not erased.
        for (at, contents) in contents {
            if at != output {
                assert_eq!(bytes(at, contents.len()), contents, "{fault:?}");
            }
        }
        let accesses = hardware.borrow().accesses;
        assert!(c.device(old.id).is_err());
        assert_eq!(hardware.borrow().accesses, accesses);
    }
}

#[test]
fn changed_published_stream_geometry_refuses_before_allocation_or_context_publication() {
    let mut memory = vec![0u64; 512 * 1024];
    let (shared, old, _, hardware, mut dma) = prepared(&mut memory, SUPER_SPEED, 32, 1);
    let endpoints = interfaces(&old.configuration)[0].endpoints.clone();
    let mut c = shared.borrow_mut();
    let fresh = selected(
        // SAFETY: the model device is stopped and drained, so nothing still uses what this
        // releases.
        unsafe { c.reset_and_reuse_root(&old, &endpoints, &mut dma) }.unwrap(),
        &old,
    );
    c.device(fresh.id).unwrap().set_configuration(1).unwrap();
    let remaining = dma.remaining();
    let input = c.slots[usize::from(fresh.slot)]
        .as_ref()
        .unwrap()
        .input
        .bytes()
        .to_vec();
    let command_count = hardware.borrow().commands_seen.len();
    assert!(
        c.device(fresh.id)
            .unwrap()
            .configure_streams(&endpoints, &[0x82, 0x83, 4], 1, &mut dma)
            .is_err()
    );
    assert_eq!(dma.remaining(), remaining);
    assert_eq!(hardware.borrow().commands_seen.len(), command_count);
    assert_eq!(
        c.slots[usize::from(fresh.slot)]
            .as_ref()
            .unwrap()
            .input
            .bytes(),
        input
    );
    // The refused request kept every stream/array owner for exact retry.
    c.device(fresh.id)
        .unwrap()
        .configure_streams(&endpoints, &[0x82, 0x83, 4], 2, &mut dma)
        .unwrap();
    assert_eq!(dma.remaining(), remaining);
}

#[test]
fn published_pool_keeps_unused_dropped_rings_through_96_resets_and_real_reconfigure() {
    for context in [32, 64] {
        let mut memory = vec![0u64; 512 * 1024];
        let (shared, mut old, _, hardware, mut dma) = prepared(&mut memory, HIGH_SPEED, context, 1);
        let all = interfaces(&old.configuration)[0].endpoints.clone();
        let active: Vec<_> = all.iter().copied().filter(|e| e.dci() != 8).collect();
        let dropped = *all.iter().find(|e| e.dci() == 8).unwrap();
        let original = geometry(&shared.borrow(), old.slot);
        shared
            .borrow_mut()
            .device(old.id)
            .unwrap()
            .deconfigure(&[dropped])
            .unwrap();
        let remaining = dma.remaining();
        for cycle in 0..96 {
            let mut c = shared.borrow_mut();
            let fresh = selected(
                // SAFETY: the model device is stopped and drained, so nothing still uses what this
                // releases.
                unsafe { c.reset_and_reuse_root(&old, &active, &mut dma) }.unwrap(),
                &old,
            );
            c.device(fresh.id).unwrap().set_configuration(1).unwrap();
            c.device(fresh.id)
                .unwrap()
                .configure(&active, None, &mut dma)
                .unwrap();
            // A previously acknowledged Drop's ring can remain unused for many
            // whole-device lifetimes; it must follow the pool without leaking.
            if cycle % 8 == 0 {
                c.device(fresh.id)
                    .unwrap()
                    .configure(&[dropped], None, &mut dma)
                    .unwrap();
                c.device(fresh.id).unwrap().deconfigure(&[dropped]).unwrap();
                c.device(fresh.id)
                    .unwrap()
                    .configure(&[dropped], None, &mut dma)
                    .unwrap();
                c.device(fresh.id).unwrap().deconfigure(&[dropped]).unwrap();
            }
            let mut retained = geometry(&c, fresh.slot);
            retained.extend(c.retry_resources.allocation_geometry());
            retained.sort_unstable();
            assert_eq!(retained, original);
            assert_eq!(dma.remaining(), remaining);
            assert_eq!(hardware.borrow().resets, cycle + 1);
            old = fresh;
        }
    }
}

struct FailSecondHealth {
    inner: Box<dyn Registers>,
    reads: usize,
}
impl Registers for FailSecondHealth {
    fn read32(&mut self, at: usize) -> u32 {
        let status = self.inner.read32(at);
        if at == 0x40 + USBSTS {
            self.reads += 1;
            if self.reads == 2 {
                return status | HCE;
            }
        }
        status
    }
    fn write32(&mut self, at: usize, value: u32) {
        self.inner.write32(at, value);
    }
    fn write64(&mut self, at: usize, value: u64) {
        self.inner.write64(at, value);
    }
}
struct NoRegisters;
impl Registers for NoRegisters {
    fn read32(&mut self, _: usize) -> u32 {
        panic!("temporary registers used")
    }
    fn write32(&mut self, _: usize, _: u32) {
        panic!("temporary registers used")
    }
}
#[test]
fn fatal_health_after_taking_published_endpoint_storage_keeps_every_owner() {
    let mut memory = vec![0u64; 512 * 1024];
    let (shared, old, _, hardware, mut dma) = prepared(&mut memory, SUPER_SPEED, 64, 1);
    let endpoints = interfaces(&old.configuration)[0].endpoints.clone();
    let mut c = shared.borrow_mut();
    let fresh = selected(
        // SAFETY: the model device is stopped and drained, so nothing still uses what this
        // releases.
        unsafe { c.reset_and_reuse_root(&old, &endpoints, &mut dma) }.unwrap(),
        &old,
    );
    c.device(fresh.id).unwrap().set_configuration(1).unwrap();
    let original = c.retry_resources.allocation_geometry();
    let remaining = dma.remaining();
    let input = c.slots[usize::from(fresh.slot)]
        .as_ref()
        .unwrap()
        .input
        .bytes()
        .to_vec();
    let command_count = hardware.borrow().commands_seen.len();
    let inner = core::mem::replace(&mut c.registers, Box::new(NoRegisters));
    c.registers = Box::new(FailSecondHealth { inner, reads: 0 });
    assert_eq!(
        c.device(fresh.id)
            .unwrap()
            .configure_streams(&endpoints, &[0x82, 0x83, 4], 2, &mut dma),
        Err(BlockError::Device { status: HCE })
    );
    assert_eq!(c.retry_resources.allocation_geometry(), original);
    assert_eq!(dma.remaining(), remaining);
    assert_eq!(hardware.borrow().commands_seen.len(), command_count);
    assert_eq!(
        c.slots[usize::from(fresh.slot)]
            .as_ref()
            .unwrap()
            .input
            .bytes(),
        input
    );
}

#[test]
fn failed_fresh_enable_address_or_identity_keeps_the_entire_published_pool() {
    for fault in [
        Fault::EnableAfterReset,
        Fault::SilentReserve,
        Fault::AddressAfterReset,
        Fault::Identity,
    ] {
        let mut memory = vec![0u64; 512 * 1024];
        let (shared, old, _, hardware, mut dma) = prepared(&mut memory, SUPER_SPEED, 32, 1);
        let endpoints = interfaces(&old.configuration)[0].endpoints.clone();
        let original = geometry(&shared.borrow(), old.slot);
        let remaining = dma.remaining();
        hardware.borrow_mut().fault = fault;
        let mut c = shared.borrow_mut();
        assert!(
            // SAFETY: the model device is stopped and drained, so nothing still uses what this
            // releases.
            unsafe { c.reset_and_reuse_root(&old, &endpoints, &mut dma) }.is_err(),
            "{fault:?}"
        );
        let mut retained = c.retry_resources.allocation_geometry();
        for (slot, state) in c.slots.iter().enumerate() {
            if state.is_some() {
                retained.extend(geometry(&c, slot as u8));
            }
        }
        retained.sort_unstable();
        assert_eq!(retained, original, "{fault:?}");
        assert_eq!(dma.remaining(), remaining);
        let accesses = hardware.borrow().accesses;
        assert!(c.device(old.id).is_err());
        assert_eq!(hardware.borrow().accesses, accesses);
    }
}

fn unread_stream_read(
    c: &mut Controller,
    id: SlotId,
    command: &mut DmaBuffer,
    data: &DmaBuffer,
    status: &DmaBuffer,
) -> (
    transfer::TransferTicket,
    streams::StreamTransfer,
    streams::StreamTransfer,
) {
    command.bytes_mut().fill(0);
    command.bytes_mut()[0] = 1;
    command.bytes_mut()[3] = 1;
    command.bytes_mut()[16] = 0x28;
    command.bytes_mut()[24] = 1;
    let mut owner = c.device(id).unwrap();
    let cbw = owner.submit_ticket(2, command.physical(), 32).unwrap();
    let finish = owner.submit_stream(5, 1, status.physical(), 64).unwrap();
    // Last publication creates both stream success events; no readiness
    // read or drain follows before the caller probes its stale IDs.
    let payload = owner.submit_stream(7, 1, data.physical(), 512).unwrap();
    (cbw, payload, finish)
}
#[test]
fn old_stream_ticket_cannot_consume_actual_unread_completion_at_identical_reused_pointer() {
    for context in [32, 64] {
        let mut memory = vec![0u64; 512 * 1024];
        let (shared, old, _, hardware, mut dma) = prepared(&mut memory, SUPER_SPEED, context, 1);
        let endpoints = interfaces(&old.configuration)[0].endpoints.clone();
        let mut command = dma.allocate(512, 512).unwrap();
        let data = dma.allocate(512, 65536).unwrap();
        let status = dma.allocate(512, 512).unwrap();
        let mut c = shared.borrow_mut();
        let (old_command, old_stream, _) =
            unread_stream_read(&mut c, old.id, &mut command, &data, &status);
        let fresh = selected(
            // SAFETY: the model device is stopped and drained, so nothing still uses what this
            // releases.
            unsafe { c.reset_and_reuse_root(&old, &endpoints, &mut dma) }.unwrap(),
            &old,
        );
        configure(&mut c, &fresh, &endpoints, &mut dma);
        let (current_command, current_stream, current_status) =
            unread_stream_read(&mut c, fresh.id, &mut command, &data, &status);
        assert_eq!(
            old_stream.submitted_pointer(),
            current_stream.submitted_pointer()
        );
        let accesses = hardware.borrow().accesses;
        let cursor = (c.event_index, c.event_cycle);
        let pending: Vec<_> = c
            .pending
            .iter()
            .map(|e| (e.parameter, e.status, e.control))
            .collect();
        let event_bytes = c.events.bytes().to_vec();
        let dma_bytes = data.bytes().to_vec();
        assert!(
            hardware.borrow().consumed < hardware.borrow().event_count,
            "success event was not unread"
        );
        assert!(c.completed_stream(&old_stream).unwrap().is_err());
        assert!(c.completed_ticket(&old_command).unwrap().is_err());
        assert!(c.device(old.id).is_err());
        assert_eq!(hardware.borrow().accesses, accesses);
        assert_eq!((c.event_index, c.event_cycle), cursor);
        assert_eq!(
            c.pending
                .iter()
                .map(|e| (e.parameter, e.status, e.control))
                .collect::<Vec<_>>(),
            pending
        );
        assert_eq!(c.events.bytes(), event_bytes);
        assert_eq!(data.bytes(), dma_bytes);
        assert_eq!(c.completed_stream(&current_stream), Some(Ok(512)));
        assert_eq!(c.completed_stream(&current_status), Some(Ok(16)));
        assert_eq!(c.completed_ticket(&current_command), Some(Ok(32)));
    }
}

struct ObserveReinitialized {
    inner: Box<dyn Registers>,
    hardware: Rc<RefCell<Hardware>>,
    output: u64,
    input: u64,
    control: u64,
    context: usize,
    speed: u8,
    rings: Vec<(u64, usize)>,
    arrays: Vec<(u64, usize, Vec<u64>)>,
    observed: Rc<RefCell<usize>>,
}
impl Registers for ObserveReinitialized {
    fn read32(&mut self, at: usize) -> u32 {
        self.inner.read32(at)
    }
    fn write32(&mut self, at: usize, value: u32) {
        if at == 0x40 + PORTSC && value & PR != 0 {
            let h = self.hardware.borrow();
            assert!(h.enabled.iter().skip(1).all(|enabled| !enabled));
            assert!(h.pending.is_empty());
            assert!(h.deferred.is_empty());
            assert_eq!(h.consumed, h.event_count);
            drop(h);
            // Dirty ONLY the original fully retired storage,
            // after the peer has acknowledged Disable and all ordered events.
            for (address, length) in &self.rings {
                copy(*address, &vec![0xa5; *length]);
            }
            for (address, length, _) in &self.arrays {
                copy(*address, &vec![0xa5; *length]);
            }
            copy(self.output, &vec![0xa5; 32 * self.context]);
            copy(self.input, &vec![0xa5; 33 * self.context]);
            copy(self.control, &vec![0xa5; CONTROL_BYTES]);
        }
        if at == 0x1000 && self.hardware.borrow().pending_command_kind() == ADDRESS_DEVICE {
            assert_eq!(
                bytes(self.output, 32 * self.context),
                vec![0; 32 * self.context]
            );
            assert_eq!(bytes(self.control, CONTROL_BYTES), vec![0; CONTROL_BYTES]);
            for (address, length) in &self.rings {
                let mut expected = vec![0u8; *length];
                expected[(RING_TRBS - 1) * TRB..(RING_TRBS - 1) * TRB + 8]
                    .copy_from_slice(&address.to_le_bytes());
                assert_eq!(
                    bytes(*address, *length),
                    expected,
                    "ring/padding not reinitialized"
                );
            }
            for (address, length, rings) in &self.arrays {
                let mut expected = vec![0u8; *length];
                for (index, ring) in rings.iter().enumerate() {
                    expected[(index + 1) * 16..(index + 1) * 16 + 8]
                        .copy_from_slice(&(ring | 3).to_le_bytes());
                }
                assert_eq!(
                    bytes(*address, *length),
                    expected,
                    "stream0/unused/reserved bytes retained"
                );
            }
            let mut expected = vec![0u8; 33 * self.context];
            let mut word =
                |at: usize, value: u32| expected[at..at + 4].copy_from_slice(&value.to_le_bytes());
            word(4, 3);
            word(self.context, u32::from(self.speed) << 20 | 1 << 27);
            word(self.context + 4, 1 << 16);
            word(
                2 * self.context + 4,
                3 << 1
                    | CONTROL_TYPE << 3
                    | if self.speed >= SUPER_SPEED {
                        512 << 16
                    } else {
                        64 << 16
                    },
            );
            word(2 * self.context + 16, 8);
            let ep0 = self.rings[0].0;
            expected[2 * self.context + 8..2 * self.context + 16]
                .copy_from_slice(&(ep0 | 1).to_le_bytes());
            assert_eq!(bytes(self.input, 33 * self.context), expected);
            *self.observed.borrow_mut() += 1;
        }
        self.inner.write32(at, value);
    }
    fn write64(&mut self, at: usize, value: u64) {
        self.inner.write64(at, value);
    }
}
#[test]
fn published_return_erases_all_context_stream_and_overfetch_bytes_only_after_real_disable() {
    for speed in [HIGH_SPEED, SUPER_SPEED] {
        for context in [32, 64] {
            for profile in [dma::Profile::SPEC, dma::Profile::pci(0x1d17, 0x9202)] {
                let mut memory = vec![0u64; 512 * 1024];
                let (shared, old, hardware, mut dma) =
                    fixture_profile(&mut memory, speed, context, 1, (false, false, profile));
                let endpoints = interfaces(&old.configuration)[0].endpoints.clone();
                let mut c = shared.borrow_mut();
                configure(&mut c, &old, &endpoints, &mut dma);
                let state = c.slots[usize::from(old.slot)].as_ref().unwrap();
                let mut rings = Vec::new();
                let mut arrays = Vec::new();
                for transfer in state.endpoints.iter().flatten() {
                    rings.push((transfer.ring.buffer.physical(), transfer.ring.buffer.len()));
                    if let Some(streams) = &transfer.streams {
                        let geometry = streams.allocation_geometry();
                        arrays.push((
                            geometry[0].0,
                            geometry[0].1,
                            geometry[1..].iter().map(|(at, _)| *at).collect(),
                        ));
                        rings.extend_from_slice(&geometry[1..]);
                    }
                }
                let (output, input, control) = (
                    state._output.physical(),
                    state.input.physical(),
                    state.control.physical(),
                );
                let observed = Rc::new(RefCell::new(0));
                let inner = core::mem::replace(&mut c.registers, Box::new(NoRegisters));
                c.registers = Box::new(ObserveReinitialized {
                    inner,
                    hardware: hardware.clone(),
                    output,
                    input,
                    control,
                    context,
                    speed,
                    rings,
                    arrays,
                    observed: observed.clone(),
                });
                // SAFETY: the model device is stopped and drained, so nothing still uses what this
                // releases.
                let fresh = unsafe { c.reset_and_reuse_root(&old, &endpoints, &mut dma) }.unwrap();
                assert_eq!(*observed.borrow(), 1);
                assert_ne!(old.id, fresh.id);
            }
        }
    }
}
