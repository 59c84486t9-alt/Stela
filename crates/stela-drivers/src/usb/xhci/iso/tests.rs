use super::*;
use crate::bus::dma::RegionAllocator;
use alloc::collections::BTreeMap;
extern crate std;

struct Td {
    trb: u64,
    buffer: u64,
    bytes: usize,
    control: u32,
}
struct Hardware {
    commands: u64,
    command_index: usize,
    events: u64,
    event_index: usize,
    output: u64,
    context_bytes: usize,
    cursors: BTreeMap<u8, (u64, usize, u32)>,
    active: Vec<(u8, Td)>,
    seen: Vec<(u32, u8)>,
    mfindex: u32,
    fail: Option<u32>,
    silent: Option<u32>,
    fatal: bool,
    output_bytes: Vec<u8>,
}
impl Hardware {
    fn word(address: u64) -> u32 {
        assert!(address > 65536 && address.is_multiple_of(4));
        unsafe { (address as *const u32).read_volatile() }
    }
    fn long(address: u64) -> u64 {
        assert!(address > 65536 && address.is_multiple_of(8));
        unsafe { (address as *const u64).read_volatile() }
    }
    fn state(&mut self, dci: u8, state: u32) {
        let at = self.output + u64::from(dci) * self.context_bytes as u64;
        unsafe {
            (at as *mut u32).write_volatile(Self::word(at) & !7 | state);
        }
    }
    fn event(&mut self, parameter: u64, code: u32, dci: u8, residual: usize, kind: u32) {
        let at = self.events + (self.event_index % RING_TRBS * TRB) as u64;
        unsafe {
            (at as *mut u64).write_volatile(parameter);
            ((at + 8) as *mut u32).write_volatile(code << 24 | residual as u32);
            ((at + 12) as *mut u32).write_volatile(
                1 << 24
                    | u32::from(dci) << 16
                    | kind << 10
                    | u32::from((self.event_index / RING_TRBS).is_multiple_of(2)),
            );
        }
        self.event_index += 1;
    }
    fn command(&mut self) {
        let at = self.commands + (self.command_index % (RING_TRBS - 1) * TRB) as u64;
        let parameter = Self::long(at);
        let control = Self::word(at + 12);
        assert_eq!(
            control & CYCLE,
            u32::from((self.command_index / (RING_TRBS - 1)).is_multiple_of(2))
        );
        let kind = control >> 10 & 63;
        let dci = (control >> 16 & 31) as u8;
        self.command_index += 1;
        self.seen.push((kind, dci));
        if self.silent == Some(kind) {
            return;
        }
        let code = if self.fail == Some(kind) { 17 } else { SUCCESS };
        if code == SUCCESS {
            match kind {
                CONFIGURE_ENDPOINT => {
                    let add = Self::word(parameter + 4);
                    let drop = Self::word(parameter);
                    for ep in 2..32u8 {
                        if drop & (1 << ep) != 0 {
                            self.state(ep, 0);
                            self.cursors.remove(&ep);
                        }
                        if add & (1 << ep) == 0 {
                            continue;
                        }
                        let from = parameter + (u64::from(ep) + 1) * self.context_bytes as u64;
                        let to = self.output + u64::from(ep) * self.context_bytes as u64;
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                from as *const u8,
                                to as *mut u8,
                                self.context_bytes,
                            );
                        }
                        let info2 = Self::word(to + 4);
                        assert!(matches!(info2 >> 3 & 7, 1 | 5));
                        assert_eq!(info2 & 6, 0);
                        assert_eq!(Self::word(to + 16) & 0xffff, Self::word(to + 16) >> 16);
                        self.state(ep, ENDPOINT_RUNNING);
                    }
                }
                STOP_ENDPOINT => self.state(dci, ENDPOINT_STOPPED),
                RESET_ENDPOINT => self.state(dci, ENDPOINT_STOPPED),
                SET_DEQUEUE => {
                    let endpoint = self.output + u64::from(dci) * self.context_bytes as u64;
                    assert_eq!(Self::word(endpoint) & 7, ENDPOINT_STOPPED);
                    let base = Self::long(endpoint + 8) & !((RING_TRBS * TRB) as u64 - 1);
                    self.cursors.insert(
                        dci,
                        (
                            base,
                            ((parameter & !15) - base) as usize / TRB,
                            parameter as u32 & 1,
                        ),
                    );
                    let old = core::mem::take(&mut self.active);
                    for (ep, td) in old {
                        if ep == dci {
                            self.event(td.trb, 26, dci, td.bytes, TRANSFER_EVENT);
                        } else {
                            self.active.push((ep, td));
                        }
                    }
                }
                _ => panic!("unexpected command {kind}"),
            }
        }
        self.event(at, code, 0, 0, COMMAND_COMPLETION);
    }
    fn transfer(&mut self, dci: u8) {
        let ep = self.output + u64::from(dci) * self.context_bytes as u64;
        let initial = Self::long(ep + 8);
        let base = initial & !((RING_TRBS * TRB) as u64 - 1);
        let cursor = self.cursors.entry(dci).or_insert((
            base,
            ((initial & !15) - base) as usize / TRB,
            initial as u32 & 1,
        ));
        let trb = cursor.0 + (cursor.1 * TRB) as u64;
        let control = Self::word(trb + 12);
        let bytes = (Self::word(trb + 8) & 0x1ffff) as usize;
        assert_eq!(control & CYCLE, cursor.2);
        assert_eq!(control >> 10 & 63, ISOCH);
        assert_ne!(control & IOC, 0);
        let packet = Self::word(ep + 4) >> 16;
        assert_eq!(
            control >> 16 & 15,
            (bytes as u32).div_ceil(packet).max(1) - 1
        );
        let buffer = Self::long(trb);
        assert!(buffer % 65536 + bytes as u64 <= 65536);
        assert!(
            !self
                .active
                .iter()
                .any(|(ep, td)| *ep == dci && td.trb == trb)
        );
        self.active.push((
            dci,
            Td {
                trb,
                buffer,
                bytes,
                control,
            },
        ));
        cursor.1 += 1;
        if cursor.1 == RING_TRBS - 1 {
            let link = cursor.0 + ((RING_TRBS - 1) * TRB) as u64;
            assert_eq!(Self::long(link), cursor.0);
            assert_eq!(Self::word(link + 12) & 1, cursor.2);
            assert_eq!(Self::word(link + 12) >> 10 & 63, LINK);
            assert_ne!(Self::word(link + 12) & TOGGLE, 0);
            cursor.1 = 0;
            cursor.2 ^= 1;
        }
        self.state(dci, ENDPOINT_RUNNING);
    }
    fn complete(&mut self, dci: u8, index: usize, code: u32, residual: usize) {
        let at = self
            .active
            .iter()
            .enumerate()
            .filter(|(_, (ep, _))| *ep == dci)
            .nth(index)
            .unwrap()
            .0;
        let (_, td) = self.active.remove(at);
        if code == 6 {
            self.state(dci, ENDPOINT_HALTED);
        }
        if matches!(code, SUCCESS | SHORT_PACKET) && residual <= td.bytes {
            let n = td.bytes - residual;
            if dci & 1 != 0 {
                unsafe {
                    core::ptr::write_bytes(td.buffer as *mut u8, 0x5a, n);
                }
            } else {
                self.output_bytes.extend_from_slice(unsafe {
                    core::slice::from_raw_parts(td.buffer as *const u8, n)
                });
            }
        }
        self.event(td.trb, code, dci, residual, TRANSFER_EVENT);
    }
}
struct Model(Rc<RefCell<Hardware>>);
impl Registers for Model {
    fn read32(&mut self, offset: usize) -> u32 {
        let model = self.0.borrow();
        if offset == 0x800 {
            model.mfindex
        } else if offset == 0x40 + USBSTS && model.fatal {
            HSE
        } else {
            0
        }
    }
    fn write32(&mut self, offset: usize, value: u32) {
        match offset {
            0x1000 => self.0.borrow_mut().command(),
            0x1004 => self.0.borrow_mut().transfer(value as u8),
            _ => {}
        }
    }
}
fn endpoint(address: u8, speed: u8) -> Endpoint {
    Endpoint {
        address,
        attributes: 1,
        max_packet: if speed == FULL_SPEED {
            192
        } else {
            1024 | 2 << 11
        },
        interval: 1,
        companion: None,
    }
}
fn controller(
    dma: &mut dyn DmaAllocator,
    speed: u8,
    context_bytes: usize,
    cfc: bool,
) -> (Controller, Rc<RefCell<Hardware>>) {
    let commands = Ring::new(dma).unwrap();
    let events = dma.allocate(RING_TRBS * TRB, RING_TRBS * TRB).unwrap();
    let output = dma.allocate(32 * context_bytes, 64).unwrap();
    let model = Rc::new(RefCell::new(Hardware {
        commands: commands.buffer.physical(),
        command_index: 0,
        events: events.physical(),
        event_index: 0,
        output: output.physical(),
        context_bytes,
        cursors: BTreeMap::new(),
        active: Vec::new(),
        seen: Vec::new(),
        mfindex: 0x3ff0,
        fail: None,
        silent: None,
        fatal: false,
        output_bytes: Vec::new(),
    }));
    let mut slots = vec![None];
    slots.push(Some(Slot {
        attachment: Attachment {
            root_port: 1,
            route: 0,
            tier: 0,
            speed,
            translator: None,
        },
        retiring: false,
        input: dma.allocate(33 * context_bytes, 64).unwrap(),
        _output: output,
        context: [u32::from(speed) << 20 | 1 << 27, 1 << 16, 0, 0],
        endpoints: Default::default(),
        retired_rings: Default::default(),
        control: dma.allocate(CONTROL_BYTES, CONTROL_BYTES).unwrap(),
        speed,
        current_configuration: Some(1),
    }));
    (
        Controller {
            registers: Box::new(Model(model.clone())),
            clock: Clock {
                ticks_per_microsecond: 1,
            },
            operational: 0x40,
            runtime: 0x800,
            doorbells: 0x1000,
            context_bytes,
            dma_profile: dma::Profile::SPEC,
            max_primary_streams: 4,
            stream_policy: streams::Policy::Unknown,
            iso_caps: {
                let mut caps = Capabilities::new(0x110, 0xb, if cfc { 1 << 11 } else { 0 });
                caps.qualify(Policy::pci(0x1022, 0x15b6));
                caps
            },
            max_slots: 1,
            max_ports: 1,
            port_major: vec![2],
            dcbaa: dma.allocate(16, 64).unwrap(),
            _scratchpads: Vec::new(),
            commands,
            events,
            _event_table: dma.allocate(16, 64).unwrap(),
            event_index: 0,
            event_cycle: true,
            slots,
            slot_ownership: vec![reset::Ownership::Vacant, reset::Ownership::Enabled],
            pending: Vec::new(),
            error: None,
            command_poisoned: false,
            location: String::from("native iso model"),
        },
        model,
    )
}

#[test]
fn queued_native_iso_contexts_and_scheduling_complete_actual_dma_for_both_directions() {
    for speed in [FULL_SPEED, HIGH_SPEED] {
        for context_bytes in [32, 64] {
            for cfc in [false, true] {
                let mut backing = vec![0u64; 128 * 1024];
                let start = backing.as_mut_ptr() as u64;
                let mut dma =
                    unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
                let (mut controller, model) = controller(&mut dma, speed, context_bytes, cfc);
                controller.qualify_iso_test_model(0x1022, 0x15b6);
                let endpoints = [endpoint(1, speed), endpoint(0x82, speed)];
                controller.configure(1, &endpoints, None, &mut dma).unwrap();
                let out = dma.allocate(4096, 4096).unwrap();
                let input = dma.allocate(4096, 4096).unwrap();
                unsafe {
                    core::ptr::write_bytes(out.as_ptr(), 0xa5, out.len());
                }
                let mut tickets = Vec::new();
                for n in 0..32 {
                    for endpoint in &endpoints {
                        tickets.push(
                            controller
                                .submit_iso(
                                    1,
                                    endpoint.dci(),
                                    if endpoint.is_in() {
                                        input.physical()
                                    } else {
                                        out.physical()
                                    } + n * 32,
                                    32,
                                )
                                .unwrap(),
                        );
                    }
                }
                assert_eq!(model.borrow().active.len(), 64);
                for dci in [2, 5] {
                    let fields: Vec<u32> = model
                        .borrow()
                        .active
                        .iter()
                        .filter(|(ep, _)| *ep == dci)
                        .map(|(_, td)| td.control)
                        .collect();
                    assert_eq!(fields[0] & SIA, 0);
                    assert_eq!(fields[1] & SIA, if cfc { 0 } else { SIA });
                    for n in 0..32 {
                        model.borrow_mut().complete(
                            dci,
                            0,
                            if n % 2 == 0 { SUCCESS } else { SHORT_PACKET },
                            if n % 2 == 0 { 0 } else { 4 },
                        );
                    }
                }
                for (n, ticket) in tickets.iter().enumerate() {
                    let completion = controller.completed_iso(ticket).unwrap().unwrap();
                    assert_eq!(completion.bytes, if n / 2 % 2 == 0 { 32 } else { 28 });
                    assert!(controller.completed_iso(ticket).unwrap().is_err());
                }
                assert_eq!(model.borrow().output_bytes.len(), 16 * 32 + 16 * 28);
                assert_eq!(&input.bytes()[..32], &[0x5a; 32]);
            }
        }
    }
}

#[test]
fn packet_failures_are_terminal_but_invalid_residual_and_transport_faults_retain_dma() {
    for (code, status) in [
        (23, IsoStatus::MissedService),
        (4, IsoStatus::Transaction),
        (3, IsoStatus::Babble),
        (18, IsoStatus::Bandwidth),
        (31, IsoStatus::BufferOverrun),
    ] {
        let mut backing = vec![0u64; 32 * 1024];
        let start = backing.as_mut_ptr() as u64;
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = controller(&mut dma, HIGH_SPEED, 32, true);
        controller
            .configure(1, &[endpoint(0x81, HIGH_SPEED)], None, &mut dma)
            .unwrap();
        let buffer = dma.allocate(4096, 4096).unwrap();
        let ticket = controller.submit_iso(1, 3, buffer.physical(), 128).unwrap();
        model.borrow_mut().complete(3, 0, code, 32);
        assert_eq!(
            controller.completed_iso(&ticket).unwrap().unwrap().status,
            status
        );
        if status == IsoStatus::MissedService {
            assert!(controller.submit_iso(1, 3, buffer.physical(), 128).is_err());
            controller.cancel(1, 3).unwrap();
        }
        let ticket = controller.submit_iso(1, 3, buffer.physical(), 128).unwrap();
        model.borrow_mut().complete(3, 0, SUCCESS, 129);
        assert!(controller.completed_iso(&ticket).unwrap().is_err());
        assert!(controller.submit_iso(1, 3, buffer.physical(), 128).is_err());
        controller.cancel(1, 3).unwrap();
        assert!(controller.completed_iso(&ticket).unwrap().is_err());
    }
}

#[test]
fn cancellation_acknowledges_all_intervals_and_stale_events_before_reuse() {
    for failure in [None, Some(STOP_ENDPOINT), Some(SET_DEQUEUE)] {
        let mut backing = vec![0u64; 32 * 1024];
        let start = backing.as_mut_ptr() as u64;
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = controller(&mut dma, HIGH_SPEED, 64, true);
        controller
            .configure(1, &[endpoint(0x81, HIGH_SPEED)], None, &mut dma)
            .unwrap();
        let buffer = dma.allocate(4096, 4096).unwrap();
        let tickets: Vec<_> = (0..32)
            .map(|n| {
                controller
                    .submit_iso(1, 3, buffer.physical() + n * 32, 32)
                    .unwrap()
            })
            .collect();
        model.borrow_mut().fail = failure;
        let result = controller.cancel(1, 3);
        if failure.is_some() {
            assert!(result.is_err());
            assert!(controller.submit_iso(1, 3, buffer.physical(), 32).is_err());
            assert_eq!(
                controller.slot(1).unwrap().endpoints[3]
                    .as_ref()
                    .unwrap()
                    .iso
                    .as_ref()
                    .unwrap()
                    .active
                    .len(),
                32
            );
            assert_eq!(model.borrow().active.len(), 32);
        } else {
            result.unwrap();
            assert!(controller.pending.is_empty());
            assert!(model.borrow().active.is_empty());
            for ticket in tickets {
                assert!(controller.completed_iso(&ticket).unwrap().is_err());
            }
            controller.submit_iso(1, 3, buffer.physical(), 32).unwrap();
        }
    }
}

#[test]
fn occupancy_wrap_schedule_and_descriptor_failures_do_not_overwrite_owned_trbs() {
    let mut backing = vec![0u64; 32 * 1024];
    let start = backing.as_mut_ptr() as u64;
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut controller, model) = controller(&mut dma, HIGH_SPEED, 32, true);
    controller
        .configure(1, &[endpoint(0x81, HIGH_SPEED)], None, &mut dma)
        .unwrap();
    let buffer = dma.allocate(4096, 4096).unwrap();
    let tickets: Vec<_> = (0..RING_TRBS - 2)
        .map(|_| controller.submit_iso(1, 3, buffer.physical(), 16).unwrap())
        .collect();
    let before = controller.slot(1).unwrap().endpoints[3]
        .as_ref()
        .unwrap()
        .ring
        .address();
    assert!(controller.submit_iso(1, 3, buffer.physical(), 16).is_err());
    assert_eq!(
        controller.slot(1).unwrap().endpoints[3]
            .as_ref()
            .unwrap()
            .ring
            .address(),
        before
    );
    for ticket in tickets {
        model.borrow_mut().complete(3, 0, SUCCESS, 0);
        assert_eq!(
            controller.completed_iso(&ticket).unwrap().unwrap().bytes,
            16
        );
    }
    for _ in 0..300 {
        let ticket = controller.submit_iso(1, 3, buffer.physical(), 16).unwrap();
        model.borrow_mut().complete(3, 0, SUCCESS, 0);
        controller.completed_iso(&ticket).unwrap().unwrap();
    }
    model.borrow_mut().mfindex = 1024;
    assert!(controller.submit_iso(1, 3, buffer.physical(), 16).is_err());
    controller.cancel(1, 3).unwrap();
    controller.submit_iso(1, 3, buffer.physical(), 16).unwrap();
    assert!(controller.submit(1, 3, buffer.physical(), 16).is_err());
    for speed in [LOW_SPEED, SUPER_SPEED, SUPER_SPEED_PLUS] {
        assert!(Recipe::new(&endpoint(0x81, HIGH_SPEED), speed).is_err());
    }
    let mut endpoint = endpoint(0x81, HIGH_SPEED);
    endpoint.max_packet |= 3 << 11;
    assert!(Recipe::new(&endpoint, HIGH_SPEED).is_err());
    endpoint.max_packet = 1024;
    endpoint.attributes = 0x31;
    assert!(Recipe::new(&endpoint, HIGH_SPEED).is_err());
}

#[test]
fn acknowledged_endpoint_drop_retains_rings_and_failure_quarantines_every_selected_owner() {
    for failure in [
        None,
        Some(CONFIGURE_ENDPOINT),
        Some(STOP_ENDPOINT),
        Some(SET_DEQUEUE),
    ] {
        let mut backing = vec![0u64; 32 * 1024];
        let start = backing.as_mut_ptr() as u64;
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = controller(&mut dma, HIGH_SPEED, 64, true);
        let endpoints = [
            endpoint(1, HIGH_SPEED),
            endpoint(0x82, HIGH_SPEED),
            endpoint(0x83, HIGH_SPEED),
        ];
        controller.configure(1, &endpoints, None, &mut dma).unwrap();
        let buffer = dma.allocate(4096, 4096).unwrap();
        let a = controller.submit_iso(1, 2, buffer.physical(), 32).unwrap();
        let b = controller
            .submit_iso(1, 5, buffer.physical() + 32, 32)
            .unwrap();
        let keep = controller
            .submit_iso(1, 7, buffer.physical() + 64, 32)
            .unwrap();
        let old_ring = controller.slot(1).unwrap().endpoints[2]
            .as_ref()
            .unwrap()
            .ring
            .buffer
            .physical();
        model.borrow_mut().fail = failure;
        let result = controller.deconfigure(1, &endpoints[..2]);
        if failure.is_some() {
            assert!(result.is_err());
            let slot = controller.slot(1).unwrap();
            assert!(slot.endpoints[2].as_ref().unwrap().poisoned);
            assert!(slot.endpoints[5].as_ref().unwrap().poisoned);
            assert!(slot.retired_rings[2].is_none());
            assert!(slot.retired_rings[5].is_none());
            assert!(!slot.endpoints[7].as_ref().unwrap().poisoned);
            assert!(controller.submit_iso(1, 2, buffer.physical(), 32).is_err());
            assert!(
                controller
                    .configure(1, &endpoints[..2], None, &mut dma)
                    .is_err()
            );
        } else {
            result.unwrap();
            assert!(controller.slot(1).unwrap().endpoints[2].is_none());
            assert!(controller.slot(1).unwrap().endpoints[5].is_none());
            assert!(controller.slot(1).unwrap().endpoints[7].is_some());
            controller
                .configure(1, &endpoints[..2], None, &mut dma)
                .unwrap();
            assert_eq!(
                old_ring,
                controller.slot(1).unwrap().endpoints[2]
                    .as_ref()
                    .unwrap()
                    .ring
                    .buffer
                    .physical()
            );
            assert!(controller.completed_iso(&a).unwrap().is_err());
            assert!(controller.completed_iso(&b).unwrap().is_err());
            model.borrow_mut().complete(7, 0, SUCCESS, 0);
            controller.completed_iso(&keep).unwrap().unwrap();
            let fresh = controller.submit_iso(1, 2, buffer.physical(), 32).unwrap();
            model
                .borrow_mut()
                .event(a.trb, SUCCESS, 2, 0, TRANSFER_EVENT);
            assert!(controller.completed_iso(&fresh).is_none());
            model.borrow_mut().complete(2, 0, SUCCESS, 0);
            controller.completed_iso(&fresh).unwrap().unwrap();
        }
    }
}

mod reuse;

#[test]
fn invalid_descriptor_route_teardown_and_submission_have_no_dma_publication() {
    let mut backing = vec![0u64; 32 * 1024];
    let start = backing.as_mut_ptr() as u64;
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut controller, model) = controller(&mut dma, HIGH_SPEED, 32, true);
    let endpoint = endpoint(0x81, HIGH_SPEED);
    controller.slot(1).unwrap().attachment.tier = 1;
    assert!(
        controller
            .configure(1, &[endpoint], None, &mut dma)
            .is_err()
    );
    assert!(model.borrow().seen.is_empty());
    controller.slot(1).unwrap().attachment.tier = 0;
    controller
        .configure(1, &[endpoint], None, &mut dma)
        .unwrap();
    let buffer = dma.allocate(4096, 4096).unwrap();
    let commands = model.borrow().seen.len();
    let remaining = dma.remaining();
    assert!(controller.deconfigure(1, &[endpoint, endpoint]).is_err());
    assert_eq!(model.borrow().seen.len(), commands);
    assert!(
        controller
            .submit_iso(1, 3, buffer.physical(), 3073)
            .is_err()
    );
    assert!(
        controller
            .submit_iso(1, 3, buffer.physical().next_multiple_of(65536) - 1, 32)
            .is_err()
    );
    assert_eq!(dma.remaining(), remaining);
    assert!(model.borrow().active.is_empty());
    assert!(controller.clear(1, &endpoint).is_err());
    assert_eq!(model.borrow().seen.len(), commands);
    let ticket = controller.submit_iso(1, 3, buffer.physical(), 0).unwrap();
    assert_eq!(model.borrow().active[0].1.control >> 16 & 15, 0);
    model.borrow_mut().complete(3, 0, SUCCESS, 0);
    assert_eq!(controller.completed_iso(&ticket).unwrap().unwrap().bytes, 0);
}

#[test]
fn silent_cancellation_and_fatal_controller_status_never_release_queued_buffers() {
    for silent in [STOP_ENDPOINT, SET_DEQUEUE] {
        let mut backing = vec![0u64; 32 * 1024];
        let start = backing.as_mut_ptr() as u64;
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = controller(&mut dma, HIGH_SPEED, 32, true);
        controller
            .configure(1, &[endpoint(0x81, HIGH_SPEED)], None, &mut dma)
            .unwrap();
        let buffer = dma.allocate(4096, 4096).unwrap();
        let ticket = controller.submit_iso(1, 3, buffer.physical(), 32).unwrap();
        model.borrow_mut().silent = Some(silent);
        assert!(controller.cancel(1, 3).is_err());
        assert!(controller.command_poisoned);
        assert_eq!(
            controller.slot(1).unwrap().endpoints[3]
                .as_ref()
                .unwrap()
                .iso
                .as_ref()
                .unwrap()
                .active
                .len(),
            1
        );
        assert!(controller.completed_iso(&ticket).unwrap().is_err());
    }
    let mut backing = vec![0u64; 32 * 1024];
    let start = backing.as_mut_ptr() as u64;
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut controller, model) = controller(&mut dma, HIGH_SPEED, 32, true);
    controller
        .configure(1, &[endpoint(0x81, HIGH_SPEED)], None, &mut dma)
        .unwrap();
    let buffer = dma.allocate(4096, 4096).unwrap();
    let ticket = controller.submit_iso(1, 3, buffer.physical(), 32).unwrap();
    model.borrow_mut().fatal = true;
    assert!(controller.completed_iso(&ticket).unwrap().is_err());
    assert!(controller.cancel(1, 3).is_err());
    assert_eq!(
        controller.slot(1).unwrap().endpoints[3]
            .as_ref()
            .unwrap()
            .iso
            .as_ref()
            .unwrap()
            .active
            .len(),
        1
    );
}

#[test]
fn actual_profile_scope_rejects_unknown_raw_and_legacy_controllers() {
    for vendor in [0, 0x1022, 0x1b36] {
        for device in [
            0, 0x15b6, 0x15b7, 0x15b8, 0x43fc, 0x15e0, 0x15e5, 0x43bb, 0x000d,
        ] {
            let mut caps = Capabilities::new(0x110, 0, 0);
            assert!(caps.admit().is_err());
            caps.qualify(Policy::pci(vendor, device));
            assert_eq!(
                caps.admit().is_ok(),
                vendor == 0x1022 && matches!(device, 0x15b6 | 0x15b7 | 0x15b8 | 0x43fc)
                    || vendor == 0x1b36 && device == 0x000d
            );
        }
    }
    let mut old = Capabilities::new(0x96, 0, 0);
    old.qualify(Policy::Qemu);
    assert!(old.admit().is_err());
}

#[test]
#[ignore = "requires immutable pinned Linux isochronous helper trace"]
fn unchanged_linux_iso_context_scheduling_burst_and_terminal_completion() {
    use sha2::{Digest, Sha256};
    let trace = std::fs::read_to_string(
        std::env::var("STELA_XHCI_ISO_ORACLE").expect("path to fresh source oracle trace"),
    )
    .unwrap();
    assert_eq!(
        alloc::format!("{:x}", Sha256::digest(trace.as_bytes())),
        "8dff7cfded211423e137dde9864585635f4ac2467fe7c93057081a0c925927e6"
    );
    let mut count = 0;
    for line in trace.lines() {
        let mut fields = line.split_whitespace();
        let kind = fields.next().unwrap();
        let values: Vec<i64> = fields.map(|v| v.parse().unwrap()).collect();
        match kind {
            "E" => {
                assert_eq!(values.len(), 8);
                let speed = if values[0] == 2 {
                    FULL_SPEED
                } else {
                    HIGH_SPEED
                };
                let ep = Endpoint {
                    address: if values[3] != 0 { 0x81 } else { 1 },
                    attributes: 1,
                    max_packet: values[4] as u16 | (values[2] as u16) << 11,
                    interval: values[1] as u8,
                    companion: None,
                };
                match Recipe::new(&ep, speed) {
                    Ok(recipe) => {
                        let context = recipe.context();
                        assert_eq!(
                            [context.info, context.info2, context.tx_info],
                            [values[5] as u32, values[6] as u32, values[7] as u32]
                        );
                    }
                    Err(_) => assert!(values[5] >> 16 > 12),
                }
            }
            "S" => {
                assert_eq!(values.len(), 8);
                let caps = Capabilities::new(
                    0x110,
                    values[1] as u32,
                    if values[2] != 0 { 1 << 11 } else { 0 },
                );
                let next = if values[4] < 0 {
                    None
                } else {
                    Some(values[4] as u32)
                };
                match schedule(values[0] as u32, caps, values[3] as u32, next) {
                    Ok((start, field)) => {
                        assert_eq!(values[7], 1);
                        assert_eq!(start, values[5] as u32);
                        assert_eq!(
                            field,
                            if values[6] != 0 {
                                (start / 8) << 20
                            } else {
                                SIA
                            }
                        );
                    }
                    Err(_) => assert_eq!(values[7], 0),
                }
            }
            "C" => {
                assert_eq!(values.len(), 6);
                assert_eq!(values[4], 1); // process_isoc_td reached finish callback.
                if matches!(values[0], 6 | 22) {
                    // The original finish path still requires halt/slot recovery:
                    // its packet-status assignment is not a DMA-release ACK.
                    assert!(completion(values[0] as u32, 128, values[1] as usize).is_err());
                    assert_eq!(values[3], -71);
                    assert_eq!(values[5], i64::from(values[0] == 6));
                } else {
                    assert_eq!(values[5], 0);
                    let packet = completion(values[0] as u32, 128, values[1] as usize).unwrap();
                    assert_eq!(packet.bytes, values[2] as usize);
                    assert_eq!(
                        match packet.status {
                            IsoStatus::Success | IsoStatus::Short => 0,
                            IsoStatus::MissedService => -18,
                            IsoStatus::Transaction => -71,
                            IsoStatus::Babble | IsoStatus::BufferOverrun => -75,
                            IsoStatus::Bandwidth => -70,
                        },
                        values[3]
                    );
                }
            }
            "B" => {
                assert_eq!(values.len(), 3);
                let recipe = Recipe::new(&endpoint(0x81, HIGH_SPEED), HIGH_SPEED).unwrap();
                let field = trb_control(recipe, values[0] as usize * 1024, 0);
                assert_eq!(field >> 7 & 3, values[1] as u32);
                assert_eq!(field >> 16 & 15, values[2] as u32);
            }
            _ => panic!("unknown source trace row"),
        }
        count += 1;
    }
    assert_eq!(count, 4656);
}

#[test]
fn transferless_errors_stalls_and_incompatible_slots_never_release_an_arbitrary_ticket() {
    for code in [6, 14, 15, 22, 23, 36, 99] {
        let mut backing = vec![0u64; 32 * 1024];
        let start = backing.as_mut_ptr() as u64;
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = controller(&mut dma, HIGH_SPEED, 32, true);
        controller
            .configure(1, &[endpoint(0x81, HIGH_SPEED)], None, &mut dma)
            .unwrap();
        let buffer = dma.allocate(4096, 4096).unwrap();
        let ticket = controller.submit_iso(1, 3, buffer.physical(), 32).unwrap();
        let other = controller
            .submit_iso(1, 3, buffer.physical() + 32, 32)
            .unwrap();
        if code == 6 || code == 22 {
            model.borrow_mut().complete(3, 0, code, 0);
        } else {
            model.borrow_mut().event(0, code, 3, 0, TRANSFER_EVENT);
        }
        assert!(controller.completed_iso(&ticket).unwrap().is_err());
        assert_eq!(
            controller.slot(1).unwrap().endpoints[3]
                .as_ref()
                .unwrap()
                .iso
                .as_ref()
                .unwrap()
                .active
                .len(),
            2
        );
        assert!(controller.completed_iso(&other).unwrap().is_err());
        assert!(
            controller
                .submit_iso(1, 3, buffer.physical() + 64, 32)
                .is_err()
        );
        if code == 22 {
            let n = model.borrow().seen.len();
            assert!(controller.cancel(1, 3).is_err());
            assert_eq!(model.borrow().seen.len(), n);
        } else {
            controller.cancel(1, 3).unwrap();
            assert!(model.borrow().active.is_empty());
            assert!(controller.completed_iso(&ticket).unwrap().is_err());
            controller.submit_iso(1, 3, buffer.physical(), 32).unwrap();
            if code == 6 {
                assert!(
                    model
                        .borrow()
                        .seen
                        .iter()
                        .any(|(kind, _)| *kind == RESET_ENDPOINT)
                );
            }
        }
    }
}

#[test]
#[ignore = "requires immutable pinned Linux AMD PCI quirk and PLL trace"]
fn unchanged_linux_actual_amd_pci_profiles_and_saved_smbus_do_not_inherit_legacy_quirks() {
    use sha2::{Digest, Sha256};
    let trace = std::fs::read_to_string(
        std::env::var("STELA_XHCI_AMD_PCI_ORACLE").expect("path to fresh source oracle trace"),
    )
    .unwrap();
    assert_eq!(
        alloc::format!("{:x}", Sha256::digest(trace.as_bytes())),
        "f15c7bae3478f2cbf04438ef5fa64d24799ee708dc73d32fec4d1f687c4e57b9"
    );
    let mut count = 0;
    let mut legacy_positive = false;
    let mut actual_negative = 0;
    for line in trace.lines() {
        let mut fields = line.split_whitespace();
        let kind = fields.next().unwrap();
        let values: Vec<u64> = fields.map(|v| v.parse().unwrap()).collect();
        assert_eq!(values.len(), 5);
        match kind {
            "P" => {
                assert!(matches!(values[0], 0x15b6 | 0x15b7 | 0x15b8 | 0x43fc));
                let mut caps = Capabilities::new(values[2] as u16, 0, 0);
                caps.qualify(Policy::pci(0x1022, values[0] as u16));
                caps.admit().unwrap();
                // xHCI>=1.2 permits runtime PM generically; this cold polled
                // backend does not claim a suspend/runtime-power service.
                assert_eq!(values[3], if values[2] >= 0x120 { 1 << 33 } else { 0 });
                assert_eq!(values[4], 0);
            }
            "L" => {
                if values[0] == 0x1022 && values[1] == 0x790b {
                    assert_eq!(values[3], 0);
                    actual_negative += 1;
                }
                legacy_positive |= values[3] != 0;
            }
            _ => panic!("unknown PCI source trace"),
        }
        count += 1;
    }
    assert_eq!(count, 4096);
    assert_eq!(actual_negative, 256);
    assert!(legacy_positive);
}

/// Opaque reuse of the real-ring ISO model by class lifecycle regressions. This
/// is not USB enumeration, normal control/HCI I/O or a hardware qualification.
pub(crate) struct ClassIsoFixture {
    controller: Shared,
    hardware: Rc<RefCell<Hardware>>,
}
pub(crate) fn class_fixture(dma: &mut dyn DmaAllocator, speed: u8) -> ClassIsoFixture {
    let (controller, hardware) = controller(dma, speed, 32, true);
    ClassIsoFixture {
        controller: Rc::new(RefCell::new(controller)),
        hardware,
    }
}
impl ClassIsoFixture {
    pub(crate) fn controller(&self) -> Shared {
        self.controller.clone()
    }
    pub(crate) fn set_mfindex(&self, value: u32) {
        self.hardware.borrow_mut().mfindex = value;
    }
    /// Complete the oldest actual queued service on this endpoint.
    pub(crate) fn complete(&self, dci: u8, code: u32, residual: usize) {
        self.hardware.borrow_mut().complete(dci, 0, code, residual);
    }
    pub(crate) fn commands(&self) -> Vec<(u32, u8)> {
        self.hardware.borrow().seen.clone()
    }
}
