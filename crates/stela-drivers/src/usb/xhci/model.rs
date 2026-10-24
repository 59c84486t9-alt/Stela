//! xHCI controller and device models shared by tests across the USB stack.
pub(crate) use super::bind::{bind, bind_with_provider};
pub(crate) use super::configuration::tests::{addressed_device, device, ecm};
pub(crate) use super::configuration::{sanitize, select};
pub(crate) use super::iso::tests::class_fixture as iso_class_fixture;
pub(crate) use super::reset::tests::{
    Fault as ResetFault, Hardware as ResetHardware, fixture as reset_fixture,
    fixture_bot as reset_bot_fixture,
};
use super::*;
pub(crate) use crate::bus::dma::RegionAllocator;

impl Controller {
    /// Record the speed a model device in `slot` was addressed at.
    pub(crate) fn set_slot_speed(&mut self, slot: u8, speed: u8) {
        self.slots[usize::from(slot)].as_mut().unwrap().speed = speed;
    }
    /// Whether failed cancellation poisoned an endpoint.
    pub(crate) fn endpoint_poisoned(&self, slot: u8, dci: usize) -> bool {
        self.slots[usize::from(slot)].as_ref().unwrap().endpoints[dci]
            .as_ref()
            .unwrap()
            .poisoned
    }
    /// The contents of a slot's EP0 data buffer.
    pub(crate) fn control_bytes(&self, slot: u8) -> Vec<u8> {
        self.slots[usize::from(slot)]
            .as_ref()
            .unwrap()
            .control
            .bytes()
            .to_vec()
    }
}

/// A command/event DMA model with a device that needs the full
/// SET_ADDRESS recovery interval before accepting its first Setup.
pub(crate) struct AddressModel {
    pub(crate) port_speed: u8,
    pub(crate) context_bytes: usize,
    pub(crate) commands: u64,
    pub(crate) command_index: usize,
    pub(crate) events: u64,
    pub(crate) event_index: usize,
    pub(crate) control_ring: u64,
    pub(crate) dcbaa: u64,
    pub(crate) output: u64,
    pub(crate) ready_at: u64,
    pub(crate) recovery_ticks: u64,
    pub(crate) address_code: u32,
    pub(crate) commands_seen: Vec<u32>,
    pub(crate) setup_seen: Vec<[u8; 8]>,
    pub(crate) early_setup: bool,
}

impl AddressModel {
    pub(crate) fn event(&mut self, parameter: u64, code: u32, kind: u32, endpoint: u8) {
        let address = self.events + (self.event_index * TRB) as u64;
        // SAFETY: these are aligned DMA words in the test's backing
        // allocation, which outlives the controller and this model.
        unsafe {
            (address as *mut u64).write_volatile(parameter);
            ((address + 8) as *mut u32).write_volatile(code << 24);
            ((address + 12) as *mut u32)
                .write_volatile(1 << 24 | u32::from(endpoint) << 16 | kind << 10 | CYCLE);
        }
        self.event_index += 1;
    }
}

pub(crate) struct AddressRegisters(Rc<RefCell<AddressModel>>);

impl Registers for AddressRegisters {
    fn read32(&mut self, offset: usize) -> u32 {
        if offset == 0x440 {
            PP | CCS | PED | u32::from(self.0.borrow().port_speed) << 10
        } else {
            0
        }
    }

    fn write32(&mut self, offset: usize, _value: u32) {
        let mut model = self.0.borrow_mut();
        if offset == 0x1000 {
            let address = model.commands + (model.command_index * TRB) as u64;
            // SAFETY: the command ring and the input context named by
            // Address Device belong to the live test DMA allocation.
            let (parameter, kind) = unsafe {
                (
                    (address as *const u64).read_volatile(),
                    ((address + 12) as *const u32).read_volatile() >> 10 & 0x3f,
                )
            };
            model.command_index += 1;
            model.commands_seen.push(kind);
            let code = if kind == ADDRESS_DEVICE {
                // SAFETY: the live DCBAA slot points to the output context
                // allocated by address() before publishing this command.
                model.output = unsafe { ((model.dcbaa + 8) as *const u64).read_volatile() };
                // SAFETY: EP0's dequeue pointer in the actual input context
                // points to this test controller's retained control ring.
                model.control_ring = unsafe {
                    ((parameter + 2 * model.context_bytes as u64 + 8) as *const u64).read_volatile()
                        & !0xf
                };
                model.ready_at = Clock::ticks() + model.recovery_ticks;
                model.address_code
            } else {
                if matches!(kind, RESET_ENDPOINT | STOP_ENDPOINT) {
                    // SAFETY: EP0 state in the actual retained output context.
                    unsafe {
                        ((model.output + model.context_bytes as u64) as *mut u32)
                            .write_volatile(ENDPOINT_STOPPED);
                    }
                }
                if kind == SET_DEQUEUE {
                    model.control_ring = parameter & !0xf;
                }
                SUCCESS
            };
            model.event(address, code, COMMAND_COMPLETION, 0);
        } else if offset == 0x1004 {
            // This model runs one GET_DESCRIPTOR with Setup/Data/Status.
            let ring = model.control_ring;
            // SAFETY: the ring is initialized by control() before its
            // doorbell, in the test's still-live DMA allocation.
            let request = unsafe { (ring as *const u64).read_volatile().to_le_bytes() };
            model.setup_seen.push(request);
            model.early_setup = Clock::ticks() < model.ready_at;
            let (parameter, code) = if model.early_setup {
                // SAFETY: failed transfer halts EP0 in the live context.
                unsafe {
                    ((model.output + model.context_bytes as u64) as *mut u32)
                        .write_volatile(ENDPOINT_HALTED);
                }
                (ring, 4)
            } else {
                (ring + 2 * TRB as u64, SUCCESS)
            };
            model.event(parameter, code, TRANSFER_EVENT, 1);
        }
    }
}

pub(crate) fn address_controller(
    dma: &mut dyn DmaAllocator,
    address_code: u32,
) -> (Controller, Rc<RefCell<AddressModel>>) {
    address_controller_with_capabilities(dma, address_code, None)
}

/// Independent capability-register image installed before the model Controller
/// captures ISO capabilities. The default fixture does not install this peer.
struct CapabilityRegisters {
    original: Box<dyn Registers>,
    words: [u32; 3],
}
impl Registers for CapabilityRegisters {
    fn read32(&mut self, offset: usize) -> u32 {
        match offset {
            0x00 => self.words[0],
            0x08 => self.words[1],
            0x10 => self.words[2],
            _ => self.original.read32(offset),
        }
    }
    fn write32(&mut self, offset: usize, value: u32) {
        self.original.write32(offset, value);
    }
}

fn address_controller_with_capabilities(
    dma: &mut dyn DmaAllocator,
    address_code: u32,
    capability_words: Option<[u32; 3]>,
) -> (Controller, Rc<RefCell<AddressModel>>) {
    let commands = Ring::new(dma).unwrap();
    let events = dma.allocate(RING_TRBS * TRB, 64).unwrap();
    let clock = Clock {
        ticks_per_microsecond: 1_000,
    };
    let model = Rc::new(RefCell::new(AddressModel {
        port_speed: HIGH_SPEED,
        context_bytes: 32,
        commands: commands.buffer.physical(),
        command_index: 0,
        events: events.physical(),
        event_index: 0,
        control_ring: 0,
        dcbaa: 0,
        output: 0,
        ready_at: 0,
        recovery_ticks: ADDRESS_RECOVERY_US * clock.ticks_per_microsecond,
        address_code,
        commands_seen: Vec::new(),
        setup_seen: Vec::new(),
        early_setup: false,
    }));
    let mut registers: Box<dyn Registers> = Box::new(AddressRegisters(model.clone()));
    let iso_caps = if let Some(words) = capability_words {
        registers = Box::new(CapabilityRegisters {
            original: registers,
            words,
        });
        // Actual reads of the installed independent wire image precede capture;
        // caller integers never replace an already-constructed Controller field.
        let version = (registers.read32(0x00) >> 16) as u16;
        let hcs2 = registers.read32(0x08);
        let hcc1 = registers.read32(0x10);
        iso::Capabilities::new(version, hcs2, hcc1)
    } else {
        iso::Capabilities::new(0x100, 0, 0)
    };
    let controller = Controller {
        registers,
        clock,
        operational: 0x40,
        runtime: 0x800,
        doorbells: 0x1000,
        context_bytes: 32,
        dma_profile: dma::Profile::SPEC,
        hardware: hardware::State::Running,
        quirks: quirks::Profile::default(),
        max_primary_streams: 4,
        stream_policy: streams::Policy::Unknown,
        iso_caps,
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
        slots: vec![None, None],
        legacy_slot_fenced: vec![false; 2],
        retry_resources: slot_resources::Cache::new(2),
        slot_ownership: vec![reset::Ownership::Vacant; 2],
        power: power::Ledger::new(2),
        pending: Vec::new(),
        error: None,
        command_poisoned: false,
        location: String::from("test xhci"),
    };
    model.borrow_mut().dcbaa = controller.dcbaa.physical();
    (controller, model)
}

/// Hardware model enforces the endpoint state restrictions absent from the
/// old address model: Stop accepts Running, Reset accepts Halted, Set Dequeue
/// accepts Stopped. It can leave DMA active on command failure.
pub(crate) struct CancelModel {
    pub(crate) port_speed: u8,
    pub(crate) context_bytes: usize,
    pub(crate) commands: u64,
    pub(crate) command_index: usize,
    pub(crate) events: u64,
    pub(crate) event_index: usize,
    pub(crate) output: u64,
    pub(crate) rings: [u64; 32],
    pub(crate) indices: [usize; 32],
    pub(crate) active: [Option<(u64, u64, usize)>; 32],
    pub(crate) connected: bool,
    pub(crate) fail: Option<(u32, u32)>,
    pub(crate) silence: Option<u32>,
    pub(crate) race_halt: bool,
    pub(crate) stale: Option<u64>,
    pub(crate) seen: Vec<u32>,
    pub(crate) dequeues: Vec<u64>,
    pub(crate) setup: Vec<([u8; 8], Vec<u8>)>,
    pub(crate) incoming_events: alloc::collections::VecDeque<Vec<u8>>,
    pub(crate) incoming_acl: alloc::collections::VecDeque<Vec<u8>>,
    pub(crate) outgoing: Vec<Vec<u8>>,
    pub(crate) fatal_status: u32,
    pub(crate) fatal_on_command: Option<u32>,
    pub(crate) silence_transfer: Option<usize>,
    pub(crate) halt_transfer: Option<usize>,
    pub(crate) script: Option<crate::usb::bluetooth::intel::tests::Script>,
    pub(crate) descriptors: Vec<(u8, u8, Vec<u8>)>,
    pub(crate) configuration_value: u8,
    pub(crate) configuration_seen_before_endpoints: Vec<u8>,
    pub(crate) short_control_out: bool,
    pub(crate) control_replies: alloc::collections::VecDeque<([u8; 8], Vec<u8>)>,
    pub(crate) stall_control: Option<u8>,
    pub(crate) silence_control: Option<u8>,
    pub(crate) short_bulk_out: bool,
    pub(crate) ethernet: Option<ethernet::rtl815x::tests::Model>,
    pub(crate) ethernet_upload: Option<ethernet::rtl815x::FirmwareModel>,
    pub(crate) asix: Option<ethernet::AsixModel>,
    pub(crate) asix_legacy: Option<ethernet::LegacyModel>,
    pub(crate) asix_ticks: u64,
}

impl CancelModel {
    pub(crate) fn state(&self, dci: usize) -> u32 {
        // SAFETY: output context is live aligned test DMA, exclusively
        // accessed by this model between controller operations.
        unsafe {
            ((self.output + dci as u64 * self.context_bytes as u64) as *const u32).read_volatile()
                & 7
        }
    }
    pub(crate) fn set_state(&mut self, dci: usize, state: u32) {
        // EP State occupies bits 2:0; hardware transitions retain the configured
        // Interval, Mult and stream-array fields in the rest of this word.
        // SAFETY: same live context as state().
        unsafe {
            let info = (self.output + dci as u64 * self.context_bytes as u64) as *mut u32;
            info.write_volatile(info.read_volatile() & !7 | state & 7);
        }
    }
    pub(crate) fn event(&mut self, parameter: u64, code: u32, kind: u32, dci: u8, residual: usize) {
        let cycle = u32::from((self.event_index / RING_TRBS).is_multiple_of(2));
        let address = self.events + ((self.event_index % RING_TRBS) * TRB) as u64;
        // SAFETY: all three fields are in the still-live test event ring.
        unsafe {
            (address as *mut u64).write_volatile(parameter);
            ((address + 8) as *mut u32).write_volatile(code << 24 | residual as u32);
            ((address + 12) as *mut u32)
                .write_volatile(1 << 24 | u32::from(dci) << 16 | kind << 10 | cycle);
        }
        self.event_index += 1;
    }
    pub(crate) fn receive(&mut self, dci: usize) {
        let queue = if (self.asix.is_some() || self.asix_legacy.is_some())
            && dci >= 3
            && !dci.is_multiple_of(2)
        {
            &mut self.incoming_events
        } else {
            match dci {
                3 => &mut self.incoming_events,
                5 => &mut self.incoming_acl,
                _ => return,
            }
        };
        if self.active[dci].is_none() || queue.is_empty() {
            return;
        }
        let bytes = queue.pop_front().unwrap();
        let (trb, buffer, length) = self.active[dci].take().unwrap();
        assert!(bytes.len() <= length);
        // SAFETY: submitted TD names exactly this live DMA allocation;
        // only the model owns it until the completion it posts below.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer as *mut u8, bytes.len());
        }
        self.event(
            trb,
            SHORT_PACKET,
            TRANSFER_EVENT,
            dci as u8,
            length - bytes.len(),
        );
    }
    pub(crate) fn command(&mut self) {
        let at = self.commands + (self.command_index * TRB) as u64;
        // SAFETY: the controller has published this command before ringing.
        let (parameter, control) = unsafe {
            (
                (at as *const u64).read_volatile(),
                ((at + 12) as *const u32).read_volatile(),
            )
        };
        self.command_index += 1;
        let kind = control >> 10 & 0x3f;
        let dci = (control >> 16 & 0x1f) as usize;
        self.seen.push(kind);
        if self.silence == Some(kind) {
            return;
        }
        let mut code = SUCCESS;
        if let Some((wanted, status)) = self.fail
            && kind == wanted
        {
            code = status;
        }
        if code == SUCCESS {
            match kind {
                CONFIGURE_ENDPOINT => {
                    let value = self.configuration_value;
                    self.configuration_seen_before_endpoints.push(value);
                    // SAFETY: Configure Endpoint points to the live input
                    // context, with enabled endpoint dequeue pointers.
                    let flags = unsafe { ((parameter + 4) as *const u32).read_volatile() };
                    for index in 2..32 {
                        if flags & (1 << index) != 0 {
                            self.rings[index] = unsafe {
                                ((parameter + (index as u64 + 1) * self.context_bytes as u64 + 8)
                                    as *const u64)
                                    .read_volatile()
                                    & !0xf
                            };
                            self.indices[index] = 0;
                            self.set_state(index, 1);
                        }
                    }
                }
                STOP_ENDPOINT => {
                    if self.race_halt {
                        self.race_halt = false;
                        self.set_state(dci, 2);
                        code = 19;
                    } else if self.state(dci) == 1 {
                        self.set_state(dci, 3);
                        self.active[dci] = None;
                    } else {
                        code = 19;
                    }
                }
                RESET_ENDPOINT => {
                    if self.state(dci) == 2 {
                        self.set_state(dci, 3);
                        self.active[dci] = None;
                    } else {
                        code = 19;
                    }
                }
                SET_DEQUEUE => {
                    if self.state(dci) != 3 {
                        code = 19;
                    } else {
                        self.dequeues.push(parameter);
                        self.indices[dci] = ((parameter & !0xf) - self.rings[dci]) as usize / TRB;
                        if let Some(stale) = self.stale.take() {
                            self.event(stale, 26, TRANSFER_EVENT, dci as u8, 0);
                        }
                    }
                }
                _ => {}
            }
        }
        if self.fatal_on_command == Some(kind) {
            self.fatal_status = HSE;
        }
        self.event(at, code, COMMAND_COMPLETION, 0, 0);
    }
    pub(crate) fn scripted(&mut self, bulk: bool, packet: &[u8]) {
        use crate::usb::bluetooth::Pipe;
        if let Some(script) = &mut self.script {
            for (pipe, event) in script.command(bulk, packet) {
                match pipe {
                    Pipe::Event => &mut self.incoming_events,
                    Pipe::Acl => &mut self.incoming_acl,
                }
                .push_back(event);
            }
        }
    }
    pub(crate) fn legacy_request(&mut self, request: [u8; 8], output: &[u8]) -> Vec<u8> {
        // Controller Clock uses one test tick per microsecond.
        let ticks = unsafe { core::arch::x86_64::_rdtsc() };
        let legacy = self.asix_legacy.as_mut().unwrap();
        if self.asix_ticks != 0 {
            legacy.delay(ticks - self.asix_ticks);
        }
        self.asix_ticks = ticks;
        legacy.request(request, output).unwrap()
    }
    pub(crate) fn transfer(&mut self, dci: usize) {
        self.indices[dci] %= RING_TRBS - 1;
        let at = self.rings[dci] + (self.indices[dci] * TRB) as u64;
        // SAFETY: a doorbell publishes a live transfer ring entry and any
        // data buffer encoded by that entry.
        let (parameter, length) = unsafe {
            (
                (at as *const u64).read_volatile(),
                ((at + 8) as *const u32).read_volatile() as usize & 0x1ffff,
            )
        };
        self.set_state(dci, 1);
        if self.halt_transfer == Some(dci) {
            // A STALL leaves the failed TD at the hardware dequeue pointer.
            // Reset stops it, but only Set Dequeue abandons it; another
            // doorbell could otherwise resume this same TD.
            self.set_state(dci, ENDPOINT_HALTED);
            self.active[dci] = Some((at, parameter, length));
            self.event(at, STALL, TRANSFER_EVENT, dci as u8, 0);
            return;
        }
        if dci == 1 {
            let request = parameter.to_le_bytes();
            let length = usize::from(u16::from_le_bytes([request[6], request[7]]));
            let mut received = length;
            let data = if length == 0 {
                if request[0] == 0 && request[1] == SET_CONFIGURATION {
                    self.configuration_value = request[2];
                }
                if request[0] == 0x40 && self.asix_legacy.is_some() {
                    self.legacy_request(request, &[]);
                }
                Vec::new()
            } else {
                // SAFETY: the next Data TRB's buffer is live through this
                // synchronous modeled control completion.
                let next =
                    self.rings[dci] + (((self.indices[dci] + 1) % (RING_TRBS - 1)) * TRB) as u64;
                let buffer = unsafe { (next as *const u64).read_volatile() };
                if matches!(request[0], 0x80 | 0x81)
                    && request[1] == GET_DESCRIPTOR
                    && let Some((_, _, bytes)) = self
                        .descriptors
                        .iter()
                        .find(|(kind, index, _)| (*kind, *index) == (request[3], request[2]))
                {
                    received = bytes.len().min(length);
                    // SAFETY: buffer has the requested length and the
                    // device writes only that bounded response.
                    unsafe {
                        core::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer as *mut u8, received);
                    }
                }
                if matches!(request[0], 0xa1 | 0x82) && !self.control_replies.is_empty() {
                    let (expected, reply) = self.control_replies.pop_front().unwrap();
                    assert_eq!(request, expected);
                    received = reply.len();
                    assert!(received <= length);
                    // SAFETY: this synchronous device reply fits the live
                    // Data TRB allocation, retained through completion.
                    unsafe {
                        core::ptr::copy_nonoverlapping(reply.as_ptr(), buffer as *mut u8, received);
                    }
                }
                if matches!(request[0], 0xc0 | 0x40)
                    && (self.asix.is_some()
                        || self.asix_legacy.is_some()
                        || (request[1] == 5
                            && (self.ethernet.is_some() || self.ethernet_upload.is_some())))
                {
                    let output = if request[0] == 0x40 {
                        // SAFETY: Data TRB refers to the live control buffer.
                        unsafe { core::slice::from_raw_parts(buffer as *const u8, length) }
                    } else {
                        &[]
                    };
                    let reply = if self.asix_legacy.is_some() {
                        self.legacy_request(request, output)
                    } else if let Some(asix) = &mut self.asix {
                        asix.request(request, output).unwrap()
                    } else if let Some(ethernet) = &mut self.ethernet {
                        ethernet.request(request, output).unwrap()
                    } else {
                        self.ethernet_upload
                            .as_mut()
                            .unwrap()
                            .request(request, output)
                            .unwrap()
                    };
                    if request[0] == 0xc0 {
                        received = reply.len();
                        assert!(received <= length);
                        // SAFETY: reply is bounded by this TD's requested buffer.
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                reply.as_ptr(),
                                buffer as *mut u8,
                                received,
                            );
                        }
                    }
                }
                if request[0] & 0x80 == 0 && self.short_control_out {
                    received = length - 1;
                }
                unsafe { core::slice::from_raw_parts(buffer as *const u8, length).to_vec() }
            };
            if request[0] & 0x80 == 0 && request[1] != SET_CONFIGURATION {
                self.scripted(false, &data);
            }
            self.setup.push((request, data));
            let trbs = if length == 0 { 2 } else { 3 };
            if self.stall_control == Some(request[1]) {
                self.set_state(dci, ENDPOINT_HALTED);
                self.active[dci] = Some((at, 0, length));
                self.event(at, STALL, TRANSFER_EVENT, dci as u8, 0);
                return;
            }
            if self.silence_transfer == Some(dci) || self.silence_control == Some(request[1]) {
                self.active[dci] = Some((at, 0, length));
            } else {
                if received < length {
                    self.event(
                        self.rings[dci]
                            + (((self.indices[dci] + 1) % (RING_TRBS - 1)) * TRB) as u64,
                        SHORT_PACKET,
                        TRANSFER_EVENT,
                        1,
                        length - received,
                    );
                }
                self.event(
                    self.rings[dci]
                        + (((self.indices[dci] + trbs as usize - 1) % (RING_TRBS - 1)) * TRB)
                            as u64,
                    SUCCESS,
                    TRANSFER_EVENT,
                    1,
                    0,
                );
            }
            self.indices[dci] += trbs as usize;
        } else {
            self.indices[dci] += 1;
            if dci == 4
                || ((self.asix.is_some() || self.asix_legacy.is_some())
                    && dci >= 2
                    && dci.is_multiple_of(2))
            {
                // SAFETY: the submitted bulk OUT buffer is live until the
                // completion below acknowledges its bytes.
                let packet =
                    unsafe { core::slice::from_raw_parts(parameter as *const u8, length).to_vec() };
                self.scripted(true, &packet);
                self.outgoing.push(packet);
                if self.silence_transfer == Some(dci) {
                    self.active[dci] = Some((at, parameter, length));
                } else {
                    let short = self.short_bulk_out && length != 0;
                    self.event(
                        at,
                        if short { SHORT_PACKET } else { SUCCESS },
                        TRANSFER_EVENT,
                        dci as u8,
                        usize::from(short),
                    );
                }
            } else {
                self.active[dci] = Some((at, parameter, length));
            }
        }
    }
}

pub(crate) struct CancelRegisters(Rc<RefCell<CancelModel>>);

impl Registers for CancelRegisters {
    fn read32(&mut self, offset: usize) -> u32 {
        let mut model = self.0.borrow_mut();
        if offset == 0x40 + PORTSC {
            return PP
                | u32::from(model.port_speed) << PORT_SPEED_SHIFT
                | if model.connected { CCS | PED } else { 0 };
        }
        if offset == 0x40 + USBSTS {
            if model.asix.is_some() || model.asix_legacy.is_some() {
                for dci in (3..32).step_by(2) {
                    model.receive(dci);
                }
            } else {
                model.receive(3);
                model.receive(5);
            }
            return model.fatal_status;
        }
        0
    }
    fn write32(&mut self, offset: usize, value: u32) {
        if offset == 0x1000 {
            self.0.borrow_mut().command();
        } else if offset == 0x1004 {
            self.0.borrow_mut().transfer(value as usize);
        }
    }
}

pub(crate) fn unconfigured_cancellation_controller(
    dma: &mut dyn DmaAllocator,
) -> (Controller, Rc<RefCell<CancelModel>>) {
    unconfigured_cancellation_controller_with_configurations(
        dma,
        &[vec![9, 2, 9, 0, 0, 1, 0, 0x80, 50]],
    )
}

pub(crate) fn unconfigured_cancellation_controller_with_configurations(
    dma: &mut dyn DmaAllocator,
    configurations: &[Vec<u8>],
) -> (Controller, Rc<RefCell<CancelModel>>) {
    cancellation_controller_at_speed(dma, configurations, FULL_SPEED)
}

fn cancellation_controller_at_speed(
    dma: &mut dyn DmaAllocator,
    configurations: &[Vec<u8>],
    speed: u8,
) -> (Controller, Rc<RefCell<CancelModel>>) {
    cancellation_controller_with_capabilities(dma, configurations, speed, None)
}

fn cancellation_controller_with_capabilities(
    dma: &mut dyn DmaAllocator,
    configurations: &[Vec<u8>],
    speed: u8,
    capability_words: Option<[u32; 3]>,
) -> (Controller, Rc<RefCell<CancelModel>>) {
    cancellation_controller_with_context(dma, configurations, speed, capability_words, 32)
}

/// Actual Address Device and SET_CONFIGURATION acknowledgements for endpoint
/// peers that exercise retained 32- and 64-byte contexts. No generation, parent
/// identity or current grant is synthesized by the later endpoint-only peer.
pub(crate) fn configured_endpoint_controller(
    dma: &mut dyn DmaAllocator,
    speed: u8,
    context_bytes: usize,
) -> Controller {
    let (mut controller, peer) = cancellation_controller_with_context(
        dma,
        &[vec![9, 2, 9, 0, 0, 1, 0, 0x80, 0]],
        speed,
        None,
        context_bytes,
    );
    controller.set_configuration(1, 1).unwrap();
    assert_eq!(peer.borrow().configuration_value, 1);
    assert_eq!(
        peer.borrow().setup[0].0,
        setup(0, SET_CONFIGURATION, 1, 0, 0)
    );
    controller
}

fn cancellation_controller_with_context(
    dma: &mut dyn DmaAllocator,
    configurations: &[Vec<u8>],
    speed: u8,
    capability_words: Option<[u32; 3]>,
    context_bytes: usize,
) -> (Controller, Rc<RefCell<CancelModel>>) {
    assert!(matches!(context_bytes, 32 | 64));
    let (mut controller, address_peer) =
        address_controller_with_capabilities(dma, SUCCESS, capability_words);
    controller.context_bytes = context_bytes;
    {
        let mut peer = address_peer.borrow_mut();
        peer.context_bytes = context_bytes;
        peer.port_speed = speed;
    }
    if speed >= SUPER_SPEED {
        controller.port_major[0] = 3;
    }
    let slot = controller
        .address(
            Attachment {
                root_port: 1,
                speed,
                route: 0,
                tier: 0,
                translator: None,
                parent: None,
            },
            dma,
        )
        .unwrap();
    assert_eq!(slot, 1);
    let state = controller.slots[1].as_ref().unwrap();
    let mut rings = [0; 32];
    rings[1] = state.endpoints[1].as_ref().unwrap().ring.buffer.physical();
    let model = Rc::new(RefCell::new(CancelModel {
        port_speed: speed,
        context_bytes,
        commands: controller.commands.buffer.physical(),
        command_index: controller.commands.index,
        events: controller.events.physical(),
        event_index: controller.event_index,
        output: state._output.physical(),
        rings,
        indices: [0; 32],
        active: [None; 32],
        connected: true,
        fail: None,
        silence: None,
        race_halt: false,
        stale: None,
        seen: Vec::new(),
        dequeues: Vec::new(),
        setup: Vec::new(),
        incoming_events: Default::default(),
        incoming_acl: Default::default(),
        outgoing: Vec::new(),
        fatal_status: 0,
        fatal_on_command: None,
        silence_transfer: None,
        halt_transfer: None,
        script: None,
        descriptors: Vec::new(),
        configuration_value: 0,
        configuration_seen_before_endpoints: Vec::new(),
        short_control_out: false,
        control_replies: Default::default(),
        stall_control: None,
        silence_control: None,
        short_bulk_out: false,
        ethernet: None,
        ethernet_upload: None,
        asix: None,
        asix_legacy: None,
        asix_ticks: 0,
    }));
    model.borrow_mut().set_state(1, 1);
    controller.registers = Box::new(CancelRegisters(model.clone()));
    // A short actual test deadline without pretending any completion happened.
    controller.clock.ticks_per_microsecond = 1;
    if !configurations.is_empty() {
        // These are the fixture's original wire descriptor/current profiles;
        // production discovery retains the descriptors before class binding.
        controller.current_descriptions(1, configurations).unwrap();
    }
    (controller, model)
}

pub(crate) fn cancellation_controller(
    dma: &mut dyn DmaAllocator,
) -> (Controller, Rc<RefCell<CancelModel>>) {
    let (mut controller, model) = unconfigured_cancellation_controller(dma);
    controller.set_configuration(1, 1).unwrap();
    let endpoints = [
        Endpoint {
            address: 0x81,
            attributes: 3,
            max_packet: 16,
            interval: 1,
            companion: None,
        },
        Endpoint {
            address: 0x82,
            attributes: 2,
            max_packet: 64,
            interval: 0,
            companion: None,
        },
        Endpoint {
            address: 0x02,
            attributes: 2,
            max_packet: 64,
            interval: 0,
            companion: None,
        },
    ];
    controller.configure(1, &endpoints, None, dma).unwrap();
    model.borrow_mut().seen.clear();
    (controller, model)
}

/// Shared class-driver regression fixture: a real submitted TD left
/// unresolved by failed Running Stop or Halted Set Dequeue recovery.
pub(crate) fn controller_with_unresolved_td(
    dma: &mut dyn DmaAllocator,
    buffer: u64,
    length: usize,
    dci: u8,
    halted: bool,
) -> Shared {
    if halted {
        let (controller, _) = failed_stall_recovery(dma, buffer, length, dci);
        return Rc::new(RefCell::new(controller));
    }
    let (mut controller, model) = cancellation_controller(dma);
    model.borrow_mut().silence_transfer = Some(usize::from(dci));
    model.borrow_mut().fail = Some((STOP_ENDPOINT, CONTEXT_STATE_ERROR));
    if dci == 1 {
        assert!(
            controller
                .control(1, setup(0x20, 0, 0, 0, 3), &[3, 0x0c, 0])
                .is_err()
        );
    } else {
        controller.submit(1, dci, buffer, length).unwrap();
        assert!(controller.cancel(1, dci).is_err());
    }
    assert!(model.borrow().active[usize::from(dci)].is_some());
    Rc::new(RefCell::new(controller))
}

pub(crate) fn fixture_endpoint(dci: u8) -> Endpoint {
    Endpoint {
        address: (dci / 2) | if dci & 1 != 0 { 0x80 } else { 0 },
        attributes: if dci == 3 { 3 } else { 2 },
        max_packet: if dci == 3 { 16 } else { 64 },
        interval: u8::from(dci == 3),
        companion: None,
    }
}

pub(crate) fn failed_stall_recovery(
    dma: &mut dyn DmaAllocator,
    buffer: u64,
    length: usize,
    dci: u8,
) -> (Controller, Rc<RefCell<CancelModel>>) {
    let (mut controller, model) = cancellation_controller(dma);
    model.borrow_mut().halt_transfer = Some(usize::from(dci));
    model.borrow_mut().fail = Some((SET_DEQUEUE, CONTEXT_STATE_ERROR));
    let result = if dci == 1 {
        controller
            .control(1, setup(0x20, 0, 0, 0, 3), &[3, 0x0c, 0])
            .map(|_| ())
    } else {
        let trb = controller.submit(1, dci, buffer, length).unwrap();
        assert_eq!(
            controller.completed(1, dci, trb, length),
            Some(Err(BlockError::Device { status: STALL }))
        );
        controller.clear(1, &fixture_endpoint(dci))
    };
    assert_eq!(
        result,
        Err(BlockError::Device {
            status: CONTEXT_STATE_ERROR
        })
    );
    assert_eq!(model.borrow().seen, vec![RESET_ENDPOINT, SET_DEQUEUE]);
    assert_eq!(model.borrow().state(usize::from(dci)), ENDPOINT_STOPPED);
    // EP0 already completed the configuration request in this fixture.
    assert_eq!(
        model.borrow().indices[usize::from(dci)],
        if dci == 1 { 2 } else { 0 }
    );
    assert!(model.borrow().dequeues.is_empty());
    assert!(!controller.command_poisoned);
    (controller, model)
}

/// Compose a forwarding peer around the existing real EP0/command DMA model.
/// The caller supplies original descriptor bytes and a separately modeled PCI
/// function; stream admission uses the same observed ConfigSpace policy as a
/// native attachment. The wrapper observes the original rings, not fake tickets.
/// Existing fixture construction and defaults remain unchanged.
pub(crate) fn forwarding_fixture<C: crate::bus::pci::ConfigSpace>(
    dma: &mut dyn DmaAllocator,
    configurations: &[Vec<u8>],
    speed: u8,
    function: &mut Function<C>,
    wrap: impl FnOnce(Box<dyn Registers>, Rc<RefCell<CancelModel>>) -> Box<dyn Registers>,
) -> (Controller, Rc<RefCell<CancelModel>>) {
    let (mut controller, model) = cancellation_controller_at_speed(dma, configurations, speed);
    controller.stream_policy = streams::pci_policy(function).unwrap();
    controller.registers = wrap(controller.registers, model.clone());
    (controller, model)
}

/// A forwarding peer whose capability-register image is installed and read
/// before the original Controller captures its immutable scheduling policy.
/// The existing fixture above retains its no-CFC/default capability path.
#[allow(clippy::too_many_arguments)]
pub(crate) fn forwarding_scheduled_fixture<C: crate::bus::pci::ConfigSpace>(
    dma: &mut dyn DmaAllocator,
    configurations: &[Vec<u8>],
    speed: u8,
    function: &mut Function<C>,
    version: u16,
    hcs2: u32,
    hcc1: u32,
    wrap: impl FnOnce(Box<dyn Registers>, Rc<RefCell<CancelModel>>) -> Box<dyn Registers>,
) -> (Controller, Rc<RefCell<CancelModel>>) {
    let (mut controller, model) = cancellation_controller_with_capabilities(
        dma,
        configurations,
        speed,
        Some([u32::from(version) << 16 | 0x40, hcs2, hcc1]),
    );
    controller.stream_policy = streams::pci_policy(function).unwrap();
    controller.registers = wrap(controller.registers, model.clone());
    (controller, model)
}

/// Same actual failed ordinary-TD fixture with its unique submitted ticket
/// retained by asynchronous class owners instead of a fabricated ring address.
pub(crate) fn controller_with_unresolved_ticket(
    dma: &mut dyn DmaAllocator,
    buffer: u64,
    length: usize,
    dci: u8,
    halted: bool,
) -> (Shared, TransferTicket) {
    let (mut controller, model) = cancellation_controller(dma);
    if halted {
        model.borrow_mut().halt_transfer = Some(usize::from(dci));
        model.borrow_mut().fail = Some((SET_DEQUEUE, CONTEXT_STATE_ERROR));
    } else {
        model.borrow_mut().silence_transfer = Some(usize::from(dci));
        model.borrow_mut().fail = Some((STOP_ENDPOINT, CONTEXT_STATE_ERROR));
    }
    let id = controller.device_id(1).unwrap();
    let ticket = controller
        .device(id)
        .unwrap()
        .submit_ticket(dci, buffer, length)
        .unwrap();
    if halted {
        assert_eq!(
            controller.completed_ticket(&ticket),
            Some(Err(BlockError::Device { status: STALL }))
        );
        assert_eq!(
            controller.device(id).unwrap().clear(&fixture_endpoint(dci)),
            Err(BlockError::Device {
                status: CONTEXT_STATE_ERROR
            })
        );
        assert_eq!(model.borrow().seen, vec![RESET_ENDPOINT, SET_DEQUEUE]);
        assert_eq!(model.borrow().state(usize::from(dci)), ENDPOINT_STOPPED);
    } else {
        assert!(controller.cancel_ticket(&ticket).is_err());
        assert!(model.borrow().active[usize::from(dci)].is_some());
    }
    assert!(controller.endpoint_poisoned(1, usize::from(dci)));
    (Rc::new(RefCell::new(controller)), ticket)
}

/// Actual high-speed class profile, with the retained original configuration.
pub(crate) fn high_speed_media_controller(
    dma: &mut dyn DmaAllocator,
    configuration: &[u8],
) -> (Controller, Rc<RefCell<CancelModel>>) {
    cancellation_controller_at_speed(dma, &[configuration.to_vec()], HIGH_SPEED)
}
