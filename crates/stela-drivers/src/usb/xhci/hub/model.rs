//! Native controller fixture: consumes actual command/context/EP0/normal TRBs.
use super::*;
use alloc::collections::{BTreeMap, VecDeque};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Fault {
    None,
    Power,
    PowerAbsent,
    Reset,
    ResetForever,
    Disconnect,
    NoEnable,
    Suspended,
    UnknownSpeed,
    HotThenWarm,
    Inactive,
    WarmForever,
    ShortStatus,
    ClearChange,
    LinkNotU0,
    ConfigError,
    ConnectionChange,
    ResetConnectionBounce,
    FirstResetDisabled,
    FirstResetNotU0,
    OverCurrentChange,
    NoResetChange,
}
#[derive(Clone)]
pub(super) struct PortModel {
    pub fault: Fault,
    pub child_speed: u8,
    pub status: u16,
    pub change: u16,
    pub extended: u32,
    pub connection_samples: VecDeque<(bool, bool)>,
    pub reset_count: usize,
    pending: VecDeque<(u16, u16)>,
}
impl PortModel {
    pub fn connected() -> Self {
        Self {
            fault: Fault::None,
            child_speed: SUPER_SPEED,
            status: 3,
            change: 1,
            extended: 0x11,
            connection_samples: VecDeque::new(),
            reset_count: 0,
            pending: VecDeque::new(),
        }
    }
}
#[derive(Clone)]
pub(super) struct Node {
    pub speed: u8,
    pub ports: Option<Vec<PortModel>>,
    pub bos: Option<Vec<u8>>,
    pub descriptor: Option<Vec<u8>>,
    pub configured: bool,
    pub depth: Option<u16>,
    pub self_powered: bool,
    pub unconfigured_self_powered: Option<bool>,
    pub max_power: u8,
    pub controller_current: u8,
    pub hub_status: u16,
    pub hub_change: u16,
    pub after_power_status: Option<u16>,
}
impl Node {
    pub fn hub(speed: u8, ports: usize) -> Self {
        Self {
            speed,
            ports: Some(vec![PortModel::connected(); ports]),
            bos: None,
            descriptor: None,
            configured: false,
            depth: None,
            self_powered: true,
            unconfigured_self_powered: None,
            max_power: 0,
            controller_current: 0,
            hub_status: 0,
            hub_change: 0,
            after_power_status: None,
        }
    }
    pub fn leaf(speed: u8) -> Self {
        Self {
            speed,
            ports: None,
            bos: None,
            descriptor: None,
            configured: false,
            depth: None,
            self_powered: true,
            unconfigured_self_powered: None,
            max_power: 0,
            controller_current: 0,
            hub_status: 0,
            hub_change: 0,
            after_power_status: None,
        }
    }
    fn device(&self) -> Vec<u8> {
        let mut out = vec![
            18, 1, 0, 3, 0, 0, 0, 9, 0x34, 0x12, 0x78, 0x56, 0, 1, 0, 0, 0, 1,
        ];
        if self.ports.is_some() {
            out[4] = HUB_CLASS;
            out[6] = if self.speed >= SUPER_SPEED { 3 } else { 1 };
        }
        if self.speed < SUPER_SPEED {
            out[2..4].copy_from_slice(&0x0200u16.to_le_bytes());
            out[7] = 64;
        }
        if self.bos.is_some() {
            out[2..4].copy_from_slice(&0x0310u16.to_le_bytes());
        }
        out
    }
    pub fn configuration(&self) -> Vec<u8> {
        let hub = self.ports.is_some();
        let mut out = vec![
            9,
            2,
            0,
            0,
            1,
            1,
            0,
            0x80 | if self.self_powered { 0x40 } else { 0 },
            self.max_power,
            9,
            4,
            0,
            0,
            if hub { 1 } else { 2 },
            if hub { 9 } else { 8 },
            if hub { 0 } else { 6 },
            if hub { 0 } else { 0x50 },
            0,
        ];
        if hub {
            out.extend_from_slice(&[7, 5, 0x81, 3, 2, 0, 8]);
            if self.speed >= SUPER_SPEED {
                out.extend_from_slice(&[6, 0x30, 0, 0, 2, 0]);
            }
        } else {
            for address in [0x81, 2] {
                let packet = if self.speed >= SUPER_SPEED {
                    1024u16
                } else if self.speed == HIGH_SPEED {
                    512u16
                } else {
                    64u16
                };
                out.extend_from_slice(&[7, 5, address, 2, packet as u8, (packet >> 8) as u8, 0]);
                if self.speed >= SUPER_SPEED {
                    out.extend_from_slice(&[6, 0x30, 0, 0, 0, 0]);
                }
            }
        }
        let length = out.len() as u16;
        out[2..4].copy_from_slice(&length.to_le_bytes());
        out
    }
    fn hub_descriptor(&self) -> Vec<u8> {
        self.descriptor.clone().unwrap_or_else(|| {
            if self.speed >= SUPER_SPEED {
                vec![
                    12,
                    0x2a,
                    self.ports.as_ref().unwrap().len() as u8,
                    1,
                    0,
                    1,
                    self.controller_current,
                    0,
                    0,
                    0,
                    0,
                    0,
                ]
            } else {
                vec![
                    9,
                    0x29,
                    self.ports.as_ref().unwrap().len() as u8,
                    0x61,
                    0,
                    1,
                    self.controller_current,
                    0,
                    0xff,
                ]
            }
        })
    }
}

struct Cursor {
    at: u64,
    cycle: u32,
}
impl Cursor {
    fn new(pointer: u64) -> Self {
        Self {
            at: pointer & !0xf,
            cycle: pointer as u32 & 1,
        }
    }
    fn next(&mut self) -> (u64, u64, u32, u32) {
        let mut at = self.at;
        let mut control = read32(at + 12);
        if control >> 10 & 0x3f == LINK {
            assert_eq!(control & CYCLE, self.cycle);
            self.at = read64(at) & !0xf;
            if control & TOGGLE != 0 {
                self.cycle ^= 1;
            }
            at = self.at;
            control = read32(at + 12);
        }
        assert_eq!(
            control & CYCLE,
            self.cycle,
            "controller consumed unpublished TRB"
        );
        self.at += 16;
        (at, read64(at), read32(at + 8), control)
    }
}
fn read32(at: u64) -> u32 {
    assert!(
        at >= 65536 && at.is_multiple_of(4),
        "invalid fixture DMA word {at:#x}"
    );
    // SAFETY: caller uses only retained actual fixture DMA fields.
    unsafe { (at as *const u32).read_volatile() }
}
fn read64(at: u64) -> u64 {
    assert!(
        at >= 65536 && at.is_multiple_of(8),
        "invalid fixture DMA pointer {at:#x}"
    );
    // SAFETY: caller uses only retained actual fixture DMA fields.
    unsafe { (at as *const u64).read_volatile() }
}
fn write32(at: u64, value: u32) {
    // SAFETY: caller has the fixture's device-side ownership of this DMA.
    unsafe { (at as *mut u32).write_volatile(value) }
}
pub(super) struct Hardware {
    pub nodes: BTreeMap<u32, Node>,
    pub requests: Vec<(u8, u32, [u8; 8])>,
    pub contexts: Vec<(u8, u32, [u32; 4])>,
    pub commands: Vec<(u32, u8)>,
    pub fail: Option<(u32, u8)>,
    pub silent: Option<(u32, u8)>,
    pub outgoing: Vec<Vec<u8>>,
    pub loss_after_child_route: Option<u32>,
    pub silent_configuration: Option<u8>,
    pub failed_configuration: Option<u8>,
    pub root_status: Option<u32>,
    pub mmio_reads: usize,
    pub mmio_writes: usize,
    registers: BTreeMap<usize, u32>,
    running: bool,
    context_bytes: usize,
    command: Option<Cursor>,
    endpoints: BTreeMap<(u8, u8), Cursor>,
    outputs: BTreeMap<u8, u64>,
    routes: BTreeMap<u8, u32>,
    event_base: u64,
    events: usize,
    next_slot: u8,
}
impl Hardware {
    pub fn new(context_bytes: usize, nodes: BTreeMap<u32, Node>) -> Self {
        Self {
            nodes,
            requests: Vec::new(),
            contexts: Vec::new(),
            commands: Vec::new(),
            fail: None,
            silent: None,
            outgoing: Vec::new(),
            loss_after_child_route: None,
            silent_configuration: None,
            failed_configuration: None,
            root_status: None,
            mmio_reads: 0,
            mmio_writes: 0,
            registers: BTreeMap::new(),
            running: false,
            context_bytes,
            command: None,
            endpoints: BTreeMap::new(),
            outputs: BTreeMap::new(),
            routes: BTreeMap::new(),
            event_base: 0,
            events: 0,
            next_slot: 1,
        }
    }
    fn register64(&self, at: usize) -> u64 {
        u64::from(*self.registers.get(&at).unwrap_or(&0))
            | u64::from(*self.registers.get(&(at + 4)).unwrap_or(&0)) << 32
    }
    fn event(&mut self, parameter: u64, code: u32, kind: u32, slot: u8, dci: u8, residual: usize) {
        let at = self.event_base + ((self.events % RING_TRBS) * TRB) as u64;
        // SAFETY: event_base came from the published actual ERST allocation.
        unsafe {
            (at as *mut u64).write_volatile(parameter);
        }
        write32(at + 8, code << 24 | residual as u32);
        write32(
            at + 12,
            u32::from(slot) << 24
                | u32::from(dci) << 16
                | kind << 10
                | u32::from((self.events / RING_TRBS).is_multiple_of(2)),
        );
        self.events += 1;
    }
    fn command(&mut self) {
        let (at, parameter, _, control) = self.command.as_mut().unwrap().next();
        let kind = control >> 10 & 0x3f;
        let mut slot = (control >> 24) as u8;
        let dci = (control >> 16 & 31) as u8;
        self.commands.push((kind, slot));
        if self.silent == Some((kind, slot)) {
            return;
        }
        let code = if self.fail == Some((kind, slot)) {
            11
        } else {
            SUCCESS
        };
        if code == SUCCESS {
            match kind {
                ENABLE_SLOT => {
                    slot = self.next_slot;
                    self.next_slot += 1;
                }
                ADDRESS_DEVICE | CONFIGURE_ENDPOINT | EVALUATE_CONTEXT => {
                    let output = read64(self.register64(0x40 + DCBAAP) + u64::from(slot) * 8);
                    self.outputs.insert(slot, output);
                    let add = read32(parameter + 4);
                    if kind == CONFIGURE_ENDPOINT {
                        let drop = read32(parameter);
                        for dci in 2..32 {
                            if drop & (1 << dci) != 0 {
                                self.endpoints.remove(&(slot, dci as u8));
                                write32(output + (dci * self.context_bytes) as u64, 0);
                            }
                        }
                    }
                    for dci in 0..32 {
                        if add & (1 << dci) == 0 {
                            continue;
                        }
                        let input = parameter + ((dci + 1) * self.context_bytes) as u64;
                        let target = output + (dci * self.context_bytes) as u64;
                        if kind == EVALUATE_CONTEXT && dci > 0 {
                            // Evaluate EP0 changes max packet only; unlike
                            // Configure it does not replace a dequeue pointer.
                            write32(target + 4, read32(input + 4));
                            continue;
                        }
                        // SAFETY: copied complete retained xHCI contexts are disjoint.
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                input as *const u8,
                                target as *mut u8,
                                self.context_bytes,
                            );
                        }
                        if dci > 0 {
                            write32(target, read32(target) & !7 | ENDPOINT_RUNNING);
                            self.endpoints
                                .insert((slot, dci as u8), Cursor::new(read64(target + 8)));
                        }
                    }
                    let words = [
                        read32(output),
                        read32(output + 4),
                        read32(output + 8),
                        read32(output + 12),
                    ];
                    let route = words[0] & 0xfffff;
                    self.routes.insert(slot, route);
                    self.contexts.push((slot, kind, words));
                    if kind == ADDRESS_DEVICE && self.loss_after_child_route == Some(route) {
                        self.nodes.get_mut(&0).unwrap().hub_status = 1;
                    }
                }
                STOP_ENDPOINT | RESET_ENDPOINT => {
                    let output = self.outputs[&slot] + u64::from(dci) * self.context_bytes as u64;
                    write32(output, read32(output) & !7 | ENDPOINT_STOPPED);
                }
                SET_DEQUEUE => {
                    self.endpoints.insert((slot, dci), Cursor::new(parameter));
                }
                _ => panic!("unexpected native hub command {kind}"),
            }
        }
        self.event(at, code, COMMAND_COMPLETION, slot, 0, 0);
    }
    fn request(&mut self, slot: u8, request: [u8; 8]) -> Result<Vec<u8>, u32> {
        let route = self.routes[&slot];
        self.requests.push((slot, route, request));
        let node = self
            .nodes
            .get_mut(&route)
            .expect("no fixture at published child route");
        let value = u16::from_le_bytes([request[2], request[3]]);
        let index = u16::from_le_bytes([request[4], request[5]]);
        match (request[0], request[1]) {
            (0x80, GET_STATUS) => Ok(vec![
                u8::from(if node.configured {
                    node.self_powered
                } else {
                    node.unconfigured_self_powered.unwrap_or(node.self_powered)
                }),
                0,
            ]),
            (0xa0, GET_STATUS) => {
                assert!(node.configured);
                let powered = node
                    .ports
                    .as_ref()
                    .unwrap()
                    .iter()
                    .all(|port| port.status & 1 << 9 != 0);
                let status = if powered {
                    node.after_power_status.unwrap_or(node.hub_status)
                } else {
                    node.hub_status
                };
                let mut bytes = Vec::new();
                bytes.extend_from_slice(&status.to_le_bytes());
                bytes.extend_from_slice(&node.hub_change.to_le_bytes());
                Ok(bytes)
            }
            (0x20, CLEAR_FEATURE) => {
                assert_eq!(value, 0);
                node.hub_change &= !1;
                Ok(Vec::new())
            }
            (0x80, GET_DESCRIPTOR) => match (value >> 8) as u8 {
                DEVICE_DESCRIPTOR => Ok(node.device()),
                CONFIGURATION_DESCRIPTOR => Ok(node.configuration()),
                15 => Ok(node.bos.clone().unwrap_or_else(|| vec![5, 15, 5, 0, 0])),
                _ => Err(6),
            },
            (0xa0, GET_DESCRIPTOR) => {
                assert_eq!(
                    value >> 8,
                    if node.speed >= SUPER_SPEED {
                        0x2a
                    } else {
                        0x29
                    }
                );
                Ok(node.hub_descriptor())
            }
            (0, SET_CONFIGURATION) => {
                assert!(value <= 1);
                if self.failed_configuration == Some(slot) {
                    return Err(6);
                }
                node.configured = value != 0;
                Ok(Vec::new())
            }
            (0x20, 12) => {
                assert!(node.configured);
                assert_eq!(
                    value,
                    (0..5).filter(|tier| route >> (tier * 4) & 15 != 0).count() as u16
                );
                node.depth = Some(value);
                Ok(Vec::new())
            }
            (0x23, SET_FEATURE | CLEAR_FEATURE) | (0xa3, GET_STATUS) => {
                let ss = node.speed >= SUPER_SPEED;
                let configured = node.configured;
                let depth = node.depth;
                let port = &mut node.ports.as_mut().unwrap()[usize::from(index) - 1];
                match (request[0], request[1]) {
                    (0x23, SET_FEATURE) if value == PORT_POWER => {
                        assert!(configured);
                        if ss {
                            assert!(depth.is_some());
                        }
                        if port.fault == Fault::Power {
                            return Err(6);
                        }
                        if port.fault != Fault::PowerAbsent {
                            port.status |= if ss { 1 << 9 } else { 1 << 8 };
                        }
                    }
                    (0x23, SET_FEATURE) if value == PORT_RESET || value == 28 => {
                        assert!(configured);
                        if ss {
                            assert!(depth.is_some());
                        }
                        assert!(
                            port.connection_samples.is_empty(),
                            "reset before connection settled"
                        );
                        if port.fault == Fault::Reset {
                            return Err(6);
                        }
                        let power = if ss { 1 << 9 } else { 1 << 8 };
                        assert_ne!(port.status & power, 0);
                        if ss && matches!(port.status & 0x1e0, 0xc0 | 0x140) {
                            assert_eq!(value, 28);
                        }
                        port.reset_count += 1;
                        let mut change = if value == 28 { 1 << 5 } else { 1 << 4 };
                        port.status = (port.status | 1 << 4) & !2;
                        let mut status = power | 3;
                        if !ss {
                            status |= match port.child_speed {
                                LOW_SPEED => 1 << 9,
                                HIGH_SPEED => 1 << 10,
                                _ => 0,
                            };
                        }
                        match port.fault {
                            Fault::ResetForever => status |= 1 << 4,
                            Fault::Disconnect => status = power,
                            Fault::NoEnable => status &= !2,
                            Fault::FirstResetDisabled if port.reset_count == 1 => status &= !2,
                            Fault::FirstResetNotU0 if port.reset_count == 1 => status |= 5 << 5,
                            Fault::HotThenWarm if value == PORT_RESET => status |= 0xc0,
                            Fault::WarmForever => status |= 0x140,
                            Fault::LinkNotU0 => status |= 1 << 5,
                            Fault::ConfigError => change |= 1 << 7,
                            Fault::ConnectionChange => change |= 1,
                            Fault::OverCurrentChange => change |= 1 << 3,
                            Fault::NoResetChange => change = 0,
                            _ => {}
                        }
                        if port.fault == Fault::ResetConnectionBounce {
                            port.pending.push_back((power | 1 << 4, 0));
                            port.pending.push_back((power, change | 1));
                            change |= 1;
                        }
                        port.pending.push_back((status, change));
                    }
                    (0x23, CLEAR_FEATURE) => {
                        if port.fault == Fault::ClearChange {
                            return Err(6);
                        }
                        let bit = match value {
                            16 => 1,
                            19 => 1 << 3,
                            20 => 1 << 4,
                            29 if ss => 1 << 5,
                            25 if ss => 1 << 6,
                            26 if ss => 1 << 7,
                            _ => panic!("USB2/reserved change selector used on SS port {value}"),
                        };
                        port.change &= !bit;
                    }
                    (0xa3, GET_STATUS) => {
                        if let Some((connected, changed)) = port.connection_samples.pop_front() {
                            port.status = (port.status & !1) | u16::from(connected);
                            port.change |= u16::from(changed);
                        }
                        if let Some((status, change)) = port.pending.pop_front() {
                            port.status = status;
                            port.change |= change;
                        }
                        let mut bytes = Vec::new();
                        bytes.extend_from_slice(&port.status.to_le_bytes());
                        bytes.extend_from_slice(&port.change.to_le_bytes());
                        if value == 2 {
                            bytes.extend_from_slice(&port.extended.to_le_bytes());
                        }
                        if port.fault == Fault::ShortStatus {
                            bytes.pop();
                        }
                        return Ok(bytes);
                    }
                    _ => panic!("unexpected hub request {request:?}"),
                }
                Ok(Vec::new())
            }
            _ => Err(6),
        }
    }
    fn transfer(&mut self, slot: u8, dci: u8) {
        if dci == 1 {
            let cursor = self.endpoints.get_mut(&(slot, dci)).unwrap();
            let (_, parameter, _, setup_control) = cursor.next();
            assert_eq!(setup_control >> 10 & 0x3f, SETUP);
            let request = parameter.to_le_bytes();
            let requested = usize::from(u16::from_le_bytes([request[6], request[7]]));
            let mut data = None;
            if requested > 0 {
                let td = cursor.next();
                assert_eq!(td.3 >> 10 & 0x3f, DATA);
                data = Some(td);
            }
            let (status, _, _, control) = cursor.next();
            assert_eq!(control >> 10 & 0x3f, STATUS);
            match self.request(slot, request) {
                Ok(mut reply) => {
                    if request[0] == 0
                        && request[1] == SET_CONFIGURATION
                        && self.silent_configuration == Some(slot)
                    {
                        return;
                    }
                    if let Some((address, buffer, length, _)) = data {
                        reply.truncate(requested);
                        assert_eq!(length as usize, requested);
                        // SAFETY: DATA TRB gives this device-side live DMA range.
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                reply.as_ptr(),
                                buffer as *mut u8,
                                reply.len(),
                            );
                        }
                        if reply.len() < requested {
                            self.event(
                                address,
                                SHORT_PACKET,
                                TRANSFER_EVENT,
                                slot,
                                dci,
                                requested - reply.len(),
                            );
                        }
                    }
                    self.event(status, SUCCESS, TRANSFER_EVENT, slot, dci, 0);
                }
                Err(code) => {
                    let output = self.outputs[&slot] + u64::from(dci) * self.context_bytes as u64;
                    write32(output, read32(output) & !7 | ENDPOINT_HALTED);
                    self.event(status, code, TRANSFER_EVENT, slot, dci, 0);
                }
            }
        } else {
            let (trb, buffer, length, control) =
                self.endpoints.get_mut(&(slot, dci)).unwrap().next();
            assert_eq!(control >> 10 & 0x3f, NORMAL);
            if dci & 1 != 0 {
                // SAFETY: actual published IN payload belongs to this fixture.
                unsafe {
                    core::ptr::write_bytes(buffer as *mut u8, slot, length as usize);
                }
            } else {
                // SAFETY: actual published OUT payload belongs to this fixture.
                self.outgoing.push(
                    unsafe { core::slice::from_raw_parts(buffer as *const u8, length as usize) }
                        .to_vec(),
                );
            }
            self.event(trb, SUCCESS, TRANSFER_EVENT, slot, dci, 0);
        }
    }
}
pub(super) struct RegistersModel(pub Rc<RefCell<Hardware>>);
impl Registers for RegistersModel {
    fn read32(&mut self, at: usize) -> u32 {
        let mut state = self.0.borrow_mut();
        state.mmio_reads += 1;
        match at {
            0 => 0x0110_0040,
            HCSPARAMS1 => 1 << 24 | 32,
            HCCPARAMS1 => 1 | 0x20 << 16 | if state.context_bytes == 64 { 4 } else { 0 },
            DBOFF => 0x1000,
            RTSOFF => 0x800,
            0x40 => {
                if state.running {
                    RUN
                } else {
                    0
                }
            }
            0x44 => {
                if state.running {
                    0
                } else {
                    HCH
                }
            }
            0x48 => 1,
            0x80 => {
                (if state.nodes[&0].speed >= SUPER_SPEED {
                    3
                } else {
                    2
                }) << 24
                    | SUPPORTED_PROTOCOL
            }
            0x88 => 1 | 1 << 8,
            0x440 => state
                .root_status
                .unwrap_or(PP | CCS | PED | PRC | u32::from(state.nodes[&0].speed) << 10),
            _ => *state.registers.get(&at).unwrap_or(&0),
        }
    }
    fn write32(&mut self, at: usize, value: u32) {
        let mut state = self.0.borrow_mut();
        state.mmio_writes += 1;
        state.registers.insert(at, value);
        if at == 0x40 {
            state.running = value & RUN != 0;
            if state.running {
                state.command = Some(Cursor::new(state.register64(0x40 + CRCR)));
                state.event_base = read64(state.register64(0x800 + ERSTBA));
            }
        }
        if at == 0x1000 {
            state.command();
        } else if (0x1004..0x1084).contains(&at) {
            state.transfer(((at - 0x1000) / 4) as u8, (value & 255) as u8);
        }
    }
}
