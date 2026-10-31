//! A USB4 domain in software: routers with the register behavior the
//! connection manager depends on, behind [`Transport`].
use super::{Admission, Platform, Report, Transport, Uuid, regs::*};
use crate::bus::thunderbolt::{
    channel::{self, Event},
    config::{Address, PlugEvent, Reply, Route, Space},
};
use alloc::{
    boxed::Box,
    collections::{BTreeMap, VecDeque},
    vec::Vec,
};
use std::sync::{Arc, Mutex};

extern crate std;

/// Where the routers from before USB4 have their vendor capabilities.
pub const PLUG_EVENTS: u16 = 0x60;
const VENDOR_TIME: u16 = 0x70;
pub const LINK_CONTROLLER: u16 = 0x90;
/// The lane controllers, 0x100 apart, follow the common registers.
const LANE_CONTROLLERS: u16 = 0x20;
pub const fn lane_controller(number: u8) -> u16 {
    LINK_CONTROLLER + LANE_CONTROLLERS + ((number - 1) / 2) as u16 * 0x100
}
const EEPROM_BASE: usize = 0x10;

pub const TIME: u16 = 0x10;
pub const PHY: u16 = 0x40;
pub const USB4: u16 = 0x50;
pub const ADAPTER: u16 = 0x40;
const HEADER_CAPABILITY: u16 = 0x30;

fn dword(port: u8, kind: u32, buffers: u32, hops: u32) -> [u32; 8] {
    [
        0x8086,
        u32::from(if kind == 1 { PHY } else { ADAPTER }),
        kind | 1 << 24,
        u32::from(port) << 20,
        buffers,
        hops | hops << 11,
        0,
        0,
    ]
}

/// One simulated router.
pub struct Model {
    pub upstream: u8,
    pub version: u32,
    pub header: [u32; 5],
    pub words: BTreeMap<(u8, u8, u16), u32>,
    pub links: BTreeMap<u8, u64>,
    /// What `OP_DROM_READ` and the EEPROM read.
    pub drom: Vec<u8>,
    /// Bits clocked since the chip was selected, and the command in them.
    clocked: usize,
    command: u32,
}

impl Model {
    fn get(&self, port: u8, space: Space, offset: u16) -> u32 {
        self.words
            .get(&(port, space as u8, offset))
            .copied()
            .unwrap_or(0)
    }
    fn set(&mut self, port: u8, space: Space, offset: u16, value: u32) {
        self.words.insert((port, space as u8, offset), value);
    }
    fn port_kind(&self, port: u8) -> u32 {
        self.get(port, Space::Port, 2) & 0x00ff_ffff
    }
    /// A port of `kind`, numbered `port`.
    pub fn add_port(&mut self, port: u8, kind: u32) {
        let buffers = if kind == 1 { 120 << 20 } else { 7 << 20 };
        for (offset, word) in dword(port, kind, buffers, 64).into_iter().enumerate() {
            self.set(port, Space::Port, offset as u16, word);
        }
        let first = if kind == 1 { PHY } else { ADAPTER };
        // Each capability's header word: the next offset, its id.
        match kind {
            1 => {
                // Only a USB4 port's lane 0 has the USB4 port capability.
                let next = if port % 2 == 1 && self.version != 0 {
                    USB4
                } else {
                    TIME
                };
                self.set(
                    port,
                    Space::Port,
                    USB4,
                    u32::from(TIME) | u32::from(CAP_USB4) << 8,
                );
                self.set(port, Space::Port, TIME, u32::from(CAP_TIME) << 8);
                // Dual-width capable, up and single at Gen3 once linked.
                self.set(
                    port,
                    Space::Port,
                    PHY,
                    u32::from(next) | u32::from(CAP_PHY) << 8 | 3 << 20,
                );
                self.set(port, Space::Port, PHY + 1, 4 << 16 | 1 << 20 | 1);
                self.set(port, Space::Port, USB4 + PORT_CS_18, PORT_CS_18_BE);
                self.set(port, Space::Hops, 0, 2 << HOP_INITIAL_CREDITS_SHIFT);
            }
            _ => {
                self.set(port, Space::Port, first, u32::from(CAP_ADAPTER) << 8);
            }
        }
    }
    fn plugged(&self, port: u8) -> bool {
        self.links.contains_key(&port)
    }
}

/// A router with `ports` adapters of the given kinds, in order from port 1.
pub fn router(version: u32, upstream: u8, kinds: &[u32]) -> Model {
    let mut model = Model {
        upstream,
        version,
        header: [
            0x8086 | 0x1234 << 16,
            u32::from(HEADER_CAPABILITY) | (kinds.len() as u32) << 14,
            0,
            0,
            version << 29,
        ],
        words: BTreeMap::new(),
        links: BTreeMap::new(),
        drom: Vec::new(),
        clocked: 0,
        command: 0,
    };
    for (index, kind) in kinds.iter().enumerate() {
        model.add_port(index as u8 + 1, *kind);
    }
    // The TMU capability, last of the router's.
    model.set(
        0,
        Space::Router,
        HEADER_CAPABILITY,
        u32::from(CAP_TIME) << 8,
    );
    model.set(0, Space::Router, ROUTER_CS_7, 0x1111_0000 + version);
    model.set(0, Space::Router, ROUTER_CS_7 + 1, 0x2222);
    model
}

/// A router from before USB4 of Intel's `device`, whose lanes can bond.
pub fn legacy(device: u16, upstream: u8, kinds: &[u32]) -> Model {
    let mut model = router(0, upstream, kinds);
    model.header[0] = 0x8086 | u32::from(device) << 16;
    let vendor = |next: u16, id: u32, length: u32| {
        u32::from(next) | u32::from(CAP_VENDOR) << 8 | id << 16 | length << 24
    };
    let time = u32::from(PLUG_EVENTS) | u32::from(CAP_TIME) << 8;
    model.set(0, Space::Router, HEADER_CAPABILITY, time);
    let plug_events = vendor(VENDOR_TIME, u32::from(VSE_PLUG_EVENTS), 0x10);
    model.set(0, Space::Router, PLUG_EVENTS, plug_events);
    model.set(0, Space::Router, PLUG_EVENTS + 1, PLUG_EVENTS_DISABLE);
    model.set(
        0,
        Space::Router,
        PLUG_EVENTS + EEPROM_CTL,
        EEPROM_PRESENT | EEPROM_CS,
    );
    model.set(
        0,
        Space::Router,
        PLUG_EVENTS + DROM_OFFSET,
        EEPROM_BASE as u32,
    );
    let time = vendor(LINK_CONTROLLER, u32::from(VSE_TIME), 8);
    model.set(0, Space::Router, VENDOR_TIME, time);
    let controller = vendor(0, u32::from(VSE_LINK_CONTROLLER), 8);
    model.set(0, Space::Router, LINK_CONTROLLER, controller);
    let description = 2 | u32::from(LANE_CONTROLLERS) << 8 | 0x100 << 16;
    model.set(0, Space::Router, LINK_CONTROLLER + LC_DESC, description);
    for (index, word) in [0xa1a2, 0xb1b2, 0xc1c2, 0xd1d2].into_iter().enumerate() {
        model.set(
            0,
            Space::Router,
            LINK_CONTROLLER + LC_FUSE + index as u16,
            word,
        );
    }
    for number in [1, 3] {
        let attributes = lane_controller(number) + LC_PORT_ATTR;
        model.set(0, Space::Router, attributes, LC_PORT_ATTR_BE);
    }
    model
}

pub const LANE: u32 = 1;
pub const DP_IN: u32 = 0x0e_0101;
pub const DP_OUT: u32 = 0x0e_0102;
pub const PCIE_DOWN: u32 = 0x10_0101;
pub const PCIE_UP: u32 = 0x10_0102;
pub const USB3_DOWN: u32 = 0x20_0101;
pub const USB3_UP: u32 = 0x20_0102;

/// A read's port and words, or an error code.
type Outcome = Result<(u8, Vec<u32>), u8>;

#[derive(Default)]
pub struct State {
    pub now: u64,
    pub routers: BTreeMap<u64, Model>,
    pub events: VecDeque<Event>,
    pending: Option<(u64, Outcome)>,
    next: u64,
    /// Requests that get no reply while `Some`, from this route on.
    pub silent: Option<u64>,
    /// Writes in order: route, port, space, offset, value.
    pub writes: Vec<(u64, u8, u8, u16, u32)>,
    pub reports: Vec<Report>,
    pub admitted: bool,
}

impl State {
    /// Attach `model` at `route`; its parent's lanes see it.
    pub fn connect(&mut self, route: u64, model: Model) {
        self.routers.insert(route, model);
        if route != 0 {
            let level = super::depth(route);
            let (above, port) = (super::parent(route), super::port_at(route, level - 1));
            let parent = self.routers.get_mut(&above).unwrap();
            parent.links.insert(port, route);
            parent.links.insert(port + 1, route);
        }
    }
    /// A plug or unplug event from `route`'s `port`.
    pub fn event(&mut self, route: u64, port: u8, unplug: bool) {
        self.events.push_back(Event::Plug(PlugEvent {
            route: Route::new(route).unwrap(),
            port,
            unplug,
            header_flags: 0,
        }));
    }
    /// Pull the cable at `route`.
    pub fn disconnect(&mut self, route: u64) {
        let level = super::depth(route);
        let (above, port) = (super::parent(route), super::port_at(route, level - 1));
        let parent = self.routers.get_mut(&above).unwrap();
        parent.links.remove(&port);
        parent.links.remove(&(port + 1));
        let gone: Vec<u64> = self
            .routers
            .keys()
            .copied()
            .filter(|candidate| super::beneath(*candidate, route))
            .collect();
        for route in gone {
            self.routers.remove(&route);
        }
        self.event(above, port, true);
    }
    pub fn word(&self, route: u64, port: u8, space: Space, offset: u16) -> u32 {
        self.routers[&route].get(port, space, offset)
    }
    fn reachable(&self, route: u64) -> bool {
        self.routers.contains_key(&route)
    }

    /// Reads, with the status bits a real router computes.
    fn load(&mut self, route: u64, address: Address) -> Vec<u32> {
        let model = self.routers.get_mut(&route).unwrap();
        let mut data = Vec::new();
        for index in 0..u16::from(address.words) {
            let offset = address.offset + index;
            let word = match address.space {
                Space::Router if offset < 5 => model.header[usize::from(offset)],
                space => model.get(address.port, space, offset),
            };
            data.push(word);
        }
        // Lanes report a link state in the PHY's second word.
        if address.space == Space::Port
            && model.port_kind(address.port) == LANE
            && address.offset == PHY
            && address.words == 2
        {
            let state = if model.plugged(address.port) { 2 } else { 7 };
            data[1] |= state << 26;
        }
        data
    }

    /// Writes, with the side effects a real router has.
    fn store(&mut self, route: u64, address: Address, data: &[u32]) {
        for (index, word) in data.iter().enumerate() {
            let offset = address.offset + index as u16;
            self.writes
                .push((route, address.port, address.space as u8, offset, *word));
            let model = self.routers.get_mut(&route).unwrap();
            match address.space {
                Space::Router if offset < 5 => model.header[usize::from(offset)] = *word,
                space => model.set(address.port, space, offset, *word),
            }
            self.react(route, address, offset, *word);
        }
    }

    fn bond(&mut self, route: u64, lane: u8) {
        let model = self.routers.get_mut(&route).unwrap();
        for lane in [lane, lane + 1] {
            let phy = model.get(lane, Space::Port, PHY + 1);
            let dual = (phy & !(63 << 20)) | WIDTH_DUAL << 20;
            model.set(lane, Space::Port, PHY + 1, dual);
        }
    }

    fn react(&mut self, route: u64, address: Address, offset: u16, word: u32) {
        let port = address.port;
        let model = self.routers.get_mut(&route).unwrap();
        match (address.space, offset) {
            (Space::Router, ROUTER_CS_5) => {
                let status = model.get(0, Space::Router, ROUTER_CS_6);
                let ready = ROUTER_CS_6_RR
                    | if word & ROUTER_CS_5_CV != 0 {
                        ROUTER_CS_6_CR
                    } else {
                        0
                    };
                model.set(0, Space::Router, ROUTER_CS_6, status | ready);
            }
            (Space::Router, ROUTER_CS_26)
                if word & ROUTER_CS_26_OV != 0 && word as u16 != OP_DROM_READ =>
            {
                if word as u16 == OP_BUFFER_ALLOC {
                    let table: [(u32, u32); 5] = [
                        (u32::from(BA_MAX_USB3), 14),
                        (u32::from(BA_MIN_DP_AUX), 1),
                        (u32::from(BA_MIN_DP_MAIN), 6),
                        (u32::from(BA_MAX_PCIE), 32),
                        (u32::from(BA_MAX_HI), 14),
                    ];
                    for (index, (id, value)) in table.into_iter().enumerate() {
                        model.set(
                            0,
                            Space::Router,
                            ROUTER_CS_9 + index as u16,
                            id | value << 16,
                        );
                    }
                    model.set(0, Space::Router, ROUTER_CS_25, table.len() as u32);
                }
                model.set(0, Space::Router, ROUTER_CS_26, word & !ROUTER_CS_26_OV);
            }
            (Space::Router, ROUTER_CS_26)
                if word & ROUTER_CS_26_OV != 0 && word as u16 == OP_DROM_READ =>
            {
                let metadata = model.get(0, Space::Router, ROUTER_CS_25);
                if model.drom.is_empty() {
                    model.set(0, Space::Router, ROUTER_CS_26, ROUTER_CS_26_ONS);
                    return;
                }
                let address = ((metadata >> DROM_ADDRESS_SHIFT) & 0x1fff) as usize * 4;
                let words = (metadata >> DROM_SIZE_SHIFT) as usize & 31;
                for index in 0..words {
                    let mut bytes = [0; 4];
                    for (at, byte) in bytes.iter_mut().enumerate() {
                        let source = address + index * 4 + at;
                        *byte = model.drom.get(source).copied().unwrap_or(0);
                    }
                    let value = u32::from_le_bytes(bytes);
                    model.set(0, Space::Router, ROUTER_CS_9 + index as u16, value);
                }
                model.set(0, Space::Router, ROUTER_CS_26, word & !ROUTER_CS_26_OV);
            }
            (Space::Router, _) if offset == TIME_POST + 1 && word == 0 => {
                model.set(0, Space::Router, TIME_POST, 0);
            }
            (Space::Router, _) if offset == PLUG_EVENTS + EEPROM_CTL && model.version == 0 => {
                if word & EEPROM_CS != 0 {
                    (model.clocked, model.command) = (0, 0);
                } else if word & EEPROM_SK != 0 {
                    let bit = model.clocked;
                    model.clocked += 1;
                    if bit < 24 {
                        model.command = model.command << 1 | u32::from(word & EEPROM_DI != 0);
                    } else {
                        let address = (model.command & 0xffff) as usize + (bit - 24) / 8;
                        let byte = address
                            .checked_sub(EEPROM_BASE)
                            .and_then(|at| model.drom.get(at).copied())
                            .unwrap_or(0xff);
                        let high = byte >> (7 - (bit - 24) % 8) & 1 != 0;
                        let word = if high {
                            word | EEPROM_DO
                        } else {
                            word & !EEPROM_DO
                        };
                        model.set(0, Space::Router, offset, word);
                    }
                }
            }
            (Space::Hops, _) => {
                let hop = offset & !1;
                let first = model.get(port, Space::Hops, hop);
                if first & HOP_ENABLE == 0 {
                    let second = model.get(port, Space::Hops, hop + 1);
                    model.set(port, Space::Hops, hop + 1, second & !HOP_PENDING);
                }
            }
            (Space::Port, _) => {
                let kind = model.port_kind(port);
                if kind == LANE && offset == PHY + LANE_ADP_CS_1 && word & LANE_ADP_CS_1_LB != 0 {
                    // Both ends of a link bond together.
                    let child = model.links[&port];
                    let up = self.routers[&child].upstream;
                    for (route, lane) in [(route, port), (child, up)] {
                        self.bond(route, lane);
                    }
                    return;
                }
                if kind == LANE
                    && offset == USB4 + PORT_CS_19
                    && word & PORT_CS_19_DPR == 0
                    && model.plugged(port)
                    && model.get(port, Space::Port, ADP_CS_5 + 0x100) == 0
                {
                    // A released port reset trains the link again.
                    model.set(port, Space::Port, ADP_CS_5 + 0x100, 1);
                    self.event(route, port, false);
                    return;
                }
                if matches!(kind, USB3_DOWN) && offset == ADAPTER + ADP_USB3_CS_2 {
                    let current = model.get(port, Space::Port, ADAPTER + ADP_USB3_CS_1);
                    let acknowledged = if word & ADP_USB3_CS_2_CMR != 0 {
                        current | ADP_USB3_CS_1_HCA
                    } else {
                        current & !ADP_USB3_CS_1_HCA
                    };
                    model.set(port, Space::Port, ADAPTER + ADP_USB3_CS_1, acknowledged);
                }
                if kind == DP_OUT && offset == ADAPTER + DP_STATUS_CTRL {
                    model.set(port, Space::Port, offset, word & !DP_STATUS_CTRL_CMHS);
                }
            }
            _ => {}
        }
    }
}

const TIME_POST: u16 = HEADER_CAPABILITY + TMU_RTR_CS_24;

/// The shared handle a test keeps on the fabric.
#[derive(Clone)]
pub struct Fabric(pub Arc<Mutex<State>>);

impl Fabric {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(State {
            admitted: true,
            ..State::default()
        })))
    }
    pub fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.0.lock().unwrap()
    }
    pub fn manager(&self) -> super::Manager {
        super::Manager::new(Box::new(Link(self.clone())), Box::new(Host(self.clone())))
    }
    pub fn tunnels_up(&self, protocol: super::Protocol) -> usize {
        self.lock()
            .reports
            .iter()
            .filter(|report| {
                matches!(report, Report::TunnelUp { protocol: found, .. } if found == &protocol)
            })
            .count()
    }
}

struct Link(Fabric);
struct Host(Fabric);

impl Link {
    fn submit(
        &mut self,
        route: Route,
        address: Address,
        data: Option<&[u32]>,
    ) -> Result<u64, channel::Error> {
        let mut state = self.0.lock();
        if state.pending.is_some() {
            return Err(channel::Error::Busy);
        }
        state.next += 1;
        let id = state.next;
        let raw = route.raw();
        if state
            .silent
            .is_some_and(|silent| super::beneath(raw, silent))
        {
            state.pending = Some((id, Err(0xff)));
            return Ok(id);
        }
        let outcome = if !state.reachable(raw) {
            Err(0)
        } else {
            let upstream = state.routers[&raw].upstream;
            match data {
                Some(data) => {
                    state.store(raw, address, data);
                    Ok((upstream, Vec::new()))
                }
                None => Ok((upstream, state.load(raw, address))),
            }
        };
        state.pending = Some((id, outcome));
        Ok(id)
    }
}

impl Transport for Link {
    fn read(
        &mut self,
        route: Route,
        address: Address,
        _: u64,
        _: u64,
    ) -> Result<u64, channel::Error> {
        self.submit(route, address, None)
    }
    fn write(
        &mut self,
        route: Route,
        address: Address,
        data: &[u32],
        _: u64,
        _: u64,
    ) -> Result<u64, channel::Error> {
        self.submit(route, address, Some(data))
    }
    fn poll(&mut self, _: u64) -> Result<Option<Event>, channel::Error> {
        let mut state = self.0.lock();
        if let Some(event) = state.events.pop_front() {
            return Ok(Some(event));
        }
        Ok(state
            .pending
            .take()
            .map(|(request, outcome)| match outcome {
                Ok((upstream_port, data)) => Event::Completed {
                    request,
                    reply: Reply::Configuration {
                        upstream_port,
                        data,
                    },
                },
                Err(0xff) => Event::TimedOut { request },
                Err(code) => Event::Completed {
                    request,
                    reply: Reply::ControllerError {
                        route: Route::new(0).unwrap(),
                        port: 0,
                        code,
                        packet_group: 0,
                        raw: u32::from(code),
                    },
                },
            }))
    }
}

impl Platform for Host {
    fn now_ms(&self) -> u64 {
        self.0.lock().now
    }
    fn report(&mut self, report: Report) {
        self.0.lock().reports.push(report);
    }
    fn admit_pcie(&self, _: Uuid) -> Admission {
        if self.0.lock().admitted {
            Admission::Isolated
        } else {
            Admission::Refused
        }
    }
}
