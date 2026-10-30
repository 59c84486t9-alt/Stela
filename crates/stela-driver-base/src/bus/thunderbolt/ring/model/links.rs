//! Modeled link reservations, fixtures and the peer answering link bring-up.

use super::*;

pub(crate) struct LinkReservation {
    pub(crate) partners: super::super::super::link::Partners,
    pub(crate) dropped: Arc<AtomicUsize>,
}

impl Drop for LinkReservation {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

// SAFETY: fixture owns reciprocal model lanes and both routers in
// this same synthetic NHI reset/topology epoch. No production topology,
// policy, power or attachment provider is invented by the driver.
unsafe impl super::super::super::link::Reservation for LinkReservation {
    fn observed(&self) -> super::super::super::link::Partners {
        self.partners
    }
}

pub(crate) struct LinkFixture {
    pub(crate) _source: Source,
    pub(crate) domain: Arc<Domain>,
    pub(crate) model: Arc<Model>,
    pub(crate) channel: super::super::super::channel::Channel<Model>,
    pub(crate) parent: super::super::super::router::Configured,
    pub(crate) child: super::super::super::router::Configured,
    pub(crate) reservation: Arc<LinkReservation>,
    pub(crate) cursor: NativeCursor,
    pub(crate) dropped: [Arc<AtomicUsize>; 3],
}

pub(crate) fn link_inventory(owner: &mut RouterOwner, max: u8, primary: u8) {
    use super::super::super::topology::{AdapterObservation, Capability};
    owner.target.header.raw[1] =
        (owner.target.header.raw[1] & !(63 << 14)) | (u32::from(max) << 14);
    owner.target.adapters = (1..=max)
        .map(|port| {
            let mut adapter =
                router_adapter(port, 1, if port == primary { Some(0x30) } else { None });
            if let AdapterObservation::Present { capabilities, .. } = &mut adapter {
                capabilities.insert(
                    0,
                    Capability {
                        offset: 8,
                        id: 1,
                        vendor_specific: None,
                        length: None,
                        next: if port == primary { 0x30 } else { 0 },
                        raw: vec![1 << 8 | if port == primary { 0x30 } else { 0 }],
                    },
                );
            }
            adapter
        })
        .collect();
}

pub(crate) fn add_path_usb3_adapter(
    inventory: &mut super::super::super::topology::Inventory,
    kind: u32,
) {
    use super::super::super::topology::AdapterObservation;
    let port = inventory.header.max_port() + 1;
    inventory.header.raw[1] = (inventory.header.raw[1] & !(63 << 14)) | (u32::from(port) << 14);
    let mut adapter = router_adapter(port, kind, Some(0x50));
    if let AdapterObservation::Present {
        header,
        capabilities,
        ..
    } = &mut adapter
    {
        header.raw[1] = 0x50;
        capabilities[0].id = 4;
        capabilities[0].raw[0] = 4 << 8;
    }
    inventory.adapters.push(adapter);
    for adapter in &mut inventory.adapters {
        if let AdapterObservation::Present { header, .. } = adapter {
            header.raw[5] = 127 | (127 << 11);
        }
    }
}

pub(crate) fn link_fixture(map: u8, mode: bool) -> LinkFixture {
    link_fixture_with_usb3(map, mode, false)
}

pub(crate) fn link_fixture_with_usb3(map: u8, mode: bool, usb3: bool) -> LinkFixture {
    link_fixture_with_protocol(map, mode, if usb3 { 0x200101 } else { 0 })
}
pub(crate) fn link_fixture_with_protocol(map: u8, mode: bool, protocol: u32) -> LinkFixture {
    use super::super::super::{link::Partners, router::Setup};
    let (source, domain, model, mut channel) = channel();
    channel.start(0).unwrap();
    let mut cursor = NativeCursor::default();
    let mask = 64
        | if mode { 16 } else { 0 }
        | if protocol == 0x100101 {
            2
        } else {
            u32::from(protocol != 0)
        };
    let mut parent_owner = router_owner(0, 1, mask);
    link_inventory(
        &mut parent_owner,
        if map == 0 { 2 } else { 5 },
        if map == 0 { 1 } else { 2 },
    );
    if protocol != 0 {
        add_path_usb3_adapter(&mut parent_owner.target, protocol);
    }
    let parent_owner = Arc::new(parent_owner);
    let parent_drop = parent_owner.dropped.clone();
    let mut peer = RouterPeer::new(parent_owner.clone(), mask);
    // SAFETY: same synthetic NHI/domain/IMR epoch and current
    // inventories with explicit model native policy; exclusive idle channel.
    let mut setup = unsafe { Setup::new(channel, parent_owner.clone(), cursor.now) }.unwrap();
    let parent = configured_router(&mut peer, &domain, &model, &mut setup, &mut cursor);
    channel = setup.into_channel();
    drop(peer);
    let route = if map == 0 { 1 } else { 2 };
    let mut child_owner = router_owner(route, 1, mask);
    link_inventory(&mut child_owner, if map == 0 { 2 } else { 3 }, 1);
    let mut current_parent = parent_owner.target.clone();
    current_parent.header = parent.header.clone();
    child_owner.parent = Some(current_parent);
    if protocol != 0 {
        add_path_usb3_adapter(&mut child_owner.target, protocol + 1);
    }
    let child_owner = Arc::new(child_owner);
    let child_drop = child_owner.dropped.clone();
    let mut peer = RouterPeer::new(child_owner.clone(), mask);
    // SAFETY: same synthetic requester/epoch and already configured
    // parent, current topology and native model policy.
    let mut setup = unsafe { Setup::new(channel, child_owner.clone(), cursor.now) }.unwrap();
    let child = configured_router(&mut peer, &domain, &model, &mut setup, &mut cursor);
    channel = setup.into_channel();
    drop(peer);
    drop(parent_owner);
    drop(child_owner);
    let reservation_drop = Arc::new(AtomicUsize::new(0));
    let reservation = Arc::new(LinkReservation {
        partners: Partners {
            identity: parent.identity,
            topology_epoch: 2,
            child: [1, if map == 0 { 2 } else { 3 }],
            parent: if map == 0 { [1, 2] } else { [2, 5] },
            observations: core::array::from_fn(|i| {
                let ports = if map == 0 { [1, 2, 1, 2] } else { [1, 3, 2, 5] };
                let routes = [child.route, child.route, parent.route, parent.route];
                super::super::super::link::ObservedLane {
                    route: routes[i],
                    port: ports[i],
                    lane_index: (i % 2) as u8,
                    dual_port: ports[i ^ 1],
                    remote_route: routes[i ^ 2],
                    remote_port: ports[i ^ 2],
                }
            }),
        },
        dropped: reservation_drop.clone(),
    });
    LinkFixture {
        _source: source,
        domain,
        model,
        channel,
        parent,
        child,
        reservation,
        cursor,
        dropped: [parent_drop, child_drop, reservation_drop],
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LinkWrite {
    pub(crate) index: usize,
    pub(crate) offset: u16,
    pub(crate) value: u32,
}

pub(crate) struct LinkPeer {
    pub(crate) partners: super::super::super::link::Partners,
    pub(crate) route: u64,
    pub(crate) mode: bool,
    pub(crate) phy: [[u32; 2]; 4],
    pub(crate) credits: [u32; 4],
    pub(crate) pc: [u32; 2],
    pub(crate) writes: Vec<LinkWrite>,
    pub(crate) bonding: bool,
    pub(crate) bond_reads: u32,
    pub(crate) hold_width: bool,
    pub(crate) reject: Option<(usize, u16)>,
    pub(crate) deny_bond: bool,
    pub(crate) port_wait_state: Option<u8>,
    pub(crate) secondary_reads: u32,
}

impl LinkPeer {
    pub(crate) fn new(
        partners: super::super::super::link::Partners,
        generation: u8,
        dual: bool,
        mode: bool,
        seed: u32,
    ) -> Self {
        let mut phy = [[0; 2]; 4];
        let mut credits = [0; 4];
        for i in 0..4 {
            let mut word = (0x104234ab ^ (seed * 0x01804109) ^ ((i as u32) * 0x01010001))
                & !((15 << 16) | (63 << 20) | (15 << 26) | 0x30 | 0xc000);
            word |= (if generation == 2 { 8 } else { 4 }) << 16;
            word |= (if dual { 2 } else { 1 }) << 20;
            word |= 2 << 26;
            word |= 1 << 4;
            if dual && i == 2 {
                word |= 1 << 15;
            }
            phy[i] = [
                (if i % 2 == 0 { 0x130 } else { 0x100 })
                    | (2 << 20)
                    | ((if generation == 2 { 8 } else { 12 }) << 16)
                    | if mode { 1 << 31 } else { 0 },
                word,
            ];
            credits[i] = ((64 + seed + i as u32) << 20) | (8 + (seed + i as u32) % 4);
        }
        Self {
            partners,
            route: u64::from(partners.parent[0]),
            mode,
            phy,
            credits,
            pc: [0x14050101 ^ (seed * 0x10001); 2],
            writes: vec![],
            bonding: false,
            bond_reads: 0,
            hold_width: false,
            reject: None,
            deny_bond: false,
            port_wait_state: None,
            secondary_reads: 0,
        }
    }
    pub(crate) fn respond(&mut self, domain: &Domain, model: &Model, index: usize) -> Encoded {
        let descriptor = domain.read32(model.descriptor_address(Direction::Tx, index) + 8);
        let kind = PacketType::try_from(((descriptor >> 12) & 15) as u8).unwrap();
        let bytes = domain.data(
            model.frame_address(Direction::Tx, index),
            (descriptor & 0xfff) as usize,
        );
        let mut words: Vec<u32> = bytes[..bytes.len() - 4]
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| u32::from_be_bytes(*word))
            .collect();
        let route = (u64::from(words[0]) << 32) | u64::from(words[1]);
        let address = words[2];
        assert_eq!((address >> 25) & 3, 1);
        let port = ((address >> 19) & 63) as u8;
        let offset = (address & 0x1fff) as u16;
        let count = ((address >> 13) & 63) as usize;
        let lane = if route == self.route {
            self.partners
                .child
                .iter()
                .position(|number| *number == port)
                .unwrap()
        } else {
            assert_eq!(route, 0);
            2 + self
                .partners
                .parent
                .iter()
                .position(|number| *number == port)
                .unwrap()
        };
        let data = if kind == PacketType::Write {
            assert_eq!(count, 1);
            let value = words[3];
            self.writes.push(LinkWrite {
                index: lane,
                offset,
                value,
            });
            match offset {
                9 => {
                    self.phy[lane][1] = if self.reject == Some((lane, offset)) {
                        value & !((3 << 4) | (1 << 15))
                    } else {
                        value
                    };
                    if lane == 2 && value & (1 << 15) != 0 {
                        self.bonding = true;
                        self.bond_reads = 0;
                    }
                }
                0x43 => {
                    assert!(lane == 0 || lane == 2);
                    self.pc[lane / 2] = if self.reject == Some((lane, offset)) {
                        value & !(1 << 3)
                    } else {
                        value
                    };
                }
                _ => panic!("unsupported actual link write"),
            }
            vec![]
        } else {
            assert_eq!(kind, PacketType::Read);
            if lane == 2 && offset == 9 && self.bonding {
                self.bond_reads += 1;
                if self.bond_reads >= 2 && !self.hold_width {
                    for i in 0..4 {
                        self.phy[i][1] = (self.phy[i][1] & !(63 << 20)) | (2 << 20);
                        self.credits[i] += 32 << 20;
                    }
                    self.bonding = false;
                }
            }
            match (offset, count) {
                (8, 2) => {
                    let mut data = self.phy[lane].to_vec();
                    if lane == 3 {
                        self.secondary_reads += 1;
                        if self.secondary_reads > 1
                            && let Some(state) = self.port_wait_state
                        {
                            data[1] = (data[1] & !(15 << 26)) | (u32::from(state) << 26);
                        }
                    }
                    data
                }
                (8, 1) => vec![self.phy[lane][0]],
                (9, 1) => vec![self.phy[lane][1]],
                (4, 1) => vec![self.credits[lane]],
                (0x42, 1) => vec![
                    if self.deny_bond { 0 } else { 1 << 8 } | if self.mode { 1 << 9 } else { 0 },
                ],
                (0x43, 1) => {
                    assert!(lane == 0 || lane == 2);
                    vec![self.pc[lane / 2]]
                }
                _ => panic!("unsupported actual link read"),
            }
        };
        words.truncate(3);
        words[0] |= 1 << 31;
        words[2] = (address & !(63 << 19))
            | if lane < 2 {
                u32::from(self.partners.child[0]) << 19
            } else {
                0
            };
        words.extend(data);
        incoming(kind, &words)
    }
}

pub(crate) fn drive_link(
    peer: &mut LinkPeer,
    domain: &Domain,
    model: &Model,
    activate: &mut super::super::super::link::Activate<Model>,
    cursor: &mut NativeCursor,
) -> super::super::super::link::Linked {
    use super::super::super::link::Event;
    assert!(activate.poll(cursor.now).unwrap().is_none());
    for _ in 0..150 {
        let reply = peer.respond(domain, model, cursor.tx % 10);
        model.finish(Direction::Tx, cursor.tx % 10, &[], None);
        finish_rx(model, cursor.rx % 10, &reply);
        cursor.tx += 1;
        cursor.rx += 1;
        cursor.now += 1;
        match activate.poll(cursor.now).unwrap() {
            Some(Event::Linked(value)) => return *value,
            Some(Event::Discarded(error)) => panic!("{error:?}"),
            None => {}
        }
    }
    panic!("actual native link activation did not finish")
}
