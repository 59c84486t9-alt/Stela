//! Modeled path reservations, fixtures and the peer answering hop programming.

use super::*;

pub(crate) struct PathReservation {
    pub(crate) allocation: super::super::super::path::Allocation,
    pub(crate) dropped: Arc<AtomicUsize>,
}

impl Drop for PathReservation {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

// SAFETY: model keeps protected IDs/credits/permission on the exact
// configured synthetic link. This supplies no production allocator/provider.
unsafe impl super::super::super::path::Reservation for PathReservation {
    fn allocation(&self) -> super::super::super::path::Allocation {
        self.allocation
    }
    fn is_current(&self) -> bool {
        // This fixture's allocation remains held in its isolated epoch;
        // no independent reset or reassignment actor exists in the model.
        true
    }
}

pub(crate) struct PathFixture {
    pub(crate) domain: Arc<Domain>,
    pub(crate) model: Arc<Model>,
    pub(crate) channel: super::super::super::channel::Channel<Model>,
    pub(crate) linked: Box<super::super::super::link::Linked>,
    pub(crate) reservation: Arc<PathReservation>,
    pub(crate) cursor: NativeCursor,
    pub(crate) dropped: [Arc<AtomicUsize>; 4],
}

pub(crate) fn path_fixture(
    direction: super::super::super::path::Direction,
    credits: super::super::super::path::LaneCredits,
) -> PathFixture {
    use super::super::super::{link::Activate, path::Allocation, router::Decision};
    let LinkFixture {
        domain,
        model,
        channel,
        parent,
        child,
        reservation,
        mut cursor,
        dropped,
        ..
    } = link_fixture_with_usb3(1, false, true);
    let mut peer = LinkPeer::new(reservation.partners, 3, false, false, 3);
    // SAFETY: model NHI, both configured owners, observed lanes.
    let mut activate =
        unsafe { Activate::new(channel, parent, child, reservation, cursor.now) }.unwrap();
    let linked = Box::new(drive_link(
        &mut peer,
        &domain,
        &model,
        &mut activate,
        &mut cursor,
    ));
    let channel = activate.into_channel();
    let (parent, child) = linked.retained_routers().unwrap();
    let allocation = Allocation {
        identity: linked.partners.identity,
        topology_epoch: linked.partners.topology_epoch,
        grant_epoch: 3,
        direction,
        usb3_down: parent.header.max_port(),
        usb3_up: child.header.max_port(),
        hops: [(8, 31), (31, 8)],
        lane_credits: credits,
        permission: Decision::Allowed,
    };
    let path_drop = Arc::new(AtomicUsize::new(0));
    let reservation = Arc::new(PathReservation {
        allocation,
        dropped: path_drop.clone(),
    });
    PathFixture {
        domain,
        model,
        channel,
        linked,
        reservation,
        cursor,
        dropped: [
            dropped[0].clone(),
            dropped[1].clone(),
            dropped[2].clone(),
            path_drop,
        ],
    }
}

pub(crate) struct PathPeer {
    pub(crate) routes: [u64; 2],
    pub(crate) ports: [u8; 2],
    pub(crate) upstream: [u8; 2],
    pub(crate) headers: [[u32; 8]; 2],
    pub(crate) raw: [[u32; 2]; 2],
    pub(crate) reads: [usize; 2],
    pub(crate) disabled: [bool; 2],
    pub(crate) writes: Vec<(usize, u8, u16, [u32; 2])>,
    pub(crate) hold_pending: bool,
    pub(crate) hold_hop: [bool; 2],
    pub(crate) reject: Option<usize>,
    pub(crate) changed_header: bool,
    pub(crate) credit: u32,
}

impl PathPeer {
    pub(crate) fn new(
        linked: &super::super::super::link::Linked,
        allocation: super::super::super::path::Allocation,
        stale: bool,
        seed: u32,
    ) -> Self {
        use super::super::super::{path::Direction, topology::AdapterObservation};
        let (parent, child) = linked.retained_routers().unwrap();
        let (source, destination, ports) = match allocation.direction {
            Direction::Downstream => (
                parent,
                child,
                [allocation.usb3_down, linked.partners.child[0]],
            ),
            Direction::Upstream => (
                child,
                parent,
                [allocation.usb3_up, linked.partners.parent[0]],
            ),
        };
        let owners = [source, destination];
        let headers = core::array::from_fn(|i| {
            owners[i]
                .retained_owner()
                .target()
                .adapters
                .iter()
                .find_map(|adapter| match adapter {
                    AdapterObservation::Present { port, header, .. } if *port == ports[i] => {
                        Some(header.raw)
                    }
                    _ => None,
                })
                .unwrap()
        });
        Self {
            routes: [source.route.raw(), destination.route.raw()],
            ports,
            upstream: [
                source.retained_owner().target().upstream_port,
                destination.retained_owner().target().upstream_port,
            ],
            headers,
            raw: core::array::from_fn(|i| {
                [
                    (0x12345678 ^ (seed * 0x104001) ^ (i as u32 * 0x13579)) & !(1 << 31)
                        | if stale { 1 << 31 } else { 0 },
                    (0xabcdef12 ^ (seed * 0x104101) ^ (i as u32 * 0x13579))
                        | if stale { 1 << 28 } else { 0 },
                ]
            }),
            reads: [0; 2],
            disabled: [false; 2],
            writes: vec![],
            hold_pending: false,
            hold_hop: [false; 2],
            reject: None,
            changed_header: false,
            credit: (100 << 20) | 8,
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
        let port = ((address >> 19) & 63) as u8;
        let lane = self
            .routes
            .iter()
            .zip(self.ports)
            .position(|(r, p)| *r == route && p == port)
            .unwrap();
        let space = (address >> 25) & 3;
        let offset = address & 8191;
        let count = ((address >> 13) & 63) as usize;
        let data = if kind == PacketType::Write {
            assert_eq!((space, count), (0, 2));
            let value = [words[3], words[4]];
            self.writes.push((lane, port, offset as u16, value));
            if self.reject == Some(self.writes.len()) {
                self.raw[lane] = [value[0] ^ (1 << 31), value[1]];
            } else {
                self.raw[lane] = value;
            }
            self.disabled[lane] = self.raw[lane][0] & (1 << 31) == 0;
            if self.disabled[lane] {
                self.reads[lane] = 0;
            }
            vec![]
        } else {
            assert_eq!(kind, PacketType::Read);
            match (space, offset, count) {
                (1, 0, 8) => {
                    let mut data = self.headers[lane];
                    if self.changed_header {
                        data[2] ^= 1;
                    }
                    data.to_vec()
                }
                (1, 4, 1) => vec![self.credit],
                (0, _, 2) => {
                    self.reads[lane] += 1;
                    if self.disabled[lane]
                        && self.reads[lane] >= 2
                        && !self.hold_pending
                        && !self.hold_hop[lane]
                    {
                        self.raw[lane][1] &= !(1 << 28);
                    }
                    self.raw[lane].to_vec()
                }
                _ => panic!("unexpected actual path read"),
            }
        };
        words.truncate(3);
        words[0] |= 1 << 31;
        words[2] = (address & !(63 << 19)) | (u32::from(self.upstream[lane]) << 19);
        words.extend(data);
        incoming(kind, &words)
    }
}

pub(crate) fn path_step(
    peer: &mut PathPeer,
    domain: &Domain,
    model: &Model,
    activate: &mut super::super::super::path::Activate<Model>,
    cursor: &mut NativeCursor,
) -> Result<Option<super::super::super::path::Event>, super::super::super::path::Error> {
    let producer = model.read32(TX_DESCRIPTOR + 8) >> 16;
    if producer as usize == cursor.tx % 10 {
        cursor.now += 1;
        return activate.poll(cursor.now);
    }
    let reply = peer.respond(domain, model, cursor.tx % 10);
    model.finish(Direction::Tx, cursor.tx % 10, &[], None);
    finish_rx(model, cursor.rx % 10, &reply);
    cursor.tx += 1;
    cursor.rx += 1;
    cursor.now += 1;
    activate.poll(cursor.now)
}

pub(crate) fn drive_path(
    peer: &mut PathPeer,
    domain: &Domain,
    model: &Model,
    activate: &mut super::super::super::path::Activate<Model>,
    cursor: &mut NativeCursor,
) -> super::super::super::path::Active {
    use super::super::super::path::Event;
    activate.poll(cursor.now).unwrap();
    for _ in 0..100 {
        match path_step(peer, domain, model, activate, cursor).unwrap() {
            Some(Event::Active(value)) => return value,
            Some(Event::Discarded(error)) => panic!("{error:?}"),
            None => {}
        }
    }
    panic!("actual path did not activate")
}
