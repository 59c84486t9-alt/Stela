//! Modeled USB3 tunnels: activation, stop and release fixtures and their peers.

use super::*;

pub(crate) struct TunnelFixture {
    pub(crate) current: Arc<AtomicBool>,
    pub(crate) domain: Arc<Domain>,
    pub(crate) model: Arc<Model>,
    pub(crate) channel: super::super::super::channel::Channel<Model>,
    pub(crate) bandwidth: Box<super::super::super::usb3::Allocated>,
    pub(crate) down: Arc<PathReservation>,
    pub(crate) up: Arc<PathReservation>,
    pub(crate) cursor: NativeCursor,
    pub(crate) dropped: [Arc<AtomicUsize>; 6],
    pub(crate) band_writes: Vec<(u16, u32)>,
}

pub(crate) fn tunnel_fixture(
    credits: super::super::super::path::LaneCredits,
    seed: u32,
) -> TunnelFixture {
    use super::super::super::{
        path::Direction,
        usb3::{Allocate, Rates},
    };
    let wanted = [0, 1, 1023, 8191, 10000, 16384, 18000, 20000];
    let (
        PathFixture {
            domain,
            model,
            channel,
            linked,
            reservation,
            mut cursor,
            dropped,
        },
        accounting,
        accounting_drop,
    ) = bandwidth_fixture(Rates {
        upstream: wanted[seed as usize % 8],
        downstream: wanted[(seed as usize / 8) % 8],
    });
    let mut allocation = reservation.allocation;
    allocation.lane_credits = credits;
    let down_drop = Arc::new(AtomicUsize::new(0));
    let up_drop = Arc::new(AtomicUsize::new(0));
    let down = Arc::new(PathReservation {
        allocation,
        dropped: down_drop.clone(),
    });
    allocation.direction = Direction::Upstream;
    let up = Arc::new(PathReservation {
        allocation,
        dropped: up_drop.clone(),
    });
    drop(reservation);
    let current = accounting.current.clone();
    let mut peer = BandwidthPeer::new(&linked, accounting.grant, seed);
    // SAFETY: protected native synthetic link/accounting/permission.
    let mut allocate = unsafe { Allocate::new(channel, linked, accounting, cursor.now) }.unwrap();
    let bandwidth = drive_bandwidth(&mut peer, &domain, &model, &mut allocate, &mut cursor);
    let channel = allocate.into_channel();
    TunnelFixture {
        current,
        domain,
        model,
        channel,
        bandwidth,
        down,
        up,
        cursor,
        dropped: [
            dropped[0].clone(),
            dropped[1].clone(),
            dropped[2].clone(),
            accounting_drop,
            down_drop,
            up_drop,
        ],
        band_writes: peer.writes,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TunnelWrite {
    pub(crate) route: u64,
    pub(crate) port: u8,
    pub(crate) space: u8,
    pub(crate) offset: u16,
    pub(crate) data: Vec<u32>,
}

pub(crate) struct TunnelPeer {
    pub(crate) down: PathPeer,
    pub(crate) up: PathPeer,
    pub(crate) endpoints: [u32; 2],
    pub(crate) writes: Vec<TunnelWrite>,
    pub(crate) clear_valid: bool,
    pub(crate) reject: Option<usize>,
    pub(crate) fail_second_header: bool,
}

impl TunnelPeer {
    pub(crate) fn new(fixture: &TunnelFixture, stale: bool, seed: u32) -> Self {
        Self {
            down: PathPeer::new(
                fixture.bandwidth.linked(),
                fixture.down.allocation,
                stale,
                seed,
            ),
            up: PathPeer::new(
                fixture.bandwidth.linked(),
                fixture.up.allocation,
                stale,
                seed + 1,
            ),
            endpoints: [0; 2],
            writes: vec![],
            clear_valid: seed & 1 != 0,
            reject: None,
            fail_second_header: false,
        }
    }
    pub(crate) fn respond(&mut self, domain: &Domain, model: &Model, index: usize) -> Encoded {
        let descriptor = domain.read32(model.descriptor_address(Direction::Tx, index) + 8);
        let kind = PacketType::try_from(((descriptor >> 12) & 15) as u8).unwrap();
        let bytes = domain.data(
            model.frame_address(Direction::Tx, index),
            (descriptor & 4095) as usize,
        );
        let words: Vec<u32> = bytes[..bytes.len() - 4]
            .as_chunks::<4>()
            .0
            .iter()
            .map(|b| u32::from_be_bytes(*b))
            .collect();
        let route = (u64::from(words[0]) << 32) | u64::from(words[1]);
        let address = words[2];
        let port = ((address >> 19) & 63) as u8;
        let space = ((address >> 25) & 3) as u8;
        let offset = (address & 8191) as u16;
        if kind == PacketType::Write {
            self.writes.push(TunnelWrite {
                route,
                port,
                space,
                offset,
                data: words[3..].to_vec(),
            });
        }
        let reject = kind == PacketType::Write && self.reject == Some(self.writes.len());
        if space == 1 && offset == 0x50 {
            let endpoint = if route == self.down.routes[0] && port == self.down.ports[0] {
                0
            } else {
                assert_eq!((route, port), (self.up.routes[0], self.up.ports[0]));
                1
            };
            let data = if kind == PacketType::Write {
                assert!(matches!(words[3], 0xc0000000 | 0x40000000));
                let value = if reject {
                    words[3] ^ (1 << 31)
                } else {
                    words[3]
                };
                self.endpoints[endpoint] = if self.clear_valid {
                    value & !(1 << 30)
                } else {
                    value
                };
                vec![]
            } else {
                vec![self.endpoints[endpoint]]
            };
            let upstream = if endpoint == 0 {
                self.down.upstream[0]
            } else {
                self.up.upstream[0]
            };
            let mut reply = words[..3].to_vec();
            reply[0] |= 1 << 31;
            reply[2] = (address & !(63 << 19)) | (u32::from(upstream) << 19);
            reply.extend(data);
            return incoming(kind, &reply);
        }
        let down = self
            .down
            .routes
            .iter()
            .zip(self.down.ports)
            .any(|(r, p)| *r == route && p == port);
        let changed_second = !down && self.fail_second_header && self.down.writes.len() >= 4;
        let peer = if down { &mut self.down } else { &mut self.up };
        if reject {
            peer.reject = Some(peer.writes.len() + 1);
        }
        if changed_second {
            peer.changed_header = true;
        }
        peer.respond(domain, model, index)
    }
}

pub(crate) fn tunnel_step(
    peer: &mut TunnelPeer,
    domain: &Domain,
    model: &Model,
    engine: &mut super::super::super::usb3::ActivateTunnel<Model>,
    cursor: &mut NativeCursor,
) -> Result<Option<super::super::super::usb3::TunnelEvent>, super::super::super::usb3::Error> {
    if (model.read32(TX_DESCRIPTOR + 8) >> 16) as usize == cursor.tx % 10 {
        cursor.now += 1;
        return engine.poll(cursor.now);
    }
    let reply = peer.respond(domain, model, cursor.tx % 10);
    model.finish(Direction::Tx, cursor.tx % 10, &[], None);
    finish_rx(model, cursor.rx % 10, &reply);
    cursor.tx += 1;
    cursor.rx += 1;
    cursor.now += 1;
    engine.poll(cursor.now)
}

pub(crate) fn drive_tunnel(
    peer: &mut TunnelPeer,
    domain: &Domain,
    model: &Model,
    engine: &mut super::super::super::usb3::ActivateTunnel<Model>,
    cursor: &mut NativeCursor,
) -> Box<super::super::super::usb3::ActiveTunnel> {
    use super::super::super::usb3::TunnelEvent;
    engine.poll(cursor.now).unwrap();
    for _ in 0..200 {
        match tunnel_step(peer, domain, model, engine, cursor).unwrap() {
            Some(TunnelEvent::Active(value)) => return value,
            Some(TunnelEvent::Discarded(error)) => panic!("{error:?}"),
            None => {}
        }
    }
    panic!("actual source USB3 tunnel phase did not finish")
}

pub(crate) struct StopFixture {
    pub(crate) domain: Arc<Domain>,
    pub(crate) model: Arc<Model>,
    pub(crate) channel: super::super::super::channel::Channel<Model>,
    pub(crate) active: Box<super::super::super::usb3::ActiveTunnel>,
    pub(crate) peer: TunnelPeer,
    pub(crate) cursor: NativeCursor,
    pub(crate) current: Arc<AtomicBool>,
    pub(crate) dropped: [Arc<AtomicUsize>; 6],
    pub(crate) activation: Vec<TunnelWrite>,
    pub(crate) bandwidth_peer: BandwidthPeer,
}

pub(crate) fn stop_fixture(
    credits: super::super::super::path::LaneCredits,
    seed: u32,
) -> StopFixture {
    use super::super::super::usb3::ActivateTunnel;
    let fixture = tunnel_fixture(credits, seed);
    let mut peer = TunnelPeer::new(&fixture, true, seed);
    let control = fixture.band_writes.last().unwrap().1;
    let scale = fixture
        .band_writes
        .iter()
        .find(|(offset, _)| *offset == 0x53)
        .unwrap()
        .1;
    let bandwidth_peer = BandwidthPeer {
        port: 6,
        header: peer.down.headers[0],
        control,
        scale,
        consumed: if seed & 1 == 0 { 0 } else { 1023 }
            | ((if seed.is_multiple_of(3) { 1023 } else { 255 }) << 12),
        writes: vec![],
        transition: None,
        polls: 0,
        hold: [false; 2],
        reject: None,
    };
    let TunnelFixture {
        domain,
        model,
        channel,
        bandwidth,
        down,
        up,
        mut cursor,
        current,
        dropped,
        band_writes,
    } = fixture;
    // SAFETY: complete synthetic control/accounting/path permission.
    let mut engine =
        unsafe { ActivateTunnel::new(channel, bandwidth, down, up, cursor.now) }.unwrap();
    let active = drive_tunnel(&mut peer, &domain, &model, &mut engine, &mut cursor);
    let channel = engine.into_channel();
    let mut activation: Vec<_> = band_writes
        .into_iter()
        .map(|(offset, value)| TunnelWrite {
            route: 0,
            port: 6,
            space: 1,
            offset,
            data: vec![value],
        })
        .collect();
    activation.append(&mut peer.writes);
    peer.down.writes.clear();
    peer.up.writes.clear();
    for path in [&mut peer.down, &mut peer.up] {
        for i in 0..2 {
            path.raw[i][1] |= 1 << 28;
            path.disabled[i] = false;
            path.reads[i] = 0;
        }
    }
    StopFixture {
        domain,
        model,
        channel,
        active,
        peer,
        cursor,
        current,
        dropped,
        activation,
        bandwidth_peer,
    }
}

pub(crate) fn stop_step(
    peer: &mut TunnelPeer,
    domain: &Domain,
    model: &Model,
    engine: &mut super::super::super::usb3::StopTunnel<Model>,
    cursor: &mut NativeCursor,
) -> Result<Option<super::super::super::usb3::StopEvent>, super::super::super::usb3::Error> {
    if (model.read32(TX_DESCRIPTOR + 8) >> 16) as usize == cursor.tx % 10 {
        cursor.now += 1;
        return engine.poll(cursor.now);
    }
    let reply = peer.respond(domain, model, cursor.tx % 10);
    model.finish(Direction::Tx, cursor.tx % 10, &[], None);
    finish_rx(model, cursor.rx % 10, &reply);
    cursor.tx += 1;
    cursor.rx += 1;
    cursor.now += 1;
    engine.poll(cursor.now)
}

pub(crate) fn drive_stop(
    peer: &mut TunnelPeer,
    domain: &Domain,
    model: &Model,
    engine: &mut super::super::super::usb3::StopTunnel<Model>,
    cursor: &mut NativeCursor,
) -> Box<super::super::super::usb3::Stopped> {
    use super::super::super::usb3::StopEvent;
    engine.poll(cursor.now).unwrap();
    for _ in 0..200 {
        match stop_step(peer, domain, model, engine, cursor).unwrap() {
            Some(StopEvent::Stopped(value)) => return value,
            Some(StopEvent::Discarded(e)) => panic!("{e:?}"),
            None => {}
        }
    }
    panic!("normal actual tunnel stop did not finish")
}

pub(crate) fn release_step(
    peer: &mut BandwidthPeer,
    domain: &Domain,
    model: &Model,
    engine: &mut super::super::super::usb3::ReleaseUnused<Model>,
    cursor: &mut NativeCursor,
) -> Result<Option<super::super::super::usb3::TunnelEvent>, super::super::super::usb3::Error> {
    if (model.read32(TX_DESCRIPTOR + 8) >> 16) as usize == cursor.tx % 10 {
        cursor.now += 1;
        return engine.poll(cursor.now);
    }
    let reply = peer.respond(domain, model, cursor.tx % 10);
    model.finish(Direction::Tx, cursor.tx % 10, &[], None);
    finish_rx(model, cursor.rx % 10, &reply);
    cursor.tx += 1;
    cursor.rx += 1;
    cursor.now += 1;
    engine.poll(cursor.now)
}

pub(crate) fn drive_release(
    peer: &mut BandwidthPeer,
    domain: &Domain,
    model: &Model,
    engine: &mut super::super::super::usb3::ReleaseUnused<Model>,
    cursor: &mut NativeCursor,
) -> Box<super::super::super::usb3::ActiveTunnel> {
    use super::super::super::usb3::TunnelEvent;
    engine.poll(cursor.now).unwrap();
    for _ in 0..100 {
        match release_step(peer, domain, model, engine, cursor).unwrap() {
            Some(TunnelEvent::Active(value)) => return value,
            Some(TunnelEvent::Discarded(e)) => panic!("{e:?}"),
            None => {}
        }
    }
    panic!("source release-unused handshake did not finish")
}
