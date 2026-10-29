//! Modeled USB3 bandwidth reservations, fixtures and the peer answering
//! allocation.

use super::*;

pub(crate) struct BandwidthReservation {
    pub(crate) current: Arc<AtomicBool>,
    pub(crate) grant: super::super::super::usb3::Grant,
    pub(crate) dropped: Arc<AtomicUsize>,
}

impl Drop for BandwidthReservation {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

// SAFETY: synthetic domain accounting and permission protect this
// exact root/peer link and source floor/quantization throughout the phase.
// When used by tunnel fixtures it also keeps exclusive synthetic
// CS0 endpoint control on both mapped adapters through final owner lifetime.
// These fixtures implement no production accounting/policy/control service.
unsafe impl super::super::super::usb3::Reservation for BandwidthReservation {
    fn is_current(&self) -> bool {
        self.current.load(Ordering::Acquire)
    }
    fn grant(&self) -> super::super::super::usb3::Grant {
        self.grant
    }
}

pub(crate) fn bandwidth_fixture(
    requested: super::super::super::usb3::Rates,
) -> (PathFixture, Arc<BandwidthReservation>, Arc<AtomicUsize>) {
    use super::super::super::{
        path::{Direction, LaneCredits},
        usb3::Grant,
    };
    let fixture = path_fixture(Direction::Downstream, LaneCredits::LegacyBonded);
    let allocation = fixture.reservation.allocation;
    let dropped = Arc::new(AtomicUsize::new(0));
    let reservation = Arc::new(BandwidthReservation {
        current: Arc::new(AtomicBool::new(true)),
        grant: Grant {
            identity: allocation.identity,
            topology_epoch: allocation.topology_epoch,
            grant_epoch: allocation.grant_epoch,
            usb3_down: allocation.usb3_down,
            usb3_up: allocation.usb3_up,
            permission: allocation.permission,
            requested,
        },
        dropped: dropped.clone(),
    });
    (fixture, reservation, dropped)
}

pub(crate) struct BandwidthPeer {
    pub(crate) port: u8,
    pub(crate) header: [u32; 8],
    pub(crate) control: u32,
    pub(crate) consumed: u32,
    pub(crate) scale: u32,
    pub(crate) writes: Vec<(u16, u32)>,
    pub(crate) transition: Option<bool>,
    pub(crate) polls: usize,
    pub(crate) hold: [bool; 2],
    pub(crate) reject: Option<usize>,
}

impl BandwidthPeer {
    pub(crate) fn new(
        link: &super::super::super::link::Linked,
        grant: super::super::super::usb3::Grant,
        seed: u32,
    ) -> Self {
        use super::super::super::topology::AdapterObservation;
        let parent = link.retained_routers().unwrap().0;
        let header = parent
            .retained_owner()
            .target()
            .adapters
            .iter()
            .find_map(|a| match a {
                AdapterObservation::Present { port, header, .. } if *port == grant.usb3_down => {
                    Some(header.raw)
                }
                _ => None,
            })
            .unwrap();
        Self {
            port: grant.usb3_down,
            header,
            control: (0x12345678 ^ (seed * 0x10201)) & !(1 << 31),
            consumed: (seed % 256) | (((seed * 3) % 256) << 12),
            scale: (seed % 4) | 0x30000000,
            writes: vec![],
            transition: None,
            polls: 0,
            hold: [false; 2],
            reject: None,
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
            .map(|v| u32::from_be_bytes(*v))
            .collect();
        let address = words[2];
        assert_eq!((words[0], words[1]), (0, 0));
        assert_eq!((address >> 25) & 3, 1);
        assert_eq!(((address >> 19) & 63) as u8, self.port);
        let offset = (address & 8191) as u16;
        let data = if kind == PacketType::Write {
            assert_eq!((address >> 13) & 63, 1);
            let value = words[3];
            self.writes.push((offset, value));
            let reject = self.reject == Some(self.writes.len());
            match offset {
                0x52 => {
                    let old = self.control;
                    self.control = if reject {
                        value ^ if self.writes.len() == 3 { 1 } else { 1 << 31 }
                    } else {
                        value
                    };
                    if (old ^ value) & (1 << 31) != 0 {
                        self.transition = Some(value & (1 << 31) != 0);
                        self.polls = 0;
                    }
                }
                0x53 => self.scale = if reject { value ^ 1 } else { value },
                _ => panic!("unexpected source bandwidth write"),
            };
            vec![]
        } else {
            assert_eq!(kind, PacketType::Read);
            match offset {
                0 => self.header.to_vec(),
                0x51 => {
                    if let Some(set) = self.transition {
                        self.polls += 1;
                        if self.polls >= 2 && !self.hold[usize::from(!set)] {
                            self.consumed =
                                (self.consumed & !(1 << 31)) | if set { 1 << 31 } else { 0 };
                            self.transition = None;
                        }
                    }
                    vec![self.consumed]
                }
                0x52 => vec![self.control],
                0x53 => vec![self.scale],
                _ => panic!("unexpected bandwidth read"),
            }
        };
        words.truncate(3);
        words[0] |= 1 << 31;
        words[2] &= !(63 << 19);
        words.extend(data);
        incoming(kind, &words)
    }
}

pub(crate) fn bandwidth_step(
    peer: &mut BandwidthPeer,
    domain: &Domain,
    model: &Model,
    allocate: &mut super::super::super::usb3::Allocate<Model>,
    cursor: &mut NativeCursor,
) -> Result<Option<super::super::super::usb3::Event>, super::super::super::usb3::Error> {
    if (model.read32(TX_DESCRIPTOR + 8) >> 16) as usize == cursor.tx % 10 {
        cursor.now += 1;
        return allocate.poll(cursor.now);
    }
    let reply = peer.respond(domain, model, cursor.tx % 10);
    model.finish(Direction::Tx, cursor.tx % 10, &[], None);
    finish_rx(model, cursor.rx % 10, &reply);
    cursor.tx += 1;
    cursor.rx += 1;
    cursor.now += 1;
    allocate.poll(cursor.now)
}

pub(crate) fn drive_bandwidth(
    peer: &mut BandwidthPeer,
    domain: &Domain,
    model: &Model,
    allocate: &mut super::super::super::usb3::Allocate<Model>,
    cursor: &mut NativeCursor,
) -> Box<super::super::super::usb3::Allocated> {
    use super::super::super::usb3::Event;
    allocate.poll(cursor.now).unwrap();
    for _ in 0..100 {
        match bandwidth_step(peer, domain, model, allocate, cursor).unwrap() {
            Some(Event::Allocated(value)) => return value,
            Some(Event::Discarded(error)) => panic!("{error:?}"),
            None => {}
        }
    }
    panic!("actual HCA transitions did not finish")
}
