//! Modeled routers: their owners, adapters and the peer answering router
//! configuration.

use super::*;

pub(crate) struct RouterOwner {
    pub(crate) target: super::super::super::topology::Inventory,
    pub(crate) parent: Option<super::super::super::topology::Inventory>,
    pub(crate) policy: super::super::super::router::Policy,
    pub(crate) epoch: u64,
    pub(crate) dropped: Arc<AtomicUsize>,
}

impl Drop for RouterOwner {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

// SAFETY: fixtures reserve one synthetic NHI/domain/IMR epoch and
// unchanged real model inventories. Policy is an explicit model input,
// not a production platform/_OSC/security provider or Type-C inference.
unsafe impl super::super::super::router::Owner for RouterOwner {
    fn identity(&self) -> super::super::super::domain::Identity {
        super::super::super::domain::Identity {
            nhi: crate::bus::pci::Address {
                segment: 0,
                bus: 1,
                device: 2,
                function: 0,
            },
            epoch: self.epoch,
        }
    }
    fn target(&self) -> &super::super::super::topology::Inventory {
        &self.target
    }
    fn parent(&self) -> Option<&super::super::super::topology::Inventory> {
        self.parent.as_ref()
    }
    fn policy(&self) -> super::super::super::router::Policy {
        self.policy
    }
}

pub(crate) fn router_adapter(
    port: u8,
    kind: u32,
    cap: Option<u16>,
) -> super::super::super::topology::AdapterObservation {
    use super::super::super::topology::{AdapterHeader, AdapterObservation, Capability};
    let mut raw = [0; 8];
    raw[2] = kind;
    raw[3] = u32::from(port) << 20;
    AdapterObservation::Present {
        port,
        header: AdapterHeader { raw },
        capabilities: cap
            .map(|offset| {
                vec![Capability {
                    offset,
                    id: 6,
                    vendor_specific: None,
                    length: None,
                    next: 0,
                    raw: vec![6 << 8],
                }]
            })
            .unwrap_or_default(),
    }
}

pub(crate) fn router_owner(route: u64, version: u8, mask: u32) -> RouterOwner {
    use super::super::super::{
        config::Route,
        router::{Decision, Policy},
        topology::{Inventory, Path, RouterHeader},
    };
    let path = Path::new(Route::new(route).unwrap()).unwrap();
    let header = RouterHeader {
        raw: [
            0x12348086,
            0x43808000 | (9 << 8),
            0xdeadbeef,
            0x10203040,
            (u32::from(version) << 29) | 0x00ab34cd,
        ],
    };
    let target = Inventory {
        path,
        upstream_port: if route == 0 { 0 } else { 1 },
        header,
        capabilities: vec![],
        adapters: vec![
            router_adapter(1, 1, Some(0x30)),
            router_adapter(2, 0x0e0101, Some(0x40)),
        ],
    };
    let parent = if route == 0 {
        None
    } else {
        let depth = path.depth() - 1;
        let shift = depth * 8;
        let raw = route & ((1u64 << shift) - 1);
        let upstream = if depth == 0 { 0 } else { 5 };
        let parent_path = Path::new(Route::new(raw).unwrap()).unwrap();
        let down = (route >> shift) as u8;
        Some(Inventory {
            path: parent_path,
            upstream_port: upstream,
            header: RouterHeader {
                raw: [
                    0x56788086,
                    (5 << 14) | (u32::from(upstream) << 8) | (u32::from(depth) << 20),
                    raw as u32,
                    (raw >> 32) as u32 | (1 << 31),
                    1 << 29,
                ],
            },
            capabilities: vec![],
            adapters: (1..=5)
                .map(|port| {
                    router_adapter(
                        port,
                        match port {
                            1 | 2 | 5 => 1,
                            3 => {
                                if mask & 4 != 0 {
                                    0x200101
                                } else {
                                    0
                                }
                            }
                            4 => {
                                if mask & 8 != 0 {
                                    0x100101
                                } else {
                                    0
                                }
                            }
                            _ => unreachable!(),
                        },
                        if port == down && mask & 64 != 0 {
                            Some(0x30)
                        } else {
                            None
                        },
                    )
                })
                .collect(),
        })
    };
    RouterOwner {
        target,
        parent,
        policy: Policy {
            usb3: if mask & 1 != 0 {
                Decision::Allowed
            } else {
                Decision::Denied
            },
            pcie: if mask & 2 != 0 {
                Decision::Allowed
            } else {
                Decision::Denied
            },
        },
        epoch: 1,
        dropped: Arc::new(AtomicUsize::new(0)),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RouterWrite {
    pub(crate) port: u8,
    pub(crate) space: u8,
    pub(crate) offset: u16,
    pub(crate) data: Vec<u32>,
}

pub(crate) struct RouterPeer {
    pub(crate) owner: Arc<RouterOwner>,
    pub(crate) regs: [u32; 8],
    pub(crate) hotplug: Vec<u32>,
    pub(crate) mask: u32,
    pub(crate) writes: Vec<RouterWrite>,
    pub(crate) setup_written: bool,
    pub(crate) valid_written: bool,
    pub(crate) ready_reads: u32,
    pub(crate) configured_reads: u32,
    pub(crate) hold_ready: bool,
    pub(crate) hold_configured: bool,
    pub(crate) reject_header: bool,
    pub(crate) override_upstream: Option<u8>,
}

impl RouterPeer {
    pub(crate) fn new(owner: Arc<RouterOwner>, mask: u32) -> Self {
        let mut regs = [0; 8];
        regs[..5].copy_from_slice(&owner.target.header.raw);
        regs[5] = 0x00d5001f;
        regs[6] = 0x1202 | if mask & 32 != 0 { 1 << 18 } else { 0 };
        let hotplug = (0..owner.target.header.max_port())
            .map(|i| match i {
                0 => 0x92345678,
                1 => 0xabcdef01,
                _ => 0x98765430 + u32::from(i),
            })
            .collect();
        Self {
            owner,
            regs,
            hotplug,
            mask,
            writes: vec![],
            setup_written: false,
            valid_written: false,
            ready_reads: 0,
            configured_reads: 0,
            hold_ready: false,
            hold_configured: false,
            reject_header: false,
            override_upstream: None,
        }
    }
    pub(crate) fn respond(&mut self, domain: &Domain, model: &Model, index: usize) -> Encoded {
        let descriptor = domain.read32(model.descriptor_address(Direction::Tx, index) + 8);
        let kind = PacketType::try_from(((descriptor >> 12) & 15) as u8).unwrap();
        let frame = domain.data(
            model.frame_address(Direction::Tx, index),
            (descriptor & 0xfff) as usize,
        );
        let mut words: Vec<u32> = frame[..frame.len() - 4]
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| u32::from_be_bytes(*word))
            .collect();
        let route = (u64::from(words[0]) << 32) | u64::from(words[1]);
        let address = words[2];
        let offset = (address & 0x1fff) as u16;
        let count = ((address >> 13) & 63) as usize;
        let port = ((address >> 19) & 63) as u8;
        let space = ((address >> 25) & 3) as u8;
        let target = route == self.owner.target.path.route().raw();
        let upstream = if target {
            self.owner.target.upstream_port
        } else {
            self.owner
                .parent
                .as_ref()
                .expect("actual parent")
                .upstream_port
        };
        let data = if kind == PacketType::Write {
            assert!(target, "setup must not program parent");
            let data = words[3..].to_vec();
            assert_eq!(data.len(), count);
            self.writes.push(RouterWrite {
                port,
                space,
                offset,
                data: data.clone(),
            });
            if space == 2 {
                self.regs[usize::from(offset)..usize::from(offset) + count].copy_from_slice(&data);
                if offset == 1 && self.reject_header {
                    self.regs[3] &= !(1 << 31);
                }
                if offset == 5 {
                    self.setup_written = true;
                    if data[0] & (1 << 31) != 0 {
                        self.valid_written = true;
                    }
                }
            } else {
                assert_eq!((space, offset, count), (1, 5, 1));
                self.hotplug[usize::from(port) - 1] = data[0];
            }
            vec![]
        } else {
            assert_eq!(kind, PacketType::Read);
            if !target {
                let parent = self.owner.parent.as_ref().unwrap();
                assert_eq!(route, parent.path.route().raw());
                assert_eq!(space, 1);
                assert_eq!(offset, 0x42);
                assert_eq!(count, 1);
                vec![if self.mask & 16 != 0 { 1 << 9 } else { 0 }]
            } else if space == 2 {
                if offset == 6 {
                    if self.setup_written {
                        self.ready_reads += 1;
                        if self.ready_reads >= 2 && !self.hold_ready {
                            self.regs[6] |= 1 << 24;
                        }
                    }
                    if self.valid_written {
                        self.configured_reads += 1;
                        if self.configured_reads >= 2 && !self.hold_configured {
                            self.regs[6] |= 1 << 25;
                        }
                    }
                }
                self.regs[usize::from(offset)..usize::from(offset) + count].to_vec()
            } else {
                assert_eq!((space, offset, count), (1, 5, 1));
                vec![self.hotplug[usize::from(port) - 1]]
            }
        };
        words.truncate(3);
        words[0] |= 1 << 31;
        words[2] =
            (address & !(63 << 19)) | (u32::from(self.override_upstream.unwrap_or(upstream)) << 19);
        words.extend(data);
        incoming(kind, &words)
    }
}

pub(crate) fn drive_router(
    peer: &mut RouterPeer,
    domain: &Domain,
    model: &Model,
    setup: &mut super::super::super::router::Setup<Model>,
) -> super::super::super::router::Configured {
    use super::super::super::router::Event;
    assert!(setup.poll(0).unwrap().is_none());
    for n in 0..100 {
        let index = n % 10;
        let reply = peer.respond(domain, model, index);
        model.finish(Direction::Tx, index, &[], None);
        finish_rx(model, index, &reply);
        match setup.poll(n as u64 + 1).unwrap() {
            Some(Event::Configured(configured)) => return configured,
            Some(Event::Discarded(error)) => panic!("discarded {error:?}"),
            None => {}
        }
    }
    panic!("bounded router setup did not finish")
}

#[derive(Default)]
pub(crate) struct NativeCursor {
    pub(crate) tx: usize,
    pub(crate) rx: usize,
    pub(crate) now: u64,
}

pub(crate) fn configured_router(
    peer: &mut RouterPeer,
    domain: &Domain,
    model: &Model,
    setup: &mut super::super::super::router::Setup<Model>,
    cursor: &mut NativeCursor,
) -> super::super::super::router::Configured {
    use super::super::super::router::Event;
    assert!(setup.poll(cursor.now).unwrap().is_none());
    for _ in 0..100 {
        let reply = peer.respond(domain, model, cursor.tx % 10);
        model.finish(Direction::Tx, cursor.tx % 10, &[], None);
        finish_rx(model, cursor.rx % 10, &reply);
        cursor.tx += 1;
        cursor.rx += 1;
        cursor.now += 1;
        match setup.poll(cursor.now).unwrap() {
            Some(Event::Configured(value)) => return value,
            Some(Event::Discarded(error)) => panic!("{error:?}"),
            None => {}
        }
    }
    panic!("actual source router setup did not finish")
}
