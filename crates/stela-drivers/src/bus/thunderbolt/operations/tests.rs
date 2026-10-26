// SPDX-License-Identifier: GPL-2.0-only
use super::*;
use crate::bus::thunderbolt::{
    config::{Encoded, PacketType},
    ring::{Direction, TX_DESCRIPTOR, model::*},
    router::Configured,
};
use alloc::vec;
use core::sync::atomic::{AtomicBool, AtomicUsize};

struct Native {
    inventory: Inventory,
    operation: Operation,
    current: AtomicBool,
    router: Option<Configured>,
    dropped: Arc<AtomicUsize>,
}
// SAFETY: isolated actual configured router and serialized native model operation
// engine; model control/DP association remains retained by original ownership.
unsafe impl Owner for Native {
    fn inventory(&self) -> &Inventory {
        &self.inventory
    }
    fn operation(&self) -> Operation {
        self.operation
    }
    fn is_current(&self) -> bool {
        self.current.load(Ordering::Relaxed)
    }
}
impl Drop for Native {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
        if let Some(router) = self.router.take() {
            // SAFETY: isolated model final CM transfer keeps the original actual
            // router/operation engine retained; uncertain Arc owners never drop.
            unsafe { router.retire() };
        }
    }
}
struct Fixture {
    domain: Arc<Domain>,
    model: Arc<Model>,
    channel: Channel<Model>,
    owner: Arc<Native>,
    cursor: NativeCursor,
    router_dropped: Arc<AtomicUsize>,
}
fn fixture(operation: Operation) -> Fixture {
    let LinkFixture {
        domain,
        model,
        channel,
        parent,
        child,
        cursor,
        dropped,
        ..
    } = link_fixture_with_protocol(1, false, 0x0e0101);
    let mut inventory = parent.retained_owner().target().clone();
    inventory.header = parent.header.clone();
    let owner = Arc::new(Native {
        inventory,
        operation,
        current: AtomicBool::new(true),
        router: Some(parent),
        dropped: Arc::new(AtomicUsize::new(0)),
    });
    // SAFETY: actual isolated modeled child setup transferred to retained CM;
    // no command against that child or physical dependent tunnel is published.
    unsafe { child.retire() };
    Fixture {
        domain,
        model,
        channel,
        owner,
        cursor,
        router_dropped: dropped[0].clone(),
    }
}
struct Peer {
    header: [u32; 5],
    upstream: u8,
    metadata: u32,
    command: u32,
    reads: usize,
    unsupported: bool,
    hold: bool,
    allocated: bool,
    status: Option<u8>,
    reject: Option<usize>,
    writes: Vec<(u64, u16, Vec<u32>)>,
    data: Vec<u32>,
}
impl Peer {
    fn new(f: &Fixture) -> Self {
        Self {
            header: f.owner.inventory.header.raw,
            upstream: f.owner.inventory.upstream_port,
            metadata: 0,
            command: 0,
            reads: 0,
            unsupported: false,
            hold: false,
            allocated: false,
            status: None,
            reject: None,
            writes: vec![],
            data: (0..16).map(|n| 0xab000000 | (n * 0x104001)).collect(),
        }
    }
    fn respond(&mut self, domain: &Domain, model: &Model, index: usize) -> Encoded {
        let index = index % 10;
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
            .map(|w| u32::from_be_bytes(*w))
            .collect();
        let route = (u64::from(words[0]) << 32) | u64::from(words[1]);
        let address = words[2];
        let offset = (address & 8191) as u16;
        let count = ((address >> 13) & 63) as usize;
        assert_eq!((address >> 19) & 63, 0);
        assert_eq!((address >> 25) & 3, Space::Router as u32);
        let writing = kind == PacketType::Write;
        if writing {
            self.writes.push((route, offset, words[3..].to_vec()));
        }
        let data = match offset {
            0 => {
                assert!(!writing);
                assert_eq!(count, 5);
                self.header.to_vec()
            }
            25 => {
                assert_eq!(count, 1);
                if writing {
                    self.metadata = words[3] ^ u32::from(self.reject == Some(self.writes.len()));
                    vec![]
                } else {
                    vec![self.metadata]
                }
            }
            26 => {
                assert_eq!(count, 1);
                if writing {
                    self.command = words[3];
                    self.reads = 0;
                    vec![]
                } else {
                    if self.command & OV != 0 {
                        self.reads += 1;
                        if self.reads >= 2 && !self.hold {
                            self.command &= !OV;
                            if self.unsupported {
                                self.command |= ONS;
                            } else {
                                let status = match self.command & 65535 {
                                    0x10 => u8::from(self.allocated),
                                    0x11 => {
                                        let s = u8::from(self.allocated);
                                        if self.status.unwrap_or(s) == 0 {
                                            self.allocated = true;
                                        }
                                        s
                                    }
                                    0x12 => {
                                        let s = u8::from(!self.allocated);
                                        if self.status.unwrap_or(s) == 0 {
                                            self.allocated = false;
                                        }
                                        s
                                    }
                                    0x24 => 0,
                                    _ => panic!("unrequested operation"),
                                };
                                self.command |= u32::from(self.status.unwrap_or(status)) << 24;
                                self.metadata ^= 0xa5000000;
                            }
                        }
                    }
                    vec![self.command]
                }
            }
            9 => {
                assert!(!writing);
                assert!(count <= 16);
                self.data[..count].to_vec()
            }
            _ => panic!("unexpected router operation offset"),
        };
        words.truncate(3);
        words[0] |= 1 << 31;
        words[2] = (address & !(63 << 19)) | (u32::from(self.upstream) << 19);
        words.extend(data);
        incoming(kind, &words)
    }
}
fn step(
    peer: &mut Peer,
    domain: &Domain,
    model: &Model,
    cursor: &mut NativeCursor,
    control: &mut Control<Model>,
) -> Result<Option<Event>, Error> {
    if (model.read32(TX_DESCRIPTOR + 8) >> 16) as usize != cursor.tx % 10 {
        let reply = peer.respond(domain, model, cursor.tx);
        model.finish(Direction::Tx, cursor.tx % 10, &[], None);
        finish_rx(model, cursor.rx % 10, &reply);
        cursor.tx += 1;
        cursor.rx += 1;
    }
    cursor.now += 1;
    control.poll(cursor.now)
}
fn drive(
    peer: &mut Peer,
    domain: &Domain,
    model: &Model,
    cursor: &mut NativeCursor,
    control: &mut Control<Model>,
) -> Result<Completed, Error> {
    control.poll(cursor.now)?;
    for _ in 0..80 {
        if let Some(Event::Completed(c)) = step(peer, domain, model, cursor, control)? {
            return Ok(c);
        }
    }
    panic!("actual operation did not finish")
}
#[test]
fn actual_router_operations_query_allocate_deallocate_and_drom_retained_completion() {
    for operation in [
        Operation::QueryDp { port: 6 },
        Operation::AllocateDp { port: 6 },
        Operation::DeallocateDp { port: 6 },
        Operation::DromRead {
            dword_address: 8176,
            words: 16,
        },
    ] {
        let f = fixture(operation);
        let mut peer = Peer::new(&f);
        peer.allocated = matches!(operation, Operation::DeallocateDp { .. });
        let Fixture {
            domain,
            model,
            channel,
            mut owner,
            mut cursor,
            router_dropped,
        } = f;
        // SAFETY: actual configured router, exact isolated operation/DP grant and idle model channel.
        let mut control = unsafe { Control::new(channel, owner.clone(), cursor.now) }.unwrap();
        let completed = drive(&mut peer, &domain, &model, &mut cursor, &mut control).unwrap();
        let mut channel = control.into_channel();
        assert_eq!(completed.operation, operation);
        assert_eq!(completed.status, 0);
        let (opcode, metadata, words) = operation.parameters().unwrap();
        assert_eq!(
            peer.writes,
            vec![
                (0, 25, vec![metadata]),
                (0, 26, vec![OV | u32::from(opcode)])
            ]
        );
        assert_eq!(completed.metadata, metadata ^ 0xa5000000);
        assert_eq!(completed.data, peer.data[..usize::from(words)]);
        assert_eq!(
            Arc::strong_count(&owner),
            2,
            "original CM plus completed receipt"
        );
        assert_eq!(router_dropped.load(Ordering::Relaxed), 0);
        // SAFETY: actual isolated model completion transferred with all original owners to final CM drain.
        unsafe { completed.retire() };
        if matches!(operation, Operation::AllocateDp { .. }) {
            Arc::get_mut(&mut owner).unwrap().operation = Operation::DeallocateDp { port: 6 };
            // SAFETY: same actual original CM retains the just-allocated resource.
            let mut cleanup = unsafe { Control::new(channel, owner.clone(), cursor.now) }.unwrap();
            let freed = drive(&mut peer, &domain, &model, &mut cursor, &mut cleanup).unwrap();
            channel = cleanup.into_channel();
            assert!(!peer.allocated);
            // SAFETY: actual deallocation acknowledged and original CM retains all independent owners.
            unsafe { freed.retire() };
        }
        drop(owner);
        assert_eq!(router_dropped.load(Ordering::Relaxed), 1);
        channel_release(&mut channel);
    }
}
#[test]
fn actual_router_unsupported_and_status_failures_never_allocate_by_default() {
    for operation in [
        Operation::QueryDp { port: 6 },
        Operation::AllocateDp { port: 6 },
        Operation::DeallocateDp { port: 6 },
        Operation::DromRead {
            dword_address: 0,
            words: 4,
        },
    ] {
        for unsupported in [false, true] {
            let f = fixture(operation);
            let mut peer = Peer::new(&f);
            peer.unsupported = unsupported;
            peer.status = Some(7);
            let Fixture {
                domain,
                model,
                channel,
                owner,
                mut cursor,
                router_dropped,
            } = f;
            // SAFETY: real isolated modeled router/native resource pairing.
            let mut control = unsafe { Control::new(channel, owner.clone(), cursor.now) }.unwrap();
            let result = drive(&mut peer, &domain, &model, &mut cursor, &mut control);
            if !unsupported && matches!(operation, Operation::QueryDp { .. }) {
                let completed = result.expect("actual unavailable query");
                assert_eq!(completed.status, 7);
                drop(completed);
            } else {
                let error = match result {
                    Err(e) => e,
                    _ => panic!("unsupported/status must not grant resource"),
                };
                assert_eq!(
                    error,
                    if unsupported {
                        Error::OperationUnsupported(operation.parameters().unwrap().0)
                    } else if matches!(operation, Operation::AllocateDp { .. }) {
                        Error::ResourceBusy
                    } else {
                        Error::ResourceStatus(7)
                    }
                );
                assert!(matches!(control.poll(cursor.now + 1), Err(Error::Poisoned)));
            }
            let mut channel = control.into_channel();
            drop(owner);
            assert_eq!(router_dropped.load(Ordering::Relaxed), 0);
            assert!(!peer.allocated);
            channel_release(&mut channel);
        }
    }
}

#[test]
fn actual_dp_resource_roundtrip_preserves_real_router_and_busy_query_state() {
    let f = fixture(Operation::QueryDp { port: 6 });
    let mut peer = Peer::new(&f);
    let Fixture {
        domain,
        model,
        mut channel,
        mut owner,
        mut cursor,
        router_dropped,
    } = f;
    for (operation, status) in [
        (Operation::QueryDp { port: 6 }, 0),
        (Operation::AllocateDp { port: 6 }, 0),
        (Operation::QueryDp { port: 6 }, 1),
        (Operation::DeallocateDp { port: 6 }, 0),
        (Operation::QueryDp { port: 6 }, 0),
    ] {
        Arc::get_mut(&mut owner).unwrap().operation = operation;
        // SAFETY: native model CM serializes operations on original actual owner.
        let mut control = unsafe { Control::new(channel, owner.clone(), cursor.now) }.unwrap();
        let completed = drive(&mut peer, &domain, &model, &mut cursor, &mut control).unwrap();
        assert_eq!(completed.status, status);
        channel = control.into_channel();
        assert_eq!(router_dropped.load(Ordering::Relaxed), 0);
        // SAFETY: live original native model CM retains the exact resource and router between operations.
        unsafe { completed.retire() };
    }
    assert!(!peer.allocated);
    drop(owner);
    assert_eq!(router_dropped.load(Ordering::Relaxed), 1);
    channel_release(&mut channel);
}
#[test]
fn each_actual_operation_write_uncertainty_readback_and_busy_timeout_poison_and_retain() {
    for target in 1..=2 {
        for fault in 0..3 {
            let f = fixture(Operation::AllocateDp { port: 6 });
            let mut peer = Peer::new(&f);
            if fault == 2 {
                if target == 1 {
                    peer.reject = Some(target);
                } else {
                    peer.hold = true;
                }
            }
            let Fixture {
                domain,
                model,
                channel,
                owner,
                mut cursor,
                router_dropped,
            } = f;
            // SAFETY: exact actual isolated configured router/native operation reservation.
            let mut control = unsafe { Control::new(channel, owner.clone(), cursor.now) }.unwrap();
            control.poll(cursor.now).unwrap();
            let mut failed = false;
            for _ in 0..600 {
                if (model.read32(TX_DESCRIPTOR + 8) >> 16) as usize == cursor.tx % 10 {
                    cursor.now += 1;
                    control.poll(cursor.now).unwrap();
                    continue;
                }
                let before = peer.writes.len();
                let mut reply = peer.respond(&domain, &model, cursor.tx);
                let selected = peer.writes.len() != before && peer.writes.len() == target;
                if selected && fault == 1 {
                    reply = controller_error(&domain, &model, &cursor);
                }
                model.finish(Direction::Tx, cursor.tx % 10, &[], None);
                cursor.tx += 1;
                cursor.now += 1;
                if selected && fault == 0 {
                    cursor.now += 501;
                } else {
                    finish_rx(&model, cursor.rx % 10, &reply);
                    cursor.rx += 1;
                }
                if control.poll(cursor.now).is_err() {
                    failed = true;
                    break;
                }
            }
            assert!(failed);
            assert_eq!(peer.writes.len(), target);
            let writes = model.state.lock().unwrap().writes.len();
            assert!(matches!(control.poll(cursor.now + 1), Err(Error::Poisoned)));
            assert_eq!(writes, model.state.lock().unwrap().writes.len());
            let mut channel = control.into_channel();
            drop(owner);
            assert_eq!(router_dropped.load(Ordering::Relaxed), 0);
            channel_release(&mut channel);
        }
    }
}
#[test]
fn actual_operation_preflight_idle_header_revocation_and_ranges_refuse_publication() {
    for fault in 0..3 {
        let f = fixture(Operation::AllocateDp { port: 6 });
        let mut peer = Peer::new(&f);
        if fault == 0 {
            peer.command = OV;
            peer.hold = true;
        } else if fault == 1 {
            peer.header[0] ^= 1;
        } else {
            f.owner.current.store(false, Ordering::Relaxed);
        }
        let Fixture {
            domain,
            model,
            channel,
            owner,
            mut cursor,
            ..
        } = f;
        // SAFETY: deliberately changed actual model state is refused before mutation.
        let new = unsafe { Control::new(channel, owner.clone(), cursor.now) };
        if fault == 2 {
            assert!(matches!(new, Err(Error::Revoked)));
            continue;
        }
        let mut control = new.ok().unwrap();
        let result = drive(&mut peer, &domain, &model, &mut cursor, &mut control);
        assert!(matches!(result, Err(Error::Busy | Error::Changed)));
        assert!(peer.writes.is_empty());
        let mut channel = control.into_channel();
        channel_release(&mut channel);
    }
    for operation in [
        Operation::DromRead {
            dword_address: 8192,
            words: 1,
        },
        Operation::DromRead {
            dword_address: 8191,
            words: 2,
        },
        Operation::DromRead {
            dword_address: 0,
            words: 0,
        },
        Operation::DromRead {
            dword_address: 0,
            words: 17,
        },
        Operation::AllocateDp { port: 2 },
    ] {
        let f = fixture(operation);
        let Fixture {
            channel,
            owner,
            model,
            ..
        } = f;
        let writes = model.state.lock().unwrap().writes.len();
        // SAFETY: invalid actual request metadata is rejected before publication.
        assert!(unsafe { Control::new(channel, owner, 0) }.is_err());
        assert_eq!(writes, model.state.lock().unwrap().writes.len());
    }
}

#[test]
#[ignore = "requires pinned unchanged Linux native router operation transcript"]
fn unchanged_linux_router_operation_bytes_and_source_statuses_match_actual_native_dma() {
    extern crate std;
    let trace = std::fs::read_to_string(
        std::env::var("STELA_THUNDERBOLT_OPERATIONS_ORACLE").expect("set router operation trace"),
    )
    .unwrap();
    let mut cases = 0;
    for line in trace.lines() {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        let n = |i: usize| fields[i].parse::<u32>().unwrap();
        assert_eq!(fields[0], "O");
        let unsupported = n(2) != 0;
        let status = n(3) as u8;
        let seed = n(4);
        let operation = match n(1) {
            0 => Operation::QueryDp { port: 6 },
            1 => Operation::AllocateDp { port: 6 },
            2 => Operation::DeallocateDp { port: 6 },
            3 => Operation::DromRead {
                dword_address: n(5) as u16,
                words: n(6) as u8,
            },
            _ => panic!("source operation"),
        };
        let linux_ret = fields[7].parse::<i32>().unwrap();
        // Source wrappers intentionally treat ONS DP resource operations as a
        // successful fallback. Native code keeps unsupported explicit and never
        // fabricates a grant; verify that deliberate policy boundary separately.
        assert_eq!(
            linux_ret,
            if unsupported {
                if n(1) == 0 {
                    1
                } else if n(1) == 3 {
                    -95
                } else {
                    0
                }
            } else if n(1) == 0 {
                i32::from(status == 0)
            } else if status == 0 {
                0
            } else if n(1) == 1 {
                -16
            } else {
                -5
            }
        );
        let f = fixture(operation);
        let mut peer = Peer::new(&f);
        peer.unsupported = unsupported;
        peer.status = Some(status);
        peer.allocated = n(1) == 2;
        for (i, word) in peer.data.iter_mut().enumerate() {
            *word = 0xab000000 ^ (seed * 0x01010001) ^ (i as u32 * 0x104001);
        }
        let Fixture {
            domain,
            model,
            channel,
            mut owner,
            mut cursor,
            router_dropped,
        } = f;
        // SAFETY: actual configured native model router and protected source operation association.
        let mut control = unsafe { Control::new(channel, owner.clone(), cursor.now) }.unwrap();
        let result = drive(&mut peer, &domain, &model, &mut cursor, &mut control);
        let count = n(8) as usize;
        assert_eq!(peer.writes.len(), count);
        let mut at = 9;
        for (route, offset, data) in &peer.writes {
            assert_eq!(*route, 0);
            assert_eq!(u32::from(*offset), n(at));
            assert_eq!(data.len(), n(at + 1) as usize);
            at += 2;
            for word in data {
                assert_eq!(*word, n(at), "case {}", cases);
                at += 1;
            }
        }
        assert_eq!(peer.metadata, n(at));
        assert_eq!(peer.command, n(at + 1));
        at += 2;
        let expect_error = if unsupported {
            Some(Error::OperationUnsupported(
                operation.parameters().unwrap().0,
            ))
        } else if status != 0 && n(1) == 1 {
            Some(Error::ResourceBusy)
        } else if status != 0 && n(1) >= 2 {
            Some(Error::ResourceStatus(status))
        } else {
            None
        };
        match (expect_error, result) {
            (Some(expected), Err(actual)) => {
                assert_eq!(actual, expected);
                if n(1) == 3 && !unsupported {
                    assert_eq!(control.data, (at..fields.len()).map(n).collect::<Vec<_>>());
                }
            }
            (None, Ok(completed)) => {
                assert_eq!(completed.status, status);
                assert_eq!(completed.metadata, peer.metadata);
                if n(1) == 3 {
                    assert_eq!(
                        completed.data,
                        (at..fields.len()).map(n).collect::<Vec<_>>()
                    );
                } else {
                    assert!(completed.data.is_empty());
                }
                // SAFETY: source fixture final native CM transfer keeps any allocated real model resource owned.
                unsafe { completed.retire() };
            }
            _ => panic!(
                "source case {} produced wrong native resource result",
                cases
            ),
        }
        if n(1) == 3 {
            at += n(6) as usize;
        }
        assert_eq!(at, fields.len());
        let mut channel = control.into_channel();
        if expect_error.is_none() && matches!(operation, Operation::AllocateDp { .. }) {
            Arc::get_mut(&mut owner).unwrap().operation = Operation::DeallocateDp { port: 6 };
            // SAFETY: original actual CM still owns the successfully allocated model resource.
            let mut cleanup = unsafe { Control::new(channel, owner.clone(), cursor.now) }.unwrap();
            let freed = drive(&mut peer, &domain, &model, &mut cursor, &mut cleanup).unwrap();
            channel = cleanup.into_channel();
            assert!(!peer.allocated);
            // SAFETY: real second native deallocation completed before final owner retirement.
            unsafe { freed.retire() };
        }
        drop(owner);
        assert_eq!(
            router_dropped.load(Ordering::Relaxed),
            usize::from(expect_error.is_none())
        );
        channel_release(&mut channel);
        cases += 1;
    }
    assert_eq!(cases, 512);
}

#[test]
fn actual_router_admission_loss_after_metadata_or_command_write_retains_original_engine() {
    for target in 1..=2 {
        let f = fixture(Operation::AllocateDp { port: 6 });
        let mut peer = Peer::new(&f);
        let Fixture {
            domain,
            model,
            channel,
            owner,
            mut cursor,
            router_dropped,
        } = f;
        // SAFETY: exact configured native model controller/router reservation.
        let mut control = unsafe { Control::new(channel, owner.clone(), cursor.now) }.unwrap();
        control.poll(cursor.now).unwrap();
        let mut revoked = false;
        for _ in 0..40 {
            if (model.read32(TX_DESCRIPTOR + 8) >> 16) as usize != cursor.tx % 10 {
                let reply = peer.respond(&domain, &model, cursor.tx);
                model.finish(Direction::Tx, cursor.tx % 10, &[], None);
                finish_rx(&model, cursor.rx % 10, &reply);
                cursor.tx += 1;
                cursor.rx += 1;
                if peer.writes.len() == target {
                    owner.current.store(false, Ordering::Relaxed);
                    revoked = true;
                }
            }
            cursor.now += 1;
            if revoked {
                assert!(matches!(control.poll(cursor.now), Err(Error::Revoked)));
                break;
            }
            control.poll(cursor.now).unwrap();
        }
        assert!(revoked);
        assert_eq!(peer.writes.len(), target);
        let writes = model.state.lock().unwrap().writes.len();
        owner.current.store(true, Ordering::Relaxed);
        assert!(matches!(control.poll(cursor.now + 1), Err(Error::Poisoned)));
        assert_eq!(writes, model.state.lock().unwrap().writes.len());
        let mut channel = control.into_channel();
        drop(owner);
        assert_eq!(router_dropped.load(Ordering::Relaxed), 0);
        channel_release(&mut channel);
    }
}
