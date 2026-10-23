// SPDX-License-Identifier: GPL-2.0-only
//! Independent wire peer composed with the original Controller/EP0 DMA fixture.
//! Numeric wire definitions below come from the xHCI layout, not production
//! encoding constants. The peer reads actual published contexts/TRBs, writes
//! actual DMA/event memory and enforces endpoint stop before dequeue changes.
use super::*;
use crate::{
    bus::pci::{Address, ConfigSpace, Function},
    usb::xhci::{Registers, model},
};
use alloc::{boxed::Box, rc::Rc, vec};
use core::cell::RefCell;

const ENTRY_BYTES: usize = 16;
const RING_ENTRIES: usize = 256;
const TRANSFER_EVENT: u32 = 32;
const CONFIGURE: u32 = 12;
const STOP: u32 = 15;
const SET_DEQUEUE: u32 = 16;

struct Config;
impl ConfigSpace for Config {
    fn read32(&self, at: u16) -> u32 {
        match at {
            0 => 0x0014_1b36,
            8 => 0x0c03_3001,
            _ => 0,
        }
    }
    fn write32(&mut self, _: u16, _: u32) {
        panic!("read-only qualification");
    }
}
#[derive(Clone)]
struct Td {
    endpoint: u8,
    stream: u16,
    trb: u64,
    buffer: u64,
    length: usize,
    control: u32,
}
struct Peer {
    base: Rc<RefCell<model::CancelModel>>,
    cursor: BTreeMap<(u8, u16), (u64, usize, u32)>,
    active: Vec<Td>,
    published: Vec<Td>,
    out: Vec<Vec<u8>>,
    mfindex: u32,
    fatal_after: Option<usize>,
}
impl Peer {
    fn word(at: u64) -> u32 {
        assert!(at > 65536 && at.is_multiple_of(4));
        // SAFETY: every address is decoded from a retained fixture allocation.
        unsafe { (at as *const u32).read_volatile() }
    }
    fn long(at: u64) -> u64 {
        assert!(at > 65536 && at.is_multiple_of(8));
        // SAFETY: retained aligned fixture DMA.
        unsafe { (at as *const u64).read_volatile() }
    }
    fn command(&mut self, kind: u32, parameter: u64, dci: u8, stream: u16, status: u32) {
        if status != 1 {
            return;
        }
        match kind {
            CONFIGURE => {
                let add = Self::word(parameter + 4);
                let drop = Self::word(parameter);
                let base = self.base.borrow();
                for ep in 2..32 {
                    if (add | drop) & (1 << ep) != 0 {
                        self.cursor
                            .retain(|(endpoint, _), _| usize::from(*endpoint) != ep);
                    }
                    if add & (1 << ep) != 0 {
                        let from = parameter + (ep as u64 + 1) * base.context_bytes as u64;
                        let to = base.output + ep as u64 * base.context_bytes as u64;
                        // SAFETY: real Configure Endpoint contexts retain both allocations.
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                from as *const u8,
                                to as *mut u8,
                                base.context_bytes,
                            );
                        }
                        // The hardware endpoint is Running after Configure ACK.
                        unsafe {
                            (to as *mut u32).write_volatile(Self::word(to) & !7 | 1);
                        }
                    } else if drop & (1 << ep) != 0 {
                        // SAFETY: drop context belongs to this retained slot.
                        unsafe {
                            ((base.output + ep as u64 * base.context_bytes as u64) as *mut u32)
                                .write_volatile(0);
                        }
                    }
                }
            }
            STOP => {
                self.active.retain(|td| td.endpoint != dci);
            }
            SET_DEQUEUE => {
                assert_eq!(self.base.borrow().state(usize::from(dci)), 3);
                // The acknowledged dequeue command changes the actual hardware
                // cursor; the original stream context need not be rewritten.
                self.cursor.insert(
                    (dci, stream),
                    (
                        parameter & !4095,
                        ((parameter & !15) % 4096) as usize / ENTRY_BYTES,
                        parameter as u32 & 1,
                    ),
                );
            }
            _ => {}
        }
    }
    fn doorbell(&mut self, value: u32) {
        let dci = (value & 0xff) as u8;
        let stream = (value >> 16) as u16;
        assert!(dci >= 2);
        let ep = {
            let base = self.base.borrow();
            base.output + u64::from(dci) * base.context_bytes as u64
        };
        let info = Self::word(ep);
        let dequeue = Self::long(ep + 8);
        let initial = if stream != 0 {
            assert_ne!(info & (1 << 15), 0); // LSA
            assert_ne!(info >> 10 & 31, 0); // MaxPStreams
            let context = (dequeue & !15) + u64::from(stream) * ENTRY_BYTES as u64;
            let pointer = Self::long(context);
            assert_eq!(pointer & 14, 2); // Primary Transfer Ring
            pointer
        } else {
            assert_eq!(info >> 10 & 31, 0);
            dequeue
        };
        let cursor = self.cursor.entry((dci, stream)).or_insert((
            initial & !4095,
            ((initial & !15) % 4096) as usize / ENTRY_BYTES,
            initial as u32 & 1,
        ));
        let at = cursor.0 + (cursor.1 * ENTRY_BYTES) as u64;
        let control = Self::word(at + 12);
        assert_eq!(control & 1, cursor.2);
        let kind = control >> 10 & 63;
        assert_eq!(kind, if stream == 0 { 5 } else { 1 });
        assert_ne!(control & (1 << 5), 0); // IOC
        let length = (Self::word(at + 8) & 0x1ffff) as usize;
        let buffer = Self::long(at);
        assert!(buffer % 65536 + length as u64 <= 65536);
        let td = Td {
            endpoint: dci,
            stream,
            trb: at,
            buffer,
            length,
            control,
        };
        assert!(!self.active.iter().any(|old| old.trb == at));
        self.active.push(td.clone());
        self.published.push(td);
        cursor.1 += 1;
        if cursor.1 == RING_ENTRIES - 1 {
            let link = cursor.0 + ((RING_ENTRIES - 1) * ENTRY_BYTES) as u64;
            assert_eq!(Self::long(link), cursor.0);
            assert_eq!(Self::word(link + 12) >> 10 & 63, 6);
            assert_ne!(Self::word(link + 12) & 2, 0);
            cursor.1 = 0;
            cursor.2 ^= 1;
        }
        self.base.borrow_mut().set_state(usize::from(dci), 1);
        if self.fatal_after == Some(self.published.len()) {
            self.base.borrow_mut().fatal_status = 1 << 2;
        }
    }
    fn complete(&mut self, dci: u8, stream: u16, code: u32, residual: usize, bytes: &[u8]) {
        let index = self
            .active
            .iter()
            .position(|td| td.endpoint == dci && td.stream == stream)
            .unwrap();
        let td = self.active.remove(index);
        assert!(residual <= td.length);
        if code == 6 {
            self.base.borrow_mut().set_state(usize::from(dci), 2);
        }
        if matches!(code, 1 | 13) {
            if dci & 1 != 0 {
                assert_eq!(bytes.len(), td.length - residual);
                // SAFETY: only this terminal TD's retained requested DMA extent is written.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        td.buffer as *mut u8,
                        bytes.len(),
                    );
                }
            } else {
                // SAFETY: fixture reads only the published OUT TD extent.
                self.out.push(unsafe {
                    core::slice::from_raw_parts(td.buffer as *const u8, td.length - residual)
                        .to_vec()
                });
            }
        }
        self.base
            .borrow_mut()
            .event(td.trb, code, TRANSFER_EVENT, dci, residual);
    }
}
struct RegisterPeer {
    original: Box<dyn Registers>,
    peer: Rc<RefCell<Peer>>,
}
impl Registers for RegisterPeer {
    fn read32(&mut self, at: usize) -> u32 {
        if at == 0x800 {
            self.peer.borrow().mfindex
        } else {
            self.original.read32(at)
        }
    }
    fn write32(&mut self, at: usize, value: u32) {
        if at == 0x1004 && value & 0xff != 1 {
            self.peer.borrow_mut().doorbell(value);
            return;
        }
        let command = if at == 0x1000 {
            let peer = self.peer.borrow();
            let base = peer.base.borrow();
            let at = base.commands + (base.command_index % 255 * ENTRY_BYTES) as u64;
            let control = Peer::word(at + 12);
            let kind = control >> 10 & 63;
            Some((
                kind,
                Peer::long(at),
                (control >> 16 & 31) as u8,
                (Peer::word(at + 8) >> 16) as u16,
                if let Some((wanted, status)) = base.fail {
                    if wanted == kind { status } else { 1 }
                } else {
                    1
                },
                base.silence == Some(kind),
            ))
        } else {
            None
        };
        self.original.write32(at, value);
        if let Some((kind, parameter, dci, stream, status, false)) = command {
            self.peer
                .borrow_mut()
                .command(kind, parameter, dci, stream, status);
        }
    }
}
fn fixture(dma: &mut dyn DmaAllocator, streams: bool) -> (Device, Rc<RefCell<Peer>>) {
    let mut configuration = vec![
        9, 2, 32, 0, 1, 19, 0, 0x80, 50, 9, 4, 0, 0, 2, 0xff, 0, 0, 0,
    ];
    let speed = if streams {
        xhci::SUPER_SPEED
    } else {
        xhci::FULL_SPEED
    };
    for address in [0x81, 2] {
        if streams {
            configuration.extend_from_slice(&[7, 5, address, 2, 0, 4, 0, 6, 48, 0, 2, 0, 0]);
        } else {
            configuration.extend_from_slice(&[7, 5, address, 1, 192, 0, 1]);
        }
    }
    configuration[2] = configuration.len() as u8;
    let configurations = vec![configuration];
    let mut function = Function::new(
        Address {
            segment: 0,
            bus: 0,
            device: 1,
            function: 0,
        },
        Config,
    )
    .unwrap();
    let mut peer = None;
    let (controller, _) = model::forwarding_fixture(
        dma,
        &configurations,
        speed,
        &mut function,
        |original, base| {
            let shared = Rc::new(RefCell::new(Peer {
                base,
                cursor: BTreeMap::new(),
                active: Vec::new(),
                published: Vec::new(),
                out: Vec::new(),
                mfindex: 16000,
                fatal_after: None,
            }));
            peer = Some(shared.clone());
            Box::new(RegisterPeer {
                original,
                peer: shared,
            })
        },
    );
    let mut physical = model::device(configurations);
    physical.id = controller.test_device_id(1).unwrap();
    physical.speed = speed;
    let mut owner = Device::claimed(Rc::new(RefCell::new(controller)), physical).unwrap();
    owner.configure(19, dma).unwrap();
    (owner, peer.unwrap())
}

#[test]
fn queued_packet_lists_keep_individual_payloads_residuals_misses_and_original_schedule() {
    let mut ram = vec![0u64; 512 * 1024];
    let start = ram.as_mut_ptr() as u64;
    // SAFETY: exclusive model RAM outlives all original controllers and owners.
    let mut dma = unsafe { model::RegionAllocator::new(start..start + ram.len() as u64 * 8) };
    let (mut owner, peer) = fixture(&mut dma, false);
    let first = owner
        .submit_isochronous(0x81, &[4, 5, 0], &[], &mut dma)
        .unwrap();
    let second = owner
        .submit_isochronous(0x81, &[3, 2], &[], &mut dma)
        .unwrap();
    assert!(owner.submit(0x81, 0, 1, &[]).is_err());
    assert_eq!(peer.borrow().active.len(), 5);
    assert!(owner.poll(second).unwrap().is_none());
    // Independent FS bInterval=1 => one service every frame (8 microframes).
    let controls: Vec<_> = peer
        .borrow()
        .published
        .iter()
        .map(|td| td.control)
        .collect();
    assert_eq!(controls[0] >> 20 & 2047, 2002); // ceil((MFINDEX + 10)/8)
    // This fixture advertises no Contiguous Frame ID capability: native Linux
    // scheduling keeps subsequent intervals in SIA mode, not invented frames.
    assert!(controls[1..].iter().all(|control| control & (1 << 31) != 0));
    peer.borrow_mut().complete(3, 0, 1, 0, &[1, 2, 3, 4]);
    assert!(owner.poll(first).unwrap().is_none());
    peer.borrow_mut().complete(3, 0, 13, 3, &[9, 8]);
    peer.borrow_mut().complete(3, 0, 23, 0, &[]);
    let done = owner.poll(first).unwrap().unwrap();
    assert_eq!(done.actual, Some(6));
    assert_eq!(done.packets.len(), 3);
    assert_eq!(done.packets[0].data, [1, 2, 3, 4]);
    assert_eq!(
        (
            done.packets[1].offset,
            done.packets[1].requested,
            done.packets[1].actual
        ),
        (4, 5, Some(2))
    );
    assert_eq!(
        done.packets[1].status,
        Status::Isochronous(xhci::IsoStatus::Short)
    );
    assert_eq!(
        done.packets[2].status,
        Status::Isochronous(xhci::IsoStatus::MissedService)
    );
    assert!(done.data.is_empty());
    assert!(owner.poll(first).is_err());
    peer.borrow_mut().complete(3, 0, 1, 0, &[4, 5, 6]);
    peer.borrow_mut().complete(3, 0, 1, 0, &[7, 8]);
    assert_eq!(owner.poll(second).unwrap().unwrap().actual, Some(5));
    let allocated = dma.remaining();
    let output = owner
        .submit_isochronous(2, &[2, 3], &[1, 2, 3, 4, 5], &mut dma)
        .unwrap();
    assert_eq!(dma.remaining(), allocated); // original buffers are recycled
    peer.borrow_mut().complete(4, 0, 1, 0, &[]);
    peer.borrow_mut().complete(4, 0, 1, 0, &[]);
    let done = owner.poll(output).unwrap().unwrap();
    assert_eq!(done.actual, Some(5));
    assert_eq!(peer.borrow().out, [vec![1, 2], vec![3, 4, 5]]);
    assert!(done.packets.iter().all(|packet| packet.data.is_empty()));
}

#[test]
fn cancellation_and_configuration_preserve_collected_packets_and_end_old_identities() {
    let mut ram = vec![0u64; 512 * 1024];
    let start = ram.as_mut_ptr() as u64;
    // SAFETY: exclusive live fixture DMA.
    let mut dma = unsafe { model::RegionAllocator::new(start..start + ram.len() as u64 * 8) };
    let (mut owner, peer) = fixture(&mut dma, false);
    let first = owner
        .submit_isochronous(0x81, &[2, 3], &[], &mut dma)
        .unwrap();
    let second = owner.submit_isochronous(0x81, &[4], &[], &mut dma).unwrap();
    peer.borrow_mut().complete(3, 0, 1, 0, &[7, 8]);
    owner.configure(19, &mut dma).unwrap();
    let one = owner.poll(first).unwrap().unwrap();
    assert_eq!(one.status, Status::Cancelled);
    assert_eq!(one.packets[0].data, [7, 8]);
    assert_eq!(one.packets[0].actual, Some(2));
    assert_eq!(one.packets[1].status, Status::Cancelled);
    assert_eq!(one.packets[1].actual, None);
    assert_eq!(owner.poll(second).unwrap().unwrap().packets.len(), 1);
    assert!(peer.borrow().active.is_empty());
    let fresh = owner.submit_isochronous(0x81, &[2], &[], &mut dma).unwrap();
    assert!(owner.poll(first).is_err());
    peer.borrow_mut().complete(3, 0, 1, 0, &[9, 9]);
    assert_eq!(owner.poll(fresh).unwrap().unwrap().packets[0].data, [9, 9]);
}

#[test]
fn packet_extent_limits_and_foreign_requests_cannot_publish_or_consume_dma() {
    let mut ram = vec![0u64; 512 * 1024];
    let start = ram.as_mut_ptr() as u64;
    // SAFETY: original model RAM stays exclusive for both owners.
    let mut dma = unsafe { model::RegionAllocator::new(start..start + ram.len() as u64 * 8) };
    let (mut owner, peer) = fixture(&mut dma, false);
    let (mut foreign, foreign_peer) = fixture(&mut dma, false);
    let before = dma.remaining();
    for (address, lengths, out) in [
        (0x81, vec![], vec![]),
        (0x81, vec![193], vec![]),
        (0x81, vec![1; 33], vec![]),
        (2, vec![2], vec![1]),
        (0x81, vec![1], vec![1]),
        (0x82, vec![1], vec![]),
    ] {
        assert!(
            owner
                .submit_isochronous(address, &lengths, &out, &mut dma)
                .is_err()
        );
    }
    assert_eq!(dma.remaining(), before);
    assert!(peer.borrow().published.is_empty());
    let pending = owner
        .submit_isochronous(0x81, &[1; 32], &[], &mut dma)
        .unwrap();
    assert!(foreign.poll(pending).is_err());
    assert!(foreign_peer.borrow().published.is_empty());
    for _ in 0..3 {
        owner
            .submit_isochronous(0x81, &[1; 32], &[], &mut dma)
            .unwrap();
    }
    let before = peer.borrow().published.len();
    assert!(owner.submit_isochronous(0x81, &[1], &[], &mut dma).is_err());
    assert_eq!(peer.borrow().published.len(), before);
    owner.cancel(0x81).unwrap();
    assert_eq!(owner.take_completions().len(), 4);
}

#[test]
fn failed_stop_or_post_publication_controller_failure_retains_all_original_buffers() {
    for fail_after_publication in [false, true] {
        let mut ram = vec![0u64; 512 * 1024];
        let start = ram.as_mut_ptr() as u64;
        // SAFETY: fenced owners drop before their original RAM does.
        let mut dma = unsafe { model::RegionAllocator::new(start..start + ram.len() as u64 * 8) };
        let (mut owner, peer) = fixture(&mut dma, false);
        if fail_after_publication {
            peer.borrow_mut().fatal_after = Some(1);
            assert!(
                owner
                    .submit_isochronous(0x81, &[2, 3], &[], &mut dma)
                    .is_err()
            );
        } else {
            let request = owner
                .submit_isochronous(0x81, &[2, 3], &[], &mut dma)
                .unwrap();
            peer.borrow().base.borrow_mut().fail = Some((STOP, 17));
            assert!(owner.cancel(0x81).is_err());
            assert!(owner.poll(request).is_err());
        }
        assert!(owner.fenced());
        assert_eq!(owner.iso_requests.len(), 1);
        assert!(owner.iso_spare.is_empty());
        let pending = owner.iso_requests.values().next().unwrap();
        assert_eq!(pending.buffer.len(), 65536);
        assert!(owner.take_completions().is_empty());
        assert!(!peer.borrow().active.is_empty());
        assert!(owner.submit_isochronous(0x81, &[1], &[], &mut dma).is_err());
    }
}

#[test]
fn qualified_primary_streams_reuse_original_payload_dma_and_reject_stale_streams() {
    let mut ram = vec![0u64; 512 * 1024];
    let start = ram.as_mut_ptr() as u64;
    // SAFETY: original stream arrays, rings and payload DMA remain live.
    let mut dma = unsafe { model::RegionAllocator::new(start..start + ram.len() as u64 * 8) };
    let (mut owner, peer) = fixture(&mut dma, true);
    assert!(owner.enable_streams(&[0x81, 2], 3, &mut dma).unwrap() >= 3);
    for stream in [1, 2, 3, 1] {
        let request = owner.submit(0x81, stream, 4, &[]).unwrap();
        assert!(owner.submit(0x81, stream, 4, &[]).is_err());
        assert!(owner.poll(request).unwrap().is_none());
        peer.borrow_mut()
            .complete(3, stream, 13, 1, &[stream as u8, 7, 8]);
        let done = owner.poll(request).unwrap().unwrap();
        assert_eq!(done.data, [stream as u8, 7, 8]);
        assert_eq!(done.actual, Some(3));
        assert!(owner.poll(request).is_err());
    }
    assert!(owner.submit(0x81, 0, 1, &[]).is_err());
    assert!(owner.submit(0x81, 4, 1, &[]).is_err());
    let outgoing = owner.submit(2, 2, 3, &[9, 8, 7]).unwrap();
    peer.borrow_mut().complete(4, 2, 1, 0, &[]);
    assert_eq!(owner.poll(outgoing).unwrap().unwrap().actual, Some(3));
    assert_eq!(peer.borrow().out, [vec![9, 8, 7]]);
    let pending = owner.submit(0x81, 2, 4, &[]).unwrap();
    owner.cancel(0x81).unwrap();
    assert_eq!(
        owner.poll(pending).unwrap().unwrap().status,
        Status::Cancelled
    );
    owner.configure(19, &mut dma).unwrap();
    assert!(owner.submit(0x81, 2, 4, &[]).is_err());
}

#[test]
fn transport_error_stops_all_endpoint_requests_without_reading_unknown_packet_bytes() {
    let mut ram = vec![0u64; 512 * 1024];
    let start = ram.as_mut_ptr() as u64;
    // SAFETY: original DMA remains exclusive through native endpoint retirement.
    let mut dma = unsafe { model::RegionAllocator::new(start..start + ram.len() as u64 * 8) };
    let (mut owner, peer) = fixture(&mut dma, false);
    let first = owner
        .submit_isochronous(0x81, &[2, 3], &[], &mut dma)
        .unwrap();
    let second = owner.submit_isochronous(0x81, &[4], &[], &mut dma).unwrap();
    peer.borrow_mut().complete(3, 0, 1, 0, &[5, 6]);
    assert!(owner.poll(first).unwrap().is_none());
    peer.borrow_mut().complete(3, 0, 99, 0, &[]);
    let done = owner.poll(first).unwrap().unwrap();
    assert!(matches!(done.status, Status::Failed(_)));
    assert_eq!(done.packets[0].data, [5, 6]);
    assert_eq!(
        done.packets[0].status,
        Status::Isochronous(xhci::IsoStatus::Success)
    );
    assert_eq!(done.packets[1].actual, None);
    assert!(done.packets[1].data.is_empty());
    assert!(matches!(done.packets[1].status, Status::Failed(_)));
    assert_eq!(
        owner.poll(second).unwrap().unwrap().status,
        Status::Cancelled
    );
    assert!(peer.borrow().active.is_empty());
    assert!(!owner.fenced());
    let fresh = owner.submit_isochronous(0x81, &[1], &[], &mut dma).unwrap();
    peer.borrow_mut().complete(3, 0, 1, 0, &[7]);
    assert_eq!(owner.poll(fresh).unwrap().unwrap().packets[0].data, [7]);
}
