// SPDX-License-Identifier: GPL-2.0-only
//! Independent wire peer composed with the original Controller/EP0 DMA fixture.
//! Numeric wire definitions below come from the xHCI layout, not production
//! encoding constants. The peer reads published contexts/TRBs, writes
//! DMA/event memory and enforces endpoint stop before dequeue changes.
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
    advance_after: Option<(usize, u32)>,
    explicit_next: BTreeMap<u8, u32>,
    stop_event: Option<(u8, u32, usize, Vec<u8>)>,
    trap_mmio: bool,
}
impl Peer {
    fn word(at: u64) -> u32 {
        assert!(at > 65536 && at.is_multiple_of(4));
        // SAFETY: every address is decoded from a fixture allocation.
        unsafe { (at as *const u32).read_volatile() }
    }
    fn long(at: u64) -> u64 {
        assert!(at > 65536 && at.is_multiple_of(8));
        // SAFETY: aligned fixture DMA.
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
                        self.explicit_next.remove(&(ep as u8));
                        self.cursor
                            .retain(|(endpoint, _), _| usize::from(*endpoint) != ep);
                    }
                    if add & (1 << ep) != 0 {
                        let from = parameter + (ep as u64 + 1) * base.context_bytes as u64;
                        let to = base.output + ep as u64 * base.context_bytes as u64;
                        // SAFETY: real Configure Endpoint contexts keep both allocations.
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                from as *const u8,
                                to as *mut u8,
                                base.context_bytes,
                            );
                        }
                        // The hardware endpoint is Running after Configure ACK.
                        // SAFETY: the pointer addresses live memory this test's model owns, in
                        // bounds, and nothing accesses it concurrently.
                        unsafe {
                            (to as *mut u32).write_volatile(Self::word(to) & !7 | 1);
                        }
                    } else if drop & (1 << ep) != 0 {
                        // SAFETY: drop context belongs to this slot.
                        unsafe {
                            ((base.output + ep as u64 * base.context_bytes as u64) as *mut u32)
                                .write_volatile(0);
                        }
                    }
                }
            }
            STOP => {
                self.explicit_next.remove(&dci);
                self.active.retain(|td| td.endpoint != dci);
            }
            SET_DEQUEUE => {
                assert_eq!(self.base.borrow().state(usize::from(dci)), 3);
                // The acknowledged dequeue command changes the hardware
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
        let endpoint_type = Self::word(ep + 4) >> 3 & 7;
        assert_eq!(kind, if matches!(endpoint_type, 1 | 5) { 5 } else { 1 });
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
        if let Some((count, now)) = self.advance_after
            && count == self.published.len()
        {
            self.mfindex = now;
        }
    }
    fn service_explicit(&mut self, dci: u8, target: u32, code: u32, residual: usize, bytes: &[u8]) {
        assert!(target < 16384);
        let ep = {
            let base = self.base.borrow();
            base.output + u64::from(dci) * base.context_bytes as u64
        };
        // Interval comes from the configured endpoint context; Frame ID
        // and CFC's implicit subframe progression come from published wire TDs.
        let interval = 1u32 << (Self::word(ep) >> 16 & 0xff);
        assert!(target.is_multiple_of(interval));
        let td = self.active.iter().find(|td| td.endpoint == dci).unwrap();
        assert_eq!(td.control & (1 << 31), 0);
        assert_eq!(td.control >> 20 & 2047, target / 8);
        if let Some(next) = self.explicit_next.get(&dci) {
            assert_eq!(*next, target);
        } else {
            assert!(target.is_multiple_of(8));
        }
        self.mfindex = target;
        self.complete(dci, 0, code, residual, bytes);
        if self.active.iter().any(|td| td.endpoint == dci) {
            self.explicit_next.insert(dci, (target + interval) % 16384);
        } else {
            self.explicit_next.remove(&dci);
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
        if matches!(code, 1 | 13 | 26 | 28) {
            // Stopped Short Packet reports bytes, unlike the residual
            // field used by Success, Short Packet and Stopped.
            let actual = if code == 28 {
                residual
            } else {
                td.length - residual
            };
            if dci & 1 != 0 {
                assert_eq!(bytes.len(), actual);
                // SAFETY: only this terminal TD's requested DMA extent is written.
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
                    core::slice::from_raw_parts(td.buffer as *const u8, actual).to_vec()
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
        assert!(
            !self.peer.borrow().trap_mmio,
            "stale owner reached MMIO read"
        );
        if at == 0x800 {
            self.peer.borrow().mfindex
        } else {
            self.original.read32(at)
        }
    }
    fn write32(&mut self, at: usize, value: u32) {
        assert!(
            !self.peer.borrow().trap_mmio,
            "stale owner reached MMIO write"
        );
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
        if let Some((STOP, _, dci, _, _, _)) = command {
            let event = self.peer.borrow_mut().stop_event.take();
            if let Some((endpoint, code, residual, bytes)) = event {
                assert_eq!(endpoint, dci);
                self.peer
                    .borrow_mut()
                    .complete(dci, 0, code, residual, &bytes);
            }
        }
        self.original.write32(at, value);
        if let Some((kind, parameter, dci, stream, status, false)) = command {
            self.peer
                .borrow_mut()
                .command(kind, parameter, dci, stream, status);
        }
    }
}
fn fixture(dma: &mut dyn DmaAllocator, streams: bool) -> (Device, Rc<RefCell<Peer>>) {
    fixture_with_schedule(
        dma,
        streams,
        if streams {
            xhci::SUPER_SPEED
        } else {
            xhci::FULL_SPEED
        },
        1,
        None,
    )
}

fn fixture_with_schedule(
    dma: &mut dyn DmaAllocator,
    streams: bool,
    speed: u8,
    interval: u8,
    capabilities: Option<(u16, u32, u32)>,
) -> (Device, Rc<RefCell<Peer>>) {
    let mut configuration = vec![
        9, 2, 32, 0, 1, 19, 0, 0x80, 50, 9, 4, 0, 0, 2, 0xff, 0, 0, 0,
    ];
    for address in [0x81, 2] {
        if streams {
            configuration.extend_from_slice(&[7, 5, address, 2, 0, 4, 0, 6, 48, 0, 2, 0, 0]);
        } else {
            configuration.extend_from_slice(&[7, 5, address, 1, 192, 0, interval]);
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
    let wrap = |original, base| {
        let shared = Rc::new(RefCell::new(Peer {
            base,
            cursor: BTreeMap::new(),
            active: Vec::new(),
            published: Vec::new(),
            out: Vec::new(),
            mfindex: 16000,
            fatal_after: None,
            advance_after: None,
            explicit_next: BTreeMap::new(),
            stop_event: None,
            trap_mmio: false,
        }));
        peer = Some(shared.clone());
        Box::new(RegisterPeer {
            original,
            peer: shared,
        }) as Box<dyn Registers>
    };
    let (controller, _) = if let Some((version, hcs2, hcc1)) = capabilities {
        model::forwarding_scheduled_fixture(
            dma,
            &configurations,
            speed,
            &mut function,
            model::CapabilityImage {
                version,
                hcs2,
                hcc1,
            },
            wrap,
        )
    } else {
        model::forwarding_fixture(dma, &configurations, speed, &mut function, wrap)
    };
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
    assert_eq!(owner.take_completions().unwrap().len(), 4);
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
        assert!(owner.take_completions().unwrap().is_empty());
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
fn cancellation_preserves_unpolled_terminal_receipts_for_each_transfer_kind() {
    for kind in 0..3 {
        let mut ram = vec![0u64; 512 * 1024];
        let start = ram.as_mut_ptr() as u64;
        // SAFETY: original payload, endpoint and event DMA outlive retirement.
        let mut dma = unsafe { model::RegionAllocator::new(start..start + ram.len() as u64 * 8) };
        let (mut owner, peer) = fixture(&mut dma, kind != 2);
        let stream = if kind == 1 {
            owner.enable_streams(&[0x81, 2], 3, &mut dma).unwrap();
            2
        } else {
            0
        };
        let original = owner.pipes[&0x81].buffer.physical();
        let request = owner.submit(0x81, stream, 5, &[]).unwrap();
        peer.borrow_mut().complete(3, stream, 13, 2, &[1, 2, 3]);
        owner.cancel(0x81).unwrap();
        let done = owner.poll(request).unwrap().unwrap();
        assert_eq!(done.actual, Some(3));
        assert_eq!(done.data, [1, 2, 3]);
        assert_eq!(
            done.status,
            if kind == 2 {
                Status::Isochronous(xhci::IsoStatus::Short)
            } else {
                Status::Complete
            }
        );
        assert!(peer.borrow().base.borrow().seen.contains(&STOP));
        assert!(peer.borrow().base.borrow().seen.contains(&SET_DEQUEUE));
        assert!(owner.poll(request).is_err());
        let fresh = owner.submit(0x81, stream, 1, &[]).unwrap();
        assert_eq!(owner.pipes[&0x81].buffer.physical(), original);
        peer.borrow_mut().complete(3, stream, 1, 0, &[9]);
        assert_eq!(owner.poll(fresh).unwrap().unwrap().data, [9]);
    }
}

#[test]
fn ordinary_cancellation_preserves_receive_boundaries_racing_actual_stop() {
    for code in [1, 13, 26, 28] {
        for failure in [None, Some(STOP), Some(SET_DEQUEUE)] {
            let mut ram = vec![0u64; 512 * 1024];
            let start = ram.as_mut_ptr() as u64;
            // SAFETY: failed acknowledgements keep every original allocation.
            let mut dma =
                unsafe { model::RegionAllocator::new(start..start + ram.len() as u64 * 8) };
            let (mut owner, peer) = fixture(&mut dma, true);
            let original = owner.pipes[&0x81].buffer.physical();
            let request = owner.submit(0x81, 0, 7, &[]).unwrap();
            peer.borrow_mut().stop_event =
                Some((3, code, if code == 28 { 3 } else { 4 }, vec![4, 5, 6]));
            peer.borrow().base.borrow_mut().fail = failure.map(|command| (command, 17));
            if failure.is_some() {
                assert!(owner.cancel(0x81).is_err());
                assert!(owner.fenced());
                assert_eq!(owner.pipes[&0x81].buffer.physical(), original);
                assert_eq!(
                    owner.pipes[&0x81].pending.as_ref().unwrap().request,
                    request
                );
                assert!(owner.take_completions().unwrap().is_empty());
                assert!(owner.poll(request).is_err());
                assert!(owner.submit(0x81, 0, 7, &[]).is_err());
                continue;
            }
            owner.cancel(0x81).unwrap();
            let done = owner.poll(request).unwrap().unwrap();
            assert_eq!(done.actual, Some(3));
            assert_eq!(done.data, [4, 5, 6]);
            assert_eq!(
                done.status,
                if matches!(code, 1 | 13) {
                    Status::Complete
                } else {
                    Status::Cancelled
                }
            );
            assert!(!owner.fenced());
            assert!(owner.poll(request).is_err());
        }
    }
}

#[test]
fn explicit_cancellation_preserves_observed_transport_errors_and_failed_ack_ownership() {
    for kind in 0..4 {
        for failed_ack in [false, true] {
            let mut ram = vec![0u64; 512 * 1024];
            let start = ram.as_mut_ptr() as u64;
            // SAFETY: no failed retirement releases or reallocates this DMA.
            let mut dma =
                unsafe { model::RegionAllocator::new(start..start + ram.len() as u64 * 8) };
            let (mut owner, peer) = fixture(&mut dma, kind < 2);
            let stream = if kind == 1 {
                owner.enable_streams(&[0x81, 2], 3, &mut dma).unwrap();
                1
            } else {
                0
            };
            let request = if kind == 3 {
                owner
                    .submit_isochronous(0x81, &[5, 2], &[], &mut dma)
                    .unwrap()
            } else {
                owner.submit(0x81, stream, 5, &[]).unwrap()
            };
            let original = if kind == 3 {
                owner.iso_requests[&request].buffer.physical()
            } else {
                owner.pipes[&0x81].buffer.physical()
            };
            peer.borrow_mut().complete(3, stream, 99, 0, &[]);
            if failed_ack {
                peer.borrow().base.borrow_mut().fail = Some((SET_DEQUEUE, 17));
                assert!(owner.cancel(0x81).is_err());
                assert!(owner.fenced());
                if kind == 3 {
                    assert_eq!(owner.iso_requests[&request].buffer.physical(), original);
                    assert!(owner.iso_spare.is_empty());
                } else {
                    assert_eq!(owner.pipes[&0x81].buffer.physical(), original);
                    assert_eq!(
                        owner.pipes[&0x81].pending.as_ref().unwrap().request,
                        request
                    );
                }
                assert!(owner.take_completions().unwrap().is_empty());
                continue;
            }
            owner.cancel(0x81).unwrap();
            let done = owner.poll(request).unwrap().unwrap();
            assert!(matches!(done.status, Status::Failed(_)));
            assert_eq!(done.actual, None);
            assert!(done.data.is_empty());
            assert!(done.packets.iter().all(|packet| {
                matches!(packet.status, Status::Failed(_))
                    && packet.actual.is_none()
                    && packet.data.is_empty()
            }));
            assert!(!owner.fenced());
            assert!(owner.poll(request).is_err());
        }
    }
}

#[test]
fn retired_request_refuses_before_mmio_and_preserves_current_unpolled_completion() {
    let mut ram = vec![0u64; 512 * 1024];
    let start = ram.as_mut_ptr() as u64;
    // SAFETY: current and retired request records share kept fixture DMA.
    let mut dma = unsafe { model::RegionAllocator::new(start..start + ram.len() as u64 * 8) };
    let (mut owner, peer) = fixture(&mut dma, true);
    let old = owner.submit(0x81, 0, 2, &[]).unwrap();
    peer.borrow_mut().complete(3, 0, 1, 0, &[1, 2]);
    assert_eq!(owner.poll(old).unwrap().unwrap().data, [1, 2]);
    let fresh = owner.submit(0x81, 0, 3, &[]).unwrap();
    peer.borrow_mut().complete(3, 0, 1, 0, &[7, 8, 9]);
    let before = ram.clone();
    let commands = peer.borrow().base.borrow().seen.clone();
    peer.borrow_mut().trap_mmio = true;
    for retired in [old, Request(u64::MAX)] {
        assert_eq!(
            owner.poll(retired),
            Err(BlockError::Unsupported(
                "stale or foreign forwarded USB request",
            ))
        );
        assert_eq!(owner.pipes[&0x81].pending.as_ref().unwrap().request, fresh);
        assert_eq!(ram, before);
        assert_eq!(peer.borrow().base.borrow().seen, commands);
    }
    peer.borrow_mut().trap_mmio = false;
    assert_eq!(owner.poll(fresh).unwrap().unwrap().data, [7, 8, 9]);
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
    // The endpoint's observed transport failure also fences the uncompleted
    // sibling; cancellation cannot relabel that failed observation as success.
    assert!(matches!(
        owner.poll(second).unwrap().unwrap().status,
        Status::Failed(_)
    ));
    assert!(peer.borrow().active.is_empty());
    assert!(!owner.fenced());
    let fresh = owner.submit_isochronous(0x81, &[1], &[], &mut dma).unwrap();
    peer.borrow_mut().complete(3, 0, 1, 0, &[7]);
    assert_eq!(owner.poll(fresh).unwrap().unwrap().packets[0].data, [7]);
}

fn scheduled_refused_without_publication(
    owner: &mut Device,
    peer: &Rc<RefCell<Peer>>,
    dma: &mut model::RegionAllocator,
    lengths: &[usize],
    target: u16,
) {
    let remaining = dma.remaining();
    let requests: Vec<_> = owner.iso_requests.keys().copied().collect();
    let completed = owner.completed.clone();
    let spare: Vec<_> = owner.iso_spare.iter().map(DmaBuffer::physical).collect();
    let cursors = peer.borrow().cursor.clone();
    let published = peer.borrow().published.len();
    let active: Vec<_> = peer
        .borrow()
        .active
        .iter()
        .map(|td| (td.trb, td.buffer, td.length, td.control))
        .collect();
    let commands = peer.borrow().base.borrow().command_index;
    assert!(
        owner
            .submit_isochronous_scheduled(
                0x81,
                lengths,
                &[],
                xhci::IsoSchedule::AtMicroframe(target),
                dma,
            )
            .is_err()
    );
    assert!(!owner.fenced());
    assert_eq!(dma.remaining(), remaining);
    assert_eq!(
        owner.iso_requests.keys().copied().collect::<Vec<_>>(),
        requests
    );
    assert_eq!(owner.completed, completed);
    assert_eq!(
        owner
            .iso_spare
            .iter()
            .map(DmaBuffer::physical)
            .collect::<Vec<_>>(),
        spare
    );
    let peer = peer.borrow();
    assert_eq!(peer.cursor, cursors);
    assert_eq!(peer.published.len(), published);
    assert_eq!(
        peer.active
            .iter()
            .map(|td| (td.trb, td.buffer, td.length, td.control))
            .collect::<Vec<_>>(),
        active
    );
    assert_eq!(peer.base.borrow().command_index, commands);
}

#[test]
fn explicit_single_packet_uses_requested_frame_and_cannot_fallback_without_cfc() {
    let mut ram = vec![0u64; 512 * 1024];
    let start = ram.as_mut_ptr() as u64;
    // SAFETY: original model RAM is held through terminal events and cancel ACK.
    let mut dma = unsafe { model::RegionAllocator::new(start..start + ram.len() as u64 * 8) };
    let (mut owner, peer) = fixture(&mut dma, false);
    // This fixture has no Contiguous Frame ID capability. A two-packet
    // request must fail as a whole before its otherwise-valid first TD escapes.
    scheduled_refused_without_publication(&mut owner, &peer, &mut dma, &[2, 3], 16032);
    let request = owner
        .submit_isochronous_scheduled(
            0x81,
            &[3],
            &[],
            xhci::IsoSchedule::AtMicroframe(16032),
            &mut dma,
        )
        .unwrap();
    let control = peer.borrow().published[0].control;
    assert_eq!(control >> 20 & 2047, 2004);
    assert_eq!(control & (1 << 31), 0);
    assert!(owner.poll(request).unwrap().is_none());
    // Even the exact next frame is not an explicit continuation on this host.
    // Rejection must preserve the original pending request and its DMA.
    scheduled_refused_without_publication(&mut owner, &peer, &mut dma, &[1], 16040);
    assert!(owner.poll(request).unwrap().is_none());
    peer.borrow_mut().mfindex = 16032;
    peer.borrow_mut().complete(3, 0, 13, 1, &[0x31, 0x32]);
    let done = owner.poll(request).unwrap().unwrap();
    assert_eq!(done.status, Status::Complete);
    assert_eq!(done.actual, Some(2));
    assert_eq!(done.packets[0].data, [0x31, 0x32]);
    assert_eq!(done.packets[0].requested, 3);
    assert_eq!(
        done.packets[0].status,
        Status::Isochronous(xhci::IsoStatus::Short)
    );
    assert!(owner.poll(request).is_err());
}

#[test]
fn explicit_packet_request_rejects_past_alignment_and_ambiguous_epochs_before_allocation() {
    let mut ram = vec![0u64; 512 * 1024];
    let start = ram.as_mut_ptr() as u64;
    // SAFETY: exclusive fixture RAM remains live until the native owner drops.
    let mut dma = unsafe { model::RegionAllocator::new(start..start + ram.len() as u64 * 8) };
    let (mut owner, peer) = fixture(&mut dma, false);
    for target in [15992, 16000, 16008, 16017, 0x4000, u16::MAX] {
        scheduled_refused_without_publication(&mut owner, &peer, &mut dma, &[1], target);
    }
    peer.borrow_mut().mfindex = 0;
    for target in [0, 8, 896 * 8, 1024 * 8, 2047 * 8] {
        scheduled_refused_without_publication(&mut owner, &peer, &mut dma, &[1], target);
    }
    assert!(peer.borrow().published.is_empty());
    assert!(owner.iso_requests.is_empty());
}

#[test]
fn explicit_request_cancellation_and_configuration_retire_original_identities() {
    let mut ram = vec![0u64; 512 * 1024];
    let start = ram.as_mut_ptr() as u64;
    // SAFETY: original packet DMA remains live through endpoint Stop/Dequeue ACK.
    let mut dma = unsafe { model::RegionAllocator::new(start..start + ram.len() as u64 * 8) };
    let (mut owner, peer) = fixture(&mut dma, false);
    let first = owner
        .submit_isochronous_scheduled(
            0x81,
            &[3],
            &[],
            xhci::IsoSchedule::AtMicroframe(16032),
            &mut dma,
        )
        .unwrap();
    owner.cancel(0x81).unwrap();
    assert!(peer.borrow().active.is_empty());
    let done = owner.poll(first).unwrap().unwrap();
    assert_eq!(done.status, Status::Cancelled);
    assert_eq!(done.packets[0].actual, None);
    assert!(done.packets[0].data.is_empty());
    let remaining = dma.remaining();
    let second = owner
        .submit_isochronous_scheduled(
            0x81,
            &[3],
            &[],
            xhci::IsoSchedule::AtMicroframe(16048),
            &mut dma,
        )
        .unwrap();
    assert_eq!(dma.remaining(), remaining);
    assert_ne!(second, first);
    assert!(owner.poll(first).is_err());
    owner.configure(19, &mut dma).unwrap();
    assert!(peer.borrow().active.is_empty());
    assert_eq!(
        owner.poll(second).unwrap().unwrap().status,
        Status::Cancelled
    );
    let fresh = owner
        .submit_isochronous_scheduled(
            0x81,
            &[2],
            &[],
            xhci::IsoSchedule::AtMicroframe(16064),
            &mut dma,
        )
        .unwrap();
    assert!(owner.poll(second).is_err());
    peer.borrow_mut().mfindex = 16064;
    peer.borrow_mut().complete(3, 0, 1, 0, &[0x71, 0x72]);
    let done = owner.poll(fresh).unwrap().unwrap();
    assert_eq!(done.packets[0].data, [0x71, 0x72]);
    assert_eq!(done.packets[0].actual, Some(2));
    owner.shutdown().unwrap();
    let published = peer.borrow().published.len();
    assert!(
        owner
            .submit_isochronous_scheduled(
                0x81,
                &[1],
                &[],
                xhci::IsoSchedule::AtMicroframe(16080),
                &mut dma,
            )
            .is_err()
    );
    assert_eq!(peer.borrow().published.len(), published);
}

#[test]
fn explicit_packet_lists_wrap_real_microframes_and_keep_subframe_queue_continuations() {
    let mut ram = vec![0u64; 512 * 1024];
    let start = ram.as_mut_ptr() as u64;
    // SAFETY: every TD/event/payload is within this independent RAM.
    let mut dma = unsafe { model::RegionAllocator::new(start..start + ram.len() as u64 * 8) };
    let (mut owner, peer) = fixture_with_schedule(
        &mut dma,
        false,
        xhci::HIGH_SPEED,
        1,
        Some((0x110, 0xb, 1 << 11)),
    );
    peer.borrow_mut().mfindex = 16300;
    let mut lengths = vec![3; 16];
    lengths[2] = 0;
    let first = owner
        .submit_isochronous_scheduled(
            0x81,
            &lengths,
            &[],
            xhci::IsoSchedule::AtMicroframe(16376),
            &mut dma,
        )
        .unwrap();
    let second = owner
        .submit_isochronous_scheduled(
            0x81,
            &[2, 2],
            &[],
            xhci::IsoSchedule::AtMicroframe(8),
            &mut dma,
        )
        .unwrap();
    assert_eq!(peer.borrow().published.len(), 18);
    for (index, td) in peer.borrow().published.iter().enumerate() {
        let target = (16376 + index as u32) % 16384;
        assert_eq!(td.control & (1 << 31), 0);
        assert_eq!(td.control >> 20 & 2047, target / 8);
    }
    assert!(owner.poll(second).unwrap().is_none());
    let mut completed = None;
    for (index, length) in lengths.iter().copied().enumerate() {
        let target = (16376 + index as u32) % 16384;
        let (code, residual, bytes) = match index {
            1 => (13, 1, vec![0x81, 0x82]),
            5 => (23, length, vec![]),
            _ => (1, 0, vec![index as u8; length]),
        };
        peer.borrow_mut()
            .service_explicit(3, target, code, residual, &bytes);
        let done = owner.poll(first).unwrap();
        if index + 1 == lengths.len() {
            completed = done;
        } else {
            assert!(done.is_none());
        }
    }
    let done = completed.unwrap();
    assert_eq!(done.status, Status::Complete);
    assert_eq!(done.packets.len(), 16);
    assert_eq!(done.actual, Some(41)); // 14*3 minus one short byte; zero/miss are holes.
    assert!(done.data.is_empty());
    for (index, packet) in done.packets.iter().enumerate() {
        assert_eq!(packet.requested, lengths[index]);
        if index == 1 {
            assert_eq!(packet.actual, Some(2));
            assert_eq!(packet.data, [0x81, 0x82]);
            assert_eq!(packet.status, Status::Isochronous(xhci::IsoStatus::Short));
        } else if index == 5 {
            assert_eq!(packet.actual, Some(0));
            assert!(packet.data.is_empty());
            assert_eq!(
                packet.status,
                Status::Isochronous(xhci::IsoStatus::MissedService)
            );
        } else {
            assert_eq!(packet.actual, Some(lengths[index]));
            assert_eq!(packet.data, vec![index as u8; lengths[index]]);
        }
    }
    assert!(owner.poll(first).is_err());
    for target in [8, 9] {
        peer.borrow_mut()
            .service_explicit(3, target, 1, 0, &[0xc1, 0xc2]);
    }
    let done = owner.poll(second).unwrap().unwrap();
    assert_eq!(done.actual, Some(4));
    assert!(
        done.packets
            .iter()
            .all(|packet| packet.data == [0xc1, 0xc2])
    );
}

#[test]
fn explicit_preflight_uses_actual_interval_and_checks_entire_list_horizon_without_cancel() {
    let mut ram = vec![0u64; 512 * 1024];
    let start = ram.as_mut_ptr() as u64;
    // SAFETY: original addressed endpoint contexts and payload DMA remain live.
    let mut dma = unsafe { model::RegionAllocator::new(start..start + ram.len() as u64 * 8) };
    let (mut owner, peer) = fixture_with_schedule(
        &mut dma,
        false,
        xhci::FULL_SPEED,
        2,
        Some((0x110, 0, 1 << 11)),
    );
    let first = owner
        .submit_isochronous_scheduled(
            0x81,
            &[1, 2],
            &[],
            xhci::IsoSchedule::AtMicroframe(16032),
            &mut dma,
        )
        .unwrap();
    // FS bInterval=2 configures a 16-microframe interval. Neither an
    // aligned gap nor a copied descriptor's wrong phase can change that queue.
    for target in [16056, 16080, 16032] {
        scheduled_refused_without_publication(&mut owner, &peer, &mut dma, &[1], target);
    }
    assert!(owner.poll(first).unwrap().is_none());
    let second = owner
        .submit_isochronous_scheduled(
            0x81,
            &[1, 1],
            &[],
            xhci::IsoSchedule::AtMicroframe(16064),
            &mut dma,
        )
        .unwrap();
    for (target, bytes) in [
        (16032, vec![1]),
        (16048, vec![2, 3]),
        (16064, vec![4]),
        (16080, vec![5]),
    ] {
        peer.borrow_mut().service_explicit(3, target, 1, 0, &bytes);
    }
    assert_eq!(owner.poll(first).unwrap().unwrap().actual, Some(3));
    assert_eq!(owner.poll(second).unwrap().unwrap().actual, Some(2));

    let (mut high, high_peer) = fixture_with_schedule(
        &mut dma,
        false,
        xhci::HIGH_SPEED,
        1,
        Some((0x110, 0xb, 1 << 11)),
    );
    high_peer.borrow_mut().mfindex = 0;
    // A valid first target cannot publish if a later packet crosses frame 895.
    scheduled_refused_without_publication(&mut high, &high_peer, &mut dma, &[1; 9], 895 * 8);
    for target in [32, 41] {
        scheduled_refused_without_publication(&mut high, &high_peer, &mut dma, &[1], target);
    }
    assert!(high_peer.borrow().published.is_empty());
}

#[test]
fn explicit_clock_advance_during_publication_requires_real_endpoint_cancellation() {
    let mut ram = vec![0u64; 512 * 1024];
    let start = ram.as_mut_ptr() as u64;
    // SAFETY: original buffers remain held until real endpoint retirement ACK.
    let mut dma = unsafe { model::RegionAllocator::new(start..start + ram.len() as u64 * 8) };
    let (mut owner, peer) = fixture_with_schedule(
        &mut dma,
        false,
        xhci::FULL_SPEED,
        1,
        Some((0x110, 0, 1 << 11)),
    );
    let earlier = owner
        .submit_isochronous_scheduled(
            0x81,
            &[2],
            &[],
            xhci::IsoSchedule::AtMicroframe(16032),
            &mut dma,
        )
        .unwrap();
    peer.borrow_mut().advance_after = Some((2, 16048));
    assert!(
        owner
            .submit_isochronous_scheduled(
                0x81,
                &[2, 3],
                &[],
                xhci::IsoSchedule::AtMicroframe(16040),
                &mut dma,
            )
            .is_err()
    );
    assert!(!owner.fenced());
    assert_eq!(peer.borrow().published.len(), 2); // third TD was never published.
    assert!(peer.borrow().active.is_empty());
    assert!(peer.borrow().base.borrow().seen.contains(&STOP));
    assert!(peer.borrow().base.borrow().seen.contains(&SET_DEQUEUE));
    assert!(owner.iso_requests.is_empty());
    let done = owner.poll(earlier).unwrap().unwrap();
    assert_eq!(done.status, Status::Cancelled);
    assert_eq!(done.packets[0].actual, None);
    assert!(done.packets[0].data.is_empty());
    assert!(owner.take_completions().unwrap().is_empty()); // failed call exposes no phantom ID.
    assert_eq!(owner.iso_spare.len(), 2);
}

#[test]
fn explicit_partial_publication_or_failed_stop_retains_every_original_packet_buffer() {
    for fatal in [false, true] {
        let mut ram = vec![0u64; 512 * 1024];
        let start = ram.as_mut_ptr() as u64;
        // SAFETY: failed-retirement owners and every original DMA allocation stay live.
        let mut dma = unsafe { model::RegionAllocator::new(start..start + ram.len() as u64 * 8) };
        let (mut owner, peer) = fixture_with_schedule(
            &mut dma,
            false,
            xhci::FULL_SPEED,
            1,
            Some((0x110, 0, 1 << 11)),
        );
        if fatal {
            peer.borrow_mut().fatal_after = Some(1);
            assert!(
                owner
                    .submit_isochronous_scheduled(
                        0x81,
                        &[2, 3],
                        &[],
                        xhci::IsoSchedule::AtMicroframe(16032),
                        &mut dma,
                    )
                    .is_err()
            );
            assert_eq!(peer.borrow().published.len(), 1);
        } else {
            owner
                .submit_isochronous_scheduled(
                    0x81,
                    &[2, 3],
                    &[],
                    xhci::IsoSchedule::AtMicroframe(16032),
                    &mut dma,
                )
                .unwrap();
            peer.borrow().base.borrow_mut().fail = Some((STOP, 17));
            assert!(owner.cancel(0x81).is_err());
            assert_eq!(peer.borrow().published.len(), 2);
        }
        assert!(owner.fenced());
        assert_eq!(owner.iso_requests.len(), 1);
        assert!(owner.iso_spare.is_empty());
        assert!(owner.take_completions().unwrap().is_empty());
        let pending = owner.iso_requests.values().next().unwrap();
        assert_eq!(pending.buffer.len(), 65536);
        assert_eq!(peer.borrow().active[0].buffer, pending.buffer.physical());
        let published = peer.borrow().published.len();
        assert!(
            owner
                .submit_isochronous_scheduled(
                    0x81,
                    &[1],
                    &[],
                    xhci::IsoSchedule::AtMicroframe(16064),
                    &mut dma,
                )
                .is_err()
        );
        assert_eq!(peer.borrow().published.len(), published);
    }
}

#[test]
fn modeled_state_transitions_preserve_actual_configured_endpoint_context_fields() {
    let mut ram = vec![0u64; 512 * 1024];
    let start = ram.as_mut_ptr() as u64;
    // SAFETY: configured endpoint contexts and every ring remain in
    // this exclusive fixture allocation until their original owners drop.
    let mut dma = unsafe { model::RegionAllocator::new(start..start + ram.len() as u64 * 8) };
    let check = |peer: &Rc<RefCell<Peer>>, dci: u8, mask: u32, expected: u32| {
        let base = peer.borrow().base.clone();
        let model = base.borrow();
        let at = model.output + u64::from(dci) * model.context_bytes as u64;
        let original: Vec<_> = (0..model.context_bytes / 4)
            .map(|word| Peer::word(at + word as u64 * 4))
            .collect();
        assert_eq!(original[0] & mask, expected);
        assert_eq!(original[0] & 7, 1);
        drop(model);
        // Running -> Halted -> Stopped -> Error -> Disabled -> Running covers
        // every architected state value without changing the configured fields.
        for state in [2, 3, 4, 0, 1] {
            base.borrow_mut().set_state(usize::from(dci), state);
            assert_eq!(base.borrow().state(usize::from(dci)), state);
            for (word, expected) in original.iter().enumerate() {
                let actual = Peer::word(at + word as u64 * 4);
                assert_eq!(
                    actual,
                    if word == 0 {
                        *expected & !7 | state
                    } else {
                        *expected
                    }
                );
            }
        }
    };
    let (_full, full_peer) = fixture_with_schedule(
        &mut dma,
        false,
        xhci::FULL_SPEED,
        2,
        Some((0x110, 0, 1 << 11)),
    );
    // Original FS bInterval2 is configured as Interval4 (16 microframes).
    check(&full_peer, 3, 0xff << 16, 4 << 16);

    let (mut superspeed, superspeed_peer) = fixture(&mut dma, true);
    assert!(superspeed.enable_streams(&[0x81, 2], 3, &mut dma).unwrap() >= 3);
    // The real primary-stream layout has LSA=1 and MaxPStreams=1 for four entries.
    check(&superspeed_peer, 3, 1 << 15 | 31 << 10, 1 << 15 | 1 << 10);
    let endpoint = Endpoint {
        address: 0x83,
        attributes: 1,
        max_packet: 256,
        interval: 5,
        companion: Some(xhci::SuperSpeedCompanion {
            max_burst: 1,
            attributes: 2,
            bytes_per_interval: 1536,
        }),
    };
    superspeed
        .controller
        .borrow_mut()
        .device(superspeed.physical.id)
        .unwrap()
        .configure(&[endpoint], None, &mut dma)
        .unwrap();
    // A second native Configure command keeps nonzero Interval and Mult.
    check(&superspeed_peer, 7, 0xff << 16 | 3 << 8, 4 << 16 | 2 << 8);
}

/// These independent controllers both reached real Address Device ACK for slot
/// one. Substituting only the controller reference models a hostile
/// old consumer alias; no SlotId or generation is manufactured. Same-controller
/// published-slot reuse is checked separately by the topology owner.
#[test]
fn stale_forwarding_cached_receipts_refuse_before_mmio_and_preserve_current_dma() {
    for iso in [false, true] {
        let mut ram = vec![0u64; 1024 * 1024];
        let start = ram.as_mut_ptr() as u64;
        // SAFETY: exclusive backing remains live until both controllers drop.
        let mut dma = unsafe { model::RegionAllocator::new(start..start + ram.len() as u64 * 8) };
        let (mut previous, old_peer) = fixture(&mut dma, !iso);
        let (mut current, peer) = fixture(&mut dma, !iso);
        let old_id = previous.physical.id;
        let fresh_id = current.physical.id;
        assert_eq!(old_id.hardware_slot(), fresh_id.hardware_slot());
        assert_ne!(old_id, fresh_id);
        let old = if iso {
            previous
                .submit_isochronous(0x81, &[2, 2], &[], &mut dma)
                .unwrap()
        } else {
            previous.submit(0x81, 0, 4, &[]).unwrap()
        };
        if iso {
            old_peer.borrow_mut().complete(3, 0, 1, 0, &[0xa1, 0xb2]);
        }
        previous.cancel(0x81).unwrap();
        assert_eq!(previous.completed.len(), 1);
        assert_eq!(previous.completed[0].status, Status::Cancelled);
        assert_eq!(previous.completed[0].packets.len(), if iso { 2 } else { 0 });
        if iso {
            assert_eq!(previous.completed[0].packets[0].data, [0xa1, 0xb2]);
            assert_eq!(previous.completed[0].packets[1].status, Status::Cancelled);
        }
        let cached = current.submit(2, 0, 2, &[0x34, 0x56]).unwrap();
        current.cancel(2).unwrap();
        let unread = if iso {
            current
                .submit_isochronous(0x81, &[4], &[], &mut dma)
                .unwrap()
        } else {
            current.submit(0x81, 0, 4, &[]).unwrap()
        };
        peer.borrow_mut()
            .complete(3, 0, 1, 0, &[0x12, 0x23, 0x34, 0x45]);
        previous.controller = current.controller.clone();
        let receipts = previous.completed.clone();
        let current_receipts = current.completed.clone();
        let before = ram.clone();
        let remaining = dma.remaining();
        peer.borrow_mut().trap_mmio = true;
        assert!(previous.poll(old).is_err());
        assert!(previous.take_completions().is_err());
        assert!(previous.cancel(0x81).is_err());
        assert!(previous.shutdown().is_err());
        assert!(previous.configure(0, &mut dma).is_err());
        assert!(previous.submit(0x81, 0, 1, &[]).is_err());
        assert_eq!(previous.completed, receipts);
        assert_eq!(current.completed, current_receipts);
        assert!(!previous.fenced);
        assert_eq!(previous.configuration, 19);
        assert_eq!(dma.remaining(), remaining);
        assert_eq!(ram, before);
        // Current cached cancellation ACKs need no hardware access.
        assert_eq!(
            current.poll(cached).unwrap().unwrap().status,
            Status::Cancelled
        );
        assert!(current.take_completions().unwrap().is_empty());
        assert_eq!(ram, before);
        peer.borrow_mut().trap_mmio = false;
        let done = current.poll(unread).unwrap().unwrap();
        assert_eq!(done.actual, Some(4));
        if iso {
            assert_eq!(done.packets[0].data, [0x12, 0x23, 0x34, 0x45]);
        } else {
            assert_eq!(done.data, [0x12, 0x23, 0x34, 0x45]);
        }
    }
}

#[test]
fn current_shutdown_fenced_forwarding_owner_can_drain_real_cancellation_receipts() {
    for iso in [false, true] {
        let mut ram = vec![0u64; 512 * 1024];
        let start = ram.as_mut_ptr() as u64;
        // SAFETY: original DMA allocations outlive this real shutdown exchange.
        let mut dma = unsafe { model::RegionAllocator::new(start..start + ram.len() as u64 * 8) };
        let (mut owner, peer) = fixture(&mut dma, !iso);
        let incoming = if iso {
            owner.submit_isochronous(0x81, &[4], &[], &mut dma).unwrap()
        } else {
            owner.submit(0x81, 0, 4, &[]).unwrap()
        };
        let outgoing = owner.submit(2, 0, 2, &[0x67, 0x89]).unwrap();
        owner.shutdown().unwrap();
        assert!(owner.fenced());
        assert!(peer.borrow().active.is_empty());
        assert_eq!(peer.borrow().base.borrow().configuration_value, 0);
        assert_eq!(owner.completed.len(), 2);
        let before = ram.clone();
        peer.borrow_mut().trap_mmio = true;
        assert_eq!(
            owner.poll(incoming).unwrap().unwrap().status,
            Status::Cancelled
        );
        let drained = owner.take_completions().unwrap();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].request, outgoing);
        assert_eq!(drained[0].status, Status::Cancelled);
        assert!(owner.take_completions().unwrap().is_empty());
        assert!(owner.poll(incoming).is_err());
        assert_eq!(ram, before);
    }
}

#[test]
fn actual_same_controller_root_reuse_preserves_stale_forwarding_cache_and_current_completion() {
    for speed in [xhci::HIGH_SPEED, xhci::SUPER_SPEED] {
        for context in [32, 64] {
            for iso in [false, true] {
                let mut memory = vec![0u64; 512 * 1024];
                let (mut host, shared, physical, hardware, mut dma) =
                    model::reset_forwarding_fixture(&mut memory, speed, context, iso);
                let mut previous = host.forward_device(physical.id).unwrap();
                previous
                    .configure(physical.configuration_value(), &mut dma)
                    .unwrap();
                let original = previous.physical.clone();
                let endpoints = xhci::interfaces(&original.configuration)
                    .remove(0)
                    .endpoints;
                let endpoint = endpoints[0];
                assert!(endpoint.is_in());
                let retired_request = if iso {
                    previous
                        .submit_isochronous(endpoint.address, &[4], &[], &mut dma)
                        .unwrap()
                } else {
                    previous.submit(endpoint.address, 0, 4, &[]).unwrap()
                };
                if iso {
                    hardware.borrow_mut().complete_forwarded(
                        original.slot,
                        endpoint.dci(),
                        &[0xa1, 0xb2, 0xc3, 0xd4],
                    );
                }
                previous.cancel(endpoint.address).unwrap();
                assert_eq!(previous.completed.len(), 1);
                assert_eq!(previous.completed[0].status, Status::Cancelled);
                if iso {
                    assert_eq!(
                        previous.completed[0].packets[0].data,
                        [0xa1, 0xb2, 0xc3, 0xd4]
                    );
                }
                // SAFETY: the topology owner exclusively transfers this complete
                // original leaf inventory; old aliases remain only as refusal controls.
                let mut fresh = unsafe {
                    shared
                        .borrow_mut()
                        .reset_and_reuse_root(&original, &endpoints, &mut dma)
                }
                .unwrap();
                fresh.configuration = fresh.configurations[0].clone();
                assert_eq!(fresh.slot, original.slot);
                assert_ne!(fresh.id, original.id);
                assert_eq!(hardware.borrow().resets, 1);
                assert_eq!(hardware.borrow().enables, [original.slot, fresh.slot]);
                assert!(
                    hardware
                        .borrow()
                        .commands_seen
                        .iter()
                        .any(|(kind, slot, _)| *kind == 10 && *slot == original.slot)
                );
                // The reset service preserved the original Forwarded
                // consumer claim and transferred it to this returned generation.
                let mut current = Device::claimed(shared.clone(), fresh).unwrap();
                current.configure(1, &mut dma).unwrap();
                assert!(Rc::ptr_eq(&previous.controller, &current.controller));
                let cached = current.submit(endpoint.address, 0, 4, &[]).unwrap();
                current.cancel(endpoint.address).unwrap();
                let unread = if iso {
                    current
                        .submit_isochronous(endpoint.address, &[4], &[], &mut dma)
                        .unwrap()
                } else {
                    current.submit(endpoint.address, 0, 4, &[]).unwrap()
                };
                hardware.borrow_mut().complete_forwarded(
                    current.physical.slot,
                    endpoint.dci(),
                    &[0x12, 0x23, 0x34, 0x45],
                );
                let old_cache = previous.completed.clone();
                let current_cache = current.completed.clone();
                let accesses = hardware.borrow().accesses;
                let remaining = dma.remaining();
                let before = memory.clone();
                hardware.borrow_mut().trap_mmio = true;
                assert!(previous.poll(retired_request).is_err());
                assert!(previous.take_completions().is_err());
                assert!(previous.cancel(endpoint.address).is_err());
                assert!(previous.shutdown().is_err());
                assert_eq!(previous.completed, old_cache);
                assert_eq!(current.completed, current_cache);
                assert!(!previous.fenced);
                assert_eq!(hardware.borrow().accesses, accesses);
                assert_eq!(dma.remaining(), remaining);
                assert_eq!(memory, before);
                assert_eq!(
                    current.poll(cached).unwrap().unwrap().status,
                    Status::Cancelled
                );
                assert_eq!(hardware.borrow().accesses, accesses);
                assert_eq!(memory, before);
                hardware.borrow_mut().trap_mmio = false;
                let done = current.poll(unread).unwrap().unwrap();
                assert_eq!(done.actual, Some(4));
                if iso {
                    assert_eq!(done.packets[0].data, [0x12, 0x23, 0x34, 0x45]);
                } else {
                    assert_eq!(done.data, [0x12, 0x23, 0x34, 0x45]);
                }
                assert_eq!(hardware.borrow().resets, 1);
            }
        }
    }
}
