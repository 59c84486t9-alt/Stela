//! A native-layout EHCI/DMA/USB peer. CPU and device caches are separate:
//! publication and completed cache ownership must pass actual domain methods.
//! This models contracts and fault paths, never physical EHCI qualification.
use super::*;
use crate::bus::dma::{
    mapping::{DmaDomain, DomainMapping},
    memory::{PageBacking, PageGeometry, PageSource, PinnedPages},
    pages::DmaPages,
};
use alloc::{sync::Arc, vec};
use core::{alloc::Layout, ops::Range, ptr::NonNull};
use std::sync::Mutex;
extern crate std;

const OP: usize = 0x20;
const QTD: usize = 128;
const ACTIVE: u32 = 128;
const TOGGLE: u32 = 1 << 31;
const DESCRIPTION: [u8; 32] = [
    9, 2, 32, 0, 1, 1, 0, 0x80, 50, 9, 4, 0, 0, 2, 8, 6, 0x50, 0, 7, 5, 0x81, 2, 0, 2, 0, 7, 5, 2,
    2, 0, 2, 0,
];
#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    Complete,
    Hold,
    Stall,
    Babble,
    Transaction,
    Partial,
}
struct Shared {
    words: Vec<u32>,
    config: [u32; 64],
    now: u64,
    io: usize,
    writes: Vec<(usize, u32)>,
    bme: bool,
    retired: bool,
    reset_ack: bool,
    start_ack: bool,
    stop_ack: bool,
    bios_ack: bool,
    sticky_smi: bool,
    drain_fail: bool,
    device_sync_fail: bool,
    cpu_sync_fail: bool,
    drained: bool,
    drains: usize,
    device_syncs: usize,
    cpu_syncs: usize,
    cpu: Option<CpuMapping>,
    device: Vec<u8>,
    iova: u64,
    mapped: bool,
    allocations: usize,
    unmapped: usize,
    mode: Mode,
    request: Option<[u8; 8]>,
    response: Vec<u8>,
    description: Vec<u8>,
    hold_status: Option<u8>,
    offset: usize,
    short_limit: Option<usize>,
    setup_trace: Vec<[u8; 8]>,
    status_pids: Vec<u32>,
    bulk_toggles: Vec<bool>,
    received: Vec<u8>,
    suppress_writeback: bool,
    reset_disconnect: bool,
    high_speed: bool,
}
impl Shared {
    fn new() -> Self {
        let mut words = vec![0; 128];
        words[0] = 0x0100_0020;
        words[1] = 1 | 16 | 1 << 12;
        words[2] = 1 | (0x40 << 8);
        words[(OP + STS) / 4] = HALT;
        words[(OP + PORT) / 4] = CONNECT | POWER;
        let mut config = [0; 64];
        config[16] = 1 | (1 << 16);
        Self {
            words,
            config,
            now: 0,
            io: 0,
            writes: Vec::new(),
            bme: false,
            retired: false,
            reset_ack: true,
            start_ack: true,
            stop_ack: true,
            bios_ack: true,
            sticky_smi: false,
            drain_fail: false,
            device_sync_fail: false,
            cpu_sync_fail: false,
            drained: false,
            drains: 0,
            device_syncs: 0,
            cpu_syncs: 0,
            cpu: None,
            device: Vec::new(),
            iova: 0,
            mapped: false,
            allocations: 0,
            unmapped: 0,
            mode: Mode::Complete,
            request: None,
            response: Vec::new(),
            description: DESCRIPTION.to_vec(),
            hold_status: None,
            offset: 0,
            short_limit: None,
            setup_trace: Vec::new(),
            status_pids: Vec::new(),
            bulk_toggles: Vec::new(),
            received: Vec::new(),
            suppress_writeback: false,
            reset_disconnect: false,
            high_speed: true,
        }
    }
    fn u32(&self, offset: usize) -> u32 {
        u32::from_le_bytes(self.device[offset..offset + 4].try_into().unwrap())
    }
    fn put(&mut self, offset: usize, value: u32) {
        self.device[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn dma_offset(&self, low: u32, high: u32) -> usize {
        let address = u64::from(low) | u64::from(high) << 32;
        usize::try_from(address.checked_sub(self.iova).unwrap()).unwrap()
    }
    fn execute(&mut self) {
        if self.mode == Mode::Hold {
            return;
        }
        assert!(self.bme && self.mapped);
        assert_eq!(self.words[(OP + SEGMENT) / 4], (self.iova >> 32) as u32);
        assert_eq!(self.words[(OP + ASYNC) / 4], self.iova as u32);
        assert_eq!(self.u32(0), self.iova as u32 | 2);
        let info = self.u32(4);
        assert_ne!(info & (1 << 15), 0);
        assert_eq!(info & (3 << 12), 2 << 12);
        assert_eq!(self.u32(8), 1 << 30);
        let control = info & (1 << 14) != 0;
        assert_eq!((info >> 16) & 0x7ff, if control { 64 } else { 512 });
        let mut resume = self.u32(24) & ACTIVE != 0;
        let mut next = if resume { self.u32(12) } else { self.u32(16) };
        let mut visited = 0;
        let mut bulk_toggle = self.u32(24) & TOGGLE != 0;
        if !control {
            self.bulk_toggles.push(bulk_toggle);
            if !resume {
                self.offset = 0;
            }
        }
        while next & 1 == 0 {
            visited += 1;
            assert!(visited <= 6);
            let td = self.dma_offset(next & !31, (self.iova >> 32) as u32);
            assert!((QTD..QTD + 6 * 64).contains(&td) && (td - QTD).is_multiple_of(64));
            let initial = if resume {
                self.u32(24)
            } else {
                self.u32(td + 8)
            };
            assert_ne!(initial & ACTIVE, 0);
            let pid = (initial >> 8) & 3;
            let requested = ((initial >> 16) & 0x7fff) as usize;
            let pointer = if requested == 0 {
                0
            } else {
                if resume {
                    self.dma_offset(self.u32(28), self.u32(48))
                } else {
                    self.dma_offset(self.u32(td + 12), self.u32(td + 32))
                }
            };
            if requested != 0 {
                assert!(pointer + requested <= self.device.len());
                let start = self.iova + pointer as u64;
                let pages = (((start + requested as u64 - 1) >> 12) - (start >> 12) + 1) as usize;
                assert!(pages <= 5);
                for page in 1..pages {
                    if resume {
                        continue;
                    }
                    assert_eq!(
                        u64::from(self.u32(td + 12 + page * 4))
                            | u64::from(self.u32(td + 32 + page * 4)) << 32,
                        (start & !4095) + page as u64 * 4096
                    );
                }
            }
            self.put(12, next & !31);
            if !resume {
                self.put(16, self.u32(td));
                self.put(20, self.u32(td + 4));
                for page in 0..5 {
                    self.put(28 + page * 4, self.u32(td + 12 + page * 4));
                    self.put(48 + page * 4, self.u32(td + 32 + page * 4));
                }
            }
            resume = false;
            let mut actual = requested;
            let mut error = 0;
            if !control {
                error = match self.mode {
                    Mode::Stall => 64,
                    Mode::Babble => 64 | 16,
                    Mode::Transaction => 64 | 8,
                    _ => 0,
                };
                if error != 0 {
                    actual = 0;
                }
                if self.mode == Mode::Partial {
                    actual = requested.min(512);
                }
                if pid == 1 {
                    actual = actual.min(
                        self.short_limit
                            .unwrap_or(usize::MAX)
                            .saturating_sub(self.offset),
                    );
                }
            }
            if pid == 2 {
                assert!(control);
                assert_eq!(requested, 8);
                assert_eq!(initial & TOGGLE, 0);
                let setup: [u8; 8] = self.device[pointer..pointer + 8].try_into().unwrap();
                self.request = Some(setup);
                self.setup_trace.push(setup);
                self.offset = 0;
                self.response = if setup[1] == 6 && setup[3] == 2 {
                    self.description.clone()
                } else {
                    vec![0x5a; usize::from(u16::from_le_bytes([setup[6], setup[7]]))]
                };
            } else if control && requested == 0 {
                let setup = self.request.unwrap();
                if self.hold_status == Some(setup[1]) {
                    // Device NAKs STATUS forever: current overlay remains
                    // ACTIVE; no ACK/writeback/local state may be invented.
                    self.put(24, initial);
                    break;
                }
                let length = u16::from_le_bytes([setup[6], setup[7]]);
                assert_eq!(
                    pid,
                    if length == 0 || setup[0] & 0x80 == 0 {
                        1
                    } else {
                        0
                    }
                );
                assert_ne!(initial & TOGGLE, 0);
                self.status_pids.push(pid);
            } else if pid == 1 {
                if control {
                    actual = actual.min(self.response.len().saturating_sub(self.offset));
                }
                for byte in 0..actual {
                    self.device[pointer + byte] = if control {
                        self.response[self.offset + byte]
                    } else {
                        ((self.offset + byte) % 251) as u8
                    };
                }
            } else {
                self.received
                    .extend_from_slice(&self.device[pointer..pointer + actual]);
            }
            let mut token = (initial & !(ACTIVE | (0x7fff << 16)))
                | (((requested - actual) as u32) << 16)
                | error;
            if !control {
                let packets = if error != 0 {
                    0
                } else if self.mode == Mode::Partial {
                    actual.div_ceil(512)
                } else if requested == 0 {
                    1
                } else if actual == requested {
                    actual.div_ceil(512)
                } else {
                    actual / 512 + 1
                };
                if packets % 2 != 0 {
                    bulk_toggle = !bulk_toggle;
                }
                token = (token & !TOGGLE) | if bulk_toggle { TOGGLE } else { 0 };
            }
            if pid != 2 {
                self.offset += actual;
            }
            if self.mode == Mode::Partial && !control {
                token |= ACTIVE;
            }
            self.put(24, token);
            if token & ACTIVE != 0 {
                // Keep the original qTD writeback ACTIVE/stale; actual partial
                // progress lives solely in the retained current QH overlay.
                let pointer = self.iova + pointer as u64 + actual as u64;
                self.put(28, pointer as u32);
                self.put(48, (pointer >> 32) as u32);
            } else if !self.suppress_writeback || self.u32(td) & 1 == 0 {
                self.put(td + 8, token);
            }
            next = if requested != actual && pid == 1 && error == 0 {
                self.u32(td + 4)
            } else {
                self.u32(td)
            };
            if token & ACTIVE == 0 {
                self.put(16, next);
            }
            if error != 0 || token & ACTIVE != 0 {
                break;
            }
        }
    }
}

struct Backing {
    cpu: NonNull<u8>,
    layout: Layout,
    physical: Vec<u64>,
}
// SAFETY: test allocation is exclusively pinned, bytewise synchronized through
// the modeled domain. It never purports to reserve actual physical hardware.
unsafe impl Send for Backing {}
unsafe impl Sync for Backing {}
unsafe impl PageBacking for Backing {
    fn cpu_base(&self) -> NonNull<u8> {
        self.cpu
    }
    fn physical_pages(&self) -> &[u64] {
        &self.physical
    }
    fn page_shift(&self) -> u8 {
        12
    }
    fn cache_attribute(&self) -> CacheAttribute {
        CacheAttribute::WriteBack
    }
}
impl Drop for Backing {
    fn drop(&mut self) {
        // SAFETY: last pinned owner released this exact test allocation.
        unsafe {
            alloc::alloc::dealloc(self.cpu.as_ptr(), self.layout);
        }
    }
}
struct Source(Arc<Mutex<Shared>>);
impl PageSource for Source {
    fn page_geometry(&self) -> Result<PageGeometry, MemoryError> {
        PageGeometry::base_only(12)
    }
    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
    ) -> Result<PinnedPages, MemoryError> {
        assert_eq!(attribute, CacheAttribute::WriteBack);
        let bytes = bytes.next_multiple_of(4096);
        let layout = Layout::from_size_align(bytes, alignment).unwrap();
        // SAFETY: initialized private aligned test RAM, retained by Backing.
        let cpu = NonNull::new(unsafe { alloc::alloc::alloc_zeroed(layout) })
            .ok_or(MemoryError::OutOfMemory)?;
        self.0.lock().unwrap().allocations += 1;
        PinnedPages::new(
            Box::new(Backing {
                cpu,
                layout,
                physical: (0..bytes / 4096)
                    .map(|page| 0x1000_0000 + page as u64 * 4096)
                    .collect(),
            }),
            bytes,
            alignment,
        )
    }
}
struct Domain(Arc<Mutex<Shared>>);
// SAFETY: this test-only domain maps the exact retained pins to a disjoint
// modeled IOVA/cache, never native requester authority. Syncs assert ASS0 and
// drainage; the peer alone writes the simulated device image.
unsafe impl DmaDomain for Domain {
    unsafe fn map(
        &self,
        pages: &DmaPages,
        direction: Direction,
        limit: u64,
    ) -> Result<DomainMapping, DmaError> {
        assert_eq!(direction, Direction::Bidirectional);
        let mut m = self.0.lock().unwrap();
        assert!(!m.mapped);
        m.cpu = Some(
            pages
                .as_single()
                .unwrap()
                .cpu_mapping(CacheAttribute::WriteBack)
                .unwrap(),
        );
        m.device = vec![0; pages.bytes()];
        m.iova = if limit > u64::from(u32::MAX) {
            0x1_0200_0000
        } else {
            0x0200_0000
        };
        m.mapped = true;
        Ok(DomainMapping {
            id: 1,
            address: m.iova,
            bytes: pages.bytes(),
        })
    }
    unsafe fn unmap(&self, mapping: DomainMapping) -> Result<(), DmaError> {
        let mut m = self.0.lock().unwrap();
        assert_eq!(mapping.address, m.iova);
        assert_eq!(m.words[(OP + STS) / 4] & (ASS | PSS), 0);
        assert!(m.drained);
        m.mapped = false;
        m.cpu = None;
        m.unmapped += 1;
        Ok(())
    }
    unsafe fn sync_for_device(
        &self,
        mapping: DomainMapping,
        range: Range<usize>,
        _: Direction,
    ) -> Result<(), DmaError> {
        let mut m = self.0.lock().unwrap();
        assert_eq!(mapping.address, m.iova);
        assert_eq!(m.words[(OP + STS) / 4] & ASS, 0);
        if m.device_sync_fail {
            return Err(DmaError::VisibilityFailed);
        }
        let pointer = m
            .cpu
            .as_ref()
            .unwrap()
            .address(range.start, range.len())
            .unwrap();
        // SAFETY: actual model engine stopped; exact mapped CPU pins/bounds.
        let bytes = unsafe { core::slice::from_raw_parts(pointer.as_ptr(), range.len()) };
        m.device[range].copy_from_slice(bytes);
        m.device_syncs += 1;
        m.drained = false;
        Ok(())
    }
    unsafe fn sync_for_cpu(
        &self,
        mapping: DomainMapping,
        range: Range<usize>,
        _: Direction,
    ) -> Result<(), DmaError> {
        let mut m = self.0.lock().unwrap();
        assert_eq!(mapping.address, m.iova);
        assert_eq!(m.words[(OP + STS) / 4] & ASS, 0);
        assert!(m.drained);
        if m.cpu_sync_fail {
            return Err(DmaError::VisibilityFailed);
        }
        let pointer = m
            .cpu
            .as_ref()
            .unwrap()
            .address(range.start, range.len())
            .unwrap();
        // SAFETY: stopped/drained model device cache, private exact CPU pins.
        unsafe {
            ptr::copy_nonoverlapping(
                m.device[range.clone()].as_ptr(),
                pointer.as_ptr(),
                range.len(),
            );
        }
        m.cpu_syncs += 1;
        Ok(())
    }
    unsafe fn drain_posted_writes(&self) -> Result<(), DmaError> {
        let mut m = self.0.lock().unwrap();
        assert_eq!(m.words[(OP + STS) / 4] & (ASS | PSS), 0);
        if m.drain_fail {
            return Err(DmaError::DrainUnavailable);
        }
        m.drained = true;
        m.drains += 1;
        Ok(())
    }
}
struct Access(Arc<Mutex<Shared>>);
impl Hardware for Access {
    fn validate(&mut self) -> Result<(), Error> {
        Ok(())
    }
    fn read32(&mut self, offset: usize) -> Result<u32, Error> {
        let mut m = self.0.lock().unwrap();
        m.io += 1;
        Ok(m.words[offset / 4])
    }
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), Error> {
        let mut m = self.0.lock().unwrap();
        m.io += 1;
        m.writes.push((offset, value));
        if offset == OP + CMD {
            m.words[offset / 4] = value;
            if value & RESET != 0 {
                if m.reset_ack {
                    m.words[offset / 4] = 0;
                    m.words[(OP + STS) / 4] = HALT;
                }
                return Ok(());
            }
            if value & RUN == 0 {
                m.words[(OP + STS) / 4] |= HALT;
            } else {
                m.words[(OP + STS) / 4] &= !HALT;
            }
            if value & ASE != 0 {
                if m.start_ack {
                    m.words[(OP + STS) / 4] |= ASS;
                    m.execute();
                }
            } else if m.stop_ack {
                m.words[(OP + STS) / 4] &= !ASS;
            }
        } else if offset == OP + STS {
            m.words[offset / 4] &= !(value & 0x3f);
        } else if (OP + PORT..OP + PORT + 60).contains(&offset) {
            let old = m.words[offset / 4];
            let mut next = (value & !(PORT_CHANGES | CONNECT | ENABLE))
                | (old & (CONNECT | ENABLE))
                | (old & PORT_CHANGES & !value);
            if value & ENABLE == 0 {
                next &= !ENABLE;
            }
            if old & PORT_RESET != 0 && value & PORT_RESET == 0 {
                if m.reset_disconnect {
                    next |= 1 << 1;
                } else {
                    if m.high_speed {
                        next |= ENABLE | 1 << 3;
                    }
                }
            }
            m.words[offset / 4] = next;
        } else {
            m.words[offset / 4] = value;
        }
        Ok(())
    }
    fn config_read(&mut self, offset: u16) -> Result<u32, Error> {
        let m = self.0.lock().unwrap();
        Ok(m.config[usize::from(offset) / 4]
            | if offset == 0x44 && m.sticky_smi {
                1 << 2
            } else {
                0
            })
    }
    fn config_write(&mut self, offset: u16, value: u32) -> Result<(), Error> {
        let mut m = self.0.lock().unwrap();
        m.config[usize::from(offset) / 4] = value & !0xe000_0000;
        Ok(())
    }
    fn config_os_owned(&mut self, offset: u16) -> Result<(), Error> {
        let mut m = self.0.lock().unwrap();
        let acknowledge = m.bios_ack;
        m.config[usize::from(offset) / 4] |= 1 << 24;
        if acknowledge {
            m.config[usize::from(offset) / 4] &= !(1 << 16);
        }
        Ok(())
    }
    fn bytes(&self) -> usize {
        512
    }
    fn now_us(&mut self) -> u64 {
        let mut m = self.0.lock().unwrap();
        m.now += 1000;
        m.now
    }
    fn pause(&mut self) {}
    fn delay_us(&mut self, us: u64) -> Result<(), Error> {
        self.0.lock().unwrap().now += us;
        Ok(())
    }
    fn allocate(&mut self, limit: u64) -> Result<Arena, Error> {
        let pages = Source(self.0.clone()).allocate(
            schedule::ARENA_BYTES,
            4096,
            CacheAttribute::WriteBack,
        )?;
        let cpu = pages.cpu_mapping(CacheAttribute::WriteBack)?;
        let dma = DmaMapping::map(
            Arc::new(Domain(self.0.clone())),
            pages,
            Direction::Bidirectional,
            limit,
        )?;
        Arena::new(cpu, dma)
    }
    fn bus_master(&mut self, enabled: bool) -> Result<(), Error> {
        self.0.lock().unwrap().bme = enabled;
        Ok(())
    }
    fn drain(&mut self) -> Result<(), Error> {
        // SAFETY: production caller proves schedule/halt quiescence.
        unsafe {
            Domain(self.0.clone()).drain_posted_writes()?;
        }
        Ok(())
    }
    fn retire(&mut self) -> Result<(), Error> {
        let mut m = self.0.lock().unwrap();
        assert!(!m.bme && !m.mapped);
        m.retired = true;
        Ok(())
    }
}
fn controller(m: Arc<Mutex<Shared>>) -> Controller {
    Controller::initialize(Box::new(Access(m)))
        .unwrap_or_else(|failure| panic!("{:?}", failure.error))
}
fn attached() -> (Controller, Arc<Mutex<Shared>>, DeviceId, Vec<BulkPipe>) {
    let m = Arc::new(Mutex::new(Shared::new()));
    let mut c = controller(m.clone());
    let id = c.reset_port(1).unwrap();
    c.set_address(&id, 7).unwrap();
    let pipes = c.configure(&id, 0).unwrap();
    (c, m, id, pipes)
}
fn input(pipes: &[BulkPipe]) -> &BulkPipe {
    pipes.iter().find(|pipe| pipe.endpoint & 0x80 != 0).unwrap()
}
fn output(pipes: &[BulkPipe]) -> &BulkPipe {
    pipes.iter().find(|pipe| pipe.endpoint & 0x80 == 0).unwrap()
}

#[test]
fn actual_native_hs_control_status_descriptor_configuration_and_bulk_dma_chain() {
    let (mut c, m, id, pipes) = attached();
    let setup = [0x80, 0x55, 0, 0, 0, 0, 0, 0];
    assert_eq!(c.control_in(&id, setup).unwrap(), Vec::<u8>::new());
    assert_eq!(m.lock().unwrap().status_pids.last(), Some(&1)); // zero-data IN request still STATUS IN
    let bytes: Vec<u8> = (0..MAX_TRANSFER).map(|byte| (byte % 239) as u8).collect();
    let ticket = c
        .submit_bulk_out(output(&pipes), &bytes, 1_000_000)
        .unwrap();
    let completion = c.poll(&ticket).unwrap().unwrap();
    assert_eq!(completion.actual, MAX_TRANSFER);
    assert!(completion.data.is_empty());
    assert!(m.lock().unwrap().received.ends_with(&bytes));
    let ticket = c
        .submit_bulk_in(input(&pipes), MAX_TRANSFER, 1_000_000)
        .unwrap();
    let completion = c.poll(&ticket).unwrap().unwrap();
    assert_eq!(completion.actual, MAX_TRANSFER);
    assert_eq!(
        completion.data,
        (0..MAX_TRANSFER)
            .map(|byte| (byte % 251) as u8)
            .collect::<Vec<_>>()
    );
    assert_eq!(m.lock().unwrap().allocations, 1);
    c.shutdown().unwrap();
    let m = m.lock().unwrap();
    assert!(m.retired);
    assert_eq!(m.unmapped, 1);
    assert!(m.drains > 0 && m.cpu_syncs > 0 && m.device_syncs > 0);
}
#[test]
fn actual_hs_short_bulk_skips_active_successors_and_keeps_overlay_toggle_with_zlp() {
    let (mut c, m, _, pipes) = attached();
    m.lock().unwrap().short_limit = Some(16_384 + 23);
    let ticket = c
        .submit_bulk_in(input(&pipes), MAX_TRANSFER, 1_000_000)
        .unwrap();
    let result = c.poll(&ticket).unwrap().unwrap();
    assert_eq!(result.actual, 16_407);
    assert_eq!(result.data.len(), 16_407);
    m.lock().unwrap().short_limit = None;
    let ticket = c.submit_bulk_in(input(&pipes), 0, 1_000_000).unwrap();
    assert_eq!(c.poll(&ticket).unwrap().unwrap().actual, 0);
    let ticket = c.submit_bulk_in(input(&pipes), 512, 1_000_000).unwrap();
    assert_eq!(c.poll(&ticket).unwrap().unwrap().actual, 512);
    let toggles = &m.lock().unwrap().bulk_toggles;
    assert_eq!(toggles, &[false, true, false]);
}
#[test]
fn actual_control_short_data_follows_status_and_qh_overlay_supersedes_stale_qtd() {
    let (mut c, m, id, _) = attached();
    m.lock().unwrap().suppress_writeback = true;
    // Descriptor32bytes requested as20000: first DATAshort must jump directly
    // to STATUS, leaving a later data descriptor ACTIVE and untouched.
    let setup = [0x80, 6, 0, 2, 0, 0, 0x20, 0x4e];
    let result = c.control_in(&id, setup).unwrap();
    assert_eq!(result, DESCRIPTION);
    // Only current STATUS writeback was suppressed: SETUP/DATA writebacks
    // remain mandatory; untouched later DATA is ACTIVE and is skipped.
}
#[test]
fn stale_device_pipe_and_transfer_refuse_before_io_and_preserve_current_completion() {
    let (mut c, m, old, pipes) = attached();
    let first = c.submit_bulk_in(input(&pipes), 33, 1_000_000).unwrap();
    c.poll(&first).unwrap().unwrap();
    let current = c.submit_bulk_in(input(&pipes), 17, 1_000_000).unwrap();
    let before = {
        let m = m.lock().unwrap();
        (m.io, m.device.clone(), m.cpu_syncs, m.device_syncs)
    };
    assert_eq!(c.poll(&first), Err(Error::Stale));
    assert_eq!(c.cancel(&first), Err(Error::Stale));
    let after = {
        let m = m.lock().unwrap();
        (m.io, m.device.clone(), m.cpu_syncs, m.device_syncs)
    };
    assert_eq!(before, after);
    assert_eq!(c.poll(&current).unwrap().unwrap().actual, 17);
    let replacement = c.reset_port(1).unwrap();
    c.set_address(&replacement, 7).unwrap();
    let fresh = c.configure(&replacement, 0).unwrap();
    let before = m.lock().unwrap().io;
    assert_eq!(
        c.control_in(&old, [0x80, 6, 0, 1, 0, 0, 18, 0]),
        Err(Error::Stale)
    );
    assert_eq!(
        c.submit_bulk_in(input(&pipes), 1, 1000).err(),
        Some(Error::Stale)
    );
    assert_eq!(m.lock().unwrap().io, before);
    let ticket = c.submit_bulk_in(input(&fresh), 9, 1_000_000).unwrap();
    assert_eq!(c.poll(&ticket).unwrap().unwrap().actual, 9);
}
#[test]
fn foreign_controller_and_reconfigured_pipes_have_no_authority() {
    let (mut c, m, id, pipes) = attached();
    let (mut other, other_model, _, other_pipes) = attached();
    let current = other
        .submit_bulk_in(input(&other_pipes), 19, 1_000_000)
        .unwrap();
    let other_before = {
        let m = other_model.lock().unwrap();
        (m.io, m.device.clone(), m.cpu_syncs, m.device_syncs)
    };
    let before = m.lock().unwrap().io;
    assert_eq!(
        other.control_in(&id, [0x80, 6, 0, 1, 0, 0, 18, 0]),
        Err(Error::Stale)
    );
    assert_eq!(m.lock().unwrap().io, before);
    let other_after = {
        let m = other_model.lock().unwrap();
        (m.io, m.device.clone(), m.cpu_syncs, m.device_syncs)
    };
    assert_eq!(other_before, other_after);
    assert_eq!(other.poll(&current).unwrap().unwrap().actual, 19);
    c.configure(&id, 0).unwrap();
    let before = m.lock().unwrap().io;
    assert_eq!(
        c.submit_bulk_out(output(&pipes), &[1], 1000).err(),
        Some(Error::Stale)
    );
    assert_eq!(m.lock().unwrap().io, before);
}
#[test]
fn actual_stall_requires_successful_clear_feature_before_toggle_reset() {
    let (mut c, m, _, pipes) = attached();
    m.lock().unwrap().mode = Mode::Stall;
    let ticket = c
        .submit_bulk_out(output(&pipes), &[1, 2, 3], 1_000_000)
        .unwrap();
    assert!(matches!(c.poll(&ticket), Err(Error::Device(_))));
    let before = m.lock().unwrap().io;
    assert_eq!(
        c.submit_bulk_out(output(&pipes), &[4], 1000).err(),
        Some(Error::Device(64))
    );
    assert_eq!(m.lock().unwrap().io, before + 2); // live root+health only, no DMA mutation
    m.lock().unwrap().mode = Mode::Complete;
    c.clear_halt(output(&pipes)).unwrap();
    assert_eq!(
        m.lock().unwrap().setup_trace.last(),
        Some(&[2, 1, 0, 0, 2, 0, 0, 0])
    );
    let ticket = c.submit_bulk_out(output(&pipes), &[4], 1_000_000).unwrap();
    assert_eq!(c.poll(&ticket).unwrap().unwrap().actual, 1);
    assert_eq!(m.lock().unwrap().bulk_toggles.last(), Some(&false));
}
#[test]
fn stop_ack_timeout_keeps_complete_arena_and_native_owner_quarantined() {
    let (mut c, m, _, pipes) = attached();
    m.lock().unwrap().stop_ack = false;
    let ticket = c.submit_bulk_in(input(&pipes), 12, 1_000_000).unwrap();
    let before = m.lock().unwrap().device.clone();
    assert_eq!(c.poll(&ticket), Err(Error::Timeout));
    assert!(c.ready().is_err());
    assert_eq!(m.lock().unwrap().device, before);
    drop(c);
    let m = m.lock().unwrap();
    assert!(m.mapped && m.bme && !m.retired);
    assert_eq!(m.unmapped, 0);
}
#[test]
fn drain_and_cache_visibility_faults_never_copy_or_reuse_uncertain_dma() {
    for fault in 0..3 {
        let (mut c, m, _, pipes) = attached();
        let ticket = c.submit_bulk_in(input(&pipes), 123, 1_000_000).unwrap();
        {
            let mut m = m.lock().unwrap();
            if fault == 0 {
                m.drain_fail = true;
            } else if fault == 1 {
                m.cpu_sync_fail = true;
            } else {
                m.words[(OP + STS) / 4] |= FATAL;
            }
        }
        assert!(c.poll(&ticket).is_err());
        assert!(c.ready().is_err());
        let before = m.lock().unwrap().io;
        assert!(c.cancel(&ticket).is_err());
        assert_eq!(m.lock().unwrap().io, before);
        drop(c);
        assert_eq!(m.lock().unwrap().unmapped, 0);
    }
}
#[test]
fn publish_visibility_and_start_ack_failures_preserve_native_resources() {
    for start in [false, true] {
        let (mut c, m, _, pipes) = attached();
        {
            let mut m = m.lock().unwrap();
            if start {
                m.start_ack = false;
            } else {
                m.device_sync_fail = true;
            }
        }
        assert!(c.submit_bulk_in(input(&pipes), 33, 1_000_000).is_err());
        assert!(c.ready().is_err());
        drop(c);
        assert_eq!(m.lock().unwrap().unmapped, 0);
    }
}
#[test]
fn cancel_reads_partial_overlay_toggle_without_exposing_partial_payload() {
    let (mut c, m, _, pipes) = attached();
    m.lock().unwrap().mode = Mode::Partial;
    let ticket = c.submit_bulk_in(input(&pipes), 4096, 1_000_000).unwrap();
    c.cancel(&ticket).unwrap();
    m.lock().unwrap().mode = Mode::Complete;
    let next = c.submit_bulk_in(input(&pipes), 1, 1_000_000).unwrap();
    assert_eq!(c.poll(&next).unwrap().unwrap().data, vec![0]);
    assert_eq!(m.lock().unwrap().bulk_toggles, &[false, true]);
}
#[test]
fn no_progress_timeout_and_fatal_td_errors_fail_closed() {
    for mode in [Mode::Hold, Mode::Babble, Mode::Transaction] {
        let (mut c, m, _, pipes) = attached();
        m.lock().unwrap().mode = mode;
        let ticket = c.submit_bulk_in(input(&pipes), 16, 1000).unwrap();
        assert!(c.poll(&ticket).is_err());
        assert!(c.ready().is_err());
    }
}
#[test]
fn reset_bios_ownership_and_root_disconnect_failures_mint_no_device() {
    for bios in [false, true] {
        let m = Arc::new(Mutex::new(Shared::new()));
        {
            let mut s = m.lock().unwrap();
            if bios {
                s.bios_ack = false;
            } else {
                s.reset_ack = false;
            }
        }
        let failure = match Controller::initialize(Box::new(Access(m.clone()))) {
            Err(f) => f,
            Ok(_) => panic!("missing actual ACK accepted"),
        };
        assert_eq!(failure.error, Error::Timeout);
        assert!(failure.is_quarantined());
        assert_eq!(m.lock().unwrap().allocations, 0);
    }
    let m = Arc::new(Mutex::new(Shared::new()));
    let mut c = controller(m.clone());
    m.lock().unwrap().reset_disconnect = true;
    assert_eq!(c.reset_port(1).err(), Some(Error::Stale));
    assert!(c.ports[0].is_none());
}
#[test]
fn native32bit_capability_uses_bounded_iova_and_inactive_successors_are_not_data() {
    let m = Arc::new(Mutex::new(Shared::new()));
    m.lock().unwrap().words[2] &= !1;
    let mut c = controller(m.clone());
    assert!(m.lock().unwrap().iova <= u64::from(u32::MAX));
    let id = c.reset_port(1).unwrap();
    c.set_address(&id, 1).unwrap();
    let pipes = c.configure(&id, 0).unwrap();
    let ticket = c.submit_bulk_in(input(&pipes), 1, 1_000_000).unwrap();
    assert_eq!(c.poll(&ticket).unwrap().unwrap().data, vec![0]);
}
#[test]
fn real_disconnect_change_invalidates_attachment_before_pending_dma_is_touched() {
    let (mut c, m, _, pipes) = attached();
    let ticket = c.submit_bulk_in(input(&pipes), 32, 1_000_000).unwrap();
    let before = {
        let mut s = m.lock().unwrap();
        s.words[(OP + PORT) / 4] |= 1 << 1;
        (s.device.clone(), s.cpu_syncs, s.device_syncs)
    };
    assert_eq!(c.poll(&ticket), Err(Error::Stale));
    assert!(c.ready().is_err());
    let after = {
        let s = m.lock().unwrap();
        (s.device.clone(), s.cpu_syncs, s.device_syncs)
    };
    assert_eq!(before, after);
}

#[test]
fn actual_partial_current_overlay_resumes_without_replaying_acked_packet() {
    let (mut c, m, _, pipes) = attached();
    m.lock().unwrap().mode = Mode::Partial;
    let ticket = c.submit_bulk_in(input(&pipes), 4096, 1_000_000).unwrap();
    // Partial current qTD remains ACTIVE only in QH; its memory token still
    // requests4096. Poll must preserve actual residual/buffer/toggle overlay.
    m.lock().unwrap().mode = Mode::Hold;
    assert_eq!(c.poll(&ticket).unwrap(), None);
    m.lock().unwrap().mode = Mode::Complete;
    assert_eq!(c.poll(&ticket).unwrap(), None); // Resumes current DMA after poll.
    let result = c.poll(&ticket).unwrap().unwrap();
    assert_eq!(result.actual, 4096);
    assert_eq!(
        result.data,
        (0..4096).map(|byte| (byte % 251) as u8).collect::<Vec<_>>()
    );
}

#[test]
fn roots_serialize_default_address_and_observed_disconnect_releases_it() {
    let m = Arc::new(Mutex::new(Shared::new()));
    {
        let mut m = m.lock().unwrap();
        m.words[1] = (m.words[1] & !15) | 2;
        m.words[(OP + PORT + 4) / 4] = CONNECT | POWER;
    }
    let mut c = controller(m.clone());
    let old = c.reset_port(1).unwrap();
    let before = m.lock().unwrap().io;
    assert_eq!(c.reset_port(2).err(), Some(Error::Busy));
    assert_eq!(m.lock().unwrap().io, before);
    m.lock().unwrap().words[(OP + PORT) / 4] = POWER | (1 << 1);
    assert_eq!(c.refresh_roots().unwrap(), vec![1]);
    let next = c.reset_port(2).unwrap();
    assert_eq!(next.root_port(), 2);
    let before = m.lock().unwrap().io;
    assert_eq!(c.set_address(&old, 1), Err(Error::Stale));
    assert_eq!(m.lock().unwrap().io, before);
}

#[test]
fn full_speed_reset_hands_off_only_after_acknowledged_owner_and_never_mints_hs() {
    let m = Arc::new(Mutex::new(Shared::new()));
    let mut c = controller(m.clone());
    m.lock().unwrap().high_speed = false;
    assert_eq!(
        c.reset_port(1).err(),
        Some(Error::Unsupported("EHCI FS/LS companion traffic"))
    );
    assert!(c.ports[0].is_none());
    assert_ne!(m.lock().unwrap().words[(OP + PORT) / 4] & OWNER, 0);
    assert!(c.ready().is_ok());
}

#[test]
fn ordinary_standard_control_cannot_change_owned_device_or_endpoint_state() {
    let (mut c, m, id, _) = attached();
    for setup in [
        [0, 5, 8, 0, 0, 0, 0, 0],
        [0, 9, 1, 0, 0, 0, 0, 0],
        [1, 11, 1, 0, 0, 0, 0, 0],
        [2, 1, 0, 0, 0x81, 0, 0, 0],
    ] {
        let before = m.lock().unwrap().io;
        assert_eq!(
            c.control_out(&id, setup, &[]),
            Err(Error::Unsupported("EHCI state-changing standard request"))
        );
        assert_eq!(m.lock().unwrap().io, before);
    }
}

#[test]
fn failed_clear_halt_status_preserves_real_halt_and_toggle_then_quarantines() {
    let (mut c, m, _, pipes) = attached();
    let pipe = output(&pipes);
    let first = c.submit_bulk_out(pipe, &[1], 1_000_000).unwrap();
    c.poll(&first).unwrap().unwrap();
    m.lock().unwrap().mode = Mode::Stall;
    let stalled = c.submit_bulk_out(pipe, &[2], 1_000_000).unwrap();
    assert!(c.poll(&stalled).is_err());
    {
        let mut m = m.lock().unwrap();
        m.mode = Mode::Complete;
        m.hold_status = Some(1);
    }
    assert_eq!(c.clear_halt(pipe), Err(Error::Timeout));
    let ep =
        c.ports[0].as_ref().unwrap().endpoints[schedule::endpoint_index(pipe.endpoint)].unwrap();
    assert!(ep.halted && ep.toggle);
    let before = m.lock().unwrap().io;
    assert_eq!(
        c.submit_bulk_out(pipe, &[3], 1000).err(),
        Some(Error::Quarantined)
    );
    assert_eq!(m.lock().unwrap().io, before);
}

#[test]
fn failed_set_configuration_status_revokes_old_pipe_before_ambiguous_bus_effect() {
    let (mut c, m, id, pipes) = attached();
    let old = output(&pipes).configuration;
    m.lock().unwrap().hold_status = Some(9);
    assert_eq!(c.configure(&id, 0).err(), Some(Error::Timeout));
    let device = c.ports[0].as_ref().unwrap();
    assert_eq!(device.configuration, old + 1);
    assert!(device.endpoints.iter().all(Option::is_none));
    let before = m.lock().unwrap().io;
    assert_eq!(
        c.submit_bulk_out(output(&pipes), &[1], 1000).err(),
        Some(Error::Quarantined)
    );
    assert_eq!(m.lock().unwrap().io, before);
}

#[test]
fn actual_descriptor_dma_rejects_ambiguous_endpoint_and_invalid_hs_packet_metadata() {
    for fault in 0..4 {
        let m = Arc::new(Mutex::new(Shared::new()));
        let mut c = controller(m.clone());
        let id = c.reset_port(1).unwrap();
        c.set_address(&id, 7).unwrap();
        {
            let mut m = m.lock().unwrap();
            match fault {
                0 => {
                    m.description[20] = 2;
                    m.description[21] = 3;
                } // nonbulk2 then bulk2 duplicate
                1 => m.description[22] = 0xff, // illegal HS bulk MPS511
                2 => m.description[4] = 2,     // no second default interface
                _ => m.description[13] = 3,    // declared endpointcount mismatch
            }
        }
        assert_eq!(c.configure(&id, 0).err(), Some(Error::Invalid));
        assert!(
            c.ports[0]
                .as_ref()
                .unwrap()
                .endpoints
                .iter()
                .all(Option::is_none)
        );
        assert!(
            !m.lock()
                .unwrap()
                .setup_trace
                .iter()
                .any(|setup| setup[1] == 9)
        );
    }
}

#[test]
fn impossible_residual_is_never_copied_as_completed_dma() {
    let (mut c, m, _, pipes) = attached();
    let ticket = c.submit_bulk_in(input(&pipes), 100, 1_000_000).unwrap();
    {
        let mut m = m.lock().unwrap();
        let token = (m.u32(24) & !(0x7fff << 16)) | (101 << 16);
        m.put(24, token);
    }
    assert!(matches!(c.poll(&ticket), Err(Error::Device(_))));
    assert!(c.ready().is_err());
}

#[test]
#[ignore = "requires fresh unchanged pinned Linux qtd_fill C trace"]
fn actual_production_qtd_encoder_matches_unchanged_linux_qtd_fill_trace() {
    // This compares pure descriptor arithmetic, including54 cases whose
    // payload arithmetic crosses4GiB. It manufactures no DMA authority:
    // Arena::new separately refuses a native arena crossing its segment.
    let path = std::env::var("STELA_EHCI_QTD_ORACLE").expect("fresh C trace required");
    let trace = std::fs::read_to_string(path).unwrap();
    let mut lines = trace.lines();
    assert_eq!(
        lines.next(),
        Some(
            "case_id\taddress\tbytes\ttoken_in\tmaxpacket\tcount\thw_token\tlength\tbuf0\tbuf1\tbuf2\tbuf3\tbuf4\thi0\thi1\thi2\thi3\thi4"
        )
    );
    let mut cases = Vec::new();
    for address in [
        0x1000_0000u64,
        0x1000_03ff,
        0x1000_0fff,
        0x1000_1000,
        0xffff_f000,
        0xffff_ffff,
        0x1_2345_6abc,
    ] {
        for bytes in [1, 8, 511, 512, 4095, 4096, 4097, 16_384] {
            for pid in 0..3u32 {
                for toggle in [false, true] {
                    cases.push((address, bytes, pid, toggle));
                }
            }
        }
    }
    for pid in 0..3u32 {
        for toggle in [false, true] {
            cases.push((0, 0, pid, toggle));
        }
    }
    assert_eq!(cases.len(), 342);
    for (case, (address, bytes, pid, toggle)) in cases.into_iter().enumerate() {
        let fields: Vec<&str> = lines
            .next()
            .expect("missing required C case")
            .split('\t')
            .collect();
        assert_eq!(fields.len(), 18);
        let decimal = |index: usize| fields[index].parse::<usize>().unwrap();
        let hex = |index: usize| u64::from_str_radix(fields[index], 16).unwrap();
        assert_eq!(decimal(0), case);
        assert_eq!(hex(1), address);
        assert_eq!(decimal(2), bytes);
        let token = (3 << 10) | ACTIVE | (pid << 8) | if toggle { TOGGLE } else { 0 };
        assert_eq!(hex(3), u64::from(token));
        assert_eq!(decimal(4), if pid == 2 { 64 } else { 512 });
        assert_eq!(decimal(5), bytes);
        assert_eq!(decimal(7), bytes);
        let words = schedule::Qtd {
            bytes,
            pid: pid << 8,
            toggle,
            next: 1,
            alternate: 1,
        }
        .encode(address)
        .unwrap();
        assert_eq!(u64::from(words[2]), hex(6), "case{case} token");
        for page in 0..5 {
            assert_eq!(
                u64::from(words[3 + page]),
                hex(8 + page),
                "case{case} low{page}"
            );
            assert_eq!(
                u64::from(words[8 + page]),
                hex(13 + page),
                "case{case} high{page}"
            );
        }
    }
    assert!(lines.next().is_none(), "unexpected extra C cases");
}

#[test]
fn initial_halted_requester_drain_failure_precedes_fresh_mapping_and_bme() {
    let m = Arc::new(Mutex::new(Shared::new()));
    m.lock().unwrap().drain_fail = true;
    let failure = match Controller::initialize(Box::new(Access(m.clone()))) {
        Err(failure) => failure,
        Ok(_) => panic!("initial drain failure accepted"),
    };
    assert_eq!(failure.error, Error::Dma(DmaError::DrainUnavailable));
    assert!(failure.is_quarantined());
    let m = m.lock().unwrap();
    assert_eq!(m.allocations, 0);
    assert!(!m.mapped && !m.bme && !m.retired);
    assert_eq!(m.words[(OP + STS) / 4] & (HALT | ASS | PSS), HALT);
    assert!(
        !m.writes
            .iter()
            .any(|(offset, value)| *offset == OP + CMD && *value & RESET != 0)
    );
}

#[test]
fn sticky_legacy_smi_enable_refuses_handoff_before_reset_dma_and_bme() {
    let m = Arc::new(Mutex::new(Shared::new()));
    m.lock().unwrap().sticky_smi = true;
    let failure = match Controller::initialize(Box::new(Access(m.clone()))) {
        Err(failure) => failure,
        Ok(_) => panic!("unmasked firmware SMI accepted"),
    };
    assert_eq!(failure.error, Error::Register);
    assert!(failure.is_quarantined());
    let m = m.lock().unwrap();
    assert_eq!(m.allocations, 0);
    assert!(!m.bme && !m.mapped);
    assert!(
        !m.writes
            .iter()
            .any(|(offset, value)| *offset == OP + CMD && *value & RESET != 0)
    );
}
