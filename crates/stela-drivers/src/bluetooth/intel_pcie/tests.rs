extern crate std;
use super::*;
use crate::bus::dma::RegionAllocator;
use alloc::{collections::BTreeMap, rc::Rc};
use core::cell::{Cell, RefCell};
// Independent device model reads the published physical context and descriptor
// bytes, then writes its own completion/index memory and real W1C causes.
unsafe fn bytes(address: u64, n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| {
            // SAFETY: each caller uses an address read from live test DMA.
            unsafe { (address as *const u8).add(i).read_volatile() }
        })
        .collect()
}
unsafe fn read16(address: u64) -> u16 {
    // SAFETY: caller supplies a live two-byte DMA field.
    u16::from_le_bytes(unsafe { bytes(address, 2) }.try_into().unwrap())
}
unsafe fn read64(address: u64) -> u64 {
    // SAFETY: caller supplies a live packed eight-byte DMA field.
    u64::from_le_bytes(unsafe { bytes(address, 8) }.try_into().unwrap())
}
unsafe fn write(address: u64, b: &[u8]) {
    for (i, &byte) in b.iter().enumerate() {
        // SAFETY: caller owns the indicated live hardware-model DMA destination.
        unsafe {
            (address as *mut u8).add(i).write_volatile(byte);
        }
    }
}
pub(super) struct Model {
    identity: Identity,
    regs: BTreeMap<usize, u32>,
    time: Cell<u64>,
    writes: Vec<(u64, usize, u32)>,
    byte_writes: Vec<(usize, u8)>,
    armed: bool,
    arm_count: usize,
    retire_count: usize,
    dropped: usize,
    stop_ack: bool,
    reset_ack: bool,
    clear_stop_status_on_reset: bool,
    arm_error: bool,
    retire_error: bool,
    silence_rom: bool,
    initial_stage: u32,
    time_step: u64,
    tx_delay: u64,
    completion_override: Option<u32>,
    duplicate_completion: bool,
    silence_tx: bool,
    silence_reset: bool,
    auto_reset_stage: u32,
    auto_boot: bool,
    d0_stage: u32,
    silence_d0: bool,
    d0_delay: u64,
    read_error: Option<usize>,
    write_error: Option<(usize, usize)>,
    panic_write: Option<usize>,
    byte_error: Option<usize>,
    context: u64,
    posted: BTreeMap<u16, u64>,
    transmitted: Vec<Vec<u8>>,
    ready_at: u64,
    boot_count: usize,
    hci_script: VecDeque<(Vec<u8>, Vec<Vec<u8>>)>,
    reset_stages: VecDeque<u32>,
    deferred_events: Vec<Vec<u8>>,
    event_cursor: u16,
    rx_before_reset: Option<Vec<u8>>,
    delay_hci_events: bool,
    delayed_events: Vec<Vec<u8>>,
}
impl Model {
    fn new(device: u16) -> Self {
        Self {
            identity: Identity {
                address: Address {
                    segment: 0,
                    bus: 0,
                    device: 20,
                    function: 1,
                },
                vendor: 0x8086,
                device,
                subsystem_vendor: 0x8086,
                subsystem_device: 1,
            },
            regs: BTreeMap::from([
                (FUNC, MASTER_STOPPED),
                (BOOT, 0),
                (FH_MASK, u32::MAX),
                (HW_MASK, u32::MAX),
                (HW_REV, 0x12345678),
                (RF_ID, 0x55667788),
            ]),
            time: Cell::new(0),
            writes: Vec::new(),
            byte_writes: Vec::new(),
            armed: false,
            arm_count: 0,
            retire_count: 0,
            dropped: 0,
            stop_ack: true,
            reset_ack: true,
            clear_stop_status_on_reset: false,
            arm_error: false,
            retire_error: false,
            silence_rom: false,
            initial_stage: ROM,
            time_step: 1000,
            tx_delay: 0,
            completion_override: None,
            duplicate_completion: false,
            silence_tx: false,
            silence_reset: false,
            auto_reset_stage: IML,
            auto_boot: false,
            d0_stage: OP,
            silence_d0: false,
            d0_delay: 0,
            read_error: None,
            write_error: None,
            panic_write: None,
            byte_error: None,
            context: 0,
            posted: BTreeMap::new(),
            transmitted: Vec::new(),
            ready_at: 0,
            boot_count: 0,
            hci_script: VecDeque::new(),
            reset_stages: VecDeque::new(),
            deferred_events: Vec::new(),
            event_cursor: 0,
            rx_before_reset: None,
            delay_hci_events: false,
            delayed_events: Vec::new(),
        }
    }
    fn reg(&self, o: usize) -> u32 {
        *self.regs.get(&o).unwrap_or(&0)
    }
    fn cause(&mut self, fh: u32, hw: u32) {
        self.regs.insert(FH_CAUSE, self.reg(FH_CAUSE) | fh);
        self.regs.insert(HW_CAUSE, self.reg(HW_CAUSE) | hw);
    }
    fn context(&mut self) {
        self.context = u64::from(self.reg(CI_LOW)) | u64::from(self.reg(CI_HIGH)) << 32;
        assert_ne!(self.context, 0);
        // SAFETY: source context is published from the test allocation.
        let c = unsafe { bytes(self.context, 152) };
        assert_eq!(
            &c[..16],
            &[1, 0, 152, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(&c[48..56], &[2, 0, 2, 0, 4, 0, 0, 0]);
        assert_eq!(&c[72..80], &[32, 0, 32, 0, 0, 0, 0, 0]);
        assert_eq!(
            &c[96..112],
            &[64, 0, 1, 0, 64, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(&c[120..128], &[208, 0, 0, 0, 0x10, 0, 0, 0]);
        assert!(c[128..].iter().all(|b| *b == 0));
        for o in [16, 24, 32, 40, 56, 64, 80, 88, 112] {
            // SAFETY: these are live source context address members.
            assert_eq!(unsafe { read64(self.context + o) } % 128, 0);
        }
        // SAFETY: DBGC fragment's address is read from the live context.
        let fragment = unsafe { read64(self.context + 112) };
        // SAFETY: live208-byte model fragment.
        let b = unsafe { bytes(fragment, 208) };
        assert_eq!(
            &b[..16],
            &[
                0xa5, 0xa5, 0xa5, 0xa5, 1, 0, 0, 0, 196, 0, 0, 0, 16, 0, 0, 0
            ]
        );
        for chunk in b[16..].as_chunks::<12>().0 {
            assert_eq!(&chunk[8..], &(256 * 1024u32).to_le_bytes());
        }
    }
    fn dma_pointer(&self, offset: u64) -> u64 {
        // SAFETY: context is live and this source field is an eight-byte address.
        unsafe { read64(self.context + offset) }
    }
    fn index(&self, offset: u64, q: u64) -> u16 {
        // SAFETY: source index arrays contain two live u16 members.
        unsafe { read16(self.dma_pointer(offset) + q * 2) }
    }
    fn set_index(&self, offset: u64, q: u64, value: u16) {
        // SAFETY: this is a device-owned live completion/consumption index.
        unsafe {
            write(self.dma_pointer(offset) + q * 2, &value.to_le_bytes());
        }
    }
    fn receive(&mut self, tag: u16, kind: u32, payload: &[u8], padding: &[u8]) -> u32 {
        let address = self
            .posted
            .remove(&tag)
            .expect("device completed an unposted buffer");
        let mut data = vec![0u8; 8];
        let n = 4 + payload.len() + padding.len();
        data[..2].copy_from_slice(&(n as u16).to_le_bytes());
        data[2] = 1;
        data.extend_from_slice(&kind.to_le_bytes());
        data.extend_from_slice(payload);
        data.extend_from_slice(padding);
        // SAFETY: completion returns this exclusively device-owned buffer.
        unsafe {
            write(address, &data);
        }
        let tail = self.index(32, 1);
        let d = u32::from(tag) | (1 << 31);
        // SAFETY: model owns the next live completion ring entry.
        unsafe {
            write(self.dma_pointer(88) + u64::from(tail) * 4, &d.to_le_bytes());
        }
        self.set_index(32, 1, (tail + 1) % 64);
        self.cause(2, 0);
        d
    }
    fn write32(&mut self, o: usize, v: u32) {
        self.writes.push((self.time.get(), o, v));
        assert_ne!(self.panic_write, Some(o), "injected native register unwind");
        match o {
            FH_CAUSE | HW_CAUSE | AUTOMASK => {
                let old = self.reg(o);
                self.regs.insert(o, old & !v);
            }
            FUNC => {
                let mut value = v;
                if v & MASTER_DISCONNECT != 0 {
                    if self.stop_ack {
                        value |= MASTER_STOPPED;
                    } else {
                        value &= !MASTER_STOPPED;
                    }
                }
                if v & RESET != 0 && self.reset_ack {
                    if self.clear_stop_status_on_reset {
                        value &= !MASTER_STOPPED;
                    }
                    self.regs.insert(BOOT, 0);
                    self.posted.clear();
                    self.context = 0;
                    self.regs.insert(FH_MASK, u32::MAX);
                    self.regs.insert(HW_MASK, u32::MAX);
                    self.regs.insert(FH_CAUSE, 0);
                    self.regs.insert(HW_CAUSE, 0);
                    self.ready_at = self.time.get()
                        + if self.identity.device == 0x4d76 {
                            50_000
                        } else {
                            0
                        };
                }
                if v & (ENABLE | MAC_INIT | FUNC_INIT) == ENABLE | MAC_INIT | FUNC_INIT {
                    assert!(self.armed);
                    assert!(
                        self.time.get() >= self.ready_at,
                        "source BlazarIW reset delay omitted"
                    );
                    value &= !MASTER_STOPPED;
                    self.context();
                    if !self.silence_rom {
                        self.regs.insert(BOOT, self.initial_stage);
                        self.cause(0, 1);
                    }
                }
                self.regs.insert(o, value);
            }
            DOORBELL => {
                let next = (v & 0xffff) as u16;
                if v >> 16 == 513 {
                    assert_eq!(self.index(16, 1), next);
                    let index = (next + 63) % 64;
                    // SAFETY: model fetches the published FRBD.
                    let d = unsafe { bytes(self.dma_pointer(80) + u64::from(index) * 16, 16) };
                    let tag = u16::from_le_bytes([d[0], d[1]]);
                    assert_eq!(tag, index);
                    assert!(d[2..8].iter().all(|b| *b == 0));
                    let address = u64::from_le_bytes(d[8..].try_into().unwrap());
                    assert!(
                        self.posted.insert(tag, address).is_none(),
                        "live RX DMA overwritten"
                    );
                    self.set_index(24, 1, next);
                    if self.auto_boot && self.boot_count == 1 && self.posted.len() == 61 {
                        self.auto_boot = false;
                        self.receive(0, 4, &[0xff, 7, 2, 0, 1, 0, 0, 0, 0], &[]);
                    }
                    if self.posted.len() == 61 && !self.deferred_events.is_empty() {
                        for event in core::mem::take(&mut self.deferred_events) {
                            self.receive(self.event_cursor, 4, &event, &[0xa5]);
                            self.event_cursor = (self.event_cursor + 1) % 64;
                        }
                    }
                } else {
                    assert_eq!(v >> 16, 0);
                    assert_eq!(self.index(16, 0), next);
                    let index = (next + 31) % 32;
                    // SAFETY: model fetches the live source packed TFD.
                    let d = unsafe { bytes(self.dma_pointer(56) + u64::from(index) * 16, 16) };
                    assert_eq!(d[0], 0);
                    assert_eq!(d[3], 0);
                    assert_eq!(&d[12..], &[0; 4]);
                    let size = usize::from(u16::from_le_bytes([d[1], d[2]]));
                    let address = u64::from_le_bytes(d[4..12].try_into().unwrap());
                    // SAFETY: source descriptor gives a DMA packet buffer.
                    let packet = unsafe { bytes(address, size) };
                    self.transmitted.push(packet.clone());
                    self.time.set(self.time.get() + self.tx_delay);
                    if !self.silence_tx {
                        let tail = self.index(32, 0);
                        let completion = self
                            .completion_override
                            .unwrap_or(u32::from(next) | (1 << 24) | (1 << 31));
                        // SAFETY: device-owned live URBD0 and head index.
                        unsafe {
                            write(
                                self.dma_pointer(64) + u64::from(tail) * 4,
                                &completion.to_le_bytes(),
                            );
                        }
                        if self.duplicate_completion {
                            // SAFETY: second source completion entry in live DMA.
                            unsafe {
                                write(
                                    self.dma_pointer(64) + u64::from((tail + 1) % 32) * 4,
                                    &completion.to_le_bytes(),
                                );
                            }
                        }
                        self.set_index(
                            32,
                            0,
                            (tail + if self.duplicate_completion { 2 } else { 1 }) % 32,
                        );
                        self.set_index(24, 0, next);
                        self.cause(1, 0);
                        let opcode = if packet[..4] == 1u32.to_le_bytes() {
                            u16::from_le_bytes([packet[4], packet[5]])
                        } else {
                            0
                        };
                        if matches!(opcode, 0xfc01 | 0x0c03) && !self.silence_reset {
                            if let Some(event) = self.rx_before_reset.take() {
                                self.receive(self.event_cursor, 4, &event, &[0xb6]);
                                self.event_cursor = (self.event_cursor + 1) % 64;
                            }
                            self.boot_count += 1;
                            self.posted.clear();
                            self.regs.insert(
                                BOOT,
                                if opcode == 0xfc01 {
                                    self.reset_stages
                                        .pop_front()
                                        .unwrap_or(self.auto_reset_stage)
                                } else {
                                    OP
                                },
                            );
                            self.cause(0, 1);
                        }
                        if let Some((expected, events)) = self.hci_script.pop_front() {
                            assert_eq!(&packet[4..], expected);
                            if opcode == 0xfc01 {
                                self.event_cursor = 0;
                                self.deferred_events = events;
                            } else if self.delay_hci_events {
                                self.delayed_events = events;
                            } else {
                                for event in events {
                                    self.receive(self.event_cursor, 4, &event, &[0xa5]);
                                    self.event_cursor = (self.event_cursor + 1) % 64;
                                }
                            }
                        }
                    }
                }
                self.regs.insert(o, v);
            }
            SLEEP => {
                assert_eq!(v, 0);
                self.time.set(self.time.get() + self.d0_delay);
                if !self.silence_d0 {
                    self.regs.insert(BOOT, self.d0_stage);
                    self.cause(0, 1);
                }
                self.regs.insert(o, v);
            }
            _ => {
                self.regs.insert(o, v);
            }
        }
    }
}
pub(super) struct ModelPlatform(Rc<RefCell<Model>>);
// SAFETY: explicit independent hardware model. All pointers name kept test
// DMA, operations are serialized, and the enclosing test backing outlives it.
unsafe impl Platform for ModelPlatform {
    fn identity(&self) -> Identity {
        self.0.borrow().identity
    }
    fn read32(&mut self, o: usize) -> Result<u32> {
        let mut m = self.0.borrow_mut();
        if o == FH_CAUSE && m.reg(FH_CAUSE) == 0 && !m.delayed_events.is_empty() {
            for event in core::mem::take(&mut m.delayed_events) {
                let tag = m.event_cursor;
                m.receive(tag, 4, &event, &[0xb6]);
                m.event_cursor = (tag + 1) % 64;
            }
        }
        if m.read_error == Some(o) {
            m.read_error = None;
            return Err(Error::Mmio("model register read fault"));
        }
        Ok(m.reg(o))
    }
    fn write32(&mut self, o: usize, v: u32) -> Result<()> {
        let mut m = self.0.borrow_mut();
        m.write32(o, v);
        if let Some((offset, remaining)) = m.write_error
            && offset == o
        {
            if remaining == 1 {
                m.write_error = None;
                return Err(Error::Mmio("model effect-then-error write fault"));
            }
            m.write_error = Some((offset, remaining - 1));
        }
        Ok(())
    }
    fn write8(&mut self, o: usize, v: u8) -> Result<()> {
        let mut m = self.0.borrow_mut();
        m.byte_writes.push((o, v));
        if m.byte_error == Some(o) {
            m.byte_error = None;
            return Err(Error::Mmio("model effect-then-error IVAR fault"));
        }
        Ok(())
    }
    fn now_us(&self) -> u64 {
        let m = self.0.borrow();
        let t = m.time.get();
        m.time.set(t.wrapping_add(m.time_step));
        t
    }
    fn arm_vector_zero(&mut self) -> Result<()> {
        let mut m = self.0.borrow_mut();
        m.arm_count += 1;
        assert_eq!(m.reg(FH_MASK), !3);
        assert_eq!(m.reg(HW_MASK), !0x29);
        if m.arm_error {
            return Err(Error::Mmio("model route arm fault"));
        }
        m.armed = true;
        Ok(())
    }
    fn retire_vector_zero(&mut self) -> Result<()> {
        let mut m = self.0.borrow_mut();
        m.retire_count += 1;
        if m.retire_error {
            return Err(Error::Mmio("model real route drain fault"));
        }
        m.armed = false;
        Ok(())
    }
}
impl Drop for ModelPlatform {
    fn drop(&mut self) {
        let mut m = self.0.borrow_mut();
        m.dropped += 1;
        assert!(!m.armed, "platform dropped before actual route drain");
    }
}
pub(super) fn allocator(backing: &mut [u64]) -> RegionAllocator {
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: test keeps backing, with exclusive physical/DMA use until drop.
    unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) }
}
pub(super) fn transport(
    device: u16,
    dma: &mut RegionAllocator,
) -> (Transport<ModelPlatform>, Rc<RefCell<Model>>) {
    let m = Rc::new(RefCell::new(Model::new(device)));
    (Transport::new(ModelPlatform(m.clone()), dma).unwrap(), m)
}
#[test]
fn every_source_id_boots_published_context_and_posts_exactly61_buffers() {
    if crate::model_test_process::isolate() {
        return;
    }
    assert_eq!(
        DEVICE_IDS,
        &[0x4d76, 0xa876, 0xe376, 0xe476, 0xd346, 0x6e74]
    );
    for &id in DEVICE_IDS {
        let mut backing = vec![0u64; 1024 * 1024];
        let mut dma = allocator(&mut backing);
        let (mut t, m) = transport(id, &mut dma);
        t.start().unwrap();
        assert_eq!(t.state(), State::Rom);
        assert_eq!(t.hardware_revision(), Some(0x12345678));
        assert_eq!(t.radio_id(), Some(0x55667788));
        assert_eq!(m.borrow().posted.len(), 61);
        assert_eq!(m.borrow().arm_count, 1);
        assert_eq!(t.poll().unwrap(), []);
        assert_eq!(
            m.borrow().byte_writes,
            [
                (IVAR, 0x80),
                (IVAR + 1, 0x80),
                (IVAR + 0x20, 0x80),
                (IVAR + 0x23, 0x80),
                (IVAR + 0x25, 0x80)
            ]
        );
        t.close().unwrap();
        assert_eq!(t.state(), State::Closed);
        assert_eq!(m.borrow().retire_count, 1);
        drop(t);
        assert_eq!(m.borrow().dropped, 1);
    }
}
#[test]
fn tfd_payload_and_source_next_index_completions_wrap_without_hci_fabrication() {
    if crate::model_test_process::isolate() {
        return;
    }
    let mut backing = vec![0u64; 1024 * 1024];
    let mut dma = allocator(&mut backing);
    let (mut t, m) = transport(0xa876, &mut dma);
    t.start().unwrap();
    for i in 0..70 {
        let payload = [1, 0, 3, 0, 0xaa, i as u8, 0xbb];
        let receipt = t.send(Kind::Acl, &payload).unwrap();
        assert_eq!(receipt.descriptor, (i % 32) as u16);
        assert_eq!(receipt.next_index, ((i + 1) % 32) as u16);
        assert!(receipt.alive.is_none());
        let expected = [&2u32.to_le_bytes()[..], &payload[..]].concat();
        assert_eq!(m.borrow().transmitted.last(), Some(&expected));
        assert!(t.poll().unwrap().is_empty());
    }
}
#[test]
fn rx_completions_drain_coalesced_frames_preserve_padding_and_rearm_only_returned_dma() {
    if crate::model_test_process::isolate() {
        return;
    }
    let mut backing = vec![0u64; 1024 * 1024];
    let mut dma = allocator(&mut backing);
    let (mut t, m) = transport(0xa876, &mut dma);
    t.start().unwrap();
    for start in (0..128).step_by(4) {
        for i in start..start + 4 {
            m.borrow_mut()
                .receive((i % 64) as u16, 4, &[0xff, 2, 0x97, i as u8], &[0xaa, 0xbb]);
        }
        let packets = t.poll().unwrap();
        assert_eq!(packets.len(), 4);
        assert_eq!(m.borrow().posted.len(), 61);
        for (i, p) in packets.iter().enumerate() {
            assert_eq!(p.kind, Kind::Event);
            assert!(p.diagnostic);
            assert_eq!(p.bytes, [0xff, 2, 0x97, (start + i) as u8]);
            assert_eq!(p.padding, [0xaa, 0xbb]);
            assert_eq!(p.receive_header[2], 1);
        }
    }
}
#[test]
fn intel_reset_requires_tx_and_gp0_then_real_boot_event_before_d0() {
    if crate::model_test_process::isolate() {
        return;
    }
    let mut backing = vec![0u64; 1024 * 1024];
    let mut dma = allocator(&mut backing);
    let (mut t, m) = transport(0x4d76, &mut dma);
    t.start().unwrap();
    m.borrow_mut().auto_reset_stage = OP;
    m.borrow_mut().auto_boot = true;
    let receipt = t.send(Kind::Command, &[1, 0xfc, 0]).unwrap();
    assert_eq!(receipt.alive.unwrap().boot_stage, OP);
    assert_eq!(t.state(), State::Operational);
    assert!(t.enter_d0().is_err());
    let packets = t.poll().unwrap();
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].bytes, [0xff, 7, 2, 0, 1, 0, 0, 0, 0]);
    assert!(!packets.iter().any(|p| p.bytes.first() == Some(&0x0e)));
    assert_eq!(t.enter_d0().unwrap().boot_stage, OP);
    assert!(!t.awaiting_d0);
    assert_eq!(
        t.send(Kind::Command, &[3, 0x0c, 0])
            .unwrap()
            .alive
            .unwrap()
            .boot_stage,
        OP
    );
    assert_eq!(m.borrow().posted.len(), 61);
}
#[test]
fn iml_reset_does_not_invent_an_operational_d0_transition() {
    if crate::model_test_process::isolate() {
        return;
    }
    let mut backing = vec![0u64; 1024 * 1024];
    let mut dma = allocator(&mut backing);
    let (mut t, m) = transport(0xa876, &mut dma);
    t.start().unwrap();
    let receipt = t.send(Kind::Command, &[1, 0xfc, 0]).unwrap();
    assert_eq!(receipt.alive.unwrap().boot_stage, IML);
    assert_eq!(t.state(), State::Iml);
    assert!(t.enter_d0().is_err());
    assert!(!m.borrow().writes.iter().any(|(_, o, _)| *o == SLEEP));
}

#[test]
fn d0_requires_complete_boot_notification_and_subsequent_operational_stage() {
    if crate::model_test_process::isolate() {
        return;
    }
    for stage in [ROM, IML, OP | D3] {
        let mut backing = vec![0u64; 1024 * 1024];
        let mut dma = allocator(&mut backing);
        let (mut t, m) = transport(0xa876, &mut dma);
        t.start().unwrap();
        m.borrow_mut().auto_reset_stage = OP;
        t.send(Kind::Command, &[1, 0xfc, 0]).unwrap();
        // This is a complete HCI event, but an incomplete intel_bootup body.
        m.borrow_mut().receive(0, 4, &[0xff, 2, 2, 0], &[]);
        assert_eq!(t.poll().unwrap()[0].bytes, [0xff, 2, 2, 0]);
        assert!(t.enter_d0().is_err());
        assert!(!m.borrow().writes.iter().any(|(_, o, _)| *o == SLEEP));
        m.borrow_mut()
            .receive(1, 4, &[0xff, 7, 2, 0, 1, 0, 0, 0, 0], &[]);
        t.poll().unwrap();
        m.borrow_mut().d0_stage = stage;
        assert!(matches!(t.enter_d0(), Err(Error::Controller(_))));
        assert_eq!(t.state(), State::Failed);
        assert_eq!(t.fault_snapshot().unwrap().boot_stage, stage);
    }
}

#[test]
fn old_gp0_cannot_acknowledge_a_silent_d0_request() {
    if crate::model_test_process::isolate() {
        return;
    }
    for silent in [false, true] {
        let mut backing = vec![0u64; 1024 * 1024];
        let mut dma = allocator(&mut backing);
        let (mut t, m) = transport(0xa876, &mut dma);
        t.start().unwrap();
        m.borrow_mut().auto_reset_stage = OP;
        m.borrow_mut().auto_boot = true;
        t.send(Kind::Command, &[1, 0xfc, 0]).unwrap();
        t.poll().unwrap();
        m.borrow_mut().silence_d0 = silent;
        // An older OP GP0 is already pending before the new SLEEP write.
        m.borrow_mut().cause(0, 1);
        if silent {
            assert!(matches!(t.enter_d0(), Err(Error::Timeout(_))));
            assert_eq!(t.state(), State::Failed);
        } else {
            assert_eq!(t.enter_d0().unwrap().boot_stage, OP);
        }
    }
}

#[test]
fn d0_preexisting_stage_change_and_late_write_acknowledgment_are_refused() {
    if crate::model_test_process::isolate() {
        return;
    }
    for lost_stage in [false, true] {
        let mut backing = vec![0u64; 1024 * 1024];
        let mut dma = allocator(&mut backing);
        let (mut t, m) = transport(0xa876, &mut dma);
        t.start().unwrap();
        m.borrow_mut().auto_reset_stage = OP;
        m.borrow_mut().auto_boot = true;
        t.send(Kind::Command, &[1, 0xfc, 0]).unwrap();
        t.poll().unwrap();
        if lost_stage {
            m.borrow_mut().regs.insert(BOOT, ROM);
            m.borrow_mut().cause(0, 1);
            assert!(matches!(t.enter_d0(), Err(Error::Protocol { .. })));
            assert!(!m.borrow().writes.iter().any(|(_, o, _)| *o == SLEEP));
        } else {
            m.borrow_mut().d0_delay = 4_000_000;
            assert!(matches!(t.enter_d0(), Err(Error::Timeout(_))));
        }
        assert_eq!(t.state(), State::Failed);
    }
}

#[test]
fn rom_stage_without_gp0_never_starts_rx_or_claims_startup() {
    if crate::model_test_process::isolate() {
        return;
    }
    let mut backing = vec![0u64; 1024 * 1024];
    let mut dma = allocator(&mut backing);
    let (mut t, m) = transport(0xa876, &mut dma);
    m.borrow_mut().silence_rom = true;
    let error = t.start().unwrap_err();
    assert!(matches!(error, Error::Timeout(_)));
    assert_eq!(t.state(), State::Failed);
    assert!(m.borrow().posted.is_empty());
    assert!(t.hardware_revision().is_none());
    assert_eq!(m.borrow().retire_count, 1);
    let writes = m.borrow().writes.len();
    assert!(t.start().is_err());
    assert_eq!(m.borrow().writes.len(), writes);
    drop(t);
    assert_eq!(m.borrow().dropped, 1);
}
#[test]
fn abort_lockdown_halt_and_mailbox_fault_observations_survive_cleanup() {
    if crate::model_test_process::isolate() {
        return;
    }
    for stage in [
        ROM | (1 << 10),
        ROM | (1 << 11),
        ROM | (1 << 13),
        ROM | (1 << 14),
    ] {
        let mut backing = vec![0u64; 1024 * 1024];
        let mut dma = allocator(&mut backing);
        let (mut t, m) = transport(0xa876, &mut dma);
        m.borrow_mut().initial_stage = stage;
        m.borrow_mut().regs.insert(MAILBOX_STATUS, 5);
        m.borrow_mut().regs.insert(MAILBOX[0], 0x1234);
        m.borrow_mut().regs.insert(MAILBOX[2], 0x5678);
        let e = t.start().unwrap_err();
        let Error::Controller(snapshot) = e else {
            panic!("raw controller fault lost")
        };
        assert_eq!(snapshot.boot_stage, stage);
        assert_eq!(snapshot.mailboxes, [Some(0x1234), None, Some(0x5678), None]);
        assert_eq!(t.snapshot().boot_stage, 0);
        assert_eq!(t.fault_snapshot().unwrap().boot_stage, stage);
    }
}
#[test]
fn silent_tx_with_failed_retirement_keeps_first_fault() {
    if crate::model_test_process::isolate() {
        return;
    }
    let mut backing = vec![0u64; 1024 * 1024];
    let mut dma = allocator(&mut backing);
    let (mut t, m) = transport(0xa876, &mut dma);
    t.start().unwrap();
    m.borrow_mut().silence_tx = true;
    m.borrow_mut().stop_ack = false;
    let e = t.send(Kind::Acl, &[1, 0, 1, 0, 0xaa]).unwrap_err();
    assert!(matches!(e, Error::Cleanup { .. }));
    assert_eq!(t.state(), State::Failed);
    assert!(!t.retired);
    assert!(!t.pending.unwrap().complete);
    assert_eq!(t.fault_snapshot().unwrap().boot_stage, ROM);
    let bytes = t.memory().tx.bytes().to_vec();
    let writes = m.borrow().writes.len();
    let fault = t.fault().cloned();
    assert!(t.send(Kind::Acl, &[1, 0, 1, 0, 0xbb]).is_err());
    assert!(t.poll().is_err());
    assert!(t.close().is_err());
    assert_eq!(t.memory().tx.bytes(), bytes);
    assert_eq!(m.borrow().writes.len(), writes);
    assert_eq!(t.fault(), fault.as_ref());
    drop(t);
    assert_eq!(m.borrow().retire_count, 1);
    assert_eq!(m.borrow().dropped, 0);
}
#[test]
fn missing_bus_master_ack_or_failed_route_drain_never_release_native_ownership() {
    if crate::model_test_process::isolate() {
        return;
    }
    for route in [false, true] {
        let mut backing = vec![0u64; 1024 * 1024];
        let mut dma = allocator(&mut backing);
        let (mut t, m) = transport(0xa876, &mut dma);
        t.start().unwrap();
        if route {
            m.borrow_mut().retire_error = true;
        } else {
            m.borrow_mut().stop_ack = false;
        }
        assert!(t.close().is_err());
        assert_eq!(t.state(), State::Failed);
        assert!(!t.retired);
        let writes = m.borrow().writes.len();
        drop(t);
        assert_eq!(m.borrow().writes.len(), writes);
        assert_eq!(m.borrow().dropped, 0);
        assert_eq!(m.borrow().retire_count, 1);
    }
}

fn assert_terminal(t: &mut Transport<ModelPlatform>, m: &Rc<RefCell<Model>>) {
    assert_eq!(t.state(), State::Failed);
    assert!(t.fault().is_some());
    assert!(t.fault_snapshot().is_some());
    let fault = t.fault().cloned();
    let writes = m.borrow().writes.len();
    let byte_writes = m.borrow().byte_writes.len();
    let tx = t.memory().tx.bytes().to_vec();
    let rx = t.memory().rx.bytes().to_vec();
    assert!(t.start().is_err());
    assert!(t.send(Kind::Acl, &[1, 0, 0, 0]).is_err());
    assert!(t.poll().is_err());
    let _ = t.close();
    assert_eq!(m.borrow().writes.len(), writes);
    assert_eq!(m.borrow().byte_writes.len(), byte_writes);
    assert_eq!(t.memory().tx.bytes(), tx);
    assert_eq!(t.memory().rx.bytes(), rx);
    assert_eq!(t.fault(), fault.as_ref());
}

#[test]
fn mmio_start_read_and_effect_then_write_errors_cannot_reopen_or_rewrite_dma() {
    if crate::model_test_process::isolate() {
        return;
    }
    for failure in 0..20 {
        let mut backing = vec![0u64; 1024 * 1024];
        let mut dma = allocator(&mut backing);
        let (mut t, m) = transport(0xa876, &mut dma);
        match failure {
            0..=5 => {
                m.borrow_mut().read_error =
                    Some([FUNC, BOOT, FH_MASK, HW_MASK, HW_REV, RF_ID][failure]);
            }
            6 => m.borrow_mut().byte_error = Some(IVAR + 0x20),
            _ => {
                m.borrow_mut().write_error = Some(
                    [
                        (FUNC, 1),
                        (FUNC, 2),
                        (FUNC, 3),
                        (FUNC, 4),
                        (CI_LOW, 1),
                        (CI_HIGH, 1),
                        (FH_MASK, 1),
                        (HW_MASK, 1),
                        (FH_CAUSE, 1),
                        (HW_CAUSE, 1),
                        (AUTOMASK, 1),
                        (DOORBELL, 1),
                        (DOORBELL, 61),
                    ][failure - 7],
                );
            }
        }
        assert!(matches!(t.start(), Err(Error::Mmio(_))), "fault {failure}");
        assert_terminal(&mut t, &m);
        assert!(t.retired);
        drop(t);
        assert_eq!(m.borrow().dropped, 1);
    }
}

#[test]
fn active_transfer_errors_keep_first_fault() {
    if crate::model_test_process::isolate() {
        return;
    }
    for operation in 0..7 {
        for cleanup_fails in [false, true] {
            let mut backing = vec![0u64; 1024 * 1024];
            let mut dma = allocator(&mut backing);
            let (mut t, m) = transport(0xa876, &mut dma);
            t.start().unwrap();
            if cleanup_fails {
                m.borrow_mut().stop_ack = false;
            }
            let error = match operation {
                0 => {
                    m.borrow_mut().write_error = Some((DOORBELL, 1));
                    t.send(Kind::Acl, &[1, 0, 0, 0]).unwrap_err()
                }
                1 => {
                    m.borrow_mut().receive(0, 4, &[0xff, 1, 9], &[]);
                    m.borrow_mut().write_error = Some((DOORBELL, 1));
                    t.poll().unwrap_err()
                }
                2..=5 => {
                    m.borrow_mut().cause(0, 1);
                    if operation == 2 {
                        m.borrow_mut().read_error = Some(HW_CAUSE);
                    } else {
                        m.borrow_mut().write_error =
                            Some(([FH_CAUSE, HW_CAUSE, AUTOMASK][operation - 3], 1));
                    }
                    t.poll().unwrap_err()
                }
                _ => {
                    m.borrow_mut().auto_reset_stage = OP;
                    m.borrow_mut().auto_boot = true;
                    t.send(Kind::Command, &[1, 0xfc, 0]).unwrap();
                    t.poll().unwrap();
                    m.borrow_mut().write_error = Some((SLEEP, 1));
                    t.enter_d0().unwrap_err()
                }
            };
            assert!(matches!(error, Error::Mmio(_) | Error::Cleanup { .. }));
            assert_eq!(t.retired, !cleanup_fails);
            assert_terminal(&mut t, &m);
            drop(t);
            assert_eq!(m.borrow().dropped, usize::from(!cleanup_fails));
        }
    }
}

#[test]
fn uncertain_mask_or_reset_cleanup_write_never_releases_platform() {
    if crate::model_test_process::isolate() {
        return;
    }
    for fault in [(FH_MASK, 1), (HW_MASK, 1), (FUNC, 1), (FUNC, 2)] {
        let mut backing = vec![0u64; 1024 * 1024];
        let mut dma = allocator(&mut backing);
        let (mut t, m) = transport(0xa876, &mut dma);
        t.start().unwrap();
        m.borrow_mut().write_error = Some(fault);
        assert!(matches!(t.close(), Err(Error::Mmio(_))));
        assert!(!t.retired);
        assert_terminal(&mut t, &m);
        drop(t);
        assert_eq!(m.borrow().dropped, 0);
    }
}
#[test]
fn late_completion_and_expired_publication_budget_cannot_report_success() {
    if crate::model_test_process::isolate() {
        return;
    }
    for before_publication in [false, true] {
        let mut backing = vec![0u64; 1024 * 1024];
        let mut dma = allocator(&mut backing);
        let (mut t, m) = transport(0xa876, &mut dma);
        t.start().unwrap();
        if before_publication {
            m.borrow_mut().time_step = 500_000;
        } else {
            m.borrow_mut().tx_delay = 600_000;
        }
        assert!(matches!(
            t.send(Kind::Acl, &[1, 0, 1, 0, 0xaa]),
            Err(Error::Timeout(_))
        ));
        assert_eq!(t.state(), State::Failed);
        assert_eq!(
            m.borrow().transmitted.len(),
            usize::from(!before_publication)
        );
    }
}
#[test]
fn stale_mismatched_queue_count_immediate_and_duplicate_tx_completions_are_terminal() {
    if crate::model_test_process::isolate() {
        return;
    }
    for completion in [
        0x81000000u32,
        0x81000002,
        0x81010001,
        0x82000001,
        0x01000001,
    ] {
        let mut backing = vec![0u64; 1024 * 1024];
        let mut dma = allocator(&mut backing);
        let (mut t, m) = transport(0xa876, &mut dma);
        t.start().unwrap();
        m.borrow_mut().completion_override = Some(completion);
        assert!(matches!(
            t.send(Kind::Acl, &[1, 0, 0, 0]),
            Err(Error::Protocol { .. })
        ));
        assert!(!t.pending.unwrap().complete);
        assert_eq!(t.state(), State::Failed);
    }
    let mut backing = vec![0u64; 1024 * 1024];
    let mut dma = allocator(&mut backing);
    let (mut t, m) = transport(0xa876, &mut dma);
    t.start().unwrap();
    m.borrow_mut().duplicate_completion = true;
    assert!(matches!(
        t.send(Kind::Acl, &[1, 0, 0, 0]),
        Err(Error::Protocol { .. })
    ));
    assert_eq!(t.state(), State::Failed);
}
#[test]
fn unsolicited_tx_completion_is_not_assigned_to_a_new_packet() {
    if crate::model_test_process::isolate() {
        return;
    }
    let mut backing = vec![0u64; 1024 * 1024];
    let mut dma = allocator(&mut backing);
    let (mut t, m) = transport(0xa876, &mut dma);
    t.start().unwrap();
    let mut hardware = m.borrow_mut();
    // SAFETY: model owns these live source completion ring/head locations.
    unsafe {
        write(hardware.dma_pointer(64), &0x81000001u32.to_le_bytes());
    }
    hardware.set_index(32, 0, 1);
    hardware.cause(1, 0);
    drop(hardware);
    assert!(matches!(
        t.send(Kind::Acl, &[1, 0, 0, 0]),
        Err(Error::Protocol { .. })
    ));
    assert!(m.borrow().transmitted.is_empty());
    assert_eq!(t.state(), State::Failed);
}
#[test]
fn malformed_rfh_hci_type_payload_and_unposted_rx_tags_never_reuse_owned_storage() {
    if crate::model_test_process::isolate() {
        return;
    }
    for case in 0..5 {
        let mut backing = vec![0u64; 1024 * 1024];
        let mut dma = allocator(&mut backing);
        let (mut t, m) = transport(0xa876, &mut dma);
        t.start().unwrap();
        let raw = if case < 3 {
            let mut h = m.borrow_mut();
            let address = *h.posted.get(&0).unwrap();
            h.receive(
                0,
                if case == 1 { 99 } else { 4 },
                if case == 2 {
                    &[0x0e, 99]
                } else {
                    &[0xff, 1, 2]
                },
                &[],
            );
            if case == 0 {
                // SAFETY: buffer is now completed and exclusively returned.
                unsafe {
                    write(address, &4090u16.to_le_bytes());
                }
            }
            Some(address)
        } else {
            let mut h = m.borrow_mut();
            let tag = if case == 3 { 63u32 } else { 64 };
            // SAFETY: model owns the live next completion descriptor.
            unsafe {
                write(h.dma_pointer(88), &(tag | 1 << 31).to_le_bytes());
            }
            h.set_index(32, 1, 1);
            h.cause(2, 0);
            None
        };
        let error = t.poll().unwrap_err();
        assert!(matches!(
            error,
            Error::Packet { .. } | Error::Protocol { .. }
        ));
        assert_eq!(t.state(), State::Failed);
        if let Some(address) = raw {
            // SAFETY: physically retired test backing still keeps this buffer.
            let bytes = unsafe { bytes(address, 8) };
            assert_eq!(bytes[2], 1);
        }
    }
}
#[test]
fn out_of_order_rx_cannot_overwrite_a_still_posted_buffer_during_rearm() {
    if crate::model_test_process::isolate() {
        return;
    }
    let mut backing = vec![0u64; 1024 * 1024];
    let mut dma = allocator(&mut backing);
    let (mut t, m) = transport(0xa876, &mut dma);
    t.start().unwrap();
    let address = *m.borrow().posted.get(&0).unwrap();
    // SAFETY: immutable observation of test DMA's initial device-read/write data.
    let before = unsafe { bytes(address, 4096) };
    for tag in [1, 2, 3, 4] {
        m.borrow_mut().receive(tag, 4, &[0xff, 1, 9], &[]);
    }
    assert!(matches!(
        t.poll(),
        Err(Error::Protocol {
            requirement: "free actual RX descriptor and buffer",
            ..
        })
    ));
    // SAFETY: real modeled reset retired storage, which remains held.
    assert_eq!(unsafe { bytes(address, 4096) }, before);
    assert_eq!(t.state(), State::Failed);
}
#[test]
fn reset_transmit_does_not_complete_without_matching_alive_stage() {
    if crate::model_test_process::isolate() {
        return;
    }
    for no_cause in [false, true] {
        let mut backing = vec![0u64; 1024 * 1024];
        let mut dma = allocator(&mut backing);
        let (mut t, m) = transport(0xa876, &mut dma);
        t.start().unwrap();
        if no_cause {
            m.borrow_mut().silence_reset = true;
        } else {
            m.borrow_mut().auto_reset_stage = ROM;
        }
        assert!(matches!(
            t.send(Kind::Command, &[1, 0xfc, 0]),
            Err(Error::Timeout(_) | Error::Protocol { .. })
        ));
        assert_eq!(t.state(), State::Failed);
        assert!(t.pending.unwrap().complete);
        assert!(t.received.is_empty());
    }
}
#[test]
fn host_packet_validation_rejects_without_hardware_effect_and_accepts_all_real_types() {
    if crate::model_test_process::isolate() {
        return;
    }
    let mut backing = vec![0u64; 1024 * 1024];
    let mut dma = allocator(&mut backing);
    let (mut t, m) = transport(0xa876, &mut dma);
    t.start().unwrap();
    for (kind, bytes) in [
        (Kind::Event, vec![0x0e, 0]),
        (Kind::Acl, vec![1, 0, 1, 0]),
        (Kind::Command, vec![1, 0]),
        (Kind::Sco, vec![1, 0, 1]),
        (Kind::Iso, vec![1, 0, 1, 0]),
    ] {
        let n = m.borrow().transmitted.len();
        assert!(t.send(kind, &bytes).is_err());
        assert_eq!(m.borrow().transmitted.len(), n);
        assert_eq!(t.state(), State::Rom);
    }
    for (kind, bytes) in [
        (Kind::Command, vec![5, 0xfc, 1, 0xff]),
        (Kind::Acl, vec![1, 0, 1, 0, 0xaa]),
        (Kind::Sco, vec![1, 0, 1, 0xaa]),
        (Kind::Iso, vec![1, 0, 1, 0xc0, 0xaa]),
    ] {
        t.send(kind, &bytes).unwrap();
    }
}

fn firmware_complete(opcode: u16, payload: &[u8]) -> Vec<u8> {
    let mut event = vec![0x0e, (3 + payload.len()) as u8, 1];
    event.extend_from_slice(&opcode.to_le_bytes());
    event.extend_from_slice(payload);
    event
}
fn firmware_command(opcode: u16, payload: &[u8]) -> Vec<u8> {
    let mut command = opcode.to_le_bytes().to_vec();
    command.push(payload.len() as u8);
    command.extend_from_slice(payload);
    command
}
fn firmware_tlv(engine: u8, stage: u8) -> Vec<u8> {
    firmware_tlv_variant(engine, stage, 0x1e)
}
fn firmware_tlv_variant(engine: u8, stage: u8, variant: u8) -> Vec<u8> {
    let input = crate::bluetooth::intel::tests::tlv_version_variant(false, engine, variant);
    let mut output = vec![0];
    let mut at = 1;
    while at < input.len() {
        let n = usize::from(input[at + 1]);
        match input[at] {
            0x1c => output.extend_from_slice(&[0x1c, 1, stage]),
            0x1f if stage != 1 => output.extend_from_slice(&[0x1f, 4, 9, 0, 0, 0]),
            _ => output.extend_from_slice(&input[at..at + n + 2]),
        }
        at += n + 2;
    }
    if stage != 1 {
        output.extend_from_slice(&[0x50, 5, b'p', b'c', b'i', b'e', 0]);
    }
    output
}
fn append_firmware_upload(m: &mut Model, engine: u8, image: &[u8]) {
    // Spell source sections independently; expected bytes never come from the
    // production parser. The synthetic image contains no vendor signatures.
    let sections: Vec<(u8, &[u8])> = if engine >= 2 {
        crate::bluetooth::intel::tests::hybrid_fragments(image)
    } else if engine == 0 {
        vec![
            (0, &image[..128]),
            (3, &image[128..380]),
            (3, &image[380..384]),
            (2, &image[388..640]),
            (2, &image[640..644]),
            (1, &image[964..]),
        ]
    } else {
        vec![
            (0, &image[644..772]),
            (3, &image[772..868]),
            (2, &image[868..964]),
            (1, &image[964..]),
        ]
    };
    for (kind, data) in sections {
        let mut params = vec![kind];
        params.extend_from_slice(data);
        m.hci_script.push_back((
            firmware_command(0xfc09, &params),
            vec![firmware_complete(0xfc09, &[0])],
        ));
    }
    m.hci_script
        .back_mut()
        .unwrap()
        .1
        .push(vec![0xff, 5, 6, 0, 9, 0xfc, 0]);
    m.hci_script.push_back((
        firmware_command(0xfc01, &[0, 1, 0, 1, 0, 0, 0x20, 0]),
        vec![
            vec![0xff, 2, 0x97, 0x12],
            vec![0xff, 7, 2, 0, 1, 0, 0, 0, 0],
        ],
    ));
}
#[test]
fn shared_firmware_engine_uses_real_pcie_dma_for_rsa_ecdsa_iml_op_and_d0() {
    if crate::model_test_process::isolate() {
        return;
    }
    use crate::{
        bluetooth::intel::{self, TransportIdentity},
        firmware::{Catalog, Provenance, Resource},
    };
    use sha2::{Digest, Sha256};
    for (variant, engine) in [
        (0x1e, 0),
        (0x1e, 1),
        (0x1f, 0),
        (0x1f, 1),
        (0x22, 0),
        (0x22, 1),
        (0x20, 2),
        (0x20, 3),
        (0x21, 2),
        (0x21, 3),
        (0x22, 2),
        (0x22, 3),
    ] {
        let mut backing = vec![0u64; 1024 * 1024];
        let mut dma = allocator(&mut backing);
        let (mut t, m) = transport(0xa876, &mut dma);
        t.start().unwrap();
        let replies = [
            firmware_tlv_variant(engine, 1, variant),
            firmware_tlv_variant(engine, 2, variant),
            firmware_tlv_variant(engine, 3, variant),
        ];
        let bus = TransportIdentity::Pcie(t.identity());
        let before = intel::TlvIdentity::parse_transport(bus, &replies[0]).unwrap();
        let iml = intel::TlvIdentity::parse_transport(bus, &replies[1]).unwrap();
        let hardware = before.hardware_label();
        let revisions = [before.revision_label(), iml.iml_revision_label(&before)];
        let names = [
            before.filename("sfi"),
            iml.filename("sfi"),
            iml.filename("ddc"),
        ];
        let image = if engine >= 2 {
            intel::tests::hybrid_image()
        } else {
            intel::tests::combined_image()
        };
        let mut resources = Vec::new();
        for (index, name) in names.iter().enumerate() {
            let bytes = if index == 2 {
                vec![3, 1, 2, 0xaa]
            } else {
                image.clone()
            };
            resources.push(Resource {
                name,
                target: before.target(&hardware, &revisions[usize::from(index != 0)]),
                provenance: Provenance {
                    source: "Stela synthetic PCIe model",
                    revision: "1",
                    member: "synthetic",
                    license: "MIT",
                },
                expected_length: bytes.len(),
                expected_sha256: Sha256::digest(&bytes).into(),
                bytes,
            });
        }
        let catalog = Catalog::from_handoff(resources).unwrap();
        let mut h = m.borrow_mut();
        h.hci_script.push_back((
            firmware_command(0xfc05, &[0xff]),
            vec![firmware_complete(0xfc05, &replies[0])],
        ));
        append_firmware_upload(&mut h, engine, &image);
        h.hci_script.push_back((
            firmware_command(0xfc05, &[0xff]),
            vec![firmware_complete(0xfc05, &replies[1])],
        ));
        if variant == 0x1f {
            h.hci_script.push_back((
                firmware_command(0xfc0a, &[1, 0xb]),
                vec![firmware_complete(0xfc0a, &[0])],
            ));
        }
        append_firmware_upload(&mut h, engine, &image);
        h.hci_script.push_back((
            firmware_command(0xfc05, &[0xff]),
            vec![firmware_complete(0xfc05, &replies[2])],
        ));
        h.hci_script.push_back((
            firmware_command(0x1009, &[]),
            vec![firmware_complete(0x1009, &[0, 1, 2, 3, 4, 5, 6])],
        ));
        h.hci_script.push_back((
            firmware_command(0xfc8b, &[3, 1, 2, 0xaa]),
            vec![firmware_complete(0xfc8b, &[0])],
        ));
        h.hci_script.push_back((
            firmware_command(0xfc05, &[0xff]),
            vec![firmware_complete(0xfc05, &replies[2])],
        ));
        h.reset_stages = VecDeque::from([IML, OP]);
        drop(h);
        let report = firmware::initialize(
            &mut t,
            &catalog,
            intel::PlatformInputs {
                dsbr: intel::DsbrInput::Present {
                    revision: 7,
                    raw: 0xb1,
                },
            },
        )
        .unwrap();
        assert_eq!(report.initialization.stages.len(), 2);
        assert_eq!(
            report.initialization.dsbr.input,
            intel::DsbrInput::Present {
                revision: 7,
                raw: 0xb1
            }
        );
        assert_eq!(
            report.initialization.dsbr.applied,
            (variant == 0x1f).then_some([1, 0xb])
        );
        assert_eq!(report.initialization.address, [1, 2, 3, 4, 5, 6]);
        assert!(
            report
                .initialization
                .stages
                .iter()
                .all(|s| s.firmware.target_driver == "intel-bluetooth-pcie-tlv")
        );
        assert!(
            report.received.iter().all(|p| p.padding == [0xa5]
                && p.receive_header[2] == 1
                && p.completion >> 31 == 1)
        );
        assert!(m.borrow().hci_script.is_empty());
        assert_eq!(report.received.iter().filter(|p| p.diagnostic).count(), 2);
        assert!(
            !report
                .received
                .iter()
                .any(|p| p.bytes.first() == Some(&0x0e) && p.bytes.get(3..5) == Some(&[1, 0xfc]))
        );
        assert_eq!(
            m.borrow()
                .writes
                .iter()
                .filter(|(_, o, _)| *o == SLEEP)
                .count(),
            1
        );
        assert_eq!(t.state(), State::Operational);
        let mut h = m.borrow_mut();
        for (opcode, params, reply) in [
            (0xfc05, vec![0xff], replies[2].clone()),
            (0x1009, vec![], vec![0, 1, 2, 3, 4, 5, 6]),
            (0xfc05, vec![0xff], replies[2].clone()),
        ] {
            h.hci_script.push_back((
                firmware_command(opcode, &params),
                vec![firmware_complete(opcode, &reply)],
            ));
        }
        drop(h);
        let empty = Catalog::from_handoff(vec![]).unwrap();
        let observed =
            firmware::initialize(&mut t, &empty, intel::PlatformInputs::default()).unwrap();
        assert!(matches!(
            observed.initialization.evidence,
            intel::OwnedFirmwareEvidence::RunningUnknown
        ));
        assert!(observed.initialization.stages.is_empty());
        assert_eq!(observed.received.len(), 3);
    }
}

#[test]
fn pcie_firmware_faults_keep_native_transcript_and_uncertain_cleanup_ownership() {
    if crate::model_test_process::isolate() {
        return;
    }
    use crate::{bluetooth::intel, firmware::Catalog};
    for operation in 0..3 {
        for cleanup_fails in [false, true] {
            let mut backing = vec![0u64; 1024 * 1024];
            let mut dma = allocator(&mut backing);
            let (mut t, m) = transport(0xa876, &mut dma);
            t.start().unwrap();
            let reply = match operation {
                0 => firmware_complete(0xfc05, &[1]),
                1 => firmware_complete(0xfc05, &firmware_tlv(0, 3)),
                _ => firmware_complete(0xfc05, &firmware_tlv(0, 1)),
            };
            m.borrow_mut()
                .hci_script
                .push_back((firmware_command(0xfc05, &[0xff]), vec![reply.clone()]));
            m.borrow_mut().stop_ack = !cleanup_fails;
            let empty = Catalog::from_handoff(vec![]).unwrap();
            let error =
                firmware::initialize(&mut t, &empty, intel::PlatformInputs::default()).unwrap_err();
            assert_eq!(error.received.len(), 1);
            assert_eq!(error.received[0].bytes, reply);
            assert_eq!(error.received[0].padding, [0xa5]);
            assert_eq!(error.received[0].completion, 1 << 31);
            let cause = if let intel::Error::PcieCleanup { cause, .. } = error.cause.as_ref() {
                cause.as_ref()
            } else {
                error.cause.as_ref()
            };
            assert!(matches!(
                (operation, cause),
                (0, intel::Error::Controller { .. })
                    | (1, intel::Error::Protocol(_))
                    | (2, intel::Error::Resource(_))
            ));
            assert_eq!(m.borrow().transmitted.len(), 1);
            assert_eq!(t.retired, !cleanup_fails);
            let writes = m.borrow().writes.len();
            assert!(t.send(Kind::Command, &[5, 0xfc, 1, 0xff]).is_err());
            assert!(t.poll().is_err());
            assert_eq!(m.borrow().writes.len(), writes);
            drop(t);
            assert_eq!(m.borrow().dropped, usize::from(!cleanup_fails));
        }
    }
}

#[test]
fn firmware_error_drains_complete_native_packets_queued_before_send_or_poll_failure() {
    if crate::model_test_process::isolate() {
        return;
    }
    use crate::{
        bluetooth::intel::{self, TransportIdentity},
        firmware::{Catalog, Provenance, Resource},
    };
    use sha2::{Digest, Sha256};
    for reset_fault in [false, true] {
        for cleanup_fails in [false, true] {
            let mut backing = vec![0u64; 1024 * 1024];
            let mut dma = allocator(&mut backing);
            let (mut t, m) = transport(0xa876, &mut dma);
            t.start().unwrap();
            let version = firmware_tlv(0, 1);
            let before = intel::TlvIdentity::parse_transport(
                TransportIdentity::Pcie(t.identity()),
                &version,
            )
            .unwrap();
            let hardware = before.hardware_label();
            let revision = before.revision_label();
            let name = before.filename("sfi");
            let image = intel::tests::combined_image();
            let catalog = Catalog::from_handoff(vec![Resource {
                name: &name,
                target: before.target(&hardware, &revision),
                provenance: Provenance {
                    source: "Stela synthetic PCIe fault model",
                    revision: "1",
                    member: "synthetic",
                    license: "MIT",
                },
                expected_length: image.len(),
                expected_sha256: Sha256::digest(&image).into(),
                bytes: image.clone(),
            }])
            .unwrap();
            let original = vec![0xff, 2, 0x97, 0x48];
            let mut h = m.borrow_mut();
            if reset_fault {
                h.hci_script.push_back((
                    firmware_command(0xfc05, &[0xff]),
                    vec![firmware_complete(0xfc05, &version)],
                ));
                append_firmware_upload(&mut h, 0, &image);
                h.reset_stages.push_back(ROM);
                h.rx_before_reset = Some(original.clone());
            } else {
                h.delay_hci_events = true;
                // send receives only the TX acknowledgment. Native events()
                // subsequently polls a valid frame followed by malformed HCI.
                h.hci_script.push_back((
                    firmware_command(0xfc05, &[0xff]),
                    vec![original.clone(), vec![0xff, 99]],
                ));
            }
            h.stop_ack = !cleanup_fails;
            drop(h);
            let error = firmware::initialize(&mut t, &catalog, intel::PlatformInputs::default())
                .unwrap_err();
            let packet = error
                .received
                .iter()
                .find(|p| p.bytes == original)
                .expect("complete pre-fault PCIe packet omitted");
            assert!(packet.diagnostic);
            assert_eq!(packet.padding, [0xb6]);
            assert_eq!(packet.receive_header[2], 1);
            assert_eq!(packet.completion >> 31, 1);
            assert!(t.received.is_empty());
            assert_eq!(t.retired, !cleanup_fails);
            let writes = m.borrow().writes.len();
            assert!(t.poll().is_err());
            assert_eq!(m.borrow().writes.len(), writes);
            drop(t);
            assert_eq!(m.borrow().dropped, usize::from(!cleanup_fails));
        }
    }
}

mod native_models;

mod ownership;

struct NeverFirmware;
impl crate::firmware::Provider for NeverFirmware {
    fn load(
        &self,
        _: crate::firmware::Requirement<'_>,
    ) -> core::result::Result<crate::firmware::Image<'_>, crate::firmware::Error> {
        panic!("closed transport must not request firmware")
    }
}
#[test]
fn retirement_unwind_seals_core_before_the_first_register_effect() {
    if crate::model_test_process::isolate() {
        return;
    }
    let mut backing = vec![0u64; 1024 * 1024];
    let mut dma = allocator(&mut backing);
    let (mut transport, model) = transport(0x4d76, &mut dma);
    transport.start().unwrap();
    model.borrow_mut().panic_write = Some(FH_MASK);
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| transport.close())).is_err());
    assert_eq!(transport.state(), State::Closing);
    model.borrow_mut().panic_write = None;
    let writes = model.borrow().writes.clone();
    let error = Error::Unsupported("interrupted Intel PCIe retirement");
    assert_eq!(transport.start(), Err(error.clone()));
    assert_eq!(transport.poll(), Err(error.clone()));
    assert_eq!(
        transport.send(Kind::Command, &[3, 12, 0]),
        Err(error.clone())
    );
    assert_eq!(transport.enter_d0(), Err(error.clone()));
    assert!(!transport.ready());
    assert!(
        firmware::initialize(
            &mut transport,
            &NeverFirmware,
            crate::bluetooth::intel::PlatformInputs::default()
        )
        .is_err()
    );
    assert_eq!(transport.close(), Err(error));
    drop(transport);
    assert_eq!(model.borrow().writes, writes);
    assert_eq!(model.borrow().retire_count, 0);
}
