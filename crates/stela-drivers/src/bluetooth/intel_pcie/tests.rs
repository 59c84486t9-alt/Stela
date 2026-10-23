use super::*;
use crate::bus::dma::RegionAllocator;
use alloc::{collections::BTreeMap, rc::Rc};
use core::cell::{Cell, RefCell};
// Independent device model reads the published physical context and descriptor
// bytes, then writes its own completion/index memory and real W1C causes.
unsafe fn bytes(address: u64, n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| {
            // SAFETY: each caller uses an address read from live retained test DMA.
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
struct Model {
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
    context: u64,
    posted: BTreeMap<u16, u64>,
    transmitted: Vec<Vec<u8>>,
    ready_at: u64,
    boot_count: usize,
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
            context: 0,
            posted: BTreeMap::new(),
            transmitted: Vec::new(),
            ready_at: 0,
            boot_count: 0,
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
        // SAFETY: source context is published from the retained test allocation.
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
        // SAFETY: DBGC fragment's address is read from the actual live context.
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
                    // SAFETY: model fetches the actual published FRBD.
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
                    // SAFETY: source descriptor gives a retained DMA packet buffer.
                    let packet = unsafe { bytes(address, size) };
                    self.transmitted.push(packet.clone());
                    self.time.set(self.time.get() + self.tx_delay);
                    if !self.silence_tx {
                        let tail = self.index(32, 0);
                        let completion = self
                            .completion_override
                            .unwrap_or(u32::from(next) | (1 << 24) | (1 << 31));
                        // SAFETY: actual device-owned live URBD0 and head index.
                        unsafe {
                            write(
                                self.dma_pointer(64) + u64::from(tail) * 4,
                                &completion.to_le_bytes(),
                            );
                        }
                        if self.duplicate_completion {
                            // SAFETY: second actual source completion entry in live DMA.
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
                            self.boot_count += 1;
                            self.posted.clear();
                            self.regs.insert(
                                BOOT,
                                if opcode == 0xfc01 {
                                    self.auto_reset_stage
                                } else {
                                    OP
                                },
                            );
                            self.cause(0, 1);
                        }
                    }
                }
                self.regs.insert(o, v);
            }
            SLEEP => {
                assert_eq!(v, 0);
                self.regs.insert(BOOT, self.d0_stage);
                self.cause(0, 1);
                self.regs.insert(o, v);
            }
            _ => {
                self.regs.insert(o, v);
            }
        }
    }
}
struct ModelPlatform(Rc<RefCell<Model>>);
// SAFETY: explicit independent hardware model. All pointers name retained test
// DMA, operations are serialized, and the enclosing test backing outlives it.
unsafe impl Platform for ModelPlatform {
    fn identity(&self) -> Identity {
        self.0.borrow().identity
    }
    fn read32(&mut self, o: usize) -> Result<u32> {
        Ok(self.0.borrow().reg(o))
    }
    fn write32(&mut self, o: usize, v: u32) -> Result<()> {
        self.0.borrow_mut().write32(o, v);
        Ok(())
    }
    fn write8(&mut self, o: usize, v: u8) -> Result<()> {
        self.0.borrow_mut().byte_writes.push((o, v));
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
fn allocator(backing: &mut [u64]) -> RegionAllocator {
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: test retains backing, with exclusive physical/DMA use until drop.
    unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) }
}
fn transport(
    device: u16,
    dma: &mut RegionAllocator,
) -> (Transport<ModelPlatform>, Rc<RefCell<Model>>) {
    let m = Rc::new(RefCell::new(Model::new(device)));
    (Transport::new(ModelPlatform(m.clone()), dma).unwrap(), m)
}
#[test]
fn every_source_id_boots_actual_published_context_and_posts_exactly61_buffers() {
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
fn actual_tfd_payload_and_source_next_index_completions_wrap_without_hci_fabrication() {
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
fn intel_reset_requires_actual_tx_and_gp0_then_real_boot_event_before_d0() {
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
fn rom_stage_without_actual_gp0_never_starts_rx_or_claims_startup() {
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
fn actual_abort_lockdown_halt_and_mailbox_fault_observations_survive_cleanup() {
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
fn silent_tx_and_failed_physical_retirement_keep_first_fault_live_bytes_and_platform() {
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
    let bytes = t.memory.tx.bytes().to_vec();
    let writes = m.borrow().writes.len();
    let fault = t.fault().cloned();
    assert!(t.send(Kind::Acl, &[1, 0, 1, 0, 0xbb]).is_err());
    assert!(t.poll().is_err());
    assert!(t.close().is_err());
    assert_eq!(t.memory.tx.bytes(), bytes);
    assert_eq!(m.borrow().writes.len(), writes);
    assert_eq!(t.fault(), fault.as_ref());
    drop(t);
    assert_eq!(m.borrow().retire_count, 1);
    assert_eq!(m.borrow().dropped, 0);
}
#[test]
fn missing_bus_master_ack_or_failed_route_drain_never_release_native_ownership() {
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
#[test]
fn late_completion_and_expired_publication_budget_cannot_report_success() {
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
            // SAFETY: physically retired test backing still retains this buffer.
            let bytes = unsafe { bytes(address, 8) };
            assert_eq!(bytes[2], 1);
        }
    }
}
#[test]
fn out_of_order_rx_cannot_overwrite_a_still_posted_buffer_during_rearm() {
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
    // SAFETY: real modeled reset retired storage, which remains retained.
    assert_eq!(unsafe { bytes(address, 4096) }, before);
    assert_eq!(t.state(), State::Failed);
}
#[test]
fn reset_transmit_does_not_complete_without_actual_matching_alive_stage() {
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
