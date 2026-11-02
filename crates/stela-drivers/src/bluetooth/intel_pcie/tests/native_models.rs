//! Bounded native IRQ/HCI models: action joins are separate from payload/fabric.
extern crate std;
use super::*;
use crate::{
    Clock,
    bus::{
        irq,
        mmio::owned::PhysicalSpan,
        pci::{ConfigSpace, Function, msi::MsiConfigSpace, msix},
    },
};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Mutex;
const BASE: u64 = 0x1400_0000;
const BAR_BYTES: u64 = 0x10000;
const TABLE: usize = 0x3000;
struct Hardware {
    bt: Model,
    config: [u8; 256],
    table: Vec<u32>,
    table_writes: Vec<(u64, u32)>,
    fail_table: Option<u64>,
    payload_drains: usize,
    msi_drains: usize,
    cpu_after_payload: usize,
    fail_payload: bool,
    fail_posted_msi: bool,
    fail_msi_bind: bool,
    msi_message: Option<irq::MsiMessage>,
    config_drops: usize,
    forbid_config_reads: bool,
    bar_drops: usize,
    register_drops: usize,
    callback_eoi: Arc<AtomicU64>,
    callback_at_automask: Option<&'static irq::Registry<Cpu>>,
    callback_before_hw_restore: Option<&'static irq::Registry<Cpu>>,
    receive_at_automask: bool,
    route: Option<&'static irq::Registry<Cpu>>,
    automasked: bool,
}
impl Hardware {
    fn new() -> Self {
        let mut h = Self {
            bt: Model::new(0xa876),
            config: [0; 256],
            table: vec![0; BAR_BYTES as usize / 4],
            table_writes: Vec::new(),
            fail_table: None,
            payload_drains: 0,
            msi_drains: 0,
            cpu_after_payload: 0,
            fail_payload: false,
            fail_posted_msi: false,
            fail_msi_bind: false,
            msi_message: None,
            config_drops: 0,
            forbid_config_reads: false,
            bar_drops: 0,
            register_drops: 0,
            callback_eoi: Arc::new(AtomicU64::new(0)),
            callback_at_automask: None,
            callback_before_hw_restore: None,
            receive_at_automask: false,
            route: None,
            automasked: false,
        };
        h.put(0, 4, 0xa876_8086);
        h.put(4, 2, 6);
        h.put(6, 2, 0x10);
        h.put(8, 4, 0x0d11_0000);
        h.put(0x10, 4, BASE as u32);
        h.put(0x2c, 4, 0x0001_8086);
        h.put(0x34, 1, 0x50);
        h.put(0x50, 4, 0x11);
        h.put(0x54, 4, TABLE as u32);
        h.put(0x58, 4, 0x4000);
        h
    }
    fn put(&mut self, offset: usize, n: usize, value: u32) {
        self.config[offset..offset + n].copy_from_slice(&value.to_le_bytes()[..n]);
    }
    fn get(&self, offset: u16, n: usize) -> u32 {
        assert!(
            !self.forbid_config_reads,
            "minimum refusal reached configuration"
        );
        let mut b = [0; 4];
        b[..n].copy_from_slice(&self.config[usize::from(offset)..usize::from(offset) + n]);
        u32::from_le_bytes(b)
    }
    fn update_route(&mut self) {
        self.bt.armed = self.get(0x52, 2) & 0xc000 == 0x8000 && self.table[TABLE / 4 + 3] & 1 == 0;
    }
}
struct Config(Arc<Mutex<Hardware>>);
impl ConfigSpace for Config {
    fn read32(&self, offset: u16) -> core::result::Result<u32, crate::bus::pci::ConfigError> {
        Ok(self.0.lock().unwrap().get(offset, 4))
    }
    fn read16(&self, offset: u16) -> core::result::Result<u16, crate::bus::pci::ConfigError> {
        Ok(self.0.lock().unwrap().get(offset, 2) as u16)
    }
    fn read8(&self, offset: u16) -> core::result::Result<u8, crate::bus::pci::ConfigError> {
        Ok(self.0.lock().unwrap().get(offset, 1) as u8)
    }
    fn write16(
        &mut self,
        offset: u16,
        value: u16,
    ) -> core::result::Result<(), crate::bus::pci::ConfigError> {
        let mut h = self.0.lock().unwrap();
        let status = h.get(6, 2);
        h.put(usize::from(offset), 2, u32::from(value));
        assert_eq!(h.get(6, 2), status, "adjacent Status W1C replayed");
        h.update_route();

        Ok(())
    }
    fn write32(
        &mut self,
        _: u16,
        _: u32,
    ) -> core::result::Result<(), crate::bus::pci::ConfigError> {
        panic!("unexpected wide config store");
    }

    fn write8(&mut self, _: u16, _: u8) -> core::result::Result<(), crate::bus::pci::ConfigError> {
        panic!("unexpected narrow configuration write")
    }
}
// SAFETY: independent function model implements exact narrow config effects.
unsafe impl MsiConfigSpace for Config {}
impl Drop for Config {
    fn drop(&mut self) {
        self.0.lock().unwrap().config_drops += 1;
    }
}
struct Bar(Arc<Mutex<Hardware>>);
// SAFETY: independent resource model, same function/epoch and span.
unsafe impl msix::BarAccess for Bar {
    fn physical_span(&self) -> PhysicalSpan {
        PhysicalSpan::new(BASE, BAR_BYTES).unwrap()
    }
    fn accessible(&self, offset: u64, bytes: u64) -> bool {
        offset.checked_add(bytes).is_some_and(|n| n <= BAR_BYTES)
    }
    fn read32(&self, offset: u64) -> core::result::Result<u32, msix::IoError> {
        let h = self.0.lock().unwrap();
        assert_ne!(h.get(0x52, 2) & 0x8000, 0, "table decoder disabled");
        Ok(h.table[offset as usize / 4])
    }
    fn write32(&mut self, offset: u64, value: u32) -> core::result::Result<(), msix::IoError> {
        let mut h = self.0.lock().unwrap();
        assert_eq!(
            h.get(0x52, 2) & 0xc000,
            0xc000,
            "table changed outside actual Function Mask"
        );
        h.table_writes.push((offset, value));
        h.table[offset as usize / 4] = value;
        h.update_route();
        if h.fail_table == Some(offset) {
            h.fail_table = None;
            return Err(msix::IoError);
        }
        Ok(())
    }
}
impl Drop for Bar {
    fn drop(&mut self) {
        self.0.lock().unwrap().bar_drops += 1;
    }
}
struct Registers(Arc<Mutex<Hardware>>);
// SAFETY: explicit independent physical register model, serialized by Mutex;
// MMIO effects precede injected late errors. No production emulation.
unsafe impl native::Registers for Registers {
    fn full_bar(&self) -> PhysicalSpan {
        PhysicalSpan::new(BASE, BAR_BYTES).unwrap()
    }
    fn read32(&self, offset: usize) -> core::result::Result<u32, native::Error> {
        Ok(self.0.lock().unwrap().bt.reg(offset))
    }
    fn write32(&self, offset: usize, value: u32) -> core::result::Result<(), native::Error> {
        if offset == HW_MASK && value != u32::MAX {
            let callback = {
                let mut h = self.0.lock().unwrap();
                h.callback_before_hw_restore.take().inspect(|_| {
                    // An already-posted CPU message after FH restoration's
                    // last pending check, before this HW store takes effect.
                    h.bt.receive(1, 4, &[0xff, 1, 0x42], &[0xb6]);
                })
            };
            if let Some(registry) = callback {
                assert!(registry.dispatch(irq::FIRST_VECTOR));
            }
        }
        let mut h = self.0.lock().unwrap();
        h.bt.write32(offset, value);
        if let Some((at, n)) = h.bt.write_error
            && at == offset
        {
            if n == 1 {
                h.bt.write_error = None;
                return Err(native::Error::Requirement("modeled late register write"));
            }
            h.bt.write_error = Some((at, n - 1));
        }
        let late_callback = if offset == AUTOMASK {
            h.automasked = false;
            let callback = h.callback_at_automask.take();
            if callback.is_some() || core::mem::take(&mut h.receive_at_automask) {
                h.bt.receive(1, 4, &[0xff, 1, 0x42], &[0xb6]);
            }
            callback
        } else {
            None
        };
        let eligible =
            h.bt.reg(FH_CAUSE) & !h.bt.reg(FH_MASK) | h.bt.reg(HW_CAUSE) & !h.bt.reg(HW_MASK);
        let callback = late_callback.or(if h.bt.armed && !h.automasked && eligible != 0 {
            h.route
        } else {
            None
        });
        if callback.is_some() {
            h.automasked = true;
        }
        drop(h);
        if let Some(registry) = callback {
            // An already-posted message can reach the CPU after source
            // masking. Deliver through the registered IDT route.
            assert!(registry.dispatch(irq::FIRST_VECTOR));
        }
        Ok(())
    }
    fn write8(&self, offset: usize, value: u8) -> core::result::Result<(), native::Error> {
        self.0.lock().unwrap().bt.byte_writes.push((offset, value));
        Ok(())
    }
}
impl Drop for Registers {
    fn drop(&mut self) {
        self.0.lock().unwrap().register_drops += 1;
    }
}
struct Cpu {
    hardware: Arc<Mutex<Hardware>>,
    ticks: AtomicU64,
    fail_pending: Arc<AtomicBool>,
    eoi: Arc<AtomicU64>,
}
// SAFETY: independent existing-controller model; its source uses
// the real Registry implementation and this owned vector/CPU inventory.
unsafe impl irq::Platform for Cpu {
    fn check_cpu(&self) -> core::result::Result<(), irq::IrqError> {
        Ok(())
    }
    fn check_process(&self) -> core::result::Result<(), crate::bus::irq::IrqError> {
        self.check_cpu()
    }
    fn save_and_disable(&self) -> u64 {
        0
    }
    unsafe fn restore(&self, _: u64) {}
    fn target(&self, vector: u8) -> core::result::Result<irq::Target, irq::IrqError> {
        Ok(irq::Target {
            destination: 1,
            vector,
        })
    }
    fn pending(&self, _: u8) -> core::result::Result<bool, irq::IrqError> {
        {
            let mut h = self.hardware.lock().unwrap();
            if h.payload_drains != 0 {
                h.cpu_after_payload += 1;
            }
        }
        if self.fail_pending.load(Ordering::Acquire) {
            Err(irq::IrqError::FailedRead)
        } else {
            Ok(false)
        }
    }
    fn eoi(
        &self,
        _vector: u8,
    ) -> core::result::Result<crate::bus::irq::Trigger, crate::bus::irq::IrqError> {
        self.eoi.fetch_add(1, Ordering::Relaxed);
        Ok(crate::bus::irq::Trigger::Edge)
    }
    fn ticks(&self) -> u64 {
        self.ticks.fetch_add(1, Ordering::Relaxed)
    }
    fn timeout_ticks(&self) -> u64 {
        100
    }
    unsafe fn interrupt_window(&self) {}
}
type Driver = Transport<native::NativePlatform<Config, Bar, Registers>>;
type Inputs = native::Inputs<Config, Bar, Registers>;
type Context<T> = (
    T,
    Arc<Mutex<Hardware>>,
    &'static irq::Registry<Cpu>,
    Arc<AtomicBool>,
);
fn inputs() -> Context<Inputs> {
    let h = Arc::new(Mutex::new(Hardware::new()));
    let fail_pending = Arc::new(AtomicBool::new(false));
    let cpu = Cpu {
        hardware: h.clone(),
        ticks: AtomicU64::new(0),
        fail_pending: fail_pending.clone(),
        eoi: h.lock().unwrap().callback_eoi.clone(),
    };
    let registry = Box::leak(Box::new(irq::Registry::new(cpu)));
    h.lock().unwrap().route = Some(registry);
    let address = h.lock().unwrap().bt.identity.address;
    let function = Function::new(address, Config(h.clone())).unwrap();
    // The kept root is the independent Function hardware model,
    // not a numeric token. All BAR/register/config views keep that epoch.
    let inputs = native::Inputs {
        function,
        retained: h.clone(),
        bars: [Some(Bar(h.clone())), None, None, None, None, None],
        registers: Registers(h.clone()),
        clock: Clock {
            ticks_per_microsecond: 1000,
        },
        minimum: crate::minimum_model::owned(Clock {
            ticks_per_microsecond: 1000,
        }),
        interrupts: registry,
        domain: Arc::new(root::Payload(h.clone())),
        msi_route: root::completion(h.clone()),
    };
    (inputs, h, registry, fail_pending)
}
fn attach(dma: &mut RegionAllocator) -> Context<Driver> {
    let (inputs, h, registry, fail_pending) = inputs();
    // SAFETY: explicit independent device/root/IRQ/DMA model, same epoch.
    let platform = match unsafe { native::NativePlatform::new(inputs) } {
        Ok(platform) => platform,
        Err((error, _)) => panic!("native model refused: {error:?}"),
    };
    (
        Transport::new(platform, dma).unwrap(),
        h,
        registry,
        fail_pending,
    )
}
#[test]
fn native_owned_function_msix_callback_and_dma_service_release_only_after_real_retirement() {
    if crate::model_test_process::isolate() {
        return;
    }
    let mut backing = vec![0u64; 1024 * 1024];
    let mut dma = allocator(&mut backing);
    let (mut t, h, registry, _) = attach(&mut dma);
    t.start().unwrap();
    let eoi_before = h.lock().unwrap().callback_eoi.load(Ordering::Relaxed);
    assert!(h.lock().unwrap().bt.armed);
    assert_eq!(h.lock().unwrap().table[TABLE / 4], 0xfee01000);
    assert_eq!(
        h.lock().unwrap().table[TABLE / 4 + 2],
        u32::from(irq::FIRST_VECTOR)
    );
    h.lock().unwrap().bt.receive(0, 4, &[0xff, 1, 9], &[0xa5]);
    assert!(registry.dispatch(irq::FIRST_VECTOR));
    assert!(t.service_pending());
    assert_eq!(h.lock().unwrap().bt.reg(FH_MASK), u32::MAX);
    let packets = t.poll().unwrap();
    assert_eq!(packets[0].bytes, [0xff, 1, 9]);
    assert_eq!(packets[0].padding, [0xa5]);
    assert!(!t.service_pending());
    assert_eq!(h.lock().unwrap().bt.reg(FH_MASK), !3);
    assert_eq!(
        h.lock().unwrap().callback_eoi.load(Ordering::Relaxed),
        eoi_before + 1
    );
    t.send(Kind::Acl, &[1, 0, 1, 0, 0xaa]).unwrap();
    t.close().unwrap();
    assert_eq!(t.state(), State::Closed);
    assert!(!h.lock().unwrap().bt.armed);
    assert!(registry.dispatch(irq::FIRST_VECTOR));
    drop(t);
    let h = h.lock().unwrap();
    assert_eq!((h.config_drops, h.bar_drops, h.register_drops), (1, 1, 1));
}
#[test]
fn native_missing_stop_or_cpu_drain_never_releases_owners() {
    if crate::model_test_process::isolate() {
        return;
    }
    for no_stop in [false, true] {
        let mut backing = vec![0u64; 1024 * 1024];
        let mut dma = allocator(&mut backing);
        let (mut t, h, registry, fail_pending) = attach(&mut dma);
        t.start().unwrap();
        if no_stop {
            h.lock().unwrap().bt.stop_ack = false;
        } else {
            fail_pending.store(true, Ordering::Release);
        }
        assert!(t.close().is_err());
        assert!(!t.retired);
        assert!(
            !h.lock().unwrap().bt.armed,
            "failed stop omitted actual route mask"
        );
        // Failed explicit retirement keeps a closing tombstone for its
        // vector, rather than releasing it or running the callback.
        let eoi = h.lock().unwrap().callback_eoi.load(Ordering::Relaxed);
        assert!(registry.dispatch(irq::FIRST_VECTOR));
        assert_eq!(
            h.lock().unwrap().callback_eoi.load(Ordering::Relaxed),
            eoi + 1
        );
        let writes = h.lock().unwrap().bt.writes.len();
        drop(t);
        let h = h.lock().unwrap();
        assert_eq!(h.bt.writes.len(), writes);
        assert_eq!((h.config_drops, h.bar_drops, h.register_drops), (0, 0, 0));
    }
}
#[test]
fn native_records_real_disconnect_ack_before_reset_can_clear_status() {
    if crate::model_test_process::isolate() {
        return;
    }
    let mut backing = vec![0u64; 1024 * 1024];
    let mut dma = allocator(&mut backing);
    let (mut t, h, _, _) = attach(&mut dma);
    h.lock().unwrap().bt.clear_stop_status_on_reset = true;
    t.start().unwrap();
    t.close().unwrap();
    assert_eq!(h.lock().unwrap().bt.reg(FUNC) & MASTER_STOPPED, 0);
    assert_eq!(t.state(), State::Closed);
    drop(t);
    assert_eq!(h.lock().unwrap().config_drops, 1);
}
#[test]
fn native_late_callback_during_service_keeps_next_rx_and_work_notification() {
    if crate::model_test_process::isolate() {
        return;
    }
    for already_posted in [false, true] {
        let mut backing = vec![0u64; 1024 * 1024];
        let mut dma = allocator(&mut backing);
        let (mut t, h, registry, _) = attach(&mut dma);
        t.start().unwrap();
        h.lock().unwrap().bt.receive(0, 4, &[0xff, 1, 9], &[]);
        assert!(registry.dispatch(irq::FIRST_VECTOR));
        if already_posted {
            h.lock().unwrap().callback_at_automask = Some(registry);
        } else {
            // No CPU message until service restores the real FH mask.
            h.lock().unwrap().receive_at_automask = true;
        }
        assert_eq!(t.poll().unwrap()[0].bytes, [0xff, 1, 9]);
        assert!(
            t.service_pending(),
            "late actual callback notification lost"
        );
        let packets = t.poll().unwrap();
        assert_eq!(packets[0].bytes, [0xff, 1, 0x42]);
        assert_eq!(packets[0].padding, [0xb6]);
        assert!(!t.service_pending());
        t.close().unwrap();
    }
}
#[test]
fn native_callback_between_mask_restores_cannot_reopen_pending_sources() {
    if crate::model_test_process::isolate() {
        return;
    }
    let mut backing = vec![0u64; 1024 * 1024];
    let mut dma = allocator(&mut backing);
    let (mut t, h, registry, _) = attach(&mut dma);
    t.start().unwrap();
    h.lock().unwrap().bt.receive(0, 4, &[0xff, 1, 9], &[]);
    assert!(registry.dispatch(irq::FIRST_VECTOR));
    h.lock().unwrap().callback_before_hw_restore = Some(registry);
    assert_eq!(t.poll().unwrap()[0].bytes, [0xff, 1, 9]);
    assert!(t.service_pending());
    {
        let device = h.lock().unwrap();
        assert!(!device.automasked, "posted message must not imply automask");
        assert_eq!(device.bt.reg(FH_MASK), u32::MAX);
        assert_eq!(device.bt.reg(HW_MASK), u32::MAX);
    }
    let packets = t.poll().unwrap();
    assert_eq!(packets[0].bytes, [0xff, 1, 0x42]);
    assert_eq!(packets[0].padding, [0xb6]);
    assert!(!t.service_pending());
    assert_eq!(h.lock().unwrap().bt.reg(FH_MASK), !FH_ENABLED);
    assert_eq!(h.lock().unwrap().bt.reg(HW_MASK), !HW_ENABLED);
    t.close().unwrap();
}
#[test]
fn msix_failures_keep_raw_fault_and_terminal_owner() {
    if crate::model_test_process::isolate() {
        return;
    }
    for failed_arm in [false, true] {
        let mut backing = vec![0u64; 1024 * 1024];
        let mut dma = allocator(&mut backing);
        let (mut t, h, registry, _) = attach(&mut dma);
        if failed_arm {
            h.lock().unwrap().fail_table = Some(TABLE as u64 + 8);
            assert!(t.start().is_err());
            assert!(matches!(t.fault(), Some(Error::Cleanup { .. })));
            assert!(!t.retired);
        } else {
            t.start().unwrap();
            h.lock().unwrap().bt.write_error = Some((HW_MASK, 1));
            assert!(registry.dispatch(irq::FIRST_VECTOR));
            assert!(matches!(
                t.poll(),
                Err(Error::Native(native::Error::Handler { offset: HW_MASK }))
            ));
        }
        assert_eq!(t.state(), State::Failed);
        let writes = h.lock().unwrap().bt.writes.len();
        assert!(t.send(Kind::Acl, &[1, 0, 0, 0]).is_err());
        assert_eq!(h.lock().unwrap().bt.writes.len(), writes);
    }
}
#[test]
fn native_callback_mask_fault_during_source_restore_refuses_successful_service() {
    if crate::model_test_process::isolate() {
        return;
    }
    let mut backing = vec![0u64; 1024 * 1024];
    let mut dma = allocator(&mut backing);
    let (mut t, h, registry, _) = attach(&mut dma);
    t.start().unwrap();
    h.lock().unwrap().bt.receive(0, 4, &[0xff, 1, 9], &[0xa5]);
    assert!(registry.dispatch(irq::FIRST_VECTOR));
    {
        let mut device = h.lock().unwrap();
        device.receive_at_automask = true;
        device.bt.write_error = Some((HW_MASK, 1));
    }
    assert!(matches!(
        t.poll(),
        Err(Error::Native(native::Error::Handler { offset: HW_MASK }))
    ));
    assert_eq!(t.state(), State::Failed);
    assert_eq!(t.received[0].bytes, [0xff, 1, 9]);
    assert_eq!(t.received[0].padding, [0xa5]);
    let writes = h.lock().unwrap().bt.writes.len();
    assert!(t.poll().is_err());
    assert_eq!(h.lock().unwrap().bt.writes.len(), writes);
}
#[test]
fn native_constructor_refuses_unqualified_inputs_without_writes_and_returns_owners() {
    if crate::model_test_process::isolate() {
        return;
    }
    for failure in 0..7 {
        let (mut inputs, h, registry, _) = inputs();
        match failure {
            0 => inputs.clock.ticks_per_microsecond = 0,
            1 => inputs.function.device = 0xffff,
            2 => inputs.function.config().write16(4, 2).unwrap(),
            3 => inputs.function.config().write16(0x52, 0x8000).unwrap(),
            5 => inputs.clock.ticks_per_microsecond = u64::MAX,
            6 => inputs.clock.ticks_per_microsecond = u64::MAX / 2 / 120_000_000 + 1,
            _ => {
                inputs.bars[0] = None;
            }
        }
        let before = h.lock().unwrap().config;
        // SAFETY: negative independent model inputs; constructor must refuse
        // their unchecked metadata without changing any physical state.
        let (error, returned) = match unsafe { native::NativePlatform::new(inputs) } {
            Ok(_) => panic!("unqualified native inputs admitted"),
            Err(refusal) => refusal,
        };
        assert!(matches!(
            error,
            native::Error::Requirement(_) | native::Error::Msix(msix::Error::ActiveMsix)
        ));
        assert!(Arc::ptr_eq(&returned.registers.0, &h));
        let retained = returned
            .retained
            .clone()
            .downcast::<Mutex<Hardware>>()
            .unwrap();
        assert!(Arc::ptr_eq(&retained, &h));
        assert_eq!(h.lock().unwrap().config, before);
        assert!(h.lock().unwrap().table_writes.is_empty());
        assert!(h.lock().unwrap().bt.writes.is_empty());
        assert!(registry.dispatch(irq::FIRST_VECTOR));
    }
}
#[test]
fn native_msix_irq_dma_attachment_runs_shared_secure_iml_and_operational_firmware() {
    if crate::model_test_process::isolate() {
        return;
    }
    use crate::{
        bluetooth::intel::{self, TransportIdentity},
        firmware::{Catalog, Provenance, Resource},
    };
    use sha2::{Digest, Sha256};
    for (variant, engine) in [(0x1e, 1), (0x20, 3), (0x21, 2)] {
        let mut backing = vec![0u64; 1024 * 1024];
        let mut dma = allocator(&mut backing);
        let (mut t, h, _, _) = attach(&mut dma);
        t.start().unwrap();
        let replies = [
            firmware_tlv_variant(engine, 1, variant),
            firmware_tlv_variant(engine, 2, variant),
            firmware_tlv_variant(engine, 3, variant),
        ];
        let before =
            intel::TlvIdentity::parse_transport(TransportIdentity::Pcie(t.identity()), &replies[0])
                .unwrap();
        let iml =
            intel::TlvIdentity::parse_transport(TransportIdentity::Pcie(t.identity()), &replies[1])
                .unwrap();
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
                    source: "Stela native PCIe IRQ/DMA model",
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
        let mut device = h.lock().unwrap();
        device.bt.hci_script.push_back((
            firmware_command(0xfc05, &[0xff]),
            vec![firmware_complete(0xfc05, &replies[0])],
        ));
        append_firmware_upload(&mut device.bt, engine, &image);
        device.bt.hci_script.push_back((
            firmware_command(0xfc05, &[0xff]),
            vec![firmware_complete(0xfc05, &replies[1])],
        ));
        append_firmware_upload(&mut device.bt, engine, &image);
        for (opcode, params, reply) in [
            (0xfc05, vec![0xff], replies[2].clone()),
            (0x1009, vec![], vec![0, 1, 2, 3, 4, 5, 6]),
            (0xfc8b, vec![3, 1, 2, 0xaa], vec![0]),
            (0xfc05, vec![0xff], replies[2].clone()),
        ] {
            device.bt.hci_script.push_back((
                firmware_command(opcode, &params),
                vec![firmware_complete(opcode, &reply)],
            ));
        }
        device.bt.reset_stages = VecDeque::from([IML, OP]);
        let eoi = device.callback_eoi.clone();
        let before_irqs = eoi.load(Ordering::Relaxed);
        drop(device);
        let report =
            firmware::initialize(&mut t, &catalog, intel::PlatformInputs::default()).unwrap();
        assert_eq!(report.initialization.stages.len(), 2);
        assert_eq!(report.initialization.address, [1, 2, 3, 4, 5, 6]);
        assert!(eoi.load(Ordering::Relaxed) > before_irqs + 10);
        assert!(h.lock().unwrap().bt.hci_script.is_empty());
        assert_eq!(t.state(), State::Operational);
        t.close().unwrap();
        drop(t);
        assert_eq!(h.lock().unwrap().config_drops, 1);
    }
}

mod root;

#[test]
fn unavailable_minimum_returns_same_inputs_before_native_configuration_access() {
    if crate::model_test_process::isolate() {
        return;
    }
    let (mut inputs, hardware, _, _) = inputs();
    inputs.minimum = crate::minimum_model::refusing(inputs.clock);
    hardware.lock().unwrap().forbid_config_reads = true;
    // SAFETY: explicit isolated fixture; denied timer must stop before effects.
    let (error, inputs) = match unsafe { native::NativePlatform::new(inputs) } {
        Err(refusal) => refusal,
        Ok(_) => panic!("unavailable minimum admitted native transport"),
    };
    assert_eq!(
        error,
        native::Error::Minimum(crate::bus::pci::power::Error::Clock)
    );
    assert_eq!(hardware.lock().unwrap().config_drops, 0);
    assert!(hardware.lock().unwrap().table_writes.is_empty());
    assert_eq!(
        inputs.function.address,
        hardware.lock().unwrap().bt.identity.address
    );
}
