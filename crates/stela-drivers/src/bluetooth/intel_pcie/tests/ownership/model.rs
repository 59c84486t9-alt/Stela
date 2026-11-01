//! Synchronous device/root/page model with independent CPU, PA and IOVA values.
use super::*;
#[derive(Default)]
pub(super) struct RootState {
    pub events: Mutex<Vec<&'static str>>,
    pub fail_config: Mutex<Option<Arc<Counters>>>,
    pub fail: Mutex<Option<&'static str>>,
    pub registers_dropped: AtomicUsize,
    pub bars_dropped: AtomicUsize,
    pub pages_dropped: AtomicUsize,
    pub fail_map_at: AtomicUsize,
    pub fail_device_stop: core::sync::atomic::AtomicBool,
    pub bound: Mutex<Option<RequesterBinding>>,
    pub live: Mutex<Vec<DomainMapping>>,
}
impl RootState {
    fn step(&self, name: &'static str) -> core::result::Result<(), DmaError> {
        self.events.lock().unwrap().push(name);
        if *self.fail.lock().unwrap() == Some(name) {
            Err(DmaError::InvalidationFailed)
        } else {
            Ok(())
        }
    }
}
struct OldRoot(Arc<RootState>);
// SAFETY: isolated root owns the symbolic configuration binding. No device or
// native translation is present; failure retains the shared model graph.
unsafe impl Root for OldRoot {
    fn drain(&self) -> core::result::Result<(), DmaError> {
        self.0.step("original drain")
    }
    unsafe fn bind(
        &self,
        binding: RequesterBinding,
    ) -> core::result::Result<Box<dyn Attachment>, DmaError> {
        self.0.step("bind")?;
        binding.check_live().unwrap();
        assert!(self.0.bound.lock().unwrap().replace(binding).is_none());
        Ok(Box::new(Control(self.0.clone())))
    }
}
struct Control(Arc<RootState>);
impl Drop for Control {
    fn drop(&mut self) {
        if self.0.bound.lock().unwrap().is_some() {
            core::mem::forget(self.0.clone());
        }
    }
}
// SAFETY: unique synchronous model attachment; refuses live mappings and only
// clears its kept configuration after acknowledged symbolic detach.
unsafe impl Attachment for Control {
    fn domain(&self) -> Arc<dyn DmaDomain> {
        Arc::new(Domain(self.0.clone()))
    }
    unsafe fn detach(&mut self) -> core::result::Result<(), DmaError> {
        assert!(self.0.live.lock().unwrap().is_empty());
        self.0.step("detach")?;
        self.0
            .bound
            .lock()
            .unwrap()
            .take()
            .ok_or(DmaError::Unmapped)?;
        Ok(())
    }
}
struct Domain(Arc<RootState>);
// SAFETY: isolated RAM-only translation model. Unique IOVAs have independent PA
// labels; only CPU storage is dereferenced. All metadata access is serialized.
unsafe impl DmaDomain for Domain {
    unsafe fn map(
        &self,
        pages: &DmaPages,
        _: Direction,
        limit: u64,
    ) -> core::result::Result<DomainMapping, DmaError> {
        if self.0.bound.lock().unwrap().is_none() {
            return Err(DmaError::Unmapped);
        }
        self.0.step("map")?;
        let mut live = self.0.live.lock().unwrap();
        let id = live.len() as u64 + 1;
        if self.0.fail_map_at.load(Ordering::Relaxed) == id as usize {
            return Err(DmaError::MappingFailed);
        }
        let address = 0x2_0000_0000 + id * 0x100_0000;
        assert_ne!(address, pages.physical_pages()[0]);
        assert!(address + pages.bytes() as u64 - 1 <= limit);
        let m = DomainMapping {
            id,
            address,
            bytes: pages.bytes(),
        };
        live.push(m);
        Ok(m)
    }
    unsafe fn unmap(&self, mapping: DomainMapping) -> core::result::Result<(), DmaError> {
        self.0.step("unmap")?;
        let mut live = self.0.live.lock().unwrap();
        let index = live
            .iter()
            .position(|m| *m == mapping)
            .ok_or(DmaError::Unmapped)?;
        live.remove(index);
        Ok(())
    }
    unsafe fn sync_for_device(
        &self,
        mapping: DomainMapping,
        range: Range<usize>,
        _: Direction,
    ) -> core::result::Result<(), DmaError> {
        assert!(self.0.live.lock().unwrap().contains(&mapping));
        assert!(range.start <= range.end && range.end <= mapping.bytes);
        Ok(())
    }
    unsafe fn sync_for_cpu(
        &self,
        mapping: DomainMapping,
        range: Range<usize>,
        direction: Direction,
    ) -> core::result::Result<(), DmaError> {
        // SAFETY: same isolated model lease, checked by the delegated operation.
        unsafe { self.sync_for_device(mapping, range, direction) }
    }
    unsafe fn drain_posted_writes(&self) -> core::result::Result<(), DmaError> {
        self.0.step("domain drain")
    }
}
pub(super) struct Registers {
    pub model: Mutex<Model>,
    pub root: Arc<RootState>,
}
impl Registers {
    pub fn new(root: Arc<RootState>) -> Self {
        Self {
            model: Mutex::new(Model::new(0xa876)),
            root,
        }
    }
}
// SAFETY: synchronous RAM register peer; locking serializes every effect and
// no physical MMIO address or device permission exists.
unsafe impl native::Registers for Registers {
    fn full_bar(&self) -> PhysicalSpan {
        PhysicalSpan::new(BASE, BAR_BYTES).unwrap()
    }
    fn read32(&self, offset: usize) -> core::result::Result<u32, native::Error> {
        let m = self.model.lock().unwrap();
        if m.read_error == Some(offset) {
            return Err(native::Error::Readback {
                offset,
                observed: u32::MAX,
            });
        }
        Ok(m.reg(offset))
    }
    fn write32(&self, offset: usize, value: u32) -> core::result::Result<(), native::Error> {
        let mut m = self.model.lock().unwrap();
        if self.root.fail_device_stop.load(Ordering::Relaxed) {
            m.stop_ack = false;
        }
        m.write32(offset, value);
        if offset == FUNC && value & RESET != 0 {
            self.root.events.lock().unwrap().push("reset");
        }
        if m.write_error.is_some_and(|(at, _)| at == offset) {
            return Err(native::Error::Requirement("late modeled store"));
        }
        Ok(())
    }
    fn write8(&self, offset: usize, value: u8) -> core::result::Result<(), native::Error> {
        self.model.lock().unwrap().byte_writes.push((offset, value));
        Ok(())
    }
}
// SAFETY: explicit model retirement only; no native mapping is fabricated.
unsafe impl native::RetirableRegisters for Registers {
    unsafe fn retire_mapping(&mut self) -> core::result::Result<(), native::Error> {
        self.root
            .step("register retire")
            .map_err(|_| native::Error::Requirement("modeled register retirement"))?;
        if let Some(counts) = self.root.fail_config.lock().unwrap().take() {
            counts.fail_context_at.store(
                counts.contexts.load(Ordering::Relaxed) + 1,
                Ordering::Relaxed,
            );
        }
        Ok(())
    }
}
impl Drop for Registers {
    fn drop(&mut self) {
        self.root.registers_dropped.fetch_add(1, Ordering::Relaxed);
    }
}
pub(super) struct Bar(pub Arc<RootState>);
// SAFETY: same bounded symbolic BAR; no native effects or IRQ admission.
unsafe impl crate::bus::pci::msix::BarAccess for Bar {
    fn physical_span(&self) -> PhysicalSpan {
        PhysicalSpan::new(BASE, BAR_BYTES).unwrap()
    }
    fn accessible(&self, offset: u64, bytes: u64) -> bool {
        offset
            .checked_add(bytes)
            .is_some_and(|end| end <= BAR_BYTES)
    }
    fn read32(&self, _: u64) -> core::result::Result<u32, crate::bus::pci::msix::IoError> {
        Ok(1)
    }
    fn write32(
        &mut self,
        _: u64,
        _: u32,
    ) -> core::result::Result<(), crate::bus::pci::msix::IoError> {
        Ok(())
    }
}
impl Drop for Bar {
    fn drop(&mut self) {
        self.0.bars_dropped.fetch_add(1, Ordering::Relaxed);
    }
}
pub(super) fn preparing(root: Arc<RootState>) -> (preparation::PreparingRequester, Arc<Counters>) {
    let address = Address {
        segment: 0,
        bus: 2,
        device: 3,
        function: 0,
    };
    let (mut config, counts) = fixture(address);
    for (offset, value) in [
        (0, 0xa876_8086),
        (4, 0x0010_0402),
        (8, 0x0d11_0000),
        (0x0c, 0),
        (0x10, BASE as u32),
        (0x34, 0x50),
        (0x50, 0x11),
        (0x54, 0x3000),
        (0x58, 0x4000),
        (0x100, 0),
    ] {
        config.write32(offset, value);
    }
    let function = Function::new(address, config).unwrap();
    // SAFETY: exclusive fixture, no native firmware/IRQ/work/bypass users.
    let requester = unsafe {
        preparation::PreparingRequester::new(
            function,
            FunctionRole::Physical,
            Box::new(OldRoot(root)),
        )
    }
    .unwrap_or_else(|_| panic!("model preparation"));
    (requester, counts)
}
pub(super) fn cold(root: Arc<RootState>) -> (native::cold::Cold<Registers>, Arc<Counters>) {
    let (requester, counts) = preparing(root.clone());
    let inputs = native::cold::Inputs {
        requester,
        registers: Registers::new(root),
        clock: CLOCK,
    };
    // SAFETY: exclusively owned synchronous model with checked test TSC timing.
    let cold = unsafe { native::cold::Cold::new(inputs) }.unwrap_or_else(|(e, _)| panic!("{e:?}"));
    (cold, counts)
}
#[repr(align(4096))]
#[derive(Clone)]
struct Page([u8; 4096]);
struct Pages {
    data: Box<[Page]>,
    physical: Vec<u64>,
    root: Arc<RootState>,
}
// SAFETY: stable aligned owned CPU storage with distinct immutable PA labels.
unsafe impl PageBacking for Pages {
    fn cpu_base(&self) -> NonNull<u8> {
        NonNull::from(&self.data[0].0[0])
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
impl Drop for Pages {
    fn drop(&mut self) {
        self.root.pages_dropped.fetch_add(1, Ordering::Relaxed);
    }
}
struct Source(Arc<RootState>, AtomicUsize);
impl PageSource for Source {
    fn page_geometry(&self) -> core::result::Result<PageGeometry, MemoryError> {
        PageGeometry::base_only(12)
    }
    fn allocate(
        &self,
        bytes: usize,
        align: usize,
        attribute: CacheAttribute,
    ) -> core::result::Result<PinnedPages, MemoryError> {
        assert_eq!(attribute, CacheAttribute::WriteBack);
        let n = bytes.div_ceil(4096);
        let base = 0x800_0000 + self.1.fetch_add(1, Ordering::Relaxed) as u64 * 0x100_0000;
        PinnedPages::new(
            Box::new(Pages {
                data: vec![Page([0; 4096]); n].into_boxed_slice(),
                physical: (0..n).map(|i| base + i as u64 * 8192).collect(),
                root: self.0.clone(),
            }),
            bytes,
            align,
        )
    }
}
struct NoInterrupts;
impl irq::IrqController for NoInterrupts {
    fn request(
        &'static self,
        _: Box<dyn irq::Source>,
        _: Arc<dyn irq::Handler>,
    ) -> core::result::Result<Box<dyn irq::IrqRegistration>, irq::IrqError> {
        panic!("unstarted transport admits no IRQ")
    }
    fn quarantine_count(&self) -> u64 {
        0
    }
}
static NO_INTERRUPTS: NoInterrupts = NoInterrupts;
pub(super) type Owned = native::lifetime::OwnedTransport<Bar, Registers>;
pub(super) fn owned_inputs(
    root: Arc<RootState>,
) -> (native::lifetime::Inputs<Bar, Registers>, Arc<Counters>) {
    let (cold, counts) = cold(root.clone());
    let bound = cold
        .quiesce_and_bind()
        .unwrap_or_else(|f| panic!("{:?}", f.error));
    let mut function = bound.requester.into_function();
    let retention = function.config().retain_epoch().unwrap();
    function.enable_polled();
    let inputs = native::Inputs {
        function,
        retained: Arc::new(()),
        bars: [Some(Bar(root.clone())), None, None, None, None, None],
        registers: bound.registers,
        clock: CLOCK,
        interrupts: &NO_INTERRUPTS,
        domain: bound.attachment.domain(),
        msi_completion: irq::posted_msi::MsiCompletion::unavailable(),
    };
    // SAFETY: exclusively owned model uses the same cold receipt/root/BAR.
    let platform =
        unsafe { native::NativePlatform::new(inputs) }.unwrap_or_else(|(e, _)| panic!("{e:?}"));
    let source = Box::leak(Box::new(Source(root, AtomicUsize::new(0))));
    // SAFETY: model CPU mappings are stable and synchronous, no hardware DMA.
    let allocator = unsafe { DomainAllocator::new(source, bound.attachment.domain(), u64::MAX) };
    (
        native::lifetime::Inputs {
            platform,
            allocator,
            attachment: bound.attachment,
            retention,
        },
        counts,
    )
}
pub(super) fn owned(root: Arc<RootState>) -> (Owned, Arc<Counters>) {
    let (inputs, counts) = owned_inputs(root);
    // SAFETY: paired fixture configuration, attachment, allocator and epoch seal.
    let owned = unsafe { Owned::new(inputs) }.unwrap_or_else(|f| panic!("{:?}", f.error));
    (owned, counts)
}
