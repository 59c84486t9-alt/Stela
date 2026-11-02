// SPDX-License-Identifier: GPL-2.0-only
//! Independently observed cold queues, original posted writes and kept config.
use super::*;
pub(super) const BAR_BASE: u64 = 0x9000_0000;
pub(super) const BAR_BYTES: u64 = 0x20000;
pub(super) struct RootState {
    pub base: Arc<Domain>,
    pub pm: Arc<NativePm>,
    pub binding: Mutex<Option<RequesterBinding>>,
    pub events: Mutex<Vec<&'static str>>,
    pub fail: Mutex<Option<&'static str>>,
    pub old_pending: AtomicBool,
    pub old_backing: core::sync::atomic::AtomicU32,
    pub ever_bound: AtomicBool,
    pub detached: AtomicBool,
    pub bar_retired: Arc<AtomicBool>,
    pub registers_dropped: AtomicUsize,
    pub fail_map_at: AtomicUsize,
}
impl RootState {
    pub fn record(&self, name: &'static str) -> bool {
        self.events.lock().unwrap().push(name);
        *self.fail.lock().unwrap() == Some(name)
    }
    pub fn current(&self) -> core::result::Result<(), DmaError> {
        self.binding
            .lock()
            .unwrap()
            .as_ref()
            .ok_or(DmaError::Unmapped)?
            .check_live()
            .map_err(|_| DmaError::InvalidationFailed)
    }
    pub fn stopped(&self) {
        assert_eq!(self.pm.command() & 4, 0);
        assert_eq!(self.base.engines.load(Ordering::Relaxed), 0);
    }
}
struct OldRoot {
    state: Arc<RootState>,
    peer: Rc<Peer>,
}
// SAFETY: RAM-only original-root peer; it owns its original config/old backing,
// completes a separately queued old write, and admits only the observed stopped
// queues. No native root or asynchronous CPU/device is involved.
unsafe impl Root for OldRoot {
    fn drain(&self) -> core::result::Result<(), DmaError> {
        self.state.stopped();
        assert!(self.state.base.maps.lock().unwrap().is_empty());
        for queue in 0..32 {
            for field in [registers::TDM_TX_DESC_EN_SET, registers::RDM_RX_DESC_EN_SET] {
                assert_eq!(
                    self.peer.get(field.address + queue * field.stride) & field.mask,
                    0
                );
            }
        }
        for field in [registers::TPB_TX_BUFF_EN_SET, registers::RPB_RX_BUFF_EN_SET] {
            assert_eq!(self.peer.get(field.address) & field.mask, 0);
        }
        if self.state.record("original drain") {
            return Err(DmaError::DrainUnavailable);
        }
        if self.state.old_pending.swap(false, Ordering::Relaxed) {
            self.state.old_backing.store(0x55aa, Ordering::Relaxed);
        }
        Ok(())
    }
    unsafe fn bind(
        &self,
        binding: RequesterBinding,
    ) -> core::result::Result<
        Box<dyn crate::bus::pci::requester::preparation::AttachmentBackend>,
        DmaError,
    > {
        self.state.stopped();
        assert!(!self.state.old_pending.load(Ordering::Relaxed));
        assert_eq!(self.state.old_backing.load(Ordering::Relaxed), 0x55aa);
        assert_eq!(self.state.base.next.load(Ordering::Relaxed), 0);
        binding.check_live().unwrap();
        if self.state.record("bind") {
            return Err(DmaError::MappingFailed);
        }
        assert!(!self.state.ever_bound.swap(true, Ordering::Relaxed));
        assert!(
            self.state
                .binding
                .lock()
                .unwrap()
                .replace(binding)
                .is_none()
        );
        Ok(Box::new(Control(self.state.clone())))
    }
}
struct Control(Arc<RootState>);
impl Drop for Control {
    fn drop(&mut self) {
        if self.0.binding.lock().unwrap().is_some() {
            core::mem::forget(self.0.clone());
        }
    }
}
// SAFETY: one original model binding; detach checks every mapping and actual
// model DMA/engine state, then releases that exact config binding once.
unsafe impl crate::bus::pci::requester::preparation::AttachmentBackend for Control {
    fn domain(&self) -> Arc<dyn DmaDomain> {
        Arc::new(super::domain::NativeDomain(self.0.clone()))
    }
    unsafe fn detach(
        &mut self,
    ) -> core::result::Result<(), crate::bus::pci::requester::preparation::DetachError> {
        self.0.current()?;
        self.0.stopped();
        assert!(self.0.base.maps.lock().unwrap().is_empty());
        assert_eq!(self.0.base.pending_dma.load(Ordering::Relaxed), 0);
        assert!(self.0.base.posted.lock().unwrap().is_empty());
        if self.0.record("detach") {
            return Err(
                crate::bus::pci::requester::preparation::DetachError::Uncertain(
                    DmaError::InvalidationFailed,
                ),
            );
        }
        self.0.binding.lock().unwrap().take().unwrap();
        self.0.detached.store(true, Ordering::Relaxed);
        Ok(())
    }
}
pub(super) struct ModelRegisters {
    peer: Rc<Peer>,
    state: Arc<RootState>,
}
// SAFETY: this isolated synchronous peer observes the same firmware/queues and
// actual model config; it grants no production MMIO permission.
unsafe impl Registers for ModelRegisters {
    fn read(&self, offset: usize) -> Result<u32> {
        assert_eq!(self.state.pm.power_state(), 0, "register read outside D0");
        assert!(
            !self.state.bar_retired.load(Ordering::Relaxed),
            "read after BAR retirement"
        );
        self.peer.read(offset)
    }
    fn write(&self, offset: usize, value: u32) -> Result<()> {
        assert_eq!(self.state.pm.power_state(), 0, "register write outside D0");
        assert!(
            !self.state.bar_retired.load(Ordering::Relaxed),
            "write after BAR retirement"
        );
        self.peer.write(offset, value)
    }
}
// SAFETY: symbolic BAR for this peer alone; retirement requires its original
// control's detach and all model maps gone. Incomplete Drop keeps the peers.
unsafe impl adapter::RetirableRegisters for ModelRegisters {
    fn physical_span(&self) -> Result<owned::PhysicalSpan> {
        Ok(owned::PhysicalSpan::new(BAR_BASE, BAR_BYTES)?)
    }
    unsafe fn retire(&mut self) -> Result<()> {
        assert!(self.state.detached.load(Ordering::Relaxed));
        assert!(self.state.base.maps.lock().unwrap().is_empty());
        assert_eq!(self.state.pm.unmaps.load(Ordering::Relaxed), 0);
        if self.state.record("bar retire") {
            return Err(Error::Mapping(owned::Error::UnmapFailed));
        }
        self.state.bar_retired.store(true, Ordering::Relaxed);
        Ok(())
    }
}
impl Drop for ModelRegisters {
    fn drop(&mut self) {
        if self.state.bar_retired.load(Ordering::Relaxed) {
            self.state.registers_dropped.fetch_add(1, Ordering::Relaxed);
        } else {
            core::mem::forget(self.peer.clone());
            core::mem::forget(self.state.clone());
        }
    }
}
pub(super) type Native = adapter::Attached<ModelRegisters, Rc<Peer>>;
pub(super) struct Fixture {
    pub inputs: adapter::Inputs<ModelRegisters, Rc<Peer>>,
    pub state: Arc<RootState>,
    pub peer: Rc<Peer>,
    pub pages: Pages,
    pub dropped: Arc<AtomicUsize>,
}
pub(super) fn inputs(device: u16) -> Fixture {
    let profile = Profile::identify(0x1d6a, device).unwrap();
    let base = Arc::new(Domain::default());
    let peer = Peer::new(profile, base.clone());
    let address = Address {
        segment: 0,
        bus: 1,
        device: 0,
        function: 0,
    };
    let (function, pm) = native_config(address, device);
    let ControlledConfig { mut native, .. } = function.into_config();
    native.write16(4, 1 << 10).unwrap();
    // The complete stopped-claim validator requires a real PM capability version.
    native.write16(0x42, 3).unwrap();
    native.write32(0x10, BAR_BASE as u32).unwrap();
    native.write32(0x100, 0).unwrap();
    *base.config.lock().unwrap() = Some(pm.clone());
    *peer.native_pm.borrow_mut() = Some(pm.clone());
    let bar_retired = Arc::new(AtomicBool::new(false));
    *pm.retire_after.lock().unwrap() = Some(bar_retired.clone());
    let state = Arc::new(RootState {
        base,
        pm,
        binding: Mutex::new(None),
        events: Mutex::new(Vec::new()),
        fail: Mutex::new(None),
        old_pending: AtomicBool::new(true),
        old_backing: core::sync::atomic::AtomicU32::new(0),
        ever_bound: AtomicBool::new(false),
        detached: AtomicBool::new(false),
        bar_retired,
        registers_dropped: AtomicUsize::new(0),
        fail_map_at: AtomicUsize::new(0),
    });
    // Seed actual old queue controls, including queues this driver never uses.
    for queue in 0..32 {
        for field in [registers::TDM_TX_DESC_EN_SET, registers::RDM_RX_DESC_EN_SET] {
            peer.set(field.address + queue * field.stride, field.mask);
        }
    }
    for field in [registers::TPB_TX_BUFF_EN_SET, registers::RPB_RX_BUFF_EN_SET] {
        peer.set(field.address, field.mask);
    }
    state.base.engines.store(3, Ordering::Relaxed);
    let function = Function::new(address, native).unwrap();
    // SAFETY: same unique config/root/peer and complete symbolic physical role;
    // no native firmware, IRQ, work, bypass or competing config writer exists.
    let requester = unsafe {
        preparation::PreparingRequester::new(
            function,
            FunctionRole::Physical,
            Box::new(OldRoot {
                state: state.clone(),
                peer: peer.clone(),
            }),
        )
    }
    .unwrap_or_else(|_| panic!("model preparation"));
    let dropped = Arc::new(AtomicUsize::new(0));
    let pages = Pages {
        dropped: dropped.clone(),
        next: Cell::new(0x4000_0000),
    };
    Fixture {
        inputs: adapter::Inputs {
            requester,
            registers: ModelRegisters {
                peer: peer.clone(),
                state: state.clone(),
            },
            timer: peer.clone(),
        },
        state,
        peer,
        pages,
        dropped,
    }
}
#[expect(
    clippy::result_large_err,
    reason = "return the original owner and precise failure without allocating during refusal or retirement"
)]
pub(super) fn attach(
    inputs: adapter::Inputs<ModelRegisters, Rc<Peer>>,
    pages: &Pages,
) -> core::result::Result<Native, adapter::Failure> {
    // SAFETY: this synchronous fixture owns the original config/root/BAR peer,
    // qualified timer and coherent pages; no native hardware permission exists.
    unsafe { adapter::attach(inputs, pages) }
}
