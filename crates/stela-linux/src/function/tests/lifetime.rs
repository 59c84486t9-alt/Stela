//! PCI device references keep the Rust callback roots until final C release.
use super::*;
use stela_driver_base::platform::image::NativeReadOnlyImage;

struct HeapNames;
// SAFETY: the classifier admits no immutable addresses and dereferences
// nothing. These isolated fixtures admit only heap-generated PCI names.
unsafe impl NativeReadOnlyImage for HeapNames {
    fn contains(&self, _: usize) -> bool {
        false
    }
}

unsafe extern "C" {
    fn pci_dev_get(device: *mut c_void) -> *mut c_void;
    fn pci_dev_put(device: *mut c_void);
    fn pci_set_master(device: *mut c_void);
    fn arch_local_save_flags() -> usize;
    fn arch_local_irq_restore(flags: usize);
}
struct CountedConfig {
    bytes: Config,
    reads: Arc<AtomicUsize>,
}
impl ConfigSpace for CountedConfig {
    fn read32(&self, offset: u16) -> u32 {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.bytes.read32(offset)
    }
    fn write32(&mut self, offset: u16, value: u32) {
        self.bytes.write32(offset, value);
    }
}
struct CountedHost {
    config: CountedConfig,
    drops: Arc<AtomicUsize>,
}
impl Host for CountedHost {
    type Config = CountedConfig;
    fn config(&mut self) -> &mut CountedConfig {
        &mut self.config
    }
    fn enable_msi(&mut self) -> Result<(), Errno> {
        Ok(())
    }
    fn disable_msi(&mut self) {}
}
impl Drop for CountedHost {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
    }
}
fn attach(
    domain: &Arc<Identity>,
    drops: &Arc<AtomicUsize>,
    reads: &Arc<AtomicUsize>,
) -> Attached<CountedHost> {
    // SAFETY: this fixture's formatted PCI name is allocated by the canonical
    // heap. No literal or borrowed name enters a free-or-borrow lifecycle.
    unsafe { crate::image::register(Arc::new(HeapNames)) }
        .ok()
        .unwrap();
    // SAFETY: isolated entered process owner; the memory-only PCI config and
    // symbolic domain perform no device access, and no driver is registered.
    unsafe {
        Attached::new(
            CountedHost {
                config: CountedConfig {
                    bytes: Config([0; 256]),
                    reads: reads.clone(),
                },
                drops: drops.clone(),
            },
            domain.clone(),
            Placement::default(),
        )
    }
    .unwrap()
}

#[test]
fn extra_device_reference_keeps_callbacks_and_roots_after_removal() {
    if !isolated(
        "function::tests::lifetime::extra_device_reference_keeps_callbacks_and_roots_after_removal",
    ) {
        return;
    }
    let _entered = Entered::try_new().unwrap();
    let drops = Arc::new(AtomicUsize::new(0));
    let reads = Arc::new(AtomicUsize::new(0));
    let domain = Arc::new(Identity::default());
    let attached = attach(&domain, &drops, &reads);
    let device = attached.device();
    // SAFETY: registration owns the live device; this acquires a second ref.
    assert_eq!(unsafe { pci_dev_get(device) }, device);
    drop(attached);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    assert_eq!(Arc::strong_count(&domain), 2);
    let before = reads.load(Ordering::Relaxed);
    // SAFETY: our extra device reference keeps the C table and Rust state
    // alive despite removal; the owner is still entered in process context.
    unsafe { pci_set_master(device) };
    assert!(reads.load(Ordering::Relaxed) > before);
    // SAFETY: release our only remaining reference in the same entered owner.
    unsafe { pci_dev_put(device) };
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert_eq!(Arc::strong_count(&domain), 1);
    assert_eq!(quarantined_functions(), 0);
}

#[test]
fn atomic_final_put_quarantines_host_and_domain_roots() {
    if !isolated("function::tests::lifetime::atomic_final_put_quarantines_host_and_domain_roots") {
        return;
    }
    let _entered = Entered::try_new().unwrap();
    let drops = Arc::new(AtomicUsize::new(0));
    let reads = Arc::new(AtomicUsize::new(0));
    let domain = Arc::new(Identity::default());
    let attached = attach(&domain, &drops, &reads);
    let device = attached.device();
    // SAFETY: registration owns the live device; this acquires a second ref.
    unsafe { pci_dev_get(device) };
    drop(attached);
    // SAFETY: entered isolated model owner; save and restore exactly its IRQ
    // state around the final put. No native IRQ or hardware is involved.
    unsafe {
        let flags = arch_local_save_flags();
        arch_local_irq_restore(0);
        pci_dev_put(device);
        arch_local_irq_restore(flags);
    }
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    assert_eq!(Arc::strong_count(&domain), 2);
    assert_eq!(quarantined_functions(), 1);
}

#[test]
fn retained_refusal_storage_keeps_before_graph() {
    if !isolated("function::tests::lifetime::retained_refusal_storage_keeps_before_graph") {
        return;
    }
    let drops = Arc::new(AtomicUsize::new(0));
    let domain = Arc::new(Identity::default());
    let host = CountedHost {
        config: CountedConfig {
            bytes: Config([0; 256]),
            reads: Arc::new(AtomicUsize::new(0)),
        },
        drops: drops.clone(),
    };
    // This is the actual common retained-graph storage, not a fabricated
    // PciAuthority: a model Attachment cannot qualify a native source target.
    drop(Retained::new(Box::new((host, domain.clone()))));
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    assert_eq!(Arc::strong_count(&domain), 2);
    assert_eq!(retained_presentations(), 1);
}

#[test]
fn null_presentation_keeps_actual_host_and_domain_state() {
    if !isolated("function::tests::lifetime::null_presentation_keeps_actual_host_and_domain_state")
    {
        return;
    }
    unsafe extern "C" {
        static stela_linux_bare: crate::owner::RawOwner;
        fn stela_linux_kernel_claim(owner: *const crate::owner::RawOwner) -> i32;
        fn stela_linux_kernel_environment(owner: *const crate::owner::RawOwner) -> i32;
        fn stela_linux_kernel_ready(owner: *const crate::owner::RawOwner) -> i32;
    }
    let owner = core::ptr::addr_of!(stela_linux_bare);
    // SAFETY: isolated cold C bookkeeping model with its actual static bare
    // owner. This does not construct/qualify a KernelOwner or native Runtime.
    unsafe {
        assert_eq!(stela_linux_kernel_claim(owner), 0);
        assert_eq!(stela_linux_kernel_environment(owner), 0);
        assert_eq!(stela_linux_kernel_ready(owner), 0);
    }
    let _entered = Entered::try_new().unwrap();
    // SAFETY: every PCI name here is heap-generated; classifier reads nothing.
    unsafe { crate::image::register(Arc::new(HeapNames)) }
        .ok()
        .unwrap();
    let drops = Arc::new(AtomicUsize::new(0));
    let reads = Arc::new(AtomicUsize::new(0));
    let domain = Arc::new(Identity::default());
    let host = CountedHost {
        config: CountedConfig {
            bytes: Config([0; 256]),
            reads: reads.clone(),
        },
        drops: drops.clone(),
    };
    // SAFETY: isolated memory-only host/domain and actual entered C model
    // owner. No driver is registered. Missing enrollment must refuse before
    // publication/probe, with Rust State ownership left to this caller.
    let result = unsafe { Attached::attach(host, domain.clone(), Placement::default(), None) };
    let rejected = match result {
        Ok(_) => panic!("unenrolled presentation accepted"),
        Err(value) => value,
    };
    assert!(matches!(&rejected.error, AttachError::Native(-1)));
    drop(rejected);
    assert!(reads.load(Ordering::Relaxed) > 0);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    assert_eq!(Arc::strong_count(&domain), 2);
    assert_eq!(retained_presentations(), 1);
}
