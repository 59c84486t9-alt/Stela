//! Persistent storage service across the engine's shadow-page-table roots.
//!
//! PC drivers currently use identity addresses for their ECAM/MMIO and DMA
//! buffers. Keep their accesses in the loader's retained root, which also
//! maps the engine window, and restore the current engine root afterwards.
//! This boundary never maps host identity addresses into a guest root. All
//! buffers passed here belong to the engine window, not guest virtual RAM.
use crate::output;
use alloc::{boxed::Box, format, string::String};
use core::arch::asm;
use stela_runtime::pc::{
    self,
    block::{BlockDevice, BlockError, Identity},
    dma::RegionAllocator,
    storage::{self, Target},
};

pub(super) struct RestoreRoot {
    root: u64,
    flags: u64,
}
impl RestoreRoot {
    /// # Safety
    /// `root` is the live loader root, retaining the engine window, and the
    /// engine is serialized: no other PE/interrupt may drive this controller.
    pub(super) unsafe fn enter(root: u64) -> Self {
        let (previous, flags): (u64, u64);
        // SAFETY: CPL0, live roots with the same engine code/stack/window.
        // Interrupts remain off until the original root has been restored.
        unsafe {
            asm!("pushfq","pop {flags}","cli","mov {previous}, cr3","mov cr3, {root}",flags=out(reg)flags,previous=out(reg)previous,root=in(reg)root);
        }
        Self {
            root: previous,
            flags,
        }
    }
}
impl Drop for RestoreRoot {
    fn drop(&mut self) {
        // SAFETY: the original live root; no borrowed identity address
        // survives a BlockDevice call. Only IF was changed by enter().
        unsafe {
            asm!("mov cr3, {}",in(reg)self.root,options(nostack,preserves_flags));
            if self.flags & (1 << 9) != 0 {
                asm!("sti", options(nomem, nostack));
            }
        }
    }
}

struct Service {
    inner: Box<dyn BlockDevice>,
    root: u64,
}
impl BlockDevice for Service {
    fn identity(&self) -> &Identity {
        self.inner.identity()
    }
    fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        // SAFETY: open() captured the loader root; callers supply window RAM.
        let _root = unsafe { RestoreRoot::enter(self.root) };
        self.inner.read(lba, buffer)
    }
    fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        // SAFETY: as in read().
        let _root = unsafe { RestoreRoot::enter(self.root) };
        self.inner.write(lba, data)
    }
    fn flush(&mut self) -> Result<(), BlockError> {
        // SAFETY: as in read().
        let _root = unsafe { RestoreRoot::enter(self.root) };
        self.inner.flush()
    }
}

/// Open the explicitly selected partitions while the loader's identity root
/// is still active, before host::install, and bring up every host input
/// device and network adapter. No guessed disk/partition, no writes at open. Ownership lasts
/// with the returned services. Probe once for all consumers;
/// do not reset a controller or reuse its DMA pages for a second probe.
///
/// # Safety
/// The handoff describes this running machine, only this service uses its
/// reserved DMA pages, and the loader root/window remain live for the boot.
pub unsafe fn open(handoff: &pc::Handoff, targets: &[&Target]) -> Result<Opened, String> {
    if targets
        .iter()
        .enumerate()
        .any(|(i, t)| targets[..i].iter().any(|other| other.serial == t.serial))
    {
        return Err("ANS, restore source and NOR partitions must be on distinct host disks".into());
    }
    let root: u64;
    // SAFETY: engine CPL0, before switching away from the loader root.
    unsafe {
        asm!("mov {}, cr3",out(reg)root,options(nomem,nostack,preserves_flags));
    }
    // SAFETY: the caller owns the handoff's DMA pages and controllers.
    let mut dma = unsafe { RegionAllocator::new(handoff.dma.clone()) };
    // SAFETY: the loader mapped these ranges uncached and identity-mapped.
    let mut disks = unsafe { storage::probe(handoff, &mut dma) };
    for (address, error) in &disks.failures {
        output::arguments(format_args!("STORAGE FAILED pci={address} error={error}\n"));
    }
    let inputs = Inputs {
        devices: core::mem::take(&mut disks.inputs),
        root,
    };
    let links = super::network::Links {
        devices: core::mem::take(&mut disks.links),
        root,
    };
    let services = targets
        .iter()
        .map(|target| {
            let partition = storage::open(&mut disks.devices, target)
                .map_err(|error| format!("{}:{}: {error}", target.serial, target.partition))?;
            output::arguments(format_args!(
                "HOST PARTITION serial={} partition={} blocks={} block_size={}\n",
                target.serial,
                target.partition,
                partition.identity().blocks,
                partition.identity().block_size
            ));
            Ok(Box::new(Service {
                inner: Box::new(partition),
                root,
            }) as Box<dyn BlockDevice>)
        })
        .collect::<Result<_, String>>()?;
    Ok(Opened {
        services,
        inputs,
        links,
    })
}

/// What [`open`] brought up: a service per target, in order, and the
/// host's input devices and network adapters.
pub struct Opened {
    pub services: alloc::vec::Vec<Box<dyn BlockDevice>>,
    pub inputs: Inputs,
    pub links: super::network::Links,
}

/// The host's input devices and the loader root their registers and DMA
/// pages are reached through.
pub struct Inputs {
    pub devices: alloc::vec::Vec<pc::input::VirtioInput>,
    pub root: u64,
}
