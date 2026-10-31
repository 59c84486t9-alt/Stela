//! A physical PCI function presented to Linux, which then binds any driver
//! matching it (`compat/linux/kernel/pci_host.c`). Configuration space and DMA
//! stay Stela's: the function's owner placed it, and Linux reaches both through
//! the table here.
use super::owner::Errno;
use alloc::{boxed::Box, collections::BTreeMap, sync::Arc, vec::Vec};
use core::{
    ffi::{c_char, c_int, c_uint, c_void},
    ptr::NonNull,
};
use stela_driver_base::bus::{
    dma::{
        mapping::{Direction, DmaDomain, DomainMapping},
        memory::CacheAttribute,
        pages::DmaPages,
    },
    pci::ConfigSpace,
};

/// PCI base address registers.
const BARS: usize = 6;
/// Linux's `DMA_MAPPING_ERROR`.
const MAPPING_ERROR: u64 = u64::MAX;
const PAGE_SHIFT: u8 = 12;
const PAGE_BYTES: u64 = 1 << PAGE_SHIFT;

const PCIBIOS_BAD_REGISTER_NUMBER: c_int = 0x87;
const ENOMEM: Errno = -12;

/// The function's owner.
pub trait Host {
    type Config: ConfigSpace;
    fn config(&mut self) -> &mut Self::Config;
    /// Move the function's interrupt from its line to a message.
    fn enable_msi(&mut self) -> Result<(), Errno>;
    fn disable_msi(&mut self);
}

/// A memory BAR where its owner placed it. `flags` holds Linux's `IORESOURCE_*`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Region {
    pub start: u64,
    pub size: u64,
    pub flags: u64,
}

/// Where a function sits.
#[derive(Clone, Copy, Default)]
pub struct Placement {
    pub bus: u8,
    pub devfn: u8,
    pub irq: u32,
    /// The highest bus address `domain` hands out.
    pub dma_limit: u64,
    pub regions: [Region; BARS],
}

/// A function's MSI capability (PCI Local Bus 3.0 6.8.1), one message at most.
#[derive(Clone, Copy)]
pub struct Msi {
    capability: u16,
}

impl Msi {
    const CONTROL: u16 = 2;
    const ADDRESS: u16 = 4;
    const ENABLE: u16 = 1;
    const MULTIPLE: u16 = 7 << 4;
    const WIDE: u16 = 1 << 7;

    /// The capability at `capability`.
    pub const fn at(capability: u16) -> Self {
        Self { capability }
    }

    fn control<C: ConfigSpace>(self, config: &C) -> u16 {
        config.read16(self.capability + Self::CONTROL)
    }

    /// Stop the function sending it.
    pub fn disable<C: ConfigSpace>(self, config: &mut C) {
        let control = self.control(config) & !Self::ENABLE;
        config.write16(self.capability + Self::CONTROL, control);
    }

    /// Set the one message, disabled.
    pub fn program<C: ConfigSpace>(self, config: &mut C, address: u64, data: u16) {
        self.disable(config);
        let wide = self.control(config) & Self::WIDE != 0;
        let at = self.capability + Self::ADDRESS;
        config.write32(at, address as u32);
        if wide {
            config.write32(at + 4, (address >> 32) as u32);
        }
        config.write16(at + if wide { 8 } else { 4 }, data);
    }

    /// Let the function send it.
    pub fn enable<C: ConfigSpace>(self, config: &mut C) {
        let control = self.control(config) & !Self::MULTIPLE | Self::ENABLE;
        config.write16(self.capability + Self::CONTROL, control);
    }
}

/// `struct stela_linux_pci_function`.
#[repr(C)]
struct RawFunction {
    context: *mut c_void,
    read_config: unsafe extern "C" fn(*mut c_void, c_int, c_int, *mut u32) -> c_int,
    write_config: unsafe extern "C" fn(*mut c_void, c_int, c_int, u32) -> c_int,
    dma_map: unsafe extern "C" fn(*mut c_void, u64, usize, c_uint) -> u64,
    dma_unmap: unsafe extern "C" fn(*mut c_void, u64, usize, c_uint),
    enable_msi: unsafe extern "C" fn(*mut c_void) -> c_int,
    disable_msi: unsafe extern "C" fn(*mut c_void),
    dma_limit: u64,
    bus: c_uint,
    devfn: c_uint,
    irq: c_uint,
    regions: [Region; BARS],
}

const _: () = assert!(size_of::<RawFunction>() == 224);

unsafe extern "C" {
    fn stela_linux_pci_attach(function: *const RawFunction) -> *mut c_void;
    fn stela_linux_pci_bound(device: *const c_void) -> bool;
    fn stela_linux_pci_remove_device(device: *mut c_void);
    fn stela_linux_unsupported(operation: *const c_char);
}

/// A mapping of pages Linux's allocator pins, by the address Linux was given.
/// Passthrough domains give one physical range the same address every time, so
/// each address keeps a stack of the mappings at it.
struct Mappings {
    domain: Arc<dyn DmaDomain>,
    limit: u64,
    live: BTreeMap<u64, Vec<DomainMapping>>,
}

impl Mappings {
    fn map(&mut self, physical: u64, size: usize, direction: Direction) -> Option<u64> {
        let offset = physical % PAGE_BYTES;
        let end = physical.checked_add(u64::try_from(size).ok()?.max(1))?;
        let pages = (physical - offset..end).step_by(PAGE_BYTES as usize);
        // SAFETY: Linux keeps pages pinned while a mapping of them is live,
        // and its DMA API ends the mapping before it frees them.
        let pages = unsafe {
            DmaPages::from_physical(pages.collect(), PAGE_SHIFT, CacheAttribute::WriteBack)
        }
        .ok()?;
        // SAFETY: as above, for the pin the domain must keep.
        let mapping = unsafe { self.domain.map(&pages, direction, self.limit) }.ok()?;
        let address = mapping.address + offset;
        self.live.entry(address).or_default().push(mapping);
        Some(address)
    }

    fn unmap(&mut self, address: u64) {
        let Some(stack) = self.live.get_mut(&address) else {
            return;
        };
        let mapping = stack.pop();
        if stack.is_empty() {
            self.live.remove(&address);
        }
        // SAFETY: Linux's DMA API unmaps only once the device is done.
        if let Some(Err(_)) = mapping.map(|mapping| unsafe { self.domain.unmap(mapping) }) {
            // The domain keeps the mapping, and Linux may reuse the pages.
            // SAFETY: Linux called in, so its owner is entered.
            unsafe { stela_linux_unsupported(c"a DMA unmap that failed".as_ptr()) };
        }
    }
}

fn direction(linux: c_uint) -> Direction {
    match linux {
        1 => Direction::ToDevice,
        2 => Direction::FromDevice,
        _ => Direction::Bidirectional,
    }
}

struct State<H> {
    host: H,
    mappings: Mappings,
}

/// # Safety
/// `context` is the state of an [`Attached`] Linux still holds, and Linux, which
/// runs in one context at a time, is in no other callback of it.
unsafe fn state<'a, H>(context: *mut c_void) -> &'a mut State<H> {
    // SAFETY: the caller's contract.
    unsafe { &mut *context.cast() }
}

unsafe extern "C" fn read_config<H: Host>(
    context: *mut c_void,
    offset: c_int,
    size: c_int,
    value: *mut u32,
) -> c_int {
    // SAFETY: the table's context.
    let config = unsafe { state::<H>(context) }.host.config();
    let offset = offset as u16;
    let read = match size {
        1 => u32::from(config.read8(offset)),
        2 => u32::from(config.read16(offset)),
        4 => config.read32(offset),
        _ => return PCIBIOS_BAD_REGISTER_NUMBER,
    };
    // SAFETY: Linux gives a writable result.
    unsafe { *value = read };
    0
}

unsafe extern "C" fn write_config<H: Host>(
    context: *mut c_void,
    offset: c_int,
    size: c_int,
    value: u32,
) -> c_int {
    // SAFETY: the table's context.
    let config = unsafe { state::<H>(context) }.host.config();
    let offset = offset as u16;
    match size {
        1 => config.write8(offset, value as u8),
        2 => config.write16(offset, value as u16),
        4 => config.write32(offset, value),
        _ => return PCIBIOS_BAD_REGISTER_NUMBER,
    }
    0
}

unsafe extern "C" fn dma_map<H: Host>(
    context: *mut c_void,
    physical: u64,
    size: usize,
    linux: c_uint,
) -> u64 {
    // SAFETY: the table's context.
    let state = unsafe { state::<H>(context) };
    state
        .mappings
        .map(physical, size, direction(linux))
        .unwrap_or(MAPPING_ERROR)
}

unsafe extern "C" fn dma_unmap<H: Host>(context: *mut c_void, address: u64, _: usize, _: c_uint) {
    // SAFETY: the table's context.
    unsafe { state::<H>(context) }.mappings.unmap(address);
}

unsafe extern "C" fn enable_msi<H: Host>(context: *mut c_void) -> c_int {
    // SAFETY: the table's context.
    let result = unsafe { state::<H>(context) }.host.enable_msi();
    result.err().unwrap_or(0)
}

unsafe extern "C" fn disable_msi<H: Host>(context: *mut c_void) {
    // SAFETY: the table's context.
    unsafe { state::<H>(context) }.host.disable_msi();
}

/// A function Linux can see. Must be dropped in the Linux owner it was attached
/// in, as Linux then unbinds its driver.
pub struct Attached<H> {
    device: NonNull<c_void>,
    state: *mut State<H>,
}

impl<H: Host> Attached<H> {
    /// # Safety
    /// In an entered Linux owner, on a Linux task, as a driver may bind here.
    pub unsafe fn new(
        host: H,
        domain: Arc<dyn DmaDomain>,
        placement: Placement,
    ) -> Result<Self, Errno> {
        let state = Box::into_raw(Box::new(State {
            host,
            mappings: Mappings {
                domain,
                limit: placement.dma_limit,
                live: BTreeMap::new(),
            },
        }));
        let raw = RawFunction {
            context: state.cast(),
            read_config: read_config::<H>,
            write_config: write_config::<H>,
            dma_map: dma_map::<H>,
            dma_unmap: dma_unmap::<H>,
            enable_msi: enable_msi::<H>,
            disable_msi: disable_msi::<H>,
            dma_limit: placement.dma_limit,
            bus: placement.bus.into(),
            devfn: placement.devfn.into(),
            irq: placement.irq,
            regions: placement.regions,
        };
        // SAFETY: the caller's contract; C copies the table.
        match NonNull::new(unsafe { stela_linux_pci_attach(&raw) }) {
            Some(device) => Ok(Self { device, state }),
            None => {
                // SAFETY: refused, so Linux never saw it.
                drop(unsafe { Box::from_raw(state) });
                Err(ENOMEM)
            }
        }
    }

    /// The `struct pci_dev`, for code that names it.
    pub fn device(&self) -> *mut c_void {
        self.device.as_ptr()
    }

    /// Whether a driver took the function.
    ///
    /// # Safety
    /// In an entered Linux owner.
    pub unsafe fn bound(&self) -> bool {
        // SAFETY: the caller's contract, over this function's live device.
        unsafe { stela_linux_pci_bound(self.device.as_ptr()) }
    }
}

impl<H> Drop for Attached<H> {
    fn drop(&mut self) {
        // SAFETY: the type's contract; the removal unbinds the driver, after
        // which Linux holds no mapping and makes no call into the state.
        unsafe { stela_linux_pci_remove_device(self.device.as_ptr()) };
        // SAFETY: as above, and only `new` made it.
        drop(unsafe { Box::from_raw(self.state) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ops::Range;
    use core::sync::atomic::{AtomicU64, Ordering};
    use stela_driver_base::bus::dma::mapping::DmaError;

    /// A function's configuration space as plain memory.
    struct Config([u8; 256]);

    impl ConfigSpace for Config {
        fn read32(&self, offset: u16) -> u32 {
            let at = usize::from(offset);
            u32::from_le_bytes(self.0[at..at + 4].try_into().unwrap())
        }
        fn write32(&mut self, offset: u16, value: u32) {
            let at = usize::from(offset);
            self.0[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        fn write16(&mut self, offset: u16, value: u16) {
            let at = usize::from(offset);
            self.0[at..at + 2].copy_from_slice(&value.to_le_bytes());
        }
        fn write8(&mut self, offset: u16, value: u8) {
            self.0[usize::from(offset)] = value;
        }
    }

    #[test]
    fn msi_programs_its_one_message_by_width() {
        const CAPABILITY: u16 = 0x60;
        for (width, data_at) in [(1 << 7, 0x6c), (0, 0x68)] {
            let mut config = Config([0; 256]);
            // Enabled, with a previous owner's multiple-message setting.
            config.write16(CAPABILITY + 2, width | 1 | 2 << 4);
            let msi = Msi::at(CAPABILITY);
            msi.program(&mut config, 0x1_fee0_1000, 0x51);
            assert_eq!(config.read16(CAPABILITY + 2), width | 2 << 4);
            assert_eq!(config.read32(CAPABILITY + 4), 0xfee0_1000);
            assert_eq!(config.read16(data_at), 0x51);
            msi.enable(&mut config);
            assert_eq!(config.read16(CAPABILITY + 2), width | 1);
            msi.disable(&mut config);
            assert_eq!(config.read16(CAPABILITY + 2), width);
        }
    }

    #[derive(Default)]
    struct Identity {
        next: AtomicU64,
        unmapped: AtomicU64,
    }

    // SAFETY: bookkeeping over addresses nothing dereferences.
    unsafe impl DmaDomain for Identity {
        unsafe fn map(
            &self,
            pages: &DmaPages,
            _: Direction,
            limit: u64,
        ) -> Result<DomainMapping, DmaError> {
            let address = pages.physical_pages()[0];
            assert!(address <= limit);
            Ok(DomainMapping {
                id: self.next.fetch_add(1, Ordering::Relaxed),
                address,
                bytes: pages.bytes(),
            })
        }
        unsafe fn unmap(&self, _: DomainMapping) -> Result<(), DmaError> {
            self.unmapped.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        unsafe fn sync_for_device(
            &self,
            _: DomainMapping,
            _: Range<usize>,
            _: Direction,
        ) -> Result<(), DmaError> {
            Ok(())
        }
        unsafe fn sync_for_cpu(
            &self,
            _: DomainMapping,
            _: Range<usize>,
            _: Direction,
        ) -> Result<(), DmaError> {
            Ok(())
        }
    }

    #[test]
    fn the_same_pages_can_be_mapped_twice() {
        let domain = Arc::new(Identity::default());
        let mut mappings = Mappings {
            domain: domain.clone(),
            limit: u64::MAX >> 1,
            live: BTreeMap::new(),
        };
        let address = mappings.map(0x5010, 0x2000, Direction::ToDevice);
        assert_eq!(address, Some(0x5010));
        assert_eq!(mappings.map(0x5010, 0x10, Direction::FromDevice), address);
        mappings.unmap(0x5010);
        assert_eq!(domain.unmapped.load(Ordering::Relaxed), 1);
        assert!(mappings.live.contains_key(&0x5010));
        mappings.unmap(0x5010);
        assert!(mappings.live.is_empty());
        mappings.unmap(0x5010);
        assert_eq!(domain.unmapped.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn a_mapping_spans_every_page_it_touches() {
        let domain = Arc::new(Identity::default());
        let mut mappings = Mappings {
            domain,
            limit: u64::MAX >> 1,
            live: BTreeMap::new(),
        };
        mappings
            .map(0x1ff0, 0x20, Direction::Bidirectional)
            .unwrap();
        let mapping = mappings.live[&0x1ff0][0];
        assert_eq!(mapping.bytes, 0x2000);
        assert_eq!(mappings.map(u64::MAX, 2, Direction::ToDevice), None);
    }
}
