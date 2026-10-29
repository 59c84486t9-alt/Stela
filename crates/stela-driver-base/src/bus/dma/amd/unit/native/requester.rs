//! Requester ownership and DMA bindings behind one AMD IOMMU unit.
use super::*;
use crate::bus::pci::{ConfigSpace, Function, owned::OwnedConfig, requester::RequesterBinding};

/// What keeps the requester's configuration epoch: its function, or the
/// binding of a driver that keeps the function.
pub(super) enum Owner {
    Function(RefCell<Function<OwnedConfig>>),
    Binding(RequesterBinding),
}

struct Binding {
    id: u64,
    address: u64,
    bytes: usize,
    direction: Direction,
    pages: DmaPages,
}

/// A non-cloneable private reservation from one original requester. Metadata
/// cannot mint a token; stale/foreign tokens are rejected before hardware work.
pub struct Mapping {
    owner: Rc<()>,
    id: u64,
    address: u64,
    bytes: usize,
}
impl Mapping {
    pub fn address(&self) -> u64 {
        self.address
    }
    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

/// PCI requester, reserved AMD domain ID, DTE/root and payload pins.
/// Process local ownership preserves the original native context restriction.
pub struct Requester<P: ColdPlatform> {
    tree: PageTables<Hardware<P>>,
    table: Rc<RefCell<DeviceTable<Hardware<P>>>>,
    engine: Rc<Engine<P>>,
    owner: Rc<Owner>,
    active: Rc<RefCell<Vec<u16>>>,
    seal: Rc<()>,
    bindings: Vec<Binding>,
    rid: u16,
    /// The IDs its DMA arrives under: its own and its alias.
    group: Vec<u16>,
    next_mapping: u64,
    maximum_mappings: usize,
    detached: bool,
    poisoned: bool,
}

fn admit_function(function: &mut Function<OwnedConfig>) -> Result<u16, Error> {
    let address = function.address;
    let expected_id = u32::from(function.vendor) | u32::from(function.device) << 16;
    let config = function.config();
    if config.address() != address
        || expected_id == u32::MAX
        || config.read32(0) != expected_id
        || config.read8(0x0e) & 0x7f != 0
        || config.read16(4) & 4 != 0
    {
        return Err(Error::Requester);
    }
    if config.read32(0x100) == u32::MAX {
        return Err(Error::Profile);
    }
    for entry in config.extended_capabilities() {
        let entry = entry.map_err(|_| Error::Profile)?;
        // ATS/PRI/PASID/SR-IOV and unknown extended capabilities require wider
        // requester/alias ownership. Do not infer disabled integrated ATS from
        // the absence of its PCI capability; ColdPlatform independently owns it.
        if entry.version == 0
            || !matches!(entry.id, 1 | 3 | 0x0d | 0x15 | 0x18 | 0x19 | 0x1e | 0x1f)
        {
            return Err(Error::Profile);
        }
    }
    Ok(u16::from(address.bus) << 8 | u16::from(address.device) << 3 | u16::from(address.function))
}

impl<P: ColdPlatform> Unit<P> {
    /// # Safety
    /// `function` is the original covered requester in this unit's root
    /// and firmware epoch. The producer transfers its exclusive reset/removal/
    /// configuration ownership; all its aliases are absent in this plain
    /// profile. Engines/submissions and IRQ/work are stopped, all prior payload,
    /// posted writes and bypass traffic are drained, and no DMA can
    /// resume until success. BusMaster-clear is checked but is not this proof.
    /// Failure may keep the requester indefinitely with its uncertain root.
    pub unsafe fn attach(
        &mut self,
        mut function: Function<OwnedConfig>,
    ) -> Result<Requester<P>, Error> {
        if self.engine.retired.get() || self.engine.poisoned.get() {
            return Err(Error::Poisoned);
        }
        let guard = self.engine.resources.platform.enter().map_err(Error::Dma)?;
        let rid = admit_function(&mut function)?;
        if function.address.segment != self.segment {
            return Err(Error::Requester);
        }
        drop(guard);
        // SAFETY: forwarded.
        unsafe { self.attach_owner(rid, Owner::Function(RefCell::new(function))) }
    }

    /// Attach the requester a driver's binding names, moving it out of the
    /// window domain if it is in it.
    ///
    /// # Safety
    /// As for [`Self::attach`]; the driver keeps the function and enables
    /// bus mastering only after mapping through the returned requester.
    pub unsafe fn attach_binding(
        &mut self,
        binding: RequesterBinding,
    ) -> Result<Requester<P>, Error> {
        if self.engine.retired.get() || self.engine.poisoned.get() {
            return Err(Error::Poisoned);
        }
        if binding.address().segment != self.segment || binding.check_live().is_err() {
            return Err(Error::Requester);
        }
        let rid = binding.requester();
        // SAFETY: forwarded.
        unsafe { self.attach_owner(rid, Owner::Binding(binding)) }
    }

    /// # Safety
    /// As for [`Self::attach`], for `owner`'s requester `rid`.
    unsafe fn attach_owner(&mut self, rid: u16, owner: Owner) -> Result<Requester<P>, Error> {
        let _guard = self.engine.resources.platform.enter().map_err(Error::Dma)?;
        if !self.coverage[usize::from(rid)] {
            return Err(Error::Requester);
        }
        let group = self.group(rid);
        // A requester whose alias another requester shares has no domain
        // of its own: the shared ID would carry both.
        if self.shared(rid, &group) {
            return Err(Error::Requester);
        }
        self.engine.health()?;
        if self.active.borrow().contains(&rid) {
            return Err(Error::Busy);
        }
        let next = self.next_domain.get();
        let id = u16::try_from(next)
            .ok()
            .and_then(DomainId::new)
            .ok_or(Error::Exhausted)?;
        self.next_domain.set(next + 1); // Never recycle an ID in a live unit.
        self.active
            .borrow_mut()
            .try_reserve(1)
            .map_err(|_| Error::Memory(MemoryError::OutOfMemory))?;
        let owner = Rc::new(owner);
        let hardware = Hardware {
            engine: self.engine.clone(),
            domain: Some(id),
            requester: Some(owner.clone()),
        };
        let level = TableLevel::new(2).map_err(|_| Error::Profile)?;
        // SAFETY: fixed30-bit IOVA/2-level subset admitted from HATS,
        // IVINFO, platform PA width and original cold requester ownership.
        let mut tree = unsafe {
            PageTables::new(
                hardware,
                level,
                self.physical_bits,
                30,
                self.limits.table_pages,
                self.limits.table_backing_bytes,
            )
        }
        .map_err(Error::Translation)?;
        self.active.borrow_mut().push(rid);
        let root = tree.root_for_publication().map_err(Error::Translation)?;
        for &member in &group {
            // SAFETY: requester stopped/drained by caller; fresh domain
            // ID and exposed root stay held through DTE visibility and
            // the old domain's invalidation.
            unsafe { self.table.borrow_mut().translate(member, root, level, id) }
                .map_err(Error::DeviceTable)?;
        }
        if let Some(window) = &mut self.window {
            window.requesters.retain(|member| !group.contains(member));
        }
        drop(_guard);
        Ok(Requester {
            tree,
            table: self.table.clone(),
            engine: self.engine.clone(),
            owner,
            active: self.active.clone(),
            seal: Rc::new(()),
            bindings: Vec::new(),
            rid,
            group,
            next_mapping: 1,
            maximum_mappings: self.limits.mappings,
            detached: false,
            poisoned: false,
        })
    }
}

impl<P: ColdPlatform> Requester<P> {
    /// Use the original PCI function, for example to program the
    /// owning driver's IRQs and BusMaster after attachment. No cloned config
    /// or second mapping permission is created.
    ///
    /// # Safety
    /// The caller owns this device's configuration operation and obeys
    /// its DMA/IRQ/submission ordering. It must preserve original identity,
    /// root/routing, resource assignment and reset/removal epochs, ATS/PASID/PRI
    /// exclusion and the cold platform profile. No returned value may contain a
    /// raw config access path; do not reenter this requester from the closure.
    /// Never move, replace or extract the original Function/OwnedConfig, even
    /// with another owner having identical numeric PCI identity.
    pub unsafe fn with_function<R>(
        &mut self,
        action: impl FnOnce(&mut Function<OwnedConfig>) -> R,
    ) -> Result<R, Error> {
        self.live()?;
        let _guard = self.engine.resources.platform.enter().map_err(Error::Dma)?;
        self.engine.health()?;
        let Owner::Function(function) = &*self.owner else {
            // The binding's driver keeps the function.
            return Err(Error::Requester);
        };
        let mut function = function.try_borrow_mut().map_err(|_| Error::Busy)?;
        self.poisoned = true;
        let result = action(&mut function);
        drop(function);
        drop(_guard);
        self.poisoned = false;
        Ok(result)
    }

    fn live(&self) -> Result<(), Error> {
        if self.detached
            || self.poisoned
            || self.tree.is_poisoned()
            || self.table.borrow().is_poisoned()
            || self.engine.retired.get()
            || self.engine.poisoned.get()
        {
            return Err(Error::Poisoned);
        }
        // A binding's requester lives while its configuration epoch does.
        if let Owner::Binding(binding) = &*self.owner
            && binding.check_live().is_err()
        {
            return Err(Error::Requester);
        }
        Ok(())
    }
    fn binding(&self, mapping: &Mapping) -> Result<&Binding, Error> {
        self.live()?;
        if !Rc::ptr_eq(&mapping.owner, &self.seal) {
            return Err(Error::Mapping);
        }
        self.bindings
            .iter()
            .find(|binding| {
                binding.id == mapping.id
                    && binding.address == mapping.address
                    && binding.bytes == mapping.bytes
            })
            .ok_or(Error::Mapping)
    }
    /// Install the exact ordered original pins. No device may reference the
    /// new address until success plus explicit payload/descriptor publication.
    pub fn map(
        &mut self,
        pages: DmaPages,
        direction: Direction,
        limit: u64,
    ) -> Result<Mapping, Error> {
        self.live()?;
        if self.bindings.len() == self.maximum_mappings {
            return Err(Error::Exhausted);
        }
        let bytes = pages.bytes();
        let mut address = 4096u64; // Deliberate invalid/null IOVA guard page.
        for binding in &self.bindings {
            if address
                .checked_add(bytes as u64)
                .is_some_and(|end| end <= binding.address)
            {
                break;
            }
            address = binding
                .address
                .checked_add(binding.bytes as u64)
                .ok_or(Error::Exhausted)?;
        }
        let last = address
            .checked_add(bytes as u64)
            .and_then(|end| end.checked_sub(1))
            .ok_or(Error::Mapping)?;
        if bytes == 0 || last > limit || last >= 1 << 30 {
            return Err(Error::Dma(DmaError::AddressLimit));
        }
        let id = self.next_mapping;
        let next = id.checked_add(1).ok_or(Error::Exhausted)?;
        self.bindings
            .try_reserve(1)
            .map_err(|_| Error::Memory(MemoryError::OutOfMemory))?;
        let _guard = self.engine.resources.platform.enter().map_err(Error::Dma)?;
        self.engine.health()?;
        let position = self
            .bindings
            .partition_point(|binding| binding.address < address);
        self.bindings.insert(
            position,
            Binding {
                id,
                address,
                bytes,
                direction,
                pages: pages.clone(),
            },
        );
        self.next_mapping = next;
        self.poisoned = true;
        // SAFETY: exclusive new nonoverlapping bounded IOVA, kept
        // pins, no submission can know it yet; table hardware kept.
        let result = unsafe { self.tree.map(address, pages, direction) };
        if let Err(error) = result {
            if !self.tree.is_poisoned() {
                self.bindings.remove(position);
                drop(_guard);
                self.poisoned = false;
            }
            return Err(Error::Translation(error));
        }
        drop(_guard);
        self.poisoned = false;
        Ok(Mapping {
            owner: self.seal.clone(),
            id,
            address,
            bytes,
        })
    }
    /// # Safety
    /// Every access to this exact mapping has completed; submissions/engines
    /// and IRQ/work users are stopped and drained and cannot issue new access.
    /// The original platform's process/root/cache context still applies.
    pub unsafe fn unmap(&mut self, mapping: &Mapping) -> Result<(), Error> {
        let address = self.binding(mapping)?.address;
        let _guard = self.engine.resources.platform.enter().map_err(Error::Dma)?;
        self.engine.health()?;
        self.poisoned = true;
        // SAFETY: validated private original token; caller supplies DMA/
        // submission/IRQ/work quiescence, never inferred from a command store.
        unsafe { self.tree.unmap(address) }.map_err(Error::Translation)?;
        let position = self
            .bindings
            .iter()
            .position(|binding| binding.id == mapping.id)
            .expect("checked token");
        drop(_guard);
        self.bindings.remove(position);
        self.poisoned = false;
        Ok(())
    }
    /// # Safety
    /// CPU ownership of a CPU sync range follows device completion;
    /// no ordinary CPU writer may race a device sync. No DMA-stop is implied.
    pub unsafe fn sync(
        &self,
        mapping: &Mapping,
        range: Range<usize>,
        for_cpu: bool,
    ) -> Result<(), Error> {
        let binding = self.binding(mapping)?;
        if range.start > range.end || range.end > binding.bytes {
            return Err(Error::Mapping);
        }
        let _guard = self.engine.resources.platform.enter().map_err(Error::Dma)?;
        self.engine.health()?;
        // SAFETY: original kept pins/direction and bounded range;
        // CPU/device range ownership is the caller's obligation.
        unsafe {
            self.engine
                .resources
                .platform
                .sync(&binding.pages, range, binding.direction, for_cpu)
        }
        .map_err(Error::Dma)
    }
    pub fn drain_posted_writes(&self) -> Result<(), DmaError> {
        Err(DmaError::DrainUnavailable)
    }
    /// # Safety
    /// This requester is stopped, every mapping was quiescently removed,
    /// all payload/posted/IRQ/work users are drained and cannot resume. Original
    /// configuration/root ownership must remain held through this operation.
    pub unsafe fn detach(&mut self) -> Result<(), Error> {
        self.live()?;
        if !self.bindings.is_empty() {
            return Err(Error::Busy);
        }
        let _guard = self.engine.resources.platform.enter().map_err(Error::Dma)?;
        self.engine.health()?;
        self.poisoned = true;
        // SAFETY: caller supplies complete requester quiescence; real
        // DTE block invalidates old domain before its root may be retired.
        for &member in &self.group {
            // SAFETY: as above, for each ID the requester's DMA arrives under.
            unsafe { self.table.borrow_mut().block(member) }.map_err(Error::DeviceTable)?;
        }
        drop(_guard);
        // SAFETY: last exposed DTE is now blocked and full-domain invalidation
        // plus completion have acknowledged no remaining invalidated walks.
        unsafe { self.tree.retire() };
        self.active.borrow_mut().retain(|rid| *rid != self.rid);
        self.detached = true;
        Ok(())
    }
}

impl<P: ColdPlatform> Drop for Requester<P> {
    fn drop(&mut self) {
        if !self.detached {
            // Also keep metadata pins for an unmap whose translation removal
            // completed but outer execution-guard teardown unwound. PageTables
            // itself keeps every still-installed/uncertain mapping and root.
            core::mem::forget(core::mem::take(&mut self.bindings));
        }
    }
}
