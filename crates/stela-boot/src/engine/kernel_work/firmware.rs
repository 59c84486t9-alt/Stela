//! Actual foreground stack/root context for synchronous firmware calls.
use super::*;
use crate::engine::host::local::context::ProcessRootScope;

/// Read-only stack view retaining the SAME original allocation claim and all
/// qualified mappings as Runtime's mutable stack backing. It cannot create a
/// second Stack, export bytes, or mint a cold/C stack grant.
pub(super) struct Foreground {
    pub(super) reservation: Arc<Reservation>,
    pub(super) bounds: Range<usize>,
    pub(super) lower: Range<usize>,
    pub(super) upper: Range<usize>,
    pub(super) physical: u64,
}

/// Borrowed, non-Send synchronous callback context. Only KernelWork's actual
/// foreground callback can construct it. Map observations confer no allocation,
/// runtime-service, clock, interpreter or arbitrary pointer access permission.
pub(crate) struct FirmwareContext<'a> {
    root: ProcessRootScope<'a>,
    stack: &'a Foreground,
    queue: &'a Queue<SLOTS>,
    id: work::ContextId,
}
impl<'a> FirmwareContext<'a> {
    pub(super) fn enter(stack: &'a Foreground, queue: &'a Queue<SLOTS>) -> Result<Self, Error> {
        let id = queue.current_id().map_err(Error::Work)?;
        let root = stack
            .reservation
            .identity
            .process_root()
            .map_err(Error::Work)?;
        let context = Self {
            root,
            stack,
            queue,
            id,
        };
        context.check()?;
        context.validate_stack()?;
        Ok(context)
    }
    pub(crate) fn id(&self) -> u64 {
        self.id.get()
    }
    /// Descriptive bounds of the actual retained full usable foreground stack.
    pub(crate) fn stack_bounds(&self) -> Range<usize> {
        self.stack.bounds.clone()
    }
    pub(crate) fn check(&self) -> Result<(), Error> {
        if self.queue.current_id().map_err(Error::Work)? != self.id {
            return Err(Error::Qualification);
        }
        self.root
            .entered_original(&self.stack.reservation._handoff.native_loader_tables)
            .map_err(Error::Work)?;
        let rsp: usize;
        // SAFETY: pure current-stack observation on this actual qualified CPU;
        // no stack bytes are read and no pointer/borrow escapes this callback.
        unsafe {
            asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags));
        }
        if !self.stack.bounds.contains(&rsp) {
            return Err(Error::Qualification);
        }
        Ok(())
    }
    pub(crate) fn observe(&self, address: u64) -> Result<Option<mappings::Observation>, Error> {
        self.check()?;
        self.root.observe_original(address).map_err(Error::Work)
    }
    fn validate_stack(&self) -> Result<(), Error> {
        let bounds = self.stack_bounds();
        let bytes = bounds
            .end
            .checked_sub(bounds.start)
            .filter(|bytes| *bytes != 0)
            .ok_or(Error::Geometry)?;
        if !self
            .stack
            .reservation
            .allocation
            .contains(self.stack.physical, bytes as u64)
        {
            return Err(Error::Inventory);
        }
        for offset in (0..bytes).step_by(4096) {
            let address = bounds.start.checked_add(offset).ok_or(Error::Geometry)?;
            let expected = self
                .stack
                .physical
                .checked_add(offset as u64)
                .ok_or(Error::Geometry)?;
            let leaf = self
                .observe(address as u64)?
                .ok_or(Error::Mapping(mappings::Error::Missing))?;
            if leaf.physical != expected || !leaf.writable || leaf.user || !leaf.nx {
                return Err(Error::Mapping(mappings::Error::Permissions));
            }
        }
        for guard in [&self.stack.lower, &self.stack.upper] {
            for address in guard.clone().step_by(4096) {
                if self.observe(address as u64)?.is_some() {
                    return Err(Error::Mapping(mappings::Error::GuardMapped));
                }
            }
        }
        crate::native_memory::cache::verify_writeback(
            bounds.start as u64,
            self.stack.physical,
            bytes,
            layout::physical(0),
        )
        .map_err(Error::Cache)?;
        self.check()
    }
}
