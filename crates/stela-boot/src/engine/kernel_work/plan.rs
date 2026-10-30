//! Layout data only; the constructor separately validates the original
//! handoff, RootIdentity, sealed table/cache state and complete raw allocation.
use super::*;
use stela_boot_core::guarded_stacks::{Layout, Slot};
pub(super) enum Plan {
    Uniform {
        layout: Layout,
        raw: Region,
    },
    #[cfg(feature = "diagnostics")]
    Mixed {
        base: u64,
        virtual_bytes: u64,
        raw_bytes: u64,
        raw: Region,
    },
}
impl Plan {
    pub(super) fn uniform(handoff: &Handoff) -> Self {
        Self::Uniform {
            layout: native_smp::resources::task_stacks(),
            raw: handoff.native_resources.tasks,
        }
    }
    #[cfg(feature = "diagnostics")]
    pub(super) fn prototype(handoff: &Handoff) -> Result<Self, Error> {
        if handoff.native_resources.cores != 1
            || handoff.native_resources.prototype_task_plan
                != native_smp::resources::PrototypeTaskPlan::FirmwarePrototype32Mixed
        {
            return Err(Error::Inventory);
        }
        let base = layout::prototype_task_stacks();
        let geometry = native_smp::resources::prototype_tasks(base).map_err(|_| Error::Geometry)?;
        let ordinary = native_smp::resources::task_stacks();
        let end = layout::task_stacks()
            .checked_add(ordinary.virtual_bytes())
            .ok_or(Error::Geometry)?;
        if geometry.virtual_range().start < end
            || geometry.virtual_range().end
                > base
                    .checked_add(native_smp::resources::PROTOTYPE_WINDOW_BYTES)
                    .ok_or(Error::Geometry)?
        {
            return Err(Error::Geometry);
        }
        Ok(Self::Mixed {
            base,
            virtual_bytes: geometry.virtual_bytes(),
            raw_bytes: geometry.raw_allocation_bytes(),
            raw: handoff.native_resources.prototype_tasks,
        })
    }
    pub(super) fn validate(&self, handoff: &Handoff) -> Result<(), Error> {
        let actual = if self.mixed() {
            if handoff.native_resources.prototype_task_plan
                != native_smp::resources::PrototypeTaskPlan::FirmwarePrototype32Mixed
            {
                return Err(Error::Inventory);
            }
            handoff.native_resources.prototype_tasks
        } else {
            handoff.native_resources.tasks
        };
        let raw = self.region();
        if raw.physical != actual.physical
            || raw.bytes != actual.bytes
            || raw.bytes != self.raw_bytes()
        {
            return Err(Error::Inventory);
        }
        raw.physical.checked_add(raw.bytes).ok_or(Error::Geometry)?;
        Ok(())
    }
    pub(super) fn mixed(&self) -> bool {
        match self {
            Self::Uniform { .. } => false,
            #[cfg(feature = "diagnostics")]
            Self::Mixed { .. } => true,
        }
    }
    pub(super) fn region(&self) -> Region {
        match self {
            Self::Uniform { raw, .. } => *raw,
            #[cfg(feature = "diagnostics")]
            Self::Mixed { raw, .. } => *raw,
        }
    }
    pub(super) fn count(&self) -> usize {
        match self {
            Self::Uniform { layout, .. } => layout.count(),
            #[cfg(feature = "diagnostics")]
            Self::Mixed { .. } => native_smp::resources::PROTOTYPE_STACKS,
        }
    }
    pub(super) fn raw_bytes(&self) -> u64 {
        match self {
            Self::Uniform { layout, .. } => layout.physical_bytes(),
            #[cfg(feature = "diagnostics")]
            Self::Mixed { raw_bytes, .. } => *raw_bytes,
        }
    }
    pub(super) fn virtual_range(&self) -> Range<u64> {
        match self {
            Self::Uniform { layout, .. } => {
                layout::task_stacks()..layout::task_stacks() + layout.virtual_bytes()
            }
            #[cfg(feature = "diagnostics")]
            Self::Mixed {
                base,
                virtual_bytes,
                ..
            } => *base..*base + *virtual_bytes,
        }
    }
    pub(super) fn slot(&self, index: usize) -> Result<(Slot, u64), Error> {
        let raw = self.region();
        match self {
            Self::Uniform { layout, .. } => Ok((
                layout
                    .slot(layout::task_stacks(), index)
                    .map_err(|_| Error::Geometry)?,
                raw.physical
                    .checked_add(layout.physical_offset(index).map_err(|_| Error::Geometry)?)
                    .ok_or(Error::Geometry)?,
            )),
            #[cfg(feature = "diagnostics")]
            Self::Mixed { base, .. } => {
                // Recompute this fixed checked descriptor on the preparation
                // stack; do not add a heap allocation or1.6KiB enum payload to
                // every production Uniform plan for diagnostic metadata.
                let layout =
                    native_smp::resources::prototype_tasks(*base).map_err(|_| Error::Geometry)?;
                let end = raw.physical.checked_add(raw.bytes).ok_or(Error::Geometry)?;
                let backing = layout
                    .backing(raw.physical..end, index)
                    .map_err(|_| Error::Geometry)?;
                Ok((
                    layout.slot(index).map_err(|_| Error::Geometry)?,
                    backing.start,
                ))
            }
        }
    }
}
pub(super) fn profile() -> Result<work::StackProfile, Error> {
    let kernel = stela_drivers::gpu::linux::task::stack_requirement().map_err(Error::Work)?;
    if kernel != work::StackRequirement::exact(16 * 1024, 16 * 1024, 4096).map_err(Error::Work)? {
        return Err(Error::Geometry);
    }
    work::StackProfile::new(
        kernel,
        work::StackRequirement::at_least(128 * 1024, 4096, 4096).map_err(Error::Work)?,
        20,
        4,
    )
    .map_err(Error::Work)
}
