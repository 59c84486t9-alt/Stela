//! Distinct T8112 cache/lock and DCS/PTD owners over one actual RAM allocation.
use super::{AppleDevices, memory_resources::t8112};
use crate::platform::apple::bus::Width;
use alloc::{boxed::Box, format, string::String, sync::Arc};

impl AppleDevices {
    /// Install the actual component owners together, retaining separate device
    /// identities for memory locks and DCS/PTD publication. This supplies no
    /// original zero-mode input, PMGR, PMP, IRQ or whole-platform admission.
    pub fn add_t8112_empty_memory_resources(
        &mut self,
        memory: t8112::Prepared,
        cache: t8112::cache::EmptyResource,
    ) -> Result<(), String> {
        if self.power_configured
            || self.memory_controller.is_some()
            || self.memory_publication.is_some()
        {
            return Err("memory resource owners are already installed".into());
        }
        if !Arc::ptr_eq(memory.registered_ram(), cache.registered_ram()) {
            return Err("T8112 cache and DCS/PTD require the same actual registered RAM".into());
        }
        let cache_binding = [cache.binding()];
        // reg[0] of the original MCC node names the shared aperture, while
        // cache.binding() covers the union beginning at the AMCC planes.
        let lifecycle_physical = cache.placement().shared.0;
        if cache_binding[0].0.checked_add(cache_binding[0].1)
            != Some(memory.descriptor().channels.0)
        {
            return Err("T8112 cache union and DCS source placements disagree".into());
        }
        let memory_bindings = memory.bindings();
        let [publication, controller] = self
            .bus
            .install_many(
                [Box::new(memory), Box::new(cache)],
                [&memory_bindings, &cache_binding],
            )
            .map_err(|error| format!("T8112 memory placement: {error:?}"))?;
        self.memory_publication = Some(publication);
        self.memory_controller = Some(controller);
        // These are distinct actual lifecycle sinks of the same source MCC
        // resource. Both follow its domains; DCS/PTD must not stay active when
        // its cache/lock owner is paused. The hooks still refuse unsupported
        // reset/loss transitions rather than grant completion here.
        self.register_power_device(lifecycle_physical, controller, true)?;
        self.register_power_device(lifecycle_physical, publication, true)?;
        Ok(())
    }

    /// Bounded observations from this installed owner, not completion authority
    /// or a receipt for an operation belonging to another RAM generation.
    pub fn t8112_cache_progress(&self) -> Option<t8112::cache::Progress> {
        self.bus
            .device::<t8112::cache::EmptyResource>(self.memory_controller?)
            .map(t8112::cache::EmptyResource::progress)
    }

    pub(super) fn empty_cache_flush_needs_ram(&self, physical: u64, width: Width) -> bool {
        self.bus
            .route(physical, width)
            .ok()
            .is_some_and(|(device, offset)| {
                self.bus
                    .device::<t8112::cache::EmptyResource>(device)
                    .is_some_and(|owner| owner.requires_ram_flush(offset, width))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        machine::Devices,
        platform::apple::{
            bus::{Access, LifecycleState, MmioDevice},
            interrupt::InterruptLatch,
        },
    };
    use t8112::{
        amcc::tests::{frontend, ram, source},
        cache::{EmptyResource, SoftwareImage, ZeroWayConfiguration},
    };

    fn components() -> (t8112::Prepared, EmptyResource) {
        let memory = frontend(ram());
        let locks = memory
            .initialize_amcc_locks(
                source(),
                [None; 4],
                LifecycleState {
                    powered: true,
                    clocked: true,
                    quiesced: false,
                    reset: false,
                    retention: true,
                },
            )
            .unwrap();
        let cache = EmptyResource::initialized(
            locks,
            ZeroWayConfiguration::ClampZero,
            SoftwareImage::zeroed_control_image(),
        )
        .unwrap();
        (memory, cache)
    }

    #[test]
    fn paired_install_retains_distinct_ids_one_ram_and_reached_lock_state() {
        let (memory, mut cache) = components();
        let dcs = memory.bindings()[0].0;
        let base = cache.binding().0;
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 9, &mut latch);
        for (register, value) in [(0x680, 1), (0x684, 1), (0x688, 1), (0x68c, 1)] {
            cache
                .write(register, Width::Word, value, &mut access)
                .unwrap();
        }
        let expected = cache.locked_regions();
        assert!(expected[0].is_some());
        let mut board = AppleDevices::new();
        board
            .add_t8112_empty_memory_resources(memory, cache)
            .unwrap();
        assert_ne!(board.memory_controller, board.memory_publication);
        assert_eq!(board.power_devices.len(), 2);
        assert!(
            board.power_devices.iter().all(|sink| sink.physical == base + 0x100000)
        );
        assert_ne!(board.power_devices[0].device, board.power_devices[1].device);
        assert_eq!(
            board.bus.route(base + 0x680, Width::Word).unwrap().0,
            board.memory_controller.unwrap()
        );
        assert_eq!(
            board.bus.route(dcs, Width::Word).unwrap().0,
            board.memory_publication.unwrap()
        );
        assert_eq!(board.memory_lock(), expected);
        assert_eq!(board.t8112_cache_progress().unwrap().completed_flushes, 0);
    }

    #[test]
    fn foreign_ram_and_later_owner_overlap_leave_no_partial_publication() {
        let (memory, cache) = components();
        let (_, foreign) = components();
        let dcs = memory.bindings()[0].0;
        let base = cache.binding().0;
        let mut board = AppleDevices::new();
        assert!(
            board
                .add_t8112_empty_memory_resources(memory, foreign)
                .is_err()
        );
        assert!(board.memory_controller.is_none());
        assert!(board.memory_publication.is_none());
        assert!(board.bus.route(dcs, Width::Word).is_err());
        let binding = [cache.binding()];
        let existing = board.bus.install(Box::new(cache), &binding).unwrap();
        let (memory, cache) = components();
        assert!(
            board
                .add_t8112_empty_memory_resources(memory, cache)
                .is_err()
        );
        assert_eq!(board.bus.route(base, Width::Word).unwrap().0, existing);
        assert!(board.bus.route(dcs, Width::Word).is_err());
        assert!(board.memory_controller.is_none());
        assert!(board.memory_publication.is_none());
    }

    #[test]
    fn raw_flush_is_classified_and_refused_without_a_sealed_ram_service() {
        let (memory, cache) = components();
        let flush = cache.binding().0 + 0xf01c2c;
        let mut board = AppleDevices::new();
        board
            .add_t8112_empty_memory_resources(memory, cache)
            .unwrap();
        assert!(board.empty_cache_flush_needs_ram(flush, Width::Word));
        assert!(!board.empty_cache_flush_needs_ram(flush, Width::Double));
        assert!(board.write(0, flush, 4, 1, 7).is_err());
        assert_eq!(board.t8112_cache_progress().unwrap().completed_flushes, 0);
    }
}
