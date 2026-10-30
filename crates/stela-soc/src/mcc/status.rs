//! Source-required views of a declared Stela broadcast selector. Original
//! iBoot's helper writes +0x10000c once per MCC around all-plane programs;
//! SPTM's descriptor reader addresses +plane*0x40000. A newly created Stela
//! resource exposes these read views of its one selector, rather than
//! storing independent cache-disabled values. This is a source-consumer-derived
//! emulated protocol, not a physical Apple reset/alias observation. Retained
//! physical observations do not acquire the relationship from this declaration.
use super::{BROADCAST, PLANE_STRIDE, PLANES};

pub(super) fn canonical(offset: u64) -> Option<u64> {
    let delta = offset.checked_sub(BROADCAST)?;
    (delta.is_multiple_of(PLANE_STRIDE) && delta / PLANE_STRIDE < u64::from(PLANES))
        .then_some(BROADCAST)
}
pub(super) fn aliases() -> impl Iterator<Item = u64> {
    (1..PLANES).map(|plane| BROADCAST + u64::from(plane) * PLANE_STRIDE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use {
        crate::mcc::Configuration, crate::mcc::Controller, crate::mcc::Origin,
        stela_contracts::bus::Access, stela_contracts::bus::Lifecycle,
        stela_contracts::bus::LifecycleState, stela_contracts::bus::MmioDevice,
        stela_contracts::bus::Width, stela_contracts::interrupt::InterruptLatch,
    };

    fn running() -> LifecycleState {
        LifecycleState {
            powered: true,
            clocked: true,
            quiesced: false,
            reset: false,
            retention: true,
        }
    }
    #[test]
    fn created_views_read_one_selector_without_cache_completion() {
        let owner = Controller::initialized(
            Configuration {
                dram: vec![[0; 4]; 2],
                weights: [1; 32],
            },
            running(),
        )
        .unwrap();
        let mut first = owner.view(0).unwrap();
        let mut second = owner.view(1).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 11, &mut latch);
        let original_words = owner.observations().len();
        for offset in core::iter::once(BROADCAST).chain(aliases()) {
            assert_eq!(first.read(offset, Width::Word, &mut access), Ok(0));
        }
        first.write(BROADCAST, Width::Word, 1, &mut access).unwrap();
        // A nonzero ways request still needs its real cache/power backend.
        // Reading1 at a control alias does not complete those status bits.
        first.write(0x1c00, Width::Word, 3, &mut access).unwrap();
        assert!(first.read(0x1c04, Width::Word, &mut access).is_err());
        for offset in core::iter::once(BROADCAST).chain(aliases()) {
            assert_eq!(first.read(offset, Width::Word, &mut access), Ok(1));
            assert_eq!(second.read(offset, Width::Word, &mut access), Ok(0));
        }
        assert_eq!(owner.observations().len(), original_words);
        assert_eq!(
            owner
                .observations()
                .iter()
                .filter(|word| canonical(word.offset).is_some())
                .count(),
            2
        );
        let before = owner.observations();
        let requests = owner.requests();
        for offset in aliases() {
            for width in [Width::Byte, Width::Half, Width::Double] {
                assert!(first.read(offset, width, &mut access).is_err());
            }
            for value in [0, 1] {
                assert!(
                    first
                        .write(offset, Width::Word, value, &mut access)
                        .is_err()
                );
            }
        }
        assert_eq!(owner.observations(), before);
        assert_eq!(owner.requests(), requests);
        first.write(BROADCAST, Width::Word, 0, &mut access).unwrap();
        for offset in aliases() {
            assert_eq!(first.read(offset, Width::Word, &mut access), Ok(0));
        }
        assert!(
            first
                .read(
                    BROADCAST + u64::from(PLANES) * PLANE_STRIDE,
                    Width::Word,
                    &mut access
                )
                .is_err()
        );
        assert!(first.read(BROADCAST + 4, Width::Word, &mut access).is_err());
        let paused = LifecycleState {
            clocked: false,
            ..running()
        };
        first.set_lifecycle(paused, &mut access);
        for offset in aliases() {
            assert!(first.read(offset, Width::Word, &mut access).is_err());
        }
        first.set_lifecycle(running(), &mut access);
    }
    #[test]
    fn physical_observations_do_not_acquire_created_resource_aliases() {
        let created = Controller::initialized(
            Configuration {
                dram: vec![[0; 4]],
                weights: [1; 32],
            },
            running(),
        )
        .unwrap();
        let observed =
            Controller::from_observations(1, running(), &created.observations()).unwrap();
        assert_eq!(observed.origin(), Origin::RetainedObservation);
        let mut separate = created.observations();
        separate.push(super::super::Observation {
            aperture: 0,
            offset: BROADCAST + PLANE_STRIDE,
            value: 1,
            known: u32::MAX.into(),
        });
        assert!(Controller::from_observations(1, running(), &separate).is_err());

        for offset in aliases() {
            assert!(created.register_offsets().contains(&offset));
            assert!(!observed.register_offsets().contains(&offset));
            let mut latch = InterruptLatch::new();
            assert!(
                observed
                    .view(0)
                    .unwrap()
                    .read(offset, Width::Word, &mut Access::new(0, 0, &mut latch))
                    .is_err()
            );
        }
    }
}
