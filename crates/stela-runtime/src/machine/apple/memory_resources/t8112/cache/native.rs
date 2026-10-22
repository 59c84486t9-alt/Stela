//! Actual cache/PTD quota association and exclusive native callback borrow.
use super::super::Prepared;
use super::*;

impl EmptyResource {
    /// Borrow this exact AP-facing bank for a native quota callback. This is
    /// not a clone of its words, a PMP startup or a service-completion token.
    pub fn quota_view(&mut self) -> QuotaView<'_> {
        QuotaView(self)
    }
    fn bind_quota_publisher(
        &mut self,
        local: crate::platform::apple::ptd::transport::notifications::LocalNotifications,
    ) -> Result<publisher::Binding, &'static str> {
        if self.quota_claimed {
            return Err("actual cache native quota publisher is already admitted");
        }
        self.quota_claimed = true;
        Ok(publisher::Binding::new(self.quota_identity.clone(), local))
    }
}
impl Prepared {
    /// Bind exactly one native quota publisher to these actual component
    /// owners. It neither admits startup/IRQs nor completes a source command.
    pub fn bind_quota_publisher(
        &self,
        cache: &mut EmptyResource,
    ) -> Result<crate::platform::apple::pmp::native::cache::publisher::Binding, &'static str> {
        if !Arc::ptr_eq(&self.ram, cache.registered_ram())
            || cache.binding().0.checked_add(cache.binding().1) != Some(self.descriptor.channels.0)
        {
            return Err(
                "native quota publisher requires the same actual cache/DCS/PTD RAM and placement",
            );
        }
        cache.bind_quota_publisher(self.local.clone())
    }
}
/// An exclusive callback borrow of the actual cache, including its current
/// lifecycle and shared quota words. The backing cannot be replaced while lent.
pub struct QuotaView<'a>(&'a mut EmptyResource);
impl publisher::Bank for QuotaView<'_> {
    fn identity(&self) -> &publisher::Identity {
        &self.0.quota_identity
    }
    fn validate(&self) -> Result<(), &'static str> {
        self.0.locks.accessible()
    }
    fn read_quota(&mut self, group: u8) -> Result<u32, &'static str> {
        if usize::from(group) >= 32 {
            return Err("native quota group exceeds the actual bank");
        }
        let offset = BROADCAST + QUOTAS + u64::from(group) * 4;
        self.0.checked(offset, Width::Word)?;
        self.0.read_cache(offset).map(|word| word as u32)
    }
    fn write_quota(
        &mut self,
        group: u8,
        value: u32,
        access: &mut Access<'_>,
    ) -> Result<(), &'static str> {
        if usize::from(group) >= 32 {
            return Err("native quota group exceeds the actual bank");
        }
        self.0
            .write(
                BROADCAST + QUOTAS + u64::from(group) * 4,
                Width::Word,
                u64::from(value),
                access,
            )
            .map_err(|_| "native quota actual shared word programming refused")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::apple::memory_resources::t8112::{
        amcc::tests::{ram, source},
        tests::{configuration, descriptor},
    };
    use crate::platform::apple::{
        interrupt::InterruptLatch,
        pmp::native::cache::{
            policy::Inputs,
            publisher::{Bank, Configuration, Publisher},
        },
        ptd::{Range, transport::notifications::LocalNotifications},
    };
    use alloc::{vec, vec::Vec};

    const LIVE: LifecycleState = LifecycleState {
        powered: true,
        clocked: true,
        quiesced: false,
        reset: false,
        retention: true,
    };
    fn components() -> (Prepared, EmptyResource) {
        let mut descriptor = descriptor();
        descriptor.cache.shared = (0x100000, 0x80000);
        descriptor.cache.broadcast = BROADCAST;
        descriptor.ptd.ranges = vec![
            Range {
                id: 14,
                start: 194,
                count: 7,
                name: "authored requests".into(),
            },
            Range {
                id: 30,
                start: 208,
                count: 6,
                name: "authored responses".into(),
            },
        ];
        descriptor.ptd.interrupts = vec![14, 15];
        let memory = Prepared::initialized(descriptor, configuration(), LIVE, ram()).unwrap();
        let locks = memory
            .initialize_amcc_locks(source(), [None; 4], LIVE)
            .unwrap();
        let mut image = SoftwareImage::zeroed_control_image();
        image.quota_words = [0x4012_0040; 32];
        let cache =
            EmptyResource::initialized(locks, ZeroWayConfiguration::ClampZero, image).unwrap();
        (memory, cache)
    }
    fn inputs() -> Inputs {
        Inputs {
            budget: 64,
            reference: 64,
            hardware_scale: 0,
            hardware_multiplier: 0,
            feature_word: 0,
            slot_flags: [0; 32],
            quota_words: [1; 32],
        }
    }
    fn config() -> Configuration {
        Configuration {
            response_range: 30,
            response_words: 5,
            ack_words: 1,
            retain_attributes: true,
            suppression: Some(0),
        }
    }
    fn rows(groups: u32, scale: u32) -> Vec<u8> {
        (0..groups)
            .flat_map(|group| {
                [group, 0, 1, group, 0, 0, 3, 8192, 0, 0, scale]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
            })
            .collect()
    }
    fn publisher(
        memory: &Prepared,
        cache: &mut EmptyResource,
        groups: u32,
        scale: u32,
    ) -> Publisher {
        let binding = memory.bind_quota_publisher(cache).unwrap();
        let mut publisher = Publisher::new(
            binding,
            &mut cache.quota_view(),
            &rows(groups, scale),
            inputs(),
            config(),
        )
        .unwrap();
        publisher.publish_pending().unwrap();
        publisher
    }
    fn advance(publisher: &mut Publisher, cache: &mut EmptyResource, latch: &mut InterruptLatch) {
        publisher
            .advance(&mut cache.quota_view(), &mut Access::new(0, 7, latch))
            .unwrap();
    }
    fn quota(cache: &mut EmptyResource, group: u8) -> u32 {
        cache.quota_view().read_quota(group).unwrap()
    }
    struct Fault<'a> {
        view: QuotaView<'a>,
        local: LocalNotifications,
        attempts: Vec<(u8, u64)>,
    }
    impl Bank for Fault<'_> {
        fn identity(&self) -> &publisher::Identity {
            self.view.identity()
        }
        fn validate(&self) -> Result<(), &'static str> {
            self.view.validate()
        }
        fn read_quota(&mut self, group: u8) -> Result<u32, &'static str> {
            self.view.read_quota(group)
        }
        fn write_quota(
            &mut self,
            group: u8,
            value: u32,
            access: &mut Access<'_>,
        ) -> Result<(), &'static str> {
            self.attempts
                .push((group, self.local.bank().requests().last().unwrap().value));
            if group == 3 {
                return Err("authored pre-store refusal");
            }
            self.view.write_quota(group, value, access)
        }
    }
    #[test]
    fn initial_allocation_can_precede_first_actual_publication() {
        let (memory, mut cache) = components();
        let binding = memory.bind_quota_publisher(&mut cache).unwrap();
        let mut publisher = Publisher::new(
            binding,
            &mut cache.quota_view(),
            &rows(1, 0),
            inputs(),
            config(),
        )
        .unwrap();
        let mut latch = InterruptLatch::new();
        // Construction and an unscheduled advance perform no I/O. Native MC
        // startup can allocate before the event's first publisher invocation.
        advance(&mut publisher, &mut cache, &mut latch);
        assert_eq!(publisher.progress().completed_passes, 0);
        assert_eq!(publisher.progress().current_group, None);
        assert!(memory.publication_bank().requests().is_empty());
        publisher.allocate().unwrap();
        assert_eq!(publisher.policy().group(0).unwrap().hardware_target, 0);
        publisher.publish_allocated().unwrap();
        advance(&mut publisher, &mut cache, &mut latch);
        assert_eq!(quota(&mut cache, 0), 0x4012_0000);
        assert_eq!(publisher.progress().programmed_words, 1);
        assert_eq!(publisher.progress().completed_passes, 1);
        assert_eq!(memory.publication_bank().requests().len(), 1);
    }
    #[test]
    fn actual_words_and_ptd_preserve_interleaving_and_a_failed_fourth_store_prefix() {
        let (memory, mut cache) = components();
        let mut publisher = publisher(&memory, &mut cache, 4, 0);
        assert_eq!(publisher.policy().group(0).unwrap().ceiling, 64);
        let mut latch = InterruptLatch::new();
        advance(&mut publisher, &mut cache, &mut latch);
        assert_eq!(cache.progress().quota_writes, 0); // actual seeded targets skip unchanged stores
        assert_eq!(memory.publication_bank().requests().len(), 1);
        let packed = 16 | (17 << 16) | (18u64 << 32) | (19u64 << 48);
        for group in 0..4 {
            assert!(
                publisher
                    .set_request(group, 0x2000 | (16 + u16::from(group)))
                    .unwrap()
            );
        }
        publisher.allocate().unwrap();
        advance(&mut publisher, &mut cache, &mut latch);
        assert!(publisher.awaiting_publication());
        assert_eq!(memory.publication_bank().requests().len(), 1);
        publisher.publish_allocated().unwrap();
        let mut fault = Fault {
            view: cache.quota_view(),
            local: memory.notifications().clone(),
            attempts: vec![],
        };
        assert!(
            publisher
                .advance(&mut fault, &mut Access::new(0, 8, &mut latch))
                .is_err()
        );
        assert_eq!(fault.attempts, [(0, 0), (1, 0), (2, 0), (3, packed)]);
        drop(fault);
        assert_eq!(publisher.progress().programmed_words, 3);
        assert_eq!(publisher.progress().current_group, Some(3));
        assert_eq!(quota(&mut cache, 2), 0x4012_0012);
        assert_eq!(quota(&mut cache, 3), 0x4012_0040);
        let publications = memory.publication_bank().requests();
        assert_eq!(publications.len(), 2);
        assert_eq!(publications[1].value, packed);
        // The pending source store retains its exact prepared attributes/word.
        cache
            .quota_view()
            .write_quota(3, 0x4000_007f, &mut Access::new(0, 9, &mut latch))
            .unwrap();
        advance(&mut publisher, &mut cache, &mut latch);
        assert_eq!(quota(&mut cache, 3), 0x4012_0013);
        assert_eq!(publisher.progress().programmed_words, 4);
        assert_eq!(publisher.progress().completed_passes, 2);
        assert_eq!(memory.publication_bank().requests(), publications);
        assert_eq!(publisher.policy().dirty_masks().hardware, 0);
        assert_eq!(publisher.policy().dirty_masks().responses, 0);
        advance(&mut publisher, &mut cache, &mut latch);
        assert_eq!(memory.publication_bank().requests(), publications);
        assert!(publications.iter().all(|request| request.entry == 208)); // no command ACK213
        let consumed = memory
            .publication_bank()
            .consume_entry(208, &mut Access::new(0, 10, &mut latch))
            .unwrap();
        assert_eq!(consumed.value, packed);
        assert_eq!(consumed.metadata & 2, 2); // raw NEW_DATA, not transformed native bit54
    }
    #[test]
    fn budget_change_exposes_real_defaults_before_allocation_publication() {
        let (memory, mut cache) = components();
        let mut publisher = publisher(&memory, &mut cache, 1, 1);
        let mut latch = InterruptLatch::new();
        advance(&mut publisher, &mut cache, &mut latch);
        publisher.set_request(0, 20).unwrap();
        publisher.allocate().unwrap();
        publisher.publish_allocated().unwrap();
        advance(&mut publisher, &mut cache, &mut latch);
        assert_eq!(quota(&mut cache, 0) & 0x1ff, 20);
        publisher
            .set_budget_payload((0xfeed_u64 << 32) | (32 * 131072 + 123))
            .unwrap();
        advance(&mut publisher, &mut cache, &mut latch);
        assert_eq!(quota(&mut cache, 0) & 0x1ff, 32);
        assert_eq!(
            memory.publication_bank().requests().last().unwrap().value,
            0
        );
        assert_eq!(publisher.policy().group(0).unwrap().assigned, 20);
        assert!(publisher.awaiting_publication());
        assert!(publisher.set_request(0, 33).is_err());
        publisher.publish_allocated().unwrap();
        advance(&mut publisher, &mut cache, &mut latch);
        assert_eq!(quota(&mut cache, 0) & 0x1ff, 20);
        assert_eq!(
            memory.publication_bank().requests().last().unwrap().value,
            20
        );
        assert_eq!(publisher.progress().completed_passes, 4);
    }
    #[test]
    fn all_ones_source_target_remains_a_store_sentinel_across_default_passes() {
        let (memory, mut cache) = components();
        let mut latch = InterruptLatch::new();
        cache
            .quota_view()
            .write_quota(0, 1, &mut Access::new(0, 1, &mut latch))
            .unwrap();
        let binding = memory.bind_quota_publisher(&mut cache).unwrap();
        // Any nonzero scale byte scales source seeds; only exactly1 scales
        // hardware writes. This authored W32 boundary produces target MAX.
        let mut publisher = Publisher::new(
            binding,
            &mut cache.quota_view(),
            &rows(1, 0),
            Inputs {
                hardware_scale: 2,
                hardware_multiplier: u32::MAX,
                ..inputs()
            },
            config(),
        )
        .unwrap();
        assert_eq!(
            publisher.policy().group(0).unwrap().hardware_target,
            u32::MAX
        );
        publisher.publish_pending().unwrap();
        advance(&mut publisher, &mut cache, &mut latch);
        assert_eq!(quota(&mut cache, 0), 0x1ff);
        assert_eq!(publisher.progress().programmed_words, 1);
        publisher.set_budget_payload(64 << 17).unwrap();
        advance(&mut publisher, &mut cache, &mut latch);
        assert_eq!(quota(&mut cache, 0), 0x1ff);
        assert_eq!(publisher.progress().programmed_words, 2);
        assert_eq!(publisher.progress().completed_passes, 2);
        assert!(publisher.awaiting_publication());
        assert_eq!(memory.publication_bank().requests().len(), 2);
    }
    #[test]
    fn bindings_modes_and_counts_refuse_before_any_publication_and_do_not_reopen() {
        for configuration in [
            Configuration {
                suppression: None,
                ..config()
            },
            Configuration {
                suppression: Some(1),
                ..config()
            },
            Configuration {
                response_words: 0,
                ..config()
            },
            Configuration {
                response_words: 9,
                ..config()
            },
            Configuration {
                response_words: 6,
                ..config()
            },
            Configuration {
                ack_words: 2,
                ..config()
            },
            Configuration {
                response_range: 99,
                ..config()
            },
        ] {
            let (memory, mut cache) = components();
            let binding = memory.bind_quota_publisher(&mut cache).unwrap();
            assert!(
                Publisher::new(
                    binding,
                    &mut cache.quota_view(),
                    &rows(1, 0),
                    inputs(),
                    configuration
                )
                .is_err()
            );
            assert!(memory.bind_quota_publisher(&mut cache).is_err());
            assert!(memory.publication_bank().requests().is_empty());
            assert_eq!(cache.progress().quota_writes, 0);
        }
        let (memory, mut cache) = components();
        let (foreign_memory, mut foreign_cache) = components();
        assert!(foreign_memory.bind_quota_publisher(&mut cache).is_err());
        let mut publisher = publisher(&memory, &mut cache, 1, 0);
        assert!(
            publisher
                .advance(
                    &mut foreign_cache.quota_view(),
                    &mut Access::new(0, 0, &mut InterruptLatch::new())
                )
                .is_err()
        );
        assert!(memory.publication_bank().requests().is_empty());
        assert_eq!(cache.progress().quota_writes, 0);
        assert_eq!(publisher.progress().current_group, Some(0));
    }
    #[test]
    fn actual_ptd_and_cache_lifecycle_pauses_retain_effects_without_replay() {
        let (memory, mut cache) = components();
        let mut publisher = publisher(&memory, &mut cache, 1, 0);
        let mut latch = InterruptLatch::new();
        let mut bank = memory.publication_bank().clone();
        let paused = LifecycleState {
            quiesced: true,
            ..LIVE
        };
        bank.set_lifecycle(paused, &mut Access::new(0, 1, &mut latch));
        assert!(
            publisher
                .advance(&mut cache.quota_view(), &mut Access::new(0, 1, &mut latch))
                .is_err()
        );
        assert!(bank.requests().is_empty());
        bank.set_lifecycle(LIVE, &mut Access::new(0, 2, &mut latch));
        advance(&mut publisher, &mut cache, &mut latch);
        publisher.set_request(0, 12).unwrap();
        publisher.allocate().unwrap();
        publisher.publish_allocated().unwrap();
        cache.set_lifecycle(paused, &mut Access::new(0, 3, &mut latch));
        assert!(
            publisher
                .advance(&mut cache.quota_view(), &mut Access::new(0, 3, &mut latch))
                .is_err()
        );
        assert_eq!(bank.requests().len(), 1);
        cache.set_lifecycle(LIVE, &mut Access::new(0, 4, &mut latch));
        advance(&mut publisher, &mut cache, &mut latch);
        assert_eq!(quota(&mut cache, 0), 0x4012_000c);
        assert_eq!(bank.requests().len(), 2);
        assert_eq!(publisher.progress().programmed_words, 1);
    }
    #[test]
    #[cfg(feature = "std")]
    #[ignore = "requires original T8112 PMP and J473 DT via STELA_TEST_PMP_T8112 and STELA_TEST_MCC_J473_DT"]
    fn original_table_and_configuration_publish_through_actual_component_owners() {
        use crate::machine::adt::Node;
        let pmp = std::fs::read(std::env::var("STELA_TEST_PMP_T8112").unwrap()).unwrap();
        let dt = std::fs::read(std::env::var("STELA_TEST_MCC_J473_DT").unwrap()).unwrap();
        assert_eq!(
            crate::sha256(&pmp),
            "b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c"
        );
        assert_eq!(
            crate::sha256(&dt),
            "a99fa2260f292236fbad210fcee380fc69f101e591125bce347819e84e68034c"
        );
        for (start, end, hash) in [
            (
                0x4cbc,
                0x4ee8,
                "9d7f54726ce6b42b4f802022a6f3fb0902a2a53cb1f57bdfb028513d67d99ad7",
            ),
            (
                0x33d88,
                0x33fd8,
                "cddbc5a40505da2f2b933b13026357ea6cb0da599188f5833571d19af871cf3d",
            ),
            (
                0x3486c,
                0x34940,
                "1c2780da3e5a1fdc46fb9bbbae82b5cd3721e8461bb5988a30a536dffcaac18f",
            ),
        ] {
            assert_eq!(crate::sha256(&pmp[start..end]), hash);
        }
        let root = Node::root(&dt).unwrap();
        let raw = root
            .child("arm-io")
            .unwrap()
            .child("pmp")
            .unwrap()
            .child("iop-pmp-nub")
            .unwrap()
            .property("mcache-stream")
            .unwrap();
        assert_eq!(
            crate::sha256(raw),
            "1daa6222994ef3c8b22c87d2f4a3c3b2f224ec486093c42f8953a1544f1b8cab"
        );
        let word = |offset| u32::from_le_bytes(pmp[offset..offset + 4].try_into().unwrap());
        let (memory, mut cache) = components();
        let binding = memory.bind_quota_publisher(&mut cache).unwrap();
        let mut publisher = Publisher::new(
            binding,
            &mut cache.quota_view(),
            raw,
            Inputs {
                budget: word(0x46f88),
                reference: word(0x46f88),
                hardware_scale: pmp[0x46f90],
                hardware_multiplier: word(0x46f94),
                feature_word: word(0x352b0),
                ..inputs()
            },
            config(),
        )
        .unwrap();
        // Original source/table operands, authored live software seeds. This
        // does not execute firmware or claim original reset/cache capacity.
        assert_eq!(publisher.policy().rows().len(), 22);
        assert_eq!(publisher.policy().active_groups().count_ones(), 16);
        let mut latch = InterruptLatch::new();
        publisher.publish_pending().unwrap();
        advance(&mut publisher, &mut cache, &mut latch);
        assert_eq!(publisher.progress().programmed_words, 0);
        assert_eq!(publisher.progress().response_publications, 5);
        for group in 0..32 {
            publisher.set_request(group, 0x2008).unwrap();
        }
        publisher.allocate().unwrap();
        publisher.publish_allocated().unwrap();
        advance(&mut publisher, &mut cache, &mut latch);
        assert_eq!(publisher.progress().programmed_words, 3);
        assert_eq!(publisher.progress().response_publications, 10);
        let mut expected = [0u16; 32];
        for group in [10, 4, 18, 2, 3, 11, 17, 13, 5, 7, 14] {
            expected[group] = 8;
            assert_eq!(quota(&mut cache, group as u8), 0x4012_0040);
        }
        for group in [1, 8] {
            expected[group] = 64;
        }
        for group in [16, 15, 19] {
            assert_eq!(quota(&mut cache, group), 0x4012_0000);
        }
        let publications = memory.publication_bank().requests();
        for (block, request) in publications[5..].iter().enumerate() {
            assert_eq!(request.entry, 208 + block as u32);
            let packed = (0..4).fold(0, |value, lane| {
                value | (u64::from(expected[block * 4 + lane]) << (lane * 16))
            });
            assert_eq!(request.value, packed);
        }
        assert!(publications.iter().all(|request| request.entry < 213));
        assert_eq!(publisher.policy().dirty_masks().hardware, 0);
        assert_eq!(publisher.policy().dirty_masks().responses, 0);
    }
}
