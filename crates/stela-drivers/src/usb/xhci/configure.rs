//! Configuration of a device's endpoints: SET_CONFIGURATION and Configure
//! Endpoint (xHCI 4.6.6), validated before any context is published.
use super::*;

impl Controller {
    /// Cached device state, updated only by acknowledged standard requests.
    pub fn current_configuration(&mut self, slot: u8) -> Result<Option<u8>, BlockError> {
        self.legacy_slot(slot)?;
        self.current_configuration_owned(slot)
    }

    pub(super) fn current_configuration_owned(
        &mut self,
        slot: u8,
    ) -> Result<Option<u8>, BlockError> {
        self.live_slot(slot)?;
        self.ready()?;
        Ok(self.slot(slot)?.current_configuration)
    }

    /// Idempotent class-binding request. Repeating SET_CONFIGURATION, even with
    /// the same value, resets alternate settings and endpoint state (USB 9.4.7).
    pub fn set_configuration(&mut self, slot: u8, value: u8) -> Result<(), BlockError> {
        self.legacy_slot(slot)?;
        self.set_configuration_owned(slot, value)
    }

    pub(super) fn set_configuration_owned(
        &mut self,
        slot: u8,
        value: u8,
    ) -> Result<(), BlockError> {
        if self.current_configuration_owned(slot)? == Some(value) {
            return Ok(());
        }
        self.control_owned(
            slot,
            setup(0, SET_CONFIGURATION, u16::from(value), 0, 0),
            &[],
        )?;
        Ok(())
    }

    /// Adds `endpoints` to `slot` (Configure Endpoint, 4.6.6), with the hub
    /// fields when `hub` is `Some((ports, think_time, multi_tt))`.
    pub fn configure(
        &mut self,
        slot: u8,
        endpoints: &[Endpoint],
        hub: Option<(u8, u8, bool)>,
        dma: &mut dyn DmaAllocator,
    ) -> Result<(), BlockError> {
        self.legacy_slot(slot)?;
        self.configure_owned(slot, endpoints, hub, dma)
    }

    pub(super) fn configure_owned(
        &mut self,
        slot: u8,
        endpoints: &[Endpoint],
        hub: Option<(u8, u8, bool)>,
        dma: &mut dyn DmaAllocator,
    ) -> Result<(), BlockError> {
        self.configure_inner(slot, endpoints, hub, &[], 0, dma)
            .map(|_| ())
    }

    /// Check that every requested endpoint is valid and currently unclaimed
    /// before a class changes its device's alternate setting. This observes the
    /// current controller epoch; it does not reserve DCIs. The class must
    /// serialize the complete change and configure rechecks these same rules
    /// before recording or publishing any endpoint ownership.
    pub fn preflight_endpoints(
        &mut self,
        slot: u8,
        endpoints: &[Endpoint],
    ) -> Result<(), BlockError> {
        self.legacy_slot(slot)?;
        self.preflight_endpoints_owned(slot, endpoints)
    }

    pub(super) fn preflight_endpoints_owned(
        &mut self,
        slot: u8,
        endpoints: &[Endpoint],
    ) -> Result<(), BlockError> {
        self.endpoint_contexts(slot, endpoints).map(|_| ())
    }

    fn endpoint_contexts(
        &mut self,
        slot: u8,
        endpoints: &[Endpoint],
    ) -> Result<Vec<endpoint::Context>, BlockError> {
        self.live_slot(slot)?;
        self.ready()?;
        if !self
            .slot(slot)?
            .current_configuration
            .is_some_and(|value| value != 0)
        {
            return Err(BlockError::Unsupported(
                "USB device configuration is not acknowledged",
            ));
        }
        // Validate every endpoint and allocate every ring before publishing any
        // change. Existing rings may still be DMA-owned, even after a failure.
        let mut selected = 0u32;
        let speed = self.slot(slot)?.speed;
        let mut contexts = Vec::new();
        for endpoint in endpoints {
            let dci = endpoint.dci();
            if endpoint.address & 0x70 != 0
                || dci < 2
                || endpoint.max_packet & 0x7ff == 0
                || !matches!(endpoint.kind(), 1..=3)
                || selected & (1 << dci) != 0
            {
                return Err(BlockError::Unsupported(
                    "invalid or duplicate xHCI endpoint",
                ));
            }
            if let Some(transfer) = &self.slot(slot)?.endpoints[usize::from(dci)] {
                return Err(BlockError::Unsupported(if transfer.poisoned {
                    "xHCI endpoint cancellation failed"
                } else {
                    "xHCI endpoint replacement requires teardown"
                }));
            }
            let context = endpoint::Context::new(endpoint, speed)?;
            let context = if endpoint.kind() == 1 {
                self.iso_caps.context(context)
            } else {
                context
            };
            contexts.push(self.quirks.endpoint(context)?);
            selected |= 1 << dci;
        }
        if endpoints.iter().any(|ep| ep.kind() == 1) {
            self.iso_caps.admit()?;
            let attachment = self.slot(slot)?.attachment;
            if attachment.tier > MAX_TIERS
                || attachment.route >> (4 * MAX_TIERS) != 0
                || (attachment.tier == 0
                    && (attachment.route != 0
                        || attachment.parent.is_some()
                        || attachment.translator.is_some()))
                || (attachment.tier != 0 && (attachment.route == 0 || attachment.parent.is_none()))
            {
                return Err(BlockError::Unsupported(
                    "invalid isochronous attachment route",
                ));
            }
        }
        Ok(contexts)
    }

    pub(super) fn configure_inner(
        &mut self,
        slot: u8,
        endpoints: &[Endpoint],
        hub: Option<(u8, u8, bool)>,
        stream_endpoints: &[u8],
        requested_streams: u16,
        dma: &mut dyn DmaAllocator,
    ) -> Result<u16, BlockError> {
        let contexts = self.endpoint_contexts(slot, endpoints)?;
        let speed = self.slot(slot)?.speed;
        let layout = if stream_endpoints.is_empty() {
            None
        } else {
            self.stream_policy.admit()?;
            Some(streams::Layout::new(
                self.max_primary_streams,
                speed,
                endpoints,
                stream_endpoints,
                requested_streams,
            )?)
        };
        self.retry_resources.preflight_endpoints(
            slot,
            endpoints,
            stream_endpoints,
            layout,
            self.stream_policy == streams::Policy::Cadence,
            &self.slots[usize::from(slot)]
                .as_ref()
                .unwrap()
                .retired_rings,
        )?;
        let mut rings = Vec::new();
        rings
            .try_reserve_exact(endpoints.len())
            .map_err(|_| BlockError::NoDmaMemory)?;
        for endpoint in endpoints {
            let allocation = (|| {
                if let Some(pair) = self.retry_resources.endpoint(slot, endpoint.dci()) {
                    return Ok(pair);
                }
                let streamed = stream_endpoints.contains(&endpoint.address);
                let stream = if streamed {
                    Some(streams::Streams::new(
                        dma,
                        layout.unwrap(),
                        self.dma_profile,
                        self.stream_policy == streams::Policy::Cadence,
                    )?)
                } else {
                    None
                };
                let retained = if streamed {
                    None
                } else {
                    self.slot(slot)?.retired_rings[usize::from(endpoint.dci())].take()
                };
                let ring = match retained {
                    Some(ring) => ring,
                    None => Ring::with_profile(dma, self.dma_profile)?,
                };
                Ok((ring, stream))
            })();
            match allocation {
                Ok(pair) => rings.push(pair),
                Err(error) => {
                    // No input context or doorbell has been published. Keep
                    // both reclaimed and newly allocated ordinary rings if a
                    // subsequent allocation fails; a retry must not consume
                    // another slice of the boot-lived DMA reservation.
                    for (prior, (ring, stream)) in endpoints.iter().zip(rings) {
                        if stream.is_none() && !self.retry_resources.sealed(slot) {
                            self.slot(slot)?.retired_rings[usize::from(prior.dci())] = Some(ring);
                        } else {
                            self.retry_resources
                                .return_endpoint(slot, prior, ring, stream, speed);
                        }
                    }
                    return Err(error);
                }
            };
        }
        if let Err(error) = self.clear_input(slot) {
            for (endpoint, (ring, stream)) in endpoints.iter().zip(rings) {
                if stream.is_none() && !self.retry_resources.sealed(slot) {
                    self.slot(slot)?.retired_rings[usize::from(endpoint.dci())] = Some(ring);
                } else {
                    self.retry_resources
                        .return_endpoint(slot, endpoint, ring, stream, speed);
                }
            }
            return Err(error);
        }
        let context = self.context();
        let mut add = 1u32;
        let mut last = 1u8;
        for ((endpoint, (ring, stream)), recipe) in endpoints.iter().zip(rings).zip(contexts) {
            let dci = endpoint.dci();
            let state = self.slot(slot)?;
            let at = (usize::from(dci) + 1) * context;
            let (stream_info, dequeue) = stream
                .as_ref()
                .map_or((0, ring.dequeue_pointer()), |streams| streams.context());
            state.input.write(at, recipe.info | stream_info);
            state.input.write(at + 4, recipe.info2);
            state.input.write(at + 8, dequeue);
            state.input.write(at + 16, recipe.tx_info);
            state.endpoints[usize::from(dci)] = Some(Transfer {
                ring,
                streams: stream,
                iso: if endpoint.kind() == 1 {
                    Some(iso::Queue::new(iso::Recipe::new(endpoint, speed)?))
                } else {
                    None
                },
                is_in: endpoint.is_in(),
                poisoned: false,
                enabled: false,
                in_flight: 0,
            });
            add |= 1 << dci;
            last = last.max(dci);
        }
        let input_address = {
            let state = self.slot(slot)?;
            let mut words = state.context;
            let entries = (words[0] >> 27).max(u32::from(last));
            words[0] = words[0] & !(0x1f << 27) | entries << 27;
            if let Some((ports, think_time, multi)) = hub {
                words[0] |= 1 << 26 | u32::from(multi) << 25;
                words[1] = words[1] & 0x00ff_ffff | u32::from(ports) << 24;
                words[2] = words[2] & !(3 << 16) | u32::from(think_time & 3) << 16;
            }
            state.context = words;
            state.input.write(4, add);
            for (n, word) in words.iter().enumerate() {
                state.input.write(context + 4 * n, *word);
            }
            state.input.physical()
        };
        let result = self.command(
            input_address,
            0,
            CONFIGURE_ENDPOINT << 10 | u32::from(slot) << 24,
        );
        // Retain rings on any error: a lost command completion may still leave
        // them reachable by the controller. Never expose an unacknowledged ring.
        for endpoint in endpoints {
            let transfer = self.slot(slot)?.endpoints[usize::from(endpoint.dci())]
                .as_mut()
                .unwrap();
            transfer.enabled = result.is_ok();
            transfer.poisoned = result.is_err();
        }
        result?;
        Ok(layout.map_or(0, |layout| layout.usable))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::dma::RegionAllocator;
    use crate::usb::xhci::model::*;

    #[test]
    fn unacknowledged_configuration_never_activates_endpoints_or_reuses_poisoned_ep0() {
        for scenario in 0..3 {
            let mut backing = vec![0u64; 128 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: exclusive backing outlives controller and hardware model.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut controller, model) = unconfigured_cancellation_controller_with_configurations(
                &mut dma,
                &[
                    vec![9, 2, 9, 0, 0, 7, 0, 0x80, 50],
                    vec![9, 2, 9, 0, 0, 9, 0, 0x80, 50],
                    vec![9, 2, 9, 0, 0, 42, 0, 0x80, 50],
                ],
            );
            if scenario == 0 {
                model.borrow_mut().halt_transfer = Some(1);
            } else {
                model.borrow_mut().silence_transfer = Some(1);
                if scenario == 2 {
                    model.borrow_mut().fail = Some((STOP_ENDPOINT, 11));
                }
            }
            assert!(controller.set_configuration(1, 42).is_err());
            assert_eq!(controller.current_configuration(1), Ok(None));
            let endpoint = fixture_endpoint(3);
            assert!(
                controller
                    .configure(1, &[endpoint], None, &mut dma)
                    .is_err()
            );
            assert!(controller.slots[1].as_ref().unwrap().endpoints[3].is_none());
            let request_count = model.borrow().setup.len();
            model.borrow_mut().halt_transfer = None;
            model.borrow_mut().silence_transfer = None;
            if scenario == 2 {
                let ring = controller.slots[1].as_ref().unwrap().endpoints[1]
                    .as_ref()
                    .unwrap()
                    .ring
                    .buffer
                    .bytes()
                    .to_vec();
                assert!(controller.set_configuration(1, 42).is_err());
                assert_eq!(model.borrow().setup.len(), request_count);
                assert_eq!(
                    controller.slots[1].as_ref().unwrap().endpoints[1]
                        .as_ref()
                        .unwrap()
                        .ring
                        .buffer
                        .bytes(),
                    ring
                );
            } else {
                controller.set_configuration(1, 42).unwrap();
                assert_eq!(controller.current_configuration(1), Ok(Some(42)));
            }
        }
    }

    #[test]
    fn failed_endpoint_configuration_retains_rings_without_exposing_or_replacing_them() {
        for missing_completion in [false, true] {
            let mut backing = vec![0u64; 128 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: backing is live/exclusive through every retained DMA ring.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut controller, model) = unconfigured_cancellation_controller_with_configurations(
                &mut dma,
                &[
                    vec![9, 2, 9, 0, 0, 7, 0, 0x80, 50],
                    vec![9, 2, 9, 0, 0, 9, 0, 0x80, 50],
                    vec![9, 2, 9, 0, 0, 42, 0, 0x80, 50],
                ],
            );
            controller.set_configuration(1, 42).unwrap();
            if missing_completion {
                model.borrow_mut().silence = Some(CONFIGURE_ENDPOINT);
            } else {
                model.borrow_mut().fail = Some((CONFIGURE_ENDPOINT, 7));
            }
            let endpoint = fixture_endpoint(3);
            assert!(
                controller
                    .configure(1, &[endpoint], None, &mut dma)
                    .is_err()
            );
            let transfer = controller.slots[1].as_ref().unwrap().endpoints[3]
                .as_ref()
                .unwrap();
            assert!(!transfer.enabled);
            assert!(transfer.poisoned);
            let address = transfer.ring.buffer.physical();
            let bytes = transfer.ring.buffer.bytes().to_vec();
            let commands = model.borrow().seen.len();
            assert!(controller.submit(1, 3, address, 16).is_err());
            assert!(
                controller
                    .configure(1, &[endpoint], None, &mut dma)
                    .is_err()
            );
            let transfer = controller.slots[1].as_ref().unwrap().endpoints[3]
                .as_ref()
                .unwrap();
            assert_eq!(transfer.ring.buffer.physical(), address);
            assert_eq!(transfer.ring.buffer.bytes(), bytes);
            assert_eq!(model.borrow().seen.len(), commands);
        }
    }

    #[test]
    fn acknowledged_zero_configuration_returns_to_address_state_without_endpoint_activation() {
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: backing remains live and exclusive through controller/model use.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = unconfigured_cancellation_controller_with_configurations(
            &mut dma,
            &[
                vec![9, 2, 9, 0, 0, 7, 0, 0x80, 50],
                vec![9, 2, 9, 0, 0, 9, 0, 0x80, 50],
                vec![9, 2, 9, 0, 0, 42, 0, 0x80, 50],
            ],
        );
        controller.set_configuration(1, 42).unwrap();
        for malformed in [
            setup(0, SET_CONFIGURATION, 0x100, 0, 0),
            setup(0, SET_CONFIGURATION, 0, 1, 0),
            setup(0, SET_CONFIGURATION, 0, 0, 1),
        ] {
            assert!(controller.control(1, malformed, &[]).is_err());
        }
        assert_eq!(controller.current_configuration(1), Ok(Some(42)));
        assert_eq!(model.borrow().setup.len(), 1);
        controller.set_configuration(1, 0).unwrap();
        assert_eq!(controller.current_configuration(1), Ok(Some(0)));
        assert_eq!(model.borrow().configuration_value, 0);
        assert!(
            controller
                .configure(1, &[fixture_endpoint(3)], None, &mut dma)
                .is_err()
        );
        assert!(controller.slots[1].as_ref().unwrap().endpoints[3].is_none());
        assert!(model.borrow().seen.is_empty());
    }

    #[test]
    fn refused_superspeed_plan_preserves_inventory_without_configuration_or_dma() {
        // SuperSpeed bulk endpoints of 512 bytes, which no fixup changes.
        for streams in [false, true] {
            let mut configuration = vec![
                9, 2, 0, 0, 1, 7, 0, 0x80, 50, 9, 4, 0, 0, 2, 8, 6, 0x50, 0, 7, 5, 0x81, 2, 0, 2, 0,
            ];
            if streams {
                configuration.extend_from_slice(&[6, SS_ENDPOINT_COMPANION, 0, 17, 0, 0]);
            }
            configuration.extend_from_slice(&[7, 5, 2, 2, 0, 2, 0]);
            if streams {
                configuration.extend_from_slice(&[6, SS_ENDPOINT_COMPANION, 0, 0, 0, 0]);
            }
            let total = configuration.len() as u16;
            configuration[2..4].copy_from_slice(&total.to_le_bytes());
            let sanitized = configuration::sanitize(&configuration, SUPER_SPEED).unwrap();
            let mut device = configuration::tests::device(vec![configuration.clone()]);
            device.speed = SUPER_SPEED;
            configuration::select(&mut device).unwrap();
            assert_eq!(device.configuration, sanitized);
            assert_eq!(device.configurations, [configuration]);
            let mut backing = vec![0u64; 128 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: backing stays exclusive/live throughout model and controller access.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (controller, model) = unconfigured_cancellation_controller_with_configurations(
                &mut dma,
                &[
                    vec![9, 2, 9, 0, 0, 7, 0, 0x80, 50],
                    vec![9, 2, 9, 0, 0, 9, 0, 0x80, 50],
                    vec![9, 2, 9, 0, 0, 42, 0, 0x80, 50],
                ],
            );
            let input = controller.slots[1].as_ref().unwrap().input.bytes().to_vec();
            let shared = Rc::new(RefCell::new(controller));
            let mut found = Found::default();
            bind(&shared, device, &mut dma, &mut found);
            assert!(found.failures.is_empty());
            assert_eq!(found.unused.len(), 1);
            assert!(model.borrow().setup.is_empty() && model.borrow().seen.is_empty());
            let controller = shared.borrow();
            let slot = controller.slots[1].as_ref().unwrap();
            assert_eq!(slot.input.bytes(), input);
            assert!(slot.endpoints[2..].iter().all(Option::is_none));
            assert_eq!(slot.current_configuration, Some(0));
        }
    }

    #[test]
    fn superspeed_companions_reach_real_32_and_64_byte_controller_contexts() {
        for speed in [SUPER_SPEED, SUPER_SPEED_PLUS] {
            for context in [32, 64] {
                let mut backing = vec![0u64; 128 * 1024];
                let start = backing.as_mut_ptr() as u64;
                // SAFETY: backing outlives every model and controller DMA object.
                let mut dma =
                    unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
                let (mut controller, model) =
                    unconfigured_cancellation_controller_with_configurations(
                        &mut dma,
                        &[
                            vec![9, 2, 9, 0, 0, 7, 0, 0x80, 50],
                            vec![9, 2, 9, 0, 0, 9, 0, 0x80, 50],
                            vec![9, 2, 9, 0, 0, 42, 0, 0x80, 50],
                        ],
                    );
                controller.set_configuration(1, 7).unwrap();
                controller.context_bytes = context;
                let slot = controller.slots[1].as_mut().unwrap();
                slot.speed = speed;
                slot.context[0] = slot.context[0] & !(15 << 20) | u32::from(speed) << 20;
                slot.input = dma.allocate(33 * context, 64).unwrap();
                slot._output = dma.allocate(32 * context, 64).unwrap();
                model.borrow_mut().output = slot._output.physical();
                model.borrow_mut().context_bytes = context;
                model.borrow_mut().set_state(1, 1);
                controller.dcbaa.write(8, slot._output.physical());
                let endpoints = [
                    Endpoint {
                        address: 0x81,
                        attributes: 2,
                        max_packet: 1024,
                        interval: 0,
                        companion: Some(SuperSpeedCompanion {
                            max_burst: 7,
                            attributes: 0,
                            bytes_per_interval: 0,
                        }),
                    },
                    Endpoint {
                        address: 0x02,
                        attributes: 3,
                        max_packet: 64,
                        interval: 4,
                        companion: Some(SuperSpeedCompanion {
                            max_burst: 3,
                            attributes: 0,
                            bytes_per_interval: 37,
                        }),
                    },
                ];
                controller.configure(1, &endpoints, None, &mut dma).unwrap();
                let slot = controller.slots[1].as_ref().unwrap();
                for (ep, expected) in endpoints.iter().zip([
                    [0, 1024 << 16 | 7 << 8 | 6 << 3 | 6, 3072],
                    [3 << 16, 64 << 16 | 3 << 8 | 3 << 3 | 6, 37 << 16 | 37],
                ]) {
                    let dci = usize::from(ep.dci());
                    let at = (dci + 1) * context;
                    assert_eq!(slot.input.read::<u32>(at), expected[0]);
                    assert_eq!(slot.input.read::<u32>(at + 4), expected[1]);
                    assert_eq!(slot.input.read::<u32>(at + 16), expected[2]);
                    let transfer = slot.endpoints[dci].as_ref().unwrap();
                    assert!(transfer.enabled);
                    assert_eq!(
                        slot.input.read::<u64>(at + 8) & !15,
                        model.borrow().rings[dci]
                    );
                    assert_eq!(model.borrow().state(dci), ENDPOINT_RUNNING);
                    // All unused/reserved words stay zero at either CSZ.
                    assert!(
                        slot.input.bytes()[at + 20..at + context]
                            .iter()
                            .all(|b| *b == 0)
                    );
                }
                assert_eq!(model.borrow().seen, [CONFIGURE_ENDPOINT]);
                assert_eq!(model.borrow().configuration_seen_before_endpoints, [7]);
                for ep in &endpoints {
                    controller.cancel(1, ep.dci()).unwrap();
                }
            }
        }
    }

    #[test]
    fn invalid_superspeed_companion_refuses_before_any_dma_publication() {
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: backing remains exclusive and live throughout model DMA use.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = unconfigured_cancellation_controller_with_configurations(
            &mut dma,
            &[
                vec![9, 2, 9, 0, 0, 7, 0, 0x80, 50],
                vec![9, 2, 9, 0, 0, 9, 0, 0x80, 50],
                vec![9, 2, 9, 0, 0, 42, 0, 0x80, 50],
            ],
        );
        controller.set_configuration(1, 7).unwrap();
        controller.slots[1].as_mut().unwrap().speed = SUPER_SPEED;
        let input = controller.slots[1].as_ref().unwrap().input.bytes().to_vec();
        let commands = controller.commands.buffer.bytes().to_vec();
        let good = Endpoint {
            address: 0x81,
            attributes: 2,
            max_packet: 1024,
            interval: 0,
            companion: Some(SuperSpeedCompanion {
                max_burst: 7,
                attributes: 0,
                bytes_per_interval: 0,
            }),
        };
        for companion in [
            None,
            Some(SuperSpeedCompanion {
                max_burst: 16,
                attributes: 0,
                bytes_per_interval: 0,
            }),
            Some(SuperSpeedCompanion {
                max_burst: 7,
                attributes: 17,
                bytes_per_interval: 0,
            }),
            Some(SuperSpeedCompanion {
                max_burst: 7,
                attributes: 0,
                bytes_per_interval: 1,
            }),
        ] {
            let mut bad = good;
            bad.address = 2;
            bad.companion = companion;
            // A valid endpoint first must not publish its ring before its invalid peer.
            assert!(
                controller
                    .configure(1, &[good, bad], None, &mut dma)
                    .is_err()
            );
            let slot = controller.slots[1].as_ref().unwrap();
            assert_eq!(slot.input.bytes(), input);
            assert_eq!(controller.commands.buffer.bytes(), commands);
            assert!(slot.endpoints[3].is_none() && slot.endpoints[4].is_none());
            assert!(model.borrow().seen.is_empty());
        }
        // The acknowledged EP0 lifecycle stays usable after descriptor refusal.
        controller.set_configuration(1, 9).unwrap();
        assert_eq!(controller.current_configuration(1), Ok(Some(9)));
    }
}
