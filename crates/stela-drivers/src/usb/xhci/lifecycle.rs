// SPDX-License-Identifier: GPL-2.0-only
//! Explicitly polled topology ownership, adapting pinned Linux hub_irq,
//! port_event, hub_port_connect and usb_disconnect. No published ID is recycled.
use super::*;

#[cfg(test)]
mod downstream_tests;
#[cfg(test)]
mod generation_tests;
mod recovery;
mod suspend;

/// Private proof retained only after complete subtree transfer quiescence.
/// This never restores public access to the old hardware slot.
pub(super) struct Recovery {
    slot: u8,
    id: SlotId,
    port: Option<u8>,
}
impl Recovery {
    pub(super) fn id(&self) -> SlotId {
        self.id
    }
    pub(super) fn slot(&self) -> u8 {
        self.slot
    }
}

/// One poll's actual topology changes. Removed descriptors name permanently
/// invalidated old owners; they do not assert that failed hardware DMA stopped.
/// Added class owners come from fresh physical enumeration and normal binding.
#[derive(Default)]
pub struct Changes {
    pub added: Found,
    pub removed: Vec<Device>,
}

struct Hub {
    device: Device,
    attachment: Attachment,
    endpoint: Endpoint,
    ports: u8,
    ssp: Option<hub::descriptor::Ssp>,
    bitmap: DmaBuffer,
    pending: Option<u64>,
    retired: bool,
    recovery: Option<Recovery>,
}

/// Retains the controller even when no leaf class currently owns it. Call
/// `poll` from the native service loop, and deliver its changes to consumers.
/// Reconnection uses fresh, never-recycled hardware IDs: exhausted boot-lifetime
/// slot capacity is an explicit failure until generation-bound handles exist.
/// The explicit topology suspend/resume service does not enter platform sleep
/// or authorize a guest-directed controller reset.
pub struct Host {
    controller: Shared,
    devices: Vec<Device>,
    hubs: Vec<Hub>,
    roots: Vec<u32>,
    sleep: suspend::Sleep,
}
impl Host {
    /// Transfer this inventory's actual unbound Address-state device to the
    /// forwarding adapter. A failed constructor keeps the exclusive claim:
    /// neither dropping a handle nor a copied descriptor authorizes rebinding.
    pub(in crate::usb) fn take_forwarding(
        &mut self,
        id: SlotId,
    ) -> Result<(Shared, Device), BlockError> {
        let physical =
            self.devices
                .iter()
                .find(|device| device.id == id)
                .ok_or(BlockError::Unsupported(
                    "USB forwarding device is not in this host inventory",
                ))?;
        if physical.descriptor[4] == HUB_CLASS {
            return Err(BlockError::Unsupported(
                "USB hub forwarding requires topology ownership",
            ));
        }
        self.controller.borrow_mut().claim_forwarding(id)?;
        Ok((self.controller.clone(), physical.clone()))
    }

    pub(super) fn new(
        controller: Shared,
        devices: &[Device],
        dma: &mut dyn DmaAllocator,
        failures: &mut Vec<(String, BlockError)>,
    ) -> Self {
        let roots = {
            let mut c = controller.borrow_mut();
            (1..=c.max_ports)
                .map(|port| {
                    let at = c.port_offset(port);
                    c.registers.read32(at)
                })
                .collect()
        };
        let mut host = Self {
            controller,
            devices: devices.to_vec(),
            hubs: Vec::new(),
            roots,
            sleep: suspend::Sleep::default(),
        };
        host.register_hubs(devices, dma, failures);
        host
    }

    fn register_hubs(
        &mut self,
        devices: &[Device],
        dma: &mut dyn DmaAllocator,
        failures: &mut Vec<(String, BlockError)>,
    ) {
        for device in devices.iter().filter(|d| d.descriptor[4] == HUB_CLASS) {
            let result = (|| {
                let mut c = self.controller.borrow_mut();
                c.validate_id(device.id)?;
                let ports = c
                    .power
                    .hub_ports(device.slot)
                    .ok_or(BlockError::Unsupported(
                        "USB hub has no acknowledged power contract",
                    ))?;
                // Configure Endpoint committed MTT only after SET_INTERFACE1
                // ACK. Select that actual setting, whose endpoint may differ.
                const SLOT_MULTI_TT: u32 = 1 << 25;
                let alternate = if c.slot(device.slot)?.context[0] & SLOT_MULTI_TT != 0 {
                    MULTI_TT_ALTERNATE
                } else {
                    0
                };
                let endpoint = enumerate::hub_status_endpoint(&device.configuration, alternate)
                    .ok_or(BlockError::Unsupported("USB hub status endpoint absent"))?;
                if endpoint.kind() != 3
                    || !endpoint.is_in()
                    || usize::from(endpoint.max_packet & 0x7ff) < usize::from(ports + 1).div_ceil(8)
                {
                    return Err(BlockError::Unsupported(
                        "USB hub status bitmap exceeds actual endpoint",
                    ));
                }
                c.device(device.id)?.endpoint_ready(endpoint.dci())?;
                let attachment = c.slot(device.slot)?.attachment;
                let ssp = if matches!(device.speed, SUPER_SPEED | SUPER_SPEED_PLUS) {
                    c.hub_ssp_for(device.id)?
                } else {
                    None
                };
                let bitmap = c.dma_profile.allocate(dma, 64, 64)?;
                Ok(Hub {
                    device: device.clone(),
                    attachment,
                    endpoint,
                    ports,
                    ssp,
                    bitmap,
                    pending: None,
                    retired: false,
                    recovery: None,
                })
            })();
            match result {
                Ok(hub) => self.hubs.push(hub),
                Err(error) => failures.push((
                    format!("{} retain hub status owner", device.location),
                    error,
                )),
            }
        }
    }

    /// Poll actual root notifications/PORTSC and queued hub interrupt bitmaps.
    /// No completion or new identity is inferred from elapsed time. Topology
    /// mutation is serialized through this controller's native Rc owner.
    pub fn poll(
        &mut self,
        dma: &mut dyn DmaAllocator,
        firmware: &dyn crate::firmware::Provider,
    ) -> Changes {
        let mut changes = Changes::default();
        if !self.sleep.awake() {
            return changes;
        }
        self.reconcile(&mut changes);
        for port in 1..=self.roots.len() as u8 {
            if let Err(error) = self.root(port, dma, &mut changes) {
                changes
                    .added
                    .failures
                    .push((format!("USB root port {port} lifecycle"), error));
            }
        }
        for index in 0..self.hubs.len() {
            if self.hubs[index].recovery.is_some() {
                if let Err(error) = self.recover_hub(index, dma, &mut changes) {
                    changes.added.failures.push((
                        format!("{} hub recovery", self.hubs[index].device.location),
                        error,
                    ));
                }
                continue;
            }
            if self.hubs[index].retired {
                continue;
            }
            if let Err(error) = self.hub(index, dma, &mut changes) {
                let location = self.hubs[index].device.location.clone();
                let current = self
                    .controller
                    .borrow()
                    .known_id(self.hubs[index].device.id);
                if self.hubs[index].recovery.is_none() && current {
                    let _ = self.retire(self.hubs[index].device.id, &mut changes);
                }
                changes
                    .added
                    .failures
                    .push((format!("{location} hub lifecycle"), error));
            }
        }
        let added = changes.added.devices.clone();
        self.register_hubs(&added, dma, &mut changes.added.failures);
        for device in &added {
            bind_with_provider(
                &self.controller,
                device.clone(),
                dma,
                &mut changes.added,
                firmware,
            );
        }
        self.devices.extend(added);
        changes
    }

    /// A class-owned exclusive reset may replace a leaf between topology
    /// polls. Follow the controller's actual fresh descriptor inventory without
    /// attempting a second native bind of that already-owned replacement.
    fn reconcile(&mut self, changes: &mut Changes) {
        let current: Vec<_> = {
            let c = self.controller.borrow();
            c.slots
                .iter()
                .enumerate()
                .filter_map(|(id, state)| {
                    state
                        .as_ref()
                        .filter(|state| {
                            !state.retiring
                                && !state.suspended
                                && c.slot_ownership[id] == reset::Ownership::Enabled
                        })
                        .and_then(|state| state.inventory.clone())
                })
                .collect()
        };
        self.devices.retain(|old| {
            if current.iter().any(|device| device.id == old.id) {
                true
            } else {
                changes.removed.push(old.clone());
                false
            }
        });
        for device in current {
            if !self.devices.iter().any(|old| old.id == device.id) {
                self.devices.push(device);
            }
        }
    }

    fn root(
        &mut self,
        port: u8,
        dma: &mut dyn DmaAllocator,
        changes: &mut Changes,
    ) -> Result<(), BlockError> {
        let (status, owner, notification_error) = {
            let mut c = self.controller.borrow_mut();
            c.validate_current_graph(port)?;
            let owner = c.current_port_owner(None, port)?;
            c.ready()?;
            let notification_error = c
                .pending
                .iter()
                .find(|event| {
                    event.kind() == reset::PORT_STATUS_CHANGE
                        && event.parameter == u64::from(port) << 24
                        && event.code() != SUCCESS
                })
                .map(Event::code);
            c.pending.retain(|event| {
                !(event.kind() == reset::PORT_STATUS_CHANGE
                    && event.parameter == u64::from(port) << 24)
            });
            let at = c.port_offset(port);
            (c.registers.read32(at), owner, notification_error)
        };
        if let Some(status) = notification_error {
            if let Some(owner) = owner {
                self.retire(owner, changes)?;
            }
            return Err(BlockError::Device { status });
        }
        let previous = self.roots[usize::from(port - 1)];
        let authority = CCS | PED | PP | (1 << 3) | (PORT_SPEED_FIELD << PORT_SPEED_SHIFT);
        let old_link = previous >> PLS_SHIFT & PLS_FIELD;
        let new_link = status >> PLS_SHIFT & PLS_FIELD;
        let link_recovery = old_link != new_link
            && (matches!(old_link, 3 | LINK_INACTIVE | LINK_COMPLIANCE)
                || matches!(new_link, 3 | LINK_INACTIVE | LINK_COMPLIANCE));
        let changed = status & CSC != 0 || (previous ^ status) & authority != 0 || link_recovery;
        self.roots[usize::from(port - 1)] = status;
        if !changed {
            return Ok(());
        }
        if let Some(owner) = owner {
            self.retire(owner, changes)?;
        }
        if status & (PP | CCS) != PP | CCS || status & (1 << 3) != 0 {
            let mut c = self.controller.borrow_mut();
            c.write_port(port, status & PORT_CHANGES);
            return if status & (1 << 3) != 0 {
                Err(BlockError::Unsupported(
                    "USB root over-current requires recovery",
                ))
            } else {
                Ok(())
            };
        }
        if new_link == 3 {
            return Err(BlockError::Unsupported(
                "USB root U3 resume requires suspend owner",
            ));
        }
        let mut c = self.controller.borrow_mut();
        if previous & (1 << 3) != 0 {
            // Pinned port_event waits100ms after actual port over-current.
            c.clock.delay(100_000);
        }
        // A disabled USB2 port has not completed its speed handshake yet.
        // Its actual Supported Protocol permits reset; reserve_current still
        // requires the enabled port's actual speed before Address Device.
        if c.port_major[usize::from(port - 1)] != 2 || status & PED != 0 {
            c.root_current(
                port,
                ((status >> PORT_SPEED_SHIFT) & PORT_SPEED_FIELD) as u8,
            )?;
        }
        let location = format!("{} port {port}", c.location);
        let mut acknowledged_speed = None;
        let reset = |c: &mut Controller| {
            let Some(speed) = c.root_port(port)? else {
                return Ok(None);
            };
            let attachment = Attachment {
                root_port: port,
                route: 0,
                tier: 0,
                speed,
                translator: None,
                parent: None,
            };
            // USB3 training alone does not retire the old physical address or
            // current owner. A retained grant requires actual reset ACK.
            if c.power.port_owner(None, port).is_some() {
                c.reset_root_device(attachment)?;
            }
            acknowledged_speed = Some(speed);
            Ok(Some(attachment))
        };
        c.connect(
            location,
            None,
            reset,
            dma,
            &mut changes.added.devices,
            &mut changes.added.failures,
        );
        if let Some(speed) = acknowledged_speed {
            // Baseline only effects proved by our reset/training ACK. Preserve
            // prior connection/power authority so a late physical change is
            // observed on the next poll; late CSC is never consumed here.
            let controlled = PED | (PORT_SPEED_FIELD << PORT_SPEED_SHIFT) | PLS;
            self.roots[usize::from(port - 1)] =
                status & !controlled | PED | u32::from(speed) << PORT_SPEED_SHIFT;
        }
        Ok(())
    }

    fn hub(
        &mut self,
        index: usize,
        dma: &mut dyn DmaAllocator,
        changes: &mut Changes,
    ) -> Result<(), BlockError> {
        let bits = {
            let owner = &mut self.hubs[index];
            let mut c = self.controller.borrow_mut();
            c.validate_id(owner.device.id)?;
            let length = usize::from(owner.ports + 1).div_ceil(8);
            if let Some(ticket) = owner.pending {
                let Some(result) =
                    c.device(owner.device.id)?
                        .completed(owner.endpoint.dci(), ticket, length)
                else {
                    return Ok(());
                };
                let received = result?;
                owner.pending = None;
                let mut bits = 0u32;
                for (byte, value) in owner.bitmap.bytes()[..received].iter().enumerate() {
                    bits |= u32::from(*value) << (8 * byte);
                }
                let allowed = u32::MAX >> (31 - owner.ports);
                if bits & !allowed != 0 {
                    return Err(BlockError::Unsupported(
                        "USB hub status bitmap has nonexistent ports",
                    ));
                }
                bits
            } else {
                owner.bitmap.bytes_mut().fill(0);
                owner.pending = Some(c.device(owner.device.id)?.submit(
                    owner.endpoint.dci(),
                    owner.bitmap.physical(),
                    length,
                )?);
                return Ok(());
            }
        };
        // A notification schedules actual status reads; it never authorizes
        // recovering or acknowledging a condition that was not observed.
        {
            let id = self.hubs[index].device.id;
            let status = self
                .controller
                .borrow_mut()
                .device(id)?
                .control(setup(0xa0, GET_STATUS, 0, 0, 4), &[])?;
            if status.len() != 4 {
                return Err(BlockError::Unsupported("short USB hub lifecycle status"));
            }
            let actual = u16::from_le_bytes([status[0], status[1]]);
            let change = u16::from_le_bytes([status[2], status[3]]);
            if actual & !3 != 0 || change & !3 != 0 {
                return Err(BlockError::Unsupported("reserved USB hub lifecycle status"));
            }
            if actual != 0 || change & 2 != 0 {
                self.start_recovery(index, None, changes)?;
                return self.recover_hub(index, dma, changes);
            }
        }
        // Bitmap is notification only: actual status and power authority decide.
        {
            let mut c = self.controller.borrow_mut();
            c.observe_current_ancestors_for(self.hubs[index].device.id, true)?;
        }
        for port in 1..=self.hubs[index].ports {
            if self.hubs[index].retired {
                break;
            }
            if bits & (1 << port) != 0
                && let Err(error) = self.hub_port(index, port, dma, changes)
            {
                changes.added.failures.push((
                    format!("{}.{port} port lifecycle", self.hubs[index].device.location),
                    error,
                ));
            }
        }
        if self.hubs[index].retired {
            return Ok(());
        }
        let owner = &mut self.hubs[index];
        let length = usize::from(owner.ports + 1).div_ceil(8);
        owner.bitmap.bytes_mut().fill(0);
        owner.pending = Some(
            self.controller
                .borrow_mut()
                .device(owner.device.id)?
                .submit(owner.endpoint.dci(), owner.bitmap.physical(), length)?,
        );
        Ok(())
    }

    fn hub_port(
        &mut self,
        index: usize,
        port: u8,
        dma: &mut dyn DmaAllocator,
        changes: &mut Changes,
    ) -> Result<(), BlockError> {
        let id = self.hubs[index].device.id;
        let slot = id.hardware_slot();
        let attachment = self.hubs[index].attachment;
        let ss = attachment.speed >= SUPER_SPEED;
        let (status, change, owner) = {
            let mut c = self.controller.borrow_mut();
            let (status, change) = c.hub_port_status_for(id, port)?;
            (
                status,
                change,
                c.current_port_owner(Some((id, port)), attachment.root_port)?,
            )
        };
        if change & 8 != 0 || status & 8 != 0 {
            self.start_recovery(index, Some(port), changes)?;
            return self.recover_hub(index, dma, changes);
        }
        let reconnect = change & 1 != 0
            || status & 1 == 0
            || owner.is_none()
            || status & 2 == 0
            || status & if ss { 1 << 9 } else { 1 << 8 } == 0
            || ss && (change & (1 << 7) != 0 || matches!(status >> 5 & 15, 3 | 6 | 10));
        if reconnect && let Some(owner) = owner {
            self.retire(owner, changes)?;
        }
        let mut c = self.controller.borrow_mut();
        let selectors: &[(u16, u16)] = if ss {
            &[(1, 16), (8, 19), (16, 20), (32, 29), (64, 25), (128, 26)]
        } else {
            &[(1, 16), (2, 17), (4, 18), (8, 19), (16, 20)]
        };
        for &(bit, selector) in selectors {
            if change & bit != 0 {
                c.device(id)?.control(
                    setup(0x23, CLEAR_FEATURE, selector, u16::from(port), 0),
                    &[],
                )?;
            }
        }
        if status & if ss { 1 << 9 } else { 1 << 8 } == 0 {
            return Err(BlockError::Unsupported("USB hub port power absent"));
        }
        if ss && status >> 5 & 15 == 3 {
            return Err(BlockError::Unsupported(
                "USB hub U3 resume requires suspend owner",
            ));
        }
        if !reconnect {
            return Ok(());
        }
        let location = format!("{}.{port}", self.hubs[index].device.location);
        let ssp = self.hubs[index].ssp.as_ref();
        let reset = |c: &mut Controller| {
            c.observe_current_ancestors_for(id, true)?;
            let speed = if ss {
                c.superspeed_port_for(id, port, ssp)
            } else {
                c.hub_port_for(id, port)
            };
            c.observe_current_ancestors_for(id, true)?;
            Ok(speed?.map(|speed| Attachment {
                root_port: attachment.root_port,
                route: enumerate::child_route(attachment.route, attachment.tier, port),
                tier: attachment.tier + 1,
                speed,
                parent: Some((slot, port)),
                translator: match (speed, attachment.speed) {
                    (LOW_SPEED | FULL_SPEED, HIGH_SPEED) => Some((slot, port)),
                    _ => attachment.translator,
                },
            }))
        };
        c.connect(
            location,
            Some(self.hubs[index].device.id),
            reset,
            dma,
            &mut changes.added.devices,
            &mut changes.added.failures,
        );
        Ok(())
    }

    fn retire(&mut self, ancestor: SlotId, changes: &mut Changes) -> Result<(), BlockError> {
        self.retire_except(ancestor, None, changes)
    }

    fn retire_except(
        &mut self,
        ancestor: SlotId,
        keep: Option<SlotId>,
        changes: &mut Changes,
    ) -> Result<(), BlockError> {
        let mut c = self.controller.borrow_mut();
        c.validate_ancestry(ancestor)?;
        let root = c.slots[usize::from(ancestor.hardware_slot())]
            .as_ref()
            .unwrap()
            .attachment
            .root_port;
        c.validate_current_graph(root)?;
        let mut slots: Vec<_> = (1..c.slots.len())
            .filter(|slot| c.power.belongs_to(*slot as u8, ancestor.hardware_slot()))
            .map(|slot| slot as u8)
            .collect();
        // Validate the complete original graph before changing any consumer,
        // hub, DMA or current-owner state. No retained raw number is upgraded.
        for &slot in &slots {
            let state = c.slots[usize::from(slot)]
                .as_ref()
                .ok_or(BlockError::Unsupported(
                    "USB retirement original slot absent",
                ))?;
            let inventory = state.inventory.as_ref().ok_or(BlockError::Unsupported(
                "USB retirement original inventory absent",
            ))?;
            if state.retiring && c.slot_ownership[usize::from(slot)] == reset::Ownership::Retired {
                // Disable Slot already acknowledged this exact descendant. Its
                // original parent may also be disabled while physical current
                // remains reserved until port reset. Check the retained seals,
                // rather than demanding live parent hardware for an idle owner.
                if inventory.id.hardware_slot() != slot || !c.known_id(inventory.id) {
                    return Err(BlockError::Unsupported(
                        "USB retired inventory generation changed",
                    ));
                }
                c.power
                    .validate_generation(inventory.id, state.parent_id, state.attachment)?;
            } else {
                // Uncertain Stop/Disable still owns an Enabled slot and must
                // pass the complete live ancestry check before any more work.
                c.validate_ancestry(inventory.id)?;
            }
        }
        // Fence every generation before the first Stop, but keep physical
        // parents internally live for descendant TT-buffer retirement.
        for &slot in &slots {
            if let Some(state) = c.slots[usize::from(slot)].as_mut() {
                state.suspended = true;
            }
        }
        slots.sort_by_key(|slot| {
            core::cmp::Reverse(
                c.slots[usize::from(*slot)]
                    .as_ref()
                    .map_or(0, |state| state.attachment.tier),
            )
        });
        for hub in &mut self.hubs {
            if slots.contains(&hub.device.slot) && c.known_id(hub.device.id) {
                hub.retired = true;
                if Some(hub.device.id) != keep {
                    hub.recovery = None;
                }
            }
        }
        let mut retained = Vec::new();
        for device in self.devices.drain(..) {
            if slots.contains(&device.slot) && c.known_id(device.id) {
                changes.removed.push(device);
            } else {
                retained.push(device);
            }
        }
        self.devices = retained;
        // Invalidate every alias before the first Stop command. An uncertain
        // contributor blocks all Disable Slot publication and new enumeration.
        let mut failure = None;
        for &slot in &slots {
            if c.slot_ownership[usize::from(slot)] != reset::Ownership::Enabled {
                continue;
            }
            for dci in 1..32 {
                if c.slots[usize::from(slot)]
                    .as_ref()
                    .is_some_and(|state| state.endpoints[dci].is_some())
                    && let Err(error) = c.cancel_inner(slot, dci as u8)
                {
                    failure.get_or_insert(error);
                }
            }
        }
        // From here no private child cancellation needs a live parent. Failed
        // contributors remain quarantined with every original allocation.
        for &slot in &slots {
            c.quarantine_slot_owned(slot);
        }
        if let Some(error) = failure {
            return Err(error);
        }
        for slot in slots {
            if Some(slot) != keep.map(SlotId::hardware_slot)
                && c.slot_ownership[usize::from(slot)] == reset::Ownership::Enabled
            {
                c.disable_slot(slot, reset::Ownership::Retired)
                    .map_err(|(_, error)| error)?;
            }
        }
        Ok(())
    }
}
