//! Enumeration (USB 2.0 9.1, 11): root and hub ports are debounced, reset
//! and addressed, and each device's descriptors read.
use super::*;

/// Linux `hub_port_debounce`: sample a port until its connection holds
/// steady and say whether a device is there. `sample` returns the port's
/// connection and connect change, clearing a change it reports.
pub(super) fn debounce(
    clock: Clock,
    sample: impl FnMut() -> Result<(bool, bool), BlockError>,
) -> Result<bool, BlockError> {
    clock_ready(clock)?;
    debounce_with_delay(sample, || {
        crate::bus::pci::power::Timer::wait_us(&clock, DEBOUNCE_STEP_US)
            .map_err(|_| BlockError::Unsupported("xHCI debounce clock unavailable"))
    })
}

fn debounce_with_delay(
    mut sample: impl FnMut() -> Result<(bool, bool), BlockError>,
    mut delay: impl FnMut() -> Result<(), BlockError>,
) -> Result<bool, BlockError> {
    let mut connection = None;
    let mut stable = 0;
    let mut total = 0;
    loop {
        let (connected, changed) = sample()?;
        if !changed && connection == Some(connected) {
            stable += DEBOUNCE_STEP_US;
            if stable >= DEBOUNCE_STABLE_US {
                return Ok(connected);
            }
        } else {
            stable = 0;
            connection = Some(connected);
        }
        if total >= DEBOUNCE_TIMEOUT_US {
            return Err(BlockError::Unsupported("USB port connection never settled"));
        }
        delay()?;
        total += DEBOUNCE_STEP_US;
    }
}

/// The status change endpoint of a hub's interface in `alternate`.
pub(super) fn hub_status_endpoint(configuration: &[u8], alternate: u8) -> Option<Endpoint> {
    interfaces(configuration)
        .into_iter()
        .find(|interface| interface.class == HUB_CLASS && interface.alternate == alternate)
        .and_then(|interface| interface.endpoints.first().copied())
}

/// A hub child's route string: the parent's, with this tier's port, which
/// xHCI holds as 15 at most (Linux `usb_alloc_dev`).
pub(super) fn child_route(parent: u32, tier: u8, port: u8) -> u32 {
    parent | u32::from(port.min(MAX_ROUTE_PORT)) << (4 * tier)
}

impl Controller {
    /// Enables a slot and addresses the device at `attachment`.
    #[cfg(test)]
    pub(super) fn address(
        &mut self,
        attachment: Attachment,
        dma: &mut dyn DmaAllocator,
    ) -> Result<u8, (String, BlockError)> {
        self.address_parent(attachment, None, dma)
    }

    pub(super) fn address_parent(
        &mut self,
        attachment: Attachment,
        parent_id: Option<SlotId>,
        dma: &mut dyn DmaAllocator,
    ) -> Result<u8, (String, BlockError)> {
        during(
            "validate original USB parent",
            self.validate_attachment_parent(attachment, parent_id),
        )?;
        let generation = during("allocate device generation", identity::next_generation())?;
        let slot = during("Enable Slot", self.fresh_slot())?;
        if let Err(error) = self.reserve_current(slot, generation, attachment, parent_id) {
            let _ = self.disable_slot(slot, reset::Ownership::Vacant);
            return Err(("reserve USB upstream current".into(), error));
        }
        let context = self.context();
        let allocation = format!("slot {slot} allocate contexts and EP0 ring");
        let slot_resources::Resources {
            output,
            mut input,
            control,
            ring,
        } = during(
            allocation,
            self.address_resources(slot, attachment, parent_id, dma),
        )?;
        let max_packet: u32 = match attachment.speed {
            LOW_SPEED | FULL_SPEED => 8,
            HIGH_SPEED => 64,
            _ => 512,
        };
        let (tt_slot, tt_port) = attachment.translator.unwrap_or((0, 0));
        let slot_context = [
            attachment.route | u32::from(attachment.speed) << 20 | 1 << 27,
            u32::from(attachment.root_port) << 16,
            u32::from(tt_slot) | u32::from(tt_port) << 8,
            0,
        ];
        input.write(4, 0b11u32);
        for (n, word) in slot_context.iter().enumerate() {
            input.write(context + 4 * n, *word);
        }
        let ep0 = 2 * context;
        input.write(ep0 + 4, 3 << 1 | CONTROL_TYPE << 3 | max_packet << 16);
        input.write(ep0 + 8, ring.dequeue_pointer());
        input.write(ep0 + 16, 8u32);
        let mut endpoints: [Option<Transfer>; 32] = Default::default();
        endpoints[1] = Some(Transfer {
            ring,
            streams: None,
            iso: None,
            is_in: false,
            poisoned: false,
            enabled: true,
            in_flight: 0,
        });
        let input_address = input.device_address();
        // A failed Address Device may leave the output context untouched.
        // Publish its CPU-owned zeros before DCBAA exposes the device pointer.
        during("publish initial device context", output.sync_dirty())?;
        self.dcbaa
            .write(usize::from(slot) * 8, output.device_address());
        self.slots[usize::from(slot)] = Some(Slot {
            generation,
            parent_id,
            inventory: None,
            consumer: identity::Consumer::Unclaimed,
            suspended: false,
            attachment,
            retiring: true,
            input,
            _output: output,
            context: slot_context,
            endpoints,
            retired_rings: Default::default(),
            control,
            speed: attachment.speed,
            current_configuration: Some(0),
        });
        let addressed = self.command(
            input_address,
            0,
            ADDRESS_DEVICE << 10 | u32::from(slot) << 24,
        );
        if let Err(error) = addressed {
            let _ = self.disable_slot(slot, reset::Ownership::Vacant);
            return Err((format!("slot {slot} Address Device"), error));
        }
        // Address Device sends SET_ADDRESS with BSR=0. The xHC does not
        // time the device's recovery interval (xHCI 1.2b 4.6.5); USB 2.0
        // 9.2.6.3 permits it to ignore Setup packets for another 2 ms.
        self.clock.delay(ADDRESS_RECOVERY_US);
        self.slot(slot).unwrap().retiring = false;
        Ok(slot)
    }

    /// Changes EP0's max packet size (Evaluate Context, 4.6.7).
    fn set_control_packet(&mut self, slot: u8, max_packet: u16) -> Result<(), BlockError> {
        self.clear_input(slot)?;
        let context = self.context();
        let input_address = {
            let state = self.slot(slot)?;
            state.input.write(4, 0b10u32);
            state
                .input
                .write(2 * context + 4, u32::from(max_packet) << 16);
            state.input.device_address()
        };
        self.command(
            input_address,
            0,
            EVALUATE_CONTEXT << 10 | u32::from(slot) << 24,
        )?;
        Ok(())
    }

    /// Every device on the root ports and behind their USB 2.0 hubs; a
    /// device that fails to enumerate is reported and skipped.
    pub fn enumerate(
        &mut self,
        dma: &mut dyn DmaAllocator,
        failures: &mut Vec<(String, BlockError)>,
    ) -> Vec<Device> {
        let mut devices = Vec::new();
        for port in 1..=self.max_ports {
            let location = format!("{} port {port}", self.location);
            crate::working(&location);
            let reset = |c: &mut Self| {
                c.root_port(port).map(|speed| {
                    speed.map(|speed| Attachment {
                        root_port: port,
                        route: 0,
                        tier: 0,
                        speed,
                        translator: None,
                        parent: None,
                    })
                })
            };
            self.connect(location, None, reset, dma, &mut devices, failures);
        }
        devices
    }

    /// Linux `hub_port_connect`: reset a port and enumerate its device, up
    /// to four times; only the last failure is reported.
    pub(super) fn connect(
        &mut self,
        location: String,
        parent_id: Option<SlotId>,
        mut reset: impl FnMut(&mut Self) -> Result<Option<Attachment>, BlockError>,
        dma: &mut dyn DmaAllocator,
        devices: &mut Vec<Device>,
        failures: &mut Vec<(String, BlockError)>,
    ) {
        let mut failure = None;
        for _ in 0..PORT_INIT_TRIES {
            if let Some(id) = parent_id
                && let Err(error) = self.validate_topology_id(id)
            {
                failures.push((format!("{location} original parent generation"), error));
                return;
            }
            let attachment = match reset(self) {
                Ok(Some(attachment)) => attachment,
                Ok(None) => return,
                Err(error) => {
                    failures.push((format!("{location} enable/reset port"), error));
                    return;
                }
            };
            match self.identify_parent(attachment, parent_id, location.clone(), dma) {
                Ok(device) => {
                    return self.adopt(device, attachment, location, dma, devices, failures);
                }
                Err(error) => failure = Some((attachment, error)),
            }
        }
        if let Some((attachment, (operation, error))) = failure {
            let at = self.port_offset(attachment.root_port);
            let portsc = self.registers.read32(at);
            failures.push((
                format!(
                    "{location} speed={} root-portsc={portsc:#010x} {operation}",
                    attachment.speed
                ),
                error,
            ));
        }
    }

    /// A root port's device speed once the port is enabled, or `None` with
    /// nothing connected.
    pub(super) fn root_port(&mut self, port: u8) -> Result<Option<u8>, BlockError> {
        self.validate_current_graph(port)?;
        let at = self.port_offset(port);
        if self.registers.read32(at) & PP == 0 {
            self.write_port(port, PP);
            self.clock.delay(PORT_POWER_US);
        }
        let clock = self.clock;
        let connected = debounce(clock, || {
            let portsc = self.registers.read32(at);
            if portsc & CSC != 0 {
                self.write_port(port, CSC);
            }
            Ok((portsc & CCS != 0, portsc & CSC != 0))
        })?;
        if !connected {
            return Ok(None);
        }
        // Clear the remaining changes, so later changes are this driver's.
        let portsc = self.registers.read32(at);
        self.write_port(port, portsc & PORT_CHANGES);
        let link = portsc >> PLS_SHIFT & PLS_FIELD;
        if self.port_major[usize::from(port - 1)] == 3
            && matches!(link, LINK_INACTIVE | LINK_COMPLIANCE)
        {
            // Linux `hub_port_reset` warm-resets a SuperSpeed link stuck in
            // SS.Inactive or Compliance Mode.
            self.write_port(port, WPR);
            if !wait(&mut *self.registers, clock, PORT_RESET_US, |r| {
                r.read32(at) & (WRC | PRC) == WRC | PRC
            }) {
                return Err(BlockError::Timeout);
            }
            self.write_port(port, WRC | PRC);
            self.clock.delay(RESET_RECOVERY_US);
        } else if self.port_major[usize::from(port - 1)] != 3 {
            self.write_port(port, PR);
            let clock = self.clock;
            if !wait(&mut *self.registers, clock, PORT_RESET_US, |r| {
                r.read32(at) & PRC != 0
            }) {
                return Err(BlockError::Timeout);
            }
            self.write_port(port, PRC);
            self.clock.delay(RESET_RECOVERY_US);
        } else {
            let clock = self.clock;
            if !wait(&mut *self.registers, clock, PORT_RESET_US, |r| {
                r.read32(at) & PED != 0
            }) {
                return Err(BlockError::Timeout);
            }
        }
        let portsc = self.registers.read32(at);
        if portsc & PED == 0 {
            return Err(BlockError::Unsupported("root port did not enable"));
        }
        if self.port_major[usize::from(port - 1)] != 3
            || matches!(link, LINK_INACTIVE | LINK_COMPLIANCE)
        {
            self.current_port_reset(None, port)?;
        }
        Ok(Some((portsc >> PORT_SPEED_SHIFT & PORT_SPEED_FIELD) as u8))
    }

    /// Choose an enumerated device's configuration and bring up a hub's
    /// ports; the device joins the inventory either way.
    /// `usb_choose_configuration` for a freshly identified device. A failed
    /// selection leaves the descriptor inventory with no configuration.
    pub(super) fn choose(
        &mut self,
        device: &mut Device,
        location: &str,
        failures: &mut Vec<(String, BlockError)>,
    ) -> bool {
        if let Err(error) = self.preflight_vendor_ethernet(device) {
            failures.push((format!("{location} RTL815x configuration preflight"), error));
        }
        if let Err(why) = configuration::select_with_controller(device, Some(self)) {
            device.configuration.clear();
            failures.push((
                format!("{location} {} choose configuration", device.name()),
                BlockError::Unsupported(why),
            ));
            return false;
        }
        true
    }

    fn adopt(
        &mut self,
        mut device: Device,
        attachment: Attachment,
        location: String,
        dma: &mut dyn DmaAllocator,
        devices: &mut Vec<Device>,
        failures: &mut Vec<(String, BlockError)>,
    ) {
        if self.choose(&mut device, &location, failures)
            && device.descriptor[4] == HUB_CLASS
            && let Err(error) = self.hub(&device, attachment, dma, devices, failures)
        {
            failures.push((format!("{location} {} enumerate hub", device.name()), error));
        }
        self.initial_usb2_lpm(&device, attachment);
        // Selection failures still preserve the entire descriptor
        // inventory for diagnostics and future generic forwarding.
        if let Ok(slot) = self.slot(device.slot) {
            slot.inventory = Some(device.clone());
        }
        devices.push(device);
    }

    pub(crate) fn preflight_vendor_ethernet(
        &mut self,
        device: &mut Device,
    ) -> Result<(), BlockError> {
        if ethernet::matches(&device.descriptor) {
            use ethernet::rtl815x::Revision;
            let bytes = self.device(device.id)?.control(Revision::request(), &[])?;
            let revision = Revision::from_register(&bytes)?;
            device.vendor_ethernet_revision = Some(revision.0);
            device.vendor_ethernet_tcr = Some(u32::from_le_bytes(bytes.try_into().unwrap()));
        }
        Ok(())
    }

    /// Address a new device and read its descriptors. A device that fails
    /// gives its slot back.
    #[cfg(test)]
    pub(super) fn identify(
        &mut self,
        attachment: Attachment,
        location: String,
        dma: &mut dyn DmaAllocator,
    ) -> Result<Device, (String, BlockError)> {
        self.identify_parent(attachment, None, location, dma)
    }

    pub(super) fn identify_parent(
        &mut self,
        attachment: Attachment,
        parent_id: Option<SlotId>,
        location: String,
        dma: &mut dyn DmaAllocator,
    ) -> Result<Device, (String, BlockError)> {
        let slot = self.address_parent(attachment, parent_id, dma)?;
        let described = self.describe(slot, attachment, location);
        if described.is_err() {
            // Best effort: a slot that will not disable stays enabled.
            let _ = self.disable_slot(slot, reset::Ownership::Vacant);
        }
        if let Ok(device) = &described {
            self.slot(slot).unwrap().inventory = Some(device.clone());
        }
        described
    }

    fn describe(
        &mut self,
        slot: u8,
        attachment: Attachment,
        location: String,
    ) -> Result<Device, (String, BlockError)> {
        let first = self.enumeration_descriptor(slot, DEVICE_DESCRIPTOR, 0, 8)?;
        if first.len() < 8 {
            return during(
                format!("slot {slot} device descriptor header"),
                Err(BlockError::Unsupported("short device descriptor")),
            );
        }
        let ep0 = u16::from(first[7]);
        let expected = match attachment.speed {
            LOW_SPEED | FULL_SPEED => 8,
            HIGH_SPEED => 64,
            _ => 512,
        };
        if attachment.speed == FULL_SPEED && ep0 != expected && [8, 16, 32, 64].contains(&ep0) {
            during(
                format!("slot {slot} Evaluate Context EP0 max_packet={ep0}"),
                self.set_control_packet(slot, ep0),
            )?;
        }
        let bytes = self.enumeration_descriptor(slot, DEVICE_DESCRIPTOR, 0, 18)?;
        let descriptor: [u8; 18] = during(
            format!("slot {slot} full device descriptor"),
            bytes
                .get(..18)
                .and_then(|b| b.try_into().ok())
                .ok_or(BlockError::Unsupported("short device descriptor")),
        )?;
        let identity = format!(
            "{:04x}:{:04x}",
            u16::from_le_bytes([descriptor[8], descriptor[9]]),
            u16::from_le_bytes([descriptor[10], descriptor[11]])
        );
        if descriptor[0] != 18 || descriptor[1] != DEVICE_DESCRIPTOR || descriptor[17] == 0 {
            return during(
                format!("{identity} slot {slot} device descriptor"),
                Err(BlockError::Unsupported(
                    "invalid USB device descriptor/configuration count",
                )),
            );
        }
        let configurations = self
            .configurations(slot, descriptor[17])
            .map_err(|(operation, error)| (format!("{identity} {operation}"), error))?;
        let language = if descriptor[14..17].iter().any(|index| *index != 0) {
            self.language(slot)
        } else {
            None
        };
        let mut string =
            |index| language.and_then(|language| self.string_owned(slot, language, index));
        let manufacturer = string(descriptor[14]);
        let product = string(descriptor[15]);
        let serial = string(descriptor[16]);
        let device = Device {
            id: self
                .device_id(slot)
                .map_err(|error| ("identify device generation".into(), error))?,
            vendor_ethernet_revision: None,
            vendor_ethernet_tcr: None,
            slot,
            speed: attachment.speed,
            location,
            descriptor,
            configurations,
            configuration: Vec::new(),
            manufacturer,
            product,
            serial,
            language,
        };
        Ok(device)
    }

    /// Read every descriptor index, keeping the complete original byte streams.
    pub(super) fn configurations(
        &mut self,
        slot: u8,
        count: u8,
    ) -> Result<Vec<Vec<u8>>, (String, BlockError)> {
        if count == 0 {
            return during(
                format!("slot {slot} configuration inventory"),
                Err(BlockError::Unsupported("USB device has no configurations")),
            );
        }
        let mut configurations = Vec::new();
        let mut inventory_bytes = 0;
        for index in 0..count {
            let bytes = self.configuration(slot, index)?;
            inventory_bytes += bytes.len();
            if inventory_bytes > CONFIGURATION_INVENTORY_BYTES {
                return during(
                    format!("slot {slot} configuration {index}"),
                    Err(BlockError::Unsupported(
                        "USB configuration inventory exceeds 64 KiB",
                    )),
                );
            }
            if configurations
                .iter()
                .any(|previous: &Vec<u8>| previous[5] == bytes[5])
            {
                return during(
                    format!("slot {slot} configuration {index}"),
                    Err(BlockError::Unsupported("duplicate USB configuration value")),
                );
            }
            configurations.push(bytes);
        }
        self.current_descriptions(slot, &configurations)
            .map_err(|error| ("retain USB configuration current descriptors".into(), error))?;
        Ok(configurations)
    }

    /// Configuration descriptor `index`, whole.
    pub(super) fn configuration(
        &mut self,
        slot: u8,
        index: u8,
    ) -> Result<Vec<u8>, (String, BlockError)> {
        let head = self.enumeration_descriptor(slot, CONFIGURATION_DESCRIPTOR, index, 9)?;
        if head.len() < 9 {
            return during(
                format!("slot {slot} configuration {index} header"),
                Err(BlockError::Unsupported("short configuration descriptor")),
            );
        }
        let total = u16::from_le_bytes([head[2], head[3]]);
        if head[0] != 9
            || head[1] != CONFIGURATION_DESCRIPTOR
            || total < 9
            || usize::from(total) > CONTROL_BYTES
        {
            return during(
                format!("slot {slot} configuration {index} length={total}"),
                Err(BlockError::Unsupported(
                    "invalid or oversized USB configuration descriptor",
                )),
            );
        }
        let bytes = self.enumeration_descriptor(slot, CONFIGURATION_DESCRIPTOR, index, total)?;
        during(
            format!(
                "slot {slot} configuration {index} value={} validate",
                head[5]
            ),
            if bytes[..9] != head[..9] {
                Err(BlockError::Unsupported(
                    "USB configuration header changed during enumeration",
                ))
            } else {
                Ok(())
            },
        )?;
        Ok(bytes)
    }

    pub(super) fn enumeration_descriptor(
        &mut self,
        slot: u8,
        kind: u8,
        index: u8,
        length: u16,
    ) -> Result<Vec<u8>, (String, BlockError)> {
        during(
            format!("slot {slot} EP0 GET_DESCRIPTOR type={kind} index={index} length={length}"),
            self.descriptor(slot, kind, index, length),
        )
    }

    pub(super) fn hub(
        &mut self,
        device: &Device,
        attachment: Attachment,
        dma: &mut dyn DmaAllocator,
        devices: &mut Vec<Device>,
        failures: &mut Vec<(String, BlockError)>,
    ) -> Result<(), BlockError> {
        if self.validate_topology_id(device.id)? != device.slot {
            return Err(BlockError::Unsupported(
                "USB hub original descriptor slot changed",
            ));
        }
        if self.slot(device.slot)?.attachment != attachment {
            return Err(BlockError::Unsupported(
                "USB hub attachment is not its retained owner",
            ));
        }
        if matches!(attachment.speed, SUPER_SPEED | SUPER_SPEED_PLUS) {
            return self.superspeed_hub(device, attachment, dma, devices, failures);
        }
        if attachment.tier + 1 > MAX_TIERS {
            return Err(BlockError::Unsupported("hub more than five tiers deep"));
        }
        let slot = device.slot;
        // get_hub_descriptor: three tries for a reply holding the fixed
        // fields and the port count.
        let mut bytes = Vec::new();
        for _ in 0..3 {
            bytes = self.control_owned(
                slot,
                setup(
                    DEVICE_TO_HOST | TYPE_CLASS,
                    GET_DESCRIPTOR,
                    u16::from(HUB_DESCRIPTOR) << 8,
                    0,
                    hub::descriptor::Usb2Descriptor::REQUEST,
                ),
                &[],
            )?;
            if bytes.len() >= hub::descriptor::Usb2Descriptor::MINIMUM {
                break;
            }
        }
        if bytes.len() < hub::descriptor::Usb2Descriptor::MINIMUM {
            return Err(BlockError::Unsupported("short USB2 hub descriptor"));
        }
        let original = device
            .configurations
            .iter()
            .find(|configuration| {
                configuration.get(5).copied() == Some(device.configuration_value())
            })
            .ok_or(BlockError::Unsupported(
                "USB2 hub selected original configuration absent",
            ))?;
        let endpoint = hub::usb2_status_endpoint(original, device.speed, 0, bytes[2])?;
        let descriptor = hub::descriptor::Usb2Descriptor::new(&bytes, &endpoint)?;
        let ports = descriptor.ports;
        let tt_think = if attachment.speed == HIGH_SPEED {
            descriptor.tt_think
        } else {
            0
        };
        self.set_configuration_owned(slot, device.configuration_value())?;
        // Device status describes the configuration the device acknowledged.
        let self_powered = self.hub_power_source(slot)?;
        self.install_hub_current(slot, ports, descriptor.controller_ma, self_powered)?;
        self.observe_hub_current(slot)?;
        // Linux `hub_configure`: a multi-TT hub (device protocol 2) gets one
        // TT per port through interface 0's alternate setting 1; a refusal
        // leaves it a single-TT hub.
        let multi = device.descriptor[6] == HUB_MULTI_TT
            && self
                .control_owned(
                    slot,
                    setup(
                        RECIPIENT_INTERFACE,
                        SET_INTERFACE,
                        u16::from(MULTI_TT_ALTERNATE),
                        0,
                        0,
                    ),
                    &[],
                )
                .is_ok();
        let alternate = if multi { MULTI_TT_ALTERNATE } else { 0 };
        // SET_INTERFACE success is physical permission for this setting. If its
        // original descriptor cannot supply a complete status bitmap, refuse
        // before Configure Endpoint, downstream power or child publication.
        let endpoint = hub::usb2_status_endpoint(original, device.speed, alternate, ports)?;
        self.configure_owned(slot, &[endpoint], Some((ports, tt_think, multi)), dma)?;
        let mut powered_ports = Vec::new();
        for port in 1..=ports {
            if let Err(error) = self.reserve_port_current(slot, port) {
                failures.push((
                    format!("{}.{port} reserve initial USB current", device.location),
                    error,
                ));
                continue;
            }
            self.control_owned(
                slot,
                setup(
                    TYPE_CLASS | RECIPIENT_OTHER,
                    SET_FEATURE,
                    PORT_POWER,
                    u16::from(port),
                    0,
                ),
                &[],
            )?;
            powered_ports.push(port);
        }
        self.clock.delay(descriptor.power_good_us);
        for port in powered_ports {
            let location = format!("{}.{port}", device.location);
            crate::working(&location);
            let reset = |c: &mut Self| {
                c.hub_port_for(device.id, port).map(|speed| {
                    speed.map(|speed| Attachment {
                        root_port: attachment.root_port,
                        route: child_route(attachment.route, attachment.tier, port),
                        tier: attachment.tier + 1,
                        speed,
                        parent: Some((slot, port)),
                        translator: match (speed, attachment.speed) {
                            (LOW_SPEED | FULL_SPEED, HIGH_SPEED) => Some((slot, port)),
                            _ => attachment.translator,
                        },
                    })
                })
            };
            self.connect(location, Some(device.id), reset, dma, devices, failures);
        }
        Ok(())
    }

    pub(super) fn hub_port_status_for(
        &mut self,
        id: SlotId,
        port: u8,
    ) -> Result<(u16, u16), BlockError> {
        let slot = self.validate_topology_id(id)?;
        self.hub_port_status_owned(slot, port)
    }

    #[cfg(test)]
    pub(super) fn hub_port_status(
        &mut self,
        id: impl DeviceRef,
        port: u8,
    ) -> Result<(u16, u16), BlockError> {
        let slot = id.current_slot(self)?;
        self.hub_port_status_owned(slot, port)
    }

    pub(super) fn hub_port_status_owned(
        &mut self,
        slot: u8,
        port: u8,
    ) -> Result<(u16, u16), BlockError> {
        let status = self.control_owned(
            slot,
            setup(
                DEVICE_TO_HOST | TYPE_CLASS | RECIPIENT_OTHER,
                GET_STATUS,
                0,
                u16::from(port),
                4,
            ),
            &[],
        )?;
        if status.len() != 4 {
            return Err(BlockError::Unsupported("short hub port status"));
        }
        hub::validate_port_status(&status, self.slot(slot)?.attachment.speed)?;
        Ok((
            u16::from_le_bytes([status[0], status[1]]),
            u16::from_le_bytes([status[2], status[3]]),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::dma::RegionAllocator;
    use crate::usb::xhci::model::*;

    #[test]
    fn multi_tt_hubs_use_the_status_endpoint_of_alternate_setting_one() {
        // Interface 0 alternate 0 (single TT) and 1 (multi TT), each with
        // an interrupt IN status endpoint of its own.
        let configuration = [
            9, 2, 41, 0, 1, 1, 0, 0xe0, 0, //
            9, 4, 0, 0, 1, HUB_CLASS, 0, 1, 0, //
            7, 5, 0x81, 3, 1, 0, 12, //
            9, 4, 0, 1, 1, HUB_CLASS, 0, 2, 0, //
            7, 5, 0x82, 3, 1, 0, 12,
        ];
        assert_eq!(
            hub_status_endpoint(&configuration, 0).unwrap().address,
            0x81
        );
        assert_eq!(
            hub_status_endpoint(&configuration, MULTI_TT_ALTERNATE)
                .unwrap()
                .address,
            0x82
        );
        assert!(hub_status_endpoint(&configuration, 2).is_none());
    }

    #[test]
    fn port_connections_count_after_a_steady_hundred_milliseconds() {
        // A bounce (connected, changed, gone, back) restarts the window.
        let samples = [(true, true), (false, true), (true, true), (true, false)];
        let mut taken = samples
            .iter()
            .copied()
            .chain(core::iter::repeat((true, false)));
        let mut count = 0;
        let mut waits = 0;
        let connected = debounce_with_delay(
            || {
                count += 1;
                Ok(taken.next().unwrap())
            },
            || {
                waits += 1;
                Ok(())
            },
        );
        assert_eq!(connected, Ok(true));
        // Three changing samples, then four steady ones of 25 ms each.
        assert_eq!(count, 3 + (DEBOUNCE_STABLE_US / DEBOUNCE_STEP_US) as usize);
        assert_eq!(waits, count - 1);
        assert_eq!(
            debounce_with_delay(|| Ok((false, false)), || Ok(())),
            Ok(false)
        );
        let mut flapping = false;
        assert_eq!(
            debounce_with_delay(
                || {
                    flapping = !flapping;
                    Ok((flapping, true))
                },
                || Ok(())
            ),
            Err(BlockError::Unsupported("USB port connection never settled"))
        );
    }

    #[test]
    fn unavailable_debounce_timing_refuses_before_port_sampling_and_failed_wait_is_explicit() {
        for rate in [0, u64::MAX, (u64::MAX / 2) / 60_000_000 + 1] {
            assert!(
                debounce(
                    Clock {
                        ticks_per_microsecond: rate
                    },
                    || panic!("unavailable clock sampled real port")
                )
                .is_err()
            );
        }
        assert_eq!(
            debounce_with_delay(|| Ok((true, false)), || Err(BlockError::Timeout)),
            Err(BlockError::Timeout)
        );
    }

    #[test]
    fn hub_ports_past_fifteen_route_as_fifteen() {
        assert_eq!(child_route(0, 0, 3), 3);
        assert_eq!(child_route(0x3, 1, 9), 0x93);
        assert_eq!(child_route(0x3, 1, 20), 0xf3);
        assert_eq!(child_route(0, 4, MAX_HUB_PORTS), 0xf_0000);
    }

    #[test]
    fn the_first_setup_waits_for_set_address_recovery() {
        let mut backing = vec![0u64; 16 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: backing outlives the controller and all its DMA buffers.
        let mut dma = unsafe { RegionAllocator::new(start..start + 128 * 1024) };
        let (mut controller, model) = address_controller(&mut dma, SUCCESS);
        let attachment = Attachment {
            root_port: 1,
            route: 0,
            tier: 0,
            speed: FULL_SPEED,
            translator: None,
            parent: None,
        };
        let slot = controller.address(attachment, &mut dma).unwrap();
        let request = setup(
            0x80,
            GET_DESCRIPTOR,
            u16::from(DEVICE_DESCRIPTOR) << 8,
            0,
            8,
        );
        assert_eq!(controller.control(slot, request, &[]).unwrap().len(), 8);
        let state = model.borrow();
        assert_eq!(state.commands_seen, [ENABLE_SLOT, ADDRESS_DEVICE]);
        assert_eq!(state.setup_seen, [request]);
        assert!(!state.early_setup);
    }

    #[test]
    fn an_address_device_error_does_not_issue_a_setup() {
        let mut backing = vec![0u64; 16 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: backing outlives the controller and all its DMA buffers.
        let mut dma = unsafe { RegionAllocator::new(start..start + 128 * 1024) };
        let (mut controller, model) = address_controller(&mut dma, 4);
        let attachment = Attachment {
            root_port: 1,
            route: 0,
            tier: 0,
            speed: FULL_SPEED,
            translator: None,
            parent: None,
        };
        assert_eq!(
            controller
                .identify(attachment, String::from("port 1"), &mut dma)
                .unwrap_err(),
            (
                String::from("slot 1 Address Device"),
                BlockError::Device { status: 4 }
            )
        );
        let state = model.borrow();
        // The slot no driver was given is disabled and free for reuse.
        assert_eq!(
            state.commands_seen,
            [ENABLE_SLOT, ADDRESS_DEVICE, reset::DISABLE_SLOT]
        );
        assert!(state.setup_seen.is_empty());
        assert_eq!(controller.slot_ownership[1], reset::Ownership::Vacant);
        assert_eq!(controller.dcbaa.read::<u64>(8), 0);
    }

    #[test]
    fn descriptor_failure_retains_the_request_and_completion_code() {
        let mut backing = vec![0u64; 16 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: backing outlives the controller and all its DMA buffers.
        let mut dma = unsafe { RegionAllocator::new(start..start + 128 * 1024) };
        let (mut controller, model) = address_controller(&mut dma, SUCCESS);
        let attachment = Attachment {
            root_port: 1,
            route: 0,
            tier: 0,
            speed: FULL_SPEED,
            translator: None,
            parent: None,
        };
        let slot = controller.address(attachment, &mut dma).unwrap();
        // Model a descriptor transfer failing after successful addressing.
        model.borrow_mut().ready_at = u64::MAX;
        assert_eq!(
            controller
                .enumeration_descriptor(slot, CONFIGURATION_DESCRIPTOR, 2, 9)
                .unwrap_err(),
            (
                String::from("slot 1 EP0 GET_DESCRIPTOR type=2 index=2 length=9"),
                BlockError::Device { status: 4 }
            )
        );
        let state = model.borrow();
        assert_eq!(
            state.setup_seen,
            [setup(0x80, GET_DESCRIPTOR, 0x0202, 0, 9)]
        );
        assert_eq!(
            state.commands_seen,
            [ENABLE_SLOT, ADDRESS_DEVICE, RESET_ENDPOINT, SET_DEQUEUE]
        );
    }

    #[test]
    fn all_configuration_indices_travel_through_ep0_and_selection_uses_the_wire_value() {
        use configuration::tests::{device, ecm, vendor};
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: backing remains live and exclusive through all modeled DMA.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) =
            unconfigured_cancellation_controller_with_configurations(&mut dma, &[]);
        let originals = vec![vendor(9), ecm(42), vendor(5)];
        model.borrow_mut().descriptors = originals
            .iter()
            .enumerate()
            .map(|(index, bytes)| (CONFIGURATION_DESCRIPTOR, index as u8, bytes.clone()))
            .collect();
        let inventory = controller.configurations(1, 3).unwrap();
        assert_eq!(inventory, originals);
        let mut device = device(inventory);
        configuration::select(&mut device).unwrap();
        assert_eq!(device.configuration_value(), 42);
        assert_eq!(
            model
                .borrow()
                .setup
                .iter()
                .map(|(request, _)| request[2])
                .collect::<Vec<_>>(),
            vec![0, 0, 1, 1, 2, 2]
        );
        let all = interfaces(&device.configuration);
        let plan = configuration::plan(&device, &all[0], &all).unwrap();
        assert!(
            controller
                .configure(1, &plan.endpoints(), None, &mut dma)
                .is_err()
        );
        assert!(model.borrow().seen.is_empty());
        controller
            .set_configuration(1, device.configuration_value())
            .unwrap();
        controller
            .configure(1, &plan.endpoints(), None, &mut dma)
            .unwrap();
        assert_eq!(controller.current_configuration(1), Ok(Some(42)));
        assert_eq!(model.borrow().configuration_seen_before_endpoints, vec![42]);
        assert_eq!(
            model.borrow().setup.last().unwrap().0,
            setup(0, SET_CONFIGURATION, 42, 0, 0)
        );
        let requests = model.borrow().setup.len();
        controller.set_configuration(1, 42).unwrap(); // Another class binder must not reset the device.
        assert_eq!(model.borrow().setup.len(), requests);
        assert!(controller.set_configuration(1, 9).is_err());
        assert!(
            controller
                .control(1, setup(0, SET_CONFIGURATION, 42, 0, 0), &[])
                .is_err()
        );
        assert_eq!(model.borrow().setup.len(), requests);
        assert_eq!(controller.current_configuration(1), Ok(Some(42)));
    }

    #[test]
    fn descriptor_inventory_refuses_truncation_duplicate_values_and_silent_size_caps() {
        use configuration::tests::vendor;
        for scenario in 0..5 {
            let mut backing = vec![0u64; 128 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: exclusive live test backing holds all rings and buffers.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut controller, model) = unconfigured_cancellation_controller(&mut dma);
            let mut bytes = vendor(7);
            match scenario {
                0 => {
                    bytes.pop();
                }
                1 => {
                    bytes[2..4].copy_from_slice(&4097u16.to_le_bytes());
                }
                2 => {
                    bytes[5] = 0;
                }
                3 => {
                    bytes[2..4].copy_from_slice(&8u16.to_le_bytes());
                }
                _ => {}
            }
            model.borrow_mut().descriptors = vec![
                (CONFIGURATION_DESCRIPTOR, 0, bytes.clone()),
                (CONFIGURATION_DESCRIPTOR, 1, bytes),
            ];
            let error = controller.configurations(1, 2).unwrap_err();
            assert!(matches!(error.1, BlockError::Unsupported(_)), "{error:?}");
            assert_eq!(controller.current_configuration(1), Ok(Some(0)));
            assert!(model.borrow().seen.is_empty());
            if scenario == 1 || scenario == 3 {
                assert_eq!(model.borrow().setup.len(), 1); // Reject before requesting capped/full bytes.
            }
        }
    }

    #[test]
    fn configuration_inventory_has_an_explicit_aggregate_resource_limit() {
        use configuration::tests::vendor;
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: this exclusive allocation remains live for every DMA access.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = unconfigured_cancellation_controller(&mut dma);
        for index in 0..17 {
            let mut bytes = vendor(index + 1);
            while bytes.len() < CONTROL_BYTES {
                bytes.extend_from_slice(&[2, 0x25]); // Preserved unknown class descriptors.
            }
            bytes[2..4].copy_from_slice(&(CONTROL_BYTES as u16).to_le_bytes());
            model
                .borrow_mut()
                .descriptors
                .push((CONFIGURATION_DESCRIPTOR, index, bytes));
        }
        assert_eq!(
            controller.configurations(1, 17).unwrap_err().1,
            BlockError::Unsupported("USB configuration inventory exceeds 64 KiB")
        );
        assert_eq!(model.borrow().setup.len(), 34);
        assert_eq!(controller.current_configuration(1), Ok(Some(0)));
        assert!(model.borrow().seen.is_empty());
    }
}
