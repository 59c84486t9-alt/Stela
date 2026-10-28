// SPDX-License-Identifier: GPL-2.0-only
// Logitech/Google/Red Hat HID++ reference notices: receiver.rs and THIRD_PARTY.md.
//! Private admission from actual native class owners, never a raw second owner.
use super::*;

fn application(descriptor: &Descriptor, mut collection: Option<usize>) -> Option<(usize, u32)> {
    while let Some(index) = collection {
        let item = descriptor.collections.get(index)?;
        if item.kind == 1 {
            return Some((index, item.usage));
        }
        collection = item.parent;
    }
    None
}
pub(super) fn profile(descriptor: &Descriptor) -> bool {
    for (id, length) in [(SHORT, SHORT_BYTES), (LONG, LONG_BYTES)] {
        let mut selected_app = None;
        for kind in [ReportType::Input, ReportType::Output] {
            let Some(layout) = descriptor.layout(kind, id) else {
                return false;
            };
            if layout.wire_bytes() != length || layout.fields.is_empty() {
                return false;
            }
            let mut offset = 0;
            for field in &layout.fields {
                let Some((app_index, app)) = application(descriptor, field.collection) else {
                    return false;
                };
                if selected_app.is_some_and(|index| index != app_index) {
                    return false;
                }
                selected_app = Some(app_index);
                if field.offset != offset
                    || field.size != 8
                    || !matches!(field.flags, 0 | 2)
                    || field.minimum != 0
                    || field.maximum != 255
                    || !matches!(app, 0xff00_0001 | 0xff00_0002)
                    || (id == SHORT && app != 0xff00_0001)
                    || field.usages.is_empty()
                    || field.usages.iter().any(|u| u >> 16 != 0xff00)
                {
                    return false;
                }
                offset += field.count * field.size;
            }
            if offset != (length - 1) * 8 {
                return false;
            }
        }
    }
    true
}

/// Called once after the existing native claim/configuration/class constructors.
/// A second native bind of the same physical SlotId is already refused by xHCI.
pub(in crate::usb) fn attach_group(
    shared: &Shared,
    device: &Device,
    inputs: &mut [UsbInput],
) -> Result<bool, BlockError> {
    if device.descriptor[8..12] != [0x6d, 0x04, 0x39, 0xc5] {
        return Ok(false);
    }
    let configuration = device.configuration_value();
    {
        let mut controller = shared.borrow_mut();
        controller.validate_device_id(device.id)?;
        if configuration == 0
            || controller.device(device.id)?.current_configuration() != Ok(Some(configuration))
        {
            return Err(BlockError::Unsupported(
                "receiver requires acknowledged native configuration",
            ));
        }
    }
    let indices: Vec<_> = inputs
        .iter()
        .enumerate()
        .filter(|(_, input)| input.interface < 3)
        .map(|(n, _)| n)
        .collect();
    let actual_interfaces = crate::usb::xhci::interfaces(&device.configuration);
    let mut vendor = None;
    let mut members = Vec::new();
    for index in &indices {
        let input = &inputs[*index];
        if !actual_interfaces.iter().any(|interface| {
            interface.number == input.interface
                && interface.alternate == 0
                && interface.class == CLASS
                && interface.endpoints.contains(&input.endpoint)
        }) || !Rc::ptr_eq(&input.controller, shared)
            || input.id != device.id
            || input.state != State::Running
            || input.receiver.is_some()
        {
            return Err(BlockError::Unsupported(
                "receiver native member identity mismatch",
            ));
        }
        if input.translator.descriptor().is_some_and(profile) {
            if vendor.is_some() {
                return Err(BlockError::Unsupported("ambiguous native HID++ interfaces"));
            }
            vendor = Some(members.len());
        }
        members.push(Member {
            interface: input.interface,
            endpoint: input.endpoint,
            descriptor: input.report_descriptor.clone(),
            active: true,
        });
    }
    let Some(vendor) = vendor else {
        return Err(BlockError::Unsupported(
            "receiver HID++ descriptor profile not supported",
        ));
    };
    let group = Rc::new(RefCell::new(Group {
        controller: Rc::downgrade(shared),
        id: device.id,
        configuration,
        configuration_descriptor: device.configuration.clone(),
        members,
        vendor,
        initialization: Initialization::ArmInput,
        routes: (1..=ROUTES as u8).map(Logical::new).collect(),
        pending: None,
        first_error: None,
    }));
    for (member, index) in indices.into_iter().enumerate() {
        inputs[index].receiver = Some(Link {
            group: group.clone(),
            member,
        });
    }
    Ok(true)
}

impl UsbInput {
    fn admitted_receiver(&self) -> Result<Option<Link>, BlockError> {
        self.controller.borrow().validate_device_id(self.id)?;
        let Some(link) = &self.receiver else {
            return Ok(None);
        };
        {
            let group = link.group.borrow();
            let controller = group
                .controller
                .upgrade()
                .ok_or(BlockError::Unsupported("retired receiver controller"))?;
            let member = &group.members[link.member];
            if !Rc::ptr_eq(&controller, &self.controller)
                || group.id != self.id
                || member.interface != self.interface
                || member.endpoint != self.endpoint
                || member.descriptor != self.report_descriptor
                || group.configuration_descriptor.get(5) != Some(&group.configuration)
            {
                return Err(BlockError::Unsupported("stale receiver member seal"));
            }
            if self
                .controller
                .borrow_mut()
                .device(self.id)?
                .current_configuration()
                != Ok(Some(group.configuration))
            {
                return Err(BlockError::Unsupported(
                    "receiver configuration no longer current",
                ));
            }
        }
        Ok(Some(link.clone()))
    }

    /// Cached protocol data is published only after current native admission.
    /// This returns no invented per-pair standard input or device capabilities.
    pub fn receiver_snapshot(&mut self) -> Result<Option<Snapshot>, BlockError> {
        let Some(link) = self.admitted_receiver()? else {
            return Ok(None);
        };
        let now = self.controller.borrow().clock.now_us();
        let mut group = link.group.borrow_mut();
        group.expire(now);
        Ok(Some(group.snapshot()))
    }

    pub(in crate::usb::hid) fn invalidate_receiver(&self, error: Error) {
        // A stale member cannot mutate the group belonging to a current owner.
        if let Ok(Some(link)) = self.admitted_receiver() {
            let mut group = link.group.borrow_mut();
            group.members[link.member].active = false;
            group.invalidate(error);
        }
    }
    pub(in crate::usb::hid) fn restart_receiver(&self) {
        if let Ok(Some(link)) = self.admitted_receiver() {
            let mut group = link.group.borrow_mut();
            group.members[link.member].active = true;
            if group.members.iter().all(|m| m.active) {
                group.initialization = Initialization::ArmInput;
            }
        }
    }
    pub(in crate::usb::hid) fn receiver_observe(&mut self, bytes: &[u8]) {
        let Ok(Some(link)) = self.admitted_receiver() else {
            return;
        };
        let now = self.controller.borrow().clock.now_us();
        let mut group = link.group.borrow_mut();
        if link.member == group.vendor && group.members.iter().all(|m| m.active) {
            group.observe(bytes, now);
        }
    }
    pub(in crate::usb::hid) fn receiver_progress(&mut self) {
        if self.state != State::Running || self.retry.is_some() || self.queued.is_none() {
            return;
        }
        let Ok(Some(link)) = self.admitted_receiver() else {
            return;
        };
        let now = self.controller.borrow().clock.now_us();
        let output = {
            let mut group = link.group.borrow_mut();
            if link.member != group.vendor {
                return;
            }
            group.next(now)
        };
        let Some(output) = output else { return };
        // Internal writes retain every existing set_report descriptor/length/EP0
        // guard. Removing only this link prevents recursive self-invalidation.
        let original = self.receiver.take();
        let result = self.set_report(ReportType::Output, output.bytes[0], &output.bytes);
        self.receiver = original;
        if let Err(error) = &result {
            self.error.get_or_insert_with(|| error.clone());
        }
        // Recheck actual native ownership after the synchronous status stage.
        if self.admitted_receiver().is_err() {
            return;
        }
        let now = self.controller.borrow().clock.now_us();
        let mut group = link.group.borrow_mut();
        match result {
            Ok(()) => group.acknowledge(&output, now),
            Err(_) => {
                group.members[link.member].active = false;
                group.invalidate(Error::Transport);
            }
        }
    }
}
