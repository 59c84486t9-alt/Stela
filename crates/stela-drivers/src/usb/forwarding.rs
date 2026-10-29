// SPDX-License-Identifier: GPL-2.0-only
//! Native whole-device USB forwarding beneath a stock guest USB class stack.
//!
//! The topology owner alone constructs this owner after exclusive physical
//! claim. Descriptors remain the device's original bytes. No guest addresses,
//! USB/IP socket, application identity or synthetic class driver is involved.
//! Ordinary transfers use one bounded TD per endpoint. ISO requests queue bounded
//! packet lists on the native controller's service-interval scheduler;
//! primary streams inherit the native controller's explicit admission limits.
use super::xhci::{self, Endpoint, Interface, Shared};
use crate::{
    block::BlockError,
    bus::dma::{DmaAllocator, DmaBuffer},
};
use alloc::{collections::BTreeMap, vec::Vec};

mod configuration;
mod descriptors;
mod isochronous;
mod transfer;

/// A request identity belongs to one owner and is never reused in its lifetime.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Request(u64);

/// Hardware transfer result. Packet-level ISO faults are held.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Complete,
    Isochronous(xhci::IsoStatus),
    Failed(BlockError),
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Completion {
    pub request: Request,
    pub endpoint: u8,
    pub status: Status,
    /// None when the controller did not report a reliable byte count.
    pub actual: Option<usize>,
    /// IN data only, copied after hardware relinquishes the complete buffer.
    pub data: Vec<u8>,
    /// Empty for a single TD. A packet-list request keeps every packet,
    /// including short, missed-service, failed and cancelled intervals. Its IN
    /// payloads are in these records; `data` stays empty to preserve holes.
    pub packets: Vec<IsoPacketCompletion>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IsoPacketCompletion {
    pub offset: usize,
    pub requested: usize,
    pub actual: Option<usize>,
    pub status: Status,
    pub data: Vec<u8>,
}

enum Ticket {
    Normal(xhci::TransferTicket),
    Iso(xhci::IsoTransfer),
    Stream(xhci::StreamTransfer),
}
struct Pending {
    request: Request,
    ticket: Ticket,
    length: usize,
}
struct Pipe {
    endpoint: Endpoint,
    buffer: DmaBuffer,
    pending: Option<Pending>,
    streams: u16,
}

/// An exclusive physical leaf-device owner. Dropping this object cannot return
/// DMA to an allocator: the native allocator's buffers live for the whole boot.
/// Call shutdown to obtain acknowledged endpoint retirement before relinquishing
/// the topology claim. A failed retirement permanently fences this owner.
pub struct Device {
    controller: Shared,
    physical: xhci::Device,
    inventory: Vec<descriptors::Configuration>,
    configuration: u8,
    settings: Vec<(u8, u8)>,
    pipes: BTreeMap<u8, Pipe>,
    spare: BTreeMap<u8, DmaBuffer>,
    completed: Vec<Completion>,
    iso_requests: BTreeMap<Request, isochronous::IsoRequest>,
    iso_spare: Vec<DmaBuffer>,
    fenced: bool,
}

impl Device {
    /// Only the topology permission may call this after reserving the physical
    /// device and excluding all other native class owners, including EP0 users.
    pub(in crate::usb) fn claimed(
        controller: Shared,
        physical: xhci::Device,
    ) -> Result<Self, BlockError> {
        let inventory = descriptors::inventory(&physical)?;
        controller
            .borrow_mut()
            .device(physical.id)?
            .endpoint_ready(1)?;
        Ok(Self {
            controller,
            physical,
            inventory,
            configuration: 0,
            settings: Vec::new(),
            pipes: BTreeMap::new(),
            spare: BTreeMap::new(),
            completed: Vec::new(),
            iso_requests: BTreeMap::new(),
            iso_spare: Vec::new(),
            fenced: false,
        })
    }
    pub fn descriptors(&self) -> &xhci::Device {
        &self.physical
    }
    pub fn configuration(&self) -> Option<u8> {
        (!self.fenced).then_some(self.configuration)
    }
    pub fn alternate_settings(&self) -> Option<&[(u8, u8)]> {
        (!self.fenced).then_some(self.settings.as_slice())
    }
    pub fn fenced(&self) -> bool {
        self.fenced
    }
    fn validate_identity(&self) -> Result<(), BlockError> {
        self.controller
            .borrow()
            .validate_device_id(self.physical.id)
    }
    fn ready(&mut self) -> Result<(), BlockError> {
        self.validate_identity()?;
        if self.fenced {
            return Err(BlockError::Unsupported("forwarded USB owner is fenced"));
        }
        self.controller
            .borrow_mut()
            .device(self.physical.id)?
            .endpoint_ready(1)
    }

    /// Send an EP0 request. Requests that change host-managed USB state
    /// must use configure/set_interface/clear_halt so physical and host contexts
    /// cannot diverge. SET_ADDRESS and hub operations remain topology-owned.
    pub fn control(&mut self, request: [u8; 8], out: &[u8]) -> Result<Vec<u8>, BlockError> {
        self.ready()?;
        let kind = request[0] & 0x60;
        let recipient = request[0] & 0x1f;
        if kind == 0x60 || recipient > 2 {
            return Err(BlockError::Unsupported(
                "unsupported forwarded control recipient/type",
            ));
        }
        if kind == 0 && request[0] & 0x80 == 0 {
            return Err(BlockError::Unsupported(
                "standard USB state change requires managed operation",
            ));
        }
        let index = u16::from_le_bytes([request[4], request[5]]);
        if recipient == 1
            && ((kind == 0 && index > 255)
                || !self
                    .settings
                    .iter()
                    .any(|(number, _)| *number == index as u8))
        {
            return Err(BlockError::Unsupported(
                "control request names inactive USB interface",
            ));
        }
        if recipient == 2
            && ((kind == 0 && index > 255)
                || (!matches!(index as u8, 0 | 0x80) && !self.pipes.contains_key(&(index as u8))))
        {
            return Err(BlockError::Unsupported(
                "control request names inactive USB endpoint",
            ));
        }
        let length = usize::from(u16::from_le_bytes([request[6], request[7]]));
        if length > 4096
            || if request[0] & 0x80 != 0 {
                !out.is_empty()
            } else {
                out.len() != length
            }
        {
            return Err(BlockError::Unsupported(
                "invalid forwarded control data extent",
            ));
        }
        self.controller
            .borrow_mut()
            .device(self.physical.id)?
            .control(request, out)
    }

    pub fn clear_halt(&mut self, address: u8) -> Result<(), BlockError> {
        self.ready()?;
        let pipe = self
            .pipes
            .get(&address)
            .ok_or(BlockError::Unsupported("inactive USB endpoint"))?;
        if pipe.pending.is_some() || pipe.endpoint.kind() == 1 {
            return Err(BlockError::Unsupported(
                "halt clear requires idle non-isochronous endpoint",
            ));
        }
        self.controller
            .borrow_mut()
            .device(self.physical.id)?
            .clear(&pipe.endpoint)
    }

    /// Retire every owned endpoint through real controller acknowledgement.
    pub fn shutdown(&mut self) -> Result<(), BlockError> {
        self.ready()?;
        let addresses: Vec<u8> = self.pipes.keys().copied().collect();
        self.retire(&addresses)?;
        let result = self
            .controller
            .borrow_mut()
            .device(self.physical.id)?
            .control(xhci::setup(0, xhci::SET_CONFIGURATION, 0, 0, 0), &[]);
        self.fenced = true;
        result?;
        self.configuration = 0;
        self.settings.clear();
        Ok(())
    }
}

impl xhci::Host {
    /// Claim an enumerated, unbound physical leaf for whole-device
    /// forwarding. Native class claims and prior forwarding claims are refused
    /// by the topology/controller ledger before an owner is constructed.
    pub fn forward_device(&mut self, id: xhci::SlotId) -> Result<Device, BlockError> {
        let (controller, physical) = self.take_forwarding(id)?;
        Device::claimed(controller, physical)
    }
}

#[cfg(test)]
mod tests {
    mod native;
    use super::*;
    use crate::{bus::dma::RegionAllocator, usb::xhci::model};
    use alloc::{rc::Rc, vec};
    use core::cell::RefCell;

    fn configuration() -> Vec<u8> {
        vec![
            9, 2, 57, 0, 2, 19, 0, 0x80, 50, 9, 4, 3, 0, 2, 0xff, 0, 0, 0, 7, 5, 0x81, 3, 16, 0, 1,
            7, 5, 2, 2, 64, 0, 0, 9, 4, 7, 0, 0, 0xff, 0, 0, 0, 9, 4, 7, 2, 1, 0xff, 0, 0, 0, 7, 5,
            0x83, 3, 16, 0, 1,
        ]
    }
    fn owner(dma: &mut dyn DmaAllocator) -> (Device, Rc<RefCell<model::CancelModel>>) {
        owner_with_configuration(dma, configuration())
    }
    fn owner_with_configuration(
        dma: &mut dyn DmaAllocator,
        bytes: Vec<u8>,
    ) -> (Device, Rc<RefCell<model::CancelModel>>) {
        let configurations = vec![bytes];
        let (controller, model) =
            model::unconfigured_cancellation_controller_with_configurations(dma, &configurations);
        let mut physical = model::device(configurations);
        physical.id = controller.test_device_id(1).unwrap();
        let controller = Rc::new(RefCell::new(controller));
        (Device::claimed(controller, physical).unwrap(), model)
    }

    #[test]
    fn native_buffers_and_completions_preserve_short_in_and_out_requests() {
        let mut memory = vec![0u64; 512 * 1024];
        let start = memory.as_mut_ptr() as u64;
        // SAFETY: this model exclusively owns backing RAM until all owners drop.
        let mut dma = unsafe { RegionAllocator::new(start..start + memory.len() as u64 * 8) };
        let (mut owner, model) = owner(&mut dma);
        owner.configure(19, &mut dma).unwrap();
        assert_eq!(owner.configuration(), Some(19));
        assert_eq!(model.borrow().configuration_value, 19);
        let incoming = owner.submit(0x81, 0, 16, &[]).unwrap();
        assert!(owner.poll(incoming).unwrap().is_none());
        model.borrow_mut().push_event(vec![4, 5, 6]);
        let done = owner.poll(incoming).unwrap().unwrap();
        assert_eq!((done.actual, done.data), (Some(3), vec![4, 5, 6]));
        assert!(owner.poll(incoming).is_err());
        let outgoing = owner.submit(2, 0, 3, &[7, 8, 9]).unwrap();
        let done = owner.poll(outgoing).unwrap().unwrap();
        assert_eq!(done.actual, Some(3));
        assert!(done.data.is_empty());
        assert_eq!(model.borrow().outgoing, vec![vec![7, 8, 9]]);
    }

    #[test]
    fn changing_alternate_preserves_other_composite_interface_and_retires_old_requests() {
        let mut memory = vec![0u64; 512 * 1024];
        let start = memory.as_mut_ptr() as u64;
        // SAFETY: exclusive fixture RAM outlives the native controller and DMA.
        let mut dma = unsafe { RegionAllocator::new(start..start + memory.len() as u64 * 8) };
        let (mut owner, model) = owner(&mut dma);
        owner.configure(19, &mut dma).unwrap();
        let retained = owner.submit(0x81, 0, 16, &[]).unwrap();
        owner.set_interface(7, 2, &mut dma).unwrap();
        assert!(owner.poll(retained).unwrap().is_none());
        let old = owner.submit(0x83, 0, 16, &[]).unwrap();
        owner.set_interface(7, 0, &mut dma).unwrap();
        let done = owner.poll(old).unwrap().unwrap();
        assert_eq!((done.status, done.actual), (Status::Cancelled, None));
        assert!(!owner.pipes.contains_key(&0x83));
        assert!(owner.pipes.contains_key(&0x81));
        assert!(
            model
                .borrow()
                .setup
                .iter()
                .any(|(setup, _)| *setup == xhci::setup(1, xhci::SET_INTERFACE, 2, 7, 0))
        );
        owner.configure(19, &mut dma).unwrap();
        let done = owner.poll(retained).unwrap().unwrap();
        assert_eq!(done.status, Status::Cancelled);
        assert!(owner.take_completions().unwrap().is_empty());
    }

    #[test]
    fn failed_native_cancellation_keeps_request_buffer_and_fences_owner() {
        let mut memory = vec![0u64; 512 * 1024];
        let start = memory.as_mut_ptr() as u64;
        // SAFETY: exclusive fixture RAM remains live even after failed cancel.
        let mut dma = unsafe { RegionAllocator::new(start..start + memory.len() as u64 * 8) };
        let (mut owner, model) = owner(&mut dma);
        owner.configure(19, &mut dma).unwrap();
        let pending = owner.submit(0x81, 0, 16, &[]).unwrap();
        let physical = owner.pipes[&0x81].buffer.physical();
        model.borrow_mut().fail = Some((xhci::STOP_ENDPOINT, 19));
        assert!(owner.cancel(0x81).is_err());
        assert!(owner.fenced());
        assert_eq!(owner.pipes[&0x81].buffer.physical(), physical);
        assert!(
            owner.pipes[&0x81]
                .pending
                .as_ref()
                .is_some_and(|p| p.request == pending)
        );
        assert!(owner.take_completions().unwrap().is_empty());
        assert!(owner.submit(0x81, 0, 16, &[]).is_err());
        assert!(owner.configuration().is_none());
    }

    #[test]
    fn forwards_original_descriptors_and_class_entity_index_without_host_state_bypass() {
        let mut memory = vec![0u64; 512 * 1024];
        let start = memory.as_mut_ptr() as u64;
        // SAFETY: controller's modeled physical RAM is exclusive and boot-lived.
        let mut dma = unsafe { RegionAllocator::new(start..start + memory.len() as u64 * 8) };
        let (mut owner, model) = owner(&mut dma);
        let bytes = configuration();
        model.borrow_mut().descriptors.push((2, 0, bytes.clone()));
        let reply = owner
            .control(xhci::setup(0x80, 6, 0x200, 0, 57), &[])
            .unwrap();
        assert_eq!(reply, bytes);
        assert_eq!(owner.descriptors().configurations[0], bytes);
        assert!(owner.control(xhci::setup(0, 9, 19, 0, 0), &[]).is_err());
        owner.configure(19, &mut dma).unwrap();
        let request = xhci::setup(0xa1, 0x81, 0x100, 0x2303, 2);
        model
            .borrow_mut()
            .control_replies
            .push_back((request, vec![0x44, 0x55]));
        assert_eq!(owner.control(request, &[]).unwrap(), vec![0x44, 0x55]);
        assert!(
            owner
                .control(xhci::setup(0xa1, 0x81, 0x100, 0x2309, 2), &[])
                .is_err()
        );
        assert!(owner.submit(0x81, 1, 16, &[]).is_err());
        assert!(owner.submit(2, 0, 2, &[1]).is_err());
    }

    #[test]
    fn endpoint_status_reaches_native_ep0_before_and_after_configuration() {
        let mut memory = vec![0u64; 512 * 1024];
        let start = memory.as_mut_ptr() as u64;
        // SAFETY: exclusive fixture RAM outlives every controller transfer.
        let mut dma = unsafe { RegionAllocator::new(start..start + memory.len() as u64 * 8) };
        let (mut owner, model) = owner(&mut dma);
        for configured in [false, true] {
            if configured {
                owner.configure(19, &mut dma).unwrap();
            }
            // USB 2.0 9.3.4 ignores the direction bit for a control endpoint.
            // EP0 exists in Address state without a configured data pipe.
            for endpoint in [0, 0x80] {
                let request = xhci::setup(0x82, 0, 0, endpoint, 2);
                model
                    .borrow_mut()
                    .control_replies
                    .push_back((request, vec![0, 0]));
                let before = model.borrow().setup.len();
                assert_eq!(owner.control(request, &[]).unwrap(), vec![0, 0]);
                let hardware = model.borrow();
                assert_eq!(hardware.setup.len(), before + 1);
                assert_eq!(hardware.setup[before], (request, vec![0, 0]));
                assert!(hardware.control_replies.is_empty());
            }
            let before = model.borrow().setup.len();
            for endpoint in [0x10, 0x70, 0x90, 0x100, 0x180, 0x83] {
                assert!(
                    owner
                        .control(xhci::setup(0x82, 0, 0, endpoint, 2), &[])
                        .is_err()
                );
            }
            if !configured {
                assert!(
                    owner
                        .control(xhci::setup(0x82, 0, 0, 0x81, 2), &[])
                        .is_err()
                );
            }
            // Admitting EP0 must not open raw standard state changes.
            assert!(
                owner
                    .control(xhci::setup(2, xhci::CLEAR_FEATURE, 0, 0, 0), &[])
                    .is_err()
            );
            assert_eq!(model.borrow().setup.len(), before);
        }
        let request = xhci::setup(0x82, 0, 0, 0x81, 2);
        model
            .borrow_mut()
            .control_replies
            .push_back((request, vec![1, 0]));
        assert_eq!(owner.control(request, &[]).unwrap(), vec![1, 0]);
        assert!(model.borrow().control_replies.is_empty());
    }
    #[test]
    fn single_alternate_stall_uses_real_endpoint_clear_requests() {
        let mut memory = vec![0u64; 512 * 1024];
        let start = memory.as_mut_ptr() as u64;
        // SAFETY: exclusive fixture RAM remains live through all native ACKs.
        let mut dma = unsafe { RegionAllocator::new(start..start + memory.len() as u64 * 8) };
        let mut bytes = configuration();
        bytes.truncate(32);
        bytes[2] = 32;
        bytes[4] = 1;
        let (mut owner, model) = owner_with_configuration(&mut dma, bytes);
        owner.configure(19, &mut dma).unwrap();
        model.borrow_mut().stall_control = Some(xhci::SET_INTERFACE);
        owner.set_interface(3, 0, &mut dma).unwrap();
        assert!(!owner.fenced());
        for endpoint in [0x81, 2] {
            assert!(model.borrow().setup.iter().any(
                |(request, _)| *request == xhci::setup(2, xhci::CLEAR_FEATURE, 0, endpoint, 0)
            ));
        }
    }
}
