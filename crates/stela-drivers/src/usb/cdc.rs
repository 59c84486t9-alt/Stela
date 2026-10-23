// SPDX-License-Identifier: MIT AND GPL-2.0-only
// NCM mode negotiation adapted from Linux cdc_ncm.c:
// Copyright (C) ST-Ericsson 2010-2012
// Original author: Hans Petter Selasky <hans.petter.selasky@stericsson.com>
//! USB CDC Ethernet adapters as host network links: the Ethernet Control
//! Model (CDC ECM 1.2) and the Network Control Model (CDC NCM 1.0), the two
//! standard USB Ethernet classes.
//!
//! The communications interface (class 2, subclass 6 for ECM or 0x0d for
//! NCM) names its data interface in its Union descriptor and its station
//! address in the Ethernet Networking descriptor's iMACAddress string.
//! Attach configures the data interface's alternate setting with two bulk
//! endpoints, selects it (SET_INTERFACE), and sets the packet filter to
//! directed, broadcast and all-multicast frames (ECM 6.2.4; NCM only when
//! its functional descriptor's bmNetworkCapabilities offers the request).
//!
//! ECM moves one frame per bulk transfer: each received frame is one bulk
//! IN transfer ended by a short packet (3.3.1); each sent frame is one bulk
//! OUT transfer. NCM moves transfer blocks (`ntb`): while the data
//! interface is still at alternate setting 0, attach reads the function's
//! NTB parameters (GetNtbParameters), selects CRC-off and NTB16 when those
//! controls are supported, and caps its IN blocks at
//! [`NCM_IN_BLOCK`] bytes (SetNtbInputSize); each IN block may carry several
//! frames, and each sent frame is one OUT block. Either way a transfer that
//! is a multiple of the endpoint's packet size is followed by a zero-length
//! packet, except an NCM block of exactly the function's largest OUT size.
//! NetworkConnection notifications on the interrupt endpoint set the
//! carrier (ECM 6.3.1, and alike in NCM); until one arrives the link is
//! taken to be up. Frames above the 1514-byte Ethernet maximum are refused.
mod ntb;

use super::xhci::{
    DEVICE_TO_HOST, Device, Endpoint, Interface, Plan, RECIPIENT_INTERFACE, SET_INTERFACE, Shared,
    TYPE_CLASS, setup,
};
use crate::{
    block::BlockError,
    bus::dma::{DmaAllocator, DmaBuffer},
    net::{Link, LinkError, MAX_FRAME, Mac},
};
use alloc::{collections::VecDeque, format, string::String, vec::Vec};

pub const COMMUNICATIONS: u8 = 2;
/// The Ethernet Control Model subclass.
pub const ECM: u8 = 6;
/// The Network Control Model subclass.
pub const NCM: u8 = 0x0d;
/// Class requests and notifications address the communications interface.
const CLASS_INTERFACE: u8 = TYPE_CLASS | RECIPIENT_INTERFACE;
pub(crate) const DATA_CLASS: u8 = 10;
const CS_INTERFACE: u8 = 0x24;
const UNION: u8 = 0x06;
const ETHERNET: u8 = 0x0f;
/// The NCM functional descriptor's subtype.
const NCM_FUNCTIONAL: u8 = 0x1a;
/// bmNetworkCapabilities: SetEthernetPacketFilter is supported.
const NCM_PACKET_FILTER: u8 = 1 << 0;
/// bmNetworkCapabilities: CRC mode can be selected.
const NCM_CRC_MODE: u8 = 1 << 4;
/// bmNetworkCapabilities: SetNtbInputSize takes 8 bytes, the size and
/// wNtbInMaxDatagrams.
const NCM_INPUT_SIZE_8: u8 = 1 << 5;
const SET_ETHERNET_PACKET_FILTER: u8 = 0x43;
const GET_NTB_PARAMETERS: u8 = 0x80;
const SET_NTB_FORMAT: u8 = 0x84;
const SET_NTB_INPUT_SIZE: u8 = 0x86;
const SET_CRC_MODE: u8 = 0x8a;
const NTB16_FORMAT: u16 = 0;
const CRC_NOT_APPENDED: u16 = 0;
/// Directed, broadcast and all-multicast frames.
const FILTER: u16 = 0x04 | 0x08 | 0x02;
const NETWORK_CONNECTION: u8 = 0x00;
/// An ECM frame's DMA buffer.
const FRAME_BYTES: usize = 2048;
/// The largest NCM IN block this driver takes: room for ten full frames.
pub const NCM_IN_BLOCK: usize = 16 * 1024;
const SEND_US: u64 = 1_000_000;

/// The CDC Ethernet model an adapter speaks.
#[derive(Clone, Copy, Debug)]
enum Model {
    Ecm,
    /// With its functional descriptor's bmNetworkCapabilities.
    Ncm(u8),
}

/// How frames travel on the data interface.
enum Framing {
    Ecm,
    /// NTB16 blocks, with the next OUT block's wSequence.
    Ncm(ntb::Parameters, u16),
}

/// The interfaces and endpoints one adapter uses.
#[derive(Clone, Debug)]
pub struct Binding {
    model: Model,
    control: u8,
    data: u8,
    alternate: u8,
    mac_string: u8,
    input: Endpoint,
    output: Endpoint,
    notify: Option<Endpoint>,
}

impl Binding {
    /// The data interface and alternate setting selected by this binding.
    pub(super) fn data_setting(&self) -> (u8, u8) {
        (self.data, self.alternate)
    }

    pub(super) fn endpoints(&self) -> Vec<Endpoint> {
        let mut endpoints = alloc::vec![self.input, self.output];
        endpoints.extend(self.notify);
        endpoints
    }
}

pub(super) fn plan(interface: &Interface, all: &[Interface]) -> Result<Plan, &'static str> {
    let descriptor = |kind: u8, bytes: usize| {
        interface
            .extra
            .iter()
            .find(|d| d.len() >= bytes && d[1] == CS_INTERFACE && d[2] == kind)
    };
    let model = match interface.subclass {
        ECM => Model::Ecm,
        NCM => Model::Ncm(
            descriptor(NCM_FUNCTIONAL, 6)
                .ok_or("NCM interface without its functional descriptor")?[5],
        ),
        _ => return Err("not a CDC Ethernet interface"),
    };
    let union = descriptor(UNION, 5).ok_or("CDC Ethernet interface without a Union descriptor")?;
    let ethernet = descriptor(ETHERNET, 13)
        .ok_or("CDC Ethernet interface without an Ethernet Networking descriptor")?;
    let data = union[4];
    let setting = all
        .iter()
        .find(|i| i.number == data && i.class == DATA_CLASS && i.endpoints.len() >= 2)
        .ok_or("CDC Ethernet data interface without a bulk setting")?;
    let bulk = |is_in: bool| {
        setting
            .endpoints
            .iter()
            .copied()
            .find(|e| e.kind() == 2 && e.is_in() == is_in)
    };
    let (Some(input), Some(output)) = (bulk(true), bulk(false)) else {
        return Err("CDC Ethernet data interface without two bulk endpoints");
    };
    let notify = interface
        .endpoints
        .iter()
        .copied()
        .find(|e| e.kind() == 3 && e.is_in());
    Ok(Plan::Ethernet(Binding {
        model,
        control: interface.number,
        data,
        alternate: setting.alternate,
        mac_string: ethernet[3],
        input,
        output,
        notify,
    }))
}

fn parse_mac(text: &str) -> Option<Mac> {
    if text.len() != 12 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (n, byte) in mac.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(2 * n..2 * n + 2)?, 16).ok()?;
    }
    Some(Mac(mac))
}

pub struct UsbNet {
    controller: Shared,
    slot: u8,
    binding: Binding,
    framing: Framing,
    mac: Mac,
    receive: DmaBuffer,
    /// The received frames of an NCM block not yet taken.
    pending: VecDeque<Vec<u8>>,
    send: DmaBuffer,
    status: DmaBuffer,
    queued: Option<u64>,
    notify_queued: Option<u64>,
    connected: Option<bool>,
    pub location: String,
}

impl UsbNet {
    pub(super) fn new(
        controller: Shared,
        device: &Device,
        binding: Binding,
        dma: &mut dyn DmaAllocator,
    ) -> Result<Self, BlockError> {
        let (mac, framing) = {
            let mut c = controller.borrow_mut();
            let text = device
                .language
                .and_then(|language| c.string(device.slot, language, binding.mac_string))
                .ok_or(BlockError::Unsupported(
                    "CDC Ethernet adapter without a MAC address string",
                ))?;
            let mac = parse_mac(&text)
                .ok_or(BlockError::Unsupported("CDC Ethernet MAC address string"))?;
            let control = u16::from(binding.control);
            // NCM's mode and size requests precede the data setting.
            let framing = match binding.model {
                Model::Ecm => Framing::Ecm,
                Model::Ncm(capabilities) => {
                    let request = setup(
                        DEVICE_TO_HOST | CLASS_INTERFACE,
                        GET_NTB_PARAMETERS,
                        0,
                        control,
                        ntb::PARAMETER_BYTES as u16,
                    );
                    let reply = c.control(device.slot, request, &[])?;
                    let mut parameters =
                        ntb::Parameters::parse(&reply).map_err(BlockError::Unsupported)?;
                    if capabilities & NCM_CRC_MODE != 0 {
                        let request =
                            setup(CLASS_INTERFACE, SET_CRC_MODE, CRC_NOT_APPENDED, control, 0);
                        c.control(device.slot, request, &[])?;
                    }
                    // NTB16 is the reset default. Like Linux cdc_ncm_init,
                    // explicitly select it when both formats are offered.
                    if parameters.supports_ntb32 {
                        let request =
                            setup(CLASS_INTERFACE, SET_NTB_FORMAT, NTB16_FORMAT, control, 0);
                        c.control(device.slot, request, &[])?;
                    }
                    if parameters.in_max > NCM_IN_BLOCK {
                        parameters.in_max = NCM_IN_BLOCK;
                        let mut size = (NCM_IN_BLOCK as u32).to_le_bytes().to_vec();
                        if capabilities & NCM_INPUT_SIZE_8 != 0 {
                            // wNtbInMaxDatagrams 0: no limit.
                            size.extend_from_slice(&[0; 4]);
                        }
                        let request = setup(
                            CLASS_INTERFACE,
                            SET_NTB_INPUT_SIZE,
                            0,
                            control,
                            size.len() as u16,
                        );
                        c.control(device.slot, request, &size)?;
                    }
                    Framing::Ncm(parameters, 0)
                }
            };
            (mac, framing)
        };
        let (receive_bytes, send_bytes) = match &framing {
            Framing::Ecm => (FRAME_BYTES, FRAME_BYTES),
            Framing::Ncm(parameters, _) => (
                parameters.in_max,
                parameters
                    .encoded_len(MAX_FRAME)
                    .ok_or(BlockError::Unsupported(
                        "NCM OUT parameters cannot fit the maximum Ethernet frame",
                    ))?,
            ),
        };
        // Both one-TD buffers must stay inside one 64 KiB xHCI window. The
        // validated NTB16 OUT size is below 64 KiB, and IN is capped at 16 KiB;
        // next-power-of-two alignment therefore contains every transfer.
        let receive_align = receive_bytes
            .checked_next_power_of_two()
            .ok_or(BlockError::NoDmaMemory)?;
        let send_align = send_bytes
            .checked_next_power_of_two()
            .ok_or(BlockError::NoDmaMemory)?;
        let receive = dma.allocate(receive_bytes, receive_align)?;
        let send = dma.allocate(send_bytes, send_align)?;
        let status = dma.allocate(64, 64)?;
        // Do not activate the data setting if any bounded DMA allocation failed.
        {
            let mut c = controller.borrow_mut();
            let control = u16::from(binding.control);
            if binding.alternate != 0 {
                let request = setup(
                    1,
                    SET_INTERFACE,
                    u16::from(binding.alternate),
                    u16::from(binding.data),
                    0,
                );
                c.control(device.slot, request, &[])?;
            }
            let filter = match binding.model {
                Model::Ecm => true,
                Model::Ncm(capabilities) => capabilities & NCM_PACKET_FILTER != 0,
            };
            if filter {
                let request = setup(
                    CLASS_INTERFACE,
                    SET_ETHERNET_PACKET_FILTER,
                    FILTER,
                    control,
                    0,
                );
                c.control(device.slot, request, &[])?;
            }
        }
        Ok(Self {
            controller,
            slot: device.slot,
            binding,
            framing,
            mac,
            receive,
            pending: VecDeque::new(),
            send,
            status,
            queued: None,
            notify_queued: None,
            connected: None,
            location: format!("{} ({})", device.location, device.name()),
        })
    }

    /// Takes any NetworkConnection notifications that arrived.
    fn notifications(&mut self) {
        let Some(notify) = self.binding.notify else {
            return;
        };
        let length = usize::from(notify.max_packet & 0x7ff).min(64);
        for _ in 0..4 {
            let mut c = self.controller.borrow_mut();
            let trb = match self.notify_queued {
                Some(trb) => trb,
                None => match c.submit(self.slot, notify.dci(), self.status.physical(), length) {
                    Ok(trb) => {
                        self.notify_queued = Some(trb);
                        trb
                    }
                    Err(_) => return,
                },
            };
            let Some(result) = c.completed(self.slot, notify.dci(), trb, length) else {
                return;
            };
            self.notify_queued = None;
            if let Ok(bytes) = result
                && bytes >= 8
            {
                let header = &self.status.bytes()[..8];
                if header[0] == DEVICE_TO_HOST | CLASS_INTERFACE && header[1] == NETWORK_CONNECTION
                {
                    self.connected = Some(header[2] != 0);
                }
            }
        }
    }
}

fn link_error(error: BlockError) -> LinkError {
    LinkError::Adapter(format!("USB Ethernet: {error}"))
}

impl Link for UsbNet {
    fn mac(&self) -> Mac {
        self.mac
    }

    fn carrier(&mut self) -> bool {
        self.notifications();
        self.connected.unwrap_or(true)
    }

    fn transmit(&mut self, frame: &[u8]) -> Result<(), LinkError> {
        // A previous failed cancellation may still own this OUT buffer.
        self.controller
            .borrow_mut()
            .endpoint_ready(self.slot, self.binding.output.dci())
            .map_err(link_error)?;
        if frame.len() > MAX_FRAME {
            return Err(LinkError::Adapter(String::from(
                "frame above the Ethernet maximum",
            )));
        }
        // The length of the one OUT transfer, and the NCM block size that
        // needs no zero-length packet after it.
        let (length, whole) = match &mut self.framing {
            Framing::Ecm => {
                self.send.bytes_mut()[..frame.len()].copy_from_slice(frame);
                (frame.len(), None)
            }
            Framing::Ncm(parameters, sequence) => {
                let block = parameters
                    .encode(*sequence, frame)
                    .filter(|block| block.len() <= self.send.len())
                    .ok_or_else(|| {
                        LinkError::Adapter(String::from("frame above the NCM OUT block size"))
                    })?;
                *sequence = sequence.wrapping_add(1);
                self.send.bytes_mut()[..block.len()].copy_from_slice(&block);
                (block.len(), Some(parameters.out_max))
            }
        };
        let output = self.binding.output;
        let mut c = self.controller.borrow_mut();
        let physical = self.send.physical();
        let sent = c
            .transfer(self.slot, output.dci(), physical, length, SEND_US)
            .map_err(link_error)?;
        if sent != length {
            return Err(LinkError::Adapter(String::from(
                "short USB Ethernet OUT transfer",
            )));
        }
        let packet = usize::from(output.max_packet & 0x7ff).max(1);
        if length.is_multiple_of(packet) && whole != Some(length) {
            c.transfer(self.slot, output.dci(), physical, 0, SEND_US)
                .map_err(link_error)?;
        }
        Ok(())
    }

    fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
        if let Some(frame) = self.pending.pop_front() {
            return Ok(Some(frame));
        }
        let input = self.binding.input;
        let capacity = self.receive.bytes().len();
        let mut c = self.controller.borrow_mut();
        let trb = match self.queued {
            Some(trb) => trb,
            None => {
                let trb = c
                    .submit(self.slot, input.dci(), self.receive.physical(), capacity)
                    .map_err(link_error)?;
                self.queued = Some(trb);
                trb
            }
        };
        let Some(result) = c.completed(self.slot, input.dci(), trb, capacity) else {
            return Ok(None);
        };
        self.queued = None;
        let bytes = match result {
            Ok(bytes) => &self.receive.bytes()[..bytes],
            Err(error) => {
                let _ = c.clear(self.slot, &input);
                return Err(link_error(error));
            }
        };
        // A malformed block, like an oversized frame, is dropped as a NIC
        // drops a frame that fails its checks.
        let frames = match self.framing {
            Framing::Ecm => alloc::vec![bytes],
            Framing::Ncm(..) => ntb::decode(bytes).unwrap_or_default(),
        };
        self.pending.extend(
            frames
                .into_iter()
                .filter(|frame| !frame.is_empty() && frame.len() <= MAX_FRAME)
                .map(<[u8]>::to_vec),
        );
        Ok(self.pending.pop_front())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usb::cdc;
    use crate::usb::xhci::{model, model::*, *};
    use alloc::rc::Rc;
    use core::cell::RefCell;

    #[test]
    fn mac_strings_parse_as_twelve_hex_digits() {
        assert_eq!(
            parse_mac("02535400AB01"),
            Some(Mac([2, 0x53, 0x54, 0, 0xab, 1]))
        );
        assert_eq!(parse_mac("0253540"), None);
        assert_eq!(parse_mac("02535400AB0G"), None);
    }

    #[test]
    fn poisoned_output_refuses_to_rewrite_the_active_dma_buffer() {
        use crate::bus::dma::RegionAllocator;
        for halted in [false, true] {
            let mut backing = vec![0u64; 64 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: backing outlives the controller/model and every DMA buffer.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let mut send = dma.allocate(FRAME_BYTES, FRAME_BYTES).unwrap();
            send.bytes_mut().fill(0xa5);
            let controller = super::super::xhci::model::controller_with_unresolved_td(
                &mut dma,
                send.physical(),
                send.len(),
                4,
                halted,
            );
            let input = Endpoint {
                address: 0x82,
                attributes: 2,
                max_packet: 64,
                interval: 0,
                companion: None,
            };
            let output = Endpoint {
                address: 0x02,
                attributes: 2,
                max_packet: 64,
                interval: 0,
                companion: None,
            };
            let mut net = UsbNet {
                controller,
                slot: 1,
                binding: Binding {
                    model: Model::Ecm,
                    control: 0,
                    data: 1,
                    alternate: 0,
                    mac_string: 1,
                    input,
                    output,
                    notify: None,
                },
                framing: Framing::Ecm,
                mac: Mac([2, 0, 0, 0, 0, 1]),
                receive: dma.allocate(FRAME_BYTES, FRAME_BYTES).unwrap(),
                pending: VecDeque::new(),
                send,
                status: dma.allocate(64, 64).unwrap(),
                queued: None,
                notify_queued: None,
                connected: None,
                location: "poisoned model CDC".into(),
            };
            assert!(net.transmit(&[1, 2, 3]).is_err());
            // The model deliberately leaves this TD hardware-owned but performs no
            // DMA while the test reads its sentinel; production never reads it here.
            assert!(net.send.bytes().iter().all(|byte| *byte == 0xa5));
        }
    }

    fn cdc_device(controller: &Shared, ncm: Option<u8>) -> Device {
        let mut bytes = model::ecm(42);
        if let Some(capabilities) = ncm {
            bytes[15] = cdc::NCM;
            bytes.splice(18..18, [6, 0x24, 0x1a, 0, 1, capabilities]);
        }
        let mut at = 0;
        while at < bytes.len() {
            let length = usize::from(bytes[at]);
            if bytes[at + 1] == ENDPOINT_DESCRIPTOR {
                // Reuse the model's actual event/ACL receive queues as the
                // CDC notification and data endpoints, respectively.
                if bytes[at + 3] & 3 == 3 {
                    bytes[at + 2] = 0x81;
                } else if bytes[at + 2] & 0x80 != 0 {
                    bytes[at + 2] = 0x82;
                }
            }
            at += length;
        }
        let total = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&total.to_le_bytes());
        model::sanitize(&bytes, SUPER_SPEED).unwrap();
        let mut device = model::addressed_device(&controller.borrow(), vec![bytes]);
        device.language = Some(LANGUAGE_EN_US);
        model::select(&mut device).unwrap();
        device
    }

    #[test]
    fn native_cdc_binding_requires_its_own_addressed_generation() {
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: backing outlives both controllers and every class DMA object.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let configurations = [vec![9, 2, 9, 0, 0, 42, 0, 0x80, 50]];
        let (first, hardware) =
            unconfigured_cancellation_controller_with_configurations(&mut dma, &configurations);
        let (second, other_hardware) =
            unconfigured_cancellation_controller_with_configurations(&mut dma, &configurations);
        hardware.borrow_mut().descriptors = vec![(STRING_DESCRIPTOR, 1, cdc_mac_descriptor())];
        let first = Rc::new(RefCell::new(first));
        let second = Rc::new(RefCell::new(second));
        let device = cdc_device(&first, None);
        let foreign = cdc_device(&second, None);
        assert_eq!(device.slot, foreign.slot);
        assert_ne!(device.id, foreign.id);
        for id in [SlotId::fixture(device.slot), foreign.id] {
            let mut rejected = device.clone();
            rejected.id = id;
            let mut found = Found::default();
            bind(&first, rejected, &mut dma, &mut found);
            assert!(found.links.is_empty());
            assert_eq!(found.failures.len(), 1);
            assert_eq!(
                found.failures[0].1,
                BlockError::Unsupported("xHCI device generation is permanently retired")
            );
            // Neither the class request path nor Configure Endpoint may be
            // entered by a descriptor-only or another controller's identity.
            assert!(hardware.borrow().setup.is_empty());
            assert!(hardware.borrow().seen.is_empty());
            assert!(
                hardware
                    .borrow()
                    .configuration_seen_before_endpoints
                    .is_empty()
            );
            assert!(other_hardware.borrow().setup.is_empty());
            assert!(other_hardware.borrow().seen.is_empty());
        }
        // Refusal did not consume the genuine native claim. The exact device
        // still binds through the real EP0 and endpoint DMA submission path.
        let mut found = Found::default();
        bind(&first, device, &mut dma, &mut found);
        assert!(found.failures.is_empty(), "{:?}", found.failures);
        assert_eq!(found.links.len(), 1);
        assert_eq!(hardware.borrow().configuration_seen_before_endpoints, [42]);
        assert_eq!(
            hardware.borrow().setup[0].0,
            setup(0, SET_CONFIGURATION, 42, 0, 0)
        );
        assert!(hardware.borrow().seen.contains(&CONFIGURE_ENDPOINT));
    }

    fn cdc_mac_descriptor() -> Vec<u8> {
        let mut bytes = vec![26, STRING_DESCRIPTOR];
        for unit in "025354000001".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes
    }

    fn ncm_parameters() -> Vec<u8> {
        let mut bytes = vec![0; 28];
        bytes[..2].copy_from_slice(&28u16.to_le_bytes());
        bytes[2..4].copy_from_slice(&1u16.to_le_bytes());
        bytes[4..8].copy_from_slice(&32768u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&2048u32.to_le_bytes());
        bytes[20..22].copy_from_slice(&8u16.to_le_bytes());
        // Ethernet payload (14 bytes after its frame start) is 8-byte aligned.
        // The resulting frame start at 34 makes a 30-byte frame a 64-byte NTB.
        bytes[22..24].copy_from_slice(&0u16.to_le_bytes());
        bytes[24..26].copy_from_slice(&8u16.to_le_bytes());
        bytes
    }

    struct CdcDma<'a> {
        inner: &'a mut dyn DmaAllocator,
        fail: Option<(usize, usize)>,
        requests: Vec<(usize, usize)>,
    }

    impl DmaAllocator for CdcDma<'_> {
        fn allocate(&mut self, bytes: usize, align: usize) -> Result<DmaBuffer, BlockError> {
            self.requests.push((bytes, align));
            if self.fail == Some((bytes, align)) {
                return Err(BlockError::NoDmaMemory);
            }
            self.inner.allocate(bytes, align)
        }
    }

    #[test]
    fn padded_ncm_full_frames_use_capacity_sized_non_crossing_real_tds() {
        use crate::net::{Link, MAX_FRAME};
        for (divisor, remainder, alignment, out_max, expected) in [
            (2048u16, 0u16, 4u16, 8192u32, 3548usize),
            (2048, 0, 2048, 8192, 5596),
            // An exact maximum block must not get an extra terminating ZLP.
            (2048, 548, 2048, 4096, 4096),
            (32768, 31267, 32768, 65535, 65535),
        ] {
            let mut backing = vec![0u64; 128 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: backing outlives all modeled controller/class DMA.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (controller, model) = unconfigured_cancellation_controller_with_configurations(
                &mut dma,
                &[vec![9, 2, 9, 0, 0, 42, 0, 0x80, 50]],
            );
            model.borrow_mut().descriptors = vec![(STRING_DESCRIPTOR, 1, cdc_mac_descriptor())];
            let mut parameters = ncm_parameters();
            parameters[16..20].copy_from_slice(&out_max.to_le_bytes());
            parameters[20..22].copy_from_slice(&divisor.to_le_bytes());
            parameters[22..24].copy_from_slice(&remainder.to_le_bytes());
            parameters[24..26].copy_from_slice(&alignment.to_le_bytes());
            model
                .borrow_mut()
                .control_replies
                .push_back((setup(0xa1, 0x80, 0, 0, 28), parameters));
            let shared = Rc::new(RefCell::new(controller));
            let mut found = Found::default();
            bind(&shared, cdc_device(&shared, Some(1)), &mut dma, &mut found);
            assert!(found.failures.is_empty(), "{:?}", found.failures);
            assert_eq!(found.links.len(), 1);
            let frame: Vec<_> = (0..MAX_FRAME).map(|byte| byte as u8).collect();
            let link = &mut found.links[0];
            link.transmit(&frame).unwrap();
            assert_eq!(model.borrow().outgoing.len(), 1);
            let model_ref = model.borrow();
            let block = &model_ref.outgoing[0];
            assert_eq!(block.len(), expected);
            assert_eq!(
                u16::from_le_bytes(block[8..10].try_into().unwrap()) as usize,
                expected
            );
            let table = usize::from(u16::from_le_bytes(block[10..12].try_into().unwrap()));
            assert_eq!(table % usize::from(alignment), 0);
            let datagram = usize::from(u16::from_le_bytes(
                block[table + 8..table + 10].try_into().unwrap(),
            ));
            assert_eq!(
                (datagram + 14) % usize::from(divisor),
                usize::from(remainder)
            );
            assert_eq!(&block[datagram..], frame);
            let trb = model_ref.rings[4];
            // SAFETY: the actual published OUT TRB remains in the live model
            // ring; its referenced allocation is still retained by the link.
            let (physical, length) = unsafe {
                (
                    (trb as *const u64).read_volatile(),
                    ((trb + 8) as *const u32).read_volatile() as usize & 0x1ffff,
                )
            };
            assert_eq!(length, expected);
            assert_eq!(physical % expected.next_power_of_two() as u64, 0);
            assert!(physical % 65536 + length as u64 <= 65536);
            drop(model_ref);
            assert_eq!(link.receive().unwrap(), None);
            let (_, physical, length) = model.borrow().active[5].unwrap();
            assert_eq!(length, 16384);
            assert_eq!(physical % 16384, 0);
            assert!(physical % 65536 + length as u64 <= 65536);
        }
    }

    #[test]
    fn ncm_dma_failures_and_unrepresentable_full_frames_never_activate_data() {
        for failure in 0..5 {
            let mut backing = vec![0u64; 128 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: backing outlives all modeled controller/class DMA.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (controller, model) = unconfigured_cancellation_controller_with_configurations(
                &mut dma,
                &[vec![9, 2, 9, 0, 0, 42, 0, 0x80, 50]],
            );
            model.borrow_mut().descriptors = vec![(STRING_DESCRIPTOR, 1, cdc_mac_descriptor())];
            let mut parameters = ncm_parameters();
            parameters[16..20].copy_from_slice(&8192u32.to_le_bytes());
            parameters[20..22].copy_from_slice(&2048u16.to_le_bytes());
            let fail = match failure {
                0 => Some((16384, 16384)),
                1 => Some((3548, 4096)),
                2 => Some((64, 64)),
                3 => {
                    parameters[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
                    parameters[20..22].copy_from_slice(&32768u16.to_le_bytes());
                    parameters[22..24].copy_from_slice(&31268u16.to_le_bytes());
                    parameters[24..26].copy_from_slice(&32768u16.to_le_bytes());
                    None
                }
                4 => {
                    parameters[16..20].copy_from_slice(&3547u32.to_le_bytes());
                    None
                }
                _ => unreachable!(),
            };
            model
                .borrow_mut()
                .control_replies
                .push_back((setup(0xa1, 0x80, 0, 0, 28), parameters));
            let shared = Rc::new(RefCell::new(controller));
            let mut found = Found::default();
            let mut checked = CdcDma {
                inner: &mut dma,
                fail,
                requests: Vec::new(),
            };
            bind(
                &shared,
                cdc_device(&shared, Some(1)),
                &mut checked,
                &mut found,
            );
            assert!(found.links.is_empty());
            assert_eq!(found.failures.len(), 1);
            if let Some(request) = fail {
                assert!(checked.requests.contains(&request));
                assert_eq!(found.failures[0].1, BlockError::NoDmaMemory);
            } else {
                assert_eq!(
                    found.failures[0].1,
                    BlockError::Unsupported(
                        "NCM OUT parameters cannot fit the maximum Ethernet frame"
                    )
                );
                assert!(
                    checked
                        .requests
                        .iter()
                        .all(|request| *request == (RING_TRBS * TRB, RING_TRBS * TRB))
                );
            }
            assert!(
                !model
                    .borrow()
                    .setup
                    .iter()
                    .any(|(request, _)| matches!(request[1], SET_INTERFACE | 0x43))
            );
            // Every failure must reach the actual NCM response; an earlier
            // binding refusal is not evidence for DMA or frame-size handling.
            assert!(model.borrow().control_replies.is_empty());
            assert!(
                model
                    .borrow()
                    .setup
                    .iter()
                    .any(|(request, _)| *request == setup(0xa1, 0x80, 0, 0, 28))
            );
            assert!(model.borrow().outgoing.is_empty());
            assert!(model.borrow().active[5].is_none());
        }
    }

    #[test]
    fn cdc_short_bulk_out_is_an_error_and_never_sends_a_terminating_zlp() {
        use crate::net::Link;
        for ncm in [None, Some(1)] {
            let mut backing = vec![0u64; 128 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: backing outlives all modeled controller/class DMA.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (controller, model) = unconfigured_cancellation_controller_with_configurations(
                &mut dma,
                &[vec![9, 2, 9, 0, 0, 42, 0, 0x80, 50]],
            );
            model.borrow_mut().descriptors = vec![(STRING_DESCRIPTOR, 1, cdc_mac_descriptor())];
            if ncm.is_some() {
                model
                    .borrow_mut()
                    .control_replies
                    .push_back((setup(0xa1, 0x80, 0, 0, 28), ncm_parameters()));
            }
            let shared = Rc::new(RefCell::new(controller));
            let mut found = Found::default();
            bind(&shared, cdc_device(&shared, ncm), &mut dma, &mut found);
            assert!(found.failures.is_empty(), "{:?}", found.failures);
            assert_eq!(found.links.len(), 1);
            let link = &mut found.links[0];
            let frame = vec![0x5a; if ncm.is_some() { 30 } else { 64 }];
            model.borrow_mut().short_bulk_out = true;
            assert!(link.transmit(&frame).is_err());
            assert_eq!(model.borrow().outgoing.len(), 1);
            assert_eq!(model.borrow().outgoing[0].len(), 64);
            model.borrow_mut().short_bulk_out = false;
            link.transmit(&frame).unwrap();
            assert_eq!(model.borrow().outgoing.len(), 3);
            assert_eq!(model.borrow().outgoing[1].len(), 64);
            assert!(model.borrow().outgoing[2].is_empty());
        }
    }

    #[test]
    fn ncm_binding_negotiates_before_alt_setting_and_moves_real_transfer_blocks() {
        use crate::net::{Link, Mac};
        let cases = [0, 1, 0x10, 0x11, 0x20, 0x21, 0x30, 0x31]
            .into_iter()
            .flat_map(|capabilities| {
                [1u16, 3].into_iter().flat_map(move |formats| {
                    [16384u32, 32768]
                        .into_iter()
                        .map(move |in_max| (capabilities, formats, in_max))
                })
            });
        for (capabilities, formats, in_max) in cases {
            let mut backing = vec![0u64; 128 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: backing outlives all modeled controller/class DMA.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (controller, model) = unconfigured_cancellation_controller_with_configurations(
                &mut dma,
                &[vec![9, 2, 9, 0, 0, 42, 0, 0x80, 50]],
            );
            model.borrow_mut().descriptors = vec![(STRING_DESCRIPTOR, 1, cdc_mac_descriptor())];
            let mut parameters = ncm_parameters();
            parameters[2..4].copy_from_slice(&formats.to_le_bytes());
            parameters[4..8].copy_from_slice(&in_max.to_le_bytes());
            model
                .borrow_mut()
                .control_replies
                .push_back((setup(0xa1, 0x80, 0, 0, 28), parameters));
            let shared = Rc::new(RefCell::new(controller));
            let mut found = Found::default();
            bind(
                &shared,
                cdc_device(&shared, Some(capabilities)),
                &mut dma,
                &mut found,
            );
            assert!(found.failures.is_empty(), "{:?}", found.failures);
            assert_eq!(found.links.len(), 1);
            let mut expected = vec![
                setup(0, SET_CONFIGURATION, 42, 0, 0),
                setup(0x80, GET_DESCRIPTOR, 0x301, LANGUAGE_EN_US, 255),
                setup(0xa1, 0x80, 0, 0, 28),
            ];
            if capabilities & 0x10 != 0 {
                expected.push(setup(0x21, 0x8a, 0, 0, 0));
            }
            if formats & 2 != 0 {
                expected.push(setup(0x21, 0x84, 0, 0, 0));
            }
            if in_max > 16384 {
                expected.push(setup(
                    0x21,
                    0x86,
                    0,
                    0,
                    if capabilities & 0x20 != 0 { 8 } else { 4 },
                ));
            }
            expected.push(setup(1, SET_INTERFACE, 3, 1, 0));
            if capabilities & 1 != 0 {
                expected.push(setup(0x21, 0x43, 0x0e, 0, 0));
            }
            assert_eq!(
                model
                    .borrow()
                    .setup
                    .iter()
                    .map(|(request, _)| *request)
                    .collect::<Vec<_>>(),
                expected
            );
            assert!(model.borrow().control_replies.is_empty());
            let mut size = 16384u32.to_le_bytes().to_vec();
            if capabilities & 0x20 != 0 {
                size.extend_from_slice(&[0; 4]);
            }
            let model_ref = model.borrow();
            let size_command = model_ref
                .setup
                .iter()
                .find(|(request, _)| request[1] == 0x86);
            if in_max > 16384 {
                assert_eq!(size_command.unwrap().1, size);
            } else {
                assert!(size_command.is_none());
            }
            drop(model_ref);
            let link = &mut found.links[0];
            assert_eq!(link.mac(), Mac([2, 0x53, 0x54, 0, 0, 1]));
            let frame: Vec<_> = (0..30).collect();
            link.transmit(&frame).unwrap();
            let mut block = b"NCMH\x0c\x00\x00\x00\x40\x00\x10\x00\x00\x00\x00\x00NCM0\x10\x00\x00\x00\x22\x00\x1e\x00\x00\x00\x00\x00\x00\x00".to_vec();
            block.extend_from_slice(&frame);
            assert_eq!(model.borrow().outgoing, [block.clone(), Vec::new()]);
            model.borrow_mut().incoming_acl.push_back(block);
            assert_eq!(link.receive().unwrap(), Some(frame));
            assert_eq!(link.receive().unwrap(), None);
            // The next transfer is malformed and is dropped whole.
            model.borrow_mut().incoming_acl.push_back(b"NCMX".to_vec());
            assert_eq!(link.receive().unwrap(), None);
            for connected in [false, true] {
                model.borrow_mut().incoming_events.push_back(vec![
                    0xa1,
                    0,
                    u8::from(connected),
                    0,
                    0,
                    0,
                    0,
                    0,
                ]);
                assert_eq!(link.carrier(), connected);
            }
        }
    }

    #[test]
    fn ncm_mode_changes_require_real_status_acknowledgements_before_data_activation() {
        for request in [0x8a, 0x84] {
            for stall in [false, true] {
                let mut backing = vec![0u64; 128 * 1024];
                let start = backing.as_mut_ptr() as u64;
                // SAFETY: backing outlives all modeled controller/class DMA.
                let mut dma =
                    unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
                let (controller, model) = unconfigured_cancellation_controller_with_configurations(
                    &mut dma,
                    &[vec![9, 2, 9, 0, 0, 42, 0, 0x80, 50]],
                );
                model.borrow_mut().descriptors = vec![(STRING_DESCRIPTOR, 1, cdc_mac_descriptor())];
                let mut parameters = ncm_parameters();
                parameters[2] = 3;
                model
                    .borrow_mut()
                    .control_replies
                    .push_back((setup(0xa1, 0x80, 0, 0, 28), parameters));
                if stall {
                    model.borrow_mut().stall_control = Some(request);
                } else {
                    model.borrow_mut().silence_control = Some(request);
                }
                let shared = Rc::new(RefCell::new(controller));
                let mut found = Found::default();
                bind(
                    &shared,
                    cdc_device(&shared, Some(0x31)),
                    &mut dma,
                    &mut found,
                );
                assert!(found.links.is_empty());
                assert_eq!(found.failures.len(), 1);
                assert!(match &found.failures[0].1 {
                    BlockError::Device { status } => stall && *status == STALL,
                    BlockError::Timeout => !stall,
                    _ => false,
                });
                let model = model.borrow();
                assert_eq!(model.setup.last().unwrap().0, setup(0x21, request, 0, 0, 0));
                assert!(
                    !model
                        .setup
                        .iter()
                        .any(|(setup, _)| matches!(setup[1], SET_INTERFACE | 0x43 | 0x86))
                );
                assert!(model.outgoing.is_empty());
                assert!(model.active[1].is_none(), "failed EP0 TD must be cancelled");
                assert!(model.seen.contains(&SET_DEQUEUE));
            }
        }
    }

    #[test]
    fn malformed_parameters_and_short_size_commands_abort_before_ncm_data_activation() {
        for failure in 0..3 {
            let mut backing = vec![0u64; 128 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: backing outlives all modeled controller/class DMA.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (controller, model) = unconfigured_cancellation_controller_with_configurations(
                &mut dma,
                &[vec![9, 2, 9, 0, 0, 42, 0, 0x80, 50]],
            );
            model.borrow_mut().descriptors = vec![(STRING_DESCRIPTOR, 1, cdc_mac_descriptor())];
            let mut parameters = ncm_parameters();
            match failure {
                0 => parameters.truncate(22),
                1 => parameters[2] = 2,
                2 => model.borrow_mut().short_control_out = true,
                _ => unreachable!(),
            }
            model
                .borrow_mut()
                .control_replies
                .push_back((setup(0xa1, 0x80, 0, 0, 28), parameters));
            let shared = Rc::new(RefCell::new(controller));
            let mut found = Found::default();
            bind(
                &shared,
                cdc_device(&shared, Some(0x21)),
                &mut dma,
                &mut found,
            );
            assert_eq!(found.failures.len(), 1);
            assert!(found.links.is_empty());
            assert_eq!(
                found.failures[0].1,
                BlockError::Unsupported(match failure {
                    0 => "short NTB parameters",
                    1 => "NCM function without NTB16",
                    2 => "short USB control OUT transfer",
                    _ => unreachable!(),
                })
            );
            assert!(model.borrow().control_replies.is_empty());
            assert!(
                model
                    .borrow()
                    .setup
                    .iter()
                    .any(|(request, _)| *request == setup(0xa1, 0x80, 0, 0, 28))
            );
            if failure == 2 {
                assert_eq!(
                    model.borrow().setup.last().unwrap().0,
                    setup(0x21, 0x86, 0, 0, 8)
                );
            }
            assert!(
                !model
                    .borrow()
                    .setup
                    .iter()
                    .any(|(request, _)| request[1] == SET_INTERFACE || request[1] == 0x43)
            );
            assert!(model.borrow().outgoing.is_empty());
        }
    }
}
