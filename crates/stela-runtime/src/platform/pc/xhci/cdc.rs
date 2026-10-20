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
//! OUT transfer. NCM moves transfer blocks ([`ntb`]): while the data
//! interface is still at alternate setting 0, attach reads the function's
//! NTB parameters (GetNtbParameters) and caps its IN blocks at
//! [`NCM_IN_BLOCK`] bytes (SetNtbInputSize); each IN block may carry several
//! frames, and each sent frame is one OUT block. Either way a transfer that
//! is a multiple of the endpoint's packet size is followed by a zero-length
//! packet, except an NCM block of exactly the function's largest OUT size.
//! NetworkConnection notifications on the interrupt endpoint set the
//! carrier (ECM 6.3.1, and alike in NCM); until one arrives the link is
//! taken to be up. Frames above the 1514-byte Ethernet maximum are refused.
mod ntb;

use super::{
    super::{
        block::BlockError,
        dma::{DmaAllocator, DmaBuffer},
    },
    Device, Endpoint, Interface, Plan, Shared, setup,
};
use crate::platform::net::{Link, Mac, NetError};
use alloc::{collections::VecDeque, format, string::String, vec::Vec};

pub const COMMUNICATIONS: u8 = 2;
/// The Ethernet Control Model subclass.
pub const ECM: u8 = 6;
/// The Network Control Model subclass.
pub const NCM: u8 = 0x0d;
const DATA_CLASS: u8 = 10;
const CS_INTERFACE: u8 = 0x24;
const UNION: u8 = 0x06;
const ETHERNET: u8 = 0x0f;
/// The NCM functional descriptor's subtype.
const NCM_FUNCTIONAL: u8 = 0x1a;
/// bmNetworkCapabilities: SetEthernetPacketFilter is supported.
const NCM_PACKET_FILTER: u8 = 1 << 0;
/// bmNetworkCapabilities: SetNtbInputSize takes 8 bytes, the size and
/// wNtbInMaxDatagrams.
const NCM_INPUT_SIZE_8: u8 = 1 << 5;
const SET_ETHERNET_PACKET_FILTER: u8 = 0x43;
const GET_NTB_PARAMETERS: u8 = 0x80;
const SET_NTB_INPUT_SIZE: u8 = 0x86;
/// Directed, broadcast and all-multicast frames.
const FILTER: u16 = 0x04 | 0x08 | 0x02;
const NETWORK_CONNECTION: u8 = 0x00;
const MAX_FRAME: usize = 1514;
/// An ECM frame's transfer, and the OUT block buffer.
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
            let text = c
                .string(device.slot, binding.mac_string)
                .ok_or(BlockError::Unsupported(
                    "CDC Ethernet adapter without a MAC address string",
                ))?;
            let mac = parse_mac(&text)
                .ok_or(BlockError::Unsupported("CDC Ethernet MAC address string"))?;
            let control = u16::from(binding.control);
            // NCM's NTB size requests precede the data setting.
            let framing = match binding.model {
                Model::Ecm => Framing::Ecm,
                Model::Ncm(capabilities) => {
                    let request = setup(
                        0xa1,
                        GET_NTB_PARAMETERS,
                        0,
                        control,
                        ntb::PARAMETER_BYTES as u16,
                    );
                    let reply = c.control(device.slot, request, &[])?;
                    let mut parameters =
                        ntb::Parameters::parse(&reply).map_err(BlockError::Unsupported)?;
                    if parameters.in_max > NCM_IN_BLOCK {
                        parameters.in_max = NCM_IN_BLOCK;
                        let mut size = (NCM_IN_BLOCK as u32).to_le_bytes().to_vec();
                        if capabilities & NCM_INPUT_SIZE_8 != 0 {
                            // wNtbInMaxDatagrams 0: no limit.
                            size.extend_from_slice(&[0; 4]);
                        }
                        let request =
                            setup(0x21, SET_NTB_INPUT_SIZE, 0, control, size.len() as u16);
                        c.control(device.slot, request, &size)?;
                    }
                    Framing::Ncm(parameters, 0)
                }
            };
            if binding.alternate != 0 {
                let request = setup(
                    1,
                    super::SET_INTERFACE,
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
                let request = setup(0x21, SET_ETHERNET_PACKET_FILTER, FILTER, control, 0);
                c.control(device.slot, request, &[])?;
            }
            (mac, framing)
        };
        let receive_bytes = match &framing {
            Framing::Ecm => FRAME_BYTES,
            Framing::Ncm(parameters, _) => parameters.in_max,
        };
        Ok(Self {
            controller,
            slot: device.slot,
            binding,
            framing,
            mac,
            receive: dma.allocate(receive_bytes, FRAME_BYTES)?,
            pending: VecDeque::new(),
            send: dma.allocate(FRAME_BYTES, FRAME_BYTES)?,
            status: dma.allocate(64, 64)?,
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
                if header[0] == 0xa1 && header[1] == NETWORK_CONNECTION {
                    self.connected = Some(header[2] != 0);
                }
            }
        }
    }
}

fn link_error(error: BlockError) -> NetError {
    NetError::Link(format!("USB Ethernet: {error}"))
}

impl Link for UsbNet {
    fn mac(&self) -> Mac {
        self.mac
    }

    fn carrier(&mut self) -> bool {
        self.notifications();
        self.connected.unwrap_or(true)
    }

    fn transmit(&mut self, frame: &[u8]) -> Result<(), NetError> {
        if frame.len() > MAX_FRAME {
            return Err(NetError::Link(String::from(
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
                    .filter(|block| block.len() <= FRAME_BYTES)
                    .ok_or_else(|| {
                        NetError::Link(String::from("frame above the NCM OUT block size"))
                    })?;
                *sequence = sequence.wrapping_add(1);
                self.send.bytes_mut()[..block.len()].copy_from_slice(&block);
                (block.len(), Some(parameters.out_max))
            }
        };
        let output = self.binding.output;
        let mut c = self.controller.borrow_mut();
        let physical = self.send.physical();
        c.transfer(self.slot, output.dci(), physical, length, SEND_US)
            .map_err(link_error)?;
        let packet = usize::from(output.max_packet & 0x7ff).max(1);
        if length.is_multiple_of(packet) && whole != Some(length) {
            c.transfer(self.slot, output.dci(), physical, 0, SEND_US)
                .map_err(link_error)?;
        }
        Ok(())
    }

    fn receive(&mut self) -> Result<Option<Vec<u8>>, NetError> {
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
    use super::super::tests::{bench, run};
    use super::*;
    use crate::platform::usb::{
        Function, Speed,
        ecm::Ecm,
        hub::{Hub, Ports},
    };

    struct One(Ecm);
    impl Ports for One {
        fn count(&self) -> usize {
            1
        }
        fn speed(&self, _: usize) -> Speed {
            Speed::High
        }
        fn function(&mut self, _: usize) -> &mut dyn Function {
            &mut self.0
        }
        fn function_ref(&self, _: usize) -> &dyn Function {
            &self.0
        }
    }

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
    fn the_native_ecm_adapter_moves_frames_for_the_host() {
        let mac = Mac([0x02, 0x53, 0x54, 0, 0, 7]);
        let hub = Hub::new(One(Ecm::new(mac).unwrap()), "HUB").unwrap();
        let mut bench = bench(hub);
        let mut found = run(&mut bench);
        assert!(found.failures.is_empty(), "{:?}", found.failures);
        assert_eq!(found.links.len(), 1);
        let mut link = found.links.remove(0);
        assert_eq!(link.mac(), mac);
        assert!(link.carrier());
        assert!(bench.model.borrow().function.ports.0.up());
        // Host to network: a 1024-byte frame (two full packets and a ZLP).
        let mut frame = vec![0u8; 1024];
        frame[..6].copy_from_slice(&Mac::BROADCAST.0);
        frame[6..12].copy_from_slice(&mac.0);
        link.transmit(&frame).unwrap();
        assert_eq!(
            bench.model.borrow_mut().function.ports.0.take(),
            Some(frame.clone())
        );
        // Network to host.
        let mut inbound = vec![7u8; 600];
        inbound[..6].copy_from_slice(&mac.0);
        bench.model.borrow_mut().function.ports.0.deliver(&inbound);
        let mut received = None;
        for _ in 0..50 {
            if let Some(frame) = link.receive().unwrap() {
                received = Some(frame);
                break;
            }
        }
        assert_eq!(received, Some(inbound));
        assert!(link.transmit(&[0u8; 1515]).is_err());
    }
}
