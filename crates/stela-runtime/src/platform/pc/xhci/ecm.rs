//! USB CDC Ethernet Control Model adapters (CDC ECM 1.2) as host network
//! links.
//!
//! The communications interface (class 2, subclass 6) names its data
//! interface in its Union descriptor and its station address in the
//! Ethernet Networking descriptor's iMACAddress string. Attach configures
//! the data interface's alternate setting with two bulk endpoints, selects
//! it (SET_INTERFACE), and sets the packet filter to directed, broadcast
//! and all-multicast frames (6.2.4). Each received frame is one bulk IN
//! transfer ended by a short packet (3.3.1); each sent frame is one bulk
//! OUT transfer, followed by a zero-length packet when its length is a
//! multiple of the endpoint's packet size. NetworkConnection notifications
//! on the interrupt endpoint set the carrier (6.3.1); until one arrives the
//! link is taken to be up. Frames above the 1514-byte Ethernet maximum are
//! refused.
use super::{
    super::{
        block::BlockError,
        dma::{DmaAllocator, DmaBuffer},
    },
    Device, Endpoint, Interface, Plan, Shared, setup,
};
use crate::platform::net::{Link, Mac, NetError};
use alloc::{format, string::String, vec::Vec};

pub const COMMUNICATIONS: u8 = 2;
pub const SUBCLASS: u8 = 6;
const DATA_CLASS: u8 = 10;
const CS_INTERFACE: u8 = 0x24;
const UNION: u8 = 0x06;
const ETHERNET: u8 = 0x0f;
const SET_ETHERNET_PACKET_FILTER: u8 = 0x43;
/// Directed, broadcast and all-multicast frames.
const FILTER: u16 = 0x04 | 0x08 | 0x02;
const NETWORK_CONNECTION: u8 = 0x00;
const MAX_FRAME: usize = 1514;
const RECEIVE_BYTES: usize = 2048;
const SEND_US: u64 = 1_000_000;

/// The interfaces and endpoints one adapter uses.
#[derive(Clone, Debug)]
pub struct Binding {
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
    let union = interface
        .extra
        .iter()
        .find(|d| d.len() >= 5 && d[1] == CS_INTERFACE && d[2] == UNION)
        .ok_or("ECM interface without a Union descriptor")?;
    let ethernet = interface
        .extra
        .iter()
        .find(|d| d.len() >= 13 && d[1] == CS_INTERFACE && d[2] == ETHERNET)
        .ok_or("ECM interface without an Ethernet Networking descriptor")?;
    let data = union[4];
    let setting = all
        .iter()
        .find(|i| i.number == data && i.class == DATA_CLASS && i.endpoints.len() >= 2)
        .ok_or("ECM data interface without a bulk setting")?;
    let bulk = |is_in: bool| {
        setting
            .endpoints
            .iter()
            .copied()
            .find(|e| e.kind() == 2 && e.is_in() == is_in)
    };
    let (Some(input), Some(output)) = (bulk(true), bulk(false)) else {
        return Err("ECM data interface without two bulk endpoints");
    };
    let notify = interface
        .endpoints
        .iter()
        .copied()
        .find(|e| e.kind() == 3 && e.is_in());
    Ok(Plan::Ecm(Binding {
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
    mac: Mac,
    receive: DmaBuffer,
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
        let mac = {
            let mut c = controller.borrow_mut();
            let text = c
                .string(device.slot, binding.mac_string)
                .ok_or(BlockError::Unsupported(
                    "ECM adapter without a MAC address string",
                ))?;
            let mac = parse_mac(&text).ok_or(BlockError::Unsupported("ECM MAC address string"))?;
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
            let filter = setup(
                0x21,
                SET_ETHERNET_PACKET_FILTER,
                FILTER,
                u16::from(binding.control),
                0,
            );
            c.control(device.slot, filter, &[])?;
            mac
        };
        Ok(Self {
            controller,
            slot: device.slot,
            binding,
            mac,
            receive: dma.allocate(RECEIVE_BYTES, RECEIVE_BYTES)?,
            send: dma.allocate(RECEIVE_BYTES, RECEIVE_BYTES)?,
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
        self.send.bytes_mut()[..frame.len()].copy_from_slice(frame);
        let output = self.binding.output;
        let mut c = self.controller.borrow_mut();
        let physical = self.send.physical();
        c.transfer(self.slot, output.dci(), physical, frame.len(), SEND_US)
            .map_err(link_error)?;
        let packet = usize::from(output.max_packet & 0x7ff).max(1);
        if frame.len().is_multiple_of(packet) {
            c.transfer(self.slot, output.dci(), physical, 0, SEND_US)
                .map_err(link_error)?;
        }
        Ok(())
    }

    fn receive(&mut self) -> Result<Option<Vec<u8>>, NetError> {
        let input = self.binding.input;
        let mut c = self.controller.borrow_mut();
        let trb = match self.queued {
            Some(trb) => trb,
            None => {
                let trb = c
                    .submit(
                        self.slot,
                        input.dci(),
                        self.receive.physical(),
                        RECEIVE_BYTES,
                    )
                    .map_err(link_error)?;
                self.queued = Some(trb);
                trb
            }
        };
        let Some(result) = c.completed(self.slot, input.dci(), trb, RECEIVE_BYTES) else {
            return Ok(None);
        };
        self.queued = None;
        match result {
            Ok(0) => Ok(None),
            Ok(bytes) if bytes > MAX_FRAME => Ok(None),
            Ok(bytes) => Ok(Some(self.receive.bytes()[..bytes].to_vec())),
            Err(error) => {
                let _ = c.clear(self.slot, &input);
                Err(link_error(error))
            }
        }
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
