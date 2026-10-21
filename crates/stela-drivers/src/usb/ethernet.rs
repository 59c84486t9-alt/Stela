//! Vendor USB Ethernet backends. Candidate interfaces become usable links only
//! after exact chip identification and revision-specific initialization.
//! RTL8152B revisions 02/07 are implemented; RTL8153/8156 remain explicit gaps.
pub mod firmware;
mod framing;
mod registers;
pub mod rtl815x;

use super::xhci::{Device, Endpoint, Interface, Shared};
use crate::{
    block::BlockError,
    bus::dma::{DmaAllocator, DmaBuffer},
    net::{Link, LinkError, Mac},
};
use alloc::{collections::VecDeque, format, string::String, vec::Vec};
use core::sync::atomic::{Ordering, fence};
pub use firmware::Error;
use rtl815x::{Chip, Control, Revision};

/// The exact Realtek vendor-mode IDs audited in the donor. OEM IDs are not
/// inferred from strings or vendor identity and are not matched yet.
pub fn matches(descriptor: &[u8; 18]) -> bool {
    u16::from_le_bytes([descriptor[8], descriptor[9]]) == 0x0bda
        && matches!(
            u16::from_le_bytes([descriptor[10], descriptor[11]]),
            0x8050 | 0x8053 | 0x8152 | 0x8153 | 0x8155 | 0x8156
        )
}

#[derive(Clone, Debug)]
pub struct Binding {
    input: Endpoint,
    output: Endpoint,
    revision: Revision,
}

impl Binding {
    pub(super) fn new(device: &Device, interface: &Interface) -> Result<Self, &'static str> {
        let revision = device
            .vendor_ethernet_revision
            .map(Revision)
            .ok_or("USB Ethernet chip revision not identified")?;
        if !matches(&device.descriptor) || !revision.implemented() {
            return Err("RTL815x chip revision initialization not implemented");
        }
        if interface.class != 0xff || interface.alternate != 0 || interface.number != 0 {
            return Err("RTL815x unsupported vendor interface setting");
        }
        let input: Vec<_> = interface
            .endpoints
            .iter()
            .copied()
            .filter(|e| e.kind() == 2 && e.is_in())
            .collect();
        let output: Vec<_> = interface
            .endpoints
            .iter()
            .copied()
            .filter(|e| e.kind() == 2 && !e.is_in())
            .collect();
        if input.len() != 1 || output.len() != 1 {
            return Err("RTL815x requires unique bulk IN/OUT endpoints");
        }
        Ok(Self {
            input: input[0],
            output: output[0],
            revision,
        })
    }

    pub(super) fn endpoints(&self) -> Vec<Endpoint> {
        vec![self.input, self.output]
    }
}

struct HostControl {
    controller: Shared,
    slot: u8,
}

impl Control for HostControl {
    fn control(&mut self, request: [u8; 8], output: &[u8]) -> Result<Vec<u8>, BlockError> {
        let mut c = self.controller.borrow_mut();
        if !c.connected(self.slot)? {
            return Err(BlockError::Unsupported("USB Ethernet disconnected"));
        }
        c.control(self.slot, request, output)
    }
    fn delay_us(&mut self, microseconds: u64) {
        self.controller.borrow().clock.delay(microseconds);
    }
}

/// One receive TD and one synchronous transmit TD; DMA allocations persist
/// for the boot even after failed cancellation, as required by xHCI ownership.
pub struct UsbEthernet {
    controller: Shared,
    slot: u8,
    binding: Binding,
    chip: Chip<HostControl>,
    mac: Mac,
    receive: DmaBuffer,
    send: DmaBuffer,
    queued: Option<u64>,
    pending: VecDeque<Vec<u8>>,
    carrier: bool,
    closed: bool,
    stopped: bool,
    pub location: String,
}

impl UsbEthernet {
    pub(super) fn new(
        controller: Shared,
        device: &Device,
        binding: Binding,
        dma: &mut dyn DmaAllocator,
        provider: &dyn crate::firmware::Provider,
    ) -> Result<Self, Error> {
        if firmware::load(provider, &device.descriptor, binding.revision)?.is_some() {
            // Validation alone never substitutes for a revision's full power,
            // PHY and firmware upload sequence. Those revisions stay refused.
            return Err(Error::UnsupportedRevision(binding.revision));
        }
        let io = HostControl {
            controller: controller.clone(),
            slot: device.slot,
        };
        let (chip, mac) = Chip::attach(
            io,
            binding.revision,
            device.speed <= super::xhci::LOW_SPEED || device.speed == super::xhci::FULL_SPEED,
        )?;
        Ok(Self {
            controller,
            slot: device.slot,
            binding,
            chip,
            mac,
            receive: dma.allocate(framing::AGGREGATE, framing::AGGREGATE)?,
            send: dma.allocate(2048, 2048)?,
            queued: None,
            pending: VecDeque::new(),
            carrier: false,
            closed: false,
            stopped: false,
            location: format!("{} RTL8152B", device.location),
        })
    }

    fn open(&mut self) -> Result<(), BlockError> {
        if self.closed {
            return Err(BlockError::Unsupported("USB Ethernet closed"));
        }
        if !self.controller.borrow_mut().connected(self.slot)? {
            self.closed = true;
            return Err(BlockError::Unsupported("USB Ethernet disconnected"));
        }
        Ok(())
    }

    fn quiesce(&mut self) -> Result<(), BlockError> {
        let mut c = self.controller.borrow_mut();
        c.cancel(self.slot, self.binding.input.dci())?;
        self.queued = None;
        c.cancel(self.slot, self.binding.output.dci())?;
        self.pending.clear();
        Ok(())
    }

    fn update_carrier(&mut self) -> Result<bool, BlockError> {
        self.open()?;
        let linked = self.chip.carrier()?;
        if self.carrier
            && !linked
            && let Err(error) = self.quiesce().and_then(|()| self.chip.stop())
        {
            self.closed = true;
            self.carrier = false;
            return Err(error);
        }
        self.carrier = linked;
        Ok(linked)
    }

    /// Stop requires acknowledged cancellation of both bulk endpoints before
    /// the device reset; failed stops remain closed and never reuse DMA.
    pub fn stop(&mut self) -> Result<(), BlockError> {
        if self.stopped {
            return Ok(());
        }
        self.closed = true;
        self.carrier = false;
        self.quiesce()?;
        self.chip.stop()?;
        self.stopped = true;
        Ok(())
    }
}

impl Drop for UsbEthernet {
    fn drop(&mut self) {
        // Failure cannot release boot-lifetime DMA or claim device quiescence.
        let _ = self.stop();
    }
}

fn link_error(error: BlockError) -> LinkError {
    LinkError::Adapter(format!("USB RTL815x: {error}"))
}

impl Link for UsbEthernet {
    fn mac(&self) -> Mac {
        self.mac
    }
    fn carrier(&mut self) -> bool {
        self.update_carrier().unwrap_or(false)
    }
    fn transmit(&mut self, frame: &[u8]) -> Result<(), LinkError> {
        if !self.update_carrier().map_err(link_error)? {
            return Err(LinkError::Adapter("USB Ethernet carrier down".into()));
        }
        let mut c = self.controller.borrow_mut();
        c.endpoint_ready(self.slot, self.binding.output.dci())
            .map_err(link_error)?;
        let bytes = framing::encode(frame, self.send.bytes_mut())
            .map_err(|why| LinkError::Adapter(why.into()))?;
        fence(Ordering::Release);
        let actual = match c.transfer(
            self.slot,
            self.binding.output.dci(),
            self.send.physical(),
            bytes,
            1_000_000,
        ) {
            Ok(actual) => actual,
            Err(error) => {
                // A STALL completes the request but the halted hardware can
                // still reference its old TD until Reset/Set Dequeue succeeds.
                c.clear(self.slot, &self.binding.output)
                    .map_err(link_error)?;
                return Err(link_error(error));
            }
        };
        if actual != bytes {
            return Err(LinkError::Adapter("RTL815x short TX transfer".into()));
        }
        // The vendor protocol carries its own lengths; Linux submits no ZLP.
        Ok(())
    }
    fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
        if !self.update_carrier().map_err(link_error)? {
            return Ok(None);
        }
        if let Some(frame) = self.pending.pop_front() {
            return Ok(Some(frame));
        }
        let mut c = self.controller.borrow_mut();
        let endpoint = self.binding.input;
        let token = match self.queued {
            Some(token) => token,
            None => {
                let token = c
                    .submit(
                        self.slot,
                        endpoint.dci(),
                        self.receive.physical(),
                        self.receive.len(),
                    )
                    .map_err(link_error)?;
                self.queued = Some(token);
                token
            }
        };
        let Some(result) = c.completed(self.slot, endpoint.dci(), token, self.receive.len()) else {
            return Ok(None);
        };
        self.queued = None;
        let actual = match result {
            Ok(bytes) => bytes,
            Err(error) => {
                c.clear(self.slot, &endpoint).map_err(link_error)?;
                return Err(link_error(error));
            }
        };
        if actual > self.receive.len() {
            return Err(LinkError::Adapter(
                "RTL815x RX completion exceeds DMA".into(),
            ));
        }
        fence(Ordering::Acquire);
        self.pending.extend(
            framing::decode(&self.receive.bytes()[..actual])
                .map_err(|why| LinkError::Adapter(why.into()))?,
        );
        Ok(self.pending.pop_front())
    }
}
