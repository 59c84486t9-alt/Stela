// SPDX-License-Identifier: GPL-2.0-only
//! Physical configuration/alternate changes ordered after DMA retirement.
//! Linux core/message.c usb_set_configuration/usb_set_interface is the lifecycle
//! reference; uncertainty fences the device instead of claiming a rollback.
use super::*;

impl Device {
    fn allocate_buffers(
        &mut self,
        endpoints: &[Endpoint],
        dma: &mut dyn DmaAllocator,
    ) -> Result<(), BlockError> {
        for endpoint in endpoints {
            if !self.spare.contains_key(&endpoint.address)
                && !self.pipes.contains_key(&endpoint.address)
            {
                let buffer = dma.allocate(xhci::MAX_TD, xhci::MAX_TD)?;
                self.spare.insert(endpoint.address, buffer);
            }
        }
        Ok(())
    }
    fn install(
        &mut self,
        endpoints: &[Endpoint],
        dma: &mut dyn DmaAllocator,
    ) -> Result<(), BlockError> {
        if endpoints.is_empty() {
            return Ok(());
        }
        if let Err(error) = self
            .controller
            .borrow_mut()
            .device(self.physical.id)?
            .configure(endpoints, None, dma)
        {
            self.fenced = true;
            return Err(error);
        }
        for endpoint in endpoints {
            let buffer = self
                .spare
                .remove(&endpoint.address)
                .ok_or(BlockError::Protocol("missing forwarding DMA reservation"))?;
            self.pipes.insert(
                endpoint.address,
                Pipe {
                    endpoint: *endpoint,
                    buffer,
                    pending: None,
                    streams: 0,
                },
            );
        }
        Ok(())
    }

    /// A repeated SET_CONFIGURATION is deliberately sent again: USB resets all
    /// interfaces/toggles even when bConfigurationValue has not changed.
    pub fn configure(&mut self, value: u8, dma: &mut dyn DmaAllocator) -> Result<(), BlockError> {
        self.ready()?;
        let (settings, endpoints) = if value == 0 {
            (Vec::new(), Vec::new())
        } else {
            let configuration = self
                .inventory
                .iter()
                .find(|c| c.value == value)
                .ok_or(BlockError::Unsupported("unknown USB configuration value"))?;
            let settings: Vec<_> = configuration
                .interfaces
                .iter()
                .filter(|i| i.alternate == 0)
                .map(|i| (i.number, 0))
                .collect();
            let endpoints = descriptors::active(configuration, &settings, self.physical.speed)?;
            (settings, endpoints)
        };
        self.allocate_buffers(&endpoints, dma)?;
        let addresses: Vec<_> = self.pipes.keys().copied().collect();
        self.retire(&addresses)?;
        let result = self
            .controller
            .borrow_mut()
            .device(self.physical.id)?
            .control(
                xhci::setup(0, xhci::SET_CONFIGURATION, u16::from(value), 0, 0),
                &[],
            );
        if let Err(error) = result {
            self.fenced = true;
            return Err(error);
        }
        self.configuration = value;
        self.settings = settings;
        self.install(&endpoints, dma)
    }

    pub fn set_interface(
        &mut self,
        number: u8,
        alternate: u8,
        dma: &mut dyn DmaAllocator,
    ) -> Result<(), BlockError> {
        self.ready()?;
        let configuration = self
            .inventory
            .iter()
            .find(|c| c.value == self.configuration)
            .ok_or(BlockError::Unsupported("USB device is unconfigured"))?;
        let mut settings = self.settings.clone();
        let setting = settings
            .iter_mut()
            .find(|s| s.0 == number)
            .ok_or(BlockError::Unsupported("unknown USB interface"))?;
        setting.1 = alternate;
        // Validate the entire active composite set before quiescing anything.
        descriptors::active(configuration, &settings, self.physical.speed)?;
        let endpoints = configuration
            .interfaces
            .iter()
            .find(|i| (i.number, i.alternate) == (number, alternate))
            .ok_or(BlockError::Unsupported("unknown USB alternate setting"))?
            .endpoints
            .clone();
        let old_alternate = self.settings.iter().find(|s| s.0 == number).unwrap().1;
        let addresses: Vec<_> = configuration
            .interfaces
            .iter()
            .find(|i| (i.number, i.alternate) == (number, old_alternate))
            .unwrap()
            .endpoints
            .iter()
            .map(|ep| ep.address)
            .collect();
        self.allocate_buffers(&endpoints, dma)?;
        self.retire(&addresses)?;
        let result = self
            .controller
            .borrow_mut()
            .device(self.physical.id)?
            .control(
                xhci::setup(
                    1,
                    xhci::SET_INTERFACE,
                    u16::from(alternate),
                    u16::from(number),
                    0,
                ),
                &[],
            );
        if let Err(error) = result {
            self.fenced = true;
            return Err(error);
        }
        self.settings = settings;
        self.install(&endpoints, dma)
    }

    /// Allocate checked primary streams on actual advertised bulk endpoints.
    /// Stream count is the native controller's acknowledged usable count.
    pub fn enable_streams(
        &mut self,
        addresses: &[u8],
        requested: u16,
        dma: &mut dyn DmaAllocator,
    ) -> Result<u16, BlockError> {
        self.ready()?;
        let mut selected = 0u32;
        let mut endpoints = Vec::new();
        for address in addresses {
            let pipe = self
                .pipes
                .get(address)
                .ok_or(BlockError::Unsupported("inactive USB stream endpoint"))?;
            if selected & (1 << pipe.endpoint.dci()) != 0 {
                return Err(BlockError::Unsupported("duplicate USB stream endpoint"));
            }
            selected |= 1 << pipe.endpoint.dci();
            endpoints.push(pipe.endpoint);
        }
        self.controller
            .borrow_mut()
            .device(self.physical.id)?
            .stream_capacity(&endpoints, addresses, requested)?;
        self.retire(addresses)?;
        let result = self
            .controller
            .borrow_mut()
            .device(self.physical.id)?
            .configure_streams(&endpoints, addresses, requested, dma);
        let count = match result {
            Ok(count) => count,
            Err(error) => {
                self.fenced = true;
                return Err(error);
            }
        };
        for endpoint in endpoints {
            let buffer = self
                .spare
                .remove(&endpoint.address)
                .ok_or(BlockError::Protocol("missing stream DMA reservation"))?;
            self.pipes.insert(
                endpoint.address,
                Pipe {
                    endpoint,
                    buffer,
                    pending: None,
                    streams: count,
                },
            );
        }
        Ok(count)
    }

    pub(super) fn retire(&mut self, addresses: &[u8]) -> Result<(), BlockError> {
        for address in addresses {
            self.cancel(*address)?;
        }
        let endpoints: Vec<_> = addresses.iter().map(|a| self.pipes[a].endpoint).collect();
        if !endpoints.is_empty() {
            if let Err(error) = self
                .controller
                .borrow_mut()
                .device(self.physical.id)?
                .deconfigure(&endpoints)
            {
                self.fenced = true;
                return Err(error);
            }
        }
        for address in addresses {
            let pipe = self.pipes.remove(address).unwrap();
            self.spare.insert(*address, pipe.buffer);
        }
        Ok(())
    }
}
