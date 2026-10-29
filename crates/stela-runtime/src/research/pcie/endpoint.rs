//! Endpoint bank ownership. Configuration alone cannot back a peer.
use super::{ConfigSpace, MmioDevice};
use alloc::{boxed::Box, vec::Vec};
use core::cell::RefCell;
use {
    stela_contracts::bus::Access, stela_contracts::bus::LifecycleState, stela_contracts::bus::Width,
};

/// Exact offset of a function's whole memory BAR within its device.
/// Explicit overlapping offsets may describe aliases of the same real bank.
#[derive(Debug, Clone, Copy)]
pub struct BarMapping {
    pub bar: u8,
    pub device_offset: u64,
}

pub(super) struct Endpoint {
    pub port: usize,
    pub device_function: u8,
    pub config: ConfigSpace,
    pub intx: u8,
    pub state: LifecycleState,
    pub backend: RefCell<Box<dyn MmioDevice>>,
    pub mappings: Vec<BarMapping>,
}

impl Endpoint {
    pub fn new(
        port: usize,
        device_function: u8,
        config: ConfigSpace,
        mut backend: Box<dyn MmioDevice>,
        mappings: Vec<BarMapping>,
        state: LifecycleState,
        access: &mut Access<'_>,
    ) -> Result<Self, &'static str> {
        config.check_header_contract(false)?;
        if config
            .read(0xe, Width::Byte)
            .map_err(|_| "PCIe endpoint has no header type")?
            & 0x7f
            != 0
        {
            return Err("PCIe endpoint requires an explicitly described type-zero header");
        }
        config
            .read(super::config::COMMAND, Width::Half)
            .map_err(|_| "PCIe endpoint has no command register")?;
        if mappings.len() != config.bar_count() {
            return Err("PCIe endpoint requires exactly one actual bank mapping per BAR");
        }
        for (index, mapping) in mappings.iter().enumerate() {
            let bytes = config
                .bar_bytes(mapping.bar)
                .ok_or("PCIe mapping names no memory BAR")?;
            if mapping.device_offset.checked_add(bytes).is_none()
                || mappings[..index]
                    .iter()
                    .any(|prior| prior.bar == mapping.bar)
            {
                return Err("PCIe BAR mapping is duplicate or overflows the actual bank");
            }
        }
        let lifecycle = backend
            .lifecycle()
            .ok_or("PCIe endpoint has no actual lifecycle owner")?;
        lifecycle.check_lifecycle(state)?;
        lifecycle.set_lifecycle(state, access);
        Ok(Self {
            port,
            device_function,
            config,
            intx: 0,
            state,
            backend: RefCell::new(backend),
            mappings,
        })
    }

    pub fn check(&self, state: LifecycleState) -> Result<(), &'static str> {
        self.backend
            .try_borrow_mut()
            .map_err(|_| "PCIe endpoint is in service during lifecycle preflight")?
            .lifecycle()
            .ok_or("PCIe endpoint lifecycle capability is unavailable")?
            .check_lifecycle(state)
    }

    pub fn commit(&mut self, state: LifecycleState, access: &mut Access<'_>) {
        self.backend
            .get_mut()
            .lifecycle()
            .expect("preflighted PCIe endpoint lifecycle")
            .set_lifecycle(state, access);
        if (state.reset && !self.state.reset)
            || (!state.powered && !state.retention && self.state.powered)
        {
            self.config.reset();
            self.intx = 0;
        }
        self.state = state;
    }

    pub fn offset(&self, bar: u8, offset: u64) -> u64 {
        self.mappings
            .iter()
            .find(|mapping| mapping.bar == bar)
            .expect("complete PCIe BAR mapping")
            .device_offset
            + offset
    }
}
