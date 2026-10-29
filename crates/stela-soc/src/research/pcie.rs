//! Apple PCIe control/configuration core, independent of host PCI drivers.
//!
//! The model is an integration building block, not a loader-admitted Apple
//! controller. Board facts must place each view and supply root-port
//! configuration images. Downstream USB-A/Ethernet require real endpoint
//! models and firmware protocols; adding a config header never creates one.
//! See `docs/research/apple-pcie.md` for evidence and unsupported boundaries.
use crate::Result;
use alloc::{boxed::Box, vec::Vec};
use stela_contracts::Refusal;
use stela_contracts::refuse;
use {
    stela_contracts::bus::Access, stela_contracts::bus::Direction, stela_contracts::bus::Lifecycle,
    stela_contracts::bus::LifecycleState, stela_contracts::bus::MmioDevice,
    stela_contracts::bus::MmioError, stela_contracts::bus::Width, stela_contracts::bus::refuse,
};
use {stela_contracts::dma::DmaError, stela_contracts::dma::Port as DmaPort};
pub mod config;
mod endpoint;
pub mod port;
use config::{BUS_MASTER_ENABLE, ConfigSpace, INTX_DISABLE, MEMORY_ENABLE};
pub use endpoint::BarMapping;
use endpoint::Endpoint;
use port::{Inputs, Port};

const NAME: &str = "Apple PCIe root complex";
/// ECAM includes 256 buses, 32 devices, 8 functions, 4 KiB per function.
pub const ECAM_BYTES: u64 = 1 << 28;
/// Logical views. Placement owner maps ADT regions onto these offsets.
pub const PORT_BASE: u64 = ECAM_BYTES;
pub const PORT_STRIDE: u64 = 0x1_0000;
pub const PORT_BYTES: u64 = 0x4000;
const BUSES: u16 = 0x18;
const MEMORY_WINDOW: u16 = 0x20;
const PREFETCH_WINDOW: u16 = 0x24;
const PREFETCH_BASE_HI: u16 = 0x28;
const PREFETCH_LIMIT_HI: u16 = 0x2c;
const BRIDGE_CONTROL: u16 = 0x3e;
const SECONDARY_RESET: u64 = 1 << 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteError {
    Missing,
    Ambiguous,
}
impl RouteError {
    fn reason(self) -> &'static str {
        match self {
            Self::Missing => "requester has no active endpoint",
            Self::Ambiguous => "requester is ambiguous across root ports",
        }
    }
}

/// One root port per first-bus slot, directly attached endpoints only.
/// Switches and subordinate bridges need their own topology before admission.
pub struct RootComplex {
    lifecycle: LifecycleState,
    first_bus: u8,
    last_bus: u8,
    ports: Vec<Port>,
    roots: Vec<ConfigSpace>,
    endpoints: Vec<Endpoint>,
}
impl RootComplex {
    pub fn new(first_bus: u8, last_bus: u8, ports: Vec<(Port, ConfigSpace)>) -> Result<Self> {
        if first_bus > last_bus || ports.is_empty() || ports.len() > 32 {
            return Err(refuse!("PCIe ECAM bus/port geometry is invalid"));
        }
        for (index, (port, root)) in ports.iter().enumerate() {
            if ports[..index]
                .iter()
                .any(|(prior, _)| prior.management_irq() == port.management_irq())
                || ports
                    .iter()
                    .any(|(other, _)| other.has_msi_wire(port.management_irq()))
            {
                return Err(refuse!(
                    "PCIe management IRQ ownership overlaps another port or MSI wire"
                ));
            }
            root.check_header_contract(true)?;
            if root
                .read(0xe, Width::Byte)
                .map_err(|_| refuse!("root has no header type"))?
                & 0x7f
                != 1
            {
                return Err(refuse!("PCIe root port needs a type-one bridge header"));
            }
            // Lifecycle and topology cannot be enforced without these fields.
            root.read(BUSES, Width::Word)
                .map_err(|_| refuse!("root has no bus-number register"))?;
            root.read(config::COMMAND, Width::Half)
                .map_err(|_| refuse!("root has no command register"))?;
            root.read(BRIDGE_CONTROL, Width::Half)
                .map_err(|_| refuse!("root has no bridge control"))?;
        }
        let (ports, roots) = ports.into_iter().unzip();
        Ok(Self {
            lifecycle: LifecycleState {
                powered: true,
                clocked: true,
                quiesced: false,
                reset: false,
                retention: true,
            },
            first_bus,
            last_bus,
            ports,
            roots,
            endpoints: Vec::new(),
        })
    }
    /// The caller must attach an implemented endpoint, then drive peer input
    /// from that backend's presence. Identity alone is insufficient.
    /// `device_function` packs device in bits 7:3 and function in bits 2:0.
    pub fn attach(
        &mut self,
        port: usize,
        device_function: u8,
        config: ConfigSpace,
        backend: Box<dyn MmioDevice>,
        mappings: Vec<BarMapping>,
        access: &mut Access<'_>,
    ) -> Result<usize> {
        if port >= self.ports.len() {
            return Err(refuse!("PCIe endpoint address is invalid"));
        }
        if self
            .endpoints
            .iter()
            .any(|e| e.port == port && e.device_function == device_function)
        {
            return Err(refuse!("PCIe endpoint address is duplicate"));
        }
        let state = Self::endpoint_state(
            self.lifecycle,
            &self.ports[port],
            Self::secondary_reset(&self.roots[port]),
        );
        let endpoint = Endpoint::new(
            port,
            device_function,
            config,
            backend,
            mappings,
            state,
            access,
        )?;
        let index = self.endpoints.len();
        self.endpoints.push(endpoint);
        Ok(index)
    }
    pub fn set_port_inputs(
        &mut self,
        port: usize,
        inputs: Inputs,
        access: &mut Access<'_>,
    ) -> Result<()> {
        let p = self
            .ports
            .get(port)
            .ok_or(refuse!("PCIe port index is invalid"))?;
        if inputs.peer && !self.endpoints.iter().any(|endpoint| endpoint.port == port) {
            return Err(refuse!(
                "PCIe peer presence requires an actual attached endpoint bank"
            ));
        }
        if (!self.lifecycle.clocked || self.lifecycle.quiesced) && inputs != p.inputs() {
            return Err(refuse!(
                "PCIe external input changes during a controller pause are unqualified"
            ));
        }
        let candidate = p.preview_inputs(inputs)?;
        self.check_port(port, &candidate, &self.roots[port], self.lifecycle)?;
        self.ports[port] = candidate;
        self.commit_port(port, access);
        Ok(())
    }
    fn secondary_reset(root: &ConfigSpace) -> bool {
        root.read(BRIDGE_CONTROL, Width::Half)
            .expect("validated root bridge control")
            & SECONDARY_RESET
            != 0
    }
    fn endpoint_state(
        global: LifecycleState,
        port: &Port,
        secondary_reset: bool,
    ) -> LifecycleState {
        let reset = global.reset || !port.reset_released() || secondary_reset;
        LifecycleState {
            powered: global.powered && port.inputs().powered,
            clocked: global.clocked && port.clock_running(),
            quiesced: global.quiesced || reset || !port.link_up(),
            reset,
            retention: global.retention,
        }
    }
    fn check_port(
        &self,
        port: usize,
        candidate: &Port,
        root: &ConfigSpace,
        global: LifecycleState,
    ) -> Result<()> {
        let proposed = Self::endpoint_state(global, candidate, Self::secondary_reset(root));
        for endpoint in self
            .endpoints
            .iter()
            .filter(|endpoint| endpoint.port == port)
        {
            endpoint.check(proposed)?;
        }
        Ok(())
    }
    fn commit_port(&mut self, port: usize, access: &mut Access<'_>) {
        let state = Self::endpoint_state(
            self.lifecycle,
            &self.ports[port],
            Self::secondary_reset(&self.roots[port]),
        );
        for endpoint in self
            .endpoints
            .iter_mut()
            .filter(|endpoint| endpoint.port == port)
        {
            endpoint.commit(state, access);
        }
        self.ports[port].publish(access);
        self.update_intx(port, access);
    }
    fn service_enabled(&self) -> bool {
        self.lifecycle.powered
            && self.lifecycle.clocked
            && !self.lifecycle.quiesced
            && !self.lifecycle.reset
    }
    fn secondary(&self, port: usize) -> Option<u8> {
        let root = &self.roots[port];
        if root.read(BRIDGE_CONTROL, Width::Half).ok()? & SECONDARY_RESET != 0 {
            return None;
        }
        let buses = root.read(BUSES, Width::Word).ok()? as u32;
        let primary = buses as u8;
        let secondary = (buses >> 8) as u8;
        let subordinate = (buses >> 16) as u8;
        (primary == self.first_bus
            && secondary > self.first_bus
            && secondary <= self.last_bus
            && subordinate >= secondary
            && subordinate <= self.last_bus)
            .then_some(secondary)
    }
    fn endpoint(&self, requester: u16) -> Result<usize, RouteError> {
        if !self.service_enabled() {
            return Err(RouteError::Missing);
        }
        let bus = (requester >> 8) as u8;
        let devfn = requester as u8;
        let mut ports = (0..self.ports.len())
            .filter(|&port| self.secondary(port) == Some(bus) && self.ports[port].link_up());
        let port = ports.next().ok_or(RouteError::Missing)?;
        if ports.next().is_some() {
            return Err(RouteError::Ambiguous);
        }
        self.endpoints
            .iter()
            .position(|endpoint| endpoint.port == port && endpoint.device_function == devfn)
            .ok_or(RouteError::Missing)
    }
    fn root_memory(&self, port: usize, address: u64, bytes: u64) -> bool {
        let root = &self.roots[port];
        if root.command() & MEMORY_ENABLE == 0 || bytes == 0 {
            return false;
        }
        let Some(last) = address.checked_add(bytes - 1) else {
            return false;
        };
        for (offset, prefetch) in [(MEMORY_WINDOW, false), (PREFETCH_WINDOW, true)] {
            let Ok(window) = root.read(offset, Width::Word) else {
                continue;
            };
            let low = window as u16;
            let high = (window >> 16) as u16;
            let mut base = u64::from(low & 0xfff0) << 16;
            let mut limit = (u64::from(high & 0xfff0) << 16) | 0xf_ffff;
            if prefetch {
                if low & 0xf != high & 0xf {
                    continue;
                }
                if low & 0xf == 1 {
                    let (Ok(b), Ok(l)) = (
                        root.read(PREFETCH_BASE_HI, Width::Word),
                        root.read(PREFETCH_LIMIT_HI, Width::Word),
                    ) else {
                        continue;
                    };
                    base |= b << 32;
                    limit |= l << 32;
                } else if low & 0xf != 0 {
                    continue;
                }
            } else if low & 0xf != 0 || high & 0xf != 0 {
                continue;
            }
            if address >= base && last <= limit {
                return true;
            }
        }
        false
    }
    /// Return endpoint index, BAR index and relative offset only if both
    /// bridge memory windows and endpoint memory decoding admit every byte.
    /// Caller routes to that endpoint; this is never host passthrough.
    pub fn memory_route(&self, address: u64, bytes: u64) -> Result<(usize, u8, u64)> {
        if !self.service_enabled() {
            return Err(refuse!("PCIe native controller service is paused"));
        }
        let mut route = None;
        for (index, endpoint) in self.endpoints.iter().enumerate() {
            let Some(bus) = self.secondary(endpoint.port) else {
                continue;
            };
            if !self.ports[endpoint.port].link_up()
                || !self.root_memory(endpoint.port, address, bytes)
            {
                continue;
            }
            let requester = u16::from(bus) << 8 | u16::from(endpoint.device_function);
            if self.endpoint(requester) == Err(RouteError::Ambiguous) {
                return Err(refuse!("PCIe bus-number windows overlap"));
            }
            if let Some((bar, offset)) = endpoint
                .config
                .memory_decode(address, bytes)
                .map_err(|_| refuse!("PCIe memory BAR decoders overlap"))?
            {
                if route.is_some() {
                    return Err(refuse!("PCIe memory decoders overlap"));
                }
                route = Some((index, bar, offset));
            }
        }
        route.ok_or(refuse!(
            "no active PCIe memory decoder admits the transaction"
        ))
    }
    pub fn read_memory(
        &mut self,
        address: u64,
        width: Width,
        access: &mut Access<'_>,
    ) -> Result<u64, MmioError> {
        let (index, bar, offset) = self
            .memory_route(address, width.bytes())
            .map_err(|why| Self::error(address, width, Direction::Read, why))?;
        let endpoint = &mut self.endpoints[index];
        let offset = endpoint.offset(bar, offset);
        endpoint.backend.get_mut().read(offset, width, access)
    }
    pub fn write_memory(
        &mut self,
        address: u64,
        width: Width,
        value: u64,
        access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let (index, bar, offset) = self
            .memory_route(address, width.bytes())
            .map_err(|why| Self::error(address, width, Direction::Write, why))?;
        let endpoint = &mut self.endpoints[index];
        let offset = endpoint.offset(bar, offset);
        endpoint
            .backend
            .get_mut()
            .write(offset, width, value, access)
    }
    /// Validate link/topology/bus-master state and RID-to-SID before the
    /// caller constructs the existing DART-backed DMA port. No physical bypass.
    pub fn dma_stream(
        &mut self,
        requester: u16,
        access: &mut Access<'_>,
    ) -> Result<usize, DmaError> {
        let index = self
            .endpoint(requester)
            .map_err(|error| DmaError::Unsupported(error.reason().into()))?;
        let endpoint = &self.endpoints[index];
        if endpoint.config.command() & BUS_MASTER_ENABLE == 0
            || self.roots[endpoint.port].command() & BUS_MASTER_ENABLE == 0
        {
            return Err(DmaError::Unsupported(refuse!(
                "PCIe bus mastering is disabled"
            )));
        }
        self.ports[endpoint.port]
            .stream(requester, access)
            .map_err(|_| DmaError::Unsupported(refuse!("PCIe requester-to-stream mapping refused")))
    }
    /// DMA transfer admission wrapper uses the existing page/fault-aware port
    /// supplied by the machine's DART owner, with checked SID.
    pub fn dma_read(
        &mut self,
        requester: u16,
        address: u64,
        buffer: &mut [u8],
        dma: &mut DmaPort<'_, '_>,
    ) -> Result<(), DmaError> {
        let stream = self.dma_stream(requester, dma.access)?;
        if stream != dma.stream {
            return Err(DmaError::Unsupported(refuse!(
                "PCIe DMA port stream disagrees with RID mapping"
            )));
        }
        dma.read(address, buffer)
    }
    pub fn dma_write(
        &mut self,
        requester: u16,
        address: u64,
        data: &[u8],
        dma: &mut DmaPort<'_, '_>,
    ) -> Result<(), DmaError> {
        let stream = self.dma_stream(requester, dma.access)?;
        if stream != dma.stream {
            return Err(DmaError::Unsupported(refuse!(
                "PCIe DMA port stream disagrees with RID mapping"
            )));
        }
        dma.write(address, data)
    }
    fn update_intx(&mut self, port: usize, access: &mut Access<'_>) {
        let levels = self
            .endpoints
            .iter()
            .filter(|endpoint| {
                endpoint.port == port && endpoint.config.command() & INTX_DISABLE == 0
            })
            .fold(0, |levels, endpoint| levels | endpoint.intx);
        for pin in 0..4 {
            // Deassertion remains valid after link loss. No source can assert
            // while a down link or a reset hides its configuration function.
            let asserted = self.ports[port].link_up()
                && self.secondary(port).is_some()
                && levels & (1 << pin) != 0;
            self.ports[port]
                .set_intx(pin, asserted, access)
                .expect("validated INTx pin/link");
        }
    }
    /// Aggregate level messages from multiple functions before driving the
    /// root's four INTx inputs; disabling INTx suppresses a still-active source.
    pub fn set_intx(
        &mut self,
        requester: u16,
        pin: u8,
        asserted: bool,
        access: &mut Access<'_>,
    ) -> Result<()> {
        if pin >= 4 {
            return Err(refuse!("PCIe INTx pin exceeds D"));
        }
        let index = self.endpoint(requester).map_err(RouteError::reason)?;
        let endpoint = &mut self.endpoints[index];
        if asserted {
            endpoint.intx |= 1 << pin;
        } else {
            endpoint.intx &= !(1 << pin);
        }
        let port = endpoint.port;
        self.update_intx(port, access);
        Ok(())
    }
    fn error(
        offset: u64,
        width: Width,
        direction: Direction,
        reason: impl Into<Refusal>,
    ) -> MmioError {
        refuse(NAME, offset, width, direction, reason)
    }
    fn decode(&self, offset: u64, width: Width) -> Result<(u16, u16)> {
        if width == Width::Double
            || !offset.is_multiple_of(width.bytes())
            || offset >= ECAM_BYTES
            || offset + width.bytes() > ECAM_BYTES
        {
            return Err(refuse!(
                "ECAM requires naturally aligned byte/half/word accesses"
            ));
        }
        let bus = (offset >> 20) as u8;
        if bus < self.first_bus || bus > self.last_bus {
            return Err(refuse!("ECAM bus is outside the declared window"));
        }
        Ok(((offset >> 12) as u16, (offset & 0xfff) as u16))
    }
}

impl Lifecycle for RootComplex {
    fn check_lifecycle(&self, proposed: LifecycleState) -> Result<()> {
        if proposed.reset || !proposed.powered {
            return Err(refuse!(
                "PCIe root-complex physical reset/supply restoration is unqualified"
            ));
        }
        if (!proposed.clocked || proposed.quiesced)
            && self.ports.iter().any(Port::interrupt_pending)
        {
            return Err(refuse!(
                "PCIe controller pause with a pending IRQ has unqualified wake retention"
            ));
        }
        for (index, port) in self.ports.iter().enumerate() {
            self.check_port(index, port, &self.roots[index], proposed)?;
        }
        Ok(())
    }
    fn set_lifecycle(&mut self, proposed: LifecycleState, access: &mut Access<'_>) {
        self.lifecycle = proposed;
        for port in 0..self.ports.len() {
            self.commit_port(port, access);
        }
    }
}
impl MmioDevice for RootComplex {
    fn name(&self) -> &'static str {
        NAME
    }
    fn lifecycle(&mut self) -> Option<&mut dyn Lifecycle> {
        Some(self)
    }
    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        let error = |reason: Refusal| Self::error(offset, width, Direction::Read, reason);
        if !self.lifecycle.clocked {
            return Err(error(refuse!(
                "PCIe MMIO while the controller clock is stopped is unqualified"
            )));
        }
        if offset >= PORT_BASE {
            let port = ((offset - PORT_BASE) / PORT_STRIDE) as usize;
            let register = (offset - PORT_BASE) % PORT_STRIDE;
            if width != Width::Word || !register.is_multiple_of(4) || register >= PORT_BYTES {
                return Err(error(refuse!(
                    "port view requires aligned words in its declared aperture"
                )));
            }
            return self
                .ports
                .get(port)
                .ok_or(error(refuse!("port is not described")))?
                .read(register)
                .map(u64::from);
        }
        let (requester, register) = self.decode(offset, width).map_err(error)?;
        let bus = (requester >> 8) as u8;
        let devfn = requester as u8;
        if bus == self.first_bus {
            if devfn & 7 != 0 || (devfn >> 3) as usize >= self.roots.len() {
                return Ok(width.mask());
            }
            self.roots[(devfn >> 3) as usize]
                .read(register, width)
                .map_err(|_| error(refuse!("root config register is not implemented")))
        } else {
            if self.lifecycle.quiesced {
                return Err(error(refuse!(
                    "PCIe downstream config access while quiesced is unqualified"
                )));
            }
            // An absent function completes enumeration with all ones. Conflicting
            // active roots refuse rather than pretending an endpoint is absent.
            match self.endpoint(requester) {
                Ok(index) => self.endpoints[index]
                    .config
                    .read(register, width)
                    .map_err(|_| error(refuse!("endpoint config register is not implemented"))),
                Err(RouteError::Ambiguous) => {
                    Err(error(refuse!("requester is ambiguous across root ports")))
                }
                Err(_) => Ok(width.mask()),
            }
        }
    }
    fn advance(&mut self, access: &mut Access<'_>) -> Result<Option<u64>, MmioError> {
        if !self.service_enabled() {
            return Ok(None);
        }
        let mut deadline: Option<u64> = None;
        for endpoint in &mut self.endpoints {
            let state = endpoint.state;
            if state.powered
                && state.clocked
                && !state.quiesced
                && !state.reset
                && let Some(next) = endpoint.backend.get_mut().advance(access)?
            {
                deadline = Some(deadline.map_or(next, |current| current.min(next)));
            }
        }
        Ok(deadline)
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let error = |reason: Refusal| Self::error(offset, width, Direction::Write, reason);
        if !self.service_enabled() {
            return Err(error(refuse!("PCIe native controller service is paused")));
        }
        if offset >= PORT_BASE {
            let port = ((offset - PORT_BASE) / PORT_STRIDE) as usize;
            let register = (offset - PORT_BASE) % PORT_STRIDE;
            if width != Width::Word || !register.is_multiple_of(4) || register >= PORT_BYTES {
                return Err(error(refuse!("port view requires aligned words")));
            }
            let candidate = self
                .ports
                .get(port)
                .ok_or(error(refuse!("port is not described")))?
                .preview_write(register, value as u32)?;
            self.check_port(port, &candidate, &self.roots[port], self.lifecycle)
                .map_err(error)?;
            self.ports[port] = candidate;
            self.commit_port(port, access);
            return Ok(());
        }
        let (requester, register) = self.decode(offset, width).map_err(error)?;
        if (requester >> 8) as u8 == self.first_bus {
            let devfn = requester as u8;
            if devfn & 7 != 0 || (devfn >> 3) as usize >= self.roots.len() {
                return Ok(());
            }
            let port = (devfn >> 3) as usize;
            let mut candidate = self.roots[port].clone();
            candidate
                .write(register, width, value)
                .map_err(|_| error(refuse!("root config register is not implemented")))?;
            self.check_port(port, &self.ports[port], &candidate, self.lifecycle)
                .map_err(error)?;
            self.roots[port] = candidate;
            self.commit_port(port, access);
            Ok(())
        } else {
            match self.endpoint(requester) {
                Ok(index) => {
                    self.endpoints[index]
                        .config
                        .write(register, width, value)
                        .map_err(|_| {
                            error(refuse!("endpoint config register is not implemented"))
                        })?;
                    self.update_intx(self.endpoints[index].port, access);
                    Ok(())
                }
                Err(RouteError::Ambiguous) => {
                    Err(error(refuse!("requester is ambiguous across root ports")))
                }
                Err(_) => Ok(()),
            }
        }
    }
}

#[cfg(test)]
mod tests;
