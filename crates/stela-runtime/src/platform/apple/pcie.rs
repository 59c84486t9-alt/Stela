//! Apple PCIe control/configuration core, independent of host PCI drivers.
//!
//! The model is an integration building block, not a loader-admitted Apple
//! controller. Board facts must place each view and supply actual root-port
//! configuration images. Downstream USB-A/Ethernet require real endpoint
//! models and firmware protocols; adding a config header never creates one.
//! See `docs/research/apple-pcie.md` for evidence and unsupported boundaries.
use super::super::dma::{DmaError, Port as DmaPort};
use super::bus::{
    Access, Direction, Lifecycle, LifecycleState, MmioDevice, MmioError, Width, refuse,
};
use alloc::{boxed::Box, vec::Vec};
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
    pub fn new(
        first_bus: u8,
        last_bus: u8,
        ports: Vec<(Port, ConfigSpace)>,
    ) -> Result<Self, &'static str> {
        if first_bus > last_bus || ports.is_empty() || ports.len() > 32 {
            return Err("PCIe ECAM bus/port geometry is invalid");
        }
        for (index, (port, root)) in ports.iter().enumerate() {
            if ports[..index]
                .iter()
                .any(|(prior, _)| prior.management_irq() == port.management_irq())
                || ports
                    .iter()
                    .any(|(other, _)| other.has_msi_wire(port.management_irq()))
            {
                return Err("PCIe management IRQ ownership overlaps another port or MSI wire");
            }
            root.check_header_contract(true)?;
            if root
                .read(0xe, Width::Byte)
                .map_err(|_| "root has no header type")?
                & 0x7f
                != 1
            {
                return Err("PCIe root port needs a type-one bridge header");
            }
            // Lifecycle and topology cannot be enforced without these fields.
            root.read(BUSES, Width::Word)
                .map_err(|_| "root has no bus-number register")?;
            root.read(config::COMMAND, Width::Half)
                .map_err(|_| "root has no command register")?;
            root.read(BRIDGE_CONTROL, Width::Half)
                .map_err(|_| "root has no bridge control")?;
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
    /// from that backend's actual presence. Identity alone is insufficient.
    /// `device_function` packs device in bits 7:3 and function in bits 2:0.
    pub fn attach(
        &mut self,
        port: usize,
        device_function: u8,
        config: ConfigSpace,
        backend: Box<dyn MmioDevice>,
        mappings: Vec<BarMapping>,
        access: &mut Access<'_>,
    ) -> Result<usize, &'static str> {
        if port >= self.ports.len() {
            return Err("PCIe endpoint address is invalid");
        }
        if self
            .endpoints
            .iter()
            .any(|e| e.port == port && e.device_function == device_function)
        {
            return Err("PCIe endpoint address is duplicate");
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
    ) -> Result<(), &'static str> {
        let p = self.ports.get(port).ok_or("PCIe port index is invalid")?;
        if inputs.peer && !self.endpoints.iter().any(|endpoint| endpoint.port == port) {
            return Err("PCIe peer presence requires an actual attached endpoint bank");
        }
        if (!self.lifecycle.clocked || self.lifecycle.quiesced) && inputs != p.inputs() {
            return Err("PCIe external input changes during a controller pause are unqualified");
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
    ) -> Result<(), &'static str> {
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
    /// Caller routes to that actual endpoint; this is never host passthrough.
    pub fn memory_route(&self, address: u64, bytes: u64) -> Result<(usize, u8, u64), &'static str> {
        if !self.service_enabled() {
            return Err("PCIe native controller service is paused");
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
                return Err("PCIe bus-number windows overlap");
            }
            if let Some((bar, offset)) = endpoint
                .config
                .memory_decode(address, bytes)
                .map_err(|_| "PCIe memory BAR decoders overlap")?
            {
                if route.is_some() {
                    return Err("PCIe memory decoders overlap");
                }
                route = Some((index, bar, offset));
            }
        }
        route.ok_or("no active PCIe memory decoder admits the transaction")
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
            .map_err(|error| DmaError::Unsupported(error.reason()))?;
        let endpoint = &self.endpoints[index];
        if endpoint.config.command() & BUS_MASTER_ENABLE == 0
            || self.roots[endpoint.port].command() & BUS_MASTER_ENABLE == 0
        {
            return Err(DmaError::Unsupported("PCIe bus mastering is disabled"));
        }
        self.ports[endpoint.port]
            .stream(requester, access)
            .map_err(|_| DmaError::Unsupported("PCIe requester-to-stream mapping refused"))
    }
    /// DMA transfer admission wrapper uses the existing page/fault-aware port
    /// supplied by the machine's DART owner, with independently checked SID.
    pub fn dma_read(
        &mut self,
        requester: u16,
        address: u64,
        buffer: &mut [u8],
        dma: &mut DmaPort<'_, '_>,
    ) -> Result<(), DmaError> {
        let stream = self.dma_stream(requester, dma.access)?;
        if stream != dma.stream {
            return Err(DmaError::Unsupported(
                "PCIe DMA port stream disagrees with RID mapping",
            ));
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
            return Err(DmaError::Unsupported(
                "PCIe DMA port stream disagrees with RID mapping",
            ));
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
    ) -> Result<(), &'static str> {
        if pin >= 4 {
            return Err("PCIe INTx pin exceeds D");
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
    /// Messages are generated by a real endpoint's MSI/MSI-X implementation;
    /// the root interceptor does not invent that endpoint capability state.
    pub fn msi(
        &mut self,
        requester: u16,
        address: u64,
        data: u32,
        access: &mut Access<'_>,
    ) -> Result<(), &'static str> {
        let endpoint = self.endpoint(requester).map_err(RouteError::reason)?;
        let port = self.endpoints[endpoint].port;
        if self.endpoints[endpoint].config.command() & BUS_MASTER_ENABLE == 0
            || self.roots[port].command() & BUS_MASTER_ENABLE == 0
        {
            return Err("PCIe MSI requester bus mastering is disabled");
        }
        self.ports[port]
            .msi(address, data, access)
            .map_err(|error| if error == port::RequestError::DeliveryUnqualified { "PCIe MSI requires a qualified parent interrupt capture/mask/retirement boundary" } else { "PCIe MSI decoder refused the message" })
    }
    fn error(offset: u64, width: Width, direction: Direction, reason: &'static str) -> MmioError {
        refuse(NAME, offset, width, direction, reason)
    }
    fn decode(&self, offset: u64, width: Width) -> Result<(u16, u16), &'static str> {
        if width == Width::Double
            || !offset.is_multiple_of(width.bytes())
            || offset >= ECAM_BYTES
            || offset + width.bytes() > ECAM_BYTES
        {
            return Err("ECAM requires naturally aligned byte/half/word accesses");
        }
        let bus = (offset >> 20) as u8;
        if bus < self.first_bus || bus > self.last_bus {
            return Err("ECAM bus is outside the declared window");
        }
        Ok(((offset >> 12) as u16, (offset & 0xfff) as u16))
    }
}

impl Lifecycle for RootComplex {
    fn check_lifecycle(&self, proposed: LifecycleState) -> Result<(), &'static str> {
        if proposed.reset || !proposed.powered {
            return Err("PCIe root-complex physical reset/supply restoration is unqualified");
        }
        if (!proposed.clocked || proposed.quiesced)
            && self.ports.iter().any(Port::interrupt_pending)
        {
            return Err("PCIe controller pause with a pending IRQ has unqualified wake retention");
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
        let error = |reason| Self::error(offset, width, Direction::Read, reason);
        if !self.lifecycle.clocked {
            return Err(error(
                "PCIe MMIO while the controller clock is stopped is unqualified",
            ));
        }
        if offset >= PORT_BASE {
            let port = ((offset - PORT_BASE) / PORT_STRIDE) as usize;
            let register = (offset - PORT_BASE) % PORT_STRIDE;
            if width != Width::Word || !register.is_multiple_of(4) || register >= PORT_BYTES {
                return Err(error(
                    "port view requires aligned words in its declared aperture",
                ));
            }
            return self
                .ports
                .get(port)
                .ok_or(error("port is not described"))?
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
                .map_err(|_| error("root config register is not implemented"))
        } else {
            if self.lifecycle.quiesced {
                return Err(error(
                    "PCIe downstream config access while quiesced is unqualified",
                ));
            }
            // An absent function completes enumeration with all ones. Conflicting
            // active roots refuse rather than pretending an endpoint is absent.
            match self.endpoint(requester) {
                Ok(index) => self.endpoints[index]
                    .config
                    .read(register, width)
                    .map_err(|_| error("endpoint config register is not implemented")),
                Err(RouteError::Ambiguous) => {
                    Err(error("requester is ambiguous across root ports"))
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
        let error = |reason| Self::error(offset, width, Direction::Write, reason);
        if !self.service_enabled() {
            return Err(error("PCIe native controller service is paused"));
        }
        if offset >= PORT_BASE {
            let port = ((offset - PORT_BASE) / PORT_STRIDE) as usize;
            let register = (offset - PORT_BASE) % PORT_STRIDE;
            if width != Width::Word || !register.is_multiple_of(4) || register >= PORT_BYTES {
                return Err(error("port view requires aligned words"));
            }
            let candidate = self
                .ports
                .get(port)
                .ok_or(error("port is not described"))?
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
                .map_err(|_| error("root config register is not implemented"))?;
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
                        .map_err(|_| error("endpoint config register is not implemented"))?;
                    self.update_intx(self.endpoints[index].port, access);
                    Ok(())
                }
                Err(RouteError::Ambiguous) => {
                    Err(error("requester is ambiguous across root ports"))
                }
                Err(_) => Ok(()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::interrupt::{AicInput, InterruptLatch};
    use super::config::{MemoryBar, Register};
    use super::port::{APP_CLOCK, LTSSM, Layout, REF_CLOCK};
    use super::*;
    use crate::platform::dma::{Iommu, Memory, tests::Ram};
    use alloc::rc::Rc;
    use core::cell::RefCell;

    struct NativeState {
        state: LifecycleState,
        value: u32,
        owned: usize,
        resets: usize,
        advances: usize,
        refuse_pause: bool,
        fail_advance: bool,
    }
    struct NativeBank(Rc<RefCell<NativeState>>);
    fn native() -> (Box<dyn MmioDevice>, Rc<RefCell<NativeState>>) {
        let shared = Rc::new(RefCell::new(NativeState {
            state: LifecycleState {
                powered: true,
                clocked: true,
                quiesced: false,
                reset: false,
                retention: true,
            },
            value: 0,
            owned: 0,
            resets: 0,
            advances: 0,
            refuse_pause: false,
            fail_advance: false,
        }));
        (Box::new(NativeBank(shared.clone())), shared)
    }
    impl Lifecycle for NativeBank {
        fn check_lifecycle(&self, proposed: LifecycleState) -> Result<(), &'static str> {
            let current = self.0.borrow();
            if current.refuse_pause && (!proposed.clocked || proposed.quiesced) {
                return Err("native endpoint cannot suspend its current external transaction");
            }
            if ((proposed.reset && !current.state.reset)
                || (!proposed.powered && !proposed.retention))
                && current.owned != 0
            {
                return Err("native endpoint still owns work before physical reset");
            }
            Ok(())
        }
        fn set_lifecycle(&mut self, proposed: LifecycleState, _: &mut Access<'_>) {
            let mut current = self.0.borrow_mut();
            if proposed.reset && !current.state.reset {
                current.value = 0;
                current.resets += 1;
            }
            current.state = proposed;
        }
    }
    impl MmioDevice for NativeBank {
        fn name(&self) -> &'static str {
            "native PCIe fixture bank"
        }
        fn advance(&mut self, access: &mut Access<'_>) -> Result<Option<u64>, MmioError> {
            let mut state = self.0.borrow_mut();
            if state.fail_advance {
                return Err(refuse(
                    self.name(),
                    0x104,
                    Width::Word,
                    Direction::Read,
                    "native service could not advance",
                ));
            }
            state.advances += 1;
            Ok(Some(access.now + 24))
        }
        fn lifecycle(&mut self) -> Option<&mut dyn Lifecycle> {
            Some(self)
        }
        fn read(
            &mut self,
            offset: u64,
            width: Width,
            _: &mut Access<'_>,
        ) -> Result<u64, MmioError> {
            if offset != 0x100 || width != Width::Word {
                return Err(refuse(
                    self.name(),
                    offset,
                    width,
                    Direction::Read,
                    "no native register at this BAR offset",
                ));
            }
            Ok(u64::from(self.0.borrow().value))
        }
        fn write(
            &mut self,
            offset: u64,
            width: Width,
            value: u64,
            _: &mut Access<'_>,
        ) -> Result<(), MmioError> {
            if offset != 0x100 || width != Width::Word {
                return Err(refuse(
                    self.name(),
                    offset,
                    width,
                    Direction::Write,
                    "no native register at this BAR offset",
                ));
            }
            self.0.borrow_mut().value = value as u32;
            Ok(())
        }
    }
    fn attach(
        root: &mut RootComplex,
        port: usize,
        function: u8,
        access: &mut Access<'_>,
    ) -> Rc<RefCell<NativeState>> {
        let (backend, shared) = native();
        root.attach(
            port,
            function,
            endpoint_config(),
            backend,
            alloc::vec![BarMapping {
                bar: 0,
                device_offset: 0x100
            }],
            access,
        )
        .unwrap();
        shared
    }

    fn register(offset: u16, reset: u32, writable: u32) -> Register {
        Register {
            offset,
            reset,
            writable,
            clear: 0,
        }
    }
    // Synthetic identities are test fixtures, never production Apple IDs.
    fn root_config() -> ConfigSpace {
        ConfigSpace::new(
            &[
                register(0, 0x1234_abcd, 0),
                register(4, 0, 0x406),
                register(0xc, 1 << 16, 0),
                register(0x18, 0, 0x00ff_ffff),
                register(0x20, 0x0000_fff0, 0xfff0_fff0),
                register(0x24, 0x0001_fff1, 0xfff0_fff0),
                register(0x28, 0, u32::MAX),
                register(0x2c, 0, u32::MAX),
                register(0x3c, 0, (SECONDARY_RESET as u32) << 16),
            ],
            Vec::new(),
        )
        .unwrap()
    }
    fn endpoint_config() -> ConfigSpace {
        ConfigSpace::new(
            &[
                register(0, 0xf00d_1234, 0),
                register(4, 0, 0x406),
                register(0xc, 0, 0),
            ],
            alloc::vec![MemoryBar::new(0, 0x4000, true, false).unwrap()],
        )
        .unwrap()
    }
    fn machine() -> RootComplex {
        let p = Port::new(
            Layout::T8103,
            64,
            AicInput::new(0, 1),
            (0..32).map(|i| AicInput::new(0, 32 + i)).collect(),
        )
        .unwrap();
        let mut root = RootComplex::new(0, 3, alloc::vec![(p, root_config())]).unwrap();
        attach(
            &mut root,
            0,
            0,
            &mut Access::new(0, 0, &mut InterruptLatch::new()),
        );
        root
    }
    fn enable(root: &mut RootComplex, a: &mut Access<'_>) {
        root.set_port_inputs(
            0,
            Inputs {
                powered: true,
                reference_clock: true,
                external_reset_released: true,
                peer: true,
                link_trained: true,
            },
            a,
        )
        .unwrap();
        for (offset, value) in [(APP_CLOCK, 1), (REF_CLOCK, 1), (0x814, 1), (LTSSM, 1)] {
            root.write(PORT_BASE + offset, Width::Word, value, a)
                .unwrap();
        }
        root.write(0x18, Width::Word, 0x0001_0100, a).unwrap();
    }
    #[test]
    fn ecam_enumeration_is_gated_by_link_and_programmed_bridge_bus() {
        let mut root = machine();
        let mut l = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut l);
        assert_eq!(root.read(1 << 20, Width::Word, &mut a), Ok(0xffff_ffff));
        enable(&mut root, &mut a);
        assert_eq!(root.read(0, Width::Word, &mut a), Ok(0x1234_abcd));
        assert_eq!(root.read(1 << 20, Width::Word, &mut a), Ok(0xf00d_1234));
        assert_eq!(
            root.read((1 << 20) + 0x1000, Width::Word, &mut a),
            Ok(0xffff_ffff)
        );
        assert!(root.read(2, Width::Word, &mut a).is_err());
        assert!(root.read(4 << 20, Width::Word, &mut a).is_err());
        root.write(0x18, Width::Word, 0x0002_0200, &mut a).unwrap();
        assert_eq!(root.read(1 << 20, Width::Word, &mut a), Ok(0xffff_ffff));
        assert_eq!(root.read(2 << 20, Width::Word, &mut a), Ok(0xf00d_1234));
    }
    #[test]
    fn memory_requires_both_bridge_window_and_endpoint_bar_decode() {
        let mut root = machine();
        let mut l = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut l);
        enable(&mut root, &mut a);
        let endpoint = 1 << 20;
        root.write(endpoint + 0x10, Width::Word, 0xc000_0000, &mut a)
            .unwrap();
        root.write(endpoint + 0x14, Width::Word, 0, &mut a).unwrap();
        root.write(endpoint + 4, Width::Half, 6, &mut a).unwrap();
        assert!(root.memory_route(0xc000_0010, 4).is_err());
        root.write(4, Width::Half, 6, &mut a).unwrap();
        root.write(0x20, Width::Word, 0xc000_c000, &mut a).unwrap();
        assert_eq!(root.memory_route(0xc000_0010, 4), Ok((0, 0, 0x10)));
        assert!(root.memory_route(0xc000_3fff, 2).is_err());
        // A 64-bit prefetch window, with exact upper-base/limit handling.
        root.write(endpoint + 0x14, Width::Word, 6, &mut a).unwrap();
        root.write(0x24, Width::Word, 0xc001_c001, &mut a).unwrap();
        root.write(0x28, Width::Word, 6, &mut a).unwrap();
        root.write(0x2c, Width::Word, 6, &mut a).unwrap();
        assert_eq!(root.memory_route(0x6_c000_0010, 4), Ok((0, 0, 0x10)));
    }
    struct CheckedIommu {
        seen: Vec<usize>,
    }
    impl Iommu for CheckedIommu {
        fn page(&self) -> u64 {
            0x1000
        }
        fn translate(
            &mut self,
            _: &mut dyn Memory,
            stream: usize,
            iova: u64,
            last: u64,
            _: bool,
            _: &mut Access<'_>,
        ) -> Result<u64, DmaError> {
            self.seen.push(stream);
            if stream != 7 || last >= 0x2000 {
                return Err(DmaError::Fault(0x123));
            }
            Ok(iova + 0x10000)
        }
    }
    #[test]
    fn dma_requires_busmaster_rid_mapping_matching_dart_and_propagates_faults() {
        let mut root = machine();
        let mut l = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut l);
        enable(&mut root, &mut a);
        assert!(root.dma_stream(0x100, &mut a).is_err());
        root.write((1 << 20) + 4, Width::Half, 6, &mut a).unwrap();
        assert!(root.dma_stream(0x100, &mut a).is_err());
        root.write(4, Width::Half, 6, &mut a).unwrap();
        assert!(root.dma_stream(0x100, &mut a).is_err());
        root.write(PORT_BASE + 0x828, Width::Word, 0x8007_0100, &mut a)
            .unwrap();
        assert_eq!(root.dma_stream(0x100, &mut a), Ok(7));
        let mut ram = Ram::new(0x10000, 0x3000);
        let mut iommu = CheckedIommu { seen: Vec::new() };
        let mut dma = DmaPort {
            iommu: &mut iommu,
            stream: 6,
            memory: &mut ram,
            access: &mut a,
        };
        assert!(root.dma_write(0x100, 0, &[1, 2, 3, 4], &mut dma).is_err());
        dma.stream = 7;
        root.dma_write(0x100, 0xffe, &[1, 2, 3, 4], &mut dma)
            .unwrap();
        let mut result = [0; 4];
        root.dma_read(0x100, 0xffe, &mut result, &mut dma).unwrap();
        assert_eq!(result, [1, 2, 3, 4]);
        assert_eq!(
            root.dma_read(0x100, 0x2000, &mut result, &mut dma),
            Err(DmaError::Fault(0x123))
        );
        assert_eq!(
            root.dma_write(0x100, 0x1ffe, &[9, 8, 7, 6], &mut dma),
            Err(DmaError::Fault(0x123))
        );
        let mut committed = [0; 4];
        assert!(dma.memory.read(0x11ffe, &mut committed));
        assert_eq!(committed, [9, 8, 0, 0]);
        assert!(iommu.seen.iter().all(|&sid| sid == 7));
    }
    #[test]
    fn secondary_reset_reaches_native_owner_and_unqualified_port_power_loss_refuses() {
        let mut root = machine();
        let mut l = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut l);
        enable(&mut root, &mut a);
        root.write((1 << 20) + 4, Width::Half, 6, &mut a).unwrap();
        root.write(0x3e, Width::Half, SECONDARY_RESET, &mut a)
            .unwrap();
        assert_eq!(root.read(1 << 20, Width::Word, &mut a), Ok(0xffff_ffff));
        root.write(0x3e, Width::Half, 0, &mut a).unwrap();
        assert_eq!(root.read((1 << 20) + 4, Width::Half, &mut a), Ok(0));
        assert!(root.set_port_inputs(0, Inputs::default(), &mut a).is_err());
        assert_eq!(root.read(PORT_BASE + APP_CLOCK, Width::Word, &mut a), Ok(1));
    }
    #[test]
    fn overlapping_root_bus_numbers_refuse_instead_of_routing_by_function() {
        let mut root = machine();
        root.ports.push(
            Port::new(
                Layout::T8103,
                64,
                AicInput::new(0, 2),
                (0..32).map(|i| AicInput::new(0, 32 + i)).collect(),
            )
            .unwrap(),
        );
        root.roots.push(root_config());
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        attach(&mut root, 1, 0, &mut access);
        enable(&mut root, &mut access);
        root.set_port_inputs(
            1,
            Inputs {
                powered: true,
                reference_clock: true,
                external_reset_released: true,
                peer: true,
                link_trained: true,
            },
            &mut access,
        )
        .unwrap();
        for (offset, value) in [(APP_CLOCK, 1), (REF_CLOCK, 1), (0x814, 1), (LTSSM, 1)] {
            root.write(
                PORT_BASE + PORT_STRIDE + offset,
                Width::Word,
                value,
                &mut access,
            )
            .unwrap();
        }
        root.write((1 << 15) + 0x18, Width::Word, 0x0001_0100, &mut access)
            .unwrap();
        // Matching endpoints on two roots cannot resolve overlapping bus windows.
        assert!(root.read(1 << 20, Width::Word, &mut access).is_err());
        assert!(root.write(1 << 20, Width::Word, 0, &mut access).is_err());
        assert!(root.dma_stream(0x100, &mut access).is_err());
    }
    #[test]
    fn shared_intx_sources_hold_the_pin_until_all_enabled_functions_deassert() {
        let mut root = machine();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        attach(&mut root, 0, 1, &mut access);
        enable(&mut root, &mut access);
        root.set_intx(0x100, 0, true, &mut access).unwrap();
        root.set_intx(0x101, 0, true, &mut access).unwrap();
        root.set_intx(0x100, 0, false, &mut access).unwrap();
        assert_eq!(
            root.read(PORT_BASE + port::INT_STATUS, Width::Word, &mut access)
                .unwrap()
                & 1,
            1
        );
        root.write(
            (1 << 20) + 0x1000 + 4,
            Width::Half,
            u64::from(INTX_DISABLE),
            &mut access,
        )
        .unwrap();
        assert_eq!(
            root.read(PORT_BASE + port::INT_STATUS, Width::Word, &mut access)
                .unwrap()
                & 1,
            0
        );
        root.write((1 << 20) + 0x1000 + 4, Width::Half, 0, &mut access)
            .unwrap();
        assert_eq!(
            root.read(PORT_BASE + port::INT_STATUS, Width::Word, &mut access)
                .unwrap()
                & 1,
            1
        );
        root.write(0x3e, Width::Half, SECONDARY_RESET, &mut access)
            .unwrap();
        assert_eq!(
            root.read(PORT_BASE + port::INT_STATUS, Width::Word, &mut access)
                .unwrap()
                & 1,
            0
        );
    }
    fn map_memory(root: &mut RootComplex, access: &mut Access<'_>) {
        root.write((1 << 20) + 0x10, Width::Word, 0xc000_0000, access)
            .unwrap();
        root.write((1 << 20) + 0x14, Width::Word, 0, access)
            .unwrap();
        root.write((1 << 20) + 4, Width::Half, 6, access).unwrap();
        root.write(4, Width::Half, 6, access).unwrap();
        root.write(0x20, Width::Word, 0xc000_c000, access).unwrap();
    }
    #[test]
    fn actual_bar_bank_and_service_receive_effects_and_preserve_native_errors() {
        let mut root = machine();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 120, &mut latch);
        enable(&mut root, &mut access);
        map_memory(&mut root, &mut access);
        root.write_memory(0xc000_0000, Width::Word, 0x1234, &mut access)
            .unwrap();
        assert_eq!(
            root.read_memory(0xc000_0000, Width::Word, &mut access),
            Ok(0x1234)
        );
        assert!(matches!(
            root.write_memory(0xc000_0004, Width::Word, 5, &mut access),
            Err(MmioError::Unsupported {
                device: "native PCIe fixture bank",
                offset: 0x104,
                ..
            })
        ));
        assert_eq!(
            root.read_memory(0xc000_0000, Width::Word, &mut access),
            Ok(0x1234)
        );
        assert_eq!(root.advance(&mut access), Ok(Some(144)));
    }
    #[test]
    fn whole_port_preflight_preserves_bridge_config_and_every_native_owner_on_refusal() {
        let mut root = machine();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let second = attach(&mut root, 0, 1, &mut access);
        enable(&mut root, &mut access);
        map_memory(&mut root, &mut access);
        root.write_memory(0xc000_0000, Width::Word, 0xbeef, &mut access)
            .unwrap();
        second.borrow_mut().owned = 1;
        let resets = second.borrow().resets;
        assert!(
            root.write(0x3e, Width::Half, SECONDARY_RESET, &mut access)
                .is_err()
        );
        assert_eq!(root.read(0x3e, Width::Half, &mut access), Ok(0));
        assert_eq!(
            root.read_memory(0xc000_0000, Width::Word, &mut access),
            Ok(0xbeef)
        );
        assert_eq!(second.borrow().resets, resets);
        assert_eq!(second.borrow().owned, 1);
        assert!(
            root.write(PORT_BASE + 0x814, Width::Word, 0, &mut access)
                .is_err()
        );
        assert_eq!(
            root.read(PORT_BASE + 0x814, Width::Word, &mut access),
            Ok(1)
        );
        assert_eq!(
            root.read_memory(0xc000_0000, Width::Word, &mut access),
            Ok(0xbeef)
        );
        second.borrow_mut().owned = 0;
        root.write(0x3e, Width::Half, SECONDARY_RESET, &mut access)
            .unwrap();
        assert_eq!(second.borrow().resets, resets + 1);
        root.write(0x3e, Width::Half, SECONDARY_RESET, &mut access)
            .unwrap();
        assert_eq!(second.borrow().resets, resets + 1);
        root.write(0x3e, Width::Half, 0, &mut access).unwrap();
        assert_eq!(root.read((1 << 20) + 4, Width::Half, &mut access), Ok(0));
        map_memory(&mut root, &mut access);
        assert_eq!(
            root.read_memory(0xc000_0000, Width::Word, &mut access),
            Ok(0)
        );
    }
    #[test]
    fn retained_clock_quiesce_and_peer_loss_pause_without_resetting_actual_work() {
        let mut root = machine();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let second = attach(&mut root, 0, 1, &mut access);
        enable(&mut root, &mut access);
        map_memory(&mut root, &mut access);
        root.write_memory(0xc000_0000, Width::Word, 91, &mut access)
            .unwrap();
        second.borrow_mut().owned = 7;
        let resets = second.borrow().resets;
        let running = root.lifecycle;
        for paused in [
            LifecycleState {
                clocked: false,
                ..running
            },
            LifecycleState {
                quiesced: true,
                ..running
            },
        ] {
            root.check_lifecycle(paused).unwrap();
            root.set_lifecycle(paused, &mut access);
            assert_eq!(second.borrow().state.clocked, paused.clocked);
            assert_eq!(second.borrow().state.quiesced, paused.quiesced);
            assert_eq!(root.advance(&mut access), Ok(None));
            assert!(
                root.read_memory(0xc000_0000, Width::Word, &mut access)
                    .is_err()
            );
            assert!(root.dma_stream(0x100, &mut access).is_err());
            root.check_lifecycle(running).unwrap();
            root.set_lifecycle(running, &mut access);
            assert_eq!(
                root.read_memory(0xc000_0000, Width::Word, &mut access),
                Ok(91)
            );
            assert_eq!(second.borrow().owned, 7);
            assert_eq!(second.borrow().resets, resets);
        }
        root.write(PORT_BASE + APP_CLOCK, Width::Word, 0, &mut access)
            .unwrap();
        assert!(!second.borrow().state.clocked);
        assert!(!second.borrow().state.reset);
        root.write(PORT_BASE + APP_CLOCK, Width::Word, 1, &mut access)
            .unwrap();
        assert_eq!(
            root.read_memory(0xc000_0000, Width::Word, &mut access),
            Ok(91)
        );
        let inputs = root.ports[0].inputs();
        root.set_port_inputs(
            0,
            Inputs {
                peer: false,
                ..inputs
            },
            &mut access,
        )
        .unwrap();
        assert!(second.borrow().state.quiesced);
        assert!(!second.borrow().state.reset);
        root.set_port_inputs(0, inputs, &mut access).unwrap();
        assert_eq!(second.borrow().owned, 7);
        assert_eq!(second.borrow().resets, resets);
        assert_eq!(root.advance(&mut access), Ok(Some(24)));
        assert_eq!(second.borrow().advances, 1);
    }
    #[test]
    fn armed_irq_pause_and_cold_root_reset_refuse_without_dropping_pending_levels() {
        let mut root = machine();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        enable(&mut root, &mut access);
        root.write(
            PORT_BASE + port::INT_MASK_CLEAR,
            Width::Word,
            1,
            &mut access,
        )
        .unwrap();
        root.set_intx(0x100, 0, true, &mut access).unwrap();
        assert!(
            root.check_lifecycle(LifecycleState {
                quiesced: true,
                ..root.lifecycle
            })
            .is_err()
        );
        assert!(
            root.check_lifecycle(LifecycleState {
                reset: true,
                ..root.lifecycle
            })
            .is_err()
        );
        assert!(
            root.check_lifecycle(LifecycleState {
                powered: false,
                retention: false,
                ..root.lifecycle
            })
            .is_err()
        );
        assert_eq!(
            root.read(PORT_BASE + port::INT_STATUS, Width::Word, &mut access)
                .unwrap()
                & 1,
            1
        );
        assert!(latch.is_asserted(super::super::interrupt::Wire::Aic(AicInput::new(0, 1))));
    }
    #[test]
    fn peer_presence_requires_actual_complete_bar_and_lifecycle_ownership() {
        let p = Port::new(
            Layout::T8103,
            16,
            AicInput::new(0, 1),
            alloc::vec![AicInput::new(0, 2)],
        )
        .unwrap();
        let mut root = RootComplex::new(0, 3, alloc::vec![(p, root_config())]).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        assert!(
            root.set_port_inputs(
                0,
                Inputs {
                    peer: true,
                    ..Inputs::default()
                },
                &mut access
            )
            .is_err()
        );
        let (backend, _) = native();
        assert!(
            root.attach(0, 0, endpoint_config(), backend, Vec::new(), &mut access)
                .is_err()
        );
        let (backend, _) = native();
        assert!(
            root.attach(
                0,
                0,
                endpoint_config(),
                backend,
                alloc::vec![BarMapping {
                    bar: 0,
                    device_offset: u64::MAX
                }],
                &mut access
            )
            .is_err()
        );
        struct ConfigOnly;
        impl MmioDevice for ConfigOnly {
            fn name(&self) -> &'static str {
                "config-only fixture"
            }
            fn read(&mut self, _: u64, _: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
                unreachable!()
            }
            fn write(
                &mut self,
                _: u64,
                _: Width,
                _: u64,
                _: &mut Access<'_>,
            ) -> Result<(), MmioError> {
                unreachable!()
            }
        }
        assert!(
            root.attach(
                0,
                0,
                endpoint_config(),
                Box::new(ConfigOnly),
                alloc::vec![BarMapping {
                    bar: 0,
                    device_offset: 0
                }],
                &mut access
            )
            .is_err()
        );
    }
    #[test]
    fn whole_fabric_pause_preflight_and_native_service_failure_preserve_prior_effects() {
        let p = Port::new(
            Layout::T8103,
            16,
            AicInput::new(0, 1),
            alloc::vec![AicInput::new(0, 2)],
        )
        .unwrap();
        let mut root = RootComplex::new(0, 3, alloc::vec![(p, root_config())]).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let first = attach(&mut root, 0, 0, &mut access);
        let second = attach(&mut root, 0, 1, &mut access);
        enable(&mut root, &mut access);
        second.borrow_mut().refuse_pause = true;
        let running = root.lifecycle;
        assert!(
            root.check_lifecycle(LifecycleState {
                clocked: false,
                ..running
            })
            .is_err()
        );
        assert_eq!(root.lifecycle, running);
        assert_eq!(first.borrow().state, running);
        assert_eq!(second.borrow().state, running);
        second.borrow_mut().fail_advance = true;
        assert!(matches!(
            root.advance(&mut access),
            Err(MmioError::Unsupported {
                device: "native PCIe fixture bank",
                offset: 0x104,
                ..
            })
        ));
        assert_eq!(first.borrow().advances, 1);
        assert_eq!(second.borrow().advances, 0);
    }
    #[test]
    fn an_ambiguous_bar_cannot_disappear_and_select_another_native_function() {
        let mut root = machine();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        enable(&mut root, &mut access);
        map_memory(&mut root, &mut access);
        let config = ConfigSpace::new(
            &[
                register(0, 0x1234, 0),
                register(4, 2, 0x406),
                register(0xc, 0, 0),
            ],
            alloc::vec![
                MemoryBar::new(0, 0x4000, false, false).unwrap(),
                MemoryBar::new(1, 0x4000, false, false).unwrap()
            ],
        )
        .unwrap();
        let (bank, _) = native();
        root.attach(
            0,
            1,
            config,
            bank,
            alloc::vec![
                BarMapping {
                    bar: 0,
                    device_offset: 0x100
                },
                BarMapping {
                    bar: 1,
                    device_offset: 0x100
                }
            ],
            &mut access,
        )
        .unwrap();
        for offset in [0x10, 0x14] {
            root.write(
                (1 << 20) + 0x1000 + offset,
                Width::Word,
                0xc000_0000,
                &mut access,
            )
            .unwrap();
        }
        assert_eq!(
            root.memory_route(0xc000_0000, 4),
            Err("PCIe memory BAR decoders overlap")
        );
        assert!(
            root.read_memory(0xc000_0000, Width::Word, &mut access)
                .is_err()
        );
    }
    #[cfg(feature = "std")]
    use sha2::{Digest, Sha256};

    #[cfg(feature = "std")]
    #[test]
    fn all_59_original_boards_keep_distinct_declared_internal_pcie_resources() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../isa/apple-board-interfaces.json");
        let bytes = std::fs::read(path).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            "259773f7815c66612f2937085ad087c9afd01819117031fcdfc4a8c9e8c3a831"
        );
        let ledger: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let boards = ledger["boards"].as_array().unwrap();
        assert_eq!(boards.len(), 59);
        let mut counts = std::collections::BTreeMap::new();
        for board in boards {
            let chip = board["chip_id"].as_str().unwrap();
            let mut internal = 0;
            for interface in board["interfaces"].as_array().unwrap() {
                if !interface["compatible"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|value| {
                        let compatible = value.as_str().unwrap();
                        compatible.starts_with("apcie,") || compatible.starts_with("apcie-ge,")
                    })
                {
                    continue;
                }
                let properties = interface["properties"].as_array().unwrap();
                let reg = properties.iter().find(|row| row[0] == "reg").unwrap();
                let cells = reg[3].as_array().unwrap();
                assert_eq!(reg[2].as_u64().unwrap() % 16, 0);
                assert_eq!(cells[2], "0x10000000");
                assert_eq!(cells[3], "0x0");
                let ports = properties.iter().find(|row| row[0] == "#ports").unwrap();
                assert_eq!(ports[2], 4);
                let n = ports[3][0].as_str().unwrap();
                assert!(matches!(n, "0x1" | "0x3" | "0x4"));
                assert_eq!(
                    board["source"]["decoded_sha256"].as_str().unwrap().len(),
                    64
                );
                internal += 1;
            }
            assert!(
                internal > 0,
                "{} has no inventoried internal PCIe interface",
                board["device_class"]
            );
            *counts.entry(chip).or_insert(0usize) += internal;
        }
        let expected = [
            ("0x6000", 2),
            ("0x6001", 3),
            ("0x6002", 1),
            ("0x6020", 3),
            ("0x6021", 3),
            ("0x6022", 3),
            ("0x6030", 2),
            ("0x6031", 2),
            ("0x6032", 2),
            ("0x6034", 2),
            ("0x6040", 3),
            ("0x6041", 3),
            ("0x6050", 7),
            ("0x8103", 5),
            ("0x8112", 4),
            ("0x8122", 5),
            ("0x8132", 6),
            ("0x8140", 1),
            ("0x8142", 3),
            ("0x8152", 1),
        ]
        .into_iter()
        .collect();
        assert_eq!(counts, expected);
    }

    #[cfg(feature = "std")]
    #[test]
    #[ignore = "requires STELA_PCIE_KERNELCACHE naming the pinned original 26A434 Mach-O"]
    fn original_msi_vector_delegation_and_port_decoder_are_pinned() {
        let bytes = std::fs::read(
            std::env::var_os("STELA_PCIE_KERNELCACHE").expect("original KernelCache path"),
        )
        .unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            "06846c718a67715f540c7f5a5d5a183da6185d94b6fc01f1ce57a30b601be44d"
        );
        // KC affine VA = file offset + 0xfffffe0007004000. Original
        // ApplePCIEMSIController dispatches to its parent, not a guessed local
        // MSI status/ack bank. Vtable slots alone do not qualify electrical
        // capture or retirement behavior in that parent.
        for (offset, opcode) in [
            (0x24285d0, 0x9400ca13u32), // handleInterrupt: assertion call
            (0x24287a8, 0xf9406100),    // initVector: parent at +0xc0
            (0x24287c8, 0xd2811911),    // initVector: slot 0x8c8
            (0x24289bc, 0xf9406100),    // enableVector: same parent
            (0x24289dc, 0xd2811c11),    // enableVector: slot 0x8e0
            (0x2428bd0, 0xf9406100),    // disableVectorHard: same parent
            (0x2428bf0, 0xd2811b11),    // disableVectorHard: slot 0x8d8
            (0x2f81198, 0x12001109),    // configMSIRange: base & 0x1f
            (0x2f811a4, 0x2a094108),    // pack low16 and low5 << 16
            (0x2f811d0, 0x52802481),    // write decoder at 0x124
            (0x2f81204, 0x52802501),    // write packed base at 0x128
            (0x2f81270, 0x52802d01),    // write doorbell at 0x168
        ] {
            assert_eq!(
                u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()),
                opcode,
                "original opcode at {offset:#x}"
            );
        }
    }
}
