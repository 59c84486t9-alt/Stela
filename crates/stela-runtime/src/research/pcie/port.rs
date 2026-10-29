//! Apple port control, interrupts, MSI decoding and requester-to-stream maps.
//! Register facts: Linux v6.17 `drivers/pci/controller/pcie-apple.c`.
//! Link readiness is derived from actual modeled supplies and a backed peer.
//! Analog training, ASPM, tunnel-reset handshakes and AER recovery refuse.
use alloc::vec::Vec;
use {
    stela_contracts::bus::Access, stela_contracts::bus::Direction, stela_contracts::bus::MmioError,
    stela_contracts::bus::Width, stela_contracts::bus::refuse,
    stela_contracts::interrupt::AicInput, stela_contracts::interrupt::Wire,
};

pub const LTSSM: u64 = 0x80;
pub const INT_STATUS: u64 = 0x100;
pub const INT_MASK: u64 = 0x104;
pub const INT_MASK_SET: u64 = 0x108;
pub const INT_MASK_CLEAR: u64 = 0x10c;
pub const MSI_CONFIG: u64 = 0x124;
pub const MSI_BASE: u64 = 0x128;
pub const LINK_STATUS: u64 = 0x208;
pub const APP_CLOCK: u64 = 0x800;
pub const PORT_STATUS: u64 = 0x804;
pub const REF_CLOCK: u64 = 0x810;
const LINK_UP: u32 = 1 << 12;
const LINK_DOWN: u32 = 1 << 14;
const VALID: u32 = 1 << 31;
const CLOCK_MASK: u32 = 1 | 1 << 8;
const NAME: &str = "Apple PCIe port";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// T8103/T6000/T8112 register family. Capacity remains evidence supplied.
    T8103,
    /// T602x register family; never infer its table capacity from Linux's
    /// future-hardware probe ceiling (512).
    T6020,
}
impl Layout {
    fn reset(self) -> u64 {
        match self {
            Self::T8103 => 0x814,
            Self::T6020 => 0x82c,
        }
    }
    fn sid(self) -> u64 {
        match self {
            Self::T8103 => 0x828,
            Self::T6020 => 0x3000,
        }
    }
    fn msi(self) -> u64 {
        match self {
            Self::T8103 => 0x168,
            Self::T6020 => 0x16c,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestError {
    LinkDown,
    MissingMapping,
    AmbiguousMapping,
    MsiDisabled,
    MsiAddress,
    MsiData,
    DeliveryUnqualified,
}

/// External facts from PMGR/PHY/connector owners. `peer` means an attached
/// implemented endpoint or established tunnel, never just a visible DT node.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Inputs {
    pub powered: bool,
    pub reference_clock: bool,
    pub external_reset_released: bool,
    pub peer: bool,
    /// Established training result supplied by the actual PHY/link owner.
    /// A populated function and LTSSM start alone cannot train a link.
    pub link_trained: bool,
}

#[derive(Clone)]
pub struct Port {
    layout: Layout,
    inputs: Inputs,
    irq: AicInput,
    msi_irqs: Vec<AicInput>,
    sid: Vec<u32>,
    msi_map: Vec<u32>,
    app_clock: u32,
    ref_clock: u32,
    reset: u32,
    ltssm: u32,
    status: u32,
    mask: u32,
    intx: u32,
    msi_config: u32,
    msi_base: u32,
    msi_address: u64,
    link: bool,
}
impl Port {
    pub fn new(
        layout: Layout,
        mappings: usize,
        irq: AicInput,
        msi_irqs: Vec<AicInput>,
    ) -> Result<Self, &'static str> {
        let max = match layout {
            Layout::T8103 => 64,
            Layout::T6020 => 512,
        };
        if mappings == 0
            || mappings > max
            || msi_irqs.is_empty()
            || msi_irqs.len() > 256
            || !msi_irqs.len().is_power_of_two()
        {
            return Err("PCIe table/vector capacity is invalid");
        }
        if msi_irqs
            .iter()
            .enumerate()
            .any(|(i, line)| msi_irqs[..i].contains(line) || *line == irq)
        {
            return Err("PCIe MSI wires overlap");
        }
        Ok(Self {
            layout,
            inputs: Inputs::default(),
            irq,
            msi_map: alloc::vec![0; msi_irqs.len()],
            msi_irqs,
            sid: alloc::vec![0; mappings],
            app_clock: 0,
            ref_clock: 0,
            reset: 0,
            ltssm: 0,
            status: 0,
            mask: u32::MAX,
            intx: 0,
            msi_config: 0,
            msi_base: 0,
            msi_address: 0,
            link: false,
        })
    }
    pub fn link_up(&self) -> bool {
        self.link
    }
    pub(super) fn management_irq(&self) -> AicInput {
        self.irq
    }
    pub(super) fn has_msi_wire(&self, irq: AicInput) -> bool {
        self.msi_irqs.contains(&irq)
    }
    pub(super) fn inputs(&self) -> Inputs {
        self.inputs
    }
    pub(super) fn clock_running(&self) -> bool {
        self.inputs.reference_clock
            && self.app_clock & 1 != 0
            && (self.layout != Layout::T8103 || self.ref_clock & 1 != 0)
    }
    pub(super) fn reset_released(&self) -> bool {
        self.inputs.external_reset_released && self.reset & 1 != 0
    }
    pub(super) fn interrupt_pending(&self) -> bool {
        (self.status | self.intx) & !self.mask != 0
    }
    fn ready(&self) -> bool {
        self.inputs.powered
            && self.inputs.reference_clock
            && self.inputs.external_reset_released
            && self.app_clock & 1 != 0
            && self.reset & 1 != 0
            && (self.layout != Layout::T8103 || self.ref_clock & 1 != 0)
    }
    fn update(&mut self, access: &mut Access<'_>) {
        let link =
            self.ready() && self.inputs.peer && self.inputs.link_trained && self.ltssm & 1 != 0;
        if link != self.link {
            self.status |= if link { LINK_UP } else { LINK_DOWN };
            if !link {
                self.intx = 0;
            }
            self.link = link;
        }
        access.interrupts.set_level(
            Wire::Aic(self.irq),
            (self.status | self.intx) & !self.mask != 0,
        );
    }
    /// Source has not established port cold-reset/retention values. Refuse a
    /// live rail-loss edge instead of clearing routing as a guessed reset.
    pub fn set_inputs(
        &mut self,
        inputs: Inputs,
        access: &mut Access<'_>,
    ) -> Result<(), &'static str> {
        if self.inputs.powered && !inputs.powered {
            return Err("PCIe port supply loss and volatile routing restoration are unqualified");
        }
        self.inputs = inputs;
        self.update(access);
        Ok(())
    }
    pub fn set_intx(
        &mut self,
        pin: u8,
        asserted: bool,
        access: &mut Access<'_>,
    ) -> Result<(), &'static str> {
        if pin >= 4 {
            return Err("PCIe INTx pin exceeds D");
        }
        if asserted && !self.link {
            return Err("PCIe INTx on a down link");
        }
        if asserted {
            self.intx |= 1 << pin;
        } else {
            self.intx &= !(1 << pin);
        }
        self.update(access);
        Ok(())
    }
    /// Missing/ambiguous routing refuses without inventing a hardware TLP
    /// error: error-capture cause and retirement remain unqualified.
    pub fn stream(
        &mut self,
        requester: u16,
        _access: &mut Access<'_>,
    ) -> Result<usize, RequestError> {
        if !self.link {
            return Err(RequestError::LinkDown);
        }
        let mut matches = self
            .sid
            .iter()
            .filter(|&&entry| entry & VALID != 0 && entry as u16 == requester);
        let first = matches.next().copied();
        let ambiguous = matches.next().is_some();
        match (first, ambiguous) {
            (Some(entry), false) => Ok(((entry >> 16) & 0xff) as usize),
            (_, duplicate) => Err(if duplicate {
                RequestError::AmbiguousMapping
            } else {
                RequestError::MissingMapping
            }),
        }
    }
    /// MSI interception precedes DART translation. Only an enabled decoder
    /// at its programmed address decodes a 32-bit payload. Delivery still
    /// refuses: parent interrupt capture/mask/retirement semantics are not yet
    /// qualified. Neither a synthetic PCIe latch nor a transient AIC level
    /// substitutes for that boundary.
    pub fn msi(
        &mut self,
        address: u64,
        data: u32,
        _access: &mut Access<'_>,
    ) -> Result<(), RequestError> {
        if !self.link {
            return Err(RequestError::LinkDown);
        }
        let result = if self.msi_config & 1 == 0 {
            Err(RequestError::MsiDisabled)
        } else if address != self.msi_address {
            Err(RequestError::MsiAddress)
        } else if self.layout == Layout::T6020 {
            self.msi_map
                .get(data as usize)
                .filter(|entry| **entry & VALID != 0)
                .map(|entry| (entry & 0xff) as usize)
                .ok_or(RequestError::MsiData)
        } else {
            let count = 1usize << ((self.msi_config >> 4) & 7);
            if data < count as u32 {
                Ok((self.msi_base & 0xffff) as usize + data as usize)
            } else {
                Err(RequestError::MsiData)
            }
        };
        match result.and_then(|index| {
            self.msi_irqs
                .get(index)
                .copied()
                .ok_or(RequestError::MsiData)
        }) {
            Ok(_) => Err(RequestError::DeliveryUnqualified),
            Err(error) => Err(error),
        }
    }
    fn table(offset: u64, base: u64, entries: usize) -> Option<usize> {
        let index = offset.checked_sub(base)? / 4;
        (offset.is_multiple_of(4) && index < entries as u64).then_some(index as usize)
    }
    fn error(offset: u64, direction: Direction, reason: &'static str) -> MmioError {
        refuse(NAME, offset, Width::Word, direction, reason)
    }
    pub fn read(&self, offset: u64) -> Result<u32, MmioError> {
        if !self.inputs.powered {
            return Err(Self::error(offset, Direction::Read, "port is unpowered"));
        }
        if let Some(i) = Self::table(offset, self.layout.sid(), self.sid.len()) {
            return Ok(self.sid[i]);
        }
        if self.layout == Layout::T6020
            && let Some(i) = Self::table(offset, 0x3800, self.msi_map.len())
        {
            return Ok(self.msi_map[i]);
        }
        Ok(match offset {
            LTSSM => self.ltssm,
            INT_STATUS => self.status | self.intx,
            INT_MASK => self.mask,
            MSI_CONFIG => self.msi_config,
            MSI_BASE if self.layout == Layout::T8103 => self.msi_base,
            LINK_STATUS => u32::from(self.link),
            APP_CLOCK => self.app_clock,
            PORT_STATUS => u32::from(self.ready()),
            REF_CLOCK if self.layout == Layout::T8103 => self.ref_clock,
            o if o == self.layout.reset() => self.reset,
            o if o == self.layout.msi() => self.msi_address as u32,
            0x170 if self.layout == Layout::T6020 => (self.msi_address >> 32) as u32,
            _ => {
                return Err(Self::error(
                    offset,
                    Direction::Read,
                    "register or direction is not implemented",
                ));
            }
        })
    }
    pub fn write(
        &mut self,
        offset: u64,
        value: u32,
        access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let error = |reason| Self::error(offset, Direction::Write, reason);
        if !self.inputs.powered {
            return Err(error("port is unpowered"));
        }
        if let Some(i) = Self::table(offset, self.layout.sid(), self.sid.len()) {
            if value & 0x7f00_0000 != 0 {
                return Err(error("unsupported stream-ID encoding"));
            }
            self.sid[i] = value;
        } else if self.layout == Layout::T6020
            && let Some(index) = Self::table(offset, 0x3800, self.msi_map.len())
        {
            if value & !(VALID | 0xff) != 0 {
                return Err(error("unsupported MSI map encoding"));
            }
            self.msi_map[index] = value;
        } else {
            match offset {
                LTSSM if value & !1 == 0 => self.ltssm = value,
                INT_STATUS => self.status &= !(value & !0xf),
                INT_MASK => self.mask = value,
                INT_MASK_SET => self.mask |= value,
                INT_MASK_CLEAR => self.mask &= !value,
                APP_CLOCK if value & !CLOCK_MASK == 0 => self.app_clock = value,
                REF_CLOCK if self.layout == Layout::T8103 && value & !CLOCK_MASK == 0 => {
                    self.ref_clock = value
                }
                o if o == self.layout.reset() && value & !1 == 0 => self.reset = value,
                MSI_CONFIG => {
                    let maximum = self.msi_irqs.len().trailing_zeros();
                    if value & !0x71 != 0
                        || (value >> 4) > maximum
                        || (self.layout == Layout::T6020 && value & !1 != 0)
                    {
                        return Err(error("unsupported MSI vector-count encoding"));
                    }
                    self.msi_config = value;
                }
                MSI_BASE if self.layout == Layout::T8103 => {
                    if value != 0 {
                        return Err(error("nonzero MSI base encoding is unqualified"));
                    }
                    self.msi_base = value;
                }
                o if o == self.layout.msi() && value & 3 == 0 => {
                    self.msi_address = (self.msi_address & !u64::from(u32::MAX)) | u64::from(value);
                }
                0x170 if self.layout == Layout::T6020 => {
                    self.msi_address =
                        (self.msi_address & u64::from(u32::MAX)) | u64::from(value) << 32;
                }
                _ => return Err(error("register, value or direction is not implemented")),
            }
        }
        self.update(access);
        Ok(())
    }
    pub(super) fn publish(&mut self, access: &mut Access<'_>) {
        self.update(access);
    }

    pub(super) fn preview_write(&self, offset: u64, value: u32) -> Result<Self, MmioError> {
        let mut candidate = self.clone();
        candidate.write(offset, value, &mut Access::new(0, 0, &mut Silent))?;
        Ok(candidate)
    }
    pub(super) fn preview_inputs(&self, inputs: Inputs) -> Result<Self, &'static str> {
        let mut candidate = self.clone();
        candidate.set_inputs(inputs, &mut Access::new(0, 0, &mut Silent))?;
        Ok(candidate)
    }
}

// Only a private cloned preview uses this sink. A successful real commit
// publishes the resulting IRQ level after every actual endpoint is checked.
struct Silent;
impl stela_contracts::interrupt::InterruptSink for Silent {
    fn set_level(&mut self, _: Wire, _: bool) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_contracts::interrupt::InterruptLatch;
    fn port(layout: Layout) -> Port {
        Port::new(
            layout,
            16,
            AicInput::new(0, 100),
            (0..32).map(|i| AicInput::new(0, 200 + i)).collect(),
        )
        .unwrap()
    }
    pub(super) fn enable(p: &mut Port, a: &mut Access<'_>) {
        p.set_inputs(
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
        p.write(APP_CLOCK, 1, a).unwrap();
        if p.layout == Layout::T8103 {
            p.write(REF_CLOCK, 1, a).unwrap();
        }
        p.write(p.layout.reset(), 1, a).unwrap();
        p.write(LTSSM, 1, a).unwrap();
    }
    #[test]
    fn a_backed_peer_clocks_reset_and_training_are_all_required() {
        let mut p = port(Layout::T8103);
        let mut l = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut l);
        assert!(p.read(PORT_STATUS).is_err());
        enable(&mut p, &mut a);
        assert!(p.link_up());
        let trained = p.inputs;
        p.set_inputs(
            Inputs {
                link_trained: false,
                ..trained
            },
            &mut a,
        )
        .unwrap();
        assert!(!p.link_up());
        p.set_inputs(trained, &mut a).unwrap();
        p.write(INT_STATUS, u32::MAX, &mut a).unwrap();
        p.write(LTSSM, 0, &mut a).unwrap();
        p.write(INT_STATUS, u32::MAX, &mut a).unwrap();
        p.write(LTSSM, 1, &mut a).unwrap();
        p.write(INT_MASK_CLEAR, LINK_UP | LINK_DOWN, &mut a)
            .unwrap();
        assert_eq!(p.read(INT_STATUS).unwrap() & LINK_UP, LINK_UP);
        p.write(INT_STATUS, LINK_UP, &mut a).unwrap();
        assert_eq!(p.read(INT_STATUS).unwrap(), 0);
        let mut inputs = p.inputs;
        inputs.peer = false;
        p.set_inputs(inputs, &mut a).unwrap();
        assert!(!p.link_up());
        assert_eq!(p.read(INT_STATUS).unwrap(), LINK_DOWN);
        assert!(l.is_asserted(Wire::Aic(AicInput::new(0, 100))));
    }
    #[test]
    fn intx_is_level_and_cannot_be_cleared_as_an_edge() {
        let mut p = port(Layout::T8103);
        let mut l = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut l);
        enable(&mut p, &mut a);
        p.set_intx(2, true, &mut a).unwrap();
        p.write(INT_STATUS, u32::MAX, &mut a).unwrap();
        assert_eq!(p.read(INT_STATUS).unwrap(), 4);
        p.set_intx(2, false, &mut a).unwrap();
        assert_eq!(p.read(INT_STATUS).unwrap(), 0);
    }
    #[test]
    fn requester_lookup_reports_missing_ambiguous_and_refuses_unqualified_power_loss() {
        for layout in [Layout::T8103, Layout::T6020] {
            let mut p = port(layout);
            let mut l = InterruptLatch::new();
            let mut a = Access::new(0, 0, &mut l);
            enable(&mut p, &mut a);
            p.write(INT_STATUS, u32::MAX, &mut a).unwrap();
            assert_eq!(p.stream(0x100, &mut a), Err(RequestError::MissingMapping));
            assert_eq!(p.read(INT_STATUS), Ok(0));
            p.write(layout.sid(), VALID | 7 << 16 | 0x100, &mut a)
                .unwrap();
            assert_eq!(p.stream(0x100, &mut a), Ok(7));
            p.write(layout.sid() + 4, VALID | 8 << 16 | 0x100, &mut a)
                .unwrap();
            assert_eq!(p.stream(0x100, &mut a), Err(RequestError::AmbiguousMapping));
            assert_eq!(p.read(INT_STATUS), Ok(0));
            let mut inputs = p.inputs;
            inputs.powered = false;
            assert!(p.set_inputs(inputs, &mut a).is_err());
            assert!(p.link_up());
            assert_eq!(p.stream(0x100, &mut a), Err(RequestError::AmbiguousMapping));
        }
    }
    #[test]
    fn msi_decodes_but_refuses_unqualified_parent_capture_without_a_fake_pulse() {
        for layout in [Layout::T8103, Layout::T6020] {
            let mut p = port(layout);
            let mut l = InterruptLatch::new();
            let mut a = Access::new(0, 0, &mut l);
            enable(&mut p, &mut a);
            assert_eq!(
                p.msi(0xffff_f000, 3, &mut a),
                Err(RequestError::MsiDisabled)
            );
            p.write(layout.msi(), 0xffff_f000, &mut a).unwrap();
            if layout == Layout::T6020 {
                p.write(0x380c, VALID | 3, &mut a).unwrap();
            }
            p.write(
                MSI_CONFIG,
                if layout == Layout::T8103 { 0x51 } else { 1 },
                &mut a,
            )
            .unwrap();
            assert_eq!(
                p.msi(0xffff_f000, 3, &mut a),
                Err(RequestError::DeliveryUnqualified)
            );
            assert_eq!(p.msi(0xffff_e000, 3, &mut a), Err(RequestError::MsiAddress));
            assert_eq!(p.msi(0xffff_f000, 32, &mut a), Err(RequestError::MsiData));
            assert_eq!(p.read(INT_STATUS), Ok(LINK_UP));
            let transitions = l.take_aic_inputs();
            assert!(
                transitions
                    .iter()
                    .all(|(irq, _)| *irq == AicInput::new(0, 100))
            );
        }
    }
}
