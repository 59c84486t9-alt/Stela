//! Exclusive stopped PCI requester kept by its VT-d context. A numeric RID
//! or a cache-policy bit never grants this ownership or DMA coherency.
use crate::vtd::VtdError;
use stela_drivers::bus::pci::{
    CapabilityError, ConfigSpace, Function, owned::OwnedConfig, requester::RequesterBinding,
};

pub struct RequesterClaim {
    rid: u16,
    owner: Owner,
}
enum Owner {
    Pci(Function<OwnedConfig>),
    /// A driver's binding: the driver keeps the configuration owner, and
    /// with it bus mastering.
    Binding(RequesterBinding),
    #[cfg(test)]
    Model(#[expect(dead_code, reason = "dropped with the claim, counting its release")] ModelOwner),
}
#[cfg(test)]
struct ModelOwner(alloc::sync::Arc<core::sync::atomic::AtomicU64>);
#[cfg(test)]
impl Drop for ModelOwner {
    fn drop(&mut self) {
        self.0.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
}
impl RequesterClaim {
    /// Consume the configuration owner, never a supplied numeric RID.
    ///
    /// # Safety
    /// `function` is the uniquely enumerated ECAM function, including
    /// unmodified address/identity metadata validated against the complete
    /// platform route inventory; no reconstructed/forged Function checks.
    /// Vendor engines/DMA/posted requests and IRQ/work/reset paths are
    /// stopped and drained. This requester has coherent WB RAM DMA,
    /// independently of its CPU cache attributes and VT-d table coherency.
    /// No aliases, firmware/SMM/reset/config owner can change its identity or
    /// DMA policy. The UC config/root resource owner remains permanently
    /// through every domain or quarantine; the current opt-in fixture
    /// uses its permanently host-check root. Native production attach
    /// needs the canonical owned MMIO/root-epoch adapter, not this contract
    /// inferred from an ECAM address. No operation/final release runs in IRQ.
    pub unsafe fn from_stopped_pci(function: Function<OwnedConfig>) -> Result<Self, VtdError> {
        if function.address.segment != 0 || function.address.bus != 0 {
            return Err(VtdError::Unsupported);
        }
        let rid = u16::from(function.address.device) * 8 + u16::from(function.address.function);
        if function.address.device >= 32 || function.address.function >= 8 {
            return Err(VtdError::Unsupported);
        }
        let mut claim = Self {
            rid,
            owner: Owner::Pci(function),
        };
        claim.check_stopped()?;
        Ok(claim)
    }
    /// Keep a driver's binding of its stopped function.
    ///
    /// # Safety
    /// The function is stopped as [`StoppedRequester::from_stopped_pci`]
    /// requires, and its driver enables bus mastering only after mapping
    /// its DMA through the domain this claim attaches to.
    ///
    /// [`StoppedRequester::from_stopped_pci`]: stela_drivers::bus::pci::requester::StoppedRequester::from_stopped_pci
    pub unsafe fn from_binding(binding: RequesterBinding) -> Result<Self, VtdError> {
        binding.check_live().map_err(|_| VtdError::Busy)?;
        Ok(Self {
            rid: binding.requester(),
            owner: Owner::Binding(binding),
        })
    }
    pub fn requester(&self) -> u16 {
        self.rid
    }
    pub(super) fn check_stopped(&mut self) -> Result<(), VtdError> {
        let function = match &mut self.owner {
            Owner::Pci(f) => f,
            Owner::Binding(binding) => return binding.check_live().map_err(|_| VtdError::Busy),
            #[cfg(test)]
            Owner::Model(_) => return Ok(()),
        };
        Self::validate_stopped(function)
    }
    fn validate_stopped<C: ConfigSpace>(function: &mut Function<C>) -> Result<(), VtdError> {
        let expected = u32::from(function.vendor) | u32::from(function.device) << 16;
        let id = function.config().read32(0);
        let command = function.config().read16(4);
        if id == u32::MAX || command == u16::MAX {
            return Err(VtdError::RegisterRead);
        }
        if id != expected
            || command & (4 | 1 << 10) != 1 << 10
            || function.config().read8(0x0e) & 0x7f != 0
        {
            return Err(VtdError::Busy);
        }
        // Walk the complete list strictly here: Function::capabilities stops
        // quietly at a malformed entry and cannot check ownership.
        let status = function.config().read16(6);
        if status == u16::MAX {
            return Err(VtdError::RegisterRead);
        }
        let failed = |error| match error {
            CapabilityError::FailedRead { .. } => VtdError::RegisterRead,
            _ => VtdError::Unsupported,
        };
        let config = &*function.config();
        let read16 = |offset| match config.read16(offset) {
            u16::MAX => Err(VtdError::RegisterRead),
            value => Ok(value),
        };
        let mut pcie = false;
        for entry in config.capabilities() {
            let entry = entry.map_err(failed)?;
            let offset = entry.offset;
            let (register, mask) = match entry.id {
                0 => return Err(VtdError::Unsupported),
                5 => (offset + 2, 1),
                0x11 => (offset + 2, 1 << 15),
                0x10 => {
                    if core::mem::replace(&mut pcie, true) {
                        return Err(VtdError::Unsupported);
                    }
                    (offset + 8, 1 << 11)
                }
                _ => continue,
            };
            if read16(register)? & mask != 0 {
                return Err(VtdError::Busy);
            }
        }
        // Old-style fixture endpoints expose no extended config. The unsafe
        // native grant establishes that this is absence, not a failed read.
        if pcie && config.read32(0x100) == u32::MAX {
            return Err(VtdError::RegisterRead);
        }
        for entry in config.extended_capabilities() {
            let entry = entry.map_err(failed)?;
            let (register, mask) = match entry.id {
                0x000f => (entry.offset + 6, 1 << 15),
                0x0013 => (entry.offset + 4, 1),
                0x001b => (entry.offset + 6, 1),
                _ => continue,
            };
            if read16(register)? & mask != 0 {
                return Err(VtdError::Unsupported);
            }
        }
        Ok(())
    }
    /// Bus-master gating is not device completion or quiescence.
    pub(super) fn set_bus_master(&mut self, enabled: bool) -> Result<(), VtdError> {
        let function = match &mut self.owner {
            Owner::Pci(f) => f,
            Owner::Binding(_) => return Err(VtdError::Unsupported),
            #[cfg(test)]
            Owner::Model(_) => return Ok(()),
        };
        let command = function.config().read16(4);
        if command == u16::MAX {
            return Err(VtdError::RegisterRead);
        }
        let wanted = if enabled { command | 4 } else { command & !4 };
        function.config().write16(4, wanted);
        let actual = function.config().read16(4);
        if actual == u16::MAX {
            return Err(VtdError::RegisterRead);
        }
        if (actual & 4 != 0) != enabled {
            return Err(VtdError::Busy);
        }
        Ok(())
    }
    pub fn into_function(self) -> Result<Function<OwnedConfig>, VtdError> {
        match self.owner {
            Owner::Pci(function) => Ok(function),
            Owner::Binding(_) => Err(VtdError::Unsupported),
            #[cfg(test)]
            Owner::Model(_) => Err(VtdError::Unsupported),
        }
    }
    #[cfg(test)]
    pub(super) fn model(
        rid: u16,
        released: alloc::sync::Arc<core::sync::atomic::AtomicU64>,
    ) -> Self {
        Self {
            rid,
            owner: Owner::Model(ModelOwner(released)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_drivers::bus::pci::Address;
    struct Config([u32; 1024]);
    impl ConfigSpace for Config {
        fn read32(&self, offset: u16) -> u32 {
            self.0[usize::from(offset / 4)]
        }
        fn write32(&mut self, offset: u16, value: u32) {
            self.0[usize::from(offset / 4)] = value;
        }
    }
    fn function() -> Function<Config> {
        let mut c = Config([0; 1024]);
        c.0[0] = 0x11e8_1234;
        c.0[1] = 1 << 10;
        Function::new(
            Address {
                segment: 0,
                bus: 0,
                device: 2,
                function: 0,
            },
            c,
        )
        .unwrap()
    }
    #[test]
    fn actual_config_identity_mastering_and_interrupt_policy_are_checked() {
        let mut f = function();
        assert_eq!(RequesterClaim::validate_stopped(&mut f), Ok(()));
        for bad in [4, 0, u16::MAX] {
            f.config().write16(4, bad);
            assert!(RequesterClaim::validate_stopped(&mut f).is_err());
        }
        f.config().write16(4, 1 << 10);
        f.config().write32(0, 0x11e9_1234);
        assert_eq!(
            RequesterClaim::validate_stopped(&mut f),
            Err(VtdError::Busy)
        );
        for (id, offset, active) in [(5, 0x42, 1), (0x11, 0x42, 1 << 15), (0x10, 0x48, 1 << 11)] {
            let mut f = function();
            f.config().write16(6, 16);
            f.config().write8(0x34, 0x40);
            f.config().write16(0x40, id);
            f.config().write16(offset, active);
            assert_eq!(
                RequesterClaim::validate_stopped(&mut f),
                Err(VtdError::Busy)
            );
            f.config().write16(offset, 0);
            assert_eq!(RequesterClaim::validate_stopped(&mut f), Ok(()));
        }
    }
    #[test]
    fn malformed_or_failed_capability_reads_do_not_qualify_a_claim() {
        for pointer in [0x41, 0x3c, 0xff] {
            let mut f = function();
            f.config().write16(6, 16);
            f.config().write8(0x34, pointer);
            assert_eq!(
                RequesterClaim::validate_stopped(&mut f),
                Err(VtdError::Unsupported)
            );
        }
        let mut f = function();
        f.config().write16(6, 16);
        f.config().write8(0x34, 0x40);
        f.config().write16(0x40, 0x4005);
        assert_eq!(
            RequesterClaim::validate_stopped(&mut f),
            Err(VtdError::Unsupported)
        );
        f.config().write16(0x40, 0x10);
        f.config().write32(0x100, u32::MAX);
        assert_eq!(
            RequesterClaim::validate_stopped(&mut f),
            Err(VtdError::RegisterRead)
        );
        for (id, control, mask) in [(0xf, 0x106, 1 << 15), (0x13, 0x104, 1), (0x1b, 0x106, 1)] {
            let mut f = function();
            f.config().write32(0x100, id | 1 << 16);
            f.config().write16(control, mask);
            assert_eq!(
                RequesterClaim::validate_stopped(&mut f),
                Err(VtdError::Unsupported)
            );
            f.config().write16(control, u16::MAX);
            assert_eq!(
                RequesterClaim::validate_stopped(&mut f),
                Err(VtdError::RegisterRead)
            );
            f.config().write16(control, 0);
            assert_eq!(RequesterClaim::validate_stopped(&mut f), Ok(()));
        }
        let mut f = function();
        f.config().write32(0x100, 0x1001_000f);
        assert_eq!(
            RequesterClaim::validate_stopped(&mut f),
            Err(VtdError::Unsupported)
        );
    }
}
