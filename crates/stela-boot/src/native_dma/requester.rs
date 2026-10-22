//! Exclusive stopped PCI requester retained by its VT-d context. A numeric RID
//! or a cache-policy bit never grants this ownership or DMA coherency.
#[cfg(not(test))]
use super::vtd::VtdError;
#[cfg(test)]
use crate::boot_vtd::VtdError;
use stela_drivers::bus::pci::{ConfigSpace, Function};

pub struct RequesterClaim {
    rid: u16,
    owner: Owner,
}
enum Owner {
    Pci(Function),
    #[cfg(test)]
    Model(ModelOwner),
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
    /// Consume the actual configuration owner, never a supplied numeric RID.
    ///
    /// # Safety
    /// `function` is the actual uniquely enumerated ECAM function, including
    /// unmodified address/identity metadata validated against the complete
    /// platform route inventory; no reconstructed/forged Function qualifies.
    /// Actual vendor engines/DMA/posted requests and IRQ/work/reset paths are
    /// stopped and drained. This exact requester has coherent WB RAM DMA,
    /// independently of its CPU cache attributes and VT-d table coherency.
    /// No aliases, firmware/SMM/reset/config owner can change its identity or
    /// DMA policy. The actual UC config/root resource owner remains permanently
    /// retained through every domain or quarantine; the current opt-in fixture
    /// uses its permanently retained host-check root. Native production attach
    /// needs the canonical owned MMIO/root-epoch adapter, not this contract
    /// inferred from an ECAM address. No operation/final release runs in IRQ.
    pub unsafe fn from_stopped_pci(function: Function) -> Result<Self, VtdError> {
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
    pub fn requester(&self) -> u16 {
        self.rid
    }
    pub(super) fn check_stopped(&mut self) -> Result<(), VtdError> {
        #[cfg(not(test))]
        let Owner::Pci(function) = &mut self.owner;
        #[cfg(test)]
        let function = match &mut self.owner {
            Owner::Pci(f) => f,
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
        // Enumerate the actual list strictly here: the generic reporting helper
        // deliberately truncates malformed lists and cannot qualify ownership.
        let status = function.config().read16(6);
        if status == u16::MAX {
            return Err(VtdError::RegisterRead);
        }
        let mut pcie = false;
        if status & 16 != 0 {
            let mut offset = u16::from(function.config().read8(0x34));
            let mut seen = alloc::vec::Vec::new();
            while offset != 0 {
                if !(0x40..=0xfc).contains(&offset)
                    || !offset.is_multiple_of(4)
                    || seen.contains(&offset)
                {
                    return Err(VtdError::Unsupported);
                }
                seen.push(offset);
                let header = function.config().read16(offset);
                if header == u16::MAX {
                    return Err(VtdError::RegisterRead);
                }
                let id = header as u8;
                if matches!(id, 0 | 0xff) {
                    return Err(VtdError::Unsupported);
                }
                let (register, mask) = match id {
                    5 => (Some(offset + 2), 1),
                    0x11 => {
                        if offset > 0xf4 {
                            return Err(VtdError::Unsupported);
                        }
                        (Some(offset + 2), 1 << 15)
                    }
                    0x10 => {
                        if pcie || offset > 0xf4 {
                            return Err(VtdError::Unsupported);
                        }
                        pcie = true;
                        (Some(offset + 8), 1 << 11)
                    }
                    _ => (None, 0),
                };
                if let Some(register) = register {
                    let value = function.config().read16(register);
                    if value == u16::MAX {
                        return Err(VtdError::RegisterRead);
                    }
                    if value & mask != 0 {
                        return Err(VtdError::Busy);
                    }
                }
                offset = header >> 8;
            }
        }
        let mut seen = alloc::vec::Vec::new();
        let mut offset = 0x100u16;
        loop {
            if !(0x100..=0xffc).contains(&offset)
                || !offset.is_multiple_of(4)
                || seen.contains(&offset)
            {
                return Err(VtdError::Unsupported);
            }
            seen.push(offset);
            let header = function.config().read32(offset);
            // Exact old-style fixture endpoints expose no extended config.
            // The unsafe native grant must establish that this is absence,
            // never a guessed answer to a failed live configuration read.
            if header == u32::MAX && pcie {
                return Err(VtdError::RegisterRead);
            }
            if matches!(header, 0 | u32::MAX) {
                break;
            }
            if matches!(header as u16, 0x000f | 0x0013 | 0x001b) && offset > 0xff8 {
                return Err(VtdError::Unsupported);
            }
            let control = match header as u16 {
                0x000f => Some((offset + 6, 1 << 15)),
                0x0013 => Some((offset + 4, 1)),
                0x001b => Some((offset + 6, 1)),
                _ => None,
            };
            if let Some((offset, mask)) = control {
                let value = function.config().read16(offset);
                if value == u16::MAX {
                    return Err(VtdError::RegisterRead);
                }
                if value & mask != 0 {
                    return Err(VtdError::Unsupported);
                }
            }
            offset = (header >> 20) as u16;
            if offset == 0 {
                break;
            }
        }
        Ok(())
    }
    /// Bus-master gating is not device completion or quiescence.
    pub(super) fn set_bus_master(&mut self, enabled: bool) -> Result<(), VtdError> {
        #[cfg(not(test))]
        let Owner::Pci(function) = &mut self.owner;
        #[cfg(test)]
        let function = match &mut self.owner {
            Owner::Pci(f) => f,
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
    pub fn into_function(self) -> Result<Function, VtdError> {
        match self.owner {
            Owner::Pci(function) => Ok(function),
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
