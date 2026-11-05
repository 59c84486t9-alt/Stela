// SPDX-License-Identifier: GPL-2.0-or-later
// GL9750 PCI initialization: Linux sdhci-pci-gli.c, Copyright 2019 Genesys.
//! PCI configuration of Genesys Logic GL9750, GL9755, GL9767 and GL9763E SD hosts.
use super::*;

pub(super) struct Native {
    registers: crate::bus::mmio::Mmio,
    function: Function,
    dma_enabled: bool,
}
impl Registers for Native {
    fn check_authority(&mut self) -> Result<(), BlockError> {
        if matches!(self.function.device, 0x9755 | 0x9767 | 0xe763) {
            runtime_configuration(&mut self.function, self.dma_enabled)?;
        }
        if self.function.device == 0xe763 {
            gl9763e::legacy_authority(&mut self.registers)?;
        }
        Ok(())
    }
    fn configuration(&mut self) -> Result<&mut dyn ConfigSpace, BlockError> {
        runtime_configuration(&mut self.function, self.dma_enabled)
    }
    fn dma_ready(&mut self) -> Result<(), BlockError> {
        dma_grant(&mut self.function, &mut self.dma_enabled)
    }
    fn read8(&mut self, at: usize) -> u8 {
        if matches!(self.function.device, 0x9767 | 0xe763) {
            self.registers.read8(at)
        } else {
            (self.registers.read32(at & !3) >> (8 * (at & 3))) as u8
        }
    }
    fn read16(&mut self, at: usize) -> u16 {
        if matches!(self.function.device, 0x9767 | 0xe763) {
            self.registers.read16(at)
        } else {
            (self.registers.read32(at & !3) >> (8 * (at & 3))) as u16
        }
    }
    fn read32(&mut self, at: usize) -> u32 {
        let value = self.registers.read32(at);
        if self.function.device == 0x9750 && at == MAX_CURRENT && value & 255 == 0 {
            value | 0xc8
        } else {
            value
        }
    }
    fn write8(&mut self, at: usize, value: u8) {
        self.registers.write8(at, value);
    }
    fn write16(&mut self, at: usize, value: u16) {
        self.registers.write16(at, value);
    }
    fn write32(&mut self, at: usize, value: u32) {
        self.registers.write32(at, value);
    }
}

pub(super) fn runtime_configuration<C: ConfigSpace>(
    f: &mut Function<C>,
    dma_enabled: bool,
) -> Result<&mut dyn ConfigSpace, BlockError> {
    if f.vendor != 0x17a0
        || !matches!(f.device, 0x9755 | 0x9767 | 0xe763)
        || f.config().read32(0)? != u32::from(f.device) << 16 | 0x17a0
        || f.config().read32(8)? & 0xffff_0000 != 0x0805_0000
    {
        return Err(BlockError::Unsupported(
            "GL9755 runtime PCI identity changed",
        ));
    }
    if f.device == 0x9767 && f.config().read32(0x940)? & 3 != 0 {
        return Err(BlockError::Unsupported(
            "GL9767 SD Express transition requires its child owner",
        ));
    }
    let pm = crate::pci::capability(f.config(), 1)?.ok_or(BlockError::Unsupported(
        "GL9755 runtime power capability lost",
    ))?;
    for (id, mask) in [(5, 1), (0x11, 1 << 15)] {
        if let Some(at) = crate::pci::capability(f.config(), id)?
            && f.config().read16(at + 2)? & mask != 0
        {
            return Err(BlockError::Unsupported(
                "GL9755 runtime interrupt ownership changed",
            ));
        }
    }
    let command = f.config().read16(4)?;
    if f.config().read16(pm + 4)? & 3 != 0
        || command == u16::MAX
        || command & 0x402 != 0x402
        || (command & 4 != 0) != dma_enabled
    {
        return Err(BlockError::Unsupported(
            "GL9755 runtime PCI power/requester epoch changed",
        ));
    }
    Ok(f.config())
}

#[expect(
    clippy::result_large_err,
    reason = "Return the same affine device, mapping and timer graph without a fallible failure-path allocation."
)]
pub(super) fn prepare(mut owner: Retained<OwnedPreparation>) -> Result<Native, OwnedAttachFailure> {
    let result = {
        let owner = owner.get_mut();
        owner.stage = PreparationStage::ProfileInitialization;
        let f = &mut owner.function;
        let r = &mut owner.registers;
        let clock = owner.clock;
        let minimum = owner.minimum.as_ref();
        if f.device == 0xe763 {
            gl9763e::initialize(f, r, clock)
        } else if f.device == 0x9767 {
            gl9767::initialize(f, r, clock, minimum)
        } else if f.device == 0x9755 {
            gl9755::initialize(f, r, clock, minimum)
        } else {
            setup(f, r, clock, minimum)
        }
    };
    if let Err(error) = result {
        return Err(OwnedAttachFailure {
            error,
            owner: Retained::new(FailedAttachment::Preparation(owner.into_inner())),
        });
    }
    let owner = owner.into_inner();
    Ok(Native {
        registers: owner.registers,
        function: owner.function,
        dma_enabled: false,
    })
}

pub(super) fn dma_grant<C: ConfigSpace>(
    function: &mut Function<C>,
    enabled: &mut bool,
) -> Result<(), BlockError> {
    let identity = u32::from(function.vendor) | u32::from(function.device) << 16;
    if !matches!(
        identity,
        0x9750_17a0 | 0x9755_17a0 | 0x9767_17a0 | 0xe763_17a0
    ) || function.config().read32(0)? != identity
    {
        return Err(BlockError::Unsupported(
            "GL9750 DMA requester identity changed",
        ));
    }
    if matches!(function.device, 0x9767 | 0xe763) {
        runtime_configuration(function, *enabled)?;
    }
    let pm = crate::pci::capability(function.config(), 1)?.ok_or(BlockError::Unsupported(
        "GL9750 DMA lost PCI power capability",
    ))?;
    for (id, enabled_mask) in [(5, 1), (0x11, 1 << 15)] {
        if let Some(at) = crate::pci::capability(function.config(), id)?
            && function.config().read16(at + 2)? & enabled_mask != 0
        {
            return Err(BlockError::Unsupported(
                "GL9750 DMA interrupt ownership changed",
            ));
        }
    }
    let command = function.config().read16(4)?;
    if function.config().read16(pm + 4)? & 3 != 0
        || command == u16::MAX
        || command & 0x402 != 0x402
        || (command & 4 != 0) != *enabled
    {
        return Err(BlockError::Unsupported(
            "GL9750 DMA requester epoch/power changed",
        ));
    }
    if !*enabled {
        function.config().write16(4, command | 4)?;
    }
    let acknowledged = function.config().read16(4)?;
    if acknowledged == u16::MAX
        || acknowledged & 0x406 != 0x406
        || function.config().read32(0)? != identity
    {
        return Err(BlockError::Unsupported(
            "GL9750 PCI DMA grant did not acknowledge",
        ));
    }
    *enabled = true;
    Ok(())
}

pub(super) fn setup<C: ConfigSpace>(
    function: &mut Function<C>,
    registers: &mut dyn Registers,
    clock: Clock,
    minimum: &dyn crate::bus::pci::power::Timer,
) -> Result<(), BlockError> {
    minimum.check().map_err(BlockError::PciPower)?;
    validate_clock(clock)?;
    if function.config().read32(0)? != 0x9750_17a0 {
        return Err(BlockError::Unsupported("GL9750 owned PCI identity changed"));
    }
    let pm = crate::pci::capability(function.config(), 1)?.ok_or(BlockError::Unsupported(
        "GL9750 requires PCI power management",
    ))?;
    let aer = find_aer(function.config())?;
    // Retire firmware command/data before changing PHY and the PCI power epoch.
    registers.write8(RESET, RESET_ALL);
    if !clock.wait(RESET_US, || {
        (registers.read32(RESET & !3) >> 24) as u8 & RESET_ALL == 0
    }) {
        return Err(BlockError::Unsupported(
            "GL9750 initial reset did not acknowledge",
        ));
    }
    update(registers, WT, 1, 1)?;
    let mut mapped = true;
    let result = (|| {
        update(registers, CFG2, 31 << 24, 31 << 24)?;
        // Use word stores: adjacent PM status is W1C. Save the real BAR inventory
        // before D3hot; a soft reset must not silently change the mapped resource.
        let mut bars = [0u32; 6];
        for (i, saved) in bars.iter_mut().enumerate() {
            *saved = function.config().read32(0x10 + i as u16 * 4)?;
        }
        let control = function.config().read16(pm + 4)?;
        if control == u16::MAX || control & 3 != 0 {
            return Err(BlockError::Unsupported(
                "GL9750 power cycle requires actual D0",
            ));
        }
        mapped = false;
        // Keep decode contained through the power transition itself: a D0
        // soft reset may clear BARs while keeping the previous command word.
        set_pio_command(function, false)?;
        function.config().write16(pm + 4, (control & !0x8003) | 3)?;
        minimum.wait_us(10_000).map_err(BlockError::PciPower)?;
        if function.config().read16(pm + 4)? & 3 != 3 {
            return Err(BlockError::Unsupported("GL9750 D3hot did not acknowledge"));
        }
        function.config().write16(pm + 4, control & !0x8003)?;
        minimum.wait_us(10_000).map_err(BlockError::PciPower)?;
        if function.config().read16(pm + 4)? & 3 != 0 {
            return Err(BlockError::Unsupported("GL9750 D0 did not acknowledge"));
        }
        if function.config().read32(0)? != 0x9750_17a0
            || crate::pci::capability(function.config(), 1)? != Some(pm)
            || find_aer(function.config())? != aer
        {
            return Err(BlockError::Unsupported(
                "GL9750 PCI identity/capabilities changed across D3hot",
            ));
        }
        // D3hot can clear BARs without clearing Command.Memory. Contain decode
        // before either half of a 64-bit BAR is restored, then grant it only
        // after the complete original inventory has acknowledged.
        quiesce_pio(function)?;
        for (index, value) in bars.into_iter().enumerate() {
            let at = 0x10 + index as u16 * 4;
            function.config().write32(at, value)?;
            if function.config().read32(at)? != value {
                return Err(BlockError::Unsupported(
                    "GL9750 BAR restoration did not acknowledge",
                ));
            }
        }
        set_pio_command(function, true)?;
        mapped = true;
        if let Some(aer) = aer {
            let mask = function.config().read32(aer + 0x14)? | 1 << 12;
            function.config().write32(aer + 0x14, mask)?;
            if function.config().read32(aer + 0x14)? != mask {
                return Err(BlockError::Unsupported(
                    "GL9750 AER replay mask did not acknowledge",
                ));
            }
        }
        Ok(())
    })();
    // Close the original window only while the function is accessible.
    // A failed D3/D0 transition keeps the unresolved hardware owner instead.

    if matches!(
        &result,
        Err(BlockError::Config(_)
            | BlockError::PciPower(_)
            | BlockError::PciCapability(crate::bus::pci::CapabilityError::Config { .. }))
    ) {
        return result;
    }
    let close = (|| {
        if mapped
            && function.config().read32(0)? == 0x9750_17a0
            && function.config().read16(pm + 4)? & 3 == 0
            && function.config().read16(4)? & 2 != 0
        {
            update(registers, WT, 1, 0)
        } else {
            Err(BlockError::Unsupported(
                "GL9750 write window remains inaccessible",
            ))
        }
    })();
    result.and(close)
}

// Only complete measured endpoint capability bodies authorize the AER mask.
// A header embedded in a vendor payload cannot grant configuration access.
pub(super) fn find_aer<C: ConfigSpace>(config: &C) -> Result<Option<u16>, BlockError> {
    crate::pci::measured_extended(
        config,
        1,
        BlockError::Unsupported("GL9750 unqualified extended PCIe capabilities"),
    )
}
