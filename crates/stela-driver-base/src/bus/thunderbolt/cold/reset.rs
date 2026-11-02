// SPDX-License-Identifier: GPL-2.0-only
//! Supported same-function FLR selection, following pinned Linux pci.c/quirks.c.
use super::{Error, Profile};
use crate::bus::pci::{ConfigSpace, Function, capability, requester};

/// Configuration qualification only. No mask, BME bit, ring index, HRR bit or
/// posted-write drain alone acknowledges discarded latent NHI engine jobs.
pub fn check_flr<C: ConfigSpace>(
    function: &mut Function<C>,
    timer: &(impl crate::bus::pci::power::Timer + ?Sized),
) -> Result<Profile, Error> {
    timer
        .check()
        .map_err(|error| Error::Reset(crate::block::BlockError::PciPower(error)))?;
    requester::validate_stopped(function).map_err(Error::Claim)?;
    let [base, sub, interface] = function.class;
    let class = u32::from(base) << 16 | u32::from(sub) << 8 | u32::from(interface);
    let profile =
        Profile::identify(function.vendor, function.device, class).map_err(Error::Controller)?;
    // Complete NO_FLR_RESET early quirks from the unchanged native donor.
    // Generic USB4 class matching must not bypass another vendor's reset quirk.
    let quirk = match function.vendor {
        0x1022 => matches!(
            function.device,
            0x1487 | 0x148c | 0x149c | 0x7901 | 0x1502 | 0x17f0
        ),
        0x8086 => matches!(function.device, 0x1502 | 0x1503),
        0x14c3 => matches!(function.device, 0x0616 | 0x7925),
        0xd063 if function.device == 0x1000 => function.config().read8(8)? == 1,
        _ => false,
    };
    if quirk {
        return Err(Error::ResetQuirk);
    }
    let mut express = None;
    for entry in capability::capabilities(function.config()) {
        let entry = entry.map_err(Error::Capability)?;
        if entry.id == 0x10 && express.replace(entry.offset).is_some() {
            return Err(Error::Identity);
        }
    }
    let express = express.ok_or(Error::ResetRequired)?;
    let capabilities = function.config().read32(express + 4)?;
    if capabilities == u32::MAX {
        return Err(Error::Identity);
    }
    if capabilities & (1 << 28) == 0 {
        return Err(Error::ResetRequired);
    }
    Ok(profile)
}

/// Source-backed function-local reset; this is not old IRQ/work completion or
/// original-root payload drain. Caller keeps actual configuration/BAR/root and
/// all DMA backing, excludes submissions and owns the current process context.
pub fn reset<C: ConfigSpace>(
    function: &mut Function<C>,
    timer: &(impl crate::bus::pci::power::Timer + ?Sized),
) -> Result<(), Error> {
    check_flr(function, timer)?;
    if !function.function_level_reset(timer).map_err(Error::Reset)? {
        return Err(Error::ResetRequired);
    }
    // Actual ordinary configuration reads after FLR push read-ordered ingress;
    // the root still has to acknowledge its separate translated payload drain.
    requester::validate_stopped(function).map_err(Error::Claim)
}
