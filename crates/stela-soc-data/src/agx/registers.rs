//! Immutable AP register-coverage requirements of checked AGX families.
use super::generation::{Family, MMU_ENABLE};
use crate::Result;
use stela_contracts::refuse;
/// The GPC registers' offsets in the family's GPC block.
const GPC_PERFORMANCE_STATE: u64 = 0;
const GPC_HOST_INTERRUPT_ENABLE: u64 = 0x10;
const GPC_HOST_INTERRUPT_STATUS: u64 = 0x14;

const ID_VERSION: u64 = 0xd0_4000;
const ID_COUNTS_1: u64 = 0xd0_4010;
const ID_COUNTS_2: u64 = 0xd0_4014;
const ID_UNK18: u64 = 0xd0_4018;
const ID_CLUSTERS: u64 = 0xd0_401c;

const GATING_CONTROL: u64 = 0xd0_6030;
const FENDER_SLEEP: u64 = 0xd0_4074;
const FENDER_WAKE: u64 = 0xd0_6020;
const GIFAF_IDLE_STATUS_G13_G14: u64 = 0xd6_1090;
const GIFAF_IDLE_STATUS_G15: u64 = 0xd0_d090;
pub fn fender_sleep_supported(family: &Family) -> bool {
    matches!(family.name, "G13G" | "G14G" | "G15G")
}
pub fn gifaf_status(family: &Family) -> Option<u64> {
    match family.name {
        "G13G" | "G14G" => Some(GIFAF_IDLE_STATUS_G13_G14),
        "G15G" => Some(GIFAF_IDLE_STATUS_G15),
        _ => None,
    }
}

/// Check that `banks` (`(physical base, bytes, register offset)`) cover
/// every register the model serves for `family`, which must be modeled.
pub fn covers(family: &Family, banks: &[(u64, u64, u64)]) -> Result<()> {
    let gpc = family.model()?.gpc;
    let fixed = [
        gpc + GPC_PERFORMANCE_STATE,
        gpc + GPC_HOST_INTERRUPT_ENABLE,
        gpc + GPC_HOST_INTERRUPT_STATUS,
        ID_VERSION,
        ID_COUNTS_1,
        ID_COUNTS_2,
        ID_UNK18,
        ID_CLUSTERS,
        GATING_CONTROL,
        MMU_ENABLE,
        family.mmu.ttbat,
        family.mmu.invalidate,
    ];
    let mut registers = fixed
        .into_iter()
        .chain(family.core_masks.iter().copied())
        .chain(family.mmu.configuration.iter().map(|&(offset, _)| offset))
        .chain(
            fender_sleep_supported(family)
                .then_some([FENDER_SLEEP, FENDER_WAKE])
                .into_iter()
                .flatten(),
        )
        .chain(gifaf_status(family));
    let covered = |offset: u64| {
        banks.iter().any(|&(_, bytes, at)| {
            at.checked_add(bytes).is_some_and(|end| {
                offset >= at
                    && offset
                        .checked_add(4)
                        .is_some_and(|word_end| word_end <= end)
            })
        })
    };
    if registers.all(covered) {
        Ok(())
    } else {
        Err(refuse!("the sgx banks leave a modeled register unmapped"))
    }
}
