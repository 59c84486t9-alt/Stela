use super::{ControlMetadataFailure, SCTLR_EE, SCTLR_M, check_el1_m0_data_controls};
use crate::memory::stage1::Controls;

const SCTLR_C: u64 = 1 << 2;
const SCTLR_I: u64 = 1 << 12;
const SCTLR_E0E: u64 = 1 << 24;

fn snapshot(sctlr_el1: u64) -> Controls {
    Controls {
        ttbr0_el1: 0,
        ttbr1_el1: 0,
        tcr_el1: 0,
        sctlr_el1,
        mair_el1: 0,
    }
}

#[test]
fn m0_el1_big_endian_metadata_is_refused_for_all_cache_controls() {
    for caches in [0, SCTLR_C, SCTLR_I, SCTLR_C | SCTLR_I] {
        assert_eq!(
            check_el1_m0_data_controls(&snapshot(caches | SCTLR_EE)),
            Err(ControlMetadataFailure::BigEndianEl1Data),
        );
        assert_eq!(check_el1_m0_data_controls(&snapshot(caches)), Ok(()));
        assert_eq!(
            check_el1_m0_data_controls(&snapshot(caches | SCTLR_E0E)),
            Ok(()),
        );
    }
}

#[test]
fn enabled_stage1_cannot_enter_m0_metadata_profile() {
    assert_eq!(
        check_el1_m0_data_controls(&snapshot(SCTLR_M)),
        Err(ControlMetadataFailure::Stage1Enabled),
    );
}
