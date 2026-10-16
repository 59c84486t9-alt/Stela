use super::*;
use stela_compiler::block::{BlockProfile, CheckedMemoryProfile};
const SOURCE_PC: u64 = 0x100000;
const LDP_X_OFFSET: u32 = 0xa9400440;
const LDP_X_PREINDEX: u32 = 0xa9c10440;
const LDP_X_POSTINDEX: u32 = 0xa8c10440;
const LDR_X_LITERAL: u32 = 0x58000040;
const STP_X_OFFSET: u32 = 0xa9000440;

#[test]
fn actual_installed_data_classifier_keeps_pair_read_in_immutable_platform_cohort() {
    for word in [LDP_X_OFFSET, LDP_X_PREINDEX, LDP_X_POSTINDEX] {
        check_data_source_word(BlockProfile::El1PlatformV1, SOURCE_PC, word).unwrap();
        for profile in [
            BlockProfile::El1M0IntegerV1,
            BlockProfile::CheckedMemory(CheckedMemoryProfile::M0DeviceRamRead64Staged),
        ] {
            assert!(check_data_source_word(profile, SOURCE_PC, word).is_err());
        }
    }
    // The two platform memory source shapes.
    check_data_source_word(BlockProfile::El1PlatformV1, SOURCE_PC, LDR_X_LITERAL).unwrap();
    check_data_source_word(BlockProfile::El1PlatformV1, SOURCE_PC, STP_X_OFFSET).unwrap();
}

#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn installed_pair_classifier_preserves_canonical_rejected_source_rows() {
    // Rows the pair consumer refuses stay refused by the Platform cohort,
    // except the scalar load that the generic scalar consumer now owns.
    const SCALAR_CONSUMER_ROW: &str = "scalar_load";
    for (name, word) in crate::memory::domain::m0_read::pair_read_fixtures::rejected_sources() {
        let classified = check_data_source_word(BlockProfile::El1PlatformV1, SOURCE_PC, word);
        assert_eq!(classified.is_ok(), name == SCALAR_CONSUMER_ROW, "{name}");
    }
}
