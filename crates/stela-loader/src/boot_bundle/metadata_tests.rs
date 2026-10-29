//! Allocation metadata follows the same current CPU feature declaration as execution.
#[test]
fn tag_storage_requirement_matches_admitted_engine_identification() {
    for chip in stela_contracts::Chip::ALL {
        assert_eq!(
            stela_contracts::Feature::FEAT_MTE.on(chip),
            stela_engine::machine::identification::memory_tagging(chip),
            "{chip:?}"
        );
    }
}
