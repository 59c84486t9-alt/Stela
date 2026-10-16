use super::*;
#[test]
fn all_predicate_fields_and_merge_forms() {
    for d in 0..16_u32 {
        for g in 0..16_u32 {
            for n in 0..16_u32 {
                let fields = d | (g << GUARD_SHIFT) | (n << SOURCE_SHIFT);
                for base in [BRKA, BRKB] {
                    for merge in [0, MERGING_BIT] {
                        let op = decode(base | fields | merge).unwrap().unwrap();
                        assert_eq!(
                            (op.destination, op.guard, op.source),
                            (d as u8, g as u8, n as u8)
                        );
                    }
                }
                for base in [BRKAS, BRKBS, BRKN, BRKNS] {
                    assert!(decode(base | fields).is_some());
                    assert!(decode(base | fields | MERGING_BIT).is_none());
                }
                for m in 0..16_u32 {
                    for base in [BRKPA, BRKPAS, BRKPB, BRKPBS] {
                        let op = decode(base | fields | (m << PREVIOUS_SOURCE_SHIFT))
                            .unwrap()
                            .unwrap();
                        assert!(
                            matches!(op.kind, BreakKind::Previous { source: value, .. } if value == m as u8)
                        );
                    }
                }
            }
        }
    }
}
#[test]
fn nonfamily_fixed_bits_decline() {
    assert!(decode(BRKA ^ (1 << 9)).is_none());
    assert!(decode(BRKA ^ (1 << 15)).is_none());
    assert!(decode(BRKPA ^ (1 << 9)).is_none());
}
