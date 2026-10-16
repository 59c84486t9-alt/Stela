use super::*;
#[test]
fn canonical_forms_are_unique_and_decode() {
    assert_eq!(ENCODINGS.len(), 57);
    for e in ENCODINGS {
        let op = decode(e.value).unwrap();
        assert_eq!(op.canonical_id, e.id);
        assert_eq!(
            ENCODINGS
                .iter()
                .filter(|other| e.value & other.mask == other.value)
                .count(),
            1
        );
        for other in ENCODINGS {
            if e.id != other.id {
                assert_ne!(
                    e.value & (e.mask & other.mask),
                    other.value & (e.mask & other.mask)
                );
            }
        }
    }
    assert!(decode(0).is_none());
}
#[test]
fn maximum_operand_fields_preserve_form_and_bounds() {
    for e in ENCODINGS {
        let op = decode(e.value | !e.mask).unwrap();
        assert_eq!(op.canonical_id, e.id);
        match op.kind {
            Kind::Tile {
                tile,
                element,
                index,
                offset,
                vector,
                count,
                ..
            } => {
                assert_eq!(tile, element.bytes() as u8 - 1);
                assert_eq!(index, 15);
                assert_eq!(vector + count, 32);
                assert!(offset < 16);
            }
            Kind::Vectors {
                index,
                vector,
                count,
                ..
            } => {
                assert_eq!(index, 11);
                assert_eq!(vector + count, 32);
            }
            Kind::TableGpr { register, lane, .. } => {
                assert_eq!(register, 31);
                assert_eq!(lane, 7);
                assert!(op.requirements.halted);
            }
            _ => {}
        }
    }
}
#[test]
fn execution_requirements_distinguish_nonstreaming_and_debug() {
    for e in ENCODINGS {
        let op = decode(e.value).unwrap();
        assert_eq!(
            op.requirements.halted,
            matches!(op.kind, Kind::TableGpr { .. })
        );
        assert_eq!(
            op.requirements.zt0,
            matches!(op.kind, Kind::ZeroTable | Kind::TableGpr { .. })
        );
        assert_eq!(
            op.requirements.streaming,
            matches!(
                op.kind,
                Kind::Tile { .. } | Kind::Vectors { .. } | Kind::ZeroVectors { .. }
            )
        );
        if let Kind::Tile {
            count: 4,
            element: ElementSize::Doubleword,
            ..
        } = op.kind
        {
            assert_eq!(op.requirements.minimum_current_svl_bits, 256);
        }
    }
}
