use super::*;
use alloc::vec::Vec;

fn operand(layout: Layout) -> Operand {
    Operand {
        direction: Direction::Load,
        first_vector: 31,
        base: Register::X(5),
        element_bytes: 2,
        layout,
        post_index: PostIndex::TransferredBytes,
    }
}

#[test]
fn interleaving_and_repetitions_follow_source_order_and_wrap_vectors() {
    let interleaved = operand(Layout::Multiple {
        repetitions: 1,
        structures: 3,
        vector_bytes: LOW_VECTOR_BYTES,
    });
    let accesses: Vec<_> = interleaved.accesses().collect();
    assert_eq!(interleaved.transferred_bytes(), 24);
    assert_eq!(accesses.len(), 12);
    for (ordinal, access) in accesses.iter().enumerate() {
        assert_eq!(access.vector, [31, 0, 1][ordinal % 3]);
        assert_eq!(access.byte_offset, (ordinal * 2) as u8);
        assert_eq!(
            access.commit,
            LoadCommit::Lane {
                index: (ordinal / 3) as u8,
                clear_upper: ordinal < 3,
            }
        );
    }
    let consecutive = operand(Layout::Multiple {
        repetitions: 4,
        structures: 1,
        vector_bytes: LOW_VECTOR_BYTES,
    });
    for (ordinal, access) in consecutive.accesses().enumerate() {
        assert_eq!(access.vector, [31, 0, 1, 2][ordinal / 4]);
        assert_eq!(
            access.commit,
            LoadCommit::Lane {
                index: (ordinal % 4) as u8,
                clear_upper: ordinal % 4 == 0,
            }
        );
    }
}

#[test]
fn lane_preserves_unselected_bits_and_replication_has_scalar_footprint() {
    let lane = operand(Layout::Lane {
        structures: 4,
        index: 7,
    });
    assert_eq!(lane.transferred_bytes(), 8);
    assert!(lane.accesses().all(|access| access.commit
        == LoadCommit::Lane {
            index: 7,
            clear_upper: false,
        }));
    let replicate = operand(Layout::Replicate {
        structures: 4,
        vector_bytes: LOW_VECTOR_BYTES,
    });
    assert_eq!(replicate.transferred_bytes(), 8);
    assert!(replicate.accesses().all(|access| access.commit
        == LoadCommit::Replicate {
            vector_bytes: LOW_VECTOR_BYTES,
        }));
}
