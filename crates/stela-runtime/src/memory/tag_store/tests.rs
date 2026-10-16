use super::*;
use std::sync::{Arc, Barrier};
use std::thread;

const CONCURRENT_ITERATIONS: usize = 1024;

fn tag(value: u8) -> AllocationTag {
    AllocationTag::new(value).unwrap()
}

#[test]
fn pristine_reads_and_initial_tag_writes_do_not_allocate() {
    let initial = tag(11);
    let store = TagStore::new(TAG_CHUNK_BYTES * 3, initial).unwrap();
    for offset in (0..TAG_CHUNK_BYTES * 3).step_by(TAG_GRANULE_BYTES) {
        assert_eq!(store.read(offset), Ok(initial));
        assert_eq!(store.write(offset, initial), Ok(()));
    }
    assert!(store.chunks.read().unwrap().is_empty());
}

#[test]
fn writes_preserve_neighbors_and_chunk_boundaries() {
    let store = TagStore::new(TAG_CHUNK_BYTES * 2, tag(7)).unwrap();
    for (offset, value) in [
        (0, 1),
        (TAG_GRANULE_BYTES, 15),
        (TAG_CHUNK_BYTES - TAG_GRANULE_BYTES, 3),
        (TAG_CHUNK_BYTES, 12),
    ] {
        store.write(offset, tag(value)).unwrap();
    }
    for offset in (0..TAG_CHUNK_BYTES * 2).step_by(TAG_GRANULE_BYTES) {
        let expected = match offset {
            0 => 1,
            TAG_GRANULE_BYTES => 15,
            x if x == TAG_CHUNK_BYTES - TAG_GRANULE_BYTES => 3,
            TAG_CHUNK_BYTES => 12,
            _ => 7,
        };
        assert_eq!(store.read(offset), Ok(tag(expected)));
    }
    assert_eq!(store.chunks.read().unwrap().len(), 2);
}

#[test]
fn invalid_ranges_and_incomplete_tail_decline_without_allocation() {
    assert_eq!(
        TagStore::new(0, AllocationTag::ZERO).unwrap_err(),
        TagStoreError::EmptyBacking
    );
    let store = TagStore::new(TAG_GRANULE_BYTES + 1, AllocationTag::ZERO).unwrap();
    assert_eq!(store.read(0), Ok(AllocationTag::ZERO));
    for (offset, error) in [
        (1, TagStoreError::UnalignedOffset),
        (TAG_GRANULE_BYTES, TagStoreError::OutOfBounds),
        (
            usize::MAX - (TAG_GRANULE_BYTES - 1),
            TagStoreError::OutOfBounds,
        ),
    ] {
        assert_eq!(store.read(offset), Err(error));
        assert_eq!(store.write(offset, tag(3)), Err(error));
    }
    assert!(store.chunks.read().unwrap().is_empty());
}

#[test]
fn huge_backing_allocates_only_touched_chunks() {
    let backing_bytes = usize::try_from(64u64 << 30).unwrap();
    let store = TagStore::new(backing_bytes, AllocationTag::ZERO).unwrap();
    let last = backing_bytes - TAG_GRANULE_BYTES;
    assert_eq!(store.read(last), Ok(AllocationTag::ZERO));
    assert!(store.chunks.read().unwrap().is_empty());
    store.write(0, tag(3)).unwrap();
    store.write(last, tag(12)).unwrap();
    assert_eq!(store.read(0), Ok(tag(3)));
    assert_eq!(store.read(last), Ok(tag(12)));
    assert_eq!(store.read(backing_bytes / 2), Ok(AllocationTag::ZERO));
    let chunks = store.chunks.read().unwrap();
    assert_eq!(chunks.len(), 2);
    assert_eq!(
        chunks.values().map(Vec::len).sum::<usize>(),
        2 * TAG_CHUNK_GRANULES
    );
}

#[test]
fn aliases_share_values_and_separate_backings_keep_independent_planes() {
    let first = Arc::new(TagStore::new(TAG_GRANULE_BYTES, tag(2)).unwrap());
    let alias = Arc::clone(&first);
    let private = TagStore::new(TAG_GRANULE_BYTES, tag(2)).unwrap();
    first.write(0, tag(13)).unwrap();
    assert_eq!(alias.read(0), Ok(tag(13)));
    assert_eq!(private.read(0), Ok(tag(2)));
}

#[test]
fn concurrent_chunk_creation_and_neighbor_writes_preserve_whole_tags() {
    let store = TagStore::new(TAG_CHUNK_BYTES, tag(3)).unwrap();
    let barrier = Barrier::new(7);
    thread::scope(|scope| {
        for value in [3, 12] {
            let (store, barrier) = (&store, &barrier);
            scope.spawn(move || {
                barrier.wait();
                for _ in 0..CONCURRENT_ITERATIONS {
                    store.write(0, tag(value)).unwrap();
                }
            });
        }
        scope.spawn(|| {
            barrier.wait();
            for _ in 0..CONCURRENT_ITERATIONS {
                assert!(matches!(store.read(0).unwrap().value(), 3 | 12));
            }
        });
        for index in 1..=4 {
            let (store, barrier) = (&store, &barrier);
            scope.spawn(move || {
                barrier.wait();
                let offset = index * TAG_GRANULE_BYTES;
                for _ in 0..CONCURRENT_ITERATIONS {
                    store.write(offset, tag(index as u8)).unwrap();
                    assert_eq!(store.read(offset), Ok(tag(index as u8)));
                }
            });
        }
    });
    assert_eq!(store.chunks.read().unwrap().len(), 1);
    for index in 1..=4 {
        assert_eq!(store.read(index * TAG_GRANULE_BYTES), Ok(tag(index as u8)));
    }
}

#[test]
fn poisoned_storage_reports_failure_without_silently_resetting_tags() {
    let store = TagStore::new(TAG_GRANULE_BYTES, tag(7)).unwrap();
    let result = std::panic::catch_unwind(|| {
        let _guard = store.chunks.write().unwrap();
        panic!("deliberate lock poison");
    });
    assert!(result.is_err());
    assert_eq!(store.read(0), Err(TagStoreError::LockPoisoned));
    assert_eq!(store.write(0, tag(3)), Err(TagStoreError::LockPoisoned));
}
