use super::{
    Blocks, Candidate, Growth, Needs, Place, Purpose, Resident, Source, Tiling, block_bytes,
};
use alloc::{vec, vec::Vec};

const MIB: u64 = 1 << 20;

/// Memory types of fixed capacities; each allocation is a new number.
struct Heaps {
    capacity: Vec<u64>,
    used: Vec<u64>,
    live: Vec<(u32, u32, u64)>,
    allocations: Vec<(u32, u64, Purpose)>,
    freed: Vec<u32>,
    next: u32,
}

impl Heaps {
    fn new(capacity: &[u64]) -> Self {
        Self {
            capacity: capacity.to_vec(),
            used: vec![0; capacity.len()],
            live: Vec::new(),
            allocations: Vec::new(),
            freed: Vec::new(),
            next: 0,
        }
    }

    fn blocks_allocated(&self) -> usize {
        self.allocations
            .iter()
            .filter(|&&(_, _, purpose)| purpose == Purpose::Block)
            .count()
    }
}

impl Source for Heaps {
    type Memory = u32;
    type Error = &'static str;

    fn allocate(
        &mut self,
        memory_type: u32,
        size: u64,
        purpose: Purpose,
    ) -> Result<u32, Self::Error> {
        let index = memory_type as usize;
        if self.used[index] + size > self.capacity[index] {
            return Err("out of memory");
        }
        self.used[index] += size;
        self.next += 1;
        self.live.push((self.next, memory_type, size));
        self.allocations.push((memory_type, size, purpose));
        Ok(self.next)
    }

    fn free(&mut self, memory: u32) {
        let index = self
            .live
            .iter()
            .position(|&(live, ..)| live == memory)
            .expect("freed memory is live");
        let (_, memory_type, size) = self.live.remove(index);
        self.used[memory_type as usize] -= size;
        self.freed.push(memory);
    }
}

fn candidate(memory_type: u32, block_bytes: u64) -> Candidate {
    Candidate {
        memory_type,
        block_bytes,
        atom: 1,
    }
}

fn needs(size: u64, alignment: u64, tiling: Tiling) -> Needs {
    Needs {
        size,
        alignment,
        tiling,
        own: false,
    }
}

fn placed(resident: Result<Resident<u32>, Option<&str>>) -> Place {
    match resident {
        Ok(Resident::Placed(place)) => place,
        other => panic!("not placed: {other:?}"),
    }
}

/// Places `needs` in type 0's 16 MiB blocks.
fn place(blocks: &mut Blocks<u32>, heaps: &mut Heaps, needs: Needs) -> Place {
    placed(blocks.allocate(heaps, needs, false, &[candidate(0, 16 * MIB)]))
}

#[test]
fn growth_names_what_a_placement_would_allocate_and_an_adopted_block_spares_it() {
    let mut heaps = Heaps::new(&[1 << 30, 1 << 30]);
    let mut blocks = Blocks::new(1);
    let candidates = [candidate(0, 16 * MIB), candidate(1, 16 * MIB)];
    let small = needs(4096, 256, Tiling::Optimal);
    // No block yet: the first candidate's block.
    assert_eq!(
        blocks.growth(small, false, &candidates),
        Growth::Block(candidates[0])
    );
    // More than half a block, or the driver's preference: memory of its own.
    let large = needs(9 * MIB, 256, Tiling::Optimal);
    assert_eq!(blocks.growth(large, false, &candidates), Growth::Own(0));
    let own = Needs { own: true, ..small };
    assert_eq!(blocks.growth(own, false, &candidates), Growth::Own(0));
    assert_eq!(blocks.growth(small, false, &[]), Growth::None);
    // A block allocated elsewhere takes the place with no allocation here.
    blocks.adopt_block(0, false, 1000, 16 * MIB);
    assert_eq!(blocks.growth(small, false, &candidates), Growth::None);
    assert_eq!(
        blocks.growth(small, true, &candidates),
        Growth::Block(candidates[0]),
        "a mapped resource takes a mapped block"
    );
    let place = placed(blocks.allocate(&mut heaps, small, false, &candidates));
    assert_eq!(blocks.memory(place.block), Some((1000, 16 * MIB)));
    assert!(heaps.allocations.is_empty());
    blocks.adopt_own();
    assert_eq!(blocks.report().own, 1);
    assert_eq!(blocks.report().blocks, 1);
}

#[test]
fn blocks_are_an_eighth_of_small_heaps() {
    assert_eq!(block_bytes(16 << 30, true), 64 * MIB);
    assert_eq!(block_bytes(16 << 30, false), 16 * MIB);
    assert_eq!(block_bytes(256 * MIB, true), 32 * MIB);
    assert_eq!(
        block_bytes(100 * MIB, true),
        8 * MIB,
        "rounds down to a power of two"
    );
    assert_eq!(block_bytes(7, true), 0);
}

#[test]
fn places_start_at_their_alignment() {
    let mut heaps = Heaps::new(&[1 << 30]);
    let mut blocks = Blocks::new(1);
    let mut places = Vec::new();
    for (size, alignment) in [(100, 16), (4096, 4096), (10, 1), (300, 256), (1, 65536)] {
        let place = place(
            &mut blocks,
            &mut heaps,
            needs(size, alignment, Tiling::Optimal),
        );
        assert_eq!(place.offset % alignment, 0, "{size} bytes at {alignment}");
        assert_eq!(place.block, 0);
        places.push(place);
    }
    let offsets: Vec<_> = places.iter().map(|place| place.offset).collect();
    assert_eq!(offsets, [0, 4096, 100, 256, 65536], "first fit fills holes");
    for (index, a) in places.iter().enumerate() {
        for b in &places[index + 1..] {
            assert!(
                a.offset + a.size <= b.offset || b.offset + b.size <= a.offset,
                "places do not overlap"
            );
        }
    }
    assert_eq!(heaps.blocks_allocated(), 1);
}

#[test]
fn optimal_places_skip_a_linear_neighbour_s_granularity_page() {
    let mut heaps = Heaps::new(&[1 << 30]);
    let mut blocks = Blocks::new(1024);
    let linear = place(&mut blocks, &mut heaps, needs(100, 16, Tiling::Linear));
    assert_eq!(linear.offset, 0);
    let optimal = place(&mut blocks, &mut heaps, needs(100, 256, Tiling::Optimal));
    assert_eq!(optimal.offset, 1024, "not 256, on the buffer's page");
    let linear = place(&mut blocks, &mut heaps, needs(100, 16, Tiling::Linear));
    assert_eq!(linear.offset, 112, "linear places share their pages");
    let optimal = place(&mut blocks, &mut heaps, needs(100, 256, Tiling::Optimal));
    assert_eq!(
        optimal.offset, 1280,
        "after the optimal place, off the buffers' page"
    );
}

#[test]
fn linear_places_end_before_an_optimal_neighbour_s_granularity_page() {
    let mut heaps = Heaps::new(&[1 << 30]);
    let mut blocks = Blocks::new(1024);
    let first = place(&mut blocks, &mut heaps, needs(256, 256, Tiling::Optimal));
    let second = place(&mut blocks, &mut heaps, needs(256, 256, Tiling::Optimal));
    assert_eq!((first.offset, second.offset), (0, 256));
    assert!(blocks.release(&mut heaps, first));
    let linear = place(&mut blocks, &mut heaps, needs(16, 16, Tiling::Linear));
    assert_eq!(
        linear.offset, 1024,
        "not in the hole that shares the image's page"
    );
    let optimal = place(&mut blocks, &mut heaps, needs(256, 256, Tiling::Optimal));
    assert_eq!(optimal.offset, 0, "an image takes the hole");
}

#[test]
fn freed_places_are_reused_first_fit_and_merge() {
    let mut heaps = Heaps::new(&[1 << 30]);
    let mut blocks = Blocks::new(1);
    let places: Vec<_> = (0..6)
        .map(|_| place(&mut blocks, &mut heaps, needs(MIB, 4096, Tiling::Optimal)))
        .collect();
    assert!(blocks.release(&mut heaps, places[1]));
    assert!(blocks.release(&mut heaps, places[4]));
    let two = place(
        &mut blocks,
        &mut heaps,
        needs(2 * MIB, 4096, Tiling::Optimal),
    );
    assert_eq!(two.offset, 6 * MIB, "no hole holds two MiB");
    assert!(blocks.release(&mut heaps, places[2]));
    let merged = place(
        &mut blocks,
        &mut heaps,
        needs(2 * MIB, 4096, Tiling::Optimal),
    );
    assert_eq!(merged.offset, MIB, "neighbouring holes merge");
    let small = place(&mut blocks, &mut heaps, needs(4096, 4096, Tiling::Optimal));
    assert_eq!(small.offset, 4 * MIB, "the first hole that fits");
    assert_eq!(heaps.blocks_allocated(), 1);
    let report = blocks.report();
    assert_eq!((report.blocks, report.placed), (1, 6));
    assert_eq!(
        report.placed_bytes,
        4 * MIB + 2 * MIB + 2 * MIB + 4096 - MIB
    );
}

#[test]
fn full_blocks_open_another_block_of_their_pool() {
    let mut heaps = Heaps::new(&[1 << 30]);
    let mut blocks = Blocks::new(1);
    let places: Vec<_> = (0..3)
        .map(|_| {
            place(
                &mut blocks,
                &mut heaps,
                needs(8 * MIB, 4096, Tiling::Optimal),
            )
        })
        .collect();
    assert_eq!(
        places.iter().map(|place| place.block).collect::<Vec<_>>(),
        [0, 0, 1]
    );
    let mapped = placed(blocks.allocate(
        &mut heaps,
        needs(MIB, 4096, Tiling::Linear),
        true,
        &[candidate(0, 16 * MIB)],
    ));
    assert_eq!(mapped.block, 2, "mapped resources have blocks of their own");
}

#[test]
fn an_emptied_block_is_freed_once_its_pool_keeps_another_empty_block() {
    let mut heaps = Heaps::new(&[1 << 30]);
    let mut blocks = Blocks::new(1);
    let places: Vec<_> = (0..4)
        .map(|_| {
            place(
                &mut blocks,
                &mut heaps,
                needs(8 * MIB, 4096, Tiling::Optimal),
            )
        })
        .collect();
    assert!(blocks.release(&mut heaps, places[2]));
    assert!(blocks.release(&mut heaps, places[3]));
    assert!(heaps.freed.is_empty(), "the pool's only empty block stays");
    assert!(blocks.release(&mut heaps, places[0]));
    assert!(blocks.release(&mut heaps, places[1]));
    assert_eq!(heaps.freed, [1], "the second empty block goes");
    assert!(
        !blocks.release(&mut heaps, places[1]),
        "a place is released once"
    );
    let again = place(
        &mut blocks,
        &mut heaps,
        needs(8 * MIB, 4096, Tiling::Optimal),
    );
    assert_eq!(again.block, 1, "the kept block serves the pool");
    assert!(blocks.release(&mut heaps, again));
    assert_eq!(blocks.release_empty(&mut heaps), 1);
    assert_eq!(heaps.used, [0]);
    assert_eq!(blocks.report().blocks, 0);
}

#[test]
fn resources_the_driver_wants_alone_or_larger_than_half_a_block_get_their_own_memory() {
    let mut heaps = Heaps::new(&[1 << 30]);
    let mut blocks = Blocks::new(1);
    let types = [candidate(0, 16 * MIB)];
    let alone = Needs {
        own: true,
        ..needs(MIB, 4096, Tiling::Optimal)
    };
    let large = needs(8 * MIB + 1, 4096, Tiling::Optimal);
    let aligned = needs(4096, 16 * MIB, Tiling::Optimal);
    for needs in [alone, large, aligned] {
        assert!(matches!(
            blocks.allocate(&mut heaps, needs, false, &types),
            Ok(Resident::Own(_))
        ));
    }
    let blockless = [candidate(0, 0)];
    assert!(matches!(
        blocks.allocate(
            &mut heaps,
            needs(4096, 4096, Tiling::Linear),
            false,
            &blockless
        ),
        Ok(Resident::Own(_))
    ));
    assert_eq!(heaps.blocks_allocated(), 0);
    assert_eq!(blocks.report().own, 4);
    blocks.release_own();
    assert_eq!(blocks.report().own, 3);
}

#[test]
fn a_type_without_room_for_a_block_gives_the_resource_its_own_memory() {
    let mut heaps = Heaps::new(&[4 * MIB, 1 << 30]);
    let mut blocks = Blocks::new(1);
    let resident = blocks.allocate(
        &mut heaps,
        needs(MIB, 4096, Tiling::Optimal),
        false,
        &[candidate(0, 16 * MIB), candidate(1, 16 * MIB)],
    );
    assert!(matches!(resident, Ok(Resident::Own(_))));
    assert_eq!(
        heaps.allocations,
        [(0, MIB, Purpose::Own)],
        "in the preferred type"
    );
}

#[test]
fn a_full_type_passes_the_resource_to_the_next_candidate() {
    let mut heaps = Heaps::new(&[MIB / 2, 1 << 30]);
    let mut blocks = Blocks::new(1);
    let place = placed(blocks.allocate(
        &mut heaps,
        needs(MIB, 4096, Tiling::Optimal),
        false,
        &[candidate(0, 16 * MIB), candidate(1, 16 * MIB)],
    ));
    assert_eq!(blocks.memory(place.block), Some((1, 16 * MIB)));
}

#[test]
fn exhausted_memory_frees_empty_blocks_before_refusing() {
    let mut heaps = Heaps::new(&[40 * MIB]);
    let mut blocks = Blocks::new(1);
    let types = [candidate(0, 16 * MIB)];
    let mapped =
        placed(blocks.allocate(&mut heaps, needs(MIB, 4096, Tiling::Linear), true, &types));
    let first = place(&mut blocks, &mut heaps, needs(MIB, 4096, Tiling::Optimal));
    assert!(blocks.release(&mut heaps, mapped));
    assert!(
        heaps.freed.is_empty(),
        "the mapped pool keeps its empty block"
    );
    let own = blocks.allocate(
        &mut heaps,
        needs(20 * MIB, 4096, Tiling::Optimal),
        false,
        &types,
    );
    assert!(
        matches!(own, Ok(Resident::Own(_))),
        "the empty block made room"
    );
    assert_eq!(heaps.freed.len(), 1);
    let refused = blocks.allocate(
        &mut heaps,
        needs(20 * MIB, 4096, Tiling::Optimal),
        false,
        &types,
    );
    assert_eq!(refused, Err(Some("out of memory")));
    assert!(
        blocks.release(&mut heaps, first),
        "the occupied block stays"
    );
    assert_eq!(
        blocks.allocate(&mut heaps, needs(MIB, 1, Tiling::Linear), false, &[]),
        Err(None),
        "no memory type suits it"
    );
}

#[test]
fn non_coherent_places_hold_whole_atoms() {
    let mut heaps = Heaps::new(&[1 << 30]);
    let mut blocks = Blocks::new(1);
    let types = [Candidate {
        atom: 64,
        ..candidate(0, 16 * MIB)
    }];
    let places: Vec<_> = (0..3)
        .map(|_| placed(blocks.allocate(&mut heaps, needs(10, 4, Tiling::Linear), true, &types)))
        .collect();
    for place in &places {
        assert_eq!((place.offset % 64, place.size), (0, 64));
    }
    assert_eq!(places[2].offset, 128);
}

#[test]
fn releasing_every_block_frees_its_memory() {
    let mut heaps = Heaps::new(&[1 << 30]);
    let mut blocks = Blocks::new(1);
    for _ in 0..3 {
        place(
            &mut blocks,
            &mut heaps,
            needs(6 * MIB, 4096, Tiling::Optimal),
        );
    }
    assert_eq!(blocks.report().blocks, 2);
    blocks.release_all(&mut heaps);
    assert_eq!(heaps.used, [0]);
    assert_eq!(blocks.memory(0), None);
}
