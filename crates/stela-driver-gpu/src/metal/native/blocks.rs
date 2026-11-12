//! Placement of buffers and images in large memory blocks.
//!
//! Each `vkAllocateMemory` costs the kernel a buffer object and its GPU
//! mappings (nouveau's `GEM_NEW`), so resources of one memory type share
//! blocks, placed first fit at their alignment. Linear and optimal resources
//! never share a `bufferImageGranularity` page. A resource takes memory of
//! its own when the driver requires or prefers that, when it is more than
//! half a block, or when no block can be allocated for it; a memory type
//! that cannot hold it passes it to the next candidate type. A block that
//! empties is freed unless it is its pool's only empty block, and empty
//! blocks are freed before an allocation is refused.
use crate::metal::vulkan::backend::MemoryBlocks;
use alloc::collections::BTreeMap;

/// The block size of device-local memory.
const DEVICE_BLOCK_BYTES: u64 = 64 << 20;
/// The block size of system memory, which is pinned for the GPU while a
/// block lives.
const SYSTEM_BLOCK_BYTES: u64 = 16 << 20;

/// The size of the blocks of a memory type in a heap of `heap` bytes: at
/// most an eighth of the heap, so a few blocks never hold most of it; zero
/// when the heap is too small for blocks.
pub(super) fn block_bytes(heap: u64, device_local: bool) -> u64 {
    let limit = if device_local {
        DEVICE_BLOCK_BYTES
    } else {
        SYSTEM_BLOCK_BYTES
    };
    match heap / 8 {
        0 => 0,
        eighth => limit.min(1 << eighth.ilog2()),
    }
}

/// How a resource lays out its memory, which `bufferImageGranularity`
/// keeps apart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Tiling {
    /// Buffers and linear images.
    Linear,
    /// Optimally tiled images.
    Optimal,
}

/// One resource's memory requirements.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Needs {
    pub size: u64,
    /// A power of two.
    pub alignment: u64,
    pub tiling: Tiling,
    /// The driver requires or prefers memory of the resource's own
    /// (`VkMemoryDedicatedRequirements`).
    pub own: bool,
}

/// A memory type a resource may use, in order of preference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Candidate {
    pub memory_type: u32,
    /// The size of this type's blocks; zero places nothing in blocks.
    pub block_bytes: u64,
    /// What mapped, non-coherent memory flushes and invalidates at a time
    /// (`nonCoherentAtomSize`), which places keep whole so an invalidate
    /// never discards another place's writes; 1 otherwise.
    pub atom: u64,
}

/// What a block allocation or an allocation of a resource's own is for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Purpose {
    Block,
    Own,
}

/// Where memory comes from.
pub(super) trait Source {
    type Memory: Copy;
    type Error;
    /// `size` bytes of `memory_type`.
    fn allocate(
        &mut self,
        memory_type: u32,
        size: u64,
        purpose: Purpose,
    ) -> Result<Self::Memory, Self::Error>;
    /// Frees memory nothing uses any longer.
    fn free(&mut self, memory: Self::Memory);
}

/// What placing a resource would allocate first ([`Blocks::growth`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Growth {
    /// Nothing: a block has room.
    None,
    /// A new block of this candidate's type and size.
    Block(Candidate),
    /// Memory of the resource's own, of this type.
    Own(u32),
}

/// A resource's place in a block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Place {
    pub block: u64,
    pub offset: u64,
    pub size: u64,
}

/// A resource's memory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Resident<M> {
    Placed(Place),
    Own(M),
}

/// The resources that share a block: of one memory type, mapped or not.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Pool {
    memory_type: u32,
    mapped: bool,
}

/// A place a resource asks for.
#[derive(Clone, Copy, Debug)]
struct Request {
    size: u64,
    alignment: u64,
    tiling: Tiling,
}

struct Block<M> {
    pool: Pool,
    memory: M,
    size: u64,
    /// The placed ranges by offset, with their sizes and tilings.
    ranges: BTreeMap<u64, (u64, Tiling)>,
}

impl<M> Block<M> {
    /// The first offset where `request` fits.
    fn fit(&self, request: Request, granularity: u64) -> Option<u64> {
        let mut start = 0;
        let mut before = None;
        for (&offset, &(size, tiling)) in &self.ranges {
            let gap = Gap {
                start,
                end: offset,
                before,
                after: Some((offset, tiling)),
            };
            if let Some(place) = gap.fit(request, granularity) {
                return Some(place);
            }
            start = offset + size;
            before = Some((start, tiling));
        }
        Gap {
            start,
            end: self.size,
            before,
            after: None,
        }
        .fit(request, granularity)
    }

    fn used(&self) -> u64 {
        self.ranges.values().map(|&(size, _)| size).sum()
    }
}

/// Free space between two placed ranges.
struct Gap {
    start: u64,
    end: u64,
    /// The end and tiling of the range before.
    before: Option<(u64, Tiling)>,
    /// The start and tiling of the range after.
    after: Option<(u64, Tiling)>,
}

impl Gap {
    fn fit(&self, request: Request, granularity: u64) -> Option<u64> {
        let page = |offset: u64| offset / granularity;
        let mut start = self.start.checked_next_multiple_of(request.alignment)?;
        if let Some((end, tiling)) = self.before
            && tiling != request.tiling
            && page(end - 1) == page(start)
        {
            start = start.checked_next_multiple_of(granularity.max(request.alignment))?;
        }
        let end = start.checked_add(request.size)?;
        let apart =
            |(next, tiling): (u64, Tiling)| tiling == request.tiling || page(end - 1) != page(next);
        (end <= self.end && self.after.is_none_or(apart)).then_some(start)
    }
}

/// Every block of one device.
pub(super) struct Blocks<M> {
    /// `bufferImageGranularity`, a power of two.
    granularity: u64,
    blocks: BTreeMap<u64, Block<M>>,
    next: u64,
    /// Live resources in memory of their own.
    own: usize,
}

impl<M: Copy> Blocks<M> {
    pub(super) fn new(granularity: u64) -> Self {
        Self {
            granularity: granularity.max(1).next_power_of_two(),
            blocks: BTreeMap::new(),
            next: 0,
            own: 0,
        }
    }

    /// Memory for a resource of `needs` from the first of `candidates` that
    /// has room. When none has, empty blocks are freed and the candidates
    /// tried again. Fails with the last allocation's error, or `None`
    /// without candidates.
    pub(super) fn allocate<S: Source<Memory = M>>(
        &mut self,
        source: &mut S,
        needs: Needs,
        mapped: bool,
        candidates: &[Candidate],
    ) -> Result<Resident<M>, Option<S::Error>> {
        let mut last = None;
        loop {
            for candidate in candidates {
                if !needs.own
                    && let Some(place) = self.place(source, needs, mapped, candidate)
                {
                    return Ok(Resident::Placed(place));
                }
                match source.allocate(candidate.memory_type, needs.size, Purpose::Own) {
                    Ok(memory) => {
                        self.own += 1;
                        return Ok(Resident::Own(memory));
                    }
                    Err(error) => last = Some(error),
                }
            }
            if self.release_empty(source) == 0 {
                return Err(last);
            }
        }
    }

    /// What [`Self::allocate`] would allocate first for `needs`: nothing
    /// when a block of the first candidate has room, else a block of that
    /// candidate, or memory of the resource's own.
    pub(super) fn growth(&self, needs: Needs, mapped: bool, candidates: &[Candidate]) -> Growth {
        let Some(first) = candidates.first() else {
            return Growth::None;
        };
        let request = Self::request(needs, first);
        let Some(request) = request.filter(|_| !needs.own) else {
            return Growth::Own(first.memory_type);
        };
        let pool = Pool {
            memory_type: first.memory_type,
            mapped,
        };
        let room = self
            .blocks
            .values()
            .any(|block| block.pool == pool && block.fit(request, self.granularity).is_some());
        if room {
            Growth::None
        } else {
            Growth::Block(*first)
        }
    }

    /// Adds an empty block of `size` bytes of `memory_type`, allocated
    /// elsewhere ([`Purpose::Block`]), which later places use.
    pub(super) fn adopt_block(&mut self, memory_type: u32, mapped: bool, memory: M, size: u64) {
        let block = Block {
            pool: Pool {
                memory_type,
                mapped,
            },
            memory,
            size,
            ranges: BTreeMap::new(),
        };
        self.blocks.insert(self.next, block);
        self.next += 1;
    }

    /// Records a resource in memory of its own allocated elsewhere.
    pub(super) fn adopt_own(&mut self) {
        self.own += 1;
    }

    /// The place `needs` asks of a block of `candidate`'s type; `None` when
    /// it takes more than half a block.
    fn request(needs: Needs, candidate: &Candidate) -> Option<Request> {
        let atom = candidate.atom.max(1);
        let request = Request {
            size: needs.size.max(1).checked_next_multiple_of(atom)?,
            alignment: needs.alignment.max(atom),
            tiling: needs.tiling,
        };
        let half = candidate.block_bytes / 2;
        (request.alignment.is_power_of_two() && request.size <= half && request.alignment <= half)
            .then_some(request)
    }

    /// A place in a block of `candidate`'s type, in a new block when none
    /// has room.
    fn place<S: Source<Memory = M>>(
        &mut self,
        source: &mut S,
        needs: Needs,
        mapped: bool,
        candidate: &Candidate,
    ) -> Option<Place> {
        let request = Self::request(needs, candidate)?;
        let pool = Pool {
            memory_type: candidate.memory_type,
            mapped,
        };
        let granularity = self.granularity;
        let existing = self
            .blocks
            .iter_mut()
            .filter(|(_, block)| block.pool == pool)
            .find_map(|(&id, block)| Some((id, block.fit(request, granularity)?)));
        let (block, offset) = match existing {
            Some(found) => found,
            None => {
                let memory = source
                    .allocate(candidate.memory_type, candidate.block_bytes, Purpose::Block)
                    .ok()?;
                let block = Block {
                    pool,
                    memory,
                    size: candidate.block_bytes,
                    ranges: BTreeMap::new(),
                };
                // A request of at most half a block, aligned to at most
                // half, fits an empty block at 0.
                let offset = block.fit(request, granularity)?;
                let id = self.next;
                self.next += 1;
                self.blocks.insert(id, block);
                (id, offset)
            }
        };
        self.blocks
            .get_mut(&block)?
            .ranges
            .insert(offset, (request.size, request.tiling));
        Some(Place {
            block,
            offset,
            size: request.size,
        })
    }

    /// The block memory behind `place` and its size.
    pub(super) fn memory(&self, block: u64) -> Option<(M, u64)> {
        self.blocks
            .get(&block)
            .map(|block| (block.memory, block.size))
    }

    /// Returns `place` to its block, freeing the block when it empties and
    /// its pool keeps another empty block. False when nothing is placed
    /// there.
    pub(super) fn release<S: Source<Memory = M>>(&mut self, source: &mut S, place: Place) -> bool {
        let Some(block) = self.blocks.get_mut(&place.block) else {
            return false;
        };
        if block.ranges.remove(&place.offset).is_none() {
            return false;
        }
        if block.ranges.is_empty() {
            let pool = block.pool;
            let spare = self.blocks.iter().any(|(&id, other)| {
                id != place.block && other.pool == pool && other.ranges.is_empty()
            });
            if spare && let Some(block) = self.blocks.remove(&place.block) {
                source.free(block.memory);
            }
        }
        true
    }

    /// Records that a resource's own memory was freed.
    pub(super) fn release_own(&mut self) {
        self.own = self.own.saturating_sub(1);
    }

    /// Frees every empty block; answers how many.
    pub(super) fn release_empty<S: Source<Memory = M>>(&mut self, source: &mut S) -> usize {
        let before = self.blocks.len();
        self.blocks.retain(|_, block| {
            let empty = block.ranges.is_empty();
            if empty {
                source.free(block.memory);
            }
            !empty
        });
        before - self.blocks.len()
    }

    /// Frees every block, placed resources or not.
    pub(super) fn release_all<S: Source<Memory = M>>(&mut self, source: &mut S) {
        for block in core::mem::take(&mut self.blocks).into_values() {
            source.free(block.memory);
        }
    }

    pub(super) fn report(&self) -> MemoryBlocks {
        MemoryBlocks {
            blocks: self.blocks.len(),
            block_bytes: self.blocks.values().map(|block| block.size).sum(),
            placed: self.blocks.values().map(|block| block.ranges.len()).sum(),
            placed_bytes: self.blocks.values().map(Block::used).sum(),
            own: self.own,
        }
    }
}

#[cfg(test)]
mod tests;
