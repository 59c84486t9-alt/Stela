//! Structured AdvSIMD loads and stores (LD1-4, ST1-4, LD1R-4R), in architectural
//! access order, with post-index writeback.
use crate::aarch64::{Register, register};

mod multiple;
mod single;

const BASE_SHIFT: u32 = 5;
const INDEX_SHIFT: u32 = 16;
const REGISTER_MASK: u32 = 31;
const POST_INDEX_BIT: u32 = 1 << 23;
const LOW_VECTOR_BYTES: u8 = 8;
const VECTOR_REGISTER_MASK: u8 = 31;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Load,
    Store,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostIndex {
    None,
    TransferredBytes,
    /// X0..X30; encoded Rm31 selects TransferredBytes rather than XZR.
    Register(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    Multiple {
        repetitions: u8,
        structures: u8,
        vector_bytes: u8,
    },
    Lane {
        structures: u8,
        index: u8,
    },
    Replicate {
        structures: u8,
        vector_bytes: u8,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub direction: Direction,
    pub first_vector: u8,
    pub base: Register,
    pub element_bytes: u8,
    pub layout: Layout,
    pub post_index: PostIndex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadCommit {
    Lane { index: u8, clear_upper: bool },
    Replicate { vector_bytes: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Access {
    pub vector: u8,
    pub byte_offset: u8,
    pub commit: LoadCommit,
}

impl Operand {
    pub fn transferred_bytes(self) -> u8 {
        match self.layout {
            Layout::Multiple {
                repetitions,
                structures,
                vector_bytes,
            } => repetitions * structures * vector_bytes,
            Layout::Lane { structures, .. } | Layout::Replicate { structures, .. } => {
                structures * self.element_bytes
            }
        }
    }

    /// At most 64 accesses, without a separately allocated or cached schedule.
    pub fn accesses(self) -> impl Iterator<Item = Access> {
        let count = self.transferred_bytes() / self.element_bytes;
        (0..count).map(move |ordinal| {
            let (vector_delta, commit) = match self.layout {
                Layout::Multiple {
                    structures,
                    vector_bytes,
                    ..
                } => {
                    let elements = vector_bytes / self.element_bytes;
                    let repetition = ordinal / (elements * structures);
                    let index = (ordinal / structures) % elements;
                    let structure = ordinal % structures;
                    (
                        repetition + structure,
                        LoadCommit::Lane {
                            index,
                            clear_upper: vector_bytes == LOW_VECTOR_BYTES && index == 0,
                        },
                    )
                }
                Layout::Lane { index, .. } => (
                    ordinal,
                    LoadCommit::Lane {
                        index,
                        clear_upper: false,
                    },
                ),
                Layout::Replicate { vector_bytes, .. } => {
                    (ordinal, LoadCommit::Replicate { vector_bytes })
                }
            };
            Access {
                vector: (self.first_vector + vector_delta) & VECTOR_REGISTER_MASK,
                byte_offset: ordinal * self.element_bytes,
                commit,
            }
        })
    }
}

fn decode_addressing(word: u32) -> (Register, PostIndex) {
    let base = register((word >> BASE_SHIFT) & REGISTER_MASK, true);
    let index = ((word >> INDEX_SHIFT) & REGISTER_MASK) as u8;
    let post_index = if word & POST_INDEX_BIT == 0 {
        PostIndex::None
    } else if u32::from(index) == REGISTER_MASK {
        PostIndex::TransferredBytes
    } else {
        PostIndex::Register(index)
    };
    (base, post_index)
}

#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    multiple::decode(word).or_else(|| single::decode(word))
}

#[cfg(test)]
mod tests;
