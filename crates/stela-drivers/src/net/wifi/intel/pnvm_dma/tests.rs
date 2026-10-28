use super::super::{
    dma::tests::{Domain, Records, Source},
    identity::{Observed, Profile},
};
use super::*;
use core::sync::atomic::Ordering;
use std::sync::Mutex;
extern crate std;
fn chunks(bytes: &[Vec<u8>]) -> Vec<pnvm::Chunk<'_>> {
    bytes
        .iter()
        .enumerate()
        .map(|(index, data)| pnvm::Chunk {
            kind: pnvm::ChunkKind::MemoryDescriptor {
                address: 0xf0000000 + index as u32,
            },
            data,
            tlv_index: index,
        })
        .collect()
}
fn prepare(
    chunks: &[pnvm::Chunk<'_>],
    fragmented: bool,
    source: &Source,
    domain: &Arc<Domain>,
) -> Result<MappedTable, Error> {
    // SAFETY: the source owns fresh real RAM and the isolated model domain
    // grants no competing access; publication below is a model-only event.
    unsafe { MappedTable::prepare(chunks, fragmented, source, Some(domain.clone())) }
}

mod model;
mod reference;
