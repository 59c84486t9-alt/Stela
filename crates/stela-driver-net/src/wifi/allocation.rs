//! Common native DMA backing construction for Wi-Fi queue owners.
//!
//! Publication, completion and uncertain retirement stay with the vendor
//! queue. A WB mapping alone does not establish hardware coherence: each
//! installer must check the requester and its NoSnoop/ATS policy.
use crate::bus::dma::{
    mapping::{Direction, DmaDomain, DmaError, DmaMapping},
    memory::{CacheAttribute, CpuMapping, MemoryError, PageSource},
};
use alloc::sync::Arc;

/// Preserve the native allocation, CPU mapping and device mapping order.
/// Each vendor keeps its existing typed error conversions and queue lifetime.
pub(super) fn allocate_32bit<E>(
    source: &dyn PageSource,
    domain: Arc<dyn DmaDomain>,
    bytes: usize,
    direction: Direction,
) -> Result<(CpuMapping, DmaMapping), E>
where
    E: From<MemoryError> + From<DmaError>,
{
    let pages = source.allocate(bytes, 4096, CacheAttribute::WriteBack)?;
    let cpu = pages.cpu_mapping(CacheAttribute::WriteBack)?;
    let dma = DmaMapping::map(domain, pages, direction, u32::MAX.into())?;
    Ok((cpu, dma))
}
