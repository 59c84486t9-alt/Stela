//! Sparse allocation-tag storage of one physical backing, shared by its aliases.

use super::tags::AllocationTag;
use crate::platform::sync::RwLock;
#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap as HashMap;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, Ordering};
#[cfg(feature = "std")]
use std::collections::HashMap;

pub use super::tags::TAG_GRANULE_BYTES;
const TAG_CHUNK_GRANULES: usize = 256;
const TAG_CHUNK_BYTES: usize = TAG_GRANULE_BYTES * TAG_CHUNK_GRANULES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagStoreError {
    EmptyBacking,
    UnalignedOffset,
    OutOfBounds,
    LockPoisoned,
    AllocationFailed,
}

impl core::fmt::Display for TagStoreError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "allocation-tag storage failed: {self:?}")
    }
}

impl core::error::Error for TagStoreError {}

/// The tag plane of an existing physical backing.
///
/// Construction and reads of untouched granules allocate nothing; each
/// populated chunk holds at most TAG_CHUNK_GRANULES atomic bytes. The backing
/// owner chooses the initial tag.
#[derive(Debug)]
pub struct TagStore {
    backing_bytes: usize,
    initial_tag: AllocationTag,
    chunks: RwLock<HashMap<usize, Vec<AtomicU8>>>,
}

impl TagStore {
    pub fn new(backing_bytes: usize, initial_tag: AllocationTag) -> Result<Self, TagStoreError> {
        if backing_bytes == 0 {
            return Err(TagStoreError::EmptyBacking);
        }
        Ok(Self {
            backing_bytes,
            initial_tag,
            chunks: RwLock::new(HashMap::new()),
        })
    }

    /// Read one complete, aligned physical granule's allocation tag.
    /// Reading an untouched chunk returns its initial tag without allocating.
    pub fn read(&self, backing_offset: usize) -> Result<AllocationTag, TagStoreError> {
        let (chunk_index, tag_index) = self.location(backing_offset)?;
        let chunks = self
            .chunks
            .read()
            .map_err(|_| TagStoreError::LockPoisoned)?;
        Ok(chunks.get(&chunk_index).map_or(self.initial_tag, |tags| {
            // Only checked AllocationTag values enter these cells.
            AllocationTag::new(tags[tag_index].load(Ordering::Relaxed))
                .expect("stored allocation tag fits four bits")
        }))
    }

    /// Publish one tag atomically. This does not publish or synchronize data RAM.
    /// The caller supplies the execution domain's ordering and writer protocol.
    pub fn write(&self, backing_offset: usize, tag: AllocationTag) -> Result<(), TagStoreError> {
        let (chunk_index, tag_index) = self.location(backing_offset)?;
        {
            let chunks = self
                .chunks
                .read()
                .map_err(|_| TagStoreError::LockPoisoned)?;
            if let Some(tags) = chunks.get(&chunk_index) {
                tags[tag_index].store(tag.value(), Ordering::Relaxed);
                return Ok(());
            }
            // This read-locked absence is the operation's linearization point:
            // another writer cannot insert a chunk until the guard is released.
            if tag == self.initial_tag {
                return Ok(());
            }
        }
        let mut chunks = self
            .chunks
            .write()
            .map_err(|_| TagStoreError::LockPoisoned)?;
        if let Some(tags) = chunks.get(&chunk_index) {
            tags[tag_index].store(tag.value(), Ordering::Relaxed);
            return Ok(());
        }
        let mut tags = Vec::new();
        tags.try_reserve_exact(TAG_CHUNK_GRANULES)
            .map_err(|_| TagStoreError::AllocationFailed)?;
        tags.resize_with(TAG_CHUNK_GRANULES, || {
            AtomicU8::new(self.initial_tag.value())
        });
        tags[tag_index].store(tag.value(), Ordering::Relaxed);
        #[cfg(feature = "std")]
        chunks
            .try_reserve(1)
            .map_err(|_| TagStoreError::AllocationFailed)?;
        chunks.insert(chunk_index, tags);
        Ok(())
    }

    fn location(&self, backing_offset: usize) -> Result<(usize, usize), TagStoreError> {
        if !backing_offset.is_multiple_of(TAG_GRANULE_BYTES) {
            return Err(TagStoreError::UnalignedOffset);
        }
        if backing_offset
            .checked_add(TAG_GRANULE_BYTES)
            .is_none_or(|end| end > self.backing_bytes)
        {
            return Err(TagStoreError::OutOfBounds);
        }
        Ok((
            backing_offset / TAG_CHUNK_BYTES,
            (backing_offset % TAG_CHUNK_BYTES) / TAG_GRANULE_BYTES,
        ))
    }
}

#[cfg(test)]
mod tests;
