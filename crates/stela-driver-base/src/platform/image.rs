//! Immutable native image data, supplied by a platform owner.
//!
//! This boundary classifies addresses only. It reads no caller pointer, maps
//! nothing and grants no allocation/free or arbitrary-memory access. There is
//! no range-vector, predicate, PE-flags or default provider constructor.

/// The immutable data of a native executable image.
///
/// # Safety
/// Every address classified true is inside immutable native image DATA backed
/// by owned RAM. The image's relocation/initialization is finished; no
/// later patcher, writable alias, DMA/guest owner or allocator may mutate or
/// recycle that backing. Every native execution root that can use a borrower
/// keeps read-only mappings. The provider keeps the image,
/// backing and root/table ownership for its entire lifetime, including source
/// shutdown, errors and uncertain retirement. Image metadata alone, caller
/// ranges and a current-root observation establish none of that permission.
///
/// Classification is infallible and does not dereference `address`, allocate,
/// block, inspect IRQ-local mutable state or change hardware. It returns true
/// only for data covered by the immutable-image permission. Code,
/// mutable statics, heap/stack/DMA RAM and unknown pages are not such data.
///
/// Consumers keep this capability through every object that borrows an
/// image pointer. If they cannot prove all borrowers retired, they permanently
/// keep/quarantine the registration and capability. A missing registration
/// must refuse the dependent lifecycle (or trap a violated admission contract);
/// it must never become `false` in a free-or-borrow query that could free a
/// literal. No safe caller can turn an arbitrary predicate into this contract.
pub unsafe trait NativeReadOnlyImage: Send + Sync {
    fn contains(&self, address: usize) -> bool;
}
