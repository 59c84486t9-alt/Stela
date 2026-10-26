//! Wire identities carry no address or authorization. The real task-owned
//! registry must validate type, connection, live generation and device epoch.
use alloc::vec::Vec;
use core::num::{NonZeroU32, NonZeroU64};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Exhausted;

/// Generation exhaustion retires a registry slot; never wrap into an old ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Generation(NonZeroU32);
impl Generation {
    pub const FIRST: Self = Self(NonZeroU32::MIN);
    pub const fn next(self) -> Result<Self, Exhausted> {
        match self.0.get().checked_add(1) {
            Some(value) => Ok(Self(NonZeroU32::new(value).unwrap())),
            None => Err(Exhausted),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectHandle {
    slot: u32,
    generation: Generation,
}
impl ObjectHandle {
    pub const fn new(slot: u32, generation: Generation) -> Self {
        Self { slot, generation }
    }
    pub const fn encode(self) -> u64 {
        ((self.generation.0.get() as u64) << 32) | self.slot as u64
    }
    pub const fn decode(value: u64) -> Option<Self> {
        match NonZeroU32::new((value >> 32) as u32) {
            Some(generation) => Some(Self::new(value as u32, Generation(generation))),
            None => None,
        }
    }
    pub const fn slot(self) -> u32 {
        self.slot
    }
    pub const fn generation(self) -> Generation {
        self.generation
    }
}

/// Device reset/removal changes the actual owner's epoch. Parsing an epoch
/// never proves reset or invalidation; the registered backend supplies it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceEpoch(NonZeroU64);
impl DeviceEpoch {
    pub const fn from_registered(value: NonZeroU64) -> Self {
        Self(value)
    }
    pub const fn get(self) -> u64 {
        self.0.get()
    }
    pub const fn next(self) -> Result<Self, Exhausted> {
        match self.0.get().checked_add(1) {
            Some(value) => Ok(Self(NonZeroU64::new(value).unwrap())),
            None => Err(Exhausted),
        }
    }
}

/// A connection's serialized request sequence. Timeout/retry requires an
/// explicit dispatcher policy; this never reissues a consumed ID.
pub struct RequestSequence {
    next: Option<NonZeroU64>,
}
impl Default for RequestSequence {
    fn default() -> Self {
        Self {
            next: Some(NonZeroU64::MIN),
        }
    }
}
impl RequestSequence {
    pub fn take(&mut self) -> Result<NonZeroU64, Exhausted> {
        let value = self.next.ok_or(Exhausted)?;
        self.next = value.get().checked_add(1).and_then(NonZeroU64::new);
        Ok(value)
    }
}

/// A failed table operation establishes no resource, task or device authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TableError {
    WrongConnection,
    WrongEpoch,
    Closed,
    StaleHandle,
    Full,
    OutOfMemory,
}

/// Insertion failure returns the original owner, including on allocation failure.
#[derive(Debug)]
pub struct InsertError<T> {
    pub error: TableError,
    pub value: T,
}

struct Slot<T> {
    // None permanently retires this slot after its final generation is removed.
    generation: Option<Generation>,
    value: Option<T>,
    next_free: Option<u32>,
}

/// Actual ownership of objects published by one connection and device epoch.
///
/// The authenticated dispatcher must keep exactly one table for its registered
/// connection/epoch, with all resource kinds in `T` (normally a typed enum).
/// It must validate that kind and each operation's access permissions before
/// using an object. Numeric scope checks here are not task authentication,
/// runtime device admission, or proof of GPU completion. Do not recreate a
/// table with the same scope while any old handle can reach that dispatcher.
///
/// Removal transfers ownership; it does not retire DMA, submitted commands or
/// memory mappings. `T` must itself retain those owners until real retirement,
/// including if a table or returned owner is dropped. Closing a table refuses
/// every wire access while retaining its objects for the backend's cleanup.
/// Mutable access serializes table changes; no internal lock or callback runs.
pub struct ObjectTable<T> {
    connection: NonZeroU64,
    epoch: DeviceEpoch,
    max_slots: NonZeroU32,
    slots: Vec<Slot<T>>,
    free: Option<u32>,
    live: usize,
    closed: bool,
}

impl<T> ObjectTable<T> {
    /// Creates empty ownership storage without allocating or admitting a GPU.
    /// The registered dispatcher supplies the scope and a bounded slot ceiling.
    pub fn new(connection: NonZeroU64, epoch: DeviceEpoch, max_slots: NonZeroU32) -> Self {
        Self {
            connection,
            epoch,
            max_slots,
            slots: Vec::new(),
            free: None,
            live: 0,
            closed: false,
        }
    }

    pub fn len(&self) -> usize {
        self.live
    }

    pub fn is_empty(&self) -> bool {
        self.live == 0
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    fn check_scope(&self, connection: NonZeroU64, epoch: DeviceEpoch) -> Result<(), TableError> {
        if connection != self.connection {
            Err(TableError::WrongConnection)
        } else if epoch != self.epoch {
            Err(TableError::WrongEpoch)
        } else if self.closed {
            Err(TableError::Closed)
        } else {
            Ok(())
        }
    }

    pub fn insert(
        &mut self,
        connection: NonZeroU64,
        epoch: DeviceEpoch,
        value: T,
    ) -> Result<ObjectHandle, InsertError<T>> {
        self.insert_with(connection, epoch, value, |slots| {
            slots.try_reserve(1).map_err(|_| TableError::OutOfMemory)
        })
    }

    fn insert_with(
        &mut self,
        connection: NonZeroU64,
        epoch: DeviceEpoch,
        value: T,
        reserve: impl FnOnce(&mut Vec<Slot<T>>) -> Result<(), TableError>,
    ) -> Result<ObjectHandle, InsertError<T>> {
        if let Err(error) = self.check_scope(connection, epoch) {
            return Err(InsertError { error, value });
        }
        let (index, generation) = if let Some(index) = self.free {
            let slot = &mut self.slots[index as usize];
            // Only removal links a vacant, nonexhausted slot into this list.
            let generation = slot.generation.unwrap();
            self.free = slot.next_free.take();
            slot.value = Some(value);
            (index, generation)
        } else {
            if self.slots.len() >= self.max_slots.get() as usize {
                return Err(InsertError {
                    error: TableError::Full,
                    value,
                });
            }
            if let Err(error) = reserve(&mut self.slots) {
                return Err(InsertError { error, value });
            }
            let index = self.slots.len() as u32;
            self.slots.push(Slot {
                generation: Some(Generation::FIRST),
                value: Some(value),
                next_free: None,
            });
            (index, Generation::FIRST)
        };
        self.live += 1;
        Ok(ObjectHandle::new(index, generation))
    }

    pub fn get(
        &self,
        connection: NonZeroU64,
        epoch: DeviceEpoch,
        handle: ObjectHandle,
    ) -> Result<&T, TableError> {
        self.check_scope(connection, epoch)?;
        let slot = self
            .slots
            .get(handle.slot() as usize)
            .filter(|slot| slot.generation == Some(handle.generation()))
            .ok_or(TableError::StaleHandle)?;
        slot.value.as_ref().ok_or(TableError::StaleHandle)
    }

    pub fn get_mut(
        &mut self,
        connection: NonZeroU64,
        epoch: DeviceEpoch,
        handle: ObjectHandle,
    ) -> Result<&mut T, TableError> {
        self.check_scope(connection, epoch)?;
        let slot = self
            .slots
            .get_mut(handle.slot() as usize)
            .filter(|slot| slot.generation == Some(handle.generation()))
            .ok_or(TableError::StaleHandle)?;
        slot.value.as_mut().ok_or(TableError::StaleHandle)
    }

    /// Unpublishes the exact live generation before transferring its owner.
    /// Exhaustion permanently retires the slot instead of aliasing an old ID.
    pub fn remove(
        &mut self,
        connection: NonZeroU64,
        epoch: DeviceEpoch,
        handle: ObjectHandle,
    ) -> Result<T, TableError> {
        self.check_scope(connection, epoch)?;
        let slot = self
            .slots
            .get_mut(handle.slot() as usize)
            .filter(|slot| slot.generation == Some(handle.generation()))
            .ok_or(TableError::StaleHandle)?;
        let value = slot.value.take().ok_or(TableError::StaleHandle)?;
        match handle.generation().next() {
            Ok(next) => {
                slot.generation = Some(next);
                slot.next_free = self.free;
                self.free = Some(handle.slot());
            }
            Err(Exhausted) => slot.generation = None,
        }
        self.live -= 1;
        Ok(value)
    }

    /// Fail closed after actual disconnect/reset/removal without releasing any
    /// object. This changes no physical device state and is irreversible.
    pub fn close(&mut self) {
        self.closed = true;
    }

    /// Consumes publication storage, transferring each remaining actual owner.
    /// The caller still owes each backend's real retirement/cleanup protocol.
    pub fn into_objects(self) -> impl Iterator<Item = T> {
        self.slots.into_iter().filter_map(|slot| slot.value)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::{cell::Cell, rc::Rc};

    fn scope() -> (NonZeroU64, DeviceEpoch) {
        (
            NonZeroU64::new(7).unwrap(),
            DeviceEpoch::from_registered(NonZeroU64::new(11).unwrap()),
        )
    }

    fn table<T>(max_slots: u32) -> ObjectTable<T> {
        let (connection, epoch) = scope();
        ObjectTable::new(connection, epoch, NonZeroU32::new(max_slots).unwrap())
    }

    struct Owner(Rc<Cell<usize>>);
    impl Drop for Owner {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    #[test]
    fn independent_handle_words_and_exhaustion_never_alias() {
        let generation = Generation(NonZeroU32::new(0x1122_3344).unwrap());
        let id = ObjectHandle::new(0xaabb_ccdd, generation);
        assert_eq!(id.encode(), 0x1122_3344_aabb_ccdd);
        assert_eq!(ObjectHandle::decode(0x1122_3344_aabb_ccdd), Some(id));
        assert_eq!(ObjectHandle::decode(0), None);
        assert_eq!(ObjectHandle::decode(u64::from(u32::MAX)), None);
        assert_ne!(id, ObjectHandle::new(id.slot(), generation.next().unwrap()));
        assert_eq!(Generation(NonZeroU32::MAX).next(), Err(Exhausted));
        assert_eq!(
            DeviceEpoch::from_registered(NonZeroU64::MAX).next(),
            Err(Exhausted)
        );
    }
    #[test]
    fn final_request_is_issued_once() {
        let mut normal = RequestSequence::default();
        assert_eq!(normal.take().unwrap().get(), 1);
        assert_eq!(normal.take().unwrap().get(), 2);
        let mut end = RequestSequence {
            next: Some(NonZeroU64::MAX),
        };
        assert_eq!(end.take(), Ok(NonZeroU64::MAX));
        assert_eq!(end.take(), Err(Exhausted));
        assert_eq!(end.take(), Err(Exhausted));
    }

    #[test]
    fn real_owners_survive_close_and_transfer_only_once() {
        let (connection, epoch) = scope();
        let drops = Rc::new(Cell::new(0));
        let mut table = table(2);
        let first = table
            .insert(connection, epoch, Owner(drops.clone()))
            .ok()
            .unwrap();
        table
            .insert(connection, epoch, Owner(drops.clone()))
            .ok()
            .unwrap();
        assert_eq!(table.len(), 2);
        let owner = table.remove(connection, epoch, first).unwrap();
        assert_eq!(drops.get(), 0);
        assert_eq!(table.len(), 1);
        assert!(matches!(
            table.remove(connection, epoch, first),
            Err(TableError::StaleHandle)
        ));
        table.close();
        table.close();
        assert!(table.is_closed());
        assert_eq!(drops.get(), 0);
        drop(owner);
        assert_eq!(drops.get(), 1);
        let mut remaining = table.into_objects();
        let last = remaining.next().unwrap();
        assert!(remaining.next().is_none());
        assert_eq!(drops.get(), 1);
        drop(last);
        assert_eq!(drops.get(), 2);
    }

    #[test]
    fn wire_access_checks_scope_before_any_object_mutation() {
        let (connection, epoch) = scope();
        let wrong_connection = NonZeroU64::new(connection.get() + 1).unwrap();
        let wrong_epoch = epoch.next().unwrap();
        let mut table = table(2);
        let handle = table.insert(connection, epoch, 42).unwrap();
        for (caller, device, error) in [
            (wrong_connection, epoch, TableError::WrongConnection),
            (connection, wrong_epoch, TableError::WrongEpoch),
        ] {
            assert_eq!(table.get(caller, device, handle), Err(error));
            assert_eq!(table.get_mut(caller, device, handle), Err(error));
            assert_eq!(table.remove(caller, device, handle), Err(error));
            let failed = table.insert(caller, device, 99).unwrap_err();
            assert_eq!(failed.error, error);
            assert_eq!(failed.value, 99);
            assert_eq!(table.len(), 1);
            assert_eq!(table.get(connection, epoch, handle), Ok(&42));
        }
        table.close();
        assert_eq!(
            table.get(connection, epoch, handle),
            Err(TableError::Closed)
        );
        assert_eq!(
            table.get_mut(connection, epoch, handle),
            Err(TableError::Closed)
        );
        assert_eq!(
            table.remove(connection, epoch, handle),
            Err(TableError::Closed)
        );
        assert_eq!(
            table.insert(connection, epoch, 99).unwrap_err().error,
            TableError::Closed
        );
        assert_eq!(table.into_objects().collect::<std::vec::Vec<_>>(), [42]);
    }

    #[test]
    fn reused_slot_cannot_alias_old_wire_handles() {
        let (connection, epoch) = scope();
        let mut table = table(1);
        let old = table.insert(connection, epoch, 13).unwrap();
        assert_eq!(table.remove(connection, epoch, old), Ok(13));
        let new = table.insert(connection, epoch, 29).unwrap();
        assert_eq!(old.slot(), new.slot());
        assert_ne!(old.encode(), new.encode());
        assert_eq!(
            table.get(connection, epoch, old),
            Err(TableError::StaleHandle)
        );
        assert_eq!(
            table.get_mut(connection, epoch, old),
            Err(TableError::StaleHandle)
        );
        assert_eq!(
            table.remove(connection, epoch, old),
            Err(TableError::StaleHandle)
        );
        let forged = ObjectHandle::new(u32::MAX, new.generation());
        assert_eq!(
            table.get(connection, epoch, forged),
            Err(TableError::StaleHandle)
        );
        assert_eq!(table.get(connection, epoch, new), Ok(&29));
        *table.get_mut(connection, epoch, new).unwrap() = 31;
        assert_eq!(table.remove(connection, epoch, new), Ok(31));
        assert!(table.is_empty());
    }

    #[test]
    fn generation_exhaustion_retires_capacity_without_wraparound() {
        let (connection, epoch) = scope();
        let mut table = table(2);
        let initial = table.insert(connection, epoch, 13).unwrap();
        // Seed the final representable generation; reaching it by billions of
        // public insert/remove operations would exercise the identical branch.
        let final_generation = Generation(NonZeroU32::MAX);
        table.slots[initial.slot() as usize].generation = Some(final_generation);
        let last = ObjectHandle::new(initial.slot(), final_generation);
        assert_eq!(table.remove(connection, epoch, last), Ok(13));
        assert_eq!(
            table.get(connection, epoch, initial),
            Err(TableError::StaleHandle)
        );
        assert_eq!(
            table.get(connection, epoch, last),
            Err(TableError::StaleHandle)
        );
        let next = table.insert(connection, epoch, 29).unwrap();
        assert_ne!(next.slot(), last.slot());
        assert_eq!(next.generation(), Generation::FIRST);
        let full = table.insert(connection, epoch, 31).unwrap_err();
        assert_eq!(full.error, TableError::Full);
        assert_eq!(full.value, 31);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn growth_failure_returns_ownership_and_preserves_existing_publication() {
        let (connection, epoch) = scope();
        let drops = Rc::new(Cell::new(0));
        let mut table = table(2);
        let old = table
            .insert(connection, epoch, Owner(drops.clone()))
            .ok()
            .unwrap();
        let attempted_reservations = Cell::new(0);
        let failed = match table.insert_with(connection, epoch, Owner(drops.clone()), |_| {
            attempted_reservations.set(attempted_reservations.get() + 1);
            Err(TableError::OutOfMemory)
        }) {
            Err(failed) => failed,
            Ok(_) => panic!("injected allocation failure published a resource"),
        };
        assert_eq!(attempted_reservations.get(), 1);
        assert_eq!(failed.error, TableError::OutOfMemory);
        assert_eq!(drops.get(), 0);
        assert_eq!(table.len(), 1);
        assert!(table.get(connection, epoch, old).is_ok());
        drop(failed.value);
        assert_eq!(drops.get(), 1);
        drop(table);
        assert_eq!(drops.get(), 2);
    }

    #[test]
    fn free_slot_reuse_needs_no_allocation_and_respects_the_slot_ceiling() {
        let (connection, epoch) = scope();
        let mut table = table(3);
        let first = table.insert(connection, epoch, 10).unwrap();
        let second = table.insert(connection, epoch, 20).unwrap();
        let third = table.insert(connection, epoch, 30).unwrap();
        let full = table
            .insert_with(connection, epoch, 40, |_| {
                panic!("a full bounded table attempted to grow")
            })
            .unwrap_err();
        assert_eq!(full.error, TableError::Full);
        assert_eq!(full.value, 40);
        assert_eq!(table.remove(connection, epoch, first), Ok(10));
        assert_eq!(table.remove(connection, epoch, third), Ok(30));
        for expected_slot in [third.slot(), first.slot()] {
            let new = table
                .insert_with(connection, epoch, 40, |_| {
                    panic!("free-slot reuse attempted an allocation")
                })
                .unwrap();
            assert_eq!(new.slot(), expected_slot);
        }
        assert_eq!(table.len(), 3);
        assert_eq!(table.get(connection, epoch, second), Ok(&20));
        assert_eq!(
            table.get(connection, epoch, first),
            Err(TableError::StaleHandle)
        );
        assert_eq!(
            table.get(connection, epoch, third),
            Err(TableError::StaleHandle)
        );
    }
}
