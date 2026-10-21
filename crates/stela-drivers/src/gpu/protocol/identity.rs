//! Wire identities carry no address or authorization. The real task-owned
//! registry must validate type, connection, live generation and device epoch.
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

#[cfg(test)]
mod tests {
    use super::*;
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
}
