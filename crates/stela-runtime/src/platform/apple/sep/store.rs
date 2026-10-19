//! Stela-owned durable nonce/firmware-commitment substrate, not Apple's xART
//! on-disk format. `AppleSEPXART::nonce_generate/read/invalidate` (kernel
//! file 0x2d7171c/0x2d717ac/0x2d718cc) requires distinct persistent state from
//! the ROM nonce; `_nonce_action` 0x2d71698 requires a 20-byte destination.
//! Sandcat also exposes slots (0x2d7183c). The slot allocation and full xART
//! wire ABI remain gated: this module is not an advertised endpoint.
//!
//! Records are authenticated with a purpose-separated `keys::Roots::uid`
//! key. The store must protect its committed generation against rollback;
//! an HMAC alone cannot detect replacement by an older valid snapshot.
pub mod persist;

use super::{Entropy, keys::Roots};
use alloc::{collections::BTreeMap, vec::Vec};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"STSEPN01";
const PURPOSE: &[u8] = b"sepos/nonce-store/v1";
const MAC_BYTES: usize = 32;
const HEADER_BYTES: usize = 18;
pub const NONCE_BYTES: usize = 20;
const RECORD_BYTES: usize = 1 + NONCE_BYTES;
const MAX_SLOTS: usize = 256;
const HASH_BYTES: usize = 48;
const MAX_BYTES: usize = HEADER_BYTES + MAX_SLOTS * RECORD_BYTES + 1 + HASH_BYTES + MAC_BYTES;

/// A protected committed head. Generation is separate from the record so
/// loading a valid but stale HMAC record can be detected.
pub struct Head {
    pub generation: u64,
    pub record: Vec<u8>,
}

/// A Stela-owned store outside guest RAM. Implementations must durably and
/// atomically replace the record AND protected generation, compare the expected
/// generation, and never silently recreate a lost store. `None` means genuinely
/// unprovisioned. A commit error may have an uncertain outcome: the caller
/// poisons its live state and requires reopening, never acknowledges success.
pub trait Backend {
    fn load(&mut self) -> Result<Option<Head>, &'static str>;
    fn commit(&mut self, expected: u64, next: Head) -> Result<(), &'static str>;
}

impl Backend for alloc::boxed::Box<dyn Backend> {
    fn load(&mut self) -> Result<Option<Head>, &'static str> {
        (**self).load()
    }
    fn commit(&mut self, expected: u64, next: Head) -> Result<(), &'static str> {
        (**self).commit(expected, next)
    }
}

/// A store that lives as long as the machine: for a boot without a host
/// partition for SEP state. It keeps the full contract within one power
/// cycle and loses everything at power-off, which the boot reports.
#[derive(Default)]
pub struct Volatile {
    head: Option<Head>,
}

impl Backend for Volatile {
    fn load(&mut self) -> Result<Option<Head>, &'static str> {
        Ok(self.head.as_ref().map(|head| Head {
            generation: head.generation,
            record: head.record.clone(),
        }))
    }
    fn commit(&mut self, expected: u64, next: Head) -> Result<(), &'static str> {
        if self.head.as_ref().map_or(0, |head| head.generation) != expected {
            return Err("SEP nonce store generation conflict");
        }
        self.head = Some(next);
        Ok(())
    }
}

#[derive(Clone)]
struct State {
    generation: u64,
    slots: BTreeMap<u8, [u8; NONCE_BYTES]>,
    firmware: Option<[u8; HASH_BYTES]>,
}

pub struct Nonces<B: Backend> {
    backend: B,
    key: Zeroizing<[u8; MAC_BYTES]>,
    state: Option<State>,
}

impl<B: Backend> Nonces<B> {
    /// Explicit first provisioning only. Reopening an existing machine uses
    /// `open`, which refuses loss/corruption rather than resetting its nonces.
    pub fn provision(roots: &Roots, mut backend: B) -> Result<Self, &'static str> {
        if backend.load()?.is_some() {
            return Err("SEP nonce store is already provisioned");
        }
        let key = roots.uid(PURPOSE)?;
        let state = State {
            generation: 1,
            slots: BTreeMap::new(),
            firmware: None,
        };
        let record = encode(&state, &key);
        backend.commit(
            0,
            Head {
                generation: 1,
                record,
            },
        )?;
        Ok(Self {
            backend,
            key,
            state: Some(state),
        })
    }

    pub fn open(roots: &Roots, mut backend: B) -> Result<Self, &'static str> {
        let key = roots.uid(PURPOSE)?;
        let head = backend
            .load()?
            .ok_or("SEP nonce store is missing; explicit provisioning required")?;
        let state = decode(head, &key)?;
        Ok(Self {
            backend,
            key,
            state: Some(state),
        })
    }

    fn state(&self) -> Result<&State, &'static str> {
        self.state
            .as_ref()
            .ok_or("SEP nonce store commit outcome is uncertain; reopen required")
    }

    fn update(&mut self, mut next: State) -> Result<(), &'static str> {
        let expected = self.state()?.generation;
        next.generation = expected
            .checked_add(1)
            .ok_or("SEP nonce store generation exhausted")?;
        let record = encode(&next, &self.key);
        // Poison before entering a backend whose error may mean that the
        // write reached durable storage but its acknowledgement was lost.
        self.state = None;
        self.backend.commit(
            expected,
            Head {
                generation: next.generation,
                record,
            },
        )?;
        self.state = Some(next);
        Ok(())
    }

    pub fn read(&self, slot: u8) -> Result<[u8; NONCE_BYTES], &'static str> {
        self.state()?
            .slots
            .get(&slot)
            .copied()
            .ok_or("SEP nonce slot is not generated or was invalidated")
    }

    /// The service, once recovered, owns slot selection. No Apple slot count
    /// or allocation rule is inferred here. Entropy/commit failures yield no
    /// nonce reply; the previous state survives an entropy failure.
    pub fn generate(
        &mut self,
        slot: u8,
        entropy: &mut dyn Entropy,
    ) -> Result<[u8; NONCE_BYTES], &'static str> {
        let mut next = self.state()?.clone();
        let mut nonce = [0; NONCE_BYTES];
        entropy.fill(&mut nonce)?;
        next.slots.insert(slot, nonce);
        self.update(next)?;
        Ok(nonce)
    }

    pub fn invalidate(&mut self, slot: u8) -> Result<(), &'static str> {
        let mut next = self.state()?.clone();
        if next.slots.remove(&slot).is_none() {
            return Err("SEP nonce slot is not generated or was invalidated");
        }
        self.update(next)
    }

    /// A measured, already-authorized manifest commitment. This stores bytes;
    /// it grants no Image4 authentication, signing or rollback authorization.
    pub fn commit_firmware(&mut self, digest: [u8; HASH_BYTES]) -> Result<(), &'static str> {
        let mut next = self.state()?.clone();
        next.firmware = Some(digest);
        self.update(next)
    }

    pub fn firmware(&self) -> Result<Option<[u8; HASH_BYTES]>, &'static str> {
        Ok(self.state()?.firmware)
    }

    /// Erase every nonce and the firmware commitment, as an Erase Install
    /// erases the SEP's anti-replay state; the generation keeps counting.
    pub fn erase(&mut self) -> Result<(), &'static str> {
        self.state()?;
        self.update(State {
            generation: 0,
            slots: BTreeMap::new(),
            firmware: None,
        })
    }

    pub fn into_backend(self) -> B {
        self.backend
    }
}

fn encode(state: &State, key: &[u8; MAC_BYTES]) -> Vec<u8> {
    let mut record = Vec::new();
    record.extend_from_slice(MAGIC);
    record.extend_from_slice(&state.generation.to_be_bytes());
    record.extend_from_slice(&(state.slots.len() as u16).to_be_bytes());
    for (&slot, nonce) in &state.slots {
        record.push(slot);
        record.extend_from_slice(nonce);
    }
    record.push(u8::from(state.firmware.is_some()));
    if let Some(hash) = state.firmware {
        record.extend_from_slice(&hash);
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts 256-bit keys");
    mac.update(&record);
    record.extend_from_slice(&mac.finalize().into_bytes());
    record
}

fn decode(head: Head, key: &[u8; MAC_BYTES]) -> Result<State, &'static str> {
    let bytes = head.record.as_slice();
    if !(HEADER_BYTES + 1 + MAC_BYTES..=MAX_BYTES).contains(&bytes.len()) {
        return Err("SEP nonce store record length is invalid");
    }
    let end = bytes.len() - MAC_BYTES;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts 256-bit keys");
    mac.update(&bytes[..end]);
    mac.verify_slice(&bytes[end..])
        .map_err(|_| "SEP nonce store authentication failed")?;
    if &bytes[..MAGIC.len()] != MAGIC {
        return Err("SEP nonce store format is unsupported");
    }
    let generation = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
    if generation == 0 || generation != head.generation {
        return Err("SEP nonce store generation is stale or invalid");
    }
    let count = usize::from(u16::from_be_bytes(bytes[16..18].try_into().unwrap()));
    if count > MAX_SLOTS || HEADER_BYTES + count * RECORD_BYTES + 1 > end {
        return Err("SEP nonce store slot count is invalid");
    }
    let mut slots = BTreeMap::new();
    let mut previous = None;
    let mut at = HEADER_BYTES;
    for _ in 0..count {
        let slot = bytes[at];
        if previous.is_some_and(|p| p >= slot) {
            return Err("SEP nonce store slots are duplicated or unsorted");
        }
        previous = Some(slot);
        slots.insert(slot, bytes[at + 1..at + RECORD_BYTES].try_into().unwrap());
        at += RECORD_BYTES;
    }
    let firmware = match bytes[at] {
        0 if at + 1 == end => None,
        1 if at + 1 + HASH_BYTES == end => Some(bytes[at + 1..end].try_into().unwrap()),
        _ => return Err("SEP nonce store commitment or trailing data is invalid"),
    };
    Ok(State {
        generation,
        slots,
        firmware,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Default)]
    struct Memory {
        head: Option<Head>,
        fail: bool,
        fail_after: bool,
    }
    impl Backend for Memory {
        fn load(&mut self) -> Result<Option<Head>, &'static str> {
            Ok(self.head.as_ref().map(|h| Head {
                generation: h.generation,
                record: h.record.clone(),
            }))
        }
        fn commit(&mut self, expected: u64, next: Head) -> Result<(), &'static str> {
            if self.head.as_ref().map_or(0, |h| h.generation) != expected {
                return Err("generation conflict");
            }
            if self.fail {
                return Err("write failed");
            }
            self.head = Some(next);
            if self.fail_after {
                return Err("acknowledgement lost");
            }
            Ok(())
        }
    }
    fn roots() -> Roots {
        Roots::provisioned([1; 32], [2; 32]).unwrap()
    }
    fn entropy(bytes: &mut [u8]) -> Result<(), &'static str> {
        bytes.fill(0x5a);
        Ok(())
    }
    #[test]
    fn nonces_and_commitments_survive_reopen_and_invalidation() {
        let mut store = Nonces::provision(&roots(), Memory::default()).unwrap();
        assert!(store.read(0).is_err());
        let nonce = store.generate(7, &mut entropy).unwrap();
        store.commit_firmware([3; 48]).unwrap();
        let mut reopened = Nonces::open(&roots(), store.into_backend()).unwrap();
        assert_eq!(reopened.read(7), Ok(nonce));
        assert_eq!(reopened.firmware(), Ok(Some([3; 48])));
        reopened.invalidate(7).unwrap();
        let reopened = Nonces::open(&roots(), reopened.into_backend()).unwrap();
        assert!(reopened.read(7).is_err());
        assert!(Nonces::provision(&roots(), reopened.into_backend()).is_err());
        assert!(Nonces::open(&roots(), Memory::default()).is_err());
    }
    #[test]
    fn wrong_machine_tampering_and_rollback_refuse_instead_of_reprovisioning() {
        let store = Nonces::provision(&roots(), Memory::default()).unwrap();
        let mut backend = store.into_backend();
        let other = Roots::provisioned([2; 32], [2; 32]).unwrap();
        assert!(
            Nonces::open(
                &other,
                Memory {
                    head: backend.load().unwrap(),
                    ..Memory::default()
                }
            )
            .is_err()
        );
        backend.head.as_mut().unwrap().generation += 1;
        assert!(
            Nonces::open(
                &roots(),
                Memory {
                    head: backend.load().unwrap(),
                    ..Memory::default()
                }
            )
            .is_err()
        );
        backend.head.as_mut().unwrap().record[0] ^= 1;
        assert!(Nonces::open(&roots(), backend).is_err());
    }
    #[test]
    fn entropy_failure_preserves_state_and_uncertain_commits_poison_until_reopen() {
        let mut store = Nonces::provision(&roots(), Memory::default()).unwrap();
        let first = store.generate(1, &mut entropy).unwrap();
        let mut fail = |bytes: &mut [u8]| {
            bytes[0] = 1;
            Err("entropy failed")
        };
        assert!(store.generate(1, &mut fail).is_err());
        assert_eq!(store.read(1), Ok(first));
        store.backend.fail = true;
        assert!(store.invalidate(1).is_err());
        assert!(store.read(1).is_err());
        assert!(store.firmware().is_err());
        let mut backend = store.into_backend();
        backend.fail = false;
        backend.fail_after = true;
        let mut store = Nonces::open(&roots(), backend).unwrap();
        assert_eq!(store.read(1), Ok(first));
        assert!(store.invalidate(1).is_err());
        assert!(store.read(1).is_err());
        let mut backend = store.into_backend();
        backend.fail_after = false;
        assert!(Nonces::open(&roots(), backend).unwrap().read(1).is_err());
    }
}
