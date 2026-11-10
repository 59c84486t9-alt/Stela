//! What the compiler keeps of its work for a device's boot: reflections by
//! module digest, entry and function constant values, and compiled NIR by
//! the digest of everything a compilation reads ([`NirCache`]). Both are
//! keyed by content, so processes that load the same library share them.
//!
//! A compilation the cache holds is lent to the device, which releases it
//! once its pipeline is created: Mesa's runtime clones the NIR it is given,
//! so one shader serves every pipeline made from it. An evicted shader is
//! released once the last lender returns it.
use super::{Provenance, Reflection};
use crate::metal::{shader::CompiledShader, vulkan::object::ShaderCode};
use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};

/// The most reflections kept; past it, the oldest go.
const REFLECTIONS: usize = 4096;

/// A reflection's input: the module's digest, the entry, and the function
/// constant values, none for the function as declared.
pub(super) type ReflectionKey = ([u8; 32], String, Option<Vec<(u32, Vec<u8>)>>);

/// Reflections by [`ReflectionKey`], oldest first out.
#[derive(Default)]
pub(super) struct ReflectionCache {
    entries: BTreeMap<ReflectionKey, (u64, Reflection, Provenance)>,
    order: BTreeMap<u64, ReflectionKey>,
    next: u64,
}

impl ReflectionCache {
    pub(super) fn get(&self, key: &ReflectionKey) -> Option<(Reflection, Provenance)> {
        self.entries
            .get(key)
            .map(|(_, reflection, provenance)| (reflection.clone(), provenance.clone()))
    }

    pub(super) fn insert(
        &mut self,
        key: ReflectionKey,
        reflection: Reflection,
        provenance: Provenance,
    ) {
        if self.entries.contains_key(&key) {
            return;
        }
        while self.entries.len() >= REFLECTIONS {
            let Some((_, oldest)) = self.order.pop_first() else {
                break;
            };
            self.entries.remove(&oldest);
        }
        let stamp = self.next;
        self.next += 1;
        self.order.insert(stamp, key.clone());
        self.entries.insert(key, (stamp, reflection, provenance));
    }

    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }
}

/// A shader the cache holds, lent to `lent` callers now.
struct Held {
    shader: CompiledShader,
    bytes: usize,
    lent: u32,
    /// Lent or adopted this call: kept until [`NirCache::unpin`].
    pinned: bool,
    used: u64,
}

/// Compiled NIR by key, within a byte budget.
pub(super) struct NirCache {
    budget: usize,
    bytes: usize,
    held: BTreeMap<[u8; 32], Held>,
    /// The key of each held shader, by its code.
    codes: BTreeMap<u64, [u8; 32]>,
    /// Evicted shaders still lent, by code: count of lenders.
    evicted: BTreeMap<u64, u32>,
    /// Evicted shaders no one holds, for the owner to release.
    doomed: Vec<ShaderCode>,
    clock: u64,
    pub(super) hits: u64,
    pub(super) misses: u64,
    pub(super) evictions: u64,
}

/// What [`NirCache::release`] leaves to the caller.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum Returned {
    /// The cache still holds it, or a lender still has it.
    Kept,
    /// The caller releases it to the service.
    Release,
}

impl NirCache {
    pub(super) fn new(budget: usize) -> Self {
        Self {
            budget,
            bytes: 0,
            held: BTreeMap::new(),
            codes: BTreeMap::new(),
            evicted: BTreeMap::new(),
            doomed: Vec::new(),
            clock: 0,
            hits: 0,
            misses: 0,
            evictions: 0,
        }
    }

    /// The shader of `key`, lent until [`Self::release`] returns it.
    pub(super) fn lend(&mut self, key: &[u8; 32]) -> Option<CompiledShader> {
        self.clock += 1;
        let Some(held) = self.held.get_mut(key) else {
            self.misses += 1;
            return None;
        };
        self.hits += 1;
        held.lent += 1;
        held.pinned = true;
        held.used = self.clock;
        Some(held.shader.clone())
    }

    /// Keeps `shader`, `bytes` of NIR, under `key`; lent once when `lent`.
    /// Shaders over a quarter of the budget are not kept, and an equal key
    /// already held keeps its own: `shader` is then the caller's to release
    /// (`Returned::Release`) unless lent.
    pub(super) fn insert(
        &mut self,
        key: [u8; 32],
        shader: CompiledShader,
        bytes: usize,
        lent: bool,
    ) -> Returned {
        if self.held.contains_key(&key) || bytes > self.budget / 4 {
            return Returned::Release;
        }
        self.evict(bytes);
        self.clock += 1;
        self.bytes += bytes;
        self.codes.insert(shader.code.0, key);
        self.held.insert(
            key,
            Held {
                shader,
                bytes,
                lent: u32::from(lent),
                pinned: true,
                used: self.clock,
            },
        );
        Returned::Kept
    }

    /// Makes room for `bytes`, oldest unpinned first; what is still lent
    /// waits for its lenders.
    fn evict(&mut self, bytes: usize) {
        while self.bytes + bytes > self.budget {
            let Some((&key, _)) = self
                .held
                .iter()
                .filter(|(_, held)| !held.pinned)
                .min_by_key(|(_, held)| held.used)
            else {
                break;
            };
            let held = self.held.remove(&key).expect("the oldest is held");
            self.codes.remove(&held.shader.code.0);
            self.bytes -= held.bytes;
            self.evictions += 1;
            if held.lent == 0 {
                self.doomed.push(held.shader.code);
            } else {
                self.evicted.insert(held.shader.code.0, held.lent);
            }
        }
    }

    /// Returns a lent `code`, or one the cache never held.
    pub(super) fn release(&mut self, code: ShaderCode) -> Returned {
        if let Some(key) = self.codes.get(&code.0) {
            let held = self.held.get_mut(key).expect("a held code's shader");
            held.lent = held.lent.saturating_sub(1);
            return Returned::Kept;
        }
        match self.evicted.get_mut(&code.0) {
            Some(lent) if *lent > 1 => {
                *lent -= 1;
                Returned::Kept
            }
            Some(_) => {
                self.evicted.remove(&code.0);
                Returned::Release
            }
            None => Returned::Release,
        }
    }

    /// Ends a call: what it lent or adopted may be evicted again.
    pub(super) fn unpin(&mut self) {
        self.held.values_mut().for_each(|held| held.pinned = false);
    }

    /// Shaders evicted with no lender, for the caller to release.
    pub(super) fn take_doomed(&mut self) -> Vec<ShaderCode> {
        core::mem::take(&mut self.doomed)
    }

    pub(super) fn entries(&self) -> usize {
        self.held.len()
    }

    pub(super) fn bytes(&self) -> usize {
        self.bytes
    }
}

/// Serializes the compiler's AIR to NIR, under the service's lock or outside
/// it: LLVM's bitcode reader and the AIR frontend run one compilation at a
/// time, while the service's other calls go on.
pub struct CompileLock {
    held: AtomicBool,
    /// A compilation deferred in the call served now: its later writes to
    /// the caller are dropped, as the call runs again.
    deferred: AtomicBool,
}

impl CompileLock {
    pub(super) const fn new() -> Self {
        Self {
            held: AtomicBool::new(false),
            deferred: AtomicBool::new(false),
        }
    }

    /// Holds the lock, running `relax` while another holds it.
    pub fn hold(&self, relax: fn()) -> CompileGuard<'_> {
        while self
            .held
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            relax();
        }
        CompileGuard(self)
    }

    /// Whether the call served now deferred a compilation.
    pub fn deferred(&self) -> bool {
        self.deferred.load(Ordering::Acquire)
    }

    pub(super) fn set_deferred(&self, deferred: bool) {
        self.deferred.store(deferred, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) const fn new_for_tests() -> Self {
        Self::new()
    }

    #[cfg(test)]
    pub(crate) fn set_deferred_for_tests(&self, deferred: bool) {
        self.set_deferred(deferred);
    }
}

/// The compile lock, held.
pub struct CompileGuard<'a>(&'a CompileLock);

impl Drop for CompileGuard<'_> {
    fn drop(&mut self) {
        self.0.held.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metal::shader::{Stage, tests::interface};

    fn shader(code: u64) -> CompiledShader {
        CompiledShader {
            code: ShaderCode(code),
            interface: interface(Stage::Kernel),
            provenance: Provenance::default(),
        }
    }

    #[test]
    fn a_held_shader_is_lent_and_never_released_while_held() {
        let mut cache = NirCache::new(1000);
        assert_eq!(cache.lend(&[1; 32]), None);
        assert_eq!(
            cache.insert([1; 32], shader(0x10), 100, true),
            Returned::Kept
        );
        assert_eq!(cache.release(ShaderCode(0x10)), Returned::Kept);
        assert_eq!(
            cache.lend(&[1; 32]).map(|lent| lent.code),
            Some(ShaderCode(0x10))
        );
        assert_eq!(cache.release(ShaderCode(0x10)), Returned::Kept);
        // A code it never held is the caller's.
        assert_eq!(cache.release(ShaderCode(0x20)), Returned::Release);
        assert_eq!((cache.hits, cache.misses), (1, 1));
    }

    #[test]
    fn eviction_waits_for_lenders_and_for_the_call_that_lent() {
        let mut cache = NirCache::new(400);
        cache.insert([1; 32], shader(0x10), 100, true);
        cache.unpin();
        // Pinned by this call: not evicted, though over budget.
        cache.insert([2; 32], shader(0x20), 100, false);
        cache.insert([3; 32], shader(0x30), 100, false);
        cache.insert([4; 32], shader(0x40), 100, false);
        assert_eq!(cache.entries(), 4);
        cache.unpin();
        // The oldest, still lent, leaves the cache but not its lender.
        cache.insert([5; 32], shader(0x50), 100, false);
        assert_eq!(cache.entries(), 4);
        assert!(cache.take_doomed().is_empty());
        assert_eq!(cache.lend(&[1; 32]), None);
        assert_eq!(cache.release(ShaderCode(0x10)), Returned::Release);
        // The next eviction, of a shader no one holds, frees it.
        cache.unpin();
        cache.insert([6; 32], shader(0x60), 100, false);
        assert_eq!(cache.take_doomed(), [ShaderCode(0x20)]);
        assert_eq!(cache.bytes(), 400);
    }

    #[test]
    fn a_shader_past_a_quarter_of_the_budget_is_not_kept() {
        let mut cache = NirCache::new(400);
        assert_eq!(
            cache.insert([1; 32], shader(0x10), 101, true),
            Returned::Release
        );
        assert_eq!(cache.entries(), 0);
    }

    #[test]
    fn reflections_keep_the_newest_within_their_bound() {
        let mut cache = ReflectionCache::default();
        let key = |index: u32| {
            (
                [0; 32],
                String::from("f"),
                Some(alloc::vec![(index, Vec::new())]),
            )
        };
        let reflection = Reflection::Visible {
            constants: Vec::new(),
            command_barriers: false,
        };
        for index in 0..REFLECTIONS as u32 + 1 {
            cache.insert(key(index), reflection.clone(), Provenance::default());
        }
        assert_eq!(cache.len(), REFLECTIONS);
        assert!(cache.get(&key(0)).is_none());
        assert!(cache.get(&key(REFLECTIONS as u32)).is_some());
    }
}
