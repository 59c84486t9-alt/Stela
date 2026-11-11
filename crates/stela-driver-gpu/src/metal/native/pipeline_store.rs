//! Compiled pipelines kept across boots: the pipeline store.
//!
//! The boot reads the store's file before the device opens and hands its
//! bytes here ([`provide`]). The first backend to open claims it and, when
//! the key matches, seeds the pipeline cache its compiled pipelines read and
//! fill; its snapshots of that cache replace the kept bytes, and at a
//! quiescent point the boot takes the newest ([`take`]) and writes it over
//! the file.
//!
//! A store is a header, the driver's `vkGetPipelineCacheData` bytes, then
//! the AIR compiler's NIR by the digest of what each compilation read
//! ([`NirEntries`]), which a warm boot deserializes instead of lowering AIR
//! again; the header gives the NIR's length and digest after the cache's,
//! zero for none. The
//! header names a [`Key`]: the build identity of the compiler that turns NIR
//! into machine code, and the GPU's vendor, device, driver and pipeline cache
//! UUID. NVK's pipeline cache UUID is the same for every Stela build
//! (`compat/mesa/build_id.c`), so only the build identity tells builds
//! apart. Inside the cache NVK keys each shader by a digest of its
//! serialized NIR, the pipeline state and the layout, so a function's AIR,
//! constants, formats and linked functions select their own entries. A store
//! of another key, a damaged one or one past the bound is reported once and
//! ignored: its pipelines compile again.
use crate::metal::vulkan::physical::Identity;
use alloc::{sync::Arc, vec::Vec};
use ash::vk;
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};
use stela_crypto::{Sha256, digest::Digest};

/// A store's first bytes.
pub const MAGIC: [u8; 8] = *b"STLGPIPE";
/// The header layout this build reads and writes.
pub const VERSION: u32 = 1;
/// The header: magic, version, a zero word, the key, the payload's length
/// and its SHA-256, then the NIR's length and its SHA-256, zeros for none.
pub const HEADER_BYTES: usize = 128;
const KEY_AT: usize = 16;
const LENGTH_AT: usize = 48;
const CHECKSUM_AT: usize = 56;
const NIR_LENGTH_AT: usize = 88;
const NIR_CHECKSUM_AT: usize = 96;
/// The most bytes of NIR a store keeps.
pub const MAX_NIR_BYTES: u64 = 96 << 20;
/// The largest store kept, header included, whatever the file allows: the
/// boot holds its bytes and the driver a cache of them for the whole boot.
pub const MAX_BYTES: u64 = 256 << 20;
/// A backend snapshots its cache after this many pipelines it did not find
/// there, and when the device goes idle with any.
pub const SNAPSHOT_COMPILES: u32 = 16;

/// What a store's pipelines are valid for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Key(pub [u8; 32]);

impl Key {
    /// The key of pipelines the compiler of build identity `compiler`
    /// builds for `gpu`.
    pub fn new(compiler: &[u8], gpu: &Identity) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(MAGIC);
        hasher.update(VERSION.to_le_bytes());
        hasher.update((compiler.len() as u64).to_le_bytes());
        hasher.update(compiler);
        hasher.update(gpu.vendor_id.to_le_bytes());
        hasher.update(gpu.device_id.to_le_bytes());
        hasher.update(gpu.driver_id.raw().to_le_bytes());
        hasher.update(gpu.driver_version.to_le_bytes());
        hasher.update(gpu.pipeline_cache_uuid);
        Self(hasher.finalize().into())
    }
}

/// Why a store's bytes seed nothing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rejection {
    /// A blank file: nothing was kept yet.
    Blank,
    /// Not a store, or one of another header version.
    Format,
    /// Another compiler build's or GPU's pipelines.
    Stale,
    /// A payload longer than the file or the bound.
    Length,
    /// A payload whose checksum does not match.
    Damaged,
}

impl Rejection {
    fn describe(self) -> &'static str {
        match self {
            Self::Blank => "it is blank",
            Self::Format => "it is not a pipeline store of this version",
            Self::Stale => "it holds another compiler build's or GPU's pipelines",
            Self::Length => "its length is past the file or the bound",
            Self::Damaged => "its checksum does not match",
        }
    }
}

fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes"))
}

/// The bytes a store whose file begins with `header` takes, header
/// included, for a reader that has only its first [`HEADER_BYTES`].
pub fn stored_bytes(header: &[u8]) -> Result<u64, Rejection> {
    let head = &header[..header.len().min(HEADER_BYTES)];
    if head.iter().all(|&byte| byte == 0) {
        return Err(Rejection::Blank);
    }
    let header = header.get(..HEADER_BYTES).ok_or(Rejection::Format)?;
    if header[..8] != MAGIC || word(header, 8) != VERSION {
        return Err(Rejection::Format);
    }
    let length = u64::from_le_bytes(header[LENGTH_AT..CHECKSUM_AT].try_into().expect("a length"));
    let nir = nir_length(header);
    length
        .checked_add(nir)
        .and_then(|length| length.checked_add(HEADER_BYTES as u64))
        .filter(|&bytes| bytes <= MAX_BYTES)
        .ok_or(Rejection::Length)
}

fn nir_length(header: &[u8]) -> u64 {
    u64::from_le_bytes(
        header[NIR_LENGTH_AT..NIR_CHECKSUM_AT]
            .try_into()
            .expect("a length"),
    )
}

/// The header of a store of `payload` for `key`.
pub fn header(key: &Key, payload: &[u8]) -> [u8; HEADER_BYTES] {
    header_with_nir(key, payload, &[])
}

/// The header of a store of `payload` and then `nir` for `key`.
pub fn header_with_nir(key: &Key, payload: &[u8], nir: &[u8]) -> [u8; HEADER_BYTES] {
    let mut header = [0; HEADER_BYTES];
    header[..8].copy_from_slice(&MAGIC);
    header[8..12].copy_from_slice(&VERSION.to_le_bytes());
    header[KEY_AT..LENGTH_AT].copy_from_slice(&key.0);
    header[LENGTH_AT..CHECKSUM_AT].copy_from_slice(&(payload.len() as u64).to_le_bytes());
    header[CHECKSUM_AT..CHECKSUM_AT + 32].copy_from_slice(&Sha256::digest(payload));
    if !nir.is_empty() {
        header[NIR_LENGTH_AT..NIR_CHECKSUM_AT].copy_from_slice(&(nir.len() as u64).to_le_bytes());
        header[NIR_CHECKSUM_AT..NIR_CHECKSUM_AT + 32].copy_from_slice(&Sha256::digest(nir));
    }
    header
}

/// The NIR of `stored`, whose payload [`payload`] accepted for `key`
/// within `bound`: empty for none, or for NIR that is damaged, which then
/// compiles again.
pub fn nir_section<'a>(stored: &'a [u8], key: &Key, bound: u64) -> &'a [u8] {
    let Ok(payload) = payload(stored, key, bound) else {
        return &[];
    };
    let start = HEADER_BYTES + payload.len();
    let length = nir_length(stored);
    let Some(nir) = usize::try_from(length)
        .ok()
        .and_then(|length| stored.get(start..start.checked_add(length)?))
    else {
        return &[];
    };
    if Sha256::digest(nir)[..] != stored[NIR_CHECKSUM_AT..NIR_CHECKSUM_AT + 32] {
        return &[];
    }
    nir
}

/// A store's NIR: entries of a 32-byte key, a 32-bit little-endian length
/// and that many bytes of serialized NIR.
pub struct NirEntries<'a>(pub &'a [u8]);

impl<'a> Iterator for NirEntries<'a> {
    type Item = ([u8; 32], &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let key: [u8; 32] = self.0.get(..32)?.try_into().ok()?;
        let length = u32::from_le_bytes(self.0.get(32..36)?.try_into().ok()?) as usize;
        let blob = self.0.get(36..36usize.checked_add(length)?)?;
        self.0 = &self.0[36 + length..];
        Some((key, blob))
    }
}

/// Appends an entry of `key` and `blob` to a store's NIR.
fn push_entry(nir: &mut Vec<u8>, key: &[u8; 32], blob: &[u8]) {
    nir.extend_from_slice(key);
    nir.extend_from_slice(&(blob.len() as u32).to_le_bytes());
    nir.extend_from_slice(blob);
}

/// The payload of `stored`, a store's file or its first bytes, when it holds
/// `key`'s pipelines within `bound` bytes.
pub fn payload<'a>(stored: &'a [u8], key: &Key, bound: u64) -> Result<&'a [u8], Rejection> {
    let bytes = stored_bytes(stored)?;
    if stored[KEY_AT..LENGTH_AT] != key.0 {
        return Err(Rejection::Stale);
    }
    if bytes > bound.min(MAX_BYTES) || bytes > stored.len() as u64 {
        return Err(Rejection::Length);
    }
    // The cache's bytes, which the NIR follows.
    let cache = bytes - nir_length(stored) - HEADER_BYTES as u64;
    let payload = &stored[HEADER_BYTES..HEADER_BYTES + cache as usize];
    if Sha256::digest(payload)[..] != stored[CHECKSUM_AT..CHECKSUM_AT + 32] {
        return Err(Rejection::Damaged);
    }
    Ok(payload)
}

/// When a backend snapshots its cache, and whether the cache still grows.
#[derive(Debug)]
pub struct Policy {
    bound: u64,
    unsaved: u32,
    grows: bool,
}

impl Policy {
    pub fn new(bound: u64) -> Self {
        Self {
            bound: bound.min(MAX_BYTES),
            unsaved: 0,
            grows: true,
        }
    }

    /// Whether compiled pipelines are added to the cache. Once a snapshot
    /// passes the bound they are only looked up there.
    pub fn grows(&self) -> bool {
        self.grows
    }

    /// A pipeline was created through the cache, `hit` when it was found
    /// there: whether to snapshot now.
    pub fn created(&mut self, hit: bool) -> bool {
        if self.grows && !hit {
            self.unsaved += 1;
        }
        self.grows && self.unsaved >= SNAPSHOT_COMPILES
    }

    /// Whether an idle device has pipelines to snapshot.
    pub fn unsaved(&self) -> bool {
        self.grows && self.unsaved > 0
    }

    /// A snapshot of `payload` bytes was taken: whether it is kept. One past
    /// the bound stops the cache growing.
    pub fn snapshotted(&mut self, payload: usize) -> bool {
        self.unsaved = 0;
        let fits = (HEADER_BYTES as u64).saturating_add(payload as u64) <= self.bound;
        self.grows &= fits;
        fits
    }

    /// Snapshots failed: the cache stops growing.
    pub fn stop(&mut self) {
        self.unsaved = 0;
        self.grows = false;
    }
}

/// The bytes a backend seeds its cache with.
#[derive(Clone, Debug)]
pub enum Seed {
    Empty,
    /// The payload the boot read.
    Stored(&'static [u8]),
    /// A previous backend's newest snapshot, for a reopened device.
    Kept(Arc<Vec<u8>>),
}

impl Seed {
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Empty => &[],
            Self::Stored(bytes) => bytes,
            Self::Kept(bytes) => bytes,
        }
    }
}

/// A backend's hold on the store.
#[derive(Debug)]
pub struct Claim {
    generation: u64,
    pub key: Key,
    pub bound: u64,
    pub seed: Seed,
    /// Why the stored bytes seed nothing, unless they are blank.
    pub refused: Option<Rejection>,
}

/// A store to write: its header and payload.
#[derive(Debug)]
pub struct Sealed {
    pub header: [u8; HEADER_BYTES],
    pub payload: Arc<Vec<u8>>,
}

/// The boot's store: what it read, and the newest snapshot.
#[derive(Debug)]
pub struct Store {
    compiler: Vec<u8>,
    bound: u64,
    stored: &'static [u8],
    owner: Option<(u64, Key)>,
    claims: u64,
    kept: Option<(Key, Arc<Vec<u8>>)>,
    taken: bool,
    /// The key the stored bytes matched at a claim, and their NIR.
    matched: Option<Key>,
    /// The keys of the matched NIR, verified once at the claim, so that
    /// adding NIR does not hash the stored file again.
    stored_keys: alloc::collections::BTreeSet<[u8; 32]>,
    /// NIR compiled this boot, by key, and its bytes.
    nir: alloc::collections::BTreeMap<[u8; 32], Vec<u8>>,
    nir_bytes: u64,
}

impl Store {
    /// A store of `stored`, its file's bytes (empty for a blank one), for
    /// the compiler of build identity `compiler`, holding up to `bound`
    /// bytes.
    pub fn new(stored: &'static [u8], compiler: &[u8], bound: u64) -> Self {
        Self {
            compiler: compiler.to_vec(),
            bound: bound.min(MAX_BYTES),
            stored,
            owner: None,
            claims: 0,
            kept: None,
            taken: false,
            matched: None,
            stored_keys: alloc::collections::BTreeSet::new(),
            nir: alloc::collections::BTreeMap::new(),
            nir_bytes: 0,
        }
    }

    /// The stored NIR, for the device whose claim matched the store.
    pub fn stored_nir(&self) -> NirEntries<'static> {
        NirEntries(match self.matched {
            Some(key) => nir_section(self.stored, &key, self.bound),
            None => &[],
        })
    }

    /// Keeps `blob`, NIR of `key` compiled this boot, for the next.
    pub fn add_nir(&mut self, key: [u8; 32], blob: &[u8]) {
        let bytes = blob.len() as u64 + 36;
        if self.taken
            || self.matched.is_none() && self.owner.is_none()
            || self.nir_bytes + bytes > MAX_NIR_BYTES
            || self.stored_keys.contains(&key)
        {
            return;
        }
        if self.nir.insert(key, blob.to_vec()).is_none() {
            self.nir_bytes += bytes;
        }
    }

    /// The serialized NIR of `key` that [`Self::add_nir`] kept this boot.
    pub fn recall_nir(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
        self.nir.get(key).cloned()
    }

    /// The store for a backend of `gpu`. A newer backend of the same key
    /// replaces the holder, as a reopened device does; another GPU's while
    /// one holds it, or any after [`Self::take`], has none.
    pub fn claim(&mut self, gpu: &Identity) -> Option<Claim> {
        let key = Key::new(&self.compiler, gpu);
        if self.taken || self.owner.is_some_and(|(_, owner)| owner != key) {
            return None;
        }
        self.claims += 1;
        self.owner = Some((self.claims, key));
        let matched = payload(self.stored, &key, self.bound).is_ok();
        if matched && self.matched != Some(key) {
            self.matched = Some(key);
            self.stored_keys = self.stored_nir().map(|(stored, _)| stored).collect();
        }
        let (seed, refused) = match &self.kept {
            Some((kept, payload)) if *kept == key => (Seed::Kept(payload.clone()), None),
            _ => match payload(self.stored, &key, self.bound) {
                Ok(payload) => (Seed::Stored(payload), None),
                Err(Rejection::Blank) => (Seed::Empty, None),
                Err(rejection) => (Seed::Empty, Some(rejection)),
            },
        };
        Some(Claim {
            generation: self.claims,
            key,
            bound: self.bound,
            seed,
            refused,
        })
    }

    /// Keep `payload`, the holder's newest snapshot.
    pub fn keep(&mut self, claim: &Claim, payload: Vec<u8>) {
        if self.holds(claim) {
            self.kept = Some((claim.key, Arc::new(payload)));
        }
    }

    /// Ends `claim`'s hold, when it still holds the store.
    pub fn release(&mut self, claim: &Claim) {
        if self.holds(claim) {
            self.owner = None;
        }
    }

    fn holds(&self, claim: &Claim) -> bool {
        !self.taken
            && self
                .owner
                .is_some_and(|(generation, _)| generation == claim.generation)
    }

    /// The newest snapshot to write, sealed, with the stored NIR and what
    /// this boot added, within the bound; the store takes none after.
    pub fn take(&mut self) -> Option<Sealed> {
        let owner = self.owner.map(|(_, key)| key);
        self.taken = true;
        self.owner = None;
        let added = core::mem::take(&mut self.nir);
        let (key, cache) = match self.kept.take() {
            Some((key, payload)) => (key, payload),
            None if added.is_empty() => return None,
            // New NIR alone: the stored cache goes on beside it.
            None => {
                let key = self.matched.or(owner)?;
                let cache = payload(self.stored, &key, self.bound).unwrap_or(&[]);
                (key, Arc::new(cache.to_vec()))
            }
        };
        let room = self
            .bound
            .saturating_sub(HEADER_BYTES as u64 + cache.len() as u64)
            .min(MAX_NIR_BYTES);
        let mut nir = Vec::new();
        let stored = match self.matched {
            Some(matched) if matched == key => nir_section(self.stored, &key, self.bound),
            _ => &[],
        };
        for (entry, blob) in
            NirEntries(stored).chain(added.iter().map(|(key, blob)| (*key, &blob[..])))
        {
            if (nir.len() + 36 + blob.len()) as u64 > room {
                break;
            }
            push_entry(&mut nir, &entry, blob);
        }
        let header = header_with_nir(&key, &cache, &nir);
        let mut payload = Arc::unwrap_or_clone(cache);
        payload.extend_from_slice(&nir);
        Some(Sealed {
            header,
            payload: Arc::new(payload),
        })
    }
}

/// The boot's store, behind a lock no interrupt handler takes.
struct Cell {
    held: AtomicBool,
    store: UnsafeCell<Option<Store>>,
}
// SAFETY: `with_store` holds `held` for every access.
unsafe impl Sync for Cell {}
static STORE: Cell = Cell {
    held: AtomicBool::new(false),
    store: UnsafeCell::new(None),
};

fn with_store<R>(f: impl FnOnce(&mut Option<Store>) -> R) -> R {
    while STORE
        .held
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        while STORE.held.load(Ordering::Relaxed) {
            core::hint::spin_loop();
        }
    }
    // SAFETY: `held` excludes every other access until it is released.
    let result = f(unsafe { &mut *STORE.store.get() });
    STORE.held.store(false, Ordering::Release);
    result
}

/// Give the devices that open later the store the boot read: `stored`, the
/// file's bytes, for the compiler of build identity `compiler`, holding up
/// to `bound` bytes. Without it compiled pipelines keep no cache.
pub fn provide(stored: &'static [u8], compiler: &[u8], bound: u64) {
    let store = Store::new(stored, compiler, bound);
    with_store(|slot| *slot = Some(store));
}

/// At a quiescent point: the newest snapshot to write, if any pipeline was
/// added since the store was read. Later snapshots are not kept.
pub fn take() -> Option<Sealed> {
    with_store(|slot| slot.as_mut()?.take())
}

/// The NIR the store holds for the device that claimed it, by key.
pub fn stored_nir() -> Vec<([u8; 32], &'static [u8])> {
    with_store(|slot| {
        slot.as_ref()
            .map(|store| store.stored_nir().collect())
            .unwrap_or_default()
    })
}

/// Keeps `blob`, NIR of `key` compiled this boot, for the next boot.
pub fn add_nir(key: &[u8; 32], blob: &[u8]) {
    with_store(|slot| {
        if let Some(store) = slot {
            store.add_nir(*key, blob);
        }
    });
}

/// The serialized NIR of `key` compiled this boot, while the store keeps it.
pub fn recall_nir(key: &[u8; 32]) -> Option<Vec<u8>> {
    with_store(|slot| slot.as_ref()?.recall_nir(key))
}

/// The cache a backend's compiled pipelines read and fill, seeded from the
/// store, and when it is snapshotted.
pub(super) struct Persisted {
    claim: Option<Claim>,
    cache: vk::PipelineCache,
    policy: Policy,
    log: fn(&str),
}

impl Persisted {
    /// No store: compiled pipelines keep no cache.
    /// Where the store's messages go.
    pub(super) fn log(&self) -> fn(&str) {
        self.log
    }

    pub(super) fn none(log: fn(&str)) -> Self {
        Self {
            claim: None,
            cache: vk::PipelineCache::null(),
            policy: Policy::new(0),
            log,
        }
    }

    /// Claims the boot's store for `gpu` and seeds a cache from it. A seed
    /// the driver refuses leaves the cache empty.
    ///
    /// # Safety
    ///
    /// `device` is the backend's live device, whose physical device `gpu`
    /// describes.
    pub(super) unsafe fn open(device: &ash::Device, gpu: &Identity, log: fn(&str)) -> Self {
        let Some(mut claim) = with_store(|slot| slot.as_mut()?.claim(gpu)) else {
            return Self::none(log);
        };
        if let Some(rejection) = claim.refused {
            log(&alloc::format!(
                "pipeline store ignored: {}; its pipelines compile again",
                rejection.describe()
            ));
        }
        let seed = core::mem::replace(&mut claim.seed, Seed::Empty);
        let create = |data: &[u8]| {
            let info = vk::PipelineCacheCreateInfo::default().initial_data(data);
            // SAFETY: the create info and the data outlive the call; the
            // driver ignores data whose header is not its own.
            unsafe { device.create_pipeline_cache(&info, None) }
        };
        let cache = create(seed.bytes()).or_else(|error| {
            if seed.bytes().is_empty() {
                return Err(error);
            }
            log(&alloc::format!(
                "pipeline store refused by the driver ({error:?}); its pipelines compile again"
            ));
            create(&[])
        });
        match cache {
            Ok(cache) => Self {
                policy: Policy::new(claim.bound),
                claim: Some(claim),
                cache,
                log,
            },
            Err(error) => {
                log(&alloc::format!(
                    "pipeline store unused: no pipeline cache ({error:?}); pipelines compile \
                     every boot"
                ));
                with_store(|slot| {
                    if let Some(store) = slot {
                        store.release(&claim);
                    }
                });
                Self::none(log)
            }
        }
    }

    /// The cache a compiled pipeline is looked up in, and whether it is
    /// added there when it is missing.
    pub(super) fn cache(&self) -> Option<(vk::PipelineCache, bool)> {
        self.claim
            .is_some()
            .then_some((self.cache, self.policy.grows()))
    }

    /// A compiled pipeline was created through [`Self::cache`], `hit` when
    /// the cache held it.
    pub(super) fn created(&mut self, device: &ash::Device, hit: bool) {
        if self.claim.is_some() && self.policy.created(hit) {
            self.snapshot(device);
        }
    }

    /// The device is idle: snapshot the pipelines added since the last.
    pub(super) fn idle(&mut self, device: &ash::Device) {
        if self.claim.is_some() && self.policy.unsaved() {
            self.snapshot(device);
        }
    }

    fn snapshot(&mut self, device: &ash::Device) {
        let Some(claim) = &self.claim else {
            return;
        };
        // SAFETY: the cache is this device's and alive; the backend creates
        // no pipeline meanwhile.
        match unsafe { device.get_pipeline_cache_data(self.cache) } {
            Ok(payload) => {
                let bytes = payload.len();
                if self.policy.snapshotted(bytes) {
                    with_store(|slot| {
                        if let Some(store) = slot {
                            store.keep(claim, payload);
                        }
                    });
                } else {
                    (self.log)(&alloc::format!(
                        "pipeline store full: {bytes} bytes pass its bound of {}; newer \
                         pipelines compile every boot",
                        claim.bound
                    ));
                }
            }
            Err(error) => {
                self.policy.stop();
                (self.log)(&alloc::format!(
                    "pipeline store not snapshotted ({error:?}); newer pipelines compile \
                     every boot"
                ));
            }
        }
    }

    /// Releases the store and destroys the cache.
    ///
    /// # Safety
    ///
    /// `device` is the live device the cache was created on, and no
    /// pipeline creation uses the cache.
    pub(super) unsafe fn destroy(&mut self, device: &ash::Device) {
        if let Some(claim) = self.claim.take() {
            with_store(|slot| {
                if let Some(store) = slot {
                    store.release(&claim);
                }
            });
            // SAFETY: the caller's guarantees.
            unsafe { device.destroy_pipeline_cache(self.cache, None) };
            self.cache = vk::PipelineCache::null();
        }
    }
}

#[cfg(test)]
mod tests;
