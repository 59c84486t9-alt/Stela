//! The hosted directory store of block translations
//! (`docs/design/runtime.md#persistent-translation-store`), shared by every
//! hosted process and run of the same translator.
//!
//! Engines look records up as they fetch a page's first block and offer
//! the blocks they compile. Worker threads compile each offered block again
//! at the two probe addresses, keep the entries [`translations::prove`]
//! accepts and write their records off the guest's path; the process's end
//! (and an `execve`) waits a bounded time for them and writes what they
//! proved. A record is replaced whole through a sibling file and `rename`,
//! merged with the entries already there, so concurrent processes never
//! publish a partial record.
//!
//! A fork child starts its own store state: the parent's workers and
//! unwritten entries stay the parent's.
pub mod ahead;
mod image;

use crate::machine::{Offer, Translations};
use crate::translations::{self, Digest, Record};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex, MutexGuard, OnceLock,
        atomic::{AtomicPtr, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};
use stela_compiler::block::CompiledBlock;

/// The environment variable naming the store's home, or `off`.
pub const HOME_VARIABLE: &str = "STELA_TRANSLATION_CACHE";
/// The environment variable bounding the home's size in bytes.
pub const BOUND_VARIABLE: &str = "STELA_TRANSLATION_CACHE_BYTES";
const DEFAULT_HOME: &str = "Library/Caches/stela/translations";
const DEFAULT_BOUND: u64 = 4 << 30;
/// The home's layout version directory.
const LAYOUT: &str = "v1";
const RECORD_EXTENSION: &str = "stlt";
const USAGE_FILE: &str = "usage";
const TRANSLATOR_FILE: &str = "translator.txt";
/// Threads proving offered blocks.
const WORKERS: usize = 2;
/// Proven pages a worker lets gather before it writes them.
const WRITE_BATCH: usize = 256;
/// The longest the process's end waits for the workers.
const FINISH_WAIT: Duration = Duration::from_secs(2);
/// How stale a hit record's modification time may become before a hit
/// refreshes it for eviction.
const REFRESH_AGE: Duration = Duration::from_secs(24 * 60 * 60);
/// Eviction removes records until the home is this fraction of its bound.
const EVICT_TO_PERCENT: u64 = 90;
/// No record is larger: a page's 4 KiB of code in every context.
const MAX_RECORD_BYTES: u64 = 64 << 20;
/// The most native code a process keeps prepared for its threads.
const MAX_PREPARED_BYTES: usize = 512 << 20;

/// What the store did, for `--statistics`.
#[derive(Debug, Default)]
pub struct Counters {
    pub records_loaded: AtomicU64,
    pub records_absent: AtomicU64,
    pub records_invalid: AtomicU64,
    pub proven: AtomicU64,
    pub unprovable: AtomicU64,
    pub dropped: AtomicU64,
    pub records_written: AtomicU64,
    pub bytes_written: AtomicU64,
    pub evicted: AtomicU64,
}

pub static COUNTERS: Counters = Counters {
    records_loaded: AtomicU64::new(0),
    records_absent: AtomicU64::new(0),
    records_invalid: AtomicU64::new(0),
    proven: AtomicU64::new(0),
    unprovable: AtomicU64::new(0),
    dropped: AtomicU64::new(0),
    records_written: AtomicU64::new(0),
    bytes_written: AtomicU64::new(0),
    evicted: AtomicU64::new(0),
};

/// Where the store lives and how large it may grow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub home: PathBuf,
    pub bound: u64,
}

impl Config {
    /// The store the environment names: `None` when it is `off` or no home
    /// can be found.
    pub fn from_environment() -> Option<Self> {
        Self::from_values(
            std::env::var_os(HOME_VARIABLE),
            std::env::var(BOUND_VARIABLE).ok(),
            std::env::var_os("HOME"),
        )
    }

    fn from_values(
        home: Option<std::ffi::OsString>,
        bound: Option<String>,
        user_home: Option<std::ffi::OsString>,
    ) -> Option<Self> {
        let home = match home {
            Some(value) if value == "off" => return None,
            Some(value) if !value.is_empty() => PathBuf::from(value),
            _ => PathBuf::from(user_home?).join(DEFAULT_HOME),
        };
        let bound = bound
            .and_then(|value| value.parse().ok())
            .unwrap_or(DEFAULT_BOUND);
        Some(Self { home, bound })
    }
}

struct State {
    /// Records looked up, `None` for those absent or invalid.
    loaded: BTreeMap<Digest, Option<Arc<Record>>>,
    /// Blocks this process prepared, by page key, PC and context, for its
    /// other threads, whose engines compile separately.
    prepared: HashMap<(Digest, u64, Digest), CompiledBlock>,
    /// The native bytes `prepared` holds.
    prepared_bytes: usize,
    queue: VecDeque<Offer>,
    /// Offers a worker is proving.
    busy: usize,
    /// Proven entries not yet written, by page.
    unwritten: BTreeMap<Digest, Record>,
    workers: usize,
    closed: bool,
}

/// The store's directory, when the process has one.
struct Disk {
    config: Config,
    /// `HOME/v1/TRANSLATOR`.
    namespace: PathBuf,
}

/// One process's store: the blocks its threads and its ahead-of-time
/// translation prepared, and its disk, if it has one.
struct Shared {
    disk: Option<Disk>,
    translator: Digest,
    pid: u32,
    state: Mutex<State>,
    /// Signals work for the workers and their progress to the finish.
    changed: Condvar,
    written_bytes: AtomicU64,
    ahead: ahead::Ahead,
}

fn lock<T>(state: &Mutex<T>) -> MutexGuard<'_, T> {
    state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

static CONFIG: OnceLock<Option<Config>> = OnceLock::new();
/// This process's store, recreated in a fork child.
static CURRENT: AtomicPtr<Shared> = AtomicPtr::new(core::ptr::null_mut());

/// Use the store `config` names for this process.
pub fn configure(config: Option<Config>) {
    let _ = CONFIG.set(config);
}

/// The calling process's store, created on first use and again in a fork
/// child, whose parent's state (its locks included) it never touches.
fn shared() -> Option<&'static Shared> {
    let config = CONFIG.get()?;
    let pid = std::process::id();
    let current = CURRENT.load(Ordering::Acquire);
    // SAFETY: stores are leaked, never freed.
    if let Some(shared) = unsafe { current.as_ref() }
        && shared.pid == pid
    {
        return Some(shared);
    }
    let translator = translations::translator_id();
    let shared = Box::leak(Box::new(Shared {
        disk: config.as_ref().map(|config| Disk {
            namespace: config.home.join(LAYOUT).join(translator.hex()),
            config: config.clone(),
        }),
        translator,
        pid,
        state: Mutex::new(State {
            loaded: BTreeMap::new(),
            prepared: HashMap::new(),
            prepared_bytes: 0,
            queue: VecDeque::new(),
            busy: 0,
            unwritten: BTreeMap::new(),
            workers: 0,
            closed: false,
        }),
        changed: Condvar::new(),
        written_bytes: AtomicU64::new(0),
        ahead: ahead::Ahead::default(),
    }));
    CURRENT.store(shared, Ordering::Release);
    Some(shared)
}

/// The engine's view of this process's store.
#[derive(Debug, Default)]
pub struct Store;

impl Store {
    /// A handle, if the process has a store.
    pub fn open() -> Option<Self> {
        shared().map(|_| Self)
    }
}

impl Translations for Store {
    fn record(&mut self, key: &Digest) -> Option<Arc<Record>> {
        shared()?.record(key)
    }

    fn prepared(&mut self, key: &Digest, pc: u64, context: &Digest) -> Option<CompiledBlock> {
        let shared = shared()?;
        lock(&shared.state)
            .prepared
            .get(&(*key, pc, *context))
            .cloned()
    }

    fn offer(&mut self, offer: Offer) {
        let Some(shared) = shared() else {
            return;
        };
        shared.ahead.note(shared, &offer);
        shared.prepare(offer);
    }
}

impl Shared {
    /// The record of page `key`, read once.
    fn record(&self, key: &Digest) -> Option<Arc<Record>> {
        let disk = self.disk.as_ref()?;
        if let Some(loaded) = lock(&self.state).loaded.get(key) {
            return loaded.clone();
        }
        let record = self.load(disk, key).map(Arc::new);
        lock(&self.state).loaded.insert(*key, record.clone());
        record
    }

    /// Whether the block at `pc` of page `key` is prepared in `context`.
    fn has_prepared(&self, key: &Digest, pc: u64, context: &Digest) -> bool {
        lock(&self.state)
            .prepared
            .contains_key(&(*key, pc, *context))
    }

    /// Keep `offer`'s block for the process's threads and queue it for its
    /// workers to prove and write.
    fn prepare(&'static self, offer: Offer) {
        let mut state = lock(&self.state);
        let bytes = offer.block.native.x86_64_code.len();
        if state.prepared_bytes + bytes <= MAX_PREPARED_BYTES {
            state.prepared_bytes += bytes;
            state
                .prepared
                .insert((offer.key, offer.pc, offer.context), offer.block.clone());
        }
        if state.closed || self.disk.is_none() {
            return;
        }
        let shared = self;
        state.queue.push_back(offer);
        if state.workers < WORKERS {
            state.workers += 1;
            drop(state);
            let spawned = std::thread::Builder::new()
                .name("stela-translations".into())
                .spawn(move || shared.work());
            if spawned.is_err() {
                lock(&shared.state).workers -= 1;
            }
            return;
        }
        drop(state);
        shared.changed.notify_one();
    }

    fn path(disk: &Disk, key: &Digest) -> PathBuf {
        let hex = key.hex();
        disk.namespace
            .join(&hex[..2])
            .join(format!("{hex}.{RECORD_EXTENSION}"))
    }

    /// The valid record of page `key` on disk.
    fn load(&self, disk: &Disk, key: &Digest) -> Option<Record> {
        let path = Self::path(disk, key);
        let Some(bytes) = read_bounded(&path) else {
            COUNTERS.records_absent.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        match Record::decode(&bytes, &self.translator, key) {
            Ok(record) => {
                COUNTERS.records_loaded.fetch_add(1, Ordering::Relaxed);
                refresh(&path);
                Some(record)
            }
            Err(_) => {
                COUNTERS.records_invalid.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// Prove offers until the store closes and the queue is empty.
    fn work(&self) {
        loop {
            let mut state = lock(&self.state);
            let offer = loop {
                if let Some(offer) = state.queue.pop_front() {
                    break offer;
                }
                if state.closed {
                    state.workers -= 1;
                    drop(state);
                    self.changed.notify_all();
                    return;
                }
                state = self
                    .changed
                    .wait(state)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            };
            state.busy += 1;
            drop(state);
            let entry = prove(&offer);
            let mut state = lock(&self.state);
            state.busy -= 1;
            match entry {
                Some(entry) => {
                    COUNTERS.proven.fetch_add(1, Ordering::Relaxed);
                    let translator = self.translator;
                    state
                        .unwritten
                        .entry(offer.key)
                        .or_insert_with(|| Record::new(translator, offer.key))
                        .insert(entry);
                }
                None => {
                    COUNTERS.unprovable.fetch_add(1, Ordering::Relaxed);
                }
            }
            let batch = (state.unwritten.len() >= WRITE_BATCH)
                .then(|| std::mem::take(&mut state.unwritten));
            drop(state);
            self.changed.notify_all();
            if let Some(batch) = batch {
                self.write(batch);
            }
        }
    }

    /// Write each record merged with the one on disk.
    fn write(&self, records: BTreeMap<Digest, Record>) {
        let Some(disk) = &self.disk else {
            return;
        };
        for (key, mut record) in records {
            let path = Self::path(disk, &key);
            let previous = read_bounded(&path);
            if let Some(stored) = previous
                .as_deref()
                .and_then(|bytes| Record::decode(bytes, &self.translator, &key).ok())
            {
                record.merge(stored);
            }
            let bytes = record.encode();
            if write_replacing(&path, &bytes).is_ok() {
                COUNTERS.records_written.fetch_add(1, Ordering::Relaxed);
                COUNTERS
                    .bytes_written
                    .fetch_add(bytes.len() as u64, Ordering::Relaxed);
                let grown = (bytes.len() as u64)
                    .saturating_sub(previous.map_or(0, |previous| previous.len() as u64));
                self.written_bytes.fetch_add(grown, Ordering::Relaxed);
            }
        }
    }

    /// Stop taking offers, wait for the workers until `deadline`, drop what
    /// they did not reach and write what they proved.
    fn finish(&self, deadline: Instant) {
        self.ahead.close();
        let Some(disk) = &self.disk else {
            return;
        };
        let mut state = lock(&self.state);
        state.closed = true;
        self.changed.notify_all();
        while (state.busy != 0 || !state.queue.is_empty()) && state.workers != 0 {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            state = self
                .changed
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
        COUNTERS
            .dropped
            .fetch_add(state.queue.len() as u64, Ordering::Relaxed);
        state.queue.clear();
        let unwritten = std::mem::take(&mut state.unwritten);
        drop(state);
        if unwritten.is_empty() {
            return;
        }
        let _ = std::fs::create_dir_all(&disk.namespace);
        let described = disk.namespace.join(TRANSLATOR_FILE);
        if !described.exists() {
            let text = format!(
                "stela {}\ncompiler {}\nengine {}\nschema {}\n",
                env!("CARGO_PKG_VERSION"),
                stela_compiler::SOURCE_SHA256,
                translations::ENGINE_SOURCE_SHA256,
                translations::SCHEMA,
            );
            let _ = write_replacing(&described, text.as_bytes());
        }
        self.write(unwritten);
        self.account(disk);
    }

    /// Add this process's growth to the home's usage and evict past the
    /// bound.
    fn account(&self, disk: &Disk) {
        let grown = self.written_bytes.swap(0, Ordering::Relaxed);
        let root = disk.config.home.join(LAYOUT);
        let Ok(mut file) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(root.join(USAGE_FILE))
        else {
            return;
        };
        let descriptor = std::os::fd::AsRawFd::as_raw_fd(&file);
        // SAFETY: an open descriptor; the lock ends when the file closes.
        if unsafe { libc::flock(descriptor, libc::LOCK_EX) } != 0 {
            return;
        }
        let mut text = String::new();
        let _ = file.read_to_string(&mut text);
        let mut usage = text.trim().parse::<u64>().unwrap_or(0) + grown;
        if usage > disk.config.bound {
            usage = evict(&root, disk.config.bound * EVICT_TO_PERCENT / 100);
        }
        let _ = file.set_len(0);
        let _ = std::io::Seek::rewind(&mut file);
        let _ = file.write_all(usage.to_string().as_bytes());
    }
}

/// Compile the offered block at both probe addresses and prove its entry.
fn prove(offer: &Offer) -> Option<translations::Entry> {
    let displacements = translations::probe_displacements(offer.page);
    let probes = displacements.map(|displacement| {
        offer
            .preparation
            .compile_input(&offer.input, offer.pc.wrapping_add(displacement))
            .ok()
    });
    let [Some(first), Some(second)] = &probes else {
        return None;
    };
    translations::prove(
        &offer.block,
        offer.page,
        offer.pc,
        offer.context,
        [first, second],
    )
}

/// The process ends or replaces its image: write what the workers proved.
pub fn finish() {
    let pid = std::process::id();
    // SAFETY: stores are leaked, never freed.
    if let Some(shared) = unsafe { CURRENT.load(Ordering::Acquire).as_ref() }
        && shared.pid == pid
    {
        shared.finish(Instant::now() + FINISH_WAIT);
    }
}

/// The engine's and the store's counts, one line each, for `--statistics`.
pub fn summary(engine: &crate::machine::Statistics) -> Vec<String> {
    let ticks_per_millisecond = super::host::COUNTER_HZ / 1000;
    // Seconds of counter ticks per item.
    let per = |ticks: u64, items: u64| {
        ticks as f64 / super::host::COUNTER_HZ as f64 / items.max(1) as f64
    };
    let counter = |value: &AtomicU64| value.load(Ordering::Relaxed);
    let mut lines = vec![
        format!(
            "engine: {} blocks run, {} chained, {} lookup hits, {} exits",
            engine.blocks,
            engine.chained,
            engine.lookup_hits,
            engine.exit_kinds.iter().sum::<u64>()
        ),
        format!(
            "engine: {} blocks ({} instructions) compiled in {} ms ({:.1} us a block, {:.0} ns \
             an instruction), {} from the store, {} shared by threads, {} offered to it",
            engine.compiled,
            engine.compiled_instructions,
            engine.compile_ticks / ticks_per_millisecond,
            per(engine.compile_ticks, engine.compiled) * 1e6,
            per(engine.compile_ticks, engine.compiled_instructions) * 1e9,
            engine.stored,
            engine.shared,
            engine.offered
        ),
        format!("engine: exits by kind {:?}", engine.exit_kinds),
    ];
    if CONFIG.get().is_some_and(Option::is_some) {
        lines.push(format!(
            "store: {} records loaded, {} absent, {} invalid; {} blocks proven, {} unprovable, \
             {} dropped; {} records written ({} bytes), {} evicted",
            counter(&COUNTERS.records_loaded),
            counter(&COUNTERS.records_absent),
            counter(&COUNTERS.records_invalid),
            counter(&COUNTERS.proven),
            counter(&COUNTERS.unprovable),
            counter(&COUNTERS.dropped),
            counter(&COUNTERS.records_written),
            counter(&COUNTERS.bytes_written),
            counter(&COUNTERS.evicted),
        ));
    } else {
        lines.push("store: off".into());
    }
    lines.push(format!(
        "ahead: {} images read naming {} entries; {} blocks prepared, {} already prepared, {} \
         refused",
        counter(&ahead::COUNTERS.images),
        counter(&ahead::COUNTERS.entries),
        counter(&ahead::COUNTERS.prepared),
        counter(&ahead::COUNTERS.already),
        counter(&ahead::COUNTERS.refused),
    ));
    lines
}

fn read_bounded(path: &Path) -> Option<Vec<u8>> {
    let mut file = std::fs::File::open(path).ok()?;
    let length = file.metadata().ok()?.len();
    if length > MAX_RECORD_BYTES {
        return None;
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.read_to_end(&mut bytes).ok()?;
    Some(bytes)
}

/// Keep a record in use from eviction: its modification time ages a day
/// at most.
fn refresh(path: &Path) {
    let Ok(file) = std::fs::File::options().write(true).open(path) else {
        return;
    };
    let stale = file
        .metadata()
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| SystemTime::now().duration_since(modified).ok())
        .is_some_and(|age| age > REFRESH_AGE);
    if stale {
        let _ = file.set_modified(SystemTime::now());
    }
}

/// Replace `path` with `bytes` through a sibling file, creating its
/// directory.
fn write_replacing(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let directory = path.parent().expect("a record path has a directory");
    std::fs::create_dir_all(directory)?;
    let sibling = directory.join(format!(
        ".{}.{}.{}",
        path.file_name()
            .expect("a record path has a name")
            .to_string_lossy(),
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let written = std::fs::write(&sibling, bytes).and_then(|()| std::fs::rename(&sibling, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&sibling);
    }
    written
}

/// Remove the least recently modified records under `root` until its
/// records take `target` bytes at most; the bytes left.
fn evict(root: &Path, target: u64) -> u64 {
    let mut records = Vec::new();
    let mut total = 0;
    for namespace in read_directory(root) {
        for shard in read_directory(&namespace) {
            for path in read_directory(&shard) {
                if path
                    .extension()
                    .is_some_and(|extension| extension == RECORD_EXTENSION)
                    && let Ok(metadata) = std::fs::metadata(&path)
                {
                    total += metadata.len();
                    let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                    records.push((modified, metadata.len(), path));
                }
            }
        }
    }
    records.sort();
    for (_, bytes, path) in records {
        if total <= target {
            break;
        }
        if std::fs::remove_file(&path).is_ok() {
            total -= bytes;
            COUNTERS.evicted.fetch_add(1, Ordering::Relaxed);
        }
    }
    total
}

fn read_directory(path: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(path)
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .filter(|path| path.is_dir() || path.is_file())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_replace_through_a_sibling_and_eviction_removes_the_oldest_first() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join(LAYOUT);
        let shard = root.join("namespace").join("ab");
        let paths: Vec<_> = (0..3)
            .map(|index| shard.join(format!("{index}.{RECORD_EXTENSION}")))
            .collect();
        for (age, path) in paths.iter().enumerate() {
            write_replacing(path, &[age as u8; 100]).unwrap();
            let file = std::fs::File::options().write(true).open(path).unwrap();
            file.set_modified(SystemTime::now() - Duration::from_secs(1000 * (3 - age as u64)))
                .unwrap();
        }
        write_replacing(&paths[2], &[9; 100]).unwrap();
        assert_eq!(std::fs::read(&paths[2]).unwrap(), [9; 100]);
        assert_eq!(read_directory(&shard).len(), 3, "no sibling is left");
        assert_eq!(evict(&root, 150), 100);
        assert!(!paths[0].exists() && !paths[1].exists() && paths[2].exists());
    }

    #[test]
    fn the_environment_names_the_home_and_bound_or_turns_the_store_off() {
        let user = Some("/Users/u".into());
        assert_eq!(
            Config::from_values(Some("off".into()), None, user.clone()),
            None
        );
        assert_eq!(
            Config::from_values(None, None, user.clone()),
            Some(Config {
                home: PathBuf::from("/Users/u").join(DEFAULT_HOME),
                bound: DEFAULT_BOUND,
            })
        );
        assert_eq!(
            Config::from_values(Some("/c".into()), Some("12".into()), None),
            Some(Config {
                home: PathBuf::from("/c"),
                bound: 12,
            })
        );
        assert_eq!(Config::from_values(None, None, None), None);
    }
}
