// SPDX-License-Identifier: MIT
//! Bounded descriptor-relative build inputs, shared by source selection and
//! original-object registration capture. No compiler or source is executed.
//! Resolve explicitly selected root aliases once; never follow links below.
//! Final rechecks refuse observed changes, not atomic cross-file/ABA snapshots.
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    path::{Component, Path, PathBuf},
};

pub type Hash = [u8; 32];
pub type Result<T> = std::result::Result<T, String>;
macro_rules! require { ($condition:expr, $($message:tt)*) => { if !$condition { return Err(format!($($message)*)); } }; }
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct RootId(usize);
impl RootId {
    pub fn index(self) -> usize {
        self.0
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Key(usize);
impl Key {
    pub fn index(self) -> usize {
        self.0
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_unique_files: usize,
    pub max_unique_bytes: u64,
    pub max_roots: usize,
}
pub struct Request<'a> {
    pub root: RootId,
    pub relative: &'a Path,
    pub expected_sha256: Option<Hash>,
    pub max_bytes: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Identity {
    pub device: i128,
    pub inode: u128,
    pub mode: u64,
    pub bytes: u64,
    pub mtime_secs: i128,
    pub mtime_nanos: i128,
    pub ctime_secs: i128,
    pub ctime_nanos: i128,
}
impl Identity {
    fn same_object(&self, other: &Self) -> bool {
        self.device == other.device && self.inode == other.inode
    }
}
#[derive(Clone, Debug)]
pub struct Binding {
    pub key: Key,
    pub path: PathBuf,
    pub bytes: u64,
    pub sha256: Hash,
    pub identity: Identity,
}
#[derive(Clone, Debug)]
pub struct RootBinding {
    pub root: RootId,
    pub path: PathBuf,
    pub identity: Identity,
}
#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub unique_files: usize,
    pub unique_bytes: u64,
    pub bytes_hashed: u64,
    pub bytes_returned: u64,
    pub metadata_cache_hits: u64,
}
#[derive(Debug)]
pub struct Bindings {
    pub files: Vec<Binding>,
    pub roots: Vec<RootBinding>,
    pub stats: Stats,
}
#[derive(Clone)]
struct Record {
    root: RootId,
    relative: PathBuf,
    path: PathBuf,
    expected: Option<Hash>,
    max_bytes: u64,
    observed: Option<Binding>,
}

/// A logical path is validated without resolving below-root symlinks or '..'.
/// Per-component opens later enforce the corresponding filesystem boundary.
pub fn validate_relative(path: &Path) -> Result<()> {
    require!(
        !path.as_os_str().is_empty() && !path.is_absolute(),
        "expected nonempty relative input path"
    );
    require!(
        path.as_os_str().len() <= 16 * 1024,
        "relative input path exceeds finite bound"
    );
    for component in path.components() {
        require!(
            matches!(component, Component::Normal(_)),
            "noncanonical relative input path: {}",
            path.display()
        );
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::os::unix::ffi::OsStrExt;
        require!(
            path.as_os_str()
                .as_bytes()
                .split(|byte| *byte == b'/')
                .all(|part| !part.is_empty()
                    && part != b"."
                    && part != b".."
                    && !part.contains(&0)),
            "invalid relative input components"
        );
    }
    Ok(())
}

pub struct Inputs {
    limits: Limits,
    roots: Vec<platform::Root>,
    records: Vec<Record>,
    paths: BTreeMap<PathBuf, Key>,
    stats: Stats,
}
impl Inputs {
    pub fn new(limits: Limits) -> Result<Self> {
        require!(
            platform::SUPPORTED,
            "safe build inputs require Linux/macOS no-follow descriptor operations"
        );
        require!(
            limits.max_unique_files > 0
                && limits.max_unique_bytes > 0
                && limits.max_unique_bytes < u64::MAX
                && limits.max_roots > 0,
            "nonzero finite input limits required"
        );
        Ok(Self {
            limits,
            roots: Vec::new(),
            records: Vec::new(),
            paths: BTreeMap::new(),
            stats: Stats::default(),
        })
    }
    pub fn add_root(&mut self, selected: &Path) -> Result<RootId> {
        let root = platform::Root::new(selected)?;
        if let Some(index) = self.roots.iter().position(|known| known.path == root.path) {
            require!(
                self.roots[index].identity.same_object(&root.identity),
                "selected root identity changed"
            );
            return Ok(RootId(index));
        }
        require!(
            self.roots.len() < self.limits.max_roots,
            "input root count exceeds bound"
        );
        let id = RootId(self.roots.len());
        self.roots.push(root);
        Ok(id)
    }
    fn root(&self, root: RootId) -> Result<&platform::Root> {
        self.roots
            .get(root.0)
            .ok_or_else(|| "unknown input root".to_owned())
    }
    pub fn root_path(&self, root: RootId) -> Result<&Path> {
        Ok(&self.root(root)?.path)
    }
    /// Preflight all intended uses before content access. Same absolute lexical
    /// path shares one record, one expected pin and the tightest role cap.
    /// Return request-order keys including duplicates. Errors commit nothing.
    pub fn prepare(&mut self, requests: &[Request<'_>]) -> Result<Vec<Key>> {
        let mut records = self.records.clone();
        let mut paths = self.paths.clone();
        let mut keys = Vec::new();
        for request in requests {
            validate_relative(request.relative)?;
            require!(
                request.max_bytes > 0 && request.max_bytes <= self.limits.max_unique_bytes,
                "invalid per-role input cap"
            );
            let path = self.root(request.root)?.path.join(request.relative);
            let key = if let Some(key) = paths.get(&path).copied() {
                let record = &mut records[key.0];
                if let (Some(old), Some(new)) = (record.expected, request.expected_sha256) {
                    require!(
                        old == new,
                        "conflicting expected hashes for {}",
                        path.display()
                    );
                }
                if let Some(expected) = request.expected_sha256 {
                    if let Some(observed) = &record.observed {
                        require!(
                            observed.sha256 == expected,
                            "late expected hash conflicts with captured input"
                        );
                    }
                    record.expected = Some(expected);
                }
                record.max_bytes = record.max_bytes.min(request.max_bytes);
                if let Some(observed) = &record.observed {
                    require!(
                        observed.bytes <= record.max_bytes,
                        "captured input exceeds tightened role cap"
                    );
                }
                key
            } else {
                require!(
                    records.len() < self.limits.max_unique_files,
                    "unique prepared input count exceeds bound"
                );
                let key = Key(records.len());
                paths.insert(path.clone(), key);
                records.push(Record {
                    root: request.root,
                    relative: request.relative.to_owned(),
                    path,
                    expected: request.expected_sha256,
                    max_bytes: request.max_bytes,
                    observed: None,
                });
                key
            };
            keys.push(key);
        }
        self.records = records;
        self.paths = paths;
        Ok(keys)
    }
    fn capture(&mut self, key: Key, bytes: bool) -> Result<(Binding, Option<Vec<u8>>)> {
        self.capture_with(key, bytes, &mut |_| Ok(()))
    }
    fn capture_with(
        &mut self,
        key: Key,
        bytes: bool,
        hook: &mut impl FnMut(platform::Step) -> Result<()>,
    ) -> Result<(Binding, Option<Vec<u8>>)> {
        let record = self
            .records
            .get(key.0)
            .cloned()
            .ok_or_else(|| "unprepared input key".to_owned())?;
        let cached = record.observed.as_ref();
        let hash = bytes || cached.is_none();
        let cap = if cached.is_none() {
            record.max_bytes.min(
                self.limits
                    .max_unique_bytes
                    .saturating_sub(self.stats.unique_bytes),
            )
        } else {
            record.max_bytes
        };
        let captured = self
            .root(record.root)?
            .capture(&record.relative, cap, hash, bytes, hook)?;
        if let Some(previous) = cached {
            require!(
                previous.identity == captured.identity,
                "input identity changed: {}",
                record.path.display()
            );
        }
        if let Some(digest) = captured.sha256 {
            if let Some(expected) = record.expected {
                require!(
                    digest == expected,
                    "input hash mismatch: {}",
                    record.path.display()
                );
            }
            if let Some(previous) = cached {
                require!(
                    digest == previous.sha256,
                    "input bytes changed: {}",
                    record.path.display()
                );
            }
            self.stats.bytes_hashed = self
                .stats
                .bytes_hashed
                .checked_add(captured.identity.bytes)
                .ok_or("hash byte counter exhausted")?;
        } else {
            self.stats.metadata_cache_hits = self
                .stats
                .metadata_cache_hits
                .checked_add(1)
                .ok_or("input cache counter exhausted")?;
        }
        let digest = captured
            .sha256
            .or_else(|| cached.map(|value| value.sha256))
            .ok_or("missing input digest")?;
        let binding = Binding {
            key,
            path: record.path,
            bytes: captured.identity.bytes,
            sha256: digest,
            identity: captured.identity,
        };
        if cached.is_none() {
            self.stats.unique_bytes = self
                .stats
                .unique_bytes
                .checked_add(binding.bytes)
                .ok_or("unique byte counter exhausted")?;
            self.stats.unique_files += 1;
            self.records[key.0].observed = Some(binding.clone());
        }
        if let Some(value) = &captured.bytes {
            self.stats.bytes_returned = self
                .stats
                .bytes_returned
                .checked_add(u64::try_from(value.len()).map_err(|e| e.to_string())?)
                .ok_or("returned byte counter exhausted")?;
        }
        Ok((binding, captured.bytes))
    }
    /// Hash-only first use. Repeats reopen safely and check identity/cap without
    /// copying or rehashing a compiler/common header for every translation unit.
    pub fn verify(&mut self, key: Key) -> Result<Binding> {
        Ok(self.capture(key, false)?.0)
    }
    /// Temporary bytes for a parser/object scanner; not kept here.
    pub fn read(&mut self, key: Key) -> Result<Vec<u8>> {
        self.capture(key, true)?
            .1
            .ok_or_else(|| "missing captured bytes".to_owned())
    }
    /// Fresh streamed hash once per unique observed file, all roots
    /// rechecked. Consuming closes reader-owned descriptors on success or error.
    pub fn finish(mut self) -> Result<Bindings> {
        for root in &self.roots {
            root.check()?;
        }
        let mut files = Vec::new();
        for record in &self.records {
            let Some(binding) = &record.observed else {
                continue;
            };
            let captured = self.root(record.root)?.capture(
                &record.relative,
                record.max_bytes,
                true,
                false,
                &mut |_| Ok(()),
            )?;
            require!(
                captured.identity == binding.identity && captured.sha256 == Some(binding.sha256),
                "input changed before publication: {}",
                record.path.display()
            );
            self.stats.bytes_hashed = self
                .stats
                .bytes_hashed
                .checked_add(binding.bytes)
                .ok_or("hash byte counter exhausted")?;
            files.push(binding.clone());
        }
        for root in &self.roots {
            root.check()?;
        }
        let roots = self
            .roots
            .iter()
            .enumerate()
            .map(|(index, root)| RootBinding {
                root: RootId(index),
                path: root.path.clone(),
                identity: root.identity.clone(),
            })
            .collect();
        Ok(Bindings {
            files,
            roots,
            stats: self.stats,
        })
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod platform {
    use super::*;
    use std::{
        ffi::{CString, OsStr},
        io::{self, Read},
        mem::MaybeUninit,
        os::{
            fd::{AsRawFd, FromRawFd, RawFd},
            unix::ffi::OsStrExt,
        },
    };
    pub(super) const SUPPORTED: bool = true;
    const DIRECTORY: i32 =
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
    const INPUT: i32 =
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOCTTY;
    fn os<T>(value: io::Result<T>) -> Result<T> {
        value.map_err(|error| error.to_string())
    }
    fn convert(value: &libc::stat) -> Result<Identity> {
        Ok(Identity {
            device: i128::from(value.st_dev),
            inode: u128::from(value.st_ino),
            mode: u64::from(value.st_mode),
            bytes: u64::try_from(value.st_size).map_err(|_| "negative input size")?,
            mtime_secs: i128::from(value.st_mtime),
            mtime_nanos: i128::from(value.st_mtime_nsec),
            ctime_secs: i128::from(value.st_ctime),
            ctime_nanos: i128::from(value.st_ctime_nsec),
        })
    }
    pub(super) fn identity(file: &File) -> Result<Identity> {
        let mut value = MaybeUninit::<libc::stat>::uninit();
        // SAFETY: live File owns fd; exact stat output storage is writable.
        let status = unsafe { libc::fstat(file.as_raw_fd(), value.as_mut_ptr()) };
        require!(
            status == 0,
            "descriptor stat: {}",
            io::Error::last_os_error()
        );
        // SAFETY: successful fstat initialized all stat fields used by convert.
        convert(unsafe { value.assume_init_ref() })
    }
    fn directory_mode(value: &Identity) -> bool {
        value.mode & u64::from(libc::S_IFMT) == u64::from(libc::S_IFDIR)
    }
    fn regular(value: &Identity) -> bool {
        value.mode & u64::from(libc::S_IFMT) == u64::from(libc::S_IFREG)
    }
    fn component(value: &OsStr) -> Result<CString> {
        CString::new(value.as_bytes()).map_err(|error| format!("invalid input component: {error}"))
    }
    fn open_at(parent: RawFd, name: &OsStr, flags: i32) -> Result<File> {
        let name = component(name)?;
        // SAFETY: live parent, terminated name, no creation vararg.
        let fd = unsafe { libc::openat(parent, name.as_ptr(), flags) };
        require!(
            fd >= 0,
            "no-follow open {:?}: {}",
            name,
            io::Error::last_os_error()
        );
        // SAFETY: successful openat uniquely transfers descriptor ownership.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    fn absolute(path: &Path) -> Result<File> {
        require!(path.is_absolute(), "input root must be absolute");
        // SAFETY: terminated literal and no O_CREAT vararg.
        let fd = unsafe { libc::open(c"/".as_ptr(), DIRECTORY) };
        require!(
            fd >= 0,
            "filesystem root open: {}",
            io::Error::last_os_error()
        );
        // SAFETY: successful open produced exactly this owned descriptor.
        let mut parent = unsafe { File::from_raw_fd(fd) };
        for part in path.components() {
            match part {
                Component::RootDir => {}
                Component::Normal(name) => parent = open_at(parent.as_raw_fd(), name, DIRECTORY)?,
                _ => return Err("noncanonical absolute root".into()),
            }
        }
        Ok(parent)
    }
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) enum Step {
        BeforeDirectory(usize),
        BeforeFinalOpen,
        BeforeRead,
        AfterRead,
    }
    pub(super) struct Capture {
        pub identity: Identity,
        pub sha256: Option<Hash>,
        pub bytes: Option<Vec<u8>>,
    }
    pub(super) struct Root {
        pub path: PathBuf,
        pub identity: Identity,
        directory: File,
    }
    impl Root {
        pub fn new(selected: &Path) -> Result<Self> {
            let path = os(selected.canonicalize())?;
            let directory = absolute(&path)?;
            let identity = identity(&directory)?;
            require!(
                directory_mode(&identity),
                "selected root is not a directory"
            );
            Ok(Self {
                path,
                identity,
                directory,
            })
        }
        pub fn check(&self) -> Result<()> {
            let current = absolute(&self.path)?;
            require!(
                self.identity.same_object(&identity(&current)?),
                "selected input root changed"
            );
            Ok(())
        }
        fn walk(
            &self,
            path: Option<&Path>,
            hook: &mut impl FnMut(Step) -> Result<()>,
        ) -> Result<File> {
            let mut parent = os(self.directory.try_clone())?;
            if let Some(path) = path {
                validate_relative(path)?;
                for (index, part) in path.components().enumerate() {
                    hook(Step::BeforeDirectory(index))?;
                    let Component::Normal(part) = part else {
                        return Err("invalid input directory component".into());
                    };
                    parent = open_at(parent.as_raw_fd(), part, DIRECTORY)?;
                }
            }
            Ok(parent)
        }
        pub fn capture(
            &self,
            relative: &Path,
            limit: u64,
            hash: bool,
            retain: bool,
            hook: &mut impl FnMut(Step) -> Result<()>,
        ) -> Result<Capture> {
            validate_relative(relative)?;
            let parent_path = relative
                .parent()
                .filter(|path| !path.as_os_str().is_empty());
            let parent = self.walk(parent_path, hook)?;
            let name = relative.file_name().ok_or("input filename missing")?;
            let encoded = component(name)?;
            let mut metadata = MaybeUninit::<libc::stat>::uninit();
            // SAFETY: live parent, terminated name, writable stat storage.
            let status = unsafe {
                libc::fstatat(
                    parent.as_raw_fd(),
                    encoded.as_ptr(),
                    metadata.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            require!(
                status == 0,
                "no-follow input stat {}: {}",
                relative.display(),
                io::Error::last_os_error()
            );
            // SAFETY: successful fstatat initialized stat fields used below.
            let before_path = convert(unsafe { metadata.assume_init_ref() })?;
            require!(
                regular(&before_path) && before_path.bytes <= limit,
                "nonregular/symlink/oversized input: {}",
                relative.display()
            );
            hook(Step::BeforeFinalOpen)?;
            let mut input = open_at(parent.as_raw_fd(), name, INPUT)?;
            let before = identity(&input)?;
            require!(
                regular(&before) && before == before_path,
                "input changed during safe open: {}",
                relative.display()
            );
            if !hash {
                return Ok(Capture {
                    identity: before,
                    sha256: None,
                    bytes: None,
                });
            }
            hook(Step::BeforeRead)?;
            let mut digest = Sha256::new();
            let mut bytes = retain.then(Vec::new);
            let mut size = 0u64;
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let remaining = limit
                    .checked_add(1)
                    .and_then(|bound| bound.checked_sub(size))
                    .ok_or("input limit overflow")?;
                let count = usize::try_from(
                    remaining.min(u64::try_from(buffer.len()).map_err(|e| e.to_string())?),
                )
                .map_err(|e| e.to_string())?;
                let read = os(input.read(&mut buffer[..count]))?;
                if read == 0 {
                    break;
                }
                size = size
                    .checked_add(u64::try_from(read).map_err(|e| e.to_string())?)
                    .ok_or("input size overflow")?;
                require!(size <= limit, "input grew beyond byte bound");
                digest.update(&buffer[..read]);
                if let Some(bytes) = &mut bytes {
                    bytes.try_reserve(read).map_err(|error| error.to_string())?;
                    bytes.extend_from_slice(&buffer[..read]);
                }
            }
            hook(Step::AfterRead)?;
            let after = identity(&input)?;
            require!(
                before == after && size == before.bytes,
                "input changed during bounded capture"
            );
            Ok(Capture {
                identity: after,
                sha256: Some(digest.finalize().into()),
                bytes,
            })
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod platform {
    use super::*;
    pub(super) const SUPPORTED: bool = false;
    pub(super) struct Root {
        pub path: PathBuf,
        pub identity: Identity,
    }
    pub(super) enum Step {}
    pub(super) struct Capture {
        pub identity: Identity,
        pub sha256: Option<Hash>,
        pub bytes: Option<Vec<u8>>,
    }
    fn unsupported<T>() -> Result<T> {
        Err("safe no-follow input operations unsupported on this host".into())
    }
    impl Root {
        pub fn new(_: &Path) -> Result<Self> {
            unsupported()
        }
        pub fn check(&self) -> Result<()> {
            unsupported()
        }
        pub fn capture(
            &self,
            _: &Path,
            _: u64,
            _: bool,
            _: bool,
            _: &mut impl FnMut(Step) -> Result<()>,
        ) -> Result<Capture> {
            unsupported()
        }
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    use platform::Step;
    use std::{
        ffi::CString,
        fs,
        os::unix::{ffi::OsStrExt, fs::symlink},
    };
    fn limits() -> Limits {
        Limits {
            max_unique_files: 32,
            max_unique_bytes: 1024,
            max_roots: 4,
        }
    }
    fn fixture() -> (tempfile::TempDir, Inputs, RootId) {
        let directory = tempfile::tempdir().unwrap();
        let mut inputs = Inputs::new(limits()).unwrap();
        let root = inputs.add_root(directory.path()).unwrap();
        (directory, inputs, root)
    }
    fn key(
        inputs: &mut Inputs,
        root: RootId,
        path: &str,
        expected: Option<Hash>,
        max_bytes: u64,
    ) -> Key {
        inputs
            .prepare(&[Request {
                root,
                relative: Path::new(path),
                expected_sha256: expected,
                max_bytes,
            }])
            .unwrap()[0]
    }
    fn digest(bytes: &[u8]) -> Hash {
        Sha256::digest(bytes).into()
    }
    fn fifo(path: &Path) {
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: terminated private fixture path; creates its own named pipe.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    }
    #[test]
    fn preflight_is_transactional_conflicting_pins_and_role_caps_cannot_downgrade() {
        let (directory, mut inputs, root) = fixture();
        fs::write(directory.path().join("one"), b"original").unwrap();
        let hash = digest(b"original");
        let first = key(&mut inputs, root, "one", Some(hash), 8);
        assert!(
            inputs
                .prepare(&[
                    Request {
                        root,
                        relative: Path::new("two"),
                        expected_sha256: None,
                        max_bytes: 8
                    },
                    Request {
                        root,
                        relative: Path::new("one"),
                        expected_sha256: Some(digest(b"modified")),
                        max_bytes: 8
                    },
                ])
                .is_err()
        );
        assert_eq!(inputs.records.len(), 1);
        assert_eq!(inputs.stats.bytes_hashed, 0);
        assert_eq!(key(&mut inputs, root, "one", None, 16), first);
        assert_eq!(inputs.records[first.0].expected, Some(hash));
        assert_eq!(inputs.records[first.0].max_bytes, 8);
        inputs.verify(first).unwrap();
        assert!(
            inputs
                .prepare(&[Request {
                    root,
                    relative: Path::new("one"),
                    expected_sha256: None,
                    max_bytes: 7
                }])
                .is_err()
        );
        assert_eq!(inputs.records[first.0].max_bytes, 8);
        assert!(
            inputs
                .prepare(&[Request {
                    root,
                    relative: Path::new("bad/../one"),
                    expected_sha256: None,
                    max_bytes: 8
                }])
                .is_err()
        );
        assert!(validate_relative(Path::new("bad/./one")).is_err());
        assert!(validate_relative(Path::new("bad//one")).is_err());
    }
    #[test]
    fn hash_only_cache_counts_unique_inputs_and_final_rehash_without_keeping_bytes() {
        let (directory, mut inputs, root) = fixture();
        fs::write(directory.path().join("compiler"), b"compiler").unwrap();
        let compiler = key(
            &mut inputs,
            root,
            "compiler",
            Some(digest(b"compiler")),
            512,
        );
        for _ in 0..774 {
            assert_eq!(inputs.verify(compiler).unwrap().bytes, 8);
        }
        assert_eq!(inputs.stats.bytes_hashed, 8);
        assert_eq!(inputs.stats.bytes_returned, 0);
        assert_eq!(inputs.stats.metadata_cache_hits, 773);
        assert_eq!(inputs.stats.unique_files, 1);
        let finished = inputs.finish().unwrap();
        assert_eq!(finished.files.len(), 1);
        assert_eq!(finished.stats.bytes_hashed, 16);
        assert_eq!(finished.stats.unique_bytes, 8);
        assert_eq!(finished.stats.bytes_returned, 0);
    }
    #[test]
    fn overlapping_explicit_roots_deduplicate_and_temporary_object_bytes_are_accounted() {
        let (directory, mut inputs, root) = fixture();
        fs::create_dir(directory.path().join("objects")).unwrap();
        fs::write(directory.path().join("objects/one.o"), b"object").unwrap();
        let child = inputs.add_root(&directory.path().join("objects")).unwrap();
        let keys = inputs
            .prepare(&[
                Request {
                    root,
                    relative: Path::new("objects/one.o"),
                    expected_sha256: Some(digest(b"object")),
                    max_bytes: 16,
                },
                Request {
                    root: child,
                    relative: Path::new("one.o"),
                    expected_sha256: Some(digest(b"object")),
                    max_bytes: 6,
                },
            ])
            .unwrap();
        assert_eq!(keys[0], keys[1]);
        assert_eq!(inputs.read(keys[0]).unwrap(), b"object");
        inputs.verify(keys[1]).unwrap();
        let finished = inputs.finish().unwrap();
        assert_eq!(finished.files.len(), 1);
        assert_eq!(finished.roots.len(), 2);
        assert_eq!(finished.stats.unique_bytes, 6);
        assert_eq!(finished.stats.bytes_hashed, 12);
        assert_eq!(finished.stats.bytes_returned, 6);
    }
    #[test]
    fn nonregular_inputs_aliases_and_bounds_refuse_without_a_blocking_pipe_open() {
        let (directory, mut inputs, root) = fixture();
        fs::write(directory.path().join("one"), b"original").unwrap();
        fifo(&directory.path().join("pipe"));
        symlink("one", directory.path().join("alias")).unwrap();
        for path in ["pipe", "alias"] {
            let selected = key(&mut inputs, root, path, None, 8);
            assert!(inputs.read(selected).is_err());
        }
        let selected = key(&mut inputs, root, "one", None, 7);
        assert!(inputs.read(selected).is_err());
    }
    #[test]
    fn final_symlink_fifo_and_same_byte_inode_swaps_refuse_before_data_read() {
        for swap in 0..3 {
            let (directory, mut inputs, root) = fixture();
            let path = directory.path().join("one");
            fs::write(&path, b"original").unwrap();
            let outside = tempfile::tempdir().unwrap();
            let secret = outside.path().join("secret");
            fs::write(&secret, b"outside").unwrap();
            let replacement = directory.path().join("replacement");
            fs::write(&replacement, b"original").unwrap();
            let selected = key(&mut inputs, root, "one", None, 8);
            let mut reads = 0;
            let result = inputs.capture_with(selected, true, &mut |step| {
                if step == Step::BeforeFinalOpen {
                    match swap {
                        0 => {
                            fs::remove_file(&path).map_err(|error| error.to_string())?;
                            symlink(&secret, &path).map_err(|error| error.to_string())?;
                        }
                        1 => {
                            fs::remove_file(&path).map_err(|error| error.to_string())?;
                            fifo(&path);
                        }
                        _ => fs::rename(&replacement, &path).map_err(|error| error.to_string())?,
                    }
                }
                if step == Step::BeforeRead {
                    reads += 1;
                }
                Ok(())
            });
            assert!(result.is_err());
            assert_eq!(reads, 0);
            assert_eq!(inputs.stats.unique_files, 0);
        }
    }
    #[test]
    fn intermediate_symlink_race_never_reads_outside_selected_root() {
        let (directory, mut inputs, root) = fixture();
        let nested = directory.path().join("dir");
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join("one"), b"original").unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("one"), b"outside").unwrap();
        let selected = key(&mut inputs, root, "dir/one", None, 8);
        let mut reads = 0;
        assert!(
            inputs
                .capture_with(selected, true, &mut |step| {
                    if step == Step::BeforeDirectory(0) {
                        fs::rename(&nested, directory.path().join("held"))
                            .map_err(|error| error.to_string())?;
                        symlink(outside.path(), &nested).map_err(|error| error.to_string())?;
                    }
                    if step == Step::BeforeRead {
                        reads += 1;
                    }
                    Ok(())
                })
                .is_err()
        );
        assert_eq!(reads, 0);
    }
    #[test]
    fn opened_parent_is_anchored_but_rename_is_refused_before_publication() {
        let (directory, mut inputs, root) = fixture();
        let nested = directory.path().join("dir");
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join("one"), b"original").unwrap();
        let selected = key(&mut inputs, root, "dir/one", None, 8);
        let (_, bytes) = inputs
            .capture_with(selected, true, &mut |step| {
                if step == Step::BeforeFinalOpen {
                    fs::rename(&nested, directory.path().join("held"))
                        .map_err(|error| error.to_string())?;
                    fs::create_dir(&nested).map_err(|error| error.to_string())?;
                    fs::write(nested.join("one"), b"outside").map_err(|error| error.to_string())?;
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(bytes.unwrap(), b"original");
        assert!(inputs.finish().is_err());
    }
    #[test]
    fn file_growth_after_stat_and_metadata_change_after_read_refuse() {
        for growth in [true, false] {
            let (directory, mut inputs, root) = fixture();
            let path = directory.path().join("one");
            fs::write(&path, b"original").unwrap();
            let selected = key(&mut inputs, root, "one", None, 8);
            assert!(
                inputs
                    .capture_with(selected, true, &mut |step| {
                        if growth && step == Step::BeforeRead {
                            fs::write(&path, b"too-large").map_err(|error| error.to_string())?;
                        }
                        if !growth && step == Step::AfterRead {
                            fs::write(&path, b"modified").map_err(|error| error.to_string())?;
                            File::open(&path)
                                .and_then(|file| {
                                    file.set_modified(std::time::SystemTime::UNIX_EPOCH)
                                })
                                .map_err(|error| error.to_string())?;
                        }
                        Ok(())
                    })
                    .is_err()
            );
        }
    }
    #[test]
    fn unique_file_and_byte_limits_refuse_new_inputs() {
        let directory = tempfile::tempdir().unwrap();
        for path in ["one", "two"] {
            fs::write(directory.path().join(path), b"data").unwrap();
        }
        let mut inputs = Inputs::new(Limits {
            max_unique_bytes: 7,
            max_unique_files: 2,
            ..limits()
        })
        .unwrap();
        let root = inputs.add_root(directory.path()).unwrap();
        let first = key(&mut inputs, root, "one", None, 4);
        let second = key(&mut inputs, root, "two", None, 4);
        inputs.verify(first).unwrap();
        assert!(inputs.verify(second).is_err());
        assert!(
            inputs
                .prepare(&[Request {
                    root,
                    relative: Path::new("three"),
                    expected_sha256: None,
                    max_bytes: 1
                }])
                .is_err()
        );
    }

    #[test]
    fn expected_hash_mismatch_is_not_cached() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("one"), b"data").unwrap();
        let mut inputs = Inputs::new(limits()).unwrap();
        let root = inputs.add_root(directory.path()).unwrap();
        let selected = key(&mut inputs, root, "one", Some(digest(b"else")), 4);
        assert!(inputs.verify(selected).is_err());
        assert!(inputs.records[selected.0].observed.is_none());
    }
    #[test]
    fn same_byte_replacement_and_changed_root_are_final_failures() {
        let (directory, mut inputs, root) = fixture();
        let path = directory.path().join("one");
        fs::write(&path, b"original").unwrap();
        let selected = key(&mut inputs, root, "one", None, 8);
        inputs.verify(selected).unwrap();
        let replacement = directory.path().join("replacement");
        fs::write(&replacement, b"original").unwrap();
        fs::rename(replacement, path).unwrap();
        assert!(inputs.finish().is_err());
        let parent = tempfile::tempdir().unwrap();
        let selected = parent.path().join("selected");
        fs::create_dir(&selected).unwrap();
        let mut inputs = Inputs::new(limits()).unwrap();
        inputs.add_root(&selected).unwrap();
        fs::rename(&selected, parent.path().join("held")).unwrap();
        fs::create_dir(&selected).unwrap();
        assert!(inputs.finish().is_err());
    }
}
