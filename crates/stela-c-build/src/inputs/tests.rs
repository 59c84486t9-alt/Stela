//! Bounded source paths, identity, cache and final rechecks.
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
                            .and_then(|file| file.set_modified(std::time::SystemTime::UNIX_EPOCH))
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
