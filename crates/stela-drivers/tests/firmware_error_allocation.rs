//! A separate process denies every global allocation during canonical lookup,
//! owned error cloning and formatting into caller-owned storage.
use sha2::{Digest, Sha256};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    fmt::{self, Write},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
use stela_drivers::firmware::{
    Catalog, Error, ErrorKind, ErrorName, HandoffProvider, Provenance, Provider, Requirement,
    Resource, Target,
};

struct FailingAllocator;
static FAIL: AtomicBool = AtomicBool::new(false);
static DENIED: AtomicUsize = AtomicUsize::new(0);
// SAFETY: forwards the exact allocation/deallocation contracts to System,
// except that the explicitly armed child-process phase returns allocation failure.
unsafe impl GlobalAlloc for FailingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if FAIL.load(Ordering::Relaxed) {
            DENIED.fetch_add(1, Ordering::Relaxed);
            core::ptr::null_mut()
        } else {
            unsafe { System.alloc(layout) }
        }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if FAIL.load(Ordering::Relaxed) {
            DENIED.fetch_add(1, Ordering::Relaxed);
            core::ptr::null_mut()
        } else {
            unsafe { System.alloc_zeroed(layout) }
        }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if FAIL.load(Ordering::Relaxed) {
            DENIED.fetch_add(1, Ordering::Relaxed);
            core::ptr::null_mut()
        } else {
            unsafe { System.realloc(ptr, layout, size) }
        }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: FailingAllocator = FailingAllocator;

struct Buffer {
    bytes: [u8; 4096],
    used: usize,
}
impl fmt::Write for Buffer {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let end = self.used.checked_add(value.len()).ok_or(fmt::Error)?;
        let destination = self.bytes.get_mut(self.used..end).ok_or(fmt::Error)?;
        destination.copy_from_slice(value.as_bytes());
        self.used = end;
        Ok(())
    }
}
fn target() -> Target<'static> {
    Target {
        driver: "fixture",
        hardware: "synthetic",
        revision: "v1",
        board: None,
    }
}
fn requirement() -> Requirement<'static> {
    Requirement {
        name: "vendor/fw.bin",
        target: target(),
        minimum_bytes: 3,
    }
}

#[test]
fn complete_diagnostics_own_unbounded_utf8_names_and_keep_exact_equality() {
    let name = "vendor/é😀".repeat(80);
    let original = name.clone();
    let (error, cloned) = {
        let empty = Catalog::from_handoff(vec![]).unwrap();
        let error = empty
            .load(Requirement {
                name: &name,
                ..requirement()
            })
            .unwrap_err();
        let cloned = error.clone();
        (error, cloned)
    };
    drop(name);
    assert_eq!(error.kind, ErrorKind::Missing);
    assert_eq!(error.name.as_str(), Some(original.as_str()));
    assert_eq!(error.name, original);
    assert_eq!(cloned, error);
    assert!(error.name.ends_with("é😀"));
    let unavailable = ErrorName::AllocationFailed {
        original_bytes: original.len(),
        sha256: Sha256::digest(original.as_bytes()).into(),
    };
    assert_ne!(unavailable, error.name);
    assert_ne!(unavailable, original);
    assert!(unavailable.as_str().is_none());
    assert!(!unavailable.ends_with("é😀"));
}

#[test]
fn canonical_error_paths_survive_global_allocator_failure() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "global_allocator_failure_child",
            "--test-threads=1",
            "--nocapture",
        ])
        .env("STELA_FIRMWARE_OOM_CHILD", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
}

#[test]
fn global_allocator_failure_child() {
    if std::env::var_os("STELA_FIRMWARE_OOM_CHILD").is_none() {
        return;
    }
    let catalog = Catalog::from_persistent_handoff(vec![Resource {
        name: requirement().name,
        target: target(),
        provenance: Provenance {
            source: "synthetic",
            revision: "v1",
            member: "abc.bin",
            license: "CC0-1.0",
        },
        expected_length: 3,
        expected_sha256: [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ],
        bytes: &b"abc"[..],
    }])
    .unwrap();
    let empty = Catalog::from_handoff(vec![]).unwrap();
    let provider = HandoffProvider::new(Some(&catalog));
    let absent = HandoffProvider::new(None);
    let mut long_name = "x".repeat(1024);
    let long_sha: [u8; 32] = Sha256::digest(long_name.as_bytes()).into();
    let short_sha: [u8; 32] = Sha256::digest(requirement().name.as_bytes()).into();
    let owned_before_failure = empty
        .load(Requirement {
            name: &long_name,
            ..requirement()
        })
        .unwrap_err();
    assert_eq!(owned_before_failure.name.as_str(), Some(long_name.as_str()));
    let already_owned = String::from("prepared/vendor.bin");
    let mut formatted = Buffer {
        bytes: [0; 4096],
        used: 0,
    };

    // All setup and test-harness work is complete. Every global allocation now
    // returns null. A direct probe verifies the allocator is actually armed.
    FAIL.store(true, Ordering::SeqCst);
    let probe = unsafe { std::alloc::alloc(Layout::new::<u64>()) };
    let armed = probe.is_null();
    if !probe.is_null() {
        unsafe { std::alloc::dealloc(probe, Layout::new::<u64>()) };
    }
    let success = provider.load(requirement()).unwrap();
    let moved: ErrorName = already_owned.into();
    let success_allocated_nothing = DENIED.load(Ordering::Relaxed) == 1;
    let long_error = empty
        .load(Requirement {
            name: &long_name,
            ..requirement()
        })
        .unwrap_err();
    let missing = absent.load(requirement()).unwrap_err();
    let wrong = provider
        .load(Requirement {
            target: Target {
                revision: "other",
                ..target()
            },
            ..requirement()
        })
        .unwrap_err();
    let truncated = provider
        .load(Requirement {
            minimum_bytes: 4,
            ..requirement()
        })
        .unwrap_err();
    let invalid_requirement = absent
        .load(Requirement {
            minimum_bytes: 0,
            ..requirement()
        })
        .unwrap_err();
    let invalid_target = absent
        .load(Requirement {
            target: Target {
                hardware: "",
                ..target()
            },
            ..requirement()
        })
        .unwrap_err();
    let controls = absent
        .load(Requirement {
            name: "bad\n\0\x1b",
            ..requirement()
        })
        .unwrap_err();
    let empty_name = absent
        .load(Requirement {
            name: "",
            ..requirement()
        })
        .unwrap_err();
    let digest_error = Error {
        name: requirement().name.into(),
        kind: ErrorKind::DigestMismatch {
            expected: [0; 32],
            actual: [1; 32],
        },
    };
    let cloned = owned_before_failure.clone();
    let before_unavailable_clone = DENIED.load(Ordering::Relaxed);
    let unavailable_clone = missing.clone();
    let unavailable_clone_allocated_nothing =
        DENIED.load(Ordering::Relaxed) == before_unavailable_clone;
    let valid = armed
        && success_allocated_nothing
        && unavailable_clone_allocated_nothing
        && success.bytes() == b"abc"
        && moved.as_str() == Some("prepared/vendor.bin")
        && long_error.kind == ErrorKind::Missing
        && long_error.name.as_str().is_none()
        && matches!(long_error.name, ErrorName::AllocationFailed { original_bytes: 1024, sha256 } if sha256 == long_sha)
        && long_error.name != long_name
        && long_error.name != long_name[..256]
        && !long_error.name.ends_with("x")
        && missing.name.as_str().is_none()
        && missing.kind == ErrorKind::Missing
        && matches!(missing.name, ErrorName::AllocationFailed { original_bytes, sha256 } if original_bytes == requirement().name.len() && sha256 == short_sha)
        && unavailable_clone == missing
        && wrong.kind == ErrorKind::WrongTarget
        && truncated.kind
            == ErrorKind::Truncated {
                expected: 4,
                actual: 3,
            }
        && invalid_requirement.kind == ErrorKind::InvalidRequirement
        && invalid_target.kind == ErrorKind::InvalidTarget("hardware")
        && controls.kind == ErrorKind::InvalidName
        && empty_name.kind == ErrorKind::InvalidName
        && empty_name.name.as_str() == Some("")
        && cloned.kind == owned_before_failure.kind
        && cloned.name != owned_before_failure.name
        && matches!(cloned.name, ErrorName::AllocationFailed { original_bytes: 1024, sha256 } if sha256 == long_sha);
    let before_format = DENIED.load(Ordering::Relaxed);
    let rendered = write!(&mut formatted, "{missing} {wrong} {truncated} {invalid_requirement} {invalid_target} {controls} {digest_error:?} {owned_before_failure}").is_ok();
    let formatting_allocated_nothing = DENIED.load(Ordering::Relaxed) == before_format;
    long_name.clear();
    drop(catalog);
    drop(empty);
    let independent = owned_before_failure.name.as_str().unwrap().len() == 1024
        && matches!(cloned.name, ErrorName::AllocationFailed { original_bytes: 1024, sha256 } if sha256 == long_sha);
    let denied = DENIED.load(Ordering::Relaxed);
    FAIL.store(false, Ordering::SeqCst);

    assert!(valid && rendered && independent && formatting_allocated_nothing);
    assert!(size_of::<Error>() <= 128);
    assert!(size_of::<Result<stela_drivers::firmware::Image<'static>, Error>>() <= 128);
    let text = std::str::from_utf8(&formatted.bytes[..formatted.used]).unwrap();
    assert!(text.contains("name unavailable: allocation failed; original bytes="));
    assert!(text.contains("sha256="));
    assert!(!text.chars().any(char::is_control));
    println!(
        "fallible name attempts + probe returned null: {denied}; success lookup, unavailable clone and formatting allocated nothing"
    );

    println!(
        "global allocator denied all allocations: ErrorName={} ErrorKind={} Error={} bytes",
        size_of::<ErrorName>(),
        size_of::<ErrorKind>(),
        size_of::<Error>()
    );
    println!(
        "lookup Result={} Realtek Error={} Intel BT Error={} bytes",
        size_of::<Result<stela_drivers::firmware::Image<'static>, Error>>(),
        size_of::<stela_drivers::net::realtek::Error>(),
        size_of::<stela_drivers::usb::bluetooth::intel::Error>()
    );
}
