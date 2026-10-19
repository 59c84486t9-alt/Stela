//! Read-only lookups of the guest's system files. The x86 host has no arm64
//! system image (no arm64e shared cache, libraries or tools), so the run
//! names guest roots holding one. A read-only lookup of an absolute path
//! that exists under a root resolves there, the first root first; every
//! other lookup, and every lookup that may create, write or truncate, is
//! the host's own. Relative paths follow the host working directory, and a
//! symbolic link inside a root resolves as the host kernel resolves it.
//! A path the kernel reports (`fcntl` `F_GETPATH`, `fsgetpath`) under a
//! root reads back as the guest path below it.
use super::{Call, Kernel, Outcome, forward};
use crate::hosted::memory;
use anyhow::Result;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// `MAXPATHLEN`.
const MAX_PATH: usize = 1024;
const O_ACCMODE: u64 = 0x3;
const O_RDONLY: u64 = 0;
const O_CREAT: u64 = 0x200;
const O_TRUNC: u64 = 0x400;
const F_GETPATH: u64 = 50;
const F_GETPATH_NOFIRMLINK: u64 = 102;

/// Which argument is the path and, for an open, which the flags.
fn shape(name: &str) -> Option<(usize, Option<usize>)> {
    Some(match name {
        "open" | "open_nocancel" => (0, Some(1)),
        "openat" | "openat_nocancel" => (1, Some(2)),
        "open_dprotected_np" => (0, Some(1)),
        "guarded_open_np" => (0, Some(3)),
        "stat" | "stat64" | "lstat" | "lstat64" | "access" | "readlink" | "getattrlist"
        | "statfs" | "statfs64" | "pathconf" | "getxattr" | "listxattr" | "stat_extended"
        | "lstat_extended" | "stat64_extended" | "lstat64_extended" => (0, None),
        "fstatat" | "fstatat64" | "faccessat" | "readlinkat" | "getattrlistat" => (1, None),
        _ => return None,
    })
}

/// `host` as the guest names it: the path below the root it lies in.
fn unroot(roots: &[PathBuf], host: &[u8]) -> Option<Vec<u8>> {
    roots.iter().find_map(|root| {
        let root = root.as_os_str().as_bytes();
        let root = root.strip_suffix(b"/").unwrap_or(root);
        let rest = host.strip_prefix(root)?;
        match rest.first() {
            None => Some(b"/".to_vec()),
            Some(b'/') => Some(rest.to_vec()),
            Some(_) => None,
        }
    })
}

/// Forward a call that writes a path to `buffer`, then name a rooted file
/// by its guest path. `fsgetpath` returns the length with its NUL.
fn reported_path(kernel: &mut Kernel, call: &Call, buffer: u64) -> Result<Option<Outcome>> {
    let outcome = forward(kernel, call)?;
    if !matches!(outcome, Outcome::Return(..)) {
        return Ok(Some(outcome));
    }
    let Some(host) = memory::read_string(buffer, MAX_PATH) else {
        return Ok(Some(outcome));
    };
    let Some(mut guest) = unroot(&kernel.process.roots, &host) else {
        return Ok(Some(outcome));
    };
    guest.push(0);
    if !memory::write(buffer, &guest) {
        return Ok(Some(Outcome::Error(super::EFAULT)));
    }
    Ok(Some(if call.entry.name.starts_with("fsgetpath") {
        Outcome::value(guest.len() as u64)
    } else {
        outcome
    }))
}

/// The first root holding `path`, as the host path to look up instead.
pub(super) fn resolve(roots: &[PathBuf], path: &[u8]) -> Option<PathBuf> {
    if path.first() != Some(&b'/') {
        return None;
    }
    let relative = Path::new(std::ffi::OsStr::from_bytes(&path[1..]));
    roots
        .iter()
        .map(|root| root.join(relative))
        .find(|candidate| std::fs::symlink_metadata(candidate).is_ok())
}

pub(super) fn call(kernel: &mut Kernel, call: &Call) -> Result<Option<Outcome>> {
    if kernel.process.roots.is_empty() {
        return Ok(None);
    }
    if matches!(call.entry.name, "sys_fcntl" | "sys_fcntl_nocancel")
        && matches!(
            call.argument(1) as u32 as u64,
            F_GETPATH | F_GETPATH_NOFIRMLINK
        )
    {
        return reported_path(kernel, call, call.argument(2));
    }
    if matches!(call.entry.name, "fsgetpath" | "fsgetpath_ext") {
        return reported_path(kernel, call, call.argument(0));
    }
    let Some((path_index, flags_index)) = shape(call.entry.name) else {
        return Ok(None);
    };
    if let Some(index) = flags_index {
        let flags = call.argument(index);
        if flags & O_ACCMODE != O_RDONLY || flags & (O_CREAT | O_TRUNC) != 0 {
            return Ok(None);
        }
    }
    let Some(path) = memory::read_string(call.argument(path_index), MAX_PATH) else {
        return Ok(None);
    };
    let Some(resolved) = resolve(&kernel.process.roots, &path) else {
        return Ok(None);
    };
    let Ok(host_path) = CString::new(resolved.as_os_str().as_bytes()) else {
        return Ok(None);
    };
    if kernel.trace {
        eprintln!(
            "stela: {} {} -> {}",
            call.entry.name,
            String::from_utf8_lossy(&path),
            resolved.display()
        );
    }
    let mut rooted = Call {
        entry: call.entry,
        arguments: call.arguments,
    };
    rooted.arguments[path_index] = host_path.as_ptr() as u64;
    let outcome = forward(kernel, &rooted)?;
    drop(host_path);
    Ok(Some(outcome))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_paths_resolve_under_the_first_root_holding_them() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(second.path().join("usr/lib")).unwrap();
        std::fs::write(second.path().join("usr/lib/dyld"), b"x").unwrap();
        std::fs::create_dir_all(first.path().join("usr")).unwrap();
        let roots = [first.path().to_owned(), second.path().to_owned()];
        assert_eq!(
            resolve(&roots, b"/usr/lib/dyld"),
            Some(second.path().join("usr/lib/dyld"))
        );
        assert_eq!(resolve(&roots, b"/usr"), Some(first.path().join("usr")));
        assert_eq!(resolve(&roots, b"/etc/hosts"), None);
        assert_eq!(resolve(&roots, b"usr/lib/dyld"), None);
        assert_eq!(shape("openat"), Some((1, Some(2))));
        assert_eq!(shape("write"), None);
        let host = second.path().join("usr/lib/dyld");
        assert_eq!(
            unroot(&roots, host.as_os_str().as_bytes()).as_deref(),
            Some(&b"/usr/lib/dyld"[..])
        );
        assert_eq!(
            unroot(&roots, second.path().as_os_str().as_bytes()).as_deref(),
            Some(&b"/"[..])
        );
        assert_eq!(unroot(&roots, b"/etc/hosts"), None);
    }
}
