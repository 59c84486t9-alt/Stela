//! System calls the 26A434 kernel (xnu-13432, unpublished) adds at numbers
//! the pinned xnu-12377 catalog reserves, found by the census of the
//! guest's `SVC #0x80` sites ([`crate::hosted::requirements`]). The x86-64
//! host kernel has none of them, so each is composed from host calls with
//! the arm64 kernel's contract, or stops the run naming it.
//!
//! Each contract is read from the 26A434 kernel itself: its `sysent` row
//! (argument count and return type) and handler, behind the plain
//! `libsystem_kernel` stubs, which pass every argument register unchanged
//! (`__pipe2` stores the two descriptors the kernel returns in X0 and X1,
//! as `pipe` does).
//!
//! - `pipe2(fds, flags)` accepts `O_NONBLOCK`, `O_CLOEXEC` and `O_CLOFORK`
//!   and fails anything else with EINVAL before allocating.
//! - `dup3(from, to, flags)` fails equal descriptors, then flags beyond
//!   `O_CLOEXEC` and `O_CLOFORK`, with EINVAL, and otherwise is `dup2`
//!   setting those descriptor flags on `to`.
//! - `fchflagsat(fd, path, flags, atflags)` accepts `AT_SYMLINK_NOFOLLOW`,
//!   `AT_SYMLINK_NOFOLLOW_ANY` and `AT_RESOLVE_BENEATH`, then looks `path`
//!   up from `fd` and sets the flags as `chflags` does.
//! - `getumask()` reads the file-creation mask without changing it.
//! - `fsctlat(fd, path, cmd, data, options)` is the body 26A434's `fsctl`
//!   now shares with `AT_FDCWD`; `options` selects no symbolic links
//!   (`FSOPT_NOFOLLOW`, `FSOPT_NOFOLLOW_ANY`) and further lookup
//!   restrictions (`FSOPT_RESOLVE_BENEATH`, `FSOPT_UNIQUE`), and no option
//!   bit is rejected.
//! - `guarded_ftruncate_np(fd, guard, length)` copies the guard in, then
//!   runs `ftruncate`'s checks, looking the descriptor up by its guard as
//!   `guarded_pwrite_np` does (`fp_lookup_guarded`: EINVAL for an unguarded
//!   descriptor, EPERM for another guard).
//! - `register_uexc_handler(start, size, handler, refcon)` fails with EPERM
//!   unless the kernel booted with `-enable_uexc`; then the caller also needs
//!   the `com.apple.private.uexc` entitlement.
//! - `aio_readv(aiocb)` and `aio_writev(aiocb)` queue one vectored request.
use super::{EFAULT, EINVAL, EPERM, Kernel, Outcome, Pe};
use crate::darwin::BsdReturnType;
use crate::hosted::forward;
use anyhow::{Result, bail};
use std::sync::atomic::{AtomicU64, Ordering};

/// Each addition's number and its libsystem_kernel stub's call name.
pub(crate) const ADDITIONS: &[(u16, &str)] = &[
    (148, "pipe2"),
    (149, "dup3"),
    (214, "fchflagsat"),
    (215, "getumask"),
    (246, "aio_readv"),
    (247, "aio_writev"),
    (249, "fsctlat"),
    (352, "guarded_ftruncate_np"),
    (519, "register_uexc_handler"),
];

/// The additions [`call`] services.
pub(crate) const CALLS: &[&str] = &[
    "pipe2",
    "dup3",
    "fchflagsat",
    "getumask",
    "fsctlat",
    "guarded_ftruncate_np",
    "register_uexc_handler",
];

/// Additions serviced with a named limit: what of the arm64 kernel's
/// contract the hosted kernel does not provide.
pub(crate) const LIMITS: &[(&str, &str)] = &[
    (
        "pipe2",
        "O_CLOFORK stops the run (the host has no close-on-fork flag), and O_CLOEXEC is set \
         after the host pipe, so a spawn another thread has in the host kernel then inherits \
         the ends",
    ),
    (
        "dup3",
        "O_CLOFORK stops the run (the host has no close-on-fork flag), and O_CLOEXEC is set \
         after the host dup2, so a spawn another thread has in the host kernel then inherits \
         the copy",
    ),
    (
        "fchflagsat",
        "a path relative to a directory descriptor, or with an AT_ flag, is set through \
         setattrlistat, which succeeds rather than failing with ENOTSUP on a file system \
         without file flags",
    ),
    (
        "getumask",
        "read by setting the mask with guest code stopped: a creating call another thread \
         has in the host kernel then can see the mask getumask last read",
    ),
    (
        "fsctlat",
        "a path relative to a directory descriptor, and the FSOPT_NOFOLLOW_ANY, \
         FSOPT_RESOLVE_BENEATH and FSOPT_UNIQUE lookups, stop the run: the host's fsctl \
         looks up from the working directory and honors FSOPT_NOFOLLOW alone",
    ),
    (
        "register_uexc_handler",
        "answers EPERM as without -enable_uexc; with it in the host's boot arguments the run \
         stops, as the handler would need guest exception delivery",
    ),
];

/// Why an addition [`call`] does not service stops the run.
pub(crate) const UNIMPLEMENTED: &str =
    "a 26A434 addition at a number the pinned catalog reserves: not implemented";

/// Why vectored AIO stops the run.
const VECTORED_AIO: &str = "a vectored request must complete under the forwarded aio_error, \
     aio_return, aio_suspend and aio_cancel, and the host's AIO queue tracks each aiocb itself \
     and takes no iovec list";

/// The addition at `number`, if any.
pub(crate) fn addition(number: u16) -> Option<&'static str> {
    ADDITIONS
        .iter()
        .find(|&&(entry, _)| entry == number)
        .map(|&(_, name)| name)
}

/// A request the hosted kernel cannot complete with the arm64 kernel's
/// contract: the run stops naming it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Refusal(&'static str);

type Serviced = std::result::Result<Outcome, Refusal>;

/// Service the addition `name` with its argument registers: its return
/// type and outcome.
pub(super) fn call(
    kernel: &mut Kernel,
    _pe: &mut Pe,
    number: u16,
    name: &'static str,
    arguments: &[u64; forward::MAX_ARGUMENTS],
) -> Result<(BsdReturnType, Outcome)> {
    let serviced = match name {
        "pipe2" => kernel.exclusive(|| pipe2(arguments[1] as u32)),
        "dup3" => {
            kernel.exclusive(|| dup3(fd(arguments[0]), fd(arguments[1]), arguments[2] as u32))
        }
        "getumask" => Ok(kernel.exclusive(getumask)),
        "fchflagsat" => {
            kernel.page_in_arguments(&arguments[1..2])?;
            Ok(fchflagsat(
                fd(arguments[0]),
                arguments[1],
                arguments[2] as u32,
                arguments[3] as u32,
            ))
        }
        "fsctlat" => {
            kernel.page_in_arguments(&arguments[1..4])?;
            fsctlat(
                fd(arguments[0]),
                arguments[1],
                arguments[2],
                arguments[3],
                arguments[4] as u32,
            )
        }
        "guarded_ftruncate_np" => {
            kernel.page_in_arguments(&arguments[1..2])?;
            Ok(guarded_ftruncate(
                fd(arguments[0]),
                arguments[1],
                arguments[2] as i64,
            ))
        }
        "register_uexc_handler" => register_uexc_handler(),
        "aio_readv" | "aio_writev" => Err(Refusal(VECTORED_AIO)),
        _ => Err(Refusal(UNIMPLEMENTED)),
    };
    match serviced {
        Ok(outcome) => Ok((BsdReturnType::Int, outcome)),
        Err(Refusal(reason)) => bail!(
            "BSD system call {name} ({number}) is not implemented by the hosted kernel: \
             {reason} (arguments {arguments:x?})"
        ),
    }
}

const O_NONBLOCK: u32 = 0x4;
const O_CLOEXEC: u32 = 0x0100_0000;
/// `O_CLOFORK`, a kernel-private open flag the 26A434 calls accept.
const O_CLOFORK: u32 = 0x0800_0000;
const F_SETFD: u64 = 2;
const F_GETFL: u64 = 3;
const F_SETFL: u64 = 4;
const FD_CLOEXEC: u64 = 1;
const AT_FDCWD: i32 = -2;
const AT_SYMLINK_NOFOLLOW: u32 = 0x20;
const AT_SYMLINK_NOFOLLOW_ANY: u32 = 0x800;
const AT_RESOLVE_BENEATH: u32 = 0x2000;
const FSOPT_NOFOLLOW: u32 = 0x1;
const FSOPT_NOFOLLOW_ANY: u32 = 0x800;
const FSOPT_RESOLVE_BENEATH: u32 = 0x1000;
const FSOPT_UNIQUE: u32 = 0x2000;
const ATTR_BIT_MAP_COUNT: u16 = 5;
const ATTR_CMN_FLAGS: u32 = 0x0004_0000;
const RLIMIT_FSIZE: u64 = 1;
/// `GUARD_DUP`, which every guard holds (`GUARD_REQUIRED`), and the
/// optional `GUARD_CLOSE`, `GUARD_SOCKET_IPC`, `GUARD_FILEPORT` and
/// `GUARD_WRITE` (`bsd/sys/guarded.h`).
const GUARD_REQUIRED: u64 = 1 << 1;
const GUARD_OPTIONAL: [u64; 4] = [1 << 0, 1 << 2, 1 << 3, 1 << 4];
/// The boot argument that enables user exception handlers.
const ENABLE_UEXC: &[u8] = b"-enable_uexc";

/// A descriptor argument: an `int` in the low half of its register.
fn fd(register: u64) -> i32 {
    register as u32 as i32
}

/// A descriptor as the host call's argument register.
fn host_fd(fd: i32) -> u64 {
    i64::from(fd) as u64
}

/// The host call `name` of the pinned catalog: X0 and X1, or the errno.
fn host(name: &str, arguments: &[u64]) -> std::result::Result<(u64, u64), u64> {
    let returned = forward::bsd(super::number_of(name), arguments);
    if returned.carry {
        Err(returned.rax)
    } else {
        Ok((returned.rax, returned.rdx))
    }
}

fn outcome(result: std::result::Result<(u64, u64), u64>) -> Outcome {
    match result {
        Ok((first, second)) => Outcome::Return(first, second),
        Err(errno) => Outcome::Error(errno),
    }
}

/// Mark the host descriptor `fd` with the descriptor and status flags of
/// `flags` that the host has.
fn apply_flags(fd: u64, flags: u32) -> std::result::Result<(), u64> {
    if flags & O_CLOEXEC != 0 {
        host("sys_fcntl", &[fd, F_SETFD, FD_CLOEXEC])?;
    }
    if flags & O_NONBLOCK != 0 {
        let (status, _) = host("sys_fcntl", &[fd, F_GETFL])?;
        host("sys_fcntl", &[fd, F_SETFL, status | u64::from(O_NONBLOCK)])?;
    }
    Ok(())
}

/// `pipe2`: a host pipe whose ends then take the flags. Runs with guest
/// code stopped, so no guest thread sees an end before its flags.
fn pipe2(flags: u32) -> Serviced {
    if flags & !(O_NONBLOCK | O_CLOEXEC | O_CLOFORK) != 0 {
        return Ok(Outcome::Error(EINVAL));
    }
    if flags & O_CLOFORK != 0 {
        return Err(Refusal(
            "O_CLOFORK: the host kernel has no close-on-fork descriptor flag",
        ));
    }
    let (read, write) = match host("pipe", &[]) {
        Ok(ends) => ends,
        Err(errno) => return Ok(Outcome::Error(errno)),
    };
    if let Err(errno) = apply_flags(read, flags).and_then(|()| apply_flags(write, flags)) {
        for end in [read, write] {
            let _ = host("sys_close", &[end]);
        }
        return Ok(Outcome::Error(errno));
    }
    Ok(Outcome::Return(read, write))
}

/// `dup3`: `dup2`, whose copy then takes the descriptor flags. Runs with
/// guest code stopped, so no guest thread sees the copy before its flags.
fn dup3(from: i32, to: i32, flags: u32) -> Serviced {
    if from == to || flags & !(O_CLOEXEC | O_CLOFORK) != 0 {
        return Ok(Outcome::Error(EINVAL));
    }
    if flags & O_CLOFORK != 0 {
        return Err(Refusal(
            "O_CLOFORK: the host kernel has no close-on-fork descriptor flag",
        ));
    }
    let copy = match host("sys_dup2", &[host_fd(from), host_fd(to)]) {
        Ok((copy, _)) => copy,
        Err(errno) => return Ok(Outcome::Error(errno)),
    };
    // `dup2` leaves the copy without FD_CLOEXEC.
    Ok(match apply_flags(copy, flags & O_CLOEXEC) {
        Ok(()) => Outcome::value(copy),
        Err(errno) => Outcome::Error(errno),
    })
}

/// The mask the last `getumask` read, the value it next sets: while the
/// mask is unchanged, setting it changes nothing.
static LAST_UMASK: AtomicU64 = AtomicU64::new(0o022);

/// `getumask`: the host's `umask` returns the mask it replaces, so set it
/// to the last mask read and restore it when that differs. Runs with guest
/// code stopped.
fn getumask() -> Outcome {
    let guess = LAST_UMASK.load(Ordering::Relaxed);
    let (mask, _) = match host("umask", &[guess]) {
        Ok(mask) => mask,
        Err(errno) => return Outcome::Error(errno),
    };
    if mask != guess {
        let _ = host("umask", &[mask]);
        LAST_UMASK.store(mask, Ordering::Relaxed);
    }
    Outcome::value(mask)
}

/// Whether the lookup of `path` from `fd` starts at the working directory:
/// `AT_FDCWD`, or an absolute path, for which `nameiat` ignores `fd`. An
/// unreadable path is left to the host call, which reports EFAULT.
fn from_working_directory(fd: i32, path: u64) -> bool {
    fd == AT_FDCWD || crate::hosted::memory::read(path, 1).is_none_or(|first| first[0] == b'/')
}

/// `fchflagsat`. A lookup from the working directory without AT_ flags is
/// the host's `chflags`; any other is `setattrlistat` setting
/// `ATTR_CMN_FLAGS`, whose `nameiat` lookup takes the same restrictions
/// and whose authorization is `chflags`'s (`vnode_authattr`).
fn fchflagsat(fd: i32, path: u64, flags: u32, at_flags: u32) -> Outcome {
    if at_flags & !(AT_SYMLINK_NOFOLLOW | AT_SYMLINK_NOFOLLOW_ANY | AT_RESOLVE_BENEATH) != 0 {
        return Outcome::Error(EINVAL);
    }
    if at_flags == 0 && from_working_directory(fd, path) {
        return outcome(host("chflags", &[path, u64::from(flags)]));
    }
    let mut options = 0;
    for (at, option) in [
        (AT_SYMLINK_NOFOLLOW, FSOPT_NOFOLLOW),
        (AT_SYMLINK_NOFOLLOW_ANY, FSOPT_NOFOLLOW_ANY),
        (AT_RESOLVE_BENEATH, FSOPT_RESOLVE_BENEATH),
    ] {
        if at_flags & at != 0 {
            options |= option;
        }
    }
    // `struct attrlist`: the bitmap count, a reserved half and the common,
    // volume, directory, file and fork groups.
    let mut list = [0u8; 24];
    list[..2].copy_from_slice(&ATTR_BIT_MAP_COUNT.to_le_bytes());
    list[4..8].copy_from_slice(&ATTR_CMN_FLAGS.to_le_bytes());
    let value = flags.to_le_bytes();
    outcome(host(
        "setattrlistat",
        &[
            host_fd(fd),
            path,
            list.as_ptr() as u64,
            value.as_ptr() as u64,
            value.len() as u64,
            u64::from(options),
        ],
    ))
}

/// `fsctlat`: the host's `fsctl` for a lookup from the working directory
/// that it resolves alike.
fn fsctlat(fd: i32, path: u64, command: u64, data: u64, options: u32) -> Serviced {
    if options & (FSOPT_NOFOLLOW_ANY | FSOPT_RESOLVE_BENEATH | FSOPT_UNIQUE) != 0 {
        return Err(Refusal(
            "FSOPT_NOFOLLOW_ANY, FSOPT_RESOLVE_BENEATH and FSOPT_UNIQUE lookups: the host's \
             fsctl honors FSOPT_NOFOLLOW alone",
        ));
    }
    if !from_working_directory(fd, path) {
        return Err(Refusal(
            "a path relative to a directory descriptor: the host has no fsctlat, and its \
             fsctl looks up from the working directory",
        ));
    }
    Ok(outcome(host(
        "fsctl",
        &[path, command, data, u64::from(options)],
    )))
}

/// Whether the host descriptor `fd` holds `guard`: `fp_lookup_guarded`'s
/// answer, EBADF, EINVAL (unguarded) or EPERM (another guard). The host's
/// `change_fdguard_np` replaces a guard only when the given guard and
/// attributes are its own, so replacing each valid attribute set with
/// itself finds the match and changes nothing: the descriptor flags it
/// rewrites follow `GUARD_CLOSE`, which the replacement keeps.
fn guard_matches(fd: i32, guard: u64) -> std::result::Result<(), u64> {
    let guard = guard.to_le_bytes();
    let pointer = guard.as_ptr() as u64;
    for set in 0..1u64 << GUARD_OPTIONAL.len() {
        let attributes = GUARD_OPTIONAL
            .iter()
            .enumerate()
            .filter(|&(bit, _)| set & 1 << bit != 0)
            .fold(GUARD_REQUIRED, |attributes, (_, flag)| attributes | flag);
        match host(
            "change_fdguard_np",
            &[host_fd(fd), pointer, attributes, pointer, attributes, 0],
        ) {
            Ok(_) => return Ok(()),
            Err(EPERM) => {}
            Err(errno) => return Err(errno),
        }
    }
    Err(EPERM)
}

/// `guarded_ftruncate_np`: `ftruncate`'s checks in its order, the length's
/// before the descriptor's. A length the host's `ftruncate` refuses before
/// its lookup (negative, or past RLIMIT_FSIZE, which also raises SIGXFSZ)
/// is its answer; otherwise the guard is checked and the host truncates.
fn guarded_ftruncate(fd: i32, guard: u64, length: i64) -> Outcome {
    let Some(guard) = crate::hosted::memory::read_u64(guard) else {
        return Outcome::Error(EFAULT);
    };
    let truncate = || outcome(host("ftruncate", &[host_fd(fd), length as u64]));
    let mut limit = [0u64; 2];
    if let Err(errno) = host("getrlimit", &[RLIMIT_FSIZE, limit.as_mut_ptr() as u64]) {
        return Outcome::Error(errno);
    }
    if length < 0 || length as u64 > limit[0] {
        return truncate();
    }
    match guard_matches(fd, guard) {
        Ok(()) => truncate(),
        Err(errno) => Outcome::Error(errno),
    }
}

/// Whether the boot arguments enable user exception handlers: a
/// `-enable_uexc` flag, alone or with a value.
fn enables_uexc(boot_arguments: &[u8]) -> bool {
    boot_arguments
        .split(|byte| byte.is_ascii_whitespace())
        .any(|argument| argument.split(|&byte| byte == b'=').next() == Some(ENABLE_UEXC))
}

/// The host kernel's boot arguments (`kern.bootargs`), the kernel the
/// guest's `kern.*` variables describe.
fn boot_arguments() -> Vec<u8> {
    let name = b"kern.bootargs";
    let mut buffer = vec![0u8; 1024];
    let mut length = buffer.len() as u64;
    match host(
        "sys_sysctlbyname",
        &[
            name.as_ptr() as u64,
            name.len() as u64,
            buffer.as_mut_ptr() as u64,
            &raw mut length as u64,
            0,
            0,
        ],
    ) {
        Ok(_) => {
            buffer.truncate(length as usize);
            buffer.retain(|&byte| byte != 0);
            buffer
        }
        Err(_) => Vec::new(),
    }
}

/// `register_uexc_handler`: without `-enable_uexc` the kernel answers
/// EPERM before reading any argument.
fn register_uexc_handler() -> Serviced {
    if enables_uexc(&boot_arguments()) {
        return Err(Refusal(
            "-enable_uexc is set: a registered handler needs the com.apple.private.uexc \
             entitlement check and delivery of guest exceptions to it, which the hosted \
             kernel does not implement",
        ));
    }
    Ok(Outcome::Error(EPERM))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::os::fd::AsRawFd;
    use std::os::macos::fs::MetadataExt;
    use std::os::unix::ffi::OsStrExt;

    const EBADF: u64 = 9;
    const F_GETFD: u64 = 1;
    const UF_HIDDEN: u32 = 0x8000;
    const O_RDWR: u64 = 0x2;
    const O_CREAT: u64 = 0x200;
    const GUARD_CLOSE: u64 = 1 << 0;

    fn descriptor_flags(fd: u64) -> u64 {
        host("sys_fcntl", &[fd, F_GETFD]).unwrap().0
    }

    fn status_flags(fd: u64) -> u64 {
        host("sys_fcntl", &[fd, F_GETFL]).unwrap().0
    }

    fn close(fd: u64) {
        host("sys_close", &[fd]).unwrap();
    }

    fn c_path(path: &std::path::Path) -> CString {
        CString::new(path.as_os_str().as_bytes()).unwrap()
    }

    #[test]
    fn additions_lie_at_reserved_catalog_numbers() {
        for &(number, name) in ADDITIONS {
            assert!(
                crate::darwin::catalog::entry(number)
                    .is_none_or(|entry| entry.prototype().is_none()),
                "{name} ({number})"
            );
        }
        assert!(
            CALLS
                .iter()
                .all(|call| ADDITIONS.iter().any(|&(_, name)| name == *call))
        );
        assert!(LIMITS.iter().all(|(call, _)| CALLS.contains(call)));
        assert_eq!(addition(148), Some("pipe2"));
        assert_eq!(addition(147), None);
    }

    #[test]
    fn pipe2_sets_the_flags_on_both_ends_and_refuses_unknown_ones() {
        let Ok(Outcome::Return(read, write)) = pipe2(O_CLOEXEC | O_NONBLOCK) else {
            panic!("pipe2 failed");
        };
        for end in [read, write] {
            assert_eq!(descriptor_flags(end) & FD_CLOEXEC, FD_CLOEXEC);
            assert_ne!(status_flags(end) & u64::from(O_NONBLOCK), 0);
        }
        let byte = [0x5au8];
        host("write", &[write, byte.as_ptr() as u64, 1]).unwrap();
        let mut back = [0u8];
        host("read", &[read, back.as_mut_ptr() as u64, 1]).unwrap();
        assert_eq!(back, byte);
        // Nonblocking: an empty pipe does not wait.
        assert_eq!(
            host("read", &[read, back.as_mut_ptr() as u64, 1]),
            Err(super::super::EAGAIN)
        );
        close(read);
        close(write);
        let Ok(Outcome::Return(read, write)) = pipe2(0) else {
            panic!("pipe2 failed");
        };
        assert_eq!(descriptor_flags(read) & FD_CLOEXEC, 0);
        assert_eq!(status_flags(write) & u64::from(O_NONBLOCK), 0);
        close(read);
        close(write);
        assert_eq!(pipe2(0x2), Ok(Outcome::Error(EINVAL)));
        assert!(pipe2(O_CLOFORK).is_err());
    }

    #[test]
    fn dup3_copies_with_the_flags_and_refuses_equal_descriptors() {
        let file = tempfile::tempfile().unwrap();
        let from = file.as_raw_fd();
        let Ok(Outcome::Return(spare, _)) = pipe2(0) else {
            panic!("pipe2 failed");
        };
        let to = spare as i32;
        assert_eq!(dup3(from, to, O_CLOEXEC), Ok(Outcome::value(spare)));
        assert_eq!(descriptor_flags(spare) & FD_CLOEXEC, FD_CLOEXEC);
        assert_eq!(dup3(from, to, 0), Ok(Outcome::value(spare)));
        assert_eq!(descriptor_flags(spare) & FD_CLOEXEC, 0);
        assert_eq!(dup3(from, from, 0), Ok(Outcome::Error(EINVAL)));
        assert_eq!(dup3(from, to, O_NONBLOCK), Ok(Outcome::Error(EINVAL)));
        assert!(dup3(from, to, O_CLOFORK).is_err());
        assert_eq!(dup3(-1, to, 0), Ok(Outcome::Error(EBADF)));
        close(spare);
    }

    #[test]
    fn getumask_reads_the_mask_children_inherit() {
        let Outcome::Return(mask, 0) = getumask() else {
            panic!("getumask failed");
        };
        assert_eq!(getumask(), Outcome::value(mask));
        let shell = std::process::Command::new("/bin/sh")
            .args(["-c", "umask"])
            .output()
            .unwrap();
        let printed = String::from_utf8(shell.stdout).unwrap();
        assert_eq!(u64::from_str_radix(printed.trim(), 8).unwrap(), mask);
    }

    #[test]
    fn fchflagsat_sets_flags_from_a_directory_descriptor() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("file");
        std::fs::write(&file, b"x").unwrap();
        std::os::unix::fs::symlink("file", directory.path().join("link")).unwrap();
        let handle = std::fs::File::open(directory.path()).unwrap();
        let dirfd = handle.as_raw_fd();
        let flags = |path: &std::path::Path| std::fs::symlink_metadata(path).unwrap().st_flags();
        let name = c"file";
        assert_eq!(
            fchflagsat(dirfd, name.as_ptr() as u64, UF_HIDDEN, 0),
            Outcome::value(0)
        );
        assert_eq!(flags(&file), UF_HIDDEN);
        let link = c"link";
        assert_eq!(
            fchflagsat(dirfd, link.as_ptr() as u64, UF_HIDDEN, AT_SYMLINK_NOFOLLOW),
            Outcome::value(0)
        );
        assert_eq!(flags(&directory.path().join("link")), UF_HIDDEN);
        // Following the link reaches the file.
        assert_eq!(
            fchflagsat(dirfd, link.as_ptr() as u64, 0, 0),
            Outcome::value(0)
        );
        assert_eq!(flags(&file), 0);
        // No link anywhere on the path: a final link is the object itself,
        // one before it fails the lookup.
        assert_eq!(
            fchflagsat(dirfd, link.as_ptr() as u64, 0, AT_SYMLINK_NOFOLLOW_ANY),
            Outcome::value(0)
        );
        assert_eq!(flags(&directory.path().join("link")), 0);
        std::os::unix::fs::symlink(".", directory.path().join("here")).unwrap();
        let through = c"here/file";
        assert_eq!(
            fchflagsat(dirfd, through.as_ptr() as u64, 0, 0),
            Outcome::value(0)
        );
        assert!(matches!(
            fchflagsat(dirfd, through.as_ptr() as u64, 0, AT_SYMLINK_NOFOLLOW_ANY),
            Outcome::Error(_)
        ));
        let outside = c"../outside";
        assert!(matches!(
            fchflagsat(dirfd, outside.as_ptr() as u64, 0, AT_RESOLVE_BENEATH),
            Outcome::Error(_)
        ));
        let absolute = c_path(&file);
        assert_eq!(
            fchflagsat(-1, absolute.as_ptr() as u64, UF_HIDDEN, 0),
            Outcome::value(0)
        );
        assert_eq!(flags(&file), UF_HIDDEN);
        assert_eq!(
            fchflagsat(dirfd, name.as_ptr() as u64, 0, 0x10),
            Outcome::Error(EINVAL)
        );
        assert_eq!(
            fchflagsat(-1, name.as_ptr() as u64, 0, AT_SYMLINK_NOFOLLOW),
            Outcome::Error(EBADF)
        );
    }

    #[test]
    fn fsctlat_is_fsctl_from_the_working_directory() {
        // FSIOC_SYNC_VOLUME (`_IOW('A', 1, uint32_t)`) without waiting.
        const SYNC_VOLUME: u64 = 0x8004_4101;
        let directory = tempfile::tempdir().unwrap();
        let path = c_path(directory.path());
        let options = 0u32;
        let argument = 0u32;
        let data = &raw const argument as u64;
        assert_eq!(
            fsctlat(AT_FDCWD, path.as_ptr() as u64, SYNC_VOLUME, data, 0),
            Ok(outcome(host(
                "fsctl",
                &[path.as_ptr() as u64, SYNC_VOLUME, data, 0]
            )))
        );
        assert_eq!(
            fsctlat(7, path.as_ptr() as u64, 0, 0, options),
            Ok(outcome(host("fsctl", &[path.as_ptr() as u64, 0, 0, 0])))
        );
        let relative = c"file";
        assert!(fsctlat(7, relative.as_ptr() as u64, 0, 0, 0).is_err());
        assert!(fsctlat(AT_FDCWD, path.as_ptr() as u64, 0, 0, FSOPT_NOFOLLOW_ANY).is_err());
    }

    #[test]
    fn guarded_ftruncate_checks_the_guard_after_the_length() {
        let directory = tempfile::tempdir().unwrap();
        let path = c_path(&directory.path().join("guarded"));
        let guard = 0x5354_454c_4100_0001u64;
        let guard_bytes = guard.to_le_bytes();
        let attributes = GUARD_REQUIRED | GUARD_CLOSE;
        let (fd, _) = host(
            "guarded_open_np",
            &[
                path.as_ptr() as u64,
                guard_bytes.as_ptr() as u64,
                attributes,
                O_RDWR | O_CREAT | u64::from(O_CLOEXEC),
                0o600,
            ],
        )
        .unwrap();
        let fd = fd as i32;
        let guard_pointer = guard_bytes.as_ptr() as u64;
        let size = || {
            std::fs::metadata(std::ffi::OsStr::from_bytes(path.as_bytes()))
                .unwrap()
                .len()
        };
        assert_eq!(guarded_ftruncate(fd, guard_pointer, 5), Outcome::value(0));
        assert_eq!(size(), 5);
        let other = (guard + 1).to_le_bytes();
        assert_eq!(
            guarded_ftruncate(fd, other.as_ptr() as u64, 1),
            Outcome::Error(EPERM)
        );
        assert_eq!(size(), 5);
        assert_eq!(
            guarded_ftruncate(fd, guard_pointer, -1),
            Outcome::Error(EINVAL)
        );
        assert_eq!(guarded_ftruncate(fd, 0, 1), Outcome::Error(EFAULT));
        assert_eq!(
            guarded_ftruncate(-1, guard_pointer, 1),
            Outcome::Error(EBADF)
        );
        // The guard is unchanged: the guarded close still takes it.
        host("guarded_close_np", &[host_fd(fd), guard_pointer]).unwrap();
        let unguarded = tempfile::tempfile().unwrap();
        assert_eq!(
            guarded_ftruncate(unguarded.as_raw_fd(), guard_pointer, 1),
            Outcome::Error(EINVAL)
        );
    }

    #[test]
    fn uexc_handlers_need_the_boot_argument() {
        assert!(enables_uexc(b"-v -enable_uexc debug=0x14e"));
        assert!(enables_uexc(b"-enable_uexc=1"));
        assert!(!enables_uexc(b"-enable_uexcx -v"));
        assert!(!enables_uexc(b""));
        if !enables_uexc(&boot_arguments()) {
            assert_eq!(register_uexc_handler(), Ok(Outcome::Error(EPERM)));
        }
        assert!(LIMITS.iter().all(|(call, _)| !call.starts_with("aio_")));
        assert!(!CALLS.contains(&"aio_readv"));
    }
}
