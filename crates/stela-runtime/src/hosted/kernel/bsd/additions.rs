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
//! - `getumask()` reads the file-creation mask without changing it: the
//!   mask [`super::files`] records.
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
//! - `aio_readv(aiocb)` and `aio_writev(aiocb)` queue one vectored request
//!   of the process's asynchronous I/O ([`super::aio`]).
use super::{EFAULT, EINVAL, EPERM, Kernel, Outcome, Pe, files};
use crate::darwin::BsdReturnType;
use crate::hosted::forward;
use anyhow::{Result, bail};

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
    "aio_readv",
    "aio_writev",
];

/// Additions serviced with a named limit: what of the arm64 kernel's
/// contract the hosted kernel does not provide.
pub(crate) const LIMITS: &[(&str, &str)] = &[
    (
        "dup3",
        "O_CLOFORK of a descriptor the host cannot guard (other than a file, pipe, socket, \
         kqueue or network policy) stops the run",
    ),
    (
        "fchflagsat",
        "with an AT_ flag the flags are set through setattrlistat, which succeeds rather than \
         failing with ENOTSUP on a file system without file flags",
    ),
    (
        "fsctlat",
        "an FSOPT_RESOLVE_BENEATH lookup stops the run: the host's fsctl does not confine a \
         path beneath its starting directory",
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
        "pipe2" => {
            let _gate = kernel.process.files.gate();
            kernel.exclusive(|| pipe2(arguments[1] as u32))
        }
        "dup3" => {
            let _gate = kernel.process.files.gate();
            super::aio::duplicating(kernel, fd(arguments[0]), fd(arguments[1]));
            kernel.exclusive(|| dup3(fd(arguments[0]), fd(arguments[1]), arguments[2] as u32))
        }
        "getumask" => Ok(Outcome::value(kernel.process.files.mask())),
        "fchflagsat" => {
            kernel.page_in_arguments(&arguments[1..2])?;
            fchflagsat(
                fd(arguments[0]),
                arguments[1],
                arguments[2] as u32,
                arguments[3] as u32,
                kernel.thread_directory,
            )
        }
        "fsctlat" => {
            kernel.page_in_arguments(&arguments[1..4])?;
            fsctlat(
                fd(arguments[0]),
                arguments[1],
                arguments[2],
                arguments[3],
                arguments[4] as u32,
                kernel.thread_directory,
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
        "aio_readv" | "aio_writev" => Ok(super::aio::vectored(
            kernel,
            arguments[0],
            name == "aio_writev",
        )?),
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
/// `FD_CLOFORK`, the host's close-on-fork descriptor flag, which only
/// `change_fdguard_np` sets.
const FD_CLOFORK: u32 = 2;
/// The guard [`apply_flags`] adds and at once removes.
const TRANSIENT_GUARD: u64 = 0x5354_454c_4143_4c46;
const ENOTSUP: u64 = 45;
const AT_FDCWD: i32 = -2;
const AT_SYMLINK_NOFOLLOW: u32 = 0x20;
const AT_SYMLINK_NOFOLLOW_ANY: u32 = 0x800;
const AT_RESOLVE_BENEATH: u32 = 0x2000;
const FSOPT_NOFOLLOW: u32 = 0x1;
const FSOPT_NOFOLLOW_ANY: u32 = 0x800;
const FSOPT_RESOLVE_BENEATH: u32 = 0x1000;
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

/// Mark the host descriptor `fd`, new and unguarded, with the descriptor
/// and status flags of `flags`. Close-on-fork is the host's `FP_CLOFORK`,
/// which removing a guard sets from the flags it is given; until then the
/// guarded descriptor is close-on-exec and refuses duplication, which the
/// descriptor-flag gate ([`super::files`]) keeps every observer from
/// seeing. ENOTSUP: the host guards no descriptor of its kind.
fn apply_flags(fd: u64, flags: u32) -> std::result::Result<(), u64> {
    if flags & O_CLOFORK != 0 {
        let guard = TRANSIENT_GUARD.to_le_bytes();
        let guard = guard.as_ptr() as u64;
        host("change_fdguard_np", &[fd, 0, 0, guard, GUARD_REQUIRED, 0])?;
        let mut kept = FD_CLOFORK;
        if flags & O_CLOEXEC != 0 {
            kept |= FD_CLOEXEC as u32;
        }
        let kept = &raw mut kept as u64;
        host(
            "change_fdguard_np",
            &[fd, guard, GUARD_REQUIRED, 0, 0, kept],
        )?;
    } else if flags & O_CLOEXEC != 0 {
        host("sys_fcntl", &[fd, F_SETFD, FD_CLOEXEC])?;
    }
    if flags & O_NONBLOCK != 0 {
        let (status, _) = host("sys_fcntl", &[fd, F_GETFL])?;
        host("sys_fcntl", &[fd, F_SETFL, status | u64::from(O_NONBLOCK)])?;
    }
    Ok(())
}

/// `pipe2`: a host pipe whose ends then take the flags. Runs with guest
/// code stopped and the descriptor-flag gate held, so nothing sees an end
/// before its flags.
fn pipe2(flags: u32) -> Serviced {
    if flags & !(O_NONBLOCK | O_CLOEXEC | O_CLOFORK) != 0 {
        return Ok(Outcome::Error(EINVAL));
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
/// guest code stopped and the descriptor-flag gate held, so nothing sees
/// the copy before its flags.
fn dup3(from: i32, to: i32, flags: u32) -> Serviced {
    if from == to || flags & !(O_CLOEXEC | O_CLOFORK) != 0 {
        return Ok(Outcome::Error(EINVAL));
    }
    let copy = match host("sys_dup2", &[host_fd(from), host_fd(to)]) {
        Ok((copy, _)) => copy,
        Err(errno) => return Ok(Outcome::Error(errno)),
    };
    // `dup2` leaves the copy without FD_CLOEXEC and FD_CLOFORK.
    match apply_flags(copy, flags) {
        Ok(()) => Ok(Outcome::value(copy)),
        Err(ENOTSUP) => Err(Refusal(
            "O_CLOFORK of a descriptor the host cannot guard: its close-on-fork flag is set \
             only by removing a guard, which the host adds to files, pipes, sockets, kqueues \
             and network policies alone",
        )),
        Err(errno) => Ok(Outcome::Error(errno)),
    }
}

/// Whether the lookup of `path` from `fd` starts at the working directory:
/// `AT_FDCWD`, or an absolute path, for which `nameiat` ignores `fd`. An
/// unreadable path is left to the host call, which reports EFAULT.
fn from_working_directory(fd: i32, path: u64) -> bool {
    fd == AT_FDCWD || crate::hosted::memory::read(path, 1).is_none_or(|first| first[0] == b'/')
}

/// Run the lookup `call` makes from the directory descriptor `fd`
/// ([`files::at_directory`]).
fn from_directory(thread_directory: bool, fd: i32, call: impl FnOnce() -> Outcome) -> Serviced {
    match files::at_directory(thread_directory, fd, call) {
        Ok(outcome) => Ok(outcome),
        Err(Some(errno)) => Ok(Outcome::Error(errno)),
        Err(None) => Err(Refusal(files::UNRESTORABLE)),
    }
}

/// `fchflagsat`. Without AT_ flags it is the host's `chflags`, from the
/// directory descriptor for a relative path; with them, `setattrlistat`
/// setting `ATTR_CMN_FLAGS`, whose `nameiat` lookup takes the same
/// restrictions and whose authorization is `chflags`'s (`vnode_authattr`).
fn fchflagsat(fd: i32, path: u64, flags: u32, at_flags: u32, thread_directory: bool) -> Serviced {
    if at_flags & !(AT_SYMLINK_NOFOLLOW | AT_SYMLINK_NOFOLLOW_ANY | AT_RESOLVE_BENEATH) != 0 {
        return Ok(Outcome::Error(EINVAL));
    }
    if at_flags == 0 {
        let chflags = || outcome(host("chflags", &[path, u64::from(flags)]));
        if from_working_directory(fd, path) {
            return Ok(chflags());
        }
        return from_directory(thread_directory, fd, chflags);
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
    Ok(outcome(host(
        "setattrlistat",
        &[
            host_fd(fd),
            path,
            list.as_ptr() as u64,
            value.as_ptr() as u64,
            value.len() as u64,
            u64::from(options),
        ],
    )))
}

/// `fsctlat`: the host's `fsctl`, whose lookup honors `FSOPT_NOFOLLOW`,
/// `FSOPT_NOFOLLOW_ANY` and `FSOPT_UNIQUE`, from the directory descriptor
/// for a relative path.
fn fsctlat(
    fd: i32,
    path: u64,
    command: u64,
    data: u64,
    options: u32,
    thread_directory: bool,
) -> Serviced {
    if options & FSOPT_RESOLVE_BENEATH != 0 {
        return Err(Refusal(
            "FSOPT_RESOLVE_BENEATH: the host's fsctl does not confine a path beneath its \
             starting directory",
        ));
    }
    let fsctl = || outcome(host("fsctl", &[path, command, data, u64::from(options)]));
    if from_working_directory(fd, path) {
        return Ok(fsctl());
    }
    from_directory(thread_directory, fd, fsctl)
}

/// Whether the host descriptor `fd` holds `guard`: `fp_lookup_guarded`'s
/// answer, EBADF, EINVAL (unguarded) or EPERM (another guard). The host's
/// `change_fdguard_np` replaces a guard only when the given guard and
/// attributes are its own, so replacing each valid attribute set with
/// itself finds the match and changes nothing: the descriptor flags it
/// rewrites follow `GUARD_CLOSE`, which the replacement keeps.
pub(super) fn guard_matches(fd: i32, guard: u64) -> std::result::Result<(), u64> {
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

    /// The host's FD_CLOEXEC and FD_CLOFORK: `change_fdguard_np` reports
    /// them before refusing to leave an unguarded descriptor unguarded.
    fn guard_flags(fd: u64) -> u32 {
        let mut flags = 0u32;
        assert_eq!(
            host(
                "change_fdguard_np",
                &[fd, 0, 0, 0, 0, &raw mut flags as u64]
            ),
            Err(EINVAL)
        );
        flags
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
        let Ok(Outcome::Return(read, write)) = pipe2(O_CLOFORK) else {
            panic!("pipe2 failed");
        };
        for end in [read, write] {
            assert_eq!(guard_flags(end), FD_CLOFORK);
        }
        // A fork child does not have them.
        // SAFETY: the child only checks the descriptor and exits.
        let child = unsafe { libc::fork() };
        if child == 0 {
            // SAFETY: async-signal-safe calls only.
            unsafe {
                let open = libc::fcntl(read as i32, libc::F_GETFD) >= 0;
                libc::_exit(i32::from(open));
            }
        }
        let mut status = 0;
        // SAFETY: the child this test forked.
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert_eq!(libc::WEXITSTATUS(status), 0);
        close(read);
        close(write);
        let Ok(Outcome::Return(read, write)) = pipe2(O_CLOFORK | O_CLOEXEC) else {
            panic!("pipe2 failed");
        };
        assert_eq!(guard_flags(read), FD_CLOFORK | FD_CLOEXEC as u32);
        // The transient guard is gone: the ends close and duplicate.
        let copy = host("sys_dup", &[write]).unwrap().0;
        close(copy);
        close(read);
        close(write);
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
        assert_eq!(dup3(from, to, O_CLOFORK), Ok(Outcome::value(spare)));
        assert_eq!(guard_flags(spare), FD_CLOFORK);
        assert_eq!(dup3(from, to, 0), Ok(Outcome::value(spare)));
        assert_eq!(guard_flags(spare), 0);
        assert_eq!(dup3(-1, to, 0), Ok(Outcome::Error(EBADF)));
        close(spare);
    }

    #[test]
    fn fchflagsat_sets_flags_from_a_directory_descriptor() {
        let chflagsat = |fd, path, flags, at| fchflagsat(fd, path, flags, at, false).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("file");
        std::fs::write(&file, b"x").unwrap();
        std::os::unix::fs::symlink("file", directory.path().join("link")).unwrap();
        let handle = std::fs::File::open(directory.path()).unwrap();
        let dirfd = handle.as_raw_fd();
        let flags = |path: &std::path::Path| std::fs::symlink_metadata(path).unwrap().st_flags();
        let name = c"file";
        assert_eq!(
            chflagsat(dirfd, name.as_ptr() as u64, UF_HIDDEN, 0),
            Outcome::value(0)
        );
        assert_eq!(flags(&file), UF_HIDDEN);
        let link = c"link";
        assert_eq!(
            chflagsat(dirfd, link.as_ptr() as u64, UF_HIDDEN, AT_SYMLINK_NOFOLLOW),
            Outcome::value(0)
        );
        assert_eq!(flags(&directory.path().join("link")), UF_HIDDEN);
        // Following the link reaches the file.
        assert_eq!(
            chflagsat(dirfd, link.as_ptr() as u64, 0, 0),
            Outcome::value(0)
        );
        assert_eq!(flags(&file), 0);
        // No link anywhere on the path: a final link is the object itself,
        // one before it fails the lookup.
        assert_eq!(
            chflagsat(dirfd, link.as_ptr() as u64, 0, AT_SYMLINK_NOFOLLOW_ANY),
            Outcome::value(0)
        );
        assert_eq!(flags(&directory.path().join("link")), 0);
        std::os::unix::fs::symlink(".", directory.path().join("here")).unwrap();
        let through = c"here/file";
        assert_eq!(
            chflagsat(dirfd, through.as_ptr() as u64, 0, 0),
            Outcome::value(0)
        );
        assert!(matches!(
            chflagsat(dirfd, through.as_ptr() as u64, 0, AT_SYMLINK_NOFOLLOW_ANY),
            Outcome::Error(_)
        ));
        let outside = c"../outside";
        assert!(matches!(
            chflagsat(dirfd, outside.as_ptr() as u64, 0, AT_RESOLVE_BENEATH),
            Outcome::Error(_)
        ));
        let absolute = c_path(&file);
        assert_eq!(
            chflagsat(-1, absolute.as_ptr() as u64, UF_HIDDEN, 0),
            Outcome::value(0)
        );
        assert_eq!(flags(&file), UF_HIDDEN);
        assert_eq!(
            chflagsat(dirfd, name.as_ptr() as u64, 0, 0x10),
            Outcome::Error(EINVAL)
        );
        assert_eq!(
            chflagsat(-1, name.as_ptr() as u64, 0, AT_SYMLINK_NOFOLLOW),
            Outcome::Error(EBADF)
        );
    }

    #[test]
    fn fsctlat_is_fsctl_from_the_working_directory_or_a_directory() {
        // FSIOC_SYNC_VOLUME (`_IOW('A', 1, uint32_t)`) without waiting.
        const SYNC_VOLUME: u64 = 0x8004_4101;
        const ENOENT: u64 = 2;
        const ENOTDIR: u64 = 20;
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("file"), b"x").unwrap();
        let path = c_path(directory.path());
        let argument = 0u32;
        let data = &raw const argument as u64;
        let fsctl = |path: u64, options: u32| {
            outcome(host(
                "fsctl",
                &[path, SYNC_VOLUME, data, u64::from(options)],
            ))
        };
        let at = |fd, path: &std::ffi::CStr, options, own| {
            fsctlat(fd, path.as_ptr() as u64, SYNC_VOLUME, data, options, own).unwrap()
        };
        assert_eq!(
            at(AT_FDCWD, &path, 0, false),
            fsctl(path.as_ptr() as u64, 0)
        );
        assert_eq!(at(7, &path, 0, false), fsctl(path.as_ptr() as u64, 0));
        let handle = std::fs::File::open(directory.path()).unwrap();
        let dirfd = handle.as_raw_fd();
        let file = c_path(&directory.path().join("file"));
        assert_eq!(at(dirfd, c"file", 0, false), fsctl(file.as_ptr() as u64, 0));
        assert_eq!(at(dirfd, c"missing", 0, false), Outcome::Error(ENOENT));
        let plain = std::fs::File::open(directory.path().join("file")).unwrap();
        assert_eq!(
            at(plain.as_raw_fd(), c"file", 0, false),
            Outcome::Error(ENOTDIR)
        );
        assert_eq!(at(-1, c"file", 0, false), Outcome::Error(EBADF));
        // FSOPT_NOFOLLOW_ANY refuses a link anywhere on the path.
        std::os::unix::fs::symlink(".", directory.path().join("here")).unwrap();
        assert_eq!(
            at(dirfd, c"here/file", 0, false),
            fsctl(file.as_ptr() as u64, 0)
        );
        assert!(matches!(
            at(dirfd, c"here/file", FSOPT_NOFOLLOW_ANY, false),
            Outcome::Error(_)
        ));
        // The thread's own directory comes back; without one, the process's.
        let own = tempfile::tempdir().unwrap();
        let own_path = c_path(own.path());
        host("__pthread_chdir", &[own_path.as_ptr() as u64]).unwrap();
        assert_eq!(at(dirfd, c"file", 0, true), fsctl(file.as_ptr() as u64, 0));
        let here = std::fs::metadata(".").unwrap();
        let expected = std::fs::metadata(own.path()).unwrap();
        assert_eq!(here.st_ino(), expected.st_ino());
        host("__pthread_fchdir", &[u64::MAX]).unwrap();
        let process = std::fs::metadata(".").unwrap().st_ino();
        assert_eq!(at(dirfd, c"file", 0, false), fsctl(file.as_ptr() as u64, 0));
        assert_eq!(std::fs::metadata(".").unwrap().st_ino(), process);
        assert!(
            fsctlat(
                dirfd,
                c"file".as_ptr() as u64,
                0,
                0,
                FSOPT_RESOLVE_BENEATH,
                false
            )
            .is_err()
        );
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
    }
}
