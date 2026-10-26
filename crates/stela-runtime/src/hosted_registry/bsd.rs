//! Shared BSD dispatcher selection and requirement metadata.
#[path = "../hosted/kernel/bsd/forwarded.rs"]
mod forwarded;

pub(crate) mod process {
    pub(crate) const CALLS: &[&str] = &[
        "exit",
        "execve",
        "__mac_execve",
        "posix_spawn",
        "fork",
        "vfork",
        "proc_info",
        "proc_info_extended_id",
    ];
}

pub(crate) mod memory {
    pub(crate) const CALLS: &[&str] = &[
        "mmap",
        "munmap",
        "mprotect",
        "madvise",
        "mincore",
        "shared_region_check_np",
        "shared_region_map_and_slide_2_np",
        "map_with_linking_np",
        "mremap_encrypted",
    ];
}

pub(crate) mod time {
    pub(crate) const CALLS: &[&str] = &[
        "gettimeofday",
        "settimeofday",
        "mach_eventlink_wait_until",
        "mach_eventlink_signal_wait_until",
        "kevent",
        "kevent64",
    ];
}

pub(crate) mod sysctl {
    pub(crate) const CALLS: &[&str] = &["sysctl", "sys_sysctlbyname"];

    pub(crate) const LIMIT: &str = "static ARM namespace metadata is published independently of value support; \
        unmodeled contents and dynamic driver variables are refused, and installed-system identity \
        is read-only, including for privileged writers";
}

pub(crate) mod codesign {
    pub(crate) const CALLS: &[&str] = &["csops", "csops_audittoken"];
}

pub(crate) mod thread {
    pub(crate) const CALLS: &[&str] = &[
        "bsdthread_register",
        "bsdthread_create",
        "bsdthread_terminate",
        "bsdthread_ctl",
    ];
}

pub(crate) mod workqueue {
    pub(crate) const CALLS: &[&str] = &[
        "workq_open",
        "workq_kernreturn",
        "kevent_qos",
        "kevent_id",
        "kqueue_workloop_ctl",
    ];
}

pub(crate) mod signal {
    pub(crate) const CALLS: &[&str] = &[
        "sigaction",
        "sigprocmask",
        "__pthread_sigmask",
        "__pthread_kill",
        "sigaltstack",
        "sigpending",
        "kill",
        "__sigwait",
        "__sigwait_nocancel",
        "__disable_threadsignal",
        "__pthread_markcancel",
        "__pthread_canceled",
        "setitimer",
        "getitimer",
        "sigreturn",
        "sigsuspend",
        "sigsuspend_nocancel",
        "pselect",
        "pselect_nocancel",
    ];
}

pub(crate) mod system {
    pub(crate) const CALLS: &[&str] = &[
        "ptrace",
        "swapon",
        "debug_syscall_reject",
        "sys_debug_syscall_reject_config",
        "__mach_bridge_remote_time",
        "objc_bp_assist_cfg_np",
        "kas_info",
        "stack_snapshot_with_config",
        "microstackshot",
        "grab_pgo_data",
        "sys_panic_with_data",
        "tracker_action",
        "sys_record_system_event",
        "sys_coalition_policy_set",
        "sys_coalition_policy_get",
        "graftdmg",
        "ungraftdmg",
        "oslog_coproc_reg",
        "oslog_coproc",
        "pid_suspend",
        "pid_resume",
        "pid_shutdown_sockets",
        "funmount",
        "pivot_root",
    ];
}

pub(crate) mod files {
    pub(crate) const CALLS: &[&str] = &[
        "umask",
        "umask_extended",
        "__pthread_chdir",
        "__pthread_fchdir",
    ];
}

pub(crate) mod aio {
    pub(crate) const CALLS: &[&str] = &[
        "aio_read",
        "aio_write",
        "aio_fsync",
        "lio_listio",
        "aio_error",
        "aio_return",
        "aio_suspend",
        "aio_suspend_nocancel",
        "aio_cancel",
    ];

    /// The forwarded calls that close a descriptor, which first wait for its
    /// asynchronous I/O (`fp_close_and_unlock` calling `_aio_close`).
    pub(crate) const CLOSING: &[&str] = &[
        "sys_close",
        "sys_close_nocancel",
        "guarded_close_np",
        "sys_dup2",
    ];

    /// The model the forwarding of [`CLOSING`] follows.
    pub(crate) const OVERLAY: &str = "a descriptor's queued asynchronous I/O is cancelled and its \
         running I/O waited for before it closes";
}

pub(crate) mod signatures {
    /// The calls whose code-signature commands are kept here.
    pub(crate) const CALLS: &[&str] = &["sys_fcntl", "sys_fcntl_nocancel"];

    pub(crate) const OVERLAY: &str =
        "file code signatures (F_ADDFILESIGS*, F_CHECK_LV, F_GETSIGSINFO) are kept here";
}

pub(crate) mod paths {
    pub(crate) const OVERLAY: &str = "absolute read-only lookups resolve under the guest roots, and reported paths are the guest's";

    /// Whether the guest-root lookups apply to the call `name`.
    pub(crate) fn overlays(name: &str) -> bool {
        shape(name).is_some() || matches!(name, "fsgetpath" | "fsgetpath_ext")
    }

    /// Which argument is the path and, for an open, which the flags.
    pub(crate) fn shape(name: &str) -> Option<(usize, Option<usize>)> {
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
}

pub(crate) mod additions {
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

    /// The additions `call` services.
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
             kqueue or network policy) fails with EINVAL and is reported",
        ),
        (
            "fchflagsat",
            "with an AT_ flag the flags are set through setattrlistat, which succeeds rather than \
             failing with ENOTSUP on a file system without file flags",
        ),
        (
            "fsctlat",
            "an FSOPT_RESOLVE_BENEATH lookup fails with EINVAL and is reported: the host's fsctl \
             does not confine a path beneath its starting directory",
        ),
        (
            "register_uexc_handler",
            "answers EPERM as without -enable_uexc; with it in the host's boot arguments it also \
             answers EPERM and is reported, as the handler would need guest exception delivery",
        ),
    ];

    /// Why an addition `call` does not service fails with `nosys`.
    pub(crate) const UNIMPLEMENTED: &str =
        "a 26A434 addition at a number the pinned catalog reserves: not implemented";

    /// The addition at `number`, if any.
    pub(crate) fn addition(number: u16) -> Option<&'static str> {
        ADDITIONS
            .iter()
            .find(|&&(entry, _)| entry == number)
            .map(|&(_, name)| name)
    }
}

/// Who services a BSD call: the host kernel unchanged, or one family of
/// the hosted kernel's own models.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Family {
    Forwarded,
    Process,
    Memory,
    Time,
    Sysctl,
    CodeSigning,
    Threads,
    Workqueue,
    Signals,
    System,
    Files,
    AsynchronousIo,
    Additions,
}

impl Family {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Forwarded => "forwarded",
            Self::Process => "process",
            Self::Memory => "memory",
            Self::Time => "time",
            Self::Sysctl => "sysctl",
            Self::CodeSigning => "code signing",
            Self::Threads => "threads",
            Self::Workqueue => "workqueue",
            Self::Signals => "signals",
            Self::System => "system",
            Self::Files => "descriptor table",
            Self::AsynchronousIo => "asynchronous I/O",
            Self::Additions => "26A434 additions",
        }
    }
}

/// The modeled families and the calls each services.
pub(crate) const MODELED: &[(Family, &[&str])] = &[
    (Family::Process, process::CALLS),
    (Family::Memory, memory::CALLS),
    (Family::Time, time::CALLS),
    (Family::Sysctl, sysctl::CALLS),
    (Family::CodeSigning, codesign::CALLS),
    (Family::Threads, thread::CALLS),
    (Family::Workqueue, workqueue::CALLS),
    (Family::Signals, signal::CALLS),
    (Family::System, system::CALLS),
    (Family::Files, files::CALLS),
    (Family::AsynchronousIo, aio::CALLS),
];

/// The family servicing the call `name`, or `None` for a call the hosted
/// kernel refuses.
pub(crate) fn family(name: &str) -> Option<Family> {
    if forwarded::forwarded(name) {
        return Some(Family::Forwarded);
    }
    MODELED
        .iter()
        .find(|(_, calls)| calls.contains(&name))
        .map(|&(family, _)| family)
}

/// The calls whose forwarding a model of part of their arguments
/// precedes, with that model: guest-root path resolution and file code
/// signatures.
pub(crate) fn overlay(name: &str) -> Option<&'static str> {
    if signatures::CALLS.contains(&name) {
        Some(signatures::OVERLAY)
    } else if aio::CLOSING.contains(&name) {
        Some(aio::OVERLAY)
    } else if paths::overlays(name) {
        Some(paths::OVERLAY)
    } else {
        None
    }
}

/// Calls serviced with a named limit: what of the arm64 kernel's contract
/// the hosted kernel does not provide.
pub(crate) const LIMITS: &[(&str, &str)] = &[
    ("sysctl", sysctl::LIMIT),
    ("sys_sysctlbyname", sysctl::LIMIT),
    (
        "mmap",
        "a host-forwarded call writing into an RWX MAP_JIT page meets the view of the thread \
         holding the execution lock, which the calling thread gives up while the hosted kernel \
         services the call",
    ),
    (
        "ptrace",
        "PT_STEP fails with EINVAL and is reported: the host would single-step the target's x86 \
         host thread",
    ),
    (
        "sigaction",
        "a caught signal reaches a thread waiting in a Mach trap or a hosted-kernel wait only \
         when the wait ends",
    ),
    (
        "sigprocmask",
        "another thread's host mask follows at its next kernel exit or time slice",
    ),
    (
        "posix_spawn",
        "binary preferences naming an x86-64 slice fail with EBADARCH and are reported: the \
         slice runs under Rosetta on Apple silicon, and running it natively would show it the \
         x86 host instead; an exception-port action fails with EINVAL",
    ),
    (
        "vfork",
        "the child has its own copy of memory, not the parent's",
    ),
    (
        "mremap_encrypted",
        "decrypting a range fails with ENOTSUP, as XNU without a text crypter, and is \
         reported: the text crypter is Apple silicon's FairPlay kernel extension, which the host does not provide for arm64 images; an address with no guest \
         file mapping at or above it can find one of the hosted runtime's own",
    ),
    (
        "kqueue_workloop_ctl",
        "a workloop's fixed priority, policy and CPU limit are not applied to its servicer, \
         which is scheduled by QoS; a work interval or a bound thread fails with EINVAL and \
         is reported",
    ),
];

/// Calls the hosted kernel refuses, stopping the run with the reason.
pub(crate) const REFUSED: &[(&str, &str)] = &[];
