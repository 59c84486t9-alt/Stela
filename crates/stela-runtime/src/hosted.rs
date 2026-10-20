//! The hosted Darwin process: an unchanged arm64e Mach-O executable runs in
//! this x86-64 macOS process above the host's kernel, as the arm64 XNU
//! kernel would run it.
//!
//! A guest thread is a `Machine` PE at EL0 over an identity stage 1, so
//! guest addresses are this process's addresses and translated code reaches
//! guest memory directly. Exec is performed here as `execve` performs it:
//! the commpage, the empty shared region of the first process to use the
//! cache (dyld maps and the kernel slides it), the executable and its
//! unchanged dynamic linker at their slides, and the main stack with the
//! kernel's argument block. The main thread's PE enters dyld at its entry
//! point; every exception a thread takes to EL1 stops at the vector, where
//! [`kernel`] services it as XNU's exception handlers do and returns
//! through ERET. Each guest thread is a host thread with its own PE
//! (`threads`). The run ends at the guest's `exit`.
use crate::machine::Chip;
use anyhow::{Context as _, Result, bail, ensure};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use stela_compiler::TargetCpu;

pub mod activation;
pub mod commpage;
pub(crate) mod darwin;
pub mod exec;
pub mod features;
pub mod forward;
pub mod hardware;
pub mod host;
pub mod kernel;
pub mod memory;
pub mod pe;
pub mod requirements;
pub mod shared_region;
pub mod tables;
mod threads;

pub use kernel::{Executable, Signature};

/// How the guest process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Termination {
    /// `exit(status)`: the host process exits with the status's low byte.
    Exited(i32),
    /// The default action of a signal the hosted kernel took for it (a
    /// synchronous exception's, or one recorded for a handler the action
    /// no longer names): the host process ends by the same signal.
    Signaled(i32),
}

impl Termination {
    /// End the host process as the guest process ended, so that its
    /// parent's `wait` sees the same status.
    pub fn end_host_process(self) -> ! {
        match self {
            Self::Exited(status) => std::process::exit(status & 0xff),
            Self::Signaled(signal) => {
                let set: libc::sigset_t = 1 << (signal - 1);
                // SAFETY: the default disposition, unblocked, raised on
                // this thread.
                unsafe {
                    libc::signal(signal, libc::SIG_DFL);
                    libc::pthread_sigmask(libc::SIG_UNBLOCK, &raw const set, core::ptr::null_mut());
                    libc::raise(signal);
                }
                // A signal whose default does not end the process.
                std::process::exit(128 + signal)
            }
        }
    }
}

/// Whether SIGPIPE was ignored when this host process was exec'd, before
/// the Rust runtime's own start-up ignored it: exec keeps an ignored
/// signal ignored (`execsigs`), so the guest inherits it.
static SIGPIPE_IGNORED_AT_EXEC: AtomicBool = AtomicBool::new(false);

extern "C" fn record_sigpipe_at_exec() {
    // SAFETY: a query of the disposition into this frame.
    let mut current: libc::sigaction = unsafe { core::mem::zeroed() };
    unsafe { libc::sigaction(libc::SIGPIPE, core::ptr::null(), &raw mut current) };
    SIGPIPE_IGNORED_AT_EXEC.store(current.sa_sigaction == libc::SIG_IGN, Ordering::SeqCst);
}

/// A Mach-O initializer, which dyld runs before `main`.
#[used]
#[unsafe(link_section = "__DATA,__mod_init_func")]
static RECORD_SIGPIPE_AT_EXEC: extern "C" fn() = record_sigpipe_at_exec;

/// The dynamic linker `LC_LOAD_DYLINKER` names.
#[derive(Debug, Clone)]
pub struct Dylinker {
    pub image: exec::Image,
    /// Its unslid `LC_UNIXTHREAD` entry point.
    pub entry: u64,
}

/// Everything exec needs for one process.
#[derive(Debug, Clone)]
pub struct Launch {
    pub chip: Chip,
    pub executable: exec::Image,
    /// The image's slice offset in its file, where its Mach header lies.
    pub slice_offset: u64,
    /// The slice's CPU subtype, capability bits included: whether exec
    /// leaves user JOP enabled ([`pe::UserJop::of_subtype`]).
    pub cpu_subtype: u32,
    /// The path exec was asked to run, as `executable_path=` reports it.
    pub executable_path: Vec<u8>,
    pub signature: Signature,
    pub dylinker: Dylinker,
    /// Guest system roots, in order, that absolute paths the guest looks up
    /// read-only resolve under before the host's own file system.
    pub roots: Vec<std::path::PathBuf>,
    /// The host command that activates a new guest image in this process
    /// for `execve`: it is run with `--argv0=ARGV0 -- PATH ARGS...`
    /// appended and the new environment.
    pub reexec: Vec<std::ffi::OsString>,
    pub argv: Vec<Vec<u8>>,
    pub environment: Vec<Vec<u8>>,
    pub trace: bool,
}

/// What a run produced.
#[derive(Debug, Clone)]
pub struct Report {
    pub termination: Termination,
    pub calls: BTreeMap<&'static str, u64>,
    pub slid_pages: u64,
}

/// The x86 host's `mach_absolute_time` must count nanoseconds: the guest's
/// 24 MHz counter is derived from it.
fn check_host_timebase() -> Result<()> {
    let (numerator, denominator) = host::timebase();
    ensure!(
        numerator == 1 && denominator == 1,
        "the host timebase is {numerator}/{denominator}, not nanoseconds"
    );
    Ok(())
}

fn random_words<const N: usize>() -> Result<[u64; N]> {
    let mut bytes = vec![0u8; N * 8];
    // SAFETY: the buffer is at most 256 bytes and this frame's.
    let status = unsafe { libc::getentropy(bytes.as_mut_ptr().cast(), bytes.len()) };
    ensure!(status == 0, "getentropy failed");
    let mut words = [0u64; N];
    for (word, chunk) in words.iter_mut().zip(bytes.as_chunks::<8>().0) {
        *word = u64::from_le_bytes(*chunk);
    }
    Ok(words)
}

/// The commpage's time fields, in guest ticks.
fn commpage_time() -> Result<commpage::Time> {
    let (absolute, continuous) = (host::host_nanoseconds(), host::continuous_nanoseconds());
    let mut boot = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut length = size_of::<libc::timeval>();
    // SAFETY: the name is NUL-terminated and the buffer is this frame's.
    let status = unsafe {
        libc::sysctlbyname(
            c"kern.boottime".as_ptr(),
            (&raw mut boot).cast(),
            &raw mut length,
            core::ptr::null_mut(),
            0,
        )
    };
    ensure!(status == 0, "kern.boottime is unavailable");
    Ok(commpage::Time {
        continuous_offset: host::counter_at(continuous - absolute),
        boot_microseconds: boot.tv_sec as u64 * 1_000_000 + boot.tv_usec as u64,
    })
}

/// Run the process to its exit.
pub fn run(launch: Launch) -> Result<Report> {
    check_host_timebase()?;
    // SIGPIPE as exec left it, which the host runtime's own start-up
    // changed to ignored.
    core::hint::black_box(&RECORD_SIGPIPE_AT_EXEC);
    let sigpipe = if SIGPIPE_IGNORED_AT_EXEC.load(Ordering::SeqCst) {
        libc::SIG_IGN
    } else {
        libc::SIG_DFL
    };
    // SAFETY: restores an inherited disposition.
    unsafe { libc::signal(libc::SIGPIPE, sigpipe) };
    let target = TargetCpu::detect();
    let profile = pe::profile(launch.chip, target);
    let identification = features::Identification(&profile.fixed);
    let memory_bytes = host_memory()?;
    let hardware = hardware::Hardware::of(launch.chip, memory_bytes)?;
    let features = identification.optional_features();
    commpage::map(&commpage::data_page(
        &hardware,
        &identification,
        commpage_time()?,
    ))?;
    // The first process of its shared region: reserved and empty until
    // dyld maps the cache.
    let shared_region = Some(shared_region::SharedRegion::reserve(
        shared_region::REGION_START,
        shared_region::REGION_SIZE,
    )?);
    let executable = exec::map_executable(&launch.executable)?;
    let dylinker = exec::map_dylinker(&launch.dylinker.image)?;
    let header = launch
        .executable
        .header_address(launch.slice_offset)
        .context("the executable has no segment holding its Mach header")?
        + executable.slide;
    let stack = exec::map_stack()?;
    let keys = pe::Keys::random()?;
    let [guard0, guard1, guard2, guard3, entropy0, entropy1, munge] = random_words::<7>()?;
    let mut apple = exec::AppleStrings {
        pfz: commpage::TEXT_ADDRESS,
        stack_guard: [guard0, guard1, guard2, guard3],
        malloc_entropy: [entropy0, entropy1],
        ptr_munge: munge,
        stack: Some(stack),
        executable_file: exec::file_identity(&launch.executable.path),
        dyld_file: exec::file_identity(&launch.dylinker.image.path),
        cdhash: Some(launch.signature.cdhash),
        boot_hash: None,
        thread_port: None,
        security_config: 0,
    };
    let entry = launch.dylinker.entry + dylinker.slide;
    if launch.trace {
        eprintln!(
            "stela: executable slide {:#x}, dyld slide {:#x} (entry {entry:#x}), stack top \
             {:#x}",
            executable.slide, dylinker.slide, stack.top
        );
    }
    let jop = pe::UserJop::of_subtype(launch.cpu_subtype);
    let (engine, signer) = threads::engine(launch.chip, profile, target, keys, jop)?;
    let process = kernel::Process::new(kernel::Config {
        shared_region,
        signer,
        hardware,
        features,
        executable: Executable {
            path: launch.executable_path.clone(),
            code_signing_flags: launch.signature.exec_flags(),
            signature: Some(launch.signature.clone()),
            header,
        },
        user_stack: stack.top,
        roots: launch.roots.clone(),
        reexec: launch.reexec.clone(),
        trace: launch.trace,
        engine,
    });
    // The main thread runs on this host thread, the process's first, with
    // the signal mask exec left it; its port, which the apple strings
    // carry, is this thread's.
    let exec_mask = kernel::signals::block_all();
    let Launch {
        executable_path,
        argv,
        environment,
        ..
    } = launch;
    let ended = threads::run_main(&process, entry, exec_mask, move |kernel, pe| {
        apple.thread_port = Some(kernel.thread_port);
        let arguments = exec::install_arguments(
            &stack,
            header,
            &executable_path,
            &argv,
            &environment,
            &apple,
        )?;
        pe.cpu.set_sp(0, arguments.raw_sp);
        Ok(Ok(()))
    })?;
    let termination = match ended {
        Err(errno) => bail!("the main thread could not be created: errno {errno}"),
        Ok(Some(outcome)) => outcome?,
        // The main thread ended alone. Natively the process goes on with
        // its other threads; so does this host process, without this host
        // thread, which would otherwise be the one the host kernel parks
        // signals every thread blocks on.
        // SAFETY: the process's end no longer needs this thread.
        Ok(None) => unsafe { libc::pthread_exit(core::ptr::null_mut()) },
    };
    Ok(Report {
        termination,
        calls: threads::lock(&process.counts).clone(),
        slid_pages: process.slid_pages(),
    })
}

fn host_memory() -> Result<u64> {
    let mut value = 0u64;
    let mut length = size_of::<u64>();
    // SAFETY: the name is NUL-terminated and the buffer is this frame's.
    let status = unsafe {
        libc::sysctlbyname(
            c"hw.memsize".as_ptr(),
            (&raw mut value).cast(),
            &raw mut length,
            core::ptr::null_mut(),
            0,
        )
    };
    ensure!(status == 0, "hw.memsize is unavailable");
    Ok(value)
}
