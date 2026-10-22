//! Unsupported operations (`docs/design/runtime.md`, "Unsupported
//! operations"): an operation the hosted runtime does not implement fails
//! as the guest's platform fails an operation it lacks, and is reported
//! once per distinct (kind, image, offset, subject), the subject telling
//! apart operations one place serves (each MIG routine at the message
//! trap, each exception type at its delivery): a `stela:` line on standard
//! error, an entry in `~/Library/Logs/Stela/unsupported.log` and the
//! notifier a host application installs ([`set_notifier`]), and counted in
//! the summary the run ends with ([`summarize`]). Strict mode (`stela run
//! --strict`, `STELA_STRICT=1`) stops the run at the first one instead, as
//! tests, benchmarks and tool comparisons run; graceful is the default.
//!
//! A service refuses with [`refuse!`] (or [`refusal`]), naming the
//! guest-visible [`Failure`]; the dispatcher that called it turns the
//! refusal into that failure with [`recover`]. Every other error stays an
//! internal failure that stops the run.
use anyhow::Result;
use std::collections::HashSet;
use std::fmt;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

/// What kind of operation was unsupported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Instruction,
    BsdCall,
    MachTrap,
    MigRoutine,
    PlatformCall,
    Exception,
    /// The installed guest system lacks something a run needs.
    GuestSystem,
    /// A hosted device's user-client call (`iokit_user_client_trap`).
    DeviceCall,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Instruction => "instruction",
            Self::BsdCall => "BSD system call",
            Self::MachTrap => "Mach trap",
            Self::MigRoutine => "MIG routine",
            Self::PlatformCall => "platform call",
            Self::Exception => "exception",
            Self::GuestSystem => "guest system",
            Self::DeviceCall => "device call",
        }
    }
}

/// What the guest sees in place of the operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// The call fails with this `errno`.
    Errno(u64),
    /// XNU's `nosys`: `ENOSYS`, with `SIGSYS` sent to the thread.
    Nosys,
    /// The trap or routine returns this `kern_return_t` (or MIG code).
    Kern(u32),
    /// `EXC_SYSCALL`, which becomes `SIGSYS` at the trap.
    SyscallException,
    /// `EXC_BAD_INSTRUCTION`, which becomes `SIGILL` at the instruction.
    BadInstruction,
    /// Nothing: a note about the run, whose operation fails on its own.
    None,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Errno(errno) => match errno_name(errno) {
                Some(name) => write!(f, "it fails with {name}"),
                None => write!(f, "it fails with errno {errno}"),
            },
            Self::Nosys => f.write_str("it fails with ENOSYS and SIGSYS"),
            Self::Kern(code) => write!(f, "it returns {code:#x}"),
            Self::SyscallException => f.write_str("EXC_SYSCALL (SIGSYS) at the trap"),
            Self::BadInstruction => f.write_str("EXC_BAD_INSTRUCTION (SIGILL) at the instruction"),
            Self::None => f.write_str("it continues"),
        }
    }
}

fn errno_name(errno: u64) -> Option<&'static str> {
    use crate::hosted::darwin::{
        E2BIG, EACCES, EBADARCH, EBADEXEC, EBADF, EFAULT, EINVAL, ENOENT, ENOMEM, ENOSYS, ENOTSUP,
        EPERM, ERANGE,
    };
    Some(match errno {
        EPERM => "EPERM",
        ENOENT => "ENOENT",
        E2BIG => "E2BIG",
        EBADF => "EBADF",
        ENOMEM => "ENOMEM",
        EACCES => "EACCES",
        EFAULT => "EFAULT",
        EINVAL => "EINVAL",
        ERANGE => "ERANGE",
        ENOTSUP => "ENOTSUP",
        ENOSYS => "ENOSYS",
        EBADEXEC => "EBADEXEC",
        EBADARCH => "EBADARCH",
        _ => return None,
    })
}

/// A service's refusal of an unsupported operation: what it is and what
/// the guest sees instead.
#[derive(Debug)]
pub struct Unsupported {
    pub failure: Failure,
    pub operation: String,
}

impl fmt::Display for Unsupported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.operation)
    }
}

impl std::error::Error for Unsupported {}

/// The refusal of `operation`, failing as `failure`.
pub fn refusal(failure: Failure, operation: impl Into<String>) -> anyhow::Error {
    Unsupported {
        failure,
        operation: operation.into(),
    }
    .into()
}

/// `refuse!(failure, "format", args...)`: return the refusal of the
/// operation the message names, which fails as `failure` (an `errno` value
/// for [`Failure::Errno`], or a [`Failure`]).
macro_rules! refuse {
    ($failure:expr, $($message:tt)+) => {
        return Err($crate::hosted::unsupported::refusal(
            $crate::hosted::unsupported::IntoFailure::into_failure($failure),
            format!($($message)+),
        ))
    };
}
pub(crate) use refuse;

/// What [`refuse!`] accepts as the failure.
pub trait IntoFailure {
    fn into_failure(self) -> Failure;
}

impl IntoFailure for Failure {
    fn into_failure(self) -> Failure {
        self
    }
}

impl IntoFailure for u64 {
    fn into_failure(self) -> Failure {
        Failure::Errno(self)
    }
}

/// One reported operation, as the notifier receives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub kind: Kind,
    pub operation: String,
    /// The file holding the code that asked, or `anonymous` memory.
    pub image: String,
    pub offset: u64,
    pub failure: Failure,
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.failure == Failure::None {
            return write!(f, "note: {}", self.operation);
        }
        write!(
            f,
            "unsupported {}: {} (at {}+{:#x}); {}",
            self.kind.name(),
            self.operation,
            self.image,
            self.offset,
            self.failure
        )
    }
}

static STRICT: AtomicBool = AtomicBool::new(false);
/// Unsupported operations answered gracefully, and the distinct ones.
static ANSWERED: AtomicU64 = AtomicU64::new(0);
static DISTINCT: AtomicU64 = AtomicU64::new(0);
static NOTIFIER: OnceLock<fn(&Report)> = OnceLock::new();
static PROGRAM: OnceLock<String> = OnceLock::new();
/// A report's identity: its kind, place and subject.
type Key = (Kind, String, u64, Option<String>);
static REPORTED: Mutex<Option<HashSet<Key>>> = Mutex::new(None);

/// Whether `key` is reported for the first time.
fn first(key: Key) -> bool {
    let mut reported = REPORTED.lock().unwrap_or_else(|poison| poison.into_inner());
    reported.get_or_insert_with(HashSet::new).insert(key)
}

/// Stop at the first unsupported operation (`--strict`).
pub fn set_strict(strict: bool) {
    STRICT.store(strict, Ordering::SeqCst);
}

/// Whether unsupported operations stop the run: `--strict`, or
/// `STELA_STRICT=1` in the environment.
pub fn strict() -> bool {
    static ENVIRONMENT: OnceLock<bool> = OnceLock::new();
    STRICT.load(Ordering::SeqCst)
        || *ENVIRONMENT.get_or_init(|| std::env::var_os("STELA_STRICT").is_some_and(|v| v == "1"))
}

/// Name the guest program the log's entries are about (exec's path).
pub fn set_program(path: &str) {
    let _ = PROGRAM.set(path.to_owned());
}

/// Install the function each new report also goes to (a host application's
/// user notification). Only the first installation takes effect.
pub fn set_notifier(notifier: fn(&Report)) -> bool {
    NOTIFIER.set(notifier).is_ok()
}

/// Report the unsupported `operation` the code at `pc` asked for, which
/// the guest sees fail as `failure`: in strict mode the error that stops
/// the run, otherwise `Ok` after reporting it, once per kind, place and
/// `subject`.
pub fn report(
    kind: Kind,
    pc: u64,
    operation: &str,
    failure: Failure,
    subject: Option<&str>,
) -> Result<()> {
    if strict() {
        anyhow::bail!("{operation}");
    }
    ANSWERED.fetch_add(1, Ordering::Relaxed);
    let (image, offset) = place(pc);
    let report = Report {
        kind,
        operation: operation.to_owned(),
        image,
        offset,
        failure,
    };
    publish(report, subject);
    Ok(())
}

/// A note about the run that names no code (`Kind::GuestSystem`): reported
/// once per `key`, never a stop.
pub fn note(kind: Kind, key: &str, text: &str) {
    publish(
        Report {
            kind,
            operation: text.to_owned(),
            image: key.to_owned(),
            offset: 0,
            failure: Failure::None,
        },
        None,
    );
}

/// The guest-visible failure of an error a service returned: an
/// unsupported operation's, after reporting it (as [`report`] with
/// `subject`), outside strict mode; the error itself otherwise.
pub fn recover(
    error: anyhow::Error,
    kind: Kind,
    pc: u64,
    subject: Option<&str>,
) -> Result<Failure> {
    let Some(unsupported) = error.downcast_ref::<Unsupported>() else {
        return Err(error);
    };
    if strict() {
        return Err(error);
    }
    let failure = unsupported.failure;
    report(kind, pc, &format!("{error:#}"), failure, subject)?;
    Ok(failure)
}

fn publish(report: Report, subject: Option<&str>) {
    let key = (
        report.kind,
        report.image.clone(),
        report.offset,
        subject.map(str::to_owned),
    );
    if !first(key) {
        return;
    }
    if report.failure != Failure::None {
        DISTINCT.fetch_add(1, Ordering::Relaxed);
    }
    eprintln!("stela: {report}");
    log(&report);
    if let Some(notifier) = NOTIFIER.get() {
        notifier(&report);
    }
}

/// The run summary's line, when the run answered an unsupported operation.
fn summary() -> Option<String> {
    let answered = ANSWERED.load(Ordering::Relaxed);
    (answered > 0).then(|| {
        format!(
            "stela: {answered} unsupported operations answered gracefully ({} distinct, \
             each reported above and in ~/Library/Logs/Stela/unsupported.log)",
            DISTINCT.load(Ordering::Relaxed)
        )
    })
}

/// End the run's account of unsupported operations: the summary line on
/// standard error, when any was answered.
pub fn summarize() {
    if let Some(line) = summary() {
        eprintln!("{line}");
    }
}

/// Append the report to `~/Library/Logs/Stela/unsupported.log`, as far as
/// the file can be written: the standard-error line stands either way.
fn log(report: &Report) {
    let Some(home) = std::env::var_os("HOME") else {
        return;
    };
    let directory = PathBuf::from(home).join("Library/Logs/Stela");
    if std::fs::create_dir_all(&directory).is_err() {
        return;
    }
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(directory.join("unsupported.log"))
    else {
        return;
    };
    let program = PROGRAM.get().map_or("", String::as_str);
    let _ = writeln!(
        file,
        "{} {program}[{}] {report}",
        timestamp(),
        std::process::id()
    );
}

/// The current UTC time, ISO 8601.
fn timestamp() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let (days, rest) = (seconds / 86_400, seconds % 86_400);
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let shifted = days as i64 + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest / 60 % 60,
        rest % 60
    )
}

/// `PROC_PIDREGIONPATHINFO` and the offsets in its
/// `struct proc_regionwithpathinfo`: `pri_offset`, `pri_address`,
/// `pri_size` and `vip_path`.
const PROC_PIDREGIONPATHINFO: i32 = 8;
const REGION_OFFSET: usize = 16;
const REGION_ADDRESS: usize = 80;
const REGION_SIZE: usize = 88;
const REGION_PATH: usize = 248;
const REGION_INFO_BYTES: usize = REGION_PATH + 1024;

/// The file mapped at `pc` and the file offset `pc` lies at; `anonymous`
/// and the address itself for memory no file backs.
fn place(pc: u64) -> (String, u64) {
    let mut info = [0u8; REGION_INFO_BYTES];
    // SAFETY: a buffer of the length passed, which is
    // `struct proc_regionwithpathinfo`'s.
    let filled = unsafe {
        libc::proc_pidinfo(
            libc::getpid(),
            PROC_PIDREGIONPATHINFO,
            pc,
            info.as_mut_ptr().cast(),
            info.len() as i32,
        )
    };
    let word = |at: usize| u64::from_le_bytes(info[at..at + 8].try_into().unwrap());
    let (offset, address, size) = (word(REGION_OFFSET), word(REGION_ADDRESS), word(REGION_SIZE));
    let path = &info[REGION_PATH..];
    let path = &path[..path
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(path.len())];
    // The region found is the first at or above `pc`.
    if filled <= 0 || !(address..address.saturating_add(size)).contains(&pc) || path.is_empty() {
        return ("anonymous".to_owned(), pc);
    }
    (
        String::from_utf8_lossy(path).into_owned(),
        offset + (pc - address),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusals_carry_their_failure_through_context() {
        fn service() -> Result<()> {
            refuse!(22u64, "frob option {:#x}", 7);
        }
        let error = anyhow::Context::context(service(), "outer").unwrap_err();
        let unsupported = error.downcast_ref::<Unsupported>().unwrap();
        assert_eq!(unsupported.failure, Failure::Errno(22));
        assert_eq!(unsupported.operation, "frob option 0x7");
        // Other errors stay errors.
        assert!(recover(anyhow::anyhow!("internal"), Kind::BsdCall, 0, None).is_err());
    }

    #[test]
    fn graceful_answers_are_counted_in_the_summary() {
        // Other tests' reports only add to the counts.
        ANSWERED.fetch_add(2, Ordering::Relaxed);
        DISTINCT.fetch_add(1, Ordering::Relaxed);
        let line = summary().unwrap();
        assert!(
            line.contains("unsupported operations answered gracefully"),
            "{line}"
        );
        assert!(line.contains("distinct"), "{line}");
    }

    #[test]
    fn subjects_tell_apart_operations_at_one_place() {
        let key = |subject: Option<&str>| {
            (
                Kind::MigRoutine,
                "test image".to_owned(),
                0x1234,
                subject.map(str::to_owned),
            )
        };
        assert!(first(key(Some("task.task_get_special_port"))));
        assert!(first(key(Some("thread_act.thread_get_special_port"))));
        assert!(!first(key(Some("task.task_get_special_port"))));
        assert!(first(key(None)));
        assert!(!first(key(None)));
    }

    #[test]
    fn code_is_placed_in_its_file() {
        // This test's own text is mapped from the test executable.
        let function: fn() = code_is_placed_in_its_file;
        let (image, offset) = place(function as usize as u64);
        let executable = std::env::current_exe().unwrap();
        assert_eq!(
            std::fs::canonicalize(&image).unwrap(),
            std::fs::canonicalize(executable).unwrap()
        );
        assert!(offset > 0);
        let heap = Box::new(0u64);
        assert_eq!(place(&raw const *heap as u64).0, "anonymous");
    }

    #[test]
    fn timestamps_are_utc_dates() {
        let stamp = timestamp();
        assert_eq!(stamp.len(), 20, "{stamp}");
        assert!(stamp.starts_with("20") && stamp.ends_with('Z'), "{stamp}");
    }

    #[test]
    fn failures_name_what_the_guest_sees() {
        assert_eq!(
            Failure::Errno(crate::hosted::darwin::ENOTSUP).to_string(),
            "it fails with ENOTSUP"
        );
        assert_eq!(Failure::Errno(999).to_string(), "it fails with errno 999");
    }
}
