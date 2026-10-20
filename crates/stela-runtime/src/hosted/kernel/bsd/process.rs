//! Process lifetime: `exit` ends the run with the guest's status, which
//! becomes the host process's own (`bsd/kern/kern_exit.c` keeps its low
//! eight bits).
//!
//! `execve` checks the new image as the kernel's lookup and activators do
//! (the path resolved under the guest roots, execute permission, a Mach-O
//! with an arm64 slice or a `#!` script whose interpreter is one), then
//! replaces this process's image by executing the hosted runtime's own
//! activation command on the host with the new path, arguments and
//! environment. The host kernel's exec keeps what exec keeps: the process
//! ID, descriptors not marked close-on-exec, the signal mask and ignored
//! signals, the working directory and the credentials.
//!
//! `__mac_execve` is `execve` under a MAC label (`struct mac`), which
//! `mac_execve_enter` reads before the image: a `m_buflen` of 0 or past
//! `MAC_MAX_LABEL_BUF_LEN` fails with EINVAL and the string with
//! `copyinstr`'s errors. The policies that internalize the label are the
//! host kernel's: the label is first given to a host `__mac_execve` of the
//! empty path, which fails with ENOENT only once the label is accepted, so
//! a refused label fails before the image is looked up as on the arm64
//! kernel, and the host exec of the activation command then carries it.
//! `posix_spawn`
//! ([`super::spawn`]) creates a process with the same activation command;
//! `fork` and `vfork` ([`super::fork`]) fork the host process.
use super::{Call, EFAULT, Kernel, Outcome, Pe, paths};
use crate::hosted::activation::{self, Activator};
use crate::hosted::kernel::End;
use crate::hosted::{Termination, memory};
use anyhow::{Result, bail};
use std::ffi::{CString, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// `MAXPATHLEN`.
const MAX_PATH: usize = 1024;
/// The kernel's bound on the argument and environment bytes (`ARG_MAX`
/// on arm64 macOS, `kern.argmax`).
const ARG_MAX: usize = 1 << 20;
const ENAMETOOLONG: u64 = 63;
const E2BIG: u64 = 7;
const EACCES: u64 = 13;
const EINVAL: u64 = 22;
/// `MAC_MAX_LABEL_BUF_LEN` (`security/mac.h`).
const MAC_MAX_LABEL_BUF_LEN: u64 = 8192;

unsafe extern "C" {
    /// `__mac_execve(fname, argv, envp, mac_p)`, system call 380.
    fn __mac_execve(
        path: *const libc::c_char,
        argv: *const *const libc::c_char,
        envp: *const *const libc::c_char,
        label: *const Mac,
    ) -> libc::c_int;
}

/// `struct user64_mac`.
#[repr(C)]
struct Mac {
    buffer_length: u64,
    string: *const libc::c_char,
}

/// A label `__mac_execve` read, as the host kernel takes it.
struct Label {
    length: u64,
    string: Vec<u8>,
}

impl Label {
    /// The guest's `struct mac` at `address`, with `user_mac_copyin`'s and
    /// `copyinstr`'s errnos.
    fn read(address: u64) -> Result<Self, u64> {
        let header = memory::read(address, 16).ok_or(EFAULT)?;
        let length = u64::from_le_bytes(header[..8].try_into().unwrap());
        let string = u64::from_le_bytes(header[8..].try_into().unwrap());
        if length == 0 || length > MAC_MAX_LABEL_BUF_LEN {
            return Err(EINVAL);
        }
        let mut bytes = memory::read_string(string, length as usize - 1).ok_or(
            if memory::read(string, length as usize).is_some() {
                ENAMETOOLONG
            } else {
                EFAULT
            },
        )?;
        // The kernel's buffer is `m_buflen` bytes.
        bytes.resize(length as usize, 0);
        Ok(Self {
            length,
            string: bytes,
        })
    }

    fn host(&self) -> Mac {
        Mac {
            buffer_length: self.length,
            string: self.string.as_ptr().cast(),
        }
    }

    /// The errno the host's policies refuse the label with, or `None`
    /// when they accept it: a host exec of the empty path fails with
    /// ENOENT at its lookup, past `mac_execve_enter`.
    fn refused(&self) -> Option<u64> {
        let label = self.host();
        let empty = [std::ptr::null::<libc::c_char>()];
        // SAFETY: an empty path, empty vectors and a label that lives
        // across the call; no image is activated.
        let result = unsafe { __mac_execve(c"".as_ptr(), empty.as_ptr(), empty.as_ptr(), &label) };
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        (result != 0 && errno != libc::ENOENT).then_some(errno as u64)
    }
}

pub(super) const CALLS: &[&str] = &[
    "exit",
    "execve",
    "__mac_execve",
    "posix_spawn",
    "fork",
    "vfork",
];

pub(super) fn call(kernel: &mut Kernel, _pe: &mut Pe, call: &Call) -> Result<Option<Outcome>> {
    Ok(match call.entry.name {
        "exit" => {
            kernel.end = Some(End::Process(Termination::Exited(call.argument(0) as i32)));
            Some(Outcome::JustReturn)
        }
        "execve" => Some(execve(kernel, call, 0)?),
        "__mac_execve" => Some(execve(kernel, call, call.argument(3))?),
        "posix_spawn" => Some(super::spawn::posix_spawn(kernel, call)?),
        "fork" | "vfork" => super::fork::call(kernel, call)?,
        _ => None,
    })
}

/// A NULL-terminated guest vector of strings, or the errno reading it.
pub(super) fn strings(mut vector: u64, total: &mut usize) -> Result<Vec<Vec<u8>>, u64> {
    let mut strings = Vec::new();
    if vector == 0 {
        return Ok(strings);
    }
    loop {
        let pointer = memory::read_u64(vector).ok_or(EFAULT)?;
        if pointer == 0 {
            return Ok(strings);
        }
        let string = memory::read_string(pointer, ARG_MAX).ok_or(E2BIG)?;
        *total += string.len() + 1 + 8;
        if *total > ARG_MAX {
            return Err(E2BIG);
        }
        strings.push(string);
        vector += 8;
    }
}

/// The host file a guest path names, and the errno its lookup fails with.
fn lookup(kernel: &Kernel, path: &[u8]) -> Result<PathBuf, u64> {
    let host = paths::resolve(&kernel.process.roots, path)
        .unwrap_or_else(|| Path::new(OsStr::from_bytes(path)).to_owned());
    let name =
        CString::new(host.as_os_str().as_bytes()).map_err(|_| u64::from(libc::ENOENT as u32))?;
    // SAFETY: a NUL-terminated path.
    if unsafe { libc::access(name.as_ptr(), libc::X_OK) } != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(errno as u64);
    }
    if !std::fs::metadata(&host).is_ok_and(|metadata| metadata.is_file()) {
        return Err(EACCES);
    }
    Ok(host)
}

/// The first page of the host file `path` (all of a shorter file), which
/// exec's activators read, or the errno reading it fails with.
pub(super) fn first_page(path: &Path) -> Result<Vec<u8>, u64> {
    let mut head = vec![0u8; memory::PAGE_BYTES as usize];
    let read = std::fs::File::open(path)
        .and_then(|mut file| std::io::Read::read(&mut file, &mut head))
        .map_err(|error| error.raw_os_error().unwrap_or(0) as u64)?;
    head.truncate(read);
    Ok(head)
}

/// The activator of the host file `path`, or the errno exec fails with.
fn activate(path: &Path) -> Result<Activator, u64> {
    activation::activator(&first_page(path)?).map_err(|errno| errno as u64)
}

/// The path an exec names, or the errno reading it fails with.
pub(super) fn exec_path(address: u64) -> Result<Vec<u8>, u64> {
    memory::read_string(address, MAX_PATH).ok_or(if memory::read(address, 1).is_some() {
        ENAMETOOLONG
    } else {
        EFAULT
    })
}

/// The host file guest `path` names and the host file of the Mach-O exec
/// activates for it: the same file, or for an interpreter script the
/// interpreter, which must be a Mach-O (nested interpreters fail with
/// ENOEXEC). Or the errno exec fails with.
pub(super) fn check_image(kernel: &Kernel, path: &[u8]) -> Result<(PathBuf, PathBuf), u64> {
    let host = lookup(kernel, path)?;
    if let Activator::Interpreter(tokens) = activate(&host)? {
        let interpreter = lookup(kernel, &tokens[0])?;
        if let Activator::Interpreter(_) = activate(&interpreter)? {
            return Err(activation::ENOEXEC as u64);
        }
        return Ok((host, interpreter));
    }
    Ok((host.clone(), host))
}

/// A host vector of strings: the strings and the NULL-terminated pointers
/// to them, valid while it lives.
pub(super) struct HostVector {
    strings: Vec<CString>,
    pointers: Vec<*const libc::c_char>,
}

impl HostVector {
    pub(super) fn new(strings: Vec<CString>) -> Self {
        let mut pointers: Vec<_> = strings.iter().map(|string| string.as_ptr()).collect();
        pointers.push(std::ptr::null());
        Self { strings, pointers }
    }

    pub(super) fn as_ptr(&self) -> *const *const libc::c_char {
        self.pointers.as_ptr()
    }

    /// The program the vector's first string names.
    pub(super) fn program(&self) -> &CString {
        &self.strings[0]
    }
}

/// The host command that activates guest image `path` with `arguments`
/// (argv[0] first) in a host process: the hosted runtime's activation
/// command, the new image's argv[0] and, when exec chose one, the slice's
/// CPU subtype.
pub(super) fn activation_command(
    kernel: &Kernel,
    path: &[u8],
    arguments: &[Vec<u8>],
    cpu_subtype: Option<u32>,
) -> Result<HostVector> {
    let Some((program, prefix)) = kernel.process.reexec.split_first() else {
        bail!("exec: the hosted runtime has no activation command");
    };
    let mut command = vec![CString::new(program.as_bytes())?];
    for word in prefix {
        command.push(CString::new(word.as_bytes())?);
    }
    let mut flag = b"--argv0=".to_vec();
    flag.extend(arguments.first().map(Vec::as_slice).unwrap_or_default());
    command.push(CString::new(flag)?);
    if let Some(subtype) = cpu_subtype {
        command.push(CString::new(format!("--cpu-subtype={subtype}"))?);
    }
    command.push(CString::new("--")?);
    command.push(CString::new(path)?);
    for argument in arguments.iter().skip(1) {
        command.push(CString::new(argument.clone())?);
    }
    Ok(HostVector::new(command))
}

/// `execve(path, argv, envp)`, or `__mac_execve` with the guest's
/// `struct mac` at `label` when it is not 0.
fn execve(kernel: &mut Kernel, call: &Call, label: u64) -> Result<Outcome> {
    let [path, argv, envp, ..] = call.arguments;
    let label = match (label != 0).then(|| Label::read(label)).transpose() {
        Ok(label) => label,
        Err(errno) => return Ok(Outcome::Error(errno)),
    };
    if let Some(errno) = label.as_ref().and_then(Label::refused) {
        return Ok(Outcome::Error(errno));
    }
    let path = match exec_path(path) {
        Ok(path) => path,
        Err(errno) => return Ok(Outcome::Error(errno)),
    };
    let mut total = path.len() + 1;
    let arguments = match strings(argv, &mut total) {
        Ok(arguments) => arguments,
        Err(errno) => return Ok(Outcome::Error(errno)),
    };
    let environment = match strings(envp, &mut total) {
        Ok(environment) => environment,
        Err(errno) => return Ok(Outcome::Error(errno)),
    };
    let (host, _) = match check_image(kernel, &path) {
        Ok(files) => files,
        Err(errno) => return Ok(Outcome::Error(errno)),
    };
    let command = activation_command(kernel, &path, &arguments, None)?;
    let environment = HostVector::new(
        environment
            .into_iter()
            .map(CString::new)
            .collect::<Result<_, _>>()?,
    );
    if kernel.trace {
        eprintln!(
            "stela: execve {} -> {}",
            String::from_utf8_lossy(&path),
            host.display()
        );
    }
    // The new image keeps the descriptor table with no descriptor
    // mid-flag change.
    let _gate = kernel.process.files.gate();
    // SAFETY: NULL-terminated vectors of NUL-terminated strings that live
    // across the call; on success the host replaces this process.
    unsafe {
        match &label {
            Some(label) => __mac_execve(
                command.program().as_ptr(),
                command.as_ptr(),
                environment.as_ptr(),
                &label.host(),
            ),
            None => libc::execve(
                command.program().as_ptr(),
                command.as_ptr(),
                environment.as_ptr(),
            ),
        }
    };
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    Ok(Outcome::Error(errno as u64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hosted::memory::{PAGE_BYTES, Protection};

    #[test]
    fn a_mac_label_fails_as_mac_execve_enter_reads_it() {
        let page = memory::allocate(0, PAGE_BYTES, true, Protection::READ_WRITE).unwrap();
        let string = page + 64;
        let label = |length: u64| {
            let mut header = length.to_le_bytes().to_vec();
            header.extend(string.to_le_bytes());
            assert!(memory::write(page, &header));
            Label::read(page).map(|label| label.string)
        };
        assert!(memory::write(string, b"x/y\0"));
        assert_eq!(label(0).unwrap_err(), EINVAL);
        assert_eq!(label(MAC_MAX_LABEL_BUF_LEN + 1).unwrap_err(), EINVAL);
        // `copyinstr` needs the terminator within `m_buflen` bytes.
        assert_eq!(label(3).unwrap_err(), ENAMETOOLONG);
        assert_eq!(label(6).unwrap(), b"x/y\0\0\0");
        assert_eq!(Label::read(8).err(), Some(EFAULT));
        // An element without a policy name is EINVAL in `mac_internalize`.
        assert!(memory::write(string, b"x\0"));
        assert_eq!(label(2).map(|_| ()), Ok(()));
        assert_eq!(Label::read(page).unwrap().refused(), Some(EINVAL));
    }
}
