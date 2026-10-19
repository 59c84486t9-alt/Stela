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
//! signals, the working directory and the credentials. `posix_spawn`
//! ([`super::spawn`]) creates a process with the same activation command.
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

pub(super) const CALLS: &[&str] = &["exit", "execve", "posix_spawn"];

pub(super) fn call(kernel: &mut Kernel, _pe: &mut Pe, call: &Call) -> Result<Option<Outcome>> {
    Ok(match call.entry.name {
        "exit" => {
            kernel.end = Some(End::Process(Termination::Exited(call.argument(0) as i32)));
            Some(Outcome::JustReturn)
        }
        "execve" => Some(execve(kernel, call)?),
        "posix_spawn" => Some(super::spawn::posix_spawn(kernel, call)?),
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

fn execve(kernel: &mut Kernel, call: &Call) -> Result<Outcome> {
    let [path, argv, envp, ..] = call.arguments;
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
    // SAFETY: NULL-terminated vectors of NUL-terminated strings that live
    // across the call; on success the host replaces this process.
    unsafe {
        libc::execve(
            command.program().as_ptr(),
            command.as_ptr(),
            environment.as_ptr(),
        )
    };
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    Ok(Outcome::Error(errno as u64))
}
