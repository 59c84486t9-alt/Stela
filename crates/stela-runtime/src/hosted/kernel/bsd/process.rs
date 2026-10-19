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
//! signals, the working directory and the credentials. Creating processes
//! needs the hosted runtime in the child and stays refused by name.
use super::{Call, EFAULT, Kernel, Outcome, Pe, paths};
use crate::hosted::activation::{self, Activator};
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

pub(super) fn call(kernel: &mut Kernel, _pe: &mut Pe, call: &Call) -> Result<Option<Outcome>> {
    Ok(match call.entry.name {
        "exit" => {
            kernel.termination = Some(Termination::Exited(call.argument(0) as i32));
            Some(Outcome::JustReturn)
        }
        "execve" => Some(execve(kernel, call)?),
        _ => None,
    })
}

/// A NULL-terminated guest vector of strings, or the errno reading it.
fn strings(mut vector: u64, total: &mut usize) -> Result<Vec<Vec<u8>>, u64> {
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
    let host = paths::resolve(&kernel.roots, path)
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

/// The activator of the host file `path`, or the errno exec fails with.
fn activate(path: &Path) -> Result<Activator, u64> {
    let mut head = vec![0u8; memory::PAGE_BYTES as usize];
    let read = std::fs::File::open(path)
        .and_then(|mut file| std::io::Read::read(&mut file, &mut head))
        .map_err(|error| error.raw_os_error().unwrap_or(0) as u64)?;
    head.truncate(read);
    activation::activator(&head).map_err(|errno| errno as u64)
}

fn execve(kernel: &mut Kernel, call: &Call) -> Result<Outcome> {
    let [path, argv, envp, ..] = call.arguments;
    let Some(path) = memory::read_string(path, MAX_PATH) else {
        return Ok(Outcome::Error(if memory::read(path, 1).is_some() {
            ENAMETOOLONG
        } else {
            EFAULT
        }));
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
    let host = match lookup(kernel, &path) {
        Ok(host) => host,
        Err(errno) => return Ok(Outcome::Error(errno)),
    };
    match activate(&host) {
        Ok(Activator::MachO) => {}
        Ok(Activator::Interpreter(tokens)) => {
            // The interpreter must itself be a Mach-O: nested interpreters
            // fail with ENOEXEC.
            let interpreter = match lookup(kernel, &tokens[0]) {
                Ok(interpreter) => interpreter,
                Err(errno) => return Ok(Outcome::Error(errno)),
            };
            match activate(&interpreter) {
                Ok(Activator::MachO) => {}
                Ok(Activator::Interpreter(_)) => {
                    return Ok(Outcome::Error(activation::ENOEXEC as u64));
                }
                Err(errno) => return Ok(Outcome::Error(errno)),
            }
        }
        Err(errno) => return Ok(Outcome::Error(errno)),
    }
    let Some((program, prefix)) = kernel.reexec.split_first() else {
        bail!("execve: the hosted runtime has no activation command");
    };
    let argv0 = arguments.first().cloned().unwrap_or_default();
    let mut command: Vec<CString> = Vec::new();
    for word in prefix {
        command.push(CString::new(word.as_bytes())?);
    }
    let mut flag = b"--argv0=".to_vec();
    flag.extend(&argv0);
    command.push(CString::new(flag)?);
    command.push(CString::new("--")?);
    command.push(CString::new(path.clone())?);
    for argument in arguments.iter().skip(1) {
        command.push(CString::new(argument.clone())?);
    }
    let program = CString::new(program.as_bytes())?;
    let mut argv0_program = vec![program.clone()];
    argv0_program.extend(command);
    let environment: Vec<CString> = environment
        .into_iter()
        .map(CString::new)
        .collect::<Result<_, _>>()?;
    let mut argv_pointers: Vec<*const libc::c_char> =
        argv0_program.iter().map(|word| word.as_ptr()).collect();
    argv_pointers.push(std::ptr::null());
    let mut envp_pointers: Vec<*const libc::c_char> =
        environment.iter().map(|entry| entry.as_ptr()).collect();
    envp_pointers.push(std::ptr::null());
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
            program.as_ptr(),
            argv_pointers.as_ptr(),
            envp_pointers.as_ptr(),
        )
    };
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    Ok(Outcome::Error(errno as u64))
}
