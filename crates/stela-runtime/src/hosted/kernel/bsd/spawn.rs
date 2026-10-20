//! `posix_spawn(pid, path, adesc, argv, envp)` (`bsd/kern/kern_exec.c`):
//! a new process running a guest image, created by the host kernel as a
//! host process that runs the hosted runtime's activation command for the
//! image (`process::activation_command`).
//!
//! The image is checked as exec checks it (lookup under the guest roots,
//! execute permission, the activator). The spawn attributes' binary
//! preferences choose the slice as `exec_fat_imgact` and
//! `exec_mach_imgact` do; they name guest CPU types, so the host kernel
//! receives a copy of the attributes without them and the child runtime
//! is told the chosen slice. Every other attribute and action (flags such
//! as `POSIX_SPAWN_SETEXEC`, `SETSIGMASK`, `SETSIGDEF`, `SETPGROUP`,
//! `CLOEXEC_DEFAULT` and `START_SUSPENDED`, file actions, port actions,
//! coalition, persona and credentials) acts on the new process exactly as
//! the arm64 kernel's would: the descriptor and its blocks have one layout
//! in both LP64 ABIs, and the host kernel applies them to the host process
//! that is the guest's child. The child's process ID is the host's.
use super::{Call, Kernel, Outcome, process};
use crate::hosted::darwin::{EBADEXEC, EFAULT, EINVAL};
use crate::hosted::hardware::CPU_SUBTYPE_ARM64E;
use crate::hosted::{activation, forward, memory};
use anyhow::Result;
use std::ffi::CString;

/// `struct _posix_spawn_args_desc`: nine (size, pointer) pairs, the first
/// the attributes' (`attr_size`, `attrp`).
const DESCRIPTOR_WORDS: usize = 18;
const ATTRIBUTES_SIZE: usize = 0;
const ATTRIBUTES_POINTER: usize = 1;
const PORT_ACTIONS_SIZE: usize = 4;
const PORT_ACTIONS_POINTER: usize = 5;
/// `struct _posix_spawn_port_actions`: `pspa_alloc`, `pspa_count`, then
/// `_ps_port_action_t`s of six words, the first `port_type`.
const PORT_ACTION_BYTES: u64 = 24;
const PSPA_EXCEPTION: u32 = 1;
/// `struct _posix_spawnattr`: `psa_binprefs[NBINPREFS]` and
/// `psa_subcpuprefs[NBINPREFS]`, at the offsets 26A434's
/// `posix_spawnattr_setarchpref_np` stores them.
const BINARY_PREFERENCES: usize = 0x10;
const SUBTYPE_PREFERENCES: usize = 0x70;
const PREFERENCES: usize = 4;
/// The attributes block the kernel reads: `offsetof(psa_ports)` is well
/// past the preferences; a smaller block cannot hold them.
const MINIMUM_ATTRIBUTES: usize = SUBTYPE_PREFERENCES + PREFERENCES * 4;
/// The largest attributes block copied (the host kernel reads its own
/// prefix of it).
const MAXIMUM_ATTRIBUTES: usize = memory::PAGE_BYTES as usize;
const CPU_TYPE_ANY: u32 = u32::MAX;
const CPU_SUBTYPE_ANY: u32 = u32::MAX;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const CPU_SUBTYPE_MASK: u32 = 0xff00_0000;
/// `EBADEXEC`: no fat architecture honors the preferences.
const EBADARCH: u64 = activation::EBADARCH as u64;
const POSIX_SPAWN: u16 = 244;

/// The slice the binary preferences select among `slices` of a fat
/// (`fat`) or thin image: `Ok(None)` for regular grading, `Ok(Some(slice))`
/// for a preferred one, or the errno.
fn preferred_slice(
    preferences: &[(u32, u32); PREFERENCES],
    slices: &[(u32, u32)],
    fat: bool,
) -> Result<Option<(u32, u32)>, u64> {
    if preferences[0].0 == 0 {
        return Ok(None);
    }
    for &(cpu_type, subtype) in preferences {
        if cpu_type == 0 {
            return Err(EBADARCH);
        }
        if cpu_type == CPU_TYPE_ANY {
            return Ok(None);
        }
        // `fatfile_getbestarch_for_cputype` and `binary_match`: the CPU
        // type, and the subtype unless it is any.
        let matching = slices
            .iter()
            .copied()
            .filter(|&(slice_type, slice_subtype)| {
                slice_type == cpu_type
                    && (subtype == CPU_SUBTYPE_ANY
                        || slice_subtype & !CPU_SUBTYPE_MASK == subtype & !CPU_SUBTYPE_MASK)
            });
        // The best grade among them: arm64e above every other arm64.
        if let Some(slice) = matching.max_by_key(|&(_, slice_subtype)| {
            slice_subtype & !CPU_SUBTYPE_MASK == CPU_SUBTYPE_ARM64E
        }) {
            return Ok(Some(slice));
        }
    }
    Err(if fat { EBADEXEC } else { EBADARCH })
}

fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

pub(super) fn posix_spawn(kernel: &mut Kernel, call: &Call) -> Result<Outcome> {
    let [pid, path, adesc, argv, envp, ..] = call.arguments;
    let path = match process::exec_path(path) {
        Ok(path) => path,
        Err(errno) => return Ok(Outcome::Error(errno)),
    };
    let mut total = path.len() + 1;
    let arguments = match process::strings(argv, &mut total) {
        Ok(arguments) => arguments,
        Err(errno) => return Ok(Outcome::Error(errno)),
    };
    let (host, image) = match process::check_image(kernel, &path) {
        Ok(files) => files,
        Err(errno) => return Ok(Outcome::Error(errno)),
    };
    // The descriptor and attributes the host kernel reads: copies in host
    // memory, the attributes without guest binary preferences.
    let mut descriptor = [0u64; DESCRIPTOR_WORDS];
    let mut copied: Option<Vec<u8>> = None;
    let mut cpu_subtype = None;
    if adesc != 0 {
        let Some(bytes) = memory::read(adesc, DESCRIPTOR_WORDS * 8) else {
            return Ok(Outcome::Error(EFAULT));
        };
        for (word, chunk) in descriptor.iter_mut().zip(bytes.as_chunks::<8>().0) {
            *word = u64::from_le_bytes(*chunk);
        }
        let size = descriptor[ATTRIBUTES_SIZE] as usize;
        if size != 0 {
            if !(MINIMUM_ATTRIBUTES..=MAXIMUM_ATTRIBUTES).contains(&size) {
                return Ok(Outcome::Error(EINVAL));
            }
            let Some(bytes) = memory::read(descriptor[ATTRIBUTES_POINTER], size) else {
                return Ok(Outcome::Error(EFAULT));
            };
            let attributes = copied.insert(bytes);
            let preferences: [(u32, u32); PREFERENCES] = core::array::from_fn(|index| {
                (
                    word(attributes, BINARY_PREFERENCES + index * 4),
                    word(attributes, SUBTYPE_PREFERENCES + index * 4),
                )
            });
            // The preferences grade the Mach-O exec activates: a
            // script's interpreter.
            let head = match process::first_page(&image) {
                Ok(head) => head,
                Err(errno) => return Ok(Outcome::Error(errno)),
            };
            let fat = head.starts_with(&0xcafe_babe_u32.to_be_bytes())
                || head.starts_with(&0xcafe_babf_u32.to_be_bytes());
            match preferred_slice(&preferences, &activation::slices(&head), fat) {
                Ok(None) => {}
                Ok(Some((CPU_TYPE_ARM64, subtype))) => cpu_subtype = Some(subtype),
                Ok(Some((cpu_type, _))) => crate::hosted::unsupported::refuse!(
                    EBADARCH,
                    "posix_spawn: the binary preferences select a CPU type {cpu_type:#x} slice of \
                     {}, which runs under Rosetta on the M2: running the slice natively would show \
                     it the x86 host instead of the M2 and its Rosetta environment",
                    String::from_utf8_lossy(&path)
                ),
                Err(errno) => return Ok(Outcome::Error(errno)),
            }
            attributes[BINARY_PREFERENCES..BINARY_PREFERENCES + PREFERENCES * 4].fill(0);
            attributes[SUBTYPE_PREFERENCES..SUBTYPE_PREFERENCES + PREFERENCES * 4].fill(0);
            descriptor[ATTRIBUTES_POINTER] = attributes.as_ptr() as u64;
        }
    }
    // The child inherits the task's exception actions; an exception-port
    // action would set the child's on its host task, where the host kernel
    // delivers the hosted runtime's own faults to them.
    kernel.process.exception_ports.inheritable("posix_spawn")?;
    let actions = descriptor[PORT_ACTIONS_POINTER];
    if adesc != 0 && actions != 0 && descriptor[PORT_ACTIONS_SIZE] >= 8 {
        let count = memory::read_u32(actions + 4).unwrap_or(0);
        let within = (descriptor[PORT_ACTIONS_SIZE] - 8) / PORT_ACTION_BYTES;
        if (0..u64::from(count).min(within)).any(|index| {
            memory::read_u32(actions + 8 + index * PORT_ACTION_BYTES) == Some(PSPA_EXCEPTION)
        }) {
            crate::hosted::unsupported::refuse!(
                EINVAL,
                "posix_spawn with an exception-port action: the child would hold it on its host \
                 task, where the host kernel delivers the hosted runtime's own faults with x86 \
                 state, which is not implemented"
            );
        }
    }
    let command = process::activation_command(kernel, &path, &arguments, cpu_subtype)?;
    if kernel.trace {
        eprintln!(
            "stela: posix_spawn {} -> {}",
            String::from_utf8_lossy(&path),
            host.display()
        );
    }
    let program: &CString = command.program();
    let descriptor_pointer = if adesc == 0 {
        0
    } else {
        descriptor.as_ptr() as u64
    };
    // The child copies the descriptor table with no descriptor mid-flag
    // change.
    let _gate = kernel.process.files.gate();
    let returned = forward::bsd(
        POSIX_SPAWN,
        &[
            pid,
            program.as_ptr() as u64,
            descriptor_pointer,
            command.as_ptr() as u64,
            envp,
        ],
    );
    Ok(if returned.carry {
        Outcome::Error(returned.rax)
    } else {
        Outcome::Return(returned.rax, returned.rdx)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARM64E: (u32, u32) = (CPU_TYPE_ARM64, 0x8000_0002);
    const ARM64: (u32, u32) = (CPU_TYPE_ARM64, 0);
    const X86_64: (u32, u32) = (0x0100_0007, 3);

    fn preferences(list: &[(u32, u32)]) -> [(u32, u32); PREFERENCES] {
        core::array::from_fn(|index| list.get(index).copied().unwrap_or((0, 0)))
    }

    #[test]
    fn binary_preferences_choose_slices_as_exec_does() {
        let fat = [X86_64, ARM64E, ARM64];
        // No preference, or any CPU type: regular grading.
        assert_eq!(preferred_slice(&preferences(&[]), &fat, true), Ok(None));
        assert_eq!(
            preferred_slice(&preferences(&[(CPU_TYPE_ANY, 0)]), &fat, true),
            Ok(None)
        );
        // arm64 with any subtype grades arm64e first; a named subtype
        // selects that slice.
        assert_eq!(
            preferred_slice(
                &preferences(&[(CPU_TYPE_ARM64, CPU_SUBTYPE_ANY)]),
                &fat,
                true
            ),
            Ok(Some(ARM64E))
        );
        assert_eq!(
            preferred_slice(&preferences(&[(CPU_TYPE_ARM64, 0)]), &fat, true),
            Ok(Some(ARM64))
        );
        // A preference the image lacks moves to the next; the list's end
        // (a zero entry) is EBADARCH, a full list unmatched EBADEXEC.
        assert_eq!(
            preferred_slice(&preferences(&[(0x0100_0012, 0), ARM64]), &fat, true),
            Ok(Some(ARM64))
        );
        assert_eq!(
            preferred_slice(&preferences(&[(0x0100_0012, 0)]), &fat, true),
            Err(EBADARCH)
        );
        assert_eq!(
            preferred_slice(&preferences(&[(0x0100_0012, 0); 4]), &fat, true),
            Err(EBADEXEC)
        );
        assert_eq!(
            preferred_slice(&preferences(&[(0x0100_0012, 0); 4]), &[ARM64], false),
            Err(EBADARCH)
        );
        assert_eq!(
            preferred_slice(&preferences(&[X86_64]), &fat, true),
            Ok(Some(X86_64))
        );
    }
}
