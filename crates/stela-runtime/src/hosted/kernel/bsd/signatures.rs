//! Code signatures attached to files (`fcntl` `F_ADDFILESIGS*`,
//! `F_CHECK_LV`, `F_GETSIGSINFO`; `bsd/kern/kern_descrip.c`). XNU attaches
//! a registered blob to the vnode at its slice offset; dyld registers each
//! cache file's and each library's before mapping it. The x86-64 host's
//! kernel cannot evaluate an arm64e platform signature, so this kernel
//! keeps the attachments, by host file identity and slice offset, and
//! answers from them.
//!
//! Registration parses the superblob as `cs_blob_init_validated` does and
//! records its signed range; an unparsable blob fails with EBADEXEC. As
//! for exec, the platform identity is the code directory's platform field
//! and page hashes are not validated: the signature's trust is the host
//! file system's. Library validation is macOS's policy
//! (`docs/research/userspace.md`, code signing and library validation):
//! platform code (trust-cache or Apple-signed) loads into any process; a
//! platform process loads nothing else; another process subject to it
//! (`CS_REQUIRE_LV`, or the hardened runtime without
//! `com.apple.security.cs.disable-library-validation`) also loads code of
//! its own Team ID.
use super::codesign::{CS_PLATFORM_BINARY, CS_REQUIRE_LV, CS_RUNTIME};
use super::{Call, Kernel, Outcome};
use crate::code_signature::{self, CodeSignature};
use crate::hosted::darwin::{E2BIG, EBADEXEC, EBADF, EFAULT, EINVAL, ENOENT, ENOTSUP, EPERM};
use crate::hosted::{memory, threads::lock};
pub(crate) use crate::hosted_registry::bsd::signatures::CALLS;
use anyhow::Result;

const F_ADDSIGS: u64 = 59;
const F_ADDFILESIGS: u64 = 61;
const F_GETCODEDIR: u64 = 72;
const F_FINDSIGS: u64 = 78;
const F_ADDFILESIGS_FOR_DYLD_SIM: u64 = 83;
const F_ADDFILESIGS_RETURN: u64 = 97;
const F_CHECK_LV: u64 = 98;
const F_ADDFILESIGS_INFO: u64 = 103;
const F_ADDFILESUPPL: u64 = 104;
const F_GETSIGSINFO: u64 = 105;
const GETSIGSINFO_PLATFORM_BINARY: u32 = 1;
/// `CS_MAX_BLOB_SIZE`.
const MAX_BLOB_BYTES: u64 = 40 << 20;
/// `struct user_fsignatures`: `fs_file_start`, `fs_blob_start`,
/// `fs_blob_size`, then for `F_ADDFILESIGS_INFO` `fs_fsignatures_size`,
/// `fs_cdhash[20]` and `fs_hash_type`.
const FS_CDHASH: u64 = 32;
const FS_HASH_TYPE: u64 = 52;
const FSIGNATURES_BYTES: u64 = 56;

/// One attached blob.
struct Attached {
    device: u64,
    inode: u64,
    /// The slice's offset in the file (`csb_base_offset`).
    base: u64,
    signature: CodeSignature,
}

impl Attached {
    /// `ubc_cs_blob_get`: `offset` lies in the blob's signed range.
    fn covers(&self, offset: i64) -> bool {
        let Some(within) = offset.checked_sub(self.base as i64) else {
            return false;
        };
        within >= self.signature.start_offset as i64 && within < self.signature.end_offset as i64
    }
}

#[derive(Default)]
pub(in crate::hosted) struct Signatures {
    attached: Vec<Attached>,
}

impl Signatures {
    fn find(&self, (device, inode): (u64, u64), offset: i64) -> Option<&Attached> {
        self.attached
            .iter()
            .filter(|blob| blob.device == device && blob.inode == inode)
            .find(|blob| offset == -1 || blob.covers(offset))
    }
}

/// The host file identity behind a descriptor, or `None` when it is not a
/// regular file or directory (`DTYPE_VNODE`).
fn identity(descriptor: u64) -> Option<(u64, u64)> {
    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `fstat` fills the buffer on success.
    if unsafe { libc::fstat(descriptor as i32, status.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: initialized by the successful call.
    let status = unsafe { status.assume_init() };
    let kind = status.st_mode & libc::S_IFMT;
    (kind == libc::S_IFREG || kind == libc::S_IFDIR)
        .then_some((status.st_dev as u64, status.st_ino))
}

pub(super) fn call(kernel: &mut Kernel, call: &Call) -> Result<Option<Outcome>> {
    if !CALLS.contains(&call.entry.name) {
        return Ok(None);
    }
    let [descriptor, command, argument, ..] = call.arguments;
    let command = command as u32 as u64;
    if !matches!(
        command,
        F_ADDSIGS
            | F_ADDFILESIGS
            | F_GETCODEDIR
            | F_FINDSIGS
            | F_ADDFILESIGS_FOR_DYLD_SIM
            | F_ADDFILESIGS_RETURN
            | F_CHECK_LV
            | F_ADDFILESIGS_INFO
            | F_ADDFILESUPPL
            | F_GETSIGSINFO
    ) {
        return Ok(None);
    }
    let Some(file) = identity(descriptor) else {
        return Ok(Some(Outcome::Error(EBADF)));
    };
    let outcome = match command {
        F_GETCODEDIR | F_FINDSIGS => Outcome::Error(ENOTSUP),
        F_ADDSIGS => crate::hosted::unsupported::refuse!(
            EINVAL,
            "fcntl F_ADDSIGS: detached signatures are not implemented"
        ),
        F_ADDFILESUPPL => {
            crate::hosted::unsupported::refuse!(
                EINVAL,
                "fcntl F_ADDFILESUPPL: supplemental signatures are not implemented"
            )
        }
        F_ADDFILESIGS_FOR_DYLD_SIM => {
            crate::hosted::unsupported::refuse!(
                EINVAL,
                "fcntl F_ADDFILESIGS_FOR_DYLD_SIM: simulator dyld is not supported"
            )
        }
        F_CHECK_LV => check_library(kernel, file, argument)?,
        F_GETSIGSINFO => {
            // `fgetsigsinfo_t`: `fg_file_start`, `fg_info_request`,
            // `fg_sig_is_platform`.
            let Some(bytes) = memory::read(argument, 16) else {
                return Ok(Some(Outcome::Error(EFAULT)));
            };
            let start = i64::from_le_bytes(bytes[..8].try_into().unwrap());
            let request = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
            match lock(&kernel.process.signatures).find(file, start) {
                None => Outcome::Error(ENOENT),
                Some(_) if request != GETSIGSINFO_PLATFORM_BINARY => Outcome::Error(EINVAL),
                Some(blob) => {
                    let platform = u32::from(blob.signature.platform_code());
                    if memory::write_u32(argument + 12, platform) {
                        Outcome::value(0)
                    } else {
                        Outcome::Error(EFAULT)
                    }
                }
            }
        }
        _ => add_file_signatures(kernel, file, descriptor, command, argument)?,
    };
    if kernel.trace {
        eprintln!("stela: fcntl({descriptor}, {command}) code signature = {outcome:x?}");
    }
    Ok(Some(outcome))
}

fn add_file_signatures(
    kernel: &mut Kernel,
    file: (u64, u64),
    descriptor: u64,
    command: u64,
    argument: u64,
) -> Result<Outcome> {
    let Some(bytes) = memory::read(argument, 32) else {
        return Ok(Outcome::Error(EFAULT));
    };
    let field =
        |index: usize| u64::from_le_bytes(bytes[index * 8..index * 8 + 8].try_into().unwrap());
    let (base, blob_start, blob_size) = (field(0), field(1), field(2));
    if lock(&kernel.process.signatures)
        .find(file, base as i64)
        .is_none()
    {
        if blob_size > MAX_BLOB_BYTES {
            return Ok(Outcome::Error(E2BIG));
        }
        let mut blob = vec![0u8; blob_size as usize];
        let Some(position) = base.checked_add(blob_start) else {
            return Ok(Outcome::Error(EINVAL));
        };
        // SAFETY: reads at most `blob.len()` bytes into it. A short read
        // leaves zeros past the file's end, as the kernel's buffer has.
        let read = unsafe {
            libc::pread(
                descriptor as i32,
                blob.as_mut_ptr().cast(),
                blob.len(),
                position as libc::off_t,
            )
        };
        if read < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Ok(Outcome::Error(errno as u64));
        }
        let Ok(signature) = code_signature::parse(&blob) else {
            return Ok(Outcome::Error(EBADEXEC));
        };
        if signature.start_offset >= signature.end_offset {
            return Ok(Outcome::Error(EINVAL));
        }
        lock(&kernel.process.signatures).attached.push(Attached {
            device: file.0,
            inode: file.1,
            base,
            signature,
        });
    }
    let signatures = lock(&kernel.process.signatures);
    let Some(blob) = signatures.find(file, base as i64) else {
        return Ok(Outcome::Error(EINVAL));
    };
    // The end offset overwrites `fs_file_start`.
    if !memory::write_u64(argument, blob.signature.end_offset) {
        return Ok(Outcome::Error(EFAULT));
    }
    if command == F_ADDFILESIGS_INFO {
        let Some(size) = memory::read_u64(argument + 24) else {
            return Ok(Outcome::Error(EFAULT));
        };
        if size >= FSIGNATURES_BYTES
            && !(memory::write(argument + FS_CDHASH, &blob.signature.cdhash)
                && memory::write_u32(argument + FS_HASH_TYPE, u32::from(blob.signature.hash_type)))
        {
            return Ok(Outcome::Error(EFAULT));
        }
    }
    Ok(Outcome::value(0))
}

/// `com.apple.security.cs.disable-library-validation`: a hardened-runtime
/// process loads code of any signer.
const DISABLE_LIBRARY_VALIDATION: &str = "com.apple.security.cs.disable-library-validation";

/// Why library validation refuses `library` in a process, or `None` when
/// it admits it ("signed by Apple or with the same team ID"): platform code
/// (trust-cache or Apple-signed) loads anywhere; a platform process loads
/// nothing else; another process also loads code of its own Team ID.
fn library_refusal(
    platform_process: bool,
    own_team: Option<&str>,
    library: Option<&CodeSignature>,
) -> Option<&'static str> {
    match library {
        None => Some("code signature not found"),
        Some(library) if library.platform_code() => None,
        Some(_) if platform_process => {
            Some("mapping process is a platform binary, but mapped file is not")
        }
        Some(library) if own_team.is_some() && library.team_identifier.as_deref() == own_team => {
            None
        }
        Some(_) => Some("mapping process and mapped file (non-platform) have different Team IDs"),
    }
}

/// Whether library validation applies: to platform processes, to
/// `CS_REQUIRE_LV`, and to the hardened runtime unless it is entitled to
/// disable it.
fn requires_library_validation(flags: u32, disable_entitled: bool) -> bool {
    flags & (CS_PLATFORM_BINARY | CS_REQUIRE_LV) != 0
        || (flags & CS_RUNTIME != 0 && !disable_entitled)
}

/// `F_CHECK_LV`: whether the slice at `lv_file_start` may be mapped
/// executable into this process.
fn check_library(kernel: &mut Kernel, file: (u64, u64), argument: u64) -> Result<Outcome> {
    // `fchecklv_t`: `lv_file_start`, `lv_error_message_size`,
    // `lv_error_message`.
    let Some(bytes) = memory::read(argument, 24) else {
        return Ok(Outcome::Error(EFAULT));
    };
    let field =
        |index: usize| u64::from_le_bytes(bytes[index * 8..index * 8 + 8].try_into().unwrap());
    let (start, message_size, message) = (field(0) as i64, field(1), field(2));
    let (flags, own_team, disable_entitled) = {
        let executable = lock(&kernel.process.executable);
        let signature = executable.signature.as_ref();
        (
            executable.code_signing_flags,
            signature.and_then(|signature| signature.team_identifier.clone()),
            signature.is_some_and(|signature| signature.entitled(DISABLE_LIBRARY_VALIDATION)),
        )
    };
    if !requires_library_validation(flags, disable_entitled) {
        return Ok(Outcome::value(0));
    }
    let platform_process = flags & CS_PLATFORM_BINARY != 0;
    let refusal = library_refusal(
        platform_process,
        own_team.as_deref(),
        lock(&kernel.process.signatures)
            .find(file, start)
            .map(|blob| &blob.signature),
    );
    let Some(refusal) = refusal else {
        return Ok(Outcome::value(0));
    };
    if message != 0 && message_size != 0 {
        let mut text = refusal.as_bytes().to_vec();
        text.truncate(message_size as usize - 1);
        text.push(0);
        if !memory::write(message, &text) {
            return Ok(Outcome::Error(EFAULT));
        }
    }
    Ok(Outcome::Error(EPERM))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signature(platform: u8, team: Option<&str>, apple_signed: bool) -> CodeSignature {
        CodeSignature {
            flags: 0,
            platform,
            hash_type: code_signature::CS_HASHTYPE_SHA256,
            identifier: None,
            team_identifier: team.map(Into::into),
            cdhash: [0; code_signature::CDHASH_BYTES],
            entitlements: None,
            der_entitlements: None,
            start_offset: 0,
            end_offset: 0x8000,
            apple_signed,
        }
    }

    #[test]
    fn library_validation_admits_platform_apple_and_own_team_code() {
        let platform = signature(2, None, true);
        let apple = signature(0, None, true);
        let own = signature(0, Some("TEAM"), false);
        let other = signature(0, Some("OTHER"), false);
        assert_eq!(library_refusal(false, Some("TEAM"), Some(&platform)), None);
        assert_eq!(library_refusal(false, Some("TEAM"), Some(&apple)), None);
        assert_eq!(library_refusal(false, Some("TEAM"), Some(&own)), None);
        assert!(library_refusal(false, Some("TEAM"), Some(&other)).is_some());
        assert!(library_refusal(false, None, Some(&signature(0, None, false))).is_some());
        // A platform process (an xcrun shim) loads Apple-signed code (Xcode's
        // libxcrun), but not a third party's, even its own team's.
        assert_eq!(library_refusal(true, None, Some(&apple)), None);
        assert_eq!(library_refusal(true, None, Some(&platform)), None);
        assert!(library_refusal(true, Some("TEAM"), Some(&own)).is_some());
        assert!(library_refusal(true, None, Some(&signature(0, None, false))).is_some());
        assert!(library_refusal(false, Some("TEAM"), None).is_some());
    }

    #[test]
    fn library_validation_applies_to_platform_required_and_hardened_processes() {
        assert!(requires_library_validation(CS_PLATFORM_BINARY, false));
        assert!(requires_library_validation(CS_REQUIRE_LV, true));
        assert!(requires_library_validation(CS_RUNTIME, false));
        assert!(!requires_library_validation(CS_RUNTIME, true));
        assert!(!requires_library_validation(0, false));
    }

    #[test]
    fn the_disable_entitlement_is_a_true_boolean() {
        let plist = |value: &str| {
            format!(
                "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict>\n\t<key>{}</key>\n\t{value}\
                 </dict></plist>",
                DISABLE_LIBRARY_VALIDATION
            )
        };
        let entitled = |text: String| {
            code_signature::xml_entitlement_true(text.as_bytes(), DISABLE_LIBRARY_VALIDATION)
        };
        assert!(entitled(plist("<true/>")));
        assert!(!entitled(plist("<false/>")));
        assert!(!entitled(plist("<string>true</string>")));
    }

    #[test]
    fn a_blob_covers_its_signed_range_from_its_slice() {
        let blob = Attached {
            device: 1,
            inode: 2,
            base: 0x4000,
            signature: signature(2, None, false),
        };
        assert!(blob.covers(0x4000));
        assert!(blob.covers(0xbfff));
        assert!(!blob.covers(0xc000));
        assert!(!blob.covers(0));
        let signatures = Signatures {
            attached: vec![blob],
        };
        assert!(signatures.find((1, 2), -1).is_some());
        assert!(signatures.find((1, 3), 0x4000).is_none());
    }
}
