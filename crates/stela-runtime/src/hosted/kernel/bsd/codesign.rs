//! `csops` and `csops_audittoken` (`bsd/kern/kern_proc.c`) for this
//! process, from the executable's code signature as exec recorded it.
//! Other processes are the host's and their requests are forwarded.
//!
//! Exec's flags are the chosen code directory's flags within
//! `CS_ALLOWED_MACHO`, with `CS_VALID` and `CS_SIGNED`. A platform binary
//! (a nonzero code directory platform) also carries `CS_PLATFORM_BINARY`,
//! `CS_NO_UNTRUSTED_HELPERS` (its dyld is the platform's) and `CS_RESTRICT`,
//! as AMFI marks platform binaries; the host kernel reports `0x26010801` for
//! its own `/bin/sleep`, the same set. The status query adds
//! `CS_ENFORCEMENT`: arm64 kernels enforce code signing for every process
//! (`cs_process_enforcement`). Page hashes are not validated; the
//! signature's trust is the host file system's.
use super::{Call, EFAULT, EINVAL, ENOENT, Kernel, Outcome, forward};
use crate::code_signature;
use crate::hosted::{memory, threads::lock};
use anyhow::{Result, bail};

const ESRCH: u64 = 3;
const ERANGE: u64 = 34;
const CS_OPS_STATUS: u64 = 0;
const CS_OPS_MARKINVALID: u64 = 1;
const CS_OPS_MARKHARD: u64 = 2;
const CS_OPS_MARKKILL: u64 = 3;
const CS_OPS_CDHASH: u64 = 5;
const CS_OPS_ENTITLEMENTS_BLOB: u64 = 7;
const CS_OPS_MARKRESTRICT: u64 = 8;
const CS_OPS_SET_STATUS: u64 = 9;
const CS_OPS_IDENTITY: u64 = 11;
const CS_OPS_TEAMID: u64 = 14;
const CS_OPS_DER_ENTITLEMENTS_BLOB: u64 = 16;
const CS_OPS_VALIDATION_CATEGORY: u64 = 17;
const CS_OPS_CDHASH_WITH_INFO: u64 = 18;

pub(crate) const CS_VALID: u32 = 0x0000_0001;
const CS_ADHOC: u32 = 0x0000_0002;
const CS_HARD: u32 = 0x0000_0100;
const CS_KILL: u32 = 0x0000_0200;
const CS_CHECK_EXPIRATION: u32 = 0x0000_0400;
const CS_RESTRICT: u32 = 0x0000_0800;
const CS_ENFORCEMENT: u32 = 0x0000_1000;
pub(super) const CS_REQUIRE_LV: u32 = 0x0000_2000;
pub(super) const CS_RUNTIME: u32 = 0x0001_0000;
const CS_LINKER_SIGNED: u32 = 0x0002_0000;
const CS_EXEC_SET_HARD: u32 = 0x0010_0000;
const CS_EXEC_SET_KILL: u32 = 0x0020_0000;
const CS_EXEC_SET_ENFORCEMENT: u32 = 0x0040_0000;
const CS_NO_UNTRUSTED_HELPERS: u32 = 0x0200_0000;
pub(super) const CS_PLATFORM_BINARY: u32 = 0x0400_0000;
const CS_DEBUGGED: u32 = 0x1000_0000;
const CS_SIGNED: u32 = 0x2000_0000;
const CS_ALLOWED_MACHO: u32 = CS_ADHOC
    | CS_HARD
    | CS_KILL
    | CS_CHECK_EXPIRATION
    | CS_RESTRICT
    | CS_ENFORCEMENT
    | CS_REQUIRE_LV
    | CS_RUNTIME
    | CS_LINKER_SIGNED;
/// The flags `CS_OPS_SET_STATUS` may add.
const SETTABLE: u32 = CS_HARD
    | CS_EXEC_SET_HARD
    | CS_KILL
    | CS_EXEC_SET_KILL
    | CS_RESTRICT
    | CS_REQUIRE_LV
    | CS_ENFORCEMENT
    | CS_EXEC_SET_ENFORCEMENT;
const CS_VALIDATION_CATEGORY_PLATFORM: u32 = 1;
const CDHASH_BYTES: usize = 20;
const BLOB_HEADER_BYTES: u64 = 8;

/// The executable's code signature, as exec read it.
#[derive(Debug, Clone, Default)]
pub struct Signature {
    pub directory_flags: u32,
    pub platform: u8,
    pub hash_type: u8,
    pub cdhash: [u8; CDHASH_BYTES],
    pub identifier: Option<String>,
    pub team_identifier: Option<String>,
    /// The entitlements blobs, each with its 8-byte blob header.
    pub entitlements: Option<Vec<u8>>,
    pub der_entitlements: Option<Vec<u8>>,
    /// Whether Apple signed it (`CodeSignature::apple_signed`).
    pub apple_signed: bool,
}

impl Signature {
    /// The process's code-signing flags after exec. Trust-cache code is a
    /// restricted platform binary; Apple-signed code outside the trust
    /// caches is a platform binary too (Xcode's `python3` runs with
    /// `0x26004001` on the 25G241 host).
    pub fn exec_flags(&self) -> u32 {
        let mut flags = (self.directory_flags & CS_ALLOWED_MACHO) | CS_VALID | CS_SIGNED;
        if self.platform != 0 {
            flags |= CS_PLATFORM_BINARY | CS_NO_UNTRUSTED_HELPERS | CS_RESTRICT;
        } else if self.apple_signed {
            flags |= CS_PLATFORM_BINARY | CS_NO_UNTRUSTED_HELPERS;
        }
        flags
    }

    /// Whether exec gives the task a platform-restrictions version
    /// (`imgact_setup_platform_restrictions`, `task_set_hardened_runtime`):
    /// a platform binary, a hardened-process entitlement or a hardened
    /// browser engine. Such a task's IPC space takes the enhanced policies
    /// (`ipc_policy_for_task`) and its EXC_GUARD defaults are the
    /// platform's (`task_set_exc_guard_default`). Mach-hardening opt-outs
    /// are AMFI boot-args, which Stela does not set.
    pub fn platform_restricted(&self) -> bool {
        const HARDENING: [&str; 2] = [
            "com.apple.security.hardened-process.platform-restrictions-string",
            "com.apple.security.hardened-process.platform-restrictions",
        ];
        const BROWSER_ENGINE: [&str; 4] = [
            "com.apple.developer.web-browser-engine.host",
            "com.apple.developer.web-browser-engine.rendering",
            "com.apple.developer.web-browser-engine.networking",
            "com.apple.developer.web-browser-engine.webcontent",
        ];
        let present = |name: &str| {
            self.entitlements.as_deref().is_some_and(|blob| {
                blob.get(BLOB_HEADER_BYTES as usize..)
                    .is_some_and(|plist| code_signature::xml_entitlement_present(plist, name))
            })
        };
        self.exec_flags() & CS_PLATFORM_BINARY != 0
            || HARDENING.iter().any(|name| present(name))
            || BROWSER_ENGINE.iter().any(|name| self.entitled(name))
    }

    /// Whether a pointer-authentication failure ends the process rather
    /// than raising SIGBUS (`task_set_pac_exception_fatal_flag` at exec):
    /// for a PAC-hardened task (the private PAC-exception entitlement, or a
    /// platform-restrictions version), and for any platform binary on FPAC
    /// hardware.
    pub fn pac_exception_fatal(&self, fpac: bool) -> bool {
        let platform = self.exec_flags() & CS_PLATFORM_BINARY != 0;
        self.entitled("com.apple.private.pac.exception")
            || self.platform_restricted()
            || (fpac && platform)
    }

    /// Whether the XML entitlements grant the boolean `name`.
    pub fn entitled(&self, name: &str) -> bool {
        self.entitlements.as_deref().is_some_and(|blob| {
            blob.get(BLOB_HEADER_BYTES as usize..)
                .is_some_and(|plist| code_signature::xml_entitlement_true(plist, name))
        })
    }
}

pub(super) const CALLS: &[&str] = &["csops", "csops_audittoken"];

pub(super) fn call(kernel: &mut Kernel, call: &Call) -> Result<Option<Outcome>> {
    if !CALLS.contains(&call.entry.name) {
        return Ok(None);
    }
    let [pid, operation, address, size, token, ..] = call.arguments;
    let own = std::process::id() as u64;
    let pid = pid as u32 as u64;
    if pid != 0 && pid != own {
        return Ok(Some(forward(kernel, call)?));
    }
    if call.entry.name == "csops_audittoken" && token != 0 {
        // `val[5]` is the pid and `val[7]` the pid version.
        let Some(bytes) = memory::read(token, 32) else {
            return Ok(Some(Outcome::Error(EFAULT)));
        };
        let word =
            |index: usize| u32::from_le_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap());
        if u64::from(word(5)) != own {
            return Ok(Some(Outcome::Error(ESRCH)));
        }
    }
    Ok(Some(own_process(kernel, operation, address, size)?))
}

fn own_process(kernel: &mut Kernel, operation: u64, address: u64, size: u64) -> Result<Outcome> {
    let executable = lock(&kernel.process.executable).clone();
    let Some(signature) = executable.signature.as_ref() else {
        bail!("csops on an unsigned executable: exec admits only signed arm64 images");
    };
    let flags = executable.code_signing_flags;
    let valid = flags & (CS_VALID | CS_DEBUGGED) != 0;
    let write = |bytes: &[u8]| {
        if memory::write(address, bytes) {
            Outcome::value(0)
        } else {
            Outcome::Error(EFAULT)
        }
    };
    Ok(match operation {
        CS_OPS_STATUS => {
            let status = flags | CS_ENFORCEMENT;
            if address == 0 {
                Outcome::value(0)
            } else {
                write(&status.to_le_bytes())
            }
        }
        CS_OPS_CDHASH => {
            if size != CDHASH_BYTES as u64 {
                return Ok(Outcome::Error(EINVAL));
            }
            write(&signature.cdhash)
        }
        CS_OPS_CDHASH_WITH_INFO => {
            // `csops_cdhash_t`: the hash and its `uint32_t` type.
            let mut info = signature.cdhash.to_vec();
            info.extend(u32::from(signature.hash_type).to_le_bytes());
            if size != info.len() as u64 {
                return Ok(Outcome::Error(EINVAL));
            }
            write(&info)
        }
        CS_OPS_IDENTITY | CS_OPS_TEAMID => {
            if size < BLOB_HEADER_BYTES {
                return Ok(Outcome::Error(ERANGE));
            }
            if !valid {
                return Ok(Outcome::Error(EINVAL));
            }
            let identity = if operation == CS_OPS_TEAMID {
                &signature.team_identifier
            } else {
                &signature.identifier
            };
            let Some(identity) = identity else {
                return Ok(Outcome::Error(ENOENT));
            };
            let length = identity.len() as u64 + 1;
            let mut header = [0u8; BLOB_HEADER_BYTES as usize];
            header[4..].copy_from_slice(&((length + BLOB_HEADER_BYTES) as u32).to_be_bytes());
            if !memory::write(address, &header) {
                return Ok(Outcome::Error(EFAULT));
            }
            if size < BLOB_HEADER_BYTES + length {
                return Ok(Outcome::Error(ERANGE));
            }
            let mut text = identity.as_bytes().to_vec();
            text.push(0);
            if memory::write(address + BLOB_HEADER_BYTES, &text) {
                Outcome::value(0)
            } else {
                Outcome::Error(EFAULT)
            }
        }
        CS_OPS_ENTITLEMENTS_BLOB | CS_OPS_DER_ENTITLEMENTS_BLOB => {
            if !valid {
                return Ok(Outcome::Error(EINVAL));
            }
            let blob = if operation == CS_OPS_ENTITLEMENTS_BLOB {
                &signature.entitlements
            } else {
                &signature.der_entitlements
            };
            match blob {
                // Without entitlements the call succeeds and copies nothing.
                None => Outcome::value(0),
                Some(blob) => copy_token(blob, address, size),
            }
        }
        CS_OPS_VALIDATION_CATEGORY => {
            if signature.platform == 0 {
                bail!(
                    "csops CS_OPS_VALIDATION_CATEGORY for a non-platform executable needs \
                     AMFI's signer classification, which is not modeled"
                );
            }
            write(&CS_VALIDATION_CATEGORY_PLATFORM.to_le_bytes())
        }
        CS_OPS_MARKRESTRICT => {
            lock(&kernel.process.executable).code_signing_flags |= CS_RESTRICT;
            Outcome::value(0)
        }
        CS_OPS_MARKHARD | CS_OPS_MARKKILL => {
            let flag = if operation == CS_OPS_MARKHARD {
                CS_HARD
            } else {
                CS_KILL
            };
            lock(&kernel.process.executable).code_signing_flags |= flag;
            // A process already invalid becomes killed or fails here.
            if flags & CS_VALID == 0 {
                bail!("csops marking an invalid process is not modeled");
            }
            Outcome::value(0)
        }
        CS_OPS_SET_STATUS => {
            if size < 4 {
                return Ok(Outcome::Error(ERANGE));
            }
            let Some(requested) = memory::read_u32(address) else {
                return Ok(Outcome::Error(EFAULT));
            };
            if flags & CS_VALID == 0 {
                return Ok(Outcome::Error(EINVAL));
            }
            lock(&kernel.process.executable).code_signing_flags |= requested & SETTABLE;
            Outcome::value(0)
        }
        CS_OPS_MARKINVALID => {
            bail!("csops CS_OPS_MARKINVALID: invalidating the process's signature is not modeled")
        }
        other => bail!("csops operation {other} on this process is not implemented"),
    })
}

/// `csops_copy_token`.
fn copy_token(blob: &[u8], address: u64, size: u64) -> Outcome {
    if size < BLOB_HEADER_BYTES {
        return Outcome::Error(ERANGE);
    }
    if size < blob.len() as u64 {
        let mut header = [0u8; BLOB_HEADER_BYTES as usize];
        header[4..].copy_from_slice(&(blob.len() as u32).to_be_bytes());
        return if memory::write(address, &header) {
            Outcome::Error(ERANGE)
        } else {
            Outcome::Error(EFAULT)
        };
    }
    if memory::write(address, blob) {
        Outcome::value(0)
    } else {
        Outcome::Error(EFAULT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_binaries_match_the_hosts_report() {
        let signature = Signature {
            directory_flags: CS_RUNTIME,
            platform: 13,
            ..Signature::default()
        };
        assert_eq!(signature.exec_flags(), 0x2601_0801);
        let apple = Signature {
            apple_signed: true,
            ..Signature::default()
        };
        assert_eq!(apple.exec_flags(), 0x2600_0001);
        let adhoc = Signature {
            directory_flags: CS_ADHOC | CS_LINKER_SIGNED,
            ..Signature::default()
        };
        assert_eq!(
            adhoc.exec_flags(),
            CS_ADHOC | CS_LINKER_SIGNED | CS_VALID | CS_SIGNED
        );
    }

    #[test]
    fn pac_failures_end_hardened_tasks_only() {
        let plist = |keys: &str| {
            let mut blob = vec![0; BLOB_HEADER_BYTES as usize];
            blob.extend(format!("<plist><dict>{keys}</dict></plist>").bytes());
            Some(blob)
        };
        let third_party = Signature {
            directory_flags: CS_RUNTIME,
            ..Signature::default()
        };
        assert!(!third_party.pac_exception_fatal(true));
        let platform = Signature {
            platform: 13,
            ..Signature::default()
        };
        assert!(platform.pac_exception_fatal(false));
        let entitled = Signature {
            entitlements: plist("<key>com.apple.private.pac.exception</key><true/>"),
            ..Signature::default()
        };
        assert!(entitled.pac_exception_fatal(false));
        let restricted = Signature {
            entitlements: plist(
                "<key>com.apple.security.hardened-process.platform-restrictions</key>\
                 <integer>2</integer>",
            ),
            ..Signature::default()
        };
        assert!(restricted.pac_exception_fatal(false));
    }
}
