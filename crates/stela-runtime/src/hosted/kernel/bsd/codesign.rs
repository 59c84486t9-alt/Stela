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
use super::{Call, Kernel, Outcome, forward};
use crate::hosted::darwin::{EFAULT, EINVAL, ENOENT, ERANGE, ESRCH};
use crate::hosted::pe::UserJop;
use crate::hosted::{memory, threads::lock};
pub(crate) use crate::hosted_registry::bsd::codesign::CALLS;
use anyhow::{Context, Result, bail, ensure};
use stela_formats::code_signature;

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

/// The exec security mitigations' entitlements, legacy and security
/// names (`exec_security_mitigation_entitlement`, `bsd/kern/kern_exec.c`).
const HARDENED_PROCESS: [&str; 2] = [
    "com.apple.developer.hardened-process",
    "com.apple.security.hardened-process",
];
const HARDENED_HEAP: [&str; 2] = [
    "com.apple.developer.hardened-process.hardened-heap",
    "com.apple.security.hardened-process.hardened-heap",
];
const CHECKED_ALLOCATIONS: [&str; 2] = [
    "com.apple.developer.hardened-process.checked-allocations",
    "com.apple.security.hardened-process.checked-allocations",
];
const SCRIPT_RESTRICTIONS: &str = "com.apple.security.script-restrictions";
const IPC_CONTAINMENT_VESSEL: &str = "com.apple.security.hardened-process.containment.ipc";
const NO_GUARD_OBJECTS: &str = "com.apple.security.hardened-process.no-guard-objects";
/// `HARDENED_PROCESS_VERSION_STRING`, `HARDENED_PROCESS_VERSION` and
/// `HARDENED_PROCESS_VERSION_LATEST` (`kern_exec_internal.h`).
const HARDENED_PROCESS_VERSION_STRING: &str =
    "com.apple.security.hardened-process.enhanced-security-version-string";
const HARDENED_PROCESS_VERSION: &str =
    "com.apple.security.hardened-process.enhanced-security-version";
const HARDENED_PROCESS_VERSION_LATEST: u64 = 2;
/// `SPAWN_ENABLE_PLATFORM_RESTRICTIONS_ENT_STR` and `_INT`.
const PLATFORM_RESTRICTIONS_STRING: &str =
    "com.apple.security.hardened-process.platform-restrictions-string";
const PLATFORM_RESTRICTIONS: &str = "com.apple.security.hardened-process.platform-restrictions";
/// `kCSWebBrowser*Entitlement`: a hardened browser engine.
const BROWSER_ENGINE: [&str; 4] = [
    "com.apple.developer.web-browser-engine.host",
    "com.apple.developer.web-browser-engine.rendering",
    "com.apple.developer.web-browser-engine.networking",
    "com.apple.developer.web-browser-engine.webcontent",
];
/// `kIODriverKitEntitlementKey`.
const DRIVERKIT: &str = "com.apple.developer.driverkit";
/// The JIT entitlements: the hardened runtime's (AMFI), the platform's
/// (TXM's JIT-region check) and `SINGLE_JIT_ENTITLEMENT` (`kern_exec.c`).
const ALLOW_JIT: &str = "com.apple.security.cs.allow-jit";
const DYNAMIC_CODESIGNING: &str = "dynamic-codesigning";
const SINGLE_JIT: &str = "com.apple.security.cs.single-jit";
/// `process_is_plugin_host`'s entitlements (`bsd/kern/mach_loader.c`,
/// `OVERRIDE_PLUGIN_HOST_ENTITLEMENT`, `CLEAR_LV_ENTITLEMENT`) and its
/// `hardening_exceptions` identities, matched as prefixes. XNU compiles
/// that list in, taken from `/System/Library/Security/HardeningExceptions.plist`,
/// and never reads the file: the kernel's copy is the one modeled.
const OVERRIDE_PLUGIN_HOST: &str = "com.apple.private.security.override-plugin-host-detection";
const DISABLE_LIBRARY_VALIDATION: [&str; 3] = [
    "com.apple.security.cs.disable-library-validation",
    "com.apple.private.cs.automator-plugins",
    "com.apple.private.security.clear-library-validation",
];
const HARDENING_EXCEPTIONS: [&str; 11] = [
    "com.apple.perl5",
    "com.apple.perl",
    "org.python.python",
    "com.apple.expect",
    "com.tcltk.wish",
    "com.tcltk.tclsh",
    "com.apple.ruby",
    "com.apple.bash",
    "com.apple.zsh",
    "com.apple.ksh",
    "com.apple.sh",
];

/// `struct task_security_config` (`osfmk/kern/task.h`): its `uint16_t`
/// bit fields, then `hardened_process_version` in the third byte.
const CONFIG_HARDENED_HEAP: u32 = 1 << 0;
const CONFIG_PLATFORM_RESTRICTIONS_SHIFT: u32 = 3;
const CONFIG_SCRIPT_RESTRICTIONS: u32 = 1 << 6;
const CONFIG_IPC_CONTAINMENT_VESSEL: u32 = 1 << 7;
const CONFIG_GUARD_OBJECTS: u32 = 1 << 8;
const CONFIG_HARDENED_PROCESS_SHIFT: u32 = 16;

/// `ipc_space_policy_t` (`osfmk/ipc/ipc_types.h`) as macOS defines it.
pub const IPC_SPACE_POLICY_DEFAULT: u32 = 0x0001;
pub const IPC_SPACE_POLICY_ENHANCED: u32 = 0x0002;
pub const IPC_SPACE_POLICY_PLATFORM: u32 = 0x0004;
pub const IPC_SPACE_POLICY_CONTAINED: u32 = 0x0008;
pub const IPC_SPACE_POLICY_OPTED_OUT: u32 = 0x0080;
pub const IPC_SPACE_POLICY_ENHANCED_V0: u32 = 0x0100;
pub const IPC_SPACE_POLICY_ENHANCED_V1: u32 = 0x0200;
pub const IPC_SPACE_POLICY_ENHANCED_V2: u32 = 0x0300;
pub const IPC_SPACE_POLICY_ENHANCED_V3: u32 = 0x0400;

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

    /// Whether exec gives the task a platform-restrictions version: a
    /// platform binary, a platform-restrictions entitlement or a hardened
    /// browser engine. Such a task's IPC space takes the enhanced policies
    /// (`ipc_policy_for_task`) and its EXC_GUARD defaults are the
    /// platform's (`task_set_exc_guard_default`).
    pub fn platform_restricted(&self) -> bool {
        self.restrictions_version()
            .is_ok_and(|version| version != 0)
    }

    /// The task's platform-restrictions version: 1 for a hardened browser
    /// engine (`imgact_setup_runtime_mitigations`), then as
    /// `imgact_setup_platform_restrictions` overrides it: 3 for a platform
    /// binary, the string entitlement's version (2 to 7), 2 for the
    /// integer entitlement. An invalid string fails exec with `EINVAL`.
    pub fn restrictions_version(&self) -> Result<u8> {
        if self.platform_binary() {
            return Ok(3);
        }
        if let Some(value) = self.entitlement_value(PLATFORM_RESTRICTIONS_STRING) {
            let version = string_value(value)
                .and_then(|text| text.parse::<u8>().ok())
                .filter(|version| (2..8).contains(version));
            return version.with_context(|| {
                format!(
                    "exec fails with EINVAL: {PLATFORM_RESTRICTIONS_STRING} is {value:?}, not a \
                     version from 2 to 7"
                )
            });
        }
        if self.entitlement_value(PLATFORM_RESTRICTIONS).is_some() {
            return Ok(2);
        }
        Ok(u8::from(
            BROWSER_ENGINE.iter().any(|name| self.entitled(name)),
        ))
    }

    /// The task's hardened-process version (`load_machfile`): with the
    /// hardened-process entitlement, the string or integer version
    /// entitlement's, else and at most `HARDENED_PROCESS_VERSION_LATEST`;
    /// 0 without it. A string that is no number fails exec.
    pub fn hardened_process_version(&self) -> Result<u8> {
        if !self.mitigation(HARDENED_PROCESS)? {
            return Ok(0);
        }
        let version = match self.entitlement_value(HARDENED_PROCESS_VERSION_STRING) {
            Some(value) => string_value(value)
                .and_then(|text| text.parse::<u32>().ok())
                .with_context(|| {
                    format!(
                        "exec fails with LOAD_BADMACHO: {HARDENED_PROCESS_VERSION_STRING} is \
                         {value:?}"
                    )
                })?
                .into(),
            None => self
                .entitlement_value(HARDENED_PROCESS_VERSION)
                .and_then(integer_value)
                .unwrap_or(HARDENED_PROCESS_VERSION_LATEST),
        };
        Ok(version.min(HARDENED_PROCESS_VERSION_LATEST) as u8)
    }

    /// `task_get_security_config` after exec
    /// (`imgact_setup_runtime_mitigations`): hardened heap, the
    /// platform-restrictions version, script restrictions, the IPC
    /// containment vessel, guard objects and the hardened-process version.
    /// TPRO has no setter in xnu-12377. On a chip with memory tagging the
    /// checked-allocations bit also depends on AMFI's opt-out list, which
    /// is not modeled, so a task that could take it is refused there.
    pub fn security_config(&self, memory_tagging: bool) -> Result<u32> {
        let hardened_process = self.hardened_process_version()?;
        let platform_driver = self.platform_binary() && self.entitled(DRIVERKIT);
        ensure!(
            !memory_tagging || (hardened_process == 0 && !platform_driver),
            "the checked-allocations (MTE) configuration of a hardened process is not modeled"
        );
        let mut config = u32::from(self.restrictions_version()?)
            << CONFIG_PLATFORM_RESTRICTIONS_SHIFT
            | u32::from(hardened_process) << CONFIG_HARDENED_PROCESS_SHIFT;
        if self.mitigation(HARDENED_HEAP)? {
            config |= CONFIG_HARDENED_HEAP;
        }
        if self.entitled(SCRIPT_RESTRICTIONS) {
            config |= CONFIG_SCRIPT_RESTRICTIONS;
        }
        if self.entitled(IPC_CONTAINMENT_VESSEL) {
            config |= CONFIG_IPC_CONTAINMENT_VESSEL;
        }
        // `imgact_setup_guard_objects`.
        if !self.entitled(NO_GUARD_OBJECTS) && (u64::from(hardened_process) >= 2 || platform_driver)
        {
            config |= CONFIG_GUARD_OBJECTS;
        }
        // Both checked-allocations names fail exec, as every mitigation's.
        self.mitigation(CHECKED_ALLOCATIONS)?;
        Ok(config)
    }

    /// Whether exec treats the image as a platform plugin host and runs it
    /// with JOP keys off and Mach hardening opted out
    /// (`process_is_plugin_host`): a pointer-authenticating platform binary
    /// that disables library validation or whose identity is a hardening
    /// exception. With the override entitlement only the
    /// `posix_spawnattr_disable_ptr_auth_a_keys_np` attribute makes one,
    /// which is not modeled.
    pub fn plugin_host(&self, jop: UserJop) -> bool {
        if jop == UserJop::Disabled || !self.platform_binary() {
            return false;
        }
        let Some(identity) = &self.identifier else {
            return false;
        };
        if self.entitled(OVERRIDE_PLUGIN_HOST) {
            return false;
        }
        DISABLE_LIBRARY_VALIDATION
            .iter()
            .any(|name| self.entitled(name))
            || HARDENING_EXCEPTIONS
                .iter()
                .any(|exception| identity.starts_with(exception))
    }

    /// The task's IPC space policy (`ipc_policy_for_task`): the platform
    /// level for a platform binary, the enhanced version of its
    /// platform-restrictions version or hardened runtime, opted out for a
    /// plugin host, contained for the IPC containment vessel.
    pub fn ipc_space_policy(&self, jop: UserJop) -> Result<u32> {
        let mut policy = IPC_SPACE_POLICY_DEFAULT;
        if self.platform_binary() {
            policy |= IPC_SPACE_POLICY_PLATFORM | IPC_SPACE_POLICY_ENHANCED;
        }
        policy |= match self.restrictions_version()? {
            3.. => IPC_SPACE_POLICY_ENHANCED | IPC_SPACE_POLICY_ENHANCED_V3,
            2 => IPC_SPACE_POLICY_ENHANCED | IPC_SPACE_POLICY_ENHANCED_V2,
            1 => IPC_SPACE_POLICY_ENHANCED | IPC_SPACE_POLICY_ENHANCED_V1,
            0 if self.exec_flags() & CS_RUNTIME != 0 => {
                IPC_SPACE_POLICY_ENHANCED | IPC_SPACE_POLICY_ENHANCED_V0
            }
            0 => 0,
        };
        if self.plugin_host(jop) {
            policy |= IPC_SPACE_POLICY_OPTED_OUT;
        }
        if self.entitled(IPC_CONTAINMENT_VESSEL) {
            policy |= IPC_SPACE_POLICY_CONTAINED;
        }
        Ok(policy)
    }

    /// Whether exec's load result is a platform binary (`TFRO_PLATFORM`).
    fn platform_binary(&self) -> bool {
        self.exec_flags() & CS_PLATFORM_BINARY != 0
    }

    /// Whether a mitigation's legacy or security entitlement is granted
    /// (`exec_check_security_entitlement`); both fail exec.
    fn mitigation(&self, [legacy, security]: [&str; 2]) -> Result<bool> {
        let (legacy, security) = (self.entitled(legacy), self.entitled(security));
        ensure!(
            !(legacy && security),
            "exec fails: the image has both the legacy and the security name of an exec \
             security mitigation entitlement"
        );
        Ok(legacy || security)
    }

    /// The XML text after `<key>name</key>`, when the entitlements hold
    /// `name` with any value (`IOVnodeIsEntitlementPresentWithAnyValue`).
    fn entitlement_value(&self, name: &str) -> Option<&str> {
        let plist = self
            .entitlements
            .as_deref()?
            .get(BLOB_HEADER_BYTES as usize..)?;
        if !code_signature::xml_entitlement_present(plist, name) {
            return None;
        }
        let text = core::str::from_utf8(plist).ok()?;
        let key = format!("<key>{name}</key>");
        let at = text.find(&key)? + key.len();
        Some(text[at..].trim_start())
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

    /// Whether AMFI lets the process map JIT memory
    /// (`mac_proc_check_map_anon` with MAP_JIT, which exec also asks to
    /// size the map): any process outside the hardened runtime, and a
    /// hardened one that holds `com.apple.security.cs.allow-jit` or
    /// `dynamic-codesigning` (the entitlement TXM's JIT-region check also
    /// accepts).
    pub fn jit_allowed(&self) -> bool {
        self.exec_flags() & CS_RUNTIME == 0
            || self.entitled(ALLOW_JIT)
            || self.entitled(DYNAMIC_CODESIGNING)
    }

    /// Whether exec limits the map to one JIT entry (`vm_map_single_jit`).
    pub fn single_jit(&self) -> bool {
        self.entitled(SINGLE_JIT)
    }

    /// Whether the XML entitlements grant the boolean `name`.
    pub fn entitled(&self, name: &str) -> bool {
        self.entitlements.as_deref().is_some_and(|blob| {
            blob.get(BLOB_HEADER_BYTES as usize..)
                .is_some_and(|plist| code_signature::xml_entitlement_true(plist, name))
        })
    }
}

/// The text of a `<string>` value (`IOVnodeGetEntitlement`).
fn string_value(value: &str) -> Option<&str> {
    value
        .strip_prefix("<string>")?
        .split_once("</string>")
        .map(|(text, _)| text)
}

/// The number of an `<integer>` value (`IOVnodeGetIntegerEntitlement`).
fn integer_value(value: &str) -> Option<u64> {
    let (text, _) = value.strip_prefix("<integer>")?.split_once("</integer>")?;
    text.trim().parse().ok()
}

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
                crate::hosted::unsupported::refuse!(
                    EINVAL,
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
                crate::hosted::unsupported::refuse!(
                    EINVAL,
                    "csops marking an invalid process is not modeled"
                );
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
            crate::hosted::unsupported::refuse!(
                EINVAL,
                "csops CS_OPS_MARKINVALID: invalidating the process's signature is not modeled"
            )
        }
        other => crate::hosted::unsupported::refuse!(
            EINVAL,
            "csops operation {other} on this process is not implemented"
        ),
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

    #[test]
    fn jit_follows_the_hardened_runtime_and_its_entitlements() {
        assert!(Signature::default().jit_allowed());
        let hardened = Signature {
            directory_flags: CS_RUNTIME,
            ..Signature::default()
        };
        assert!(!hardened.jit_allowed());
        for key in [ALLOW_JIT, DYNAMIC_CODESIGNING] {
            let signature = Signature {
                directory_flags: CS_RUNTIME,
                ..entitled(&format!("<key>{key}</key><true/>"))
            };
            assert!(signature.jit_allowed(), "{key}");
        }
        let denied = Signature {
            directory_flags: CS_RUNTIME,
            ..entitled("<key>com.apple.security.cs.allow-jit</key><false/>")
        };
        assert!(!denied.jit_allowed());
        assert!(entitled("<key>com.apple.security.cs.single-jit</key><true/>").single_jit());
        assert!(!hardened.single_jit());
    }

    fn entitled(keys: &str) -> Signature {
        let mut blob = vec![0; BLOB_HEADER_BYTES as usize];
        blob.extend(format!("<plist><dict>{keys}</dict></plist>").bytes());
        Signature {
            entitlements: Some(blob),
            ..Signature::default()
        }
    }

    #[test]
    fn restriction_versions_follow_the_string_then_the_integer_entitlement() {
        let string = |value: &str| {
            entitled(&format!(
                "<key>{PLATFORM_RESTRICTIONS_STRING}</key><string>{value}</string>"
            ))
        };
        assert_eq!(string("5").restrictions_version().unwrap(), 5);
        for invalid in ["1", "8", "x", ""] {
            assert!(string(invalid).restrictions_version().is_err(), "{invalid}");
        }
        let integer = entitled(&format!(
            "<key>{PLATFORM_RESTRICTIONS}</key><integer>7</integer>"
        ));
        assert_eq!(integer.restrictions_version().unwrap(), 2);
        let browser = entitled(&format!("<key>{}</key><true/>", BROWSER_ENGINE[0]));
        assert_eq!(browser.restrictions_version().unwrap(), 1);
        assert_eq!(
            browser.ipc_space_policy(UserJop::Enabled).unwrap(),
            IPC_SPACE_POLICY_DEFAULT | IPC_SPACE_POLICY_ENHANCED | IPC_SPACE_POLICY_ENHANCED_V1
        );
        assert_eq!(Signature::default().restrictions_version().unwrap(), 0);
    }

    #[test]
    fn the_security_config_packs_each_mitigation() {
        let hardened = |extra: &str| {
            entitled(&format!(
                "<key>com.apple.security.hardened-process</key><true/>{extra}"
            ))
        };
        // The latest version without a version entitlement, and guard
        // objects from version 2.
        assert_eq!(hardened("").security_config(false).unwrap(), 0x2_0100);
        let version_one = hardened(&format!(
            "<key>{HARDENED_PROCESS_VERSION}</key><integer>1</integer>"
        ));
        assert_eq!(version_one.security_config(false).unwrap(), 0x1_0000);
        let opted_out = hardened(&format!("<key>{NO_GUARD_OBJECTS}</key><true/>"));
        assert_eq!(opted_out.security_config(false).unwrap(), 0x2_0000);
        let contained = entitled(&format!(
            "<key>{IPC_CONTAINMENT_VESSEL}</key><true/><key>{SCRIPT_RESTRICTIONS}</key><true/>"
        ));
        assert_eq!(contained.security_config(false).unwrap(), 0xc0);
        assert_eq!(
            contained.ipc_space_policy(UserJop::Enabled).unwrap(),
            IPC_SPACE_POLICY_DEFAULT | IPC_SPACE_POLICY_CONTAINED
        );
        let bad_version = hardened(&format!(
            "<key>{HARDENED_PROCESS_VERSION_STRING}</key><string>two</string>"
        ));
        assert!(bad_version.security_config(false).is_err());
        let both = hardened("<key>com.apple.developer.hardened-process</key><true/>");
        assert!(both.security_config(false).is_err());
        // Memory tagging hardware: the checked-allocations bit of a hardened
        // process is refused, an ordinary task's is clear.
        assert!(hardened("").security_config(true).is_err());
        assert_eq!(Signature::default().security_config(true).unwrap(), 0);
    }

    #[test]
    fn plugin_hosts_are_pointer_authenticating_platform_binaries() {
        let shell = Signature {
            platform: 13,
            identifier: Some("com.apple.zsh".into()),
            ..Signature::default()
        };
        assert!(shell.plugin_host(UserJop::Enabled));
        assert!(!shell.plugin_host(UserJop::Disabled));
        let third_party = Signature {
            identifier: Some("com.apple.zsh".into()),
            ..Signature::default()
        };
        assert!(!third_party.plugin_host(UserJop::Enabled));
        let mut overridden = entitled(&format!(
            "<key>{OVERRIDE_PLUGIN_HOST}</key><true/><key>{}</key><true/>",
            DISABLE_LIBRARY_VALIDATION[0]
        ));
        overridden.platform = 13;
        overridden.identifier = Some("com.example.host".into());
        assert!(!overridden.plugin_host(UserJop::Enabled));
    }
}
