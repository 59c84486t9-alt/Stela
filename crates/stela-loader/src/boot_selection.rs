//! LLB's boot choice from NVRAM: which installed system, and which of its
//! operating systems (macOS, its paired recoveryOS or System Recovery),
//! from the variables of the machine's persistent NOR bank.
//!
//! Known, from the 26A434 J473 LLB (`Firmware/all_flash/LLB.j473.RELEASE`,
//! raw image offsets):
//!
//! - 0xd46b8 reads `alt-boot-volume` and, when present, removes it and saves
//!   NVRAM before booting it, so it chooses one boot only; otherwise it reads
//!   `boot-volume`.
//! - 0xd4744 parses either as `TYPE:PARTITION:GROUP`, three UUID texts. The
//!   first must name one of three partition types, written as `uuid_unparse`
//!   of the GPT type GUID's on-disk bytes: APFS
//!   (`EF57347C-0000-AA11-AA11-00306543ECAC`), the iBoot System Container
//!   (`61696469-0067-AA11-AA11-00306543ECAC`) or the recoveryOS container
//!   (`72766352-0079-AA11-AA11-00306543ECAC`). The third is the APFS volume
//!   group.
//! - 0x2a58 removes `one-time-boot-command` (with the `iboot-failure-reason`
//!   variables) and saves NVRAM; 0x2a74 and 0x2ab8 read `auto-boot` and
//!   `auto-boot-once`. Its boot-command table is `fsboot`, `recover`
//!   ("Paired Recovery"), `recover-once`, `recover-system` ("System
//!   Recovery"), `recover-fallback`, `device-recovery`, `upgrade`,
//!   `post-upgrade`, `fsboot-safe` and `field-diags-paired`.
//! - The 26A434 kernel's `IOSetRecoveryBoot` and iBoot (0x4464) send a
//!   machine to recovery by setting `recovery-boot-mode` with `boot-command`
//!   `recover-system` or `recover`.
//!
//! Inferred: the second UUID is the partition's unique GUID in the same
//! on-disk byte order as the type; `one-time-boot-command` takes precedence
//! over `boot-command`; a set `recovery-boot-mode` without a recovery
//! command boots the paired recoveryOS (the variable stays for recoveryOS
//! to read and clear); `fsboot-safe` is a safe-mode (`-x`) macOS boot;
//! `auto-boot-once=true` overrides `auto-boot=false` once and is consumed.
//! Each variable is read from the `system` partition first, then `common`,
//! since which one LLB reads is Unknown.
//!
//! Unknown, and refused explicitly: `device-recovery`, `upgrade`,
//! `post-upgrade` and `field-diags-paired` boots, and a machine with
//! `auto-boot=false`, which LLB leaves in iBoot recovery mode.
use alloc::{format, string::String, vec::Vec};
use anyhow::{Result, bail, ensure};
use stela_runtime::machine::apple::nor::nvram::{Partition, Variables};

pub const BOOT_VOLUME: &[u8] = b"boot-volume";
pub const ALT_BOOT_VOLUME: &[u8] = b"alt-boot-volume";
pub const BOOT_COMMAND: &[u8] = b"boot-command";
pub const ONE_TIME_BOOT_COMMAND: &[u8] = b"one-time-boot-command";
pub const RECOVERY_BOOT_MODE: &[u8] = b"recovery-boot-mode";
pub const AUTO_BOOT: &[u8] = b"auto-boot";
pub const AUTO_BOOT_ONCE: &[u8] = b"auto-boot-once";
/// The variables LLB removes with `one-time-boot-command`.
pub const FAILURE_REASONS: [&[u8]; 2] = [b"iboot-failure-reason", b"iboot-failure-reason-str"];
const TRUE: &[u8] = b"true";
const FALSE: &[u8] = b"false";
/// `8-4-4-4-12` hexadecimal digits.
const UUID_TEXT_BYTES: usize = 36;
const UUID_GROUPS: [usize; 5] = [8, 4, 4, 4, 12];

/// A UUID in `uuid_t` byte order: the bytes its text names, in order.
pub type Uuid = [u8; 16];

/// Parse `uuid_parse` text: 36 characters, either case.
pub fn parse_uuid(text: &[u8]) -> Option<Uuid> {
    if text.len() != UUID_TEXT_BYTES {
        return None;
    }
    let mut uuid = [0u8; 16];
    let mut at = 0;
    let mut out = 0;
    for (index, width) in UUID_GROUPS.into_iter().enumerate() {
        if index > 0 {
            if text[at] != b'-' {
                return None;
            }
            at += 1;
        }
        for pair in text[at..at + width].chunks(2) {
            let digits = core::str::from_utf8(pair).ok()?;
            uuid[out] = u8::from_str_radix(digits, 16).ok()?;
            out += 1;
        }
        at += width;
    }
    Some(uuid)
}

/// `uuid_unparse_upper` text.
pub fn uuid_text(uuid: &Uuid) -> String {
    let mut text = String::with_capacity(UUID_TEXT_BYTES);
    let mut at = 0;
    for (index, width) in UUID_GROUPS.into_iter().enumerate() {
        if index > 0 {
            text.push('-');
        }
        for byte in &uuid[at..at + width / 2] {
            text.push_str(&format!("{byte:02X}"));
        }
        at += width / 2;
    }
    text
}

/// The partition types a boot volume may name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeType {
    /// An APFS container holding the installed system.
    Apfs,
    /// The iBoot System Container.
    SystemContainer,
    /// The recoveryOS container.
    Recovery,
}

impl VolumeType {
    const ALL: [Self; 3] = [Self::Apfs, Self::SystemContainer, Self::Recovery];

    /// The type as `boot-volume` writes it.
    pub fn text(self) -> &'static str {
        match self {
            Self::Apfs => "EF57347C-0000-AA11-AA11-00306543ECAC",
            Self::SystemContainer => "61696469-0067-AA11-AA11-00306543ECAC",
            Self::Recovery => "72766352-0079-AA11-AA11-00306543ECAC",
        }
    }

    /// The GPT type GUID's on-disk bytes.
    pub fn guid_bytes(self) -> Uuid {
        parse_uuid(self.text().as_bytes()).expect("constant UUID")
    }
}

/// A `boot-volume` or `alt-boot-volume` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootVolume {
    pub kind: VolumeType,
    /// The partition's unique GUID, on-disk bytes.
    pub partition: Uuid,
    /// The APFS volume group.
    pub volume_group: Uuid,
}

impl BootVolume {
    /// Parse `TYPE:PARTITION:GROUP`, optionally NUL-terminated.
    pub fn parse(value: &[u8]) -> Result<Self> {
        let value = value.strip_suffix(b"\0").unwrap_or(value);
        let fields: Vec<&[u8]> = value.split(|&b| b == b':').collect();
        let [kind, partition, group] = fields[..] else {
            bail!(
                "a boot volume is TYPE:PARTITION:GROUP, not {:?}",
                String::from_utf8_lossy(value)
            );
        };
        let uuid = |field: &[u8], what: &str| {
            parse_uuid(field).ok_or_else(|| {
                anyhow::anyhow!(
                    "boot volume {what} {:?} is not a UUID",
                    String::from_utf8_lossy(field)
                )
            })
        };
        let kind_bytes = uuid(kind, "type")?;
        let Some(kind) = VolumeType::ALL
            .into_iter()
            .find(|t| t.guid_bytes() == kind_bytes)
        else {
            bail!(
                "boot volume type {} is none of APFS, the iBoot System Container or recoveryOS",
                uuid_text(&kind_bytes)
            );
        };
        Ok(Self {
            kind,
            partition: uuid(partition, "partition")?,
            volume_group: uuid(group, "volume group")?,
        })
    }

    /// The value as `boot-volume` stores it.
    pub fn encode(&self) -> Vec<u8> {
        format!(
            "{}:{}:{}",
            self.kind.text(),
            uuid_text(&self.partition),
            uuid_text(&self.volume_group)
        )
        .into_bytes()
    }
}

/// An LLB boot command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Fsboot,
    FsbootSafe,
    Recover,
    RecoverOnce,
    RecoverSystem,
    RecoverFallback,
    DeviceRecovery,
    Upgrade,
    PostUpgrade,
    FieldDiagsPaired,
}

impl Command {
    const ALL: [Self; 10] = [
        Self::Fsboot,
        Self::FsbootSafe,
        Self::Recover,
        Self::RecoverOnce,
        Self::RecoverSystem,
        Self::RecoverFallback,
        Self::DeviceRecovery,
        Self::Upgrade,
        Self::PostUpgrade,
        Self::FieldDiagsPaired,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Fsboot => "fsboot",
            Self::FsbootSafe => "fsboot-safe",
            Self::Recover => "recover",
            Self::RecoverOnce => "recover-once",
            Self::RecoverSystem => "recover-system",
            Self::RecoverFallback => "recover-fallback",
            Self::DeviceRecovery => "device-recovery",
            Self::Upgrade => "upgrade",
            Self::PostUpgrade => "post-upgrade",
            Self::FieldDiagsPaired => "field-diags-paired",
        }
    }

    pub fn parse(value: &[u8]) -> Result<Self> {
        let value = value.strip_suffix(b"\0").unwrap_or(value);
        Self::ALL
            .into_iter()
            .find(|c| c.name().as_bytes() == value)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "{:?} is not an LLB boot command",
                    String::from_utf8_lossy(value)
                )
            })
    }
}

/// What the machine boots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// The installed macOS; `safe` adds the safe-mode boot argument.
    MacOs { safe: bool },
    /// The recoveryOS paired with the installed system (its container's
    /// Recovery volume).
    PairedRecovery,
    /// System Recovery: the recoveryOS container's, or Stela's recovery
    /// bundle when the disk has none.
    SystemRecovery,
}

/// The boot LLB would choose, what chose it, and the one-shot variables the
/// boot consumes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    pub target: Target,
    /// The boot volume, when NVRAM names one; otherwise the disk's only
    /// installed system is used.
    pub volume: Option<BootVolume>,
    /// Which variables decided, for the boot log.
    pub reasons: Vec<String>,
    /// Variables removed and saved before the boot.
    pub consumed: Vec<&'static [u8]>,
}

impl Selection {
    /// Whether booting this selection changes NVRAM.
    pub fn consumes(&self) -> bool {
        !self.consumed.is_empty()
    }
}

/// `name`'s value, from `system` and then `common`.
pub fn lookup<'a>(variables: &'a Variables, name: &[u8]) -> Option<&'a [u8]> {
    variables
        .get(Partition::System, name)
        .or_else(|| variables.get(Partition::Common, name))
}

fn strip(value: &[u8]) -> &[u8] {
    value.strip_suffix(b"\0").unwrap_or(value)
}

fn flag(name: &[u8], value: &[u8]) -> Result<bool> {
    match strip(value) {
        TRUE => Ok(true),
        FALSE => Ok(false),
        other => bail!(
            "{} is {:?}, neither true nor false",
            String::from_utf8_lossy(name),
            String::from_utf8_lossy(other)
        ),
    }
}

fn shown(name: &[u8], value: &[u8]) -> String {
    format!(
        "{}={}",
        String::from_utf8_lossy(name),
        String::from_utf8_lossy(strip(value))
    )
}

/// Choose the boot as LLB does; refused for the boots Stela does not model.
pub fn select(variables: &Variables) -> Result<Selection> {
    let mut selection = Selection {
        target: Target::MacOs { safe: false },
        volume: None,
        reasons: Vec::new(),
        consumed: Vec::new(),
    };
    if let Some(value) = lookup(variables, AUTO_BOOT)
        && !flag(AUTO_BOOT, value)?
    {
        match lookup(variables, AUTO_BOOT_ONCE) {
            Some(once) if flag(AUTO_BOOT_ONCE, once)? => {
                selection.reasons.push(shown(AUTO_BOOT_ONCE, once));
                selection.consumed.push(AUTO_BOOT_ONCE);
            }
            _ => bail!(
                "auto-boot=false: LLB stays in iBoot recovery mode, which Stela does not \
                 provide; remove auto-boot from the NOR NVRAM"
            ),
        }
    }
    let volume = match lookup(variables, ALT_BOOT_VOLUME) {
        Some(value) => {
            selection.consumed.push(ALT_BOOT_VOLUME);
            Some((ALT_BOOT_VOLUME, value))
        }
        None => lookup(variables, BOOT_VOLUME).map(|value| (BOOT_VOLUME, value)),
    };
    if let Some((name, value)) = volume {
        selection.volume = Some(BootVolume::parse(value)?);
        selection.reasons.push(shown(name, value));
    }
    let command = match lookup(variables, ONE_TIME_BOOT_COMMAND) {
        Some(value) => {
            selection.consumed.push(ONE_TIME_BOOT_COMMAND);
            selection.consumed.extend(FAILURE_REASONS);
            Some((ONE_TIME_BOOT_COMMAND, value))
        }
        None => lookup(variables, BOOT_COMMAND).map(|value| (BOOT_COMMAND, value)),
    };
    let command = match command {
        Some((name, value)) => {
            selection.reasons.push(shown(name, value));
            Some(Command::parse(value)?)
        }
        None => None,
    };
    let recovery_mode = lookup(variables, RECOVERY_BOOT_MODE);
    selection.target = match command {
        Some(Command::Recover | Command::RecoverOnce) => Target::PairedRecovery,
        Some(Command::RecoverSystem | Command::RecoverFallback) => Target::SystemRecovery,
        Some(
            command @ (Command::DeviceRecovery
            | Command::Upgrade
            | Command::PostUpgrade
            | Command::FieldDiagsPaired),
        ) => bail!(
            "boot-command {} is not modeled: what LLB boots for it is Unknown",
            command.name()
        ),
        _ if recovery_mode.is_some() => {
            let value = recovery_mode.expect("checked");
            selection.reasons.push(shown(RECOVERY_BOOT_MODE, value));
            Target::PairedRecovery
        }
        Some(Command::FsbootSafe) => Target::MacOs { safe: true },
        Some(Command::Fsboot) | None => Target::MacOs { safe: false },
    };
    if let Some(volume) = &selection.volume {
        ensure!(
            volume.kind == VolumeType::Apfs || !matches!(selection.target, Target::MacOs { .. }),
            "boot volume {} is not an APFS container, so it holds no macOS",
            uuid_text(&volume.partition)
        );
    }
    Ok(selection)
}

/// Remove the variables `selection` consumes from whichever partition holds
/// them; returns whether any was removed, when the bank must be saved.
pub fn consume(variables: &mut Variables, selection: &Selection) -> bool {
    let mut changed = false;
    for name in &selection.consumed {
        for partition in [Partition::System, Partition::Common] {
            changed |= variables.remove(partition, name).is_some();
        }
    }
    changed
}

/// Name `volume` as the next boot's volume: `alt-boot-volume` for one boot,
/// `boot-volume` otherwise. Written to `system`, where the macOS startup
/// disk choice is Inferred to live.
pub fn choose(variables: &mut Variables, volume: &BootVolume, once: bool) -> Result<()> {
    let name = if once { ALT_BOOT_VOLUME } else { BOOT_VOLUME };
    variables
        .set(Partition::System, name, &volume.encode())
        .map_err(|e| anyhow::anyhow!("{e}"))
}

/// `stela.cfg`'s installed-system option: the disk the bundle is built from.
pub const PREBOOT_OPTION: &str = "--preboot";
/// `stela.cfg`'s recoveryOS option: the ESP directory of Stela's recovery
/// bundle (`stela boot prepare --recovery`), booted for System Recovery.
pub const RECOVERY_BUNDLE_OPTION: &str = "--recovery-bundle";
pub const BUNDLE_OPTION: &str = "--bundle";
/// Options `stela.efi` passes its engine: the boot volume to build from and
/// a safe-mode boot.
pub const BOOT_VOLUME_OPTION: &str = "--boot-volume";
pub const SAFE_BOOT_OPTION: &str = "--safe-boot";

/// The engine options for `selection` (none when NVRAM was not read): a
/// macOS boot keeps `--preboot` and adds the boot volume and safe mode; a
/// recoveryOS boot replaces `--preboot` with `--bundle` of the
/// `--recovery-bundle` directory, and is refused without one.
/// `--recovery-bundle` never reaches the engine. Returns the options and
/// what the boot log should say.
pub fn route(options: &str, selection: Option<&Selection>) -> Result<(String, String)> {
    let mut words: Vec<&str> = options.split_ascii_whitespace().collect();
    let take = |words: &mut Vec<&str>, name: &str| -> Result<Option<String>> {
        let Some(at) = words.iter().position(|w| *w == name) else {
            return Ok(None);
        };
        ensure!(at + 1 < words.len(), "{name} has no value");
        let value = words[at + 1].into();
        words.drain(at..at + 2);
        ensure!(
            !words.contains(&name),
            "{name} appears more than once in stela.cfg"
        );
        Ok(Some(value))
    };
    for option in [BOOT_VOLUME_OPTION, SAFE_BOOT_OPTION] {
        ensure!(
            !words.contains(&option),
            "{option} is chosen from NVRAM, not stela.cfg"
        );
    }
    let recovery = take(&mut words, RECOVERY_BUNDLE_OPTION)?;
    let Some(selection) = selection else {
        return Ok((words.join(" "), "NVRAM not read".into()));
    };
    let reasons = if selection.reasons.is_empty() {
        "no boot variables".into()
    } else {
        selection.reasons.join(", ")
    };
    let mut extra: Vec<String> = Vec::new();
    let log = match selection.target {
        Target::MacOs { safe } => {
            ensure!(
                words.contains(&PREBOOT_OPTION),
                "NVRAM boots macOS, which needs {PREBOOT_OPTION}"
            );
            if let Some(volume) = &selection.volume {
                extra.push(BOOT_VOLUME_OPTION.into());
                extra.push(String::from_utf8(volume.encode()).expect("ASCII"));
            }
            if safe {
                extra.push(SAFE_BOOT_OPTION.into());
            }
            format!(
                "macOS{} ({reasons})",
                if safe { " in safe mode" } else { "" }
            )
        }
        target @ (Target::PairedRecovery | Target::SystemRecovery) => {
            let Some(directory) = recovery else {
                bail!(
                    "NVRAM boots recoveryOS ({reasons}), but stela.cfg names no \
                     {RECOVERY_BUNDLE_OPTION}"
                );
            };
            take(&mut words, PREBOOT_OPTION)?;
            ensure!(
                !words.contains(&BUNDLE_OPTION),
                "stela.cfg names both {BUNDLE_OPTION} and {RECOVERY_BUNDLE_OPTION}"
            );
            extra.push(BUNDLE_OPTION.into());
            extra.push(directory);
            match target {
                Target::PairedRecovery => format!(
                    "recoveryOS ({reasons}): the paired recoveryOS on the Recovery volume is not \
                     read, so Stela's System Recovery bundle boots"
                ),
                _ => format!("System Recovery ({reasons})"),
            }
        }
    };
    let mut text: Vec<String> = words.into_iter().map(String::from).collect();
    text.extend(extra);
    Ok((text.join(" "), log))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_runtime::machine::apple::nor::nvram::empty_bank;

    const PARTITION: &str = "A1B2C3D4-0000-1111-2222-333344445555";
    const GROUP: &str = "A304C51B-D22F-4CDD-829D-3E30CB5BD87B";

    fn variables(entries: &[(Partition, &[u8], &[u8])]) -> Variables {
        let mut variables = Variables::parse(&empty_bank()).unwrap();
        for (partition, name, value) in entries {
            variables.set(*partition, name, value).unwrap();
        }
        variables
    }

    fn volume(kind: VolumeType) -> Vec<u8> {
        format!("{}:{PARTITION}:{GROUP}", kind.text()).into_bytes()
    }

    #[test]
    fn uuids_round_trip_their_text_and_types_are_on_disk_gpt_bytes() {
        let uuid = parse_uuid(GROUP.as_bytes()).unwrap();
        assert_eq!(uuid_text(&uuid), GROUP);
        assert_eq!(
            parse_uuid(GROUP.to_ascii_lowercase().as_bytes()),
            Some(uuid)
        );
        assert_eq!(parse_uuid(b"A304C51B-D22F-4CDD-829D-3E30CB5BD87"), None);
        assert_eq!(parse_uuid(b"A304C51B+D22F-4CDD-829D-3E30CB5BD87B"), None);
        // The APFS partition type, 7C3457EF-0000-11AA-AA11-00306543ECAC,
        // as a GPT entry stores it.
        let apfs = stela_runtime::payload::gpt::Guid::parse("7C3457EF-0000-11AA-AA11-00306543ECAC")
            .unwrap();
        assert_eq!(VolumeType::Apfs.guid_bytes(), apfs.0);
    }

    #[test]
    fn boot_volumes_parse_and_encode_as_llb_reads_them() {
        let text = volume(VolumeType::Apfs);
        let parsed = BootVolume::parse(&text).unwrap();
        assert_eq!(parsed.kind, VolumeType::Apfs);
        assert_eq!(uuid_text(&parsed.volume_group), GROUP);
        assert_eq!(parsed.encode(), text);
        let mut terminated = text.clone();
        terminated.push(0);
        assert_eq!(BootVolume::parse(&terminated).unwrap(), parsed);
        assert!(BootVolume::parse(format!("{GROUP}:{PARTITION}:{GROUP}").as_bytes()).is_err());
        assert!(BootVolume::parse(&text[..text.len() - 1]).is_err());
        assert!(BootVolume::parse(b"x:y").is_err());
    }

    #[test]
    fn no_variables_boot_the_only_macos() {
        let selection = select(&variables(&[])).unwrap();
        assert_eq!(selection.target, Target::MacOs { safe: false });
        assert_eq!(selection.volume, None);
        assert!(!selection.consumes());
    }

    #[test]
    fn alt_boot_volume_and_one_time_commands_choose_one_boot_and_are_consumed() {
        let other = format!("{}:{PARTITION}:{PARTITION}", VolumeType::Apfs.text()).into_bytes();
        let mut vars = variables(&[
            (Partition::System, BOOT_VOLUME, &volume(VolumeType::Apfs)),
            (Partition::System, ALT_BOOT_VOLUME, &other),
            (Partition::Common, BOOT_COMMAND, b"fsboot"),
            (Partition::Common, ONE_TIME_BOOT_COMMAND, b"recover"),
            (Partition::Common, b"iboot-failure-reason", b"x"),
        ]);
        let selection = select(&vars).unwrap();
        assert_eq!(selection.target, Target::PairedRecovery);
        assert_eq!(
            uuid_text(&selection.volume.unwrap().volume_group),
            PARTITION
        );
        assert!(consume(&mut vars, &selection));
        assert_eq!(lookup(&vars, ALT_BOOT_VOLUME), None);
        assert_eq!(lookup(&vars, ONE_TIME_BOOT_COMMAND), None);
        assert_eq!(lookup(&vars, b"iboot-failure-reason"), None);
        // The persistent choices stay, and decide the next boot.
        let next = select(&vars).unwrap();
        assert_eq!(next.target, Target::MacOs { safe: false });
        assert_eq!(uuid_text(&next.volume.unwrap().volume_group), GROUP);
        assert!(!consume(&mut vars, &next));
        let saved = Variables::parse(&vars.encode().unwrap()).unwrap();
        assert_eq!(select(&saved).unwrap(), next);
    }

    #[test]
    fn recovery_commands_and_recovery_boot_mode_choose_recoveryos() {
        for (command, target) in [
            (&b"recover-system"[..], Target::SystemRecovery),
            (b"recover-fallback", Target::SystemRecovery),
            (b"recover-once", Target::PairedRecovery),
            (b"fsboot-safe", Target::MacOs { safe: true }),
        ] {
            let selection = select(&variables(&[(Partition::System, BOOT_COMMAND, command)]));
            assert_eq!(selection.unwrap().target, target);
        }
        let mode = variables(&[
            (Partition::Common, BOOT_COMMAND, b"fsboot"),
            (Partition::System, RECOVERY_BOOT_MODE, b"unused"),
        ]);
        let selection = select(&mode).unwrap();
        assert_eq!(selection.target, Target::PairedRecovery);
        assert!(!selection.consumes());
        let system = variables(&[
            (Partition::System, RECOVERY_BOOT_MODE, b"ssv-seal-broken"),
            (Partition::System, BOOT_COMMAND, b"recover-system"),
        ]);
        assert_eq!(select(&system).unwrap().target, Target::SystemRecovery);
    }

    #[test]
    fn unmodeled_boots_and_bad_values_are_refused() {
        for command in [
            &b"upgrade"[..],
            b"post-upgrade",
            b"device-recovery",
            b"nope",
        ] {
            assert!(select(&variables(&[(Partition::Common, BOOT_COMMAND, command)])).is_err());
        }
        assert!(select(&variables(&[(Partition::Common, AUTO_BOOT, b"false")])).is_err());
        assert!(select(&variables(&[(Partition::Common, AUTO_BOOT, b"maybe")])).is_err());
        let once = variables(&[
            (Partition::Common, AUTO_BOOT, b"false"),
            (Partition::Common, AUTO_BOOT_ONCE, b"true"),
        ]);
        let selection = select(&once).unwrap();
        assert_eq!(selection.consumed, [AUTO_BOOT_ONCE]);
        let recovery = variables(&[(
            Partition::System,
            BOOT_VOLUME,
            &volume(VolumeType::Recovery),
        )]);
        assert!(select(&recovery).is_err());
        let mut chosen = variables(&[]);
        let target = BootVolume::parse(&volume(VolumeType::Apfs)).unwrap();
        choose(&mut chosen, &target, true).unwrap();
        assert_eq!(select(&chosen).unwrap().volume, Some(target));
        assert_eq!(select(&chosen).unwrap().consumed, [ALT_BOOT_VOLUME]);
    }

    const CONFIG: &str = "--system --storage S:G --nor S:N --preboot S:G \
                          --recovery-bundle \\EFI\\stela\\recovery --ram-bytes 0x200000000";

    #[test]
    fn macos_boots_keep_the_preboot_disk_and_name_the_volume() {
        let vars = variables(&[
            (Partition::System, BOOT_VOLUME, &volume(VolumeType::Apfs)),
            (Partition::System, BOOT_COMMAND, b"fsboot-safe"),
        ]);
        let (options, log) = route(CONFIG, Some(&select(&vars).unwrap())).unwrap();
        let expected = format!(
            "--system --storage S:G --nor S:N --preboot S:G --ram-bytes 0x200000000 \
             --boot-volume {} --safe-boot",
            String::from_utf8(volume(VolumeType::Apfs)).unwrap()
        );
        assert_eq!(options, expected);
        assert!(log.starts_with("macOS in safe mode"));
        // Without NVRAM only the recovery bundle option is removed.
        let (plain, _) = route(CONFIG, None).unwrap();
        assert!(!plain.contains(RECOVERY_BUNDLE_OPTION) && plain.contains("--preboot S:G"));
    }

    #[test]
    fn recovery_boots_read_the_recovery_bundle_instead() {
        let vars = variables(&[(Partition::Common, BOOT_COMMAND, b"recover-system")]);
        let selection = select(&vars).unwrap();
        let (options, log) = route(CONFIG, Some(&selection)).unwrap();
        assert_eq!(
            options,
            "--system --storage S:G --nor S:N --ram-bytes 0x200000000 \
             --bundle \\EFI\\stela\\recovery"
        );
        assert!(log.starts_with("System Recovery"));
        let paired = select(&variables(&[(Partition::System, RECOVERY_BOOT_MODE, b"x")])).unwrap();
        assert!(
            route(CONFIG, Some(&paired))
                .unwrap()
                .1
                .contains("paired recoveryOS")
        );
        let without = "--system --preboot S:G";
        assert!(route(without, Some(&selection)).is_err());
        assert!(route("--system --safe-boot", None).is_err());
        assert!(route("--system --recovery-bundle", None).is_err());
    }
}
