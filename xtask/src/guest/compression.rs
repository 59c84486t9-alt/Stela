//! The one-shot launchd job that tells CoreVideo the guest has no universal
//! buffer compression (`guest/stela-gpu/kext/compression.h`).
//!
//! macOS offers Apple's universal lossless formats ('&BGA' and the like) by
//! SoC generation alone, so on Stela every process sees them as available.
//! StelaGPU stores them plain, which only GPU writers and readers agree on;
//! a process that paints one on the CPU, as WebKit's sandboxed GPU process
//! does without the Metal plugin, overlaps its rows. CoreVideo's default
//! `disable-buffer-compression` in the any-user global domain, which every
//! sandbox may read, makes `CVIsCompressedPixelFormatAvailable` answer no.
//! The kext stages the job while that domain does not name the key; the job
//! sets it with Apple's `defaults`, keeps any value already given, and
//! removes its own plist.
use super::{c_bytes, c_digest};
use anyhow::Result;
use std::fmt::Write as _;

/// The Data volume, where the kext finds what user space sees at `/`.
const DATA: &str = "/System/Volumes/Data";
/// The any-user global domain, as `defaults` names it (no `.plist`).
const DOMAIN: &str = "/Library/Preferences/.GlobalPreferences";
/// CoreVideo's key (`compression_policy.h`'s `STELA_COMPRESSION_KEY`).
const KEY: &str = "disable-buffer-compression";
const JOB: &str = "/Library/LaunchDaemons/org.stela.StelaGPU.compression.plist";
const LABEL: &str = "org.stela.StelaGPU.compression";
/// The job's own record of each run, readable without `log show`.
const LOG: &str = "/Library/Logs/org.stela.StelaGPU.compression.log";

/// The job's script, for `/bin/sh` as root at boot, using only the tools
/// macOS ships.
fn script() -> String {
    format!(
        r#"domain={DOMAIN}
key={KEY}
if /usr/bin/defaults read "$domain" "$key" >/dev/null 2>&1; then
  result="kept: $key is already set"
elif /usr/bin/defaults write "$domain" "$key" -bool YES; then
  result="set $key: this GPU has no universal buffer compression"
else
  result="failed to set $key"
fi
echo "$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ) $result"
/bin/rm -f {JOB}
"#
    )
}

/// The job's launchd plist: run once at load and record each run in its log.
fn job() -> Result<Vec<u8>> {
    let mut job = plist::Dictionary::new();
    job.insert("Label".into(), LABEL.into());
    job.insert(
        "ProgramArguments".into(),
        plist::Value::Array(vec!["/bin/sh".into(), "-c".into(), script().into()]),
    );
    job.insert("RunAtLoad".into(), true.into());
    job.insert("StandardOutPath".into(), LOG.into());
    job.insert("StandardErrorPath".into(), LOG.into());
    let mut bytes = Vec::new();
    plist::to_writer_xml(&mut bytes, &plist::Value::Dictionary(job))?;
    Ok(bytes)
}

/// `stela/compression.h`: the paths the kext reads and writes, and the job.
pub fn header() -> Result<String> {
    let job = job()?;
    let mut header = String::from(
        "/* The buffer compression job `cargo xtask guest` built, which the kext\n \
         * stages (guest/stela-gpu/kext/compression.h). */\n\
         #pragma once\n",
    );
    writeln!(
        header,
        "#define STELA_COMPRESSION_PREFERENCES_PATH \"{DATA}{DOMAIN}.plist\""
    )?;
    writeln!(header, "#define STELA_COMPRESSION_JOB_PATH \"{DATA}{JOB}\"")?;
    c_bytes(&mut header, "stela_compression_job", &job)?;
    writeln!(
        header,
        "static const unsigned char stela_compression_job_sha256[32] = {{{}}};",
        c_digest(&job)
    )?;
    Ok(header)
}

#[cfg(test)]
mod tests;
