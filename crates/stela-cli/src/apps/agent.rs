//! `stelad`'s per-user LaunchAgent (`docs/design/hosted-cli.md#stelad`):
//! launchd runs `stela stelad` at login and whenever a scanned applications
//! folder, the translation spool, the unsupported-operations log, Stela's
//! preferences (the modeled Mac) or the `stela` executable changes; it
//! never keeps it alive. It lives in the user's own `~/Library/LaunchAgents`
//! and is bootstrapped into the user's GUI domain only. The opt-in launcher agent earlier versions installed
//! (`stela apps --watch`) is replaced by it.
use super::Environment;
use anyhow::{Context, Result, ensure};
use plist::{Dictionary, Value};
use std::path::{Path, PathBuf};
use std::process::Command;

/// The per-user agents folder below the home directory.
pub(super) const AGENTS: &str = "Library/LaunchAgents";
const LABEL: &str = "local.stela.stelad";
/// The launcher agent `stela apps --watch` installed.
const LEGACY_LABEL: &str = "local.stela.apps";
const LAUNCHCTL: &str = "/bin/launchctl";
/// The agent's log in Stela's log folder, and the launcher agent's.
pub(super) const LOG: &str = "stelad.log";
pub(super) const LEGACY_LOG: &str = "apps.log";
/// Seconds launchd waits between two runs.
const THROTTLE_SECONDS: i64 = 10;

/// The agent's property list path.
pub(super) fn path(environment: &Environment) -> PathBuf {
    environment.agents.join(format!("{LABEL}.plist"))
}

/// The launcher agent's property list path.
pub(super) fn legacy_path(environment: &Environment) -> PathBuf {
    environment.agents.join(format!("{LEGACY_LABEL}.plist"))
}

/// What launchd watches to start the agent.
fn watched(environment: &Environment) -> Vec<PathBuf> {
    let mut paths = environment.scan.clone();
    paths.extend(environment.spool.clone());
    paths.push(environment.unsupported.clone());
    paths.push(environment.preferences.clone());
    paths.push(environment.stela.clone());
    paths
}

/// The agent's property list.
fn definition(environment: &Environment) -> Dictionary {
    let strings = |values: Vec<String>| Value::Array(values.into_iter().map(Value::from).collect());
    let mut agent = Dictionary::new();
    agent.insert("Label".into(), LABEL.into());
    agent.insert(
        "ProgramArguments".into(),
        strings(vec![
            environment.stela.to_string_lossy().into_owned(),
            "stelad".into(),
        ]),
    );
    agent.insert(
        "WatchPaths".into(),
        strings(
            watched(environment)
                .iter()
                .map(|path| path.to_string_lossy().into_owned())
                .collect(),
        ),
    );
    agent.insert("RunAtLoad".into(), true.into());
    agent.insert("ProcessType".into(), "Background".into());
    agent.insert(
        "ThrottleInterval".into(),
        Value::Integer(THROTTLE_SECONDS.into()),
    );
    let log = environment.logs.join(LOG);
    let log = log.to_string_lossy().into_owned();
    agent.insert("StandardOutPath".into(), log.clone().into());
    agent.insert("StandardErrorPath".into(), log.into());
    agent
}

/// The user's GUI launchd domain.
fn domain() -> String {
    // SAFETY: getuid has no preconditions.
    format!("gui/{}", unsafe { libc::getuid() })
}

/// Whether the property list at `plist` is Stela's agent `label`.
fn ours(plist: &Path, label: &str) -> bool {
    Value::from_file(plist)
        .ok()
        .and_then(Value::into_dictionary)
        .is_some_and(|agent| agent.get("Label").and_then(Value::as_string) == Some(label))
}

/// Unload `label` from the user's domain, when this home is launchd's.
fn bootout(environment: &Environment, label: &str) {
    if environment.register {
        let _ = Command::new(LAUNCHCTL)
            .args(["bootout", &format!("{}/{label}", domain())])
            .output();
    }
}

/// Write the agent and load it, replacing the launcher agent when that is
/// Stela's; a file of someone else's at either path is kept, and one at
/// the agent's path is refused. The changes, for people.
pub(super) fn install(environment: &Environment) -> Result<Vec<String>> {
    let plist = path(environment);
    ensure!(
        !plist.exists() || ours(&plist, LABEL),
        "{} exists and is not Stela's agent; remove it to install stelad",
        plist.display()
    );
    let mut changes = vec![];
    if remove_legacy(environment)? {
        changes.push(format!(
            "Removed {}, which stelad replaces",
            legacy_path(environment).display()
        ));
    }
    std::fs::create_dir_all(&environment.agents)?;
    std::fs::create_dir_all(&environment.logs)?;
    // launchd watches paths that exist.
    if let Some(spool) = &environment.spool {
        std::fs::create_dir_all(spool)?;
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&environment.unsupported)?;
    let replaced = plist.exists();
    Value::Dictionary(definition(environment)).to_file_xml(&plist)?;
    if environment.register {
        // A loaded earlier definition is replaced.
        bootout(environment, LABEL);
        let output = Command::new(LAUNCHCTL)
            .args(["bootstrap", &domain()])
            .arg(&plist)
            .output()
            .with_context(|| format!("cannot run {LAUNCHCTL}"))?;
        ensure!(
            output.status.success(),
            "launchctl bootstrap failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    changes.push(format!(
        "{} {}",
        if replaced { "Updated" } else { "Installed" },
        plist.display()
    ));
    Ok(changes)
}

/// Unload the agent `label` and remove its property list and log, when it
/// is Stela's: whether it was.
fn remove_agent(environment: &Environment, label: &str, plist: &Path, log: &str) -> Result<bool> {
    if !ours(plist, label) {
        return Ok(false);
    }
    bootout(environment, label);
    std::fs::remove_file(plist)?;
    let log = environment.logs.join(log);
    if log.is_file() {
        std::fs::remove_file(log)?;
    }
    Ok(true)
}

/// Remove the agent and the launcher agent, each when it is Stela's: the
/// property lists removed.
pub(super) fn remove(environment: &Environment) -> Result<Vec<PathBuf>> {
    let mut removed = vec![];
    for (label, plist, log) in [
        (LABEL, path(environment), LOG),
        (LEGACY_LABEL, legacy_path(environment), LEGACY_LOG),
    ] {
        if remove_agent(environment, label, &plist, log)? {
            removed.push(plist);
        }
    }
    Ok(removed)
}

/// Remove the launcher agent when it is Stela's: whether it was.
pub(super) fn remove_legacy(environment: &Environment) -> Result<bool> {
    remove_agent(
        environment,
        LEGACY_LABEL,
        &legacy_path(environment),
        LEGACY_LOG,
    )
}

#[cfg(test)]
mod tests {
    use super::super::tests::environment;
    use super::*;

    #[test]
    fn agent_watches_apps_spool_and_log() -> Result<()> {
        let work = tempfile::tempdir()?;
        let environment = environment(work.path());
        install(&environment)?;
        let plist = path(&environment);
        let agent = Value::from_file(&plist)?.into_dictionary().unwrap();
        assert_eq!(agent["Label"].as_string(), Some(LABEL));
        assert!(
            agent.get("KeepAlive").is_none(),
            "launchd starts it on demand"
        );
        let arguments: Vec<&str> = agent["ProgramArguments"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_string)
            .collect();
        assert_eq!(arguments, ["/usr/local/bin/stela", "stelad"]);
        let watched: Vec<PathBuf> = agent["WatchPaths"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_string)
            .map(PathBuf::from)
            .collect();
        assert_eq!(watched, super::watched(&environment));
        assert!(watched.contains(&work.path().join("Applications")));
        assert!(environment.spool.as_ref().unwrap().is_dir());
        assert!(environment.unsupported.is_file());
        assert_eq!(remove(&environment)?, std::slice::from_ref(&plist));
        assert!(!plist.exists());
        // Someone else's property list at the path is kept, and never
        // replaced.
        std::fs::write(&plist, b"not an agent")?;
        assert!(remove(&environment)?.is_empty());
        assert!(install(&environment).is_err());
        assert_eq!(std::fs::read(&plist)?, b"not an agent");
        Ok(())
    }

    #[test]
    fn agent_replacement_requires_stela_ownership() -> Result<()> {
        let work = tempfile::tempdir()?;
        let environment = environment(work.path());
        let legacy = legacy_path(&environment);
        std::fs::create_dir_all(&environment.agents)?;
        std::fs::write(&legacy, b"someone else's")?;
        install(&environment)?;
        assert_eq!(std::fs::read(&legacy)?, b"someone else's");
        let mut agent = Dictionary::new();
        agent.insert("Label".into(), LEGACY_LABEL.into());
        Value::Dictionary(agent).to_file_xml(&legacy)?;
        std::fs::create_dir_all(&environment.logs)?;
        std::fs::write(environment.logs.join(LEGACY_LOG), b"log")?;
        let changes = install(&environment)?;
        assert!(changes[0].starts_with("Removed"), "{changes:?}");
        assert!(changes[1].starts_with("Updated"), "{changes:?}");
        assert!(!legacy.exists() && !environment.logs.join(LEGACY_LOG).exists());
        assert!(path(&environment).is_file());
        Ok(())
    }
}
