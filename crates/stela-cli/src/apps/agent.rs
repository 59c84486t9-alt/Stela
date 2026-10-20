//! The opt-in per-user LaunchAgent that keeps the launchers in sync: launchd
//! runs `stela apps --quiet` whenever a scanned applications folder
//! changes. It lives in the user's own `~/Library/LaunchAgents` and is
//! bootstrapped into the user's GUI domain only.
use super::Environment;
use anyhow::{Context, Result, ensure};
use plist::{Dictionary, Value};
use std::path::{Path, PathBuf};
use std::process::Command;

/// The per-user agents folder below the home directory.
pub(super) const AGENTS: &str = "Library/LaunchAgents";
const LABEL: &str = "local.stela.apps";
const LAUNCHCTL: &str = "/bin/launchctl";
/// The agent's log in Stela's log folder.
pub(super) const LOG: &str = "apps.log";
/// Seconds launchd waits between two runs.
const THROTTLE_SECONDS: i64 = 10;

/// The agent's property list path.
pub(super) fn path(environment: &Environment) -> PathBuf {
    environment.agents.join(format!("{LABEL}.plist"))
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
            "apps".into(),
            "--quiet".into(),
        ]),
    );
    agent.insert(
        "WatchPaths".into(),
        strings(
            environment
                .scan
                .iter()
                .map(|folder| folder.to_string_lossy().into_owned())
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

/// Whether the property list at `plist` is Stela's agent.
fn ours(plist: &Path) -> bool {
    Value::from_file(plist)
        .ok()
        .and_then(Value::into_dictionary)
        .is_some_and(|agent| agent.get("Label").and_then(Value::as_string) == Some(LABEL))
}

/// Write the agent and load it; a file of someone else's at its path is
/// refused.
pub(super) fn install(environment: &Environment) -> Result<()> {
    let plist = path(environment);
    ensure!(
        !plist.exists() || ours(&plist),
        "{} exists and is not Stela's agent; remove it to use --watch",
        plist.display()
    );
    std::fs::create_dir_all(&environment.agents)?;
    std::fs::create_dir_all(&environment.logs)?;
    Value::Dictionary(definition(environment)).to_file_xml(&plist)?;
    if environment.register {
        // A loaded earlier definition is replaced.
        let _ = Command::new(LAUNCHCTL)
            .args(["bootout", &format!("{}/{LABEL}", domain())])
            .output();
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
    Ok(())
}

/// Unload the agent and remove its property list, when it is Stela's.
pub(super) fn remove(environment: &Environment, plist: &Path) -> Result<()> {
    if environment.register {
        let _ = Command::new(LAUNCHCTL)
            .args(["bootout", &format!("{}/{LABEL}", domain())])
            .output();
    }
    if ours(plist) {
        std::fs::remove_file(plist)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::tests::environment;
    use super::*;

    #[test]
    fn the_agent_runs_a_quiet_sync_when_the_scanned_folders_change() -> Result<()> {
        let work = tempfile::tempdir()?;
        let environment = environment(work.path());
        install(&environment)?;
        let plist = path(&environment);
        let agent = Value::from_file(&plist)?.into_dictionary().unwrap();
        assert_eq!(agent["Label"].as_string(), Some(LABEL));
        let arguments: Vec<&str> = agent["ProgramArguments"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_string)
            .collect();
        assert_eq!(arguments, ["/usr/local/bin/stela", "apps", "--quiet"]);
        let watched = agent["WatchPaths"].as_array().unwrap();
        assert_eq!(
            watched[0].as_string(),
            work.path().join("Applications").to_str()
        );
        remove(&environment, &plist)?;
        assert!(!plist.exists());
        // Someone else's property list at the path is kept, and never
        // replaced.
        std::fs::write(&plist, b"not an agent")?;
        remove(&environment, &plist)?;
        assert!(install(&environment).is_err());
        assert_eq!(std::fs::read(&plist)?, b"not an agent");
        Ok(())
    }
}
