//! Tests for hosted application records and launchers.
use super::*;
use crate::bundle::tests::{info, make};
use crate::run::program::tests::thin;
use plist::Value;

pub(crate) use crate::run::program::CPU_TYPE_X86_64 as X86_64;
pub(crate) use stela_runtime::hosted::hardware::CPU_TYPE_ARM64 as ARM64;

/// An app `name` in `folder` whose executable is a Mach-O of `cpu`.
pub(crate) fn app(folder: &Path, name: &str, cpu: u32) -> Result<PathBuf> {
    let path = folder.join(format!("{name}.app"));
    let mut document = plist::Dictionary::new();
    document.insert("CFBundleTypeName".into(), "Text".into());
    document.insert("LSHandlerRank".into(), "Owner".into());
    make(
        &path,
        info(&[
            ("CFBundleExecutable", name.into()),
            ("CFBundleIdentifier", format!("com.example.{name}").into()),
            ("CFBundleName", name.into()),
            ("CFBundleIconFile", "AppIcon".into()),
            (
                "CFBundleDocumentTypes",
                Value::Array(vec![Value::Dictionary(document)]),
            ),
        ]),
        &thin(cpu, 0),
    )?;
    std::fs::create_dir_all(path.join("Contents/Resources"))?;
    std::fs::write(path.join("Contents/Resources/AppIcon.icns"), b"icns")?;
    Ok(path)
}

pub(crate) fn environment(work: &Path) -> Environment {
    Environment {
        scan: vec![work.join("Applications")],
        launchers: work.join("home/Applications/Stela"),
        record: work.join("home/Library/Application Support/Stela/apps.json"),
        agents: work.join("home/Library/LaunchAgents"),
        logs: work.join("home/Library/Logs/Stela"),
        unsupported: work.join("home/Library/Logs/Stela/unsupported.log"),
        preferences: work.join("home/Library/Application Support/Stela/preferences.json"),
        state: work.join("home/Library/Application Support/Stela/stelad.json"),
        spool: Some(work.join("home/Library/Caches/stela/translations/v1/spool")),
        stela: PathBuf::from("/usr/local/bin/stela"),
        // Any signable Mach-O stands in for the launcher program.
        launcher_program: PathBuf::from("/usr/bin/true"),
        register: false,
    }
}

#[test]
fn only_arm64_only_apps_get_launchers_and_gone_apps_lose_them() -> Result<()> {
    let work = tempfile::tempdir()?;
    let applications = work.path().join("Applications");
    let utilities = applications.join("Utilities");
    std::fs::create_dir_all(&utilities)?;
    let arm = app(&applications, "Arm", ARM64)?;
    app(&applications, "Intel", X86_64)?;
    let tool = app(&utilities, "Tool", ARM64)?;
    let environment = environment(work.path());
    let mut record = Record::read(&environment.record)?;
    let dry = sync(&environment, &mut record.clone(), &[], &[], true)?;
    assert_eq!(dry.lines.len(), 2, "{:?}", dry.lines);
    assert!(!environment.launchers.exists(), "a dry run changes nothing");
    let changes = sync(&environment, &mut record, &[], &[], false)?;
    assert_eq!(changes.lines.len(), 2, "{:?}", changes.lines);
    let targets: Vec<&Path> = record
        .launchers
        .iter()
        .map(|e| e.target.as_path())
        .collect();
    assert_eq!(targets, [arm.as_path(), tool.as_path()]);
    assert!(environment.launchers.join("Arm.app").is_dir());
    assert!(!environment.launchers.join("Intel.app").exists());
    record.write(&environment.record)?;
    assert_eq!(Record::read(&environment.record)?, record);
    // A second sync changes nothing; a gone app loses its launcher.
    assert!(
        sync(&environment, &mut record, &[], &[], false)?
            .lines
            .is_empty()
    );
    std::fs::remove_dir_all(&tool)?;
    let changes = sync(&environment, &mut record, &[], &[], false)?;
    assert_eq!(changes.lines.len(), 1, "{:?}", changes.lines);
    assert!(!environment.launchers.join("Tool.app").exists());
    uninstall(&environment, &mut record, false)?;
    assert!(!environment.launchers.exists() && !environment.record.exists());
    assert!(
        !environment.launchers.parent().unwrap().exists(),
        "the folders Stela created go too"
    );
    assert!(
        arm.join("Contents/Info.plist").is_file(),
        "originals are kept"
    );
    Ok(())
}

#[test]
fn app_changes_rebuild_only_owned_launchers() -> Result<()> {
    let work = tempfile::tempdir()?;
    let applications = work.path().join("Applications");
    std::fs::create_dir_all(&applications)?;
    let arm = app(&applications, "Arm", ARM64)?;
    let environment = environment(work.path());
    let mut record = Record::default();
    sync(&environment, &mut record, &[], &[], false)?;
    let mut info = AppBundle::open(&arm)?.info;
    info.insert("CFBundleShortVersionString".into(), "2.0".into());
    Value::Dictionary(info).to_file_xml(arm.join("Contents/Info.plist"))?;
    let changes = sync(&environment, &mut record, &[], &[], false)?;
    assert!(
        changes.lines[0].starts_with("Updated"),
        "{:?}",
        changes.lines
    );
    // Someone else's bundle where a launcher would go is never replaced.
    let other = app(&applications, "Other", ARM64)?;
    let foreign = environment.launchers.join("Other.app");
    std::fs::create_dir_all(foreign.join("Contents"))?;
    std::fs::write(foreign.join("Contents/Info.plist"), b"mine")?;
    let changes = sync(&environment, &mut record, &[], &[], false)?;
    assert_eq!(changes.warnings.len(), 1, "{:?}", changes.warnings);
    assert_eq!(std::fs::read(foreign.join("Contents/Info.plist"))?, b"mine");
    assert!(!record.launchers.iter().any(|entry| entry.target == other));
    uninstall(&environment, &mut record, false)?;
    assert!(foreign.is_dir(), "uninstall keeps what Stela did not make");
    Ok(())
}

#[test]
fn apps_kept_elsewhere_are_added_and_removed_by_name() -> Result<()> {
    let work = tempfile::tempdir()?;
    let elsewhere = work.path().join("Downloads");
    std::fs::create_dir_all(&elsewhere)?;
    let arm = app(&elsewhere, "Arm", ARM64)?;
    let intel = app(&elsewhere, "Intel", X86_64)?;
    let environment = environment(work.path());
    let mut record = Record::default();
    let message = sync(&environment, &mut record, &[intel], &[], false)
        .unwrap_err()
        .to_string();
    assert!(message.contains("not an arm64 app"), "{message}");
    sync(
        &environment,
        &mut record,
        std::slice::from_ref(&arm),
        &[],
        false,
    )?;
    assert!(record.launchers[0].explicit);
    // Explicit apps stay without being named again.
    sync(&environment, &mut record, &[], &[], false)?;
    assert_eq!(record.launchers.len(), 1);
    assert!(sync(&environment, &mut record, &[], &["Nothing".into()], false).is_err());
    sync(&environment, &mut record, &[], &["Arm".into()], false)?;
    assert!(record.launchers.is_empty());
    assert!(!environment.launchers.join("Arm.app").exists());
    Ok(())
}

#[test]
fn removed_app_requires_explicit_readdition() -> Result<()> {
    let work = tempfile::tempdir()?;
    let applications = work.path().join("Applications");
    std::fs::create_dir_all(&applications)?;
    let arm = app(&applications, "Arm", ARM64)?;
    let environment = environment(work.path());
    let mut record = Record::default();
    sync(&environment, &mut record, &[], &[], false)?;
    sync(
        &environment,
        &mut record,
        &[],
        &[arm.display().to_string()],
        false,
    )?;
    assert!(record.launchers.is_empty() && record.excluded == [arm.clone()]);
    sync(&environment, &mut record, &[], &[], false)?;
    assert!(record.launchers.is_empty(), "the scan skips it");
    sync(
        &environment,
        &mut record,
        std::slice::from_ref(&arm),
        &[],
        false,
    )?;
    assert_eq!(record.launchers.len(), 1);
    assert!(record.excluded.is_empty());
    Ok(())
}

#[test]
fn uninstall_pauses_sync_and_replaces_agent() -> Result<()> {
    let work = tempfile::tempdir()?;
    let applications = work.path().join("Applications");
    std::fs::create_dir_all(&applications)?;
    app(&applications, "Arm", ARM64)?;
    let environment = environment(work.path());
    let mut record = Record {
        schema_version: RECORD_SCHEMA,
        agent: Some(agent::legacy_path(&environment)),
        ..Record::default()
    };
    agent::install(&environment)?;
    sync(&environment, &mut record, &[], &[], false)?;
    uninstall(&environment, &mut record, false)?;
    assert!(record.launchers.is_empty() && record.agent.is_none());
    assert_eq!(
        Record::read(&environment.record)?,
        Record {
            schema_version: RECORD_SCHEMA,
            paused: true,
            ..Record::default()
        },
        "the record stays while stelad is installed"
    );
    Ok(())
}

#[test]
fn model_preference_requires_known_mac() -> Result<()> {
    let work = tempfile::tempdir()?;
    let environment = environment(work.path());
    let model = stela_runtime::hosted::hardware::models()
        .find(|model| *model != stela_runtime::hosted::hardware::DEFAULT_MODEL)
        .expect("another board");
    set_model(&environment, model, true)?;
    assert!(
        !environment.preferences.exists(),
        "a dry run changes nothing"
    );
    set_model(&environment, model, false)?;
    assert_eq!(
        Preferences::read(&environment.preferences).model.as_deref(),
        Some(model)
    );
    assert!(set_model(&environment, "Mac0,0", false).is_err());
    set_model(&environment, DEFAULT_MODEL_WORD, false)?;
    assert_eq!(Preferences::read(&environment.preferences).model, None);
    Ok(())
}

#[test]
fn same_named_apps_get_launchers_named_by_their_folder() -> Result<()> {
    let work = tempfile::tempdir()?;
    let applications = work.path().join("Applications");
    let beta = applications.join("Beta");
    std::fs::create_dir_all(&beta)?;
    app(&applications, "Arm", ARM64)?;
    app(&beta, "Arm", ARM64)?;
    let environment = environment(work.path());
    let mut record = Record::default();
    sync(&environment, &mut record, &[], &[], false)?;
    let names: Vec<String> = record
        .launchers
        .iter()
        .map(|entry| entry.launcher.file_name().unwrap().to_string_lossy().into())
        .collect();
    assert_eq!(names, ["Arm (Beta).app", "Arm.app"]);
    Ok(())
}

#[test]
fn name_collision_preserves_existing_launcher() -> Result<()> {
    let work = tempfile::tempdir()?;
    let applications = work.path().join("Applications");
    let elsewhere = work.path().join("Downloads");
    std::fs::create_dir_all(&applications)?;
    std::fs::create_dir_all(&elsewhere)?;
    let scanned = app(&applications, "Arm", ARM64)?;
    let added = app(&elsewhere, "Arm", ARM64)?;
    let environment = environment(work.path());
    let mut record = Record::default();
    sync(&environment, &mut record, &[], &[], false)?;
    let changes = sync(
        &environment,
        &mut record,
        std::slice::from_ref(&added),
        &[],
        false,
    )?;
    assert!(changes.warnings.is_empty(), "{:?}", changes.warnings);
    let launchers: Vec<(&Path, &Path)> = record
        .launchers
        .iter()
        .map(|entry| (entry.launcher.as_path(), entry.target.as_path()))
        .collect();
    assert_eq!(
        launchers,
        [
            (
                environment.launchers.join("Arm (Downloads).app").as_path(),
                added.as_path()
            ),
            (
                environment.launchers.join("Arm.app").as_path(),
                scanned.as_path()
            ),
        ]
    );
    Ok(())
}
