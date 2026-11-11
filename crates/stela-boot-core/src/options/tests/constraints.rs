//! Independent complete-record examples and ordering between failed rules.
use super::*;

#[test]
fn complete_records_report_the_named_constraint() {
    let target: Target = DISK.parse().unwrap();
    let preboot = System {
        preboot: Some(target.clone()),
        ..System::default()
    };
    let install = System {
        bundle: true,
        storage: Some(target.clone()),
        nor: Some(target.clone()),
        install: Some(String::from("install.json")),
        ..System::default()
    };
    let examples = [
        (
            System {
                restore: true,
                ..System::default()
            },
            Constraint::RestoreConfiguration,
        ),
        (
            System {
                restore_identity: Some(0),
                ..System::default()
            },
            Constraint::UnexpectedRestoreInputs,
        ),
        (
            System {
                wifi_key: Some(String::from("key")),
                ..System::default()
            },
            Constraint::WifiDependency,
        ),
        (
            System {
                install_source: Some(target.partition),
                ..System::default()
            },
            Constraint::InstallSourceDependency,
        ),
        (
            System {
                install: Some(String::from("manifest")),
                ..System::default()
            },
            Constraint::InstallConfiguration,
        ),
        (
            System {
                update_restore: true,
                ..System::default()
            },
            Constraint::UpdateDependency,
        ),
        (
            System {
                development_restore: true,
                ..System::default()
            },
            Constraint::DevelopmentRestore,
        ),
        (
            System {
                development_restore: true,
                update_restore: true,
                ..install.clone()
            },
            Constraint::DevelopmentRestore,
        ),
        (
            System {
                verify_on_read: true,
                ..System::default()
            },
            Constraint::VerifyDependency,
        ),
        (
            System {
                safe_boot: true,
                ..System::default()
            },
            Constraint::PrebootSelection,
        ),
        (
            System {
                upgrade: true,
                safe_boot: true,
                ..preboot.clone()
            },
            Constraint::UpgradeSelection,
        ),
        (
            System {
                recovery: Some(recovery::Kind::Paired),
                safe_boot: true,
                ..preboot
            },
            Constraint::RecoverySafeMode,
        ),
        (
            System {
                dram_base: DRAM_BASE + 1,
                ..System::default()
            },
            Constraint::DramAlignment,
        ),
    ];
    for (options, constraint) in examples {
        assert_eq!(
            options.check(),
            Err(Error::Constraint(constraint)),
            "{constraint:?}"
        );
    }
}

#[test]
fn first_failed_constraint_and_resolution_phase_remain_ordered() {
    for (line, constraint) in [
        (
            "--system --restore-study --wifi-key key --install bad --dram-base 1",
            Constraint::RestoreConfiguration,
        ),
        (
            "--system --restore-identity 1 --wifi-key key",
            Constraint::UnexpectedRestoreInputs,
        ),
        (
            "--system --wifi-key key --update-restore",
            Constraint::WifiDependency,
        ),
        (
            "--system --update-restore --safe-boot",
            Constraint::UpdateDependency,
        ),
        (
            "--system --safe-boot --dram-base 1",
            Constraint::PrebootSelection,
        ),
        ("--system --dram-base 1", Constraint::DramAlignment),
        ("--system --preboot @disk", Constraint::UnresolvedDisk),
    ] {
        assert_eq!(
            System::parse_resolved(line),
            Err(Error::Constraint(constraint)),
            "{line}"
        );
    }
}
