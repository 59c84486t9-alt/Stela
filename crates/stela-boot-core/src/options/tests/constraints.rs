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
        tss: true,
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
                tss: false,
                ..install
            },
            Constraint::InstallTicket,
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
        (
            System {
                native_clock_check: true,
                ..System::default()
            },
            Constraint::ClockCoreCount,
        ),
        (
            System {
                native_clock_check: true,
                native_cores: Some(1),
                input: true,
                ..System::default()
            },
            Constraint::ClockExclusive,
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
        (
            "--system --dram-base 1 --native-clock-check",
            Constraint::DramAlignment,
        ),
        (
            "--system --preboot @disk --native-clock-check",
            Constraint::ClockCoreCount,
        ),
        ("--system --preboot @disk", Constraint::UnresolvedDisk),
    ] {
        assert_eq!(
            System::parse_resolved(line),
            Err(Error::Constraint(constraint)),
            "{line}"
        );
    }
}

#[test]
fn clock_exclusivity_keeps_every_independent_input() {
    let target: Target = DISK.parse().unwrap();
    let base = System {
        native_clock_check: true,
        native_cores: Some(1),
        ..System::default()
    };
    let examples = [
        System {
            native_mmio_check: true,
            ..base.clone()
        },
        System {
            native_memory_check: true,
            ..base.clone()
        },
        System {
            native_bootstrap_check: true,
            ..base.clone()
        },
        System {
            native_shared_check: true,
            ..base.clone()
        },
        System {
            native_rounds: true,
            ..base.clone()
        },
        System {
            audio_check: Some(AudioCheck::Playback),
            ..base.clone()
        },
        System {
            network_check: Some(String::from("http://h/p")),
            ..base.clone()
        },
        System {
            storage: Some(target.clone()),
            ..base.clone()
        },
        System {
            storage_ram: Some(1),
            ..base.clone()
        },
        System {
            preboot: Some(target.clone()),
            ..base.clone()
        },
        System {
            nor: Some(target.clone()),
            ..base.clone()
        },
        System {
            input: true,
            ..base.clone()
        },
        System {
            guest_network: true,
            ..base.clone()
        },
        System {
            ssid: Some(String::from("network")),
            ..base.clone()
        },
        System {
            external_disks: true,
            ..base.clone()
        },
        System {
            usb_storage: vec![String::from("serial")],
            ..base.clone()
        },
        System {
            tss: true,
            ..base.clone()
        },
        System {
            bundle: true,
            storage: Some(target.clone()),
            nor: Some(target.clone()),
            install: Some(String::from("manifest")),
            tss: true,
            ..base.clone()
        },
        System {
            bundle: true,
            storage: Some(target.clone()),
            restore: true,
            restore_source: Some(target),
            restore_manifest: true,
            restore_identity: Some(0),
            ..base.clone()
        },
    ];
    assert_eq!(base.check(), Ok(()));
    for options in examples {
        assert_eq!(
            options.check(),
            Err(Error::Constraint(Constraint::ClockExclusive))
        );
    }
}
