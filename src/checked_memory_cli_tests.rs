use super::{Cli, Command};
use clap::{Parser, error::ErrorKind};

#[test]
fn checked_memory_flag_selects_compile_preparation_only() {
    let cli = Cli::try_parse_from([
        "stela",
        "compile-block",
        "input.bin",
        "--output-dir",
        "output",
        "--checked-memory-sa0-off",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Command::CompileBlock {
            checked_memory_sa0_off: true,
            ..
        }
    ));
    assert!(
        Cli::try_parse_from([
            "stela",
            "run-blocks",
            "input.bin",
            "--checked-memory-sa0-off",
        ])
        .is_err()
    );
}

#[test]
fn checked_memory_preparation_rejects_other_service_and_extended_profiles() {
    for alternative in [
        "--system-boundaries",
        "--software-pauth",
        "--thread-registers",
    ] {
        let error = match Cli::try_parse_from([
            "stela",
            "compile-block",
            "input.bin",
            "--output-dir",
            "output",
            "--checked-memory-sa0-off",
            alternative,
        ]) {
            Ok(_) => panic!("conflicting preparation profiles accepted"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
    }
    assert!(
        Cli::try_parse_from([
            "stela",
            "compile-block",
            "input.bin",
            "--output-dir",
            "output",
            "--checked-memory-sa0-off",
            "--software-pauth",
            "--software-clock",
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "stela",
            "compile-block",
            "input.bin",
            "--output-dir",
            "output",
            "--checked-memory-sa0-off",
            "--guest-profile",
            "apple-sme2-streaming-v1",
            "--svl-bytes",
            "16",
            "--svcr",
            "0",
        ])
        .is_err()
    );
}

#[test]
fn checked_process_preparation_is_explicit_and_exclusive() {
    let args = [
        "stela",
        "compile-block",
        "input.bin",
        "--output-dir",
        "output",
        "--checked-process-sa0-off",
    ];
    assert!(matches!(
        Cli::try_parse_from(args).unwrap().command,
        Command::CompileBlock {
            checked_process_sa0_off: true,
            checked_memory_sa0_off: false,
            ..
        }
    ));
    for alternative in [
        "--checked-memory-sa0-off",
        "--system-boundaries",
        "--software-pauth",
        "--thread-registers",
    ] {
        let mut conflict = args.to_vec();
        conflict.push(alternative);
        let error = match Cli::try_parse_from(conflict) {
            Ok(_) => panic!("conflicting preparation profiles accepted"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
    }
    assert!(
        Cli::try_parse_from([
            "stela",
            "run-blocks",
            "input.bin",
            "--checked-process-sa0-off"
        ])
        .is_err()
    );
}
