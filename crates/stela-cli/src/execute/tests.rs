use crate::{Cli, Command};
use clap::Parser;

#[test]
fn explicit_process_id_requires_its_thread_owner_and_has_no_default() {
    assert!(
        Cli::try_parse_from(["stela", "run-blocks", "raw.bin", "--guest-process-id", "42",])
            .is_err()
    );
    let with_process = Cli::try_parse_from([
        "stela",
        "run-blocks",
        "raw.bin",
        "--thread-services",
        "--guest-vm-max-address",
        "0x800000000000",
        "--guest-process-id",
        "42",
    ])
    .unwrap();
    let Command::RunBlocks(crate::execute::RunBlocks {
        thread_services,
        guest_process_id,
        ..
    }) = with_process.command
    else {
        panic!("expected run-blocks command");
    };
    assert!(thread_services);
    assert_eq!(guest_process_id, Some(42));
    let legacy = Cli::try_parse_from([
        "stela",
        "run-blocks",
        "raw.bin",
        "--thread-services",
        "--guest-vm-max-address",
        "0x800000000000",
    ])
    .unwrap();
    let Command::RunBlocks(crate::execute::RunBlocks {
        guest_process_id, ..
    }) = legacy.command
    else {
        panic!("expected run-blocks command");
    };
    assert_eq!(guest_process_id, None);
}

#[test]
fn disabled_tracing_requires_an_explicit_clock_context() {
    assert!(Cli::try_parse_from(["stela", "run-blocks", "code", "--disabled-kdebug"]).is_err());
    assert!(
        Cli::try_parse_from([
            "stela",
            "run-blocks",
            "code",
            "--disabled-kdebug",
            "--clock-snapshot",
            "clock.json",
            "--software-pauth-keys",
            "keys.json"
        ])
        .is_ok()
    );
    assert!(Cli::try_parse_from(["stela", "run-blocks", "code", "--crossarch-services"]).is_ok());
}
