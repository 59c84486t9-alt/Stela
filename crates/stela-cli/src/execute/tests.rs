use crate::{Cli, Command, execute::Service};
use clap::Parser;

#[test]
fn services_parse_as_one_comma_separated_list() {
    let cli = Cli::try_parse_from([
        "stela",
        "run-blocks",
        "raw.bin",
        "--services",
        "thread,entropy",
        "--guest-process-id",
        "42",
    ])
    .unwrap();
    let Command::RunBlocks(crate::execute::RunBlocks {
        services,
        guest_process_id,
        ..
    }) = cli.command
    else {
        panic!("expected run-blocks command");
    };
    assert!(services == [Service::Thread, Service::Entropy]);
    assert_eq!(guest_process_id, Some(42));
    assert!(
        Cli::try_parse_from(["stela", "run-blocks", "raw.bin", "--services", "unknown"]).is_err()
    );
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
}
