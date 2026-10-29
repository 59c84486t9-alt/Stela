//! Grammar decisions whose value consumption and error priority are observable.
use super::*;

#[test]
fn duplicate_checks_keep_their_value_precedence() {
    for (line, error) in [
        (
            "--system --native-cores 1 --native-cores",
            Error::DuplicateNativeCores,
        ),
        (
            "--system --native-cores 1 --native-cores invalid",
            Error::DuplicateNativeCores,
        ),
        (
            "--system --audio-check playback --audio-check",
            Error::DuplicateAudioCheck,
        ),
        (
            "--system --restore-manifest a --restore-manifest",
            Error::MissingRestoreManifest,
        ),
        (
            "--system --restore-manifest a --restore-manifest b",
            Error::DuplicateRestoreManifest,
        ),
        ("--system --wifi a --wifi %", Error::WifiNetwork),
        ("--system --wifi a --wifi b", Error::DuplicateWifi),
        (
            "--system --wifi-country US --wifi-country 1",
            Error::WifiCountry,
        ),
        (
            "--system --network-check http://h/p --network-check ftp://h/p",
            Error::UrlScheme,
        ),
        (
            "--system --storage-ram 1 --storage-ram",
            Error::MissingRamStorage,
        ),
    ] {
        assert_eq!(System::parse(line).unwrap_err(), error, "{line}");
    }
}

#[test]
fn unknown_options_still_parse_their_numeric_value_first() {
    for (suffix, error) in [
        ("--unknown", Error::MissingNumericValue),
        ("--unknown bad", Error::Number),
        ("--unknown --profile", Error::Number),
        ("--unknown 1", Error::UnknownSystemOption),
    ] {
        assert_eq!(
            System::parse(&format!("--system {suffix}")).unwrap_err(),
            error
        );
    }
}

#[test]
fn raw_string_values_and_ascii_word_boundaries_are_preserved() {
    let options = System::parse(
        "--system\t--wifi\n--native-memory-check --wifi-key --profile --bundle --input",
    )
    .unwrap();
    assert_eq!(options.ssid.as_deref(), Some("--native-memory-check"));
    assert_eq!(options.wifi_key.as_deref(), Some("--profile"));
    assert_eq!(options.bundle_directory.as_deref(), Some("--input"));
    assert!(!options.native_memory_check && !options.profile && !options.input);
    assert_eq!(
        System::parse("--system\u{a0}--profile"),
        Err(Error::SystemPrefix)
    );
    assert_eq!(
        System::parse("--system --wifi a\u{a0}b")
            .unwrap()
            .ssid
            .as_deref(),
        Some("a\u{a0}b")
    );
}

#[test]
fn normalization_follows_all_assignments_and_preserves_repeated_ranges() {
    for line in [
        "--system --parallel --native-rounds",
        "--system --native-rounds --parallel",
        "--system --native-shared-check --parallel",
        "--system --native-bootstrap-check --parallel",
    ] {
        assert!(!System::parse(line).unwrap().parallel, "{line}");
    }
    assert!(
        System::parse("--system --serialized --parallel")
            .unwrap()
            .parallel
    );
    assert!(
        !System::parse("--system --parallel --serialized")
            .unwrap()
            .parallel
    );
    let options = System::parse(
        "--system --bundle first --preboot @disk --bundle last --budget 2 --budget 3 \
         --trace 1 --trace 1 --break 2 --break 2 --watch 3,4 --watch 3,4 \
         --dump x1,5 --dump x1,5 --usb-storage a --usb-storage A",
    )
    .unwrap();
    assert_eq!(options.bundle_directory.as_deref(), Some("last"));
    assert!(options.preboot.as_ref().is_some_and(is_chosen));
    assert_eq!(options.budget, 3);
    assert_eq!(options.traces, [1, 1]);
    assert_eq!(options.breakpoints, [2, 2]);
    assert_eq!(options.watches, [(3, 4), (3, 4)]);
    assert_eq!(
        options.dumps,
        [(Base::Register(1, 0), 5), (Base::Register(1, 0), 5)]
    );
    assert_eq!(options.usb_storage, ["a", "A"]);
}

#[test]
fn producer_errors_keep_the_argument_that_failed() {
    for (line, argument) in [
        ("--system --storage bad", TargetArgument::Storage),
        ("--system --nor bad", TargetArgument::Nor),
        ("--system --preboot bad", TargetArgument::Preboot),
        (
            "--system --restore-source @disk",
            TargetArgument::RestoreSource,
        ),
    ] {
        let Error::Target {
            argument: actual,
            source,
        } = System::parse(line).unwrap_err()
        else {
            panic!("expected target cause for {line}");
        };
        assert_eq!(actual, argument);
        assert_eq!(source, "storage target must be SERIAL:PARTITION-GUID");
    }
    assert!(matches!(
        System::parse("--system --install-source bad"),
        Err(Error::Guid {
            argument: GuidArgument::InstallSource,
            ..
        })
    ));
    assert!(matches!(
        HostCheck::parse("--host-check --nor-file bad:/p"),
        Err(Error::Guid {
            argument: GuidArgument::HostNorFile,
            ..
        })
    ));
    assert!(matches!(
        System::parse("--system --boot-command 0"),
        Err(Error::BootCommandOrigin { value: 0, .. })
    ));
}

#[test]
fn host_repeats_overwrite_but_late_value_errors_precede_exclusivity() {
    let options = HostCheck::parse(
        "--host-check --native-dma-check --native-dma-check --deadline 1 --deadline 2 \
         --key-seconds 3 --key-seconds 4 \
         --nor-file 11111111-2222-3333-4444-555555555555:/a \
         --nor-file 11111111-2222-3333-4444-555555555555:/b",
    )
    .unwrap();
    assert_eq!(options.deadline, Some(2));
    assert_eq!(options.key_seconds, 4);
    assert_eq!(options.nor_file.unwrap().1, "/b");
    assert_eq!(
        HostCheck::parse("--host-check --native-dma-check --native-work-check --deadline 0"),
        Err(Error::HostSeconds)
    );
    assert_eq!(
        HostCheck::parse("--host-check --native-dma-check --native-work-check"),
        Err(Error::Constraint(Constraint::HostDiagnosticExclusive))
    );
}

#[test]
fn url_compatibility_adapter_keeps_the_same_diagnostic() {
    for (url, error) in [("http://h", Error::UrlPath), ("http:///p", Error::UrlHost)] {
        assert_eq!(parse_url(url), Err(error));
        assert_eq!(split_url(url), Err(error.message()));
    }
    assert_eq!(
        split_url("https://h/p"),
        Err("only http:// URLs are supported")
    );
    assert_eq!(split_url("http://h/p"), Ok(("h", "/p")));
}
#[test]
fn https_and_syntax_hardening_keep_raw_valid_configuration_values() {
    let raw = "https://H:443/a/../p%2f?sig=%2B%3d";
    let options = System::parse(&format!("--system --network-check {raw}")).unwrap();
    assert_eq!(options.network_check.as_deref(), Some(raw));
    assert_eq!(
        System::parse("--system --network-check http://h/p --network-check https://h/p"),
        Err(Error::DuplicateNetworkCheck)
    );
    assert_eq!(
        parse_url("http://h:bad/p"),
        Err(Error::Url(stela_runtime::net::http::UrlError::Syntax))
    );
    assert_eq!(
        parse_url("http://u:p@h/p"),
        Err(Error::Url(stela_runtime::net::http::UrlError::Credentials))
    );
}
