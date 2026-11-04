use super::*;
use alloc::{format, string::ToString, vec};

#[test]
fn diagnostic_options_are_typed() {
    for text in ["--system", "--system --wifi --native-memory-check"] {
        assert_eq!(System::parse(text).unwrap().diagnostic_option(), None);
    }
    for (text, flag) in [
        ("--system --native-memory-check", "--native-memory-check"),
        (
            "--system --native-cores 1 --native-clock-check",
            "--native-clock-check",
        ),
        ("--system --native-mmio-check", "--native-mmio-check"),
        (
            "--system --native-cores 2 --native-bootstrap-check",
            "--native-bootstrap-check",
        ),
        (
            "--system --native-cores 2 --native-shared-check",
            "--native-shared-check",
        ),
    ] {
        assert_eq!(System::parse(text).unwrap().diagnostic_option(), Some(flag));
    }
}

#[test]
fn host_check_lines_round_trip_and_refuse_combined_fixtures() {
    let line = "--host-check --native-dma-check \
                --nor-file 11111111-2222-3333-4444-555555555555:/stela/nor.bin --deadline 30 \
                --key-seconds 5";
    let options = HostCheck::parse(line).unwrap();
    assert_eq!(options.deadline, Some(30));
    assert_eq!(HostCheck::parse(&options.to_string()), Ok(options));
    assert_eq!(HostCheck::parse("--host-check"), Ok(HostCheck::default()));
    for text in [
        "--system",
        "--host-check --native-dma-check --native-work-check",
        "--host-check --deadline 0",
        "--host-check --nor-file x",
        "--host-check --unknown",
    ] {
        assert!(HostCheck::parse(text).is_err(), "{text}");
    }
}

const DISK: &str = "74EXN0LI:11111111-2222-3333-4444-555555555555";

fn round_trip(text: &str) -> System {
    let options = System::parse(text).unwrap();
    let line = options.to_string();
    assert_eq!(System::parse(&line), Ok(options.clone()), "{line}");
    options
}

#[test]
fn maintenance_writes_require_an_explicit_preboot_selection() {
    let ordinary = round_trip(&format!("--system --preboot {DISK}"));
    assert!(!ordinary.maintenance_write);
    assert!(!ordinary.to_string().contains(MAINTENANCE_WRITE));
    let maintenance = round_trip(&format!("--system --preboot {DISK} {MAINTENANCE_WRITE}"));
    assert!(maintenance.maintenance_write);
    assert_eq!(
        System::parse(&format!("--system {MAINTENANCE_WRITE}")),
        Err(Error::Constraint(Constraint::PrebootSelection))
    );
}

#[test]
fn setup_lines_parse_and_serialize_identically() {
    let preboot = format!(
        "--system --storage {DISK} --nor {DISK} --preboot {DISK} --ecid 0x0000000000001234 \
         --external-disks --guest-network --tss"
    );
    let options = round_trip(&preboot);
    assert!(options.bundle && options.external_disks && options.tss);
    assert_eq!(options.ecid, Some(0x1234));
    assert_eq!(options.to_string(), preboot);
    let bundle = format!("--system --storage {DISK} --nor {DISK} --bundle \\EFI\\stela\\r");
    assert_eq!(round_trip(&bundle).to_string(), bundle);
}

#[test]
fn chosen_disk_round_trips_and_the_mount_refuses_it_unreplaced() {
    let line = "--system --storage @disk --nor @disk --preboot @disk";
    let options = round_trip(line);
    assert!(options.storage.as_ref().is_some_and(is_chosen));
    assert_eq!(options.to_string(), line);
    assert!(System::parse_resolved(line).is_err());
    let resolved = line.replace("@disk", DISK);
    assert!(System::parse_resolved(&resolved).is_ok());
}

#[test]
fn every_option_survives_a_round_trip() {
    let options = round_trip(&format!(
        "--system --storage {DISK} --nor {DISK} --bundle b --install p.json \
         --install-source 11111111-2222-3333-4444-555555555555 --tss --verify-on-read \
         --usb-storage A --usb-storage B --input --idle-skip --sep-observe --native-cores 3 \
         --native-artifacts --serialized --profile --monitor-trace --display-trace \
         --network-check http://h/p --audio-check transport-duplex --dram-base 0x10000000000 \
         --load 0x10000004000 --entry 0x10000008000 --x0 7 --budget 99 --break 0x10 \
         --trace 0x20 --watch 0x30,0x40 --dump x21-0x8,0x10 --dump 0x50,0x60"
    ));
    assert_eq!(options.usb_storage, ["A", "B"]);
    assert_eq!(options.audio_check, Some(AudioCheck::TransportDuplex));
    assert!(options.display_trace);
    assert!(!System::default().display_trace);
    assert!(!options.parallel);
    assert_eq!(options.dumps[0], (Base::Register(21, -8), 0x10));
    let restore = round_trip(&format!(
        "--system --bundle b --storage {DISK} --restore-study --restore-source {DISK} \
         --restore-manifest m.plist --restore-identity 2"
    ));
    assert_eq!(restore.restore_manifest_path.as_deref(), Some("m.plist"));
}

#[test]
fn usb4_approvals_repeat_and_keep_their_canonical_spelling() {
    let first = "d0e30f35-5f6a-4b1e-9c00-112233445566";
    let second = "01234567-89ab-cdef-0123-456789abcdef";
    let options = round_trip(&format!(
        "--system --usb4-approve {} --usb4-approve {second}",
        first.to_uppercase()
    ));
    assert_eq!(options.usb4_approved.len(), 2);
    assert_eq!(
        options.to_string(),
        format!("--system --usb4-approve {first} --usb4-approve {second}")
    );
    for (text, error) in [
        ("--system --usb4-approve", Error::Usb4Approve),
        ("--system --usb4-approve nonsense", Error::Usb4Approve),
    ] {
        assert_eq!(System::parse(text).err(), Some(error), "{text}");
    }
    assert_eq!(
        System::parse(&format!(
            "--system --usb4-approve {first} --usb4-approve {first}"
        ))
        .err(),
        Some(Error::DuplicateUsb4Approve)
    );
}

#[test]
fn wifi_names_escape_spaces_and_the_key_path_defaults() {
    let options = round_trip("--system --wifi Home%20Net%25 --wifi-country gb");
    assert_eq!(options.ssid.as_deref(), Some("Home Net%"));
    assert_eq!(options.wifi_key.as_deref(), Some(DEFAULT_WIFI_KEY));
    assert_eq!(options.wifi_country.as_deref(), Some("GB"));
    assert_eq!(
        options.to_string(),
        "--system --wifi Home%20Net%25 --wifi-country GB"
    );
    let keyed = round_trip("--system --wifi caf\u{e9} --wifi-key \\EFI\\k");
    assert_eq!(keyed.ssid.as_deref(), Some("caf\u{e9}"));
    assert_eq!(keyed.wifi_key.as_deref(), Some("\\EFI\\k"));
    for text in [
        "--system --wifi-key \\k",
        "--system --wifi-country GB",
        "--system --wifi %",
        "--system --wifi %4",
        "--system --wifi %FF",
        "--system --wifi 0123456789abcdef0123456789abcdef0",
        "--system --wifi a --wifi b",
        "--system --wifi a --wifi-country GBR",
        "--system --wifi a --wifi-country 12",
    ] {
        assert!(System::parse(text).is_err(), "{text}");
    }
}

#[test]
fn static_ipv4_and_dns_round_trip_and_stay_in_their_subnet() {
    let text = "--system --ipv4 192.168.1.20/24 --ipv4-gateway 192.168.1.1 --dns 1.1.1.1,2606:4700:4700::1111";
    let options = round_trip(text);
    assert_eq!(
        options.ipv4,
        Some(StaticIpv4 {
            address: core::net::Ipv4Addr::new(192, 168, 1, 20),
            prefix: 24
        })
    );
    assert_eq!(options.dns.len(), 2);
    assert_eq!(options.to_string(), text);
    assert_eq!(
        round_trip("--system --ipv4 10.0.0.1/31").to_string(),
        "--system --ipv4 10.0.0.1/31"
    );
    for text in [
        "--system --ipv4 192.168.1.20",
        "--system --ipv4 192.168.1.20/33",
        "--system --ipv4 192.168.1.0/24",
        "--system --ipv4 192.168.1.255/24",
        "--system --ipv4 224.0.0.1/4",
        "--system --ipv4 10.0.0.2/8 --ipv4 10.0.0.3/8",
        "--system --ipv4-gateway 192.168.1.1",
        "--system --ipv4 192.168.1.20/24 --ipv4-gateway 192.168.2.1",
        "--system --ipv4 192.168.1.20/24 --ipv4-gateway 192.168.1.20",
        "--system --dns 1.1.1.1,1.1.1.1",
        "--system --dns 1.1.1.1,1.0.0.1,9.9.9.9,8.8.8.8",
        "--system --dns 0.0.0.0",
        "--system --dns 1.1.1.1 --dns 9.9.9.9",
    ] {
        assert!(System::parse(text).is_err(), "{text}");
    }
}

#[test]
fn native_checks_imply_serialized_execution_without_writing_it() {
    let options = round_trip("--system --native-cores 2 --native-rounds");
    assert!(!options.parallel);
    assert!(!options.to_string().contains("--serialized"));
    assert!(System::parse("--system").unwrap().parallel);
}

#[test]
fn native_core_counts_refuse_duplicates_zero_and_over_capacity() {
    for text in [
        "--system --native-cores 1 --native-cores 1",
        "--system --native-cores 0",
        "--system --native-cores 65",
        "--system --native-cores x",
        "--system --native-cores",
    ] {
        assert!(System::parse(text).is_err(), "{text}");
    }
    assert_eq!(
        System::parse("--system --native-cores 64")
            .unwrap()
            .native_cores,
        Some(64)
    );
}

#[test]
fn guest_pes_bound_the_executors_that_run_them() {
    for text in [
        "--system --guest-pes",
        "--system --guest-pes 0",
        "--system --guest-pes 8 --guest-pes 8",
    ] {
        assert!(System::parse(text).is_err(), "{text}");
    }
    let options = System::parse("--system --guest-pes 8").unwrap();
    assert_eq!(options.guest_pes, Some(8));
    assert!(options.to_string().contains("--guest-pes 8"));
    assert_eq!(options.runners(64, false), 8);
    assert_eq!(options.runners(2, false), 2);
    assert_eq!(options.runners(64, true), 1);
    assert_eq!(System::parse("--system").unwrap().runners(64, false), 64);
}

#[test]
fn invalid_lines_refuse() {
    for text in [
        "--storage x",
        "--system --unknown 1",
        "--system --install p.json",
        "--system --ecid 0",
        "--system --safe-boot",
        "--system --network-check ftp://h/p",
        "--system --dram-base 0x1000",
        "--system --storage-ram 1 --storage-ram 2",
    ] {
        assert!(System::parse(text).is_err(), "{text}");
    }
}

#[test]
fn numbers_take_decimal_and_separated_hex() {
    assert_eq!(number("0x1_0000"), Ok(0x10000));
    assert_eq!(number("42"), Ok(42));
    assert!(number("0xg").is_err());
    assert_eq!(
        vec![Base::parse("x3+0x10").unwrap()],
        [Base::Register(3, 16)]
    );
}

mod constraints;
mod grammar;
