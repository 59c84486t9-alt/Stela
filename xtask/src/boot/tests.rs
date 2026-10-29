//! Tests for boot commands and run reports.
use super::*;

#[test]
fn native_clock_requires_unique_progress_and_quiet_retirement_proof() {
    let full = "CHECK native-clock PASS busy_jiffies=8 idle_waits=1 guest_mux=elapsed detach=quiet source=Observation { fadt_sha256: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], pm_port: 0, pm_mask: 0, pm_hz: 0, apic_hz: 0, cpu: 0, root: 0, idt: 0, gs: 0, max_cpuid: 0, thermal_eax: 0 }; authored UP fixture, original Linux and hardware unqualified";
    assert_eq!(native_clock_proof(full), Some(full));
    for (field, replacement) in [
        ("busy_jiffies=8", "busy_jiffies=7"),
        ("busy_jiffies=8", "busy_jiffies=18446744073709551616"),
        ("idle_waits=1", "idle_waits=0"),
        ("idle_waits=1", "idle_waits=invalid"),
        ("guest_mux=elapsed", "guest_mux=pending"),
        ("detach=quiet", "detach=active"),
        ("source=Observation", "source=unobserved"),
    ] {
        assert!(native_clock_proof(&full.replace(field, replacement)).is_none());
    }
    for extra in [
        "busy_jiffies=8",
        "idle_waits=1",
        "guest_mux=elapsed",
        "detach=quiet",
        "source=Observation",
    ] {
        assert!(native_clock_proof(&format!("{full} {extra}")).is_none());
    }
    assert!(native_clock_proof(&format!("{full}\n{full}")).is_none());
    assert!(native_clock_proof(&format!("{full}\nCHECK native-clock FAIL retire")).is_none());
    assert!(native_clock_proof("CHECK native-mmio PASS roots=all").is_none());
    assert!(native_clock_proof(full.split_once(" source=").unwrap().0).is_none());
    assert!(
        native_clock_proof(&format!(
            "{} source=Observation",
            full.split_once(" source=").unwrap().0
        ))
        .is_none()
    );
    assert!(native_clock_proof(full.split_once("; authored").unwrap().0).is_none());
    assert!(native_clock_proof(&full.replace("thermal_eax: 0", "thermal_eax:")).is_none());
    assert!(native_clock_proof(&full.replace("pm_port: 0", "pm_port: 65536")).is_none());
}

#[test]
fn native_clock_accepts_exactly_one_complete_hpet_source() {
    let full = "CHECK native-clock PASS busy_jiffies=8 idle_waits=1 guest_mux=elapsed detach=quiet source=Observation { hpet_sha256: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], hpet_base: 4096, hpet_block_id: 0, hpet_number: 0, hpet_period_fs: 10000000, apic_hz: 0, cpu: 0, root: 0, idt: 0, gs: 0, max_cpuid: 0, thermal_eax: 0 }; authored UP fixture, original Linux and hardware unqualified";
    assert_eq!(native_clock_proof(full), Some(full));
    for (field, replacement) in [
        ("hpet_sha256:", "fadt_sha256:"),
        ("hpet_sha256:", "source_sha256:"),
        ("hpet_base: 4096, ", ""),
        ("hpet_block_id: 0, ", ""),
        ("hpet_number: 0, ", ""),
        ("hpet_period_fs: 10000000, ", ""),
        ("hpet_base: 4096", "hpet_base: 18446744073709551616"),
        ("hpet_block_id: 0", "hpet_block_id: 4294967296"),
        ("hpet_number: 0", "hpet_number: 256"),
        ("hpet_period_fs: 10000000", "hpet_period_fs: 4294967296"),
        ("hpet_number: 0", "pm_port: 0"),
        ("hpet_number: 0", "hpet_number: 0, hpet_number: 0"),
        ("hpet_number: 0", "hpet_number: 0, pm_port: 0"),
        ("apic_hz: 0", "apic_hz: 0, apic_hz: 0"),
        ("guest_mux=elapsed", "guest_mux=pending"),
        ("detach=quiet", "detach=active"),
        ("idle_waits=1", "idle_waits=0"),
        ("busy_jiffies=8", "busy_jiffies=7"),
    ] {
        assert!(
            native_clock_proof(&full.replace(field, replacement)).is_none(),
            "{field}"
        );
    }
    assert!(native_clock_proof(&format!("{full}\n{full}")).is_none());
    let pm = full.replace("hpet_sha256:", "fadt_sha256:").replace(
        "hpet_base: 4096, hpet_block_id: 0, hpet_number: 0, hpet_period_fs: 10000000",
        "pm_port: 0, pm_mask: 0, pm_hz: 0",
    );
    assert_eq!(native_clock_proof(&pm), Some(pm.as_str()));
    assert!(native_clock_proof(&format!("{pm}\n{full}")).is_none());
    assert!(native_clock_proof(&pm.replace("pm_hz: 0", "pm_hz: 0, hpet_number: 0")).is_none());
}

#[test]
fn native_clock_requires_exclusive_topology() {
    use clap::Parser;
    let prefix = ["xtask", "boot", "run", "--output", "/tmp/native-clock"];
    let parse = |options: Vec<&str>| {
        let parsed = crate::Cli::try_parse_from(prefix.into_iter().chain(options))?;
        let crate::Task::Boot(Command::Run(run)) = parsed.task else {
            panic!("boot run")
        };
        Ok::<_, clap::Error>(run)
    };
    let run = parse(vec!["--native-clock-check"]).unwrap();
    assert!(run.native_clock_check);
    assert!(native_root_preflight(&run).is_ok());
    assert_eq!(
        native_clock_options(),
        format!("{KERNEL_OPTIONS} --native-clock-check --native-cores 1")
    );
    for conflict in [
        "--native-mmio-check",
        "--native-dma-check",
        "--native-dma-isolation-check",
        "--native-work-check",
        "--native-irq-work-check",
        "--network",
        "--storage-check",
        "--input",
        "--audio-check",
    ] {
        assert!(parse(vec!["--native-clock-check", conflict]).is_err());
        assert!(parse(vec![conflict, "--native-clock-check"]).is_err());
    }
    for (option, value) in [("--gdb", "1234"), ("--monitor", "1234"), ("--icount", "0")] {
        assert!(parse(vec!["--native-clock-check", option, value]).is_err());
    }
    for (option, value) in [
        ("--host-cores", "2"),
        ("--host-threads", "2"),
        ("--display", "window"),
    ] {
        assert!(
            native_root_preflight(&parse(vec!["--native-clock-check", option, value]).unwrap())
                .is_err()
        );
    }
}

#[test]
fn native_mmio_requires_complete_actual_mapping_and_refusal_proof() {
    let stack = "CHECK native-stack finite=4 actual_rsp=0x9000,0xa000 source=retired parent=clear+TLB; no Linux owner or CPU-time grant";
    let mmio = "CHECK native-mmio PASS authority=actual roots=all native_cpus=1 effective_cache=Intel-UC aperture=owned-PTE map=published retire=actual-clear+TLB reuse=readback foreign-root=refused WC=refused clock=HPET64 retained_hpet=1 root_lifetime=kernel-image ioapics=1 MCFG=0xb0000000 buses=0..=0 vendor=0x12378086; bounded authored diagnostic, Linux and physical hardware unqualified";
    let mixed32 = "CHECK native-mixed32 PASS contexts=32 kernel=21 rust=11 raw_bytes=1798144 payload_bytes=1785856 alignment_padding=12288 guards=all-roots holes=absent cache=WB retire=32-views raw=whole-boot-owned refusals=wrong-inventory+allocation-capacity; no C-current, Clock or provider grant";
    let full = format!("{mixed32}\n{stack}\n{mmio}");
    assert!(native_mmio_verified(&full));
    assert_eq!(native_mmio_observation(&full), Some(mmio));
    assert_eq!(native_stack_observation(&full), Some(stack));
    for field in [
        "authority=actual",
        "roots=all",
        "native_cpus=1",
        "effective_cache=Intel-UC",
        "aperture=owned-PTE",
        "map=published",
        "retire=actual-clear+TLB",
        "reuse=readback",
        "foreign-root=refused",
        "WC=refused",
        "clock=HPET64",
        "retained_hpet=1",
        "root_lifetime=kernel-image",
        "buses=0..=0",
        "source=retired",
        "parent=clear+TLB",
    ] {
        assert!(
            !native_mmio_verified(&full.replace(field, "unproven")),
            "{field}"
        );
    }
    for replacement in ["ioapics=0", "ioapics=invalid"] {
        assert!(!native_mmio_verified(
            &full.replace("ioapics=1", replacement)
        ));
    }
    for replacement in ["vendor=0x0;", "vendor=0xffffffff;", "vendor=invalid;"] {
        assert!(!native_mmio_verified(
            &full.replace("vendor=0x12378086;", replacement)
        ));
    }
    assert!(!native_mmio_verified("CHECK native-dma PASS old image"));
    assert!(!native_mmio_verified(&format!(
        "{full}\nCHECK native-mmio FAIL cleanup"
    )));
    assert!(!native_mmio_verified(&format!("{full}\n{full}")));
    assert!(!native_mmio_verified(mmio));
    assert!(!native_mmio_verified(stack));
    assert!(!native_mmio_verified(&format!("{full}\n{stack}")));
    assert!(!native_mmio_verified(
        &full.replace("clock=HPET64", "clock=HPET64 clock=PM24")
    ));
    assert!(!native_mmio_verified(&full.replace(
        "kernel-image ioapics",
        "kernel-image retained_hpet=0 ioapics"
    )));
    for pair in [
        "0x0,0xa000",
        "0x9000,0x0",
        "0x9000,0x9000",
        "9000,0xa000",
        "0x10000000000000000,0xa000",
        "0x9000,0xa000,0xb000",
    ] {
        assert!(
            !native_mmio_verified(&full.replace("0x9000,0xa000", pair)),
            "{pair}"
        );
    }
    for suffix in [
        "; no Linux owner or CPU-time grant",
        "; bounded authored diagnostic, Linux and physical hardware unqualified",
    ] {
        assert!(!native_mmio_verified(&full.replace(suffix, "")));
    }
    assert!(!native_mmio_verified("CHECK native-mmio FAIL MissingSdt"));
    assert!(!native_mmio_verified(&full.replace("buses=0..=0", "")));
    for range in [
        "1..=0",
        "0..=256",
        "-1..=0",
        "+0..=0",
        "0x0..=0",
        "0..0",
        "0..=",
        "0..=0..=0",
    ] {
        assert!(
            !native_mmio_verified(&full.replace("buses=0..=0", &format!("buses={range}"))),
            "{range}"
        );
    }
    assert!(!native_mmio_verified(
        &full.replace("buses=0..=0", "buses=0..=0 buses=1..=1")
    ));
    assert!(native_mmio_verified(
        &full.replace("buses=0..=0", "buses=1..=255")
    ));
}

#[test]
fn hpet_is_explicit_and_restricted_to_owned_clock_modes_before_work() {
    use clap::Parser;
    let prefix = ["xtask", "boot", "run", "--output", "/tmp/native-mmio-hpet"];
    let parse = |options: Vec<&str>| {
        let parsed = crate::Cli::try_parse_from(prefix.into_iter().chain(options))?;
        let crate::Task::Boot(Command::Run(run)) = parsed.task else {
            panic!("boot run")
        };
        Ok::<_, clap::Error>(run)
    };
    let default = parse(vec!["--native-mmio-check"]).unwrap();
    assert!(!default.hpet);
    for mode in ["--native-mmio-check", "--native-clock-check"] {
        let enabled = parse(vec![mode, "--hpet"]).unwrap();
        assert!(enabled.hpet);
        assert!(native_root_preflight(&enabled).is_ok());
        assert!(
            native_root_preflight(&parse(vec![mode, "--hpet", "--host-cores", "2"]).unwrap())
                .is_err()
        );
    }
    assert!(parse(vec!["--hpet"]).is_err());
    for options in [
        vec!["--network", "--hpet"],
        vec!["--module", "not-opened-by-preflight", "--hpet"],
    ] {
        if let Ok(invalid) = parse(options) {
            assert!(invalid.hpet && !invalid.native_mmio_check && !invalid.native_clock_check);
            assert!(native_root_preflight(&invalid).is_err());
        }
    }
    assert!(
        native_root_preflight(
            &parse(vec!["--native-mmio-check", "--hpet", "--host-cores", "2"]).unwrap()
        )
        .is_err()
    );
    let off = qemu_machine("off", false);
    assert_eq!(
        off,
        "q35,smm=off,sata=off,usb=off,smbus=off,hpet=off,i8042=off,vmport=off"
    );
    assert_eq!(
        qemu_machine("off", true),
        off.replace("hpet=off", "hpet=on")
    );
    assert_eq!(
        qemu_machine("on", false),
        off.replace("i8042=off", "i8042=on")
    );
}

#[test]
fn native_mmio_emits_system_options_without_host_check_only_keys() {
    let options = native_mmio_options();
    let words = options.split_ascii_whitespace().collect::<Vec<_>>();
    assert_eq!(words.first(), Some(&"--system"));
    assert_eq!(
        words
            .iter()
            .filter(|word| **word == "--native-mmio-check")
            .count(),
        1
    );
    assert!(options.starts_with(KERNEL_OPTIONS));
    for forbidden in ["--host-check", "--deadline", "--key-seconds"] {
        assert!(!words.contains(&forbidden));
    }
}

#[test]
fn native_mmio_refuses_conflicting_cli_and_topology_before_work() {
    use clap::Parser;
    let prefix = ["xtask", "boot", "run", "--output", "/tmp/native-mmio"];
    let parse = |options: Vec<&str>| {
        let parsed = crate::Cli::try_parse_from(prefix.into_iter().chain(options))?;
        let crate::Task::Boot(Command::Run(run)) = parsed.task else {
            panic!("boot run")
        };
        Ok::<_, clap::Error>(run)
    };
    let run = parse(vec!["--native-mmio-check"]).unwrap();
    assert!(run.native_mmio_check);
    assert!(native_root_preflight(&run).is_ok());
    for conflict in [
        "--native-dma-check",
        "--native-dma-isolation-check",
        "--native-work-check",
        "--native-irq-work-check",
        "--storage-check",
        "--network",
        "--input",
        "--audio-check",
    ] {
        assert!(parse(vec!["--native-mmio-check", conflict]).is_err());
        assert!(parse(vec![conflict, "--native-mmio-check"]).is_err());
    }
    for (option, value) in [("--gdb", "1234"), ("--monitor", "1234"), ("--icount", "0")] {
        assert!(parse(vec!["--native-mmio-check", option, value]).is_err());
        assert!(parse(vec![option, value, "--native-mmio-check"]).is_err());
    }
    for (option, value) in [
        ("--host-cores", "2"),
        ("--host-threads", "2"),
        ("--display", "window"),
    ] {
        let run = parse(vec!["--native-mmio-check", option, value]).unwrap();
        assert!(native_root_preflight(&run).is_err());
    }
}

#[test]
fn parallel_cpu_default_and_icount_select_distinct_modes() {
    assert_eq!(qemu_accelerator(None, false), "tcg,thread=multi");
    for shift in 0..=10 {
        assert_eq!(qemu_accelerator(Some(shift), false), "tcg,thread=single");
    }
    assert_eq!(qemu_accelerator(None, true), "kvm");
}

#[test]
fn cpu_selection_preserves_model_and_baseline_overrides() {
    assert_eq!(qemu_cpu(None, false, true), "max,vendor=GenuineIntel");
    assert_eq!(qemu_cpu(None, false, false), "qemu64");
    assert_eq!(qemu_cpu(Some("Nehalem"), true, true), "Nehalem,la57=off");
    assert_eq!(
        qemu_cpu(Some("max,vendor=AuthenticAMD"), false, true),
        "max,vendor=AuthenticAMD"
    );
}

#[test]
fn run_report_keeps_degraded_requirements_and_the_first_guest_panic() {
    let serial = concat!(
        "GUEST| panic handlers ready\r\n",
        "UNMODELED pc=0x1000 device write at PA 0x2000: missing lifecycle\r\n",
        "GUEST| panic(cpu 0 caller 0x3000): first failure\r\n",
        "UNMODELED pc=0x4000 debug sample: PE is off\r\n",
        "GUEST| panic: nested failure\r\n",
        "STOP UNSUPPORTED a later terminal requirement\r\n",
        "STOP reset: amcc: DRAM access disabled\r\n",
    );
    assert_eq!(
        first_unsupported(serial),
        Some("pc=0x1000 device write at PA 0x2000: missing lifecycle")
    );
    assert_eq!(
        first_guest_panic(serial),
        Some("panic(cpu 0 caller 0x3000): first failure")
    );
    assert_eq!(
        first_unsupported("STOP UNSUPPORTED pc=0x1000 instruction\n"),
        Some("pc=0x1000 instruction")
    );
    assert_eq!(
        first_guest_panic("GUEST| panic: first failure\n"),
        Some("panic: first failure")
    );
    for ordinary in [
        "GUEST| UNMODELED guest text\n",
        "GUEST| panic flow initialized\n",
        "STOP reset: ordinary restart\n",
    ] {
        assert_eq!(first_unsupported(ordinary), None);
        assert_eq!(first_guest_panic(ordinary), None);
    }
}

#[test]
fn native_fixture_does_not_hide_a_real_guest_panic() {
    assert_eq!(
        first_guest_panic("CHECK native-dma PASS traffic\nGUEST| panic(cpu 0): failed\n"),
        Some("panic(cpu 0): failed")
    );
    assert_eq!(
        first_guest_panic("GUEST| panic handlers ready\nGUEST| panic flow initialized\n"),
        None
    );
}

#[test]
fn isolation_fixture_requires_both_requesters_and_matched_fault() {
    use clap::Parser;
    let args = [
        "xtask",
        "boot",
        "run",
        "--output",
        "/tmp/isolation",
        "--native-dma-isolation-check",
    ];
    assert!(crate::Cli::try_parse_from(args).is_ok());
    for conflict in ["--native-dma-check", "--network", "--storage-check"] {
        let mut bad = args.to_vec();
        bad.push(conflict);
        assert!(crate::Cli::try_parse_from(bad).is_err());
    }
    assert!(!native_isolation_verified(
        "CHECK native-dma PASS single EDU roundtrip=verified"
    ));
    let full = "CHECK native-dma-isolation PASS rid_a=0x0010 did_a=1 rid_b=0x0018 did_b=2 same_iova=disjoint-ram roundtrip_a=verified roundtrip_b=verified wrong_domain_rid=0x0018 wrong_domain_address=0x3000 wrong_domain_reason=0x6 retained_ram=unchanged owner_access=verified other_context_after_detach=verified teardown=context+IOTLB+TE-off-ack";
    assert!(native_isolation_verified(full));
    assert!(!native_isolation_verified(
        &full.replace("wrong_domain_reason=0x6", "wrong_domain_reason=0x0")
    ));
    for marker in [
        "wrong_domain_rid=0x0018",
        "retained_ram=unchanged",
        "other_context_after_detach=verified",
        "teardown=context+IOTLB+TE-off-ack",
    ] {
        assert!(!native_isolation_verified(
            &full.replace(marker, "unproven")
        ));
    }
    assert!(!native_isolation_verified(&format!(
        "{full}\nCHECK native-dma FAIL uncertain"
    )));
}

#[test]
fn extended_irq_fixture_never_relabels_msi_only_or_partial_evidence() {
    let old = "CHECK native-irq PASS EDU vector=0x50 actual_cause=0x1 device_ACK+EOI=verified late_delivery=absent";
    assert!(!native_level_verified(old));
    let full = format!(
        "{old}; INTx gsi=22 high+shared+level first=2 second=1 hold→EOI→retrigger=verified RemoteIRR=observed/drained group_refs=released DSDT=ed48c9772aee854066c14b36ce8f787bb69d279afa15dea729b8ba2f9b77256d"
    );
    assert!(native_level_verified(&full));
    let intel = full.replace(
        "ed48c9772aee854066c14b36ce8f787bb69d279afa15dea729b8ba2f9b77256d",
        "dfe8afc13a175262e7bf69710bf7738c11d22051998d20d820685f373e31cf80",
    );
    assert!(native_level_verified(&intel));
    assert!(!native_level_verified(&format!("{intel}0")));
    assert!(!native_level_verified(&intel.replace("DSDT=df", "DSDT=00")));
    assert!(!native_level_verified(
        &full.replace("RemoteIRR=observed/drained", "RemoteIRR=unknown")
    ));
    assert!(!native_level_verified(&format!(
        "{full}\nCHECK native-dma FAIL stop uncertain"
    )));
}

#[test]
fn qemu_host_inventory_does_not_synthesize_a_native_worker_grant() {
    use clap::Parser;
    let prefix = ["xtask", "boot", "run", "--output", "/tmp/owned-cores"];
    let parsed =
        crate::Cli::try_parse_from(prefix.into_iter().chain(["--host-cores", "2"])).unwrap();
    let crate::Task::Boot(Command::Run(run)) = parsed.task else {
        panic!("boot run")
    };
    assert_eq!(run.host_cores, 2);
    assert_eq!(run.host_threads, 1);
    assert!(run.append.is_none());
    let parsed = crate::Cli::try_parse_from(prefix.into_iter().chain([
        "--host-cores",
        "8",
        "--host-threads",
        "2",
    ]))
    .unwrap();
    let crate::Task::Boot(Command::Run(run)) = parsed.task else {
        panic!("boot run")
    };
    assert_eq!((run.host_cores, run.host_threads), (8, 2));
    assert!(run.append.is_none());
    assert!(
        crate::Cli::try_parse_from(prefix.into_iter().chain(["--host-threads", "0",])).is_err()
    );
    for invalid in ["0", "65", "-1", "two"] {
        assert!(
            crate::Cli::try_parse_from(prefix.into_iter().chain(["--host-cores", invalid]))
                .is_err()
        );
    }
}

#[test]
fn native_irq_work_requires_exclusive_async_proof() {
    use clap::Parser;
    let full = "CHECK native-irq-work PASS roundtrip=verified teardown=IOTLB+TE-off-ack actual_cause=0x1 IRQ_depth=real interrupted_SP=owned-foreground ISR_SP=separate-IST current_id=IRQ-refused enqueue=owned/noninline worker=owned-distinct-context async_FXSAVE=unchanged heap=aligned-zeroed-read-write-reclaimed heap_IF=off/on-preserved mask+hardware+IRR/ISR+inflight+work=drained late_delivery=absent stack_leases=4-released BSP_device_owner=!Send";
    assert!(native_irq_work_verified(full));
    for marker in [
        "IRQ_depth=real",
        "interrupted_SP=owned-foreground",
        "current_id=IRQ-refused",
        "worker=owned-distinct-context",
        "async_FXSAVE=unchanged",
        "heap=aligned-zeroed-read-write-reclaimed",
        "heap_IF=off/on-preserved",
        "mask+hardware+IRR/ISR+inflight+work=drained",
        "BSP_device_owner=!Send",
    ] {
        assert!(!native_irq_work_verified(&full.replace(marker, "unproven")));
    }
    assert!(!native_irq_work_verified(
        "CHECK native-work PASS source_IRQ_enqueue=not-qualified"
    ));
    assert!(!native_irq_work_verified(
        "CHECK native-irq PASS actual_cause=0x1"
    ));
    assert!(!native_irq_work_verified(&format!(
        "{full}\nCHECK native-irq-work FAIL uncertain owner"
    )));
    let prefix = ["xtask", "boot", "run", "--output", "/tmp/native-irq-work"];
    let parsed =
        crate::Cli::try_parse_from(prefix.into_iter().chain(["--native-irq-work-check"])).unwrap();
    let crate::Task::Boot(Command::Run(run)) = parsed.task else {
        panic!("boot run")
    };
    assert!(run.native_irq_work_check);
    for conflict in [
        "--native-dma-check",
        "--native-dma-isolation-check",
        "--native-work-check",
        "--audio-check",
        "--network",
        "--storage-check",
    ] {
        for pair in [
            ["--native-irq-work-check", conflict],
            [conflict, "--native-irq-work-check"],
        ] {
            assert!(crate::Cli::try_parse_from(prefix.into_iter().chain(pair)).is_err());
        }
    }
}

#[test]
fn native_work_requires_its_complete_fresh_proof_and_exclusive_cli() {
    use clap::Parser;
    let full = "CHECK native-work PASS foreground=owned-stack ids=distinct/stable execute=deferred Notify=FIFO general=yield/resume Win64-shadow+all-GPR+XMM6-15=task+dispatcher-verified MXCSR+x87=preserved IF=off/on/clear-yield/exact guards=8-absent RW+NX+WB=verified idle_stack_leases=4-released pending_runtime+stacks=quarantined overflow+close=refused drain_cycles=refused source_IRQ_enqueue=not-qualified";
    assert!(native_work_verified(full));
    for marker in [
        "foreground=owned-stack",
        "Win64-shadow+all-GPR+XMM6-15=task+dispatcher-verified",
        "IF=off/on/clear-yield/exact",
        "guards=8-absent",
        "pending_runtime+stacks=quarantined",
        "drain_cycles=refused",
        "source_IRQ_enqueue=not-qualified",
    ] {
        assert!(!native_work_verified(&full.replace(marker, "unproven")));
    }
    assert!(!native_work_verified("CHECK native-dma PASS old EFI"));
    assert!(!native_work_verified(&full.replace(
        "Win64-shadow+all-GPR+XMM6-15=task+dispatcher-verified",
        "Win64-shadow+callee-save=verified"
    )));
    assert!(!native_work_verified(&format!(
        "{full}\nCHECK native-work FAIL late teardown"
    )));
    let base = [
        "xtask",
        "boot",
        "run",
        "--output",
        "/tmp/native-work",
        "--native-work-check",
    ];
    let parsed = crate::Cli::try_parse_from(base).unwrap();
    let crate::Task::Boot(Command::Run(run)) = parsed.task else {
        panic!("boot run")
    };
    assert!(run.native_work_check);
    for conflict in [
        "--native-dma-check",
        "--native-dma-isolation-check",
        "--network",
        "--storage-check",
    ] {
        assert!(crate::Cli::try_parse_from(base.into_iter().chain([conflict])).is_err());
    }
}

#[test]
fn native_work_and_audio_require_exclusive_ownership() {
    use clap::{Parser, error::ErrorKind};
    for mode in [
        "playback",
        "duplex",
        "transport-playback",
        "transport-duplex",
    ] {
        for options in [
            ["--native-work-check", "--audio-check", mode],
            ["--audio-check", mode, "--native-work-check"],
        ] {
            let error =
                crate::Cli::try_parse_from(["xtask", "boot", "run"].into_iter().chain(options))
                    .err()
                    .expect("native-work and audio fixtures must be exclusive");
            assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
        }
    }
}

#[test]
fn native_dma_fixture_requires_exclusive_test_topology() {
    use clap::Parser;
    let parsed = crate::Cli::try_parse_from([
        "xtask",
        "boot",
        "run",
        "--output",
        "/tmp/native-dma",
        "--native-dma-check",
    ])
    .unwrap();
    let crate::Task::Boot(Command::Run(run)) = parsed.task else {
        panic!("boot run");
    };
    assert!(run.native_dma_check);
    assert!(
        crate::Cli::try_parse_from([
            "xtask",
            "boot",
            "run",
            "--output",
            "/tmp/native-dma",
            "--native-dma-check",
            "--audio-check",
            "transport-playback"
        ])
        .is_err()
    );
    assert!(
        crate::Cli::try_parse_from([
            "xtask",
            "boot",
            "run",
            "--output",
            "/tmp/native-dma",
            "--native-dma-check",
            "--append",
            "--system"
        ])
        .is_err()
    );
    assert!(
        crate::Cli::try_parse_from([
            "xtask",
            "boot",
            "run",
            "--output",
            "/tmp/native-dma",
            "--native-dma-check",
            "--network"
        ])
        .is_err()
    );
}

#[test]
fn attached_storage_and_directory_volume_have_explicit_cli_contracts() {
    use clap::Parser;
    let cli = crate::Cli::try_parse_from([
        "xtask",
        "boot",
        "run",
        "--bundle",
        "/tmp/bundle",
        "--output",
        "/tmp/run",
        "--storage-disk",
        "/tmp/disk.raw",
        "--storage-serial",
        "ANS-1",
        "--directory-volume",
        "--append",
        "--system --storage ANS-1:GUID",
    ])
    .unwrap();
    let crate::Task::Boot(Command::Run(run)) = cli.task else {
        panic!("boot run");
    };
    assert_eq!(run.storage_serial, ["ANS-1"]);
    assert_eq!(run.storage_disk, [Path::new("/tmp/disk.raw")]);
    assert!(run.directory_volume);
    assert_eq!(run.append.as_deref(), Some("--system --storage ANS-1:GUID"));
    for extra in [
        vec!["--storage-disk", "/tmp/disk", "--storage-check"],
        vec!["--storage-serial", "ANS"],
        vec!["--directory-volume"],
        vec!["--network-check", "http://example.test/"],
        vec!["--usb-storage-disk", "/tmp/disk", "--storage-check"],
        vec!["--network", "--usb-network"],
        vec!["--network-model", "e1000e"],
        vec!["--network-self-check"],
        vec![
            "--network",
            "--network-self-check",
            "--network-check",
            "http://localhost/",
        ],
        vec!["--network", "--network-model", "unknown"],
        vec!["--usb-disk", "/tmp/disk", "--storage-check"],
        vec![
            "--storage-disk",
            "/tmp/disk",
            "--storage-serial",
            "bad,drive=x",
        ],
    ] {
        let args: Vec<_> = ["xtask", "boot", "run", "--output", "/tmp/run"]
            .into_iter()
            .chain(extra)
            .collect();
        assert!(crate::Cli::try_parse_from(args).is_err());
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn process_image_identifies_the_executing_binary() {
    assert_eq!(
        fs::canonicalize(process_image(std::process::id()).unwrap()).unwrap(),
        fs::canonicalize(std::env::current_exe().unwrap()).unwrap(),
    );
}

#[test]
fn audio_modes_select_explicit_evidence_backends() {
    use clap::Parser;
    for (extra, expected) in [
        (vec!["--audio-check"], audio_check::Mode::Duplex),
        (
            vec!["--audio-check", "playback"],
            audio_check::Mode::Playback,
        ),
        (vec!["--audio-check", "duplex"], audio_check::Mode::Duplex),
    ] {
        let args: Vec<_> = ["xtask", "boot", "run", "--output", "/tmp/run"]
            .into_iter()
            .chain(extra)
            .collect();
        let cli = crate::Cli::try_parse_from(args).unwrap();
        let crate::Task::Boot(Command::Run(run)) = cli.task else {
            panic!("boot run");
        };
        assert_eq!(run.audio_check, Some(expected));
    }
}

#[test]
fn network_models_select_only_implemented_pci_drivers() {
    use clap::Parser;
    for (argument, expected) in [
        ("virtio", NetworkModel::Virtio),
        ("e1000e", NetworkModel::E1000e),
        ("igb", NetworkModel::Igb),
    ] {
        let cli = crate::Cli::try_parse_from([
            "xtask",
            "boot",
            "run",
            "--output",
            "/tmp/run",
            "--network",
            "--network-model",
            argument,
            "--network-check",
            "http://localhost/check",
        ])
        .unwrap();
        let crate::Task::Boot(Command::Run(run)) = cli.task else {
            panic!("boot run");
        };
        assert_eq!(run.network_model, Some(expected));
    }
}

#[test]
fn storage_disks_pair_with_distinct_serials() {
    let file = std::env::current_exe().unwrap();
    let one = storage_disks(std::slice::from_ref(&file), &[]).unwrap();
    assert_eq!(one, [(file.clone(), "STELAANS".to_owned())]);
    let two = [file.clone(), file.clone()];
    let serials = ["TARGET".to_owned(), "SOURCE".to_owned()];
    assert_eq!(storage_disks(&two, &serials).unwrap()[1].1, "SOURCE");
    assert!(storage_disks(&two, &[]).is_err());
    assert!(storage_disks(&two, &["A".to_owned(), "A".to_owned()]).is_err());
    assert!(storage_disks(&[file.with_extension("missing")], &[]).is_err());
}

#[test]
fn option_paths_double_their_commas() {
    let path = std::path::Path::new("/tmp/bundles/Mac14,2/variables.fd");
    assert_eq!(option_path(path), "/tmp/bundles/Mac14,,2/variables.fd");
}

#[test]
fn storage_mdts_is_optional_typed_and_requires_a_disk() {
    use clap::Parser;
    let base = ["xtask", "boot", "run", "--output", "/tmp/run"];
    for value in ["1", "7", "9"] {
        let cli = crate::Cli::try_parse_from(base.into_iter().chain([
            "--storage-disk",
            "/tmp/disk.raw",
            "--storage-mdts",
            value,
        ]))
        .unwrap();
        let crate::Task::Boot(Command::Run(run)) = cli.task else {
            panic!("boot run");
        };
        assert_eq!(run.storage_mdts, Some(value.parse().unwrap()));
    }
    let cli =
        crate::Cli::try_parse_from(base.into_iter().chain(["--storage-disk", "/tmp/disk.raw"]))
            .unwrap();
    let crate::Task::Boot(Command::Run(run)) = cli.task else {
        panic!("boot run");
    };
    assert_eq!(run.storage_mdts, None);
    for extra in [
        vec!["--storage-mdts", "9"],
        vec!["--storage-disk", "/tmp/disk.raw", "--storage-mdts", "0"],
        vec!["--storage-disk", "/tmp/disk.raw", "--storage-mdts", "10"],
        vec!["--storage-disk", "/tmp/disk.raw", "--storage-mdts", "256"],
        vec!["--storage-disk", "/tmp/disk.raw", "--storage-mdts", "-1"],
        vec![
            "--storage-disk",
            "/tmp/disk.raw",
            "--storage-mdts",
            "11,serial=x",
        ],
    ] {
        assert!(crate::Cli::try_parse_from(base.into_iter().chain(extra)).is_err());
    }
}

#[test]
fn native_mmio_rejects_missing_corrupt_duplicate_and_late_mixed_inventory() {
    let mixed32 = "CHECK native-mixed32 PASS contexts=32 kernel=21 rust=11 raw_bytes=1798144 payload_bytes=1785856 alignment_padding=12288 guards=all-roots holes=absent cache=WB retire=32-views raw=whole-boot-owned refusals=wrong-inventory+allocation-capacity; no C-current, Clock or provider grant";
    let stack = "CHECK native-stack finite=4 actual_rsp=0x9000,0xa000 source=retired parent=clear+TLB; no Linux owner or CPU-time grant";
    let mmio = "CHECK native-mmio PASS authority=actual roots=all native_cpus=1 effective_cache=Intel-UC aperture=owned-PTE map=published retire=actual-clear+TLB reuse=readback foreign-root=refused WC=refused clock=HPET64 retained_hpet=1 root_lifetime=kernel-image ioapics=1 MCFG=0xb0000000 buses=0..=0 vendor=0x12378086; bounded authored diagnostic, Linux and physical hardware unqualified";
    let full = format!("{mixed32}\n{stack}\n{mmio}");
    assert_eq!(native_mmio_observation(&full), Some(mmio));
    assert_eq!(native_mixed32_observation(&full), Some(mixed32));
    for serial in [
        format!("{stack}\n{mmio}"),
        format!("{mixed32}\n{mixed32}\n{stack}\n{mmio}"),
        format!("{stack}\n{mixed32}\n{mmio}"),
        format!("{stack}\n{mmio}\n{mixed32}"),
        format!("{mixed32}\n{mmio}\n{stack}"),
        format!("{full}\nCHECK native-mixed32 FAIL guards"),
        format!("{full}\nCHECK native-mixed32"),
        format!("{full}\nCHECK native-mixed32 PASS contexts=32"),
    ] {
        assert!(native_mmio_observation(&serial).is_none(), "{serial}");
    }
    for field in mixed32.split_ascii_whitespace().skip(2) {
        let missing = mixed32.replace(field, "");
        assert!(
            native_mmio_observation(&format!("{missing}\n{stack}\n{mmio}")).is_none(),
            "missing {field}"
        );
        let corrupt = mixed32.replace(field, "unproved");
        assert!(
            native_mmio_observation(&format!("{corrupt}\n{stack}\n{mmio}")).is_none(),
            "corrupt {field}"
        );
        let repeated = mixed32.replace(field, &format!("{field} {field}"));
        assert!(
            native_mmio_observation(&format!("{repeated}\n{stack}\n{mmio}")).is_none(),
            "duplicate {field}"
        );
    }
    for old in [
        "contexts=16",
        "kernel=10",
        "raw_bytes=1798143",
        "payload_bytes=1785855",
        "alignment_padding=12287",
        "retire=31-views",
    ] {
        let (key, _) = old.split_once('=').unwrap();
        let before = mixed32
            .split_ascii_whitespace()
            .find(|field| field.starts_with(&format!("{key}=")))
            .unwrap();
        let serial = full.replace(before, old);
        assert!(native_mmio_observation(&serial).is_none(), "{old}");
    }
}
