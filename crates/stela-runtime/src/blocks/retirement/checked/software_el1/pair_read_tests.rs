//! Same factory/engine native LDP cases; no fixture-created execution key or loan.
use super::platform_tests::{capture_machine_before, capture_report_after};
use super::*;
use crate::memory::domain::m0_read::pair_read_fixtures::{self, ReadOutcome};
use crate::system::state::El1Registers;
#[test]
#[ignore = "actual current original-owner pair loads; fresh ignored output and root-reviewed producer required"]
fn actual_pair_reads_full_state_ram_and_reached_refusals_through_same_factory() {
    let output = PathBuf::from(
        std::env::var_os("STELA_EL1_PAIR_READ_NATIVE_OUTPUT").expect("fresh absolute output"),
    );
    assert!(output.is_absolute());
    std::fs::create_dir(&output).unwrap();
    for case in pair_read_fixtures::cases() {
        let out = output.join(case.name);
        std::fs::create_dir(&out).unwrap();
        let system = SystemState::new(
            pair_read_fixtures::PSTATE_LOW32 & !0xf000_0000,
            pair_read_fixtures::SP_EL0,
            El1Registers::new(1, 2, 3, 4, 0),
        )
        .unwrap();
        let before_system = system.clone();
        let machine = SoftwareEl1Machine::from_materialized(
            SoftwareEl1Profile::PlatformV1,
            out.join("cache"),
            ThreadState {
                pc: pair_read_fixtures::SOURCE_PC,
                registers: case.before(),
            },
            system,
            RegisterValues {
                sctlr_el1: 0,
                tcr_el1: 0,
                ttbr0_el1: 0,
                ttbr1_el1: 0,
                mair_el1: 0,
            },
            stela_compiler::TargetCpu::Baseline,
            case.materialize(102).unwrap(),
        )
        .unwrap();
        capture_machine_before(&out, &machine);
        std::fs::write(out.join("source.bin"), case.source()).unwrap();
        std::fs::write(out.join("expected-ram.bin"), case.expected_ram()).unwrap();
        let result = machine.run_to_shutdown(SoftwareEl1Request {
            stop_pc: (case.outcome == ReadOutcome::Complete).then(|| case.expected_pc()),
            block_budget: 2,
        });
        let report = match result {
            Ok(report) => report,
            Err(error) => {
                std::fs::write(out.join("actual-factory-error.txt"), format!("{error:#}")).unwrap();
                panic!("{} actual factory failed: {error:#}", case.name);
            }
        };
        capture_report_after(&out, &report);
        // Every raw available byte and actual typed error/producer was saved above.
        case.assert_progress(
            report
                .pair_read_progress_observation
                .expect("actual reached preparation/read prefix"),
        );
        assert_eq!(
            report.thread.registers,
            case.expected_state(),
            "{}",
            case.name
        );
        assert_eq!(report.thread.pc, case.expected_pc(), "{}", case.name);
        assert_eq!(report.system, before_system, "{}", case.name);
        assert_eq!(
            report.accounting.blocks_executed,
            usize::from(case.outcome == ReadOutcome::Complete),
            "{}",
            case.name
        );
        assert_eq!(
            report.translation_before, report.translation,
            "{} actual controls",
            case.name
        );
        if case.outcome == ReadOutcome::Complete {
            assert_eq!(report.stop, "StopAddress");
        } else {
            assert!(
                report.stop.starts_with("Indeterminate"),
                "{} {}",
                case.name,
                report.stop
            );
        }
        if case.outcome == ReadOutcome::Complete || case.completed_bytes != 0 {
            let producer = report
                .pair_read_producer_observation
                .as_ref()
                .expect("actual native producer required");
            assert_eq!(producer["same_original_outer"], true);
            assert_eq!(producer["actual_address_space"], 102);
            assert_eq!(producer["source_pc"], pair_read_fixtures::SOURCE_PC.0);
            assert!(producer["source_generation"].is_u64());
            let ids = producer["actual_identification_mmfr2_isar3"]
                .as_array()
                .expect("actual retained ID readbacks");
            assert_eq!((ids[0].as_u64().unwrap() >> 32) & 0xf, 0);
            assert_eq!(ids[1].as_u64().unwrap() & 0xf, 0);
        }
        for range in &report.ram {
            let actual = range
                .captured_bytes
                .as_ref()
                .expect("real original source diagnostic snapshot");
            let before = std::fs::read(out.join(format!(
                "before-ram-{:x}-{}.bin",
                range.source_pa, range.bytes
            )))
            .unwrap();
            assert_eq!(actual, &before, "{} unchanged original RAM", case.name);
            assert_eq!(range.sha256.as_ref().unwrap(), &stela_core::sha256(&before));
        }
    }
}

fn refusal_machine(case: &pair_read_fixtures::ReadCase, cache: PathBuf) -> SoftwareEl1Machine {
    SoftwareEl1Machine::from_materialized(
        SoftwareEl1Profile::PlatformV1,
        cache,
        ThreadState {
            pc: pair_read_fixtures::SOURCE_PC,
            registers: case.before(),
        },
        SystemState::new(
            pair_read_fixtures::PSTATE_LOW32 & !0xf000_0000,
            pair_read_fixtures::SP_EL0,
            El1Registers::new(1, 2, 3, 4, 0),
        )
        .unwrap(),
        RegisterValues {
            sctlr_el1: 0,
            tcr_el1: 0,
            ttbr0_el1: 0,
            ttbr1_el1: 0,
            mair_el1: 0,
        },
        stela_compiler::TargetCpu::Baseline,
        case.materialize(102).unwrap(),
    )
    .unwrap()
}

#[test]
#[ignore = "actual original-owner currency/order refusal rows; fresh output and reviewed producer required"]
fn actual_pair_read_owner_order_and_generation_refusals_keep_original_bank() {
    use super::super::m0::PairReadFixture;
    let output = PathBuf::from(
        std::env::var_os("STELA_EL1_PAIR_READ_REFUSAL_OUTPUT").expect("fresh absolute output"),
    );
    assert!(output.is_absolute());
    std::fs::create_dir(&output).unwrap();
    let case = pair_read_fixtures::cases()[2]; // Post-index: no base writeback on any refusal.
    assert_eq!(case.outcome, ReadOutcome::Complete);
    for name in [
        "original_order_busy",
        "different_same_domain_outer",
        "foreign_same_number_domain_outer",
        "generation_before_invoke",
        "generation_after_invoke",
    ] {
        let out = output.join(name);
        std::fs::create_dir(&out).unwrap();
        let mut machine = refusal_machine(&case, out.join("cache"));
        let before_system = machine.system.clone();
        let before_registers = machine.thread.registers.clone();
        // Capture before acquiring any fixture exclusion loan.
        capture_machine_before(&out, &machine);
        std::fs::write(out.join("source.bin"), case.source()).unwrap();
        let mut foreign_machine = None;
        match name {
            "original_order_busy" => machine.hold_pair_read_order = true,
            "different_same_domain_outer" => {
                // A second real counted loan has the same domain, but is NOT
                // the exact canonical Active outer object. No loan is forged.
                machine.pair_read_fixture = Some(PairReadFixture::DifferentOuter(
                    machine.memory.execution_loan().unwrap(),
                ));
            }
            "foreign_same_number_domain_outer" => {
                let foreign = refusal_machine(&case, out.join("foreign-unused-cache"));
                assert_eq!(foreign.address_space, machine.address_space);
                let loan = foreign.memory.execution_loan().unwrap();
                machine.pair_read_fixture = Some(PairReadFixture::DifferentOuter(loan));
                // Keep the unrelated actual materialization owner alive. It
                // never creates a PE or enters translated code.
                foreign_machine = Some(foreign);
            }
            "generation_before_invoke" => {
                machine.pair_read_fixture = Some(PairReadFixture::GenerationBeforeInvoke);
            }
            "generation_after_invoke" => {
                machine.pair_read_fixture = Some(PairReadFixture::GenerationAfterInvoke);
            }
            _ => unreachable!(),
        }
        let report = machine
            .run_to_shutdown(SoftwareEl1Request {
                stop_pc: Some(case.expected_pc()),
                block_budget: 1,
            })
            .unwrap_or_else(|error| {
                std::fs::write(out.join("actual-factory-error.txt"), format!("{error:#}")).unwrap();
                panic!("{name}: actual factory failed: {error:#}")
            });
        capture_report_after(&out, &report);
        drop(foreign_machine);
        assert!(
            report.stop.starts_with("Indeterminate"),
            "{name}: {}",
            report.stop
        );
        assert_eq!(
            report.thread.registers, before_registers,
            "{name}: original full bank"
        );
        assert_eq!(
            report.thread.pc,
            pair_read_fixtures::SOURCE_PC,
            "{name}: original PC"
        );
        assert_eq!(report.system, before_system, "{name}: original System");
        assert_eq!(
            report.translation_before, report.translation,
            "{name}: original controls"
        );
        assert_eq!(
            report.accounting.blocks_executed, 0,
            "{name}: no retirement"
        );
        let observation = report.memory_pair_read_observation.as_deref().unwrap_or("");
        if name == "foreign_same_number_domain_outer" {
            assert!(report.pair_read_progress_observation.is_none());
            assert!(report.pair_read_producer_observation.is_none());
        } else {
            let progress = report
                .pair_read_progress_observation
                .expect("actual preparation/invocation prefix");
            assert_eq!(
                progress.completed_bytes,
                if name == "generation_after_invoke" {
                    16
                } else {
                    0
                }
            );
            assert!(progress.uncertain_member.is_none());
            if name == "original_order_busy" {
                assert!(observation.contains("DeviceOrdering"), "{observation}");
                assert!(!progress.attempted);
                assert!(report.pair_read_producer_observation.is_none());
            } else if name == "different_same_domain_outer" {
                assert!(
                    observation.contains("DifferentExecutionLoan"),
                    "{observation}"
                );
                assert!(!progress.attempted);
                assert!(report.pair_read_producer_observation.is_none());
            } else {
                let producer = report
                    .pair_read_producer_observation
                    .as_ref()
                    .expect("actual retained producer");
                assert_eq!(producer["same_original_outer"], true);
                assert_eq!(producer["actual_address_space"], 102);
                assert_eq!(producer["source_pc"], pair_read_fixtures::SOURCE_PC.0);
                assert!(
                    observation.contains("SourceControl") || observation.contains("Physical"),
                    "{observation}"
                );
            }
        }
        for range in &report.ram {
            if name.starts_with("generation_") {
                // The real original binding now refuses stale-generation raw
                // observation. Save that exact error; never restore generation
                // or substitute expected bytes to manufacture an after image.
                assert!(range.captured_bytes.is_err());
                assert!(range.sha256.is_err());
                assert!(
                    out.join(format!(
                        "actual-ram-{:x}-{}.error.txt",
                        range.source_pa, range.bytes
                    ))
                    .is_file()
                );
            } else {
                let before = std::fs::read(out.join(format!(
                    "before-ram-{:x}-{}.bin",
                    range.source_pa, range.bytes
                )))
                .unwrap();
                assert_eq!(
                    range.captured_bytes.as_ref().unwrap(),
                    &before,
                    "{name}: unchanged RAM"
                );
            }
        }
    }
}
