//! WFx, SEVL, counters and IRQ delivery on the hosted-wait machine.
use super::*;
use crate::system::{
    events::{Outcome, RetireReason},
    state::{El1Registers, PSTATE_EL1H},
};
const SOURCE_PA: u64 = 0x100000;
const VECTOR_BASE: u64 = 0x8000;
const WFE: u32 = 0xd503_205f;
const WFI: u32 = 0xd503_207f;
const WFIT_X0: u32 = 0xd503_1020;
const WFIT_XZR: u32 = 0xd503_103f;
const NOP: u32 = 0xd503_201f;
const MRS_CNTFRQ_X1: u32 = 0xd53b_e001;
const MRS_CNTPCT_X2: u32 = 0xd53b_e022;
const MRS_CNTVCT_X3: u32 = 0xd53b_e043;
const MRS_CNTVCT_XZR: u32 = 0xd53b_e05f;
const ADD_X0_X3_TIMEOUT_512_LSL12: u32 = 0x9148_0060;
const DEADLINE_DELTA: u64 = 512 << 12;

fn machine(cache: PathBuf, words: &[u32]) -> SoftwareEl1Machine {
    super::platform::machine_with_profile(
        cache,
        words,
        VECTOR_BASE,
        SoftwareEl1Profile::HostedWaitV1,
    )
}
fn request(stop_pc: u64, budget: usize) -> SoftwareEl1Request {
    SoftwareEl1Request {
        stop_pc: Some(GuestAddress(stop_pc)),
        block_budget: budget,
    }
}

#[test]
fn native_wfe_factory_consumes_event_once() {
    let cache = tempfile::tempdir().unwrap();
    let machine = machine(cache.path().to_owned(), &[WFE, NOP]);
    let before = machine.thread.registers.clone();
    assert!(machine.endpoint.producer().signal_local());
    let report = machine.run_to_shutdown(request(SOURCE_PA + 4, 1)).unwrap();
    assert_eq!(report.stop, "StopAddress");
    assert_eq!(report.thread.pc, GuestAddress(SOURCE_PA + 4));
    assert_eq!(report.thread.registers, before);
    assert_eq!(
        report.wait_observation,
        Some(Outcome::Retired {
            next_pc: SOURCE_PA + 4,
            reason: RetireReason::EventConsumed,
        })
    );
    assert_eq!(report.accounting.blocks_executed, 1);
    assert!(
        report
            .system_observation
            .as_deref()
            .unwrap()
            .contains("applied: true")
    );
}

#[test]
fn native_masked_wfi_uses_registered_irq_and_keeps_mask() {
    let cache = tempfile::tempdir().unwrap();
    let mut machine = machine(cache.path().to_owned(), &[WFI, NOP]);
    let before = machine.thread.registers.clone();
    let irq = machine.take_hosted_irq().unwrap();
    irq.assert().unwrap();
    assert!(machine.take_hosted_irq().is_err());
    let report = machine.run_to_shutdown(request(SOURCE_PA + 4, 1)).unwrap();
    assert_eq!(report.stop, "StopAddress");
    assert_eq!(report.thread.pc, GuestAddress(SOURCE_PA + 4));
    assert_eq!(report.thread.registers, before);
    assert!(crate::system::exception::irq_masked(&report.system));
    assert_eq!(
        report.wait_observation,
        Some(Outcome::Retired {
            next_pc: SOURCE_PA + 4,
            reason: RetireReason::InterruptPending,
        })
    );
    assert_eq!(report.accounting.blocks_executed, 1);
    assert!(report.interrupt_observation.is_none());
}

#[test]
fn guest_counter_reads_supply_wfit_deadline_in_same_epoch() {
    let cache = tempfile::tempdir().unwrap();
    let machine = machine(
        cache.path().to_owned(),
        &[
            MRS_CNTFRQ_X1,
            MRS_CNTPCT_X2,
            MRS_CNTVCT_X3,
            ADD_X0_X3_TIMEOUT_512_LSL12,
            WFIT_X0,
            MRS_CNTVCT_XZR,
            WFIT_XZR,
            NOP,
        ],
    );
    let mut expected = machine.thread.registers.clone();
    let report = machine
        .run_to_shutdown(request(SOURCE_PA + 7 * 4, 7))
        .unwrap();
    assert_eq!(report.stop, "StopAddress");
    assert_eq!(report.thread.pc, GuestAddress(SOURCE_PA + 7 * 4));
    assert_eq!(
        report.thread.registers.x[1],
        crate::system::events::hosted::HOSTED_COUNTER_FREQUENCY
    );
    assert!(report.thread.registers.x[3] >= report.thread.registers.x[2]);
    assert_eq!(
        report.thread.registers.x[0],
        report.thread.registers.x[3] + DEADLINE_DELTA
    );
    expected.x[..4].copy_from_slice(&report.thread.registers.x[..4]);
    assert_eq!(report.thread.registers, expected);
    assert_eq!(
        report.wait_observation,
        Some(Outcome::Retired {
            next_pc: SOURCE_PA + 7 * 4,
            reason: RetireReason::DeadlineExpired,
        })
    );
    assert_eq!(report.accounting.blocks_executed, 7);
}

#[test]
fn fixed_no_source_factory_refuses_wait_before_native_execution() {
    let cache = tempfile::tempdir().unwrap();
    let machine = super::platform::machine_with_profile(
        cache.path().to_owned(),
        &[WFI, NOP],
        VECTOR_BASE,
        SoftwareEl1Profile::PlatformV1,
    );
    let report = machine.run_to_shutdown(request(SOURCE_PA + 4, 1)).unwrap();
    assert!(
        report
            .stop
            .contains("fixed no-source platform has no hosted wait resources")
    );
    assert_eq!(report.thread.pc, GuestAddress(SOURCE_PA));
    assert_eq!(report.accounting.blocks_executed, 0);
    assert!(report.system_observation.is_none());
}

#[test]
fn daif_unmask_arbitrates_retained_irq_before_next_source_fetch() {
    // DAIFClr #2 clears only I. The IRQ stayed pending after the masked WFI,
    // so it is taken before the next instruction is fetched.
    const DAIF_CLEAR_I: u32 = 0xd503_42ff;
    const SAME_EL_SPX_IRQ_VECTOR: u64 = 0x280;
    const PSTATE_I_MASK: u64 = 1 << 7;
    let cache = tempfile::tempdir().unwrap();
    let mut machine = machine(cache.path().to_owned(), &[WFI, DAIF_CLEAR_I, NOP]);
    let before = machine.thread.registers.clone();
    let irq = machine.take_hosted_irq().unwrap();
    irq.assert().unwrap();
    let report = machine
        .run_to_shutdown(request(SAME_EL_SPX_IRQ_VECTOR, 2))
        .unwrap();
    assert_eq!(report.stop, "StopAddress");
    assert_eq!(report.thread.pc, GuestAddress(SAME_EL_SPX_IRQ_VECTOR));
    assert_eq!(report.thread.registers, before);
    assert_eq!(report.system.el1_registers().elr(), SOURCE_PA + 8);
    assert_eq!(report.system.el1_registers().spsr() & PSTATE_I_MASK, 0);
    assert!(crate::system::exception::irq_masked(&report.system));
    assert_eq!(report.accounting.blocks_executed, 2);
    assert!(report.interrupt_observation.is_some());
}

#[test]
fn initially_unmasked_pending_irq_refuses_context_before_native() {
    const ISB_SY: u32 = 0xd503_3fdf;
    const MSR_SCTLR_X1: u32 = 0xd518_1001;
    const PSTATE_I_MASK: u64 = 1 << 7;
    for word in [ISB_SY, MSR_SCTLR_X1] {
        let cache = tempfile::tempdir().unwrap();
        let mut machine = machine(cache.path().to_owned(), &[word, NOP]);
        machine
            .system
            .write_daif(crate::system::pstate::DAIF_MASK & !PSTATE_I_MASK);
        machine.thread.registers.x[1] = 0;
        let before = machine.thread.registers.clone();
        let system = machine.system.clone();
        let irq = machine.take_hosted_irq().unwrap();
        irq.assert().unwrap();
        let report = machine.run_to_shutdown(request(SOURCE_PA + 4, 1)).unwrap();
        assert_eq!(
            report.stop,
            "EntryDeclined(\"hosted boundary: InterruptArbitrationRequired\")"
        );
        assert_eq!(report.thread.pc, GuestAddress(SOURCE_PA));
        assert_eq!(report.thread.registers, before);
        assert_eq!(report.system, system);
        assert_eq!(report.accounting.blocks_executed, 0);
        assert!(report.context_observation.is_none());
        assert!(report.interrupt_observation.is_none());
    }
}

#[test]
fn native_wfet_xzr_checks_initial_event_before_expired_deadline() {
    const WFET_XZR: u32 = 0xd503_101f;
    for (event_set, reason) in [
        (false, RetireReason::DeadlineExpired),
        (true, RetireReason::EventConsumed),
    ] {
        let cache = tempfile::tempdir().unwrap();
        let machine = machine(cache.path().to_owned(), &[WFET_XZR, NOP]);
        let before = machine.thread.registers.clone();
        if event_set {
            assert!(machine.endpoint.producer().signal_local());
        }
        let report = machine.run_to_shutdown(request(SOURCE_PA + 4, 1)).unwrap();
        assert_eq!(report.stop, "StopAddress");
        assert_eq!(report.thread.pc, GuestAddress(SOURCE_PA + 4));
        assert_eq!(report.thread.registers, before);
        assert_eq!(report.accounting.blocks_executed, 1);
        assert_eq!(
            report.wait_observation,
            Some(Outcome::Retired {
                next_pc: SOURCE_PA + 4,
                reason,
            })
        );
    }
}

#[test]
fn native_sevl_prefix_publishes_same_owner_event_before_wfe() {
    const SEVL: u32 = 0xd503_20bf;
    let cache = tempfile::tempdir().unwrap();
    let machine = machine(cache.path().to_owned(), &[SEVL, WFE, NOP]);
    let before = machine.thread.registers.clone();
    let before_system = machine.system.clone();
    let report = machine.run_to_shutdown(request(SOURCE_PA + 8, 2)).unwrap();
    assert_eq!(report.stop, "StopAddress");
    assert_eq!(report.thread.pc, GuestAddress(SOURCE_PA + 8));
    assert_eq!(report.accounting.blocks_executed, 2);
    assert_eq!(report.thread.registers, before);
    assert_eq!(report.system, before_system);
    assert!(report.interrupt_observation.is_none());
    assert_eq!(
        report.wait_observation,
        Some(Outcome::Retired {
            next_pc: SOURCE_PA + 8,
            reason: RetireReason::EventConsumed,
        })
    );
}

/// While WFIT is parked, the PE releases its domain exclusion so a host
/// service can publish RAM and raise the IRQ that wakes it; the resumed
/// literal load then observes the published bytes.
#[test]
fn wait_releases_domain_for_host_service_and_resumed_load_sees_publication() {
    const DATA_PA: u64 = 0x102000;
    const DATA_BYTES: usize = 16;
    const ONE_SECOND_TICKS: u64 = 1_000_000_000;
    const PUBLISHED: u64 = 0x0123_4567_89ab_cdef;
    const MRS_CNTVCT_X3: u32 = 0xd53b_e043;
    const MOVZ_X4_ONE_SECOND_HI: u32 = 0xd2a7_7344;
    const MOVK_X4_ONE_SECOND_LO: u32 = 0xf299_4004;
    const ADD_X0_X3_X4: u32 = 0x8b04_0060;
    const LDR_X1_DATA: u32 = 0x5800_ff61;
    // MRS, MOVZ, MOVK, ADD, WFIT and the resumed literal each run one block.
    const RETIRED: usize = 6;
    const WAIT_NEXT_PC: u64 = SOURCE_PA + 5 * size_of::<u32>() as u64;
    fn assert_send<T: Send>() {}
    assert_send::<HostedRamService>();
    let cache = tempfile::tempdir().unwrap();
    let source: Vec<_> = [
        MRS_CNTVCT_X3,
        MOVZ_X4_ONE_SECOND_HI,
        MOVK_X4_ONE_SECOND_LO,
        ADD_X0_X3_X4,
        WFIT_X0,
        LDR_X1_DATA,
        NOP,
    ]
    .into_iter()
    .flat_map(u32::to_le_bytes)
    .collect();
    let mut registers = stela_compiler::GuestState {
        sp: 0x2f0000,
        nzcv: 0xa0000000,
        reserved: 0xdec0de00,
        ..Default::default()
    };
    for (index, register) in registers.x.iter_mut().enumerate() {
        *register = 0x1111_0000_0000_0000 | index as u64;
    }
    let before = registers.clone();
    let system = SystemState::new(
        PSTATE_EL1H | crate::system::pstate::DAIF_MASK,
        0x2e0000,
        El1Registers::new(1, 2, 3, 4, VECTOR_BASE),
    )
    .unwrap();
    let before_system = system.clone();
    let executable = SourceRamPermissions {
        readable: true,
        writable: false,
        executable: true,
    };
    let data = SourceRamPermissions {
        readable: true,
        writable: true,
        executable: false,
    };
    let mut machine = SoftwareEl1Machine::new(SoftwareEl1Config {
        profile: SoftwareEl1Profile::HostedWaitV1,
        cache_directory: cache.path().to_owned(),
        ram: SourceRamDeclaration {
            address_space: 392,
            target: stela_compiler::TargetCpu::Baseline,
            declared_capacity: vec![PhysicalRamRange {
                source_pa: SOURCE_PA,
                bytes: 0x10000,
            }],
            initialized: vec![
                OwnedRamExtent {
                    source_pa: SOURCE_PA,
                    bytes: source.clone(),
                    permissions: executable,
                },
                OwnedRamExtent {
                    source_pa: DATA_PA,
                    bytes: vec![0; DATA_BYTES],
                    permissions: data,
                },
            ],
        },
        thread: ThreadState {
            pc: GuestAddress(SOURCE_PA),
            registers,
        },
        system,
        translation: RegisterValues {
            sctlr_el1: 0,
            tcr_el1: 0,
            ttbr0_el1: 0,
            ttbr1_el1: 0,
            mair_el1: 0,
        },
    })
    .unwrap();
    let mut service = machine
        .take_hosted_ram_service(DATA_PA, DATA_BYTES)
        .unwrap();
    assert!(machine.take_hosted_irq().is_err());
    // The service can only publish while the PE holds no execution loan, so
    // it succeeds before the PE starts or once WFIT has parked. Either way
    // the IRQ is pending by the time WFIT checks it.
    let worker = std::thread::spawn(move || -> anyhow::Result<u64> {
        loop {
            match service.try_publish_then_assert(0, &PUBLISHED.to_le_bytes())? {
                HostedRamServiceAttempt::Published { irq_sequence } => return Ok(irq_sequence),
                HostedRamServiceAttempt::ExecutionBusy | HostedRamServiceAttempt::ServiceBusy => {
                    std::thread::sleep(core::time::Duration::from_millis(1));
                }
            }
        }
    });
    let report = machine
        .run_to_shutdown(request(
            SOURCE_PA + (RETIRED * size_of::<u32>()) as u64,
            RETIRED,
        ))
        .unwrap();
    assert_ne!(worker.join().unwrap().unwrap(), 0);
    assert_eq!(report.stop, "StopAddress");
    assert_eq!(report.accounting.blocks_executed, RETIRED);
    let mut expected = before;
    expected.x[0] = report.thread.registers.x[3] + ONE_SECOND_TICKS;
    expected.x[1] = PUBLISHED;
    expected.x[3] = report.thread.registers.x[3];
    expected.x[4] = ONE_SECOND_TICKS;
    assert_eq!(report.thread.registers, expected);
    assert_eq!(report.system, before_system);
    assert!(report.interrupt_observation.is_none());
    assert_eq!(
        report.wait_observation,
        Some(Outcome::Retired {
            next_pc: WAIT_NEXT_PC,
            reason: RetireReason::InterruptPending,
        })
    );
    let mut expected_data = vec![0; DATA_BYTES];
    expected_data[..size_of::<u64>()].copy_from_slice(&PUBLISHED.to_le_bytes());
    let digest = |source_pa| {
        report
            .ram
            .iter()
            .find(|range| range.source_pa == source_pa)
            .unwrap()
            .sha256
            .clone()
    };
    assert_eq!(digest(DATA_PA), Ok(crate::sha256(&expected_data)));
    assert_eq!(digest(SOURCE_PA), Ok(crate::sha256(&source)));
}
