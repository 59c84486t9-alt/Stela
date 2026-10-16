// Tests of the software privileged PE.
use super::*;
use crate::{
    blocks::{
        ThreadState,
        retirement::{
            checked::{OwnedRunRequest, OwnedStop, accept_retained_loan},
            software_async::SoftwareAsyncDomain,
        },
    },
    memory::{
        domain::{MemorySystem, MemoryThread},
        policy::{LowerAddressProfile, TagCheckFaultMode},
    },
    system::{
        debug::halted::{
            ExtendedHaltSyndrome, ExternalControls, Initialization as DebugInitialization, Status,
        },
        execution::owner::SystemExecutionOwner,
        identification::Register,
        state::{
            El1Registers, PSTATE_EL1T, StackBank,
            higher_el::{El2Initialization, El3Initialization, Initialization},
        },
    },
};
use stela_compiler::TargetCpu;
const PC: GuestAddress = GuestAddress(0x1000);
const ITE: u32 = 1 << 24;
const HDE: u32 = 1 << 14;
fn ids(higher: bool) -> Arc<Snapshot> {
    Arc::new(
        Snapshot::declared(
            "privileged-actual-owner-software-model",
            &[
                (Register::IdAa64Pfr0El1, if higher { 0x1111 } else { 0x11 }),
                (Register::IdAa64Pfr1El1, 0),
                (Register::IdAa64Pfr2El1, 0),
                (Register::IdAa64Dfr0El1, 9),
                (Register::IdAa64Dfr1El1, 0),
                (Register::IdAa64Mmfr0El1, 0),
                (Register::IdAa64Mmfr1El1, 0),
                (Register::IdAa64Mmfr2El1, 0),
                (Register::IdAa64Mmfr4El1, 0),
                (Register::IdAa64Isar1El1, 0),
                (Register::IdAa64Isar2El1, 0),
            ],
        )
        .unwrap(),
    )
}
fn system(ids: Arc<Snapshot>, higher: bool, saved: u64) -> SystemState {
    let el1 = El1Registers::new(1, saved, 3, 4, 0x6000);
    if !higher {
        return SystemState::new(PSTATE_EL1H, 0x1110, el1).unwrap();
    }
    SystemState::new_with_higher_el(
        PSTATE_EL1H,
        0x1110,
        el1,
        ids,
        Initialization {
            el2: Some(El2Initialization {
                exception: El1Registers::new(21, 22, 23, 24, 0x8000),
                stack_pointer: 0x3330,
                hcr: 0,
                sctlr: 0,
                tcr: 0,
                hpfar: 26,
            }),
            el3: Some(El3Initialization {
                exception: El1Registers::new(31, 32, 33, 34, 0xa000),
                stack_pointer: 0x4440,
                scr: SCR_NS | SCR_HCE,
                sctlr: 0,
                tcr: 0,
            }),
        },
    )
    .unwrap()
}
fn debug(ids: Arc<Snapshot>, status: Status) -> DebugMachine {
    DebugMachine::fresh_declared(
        ids,
        DebugInitialization {
            edscr: status as u32 | ITE | HDE,
            edprsr: if status.halted() { 1 << 4 } else { 0 },
            dlr: 0x7770,
            dspsr: 0x8880,
            edesr: 0,
            edecr: 0,
            mdscr_el1: 0,
            should_advance_ss: true,
            should_advance_hs: true,
            external: ExternalControls {
                powered: true,
                double_locked: false,
                software_locked: false,
                nonsecure_invasive: true,
                secure_invasive: true,
            },
            extended_halt_syndrome: ExtendedHaltSyndrome::DeclaredAbsent,
        },
    )
    .unwrap()
}
fn memory() -> (Arc<MemoryDomain>, MemoryThread<MemoryControls>) {
    let domain = MemoryDomain::new_for_address_space(
        7,
        MemorySystem::new(16, 8).unwrap(),
        vec![],
        TargetCpu::Baseline,
    )
    .unwrap();
    let thread = domain.thread(MemoryControls::new(
        LowerAddressProfile::new(48, false).unwrap(),
        true,
        false,
        false,
        TagCheckFaultMode::Ignore,
        false,
    ));
    (domain, thread)
}
macro_rules! machine {
    ($ids:ident, $system:ident, $thread:ident, $status:expr, |$pe:ident| $body:block) => {{
        let (domain, mut memory) = memory();
        let mut producers = unsafe { SoftwareAsyncDomain::fresh_software_pe() };
        let keys = [producers.register_debug().unwrap()];
        let lease = producers.lease_debug_sources(&keys).unwrap();
        let mut backend = unsafe {
            PrivilegedOwner::fresh_software(
                7,
                LowerElControls {
                    snapshot: Arc::clone(&$ids),
                    sctlr_el1: 0,
                    tcr_el1: 0,
                    call_implementation: higher_el::Implementation {
                        without_el3_security: higher_el::WithoutEl3Security::NonSecureOnly,
                        trap_smc_without_el3: higher_el::TrapSmcWithoutEl3::Enabled,
                    },
                },
                &mut memory,
                domain,
                lease,
                CtiRoute {
                    output_slot: 0,
                    target_slots: vec![],
                },
                None,
            )
            .unwrap()
        };
        let mut $pe = unsafe {
            SystemExecutionOwner::new_pe_with_debug(
                &mut $thread,
                &mut $system,
                &mut backend,
                debug(Arc::clone(&$ids), $status),
            )
            .unwrap()
        };
        $body
    }};
}
fn thread() -> ThreadState {
    let mut registers = GuestState {
        sp: 0x2220,
        nzcv: 0xa0000000,
        fpcr: 1 << 22,
        fpsr: (1 << 27) | 0x1f,
        ..GuestState::default()
    };
    for (i, x) in registers.x.iter_mut().enumerate() {
        *x = 0x0123456789abcdefu64 ^ ((i as u64) << 48);
    }
    for (i, v) in registers.v.iter_mut().enumerate() {
        *v = [
            0x8877665544332211u64 ^ (i as u64),
            0xffeeddccbbaa9988u64 ^ ((i as u64) << 32),
        ];
    }
    ThreadState { registers, pc: PC }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn actual_hvc_smc_enter_original_banks_and_sp_once() {
    for (word, target, mode, sp, esr) in [
        (
            0xd4000002u32 | (0x1234 << 5),
            0x8400,
            PSTATE_EL2H,
            0x3330,
            (0x16 << 26) | (1 << 25) | 0x1234,
        ),
        (
            0xd4000003u32 | (0x5678 << 5),
            0xa400,
            PSTATE_EL3H,
            0x4440,
            (0x17 << 26) | (1 << 25) | 0x5678,
        ),
    ] {
        let ids = ids(true);
        let mut system = system(Arc::clone(&ids), true, 0);
        let mut thread = thread();
        let cache = tempfile::tempdir().unwrap();
        let mut runtime = crate::blocks::BlockRuntime::new_for_target(
            7,
            cache.path().to_owned(),
            BlockProfile::SystemV1,
            TargetCpu::Baseline,
        );
        runtime
            .register_code(PC, word.to_le_bytes().to_vec())
            .unwrap();
        runtime
            .register_code(GuestAddress(target), 0xd4400000u32.to_le_bytes().to_vec())
            .unwrap();
        machine!(ids, system, thread, Status::NonDebug, |pe| {
            let outcome = runtime.run_owned(
                pe.loan(),
                OwnedRunRequest {
                    stop_pc: Some(GuestAddress(target)),
                    block_budget: 1,
                },
            );
            assert!(matches!(outcome.stop, OwnedStop::StopAddress));
            assert_eq!(outcome.accounting.blocks_executed, 1);
            assert_eq!(pe.pc(), GuestAddress(target));
        });
        assert_eq!(system.pstate_misc(), mode | DAIF_MASK);
        assert_eq!(thread.registers.sp, sp);
        assert_eq!(thread.registers.nzcv, 0xa0000000);
        let bank = system.exception_registers(system.current_el()).unwrap();
        assert_eq!(bank.elr(), PC.0 + 4);
        assert_eq!(bank.spsr(), PSTATE_EL1H | 0xa0000000);
        assert_eq!(bank.esr(), esr);
        assert_eq!(
            system.read_stack_pointer(crate::system::state::StackBank::El1, &thread.registers),
            Ok(0x2220)
        );
    }
}
#[test]
#[cfg(target_arch = "x86_64")]
fn actual_hlt_stops_native_and_keeps_restart_pc() {
    let ids = ids(false);
    let mut system = system(Arc::clone(&ids), false, 0);
    let mut thread = thread();
    let cache = tempfile::tempdir().unwrap();
    let mut runtime = crate::blocks::BlockRuntime::new_for_target(
        7,
        cache.path().to_owned(),
        BlockProfile::SystemV1,
        TargetCpu::Baseline,
    );
    runtime
        .register_code(PC, 0xd4400000u32.to_le_bytes().to_vec())
        .unwrap();
    machine!(ids, system, thread, Status::NonDebug, |pe| {
        let outcome = runtime.run_owned(
            pe.loan(),
            OwnedRunRequest {
                stop_pc: None,
                block_budget: 1,
            },
        );
        assert!(matches!(
            outcome.stop,
            OwnedStop::Halted { instruction_pc: PC }
        ));
        assert_eq!(pe.pc(), PC);
        {
            let resources = accept_retained_loan(pe.loan());
            assert!(resources.authority.halted());
            assert!(!resources.authority.ready());
            let debug = resources.debug.as_ref().unwrap();
            assert_eq!(debug.status(), Status::HaltInstruction);
            assert_eq!(debug.dlr(), PC.0);
            assert_eq!(debug.dspsr(), PSTATE_EL1H | 0xa0000000);
        }
        let denied = runtime.run_owned(
            pe.loan(),
            OwnedRunRequest {
                stop_pc: None,
                block_budget: 1,
            },
        );
        assert!(matches!(denied.stop, OwnedStop::EntryDeclined(_)));
        assert_eq!(denied.accounting.blocks_executed, 0);
    });
}
#[test]
#[cfg(target_arch = "x86_64")]
fn actual_dcps_all_targets_stay_halted_and_preserve_pc() {
    for (word, el, sp) in [
        (0xd4a00001u32, ExceptionLevel::El1, 0x2220),
        (0xd4a00002, ExceptionLevel::El2, 0x3330),
        (0xd4a00003, ExceptionLevel::El3, 0x4440),
    ] {
        let ids = ids(true);
        let mut system = system(Arc::clone(&ids), true, 0);
        let mut thread = thread();
        machine!(ids, system, thread, Status::ResetCatch, |pe| {
            pe.queue_editr(0, word).unwrap();
            let outcome = pe.run_editr();
            assert!(matches!(
                outcome.stop,
                super::super::halted::DebugStop::Complete
            ));
            assert_eq!(outcome.actual_pc, PC);
            let resources = accept_retained_loan(pe.loan());
            assert!(resources.authority.halted());
            let debug = resources.debug.as_ref().unwrap();
            assert_eq!(debug.status(), Status::ResetCatch);
            assert_ne!(debug.edscr() & ITE, 0);
            assert_eq!(debug.dlr(), 0);
            assert_eq!(debug.dspsr(), 0);
        });
        assert_eq!(system.current_el(), el);
        assert_eq!(thread.registers.sp, sp);
        let bank = system.exception_registers(el).unwrap();
        assert_eq!((bank.elr(), bank.spsr(), bank.esr()), (0, 0, 0));
    }
}
#[test]
#[cfg(target_arch = "x86_64")]
fn actual_drps_restores_saved_sp_without_branch_or_resume() {
    let ids = ids(false);
    let mut system = system(Arc::clone(&ids), false, PSTATE_EL1T | NZCV_MASK | DAIF_MASK);
    let mut thread = thread();
    machine!(ids, system, thread, Status::ResetCatch, |pe| {
        pe.queue_editr(0, 0xd6bf03e0).unwrap();
        let outcome = pe.run_editr();
        assert!(matches!(
            outcome.stop,
            super::super::halted::DebugStop::Complete
        ));
        assert_eq!(outcome.actual_pc, PC);
        let resources = accept_retained_loan(pe.loan());
        assert!(resources.authority.halted());
        assert!(!resources.authority.ready());
    });
    assert_eq!(system.pstate_misc(), PSTATE_EL1T);
    assert_eq!(thread.registers.nzcv, 0);
    assert_eq!(thread.registers.sp, 0x1110);
    assert_eq!(
        system.read_stack_pointer(StackBank::El1, &thread.registers),
        Ok(0x2220)
    );
}

#[test]
#[cfg(target_arch = "x86_64")]
fn refused_debug_input_stays_queued_and_dropped_active_poison_stays_terminal() {
    let ids = ids(false);
    let mut system = system(Arc::clone(&ids), false, 0);
    let mut thread = thread();
    machine!(ids, system, thread, Status::ResetCatch, |pe| {
        pe.queue_editr(0, 0xd4a00002).unwrap(); // No original EL2 bank, so no fake DCPS2 success.
        let refused = pe.run_editr();
        assert!(matches!(
            refused.stop,
            super::super::halted::DebugStop::EntryDeclined(_)
        ));
        {
            let mut resources = accept_retained_loan(pe.loan());
            assert!(resources.backend.producers.next_editr().unwrap().is_some());
            assert!(resources.authority.halted());
            let outer = resources.backend.memory.execution_loan().unwrap();
            let attempt = resources
                .authority
                .begin_debug(&super::super::ConsumerKey(()))
                .unwrap();
            let active = super::super::Active {
                pe: &mut resources,
                outer: Some(outer),
                source_pin: None,
                attempt,
                closed: false,
            };
            drop(active);
            assert!(!resources.authority.halted());
            assert!(!resources.authority.ready());
        }
        assert!(matches!(
            pe.run_editr().stop,
            super::super::halted::DebugStop::EntryDeclined(_)
        ));
        assert_eq!(pe.pc(), PC);
    });
}

#[test]
#[cfg(target_arch = "x86_64")]
fn actual_halted_movt_480_literal_model_outputs_and_full_bank_preservation() {
    use crate::{
        scalable::ScalableState,
        system::scalable_controls::{Implementation, Readbacks, ScalableControlOwner},
    };
    use stela_compiler::{
        aarch64::scalable::{
            ScalableMode, VectorLength,
            features::{ScalableFeature, ScalableFeatures},
            profile::ScalableControls,
        },
        context::{ExecutionContext, memory::MemoryImplementationProfile},
        extended::ScalableProfile,
    };
    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect()
    }
    fn banks(state: &ScalableState, registers: &GuestState, sm: bool) -> Vec<u8> {
        let mut out = Vec::new();
        let mut za = vec![0; state.vector_length().bytes().pow(2)];
        state.read_za(0, &mut za).unwrap();
        out.extend(za);
        if sm {
            for r in 0..32 {
                let mut z = vec![0; state.vector_length().bytes()];
                state.read_z(registers, r, &mut z).unwrap();
                out.extend(z);
            }
            for r in 0..16 {
                let mut p = vec![0; state.vector_length().predicate_bytes()];
                state.read_predicate(r, &mut p).unwrap();
                out.extend(p);
            }
            let mut ffr = vec![0; state.vector_length().predicate_bytes()];
            state.read_ffr(&mut ffr).unwrap();
            out.extend(ffr);
        }
        out.extend(state.tpidr2_el0().to_le_bytes());
        out.extend(state.fpmr().to_le_bytes());
        out
    }
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("movement_model.json")).unwrap();
    let before = &fixture["before"];
    let lengths: Vec<_> = [16, 32, 64, 128, 256]
        .into_iter()
        .map(|b| VectorLength::from_bytes(b).unwrap())
        .collect();
    let mut comparisons = 0;
    for length in &lengths {
        for sm in [false, true] {
            for case in fixture["cases"].as_array().unwrap() {
                let ids = Arc::new(
                    Snapshot::declared(
                        "actual-halted-movt-independent-model-probe",
                        &[
                            (Register::IdAa64Pfr0El1, 0x11),
                            (Register::IdAa64Pfr1El1, 2 << 24),
                            (Register::IdAa64Pfr2El1, 0),
                            (Register::IdAa64Smfr0El1, 1 << 56),
                            (Register::IdAa64Zfr0El1, 0),
                            (Register::IdAa64Isar3El1, 0),
                            (Register::IdAa64Dfr0El1, 9),
                            (Register::IdAa64Dfr1El1, 0),
                            (Register::IdAa64Mmfr0El1, 0),
                            (Register::IdAa64Mmfr1El1, 0),
                            (Register::IdAa64Mmfr2El1, 0),
                            (Register::IdAa64Mmfr3El1, 0),
                            (Register::IdAa64Mmfr4El1, 0),
                            (Register::IdAa64Isar1El1, 0),
                            (Register::IdAa64Isar2El1, 0),
                        ],
                    )
                    .unwrap(),
                );
                let controls = ScalableControlOwner::new_declared_el10(
                    &ids,
                    Readbacks {
                        cpacr_el1: (3 << 20) | (3 << 24),
                        smcr_el1: ((length.bytes() / 16 - 1) as u64) | (1 << 30),
                    },
                    Implementation::declared(
                        &lengths,
                        MemoryImplementationProfile::ScalableTagChecks,
                    )
                    .unwrap(),
                )
                .unwrap();
                let mut system = system(Arc::clone(&ids), false, 0);
                let mut thread = thread();
                for (x, v) in thread
                    .registers
                    .x
                    .iter_mut()
                    .zip(before["x"].as_array().unwrap())
                {
                    *x = v.as_u64().unwrap();
                }
                thread.registers.sp = before["sp"].as_u64().unwrap();
                thread.registers.nzcv = u32::try_from(before["nzcv"].as_u64().unwrap()).unwrap();
                thread.registers.fpcr = u32::try_from(before["fpcr"].as_u64().unwrap()).unwrap();
                thread.registers.fpsr = u32::try_from(before["fpsr"].as_u64().unwrap()).unwrap();
                let mut scalable = ScalableState::new(*length, true);
                scalable
                    .apply_mode(&mut thread.registers, ScalableMode::new(sm, true))
                    .unwrap();
                let za: Vec<_> = (0..length.bytes().pow(2))
                    .map(|i| (i.wrapping_mul(37) + 11) as u8)
                    .collect();
                scalable.write_za(0, &za).unwrap();
                scalable
                    .write_zt0(0, &hex(before["zt0"].as_str().unwrap()))
                    .unwrap();
                if sm {
                    for reg in 0..32 {
                        let z: Vec<_> = (0..length.bytes())
                            .map(|i| (i * 17 + usize::from(reg) * 29 + 7) as u8)
                            .collect();
                        scalable.write_z(&mut thread.registers, reg, &z).unwrap();
                    }
                    for reg in 0..16 {
                        let p: Vec<_> = (0..length.predicate_bytes())
                            .map(|i| (i * 3 + usize::from(reg) * 11 + 5) as u8)
                            .collect();
                        scalable.write_predicate(reg, &p).unwrap();
                    }
                    scalable
                        .write_ffr(&vec![0x5a; length.predicate_bytes()])
                        .unwrap();
                }
                let expected_banks = banks(&scalable, &thread.registers, sm);
                let mut expected_registers = thread.registers.clone();
                for change in case["x_changes"].as_array().unwrap() {
                    expected_registers.x[change[0].as_u64().unwrap() as usize] =
                        change[1].as_u64().unwrap();
                }
                let mut context = ExecutionContext::default();
                let profile = ScalableProfile::new_with_features(
                    *length,
                    ScalableMode::new(sm, true),
                    ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2),
                    ScalableControls::new(lengths[4], true),
                )
                .unwrap();
                let (domain, mut memory) = memory();
                let mut producers = unsafe { SoftwareAsyncDomain::fresh_software_pe() };
                let keys = [producers.register_debug().unwrap()];
                let lease = producers.lease_debug_sources(&keys).unwrap();
                let mut backend = unsafe {
                    PrivilegedOwner::fresh_software(
                        7,
                        LowerElControls {
                            snapshot: Arc::clone(&ids),
                            sctlr_el1: 0,
                            tcr_el1: 0,
                            call_implementation: higher_el::Implementation {
                                without_el3_security: higher_el::WithoutEl3Security::NonSecureOnly,
                                trap_smc_without_el3: higher_el::TrapSmcWithoutEl3::Enabled,
                            },
                        },
                        &mut memory,
                        domain,
                        lease,
                        CtiRoute {
                            output_slot: 0,
                            target_slots: vec![],
                        },
                        Some(super::super::privileged_debug::DebugScalable {
                            controls: &controls,
                            state: &mut scalable,
                            context: &mut context,
                            specialization: profile,
                        }),
                    )
                    .unwrap()
                };
                {
                    let mut pe = unsafe {
                        SystemExecutionOwner::new_pe_with_debug(
                            &mut thread,
                            &mut system,
                            &mut backend,
                            debug(Arc::clone(&ids), Status::ResetCatch),
                        )
                        .unwrap()
                    };
                    pe.queue_editr(
                        0,
                        u32::from_str_radix(case["word"].as_str().unwrap(), 16).unwrap(),
                    )
                    .unwrap();
                    let outcome = pe.run_editr();
                    assert!(
                        matches!(outcome.stop, super::super::halted::DebugStop::Complete),
                        "{outcome:?}"
                    );
                    assert_eq!(outcome.actual_pc, PC);
                    let record = outcome.record.unwrap();
                    assert!(
                        record.native_invoked && record.native_returned && record.native_finalized
                    );
                    let resources = accept_retained_loan(pe.loan());
                    assert!(resources.authority.halted());
                    assert!(!resources.authority.ready());
                }
                drop(backend);
                assert_eq!(thread.registers, expected_registers);
                assert_eq!(banks(&scalable, &thread.registers, sm), expected_banks);
                let mut actual_zt0 = [0; 64];
                scalable.read_zt0(0, &mut actual_zt0).unwrap();
                assert_eq!(actual_zt0.as_slice(), hex(case["zt0"].as_str().unwrap()));
                assert!(
                    context.memory.is_null()
                        && context.scalable.is_null()
                        && context.system.is_null()
                );
                assert!(context.has_supported_header());
                comparisons += 1;
            }
        }
    }
    assert_eq!(comparisons, 480);
}

#[test]
#[cfg(target_arch = "x86_64")]
fn raw_editr_err_ignores_unallocated_word_before_decode() {
    let ids = ids(false);
    let mut system = system(Arc::clone(&ids), false, 0);
    let mut thread = thread();
    let before = thread.registers.clone();
    machine!(ids, system, thread, Status::ResetCatch, |pe| {
        {
            let resources = accept_retained_loan(pe.loan());
            resources.debug.as_mut().unwrap().set_overrun();
        }
        pe.queue_editr(0, u32::MAX).unwrap();
        let outcome = pe.run_editr();
        assert!(matches!(
            outcome.stop,
            super::super::halted::DebugStop::Complete
        ));
        assert_eq!(
            outcome.record.unwrap().disposition,
            crate::system::debug::halted::EditrDisposition::Ignored
        );
        assert_eq!(pe.pc(), PC);
        assert_eq!(pe.registers(), &before);
    });
}

#[test]
#[cfg(target_arch = "x86_64")]
fn absent_actual_exception_target_refuses_before_native_or_source_effects() {
    let ids = ids(true);
    let mut system = system(Arc::clone(&ids), true, 0);
    let mut thread = thread();
    let before = thread.registers.clone();
    let original_system = system.clone();
    let cache = tempfile::tempdir().unwrap();
    let mut runtime = crate::blocks::BlockRuntime::new_for_target(
        7,
        cache.path().to_owned(),
        BlockProfile::SystemV1,
        TargetCpu::Baseline,
    );
    runtime
        .register_code(PC, 0xd4000002u32.to_le_bytes().to_vec())
        .unwrap();
    machine!(ids, system, thread, Status::NonDebug, |pe| {
        let outcome = runtime.run_owned(
            pe.loan(),
            OwnedRunRequest {
                stop_pc: None,
                block_budget: 1,
            },
        );
        assert!(matches!(outcome.stop, OwnedStop::EntryDeclined(_)));
        assert!(outcome.last_native_observation.is_none());
        assert_eq!(outcome.accounting.blocks_executed, 0);
        assert_eq!(pe.pc(), PC);
        assert_eq!(pe.registers(), &before);
    });
    assert_eq!(system, original_system);
}

#[test]
#[cfg(target_arch = "x86_64")]
fn actual_fresh_factory_hvc_hlt_dcps_lifetime() {
    use super::super::software_privileged::*;
    let ids = ids(true);
    let initial_system = system(Arc::clone(&ids), true, 0);
    // Initialization values only.
    let initial_debug = DebugInitialization {
        edscr: Status::NonDebug as u32 | ITE | HDE,
        edprsr: 0,
        dlr: 0x7770,
        dspsr: 0x8880,
        edesr: 0,
        edecr: 0,
        mdscr_el1: 0,
        should_advance_ss: true,
        should_advance_hs: true,
        external: ExternalControls {
            powered: true,
            double_locked: false,
            software_locked: false,
            nonsecure_invasive: true,
            secure_invasive: true,
        },
        extended_halt_syndrome: ExtendedHaltSyndrome::DeclaredAbsent,
    };
    let cache = tempfile::tempdir().unwrap();
    let config = DeclaredPrivilegedConfig {
        identification: [
            Register::IdAa64Pfr0El1,
            Register::IdAa64Pfr1El1,
            Register::IdAa64Pfr2El1,
            Register::IdAa64Dfr0El1,
            Register::IdAa64Dfr1El1,
            Register::IdAa64Mmfr0El1,
            Register::IdAa64Mmfr1El1,
            Register::IdAa64Mmfr2El1,
            Register::IdAa64Mmfr4El1,
            Register::IdAa64Isar1El1,
            Register::IdAa64Isar2El1,
        ]
        .into_iter()
        .map(|register| (register, ids.read(register).unwrap()))
        .collect(),
        thread: thread(),
        pstate_misc: PSTATE_EL1H,
        inactive_stack_pointer: 0x1110,
        el1: *initial_system
            .exception_registers(ExceptionLevel::El1)
            .unwrap(),
        higher: Some(Initialization {
            el2: Some(El2Initialization {
                exception: El1Registers::new(21, 22, 23, 24, 0x8000),
                stack_pointer: 0x3330,
                hcr: 0,
                sctlr: 0,
                tcr: 0,
                hpfar: 26,
            }),
            el3: Some(El3Initialization {
                exception: El1Registers::new(31, 32, 33, 34, 0xa000),
                stack_pointer: 0x4440,
                scr: SCR_NS | SCR_HCE,
                sctlr: 0,
                tcr: 0,
            }),
        }),
        sctlr_el1: 0,
        tcr_el1: 0,
        debug: initial_debug,
        scalable: None,
        trap_smc_without_el3: TrapSmcWithoutEl3::Enabled,
        address_space: 7,
        cache_directory: cache.path().into(),
        code: vec![
            DeclaredPrivilegedCode {
                base: PC,
                bytes: 0xd4000002u32.to_le_bytes().to_vec(),
            },
            DeclaredPrivilegedCode {
                base: GuestAddress(0x8400),
                bytes: 0xd4400000u32.to_le_bytes().to_vec(),
            },
        ],
        debug_producer_count: 1,
        cti_output_slot: 0,
        cti_target_slots: vec![],
    };
    let report = run_declared_privileged(
        config,
        vec![
            DeclaredPrivilegedRequest::Run {
                stop_pc: Some(GuestAddress(0x8400)),
                block_budget: 1,
            },
            DeclaredPrivilegedRequest::Run {
                stop_pc: None,
                block_budget: 1,
            },
            DeclaredPrivilegedRequest::Editr {
                route_slot: 0,
                word: 0xd4a00001,
            },
        ],
    )
    .unwrap();
    assert_eq!(report.receipts.len(), 3);
    assert_eq!(report.thread.pc, GuestAddress(0x8400));
    assert!(report.receipts[0].stop.contains("StopAddress"));
    assert!(report.receipts[1].stop.contains("Halted"));
    assert_eq!(report.receipts[2].stop, "Complete");
    // DCPS1 retains a higher source EL; this lifetime already entered EL2.
    assert_eq!(report.system.current_el(), ExceptionLevel::El2);
    assert_eq!(report.thread.registers.sp, 0x3330);
    let actual_el2 = report
        .system
        .exception_registers(ExceptionLevel::El2)
        .unwrap();
    assert_eq!(
        (actual_el2.elr(), actual_el2.spsr(), actual_el2.esr()),
        (0, 0, 0)
    );
    assert!(report.receipts[2].lifecycle.contains("phase: Halted"));
    assert!(
        report
            .asynchronous
            .contains("cross_halt_outputs=[(1, 1, [])]")
    );
    assert!(report.receipts[0].source_receipts[0].contains("source_sha256"));
}

#[test]
#[cfg(target_arch = "x86_64")]
fn actual_fresh_factory_sme2_movt_owns_original_storage() {
    use super::super::software_privileged::*;
    use crate::scalable::ScalableState;
    use crate::system::scalable_controls::Readbacks;
    use stela_compiler::aarch64::scalable::{
        ScalableMode, VectorLength,
        features::{ScalableFeature, ScalableFeatures},
        profile::ScalableControls,
    };
    use stela_compiler::extended::ScalableProfile;
    let length = VectorLength::from_bytes(16).unwrap();
    let mut original_thread = thread();
    let mut original_scalable = ScalableState::new(length, true);
    original_scalable
        .apply_mode(
            &mut original_thread.registers,
            ScalableMode::new(false, true),
        )
        .unwrap();
    let zt0: Vec<_> = (0..64u8)
        .map(|i| i.wrapping_mul(19).wrapping_add(3))
        .collect();
    original_scalable.write_zt0(0, &zt0).unwrap();
    let expected_x0 = u64::from_le_bytes(zt0[..8].try_into().unwrap());
    let initial_debug = DebugInitialization {
        edscr: Status::ResetCatch as u32 | ITE | HDE,
        edprsr: 1 << 4,
        dlr: 0x7770,
        dspsr: 0x8880,
        edesr: 0,
        edecr: 0,
        mdscr_el1: 0,
        should_advance_ss: true,
        should_advance_hs: true,
        external: ExternalControls {
            powered: true,
            double_locked: false,
            software_locked: false,
            nonsecure_invasive: true,
            secure_invasive: true,
        },
        extended_halt_syndrome: ExtendedHaltSyndrome::DeclaredAbsent,
    };
    let cache = tempfile::tempdir().unwrap();
    let report = run_declared_privileged(
        DeclaredPrivilegedConfig {
            identification: vec![
                (Register::IdAa64Pfr0El1, 0x11),
                (Register::IdAa64Pfr1El1, 2 << 24),
                (Register::IdAa64Pfr2El1, 0),
                (Register::IdAa64Smfr0El1, 1 << 56),
                (Register::IdAa64Zfr0El1, 0),
                (Register::IdAa64Isar3El1, 0),
                (Register::IdAa64Dfr0El1, 9),
                (Register::IdAa64Dfr1El1, 0),
                (Register::IdAa64Mmfr0El1, 0),
                (Register::IdAa64Mmfr1El1, 0),
                (Register::IdAa64Mmfr2El1, 0),
                (Register::IdAa64Mmfr3El1, 0),
                (Register::IdAa64Mmfr4El1, 0),
                (Register::IdAa64Isar1El1, 0),
                (Register::IdAa64Isar2El1, 0),
            ],
            thread: original_thread,
            pstate_misc: PSTATE_EL1H,
            inactive_stack_pointer: 0x1110,
            el1: El1Registers::new(1, 2, 3, 4, 0x6000),
            higher: None,
            sctlr_el1: 0,
            tcr_el1: 0,
            debug: initial_debug,
            scalable: Some(DeclaredPrivilegedScalable {
                state: original_scalable,
                readbacks: Readbacks {
                    cpacr_el1: (3 << 20) | (3 << 24),
                    smcr_el1: 1 << 30,
                },
                supported_lengths: vec![length],
                specialization: ScalableProfile::new_with_features(
                    length,
                    ScalableMode::new(false, true),
                    ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2),
                    ScalableControls::new(length, true),
                )
                .unwrap(),
            }),
            trap_smc_without_el3: TrapSmcWithoutEl3::Enabled,
            address_space: 7,
            cache_directory: cache.path().into(),
            code: vec![],
            debug_producer_count: 1,
            cti_output_slot: 0,
            cti_target_slots: vec![],
        },
        vec![DeclaredPrivilegedRequest::Editr {
            route_slot: 0,
            word: 0xc04c03e0,
        }],
    )
    .unwrap();
    assert_eq!(report.thread.registers.x[0], expected_x0);
    assert_eq!(report.thread.pc, PC);
    assert_eq!(report.receipts[0].stop, "Complete");
    assert!(
        report.receipts[0]
            .debug_record
            .as_ref()
            .unwrap()
            .contains("native_finalized: true")
    );
    let mut actual_zt0 = [0; 64];
    report
        .scalable
        .unwrap()
        .read_zt0(0, &mut actual_zt0)
        .unwrap();
    assert_eq!(actual_zt0.as_slice(), zt0);
}
