use super::*;
use stela_compiler::GuestState;
use stela_contracts::bus::LifecycleState;
use {
    crate::machine::engine::FaultCause, crate::machine::engine::InstallError,
    crate::machine::engine::NativeCode, crate::machine::engine::NativeExit,
    crate::machine::engine::NativeFault, crate::machine::engine::NoDevices,
    crate::machine::engine::ProcessorBinding, crate::machine::engine::ProcessorChange,
    crate::machine::engine::Regime, crate::machine::engine::tests::board,
    stela_contracts::identity::Identity, stela_contracts::processor::ProcessorTarget,
};

#[derive(Default)]
struct LocalHost {
    worker: Option<WorkerId>,
    invalidations: usize,
    calls: usize,
    #[cfg(feature = "std")]
    concurrent_entry: Option<Arc<std::sync::Barrier>>,
}
impl Host for LocalHost {
    fn native_worker(&self) -> Option<WorkerId> {
        self.worker
    }
    fn read_ram(&mut self, _: u64, _: &mut [u8]) -> bool {
        false
    }
    fn write_ram(&mut self, _: u64, _: &[u8]) -> bool {
        false
    }
    fn install(&mut self, code: &[u8]) -> Result<NativeCode, InstallError> {
        assert_eq!(code, [0xc3]);
        Ok(NativeCode(0x1000))
    }
    fn patch(&mut self, _: NativeCode, _: &[u8]) {
        unreachable!()
    }
    fn discard_code(&mut self) {
        unreachable!()
    }
    unsafe fn execute(&mut self, code: NativeCode, state: &mut GuestState) -> NativeExit {
        assert_eq!(code, NativeCode(0x1000));
        self.calls += 1;
        #[cfg(feature = "std")]
        if let Some(barrier) = &self.concurrent_entry {
            barrier.wait();
        }
        for (i, register) in state.x.iter_mut().enumerate() {
            *register ^= 0x8000 + i as u64;
        }
        for (i, vector) in state.v.iter_mut().enumerate() {
            *vector = [i as u64, !(i as u64)];
        }
        state.sp = 0xfeed;
        state.nzcv = 0xa000_0000;
        state.fpcr = 1 << 25;
        state.fpsr = 1 << 27;
        NativeExit::Fault(NativeFault {
            origin: crate::machine::NativeFaultOrigin::Exception,
            trap: 6,
            error_code: 0,
            spills: stela_compiler::block::HostSpillSnapshot::new(),
            offset: 13,
            address: 0xabcd_0000,
            write: true,
            cause: FaultCause::InvalidOpcode,
            registers: stela_compiler::block::HostGprSnapshot::legacy(core::array::from_fn(|i| {
                0x100 + i as u64
            })),
        })
    }
    fn set_regime(&mut self, _: &Regime) {}
    fn invalidate_translations(&mut self) {
        self.invalidations += 1;
    }
    fn counter(&mut self) -> u64 {
        0
    }
    fn arm_timer(&mut self, _: Option<u64>) {}
    fn wait_for_interrupt(&mut self) {}
}

// Only this test double, not a production native lane, is implemented here.
// Its borrowed state and exit cannot be replaced by an ACK integer.
#[derive(Debug)]
struct FrameLoan<'a> {
    state: &'a mut GuestState,
    retired: &'a mut u64,
}
#[derive(Debug)]
struct FrameReturn<'a> {
    frame: FrameLoan<'a>,
    exit: NativeExit,
    code: NativeCode,
}
impl sealed::NativeFrame for FrameLoan<'_> {}
impl<'a> NativeFrame for FrameLoan<'a> {
    type Returned = FrameReturn<'a>;
    fn execute(self, host: &mut dyn Host) -> Self::Returned {
        let code = host.install(&[0xc3]).unwrap();
        // SAFETY: The test host recognizes exactly this installed test image.
        let exit = unsafe { host.execute(code, self.state) };
        *self.retired += 7;
        FrameReturn {
            frame: self,
            exit,
            code,
        }
    }
}

fn bindings() -> [WorkerBinding; 2] {
    [
        WorkerBinding {
            pe: 0,
            worker: WorkerId(17),
        },
        WorkerBinding {
            pe: 1,
            worker: WorkerId(42),
        },
    ]
}
fn ready() -> (WorkerPublications, Vec<WorkerOwner>, [LocalHost; 2]) {
    let (mut publications, mut owners) = WorkerPublications::new(&bindings()).unwrap();
    let mut hosts = [
        LocalHost {
            worker: Some(bindings()[0].worker),
            ..LocalHost::default()
        },
        LocalHost {
            worker: Some(bindings()[1].worker),
            ..LocalHost::default()
        },
    ];
    for (owner, host) in owners.iter_mut().zip(&mut hosts) {
        publications
            .accept_initial(owner.publish_initial(host).unwrap())
            .unwrap();
    }
    (publications, owners, hosts)
}
fn hold(
    publications: &mut WorkerPublications,
    owners: &mut [WorkerOwner],
    hosts: &mut [LocalHost],
    request: StopRequest,
) -> StoppedWorkers {
    for command in publications.native_stop_commands(&request).unwrap() {
        let index = owners
            .iter()
            .position(|owner| owner.binding == command.binding())
            .unwrap();
        let receipt = owners[index]
            .invalidate(command, &mut hosts[index])
            .unwrap();
        publications.accept_invalidation(receipt).unwrap();
    }
    publications.hold_stop(request).unwrap()
}

#[test]
fn retained_idle_owners_rejoin_changing_actual_run_rosters_without_new_commands() {
    let (mut publications, mut owners, mut hosts) = ready();
    let request = publications.request_stop(&[0, 1]).unwrap();
    let mut held = hold(&mut publications, &mut owners, &mut hosts, request);
    let stopped_generation = held.request.generation;
    let mut states = [GuestState::default(), GuestState::default()];
    let mut retired = [0, 0];
    for members in [&[1][..], &[0][..], &[0, 1][..]] {
        let (running, releases) = publications.release_for_run(held, members).unwrap();
        for release in releases {
            let pe = release.binding().pe;
            publications
                .accept_release(owners[pe].release(release).unwrap())
                .unwrap();
        }
        assert!(publications.require_stopped(2, &[0, 1]).is_err());
        assert_eq!(
            publications.request_rejoin(&running).unwrap_err(),
            PublicationError::StaleRun
        );
        for (pe, (state, retirement)) in states.iter_mut().zip(&mut retired).enumerate() {
            if !members.contains(&pe) {
                assert_eq!(
                    publications.dispatch(pe, ()).unwrap_err().error,
                    PublicationError::StopBusy
                );
                continue;
            }
            let loan = publications
                .dispatch(
                    pe,
                    FrameLoan {
                        state,
                        retired: retirement,
                    },
                )
                .unwrap();
            let returned = owners[pe].execute(loan, &mut hosts[pe]).unwrap();
            publications.recover(returned, |_| Ok::<_, ()>(())).unwrap();
        }
        let commands = publications.request_rejoin(&running).unwrap();
        assert_eq!(commands.len(), members.len());
        assert!(
            commands
                .iter()
                .all(|command| command.generation() == stopped_generation)
        );
        let refused = publications.rejoin(running).unwrap_err();
        assert_eq!(refused.error, PublicationError::MissingInvalidation);
        for command in commands {
            let pe = command.binding().pe;
            publications
                .accept_invalidation(owners[pe].invalidate(command, &mut hosts[pe]).unwrap())
                .unwrap();
        }
        held = publications.rejoin(refused.payload).unwrap();
        publications.require_all_held(&held).unwrap();
    }
    assert_eq!(
        hosts.iter().map(|host| host.calls).collect::<Vec<_>>(),
        [2, 2]
    );
    // Initial publication + first full stop + only two runs per PE.
    assert_eq!(
        hosts
            .iter()
            .map(|host| host.invalidations)
            .collect::<Vec<_>>(),
        [4, 4]
    );
    assert_eq!(retired, [14, 14]);
    assert_eq!(states[0], states[1]);
}

#[test]
fn sparse_idle_roster_rejects_changed_stop_generation_without_rebasing_receipts() {
    let bindings = [
        WorkerBinding {
            pe: 4,
            worker: WorkerId(17),
        },
        WorkerBinding {
            pe: 9,
            worker: WorkerId(42),
        },
    ];
    let (mut publications, mut owners) = WorkerPublications::new(&bindings).unwrap();
    let mut hosts = bindings.map(|binding| LocalHost {
        worker: Some(binding.worker),
        ..LocalHost::default()
    });
    for (owner, host) in owners.iter_mut().zip(&mut hosts) {
        publications
            .accept_initial(owner.publish_initial(host).unwrap())
            .unwrap();
    }
    let request = publications.request_stop(&[4, 9]).unwrap();
    let held = hold(&mut publications, &mut owners, &mut hosts, request);
    let (mut running, releases) = publications.release_for_run(held, &[9]).unwrap();
    for release in releases {
        publications
            .accept_release(owners[1].release(release).unwrap())
            .unwrap();
    }
    let mut state = GuestState::default();
    let mut retired = 0;
    let loan = publications
        .dispatch(
            9,
            FrameLoan {
                state: &mut state,
                retired: &mut retired,
            },
        )
        .unwrap();
    let returned = owners[1].execute(loan, &mut hosts[1]).unwrap();
    publications.recover(returned, |_| Ok::<_, ()>(())).unwrap();
    // Corrupt only the request, never manufacture a Host receipt.
    // The idle owner's old-generation hold cannot be promoted.
    let generation = running.request.generation;
    running.request.generation += 1;
    assert_eq!(
        publications.request_rejoin(&running).unwrap_err(),
        PublicationError::MissingInvalidation
    );
    let refused = publications.rejoin(running).unwrap_err();
    assert_eq!(refused.error, PublicationError::MissingInvalidation);
    let mut running = refused.payload;
    running.request.generation = generation;
    for command in publications.request_rejoin(&running).unwrap() {
        assert_eq!(command.binding().pe, 9);
        publications
            .accept_invalidation(owners[1].invalidate(command, &mut hosts[1]).unwrap())
            .unwrap();
    }
    let held = publications.rejoin(running).unwrap();
    publications.require_all_held(&held).unwrap();
    assert_eq!(hosts[0].calls, 0);
    assert_eq!(hosts[0].invalidations, 2);
    assert_eq!(hosts[1].calls, 1);
    assert_eq!(hosts[1].invalidations, 3);
    assert_eq!(retired, 7);
}

#[test]
fn selective_release_preflight_and_failed_actual_recovery_keep_full_authority() {
    let (mut publications, mut owners, mut hosts) = ready();
    let request = publications.request_stop(&[0, 1]).unwrap();
    let mut held = hold(&mut publications, &mut owners, &mut hosts, request);
    for (members, expected) in [
        (&[][..], PublicationError::EmptyCohort),
        (&[0, 0][..], PublicationError::DuplicatePe(0)),
        (&[0, 9][..], PublicationError::UnknownPe(9)),
    ] {
        let refused = publications.release_for_run(held, members).unwrap_err();
        assert_eq!(refused.error, expected);
        held = refused.payload;
        publications.require_all_held(&held).unwrap();
    }
    let services = publications.open_services(&held, 1).unwrap();
    let refused = publications.release_for_run(held, &[0]).unwrap_err();
    assert_eq!(refused.error, PublicationError::ServiceBusy);
    publications.close_services(services).unwrap();
    let (running, releases) = publications.release_for_run(refused.payload, &[1]).unwrap();
    for release in releases {
        publications
            .accept_release(owners[1].release(release).unwrap())
            .unwrap();
    }
    let mut state = GuestState::default();
    let mut retired = 0;
    let loan = publications
        .dispatch(
            1,
            FrameLoan {
                state: &mut state,
                retired: &mut retired,
            },
        )
        .unwrap();
    let returned = owners[1].execute(loan, &mut hosts[1]).unwrap();
    let failed = publications
        .recover(returned, |_| Err("actual recovery incomplete"))
        .unwrap_err();
    assert_eq!(
        publications.request_rejoin(&running).unwrap_err(),
        PublicationError::InFlight
    );
    let (mut foreign, _, _) = ready();
    assert_eq!(
        foreign.request_rejoin(&running).unwrap_err(),
        PublicationError::WrongInventory
    );
    publications
        .recover(failed.payload, |actual| {
            assert!(matches!(actual.exit, NativeExit::Fault(_)));
            assert_eq!(*actual.frame.retired, 7);
            Ok::<_, ()>(())
        })
        .unwrap();
    let mut commands = publications.request_rejoin(&running).unwrap();
    assert_eq!(commands.len(), 1);
    let wrong = owners[0]
        .invalidate(commands.pop().unwrap(), &mut hosts[0])
        .unwrap_err();
    assert_eq!(wrong.error, PublicationError::WrongOwner);
    let receipt = owners[1].invalidate(wrong.payload, &mut hosts[1]).unwrap();
    publications.accept_invalidation(receipt).unwrap();
    let held = publications.rejoin(running).unwrap();
    publications.require_all_held(&held).unwrap();
    assert_eq!(hosts[0].calls, 0);
    assert_eq!(hosts[0].invalidations, 2);
    assert_eq!(retired, 7);
    assert_eq!(state.sp, 0xfeed);
}

#[test]
fn registration_requires_unique_bindings_and_actual_initial_publication() {
    assert!(matches!(
        WorkerPublications::new(&[]),
        Err(PublicationError::EmptyCohort)
    ));
    for (bindings, error) in [
        (
            [
                bindings()[0],
                WorkerBinding {
                    worker: WorkerId(18),
                    ..bindings()[0]
                },
            ],
            PublicationError::DuplicatePe(0),
        ),
        (
            [
                bindings()[0],
                WorkerBinding {
                    pe: 1,
                    ..bindings()[0]
                },
            ],
            PublicationError::DuplicateWorker(WorkerId(17)),
        ),
    ] {
        assert_eq!(WorkerPublications::new(&bindings).unwrap_err(), error);
    }
    let (mut publications, mut owners) = WorkerPublications::new(&bindings()).unwrap();
    assert_eq!(
        publications.dispatch(0, 123).unwrap_err().error,
        PublicationError::NotInitialized
    );
    assert_eq!(
        publications.request_stop(&[0]).unwrap_err(),
        PublicationError::NotInitialized
    );
    let mut host = LocalHost {
        worker: Some(bindings()[0].worker),
        ..LocalHost::default()
    };
    let initial = owners[0].publish_initial(&mut host).unwrap();
    assert_eq!(host.invalidations, 1);
    assert_eq!(
        owners[0].publish_initial(&mut host).unwrap_err(),
        PublicationError::AlreadyInitialized
    );
    publications.accept_initial(initial).unwrap();
    assert_eq!(
        publications.dispatch(1, 456).unwrap_err().error,
        PublicationError::NotInitialized
    );
    assert_eq!(host.invalidations, 1);
}

#[test]
fn actual_host_identity_is_required_before_any_native_owner_effect() {
    let (mut publications, mut owners) = WorkerPublications::new(&bindings()).unwrap();
    let mut serial = LocalHost::default();
    assert_eq!(
        owners[0].publish_initial(&mut serial).unwrap_err(),
        PublicationError::UnqualifiedHost
    );
    let mut wrong = LocalHost {
        worker: Some(bindings()[1].worker),
        ..LocalHost::default()
    };
    assert_eq!(
        owners[0].publish_initial(&mut wrong).unwrap_err(),
        PublicationError::WrongOwner
    );
    assert_eq!((serial.invalidations, wrong.invalidations), (0, 0));
    let mut actual = LocalHost {
        worker: Some(bindings()[0].worker),
        ..LocalHost::default()
    };
    publications
        .accept_initial(owners[0].publish_initial(&mut actual).unwrap())
        .unwrap();
    let mut state = GuestState::default();
    let mut retired = 0;
    let loan = publications
        .dispatch(
            0,
            FrameLoan {
                state: &mut state,
                retired: &mut retired,
            },
        )
        .unwrap();
    let failed = owners[0].execute(loan, &mut wrong).unwrap_err();
    assert_eq!(failed.error, PublicationError::WrongOwner);
    assert_eq!(wrong.calls, 0);
    let returned = owners[0].execute(failed.payload, &mut actual).unwrap();
    publications.recover(returned, |_| Ok::<_, ()>(())).unwrap();
    let request = publications.request_stop(&[0]).unwrap();
    let command = publications
        .native_stop_commands(&request)
        .unwrap()
        .pop()
        .unwrap();
    let failed = owners[0].invalidate(command, &mut wrong).unwrap_err();
    assert_eq!(failed.error, PublicationError::WrongOwner);
    assert_eq!(wrong.invalidations, 0);
    let receipt = owners[0].invalidate(failed.payload, &mut actual).unwrap();
    publications.accept_invalidation(receipt).unwrap();
    let _held = publications.hold_stop(request).unwrap();
    assert_eq!(actual.calls, 1);
    assert_eq!(actual.invalidations, 2);
}

#[test]
fn whole_owner_view_requires_exact_complete_roster_and_one_cohort() {
    let (mut publications, mut owners, mut hosts) = ready();
    assert_eq!(
        publications.require_stopped(1, &[0]).unwrap_err(),
        PublicationError::ProcessorCount {
            expected: 1,
            actual: 2
        }
    );
    let request = publications.request_stop(&[0]).unwrap();
    let _held = hold(&mut publications, &mut owners, &mut hosts, request);
    assert_eq!(
        publications.require_stopped(2, &[0]).unwrap_err(),
        PublicationError::MissingInvalidation
    );
    let (sparse, _) = WorkerPublications::new(&[
        bindings()[0],
        WorkerBinding {
            pe: 3,
            ..bindings()[1]
        },
    ])
    .unwrap();
    assert_eq!(
        sparse.require_stopped(2, &[0]).unwrap_err(),
        PublicationError::UnknownPe(3)
    );
}

#[test]
fn a_real_return_preserves_registers_retirement_and_full_native_fault() {
    let (mut publications, mut owners, mut hosts) = ready();
    let mut state = GuestState::default();
    let mut retired = 20;
    let loan = publications
        .dispatch(
            0,
            FrameLoan {
                state: &mut state,
                retired: &mut retired,
            },
        )
        .unwrap();
    let generation = loan.generation();
    let returned = owners[0].execute(loan, &mut hosts[0]).unwrap();
    assert_eq!(returned.generation(), generation);
    assert_eq!(publications.slots[0].frame, Frame::InFlight(generation));
    publications
        .recover(returned, |actual| {
            assert_eq!(actual.code, NativeCode(0x1000));
            assert_eq!(*actual.frame.retired, 27);
            assert_eq!(
                actual.frame.state.x,
                core::array::from_fn(|i| 0x8000 + i as u64)
            );
            assert_eq!(
                actual.frame.state.v,
                core::array::from_fn(|i| [i as u64, !(i as u64)])
            );
            assert_eq!(
                (actual.frame.state.sp, actual.frame.state.nzcv),
                (0xfeed, 0xa000_0000)
            );
            assert_eq!(
                (actual.frame.state.fpcr, actual.frame.state.fpsr),
                (1 << 25, 1 << 27)
            );
            assert_eq!(
                actual.exit,
                NativeExit::Fault(NativeFault {
                    origin: crate::machine::NativeFaultOrigin::Exception,
                    trap: 6,
                    error_code: 0,
                    spills: stela_compiler::block::HostSpillSnapshot::new(),
                    offset: 13,
                    address: 0xabcd_0000,
                    write: true,
                    cause: FaultCause::InvalidOpcode,
                    registers: stela_compiler::block::HostGprSnapshot::legacy(
                        core::array::from_fn(|i| 0x100 + i as u64)
                    ),
                })
            );
            Ok::<_, ()>(())
        })
        .unwrap();
    assert_eq!(retired, 27);
    assert_eq!(state.x[30], 0x801e);
    assert_eq!(hosts[0].calls, 1);
}

#[test]
fn failed_recovery_keeps_actual_frame_and_blocks_stop_credit_until_retry() {
    let (mut publications, mut owners, mut hosts) = ready();
    let mut state = GuestState::default();
    let mut retired = 0;
    let loan = publications
        .dispatch(
            0,
            FrameLoan {
                state: &mut state,
                retired: &mut retired,
            },
        )
        .unwrap();
    let request = publications.request_stop(&[0, 1]).unwrap();
    let returned = owners[0].execute(loan, &mut hosts[0]).unwrap();
    let failed = publications
        .recover(returned, |_| Err("recovery remains pending"))
        .unwrap_err();
    assert!(matches!(
        failed.error,
        RecoveryError::Recovery("recovery remains pending")
    ));
    assert_eq!(
        publications.native_stop_commands(&request).unwrap_err(),
        PublicationError::InFlight
    );
    assert_eq!(hosts[0].invalidations, 1);
    publications
        .recover(failed.payload, |actual| {
            assert_eq!(actual.frame.state.sp, 0xfeed);
            Ok::<_, ()>(())
        })
        .unwrap();
    let held = hold(&mut publications, &mut owners, &mut hosts, request);
    publications.require_stopped(2, &[0, 1]).unwrap();
    assert_eq!(hosts.map(|host| host.invalidations), [2, 2]);
    drop(held); // Losing the release permission keeps the safe stop held.
    assert_eq!(
        publications.dispatch(0, 0).unwrap_err().error,
        PublicationError::StopBusy
    );
}

#[test]
fn whole_cohort_preflight_has_no_partial_stop_or_invalidation_effect() {
    let (mut publications, mut owners, mut hosts) = ready();
    for (members, error) in [
        (alloc::vec![0, 5], PublicationError::UnknownPe(5)),
        (alloc::vec![0, 0], PublicationError::DuplicatePe(0)),
        (alloc::vec![], PublicationError::EmptyCohort),
    ] {
        assert_eq!(publications.request_stop(&members).unwrap_err(), error);
        assert!(publications.slots.iter().all(|slot| slot.stop.is_none()));
    }
    let mut state = GuestState::default();
    let mut retired = 0;
    let loan = publications
        .dispatch(
            1,
            FrameLoan {
                state: &mut state,
                retired: &mut retired,
            },
        )
        .unwrap();
    let request = publications.request_stop(&[0, 1]).unwrap();
    assert_eq!(
        publications.native_stop_commands(&request).unwrap_err(),
        PublicationError::InFlight
    );
    assert!(
        publications
            .slots
            .iter()
            .all(|slot| slot.stop == Some((request.generation(), StopPhase::Requested)))
    );
    let returned = owners[1].execute(loan, &mut hosts[1]).unwrap();
    publications.recover(returned, |_| Ok::<_, ()>(())).unwrap();
    let mut commands = publications.native_stop_commands(&request).unwrap();
    let receipt = owners[0]
        .invalidate(commands.remove(0), &mut hosts[0])
        .unwrap();
    publications.accept_invalidation(receipt).unwrap();
    let failed = publications.hold_stop(request).unwrap_err();
    assert_eq!(failed.error, PublicationError::StaleStop);
    assert!(publications.require_stopped(2, &[0]).is_err());
    let receipt = owners[1]
        .invalidate(commands.pop().unwrap(), &mut hosts[1])
        .unwrap();
    publications.accept_invalidation(receipt).unwrap();
    let _held = publications.hold_stop(failed.payload).unwrap();
    publications.require_stopped(2, &[1, 0]).unwrap();
}

#[test]
fn identity_and_actual_owner_refusals_retain_the_original_tokens() {
    let (mut a, mut owners, mut hosts) = ready();
    let (mut b, _, _) = ready();
    let mut state = GuestState::default();
    let mut retired = 0;
    let loan = a
        .dispatch(
            0,
            FrameLoan {
                state: &mut state,
                retired: &mut retired,
            },
        )
        .unwrap();
    let failed = owners[1].execute(loan, &mut hosts[1]).unwrap_err();
    assert_eq!(failed.error, PublicationError::WrongOwner);
    assert_eq!(hosts[1].calls, 0);
    let returned = owners[0].execute(failed.payload, &mut hosts[0]).unwrap();
    let wrong = b
        .recover(returned, |_| -> Result<(), ()> {
            panic!("wrong inventory must not recover")
        })
        .unwrap_err();
    assert!(matches!(
        wrong.error,
        RecoveryError::Publication(PublicationError::WrongInventory)
    ));
    a.recover(wrong.payload, |_| Ok::<_, ()>(())).unwrap();
    let request = a.request_stop(&[0]).unwrap();
    let mut commands = a.native_stop_commands(&request).unwrap();
    let wrong = owners[1]
        .invalidate(commands.pop().unwrap(), &mut hosts[1])
        .unwrap_err();
    assert_eq!(wrong.error, PublicationError::WrongOwner);
    assert_eq!(hosts[1].invalidations, 1);
    let receipt = owners[0].invalidate(wrong.payload, &mut hosts[0]).unwrap();
    let wrong = b.accept_invalidation(receipt).unwrap_err();
    assert_eq!(wrong.error, PublicationError::WrongInventory);
    a.accept_invalidation(wrong.payload).unwrap();
    let held = a.hold_stop(request).unwrap();
    let wrong = b.release(held).unwrap_err();
    assert_eq!(wrong.error, PublicationError::WrongInventory);
    let mut releases = a.release(wrong.payload).unwrap();
    let wrong = owners[1].release(releases.pop().unwrap()).unwrap_err();
    assert_eq!(wrong.error, PublicationError::WrongOwner);
    let receipt = owners[0].release(wrong.payload).unwrap();
    let wrong = b.accept_release(receipt).unwrap_err();
    assert_eq!(wrong.error, PublicationError::WrongInventory);
    a.accept_release(wrong.payload).unwrap();
    assert!(a.slots[0].stop.is_none());
}

#[test]
fn redispatch_waits_for_same_generation_owner_release_receipts() {
    let (mut publications, mut owners, mut hosts) = ready();
    let request = publications.request_stop(&[0, 1]).unwrap();
    let held = hold(&mut publications, &mut owners, &mut hosts, request);
    assert_eq!(
        publications.dispatch(0, 1).unwrap_err().error,
        PublicationError::StopBusy
    );
    let mut releases = publications.release(held).unwrap();
    assert_eq!(
        publications.dispatch(0, 1).unwrap_err().error,
        PublicationError::StopBusy
    );
    // Releasing PE0 does not authorize PE1, nor reuse a prior stop.
    let receipt = owners[0].release(releases.remove(0)).unwrap();
    assert_eq!(
        publications.dispatch(0, 1).unwrap_err().error,
        PublicationError::StopBusy
    );
    publications.accept_release(receipt).unwrap();
    assert!(publications.slots[0].stop.is_none());
    assert_eq!(
        publications.dispatch(1, 1).unwrap_err().error,
        PublicationError::StopBusy
    );
    let receipt = owners[1].release(releases.pop().unwrap()).unwrap();
    publications.accept_release(receipt).unwrap();
    let request = publications.request_stop(&[0, 1]).unwrap();
    assert!(publications.require_stopped(2, &[0, 1]).is_err());
    let _held = hold(&mut publications, &mut owners, &mut hosts, request);
}

#[test]
fn different_held_generations_cannot_qualify_one_cpu_transaction() {
    let (mut publications, mut owners, mut hosts) = ready();
    let first = publications.request_stop(&[0]).unwrap();
    let _held0 = hold(&mut publications, &mut owners, &mut hosts, first);
    let second = publications.request_stop(&[1]).unwrap();
    let _held1 = hold(&mut publications, &mut owners, &mut hosts, second);
    assert_eq!(
        publications.require_stopped(2, &[0, 1]).unwrap_err(),
        PublicationError::StaleStop
    );
    assert!(publications.require_stopped(2, &[0]).is_err());
}

#[test]
fn generation_exhaustion_never_mutates_execution_or_stop_state() {
    let (mut publications, _, _) = ready();
    publications.generation = u64::MAX;
    assert_eq!(
        publications.dispatch(0, 1).unwrap_err().error,
        PublicationError::GenerationExhausted
    );
    assert_eq!(
        publications.request_stop(&[0, 1]).unwrap_err(),
        PublicationError::GenerationExhausted
    );
    assert!(
        publications
            .slots
            .iter()
            .all(|slot| slot.stop.is_none() && slot.frame == Frame::Recovered(None))
    );
}

#[test]
fn dropping_a_native_loan_or_return_never_credits_a_stopped_snapshot() {
    let (mut publications, mut owners, mut hosts) = ready();
    let mut state = GuestState::default();
    let mut retired = 0;
    drop(
        publications
            .dispatch(
                0,
                FrameLoan {
                    state: &mut state,
                    retired: &mut retired,
                },
            )
            .unwrap(),
    );
    let loan = publications
        .dispatch(
            1,
            FrameLoan {
                state: &mut state,
                retired: &mut retired,
            },
        )
        .unwrap();
    drop(owners[1].execute(loan, &mut hosts[1]).unwrap());
    let request = publications.request_stop(&[0, 1]).unwrap();
    assert_eq!(
        publications.native_stop_commands(&request).unwrap_err(),
        PublicationError::InFlight
    );
    assert!(publications.require_stopped(2, &[0, 1]).is_err());
}

#[test]
fn processor_write_checks_all_requested_owners_even_for_unchanged_pause_state() {
    const ACTIVE: LifecycleState = LifecycleState {
        powered: true,
        clocked: true,
        quiesced: false,
        reset: false,
        retention: false,
    };
    let mut machine = board(
        &[],
        NoDevices,
        alloc::vec![
            Identity {
                midr: 0x611f_0320,
                mpidr: 0x8000_0000,
                clock: None,
                caches: None
            },
            Identity {
                midr: 0x611f_0320,
                mpidr: 0x8000_0001,
                clock: None,
                caches: None
            },
        ],
    );
    machine
        .bind_processor_power(&[ProcessorBinding {
            domain: 1,
            target: ProcessorTarget::Core { pe: 0 },
            initial: ACTIVE,
        }])
        .unwrap();
    let (mut publications, mut owners, mut hosts) = ready();
    let before = machine.translation_generation;
    let mut independent = GuestState::default();
    let mut retired = 0;
    let loan = publications
        .dispatch(
            0,
            FrameLoan {
                state: &mut independent,
                retired: &mut retired,
            },
        )
        .unwrap();
    machine.native_publication = Some(publications);
    let unchanged = [ProcessorChange {
        domain: 1,
        state: ACTIVE,
    }];
    assert!(matches!(
        machine.processor_write().apply(&unchanged),
        Err(super::super::ProcessorPowerError::Publication(
            PublicationError::InFlight
        ))
    ));
    assert_eq!(machine.translation_generation, before);
    assert_eq!(machine.processors().paused(0), Some(false));
    let publications = machine.native_publication.as_mut().unwrap();
    let request = publications.request_stop(&[0, 1]).unwrap();
    let returned = owners[0].execute(loan, &mut hosts[0]).unwrap();
    publications.recover(returned, |_| Ok::<_, ()>(())).unwrap();
    assert!(matches!(
        machine.processor_write().apply(&unchanged),
        Err(super::super::ProcessorPowerError::Publication(
            PublicationError::MissingInvalidation
        ))
    ));
    let held = hold(
        machine.native_publication.as_mut().unwrap(),
        &mut owners,
        &mut hosts,
        request,
    );
    let paused = [ProcessorChange {
        domain: 1,
        state: LifecycleState {
            clocked: false,
            ..ACTIVE
        },
    }];
    let settled = machine.processor_write().apply(&paused).unwrap();
    assert_eq!(settled.paused(0), Some(true));
    // This exclusive owner borrow lasts through the infallible ACK.
    drop(settled);
    let publications = machine.native_publication.as_mut().unwrap();
    for release in publications.release(held).unwrap() {
        let index = owners
            .iter()
            .position(|owner| owner.binding == release.binding())
            .unwrap();
        let receipt = owners[index].release(release).unwrap();
        publications.accept_release(receipt).unwrap();
    }
    assert_eq!(machine.processors().paused(0), Some(true));
}

#[cfg(feature = "std")]
#[test]
fn two_workers_execute_actual_disjoint_loans_concurrently_and_publish_returns() {
    use std::sync::{Barrier, mpsc};
    let (mut publications, owners, _) = ready();
    let mut states = [GuestState::default(), GuestState::default()];
    let mut retired = [0, 0];
    let barrier = Arc::new(Barrier::new(3));
    std::thread::scope(|scope| {
        let (sender, receiver) = mpsc::channel();
        for ((owner, state), retirement) in owners.into_iter().zip(&mut states).zip(&mut retired) {
            let loan = publications
                .dispatch(
                    owner.binding.pe,
                    FrameLoan {
                        state,
                        retired: retirement,
                    },
                )
                .unwrap();
            let sender = sender.clone();
            let barrier = barrier.clone();
            scope.spawn(move || {
                let mut owner = owner;
                let mut host = LocalHost {
                    worker: Some(owner.binding.worker),
                    concurrent_entry: Some(barrier),
                    ..LocalHost::default()
                };
                // The barrier is inside Host::execute, so both
                // disjoint frames must enter before either can return.
                let returned = owner.execute(loan, &mut host).unwrap();
                sender.send((owner, returned, host)).unwrap();
            });
        }
        let request = publications.request_stop(&[0, 1]).unwrap();
        assert_eq!(
            publications.native_stop_commands(&request).unwrap_err(),
            PublicationError::InFlight
        );
        barrier.wait();
        let mut owners = Vec::new();
        let mut hosts = Vec::new();
        for _ in 0..2 {
            // Channel publication supplies Release/Acquire ordering. The
            // future AP transport must preserve that same ownership edge.
            let (owner, returned, host) = receiver.recv().unwrap();
            publications
                .recover(returned, |actual| {
                    assert_eq!(actual.frame.state.x[0], 0x8000);
                    assert_eq!(*actual.frame.retired, 7);
                    Ok::<_, ()>(())
                })
                .unwrap();
            owners.push(owner);
            hosts.push(host);
        }
        let _held = hold(&mut publications, &mut owners, &mut hosts, request);
        publications.require_stopped(2, &[0, 1]).unwrap();
    });
    assert_eq!(states[0], states[1]);
    assert_eq!(retired, [7, 7]);
}
