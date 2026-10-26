// SPDX-License-Identifier: MIT
// Actual ACPICA installation, OSL port transport and retained handler lifecycle.
mod ec_binding_tests {
    #[test]
    fn native_installed_ec_unlock_preserves_exact_original_native_io_cause() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let (provider, counts) = fixture_ec(false);
        let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
        let device = Device::discover(session.devices("PNP0C09").unwrap()[0]).unwrap();
        let binding =
            unsafe { Binding::install(device, ec::Config::default(), Scope::Device) }.unwrap();
        EC.lock().unwrap().as_mut().unwrap().read_error = Some(9);
        REJECT_SIGNAL.store(binding.semaphore_for_test() as usize, Ordering::Release);
        let controller = match binding.read_region(0, 8) {
            Err(Failure::Unlock {
                error: SUPPORT,
                controller: Some(error),
                io: Some(Error(9)),
                arbitration: None,
                completion: None,
            }) => error,
            other => panic!("distinct original port and unlock failures required: {other:?}"),
        };
        assert_eq!(controller.kind, ec::ErrorKind::Io);
        assert_eq!(binding.failed_controller_error(), Some(controller));
        assert_eq!(
            binding.failed_controller_diagnostics(),
            Some(ec::binding::Diagnostics {
                controller: Some(controller),
                io: Some(Error(9)),
                arbitration: None,
                synchronization: Some(SUPPORT),
            })
        );
        assert!(binding.diagnostics().is_err());
        assert_eq!(binding.failed_completion(), None);
        assert_eq!(binding.read_region(0, 8), Err(Failure::Removed));
        REJECT_SIGNAL.store(0, Ordering::Release);
        drop(binding);
        session.shutdown().unwrap();
        assert!(counts.destroyed.load(Ordering::Acquire));

        // Historical observations remain diagnostic history, but a subsequent
        // successful operation must not attribute them as its current cause.
        let (provider, counts) = fixture_ec(false);
        let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
        let device = Device::discover(session.devices("PNP0C09").unwrap()[0]).unwrap();
        let binding =
            unsafe { Binding::install(device, ec::Config::default(), Scope::Device) }.unwrap();
        EC.lock().unwrap().as_mut().unwrap().read_error = Some(9);
        assert!(matches!(
            binding.read_region(0, 8),
            Err(Failure::Controller(_))
        ));
        assert_eq!(binding.diagnostics().unwrap().io, Some(Error(9)));
        REJECT_SIGNAL.store(binding.semaphore_for_test() as usize, Ordering::Release);
        assert_eq!(
            binding.read_region(0, 8),
            Err(Failure::Unlock {
                error: SUPPORT,
                controller: None,
                io: None,
                arbitration: None,
                completion: Some(ec::binding::Completion {
                    operation: ec::binding::Operation::Read,
                    address: 0,
                    width: 8,
                    value: 0x44
                }),
            })
        );
        REJECT_SIGNAL.store(0, Ordering::Release);
        drop(binding);
        session.shutdown().unwrap();
        assert!(counts.destroyed.load(Ordering::Acquire));
    }
    #[test]
    fn native_installed_ec_each_failed_release_returns_its_own_completed_read() {
        use ec::binding::{Completion, Operation};
        let _serial = TEST_SERIAL.lock().unwrap();
        let (provider, counts) = fixture_ec(false);
        let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
        let device = Device::discover(session.devices("PNP0C09").unwrap()[0]).unwrap();
        let binding =
            unsafe { Binding::install(device, ec::Config::default(), Scope::Device) }.unwrap();
        NESTED_SEMAPHORE.store(binding.semaphore_for_test() as usize, Ordering::Release);
        NESTED_CONTEXT.store(binding.context_for_test() as usize, Ordering::Release);
        NESTED_RAM_VALUE.store(0x55, Ordering::Release);
        NESTED_OUTER_ERROR.store(LIMIT.0 as usize, Ordering::Release);
        REJECT_AFTER_SIGNAL.store(true, Ordering::Release);
        let completed = |value| Completion {
            operation: Operation::Read,
            address: 0,
            width: 8,
            value,
        };
        assert_eq!(
            binding.read_region(0, 8),
            Err(Failure::Unlock {
                error: LIMIT,
                controller: None,
                io: None,
                arbitration: None,
                completion: Some(completed(0x44)),
            })
        );
        assert_eq!(
            *NESTED_FAILURE.lock().unwrap(),
            Some(Failure::Unlock {
                error: SUPPORT,
                controller: None,
                io: None,
                arbitration: None,
                completion: Some(completed(0x55)),
            })
        );
        // B's actual release failed first. Its immutable diagnostic does not
        // replace A's independently returned actual data/effect receipt.
        assert_eq!(binding.failed_completion(), Some(completed(0x55)));
        assert_eq!(binding.synchronization_error(), Some(LIMIT));
        let before = EC.lock().unwrap().as_ref().unwrap().commands.len();
        assert_eq!(binding.read_region(0, 8), Err(Failure::Removed));
        assert_eq!(EC.lock().unwrap().as_ref().unwrap().commands.len(), before);
        drop(binding);
        session.shutdown().unwrap();
        assert!(counts.destroyed.load(Ordering::Acquire));
    }
    #[test]
    fn native_installed_ec_dependency_cannot_reopen_after_actual_callback_unlock_failure() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let (provider, counts) = fixture_ec(false);
        let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
        let device = Device::discover(session.devices("PNP0C09").unwrap()[0]).unwrap();
        let binding =
            unsafe { Binding::install(device, ec::Config::default(), Scope::Device) }.unwrap();
        NESTED_SEMAPHORE.store(binding.semaphore_for_test() as usize, Ordering::Release);
        NESTED_CONTEXT.store(binding.context_for_test() as usize, Ordering::Release);
        // The actual validation releases its semaphore. Before that release
        // returns, the provider runs another actual read whose unlock fails.
        assert!(binding.supplier().is_err());
        assert_eq!(
            *NESTED_FAILURE.lock().unwrap(),
            Some(Failure::Unlock {
                error: SUPPORT,
                controller: None,
                io: None,
                arbitration: None,
                completion: Some(ec::binding::Completion {
                    operation: ec::binding::Operation::Read,
                    address: 0,
                    width: 8,
                    value: 0x44,
                }),
            })
        );
        assert_eq!(
            binding.failed_completion(),
            Some(ec::binding::Completion {
                operation: ec::binding::Operation::Read,
                address: 0,
                width: 8,
                value: 0x44
            })
        );
        assert_eq!(binding.synchronization_error(), Some(SUPPORT));
        let before = EC.lock().unwrap().as_ref().unwrap().commands.len();
        assert!(binding.supplier().is_err());
        assert_eq!(binding.read_region(0, 8), Err(Failure::Removed));
        assert_eq!(EC.lock().unwrap().as_ref().unwrap().commands.len(), before);
        drop(binding);
        session.shutdown().unwrap();
        assert!(counts.destroyed.load(Ordering::Acquire));
    }
    #[test]
    fn native_installed_ec_dependency_shutdown_retains_storage_and_quarantines_io() {
        let _serial = TEST_SERIAL.lock().unwrap();
        if std::env::var_os("STELA_EC_DEPENDENCY_SHUTDOWN_CHILD").is_some() {
            let (provider, counts) = fixture_ec_legacy(true);
            let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
            let device = Device::discover(session.devices("PNP0C09").unwrap()[0]).unwrap();
            let binding =
                unsafe { Binding::install(device, ec::Config::default(), Scope::Device) }.unwrap();
            session.enable_hardware().unwrap();
            let context = binding.context_for_test();
            let supplier = binding.supplier().unwrap();
            let consumer = supplier.native_pin();
            drop(supplier);
            core::mem::forget(binding);
            assert_eq!(FACS[4].load(Ordering::Acquire) & 3, 0);
            assert_eq!(session.shutdown(), Err(SUPPORT));
            assert!(!counts.destroyed.load(Ordering::Acquire));
            assert!(unsafe { stela_acpi_namespace_valid() } != 0);
            let before = EC.lock().unwrap().as_ref().unwrap().commands.len();
            assert_eq!(
                unsafe { ec::binding::read_after_quiescence_for_test(context) },
                Err(Failure::Removed)
            );
            assert_eq!(EC.lock().unwrap().as_ref().unwrap().commands.len(), before);
            drop(consumer);
            let (other, _) = fixture();
            assert!(matches!(
                unsafe { Session::start(other, Mode::InterpreterOnly) },
                Err(ALREADY_EXISTS)
            ));
            return;
        }
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "platform::acpi::tests::ec_binding_tests::native_installed_ec_dependency_shutdown_retains_storage_and_quarantines_io"])
            .env("STELA_EC_DEPENDENCY_SHUTDOWN_CHILD", "1").status().unwrap();
        assert!(result.success());
    }
    #[test]
    fn native_installed_ec_dependency_requires_actual_activation_and_retains_owner() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let (provider, counts) = fixture_ec_legacy(true);
        let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
        let device = Device::discover(session.devices("PNP0C09").unwrap()[0]).unwrap();
        let binding =
            unsafe { Binding::install(device, ec::Config::default(), Scope::Device) }.unwrap();
        assert!(matches!(
            binding.supplier(),
            Err(resources::Error::Unassigned)
        ));
        assert!(EC.lock().unwrap().as_ref().unwrap().commands.is_empty());
        session.enable_hardware().unwrap();
        let supplier = binding.supplier().unwrap();
        assert_eq!(supplier.handle(), device.handle);
        let consumer = supplier.native_pin();
        drop(supplier);
        assert_eq!(binding.remove(), Err(SUPPORT));
        assert_eq!(
            device.handle.evaluate(Some("READ"), &[]),
            Ok(Some(Value::Integer(0x33))),
            "retained consumer still reaches the original live byte owner after refused removal"
        );
        drop(consumer);
        session.shutdown().unwrap();
        assert!(counts.destroyed.load(Ordering::Acquire));
        assert_eq!(SEMAPHORES.load(Ordering::Acquire), 0);

        let (provider, counts) = fixture_ec(false);
        let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
        let device = Device::discover(session.devices("PNP0C09").unwrap()[0]).unwrap();
        let binding =
            unsafe { Binding::install(device, ec::Config::default(), Scope::Device) }.unwrap();
        drop(binding.supplier().unwrap());
        LATE_DATA.store(true, Ordering::Release);
        assert!(binding.read_region(0, 8).is_err());
        let before = EC.lock().unwrap().as_ref().unwrap().commands.len();
        assert!(
            binding.supplier().is_err(),
            "aggregate _REG success cannot republish a quarantined controller"
        );
        assert_eq!(EC.lock().unwrap().as_ref().unwrap().commands.len(), before);
        drop(binding);
        session.shutdown().unwrap();
        assert!(counts.destroyed.load(Ordering::Acquire));
    }
    #[test]
    fn native_installed_ec_quiescence_rechecks_actual_ownership_before_termination() {
        let _serial = TEST_SERIAL.lock().unwrap();
        if std::env::var_os("STELA_EC_QUIESCENCE_OWNER_CHILD").is_some() {
            let (provider, counts) = fixture_ec_legacy(true);
            let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
            let device = Device::discover(session.devices("PNP0C09").unwrap()[0]).unwrap();
            let binding =
                unsafe { Binding::install(device, ec::Config::default(), Scope::Device) }.unwrap();
            session.enable_hardware().unwrap();
            let context = binding.context_for_test();
            let actual_locks = device.handle.ec_lock_count();
            assert_eq!(actual_locks.load(Ordering::Acquire), 0);
            // Admit an actual native work callback while the provider is live.
            // It acquires/retains the real ACPICA token + namespace lease only
            // when shutdown quiescence drains it after Session's initial check.
            assert_eq!(
                unsafe {
                    (provider.execute)(
                        provider.context,
                        0,
                        ec::binding::hold_global_lock_for_test,
                        context,
                    )
                },
                0
            );
            core::mem::forget(binding);
            assert_eq!(actual_locks.load(Ordering::Acquire), 0);
            assert_eq!(session.shutdown(), Err(SUPPORT));
            assert_eq!(
                actual_locks.load(Ordering::Acquire),
                1,
                "counter changed only through actual ACPICA lock acquisition"
            );
            assert_eq!(
                FACS[4].load(Ordering::Acquire) & 3,
                2,
                "actual retained firmware Owned bit prevents termination"
            );
            assert!(!counts.destroyed.load(Ordering::Acquire));
            assert!(
                unsafe { stela_acpi_namespace_valid() } != 0,
                "live namespace/core retained with actual outstanding lease"
            );
            let commands = EC.lock().unwrap().as_ref().unwrap().commands.len();
            assert_eq!(
                unsafe { ec::binding::read_after_quiescence_for_test(context) },
                Err(Failure::Removed)
            );
            assert_eq!(
                EC.lock().unwrap().as_ref().unwrap().commands.len(),
                commands
            );
            return;
        }
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "platform::acpi::tests::ec_binding_tests::native_installed_ec_quiescence_rechecks_actual_ownership_before_termination"])
            .env("STELA_EC_QUIESCENCE_OWNER_CHILD", "1").status().unwrap();
        assert!(result.success());
    }
    #[test]
    fn native_installed_ec_precedes_actual_hardware_activation_and_ini() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let (mut provider, counts) = fixture_ec(true);
        // SAFETY: this test still exclusively owns the unpublished table/provider.
        let platform = unsafe { &mut *provider.context.cast::<TestPlatform>() };
        let fadt = &mut platform
            .tables
            .iter_mut()
            .find(|(address, _)| *address == 0x3000)
            .unwrap()
            .1;
        let flags = u32::from_le_bytes(fadt[112..116].try_into().unwrap());
        fadt[112..116].copy_from_slice(&(flags | (1 << 20)).to_le_bytes());
        checksum(fadt, 9);
        // Reduced-hardware fixture genuinely needs no legacy SCI/PM register
        // callbacks; unsupported legacy requests still fail in the provider.
        provider.capabilities = FULL_CAPABILITIES;
        let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
        let device = Device::discover(session.devices("PNP0C09").unwrap()[0]).unwrap();
        let binding =
            unsafe { Binding::install(device, ec::Config::default(), Scope::FirstController) }
                .unwrap();
        assert_eq!(
            device.handle.evaluate(Some("REGN"), &[]),
            Ok(Some(Value::Integer(0)))
        );
        assert!(EC.lock().unwrap().as_ref().unwrap().commands.is_empty());
        assert!(
            binding.read_region(0, 8).is_err(),
            "uninitialized software mutex cannot authorize firmware-dependent I/O"
        );
        assert!(EC.lock().unwrap().as_ref().unwrap().commands.is_empty());
        assert_eq!(
            device.handle.evaluate(Some("INI0"), &[]),
            Ok(Some(Value::Integer(0)))
        );
        assert!(!session.hardware_enabled());
        // This must compile with the retained Binding/Handle still borrowing
        // Session: activation mutates only the BSP facade's existing Cell state.
        session.enable_hardware().unwrap();
        assert!(session.hardware_enabled());
        assert_eq!(
            device.handle.evaluate(Some("INI0"), &[]),
            Ok(Some(Value::Integer(1)))
        );
        assert_eq!(
            binding.read_region(0, 8),
            Ok(0x33),
            "actual _INI used the installed EC region"
        );
        session.enable_hardware().unwrap();
        assert_eq!(
            device.handle.evaluate(Some("INI0"), &[]),
            Ok(Some(Value::Integer(1)))
        );
        binding.remove().unwrap();
        session.shutdown().unwrap();
        assert!(counts.destroyed.load(Ordering::SeqCst));
        assert_eq!(SEMAPHORES.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn native_installed_ec_failed_sci_activation_never_connects_or_retries() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let (provider, counts) = fixture_ec_legacy(true);
        LEGACY.lock().unwrap().as_mut().unwrap().refuse_sci = true;
        let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
        let device = Device::discover(session.devices("PNP0C09").unwrap()[0]).unwrap();
        let binding =
            unsafe { Binding::install(device, ec::Config::default(), Scope::Device) }.unwrap();
        assert_eq!(session.enable_hardware(), Err(SUPPORT));
        assert!(!session.hardware_enabled());
        assert_eq!(session.enable_hardware(), Err(SUPPORT));
        assert_eq!(LEGACY.lock().unwrap().as_ref().unwrap().install_attempts, 1);
        for name in ["REGN", "INI0"] {
            assert_eq!(
                device.handle.evaluate(Some(name), &[]),
                Ok(Some(Value::Integer(0)))
            );
        }
        assert!(binding.read_region(0, 8).is_err());
        assert!(EC.lock().unwrap().as_ref().unwrap().commands.is_empty());
        assert_eq!(FACS[4].load(Ordering::Acquire) & 3, 0);
        binding.remove().unwrap();
        session.shutdown().unwrap();
        assert!(counts.destroyed.load(Ordering::Acquire));
        assert_eq!(SEMAPHORES.load(Ordering::Acquire), 0);
    }
    #[test]
    fn native_installed_ec_primary_late_byte_and_unlock_error_both_survive() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let (provider, counts) = fixture_ec(false);
        let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
        let device = Device::discover(session.devices("PNP0C09").unwrap()[0]).unwrap();
        let binding =
            unsafe { Binding::install(device, ec::Config::default(), Scope::Device) }.unwrap();
        LATE_DATA.store(true, Ordering::Release);
        REJECT_SIGNAL.store(binding.semaphore_for_test() as usize, Ordering::Release);
        let error = match binding.read_region(0, 8) {
            Err(Failure::Unlock {
                error: SUPPORT,
                controller: Some(error),
                io: None,
                arbitration: None,
                completion: None,
            }) => error,
            other => panic!("actual late read plus unlock failure required: {other:?}"),
        };
        assert_eq!(error.kind, ec::ErrorKind::Timeout(ec::Phase::Output));
        assert_eq!(error.last_data.unwrap().value, 0x44);
        assert!(error.published);
        assert_eq!(binding.failed_controller_error(), Some(error));
        assert_eq!(binding.synchronization_error(), Some(SUPPORT));
        assert_eq!(binding.failed_completion(), None);
        assert_eq!(binding.read_region(0, 8), Err(Failure::Removed));
        REJECT_SIGNAL.store(0, Ordering::Release);
        drop(binding);
        session.shutdown().unwrap();
        assert!(counts.destroyed.load(Ordering::SeqCst));
        assert_eq!(SEMAPHORES.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn native_installed_ec_subtracts_actual_raw_timer_before_unit_conversion() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let (provider, counts) = fixture_ec(false);
        let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
        let device = Device::discover(session.devices("PNP0C09").unwrap()[0]).unwrap();
        let config = ec::Config {
            polling_guard_us: 0,
            ..ec::Config::default()
        };
        let binding = unsafe { Binding::install(device, config, Scope::Device) }.unwrap();
        RAW_TIME.store(u64::MAX - 50, Ordering::Release);
        assert_eq!(binding.read_region(0, 32), Ok(0x44));
        assert!(
            RAW_TIME.load(Ordering::Acquire) < 10_000,
            "actual OSL timer crossed raw rollover"
        );
        let before = CREATED.load(Ordering::Acquire);
        assert!(matches!(
            unsafe {
                Binding::install(
                    device,
                    ec::Config {
                        lock_timeout_us: u64::MAX,
                        ..config
                    },
                    Scope::Device,
                )
            },
            Err(Failure::Controller(ec::Error {
                kind: ec::ErrorKind::InvalidConfiguration,
                ..
            }))
        ));
        assert_eq!(
            CREATED.load(Ordering::Acquire),
            before,
            "unrepresentable native duration refused before resource or device effects"
        );
        binding.remove().unwrap();
        session.shutdown().unwrap();
        assert!(counts.destroyed.load(Ordering::SeqCst));
        assert_eq!(SEMAPHORES.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn native_installed_ec_failed_registration_and_retirement_pin_original_provider() {
        let _serial = TEST_SERIAL.lock().unwrap();
        if std::env::var_os("STELA_EC_REGISTRATION_FAILURE_CHILD").is_some() {
            let (provider, counts) = fixture_ec(false);
            let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
            let device = Device::discover(session.devices("PNP0C09").unwrap()[0]).unwrap();
            // Target-validation and registration namespace leases succeed;
            // retained-context allocation fails, then actual semaphore deletion.
            ALLOCATION_ATTEMPTS.store(0, Ordering::Release);
            FAIL_ALLOCATION.store(3, Ordering::Release);
            REJECT_NEW_SEMAPHORE_DELETE.store(true, Ordering::Release);
            let result = unsafe { Binding::install(device, ec::Config::default(), Scope::Device) };
            assert_eq!(
                result.err(),
                Some(Failure::Retirement {
                    registration: Error(4),
                    retirement: SUPPORT
                })
            );
            FAIL_ALLOCATION.store(0, Ordering::Release);
            assert_eq!(ALLOCATION_ATTEMPTS.load(Ordering::Acquire), 3);
            assert_eq!(session.shutdown(), Err(SUPPORT));
            assert!(!counts.destroyed.load(Ordering::SeqCst));
            assert!(SEMAPHORES.load(Ordering::SeqCst) > 0);
            let (other, _) = fixture();
            assert!(matches!(
                unsafe { Session::start(other, Mode::InterpreterOnly) },
                Err(ALREADY_EXISTS)
            ));
            return;
        }
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "platform::acpi::tests::ec_binding_tests::native_installed_ec_failed_registration_and_retirement_pin_original_provider"])
            .env("STELA_EC_REGISTRATION_FAILURE_CHILD", "1").status().unwrap();
        assert!(result.success());
    }
    #[test]
    fn native_installed_ec_unlock_failure_preserves_consumed_event_and_completed_io() {
        use crate::platform::ec::binding::{Completion, Operation};
        let _serial = TEST_SERIAL.lock().unwrap();
        for operation in [Operation::Query, Operation::Read, Operation::Write] {
            let (provider, counts) = fixture_ec(false);
            let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
            let device = Device::discover(session.devices("PNP0C09").unwrap()[0]).unwrap();
            let binding =
                unsafe { Binding::install(device, ec::Config::default(), Scope::Device) }.unwrap();
            EC.lock().unwrap().as_mut().unwrap().queries.push_back(0xae);
            REJECT_SIGNAL.store(binding.semaphore_for_test() as usize, Ordering::Release);
            let (result, expected) = match operation {
                Operation::Query => (
                    binding.poll_query().map(|_| ()),
                    Completion {
                        operation,
                        address: 0,
                        width: 0,
                        value: 0xae,
                    },
                ),
                Operation::Read => (
                    binding.read_region(0, 8).map(|_| ()),
                    Completion {
                        operation,
                        address: 0,
                        width: 8,
                        value: 0x44,
                    },
                ),
                Operation::Write => (
                    binding.write_region(0, 8, 0x51),
                    Completion {
                        operation,
                        address: 0,
                        width: 8,
                        value: 0x51,
                    },
                ),
            };
            assert_eq!(
                result,
                Err(Failure::Unlock {
                    error: SUPPORT,
                    controller: None,
                    io: None,
                    arbitration: None,
                    completion: Some(expected),
                })
            );
            assert_eq!(binding.synchronization_error(), Some(SUPPORT));
            assert_eq!(binding.failed_completion(), Some(expected));
            let commands = EC.lock().unwrap().as_ref().unwrap().commands.len();
            assert_eq!(binding.read_region(0, 8), Err(Failure::Removed));
            assert_eq!(
                EC.lock().unwrap().as_ref().unwrap().commands.len(),
                commands
            );
            if operation == Operation::Query {
                let event = binding.take_pending_event().unwrap();
                assert_eq!(event.value(), 0xae);
                event.dispatch().unwrap();
                assert!(binding.take_pending_event().is_none());
                assert_eq!(
                    device.handle.evaluate(Some("CNT0"), &[]),
                    Ok(Some(Value::Integer(1)))
                );
            } else {
                assert!(binding.take_pending_event().is_none());
            }
            REJECT_SIGNAL.store(0, Ordering::Release);
            drop(binding);
            session.shutdown().unwrap();
            assert!(counts.destroyed.load(Ordering::SeqCst));
            assert_eq!(SEMAPHORES.load(Ordering::SeqCst), 0);
        }
    }
    use super::*;
    use crate::platform::acpi::resources;
    use crate::platform::ec::{
        self,
        binding::{Binding, Failure, Scope},
        discovery::native::Device,
    };

    struct Peripheral {
        ram: [u8; 256],
        command: u8,
        address: Option<u8>,
        output: Option<u8>,
        burst: bool,
        queries: VecDeque<u8>,
        commands: Vec<u8>,
        fail_read: bool,
        read_error: Option<Status>,
        required_lock_count: Option<Arc<AtomicUsize>>,
        require_facs: bool,
    }
    static EC: Mutex<Option<Peripheral>> = Mutex::new(None);
    static SEMAPHORES: AtomicUsize = AtomicUsize::new(0);
    static CREATED: AtomicUsize = AtomicUsize::new(0);
    static DELETED: AtomicUsize = AtomicUsize::new(0);
    static REJECT_DELETE: AtomicUsize = AtomicUsize::new(0);
    static REJECT_SIGNAL: AtomicUsize = AtomicUsize::new(0);
    static REJECT_NEW_SEMAPHORE_DELETE: AtomicBool = AtomicBool::new(false);
    static FAIL_ALLOCATION: AtomicUsize = AtomicUsize::new(0);
    static ALLOCATION_ATTEMPTS: AtomicUsize = AtomicUsize::new(0);
    static RAW_TIME: AtomicU64 = AtomicU64::new(0);
    static LATE_DATA: AtomicBool = AtomicBool::new(false);
    static NESTED_CONTEXT: AtomicUsize = AtomicUsize::new(0);
    static NESTED_SEMAPHORE: AtomicUsize = AtomicUsize::new(0);
    static NESTED_FAILURE: Mutex<Option<Failure>> = Mutex::new(None);
    static REJECT_AFTER_SIGNAL: AtomicBool = AtomicBool::new(false);
    static NESTED_RAM_VALUE: AtomicUsize = AtomicUsize::new(256);
    static NESTED_OUTER_ERROR: AtomicUsize = AtomicUsize::new(0);
    // Actual mapped FACS storage has interior-mutability and native u32
    // alignment. ACPICA's production CAS operates directly on word 4.
    static FACS: [AtomicU32; 16] = [const { AtomicU32::new(0) }; 16];
    struct Legacy {
        status: u16,
        enable: u16,
        control: u16,
        sci: Option<(Interrupt, usize)>,
        refuse_sci: bool,
        install_attempts: usize,
    }
    static LEGACY: Mutex<Option<Legacy>> = Mutex::new(None);
    unsafe extern "C" fn legacy_map(p: *mut c_void, address: u64, length: u64) -> *mut c_void {
        if address < 0x5000 || address.checked_add(length).is_none_or(|end| end > 0x5040) {
            return unsafe { map(p, address, length) };
        }
        let raw = unsafe { FACS.as_ptr().cast::<u8>().add((address - 0x5000) as usize) }
            .cast_mut()
            .cast();
        let platform = unsafe { platform(p) };
        *platform
            .leases
            .lock()
            .unwrap()
            .entry((raw as usize, length))
            .or_default() += 1;
        platform.counts.mappings.fetch_add(1, Ordering::SeqCst);
        raw
    }
    unsafe extern "C" fn legacy_install_interrupt(
        _: *mut c_void,
        irq: u32,
        handler: Interrupt,
        context: *mut c_void,
    ) -> Status {
        assert_eq!(irq, 9, "actual FADT SCI route");
        let mut legacy = LEGACY.lock().unwrap();
        let legacy = legacy.as_mut().unwrap();
        legacy.install_attempts += 1;
        if legacy.refuse_sci {
            return SUPPORT.0;
        }
        assert!(legacy.sci.replace((handler, context as usize)).is_none());
        0
    }
    unsafe extern "C" fn legacy_remove_interrupt(
        _: *mut c_void,
        irq: u32,
        handler: Interrupt,
    ) -> Status {
        assert_eq!(irq, 9);
        let mut legacy = LEGACY.lock().unwrap();
        let legacy = legacy.as_mut().unwrap();
        if let Some((installed, _)) = legacy.sci.take() {
            assert!(core::ptr::fn_addr_eq(installed, handler));
        }
        0
    }
    fn legacy_port(port: u64, width: u32, write: Option<u32>) -> Option<u32> {
        if !matches!(width, 8 | 16 | 32) || port < 0x1000 || port + u64::from(width / 8) > 0x1006 {
            return None;
        }
        let mut legacy = LEGACY.lock().unwrap();
        let legacy = legacy.as_mut()?;
        let mut bytes = [0; 6];
        bytes[..2].copy_from_slice(&legacy.status.to_le_bytes());
        bytes[2..4].copy_from_slice(&legacy.enable.to_le_bytes());
        bytes[4..].copy_from_slice(&legacy.control.to_le_bytes());
        let offset = (port - 0x1000) as usize;
        let length = (width / 8) as usize;
        let mut result = [0; 4];
        result[..length].copy_from_slice(&bytes[offset..offset + length]);
        if let Some(value) = write {
            for (i, byte) in value.to_le_bytes().iter().copied().enumerate().take(length) {
                if offset + i < 2 {
                    bytes[offset + i] &= !byte;
                }
                // PM status W1C.
                else {
                    bytes[offset + i] = byte;
                }
            }
            legacy.status = u16::from_le_bytes(bytes[..2].try_into().unwrap());
            legacy.enable = u16::from_le_bytes(bytes[2..4].try_into().unwrap());
            legacy.control = u16::from_le_bytes(bytes[4..].try_into().unwrap());
        }
        Some(u32::from_le_bytes(result))
    }
    unsafe extern "C" fn ec_timer(_: *mut c_void) -> u64 {
        RAW_TIME.fetch_add(1, Ordering::AcqRel)
    }
    unsafe extern "C" fn ec_stall(_: *mut c_void, microseconds: u32) {
        RAW_TIME.fetch_add(u64::from(microseconds) * 10, Ordering::AcqRel);
    }
    unsafe extern "C" fn ec_allocate(p: *mut c_void, bytes: u64) -> *mut c_void {
        let failure = FAIL_ALLOCATION.load(Ordering::Acquire);
        if failure != 0 && ALLOCATION_ATTEMPTS.fetch_add(1, Ordering::AcqRel) + 1 == failure {
            return ptr::null_mut();
        }
        unsafe { allocate(p, bytes) }
    }
    unsafe extern "C" fn ec_signal_semaphore(
        p: *mut c_void,
        semaphore: *mut c_void,
        units: u32,
    ) -> Status {
        let rejected = REJECT_SIGNAL.load(Ordering::Acquire) == semaphore as usize;
        if rejected && !REJECT_AFTER_SIGNAL.load(Ordering::Acquire) {
            return SUPPORT.0;
        }
        let status = unsafe { signal_semaphore(p, semaphore, units) };
        if status == 0 && rejected {
            return SUPPORT.0; // The actual release applied before its error.
        }
        let context =
            if status == 0 && NESTED_SEMAPHORE.load(Ordering::Acquire) == semaphore as usize {
                NESTED_CONTEXT.swap(0, Ordering::AcqRel)
            } else {
                0
            };
        if context != 0 {
            let value = NESTED_RAM_VALUE.load(Ordering::Acquire);
            if value <= 255 {
                // Authored peripheral change between the two actual EC reads.
                EC.lock().unwrap().as_mut().unwrap().ram[0] = value as u8;
            }
            REJECT_SIGNAL.store(semaphore as usize, Ordering::Release);
            let result =
                unsafe { ec::binding::read_after_quiescence_for_test(context as *mut c_void) };
            *NESTED_FAILURE.lock().unwrap() = result.err();
            REJECT_SIGNAL.store(0, Ordering::Release);
            let error = NESTED_OUTER_ERROR.swap(0, Ordering::AcqRel);
            if error != 0 {
                return error as Status;
            }
        }
        status
    }
    unsafe extern "C" fn ec_read_port(
        p: *mut c_void,
        port: u64,
        out: *mut u32,
        width: u32,
    ) -> Status {
        if width != 8 || !matches!(port, 0x72 | 0x76) {
            if let Some(value) = legacy_port(port, width, None) {
                unsafe { out.write(value) };
                return 0;
            }
            return unsafe { read_port(p, port, out, width) };
        }
        let mut ec = EC.lock().unwrap();
        let ec = ec.as_mut().unwrap();
        if ec.require_facs {
            assert_eq!(
                FACS[4].load(Ordering::Acquire) & 3,
                2,
                "actual firmware FACS Owned bit across every EC read"
            );
        }
        if let Some(count) = &ec.required_lock_count {
            assert_eq!(
                count.load(Ordering::Acquire),
                1,
                "actual ACPICA global lock held across every EC read"
            );
        }
        if let Some(error) = ec.read_error.take() {
            return error;
        }
        if ec.fail_read {
            ec.fail_read = false;
            return 0x0f;
        }
        let value = if port == 0x76 {
            u8::from(ec.output.is_some())
                | if ec.burst { 0x10 } else { 0 }
                | if ec.queries.is_empty() { 0 } else { 0x20 }
        } else {
            ec.output.take().expect("actual OBF")
        };
        RAW_TIME.fetch_add(10, Ordering::AcqRel);
        if port == 0x72 && LATE_DATA.swap(false, Ordering::AcqRel) {
            RAW_TIME.fetch_add(5_000_000, Ordering::AcqRel);
        }
        unsafe { out.write(u32::from(value)) };
        0
    }
    unsafe extern "C" fn ec_write_port(
        p: *mut c_void,
        port: u64,
        value: u32,
        width: u32,
    ) -> Status {
        if width != 8 || !matches!(port, 0x72 | 0x76) {
            if legacy_port(port, width, Some(value)).is_some() {
                return 0;
            }
            return unsafe { write_port(p, port, value, width) };
        }
        let value = u8::try_from(value).unwrap();
        RAW_TIME.fetch_add(10, Ordering::AcqRel);
        let mut ec = EC.lock().unwrap();
        let ec = ec.as_mut().unwrap();
        if ec.require_facs {
            assert_eq!(
                FACS[4].load(Ordering::Acquire) & 3,
                2,
                "actual firmware FACS Owned bit across every EC write"
            );
        }
        if let Some(count) = &ec.required_lock_count {
            assert_eq!(
                count.load(Ordering::Acquire),
                1,
                "actual ACPICA global lock held across every EC write"
            );
        }
        if port == 0x76 {
            assert!(ec.output.is_none());
            ec.commands.push(value);
            ec.command = value;
            ec.address = None;
            if value == 0x84 {
                ec.output = Some(ec.queries.pop_front().unwrap_or(0));
            } else if value == 0x82 {
                ec.burst = true;
                ec.output = Some(0x90);
            } else if value == 0x83 {
                ec.burst = false;
            } else {
                assert!(matches!(value, 0x80 | 0x81));
            }
        } else if let Some(address) = ec.address {
            assert_eq!(ec.command, 0x81);
            ec.ram[usize::from(address)] = value;
        } else {
            ec.address = Some(value);
            if ec.command == 0x80 {
                ec.output = Some(ec.ram[usize::from(value)]);
            } else {
                assert_eq!(ec.command, 0x81);
            }
        }
        0
    }
    unsafe extern "C" fn ec_create_semaphore(
        p: *mut c_void,
        max: u32,
        initial: u32,
        out: *mut *mut c_void,
    ) -> Status {
        let status = unsafe { create_semaphore(p, max, initial, out) };
        if status == 0 {
            if REJECT_NEW_SEMAPHORE_DELETE.swap(false, Ordering::AcqRel) {
                REJECT_DELETE.store(unsafe { *out } as usize, Ordering::Release);
            }
            SEMAPHORES.fetch_add(1, Ordering::SeqCst);
            CREATED.fetch_add(1, Ordering::SeqCst);
        }
        status
    }
    unsafe extern "C" fn ec_delete_semaphore(p: *mut c_void, semaphore: *mut c_void) -> Status {
        assert!(
            !unsafe { platform(p) }
                .counts
                .destroyed
                .load(Ordering::SeqCst)
        );
        if REJECT_DELETE.load(Ordering::Acquire) == semaphore as usize {
            return SUPPORT.0;
        }
        let status = unsafe { delete_semaphore(p, semaphore) };
        if status == 0 {
            SEMAPHORES.fetch_sub(1, Ordering::SeqCst);
            DELETED.fetch_add(1, Ordering::SeqCst);
        }
        status
    }
    fn pkg(op: &[u8], body: &[u8]) -> Vec<u8> {
        let mut bytes = op.to_vec();
        let length = body.len() + if body.len() + 1 < 64 { 1 } else { 2 };
        assert!(length < 4096);
        if length < 64 {
            bytes.push(length as u8);
        } else {
            bytes.extend([0x40 | (length as u8 & 15), (length >> 4) as u8]);
        }
        bytes.extend(body);
        bytes
    }
    fn name(id: &[u8; 4], value: &[u8]) -> Vec<u8> {
        let mut bytes = vec![8];
        bytes.extend(id);
        bytes.extend(value);
        bytes
    }
    fn method(id: &[u8; 4], arguments: u8, body: &[u8]) -> Vec<u8> {
        let mut bytes = id.to_vec();
        bytes.push(8 | arguments);
        bytes.extend(body);
        pkg(&[0x14], &bytes)
    }
    fn fixture_ec(global_lock: bool) -> (Services, Arc<Counts>) {
        SEMAPHORES.store(0, Ordering::SeqCst);
        CREATED.store(0, Ordering::SeqCst);
        DELETED.store(0, Ordering::SeqCst);
        REJECT_DELETE.store(0, Ordering::SeqCst);
        REJECT_SIGNAL.store(0, Ordering::SeqCst);
        REJECT_NEW_SEMAPHORE_DELETE.store(false, Ordering::SeqCst);
        FAIL_ALLOCATION.store(0, Ordering::SeqCst);
        ALLOCATION_ATTEMPTS.store(0, Ordering::SeqCst);
        RAW_TIME.store(0, Ordering::SeqCst);
        LATE_DATA.store(false, Ordering::SeqCst);
        NESTED_CONTEXT.store(0, Ordering::SeqCst);
        NESTED_SEMAPHORE.store(0, Ordering::SeqCst);
        *NESTED_FAILURE.lock().unwrap() = None;
        REJECT_AFTER_SIGNAL.store(false, Ordering::SeqCst);
        NESTED_RAM_VALUE.store(256, Ordering::SeqCst);
        NESTED_OUTER_ERROR.store(0, Ordering::SeqCst);
        *LEGACY.lock().unwrap() = None;
        *EC.lock().unwrap() = Some(Peripheral {
            ram: [0; 256],
            command: 0,
            address: None,
            output: None,
            burst: false,
            queries: VecDeque::new(),
            commands: Vec::new(),
            fail_read: false,
            read_error: None,
            required_lock_count: None,
            require_facs: false,
        });
        let resources = [
            0x47, 1, 0x72, 0, 0x72, 0, 1, 1, 0x47, 1, 0x76, 0, 0x76, 0, 1, 1, 0x79, 0,
        ];
        let mut buffer = vec![0x0a, resources.len() as u8];
        buffer.extend(resources);
        let mut ec = b"EC00".to_vec();
        ec.extend(name(b"_HID", b"\x0dPNP0C09\0"));
        ec.extend(name(b"_CRS", &pkg(&[0x11], &buffer)));
        ec.extend(name(b"_GLK", &[u8::from(global_lock)]));
        ec.extend(name(b"REGN", &[0]));
        ec.extend(name(b"CNT0", &[0]));
        ec.extend(name(b"INI0", &[0]));
        ec.extend(b"\x5b\x80ECRG\x03\x00\x01");
        ec.extend(pkg(b"\x5b\x81", b"ECRG\x01BYTE\x08"));
        ec.extend(method(b"_REG", 2, b"\x70\x69REGN\x70\x0a\x44BYTE"));
        ec.extend(method(b"READ", 0, b"\xa4BYTE"));
        ec.extend(method(b"WRT0", 1, b"\x70\x68BYTE\xa4BYTE"));
        ec.extend(method(b"_QAB", 0, b"\x70\x0a\x55BYTE\x75CNT0\xa4\x00"));
        ec.extend(method(b"_QAE", 0, b"\x75CNT0\xa4\x00"));
        ec.extend(method(b"_INI", 0, b"\x70\x0a\x33BYTE\x75INI0"));
        let mut aml = pkg(b"\x5b\x82", &ec);
        let mut sibling = b"SIB0".to_vec();
        sibling.extend(name(b"REGN", &[0]));
        sibling.extend(method(b"_REG", 2, b"\x70\x69REGN"));
        sibling.extend(b"\x5b\x80ECR2\x03\x01\x01");
        sibling.extend(pkg(b"\x5b\x81", b"ECR2\x01VALU\x08"));
        sibling.extend(method(b"READ", 0, b"\xa4VALU"));
        aml.extend(pkg(b"\x5b\x82", &sibling));
        let mut dsdt = table(b"DSDT", 36 + aml.len(), 2);
        dsdt[36..].copy_from_slice(&aml);
        checksum(&mut dsdt, 9);
        let (mut provider, counts) = fixture_dsdt(dsdt);
        provider.read_port = ec_read_port;
        provider.write_port = ec_write_port;
        provider.create_semaphore = ec_create_semaphore;
        provider.delete_semaphore = ec_delete_semaphore;
        provider.signal_semaphore = ec_signal_semaphore;
        provider.allocate = ec_allocate;
        provider.timer = ec_timer;
        provider.stall = ec_stall;
        (provider, counts)
    }
    fn fixture_ec_legacy(global_lock: bool) -> (Services, Arc<Counts>) {
        let (mut provider, counts) = fixture_ec(global_lock);
        for word in &FACS {
            word.store(0, Ordering::Release);
        }
        FACS[0].store(u32::from_le_bytes(*b"FACS"), Ordering::Release);
        FACS[1].store(64, Ordering::Release);
        // SAFETY: the test exclusively owns unpublished provider/table storage.
        let platform = unsafe { &mut *provider.context.cast::<TestPlatform>() };
        let fadt = &mut platform
            .tables
            .iter_mut()
            .find(|(address, _)| *address == 0x3000)
            .unwrap()
            .1;
        fadt[36..40].copy_from_slice(&0x5000u32.to_le_bytes());
        fadt[132..140].copy_from_slice(&0x5000u64.to_le_bytes());
        checksum(fadt, 9);
        *LEGACY.lock().unwrap() = Some(Legacy {
            status: 0,
            enable: 0,
            control: 1,
            sci: None,
            refuse_sci: false,
            install_attempts: 0,
        });
        EC.lock().unwrap().as_mut().unwrap().require_facs = global_lock;
        provider.map = legacy_map;
        provider.install_interrupt = legacy_install_interrupt;
        provider.remove_interrupt = legacy_remove_interrupt;
        provider.capabilities = FULL_CAPABILITIES;
        (provider, counts)
    }

    #[test]
    fn native_installed_ec_osl_transport_reg_query_and_retirement() {
        let _serial = TEST_SERIAL.lock().unwrap();
        for global_lock in [false, true] {
            let (provider, counts) = if global_lock {
                fixture_ec_legacy(true)
            } else {
                fixture_ec(false)
            };
            let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
            let handle = session.devices("PNP0C09").unwrap()[0];
            let found = Device::discover(handle).unwrap();
            if global_lock {
                EC.lock().unwrap().as_mut().unwrap().required_lock_count =
                    Some(handle.ec_lock_count());
            }
            assert_eq!(found.ports.data, 0x72);
            assert_eq!(found.ports.command, 0x76);
            assert!(handle.evaluate(Some("READ"), &[]).is_err());
            let config = ec::Config {
                polling_guard_us: 0,
                ..ec::Config::default()
            };
            let binding =
                unsafe { Binding::install(found, config, Scope::FirstController) }.unwrap();
            if global_lock {
                assert_eq!(
                    handle.evaluate(Some("REGN"), &[]),
                    Ok(Some(Value::Integer(0)))
                );
                assert!(
                    EC.lock().unwrap().as_ref().unwrap().commands.is_empty(),
                    "no eager _REG or EC effects before actual firmware arbitration setup"
                );
                assert!(matches!(
                    binding.read_region(0, 8),
                    Err(Failure::Controller(ec::Error {
                        kind: ec::ErrorKind::FirmwareLock,
                        ..
                    }))
                ));
                assert!(EC.lock().unwrap().as_ref().unwrap().commands.is_empty());
                session.enable_hardware().unwrap();
                assert!(LEGACY.lock().unwrap().as_ref().unwrap().sci.is_some());
                assert_ne!(
                    LEGACY.lock().unwrap().as_ref().unwrap().enable & 0x20,
                    0,
                    "actual Global Lock fixed-event enable sticks"
                );
                assert_eq!(
                    FACS[4].load(Ordering::Acquire) & 3,
                    0,
                    "actual FACS owner released after _REG and _INI"
                );
            }
            assert_eq!(
                session
                    .handle("\\SIB0")
                    .unwrap()
                    .evaluate(Some("REGN"), &[]),
                Ok(Some(Value::Integer(0))),
                "root EC coverage does not connect unrelated sibling _REG methods"
            );
            assert_eq!(
                handle.evaluate(Some("REGN"), &[]),
                Ok(Some(Value::Integer(1)))
            );
            assert_eq!(
                EC.lock().unwrap().as_ref().unwrap().ram[0],
                if global_lock { 0x33 } else { 0x44 },
                "actual _REG connects before the subsequent hardware-phase _INI"
            );
            assert_eq!(
                handle.evaluate(Some("WRT0"), &[Argument::Integer(0x31)]),
                Ok(Some(Value::Integer(0x31)))
            );
            assert_eq!(binding.read_region(0, 8), Ok(0x31));
            binding.write_region(2, 32, 0x12345678).unwrap();
            assert_eq!(binding.read_region(2, 32), Ok(0x12345678));
            {
                let peripheral = EC.lock().unwrap();
                let peripheral = peripheral.as_ref().unwrap();
                assert!(!peripheral.burst);
                assert!(
                    peripheral
                        .commands
                        .windows(6)
                        .any(|commands| commands == [0x82, 0x81, 0x81, 0x81, 0x81, 0x83])
                );
            }
            binding.write_region(1, 8, 0x77).unwrap();
            assert_eq!(
                session
                    .handle("\\SIB0")
                    .unwrap()
                    .evaluate(Some("READ"), &[]),
                Ok(Some(Value::Integer(0x77))),
                "first EC root handler covers actual sibling region"
            );
            EC.lock().unwrap().as_mut().unwrap().queries.push_back(0xab);
            let query = binding.poll_query().unwrap().unwrap();
            assert_eq!(query.value(), 0xab);
            assert_eq!(
                handle.ec_lock_count().load(Ordering::Acquire),
                0,
                "dispatch starts outside real EC/global lock"
            );
            query.dispatch().unwrap();
            assert_eq!(
                binding.read_region(0, 8),
                Ok(0x55),
                "_QAB reenters the same actual EC after owner/FACS lock release"
            );
            assert_eq!(
                handle.evaluate(Some("CNT0"), &[]),
                Ok(Some(Value::Integer(1)))
            );
            assert!(binding.poll_query().unwrap().is_none());
            let before = SEMAPHORES.load(Ordering::SeqCst);
            assert_eq!(
                unsafe { Binding::install(found, config, Scope::FirstController) }.err(),
                Some(Failure::Firmware(Error(0x19))), // actual ACPICA AE_SAME_HANDLER
            );
            assert_eq!(
                SEMAPHORES.load(Ordering::SeqCst),
                before + 1,
                "failed install storage remains retained until termination"
            );
            binding.remove().unwrap();
            assert_eq!(
                handle.evaluate(Some("REGN"), &[]),
                Ok(Some(Value::Integer(0)))
            );
            assert_eq!(
                EC.lock().unwrap().as_ref().unwrap().ram[0],
                0x44,
                "_REG disconnect still has actual EC transport"
            );
            assert!(handle.evaluate(Some("READ"), &[]).is_err());
            assert!(
                SEMAPHORES.load(Ordering::SeqCst) >= 2,
                "contexts remain through core callbacks"
            );
            session.shutdown().unwrap();
            assert!(counts.destroyed.load(Ordering::SeqCst));
            assert_eq!(
                SEMAPHORES.load(Ordering::SeqCst),
                0,
                "retire all driver/core semaphores before provider destruction"
            );
            assert_eq!(
                CREATED.load(Ordering::SeqCst),
                DELETED.load(Ordering::SeqCst)
            );
            assert_eq!(counts.allocations.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn native_installed_ec_failed_io_keeps_exact_controller_and_osl_errors() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let (provider, counts) = fixture_ec(false);
        let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
        let found = Device::discover(session.devices("PNP0C09").unwrap()[0]).unwrap();
        let binding = unsafe {
            Binding::install(
                found,
                ec::Config {
                    polling_guard_us: 0,
                    ..ec::Config::default()
                },
                Scope::Device,
            )
        }
        .unwrap();
        assert!(
            session
                .handle("\\SIB0")
                .unwrap()
                .evaluate(Some("READ"), &[])
                .is_err()
        );
        EC.lock().unwrap().as_mut().unwrap().fail_read = true;
        assert!(matches!(
            binding.read_region(0, 8),
            Err(Failure::Controller(ec::Error {
                kind: ec::ErrorKind::Io,
                ..
            }))
        ));
        let diagnostic = binding.diagnostics().unwrap();
        assert_eq!(diagnostic.io, Some(SUPPORT));
        assert_eq!(diagnostic.controller.unwrap().kind, ec::ErrorKind::Io);
        assert_eq!(diagnostic.arbitration, None);
        drop(binding);
        session.shutdown().unwrap();
        assert!(counts.destroyed.load(Ordering::SeqCst));
        assert_eq!(SEMAPHORES.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn native_installed_ec_failed_removal_retains_context_until_real_termination() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let (provider, counts) = fixture_ec(false);
        let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
        let device = Device::discover(session.devices("PNP0C09").unwrap()[0]).unwrap();
        let binding =
            unsafe { Binding::install(device, ec::Config::default(), Scope::Device) }.unwrap();
        binding.remove_from_core_for_test().unwrap();
        let before = SEMAPHORES.load(Ordering::SeqCst);
        assert!(binding.remove().is_err());
        assert_eq!(SEMAPHORES.load(Ordering::SeqCst), before);
        session.shutdown().unwrap();
        assert!(counts.destroyed.load(Ordering::SeqCst));
        assert_eq!(SEMAPHORES.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn native_installed_ec_retirement_failure_quarantines_provider_after_termination() {
        let _serial = TEST_SERIAL.lock().unwrap();
        if std::env::var_os("STELA_EC_RETIREMENT_FAILURE_CHILD").is_some() {
            let (provider, counts) = fixture_ec(false);
            let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
            let device = Device::discover(session.devices("PNP0C09").unwrap()[0]).unwrap();
            let binding =
                unsafe { Binding::install(device, ec::Config::default(), Scope::Device) }.unwrap();
            REJECT_DELETE.store(binding.semaphore_for_test() as usize, Ordering::Release);
            binding.remove().unwrap();
            assert_eq!(session.shutdown(), Err(SUPPORT));
            assert!(!counts.destroyed.load(Ordering::SeqCst));
            assert!(SEMAPHORES.load(Ordering::SeqCst) > 0);
            assert!(counts.allocations.load(Ordering::SeqCst) > 0);
            let (other, _) = fixture();
            assert!(matches!(
                unsafe { Session::start(other, Mode::InterpreterOnly) },
                Err(ALREADY_EXISTS)
            ));
            return;
        }
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "platform::acpi::tests::ec_binding_tests::native_installed_ec_retirement_failure_quarantines_provider_after_termination"])
            .env("STELA_EC_RETIREMENT_FAILURE_CHILD", "1").status().unwrap();
        assert!(result.success());
    }
}
