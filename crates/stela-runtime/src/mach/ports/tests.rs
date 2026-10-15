use super::*;

#[test]
fn pinned_reference_saturation_is_not_checked_overflow() {
    // Directed pinned boundary expectations; no second copy of the algorithm.
    for (before, delta, expected) in [
        (1, i32::MIN, None),
        (1, -65_536, None),
        (1, -65_535, None),
        (1, -2, None),
        (1, -1, Some(0)),
        (1, 0, Some(1)),
        (1, 1, Some(2)),
        (1, 65_535, Some(65_535)),
        (2, -3, None),
        (2, -2, Some(0)),
        (2, -1, Some(1)),
        (65_534, -65_534, Some(0)),
        (65_534, 1, Some(65_535)),
        (65_534, 65_535, Some(65_535)),
        (65_535, -65_535, Some(0)),
        (65_535, -65_534, Some(65_535)),
        (65_535, -1, Some(65_535)),
        (65_535, 0, Some(65_535)),
        (65_535, 1, Some(65_535)),
        (65_535, 65_535, Some(65_535)),
        (65_535, 65_536, None),
    ] {
        assert_eq!(
            reference_delta(before, delta),
            expected,
            "before={before} delta={delta}"
        );
    }
}

#[test]
fn port_prototypes_use_pinned_32_bit_scalars_and_full_pointer() {
    let pointer = 0x1234_5678_9abc_def0;
    assert_eq!(
        Operation::from_request(&Request {
            number: MOD_REFS_TRAP,
            arguments: vec![
                0xfeed_face_0000_0101,
                0xaaaa_bbbb_0000_0201,
                0x1234_5678_0000_0004,
                0x3333_4444_ffff_ffff
            ],
        })
        .unwrap(),
        Operation::ModRefs {
            task: 0x101,
            name: 0x201,
            right: 4,
            delta: -1
        }
    );
    assert_eq!(
        Operation::from_request(&Request {
            number: ALLOCATE_TRAP,
            arguments: vec![0x101, 1, pointer],
        })
        .unwrap(),
        Operation::Allocate {
            task: 0x101,
            right: 1,
            destination: pointer
        }
    );
    for (number, count) in [
        (ALLOCATE_TRAP, 3),
        (DEALLOCATE_TRAP, 2),
        (MOD_REFS_TRAP, 4),
        (TYPE_TRAP, 3),
    ] {
        for actual in [count - 1, count + 1] {
            assert!(
                Operation::from_request(&Request {
                    number,
                    arguments: vec![0; actual]
                })
                .is_err()
            );
        }
    }
    assert!(
        Operation::from_request(&Request {
            number: 17,
            arguments: vec![]
        })
        .is_err()
    );
}

#[test]
fn owned_type_bits_express_send_receive_without_host_metadata() {
    assert_eq!(RightState::SendReceive.type_bits(), (1 << 16) | (1 << 17));
    assert_eq!(RightState::DeadName.type_bits(), 1 << 20);
    for state in [
        RightState::Receive,
        RightState::Send,
        RightState::SendReceive,
        RightState::SendOnce,
        RightState::PortSet,
        RightState::DeadName,
    ] {
        assert_eq!(state.type_bits() & 0xe000_0000, 0);
    }
}

#[cfg(target_os = "macos")]
mod native {
    use super::*;

    #[test]
    fn host_rights_are_owned_and_guest_names_are_stable_and_distinct() {
        unsafe extern "C" {
            static mach_task_self_: u32;
            fn mach_port_get_refs(task: u32, name: u32, right: u32, refs: *mut u32) -> i32;
            fn thread_self_trap() -> u32;
            fn mach_port_deallocate(task: u32, name: u32) -> i32;
        }
        // Observe this test's current host thread, not task-wide references
        // concurrently acquired by unrelated tests. Retain one explicit query
        // reference until the owner has closed, then release it exactly once.
        // SAFETY: genuine current-task/thread names and private stack output.
        let task_host = unsafe { mach_task_self_ };
        let thread_host = unsafe { thread_self_trap() };
        assert_ne!(thread_host, MACH_PORT_NULL);
        let mut baseline = 0;
        assert_eq!(
            unsafe {
                mach_port_get_refs(
                    task_host,
                    thread_host,
                    RightKind::Send as u32,
                    &mut baseline,
                )
            },
            KERN_SUCCESS
        );
        let mut ports = HostPorts::new(123).unwrap();
        let task = ports
            .request(&Request {
                number: 28,
                arguments: vec![],
            })
            .unwrap();
        assert_eq!(
            task,
            ports
                .request(&Request {
                    number: 28,
                    arguments: vec![]
                })
                .unwrap()
        );
        let first = ports
            .request(&Request {
                number: 26,
                arguments: vec![],
            })
            .unwrap();
        let second = ports
            .request(&Request {
                number: 26,
                arguments: vec![],
            })
            .unwrap();
        assert_ne!(first, second);
        assert_ne!(first, task);
        assert_eq!(ports.rights()[0].references, 2);
        for number in [27, 29] {
            assert!(
                ports
                    .request(&Request {
                        number,
                        arguments: vec![]
                    })
                    .unwrap()
                    > 0
            );
        }
        let before = serde_json::to_string(ports.rights()).unwrap();
        assert!(
            ports
                .request(&Request {
                    number: 31,
                    arguments: vec![]
                })
                .is_err()
        );
        assert_eq!(serde_json::to_string(ports.rights()).unwrap(), before);
        let reply_host = ports
            .rights()
            .iter()
            .find(|r| r.guest_name == first as u32)
            .unwrap()
            .host_name;
        let mut refs = 0;
        // SAFETY: queried names belong to this service, and refs is writable local storage.
        assert_eq!(
            unsafe { mach_port_get_refs(task_host, reply_host, 1, &mut refs) },
            0
        );
        assert_eq!(refs, 1);
        drop(ports);
        assert_ne!(
            unsafe { mach_port_get_refs(task_host, reply_host, 1, &mut refs) },
            0
        );
        assert_eq!(
            unsafe {
                mach_port_get_refs(task_host, thread_host, RightKind::Send as u32, &mut refs)
            },
            KERN_SUCCESS
        );
        assert_eq!(refs, baseline);
        // SAFETY: only the observer reference acquired above remains ours.
        assert_eq!(
            unsafe { mach_port_deallocate(task_host, thread_host) },
            KERN_SUCCESS
        );
    }

    fn acquire_task(ports: &mut HostPorts) -> u32 {
        ports
            .request(&Request {
                number: TASK_SELF_TRAP,
                arguments: vec![],
            })
            .unwrap() as u32
    }
    fn output(outcome: Outcome) -> u32 {
        match outcome {
            Outcome::Copyout { value, .. } => value,
            other => panic!("expected source-ordered copyout, got {other:?}"),
        }
    }
    fn complete(outcome: Outcome, expected: i32) {
        match outcome {
            Outcome::Complete { value, .. } => assert_eq!(value, expected),
            other => panic!("expected completion, got {other:?}"),
        }
    }

    #[test]
    fn dedicated_receive_set_and_dead_resources_are_released_once() {
        for right in [RightKind::Receive, RightKind::PortSet, RightKind::DeadName] {
            let mut ports = HostPorts::new(701).unwrap();
            let task = acquire_task(&mut ports);
            let name = output(ports.execute(Operation::Allocate {
                task,
                right: right as u32,
                destination: 0,
            }));
            let entry = ports
                .rights()
                .iter()
                .find(|entry| entry.guest_name == name)
                .unwrap();
            let host_name = entry.host_name;
            assert!(!serde_json::to_string(entry).unwrap().contains("host_name"));
            assert_eq!(entry.retained_references, 1);
            assert_eq!(
                host::port_type(host_name).unwrap(),
                (KERN_SUCCESS, entry.state.type_bits())
            );
            // No copyout has occurred. The allocated resource remains owned even
            // when the later memory adapter cannot publish its output word.
            assert_eq!(
                output(ports.execute(Operation::Type {
                    task,
                    name,
                    destination: 0
                })),
                right.type_bit()
            );
            let operation = if right == RightKind::Receive {
                Operation::ModRefs {
                    task,
                    name,
                    right: right as u32,
                    delta: -1,
                }
            } else {
                Operation::Deallocate { task, name }
            };
            complete(ports.execute(operation), KERN_SUCCESS);
            assert!(!ports.rights().iter().any(|entry| entry.guest_name == name));
            assert_eq!(host::port_type(host_name).unwrap().0, KERN_INVALID_NAME);
        }
    }

    #[test]
    fn guest_dead_name_saturation_keeps_one_host_reference() {
        let mut ports = HostPorts::new(702).unwrap();
        let task = acquire_task(&mut ports);
        let name = output(ports.execute(Operation::Allocate {
            task,
            right: RightKind::DeadName as u32,
            destination: 0,
        }));
        complete(
            ports.execute(Operation::ModRefs {
                task,
                name,
                right: RightKind::DeadName as u32,
                delta: MACH_PORT_UREFS_MAX as i32,
            }),
            KERN_SUCCESS,
        );
        complete(
            ports.execute(Operation::Deallocate { task, name }),
            KERN_SUCCESS,
        );
        let entry = ports
            .rights()
            .iter()
            .find(|entry| entry.guest_name == name)
            .unwrap();
        assert_eq!(entry.references, MACH_PORT_UREFS_MAX);
        assert_eq!(entry.retained_references, 1);
        complete(
            ports.execute(Operation::ModRefs {
                task,
                name,
                right: RightKind::DeadName as u32,
                delta: -(MACH_PORT_UREFS_MAX as i32),
            }),
            KERN_SUCCESS,
        );
        assert!(!ports.rights().iter().any(|entry| entry.guest_name == name));
    }

    #[test]
    fn bootstrap_normalization_and_guard_refusals_preserve_retained_resources() {
        let mut ports = HostPorts::new(703).unwrap();
        let task = acquire_task(&mut ports);
        assert_eq!(acquire_task(&mut ports), task);
        assert_eq!(ports.rights()[0].references, 2);
        assert_eq!(ports.rights()[0].retained_references, 1);
        complete(
            ports.execute(Operation::Deallocate { task, name: task }),
            KERN_SUCCESS,
        );
        let before = serde_json::to_string(ports.rights()).unwrap();
        for operation in [
            Operation::Deallocate { task, name: task },
            Operation::Deallocate {
                task,
                name: 0x7fff_ff01,
            },
            Operation::ModRefs {
                task,
                name: task,
                right: RightKind::Send as u32,
                delta: -2,
            },
        ] {
            assert!(matches!(ports.execute(operation), Outcome::NoEffect { .. }));
            assert_eq!(serde_json::to_string(ports.rights()).unwrap(), before);
        }
        assert!(ports.has_task_send(task));
    }

    #[test]
    fn current_task_resolution_precedes_all_other_validation() {
        let mut ports = HostPorts::new(704).unwrap();
        for operation in [
            Operation::Allocate {
                task: 0,
                right: u32::MAX,
                destination: u64::MAX,
            },
            Operation::ModRefs {
                task: 0,
                name: u32::MAX,
                right: u32::MAX,
                delta: i32::MIN,
            },
            Operation::Type {
                task: 0,
                name: 0,
                destination: u64::MAX,
            },
        ] {
            complete(ports.execute(operation), MACH_SEND_INVALID_DEST);
        }
        assert!(ports.rights().is_empty());
    }

    #[test]
    fn null_dead_and_invalid_allocation_fast_paths_do_not_create_rights() {
        let mut ports = HostPorts::new(705).unwrap();
        let task = acquire_task(&mut ports);
        let before = serde_json::to_string(ports.rights()).unwrap();
        complete(
            ports.execute(Operation::Type {
                task,
                name: 0,
                destination: u64::MAX,
            }),
            KERN_INVALID_NAME,
        );
        assert_eq!(
            output(ports.execute(Operation::Type {
                task,
                name: MACH_PORT_DEAD,
                destination: 0
            })),
            RightKind::DeadName.type_bit()
        );
        for name in [MACH_PORT_NULL, MACH_PORT_DEAD] {
            complete(
                ports.execute(Operation::Deallocate { task, name }),
                KERN_SUCCESS,
            );
            complete(
                ports.execute(Operation::ModRefs {
                    task,
                    name,
                    right: RightKind::Send as u32,
                    delta: i32::MIN,
                }),
                KERN_SUCCESS,
            );
        }
        for right in [
            RightKind::Send as u32,
            RightKind::SendOnce as u32,
            5,
            6,
            u32::MAX,
        ] {
            complete(
                ports.execute(Operation::Allocate {
                    task,
                    right,
                    destination: 0,
                }),
                KERN_INVALID_VALUE,
            );
        }
        assert_eq!(serde_json::to_string(ports.rights()).unwrap(), before);
    }
}
