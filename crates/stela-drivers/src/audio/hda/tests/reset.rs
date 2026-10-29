// SPDX-License-Identifier: GPL-2.0-only
//! reset behavior tests.
use super::*;

#[test]
fn reset_binding_preflight() {
    let mut fixture = Fixture::new();
    let model = Model::new(16);
    let remaining = fixture.allocator.remaining();
    assert!(matches!(
        create(&model, &mut fixture, modern_config()),
        Err(Error::InvalidConfiguration)
    ));
    assert_eq!(access_counts(&model), (0, 0, 0));
    assert_eq!(fixture.allocator.remaining(), remaining);
    let (mut function, state) = reset_pci(&model);
    let prepared = pci::tests::modern_prepared_model(function.address);
    assert!(matches!(
        // SAFETY: This prepared modern identity requires mapped preflight, so claim_mmio
        // returns InvalidConfiguration before constructing or accessing an MMIO pointer.
        unsafe { prepared.claim_mmio() },
        Err(Error::InvalidConfiguration)
    ));
    let prepared = pci::tests::modern_prepared_model(function.address);
    function.address.device = 28;
    assert!(matches!(
        // SAFETY: The PCI and register models are local to this test and have no firmware
        // or concurrent device owner. A mismatched BDF is rejected before binding.
        unsafe { prepared.bind_registers(&mut function, ModelRegisters(model.clone())) },
        Err(pci::AttachError::IdentityChanged)
    ));
    function.address.device = 27;
    let prepared = pci::tests::modern_prepared_model(function.address);
    let registers =
        // SAFETY: The PCI and register models are local to this test and have no firmware
        // or concurrent device owner. A mismatched BDF is rejected before binding.
        unsafe { prepared.bind_registers(&mut function, ModelRegisters(model.clone())) }.unwrap();
    let pci_reads = state.borrow().reads;
    let timer = model.borrow().clock.clone();
    assert!(matches!(
        // SAFETY: The adapter and clock use this test's synchronous register model.
        // fixture keeps unique coherent DMA storage throughout controller use.
        unsafe { Controller::new(registers, timer, &mut fixture.allocator, config()) },
        Err(Error::InvalidConfiguration)
    ));
    assert_eq!(state.borrow().reads, pci_reads);
    assert_eq!(access_counts(&model), (0, 0, 0));
    assert_eq!(fixture.allocator.remaining(), remaining);
}

#[test]
fn clock_gate_brackets_each_reset() {
    let mut fixture = Fixture::new();
    let model = graph_model();
    let (mut function, state) = reset_pci(&model);
    let prepared = pci::tests::modern_prepared_model(function.address);
    let registers =
        // SAFETY: The PCI and register models are local to this test and have no firmware
        // or concurrent device owner. A mismatched BDF is rejected before binding.
        unsafe { prepared.bind_registers(&mut function, ModelRegisters(model.clone())) }.unwrap();
    let timer = model.borrow().clock.clone();
    // Once is the profile minimum; an explicit caller may elect bounded
    // discovery retries without weakening any mandatory controller policy.
    let selected = Config {
        probe_policy: ProbePolicy::Retry {
            attempts: 2,
            delay_us: 80,
        },
        ..modern_config()
    };
    let mut controller =
        // SAFETY: The adapter and clock use this test's synchronous register model.
        // fixture keeps unique coherent DMA storage throughout controller use.
        unsafe { Controller::new(registers, timer, &mut fixture.allocator, selected) }.unwrap();
    controller.reinitialize().unwrap();
    model.borrow_mut().codec_ready_after_resets = 3;
    let result = controller.discover_codecs().unwrap();
    assert_eq!(result.attempts, 2);
    let pci = state.borrow();
    assert_eq!(pci.writes.len(), 6);
    for pair in pci.writes.as_chunks::<2>().0 {
        assert_eq!(pair[0].0, 0xa5a5_0083);
        assert_eq!(pair[1].0, 0xa5a5_00c3);
        assert!(pair[1].1 > pair[0].1);
        assert_eq!(pair[1].2, pair[0].2 + 1);
        assert!(!pair[0].3);
        assert!(pair[1].3);
        assert!(
            model
                .borrow()
                .writes
                .iter()
                .any(|(offset, value, width)| *offset == GCTL
                    && *width == 4
                    && *value & GCTL_RESET == 0)
        );
    }
}

#[test]
fn reset_control_failure_attempts_cleanup() {
    for fault in 0..5 {
        let mut fixture = Fixture::new();
        let model = Model::new(16);
        let (mut function, state) = reset_pci(&model);
        match fault {
            0 => state.borrow_mut().reject_disable = true,
            1 => state.borrow_mut().reject_enable = true,
            2 => state.borrow_mut().failed_read = 1,
            3 => state.borrow_mut().failed_read = 2,
            _ => state.borrow_mut().failed_read = 3,
        }
        let prepared = pci::tests::modern_prepared_model(function.address);
        let registers =
            // SAFETY: The PCI and register models are local to this test and have no firmware
            // or concurrent device owner. A mismatched BDF is rejected before binding.
            unsafe { prepared.bind_registers(&mut function, ModelRegisters(model.clone())) }
                .unwrap();
        let timer = model.borrow().clock.clone();
        assert!(matches!(
            // SAFETY: The adapter and clock use this test's synchronous register model.
            // fixture keeps unique coherent DMA storage throughout controller use.
            unsafe { Controller::new(registers, timer, &mut fixture.allocator, modern_config()) },
            Err(Error::PciResetControl { offset: 0x48 })
        ));
        assert!(model.borrow().commands.is_empty());
        assert_eq!(model.borrow().get(CORBCTL, 1) & u32::from(COMMAND_RUN), 0);
        assert_eq!(model.borrow().get(RIRBCTL, 1) & u32::from(COMMAND_RUN), 0);
        if fault == 2 {
            assert!(state.borrow().clock_reads >= 2);
        }
        if fault == 3 {
            assert!(state.borrow().clock_reads >= 3);
        }
        if fault == 0 || fault == 1 || fault == 4 {
            let writes = &state.borrow().writes;
            assert_eq!(writes.len(), 2);
            assert_eq!(writes[0].0 & 0x40, 0);
            assert_ne!(writes[1].0 & 0x40, 0);
        }
    }
}

#[test]
fn failed_reset_retains_dma_until_recovery() {
    for fault in 0..3 {
        let mut fixture = Fixture::new();
        let model = Model::new(16);
        let (mut function, state) = reset_pci(&model);
        let prepared = pci::tests::modern_prepared_model(function.address);
        let registers =
            // SAFETY: The PCI and register models are local to this test and have no firmware
            // or concurrent device owner. A mismatched BDF is rejected before binding.
            unsafe { prepared.bind_registers(&mut function, ModelRegisters(model.clone())) }
                .unwrap();
        let timer = model.borrow().clock.clone();
        let mut controller =
            // SAFETY: The adapter and clock use this test's synchronous register model.
            // fixture keeps unique coherent DMA storage throughout controller use.
            unsafe { Controller::new(registers, timer, &mut fixture.allocator, modern_config()) }
                .unwrap();
        let id = controller
            .allocate_stream(Direction::Playback, pcm(), 128, 2, &mut fixture.allocator)
            .unwrap();
        controller.start(id).unwrap();
        let remaining = fixture.allocator.remaining();
        match fault {
            0 => model.borrow_mut().stream_stop_stuck = true,
            1 => model.borrow_mut().reset_exit_stuck = true,
            _ => state.borrow_mut().reject_enable = true,
        }
        let error = controller.reinitialize().unwrap_err();
        if fault == 0 {
            assert_eq!(error, Error::Timeout(Phase::StreamStop));
            assert_eq!(state.borrow().writes.len(), 2);
            assert!(controller.streams[usize::from(id.descriptor_index())].is_some());
        } else {
            assert_eq!(
                error,
                if fault == 1 {
                    Error::Timeout(Phase::LinkResetExit)
                } else {
                    Error::PciResetControl { offset: 0x48 }
                }
            );
            let writes = &state.borrow().writes;
            assert_eq!(writes.len(), 4);
            assert_eq!(writes[2].0 & 0x40, 0);
            assert_ne!(writes[3].0 & 0x40, 0);
        }
        assert_eq!(fixture.allocator.remaining(), remaining);
        let before = access_counts(&model);
        assert_eq!(controller.verb(verb()), Err(Error::NeedsReset));
        assert_eq!(
            controller.start(id),
            Err(if fault == 0 {
                Error::NeedsReset
            } else {
                Error::InvalidStream
            })
        );
        assert_eq!(
            controller.allocate_stream(Direction::Capture, pcm(), 128, 2, &mut fixture.allocator),
            Err(Error::NeedsReset)
        );
        assert_eq!(access_counts(&model), before);
        state.borrow_mut().reject_enable = false;
        model.borrow_mut().reset_exit_stuck = false;
        model.borrow_mut().stream_stop_stuck = false;
        controller.reinitialize().unwrap();
        controller.verb(verb()).unwrap();
    }
}
