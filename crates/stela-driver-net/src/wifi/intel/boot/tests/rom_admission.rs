// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2007-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
use super::*;

#[test]
fn ax210_wrong_protocol_missing_oversized_iml_and_unqualified_inputs_do_no_io_or_dma() {
    let (observation, step_catalog) = step_fixture();
    for mode in 0..5 {
        let mut bytes = if mode == 0 {
            let mut b = firmware_bytes();
            b[72..76].copy_from_slice(&(89u32 << 8).to_le_bytes());
            b
        } else {
            ax210_bytes()
        };
        if mode == 1 {
            bytes.truncate(bytes.len() - 72);
            bytes.extend(52u32.to_le_bytes());
            bytes.extend(32772u32.to_le_bytes());
            bytes.extend(vec![0xa5; 32772]);
        }
        let catalog = catalog_for(&ax210_profile(), Family::Ax210.firmware_name(), &bytes);
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = ax210_state();
        let drops = Arc::new(AtomicUsize::new(0));
        let power = awake_profile(state.clone(), drops.clone(), ax210_profile());
        let staged = crate::wifi::intel::identity::stage(&ax210_profile(), &catalog).unwrap();
        // SAFETY: Only the serialized Model can access fresh Source RAM in this Domain;
        // the absent domain/protocol/size variants are refused before publication to any device.
        let result = unsafe {
            if mode == 4 {
                RomBoot::start(power, staged, &source, Some(domain.clone()), 32)
            } else {
                RomBoot::start_ax210(
                    power,
                    staged,
                    crate::wifi::intel::platform::load_step(observation, &step_catalog).unwrap(),
                    &source,
                    if mode == 3 {
                        None
                    } else {
                        Some(domain.clone())
                    },
                    if mode == 2 { 2048 } else { 32 },
                    ProductResetPolicy::NoIwlmei,
                )
            }
        };
        assert!(matches!(
            (&result, mode),
            (
                Err(Error::Firmware(firmware::Error::Missing("AX210 IML"))),
                0
            ) | (Err(Error::Dma(dma::Error::PayloadSize)), 1)
                | (Err(Error::QueueSize), 2)
                | (
                    Err(Error::Dma(dma::Error::Dma(
                        crate::bus::dma::mapping::DmaError::IommuUnavailable
                    ))),
                    3
                )
                | (Err(Error::Family), 4)
        ));
        assert!(state.lock().unwrap().ops.is_empty());
        assert_eq!(source.calls.load(Ordering::Relaxed), 0);
        assert_eq!(domain.records.lock().unwrap().maps, 0);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn missing_domain_invalid_ring_size_and_unwoken_epoch_allocate_nothing() {
    let bytes = firmware_bytes();
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
    for mode in 0..3 {
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = Arc::new(Mutex::new(ModelState::default()));
        let drops = Arc::new(AtomicUsize::new(0));
        let power = if mode == 2 {
            Power::new(
                Model {
                    state: state.clone(),
                    _owner: Owner(drops.clone()),
                },
                profile(),
            )
        } else {
            awake(state, drops.clone())
        };
        // SAFETY: Source provides fresh exclusive model RAM with no physical DMA or IRQ;
        // missing domain, invalid ring size and unwoken power are checked before allocation.
        let result = unsafe {
            Ax200Boot::start(
                power,
                crate::wifi::intel::identity::stage(&profile(), &catalog).unwrap(),
                &source,
                if mode == 0 {
                    None
                } else {
                    Some(domain.clone())
                },
                if mode == 1 { 7 } else { 32 },
            )
        };
        assert!(matches!(
            (&result, mode),
            (
                Err(Error::Dma(dma::Error::Dma(
                    crate::bus::dma::mapping::DmaError::IommuUnavailable
                ))),
                0
            ) | (Err(Error::QueueSize), 1)
                | (Err(Error::Power(power::Error::State)), 2)
        ));
        assert_eq!(source.calls.load(Ordering::Relaxed), 0);
        assert_eq!(domain.records.lock().unwrap().maps, 0);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn staged_profile_diagnostic_name_board_and_driver_swaps_refuse_before_io_or_dma() {
    struct Redirect<'p>(resources::Image<'p>);
    impl resources::Provider for Redirect<'_> {
        fn load<'p>(
            &'p self,
            _: resources::Requirement<'_>,
        ) -> Result<resources::Image<'p>, resources::Error> {
            Ok(self.0)
        }
    }
    let bytes = firmware_bytes();
    for mode in 0..6 {
        let mut observed = profile().observed();
        if mode == 0 {
            observed.subsystem_device ^= 1;
        }
        if mode == 1 {
            observed.pci_revision ^= 1;
        }
        let other = Profile::select(observed).unwrap();
        let request = other.firmware_request();
        let mut target = request.requirement().target;
        if mode == 3 {
            target.board = Some("different-board");
        }
        if mode == 4 {
            target.driver = "diagnostic-driver";
        }
        if mode == 5 {
            target.revision = "different-raw-revision";
        }
        let name = if mode == 2 {
            "intel-diagnostic.ucode"
        } else {
            request.name
        };
        let catalog = catalog_for_target(target, name, &bytes);
        let image = resources::Provider::load(
            &catalog,
            resources::Requirement {
                name,
                target,
                minimum_bytes: 1,
            },
        )
        .unwrap();
        let provider = Redirect(image);
        let staged = crate::wifi::intel::identity::stage(&other, &provider).unwrap();
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = Arc::new(Mutex::new(ModelState::default()));
        let drops = Arc::new(AtomicUsize::new(0));
        let power = awake(state.clone(), drops.clone());
        // SAFETY: The model keeps its original Source/Domain and has no concurrent user;
        // swapped firmware metadata is refused before I/O or DMA publication.
        let result = unsafe { Ax200Boot::start(power, staged, &source, Some(domain.clone()), 32) };
        assert!(matches!(result, Err(Error::FirmwareBinding)), "swap{mode}");
        assert_eq!(source.calls.load(Ordering::Relaxed), 0);
        assert_eq!(domain.records.lock().unwrap().maps, 0);
        assert!(state.lock().unwrap().ops.is_empty());
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
}
