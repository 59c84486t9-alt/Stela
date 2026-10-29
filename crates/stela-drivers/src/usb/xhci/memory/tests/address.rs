//! Fresh output visibility through real native command/event DMA. Hardware
//! grants the slot via Enable Slot; no test constructs a software device ID.
use super::*;

const CONFIGURATION: [u8; 25] = [
    9, 2, 25, 0, 1, 1, 0, 0x80, 1, 9, 4, 0, 0, 1, 0xff, 0, 0, 0, 7, 5, 0x82, 2, 0, 2, 0,
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Addressed,
    AddressError,
    VisibilityError,
    RingVisibilityError,
}
struct Device {
    port: u32,
    reset: bool,
    command: u64,
    command_index: usize,
    table: u64,
    event_index: usize,
    dcbaa: u64,
    ep0: u64,
    ep0_index: usize,
    configuration: u8,
    controls: Vec<[u8; 8]>,
    commands: Vec<u32>,
    mode: Mode,
}
struct RegistersPeer {
    inner: CoreRegisters,
    peer: Arc<Peer>,
    device: Rc<RefCell<Device>>,
}
impl RegistersPeer {
    fn control(&mut self) {
        let mut device = self.device.borrow_mut();
        let at = device.ep0 + (device.ep0_index * TRB) as u64;
        let trb = self.peer.device(at, TRB);
        assert_eq!(
            u32::from_le_bytes(trb[12..].try_into().unwrap()) & (63 << 10 | CYCLE),
            SETUP << 10 | CYCLE
        );
        let request = trb[..8].try_into().unwrap();
        device.controls.push(request);
        let stages = if request == setup(0x80, GET_DESCRIPTOR, 0x200, 0, 25) {
            let data = self.peer.device(at + TRB as u64, TRB);
            assert_eq!(
                u32::from_le_bytes(data[12..].try_into().unwrap()) & (63 << 10 | CYCLE),
                DATA << 10 | CYCLE
            );
            assert_eq!(
                u32::from_le_bytes(data[8..12].try_into().unwrap()) & 0x1ffff,
                25
            );
            self.peer.post(
                u64::from_le_bytes(data[..8].try_into().unwrap()),
                &CONFIGURATION,
            );
            3
        } else {
            assert_eq!(request, setup(0, SET_CONFIGURATION, 1, 0, 0));
            device.configuration = 1;
            2
        };
        let status_at = at + ((stages - 1) * TRB) as u64;
        let status = self.peer.device(status_at, TRB);
        assert_eq!(
            u32::from_le_bytes(status[12..].try_into().unwrap()) & (63 << 10 | CYCLE | IOC),
            STATUS << 10 | CYCLE | IOC
        );
        device.ep0_index += stages;
        let events = u64::from_le_bytes(self.peer.device(device.table, 8).try_into().unwrap());
        let mut event = [0; TRB];
        event[..8].copy_from_slice(&status_at.to_le_bytes());
        event[8..12].copy_from_slice(&(SUCCESS << 24).to_le_bytes());
        event[12..]
            .copy_from_slice(&(1 << 24 | 1 << 16 | TRANSFER_EVENT << 10 | CYCLE).to_le_bytes());
        self.peer
            .post(events + (device.event_index * TRB) as u64, &event);
        device.event_index += 1;
    }

    fn unowned_ring(&self, input: u64, endpoint: usize) {
        let dequeue = u64::from_le_bytes(
            self.peer
                .device(input + ((endpoint + 1) * 32 + 8) as u64, 8)
                .try_into()
                .unwrap(),
        );
        assert_eq!(dequeue & 15, 1, "actual initial dequeue Cycle");
        let ring = dequeue & !15;
        assert_eq!(
            self.peer.device(ring, (RING_TRBS - 1) * TRB),
            vec![0; (RING_TRBS - 1) * TRB],
            "every initially unowned TRB must be device-visible"
        );
        let link = self.peer.device(ring + ((RING_TRBS - 1) * TRB) as u64, TRB);
        assert_eq!(u64::from_le_bytes(link[..8].try_into().unwrap()), ring);
        assert_eq!(&link[8..], &[0; 8]);
    }

    fn command(&mut self) {
        let mut device = self.device.borrow_mut();
        let at = (device.command & !63) + (device.command_index * TRB) as u64;
        let trb = self.peer.device(at, TRB);
        let parameter = u64::from_le_bytes(trb[..8].try_into().unwrap());
        let control = u32::from_le_bytes(trb[12..].try_into().unwrap());
        assert_eq!(control & CYCLE, CYCLE, "actual native command ownership");
        let kind = control >> 10 & 63;
        device.command_index += 1;
        device.commands.push(kind);
        let mut code = SUCCESS;
        match kind {
            ENABLE_SLOT => {
                if device.mode == Mode::VisibilityError {
                    // The ACK's exact event is the next CPU sync. Refuse the
                    // following device sync, then inspect its range.
                    let mut state = self.peer.state.lock().unwrap();
                    state.fail_sync = Some(state.syncs.len() + 1);
                }
            }
            ADDRESS_DEVICE => {
                assert!(device.reset, "root reset must precede addressing");
                assert_eq!(control >> 24, 1, "use actual Enable Slot grant");
                let output =
                    u64::from_le_bytes(self.peer.device(device.dcbaa + 8, 8).try_into().unwrap());
                assert_eq!(
                    self.peer.device(output, 32 * 32),
                    vec![0; 32 * 32],
                    "output must be device-visible zero before Address Device"
                );
                assert_eq!(
                    u32::from_le_bytes(self.peer.device(parameter + 36, 4).try_into().unwrap())
                        >> 16
                        & 255,
                    1
                );
                self.unowned_ring(parameter, 1);
                device.ep0 =
                    u64::from_le_bytes(self.peer.device(parameter + 72, 8).try_into().unwrap())
                        & !15;
                if device.mode == Mode::AddressError {
                    code = 17;
                } else {
                    self.peer
                        .post(output, &self.peer.device(parameter + 32, 32));
                    self.peer
                        .post(output + 32, &self.peer.device(parameter + 64, 32));
                    self.peer.post(output + 12, &1u32.to_le_bytes());
                    self.peer.post(output + 32, &ENDPOINT_RUNNING.to_le_bytes());
                }
            }
            CONFIGURE_ENDPOINT => {
                assert_eq!(
                    device.configuration, 1,
                    "actual SET_CONFIGURATION status ACK"
                );
                assert_eq!(control >> 24, 1);
                assert_eq!(
                    u32::from_le_bytes(self.peer.device(parameter + 4, 4).try_into().unwrap()),
                    1 | 1 << 5,
                    "actual bulk IN endpoint context add mask"
                );
                self.unowned_ring(parameter, 5);
                let output =
                    u64::from_le_bytes(self.peer.device(device.dcbaa + 8, 8).try_into().unwrap());
                self.peer
                    .post(output + 5 * 32, &self.peer.device(parameter + 6 * 32, 32));
                self.peer
                    .post(output + 5 * 32, &ENDPOINT_RUNNING.to_le_bytes());
            }
            reset::DISABLE_SLOT => {}
            _ => panic!("unexpected unaddressed endpoint command {kind}"),
        }
        let events = u64::from_le_bytes(self.peer.device(device.table, 8).try_into().unwrap());
        let mut event = [0; TRB];
        event[..8].copy_from_slice(&at.to_le_bytes());
        event[8..12].copy_from_slice(&(code << 24).to_le_bytes());
        event[12..].copy_from_slice(&(1 << 24 | COMMAND_COMPLETION << 10 | CYCLE).to_le_bytes());
        self.peer
            .post(events + (device.event_index * TRB) as u64, &event);
        device.event_index += 1;
    }
}
impl Registers for RegistersPeer {
    fn read32(&mut self, at: usize) -> u32 {
        match at {
            HCCPARAMS1 => 1 | 0x80 << 16,
            0x200 => 2 << 24 | SUPPORTED_PROTOCOL,
            0x208 => 1 | 1 << 8,
            0x440 => self.device.borrow().port,
            _ => self.inner.read32(at),
        }
    }
    fn write32(&mut self, at: usize, value: u32) {
        self.inner.write32(at, value);
        {
            let mut device = self.device.borrow_mut();
            let word = |base: usize, target: &mut u64| {
                if at == base {
                    *target = *target & !0xffff_ffff | u64::from(value);
                }
                if at == base + 4 {
                    *target = *target & 0xffff_ffff | u64::from(value) << 32;
                }
            };
            word(0x40 + CRCR, &mut device.command);
            word(0x40 + DCBAAP, &mut device.dcbaa);
            word(0x800 + ERSTBA, &mut device.table);
            if at == 0x440 {
                device.port &= !(value & PORT_CHANGES);
                if value & PR != 0 {
                    device.port |= PED | PRC;
                    device.reset = true;
                }
            }
        }
        if at == 0x1000 {
            self.command();
        }
        if at == 0x1004 {
            assert_eq!(value, 1, "actual EP0 doorbell");
            self.control();
        }
    }
    fn size(&self) -> Option<usize> {
        self.inner.size()
    }
}

#[test]
fn initial_output_visibility_precedes_actual_address_ack_and_failed_address_retirement() {
    for mode in [
        Mode::Addressed,
        Mode::AddressError,
        Mode::VisibilityError,
        Mode::RingVisibilityError,
    ] {
        let peer = Peer::new();
        let registers = Rc::new(RefCell::new(RegistersState::default()));
        let device = Rc::new(RefCell::new(Device {
            port: PP | CCS | PED | u32::from(HIGH_SPEED) << PORT_SPEED_SHIFT,
            reset: false,
            command: 0,
            command_index: 0,
            table: 0,
            event_index: 0,
            dcbaa: 0,
            ep0: 0,
            ep0_index: 0,
            configuration: 0,
            controls: Vec::new(),
            commands: Vec::new(),
            mode,
        }));
        let mut controller = Controller::with_memory_profile(
            Box::new(RegistersPeer {
                inner: CoreRegisters(registers),
                peer: peer.clone(),
                device: device.clone(),
            }),
            Clock {
                ticks_per_microsecond: 1000,
            },
            &mut NoBoot,
            "native addressed context visibility".into(),
            hardware::Policy::default(),
            || Ok(()),
            Some(memory(&peer)),
        )
        .unwrap();
        let speed = controller.root_port(1).unwrap().unwrap();
        let result = controller.address_parent(
            Attachment {
                root_port: 1,
                route: 0,
                tier: 0,
                speed,
                translator: None,
                parent: None,
            },
            None,
            &mut NoBoot,
        );
        match mode {
            Mode::Addressed | Mode::RingVisibilityError => {
                let slot = result.unwrap();
                let id = controller.device_id(slot).unwrap();
                assert_eq!(id.hardware_slot(), 1);
                assert_eq!(device.borrow().commands, [ENABLE_SLOT, ADDRESS_DEVICE]);
                assert_eq!(
                    controller
                        .slot(slot)
                        .unwrap()
                        ._output
                        .coherent_u32(32)
                        .unwrap()
                        & 7,
                    ENDPOINT_RUNNING
                );
                let configuration = controller
                    .control_owned(slot, setup(0x80, GET_DESCRIPTOR, 0x200, 0, 25), &[])
                    .unwrap();
                assert_eq!(configuration, CONFIGURATION);
                controller
                    .current_descriptions(slot, &[configuration])
                    .unwrap();
                controller.set_configuration_owned(slot, 1).unwrap();
                assert_eq!(controller.current_configuration_owned(slot), Ok(Some(1)));
                assert_eq!(device.borrow().controls.len(), 2);
                if mode == Mode::RingVisibilityError {
                    let mut state = peer.state.lock().unwrap();
                    // Republish EP0's CPU-produced ring first, then refuse
                    // the separate new bulk ring before its context command.
                    state.fail_sync = Some(state.syncs.len() + 1);
                }
                let configured = controller.configure_owned(
                    slot,
                    &[Endpoint {
                        address: 0x82,
                        attributes: 2,
                        max_packet: 512,
                        interval: 0,
                        companion: None,
                    }],
                    None,
                    &mut NoBoot,
                );
                if mode == Mode::Addressed {
                    configured.unwrap();
                    assert_eq!(
                        device.borrow().commands,
                        [ENABLE_SLOT, ADDRESS_DEVICE, CONFIGURE_ENDPOINT]
                    );
                    assert!(
                        controller.slot(slot).unwrap().endpoints[5]
                            .as_ref()
                            .unwrap()
                            .enabled
                    );
                } else {
                    assert!(configured.is_err());
                    assert_eq!(device.borrow().commands, [ENABLE_SLOT, ADDRESS_DEVICE]);
                    let endpoint = controller.slot(slot).unwrap().endpoints[5]
                        .as_ref()
                        .unwrap();
                    assert!(endpoint.poisoned && !endpoint.enabled);
                    {
                        let state = peer.state.lock().unwrap();
                        let (token, _) =
                            Peer::range(&state, endpoint.ring.buffer.device_address(), 1);
                        let last = state.syncs.last().unwrap();
                        assert_eq!(last.1, token, "actual new bulk ring mapping was refused");
                        assert_eq!(last.2.len(), RING_TRBS * TRB);
                    }
                    assert!(controller.ready().is_err());
                    let mappings = peer.state.lock().unwrap().bindings.len();
                    drop(controller);
                    assert_eq!(peer.state.lock().unwrap().bindings.len(), mappings);
                    assert_eq!(peer.drops.load(Ordering::Relaxed), 0);
                }
            }
            Mode::AddressError => {
                assert!(matches!(
                    result,
                    Err((_, BlockError::Device { status: 17 }))
                ));
                assert_eq!(
                    device.borrow().commands,
                    [ENABLE_SLOT, ADDRESS_DEVICE, reset::DISABLE_SLOT]
                );
                assert!(controller.device_id(1).is_err());
            }
            Mode::VisibilityError => {
                assert!(result.is_err());
                assert_eq!(device.borrow().commands, [ENABLE_SLOT]);
                assert_eq!(
                    peer.state.lock().unwrap().syncs.last().unwrap().2.len(),
                    32 * 32,
                    "actual fresh output sync must be the refused visibility"
                );
                assert_eq!(controller.dcbaa.read::<u64>(8), 0);
                assert!(controller.ready().is_err());
                let mappings = peer.state.lock().unwrap().bindings.len();
                drop(controller);
                assert_eq!(peer.state.lock().unwrap().bindings.len(), mappings);
                assert_eq!(peer.drops.load(Ordering::Relaxed), 0);
            }
        }
    }
}
