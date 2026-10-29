//! Type-C connectors, USB controllers and the peripherals and network the host
//! attaches through them.

use super::*;

impl AppleDevices {
    /// The shared cable state of one Type-C connector.
    pub(super) fn typec_port(&mut self, number: u32) -> typec::Port {
        if let Some((_, port)) = self.typec_ports.iter().find(|(n, _)| *n == number) {
            return port.clone();
        }
        let port = typec::Port::new();
        self.typec_ports.push((number, port.clone()));
        port
    }

    /// Place canonical PHY regions once. ADT aliases inside the core resolve
    /// by physical address; no length concatenation or duplicate storage.
    pub fn add_atc_phy(
        &mut self,
        placement: &stela_soc_data::board::TypecPhy,
    ) -> Result<(), String> {
        if placement.phandle == 0
            || placement.port == 0
            || self.phys.iter().any(|phy| phy.phandle == placement.phandle)
        {
            return Err("ATC PHY has an invalid/duplicate phandle or invalid connector".into());
        }
        let id = self.bus.add(Box::new(AtcPhy::new()));
        let pipe = placement.pipe.map(|pipe| (pipe, atc_phy::PIPE));
        for ((physical, bytes), offset) in [
            (placement.usb2, atc_phy::USB2),
            (placement.core, 0),
            (placement.events, atc_phy::EVENTS),
        ]
        .into_iter()
        .chain(pipe)
        {
            self.bus
                .map(id, physical, bytes, offset)
                .map_err(|error| format!("ATC PHY placement: {error:?}"))?;
        }
        self.phys.push(PhyBinding {
            phandle: placement.phandle,
            port: placement.port,
            device: id,
            retention: placement.retention,
            pipe: placement.pipe,
            events: placement.events,
        });
        Ok(())
    }

    /// Place the core once, with reg[2]/reg[8] sharing reg[0]'s bytes.
    /// Platform windows keep distinct refusing offsets; reg[3] and reg[4]
    /// are the pipehandler and core event block, which the ATC PHY placement
    /// owns (`atc-phy-parent`). IRQ indices 0..3
    /// are from AppleUSBXDCI::goOnBus (KC 0x42f5338/5380/53c8/5d24),
    /// passed unchanged to EventHandler::withParameters; initializePlatformSettings
    /// at 0x4338e74 chooses four handlers. The fifth ADT IRQ is not an event ring.
    pub fn add_usb(
        &mut self,
        placement: &stela_soc_data::board::UsbController,
        dart: DartId,
    ) -> Result<UsbId, String> {
        self.validate_native_dart("USB", dart, placement.stream as usize)?;
        let binding = self
            .phys
            .iter()
            .find(|phy| phy.phandle == placement.phy && phy.port == placement.port)
            .ok_or_else(|| {
                format!(
                    "USB atc-phy-parent {:#x} has no placed PHY on connector {}",
                    placement.phy, placement.port
                )
            })?;
        if binding.pipe != Some(placement.ranges[3]) || binding.events != placement.ranges[4] {
            return Err(
                "USB PHY lacks the matching physical pipehandler reset/event windows".into(),
            );
        }
        let phy = binding.device;
        let state = self
            .bus
            .device::<AtcPhy>(phy)
            .expect("placed PHY type")
            .usb2_state();
        let connector = self.typec_port(placement.port);
        let irqs = core::array::from_fn(|n| AicInput::new(0, placement.irqs[n] as u16));
        let mut model = Dwc3::new(irqs);
        model.set_phy_state(
            state.controller_reset,
            state.ready,
            state.clocked,
            state.quiesced,
            &mut Access::new(0, 0, &mut self.latch),
        );
        let device = self.bus.add(Box::new(model));
        let (physical, bytes) = placement.ranges[0];
        self.bus
            .map(device, physical, bytes, 0)
            .map_err(|e| format!("DWC3 placement: {e:?}"))?;
        for index in [1, 5, 6, 7] {
            let (physical, bytes) = placement.ranges[index];
            self.bus
                .map(
                    device,
                    physical,
                    bytes,
                    dwc3::PLATFORM_WINDOW_BASE + index as u64 * dwc3::PLATFORM_WINDOW_STRIDE,
                )
                .map_err(|e| format!("USB platform window {index}: {e:?}"))?;
        }
        self.usb_masters.push(UsbMaster {
            device,
            phy,
            phy_changed: true,
            dart: dart.0,
            stream: placement.stream as usize,
            session: UsbSession::new(),
            port: UsbPort::of(&connector),
            number: placement.port,
            connector,
            peripheral: None,
            next_poll: 0,
            attached: false,
            epoch: 0,
            retention: placement.retention,
            session_reset: false,
        });
        Ok(UsbId(device))
    }

    /// A cable change on one Type-C connector, as the external peer makes
    /// it. The connector's HPM dies and USB controller observe the same state.
    pub fn set_connection(
        &mut self,
        connector: u32,
        connection: Option<typec::Attached>,
    ) -> Result<(), &'static str> {
        self.typec_port(connector).set_connection(connection)?;
        Ok(())
    }

    /// Cables a native high-speed hub to Type-C connector `connector`,
    /// this machine being the downstream-facing port that sources VBUS: the
    /// HPM reports the attach and the controller's host personality finds
    /// the hub on its USB2 port. The keyboard and pointer sit on the hub's
    /// first port, and `cables` names the USB Ethernet adapter and mass
    /// storage devices on the next ones.
    pub fn attach_input(&mut self, connector: u32, cables: UsbCables) -> Result<(), &'static str> {
        let UsbCables { disks, network } = cables;
        if 1 + usize::from(network.is_some()) + disks.len() > hub::MAX_PORTS {
            return Err("the native hub has seven ports");
        }
        let network = network.map(Ecm::new).transpose()?;
        let disks = disks
            .into_iter()
            .map(MassStorage::of)
            .collect::<Result<Vec<_>, _>>()?;
        let master = self
            .usb_masters
            .iter_mut()
            .find(|master| master.number == connector)
            .ok_or("no USB controller on that connector")?;
        let attachments = Attachments {
            input: Peripheral::new(),
            network,
            disks,
        };
        master.peripheral = Some(Hub::new(attachments, "0001")?);
        master.connector.set_connection(Some(typec::Attached {
            orientation: typec::Orientation::Normal,
            role: typec::DataRole::Dfp,
            source: true,
            vbus: true,
            speed: typec::Usb2Speed::High,
        }))?;
        Ok(())
    }

    pub(super) fn usb_network(&mut self) -> Result<&mut Ecm, &'static str> {
        self.usb_masters
            .iter_mut()
            .find_map(|master| master.peripheral.as_mut()?.ports.network.as_mut())
            .ok_or("no USB Ethernet adapter is attached")
    }

    /// A frame from the host network for the guest's USB Ethernet adapter;
    /// dropped as the adapter's filter and queue decide.
    pub fn network_deliver(&mut self, frame: &[u8]) -> Result<(), &'static str> {
        self.usb_network()?.deliver(frame);
        Ok(())
    }

    /// Whether the guest has its USB Ethernet link up, and the adapter's
    /// counters; `None` without an adapter.
    pub fn network_status(&mut self) -> Option<(bool, UsbNetworkCounters)> {
        let network = self.usb_network().ok()?;
        Some((network.up(), network.counters()))
    }

    /// Whether the guest's USB Ethernet adapter has room for a frame from
    /// the host network; false without an adapter.
    pub fn network_room(&mut self) -> bool {
        self.usb_network().is_ok_and(|network| network.has_room())
    }

    /// The next frame the guest sent through its USB Ethernet adapter.
    pub fn network_take(&mut self) -> Option<Vec<u8>> {
        self.usb_network().ok()?.take()
    }

    /// The keyboard LEDs the guest set on the attached peripheral, Num Lock
    /// in bit 0 as input LED codes number them.
    pub fn keyboard_leds(&self) -> Option<u8> {
        self.usb_masters
            .iter()
            .find_map(|master| master.peripheral.as_ref())
            .map(|peripheral| peripheral.ports.input.leds())
    }

    /// One host input change for the attached peripheral.
    pub fn input(&mut self, input: Input) -> Result<(), &'static str> {
        self.usb_masters
            .iter_mut()
            .find_map(|master| master.peripheral.as_mut())
            .ok_or("no input peripheral is attached")?
            .ports
            .input
            .input(input)
    }

    /// The machine's power button went down or up. The SMC reports it to
    /// the AP as a HID button notification once the AP has enabled them;
    /// while the SoC sleeps a press is a wake source instead (`sleep`).
    pub fn power_button(&mut self, pressed: bool) -> Result<(), &'static str> {
        if self.smc()?.power_button(pressed) {
            self.wake(smc::WakeSource::PowerButton);
        }
        Ok(())
    }

    pub fn usb_client(&mut self, id: UsbId) -> Result<UsbClient<'_>, &'static str> {
        let master = self
            .usb_masters
            .iter_mut()
            .find(|master| master.device == id.0)
            .ok_or("unknown USB controller")?;
        let reset = self
            .bus
            .device_mut::<Dwc3>(master.device)
            .expect("USB master owns DWC3")
            .take_session_reset();
        master.cancel_session(reset)?;
        Ok(UsbClient(&mut master.session))
    }

    /// Each USB controller's connector, whether a host session is attached
    /// and, while one cannot be, why: for the boot log.
    pub fn usb_diagnostics(&self) -> Vec<String> {
        self.usb_masters
            .iter()
            .map(|master| {
                let controller = self.bus.device::<Dwc3>(master.device).expect("USB core");
                let phy = self.bus.device::<AtcPhy>(master.phy).expect("USB PHY");
                let why = match controller.unavailable() {
                    Some(why) if !controller.phy_ready() => {
                        format!(" unavailable={why}: {}", phy.usb2_unready().unwrap_or("?"))
                    }
                    Some(why) => format!(" unavailable={why}"),
                    None => String::new(),
                };
                let host = controller
                    .host_summary()
                    .map_or_else(String::new, |host| format!(" host=[{host}]"));
                format!(
                    "port={} attached={}{why}{host}",
                    master.number, master.attached
                )
            })
            .collect()
    }

    pub fn take_usb_log(&mut self) -> Option<UsbLog> {
        self.usb_masters
            .iter_mut()
            .find_map(|master| master.session.take_log())
    }

    /// The next line of a USB controller's host trace, with its port.
    pub fn take_usb_host_trace(&mut self) -> Option<(u32, String)> {
        self.usb_masters.iter().find_map(|master| {
            self.bus
                .device_mut::<Dwc3>(master.device)
                .and_then(Dwc3::take_host_trace)
                .map(|line| (master.number, line))
        })
    }
}
