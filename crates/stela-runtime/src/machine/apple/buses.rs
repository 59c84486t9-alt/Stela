//! Low-speed buses and their clients: GPIO banks, SPI NOR, the UART, I2C and
//! SPMI.

use super::*;

impl AppleDevices {
    /// Places the AP GPIO bank before its clients: chip-select outputs, a
    /// pulled-up net on each I2C line and on each client interrupt pin.
    pub fn add_gpio(
        &mut self,
        bank: &stela_soc_data::board::GpioBank,
        selects: &[u32],
        interrupts: &[u32],
    ) -> Result<(), String> {
        let mut nets: Vec<(u32, Net)> = Vec::new();
        for &pin in bank.i2c_lines.iter().chain(interrupts) {
            if !nets.iter().any(|(p, _)| *p == pin) {
                nets.push((pin, Net::new()));
            }
        }
        let lines = bank
            .lines
            .iter()
            .map(|&irq| AicInput::new(0, irq))
            .collect();
        let gpio = Gpio::with_profile(bank.profile, bank.pins, lines, selects, nets.clone())
            .and_then(|gpio| gpio.with_groups(bank.groups as usize))
            .map_err(String::from)?;
        let id = self.bus.add(Box::new(gpio));
        self.bus
            .map(id, bank.physical, bank.bytes, 0)
            .map_err(|e| format!("GPIO placement: {e:?}"))?;
        self.register_power_device(bank.physical, id, false)?;
        self.gpio = Some((bank.physical, nets));
        Ok(())
    }

    /// Places another GPIO bank (`aop-gpio`, `smc-gpio`) with a pulled-up
    /// board net on each pin its clients name. A pin no device drives reads
    /// its pull-up; the board model that drives one, such as the HDMI
    /// converter's hot-plug output, attaches through [`Self::gpio_line`]
    /// before the guest runs.
    pub fn add_aux_gpio(&mut self, aux: &stela_soc_data::board::AuxGpioBank) -> Result<(), String> {
        if self
            .aux_gpios
            .iter()
            .any(|(phandle, _)| *phandle == aux.bank.phandle)
        {
            return Err(format!("GPIO bank {} placed twice", aux.name));
        }
        let nets: Vec<(u32, Net)> = aux
            .client_pins
            .iter()
            .map(|&pin| (pin, Net::new()))
            .collect();
        let lines = aux
            .bank
            .lines
            .iter()
            .map(|&irq| AicInput::new(0, irq))
            .collect();
        let gpio = Gpio::with_profile(aux.bank.profile, aux.bank.pins, lines, &[], nets.clone())
            .and_then(|gpio| gpio.with_groups(aux.bank.groups as usize))
            .map_err(|error| format!("{}: {error}", aux.name))?;
        let id = self.bus.add(Box::new(gpio));
        self.bus
            .map(id, aux.bank.physical, aux.bank.bytes, 0)
            .map_err(|e| format!("{} placement: {e:?}", aux.name))?;
        self.register_power_device(aux.bank.physical, id, false)?;
        self.aux_gpios.push((aux.bank.phandle, nets));
        Ok(())
    }

    /// A driver on `pin` of the GPIO bank with phandle `bank`: released, the
    /// pin reads high; pulled low, it reads low.
    pub fn gpio_line(&mut self, bank: u32, pin: u32) -> Result<OpenDrain, String> {
        let (_, nets) = self
            .aux_gpios
            .iter()
            .find(|(phandle, _)| *phandle == bank)
            .ok_or_else(|| format!("no auxiliary GPIO bank with phandle {bank:#x}"))?;
        let (_, net) = nets
            .iter()
            .find(|(p, _)| *p == pin)
            .ok_or_else(|| format!("GPIO pin {pin} has no client in bank {bank:#x}"))?;
        net.open_drain().map_err(String::from)
    }

    pub(super) fn gpio_net(&self, pin: u32) -> Result<&Net, String> {
        self.gpio
            .as_ref()
            .and_then(|(_, nets)| nets.iter().find(|(p, _)| *p == pin))
            .map(|(_, net)| net)
            .ok_or_else(|| format!("GPIO pin {pin} has no placed board net"))
    }

    /// Installs the DT-derived SPI controller, one NOR die and
    /// its external GPIO CS wire (or the internal PIN.CS connection). An
    /// external CS requires the placed GPIO bank.
    pub fn add_spi_nor(&mut self, placement: &stela_soc_data::board::SpiNor) -> Result<(), String> {
        let device = placement.device;
        let spi = self.bus.add(Box::new(Spi::new(
            placement.image.clone(),
            AicInput::new(0, device.irq as u16),
            placement.select.is_some(),
        )));
        self.bus
            .map(spi, device.physical, device.bytes, 0)
            .map_err(|e| format!("SPI placement: {e:?}"))?;
        self.register_power_device(device.physical, spi, false)?;
        self.nor = Some(spi);
        if let Some(pin) = placement.select {
            let (base, _) = self.gpio.as_ref().ok_or("SPI CS requires the GPIO bank")?;
            self.selects.push(SelectWire {
                spi,
                physical: base + u64::from(pin) * 4,
            });
        }
        Ok(())
    }

    /// The S5L console UART at its DeviceTree ranges.
    pub fn add_uart<C: ConsoleSink + 'static>(
        &mut self,
        console: C,
        ranges: &[Range],
        irq: Option<AicInput>,
    ) -> Result<(), String> {
        let first = ranges.first().ok_or("UART has no canonical aperture")?;
        let device = self.bus.add(Box::new(S5lUart::new(console, irq)));
        self.map(device, ranges)
            .map_err(|error| format!("UART placement: {error:?}"))?;
        self.register_power_device(first.physical, device, false)
    }

    /// Place an explicitly visible I2C controller. Addressed but unchecked
    /// targets refuse; hiding a target must not turn its protocol into success.
    /// `firmware` returns a board firmware image by its guest file name; an
    /// HPM die runs `USB-C_<personality>.bin` and drives its manager's
    /// interrupt net, whose summary the manager's own address reports.
    pub fn add_i2c<'f>(
        &mut self,
        placement: &stela_soc_data::board::I2cController,
        firmware: &dyn Fn(&str) -> Option<&'f [u8]>,
    ) -> Result<(), String> {
        let device = placement.device;
        let mut model = I2c::new(AicInput::new(0, device.irq as u16));
        // Each die's alert output on its manager's interrupt net, which the
        // manager's summary samples.
        let mut alerts = Vec::new();
        for target in &placement.targets {
            if target.compatible != stela_soc_data::board::HPM {
                continue;
            }
            let name = stela_soc_data::board::hpm_firmware_file(
                target.firmware.as_deref().ok_or("HPM names no firmware")?,
            );
            let image =
                firmware(&name).ok_or_else(|| format!("board firmware {name} was not supplied"))?;
            let die = Firmware::from_image(image).map_err(|e| format!("{name}: {e}"))?;
            let port = self.typec_port(target.port.ok_or("HPM has no port number")?);
            let pin = target.interrupt.ok_or("HPM has no bus-manager interrupt")?;
            let alert = self.gpio_net(pin)?.open_drain()?;
            let hpm = Hpm::new(port, die, target.address).with_interrupt(alert.clone());
            model
                .attach(target.address, Box::new(hpm))
                .map_err(String::from)?;
            alerts.push((pin, target.address, alert));
        }
        for target in &placement.targets {
            let reason = match target.compatible.as_str() {
                stela_soc_data::board::HPM => continue,
                stela_soc_data::board::HPM_MANAGER => {
                    let dies = alerts
                        .iter()
                        .filter(|(pin, ..)| Some(*pin) == target.interrupt)
                        .map(|(_, address, alert)| (*address, alert.clone()))
                        .collect();
                    let summary = Summary::new(dies).map_err(String::from)?;
                    model
                        .attach(target.address, Box::new(summary))
                        .map_err(String::from)?;
                    continue;
                }
                stela_soc_data::board::RETIMER => "ATC retimer register protocol is undetermined",
                _ => "I2C target protocol is not modeled",
            };
            model
                .attach(target.address, Box::new(i2c::Unmodeled(reason)))
                .map_err(String::from)?;
        }
        let id = self.bus.add(Box::new(model));
        self.bus
            .map(id, device.physical, device.bytes, 0)
            .map_err(|e| format!("I2C placement: {e:?}"))?;
        self.register_power_device(device.physical, id, false)
    }

    /// Place a visible SPMI controller and its PMUs. Bank B is the device's
    /// second 16 KiB and `reg[2]`, where placed, its third. A primary PMU's
    /// RTC starts at `wall` when the engine
    /// knows the host's time.
    pub fn add_spmi(
        &mut self,
        placement: &stela_soc_data::board::SpmiController,
        wall: Option<stela_soc_data::pmu::WallClock>,
    ) -> Result<(), String> {
        if placement.pmus.iter().any(|pmu| pmu.rtc_helper.is_some()) {
            return Err("SMC RTC helper requires an explicit virtual RTC epoch authority".into());
        }
        self.add_spmi_with_epoch(
            placement,
            wall,
            pmu::RtcEpoch {
                counter: 0,
                ticks: 0,
            },
        )
    }

    /// The boot resource owner explicitly declares this virtual oscillator
    /// origin; it is not an Apple persisted/reset-state measurement.
    pub fn add_spmi_with_epoch(
        &mut self,
        placement: &stela_soc_data::board::SpmiController,
        wall: Option<stela_soc_data::pmu::WallClock>,
        epoch: pmu::RtcEpoch,
    ) -> Result<(), String> {
        self.add_spmi_with_resources(placement, wall, epoch, &[])
    }

    /// Every outside-scratch fault log and off-to-wake source requires
    /// explicitly declared initial history. SIDs are local to this
    /// controller; entries are complete and unique.
    pub fn add_spmi_with_resources(
        &mut self,
        placement: &stela_soc_data::board::SpmiController,
        wall: Option<stela_soc_data::pmu::WallClock>,
        epoch: pmu::RtcEpoch,
        history: &[(u8, stela_soc_data::pmu::Retained, Vec<u8>)],
    ) -> Result<(), String> {
        for (index, (sid, kind, bytes)) in history.iter().enumerate() {
            if history[..index]
                .iter()
                .any(|(previous, other, _)| previous == sid && other == kind)
            {
                return Err("duplicate PMU retained-history owner".into());
            }
            let (_, window) = placement
                .pmus
                .iter()
                .filter(|pmu| pmu.sid == *sid)
                .flat_map(|pmu| pmu.retained())
                .find(|(owner, _)| owner == kind)
                .ok_or("retained history has no matching outside-scratch PMU owner")?;
            if bytes.len() != usize::from(window.bytes) {
                return Err("PMU initial retained history is incomplete".into());
            }
        }
        if placement.pmus.iter().flat_map(|pmu| pmu.retained()).count() != history.len() {
            return Err("PMU outside-scratch histories require explicit initial bytes".into());
        }
        let irq = u16::try_from(placement.irq).map_err(|_| "SPMI AIC line above 65535")?;
        let mut controller =
            Spmi::with_configuration(AicInput::new(0, irq), placement.configuration);
        // Construct/preflight every slave and global service before publishing any owner.
        let mut primary = None;
        let mut primary_clock = None;
        for pmu in &placement.pmus {
            if pmu.primary && pmu.rtc.is_none() {
                return Err("PMU primary system service requires a qualified RTC owner".into());
            }
            let configuration = pmu.configuration(|kind, _| {
                let (_, _, bytes) = history
                    .iter()
                    .find(|(sid, owner, _)| *sid == pmu.sid && *owner == kind)
                    .expect("all retained owners preflighted");
                Ok(bytes.clone())
            })?;
            let clock = pmu::RtcClock::new(epoch).map_err(String::from)?;
            let model = Pmu::with_clock(configuration, clock, wall.filter(|_| pmu.rtc.is_some()))
                .map_err(String::from)?;
            self.pmu_clocks.extend(model.rtc_clock());
            if let Some(profile) = pmu.rtc_helper {
                if !pmu.primary || self.rtc_clock.is_some() || primary_clock.is_some() {
                    return Err("RTC helper has no unique primary oscillator owner".into());
                }
                self.smc()
                    .map_err(String::from)?
                    .check_bind_rtc()
                    .map_err(String::from)?;
                primary_clock = Some((
                    model
                        .rtc_clock()
                        .ok_or("RTC helper has no actual PMU oscillator")?,
                    profile,
                ));
            }
            if pmu.primary {
                if self.sleep.pmu.is_some() || primary.is_some() {
                    return Err("multiple primary PMU system-service owners".into());
                }
                primary = Some(model.interrupt());
            }
            if let Some(vector) = pmu.interrupt {
                controller.attach_with_interrupt(pmu.sid, vector, Box::new(model))
            } else {
                controller.attach(pmu.sid, Box::new(model))
            }
            .map_err(String::from)?;
        }
        let id = self.bus.add(Box::new(controller));
        for (bank, &(base, bytes)) in placement.banks.iter().enumerate() {
            self.bus
                .map(id, base, bytes, bank as u64 * stela_soc_data::spmi::BANK_B)
                .map_err(|e| format!("SPMI bank placement: {e:?}"))?;
        }
        if let Some((base, bytes)) = placement.bank_c {
            self.bus
                .map(id, base, bytes, stela_soc_data::spmi::BANK_C)
                .map_err(|e| format!("SPMI reg[2] placement: {e:?}"))?;
        }
        if let Some((clock, profile)) = primary_clock {
            self.smc()
                .map_err(String::from)?
                .bind_rtc(clock.clone(), profile)
                .map_err(String::from)?;
            self.rtc_clock = Some(clock);
        }
        if let Some(primary) = primary {
            self.sleep.pmu = Some(primary);
        }
        Ok(())
    }
}
