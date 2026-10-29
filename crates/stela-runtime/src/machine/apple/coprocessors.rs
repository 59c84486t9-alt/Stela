//! RTKit coprocessors and their engines: ANS, SMC, PMP, AGX, DCP, the SEP and
//! AES.

use super::*;

impl AppleDevices {
    /// Place an explicitly described ANS2, its started RTKit coprocessor
    /// (listing [`ans::RTKIT_ENDPOINT`]) and SART. Split the shared NVMe bank
    /// around SART's idle word so each physical byte has one owner. The boot
    /// chain's choice is to start the native RTKit service before handing off
    /// to SPTM.
    pub fn add_ans(
        &mut self,
        placement: &stela_soc_data::board::AnsController,
        backing: Box<dyn stela_drivers::block::BlockDevice>,
        build: &stela_formats::builds::Build,
    ) -> Result<(), String> {
        let irq = |n| AicInput::new(0, n);
        let rtkit = RtKit::new(
            vec![(ans::RTKIT_ENDPOINT, Box::new(ans::Endpoint) as Box<_>)],
            build.rtkit_version,
        )
        .map_err(String::from)?;
        let wrapper = Asc::booted(
            Box::new(rtkit),
            AscLines::from_interrupts(placement.interrupts.map(irq)),
        )
        .map_err(String::from)?;
        // The placement requires the boot stage's NVMe security hand-off,
        // which leaves the controller in linear submission mode.
        let controller = Ans::with_geometry(
            backing,
            &placement.namespaces,
            Some(irq(placement.completion_irq)),
            placement.geometry,
        )
        .map_err(String::from)?
        .handed_off_linear();
        let asc = self.bus.add(Box::new(wrapper));
        self.coprocessors.push(("ANS", asc));
        self.bus
            .map(asc, placement.wrapper.0, placement.wrapper.1, 0)
            .map_err(|e| format!("ANS ASC placement: {e:?}"))?;
        let bounds = if placement.sart_exclusive_bounds {
            stela_soc_data::sart::Bounds::Exclusive
        } else {
            stela_soc_data::sart::Bounds::Inclusive
        };
        let sart = self
            .bus
            .add(Box::new(Sart::with_layout(bounds, placement.sart_layout)));
        self.bus
            .map(sart, placement.sart.0, placement.sart.1, 0)
            .map_err(|e| format!("SART placement: {e:?}"))?;
        self.bus
            .map(sart, placement.sart_idle, 4, sart::IDLE)
            .map_err(|e| format!("SART idle placement: {e:?}"))?;
        if let Some(canary) = placement.sart_canary {
            self.bus
                .map(sart, canary, 4, sart::CANARY)
                .map_err(|e| format!("SART power canary placement: {e:?}"))?;
        }
        let ans = self.bus.add(Box::new(controller));
        let (base, bytes) = placement.nvme;
        let before = placement
            .sart_idle
            .checked_sub(base)
            .ok_or("SART idle word precedes NVMe")?;
        let after = before
            .checked_add(4)
            .filter(|&end| end <= bytes)
            .ok_or("SART idle word outside NVMe")?;
        for (offset, bytes) in [(0, before), (after, bytes - after)] {
            if bytes != 0 {
                self.bus
                    .map(ans, base + offset, bytes, offset)
                    .map_err(|e| format!("ANS placement: {e:?}"))?;
            }
        }
        if let Some((base, _)) = placement.vdma {
            self.bus
                .map(
                    ans,
                    base + ans::VDMA_CACHE_OFFSET,
                    placement.geometry.vdma_bytes(),
                    ans::VDMA_CACHE,
                )
                .map_err(|e| format!("ANS VDMA cache placement: {e:?}"))?;
        }
        self.storage_masters.push((ans, sart));
        // These are three banks of the same ANS resource. In particular a
        // later protected-NVMe/SART veto must precede any ASC reset effects.
        self.register_power_device(placement.wrapper.0, asc, false)?;
        self.register_power_device(placement.wrapper.0, ans, false)?;
        self.register_power_device(placement.wrapper.0, sart, false)?;
        Ok(())
    }

    /// Place an explicitly described SMC: its started, user-power-managed
    /// RTKit with the native key endpoint, the shared page at the nub's
    /// region base, and the hardware watchdog bank AppleSMC disarms. The
    /// rest of the nub region, the coprocessor's own memory, stays unmapped.
    pub fn add_smc(
        &mut self,
        placement: &stela_soc_data::board::SmcController,
        build: &stela_formats::builds::Build,
    ) -> Result<(), String> {
        let sram = smc::Sram::default();
        let keys = placement
            .gpio_keys
            .iter()
            .map(|&name| (name, smc::Key::gpio()))
            .collect();
        let endpoint = Smc::new(sram.clone(), placement.region.0, keys)
            .map_err(String::from)?
            .with_wake_bits(placement.wake_bits);
        let mut rtkit = RtKit::new(
            vec![(smc::ENDPOINT, Box::new(endpoint))],
            build.rtkit_version,
        )
        .map_err(String::from)?;
        if placement.quiesced {
            rtkit = rtkit.quiesced();
        }
        let wrapper = Asc::booted(
            Box::new(rtkit),
            AscLines::from_interrupts(placement.interrupts.map(|n| AicInput::new(0, n))),
        )
        .map_err(String::from)?;
        let asc = self.bus.add(Box::new(wrapper));
        self.coprocessors.push(("SMC", asc));
        self.bus
            .map(asc, placement.wrapper.0, placement.wrapper.1, 0)
            .map_err(|e| format!("SMC ASC placement: {e:?}"))?;
        let window = self.bus.add(Box::new(smc::SramWindow(sram)));
        self.bus
            .map(window, placement.region.0, smc::SRAM_BYTES, 0)
            .map_err(|e| format!("SMC shared page placement: {e:?}"))?;
        if let Some((base, bytes)) = placement.watchdog {
            let watchdog = self.bus.add(Box::new(smc::Watchdog));
            self.bus
                .map(watchdog, base, bytes.min(smc::WATCHDOG_BYTES), 0)
                .map_err(|e| format!("SMC watchdog placement: {e:?}"))?;
        }
        Ok(())
    }

    /// Place an explicitly described PMP: its started, user-power-managed
    /// RTKit with the native `PMPEndpoint1` (`pmp::Pmp`). Its PTD bank is
    /// the memory cache's ([`Self::add_memory_channels`]).
    pub fn add_pmp(
        &mut self,
        placement: &stela_soc_data::board::PmpController,
        build: &stela_formats::builds::Build,
    ) -> Result<(), String> {
        let mut rtkit = RtKit::new(
            vec![(pmp::ENDPOINT, Box::new(pmp::Pmp::default()))],
            build.rtkit_version,
        )
        .map_err(String::from)?;
        if placement.quiesced {
            rtkit = rtkit.quiesced();
        }
        let wrapper = Asc::booted(
            Box::new(rtkit),
            AscLines::from_interrupts(placement.interrupts.map(|n| AicInput::new(0, n))),
        )
        .map_err(String::from)?;
        let asc = self.bus.add(Box::new(wrapper));
        self.coprocessors.push(("PMP", asc));
        self.bus
            .map(asc, placement.wrapper.0, placement.wrapper.1, 0)
            .map_err(|e| format!("PMP ASC placement: {e:?}"))?;
        self.register_power_device(placement.wrapper.0, asc, false)
    }

    /// Place the AGX GPU: the started GFX coprocessor (RTKit with the native
    /// GFX endpoints, `agx::firmware`) behind its ASC wrapper, and the `sgx`
    /// register block whose MMU configuration roots the UAT the firmware
    /// masters memory through.
    pub fn add_gfx(
        &mut self,
        placement: &stela_soc_data::board::GfxController,
        build: &stela_formats::builds::Build,
    ) -> Result<(), String> {
        let sgx_physical = placement
            .sgx
            .first()
            .ok_or("SGX has no canonical register aperture")?
            .0;
        let sgx = Sgx::handed_off(placement.gpu, placement.ttbat, placement.shared_l2)
            .map_err(String::from)?;
        let power = sgx
            .firmware_power(&placement.sgx)
            .and_then(|power| power.with_asc_wrapper(placement.wrapper.0))
            .map_err(String::from)?;
        let native_control = power.native_asc_control();
        let coprocessor =
            GfxCoprocessor::with_power(placement.gpu.family, power, build).map_err(String::from)?;
        let wrapper = Asc::booted(
            Box::new(coprocessor),
            AscLines::from_interrupts(placement.interrupts.map(|n| AicInput::new(0, n))),
        )
        .map_err(String::from)?;
        let asc = self.bus.add(Box::new(wrapper));
        self.coprocessors.push(("GFX", asc));
        self.bus
            .map(asc, placement.wrapper.0, placement.wrapper.1, 0)
            .map_err(|e| format!("GFX ASC placement: {e:?}"))?;
        // T8112's 64 MiB `sgx` window spans the `gfx-asc` wrapper and a PMGR
        // fabric bridge; each physical byte has one owner, so each bank owns
        // only what the smaller banks placed before it leave.
        let block = self.bus.add(Box::new(sgx));
        for &(base, bytes, offset) in &placement.sgx {
            self.bus
                .map_gaps(block, base, bytes, offset)
                .map_err(|e| format!("sgx placement: {e:?}"))?;
        }
        if let Some(control) = native_control
            && !self
                .bus
                .route(control, Width::Double)
                .is_ok_and(|(owner, _)| owner == block)
        {
            return Err(
                "GFX native ASC control is not wholly owned by its mounted SGX bank".into(),
            );
        }
        self.gfx_masters.push((asc, block));
        // sgx and gfx-asc are distinct root resources, coupled by their
        // shared original PMGR domain, not an invented parent/child owner.
        self.register_power_device(placement.wrapper.0, asc, false)?;
        self.register_power_device(sgx_physical, block, false)?;
        Ok(())
    }

    /// Place the `dcpext` display coprocessor: its booted RTKit (reusing the
    /// common ASC wrapper) carrying the IOMFB link endpoint and the AFK/EPIC
    /// endpoints, presenting one fixed connected monitor to `scanout`, and
    /// mastering the AP's link region through `dart` stream `stream`
    /// (`window` as `dcp::Coprocessor::new` takes it) and reading swap
    /// surfaces through `surface`, the display pipe's DART stream
    /// (`dart-dispext0` stream 0 on J473AP), when it is placed. The DCPEXT
    /// nub is `quiesced`, so (like the SMC) the coprocessor acknowledges the
    /// AP's wake once RTKit enumeration completes behind the boot-chain
    /// handoff. This does not admit DCPEXT in `stela_soc_data::board::models` (see
    /// `platform::apple::dcp`).
    pub fn add_dcpext(
        &mut self,
        nub: DcpextNub,
        scanout: Box<dyn Scanout>,
        dma: DcpextDma,
        build: &stela_formats::builds::Build,
    ) -> Result<(), String> {
        let DcpextNub {
            wrapper,
            interrupts,
            quiesced,
            role,
            identity,
        } = nub;
        let DcpextDma {
            link: (dart, stream),
            window,
            surface,
        } = dma;
        if wrapper.bytes < asc::WRAPPER_BYTES {
            return Err("DCPEXT register aperture is incomplete".into());
        }
        self.validate_native_dart("DCP firmware", dart, stream)?;
        if let Some((dart, stream)) = surface {
            self.validate_native_dart("DCP surface", dart, stream)?;
        }
        let mut coprocessor = dcp::Coprocessor::for_external(scanout, window, identity, build)
            .map_err(String::from)?;
        if quiesced {
            coprocessor = coprocessor.quiesced();
        }
        let wrap = Asc::booted(
            Box::new(coprocessor),
            AscLines::from_interrupts(interrupts.map(|n| AicInput::new(0, n as u16))),
        )
        .map_err(String::from)?;
        let asc = self.bus.add(Box::new(wrap));
        self.coprocessors.push((role, asc));
        self.dcp_masters.push(DcpMaster {
            asc,
            dart: dart.0,
            stream,
            surface: surface.map(|(dart, stream)| (dart.0, stream)),
        });
        self.bus
            .map(asc, wrapper.physical, wrapper.bytes, 0)
            .map_err(|e| format!("DCPEXT ASC placement: {e:?}"))?;
        self.register_power_device(wrapper.physical, asc, false)
    }

    /// Place the display-hardware register apertures around the DCP
    /// (`dispext0`, `dptx-phy`, `display-crossbar0`): present but with no
    /// modeled register meaning, since the DCP firmware programs them. Each
    /// `(name, range)` is one aperture; an access by the AP refuses, named.
    pub fn add_display(&mut self, regions: &[(&'static str, Range)]) -> Result<(), String> {
        for &(name, range) in regions {
            let device = self.bus.add(Box::new(display_hw::Region::new(name)));
            self.bus
                .map(device, range.physical, range.bytes, 0)
                .map_err(|e| format!("{name} placement: {e:?}"))?;
        }
        Ok(())
    }

    /// SEP ROM prefix at DT wrapper/auxiliary ranges, on its four mailbox
    /// lines and dart-sep stream. This does not admit SEP in `stela_soc_data::board::models`.
    pub fn add_sep(
        &mut self,
        [wrapper, auxiliary]: [Range; 2],
        lines: asc::Lines,
        (dart, stream): (DartId, usize),
        entropy: Box<dyn sep::Entropy>,
        provisioning: SepProvisioning,
    ) -> Result<(), String> {
        let SepProvisioning {
            security,
            ecid,
            observe,
            state,
        } = provisioning;
        if wrapper.bytes < asc::WRAPPER_BYTES || auxiliary.bytes == 0 {
            return Err("SEP register apertures are incomplete".into());
        }
        let owner = self
            .bus
            .device::<Dart>(dart.0)
            .ok_or("SEP DMA owner is not a mounted DART")?;
        if stream >= owner.stream_capacity() {
            return Err("SEP incoming stream exceeds its mounted DART capacity".into());
        }
        let device = self.bus.add(Box::new(
            Sep::new(entropy, lines, security, ecid, observe, state).map_err(String::from)?,
        ));
        self.bus
            .map(device, wrapper.physical, wrapper.bytes, 0)
            .map_err(|e| format!("SEP wrapper placement: {e:?}"))?;
        self.bus
            .map(
                device,
                auxiliary.physical,
                auxiliary.bytes,
                sep::AUXILIARY_OFFSET,
            )
            .map_err(|e| format!("SEP auxiliary placement: {e:?}"))?;
        self.sep_masters.push(SepMaster {
            sep: device,
            dart: dart.0,
            stream,
        });
        Ok(())
    }

    /// An `aes,s8000` the ADT describes in `config`, at its block and
    /// key-disable ranges and, from version 5, its DKey range, whose DMA
    /// goes through `stream` of `dart` and whose UID1 key is `uid`, if the
    /// board has one.
    pub fn add_aes(
        &mut self,
        ranges: &[Range],
        config: stela_soc_data::aes::Config,
        irq: Option<AicInput>,
        (dart, stream): (DartId, usize),
        uid: Option<[u8; 32]>,
    ) -> Result<(), String> {
        self.validate_native_dart("AES", dart, stream)?;
        let expected = if config.has_dkey() { 3 } else { 2 };
        if ranges.len() != expected {
            return Err(format!(
                "AES aes-version {} has {expected} register ranges, not {}",
                config.version,
                ranges.len()
            ));
        }
        if ranges[0].bytes != aes::BLOCK_BYTES {
            return Err(format!(
                "AES block registers span {:#x} bytes, not the modeled {:#x}",
                ranges[0].bytes,
                aes::BLOCK_BYTES
            ));
        }
        if ranges[1].bytes != config.key_disable.bytes {
            return Err("AES key-disable range differs from its layout".into());
        }
        let engine = Aes::new(config, irq, uid).map_err(String::from)?;
        let device = self.bus.add(Box::new(engine));
        self.map(device, ranges)
            .map_err(|error| format!("AES placement: {error:?}"))?;
        self.register_power_device(ranges[0].physical, device, false)?;
        self.masters.push(Master {
            aes: device,
            dart: dart.0,
            stream,
        });
        Ok(())
    }

    /// The SMC's native key endpoint.
    pub(super) fn smc(&mut self) -> Result<&mut Smc, &'static str> {
        let &(_, id) = self
            .coprocessors
            .iter()
            .find(|(role, _)| *role == "SMC")
            .ok_or("the board has no SMC")?;
        self.bus
            .device_mut::<Asc>(id)
            .and_then(Asc::firmware_mut::<RtKit>)
            .and_then(|rtkit| rtkit.endpoint_mut::<Smc>(smc::ENDPOINT))
            .ok_or("the SMC coprocessor has no native key endpoint")
    }

    /// One observed key write, including its unchanged raw reply or refusal.
    pub fn take_smc_log(&mut self) -> Option<SmcWriteLog> {
        self.smc().ok()?.take_log()
    }

    /// The next entry of a display coprocessor's log: what the guest sent
    /// the DCP model and what it answered or refused.
    pub fn take_display_log(&mut self) -> Option<DisplayLog> {
        let ids: Vec<DeviceId> = self.dcp_masters.iter().map(|master| master.asc).collect();
        ids.into_iter().find_map(|id| {
            self.bus
                .device_mut::<Asc>(id)
                .and_then(Asc::firmware_mut::<dcp::Coprocessor>)
                .and_then(dcp::Coprocessor::take_log)
        })
    }
}
