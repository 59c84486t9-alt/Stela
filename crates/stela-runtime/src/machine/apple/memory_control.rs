//! Memory and I/O access controllers, DRAM channels and DART translation
//! groups.

use super::*;

impl AppleDevices {
    /// The AMCC's lock registers at each aperture of `layout`, with the
    /// regions iBoot programmed per CTRR group (`[base, base + bytes)`), and the
    /// memory cache's registers when the board shows its `cache`.
    pub fn add_memory_controller(
        &mut self,
        apertures: &[u64],
        layout: stela_soc_data::amcc::Layout,
        programmed: stela_soc_data::amcc::Programmed,
        cache: Option<stela_soc_data::amcc::Cache>,
    ) -> Result<(), String> {
        let device = self.map_lock_controller(apertures, layout, programmed, cache)?;
        self.memory_controller = Some(device);
        Ok(())
    }

    /// A separately owned I/O-access controller protects the same boot run
    /// at its declared aperture map; it does not replace the DRAM controller.
    pub fn add_io_access_controller(
        &mut self,
        apertures: &[u64],
        layout: stela_soc_data::amcc::Layout,
        programmed: stela_soc_data::amcc::Programmed,
    ) -> Result<(), String> {
        self.map_lock_controller(apertures, layout, programmed, None)?;
        Ok(())
    }

    pub(super) fn map_lock_controller(
        &mut self,
        apertures: &[u64],
        layout: stela_soc_data::amcc::Layout,
        programmed: stela_soc_data::amcc::Programmed,
        cache: Option<stela_soc_data::amcc::Cache>,
    ) -> Result<DeviceId, String> {
        if cache.is_some() {
            return Err(
                "MCC/DCS/PTD mount requires an actual qualified memory, drain and service owner"
                    .into(),
            );
        }
        if layout.cache_status.is_some_and(|status| {
            layout
                .stride
                .checked_mul(u64::from(layout.planes))
                .is_none_or(|end| status.offset >= end)
        }) {
            return Err(
                "AMCC shared MCC status requires the prepared joint memory resource owner".into(),
            );
        }
        let model = Amcc::new(layout, apertures.len(), programmed, cache).map_err(String::from)?;
        let ranges: alloc::vec::Vec<(u64, u64, u64)> = apertures
            .iter()
            .enumerate()
            .map(|(index, &physical)| {
                let offset = u64::try_from(index)
                    .ok()
                    .and_then(|index| index.checked_mul(layout.aperture_bytes))
                    .ok_or("CTRR device aperture offsets overflow")?;
                Ok((physical, layout.aperture_bytes, offset))
            })
            .collect::<Result<_, String>>()?;
        self.bus
            .install(Box::new(model), &ranges)
            .map_err(|error| format!("CTRR controller placement: {error:?}"))
    }

    /// The memory cache controller's `channels` DRAM channels, sharing
    /// `range` evenly, and the PMP's PTD bank at `ptd` with its `ranges`.
    pub fn add_memory_channels(
        &mut self,
        range: Range,
        channels: usize,
        ptd: u64,
        ranges: &[stela_soc_data::ptd::Range],
    ) -> Result<(), String> {
        let _ = (range, channels, ptd, ranges);
        Err("MCC/DCS/PTD mount requires an actual qualified memory, drain and service owner".into())
    }

    /// Independently programmed DT TRAD windows with a shared fault wire.
    /// Returned IDs keep DT instance order. This does not choose a USB DMA
    /// stream or resolve a mapper to one instance.
    pub fn add_dart_group(
        &mut self,
        ranges: &[Range],
        streams: usize,
        irq: Option<AicInput>,
        apf: Option<(u64, usize)>,
    ) -> Result<Vec<DartId>, MapError> {
        if ranges.is_empty() {
            return Err(MapError::Empty);
        }
        self.place_dart_group(Dart::group(streams, irq, ranges.len()), ranges, apf, irq)
    }

    /// Select the DT register/table family before publishing windows.
    /// Legacy filter and capture variants need their own native contracts.
    pub fn add_dart_group_for_profile(
        &mut self,
        profile: stela_soc_data::dart::Profile,
        ranges: &[Range],
        streams: usize,
        irq: Option<AicInput>,
        apf: Option<(u64, usize)>,
    ) -> Result<Vec<DartId>, String> {
        if !profile.is_t8110() && apf.is_some() {
            return Err("legacy DART APF topology and filtering are unsupported".into());
        }
        if !profile.is_t8110() && ranges.len() > 5 {
            return Err(
                "legacy DART topology exceeds the recovered five-instance placement".into(),
            );
        }
        if apf.is_some_and(|(physical, slices)| {
            !physical.is_multiple_of(stela_soc_data::dart::DAPF_BYTES)
                || slices == 0
                || slices as u64 > stela_soc_data::dart::DAPF_BYTES / 0x40
        }) {
            return Err("DART APF requires one aligned window with a native slice count".into());
        }
        if ranges.iter().any(|range| {
            !profile.admits_window(range.bytes)
                || !range
                    .physical
                    .is_multiple_of(stela_soc_data::dart::DAPF_BYTES)
                || range.physical.checked_add(range.bytes).is_none()
        }) {
            return Err(
                "DART translation ranges must be aligned windows of the profile's register file"
                    .into(),
            );
        }
        let models = Dart::group_for_profile(profile, streams, irq, ranges.len())?;
        self.place_dart_group(models, ranges, apf, irq)
            .map_err(|error| format!("DART native placement: {error:?}"))
    }

    pub(super) fn place_dart_group(
        &mut self,
        models: Vec<Dart>,
        ranges: &[Range],
        apf: Option<(u64, usize)>,
        irq: Option<AicInput>,
    ) -> Result<Vec<DartId>, MapError> {
        let mut models = models;
        self.share_dart_irq(&mut models, irq);
        let mut ids = Vec::new();
        for (index, (mut dart, range)) in models.into_iter().zip(ranges).enumerate() {
            if index == 0
                && let Some((_, slices)) = apf
            {
                dart = dart.with_apf(slices);
            }
            let device = self.bus.add(Box::new(dart));
            self.map(device, &[*range])?;
            if index == 0
                && let Some((physical, _)) = apf
            {
                self.bus.map(
                    device,
                    physical,
                    stela_soc_data::dart::DAPF_BYTES,
                    dart::DAPF_OFFSET,
                )?;
            }
            ids.push(DartId(device));
        }
        Ok(ids)
    }

    /// Fresh models have no asserted source and were built with this exact
    /// input. Bind before publishing any aperture, preserving all existing
    /// groups on the physical wire when a later group is added.
    pub(super) fn share_dart_irq(&mut self, models: &mut [Dart], input: Option<AicInput>) {
        let Some(input) = input else { return };
        let shared = match self.dart_irqs.iter().find(|(key, _)| *key == input) {
            Some((_, shared)) => shared.clone(),
            None => {
                let shared = dart::SharedIrq::new(input);
                self.dart_irqs.push((input, shared.clone()));
                shared
            }
        };
        for model in models {
            model
                .bind_shared_irq(&shared)
                .expect("fresh DART retains its declared inactive physical input");
        }
    }

    /// Map the capture view of an existing DART, sharing its lifecycle.
    /// Validate and map before attaching so a failed placement changes neither
    /// the device's capabilities nor the physical address map.
    pub fn add_dart_smmu(&mut self, dart: DartId, range: Range) -> Result<(), String> {
        if range.bytes != dart::SMMU_BYTES || !range.physical.is_multiple_of(dart::SMMU_BYTES) {
            return Err("DART SMMU range must be one aligned 16 KiB aperture".into());
        }
        let model = self
            .bus
            .device::<Dart>(dart.0)
            .ok_or("DART SMMU owner is not a DART")?;
        if !model.supports_smmu() {
            return Err("DART generation has no supported paired SMMU capture format".into());
        }
        if model.has_smmu() {
            return Err("DART already has a paired SMMU view".into());
        }
        self.bus
            .map(dart.0, range.physical, range.bytes, dart::SMMU_OFFSET)
            .map_err(|error| format!("DART SMMU mapping: {error:?}"))?;
        self.bus
            .device_mut::<Dart>(dart.0)
            .expect("validated DART owner remains present")
            .enable_smmu()
            .expect("validated DART capture support and uniqueness remain unchanged");
        Ok(())
    }

    /// A `dart,t8110` of `streams` streams at `range`.
    pub fn add_dart(
        &mut self,
        range: Range,
        streams: usize,
        irq: Option<AicInput>,
        apf: Option<(u64, usize)>,
    ) -> Result<DartId, MapError> {
        let mut model = Dart::new(streams, irq);
        self.share_dart_irq(core::slice::from_mut(&mut model), irq);
        if let Some((_, slices)) = apf {
            model = model.with_apf(slices);
        }
        let device = self.bus.add(Box::new(model));
        self.bus.map(device, range.physical, range.bytes, 0)?;
        if let Some((physical, _)) = apf {
            self.bus.map(
                device,
                physical,
                stela_soc_data::dart::DAPF_BYTES,
                dart::DAPF_OFFSET,
            )?;
        }
        Ok(DartId(device))
    }

    /// Pure preflight of boxed ownership and incoming-SID capacity.
    /// Boot adapters validate every declared bank/mapper before publication;
    /// this does not enable DMA or check a physical traffic classifier.
    pub fn validate_native_dart(
        &self,
        name: &str,
        dart: DartId,
        stream: usize,
    ) -> Result<(), String> {
        let owner = self
            .bus
            .device::<Dart>(dart.0)
            .ok_or_else(|| format!("{name} DMA owner is not a mounted DART"))?;
        if stream >= owner.stream_capacity() {
            return Err(format!(
                "{name} incoming stream exceeds its mounted DART capacity"
            ));
        }
        Ok(())
    }
}
