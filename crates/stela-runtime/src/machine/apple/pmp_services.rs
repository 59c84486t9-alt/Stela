//! Native system services joined to the cold PMP ASC and DMA owners.
use super::{AppleDevices, ExplicitRuntimeConfiguration};
use crate::platform::apple::asc::Asc;
use crate::platform::apple::pmp;
use crate::platform::apple::pmp::native::services::Clock;
use crate::platform::apple::pmp::native::services::Services;
use crate::platform::apple::rtkit::RtKit;
use alloc::{format, string::String, sync::Arc};
use stela_contracts::bus::Access;
use stela_contracts::bus::DeviceId;
use stela_contracts::bus::Width;
use stela_engine::machine::engine::DeviceError;
use stela_engine::memory::RegisteredSystemRam;
use stela_soc_data::board::Board;

pub(super) struct NativePmpServices {
    asc: DeviceId,
    services: Services,
}

impl AppleDevices {
    /// Optional system endpoints must not advertise an AP-buffer protocol
    /// whose source DART filter cannot yet perform its memory effects. The
    /// existing application endpoint remains independently usable.
    pub fn native_pmp_system_endpoint_refusal(
        board: &Board,
    ) -> Result<Option<&'static str>, String> {
        // Services::t8112 carries source-specific reporting/trace defaults.
        // A direct MCC owner supplies no validation for that protocol.
        if board.memory_cache.is_none() || board.direct_memory_cache.is_some() {
            return Ok(Some(
                "PMP reporting/trace endpoints unavailable: this memory family has no source-qualified T8112 system-service profile; no AP buffer service is advertised",
            ));
        }
        let pmp = board
            .pmp
            .as_ref()
            .ok_or("native PMP descriptor is missing")?;
        let route = pmp.dma_route(&board.darts)?;
        let dart = board
            .darts
            .get(route.iommu)
            .ok_or("native PMP DART is missing")?;
        Ok(dart.apf.is_some().then_some(
            "PMP reporting/trace endpoints unavailable: active DART address permission filtering is unqualified; no AP buffer service is advertised",
        ))
    }

    /// Join before the first guest instruction, after every device is
    /// placed and before RTKit enumeration. Keeps the existing ASC session.
    ///
    /// # Safety
    /// The native DMA binding's persistent canonical RAM, held/fenced physical
    /// worker and closed synchronous producer contracts apply to every future
    /// service/transfer. The supplied clock reads the installed native
    /// owner. Neither this method nor endpoint attachment checks raw V1.
    pub unsafe fn bind_native_pmp_services(
        &mut self,
        board: &Board,
        ram: Arc<RegisteredSystemRam>,
        configuration: ExplicitRuntimeConfiguration,
        clock: Clock,
    ) -> Result<(), String> {
        if let Some(reason) = Self::native_pmp_system_endpoint_refusal(board)? {
            return Err(reason.into());
        }
        if self.native_pmp_services.is_some() || self.native_pmp_dma.is_some() {
            return Err("native PMP services are already bound".into());
        }
        let placement = board
            .pmp
            .as_ref()
            .ok_or("native PMP services have no live ASC descriptor")?;
        let (asc, offset) = self
            .bus
            .route(placement.wrapper.0, Width::Word)
            .map_err(|e| format!("native PMP service ASC route: {e:?}"))?;
        if offset != 0
            || self
                .bus
                .device::<Asc>(asc)
                .and_then(|asc| asc.firmware::<RtKit>())
                .is_none()
        {
            return Err("native PMP system services require the actual mounted RTKit ASC".into());
        }
        // SAFETY: same source graph and persistent canonical owner.
        let broker = unsafe { self.bind_native_pmp_dma(board, ram, configuration) }?;
        // SAFETY: native callbacks run only under the same held/fenced owner.
        let (services, endpoints) =
            unsafe { Services::t8112(broker, clock) }.map_err(String::from)?;
        let kit = self
            .bus
            .device_mut::<Asc>(asc)
            .and_then(|asc| asc.firmware_mut::<RtKit>())
            .ok_or("native PMP ASC owner changed during cold binding")?;
        if kit.endpoint_mut::<pmp::Pmp>(pmp::ENDPOINT).is_none() {
            return Err("native PMP application endpoint has another actual protocol owner".into());
        }
        kit.attach_cold_system_endpoints(endpoints)
            .map_err(String::from)?;
        self.native_pmp_services = Some(NativePmpServices { asc, services });
        Ok(())
    }

    pub(super) fn native_pmp_services_deadline(&self) -> Option<u64> {
        let owner = self.native_pmp_services.as_ref()?;
        self.bus
            .device::<Asc>(owner.asc)
            .filter(|asc| asc.execution_enabled())?;
        owner.services.deadline()
    }

    /// # Safety
    /// The persistent cold binding contract remains valid: real canonical
    /// workers are held/fenced, Devices excludes all independent producers,
    /// and the associated ASC controls whether native work may advance.
    pub(super) unsafe fn service_native_pmp_services(
        &mut self,
        cpu: usize,
        now: u64,
    ) -> Result<(), DeviceError> {
        let Some(owner) = self.native_pmp_services.as_mut() else {
            return Ok(());
        };
        let asc = self.bus.device::<Asc>(owner.asc).ok_or_else(|| {
            DeviceError::TransferRefused("native PMP service ASC owner disappeared".into())
        })?;
        if !asc.execution_enabled() {
            return Ok(());
        }
        let mut access = Access::new(cpu, now, &mut self.latch);
        owner
            .services
            .advance(&mut access)
            .map_err(|e| DeviceError::TransferRefused(format!("native PMP system service: {e}")))?;
        Ok(())
    }
}
