//! Opens the Metal service for one NVIDIA GPU: admits its Vulkan device,
//! derives the platform facts Vulkan does not report, and serves a
//! [`Device`] over the backend and compiler. [`open`] composes the native
//! stack: NVK through [`NativeBackend`], which builds its pipelines from the
//! AIR compiler service's internal kernels, and an [`AirCompiler`] for the
//! device NVK reports.
use super::{Attachment, Chip, Refusal};
#[cfg(feature = "metal-vulkan")]
use crate::metal::{
    compiler::{self, AirCompiler},
    native::{InternalKernels, Loader, MemoryExporter, NativeBackend, vk},
};
use crate::metal::{
    device::Device,
    error::Error,
    service::{Service, identity::DeviceEpoch},
    shader::Compiler,
    vulkan::{backend::Backend, physical::PciBusInfo},
};
use alloc::boxed::Box;

/// The GPU the platform hands the Metal device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Gpu {
    pub pci: PciBusInfo,
    /// nouveau's `NOUVEAU_GETPARAM_CHIPSET_ID`.
    pub chipset: u16,
    pub attachment: Attachment,
}

/// Why the Metal service did not open.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenError {
    /// The device is not an NVIDIA GPU this route drives.
    Refused(Refusal),
    /// The device lacks a requirement or could not be created.
    Device(Error),
}

impl From<Error> for OpenError {
    fn from(error: Error) -> Self {
        Self::Device(error)
    }
}

/// Serves the Metal device over `backend`, which drives `gpu`, and
/// `compiler`, in the gate's `epoch` for it.
pub fn serve<B: Backend, C: Compiler>(
    backend: B,
    compiler: C,
    gpu: &Gpu,
    epoch: DeviceEpoch,
) -> Result<Service<B, C>, OpenError> {
    let identity = &backend.physical_device().identity;
    if identity.pci_bus != Some(gpu.pci) {
        return Err(Error::Invalid("the backend drives another GPU").into());
    }
    let chip = Chip::admit(identity, gpu.chipset).map_err(OpenError::Refused)?;
    let platform = chip.platform(gpu.attachment);
    Ok(Service::new(
        Device::new(backend, compiler, &platform)?,
        epoch,
    ))
}

/// The Metal service over NVK and the AIR compiler.
#[cfg(feature = "metal-vulkan")]
pub type NativeService = Service<NativeBackend, AirCompiler>;

/// Opens NVK's device for `gpu` and serves it with the AIR compiler service
/// `compiler` answers for that device.
///
/// # Safety
///
/// `loader` is NVK's entry point and `compiler` answers the AIR compiler
/// service with NVK's NIR options for the device it is given, both outliving
/// the service.
#[cfg(feature = "metal-vulkan")]
pub unsafe fn open(
    loader: Loader,
    exporter: Box<dyn MemoryExporter>,
    compiler: impl FnOnce(vk::PhysicalDevice) -> compiler::Service,
    gpu: &Gpu,
    epoch: DeviceEpoch,
) -> Result<NativeService, OpenError> {
    let mut built = None;
    let kernels = |physical| {
        let service = compiler(physical);
        // SAFETY: the caller guarantees the service and its options.
        let kernels = unsafe { service.internal_kernels() }?;
        let [accumulate, select, resolve_draws, resolve_dispatches] = kernels.code();
        // The kernels last until the pipelines hold their own copies.
        built = Some((service, kernels));
        Ok(InternalKernels {
            accumulate,
            select,
            resolve_draws,
            resolve_dispatches,
        })
    };
    // SAFETY: the caller guarantees NVK's entry point, and the kernels are
    // the service's NIR for NVK.
    let backend = unsafe { NativeBackend::new(loader, gpu.pci, exporter, kernels) }?;
    let Some((service, kernels)) = built else {
        return Err(Error::Invalid("the backend asked for no kernels").into());
    };
    drop(kernels);
    // SAFETY: the caller guarantees the service and its options outlive it.
    let compiler = unsafe { AirCompiler::new(service, backend.physical_device()) };
    serve(backend, compiler, gpu, epoch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metal::{
        device::fixture::{MockBackend, MockCompiler},
        nvidia::{CHIPS, PcieLink},
        vulkan::DriverId,
    };
    use core::num::NonZeroU64;

    fn gpu(chipset: u16) -> Gpu {
        Gpu {
            pci: PciBusInfo {
                domain: 0,
                bus: 1,
                device: 0,
                function: 0,
            },
            chipset,
            attachment: Attachment {
                link: PcieLink {
                    speed: 4,
                    width: 16,
                },
                external: true,
                location_number: 2,
            },
        }
    }

    fn serve_on(
        backend: MockBackend,
        gpu: &Gpu,
    ) -> Result<Service<MockBackend, MockCompiler>, OpenError> {
        let epoch = DeviceEpoch::from_registered(NonZeroU64::MIN);
        serve(backend, MockCompiler::default(), gpu, epoch)
    }

    #[test]
    fn an_admitted_gpu_is_served_with_its_platform() {
        let mut service = serve_on(MockBackend::new(), &gpu(CHIPS[0].chipset)).unwrap();
        let capabilities = service.device().capabilities();
        assert_eq!(capabilities.architecture, CHIPS[0].name);
        assert!(capabilities.removable);
        assert_eq!(capabilities.location_number, 2);
    }

    #[test]
    fn other_gpus_and_drivers_are_refused() {
        let mut other = gpu(CHIPS[0].chipset);
        other.pci.bus = 2;
        assert_eq!(
            serve_on(MockBackend::new(), &other).err(),
            Some(OpenError::Device(Error::Invalid(
                "the backend drives another GPU"
            )))
        );
        assert_eq!(
            serve_on(MockBackend::new(), &gpu(0x140)).err(),
            Some(OpenError::Refused(Refusal::PreTuring { chipset: 0x140 }))
        );
        let mut backend = MockBackend::new();
        let physical = backend.physical.as_mut().unwrap();
        physical.identity.driver_id = DriverId::MesaRadv;
        assert_eq!(
            serve_on(backend, &gpu(CHIPS[0].chipset)).err(),
            Some(OpenError::Refused(Refusal::NotNvk(DriverId::MesaRadv)))
        );
    }
}
