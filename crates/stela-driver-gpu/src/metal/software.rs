//! Metal with no GPU to drive: lavapipe, whose shaders llvmpipe's JIT compiles
//! for the host's own processor. It is the same `Device` over the same
//! backend and compiler; only the driver and the platform facts differ. Memory
//! a CPU reaches is already this processor's, so the driver takes host pointers.
use super::shader::Compiler;
use super::{
    abi::DeviceLocation,
    capabilities::Platform,
    device::Device,
    error::Error,
    service::{Service, identity::DeviceEpoch},
    vulkan::backend::Backend,
};
#[cfg(feature = "metal-vulkan")]
use super::{
    compiler,
    native::{Loader, MemoryExporter, Target, vk},
    nvidia::open::{NativeService, stack},
};
#[cfg(feature = "metal-vulkan")]
use alloc::boxed::Box;
use alloc::string::String;

/// lavapipe's linear images need rows no finer than its widest texel.
const LINEAR_ROW_ALIGNMENT: u64 = 16;
/// lavapipe's `minMemoryMapAlignment`, which binds linear images.
const LINEAR_OFFSET_ALIGNMENT: u64 = 64;
/// lavapipe's sparse pages, Vulkan's standard block for most formats.
const SPARSE_PAGE_BYTES: u64 = 64 << 10;

/// What Vulkan does not report of a device that is the host's processor.
pub fn platform() -> Platform {
    Platform {
        architecture: String::from("Stela Software"),
        location: DeviceLocation::BuiltIn,
        location_number: 0,
        max_transfer_rate: 0,
        headless: false,
        removable: false,
        linear_row_alignment: LINEAR_ROW_ALIGNMENT,
        linear_offset_alignment: LINEAR_OFFSET_ALIGNMENT,
        sparse_page_bytes: SPARSE_PAGE_BYTES,
    }
}

/// Serves the Metal device over `backend` and `compiler`, in the gate's `epoch`.
pub fn serve<B: Backend, C: Compiler>(
    backend: B,
    compiler: C,
    epoch: DeviceEpoch,
) -> Result<Service<B, C>, Error> {
    Ok(Service::new(
        Device::new(backend, compiler, &platform())?,
        epoch,
    ))
}

/// Opens lavapipe's device and serves it with the AIR compiler service
/// `compiler` answers for that device.
///
/// # Safety
///
/// `loader` is lavapipe's entry point and `compiler` answers the AIR compiler
/// service with lavapipe's NIR options for the device it is given, both
/// outliving the service.
#[cfg(feature = "metal-vulkan")]
pub unsafe fn open(
    loader: Loader,
    exporter: Box<dyn MemoryExporter>,
    compiler: impl FnOnce(vk::PhysicalDevice) -> compiler::Service,
    epoch: DeviceEpoch,
) -> Result<NativeService, Error> {
    // SAFETY: the caller's guarantees.
    let (backend, compiler) = unsafe { stack(loader, Target::Processor, exporter, compiler) }?;
    serve(backend, compiler, epoch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metal::device::fixture::{MockBackend, MockCompiler};

    #[test]
    fn the_platform_is_built_in_and_shows_a_display() {
        let platform = platform();
        assert_eq!(platform.location, DeviceLocation::BuiltIn);
        assert_eq!(platform.max_transfer_rate, 0);
        assert!(!platform.headless && !platform.removable);
    }

    #[test]
    fn a_device_serves_with_the_software_platform() {
        let epoch = DeviceEpoch::from_registered(core::num::NonZeroU64::MIN);
        assert!(serve(MockBackend::new(), MockCompiler::default(), epoch).is_ok());
    }
}
