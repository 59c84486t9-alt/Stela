//! HD Audio controllers on their claimed function, owned BAR0 and DMA domain,
//! started and their codecs bound as Linux's `azx_probe_continue` binds them.
use super::{Claimed, Failure, NativeServices, ServiceError, claim, map};
use crate::{
    Clock,
    audio::{
        self,
        hda::{self, CodecFailure, CodecGraph, CodecSetup},
    },
    bus::{
        dma::DomainAllocator,
        mmio::{Mmio, owned::Mapping},
        pci::{Address, Function, owned::OwnedConfig},
    },
    probe::Error,
};
use alloc::{boxed::Box, string::String, vec::Vec};

/// An HD Audio controller on its prepared function and owned BAR0.
pub type Hda = hda::Controller<hda::pci::PciRegisters<'static, Bar0, OwnedConfig>, Clock>;

/// HD Audio BAR0 through its owned uncached mapping, at native widths.
pub struct Bar0 {
    mmio: Mmio,
    bytes: usize,
    _mapping: Mapping,
}

impl hda::Registers for Bar0 {
    fn region_bytes(&self) -> usize {
        self.bytes
    }
    fn read8(&mut self, offset: usize) -> u8 {
        self.mmio.read8(offset)
    }
    fn read16(&mut self, offset: usize) -> u16 {
        self.mmio.read16(offset)
    }
    fn read32(&mut self, offset: usize) -> u32 {
        self.mmio.read32(offset)
    }
    fn write8(&mut self, offset: usize, value: u8) {
        self.mmio.write8(offset, value);
    }
    fn write16(&mut self, offset: usize, value: u16) {
        self.mmio.write16(offset, value);
    }
    fn write32(&mut self, offset: usize, value: u32) {
        self.mmio.write32(offset, value);
    }
}

/// A discovered codec and the vendor setup it bound to.
pub struct Codec {
    pub graph: CodecGraph,
    pub setup: Result<CodecSetup, audio::Error>,
}

/// An attached HD Audio controller. No guest audio device consumes it yet.
pub struct Host {
    pub location: String,
    pub controller: Hda,
    /// The controller's DMA domain allocator, which streams draw on.
    pub dma: DomainAllocator<'static>,
    pub codecs: Vec<Codec>,
    /// Codecs that failed enumeration on some discovery attempt.
    pub codec_failures: Vec<CodecFailure>,
    /// Why discovery found no usable codec.
    pub discovery_error: Option<audio::Error>,
}

/// Attach the HD Audio controller at `address`: prepare its function over
/// the owned BAR0, start the controller on the function's own DMA domain,
/// then discover its codecs and apply each one's vendor setup.
///
/// # Safety
/// [`NativeServices`]' contract holds for `services`, `clock` is the
/// handoff's calibrated clock, and no firmware, AML or SMM agent drives the
/// controller: the identity table admits only conventional (non-DSP)
/// controllers.
#[expect(
    clippy::result_large_err,
    reason = "a failed attach hands back the owners that must outlive the device"
)]
pub(in crate::probe) unsafe fn attach(
    services: &dyn NativeServices,
    address: Address,
    clock: Clock,
) -> Result<Host, Failure> {
    let refused = |error: ServiceError| (Error::Native(error), None);
    let Claimed {
        function,
        domain,
        bars,
    } = claim(services, address).map_err(refused)?;
    let mapping = map(services, address, &bars, 0).map_err(refused)?;
    let bar = bars[0].expect("map checked BAR0");
    let bytes = mapping
        .bytes()
        .map_err(|error| refused(ServiceError::Mapping(error)))?;
    let window = mapping
        .address(0, bytes)
        .map_err(|error| refused(ServiceError::Mapping(error)))?;
    let registers = Bar0 {
        // SAFETY: `window` is the whole owned uncached BAR0 mapping, which
        // `_mapping` keeps; the claimed function has no other driver.
        mmio: unsafe { Mmio::new(window.as_ptr() as u64) },
        bytes,
        _mapping: mapping,
    };
    // The controller keeps its function for the boot; nothing detaches it.
    let function: &'static mut Function<OwnedConfig> = Box::leak(Box::new(function));
    let kept = |owner: Box<dyn core::any::Any>| Some(owner);
    // SAFETY: the mount claimed the stopped function with its own domain and
    // mapped exactly its BAR0 uncached; the caller excludes other agents.
    let registers = unsafe {
        hda::pci::prepare_with_registers(
            function,
            bar,
            &clock,
            hda::pci::Ownership::ExclusiveLegacy,
            registers,
        )
    }
    .map_err(|error| (Error::HdaPci(error), kept(Box::new(domain.clone()))))?;
    let config = registers.config();
    // SAFETY: `domain` is the claimed controller's, which `prepare` set to
    // snoop; the limit is the identity's DMA reach.
    let mut dma = unsafe {
        DomainAllocator::new(
            services.pages(),
            domain,
            u64::MAX >> (64 - u32::from(config.dma_address_bits)),
        )
    };
    // SAFETY: preparation above established the function's power, decode,
    // snoop and identity setup over its own mapping and DMA domain.
    let mut controller = match unsafe { Hda::new(registers, clock, &mut dma, config) } {
        Ok(controller) => controller,
        Err(error) => return Err((Error::Hda(error), kept(Box::new(dma)))),
    };
    let (codecs, codec_failures, discovery_error) = match controller.discover_codecs() {
        Ok(discovery) => (discovery.codecs, discovery.failures, None),
        Err(failure) => (Vec::new(), failure.failures, Some(failure.error)),
    };
    let codecs = codecs
        .into_iter()
        .map(|graph| Codec {
            setup: controller.initialize_codec(&graph),
            graph,
        })
        .collect();
    Ok(Host {
        location: alloc::format!("{address}"),
        controller,
        dma,
        codecs,
        codec_failures,
        discovery_error,
    })
}
