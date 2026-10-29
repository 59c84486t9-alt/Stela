//! Original owned PCI configuration for a process-local native service.
//!
//! This is an access/lifetime boundary, not a host bridge, driver registry or
//! DMA attachment. Its unsafe producer must keep the real exclusion owner.
use super::{
    Address, EcamWindow, Function,
    owned::{ConfigError, ConfigRetention, OwnedConfig},
};
use crate::bus::dma::{
    mapping::{DmaDomain, DmaError},
    memory::PageSource,
};
use alloc::{boxed::Box, rc::Rc, sync::Arc};
use core::{any::Any, cell::RefCell, mem::ManuallyDrop};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Access { offset: u16, width: u8 },
    Config(ConfigError),
    IdentityChanged,
    Unavailable,
    Borrowed,
    Dma(DmaError),
    UnsupportedPolicy,
    AlreadyClaimed,
}

/// First unsupported configuration transition observed by this owner.
/// A denied write has no config effect but prevents claiming device readiness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeniedWrite {
    pub offset: u16,
    pub width: u8,
    pub value: u32,
}

/// Immutable observed identity and ECAM routing. This describes one
/// function; an MCFG window does not identify a Linux host/root bus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Description {
    pub address: Address,
    pub window: EcamWindow,
    pub vendor: u16,
    pub device: u16,
    pub class_revision: u32,
    pub header_type: u8,
    /// Extent of the ECAM mapping, not observed device cfg_size. A
    /// conventional function can expose only 256 bytes inside this 4 KiB window;
    /// the PCI setup/capability path must determine device support.
    pub mapped_config_bytes: u16,
}

pub type Parts = (Function<OwnedConfig>, Box<dyn Any>);

/// Sole original config writer. No config pointer, mutable Function or cloned
/// mapping escapes. The originating exclusion owner is held with it.
/// Uncertain/drop paths keep both owners permanently; refcount release alone
/// cannot establish DMA, IRQ, config-worker or C-callback retirement.
pub struct NativeFunction {
    function: ManuallyDrop<Function<OwnedConfig>>,
    exclusion: ManuallyDrop<Box<dyn Any>>,
    retention: ManuallyDrop<ConfigRetention>,
    description: Description,
    failure: Option<Error>,
    binding_issued: bool,
    bound: ManuallyDrop<Option<(Arc<dyn PciDmaDomain>, u64)>>,
    registration_issued: bool,
    denied: Option<DeniedWrite>,
    denied_count: u64,
}

impl Drop for NativeFunction {
    fn drop(&mut self) {
        // All three original owners are ManuallyDrop: ordinary reference
        // release cannot prove external C/DMA/IRQ retirement. Only release()
        // takes them after its explicit complete-retirement grant.
    }
}

fn observe(config: &OwnedConfig) -> Result<Description, Error> {
    let id = config.try_read32(0).map_err(Error::Config)?;
    if id as u16 == 0xffff || id as u16 == 0 {
        return Err(Error::Unavailable);
    }
    let class_revision = config.try_read32(8).map_err(Error::Config)?;
    let header_type = config.try_read8(0x0e).map_err(Error::Config)?;
    if header_type == 0xff {
        return Err(Error::Unavailable);
    }
    Ok(Description {
        address: config.address(),
        window: config.window(),
        vendor: id as u16,
        device: (id >> 16) as u16,
        class_revision,
        header_type,
        mapped_config_bytes: 4096,
    })
}

impl NativeFunction {
    /// Preserve the original canonical stopped-requester split. The returned
    /// binding must be consumed by its remapper attachment; it grants
    /// no translation/root takeover or isolation by itself.
    ///
    /// # Safety
    /// As for `attach`; the stopped requester's original engine/IRQ/coherency
    /// grant remains current until the remapper consumes the binding.
    pub unsafe fn attach_stopped(
        requester: super::requester::StoppedRequester,
        exclusion: Box<dyn Any>,
    ) -> Result<(Self, super::requester::RequesterBinding), (Error, Parts)> {
        let (requester, binding) = match requester.into_dma_binding() {
            Ok(pair) => pair,
            Err((_, requester)) => {
                return Err((Error::Unavailable, (requester.into_function(), exclusion)));
            }
        };
        // SAFETY: caller supplies the original attachment/exclusion grant.
        unsafe { Self::attach(requester.into_function(), exclusion) }.map(|mut function| {
            // Seal BEFORE the canonical binding escapes. It can be installed
            // into a real remapper before NativeDmaRoot::bind is called.
            function.binding_issued = true;
            (function, binding)
        })
    }
    /// Consume owned configuration and its originating exclusion owner.
    /// Rejection returns both original owners, including retirement obligations.
    ///
    /// # Safety
    /// `exclusion` is the platform/device owner, keeping this
    /// function's D0/config availability, firmware/config writer exclusion,
    /// root routing, reset, removal and assignment epoch stable. Its lifetime
    /// covers all C callbacks and child resources. No raw/foreign config alias
    /// or reset worker may coexist. All methods and final retirement obey the
    /// mapping's process/CPU context. Observed IDs grant none of this.
    /// No DMA domain, coherency, engine stop or topology is inferred here.
    pub unsafe fn attach(
        mut function: Function<OwnedConfig>,
        exclusion: Box<dyn Any>,
    ) -> Result<Self, (Error, Parts)> {
        let description = match observe(function.config()) {
            Ok(value) => value,
            Err(error) => return Err((error, (function, exclusion))),
        };
        if function.address != description.address {
            return Err((Error::IdentityChanged, (function, exclusion)));
        }
        let retention = match function.config().retain_epoch() {
            Ok(value) => value,
            Err(error) => {
                return Err((
                    Error::Config(ConfigError::Mapping(error)),
                    (function, exclusion),
                ));
            }
        };
        Ok(Self {
            function: ManuallyDrop::new(function),
            exclusion: ManuallyDrop::new(exclusion),
            retention: ManuallyDrop::new(retention),
            description,
            failure: None,
            binding_issued: false,
            bound: ManuallyDrop::new(None),
            registration_issued: false,
            denied: None,
            denied_count: 0,
        })
    }

    fn latch<T>(&mut self, result: Result<T, Error>) -> Result<T, Error> {
        if let Err(error) = result {
            self.failure.get_or_insert(error);
        }
        result
    }

    /// Pure kept mapping/execution/epoch and latched-failure observation.
    /// No config register is read. A stopped device remains current while its
    /// real mapping and remapper context are held. Detach is not a stop.
    pub fn check_current(&self) -> Result<(), Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        self.retention
            .check_live()
            .map_err(|e| Error::Config(ConfigError::Mapping(e)))?;
        if let Some((domain, generation)) = &*self.bound {
            let actual = domain
                .check_current_configuration(&self.function.config)
                .map_err(Error::Dma)?;
            if actual != *generation {
                return Err(Error::IdentityChanged);
            }
        }
        Ok(())
    }

    /// Hardware revalidation plus explicit unsupported-transition admission.
    /// Probe success must not publish a ready native device after a denied
    /// reset/power/policy operation that the original caller ignored.
    pub fn check_ready(&mut self) -> Result<(), Error> {
        self.check_live()?;
        if self.denied.is_some() {
            Err(Error::UnsupportedPolicy)
        } else {
            Ok(())
        }
    }
    pub fn denied_write(&self) -> Option<DeniedWrite> {
        self.denied
    }
    pub fn denied_write_count(&self) -> u64 {
        self.denied_count
    }

    fn deny(&mut self, offset: u16, width: u8, value: u32) -> Error {
        self.denied.get_or_insert(DeniedWrite {
            offset,
            width,
            value,
        });
        self.denied_count = self.denied_count.saturating_add(1);
        Error::UnsupportedPolicy
    }

    /// Issue one non-Clone native registration claim from this owner.
    /// Dropping the claim cannot prove unregister/child/IRQ/DMA retirement and
    /// does not make another registration available.
    pub fn claim_registration(
        function: Rc<RefCell<Self>>,
    ) -> Result<RegistrationClaim, (Error, Rc<RefCell<Self>>)> {
        let result = (|| {
            let mut owner = function.try_borrow_mut().map_err(|_| Error::Borrowed)?;
            owner.check_current()?;
            if owner.registration_issued {
                return Err(Error::AlreadyClaimed);
            }
            owner.registration_issued = true;
            Ok(())
        })();
        match result {
            Ok(()) => Ok(RegistrationClaim { function }),
            Err(error) => Err((error, function)),
        }
    }

    /// Revalidate the mapping/context and immutable observed identity.
    /// The first uncertainty is terminal; subsequent calls perform no config IO.
    pub fn check_live(&mut self) -> Result<(), Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        let result = (|| {
            self.check_current()?;
            if observe(self.function.config())? != self.description {
                return Err(Error::IdentityChanged);
            }
            self.retention
                .check_live()
                .map_err(|error| Error::Config(ConfigError::Mapping(error)))
        })();
        self.latch(result)
    }

    pub fn description(&mut self) -> Result<Description, Error> {
        self.check_live()?;
        Ok(self.description)
    }
    pub fn failure(&self) -> Option<Error> {
        self.failure
    }

    fn validate(offset: u16, width: u8) -> Result<(), Error> {
        if !matches!(width, 1 | 2 | 4)
            || !offset.is_multiple_of(u16::from(width))
            || u32::from(offset) + u32::from(width) > 4096
        {
            return Err(Error::Access { offset, width });
        }
        Ok(())
    }

    pub fn read(&mut self, offset: u16, width: u8) -> Result<u32, Error> {
        Self::validate(offset, width)?;
        self.check_live()?;
        let config = self.function.config();
        let result = match width {
            1 => config.try_read8(offset).map(u32::from),
            2 => config.try_read16(offset).map(u32::from),
            _ => config.try_read32(offset),
        }
        .map_err(Error::Config);
        let value = self.latch(result)?;
        self.check_live()?;
        Ok(value)
    }

    /// Native-width write. An error may follow a real effect; never infer
    /// rollback or retry safety from this result. First uncertainty is latched.
    pub fn write(&mut self, offset: u16, width: u8, value: u32) -> Result<(), Error> {
        Self::validate(offset, width)?;
        self.check_current()?;
        if self.binding_issued || self.registration_issued {
            // An affirmative finite transition set, rather than an incomplete
            // blacklist of known reset/PM/translation/vendor register offsets.
            // Unknown writes require stop/lease/IRQ/root requalification
            // permission, which this initial producer cannot issue.
            if self.bound.is_none() || !matches!((offset, width), (4, 1 | 2) | (5, 1)) {
                return Err(self.deny(offset, width, value));
            }
            self.check_live()?;
            let old = self.function.config().try_read16(4).map_err(Error::Config);
            let old = self.latch(old)?;
            let next = match (offset, width) {
                (4, 1) => old & 0xff00 | u16::from(value as u8),
                (5, 1) => old & 0x00ff | u16::from(value as u8) << 8,
                _ => value as u16,
            };
            // IO/MEM/BME gate changes preserve the same programmed BAR/root
            // and translated coherency policy. INTx stays disabled until the
            // original interrupt owner supplies a supported transition.
            if old == u16::MAX {
                return self.latch(Err(Error::Unavailable));
            }
            let gates = super::COMMAND_IO | super::COMMAND_MEMORY | super::COMMAND_BUS_MASTER;
            if (old ^ next) & !gates != 0 || next & super::COMMAND_INTX_DISABLE == 0 {
                return Err(self.deny(offset, width, value));
            }
            // Refused operations changed no configuration. Keep readiness
            // denied, but permit the real finite cleanup that only clears
            // already-enabled IO/MEM/BME gates. It proves no engine drainage.
            if self.denied.is_some() && next & gates & !(old & gates) != 0 {
                return Err(self.deny(offset, width, value));
            }
        }
        self.check_live()?;
        let config = self.function.config();
        let result = match width {
            1 => config.try_write8(offset, value as u8),
            2 => config.try_write16(offset, value as u16),
            _ => config.try_write32(offset, value),
        }
        .map_err(Error::Config);
        self.latch(result)?;
        self.check_live()
    }

    /// Return the original owners only after complete retirement.
    /// Failed/uncertain owners cannot be extracted by this boundary.
    ///
    /// # Safety
    /// All C references, config callbacks, device engines, DMA/posted accesses,
    /// IRQ/work and child owners are stopped/drained using their original
    /// permissions. No callback can reenter or keep this service. The caller
    /// continues the original epoch/context and mapping retirement obligations.
    #[expect(
        clippy::result_large_err,
        reason = "refusal returns this owner without allocating, which could fail after native effects"
    )]
    pub unsafe fn release(mut self) -> Result<Parts, Self> {
        if self.check_live().is_err() {
            return Err(self);
        }
        // SAFETY: successful check plus caller's complete retirement grant;
        // each ManuallyDrop field is taken/dropped exactly once on this path.
        unsafe {
            ManuallyDrop::drop(&mut self.bound);
            ManuallyDrop::drop(&mut self.retention);
            Ok((
                ManuallyDrop::take(&mut self.function),
                ManuallyDrop::take(&mut self.exclusion),
            ))
        }
    }
}

/// Remapper-backed canonical PCI pairing. This is implemented by the
/// hardware context owner, never by a caller-selected numeric RID or callback.
///
/// # Safety
/// `check_configuration` must check a live, unpoisoned hardware context
/// and its consumed canonical RequesterBinding against the SAME OwnedConfig
/// mapping/root epoch. `generation` is the real non-reused context generation.
/// It must refuse legacy/raw-config claims and uncertain/detached contexts.
pub unsafe trait PciDmaDomain: DmaDomain {
    fn check_configuration(&self, config: &OwnedConfig) -> Result<u64, DmaError>;

    /// Pure kept context/epoch observation for generic native-root
    /// guards. No config/MMIO/PIO/DMA access, allocation, waiting, unwinding or
    /// Linux reentry. Refuse unavailable execution/lock/context immediately.
    /// Legacy implementations cannot advertise this stronger contract.
    fn check_current_configuration(&self, _config: &OwnedConfig) -> Result<u64, DmaError> {
        Err(DmaError::IommuUnavailable)
    }
}

/// Unique function registration ownership. Shared config views cannot
/// manufacture a second claim. This is neither a Linux root bus/topology nor
/// a stop/drain/IRQ handoff receipt.
pub struct RegistrationClaim {
    function: Rc<RefCell<NativeFunction>>,
}
impl RegistrationClaim {
    pub fn check_current(&self) -> Result<(), Error> {
        self.function
            .try_borrow()
            .map_err(|_| Error::Borrowed)?
            .check_current()
    }
    pub fn function(&self) -> &Rc<RefCell<NativeFunction>> {
        &self.function
    }
}

/// A verified canonical requester/configuration/remapper/source chain. Public
/// construction checks the consumed binding, not just Arc/BDF equality.
/// The process-local config/exclusion owner is held through every clone of
/// this root's function handle; mapping leases keep the real hardware domain.
/// Retaining a PageSource grants no coherence, physical placement or cache
/// policy: its returned pins and the domain's mapping/coherence contract
/// must independently check every allocation.
pub struct NativeDmaRoot {
    function: Rc<RefCell<NativeFunction>>,
    domain: Arc<dyn PciDmaDomain>,
    source: Arc<dyn PageSource>,
    generation: u64,
}
pub type RootParts = (
    Rc<RefCell<NativeFunction>>,
    Arc<dyn PciDmaDomain>,
    Arc<dyn PageSource>,
);
impl NativeDmaRoot {
    pub fn bind(
        function: Rc<RefCell<NativeFunction>>,
        domain: Arc<dyn PciDmaDomain>,
        source: Arc<dyn PageSource>,
    ) -> Result<Self, (Error, RootParts)> {
        let result = (|| {
            let mut owner = function.try_borrow_mut().map_err(|_| Error::Borrowed)?;
            owner.check_ready()?;
            let generation = domain
                .check_configuration(owner.function.config())
                .map_err(Error::Dma)?;
            if owner.bound.is_some() {
                return Err(Error::AlreadyClaimed);
            }
            if !owner.binding_issued {
                return Err(Error::UnsupportedPolicy);
            }
            let observed = domain
                .check_current_configuration(&owner.function.config)
                .map_err(Error::Dma)?;
            if observed != generation {
                return Err(Error::IdentityChanged);
            }
            owner.check_ready()?;
            *owner.bound = Some((domain.clone(), generation));
            Ok(generation)
        })();
        match result {
            Ok(generation) => Ok(Self {
                function,
                domain,
                source,
                generation,
            }),
            Err(error) => Err((error, (function, domain, source))),
        }
    }
    pub fn check_live(&self) -> Result<(), Error> {
        let mut owner = self
            .function
            .try_borrow_mut()
            .map_err(|_| Error::Borrowed)?;
        owner.check_ready()?;
        let result = self
            .domain
            .check_configuration(owner.function.config())
            .map_err(Error::Dma);
        let generation = owner.latch(result)?;
        if generation != self.generation {
            return owner.latch(Err(Error::IdentityChanged));
        }
        owner.check_live()
    }
    pub fn check_current(&self) -> Result<(), Error> {
        self.function
            .try_borrow()
            .map_err(|_| Error::Borrowed)?
            .check_current()
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn function(&self) -> &Rc<RefCell<NativeFunction>> {
        &self.function
    }
    pub fn domain(&self) -> Arc<dyn DmaDomain> {
        self.domain.clone()
    }
    pub fn source(&self) -> &Arc<dyn PageSource> {
        &self.source
    }
}

#[cfg(test)]
mod tests;
