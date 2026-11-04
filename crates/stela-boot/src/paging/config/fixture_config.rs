//! Original affine configuration slots for the isolated standalone fixture.
use super::*;
use core::any::Any;
use stela_drivers::{
    bus::pci::{
        ConfigFailure, ConfigSpace,
        owned::{
            ObservedConfig, UnpublishedConfig,
            grant::{
                CompletionCheck, ConfigCustody, ConfigEpoch, ConfigOperation, DriverCustody,
                Operation, PrepublicationCustody, PrepublicationGrant,
            },
        },
    },
    sync::{FaultState, FirstFault},
};

const COMMAND: u16 = 4;
const BUS_MASTER: u16 = 4;

struct Slot {
    platform: Arc<platform::Platform>,
    parent: assignment::Parent,
    _span: PhysicalSpan,
}

// SAFETY: the exact function page is issued once under its original bus
// assignment. This projection holds the actual root and has no writer backedge.
unsafe impl PhysicalAssignment for Slot {
    fn parent(&self) -> Option<&assignment::Parent> {
        Some(&self.parent)
    }

    fn check_control(&self) -> Result<(), assignment::Error> {
        self.platform
            .check()
            .map_err(|_| assignment::Error::Context)
    }
}

struct Backing {
    platform: Arc<platform::Platform>,
    span: PhysicalSpan,
    owner: Retention<Slot>,
}

// SAFETY: private resource backed by the exact same issued slot as its writer.
unsafe impl ResourceBacking for Backing {
    fn physical_span(&self) -> PhysicalSpan {
        self.span
    }

    fn kind(&self) -> ResourceKind {
        ResourceKind::Configuration
    }

    fn begin_mapping(&self) -> Result<OpaqueUse, owned::Error> {
        self.platform
            .check()
            .map_err(|_| owned::Error::Unavailable)?;
        self.owner
            .begin_use(UseKind::Mapping)
            .map(|count| count.erase())
            .map_err(owned::Error::Assignment)
    }
}

struct Epoch {
    platform: Arc<platform::Platform>,
    owner: Retention<Slot>,
}

impl Epoch {
    fn context(&self) -> Result<(), owned::Error> {
        self.platform.check().map_err(|_| owned::Error::Unavailable)
    }
}

// SAFETY: retains the original installed root and same exact slot epoch.
// No configuration pointer or access permission is created by this projection.
unsafe impl ConfigEpoch for Epoch {
    fn check(&self) -> Result<(), owned::Error> {
        self.context()?;
        self.owner
            .check_admission()
            .map_err(owned::Error::Assignment)
    }

    fn retain(&self) -> Result<Box<dyn ConfigEpoch>, owned::Error> {
        self.check()?;
        Ok(Box::new(Self {
            platform: self.platform.clone(),
            owner: self.owner.clone(),
        }))
    }

    fn same_epoch(&self, other: &dyn ConfigEpoch) -> Result<bool, owned::Error> {
        self.check()?;
        other.check()?;
        Ok(other
            .as_any()
            .downcast_ref::<Self>()
            .is_some_and(|other| self.owner.same_assignment(&other.owner)))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

struct Completion {
    epoch: Epoch,
    fault: FirstFault<ConfigError>,
}

// SAFETY: the preowned validator rechecks this exact standalone root after
// each bounded access and latches its original failure without reentry.
unsafe impl CompletionCheck for Completion {
    fn postvalidate(&self) -> Result<(), ConfigError> {
        let result = self.epoch.context().map_err(config_error);
        if let Err(error) = result {
            self.fault.latch(error);
        }
        result
    }

    fn failure(&self) -> FaultState<ConfigError> {
        self.fault.observe()
    }
}

fn config_error(error: owned::Error) -> ConfigError {
    ConfigError::before_effect(ConfigFailure::Mapping(error))
}

pub(crate) struct FixtureConfig {
    _assignment: Assignment<Slot>,
    resource: Resource,
    completion: Arc<Completion>,
    address: Address,
    window: EcamWindow,
    containment_command: u16,
    driver: bool,
}

impl FixtureConfig {
    /// # Safety
    /// The exact standalone cohort is stopped and the original VT-d takeover
    /// completed with blocked initial contexts for every requester.
    pub(crate) unsafe fn publish_driver(&mut self) -> Result<(), owned::Error> {
        self.retirement_context()?;
        if self.driver || self.completion.epoch.owner.uses() != 1 {
            return Err(owned::Error::Busy);
        }
        self.driver = true;
        Ok(())
    }
}

// SAFETY: Source exclusively issues this exact slot after revalidating the
// complete QEMU fixture census. The operation uses that same root and count.
unsafe impl ConfigCustody for FixtureConfig {
    fn address(&self) -> Address {
        self.address
    }

    fn window(&self) -> EcamWindow {
        self.window
    }

    fn resource(&self) -> &Resource {
        &self.resource
    }

    fn begin(&self, operation: Operation) -> Result<ConfigOperation, ConfigError> {
        self.completion.epoch.context().map_err(config_error)?;
        if !self.driver
            && let Operation::Write {
                offset,
                width,
                value,
            } = operation
            && (offset, width, value) != (COMMAND, 2, u32::from(self.containment_command))
        {
            return Err(ConfigError::before_effect(
                ConfigFailure::UnqualifiedControl,
            ));
        }
        match self.completion.failure() {
            FaultState::Ready(error) => return Err(error),
            FaultState::Publishing => {
                return Err(ConfigError::before_effect(ConfigFailure::FaultPublishing));
            }
            FaultState::Empty => {}
        }
        let count = self
            .completion
            .epoch
            .owner
            .begin_use(UseKind::Configuration)
            .map_err(|error| ConfigError::before_effect(ConfigFailure::Ownership(error)))?;
        // SAFETY: exact slot count and its preowned same-epoch validator.
        Ok(unsafe { ConfigOperation::new(count.erase(), self.completion.clone()) })
    }

    fn retirement_context(&self) -> Result<(), owned::Error> {
        self.completion.epoch.context()
    }

    fn retain_epoch(&self) -> Result<Box<dyn ConfigEpoch>, owned::Error> {
        self.completion.epoch.retain()
    }
}

// SAFETY: the complete isolated fixture source keeps the original slot and
// only admits its single Command containment value before root takeover.
unsafe impl PrepublicationCustody for FixtureConfig {}
// SAFETY: only the owning fixture's completed device stops and checked
// blocked-root takeover can switch policy in the original configuration owner.
unsafe impl DriverCustody for FixtureConfig {}

impl Source {
    pub(crate) fn fixture_config(
        &self,
        permit: &crate::native_dma::diagnostic::ConfigPermit<'_>,
    ) -> Result<UnpublishedConfig, Error> {
        let (address, set_command) = permit.for_source(self).ok_or(Error::ResourceInventory)?;
        {
            let mut issued = self
                .issued_config
                .try_borrow_mut()
                .map_err(|_| Error::ResourceConflict)?;
            if issued.contains(&address) {
                return Err(Error::ResourceConflict);
            }
            issued.try_reserve(1).map_err(|_| Error::Allocation)?;
            issued.push(address);
        }
        let (window, mapping) = self.config_mapping(address, Protection::ReadOnly)?;
        let span = mapping.physical_span().map_err(Error::Mapping)?;
        // SAFETY: exact source-owned read-only lease, no competing writer.
        let mut observed = match unsafe { ObservedConfig::attach(address, window, mapping) } {
            Ok(observed) => observed,
            Err((error, mut mapping)) => {
                // SAFETY: refused attachment exposed no access or views.
                unsafe { mapping.retire() }.map_err(Error::Mapping)?;
                return Err(Error::Config(error));
            }
        };
        let command = observed.read16(COMMAND);
        observed.retire().map_err(Error::Mapping)?;
        let command = command.map_err(Error::Config)?;
        if command == u16::MAX {
            return Err(Error::Mapping(owned::Error::InvalidPlatformReply));
        }
        let bus = self
            .buses
            .iter()
            .find(|bus| bus.window == window)
            .ok_or(Error::ResourceInventory)?;
        let assignment = Assignment::from_owned(Slot {
            platform: self.platform.clone(),
            parent: bus._assignment.parent(),
            _span: span,
        });
        let close = assignment.admission_close();
        let resource = Resource::new(Box::new(Backing {
            platform: self.platform.clone(),
            span,
            owner: assignment.retain(),
        }));
        let original = Box::new(FixtureConfig {
            resource,
            completion: Arc::new(Completion {
                epoch: Epoch {
                    platform: self.platform.clone(),
                    owner: assignment.retain(),
                },
                fault: FirstFault::new(),
            }),
            _assignment: assignment,
            address,
            window,
            containment_command: (command | set_command) & !BUS_MASTER,
            driver: false,
        });
        // SAFETY: same exact issued original slot and its preowned close.
        let grant = unsafe { PrepublicationGrant::from_boxed(original, close) };
        let prepared = UnpublishedConfig::prepare(grant);
        let mapping = self
            .authority
            .map(
                prepared.configuration_resource().clone(),
                0,
                PAGE,
                CacheAttribute::Uncached,
                Protection::ReadWrite,
            )
            .map_err(Error::Mapping)?;
        prepared
            .attach(mapping)
            .map_err(|(error, _original)| Error::Config(error))
    }
}
