//! Exact native configuration custody for early legacy interrupt containment.
use super::*;
use core::{any::Any, cell::RefCell};
use stela_drivers::{
    bus::pci::{
        ConfigError, ConfigFailure,
        owned::{
            PreparedConfig, UnpublishedConfig,
            grant::{
                CompletionCheck, ConfigCustody, ConfigEpoch, ConfigOperation, Operation,
                PrepublicationCustody, PrepublicationGrant,
            },
        },
    },
    sync::{FaultState, FirstFault},
};

const COMMAND: u16 = 4;
const INTX_DISABLE: u16 = 1 << 10;

type ParkedConfig = PreparedConfig<PrepublicationGrant>;

enum Cohort {
    Unclaimed,
    Incomplete(Vec<ParkedConfig>),
    Parked { _slots: Vec<ParkedConfig> },
}

pub(in crate::native_mmio::shared) struct PciSlots(RefCell<Cohort>);

impl PciSlots {
    pub(in crate::native_mmio::shared) const fn new() -> Self {
        Self(RefCell::new(Cohort::Unclaimed))
    }
}

struct Input {
    address: Address,
    window: EcamWindow,
    span: PhysicalSpan,
    identity: u32,
    command: u16,
}

fn census(windows: &[EcamWindow], reader: &mut ConfigInventory<'_>) -> Result<Vec<Input>, Error> {
    let mut inputs = Vec::new();
    for window in windows {
        for bus in window.start_bus..=window.end_bus {
            for device in 0..32 {
                for function in 0..8 {
                    let address = Address {
                        segment: window.segment,
                        bus,
                        device,
                        function,
                    };
                    let identity = reader.read32(address, 0)?;
                    match identity as u16 {
                        u16::MAX => continue,
                        0 | 1 => return Err(Error::InvalidPlatformReply),
                        _ => {}
                    }
                    let header = ((reader.read32(address, 12)? >> 16) & 0x7f) as u8;
                    match header {
                        0 => {}
                        1 => {
                            let [primary, secondary, subordinate, _] =
                                reader.read32(address, 0x18)?.to_le_bytes();
                            if secondary != 0 || subordinate != 0 {
                                if primary != bus || secondary <= bus || subordinate < secondary {
                                    return Err(Error::InvalidPlatformReply);
                                }
                                reader.check_bridge(address, secondary..=subordinate)?;
                            }
                        }
                        _ => return Err(Error::InvalidPlatformReply),
                    }
                    let command = reader.read32(address, COMMAND)? as u16;
                    if command == u16::MAX {
                        return Err(Error::InvalidPlatformReply);
                    }
                    let (window, span) = reader
                        .geometry
                        .function(address, reader.source.platform.wire().roots())?;
                    inputs.try_reserve(1).map_err(|_| Error::Exhausted)?;
                    inputs.push(Input {
                        address,
                        window,
                        span,
                        identity,
                        command,
                    });
                }
            }
        }
    }
    Ok(inputs)
}

#[derive(Clone)]
struct Epoch {
    platform: Arc<Platform>,
    original: Retention<Reservation>,
}

impl Epoch {
    fn context(&self) -> Result<(), Error> {
        self.platform.check_mapping_control()
    }
}

// SAFETY: this projection only keeps the original aperture and slot count.
// It creates no mapping or configuration access.
unsafe impl ConfigEpoch for Epoch {
    fn check(&self) -> Result<(), Error> {
        self.context()?;
        self.original.check_admission().map_err(Error::Assignment)
    }

    fn retain(&self) -> Result<Box<dyn ConfigEpoch>, Error> {
        self.check()?;
        Ok(Box::new(self.clone()))
    }

    fn same_epoch(&self, other: &dyn ConfigEpoch) -> Result<bool, Error> {
        self.check()?;
        other.check()?;
        Ok(other
            .as_any()
            .downcast_ref::<Self>()
            .is_some_and(|other| self.original.same_assignment(&other.original)))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

struct Completion {
    epoch: Epoch,
    fault: FirstFault<ConfigError>,
}

fn mapping_error(error: Error) -> ConfigError {
    ConfigError::before_effect(ConfigFailure::Mapping(error))
}

// SAFETY: the preowned validator checks the original aperture in the
// accepting context and latches its first failure without reentry.
unsafe impl CompletionCheck for Completion {
    fn postvalidate(&self) -> Result<(), ConfigError> {
        let result = self.epoch.context().map_err(mapping_error);
        if let Err(error) = result {
            self.fault.latch(error);
        }
        result
    }

    fn failure(&self) -> FaultState<ConfigError> {
        self.fault.observe()
    }
}

struct IntxCustody {
    _original: Assignment<Reservation>,
    resource: Resource,
    completion: Arc<Completion>,
    address: Address,
    window: EcamWindow,
    command: u16,
}

// SAFETY: the census issues one exact slot from the original aperture
// reservation, shared by its resource backing and configuration counts.
unsafe impl ConfigCustody for IntxCustody {
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
        self.completion.epoch.context().map_err(mapping_error)?;
        if let Operation::Write {
            offset,
            width,
            value,
        } = operation
            && (offset, width, value) != (COMMAND, 2, u32::from(self.command))
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
            .original
            .begin_use(UseKind::Configuration)
            .map_err(|error| ConfigError::before_effect(ConfigFailure::Ownership(error)))?;
        // SAFETY: the accepted operation retains the exact slot and validator.
        Ok(unsafe { ConfigOperation::new(count.erase(), self.completion.clone()) })
    }

    fn retirement_context(&self) -> Result<(), Error> {
        self.completion.epoch.context()
    }

    fn retain_epoch(&self) -> Result<Box<dyn ConfigEpoch>, Error> {
        self.completion.epoch.retain()
    }
}

// SAFETY: only the original exclusive native source issues this slot and
// admits exactly the observed command word with Interrupt Disable set.
unsafe impl PrepublicationCustody for IntxCustody {}

fn verify(config: &UnpublishedConfig, identity: u32, command: u16) -> Result<(), ConfigError> {
    for (offset, width, expected, observed) in [
        (0, 4, identity, config.try_read32(0)?),
        (
            COMMAND,
            2,
            u32::from(command),
            u32::from(config.try_read16(COMMAND)?),
        ),
    ] {
        if expected != observed {
            return Err(ConfigError::before_effect(ConfigFailure::Readback {
                offset,
                width,
                expected,
                observed,
            }));
        }
    }
    Ok(())
}

impl Source {
    /// Take the complete early INTx cohort once and park each original slot.
    ///
    /// # Safety
    /// Firmware and APs are stopped. The caller keeps all captured buses and
    /// their topology exclusive, including reset and hotplug.
    pub(crate) unsafe fn mask_pci_intx(&self) -> Result<usize, ConfigError> {
        {
            let mut cohort = self.pci_slots.0.borrow_mut();
            if !matches!(*cohort, Cohort::Unclaimed) {
                return Err(mapping_error(Error::Busy));
            }
            *cohort = Cohort::Incomplete(Vec::new());
        }
        // SAFETY: the caller keeps the complete captured topology exclusive.
        // with_config_inventory retires the last read-only map before return.
        let inputs = unsafe { self.with_config_inventory(census) }.map_err(mapping_error)?;
        let count = inputs.len();
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(count)
            .map_err(|_| mapping_error(Error::Exhausted))?;
        *self.pci_slots.0.borrow_mut() = Cohort::Incomplete(slots);
        for input in inputs {
            let parked = self.contain_intx(input)?;
            let mut cohort = self.pci_slots.0.borrow_mut();
            let Cohort::Incomplete(slots) = &mut *cohort else {
                unreachable!("exclusive containment owns the incomplete cohort");
            };
            slots.push(parked);
        }
        let mut cohort = self.pci_slots.0.borrow_mut();
        let Cohort::Incomplete(slots) = &mut *cohort else {
            unreachable!("exclusive containment owns the incomplete cohort");
        };
        *cohort = Cohort::Parked {
            _slots: core::mem::take(slots),
        };
        Ok(count)
    }

    fn contain_intx(&self, input: Input) -> Result<ParkedConfig, ConfigError> {
        let expected = input.command | INTX_DISABLE;
        let (resource, original) = self
            .reservation(input.span, ResourceKind::Configuration)
            .map_err(mapping_error)?;
        let close = original.admission_close();
        let owner = Box::new(IntxCustody {
            completion: Arc::new(Completion {
                epoch: Epoch {
                    platform: self.platform.clone(),
                    original: original.retain(),
                },
                fault: FirstFault::new(),
            }),
            _original: original,
            resource,
            address: input.address,
            window: input.window,
            command: expected,
        });
        // SAFETY: the same affine slot backs the bounded operation and map.
        let grant = unsafe { PrepublicationGrant::from_boxed(owner, close) };
        let prepared = UnpublishedConfig::prepare(grant);
        let mapping = self
            .authority
            .map(
                prepared.configuration_resource().clone(),
                0,
                PAGE as usize,
                CacheAttribute::Uncached,
                Protection::ReadWrite,
            )
            .map_err(mapping_error)?;
        let mut config = prepared
            .attach(mapping)
            .map_err(|(error, _original)| error)?;
        verify(&config, input.identity, input.command)?;
        if expected != input.command {
            config.try_write16(COMMAND, expected)?;
            verify(&config, input.identity, expected)
                .map_err(|error| ConfigError::write_may_have_applied(COMMAND, 2, error.reason))?;
        }
        // SAFETY: the only accesses were synchronous and bounded, with no
        // escaped aliases. Source keeps this original decode and assignment.
        unsafe { config.park() }.map_err(|(error, _original)| {
            if expected == input.command {
                mapping_error(error)
            } else {
                ConfigError::write_may_have_applied(COMMAND, 2, ConfigFailure::Mapping(error))
            }
        })
    }
}
