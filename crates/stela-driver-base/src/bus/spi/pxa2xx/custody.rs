//! One preallocated provider graph through platform preparation and SSP release.
use super::*;
use alloc::boxed::Box;
use core::mem::ManuallyDrop;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Read { offset: usize },
    Write { offset: usize, value: u32 },
}
impl Access {
    pub(super) fn offset(self) -> usize {
        match self {
            Self::Read { offset } | Self::Write { offset, .. } => offset,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessResult {
    pub access: Access,
    pub read_value: Option<u32>,
}
/// Constant-size returned-call frontier. Pending identifies uncertainty; none
/// of these data grant retirement or describe a complete register trace.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Progress {
    pub accepted: u64,
    pub last: Option<AccessResult>,
    pub pending: Option<Access>,
}

pub struct PreparedController<R: Registers, T: Timer> {
    state: ManuallyDrop<Box<State<R, T>>>,
}
pub struct Controller<R: Registers, T: Timer = Clock> {
    state: ManuallyDrop<Box<State<R, T>>>,
}
pub(crate) struct Kept<R: Registers, T: Timer> {
    state: ManuallyDrop<Box<State<R, T>>>,
}
impl<R: Registers, T: Timer> Kept<R, T> {
    pub(crate) fn provider(&self) -> &R {
        &self.state.owners.as_ref().unwrap().0
    }
    pub(crate) fn progress(&self) -> Progress {
        self.state.progress
    }
}
pub struct Failure<R: Registers, T: Timer> {
    pub error: Error,
    owner: PreparedController<R, T>,
}
impl<R: Registers, T: Timer> Failure<R, T> {
    pub fn progress(&self) -> Progress {
        self.owner.state.progress
    }
    pub(crate) fn into_kept(self) -> Kept<R, T> {
        self.owner.into_kept()
    }
}
impl<R: Registers, T: Timer> core::fmt::Debug for Failure<R, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Failure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
#[derive(Debug)]
pub enum ReleaseError<E> {
    Controller(Error),
    Finalizer(E),
}
pub struct ReleaseFailure<R: Registers, T: Timer, E> {
    pub error: ReleaseError<E>,
    _owner: Controller<R, T>,
}
impl<R: Registers, T: Timer, E> ReleaseFailure<R, T, E> {
    pub(crate) fn into_kept(self) -> Kept<R, T> {
        self._owner.into_kept()
    }
    pub fn progress(&self) -> Progress {
        self._owner.progress()
    }
}

impl<R: Registers, T: Timer> PreparedController<R, T> {
    /// Allocate before any provider, timer or metadata callback. Abandonment
    /// keeps the same graph, including if the allocator itself unwinds.
    pub fn new(registers: R, timer: T, timeout_us: u64) -> Self {
        let parked = Box::new(ManuallyDrop::new(State {
            owners: Some((registers, timer)),
            description: None,
            timeout_us,
            initialized: false,
            chip_selects: 0,
            selected: None,
            failed: None,
            started: 0,
            offset: None,
            status: None,
            wire_started: false,
            io: None,
            active: false,
            progress: Progress::default(),
        }));
        // SAFETY: ManuallyDrop is layout-transparent. Transfer the unique Box
        // directly into retained storage without a callback or fallible gap.
        let state = unsafe { Box::from_raw(Box::into_raw(parked).cast::<State<R, T>>()) };
        Self {
            state: ManuallyDrop::new(state),
        }
    }
    /// Only the containing platform adapter can configure its own provider
    /// before binding. An error or unwind leaves the prepared graph terminal.
    pub(crate) fn configure<E>(
        &mut self,
        f: impl FnOnce(&mut R) -> Result<(), E>,
    ) -> Result<(), E> {
        assert!(!self.state.active && self.state.failed.is_none());
        self.state.active = true;
        let result = f(&mut self.state.owners.as_mut().unwrap().0);
        if result.is_ok() {
            self.state.active = false;
        }
        result
    }
    pub(crate) fn into_kept(self) -> Kept<R, T> {
        Kept { state: self.state }
    }
    pub fn progress(&self) -> Progress {
        self.state.progress
    }
    pub(crate) fn check_timer(&mut self) -> Result<(), Error> {
        self.state.invoke(|state| state.check_timer())
    }
    pub fn bind(mut self) -> Result<Controller<R, T>, Failure<R, T>> {
        let result = (|| {
            self.state.admit()?;
            self.state.check_timer()?;
            let (registers, _) = self.state.owners.as_ref().unwrap();
            let description = registers.description();
            let maximum = (description.profile.layout().select_mask
                >> description.profile.layout().select_shift)
                + 1;
            if description.input_clock_hz == 0
                || description.chip_selects == 0
                || u32::from(description.chip_selects) > maximum
                || registers.bytes() < description.profile.register_bytes()
            {
                return Err(self.state.error(ErrorKind::Configuration));
            }
            self.state.description = Some(description);
            self.state.chip_selects = description.chip_selects;
            Ok(())
        })();
        self.state.active = false;
        match result {
            Ok(()) => Ok(Controller { state: self.state }),
            Err(error) => Err(Failure { error, owner: self }),
        }
    }
}

impl<R: Registers, T: Timer> State<R, T> {
    fn check_timer(&self) -> Result<(), Error> {
        let timer = &self.owners.as_ref().unwrap().1;
        if self.timeout_us == 0
            || !timer.calibrated()
            || timer.check_duration(self.timeout_us).is_err()
        {
            Err(self.error(ErrorKind::Configuration))
        } else {
            Ok(())
        }
    }
    fn failure(&self) -> Option<Error> {
        self.failed
            .or_else(|| self.active.then(|| self.error(ErrorKind::Interrupted)))
    }
    fn admit(&mut self) -> Result<(), Error> {
        if self.active && self.failed.is_none() {
            self.failed = Some(self.error(ErrorKind::Interrupted));
        }
        if self.failed.is_some() {
            return Err(self.error(ErrorKind::NeedsReset));
        }
        self.active = true;
        Ok(())
    }
    fn invoke<O>(&mut self, f: impl FnOnce(&mut Self) -> Result<O, Error>) -> Result<O, Error> {
        self.admit()?;
        let result = f(self);
        self.active = false;
        result
    }
}
impl<R: Registers, T: Timer> Controller<R, T> {
    #[cfg(test)]
    pub(super) fn exhaust_progress(&mut self) {
        self.state.progress.accepted = u64::MAX;
    }
    pub fn new(registers: R, timer: T, timeout_us: u64) -> Result<Self, Failure<R, T>> {
        PreparedController::new(registers, timer, timeout_us).bind()
    }
    pub fn failure(&self) -> Option<Error> {
        self.state.failure()
    }
    pub fn progress(&self) -> Progress {
        self.state.progress
    }
    pub fn chip_selects(&self) -> u8 {
        self.state.chip_selects
    }
    pub(crate) fn into_kept(self) -> Kept<R, T> {
        Kept { state: self.state }
    }
    pub fn initialize(&mut self) -> Result<(), Error> {
        self.state.invoke(State::initialize)
    }
    pub fn message(&mut self, device: Device, transfers: &mut [Transfer<'_>]) -> Result<(), Error> {
        self.state.invoke(|state| state.message(device, transfers))
    }
    /// Extract providers only after idle, inactive CS and SSP disable ACK.
    pub fn release(mut self) -> Result<(R, T), Self> {
        if self.state.invoke(State::stop).is_err() {
            return Err(self);
        }
        Ok(self.take_owners())
    }
    /// The same allocation retains both providers while the platform finishes
    /// retirement. Its returned failure or unwind permits no later core I/O.
    pub(crate) fn release_with<E>(
        mut self,
        finish: impl FnOnce(&mut R) -> Result<(), E>,
    ) -> Result<(R, T), ReleaseFailure<R, T, E>> {
        if let Err(error) = self.state.invoke(State::stop) {
            let error = self.failure().unwrap_or(error);
            return Err(ReleaseFailure {
                error: ReleaseError::Controller(error),
                _owner: self,
            });
        }
        self.state.active = true;
        match finish(&mut self.state.owners.as_mut().unwrap().0) {
            Err(error) => Err(ReleaseFailure {
                error: ReleaseError::Finalizer(error),
                _owner: self,
            }),
            Ok(()) => {
                self.state.active = false;
                Ok(self.take_owners())
            }
        }
    }
    fn take_owners(self) -> (R, T) {
        let mut state = ManuallyDrop::into_inner(self.state);
        state.owners.take().unwrap()
    }
}
