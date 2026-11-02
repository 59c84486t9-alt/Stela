//! Retained controller graphs and constant-size register progress diagnostics.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Read { offset: usize },
    Write { offset: usize, value: u32 },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessResult {
    pub access: Access,
    pub read_value: Option<u32>,
}
/// Ordered returned-call frontier and the exact uncertain next call. This is
/// diagnostic data, not a complete register trace, delivery or retirement proof.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Progress {
    pub accepted: u64,
    pub last: Option<AccessResult>,
    pub pending: Option<Access>,
}

/// Owning refusal from the same controller. Destruction retains the graph;
/// only an acknowledged shutdown can return the original register/time owners.
pub struct Failure<R, T> {
    pub error: Error,
    owner: DesignWare<R, T>,
}
impl<R, T> Failure<R, T> {
    pub fn progress(&self) -> Progress {
        self.owner.state.progress
    }
}
impl<R, T> core::fmt::Debug for Failure<R, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Failure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl<R: Registers, T: Timer> DesignWare<R, T> {
    pub fn new(registers: R, timer: T, config: Config) -> Result<Self, Failure<R, T>> {
        // The allocation argument itself suppresses provider Drop if an
        // allocator unwinds. No provider callback precedes retained storage.
        let parked = Box::new(ManuallyDrop::new(State {
            registers,
            timer,
            config,
            tx_depth: 0,
            rx_depth: 0,
            control: 0,
            ready: false,
            progress: Progress::default(),
            active: true,
            failure: None,
            inflight_error: None,
        }));
        // SAFETY: ManuallyDrop is layout-transparent. The unique Box allocation
        // is transferred directly, with no callback or fallible gap, and the
        // outer ManuallyDrop keeps every provider until acknowledged shutdown.
        let state = unsafe { Box::from_raw(Box::into_raw(parked).cast::<State<R, T>>()) };
        let mut owner = Self {
            state: ManuallyDrop::new(state),
        };
        let result = owner.state.initialize();
        owner.state.active = false;
        match result {
            Ok(()) => Ok(owner),
            Err(error) => Err(Failure { error, owner }),
        }
    }

    /// Return the original providers only after disable acknowledgement. A
    /// returned access error or earlier unwind forbids further shutdown I/O.
    pub fn shutdown(mut self) -> Result<(R, T), Failure<R, T>> {
        let result = (|| {
            self.state.admit()?;
            self.state.active = true;
            match self.state.quiesce() {
                Ok(true) => Ok(()),
                Ok(false) => Err(Error {
                    kind: ErrorKind::Timeout(Phase::Disable),
                    recovery: Recovery::Failed,
                }),
                Err(kind) => Err(self.state.failure.unwrap_or_else(|| kind.into())),
            }
        })();
        self.state.active = false;
        match result {
            Err(error) => Err(Failure { error, owner: self }),
            Ok(()) => {
                let State {
                    registers, timer, ..
                } = *ManuallyDrop::into_inner(self.state);
                Ok((registers, timer))
            }
        }
    }
    pub fn fifo_depths(&self) -> (usize, usize) {
        (self.state.tx_depth, self.state.rx_depth)
    }
    pub fn progress(&self) -> Progress {
        self.state.progress
    }
    /// Sticky access/interruption denial. Semantic faults retain their existing
    /// returned error and acknowledged-recovery/NeedsReset behavior.
    pub fn failure(&self) -> Option<Error> {
        self.state
            .failure
            .or_else(|| self.state.active.then(|| self.state.interruption()))
    }
}

impl<R: Registers, T: Timer> State<R, T> {
    fn interruption(&self) -> Error {
        self.inflight_error
            .unwrap_or_else(|| ErrorKind::Interrupted.into())
    }
    pub(super) fn admit(&mut self) -> Result<(), Error> {
        if self.active && self.failure.is_none() {
            self.failure = Some(self.interruption());
            self.ready = false;
        }
        self.failure.map_or(Ok(()), Err)
    }
    fn prepare(&mut self, access: Access) -> Result<u64, ErrorKind> {
        if let Some(error) = self.failure {
            return Err(error.kind);
        }
        let next = match self.progress.accepted.checked_add(1) {
            Some(next) if self.progress.pending.is_none() => next,
            _ => {
                let kind = if self.progress.pending.is_some() {
                    ErrorKind::Interrupted
                } else {
                    ErrorKind::ProgressExhausted
                };
                self.ready = false;
                self.failure = Some(match self.inflight_error {
                    Some(primary) => Error {
                        kind: primary.kind,
                        recovery: if kind == ErrorKind::ProgressExhausted {
                            Recovery::ProgressExhausted
                        } else {
                            Recovery::Interrupted
                        },
                    },
                    None => kind.into(),
                });
                return Err(kind);
            }
        };
        self.progress.pending = Some(access);
        Ok(next)
    }
    fn denied(&mut self, cause: IoError) -> ErrorKind {
        self.ready = false;
        self.failure = Some(match self.inflight_error {
            Some(primary) => Error {
                kind: primary.kind,
                recovery: Recovery::Access(cause),
            },
            None => ErrorKind::Access(cause).into(),
        });
        ErrorKind::Access(cause)
    }
    pub(super) fn read(&mut self, offset: usize) -> Result<u32, ErrorKind> {
        let access = Access::Read { offset };
        let next = self.prepare(access)?;
        match self.registers.read32(offset) {
            Ok(value) => {
                self.progress.accepted = next;
                self.progress.last = Some(AccessResult {
                    access,
                    read_value: Some(value),
                });
                self.progress.pending = None;
                Ok(value)
            }
            Err(cause) => Err(self.denied(cause)),
        }
    }
    pub(super) fn write(&mut self, offset: usize, value: u32) -> Result<(), ErrorKind> {
        let access = Access::Write { offset, value };
        let next = self.prepare(access)?;
        match self.registers.write32(offset, value) {
            Ok(()) => {
                self.progress.accepted = next;
                self.progress.last = Some(AccessResult {
                    access,
                    read_value: None,
                });
                self.progress.pending = None;
                Ok(())
            }
            Err(cause) => Err(self.denied(cause)),
        }
    }
}

impl<R: Registers, T: Timer> Bus for DesignWare<R, T> {
    fn transaction(
        &mut self,
        address: Address,
        operations: &mut [Operation<'_>],
    ) -> Result<(), Error> {
        self.state.admit()?;
        address.validate()?;
        if operations.is_empty() {
            return Err(ErrorKind::EmptyTransaction.into());
        }
        if operations.iter().any(|operation| operation.len() == 0) {
            return Err(ErrorKind::EmptyMessage.into());
        }
        if !self.state.ready {
            return Err(ErrorKind::NeedsReset.into());
        }
        self.state.active = true;
        let result = self.state.transfer(address, operations);
        if let Some(error) = self.state.failure {
            self.state.active = false;
            return Err(error);
        }
        self.state.inflight_error = result.err().map(|kind| Error {
            kind,
            recovery: Recovery::Interrupted,
        });
        let recovery = self.state.quiesce();
        self.state.active = false;
        if let Some(error) = self.state.failure {
            return Err(error);
        }
        self.state.inflight_error = None;
        match (result, recovery) {
            (Ok(()), Ok(true)) => Ok(()),
            (result, recovery) => Err(Error {
                kind: result.err().unwrap_or(ErrorKind::Timeout(Phase::Disable)),
                recovery: match recovery {
                    Ok(true) => Recovery::Disabled,
                    Ok(false) => Recovery::Failed,
                    Err(ErrorKind::Access(cause)) => Recovery::Access(cause),
                    Err(_) => Recovery::Failed,
                },
            }),
        }
    }
}
