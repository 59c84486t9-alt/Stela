//! Owning failures never replace a touched provider with an empty Option.
use super::*;

pub struct Failure<R: Registers, T: Timer> {
    pub error: Error,
    owner: pxa2xx::Kept<Owner<R>, T>,
}
impl<R: Registers, T: Timer> Failure<R, T> {
    pub fn platform_progress(&self) -> pxa2xx::Progress {
        self.owner.provider().progress
    }
    pub fn progress(&self) -> pxa2xx::Progress {
        self.owner.progress()
    }
}
impl<R: Registers, T: Timer> core::fmt::Debug for Failure<R, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Failure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
pub struct AttachFailure<T: Timer> {
    pub error: Error,
    stage: NativeStage<T>,
}
enum NativeStage<T: Timer> {
    Claim {
        _resources: ManuallyDrop<NativeResources>,
        _timer: ManuallyDrop<T>,
    },
    Controller(pxa2xx::Kept<Owner<NativeRegisters>, T>),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttachStage {
    Claim,
    Controller,
}
impl<T: Timer> AttachFailure<T> {
    pub fn stage(&self) -> AttachStage {
        match self.stage {
            NativeStage::Claim { .. } => AttachStage::Claim,
            NativeStage::Controller(_) => AttachStage::Controller,
        }
    }
    pub fn platform_progress(&self) -> Option<pxa2xx::Progress> {
        match &self.stage {
            NativeStage::Controller(owner) => Some(owner.provider().progress),
            NativeStage::Claim { .. } => None,
        }
    }
}
impl<T: Timer> core::fmt::Debug for AttachFailure<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AttachFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl<R: Registers, T: Timer> Spi<R, T> {
    /// # Safety
    /// The same stopped provider owns power, reset, the established source
    /// clock, native CS pins and firmware arbitration. No DMA/IRQ child or
    /// outstanding callback may use or revoke that original epoch.
    pub unsafe fn attach(
        registers: R,
        timer: T,
        chip_selects: u8,
        timeout_us: u64,
    ) -> Result<Self, Failure<R, T>> {
        let mut prepared =
            pxa2xx::PreparedController::new(Owner::new(registers), timer, timeout_us);
        if prepared.check_timer().is_err() {
            return Err(Failure {
                error: Error::Configuration,
                owner: prepared.into_kept(),
            });
        }
        if let Err(error) = prepared.configure(|owner| owner.prepare(chip_selects)) {
            return Err(Failure {
                error,
                owner: prepared.into_kept(),
            });
        }
        let mut engine = match prepared.bind() {
            Ok(engine) => engine,
            Err(failure) => {
                return Err(Failure {
                    error: Error::Spi(failure.error),
                    owner: failure.into_kept(),
                });
            }
        };
        if let Err(error) = engine.initialize() {
            return Err(Failure {
                error: Error::Spi(error),
                owner: engine.into_kept(),
            });
        }
        Ok(Self { engine })
    }
    pub fn shutdown(self) -> Result<(Retired<R>, T), Failure<R, T>> {
        match self.engine.release_with(Owner::retire) {
            Ok((mut owner, timer)) => Ok((
                Retired {
                    registers: owner.registers.take().unwrap(),
                },
                timer,
            )),
            Err(failure) => {
                let error = match &failure.error {
                    pxa2xx::ReleaseError::Controller(error) => Error::Spi(*error),
                    pxa2xx::ReleaseError::Finalizer(error) => *error,
                };
                Err(Failure {
                    error,
                    owner: failure.into_kept(),
                })
            }
        }
    }
}
impl<T: Timer> Spi<NativeRegisters, T> {
    /// # Safety
    /// The parent's native claim and this adapter's clock, pins and firmware
    /// arbitration contracts hold for the same function and complete UC BAR.
    #[expect(
        clippy::result_large_err,
        reason = "claim failure keeps the same original config, mapping and timer without failure-path allocation"
    )]
    pub unsafe fn attach_native(
        requester: StoppedRequester,
        mapping: Mapping,
        timer: T,
        chip_selects: u8,
        timeout_us: u64,
    ) -> Result<Self, AttachFailure<T>> {
        // Keep all inputs before claim validates the original config/mapping.
        let inputs = ManuallyDrop::new((requester, mapping, timer));
        let (requester, mapping, timer) = ManuallyDrop::into_inner(inputs);
        let timer = ManuallyDrop::new(timer);
        // SAFETY: caller supplies the same stopped function and UC grant;
        // NativeRegisters::claim parks both before its first provider callback.
        let registers = match unsafe { NativeRegisters::claim(requester, mapping) } {
            Ok(registers) => registers,
            Err((error, resources)) => {
                return Err(AttachFailure {
                    error: Error::Platform(error),
                    stage: NativeStage::Claim {
                        _resources: ManuallyDrop::new(resources),
                        _timer: timer,
                    },
                });
            }
        };
        // SAFETY: same platform clock/CS grant. Attach allocates the retained
        // state before callbacks; no callback occurs in this input move.
        match unsafe {
            Self::attach(
                registers,
                ManuallyDrop::into_inner(timer),
                chip_selects,
                timeout_us,
            )
        } {
            Ok(owner) => Ok(owner),
            Err(failure) => Err(AttachFailure {
                error: failure.error,
                stage: NativeStage::Controller(failure.owner),
            }),
        }
    }
}
