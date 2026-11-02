//! Cancellation joins exact owned native state; errno is never a receipt.
use super::*;
/// Affine successful no-publication/cancellation proof. A held metadata ref
/// remains through original source allocation free; this is NOT FullReady.
/// No public constructor, Clone, errno conversion or arbitrary proof bits.
#[must_use = "retain metadata through the actual original source free tail"]
pub(crate) struct NoPublication<const N: usize> {
    binding: ManuallyDrop<Arc<TaskBinding<N>>>,
    generation: u64,
    // Actual native-half rollback receipt retained beside the independent
    // source no-exposure/unwind provenance; no error code constructs it.
    _cancelled_transfer: Option<CancelledReservation>,
}
impl<const N: usize> NoPublication<N> {
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
    /// Keep this Arc through the actual original allocation/source free tail.
    pub(crate) fn into_metadata(self) -> Arc<TaskBinding<N>> {
        ManuallyDrop::into_inner(self.binding)
    }
}
impl<'factory, 'kernel, 'catalog, 'runtime, K: KernelThreadPlatform, P: Provider, const N: usize>
    Child<'factory, 'kernel, 'catalog, 'runtime, K, P, N>
{
    /// Remove every actual unpublished native/page owner under its SAME creator.
    /// Unlent private preparations have never exposed an original C stack. After
    /// lend, the genuine original source unwind/free/RCU receipt is mandatory
    /// BEFORE exact native cancel, and C descriptor refs independently refuse.
    /// # Safety
    /// Caller is the actual original constructor/unwind path on its real
    /// creator continuation. No callback/raw source view can appear later;
    /// actual old foreign-user retirement required by prepare remains true.
    #[expect(
        clippy::result_large_err,
        reason = "exact affine native/source ownership is returned on refusal"
    )]
    pub(crate) unsafe fn cancel_unpublished(
        self,
        entered: &dyn EnteredProcess,
    ) -> Result<NoPublication<N>, Failure<'factory, 'kernel, 'catalog, 'runtime, K, P, N>> {
        let mut this = ManuallyDrop::new(self);
        if matches!(&*this.state, State::Born | State::TransferFailed(_)) {
            if let Err(error) = this.check_born_creator(entered) {
                return Err(ManuallyDrop::into_inner(this).fail(error));
            }
        }
        if matches!(
            &*this.state,
            State::Prepared {
                exposure: Exposure::Lent,
                ..
            }
        ) {
            // SAFETY: exact retained C record and source birth generation;
            // checker is source-owned actual unwind/free/RCU evidence, never
            // a generic errno, observer flag, task pointer or refcount label.
            let value = unsafe {
                stela_linux_task_child_source_unwound(
                    this.binding.task.as_ptr(),
                    this.factory.kernel.raw(),
                    this.identity.generation,
                )
            };
            if value != 0 {
                return Err(ManuallyDrop::into_inner(this).fail(Error::Source(value)));
            }
        }
        let state = this.take_state();
        let mut cancelled_transfer = None;
        let outcome = match state {
            State::Born => Ok(()),
            // This private phase originated BEFORE stack preparation/lend.
            // The genuine source birth/creator was independently checked above.
            // Native failure owns the same exclusion and keeps it on refusal.
            State::TransferFailed(owner) => match owner.cancel(entered) {
                Ok(receipt) => {
                    cancelled_transfer = Some(receipt);
                    Ok(())
                }
                Err((owner, error)) => Err((State::TransferFailed(owner), Error::Work(error))),
            },
            State::Owned(owner) => match owner.cancel(entered) {
                Ok(()) => Ok(()),
                Err((owner, error)) => Err((State::Owned(owner), Error::Work(error))),
            },
            // SAFETY: exact same private unexposed preparation; no C loan exists.
            State::Preparing(owner) => match unsafe { owner.cancel(entered) } {
                Ok(()) => Ok(()),
                Err((owner, error)) => Err((State::Preparing(owner), Error::Work(error))),
            },
            // SAFETY: private unexposed pin, original old-user contract upheld.
            State::Pinned(owner) => match unsafe { owner.cancel(entered) } {
                Ok(()) => Ok(()),
                Err((owner, error)) => Err((State::Pinned(owner), Error::Work(error))),
            },
            // SAFETY: marker never lent; no source reference can own its bytes.
            State::Admission(owner) => match unsafe { owner.cancel(entered) } {
                Ok(()) => Ok(()),
                Err((owner, error)) => Err((State::Admission(owner), Error::Pages(error))),
            },
            State::Prepared { lease, exposure } if exposure != Exposure::Lending => {
                // SAFETY: either never lent or actual source unwind checker
                // succeeded above; exact creator/native cancellation still runs.
                match unsafe { lease.cancel(entered) } {
                    Ok(()) => Ok(()),
                    Err((lease, error)) => {
                        Err((State::Prepared { lease, exposure }, Error::Pages(error)))
                    }
                }
            }
            state => Err((state, Error::PublicationUncertain)),
        };
        match outcome {
            Ok(()) => Ok(NoPublication {
                binding: this.take_binding(),
                generation: this.identity.generation,
                _cancelled_transfer: cancelled_transfer,
            }),
            Err((state, error)) => {
                this.keep(state);
                Err(ManuallyDrop::into_inner(this).fail(error))
            }
        }
    }
}
