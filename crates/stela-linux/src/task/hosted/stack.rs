//! Join the actual stopped hosted worker with its original page descriptors.
use super::*;
use crate::owner::RawOwner;
use stela_driver_base::platform::work::kernel_domain::{HostedChildReservation, HostedPages};

#[repr(C)]
pub(super) struct ModelStackTicket {
    version: u32,
    bytes: u32,
    generation: u64,
    record: usize,
    nonce: u64,
}

unsafe extern "C" {
    fn stela_linux_page_model_stack_admit(
        owner: *const RawOwner,
        cpu_base: *mut c_void,
        ticket: *mut ModelStackTicket,
    ) -> i32;
    fn stela_linux_page_owner_context(owner: *const RawOwner) -> i32;
    fn stela_linux_page_stack_cancel(ticket: *const ModelStackTicket) -> i32;
}

/// An unpublished hosted worker and its exact original descriptor reservation.
/// Abandonment keeps both reservations excluded from reuse.
#[must_use = "explicitly cancel this unpublished hosted stack"]
pub struct HostedStackReservation<'runtime, const N: usize> {
    owner: *const RawOwner,
    pub(super) worker: HostedChildReservation<'runtime, N>,
    pub(super) descriptors: Option<ModelStackTicket>,
}

/// Reserve the actual stopped worker and its model stack descriptors.
///
/// # Safety
/// Call inside the original mounted creator's entered source scope, at
/// quiescence, on the same retained runtime that supplied the inventory.
pub unsafe fn reserve_hosted_child_stack<const N: usize>(
    runtime: Pin<&HostedRuntime<N>>,
    owner: *const RawOwner,
) -> Result<HostedStackReservation<'_, N>, ResourceBootstrapError> {
    use ResourceBootstrapError::{Native, Work};
    let worker = runtime
        .reserve_child_stack(stack_requirement().map_err(Work)?)
        .map_err(Work)?;
    let stack = worker.stack();
    let base = stack
        .cpu_address(0, stack.bytes())
        .unwrap_or_else(|_| initial::fatal());
    let mut ticket = ModelStackTicket {
        version: 2,
        bytes: size_of::<ModelStackTicket>() as u32,
        generation: 0,
        record: 0,
        nonce: 0,
    };
    // SAFETY: the exact creator owns this worker and its kept mapping.
    let status =
        unsafe { stela_linux_page_model_stack_admit(owner, base.as_ptr().cast(), &mut ticket) };
    if status != 0 {
        // SAFETY: the descriptor admission returned no markers or source users.
        unsafe { worker.cancel() }.map_err(|(_, error)| Work(error))?;
        return Err(Native(status));
    }
    Ok(HostedStackReservation {
        owner,
        worker,
        descriptors: Some(ticket),
    })
}

impl<const N: usize> HostedStackReservation<'_, N> {
    pub fn stack(&self) -> HostedPages {
        self.worker.stack()
    }

    /// # Safety
    /// Call in the same entered creator at quiescence after every unpublished
    /// source stack user has joined.
    pub unsafe fn cancel(mut self) -> Result<(), (Self, ResourceBootstrapError)> {
        use ResourceBootstrapError::{Native, Work};
        if let Err(error) = self.worker.check_creator() {
            return Err((self, Work(error)));
        }
        if let Some(ticket) = self.descriptors.as_ref() {
            // SAFETY: the creator still owns the exact unpublished markers.
            let mut status = unsafe { stela_linux_page_owner_context(self.owner) };
            if status == 0 {
                // SAFETY: the quiescent entered owner and exact ticket were checked.
                status = unsafe { stela_linux_page_stack_cancel(ticket) };
            }
            if status != 0 {
                return Err((self, Native(status)));
            }
            self.descriptors = None;
        }
        // SAFETY: the descriptor join completed and the worker never ran.
        unsafe { self.worker.cancel() }
            .map_err(|(worker, error)| (Self { worker, ..self }, Work(error)))
    }
}
