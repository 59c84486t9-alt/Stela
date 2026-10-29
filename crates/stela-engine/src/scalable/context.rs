//! Execution-context pointers shared by context leaves and blocks.

use stela_compiler::context::{ExecutionContext, ScalableStateView, memory::MemoryContextView};

/// Restores the pointers before the register and service borrows expire,
/// including when an error unwinds after the native call.
pub(super) struct ContextLoan<'a> {
    context: &'a mut ExecutionContext,
    memory: *mut core::ffi::c_void,
    scalable: *mut ScalableStateView,
}

impl<'a> ContextLoan<'a> {
    fn new(context: &'a mut ExecutionContext) -> Self {
        Self {
            memory: context.memory,
            scalable: context.scalable,
            context,
        }
    }

    pub(super) fn scalable(
        context: &'a mut ExecutionContext,
        view: &mut ScalableStateView,
    ) -> Self {
        let loan = Self::new(context);
        loan.context.scalable = core::ptr::from_mut(view);
        loan
    }

    pub(super) fn memory(context: &'a mut ExecutionContext, view: &mut MemoryContextView) -> Self {
        let loan = Self::new(context);
        loan.context.memory = core::ptr::from_mut(view).cast();
        loan
    }

    pub(super) fn context(&mut self) -> &mut ExecutionContext {
        self.context
    }
}

impl Drop for ContextLoan<'_> {
    fn drop(&mut self) {
        self.context.memory = self.memory;
        self.context.scalable = self.scalable;
    }
}
