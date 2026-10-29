//! Scoped execution-context views.
use stela_compiler::context::{ExecutionContext, ScalableStateView, memory::MemoryContextView};

pub(crate) struct ContextLoan<'a> {
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

    pub(crate) fn memory(context: &'a mut ExecutionContext, view: &mut MemoryContextView) -> Self {
        let loan = Self::new(context);
        loan.context.memory = core::ptr::from_mut(view).cast();
        loan
    }

    pub(crate) fn context(&mut self) -> &mut ExecutionContext {
        self.context
    }
}

impl Drop for ContextLoan<'_> {
    fn drop(&mut self) {
        self.context.memory = self.memory;
        self.context.scalable = self.scalable;
    }
}
