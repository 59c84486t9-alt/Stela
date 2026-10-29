//! Proof that the boot-owned embedded controller is connected to AML.
use super::binding::Binding;
use crate::platform::acpi::{
    Handle,
    resources::{Dependency, Error},
};

/// An active EC supplier dependency. The binding that issued it remains
/// owned by boot; this receipt pins its callback storage against removal.
#[derive(Clone)]
pub struct Installed<'a> {
    dependency: Dependency<'a>,
}

impl<'a> Installed<'a> {
    pub fn from_binding(binding: &Binding<'a>) -> Result<Self, Error> {
        if !binding.device().handle.hardware_active() {
            return Err(Error::Unassigned);
        }
        Ok(Self {
            dependency: binding.supplier()?,
        })
    }

    pub fn handle(&self) -> Handle<'a> {
        self.dependency.handle()
    }
}
