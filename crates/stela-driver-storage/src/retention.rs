// SPDX-License-Identifier: GPL-2.0-or-later
//! Default-retained hardware resource graphs; only owning driver stages transfer them.

/// Default-retained original graph. Only this driver can transfer its contents;
/// abandonment or unwinding never releases hardware-owned resources.
#[must_use]
pub struct Retained<T> {
    inner: core::mem::ManuallyDrop<T>,
}
impl<T> Retained<T> {
    pub(crate) fn new(value: T) -> Self {
        Self {
            inner: core::mem::ManuallyDrop::new(value),
        }
    }
    pub(crate) fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }
    pub(crate) fn into_inner(self) -> T {
        core::mem::ManuallyDrop::into_inner(self.inner)
    }
}
impl<T> core::ops::Deref for Retained<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.inner
    }
}
