//! Construction custody before fallible or unwinding access callbacks.
pub(super) struct Kept<T>(Option<T>);
impl<T> Kept<T> {
    pub(super) fn new(value: T) -> Self {
        Self(Some(value))
    }
    pub(super) fn get_mut(&mut self) -> &mut T {
        self.0.as_mut().expect("kept construction owner")
    }
    pub(super) fn take(&mut self) -> T {
        self.0.take().expect("kept construction owner")
    }
}
impl<T> Drop for Kept<T> {
    fn drop(&mut self) {
        core::mem::forget(self.0.take());
    }
}
