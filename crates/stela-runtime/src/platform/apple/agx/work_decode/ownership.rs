//! Linear identity for one accepted native programming phase. Reservation
//! precedes source reads, and binds to one actual SGX object. Cancellation
//! cannot resurrect an unfinished helper in a newly reserved native run.

use alloc::rc::Rc;
use core::cell::Cell;

#[derive(Debug)]
struct State {
    live: Cell<bool>,
    issuer: Cell<Option<*const ()>>,
}
#[derive(Debug, Clone)]
pub struct Identity(Rc<State>);
impl Identity {
    pub(crate) fn new() -> Self {
        Self(Rc::new(State {
            live: Cell::new(true),
            issuer: Cell::new(None),
        }))
    }
    pub(crate) fn live(&self) -> bool {
        self.0.live.get()
    }
    pub(crate) fn same(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
    pub(crate) fn invalidate(&self) {
        self.0.live.set(false);
    }
    pub(crate) fn bind<T>(&self, issuer: &Rc<T>) -> Result<(), &'static str> {
        if !self.live() {
            return Err("GFX native programming phase was canceled");
        }
        let issuer = Rc::as_ptr(issuer).cast::<()>();
        if self.0.issuer.get().is_some_and(|old| old != issuer) {
            return Err("GFX native programming phase belongs to another SGX object");
        }
        self.0.issuer.set(Some(issuer));
        Ok(())
    }
}
