//! BSP device-dispatch metadata; the existing IDT and CPU frame remain owned
//! by main. Only actual checked native dispatch enters this state.
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use stela_drivers::bus::irq::IrqError;
pub(super) struct Context {
    depth: AtomicU32,
    interrupted: AtomicUsize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Snapshot {
    pub depth: u32,
    pub interrupted_rsp: Option<usize>,
}
pub(super) struct Guard<'a> {
    owner: &'a Context,
    depth: u32,
    interrupted: usize,
}
impl Context {
    pub const fn new() -> Self {
        Self {
            depth: AtomicU32::new(0),
            interrupted: AtomicUsize::new(0),
        }
    }
    /// # Safety
    /// `cpu` is the actual owning BSP check for this real device ISR, with
    /// local IRQs disabled. `interrupted` is copied from the unchanged CPU
    /// entry frame, never inferred from the ISR's own IST stack or caller data.
    pub unsafe fn enter(
        &self,
        cpu: Result<(), IrqError>,
        interrupted: Option<usize>,
    ) -> Result<Guard<'_>, IrqError> {
        cpu?;
        let depth = self.depth.load(Ordering::Relaxed);
        let next = depth.checked_add(1).ok_or(IrqError::Exhausted)?;
        let previous = self
            .interrupted
            .swap(interrupted.unwrap_or(0), Ordering::Relaxed);
        self.depth.store(next, Ordering::Release);
        Ok(Guard {
            owner: self,
            depth,
            interrupted: previous,
        })
    }
    pub fn current(&self, cpu: Result<(), IrqError>) -> Result<Option<Snapshot>, IrqError> {
        cpu?;
        let depth = self.depth.load(Ordering::Acquire);
        if depth == 0 {
            return Ok(None);
        }
        let rsp = self.interrupted.load(Ordering::Relaxed);
        Ok(Some(Snapshot {
            depth,
            interrupted_rsp: (rsp != 0).then_some(rsp),
        }))
    }
}
impl Drop for Guard<'_> {
    fn drop(&mut self) {
        // Same checked BSP/disabled-IRQ call chain; nested entries must have
        // completed before this actual dispatch continuation resumes.
        self.owner
            .interrupted
            .store(self.interrupted, Ordering::Relaxed);
        self.owner.depth.store(self.depth, Ordering::Release);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_entry_scopes_balance_nested_saved_frames_and_wrong_cpu_refuses() {
        let c = Context::new();
        assert_eq!(c.current(Ok(())), Ok(None));
        let first = unsafe { c.enter(Ok(()), Some(0x1230)) }.unwrap();
        assert_eq!(
            c.current(Ok(())),
            Ok(Some(Snapshot {
                depth: 1,
                interrupted_rsp: Some(0x1230)
            }))
        );
        assert!(matches!(
            unsafe { c.enter(Err(IrqError::WrongCpu), Some(0x4440)) },
            Err(IrqError::WrongCpu)
        ));
        assert_eq!(c.current(Err(IrqError::WrongCpu)), Err(IrqError::WrongCpu));
        {
            let _second = unsafe { c.enter(Ok(()), Some(0x4560)) }.unwrap();
            assert_eq!(c.current(Ok(())).unwrap().unwrap().depth, 2);
        }
        assert_eq!(
            c.current(Ok(())).unwrap().unwrap().interrupted_rsp,
            Some(0x1230)
        );
        drop(first);
        assert_eq!(c.current(Ok(())), Ok(None));
        assert_eq!(c.interrupted.load(Ordering::Relaxed), 0);
    }
    #[test]
    fn overflow_and_missing_saved_frame_never_invent_an_interrupted_pointer() {
        let c = Context::new();
        let guard = unsafe { c.enter(Ok(()), None) }.unwrap();
        assert_eq!(c.current(Ok(())).unwrap().unwrap().interrupted_rsp, None);
        drop(guard);
        c.depth.store(u32::MAX, Ordering::Relaxed);
        assert!(matches!(
            unsafe { c.enter(Ok(()), Some(0x1000)) },
            Err(IrqError::Exhausted)
        ));
        assert_eq!(c.depth.load(Ordering::Relaxed), u32::MAX);
        assert_eq!(c.interrupted.load(Ordering::Relaxed), 0);
    }
}
