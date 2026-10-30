//! Real identity-keyed wait, recursive queue lease, notify and reacquisition.
use super::*;
use stela_contracts::refuse;

#[derive(Clone)]
pub struct Key {
    runtime: Weak<RefCell<State>>,
    identity: Rc<()>,
}
impl Key {
    pub fn same_key(&self, other: &Self) -> bool {
        self.runtime.ptr_eq(&other.runtime) && Rc::ptr_eq(&self.identity, &other.identity)
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Waiting,
    Notified,
    Retired,
}
pub(super) struct Waiting {
    key: Key,
    thread: Weak<Thread>,
    frame: Weak<Frame>,
    released: Option<(usize, u32)>,
    phase: Cell<Phase>,
}
/// A real registered thread/key wait. Non-Clone, no signal/complete setter.
/// Dropping it does not wake or silently remove an outstanding source wait.
pub struct Wait {
    runtime: Weak<RefCell<State>>,
    waiting: Rc<Waiting>,
}
/// Recursive queue acquisition. Non-Clone and no Drop-time unlock:
/// source unlock must execute at its reached cursor. An abandoned lease leaves
/// the callback unable to claim retirement, preserving the unfinished effect.
pub struct Lease {
    runtime: Weak<RefCell<State>>,
    queue: usize,
    frame: Weak<Frame>,
    active: bool,
}
pub(super) fn notified(thread: &Thread) -> bool {
    thread
        .wait
        .borrow()
        .as_ref()
        .is_some_and(|wait| wait.phase.get() == Phase::Notified)
}
pub(super) fn runnable(state: &State, thread: &Thread) -> bool {
    if let Some(wait) = thread.wait.borrow().as_ref() {
        if wait.phase.get() == Phase::Waiting {
            return false;
        }
        if let Some((queue, _)) = wait.released
            && state.queues[queue].lock.is_some_and(|id| id != thread.id)
        {
            return false;
        }
    }
    if let Some(queue) = thread.mutex.get()
        && state.queues[queue].lock.is_some_and(|id| id != thread.id)
    {
        return false;
    }
    true
}
impl Runtime {
    pub fn key(&self) -> Key {
        Key {
            runtime: Rc::downgrade(&self.state),
            identity: Rc::new(()),
        }
    }
    /// Source1030048/1030210 recursive acquisition. Contention blocks this
    /// thread rather than spinning a high-priority callback and starving
    /// the lower-priority owner which must release the mutex.
    pub fn lock(&self, queue: &Queue, invocation: &Invocation) -> Completion<Lease> {
        if self
            .check_runtime(&queue.runtime)
            .and_then(|()| self.check_runtime(&invocation.runtime))
            .and_then(|()| invocation.check_current())
            .is_err()
        {
            return Completion::Refused(refuse!(
                "foreign or nonexecuting native queue acquisition"
            ));
        }
        if invocation.frame.thread.wait.borrow().is_some() {
            return Completion::Refused(refuse!("native lock acquisition before wait retirement"));
        }
        let mut s = self.state.borrow_mut();
        let q = &mut s.queues[queue.id];
        if q.lock
            .is_some_and(|thread| thread != invocation.thread_id())
        {
            invocation.frame.thread.mutex.set(Some(queue.id));
            return Completion::Busy { deadline: None };
        }
        let Some(depth) = q.depth.checked_add(1) else {
            return Completion::Refused(refuse!("native queue recursion exhausted"));
        };
        let Some(leases) = invocation.frame.leases.get().checked_add(1) else {
            return Completion::Refused(refuse!("native queue lease count exhausted"));
        };
        q.lock = Some(invocation.thread_id());
        q.depth = depth;
        invocation.frame.leases.set(leases);
        invocation.frame.thread.mutex.set(None);
        Completion::Retired {
            value: Lease {
                runtime: Rc::downgrade(&self.state),
                queue: queue.id,
                frame: Rc::downgrade(&invocation.frame),
                active: true,
            },
            refusal: None,
        }
    }
    /// Source-key wait, keeping held queue locks. Reporting publication
    /// uses an independent immediate ACK callback to notify this same key.
    pub fn wait(&self, invocation: &Invocation, key: &Key) -> Result<Wait> {
        self.register_wait(invocation, key, None)
    }
    ///1030250 atomically registers the waiter BEFORE dropping every
    /// recursive acquisition of this queue. Other queue work/immediate callbacks
    ///can then execute; returning Wait alone is not wait completion.
    pub fn drain_wait(&self, queue: &Queue, invocation: &Invocation, key: &Key) -> Result<Wait> {
        self.check_runtime(&queue.runtime)?;
        self.register_wait(invocation, key, Some(queue.id))
    }
    fn register_wait(
        &self,
        invocation: &Invocation,
        key: &Key,
        release: Option<usize>,
    ) -> Result<Wait> {
        self.check_runtime(&invocation.runtime)?;
        self.check_runtime(&key.runtime)?;
        invocation.check_current()?;
        let thread = invocation.frame.thread.clone();
        if thread.wait.borrow().is_some() || thread.mutex.get().is_some() {
            return Err(Error::Contract(refuse!(
                "native thread already has an unfinished wait"
            )));
        }
        let mut s = self.state.borrow_mut();
        let released = if let Some(queue) = release {
            let q = &s.queues[queue];
            if q.lock != Some(thread.id) || q.depth == 0 {
                return Err(Error::Contract(refuse!(
                    "native drain does not own recursive queue lock"
                )));
            }
            Some((queue, q.depth))
        } else {
            None
        };
        let waiting = Rc::new(Waiting {
            key: key.clone(),
            thread: Rc::downgrade(&thread),
            frame: Rc::downgrade(&invocation.frame),
            released,
            phase: Cell::new(Phase::Waiting),
        });
        // One borrow covers registration and release: no lost-notify gap.
        *thread.wait.borrow_mut() = Some(waiting.clone());
        s.waiters.push(Rc::downgrade(&waiting));
        if let Some((queue, _)) = released {
            s.queues[queue].lock = None;
            s.queues[queue].depth = 0;
        }
        fence(Ordering::SeqCst);
        Ok(Wait {
            runtime: Rc::downgrade(&self.state),
            waiting,
        })
    }
    ///1023624/10302bc wakes ALL waiters of the same identity. No numeric
    /// key alias, remembered notify credit, source-predicate update or callback
    /// completion is created. A later wait needs another notification.
    pub fn notify(&self, key: &Key) -> Result<usize> {
        self.check_runtime(&key.runtime)?;
        let mut s = self.state.borrow_mut();
        let mut count = 0;
        s.waiters.retain(|weak| {
            let Some(wait) = weak.upgrade() else {
                return false;
            };
            if wait.phase.get() == Phase::Waiting && wait.key.same_key(key) {
                wait.phase.set(Phase::Notified);
                if let Some(frame) = wait.frame.upgrade() {
                    frame.deadline.set(None);
                }
                count += 1;
            }
            wait.phase.get() == Phase::Waiting
        });
        fence(Ordering::Release);
        Ok(count)
    }
    pub fn queue_lock_depth(&self, queue: &Queue) -> Result<u32> {
        self.check_runtime(&queue.runtime)?;
        Ok(self.state.borrow().queues[queue.id].depth)
    }
}
impl Wait {
    /// Source wait completion/reacquisition, callable only by its same
    /// executing native invocation. Notification alone never advances source
    /// predicates or makes this a transferable success receipt.
    pub fn advance(&mut self) -> Completion<()> {
        let Some(state) = self.runtime.upgrade() else {
            return Completion::Refused(refuse!("native wait scheduler abandoned"));
        };
        let Some(frame) = self.waiting.frame.upgrade() else {
            return Completion::Refused(refuse!("native waiting invocation abandoned"));
        };
        let invocation = Invocation {
            runtime: self.runtime.clone(),
            frame,
        };
        if invocation.check_current().is_err() {
            return Completion::Refused(refuse!("native wait resumed from foreign context"));
        }
        match self.waiting.phase.get() {
            Phase::Waiting => return Completion::Busy { deadline: None },
            Phase::Retired => return Completion::Refused(refuse!("native wait already retired")),
            Phase::Notified => {}
        }
        let Some(thread) = self.waiting.thread.upgrade() else {
            return Completion::Refused(refuse!("native waiting thread abandoned"));
        };
        if !thread
            .wait
            .borrow()
            .as_ref()
            .is_some_and(|w| Rc::ptr_eq(w, &self.waiting))
        {
            return Completion::Refused(refuse!("native wait lost its actual thread registration"));
        }
        let mut s = state.borrow_mut();
        if let Some((queue, depth)) = self.waiting.released {
            let q = &mut s.queues[queue];
            if q.lock.is_some_and(|owner| owner != thread.id) {
                return Completion::Busy { deadline: None };
            }
            if q.lock.is_some() || q.depth != 0 {
                return Completion::Refused(refuse!(
                    "native drain lock was reacquired outside its wait"
                ));
            }
            q.lock = Some(thread.id);
            q.depth = depth;
        }
        fence(Ordering::Acquire);
        *thread.wait.borrow_mut() = None;
        self.waiting.phase.set(Phase::Retired);
        Completion::Retired {
            value: (),
            refusal: None,
        }
    }
}
impl Lease {
    pub fn release(&mut self) -> Result<()> {
        if !self.active {
            return Err(Error::Contract(refuse!(
                "native queue lease already released"
            )));
        }
        let state = self
            .runtime
            .upgrade()
            .ok_or(Error::Contract(refuse!("native lease scheduler abandoned")))?;
        let frame = self.frame.upgrade().ok_or(Error::Contract(refuse!(
            "native lease invocation abandoned"
        )))?;
        Invocation {
            runtime: self.runtime.clone(),
            frame: frame.clone(),
        }
        .check_current()?;
        let mut s = state.borrow_mut();
        let q = &mut s.queues[self.queue];
        if q.lock != Some(frame.thread.id)
            || q.depth == 0
            || frame.leases.get() == 0
            || frame.thread.wait.borrow().is_some()
        {
            return Err(Error::Contract(refuse!(
                "native lease release lost its lock or unfinished wait"
            )));
        }
        q.depth -= 1;
        if q.depth == 0 {
            q.lock = None;
        }
        frame.leases.set(frame.leases.get() - 1);
        self.active = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
