use super::*;
pub(super) struct Read<'a, K: KernelThreadPlatform + 'static, P: Provider + 'static, const N: usize>
{
    slot: &'a Slot<K, P, N>,
    pub(super) pointer: *mut Request<K, P, N>,
}
impl<K: KernelThreadPlatform + 'static, P: Provider + 'static, const N: usize> Drop
    for Read<'_, K, P, N>
{
    fn drop(&mut self) {
        let before = self.slot.readers.fetch_sub(1, Ordering::Release);
        if before == 0 {
            fatal();
        }
        if !self.pointer.is_null() && self.slot.phase.load(Ordering::Acquire) == RETIRING {
            self.slot.finalize_pending.store(true, Ordering::Release);
            self.slot.delivery.record();
        }
    }
}
impl<K: KernelThreadPlatform + 'static, P: Provider + 'static, const N: usize> Slot<K, P, N> {
    pub(super) fn read(&self) -> Read<'_, K, P, N> {
        if self
            .readers
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_add(1))
            .is_err()
        {
            fatal();
        }
        // Pin BEFORE pointer load. Unpublish then join excludes load-before-pin
        // UAF. Callback only decrements an integer; it never drops an owner.
        Read {
            slot: self,
            pointer: self.request.load(Ordering::Acquire),
        }
    }
}
impl<K: KernelThreadPlatform + 'static, P: Provider + 'static, const N: usize> Broker<K, P, N> {
    pub(super) fn lookup(
        &self,
        task: *mut CTask,
        owner: *const RawOwner,
        generation: Option<u64>,
    ) -> Read<'_, K, P, N> {
        if task.is_null() || owner != self.kernel.raw() {
            fatal();
        }
        for slot in &self.slots {
            let read = slot.read();
            if !read.pointer.is_null() {
                // SAFETY: actual registry strong owner until unpublished and
                // all this row's source/IRQ readers have returned.
                let request = unsafe { &*read.pointer };
                if request.record() == task && request.check(owner, generation) {
                    return read;
                }
            }
        }
        fatal()
    }
    pub(super) unsafe fn allocate(
        &'static self,
        birth: *mut OriginalBirth,
        node: i32,
        unexposed: *mut bool,
    ) -> i32 {
        if unexposed.is_null() || birth.is_null() {
            fatal();
        }
        unsafe {
            *unexposed = false;
        }
        if node != -1 && node != 0 {
            unsafe {
                *unexposed = true;
            }
            return -95;
        }
        let Some(slot) = self.slots.iter().find(|s| {
            s.phase
                .compare_exchange(EMPTY, RESERVED, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        }) else {
            // Actual no-accept branch: genuine birth not consumed and NO
            // native/source allocator invoked. Never errno=>noPub inference.
            unsafe {
                *unexposed = true;
            }
            return -12;
        };
        // Same actual Factory and its real owning mount retained before C.
        let begin = unsafe {
            self.factory
                .begin(NonNull::new(birth).unwrap_or_else(|| fatal()))
        };
        let (state, binding, record, generation) = match begin {
            Ok(child) => {
                let binding = child.binding().clone();
                let record = binding.task.as_ptr();
                let generation = child.generation();
                (Owned::Child(child), Some(binding), record, generation)
            }
            Err(failure) => (Owned::BeginFailure(failure), None, ptr::null_mut(), 0),
        };
        let request = Arc::new(Request {
            broker: self,
            slot,
            service_stage: AtomicU8::new(0),
            source_tail_seen: AtomicBool::new(false),
            record: AtomicPtr::new(record),
            generation: AtomicU64::new(generation),
            binding: UnsafeCell::new(ManuallyDrop::new(binding)),
            context: UnsafeCell::new(ManuallyDrop::new(None)),
            state: UnsafeCell::new(ManuallyDrop::new(state)),
            data_stop: UnsafeCell::new(ManuallyDrop::new(StoppedDataState::Unclaimed)),
            busy: AtomicBool::new(false),
            prepared: AtomicBool::new(false),
            entered: AtomicBool::new(false),
            events: AtomicU8::new(0),
            entry: UnsafeCell::new(None),
            fault: UnsafeCell::new(ManuallyDrop::new(None)),
            detached: UnsafeCell::new(ManuallyDrop::new(None)),
        });
        let context = Box::new(CallbackContext {
            request: NonNull::from(&*request),
        });
        // SAFETY: constructor-only before registry/native/C publication.
        unsafe {
            *request
                .context
                .get()
                .cast::<Option<Box<CallbackContext<K, P, N>>>>() = Some(context);
        }
        let raw = Arc::into_raw(request) as *mut Request<K, P, N>;
        slot.request.store(raw, Ordering::Release);
        slot.phase.store(LIVE, Ordering::Release);
        // SAFETY: exact actual registry strong ref was published above.
        let request = unsafe { &*raw };
        if record.is_null() || generation == 0 {
            fatal();
        } // retained BeginFailure, never false errno.
        // SAME actual constructor ancestry captured by original create_info
        // through private kthreadd source scope, never PID/taskptr/name magic.
        // No source body/wait or new current is executed in this observation.
        if unsafe {
            self.kernel
                .platform()
                .with_process(|_entered| self.managed.associate(record, generation))
        }
        .is_err()
        {
            fatal();
        }

        match unsafe { request.prefix() } {
            Ok(()) => {
                request.notify(CREATED);
                0
            }
            Err(_) => {
                if unsafe { request.cancel() }.is_err() {
                    fatal();
                }
                request.notify(ABORT_RECORDED);
                // Actual affine NoPublication is held in stable request; keep
                // metadata/context through original source free + abort tail.
                let errno = request.errno();
                unsafe {
                    *unexposed = true;
                }
                errno
            }
        }
    }
    pub(super) fn next_event(&self) -> Result<Option<Event<K, P, N>>, Error> {
        for slot in &self.slots {
            let read = slot.read();
            if read.pointer.is_null() {
                continue;
            }
            let request = unsafe { &*read.pointer };
            let events = request.events.swap(0, Ordering::AcqRel);
            if events == 0 {
                continue;
            }
            // SAFETY: pinned registry row keeps the exact Arc allocation.
            unsafe {
                Arc::increment_strong_count(read.pointer);
            }
            let request = unsafe { Arc::from_raw(read.pointer) };
            drop(read);
            return Ok(Some(Event {
                kind: EventKind(events),
                request: RequestHandle {
                    request: ManuallyDrop::new(request),
                    _affine: PhantomData,
                },
            }));
        }
        Ok(None)
    }
}
/// Notification bits ONLY: none proves source/RCU/native completion.
#[derive(Clone, Copy, Debug)]
pub(crate) struct EventKind(pub(super) u8);
impl EventKind {
    pub(crate) fn source_freed(self) -> bool {
        self.0 & SOURCE_FREED != 0
    }
    pub(crate) fn terminal_returned(self) -> bool {
        self.0 & TERMINAL_RETURNED != 0
    }
    pub(crate) fn abort_recorded(self) -> bool {
        self.0 & ABORT_RECORDED != 0
    }
    pub(crate) fn created(self) -> bool {
        self.0 & CREATED != 0
    }
}
pub(crate) struct Event<K: KernelThreadPlatform + 'static, P: Provider + 'static, const N: usize> {
    pub(crate) kind: EventKind,
    pub(crate) request: RequestHandle<K, P, N>,
}
/// Abandonment retains request, actual metadata and callback storage.
pub(crate) struct RequestHandle<
    K: KernelThreadPlatform + 'static,
    P: Provider + 'static,
    const N: usize,
> {
    pub(super) request: ManuallyDrop<Arc<Request<K, P, N>>>,
    pub(super) _affine: PhantomData<Rc<()>>,
}
pub(crate) struct RetiringRequest<
    K: KernelThreadPlatform + 'static,
    P: Provider + 'static,
    const N: usize,
> {
    pub(super) slot: &'static Slot<K, P, N>,
    pub(super) request: ManuallyDrop<Arc<Request<K, P, N>>>,
}
/// Only actual NoPublication or final RetiredMetadata constructs this value.
pub(crate) struct FinalMetadata<K: KernelThreadPlatform + 'static, const N: usize> {
    kernel: &'static KernelOwner<K, N>,
    slot_phase: &'static AtomicU8,
    binding: ManuallyDrop<Arc<TaskBinding<N>>>,
    generation: u64,
}
impl<K: KernelThreadPlatform + 'static, P: Provider + 'static, const N: usize>
    RequestHandle<K, P, N>
{
    pub(crate) fn generation(&self) -> u64 {
        self.request.generation()
    }
    /// # Safety
    /// Actual process release outside IRQ/C lock/native loan. Registry or
    /// retiring control still owns the whole request. No final owner drops.
    pub(crate) unsafe fn put(mut self) {
        let slot = self.request.slot;
        unsafe { ManuallyDrop::drop(&mut self.request) };
        if slot.phase.load(Ordering::Acquire) == RETIRING {
            slot.finalize_pending.store(true, Ordering::Release);
            slot.delivery.record();
        }
    }
    /// # Safety
    /// Caller actually joined native callback/physical return AND source free/
    /// producer tails (or actual NoPub AND source free tail). Event/Arc counts
    /// cannot authorize this. No later C/native Context use is possible.
    pub(crate) unsafe fn unpublish(mut self) -> Result<RetiringRequest<K, P, N>, Self> {
        let pointer = Arc::as_ptr(&self.request) as *mut Request<K, P, N>;
        for slot in &self.request.broker.slots {
            if slot.request.load(Ordering::Acquire) != pointer {
                continue;
            }
            if slot
                .phase
                .compare_exchange(LIVE, RETIRING, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return Err(self);
            }
            if slot.request.swap(ptr::null_mut(), Ordering::AcqRel) != pointer {
                fatal();
            }
            // Transfer actual registry owner; finalization still joins readers.
            let registry = unsafe { Arc::from_raw(pointer) };
            unsafe { ManuallyDrop::drop(&mut self.request) };
            return Ok(RetiringRequest {
                slot,
                request: ManuallyDrop::new(registry),
            });
        }
        Err(self)
    }
}
impl<K: KernelThreadPlatform + 'static, P: Provider + 'static, const N: usize>
    RetiringRequest<K, P, N>
{
    /// # Safety
    /// True native/source callback tails joined before unpublish; actual
    /// IF-enabled original process release, no C lock/borrow or segment loan.
    /// Independent slot readers must have returned. Unique Arc is an additional
    /// negative check, never the source/native callback-completion producer.
    pub(crate) unsafe fn finish(self) -> Result<FinalMetadata<K, N>, Self> {
        if self.slot.readers.load(Ordering::Acquire) != 0 {
            return Err(self);
        }
        let mut this = ManuallyDrop::new(self);
        let arc = unsafe { ManuallyDrop::take(&mut this.request) };
        let request = match Arc::try_unwrap(arc) {
            Ok(request) => request,
            Err(arc) => {
                this.request = ManuallyDrop::new(arc);
                return Err(ManuallyDrop::into_inner(this));
            }
        };
        let request = ManuallyDrop::new(request);
        // SAFETY: exact unique control after actual tail and row-reader joins.
        let state = unsafe { ManuallyDrop::take(&mut *request.state.get()) };
        let (binding, generation) = match state {
            Owned::NoPublication(receipt) => {
                let generation = receipt.generation();
                (receipt.into_metadata(), generation)
            }
            Owned::Retired(receipt) => {
                let generation = receipt.generation();
                (receipt.into_metadata(), generation)
            }
            state => {
                unsafe {
                    *request.state.get() = ManuallyDrop::new(state);
                };
                fatal()
            }
        };
        unsafe {
            // Real affine receipt retains binding through these nonfinal drops.
            ManuallyDrop::drop(&mut *request.detached.get());
            ManuallyDrop::drop(&mut *request.binding.get());
            ManuallyDrop::drop(&mut *request.context.get());
            ManuallyDrop::drop(&mut *request.fault.get());
        }
        let kernel = &*request.broker.kernel;
        drop(ManuallyDrop::into_inner(request));

        Ok(FinalMetadata {
            kernel,
            slot_phase: &this.slot.phase,
            binding: ManuallyDrop::new(binding),
            generation,
        })
    }
}
impl<K: KernelThreadPlatform + 'static, const N: usize> FinalMetadata<K, N> {
    /// # Safety
    /// Genuine original process after ALL source C callback borrows returned;
    /// no native transient permit. The real affine receipt above is retained.
    pub(crate) unsafe fn release(mut self) -> Result<(), Self> {
        let binding = unsafe { ManuallyDrop::take(&mut self.binding) };
        match unsafe { binding.release_original(self.kernel, self.generation) } {
            Ok(()) => {
                self.slot_phase.store(EMPTY, Ordering::Release);
                Ok(())
            }
            Err(binding) => {
                self.binding = ManuallyDrop::new(binding);
                Err(self)
            }
        }
    }
}
