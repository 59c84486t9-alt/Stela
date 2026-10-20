//! The process's workqueue kqueue (xnu `struct kqworkq`, `kevent_qos` with
//! `KEVENT_FLAG_WORKQ`, `kevent_workq_internal`): the kqueue libdispatch
//! registers its process-wide sources on, whose events the workqueue
//! delivers to kevent threads it requests at each knote's QoS.
//!
//! XNU keeps a knote in the bucket of the QoS it was attached with
//! (`knote_reset_priority`: no QoS means the event manager), never moving
//! it on a later touch. Here each bucket is a private host kqueue holding
//! that bucket's knotes ([`HostBuckets`]), so the host kernel runs every
//! filter and the activation, coalescing and `EV_CLEAR`/`EV_ONESHOT`/
//! `EV_DISPATCH` protocols as it does for any kqueue. A monitor host
//! thread waits on a further host kqueue ([`Watch`]) watching each
//! bucket's readability once (`EV_DISPATCH`): a bucket with active knotes
//! and no request makes a kevent thread request
//! (`kqueue_threadreq_initiate`), whose thread collects the bucket's
//! events onto its stack as it leaves the kernel
//! (`kqworkq_begin_processing`, `kqueue_scan`) and again each time it
//! returns (`KEVENT_FLAG_PARKING`), until a return finds none and unbinds
//! it; the watch is then armed again. Workloops
//! ([`kqworkloop`](super::kqworkloop)) keep their ordinary knotes the same
//! way under the same monitor.
use super::{EFAULT, EINVAL, ENOMEM, priority};
use crate::hosted::{forward, kernel::Process, memory, threads::lock};
use anyhow::{Result, anyhow};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

/// `KQWQ_NBUCKETS`: one per thread QoS tier, then the event manager's
/// (`KQWQ_QOS_MANAGER`), numbered from 1 as `tr_kq_qos_index` is.
pub(crate) const BUCKETS: u8 = priority::THREAD_QOS_LAST;
pub(crate) const MANAGER_BUCKET: u8 = BUCKETS;
/// `struct kevent_qos_s`.
pub(crate) const KEVENT_BYTES: u64 = 72;
/// `WQ_KEVENT_LIST_LEN` and `WQ_KEVENT_DATA_SIZE`: the events and the
/// out-of-line data a kevent thread's stack receives below `pthread_self`.
pub(crate) const LIST_LEN: u64 = 16;
pub(crate) const DATA_BYTES: u64 = 32 << 10;

/// `KEVENT_FLAG_*` (`sys/event_private.h`).
pub(crate) const KEVENT_FLAG_IMMEDIATE: u64 = 0x000001;
pub(crate) const KEVENT_FLAG_ERROR_EVENTS: u64 = 0x000002;
pub(crate) const KEVENT_FLAG_STACK_DATA: u64 = 0x000008;
pub(crate) const KEVENT_FLAG_WORKQ: u64 = 0x000020;
pub(crate) const KEVENT_FLAG_WORKLOOP: u64 = 0x000400;
pub(crate) const KEVENT_FLAG_DYNAMIC_KQ_MUST_EXIST: u64 = 0x020000;
pub(crate) const KEVENT_FLAG_DYNAMIC_KQ_MUST_NOT_EXIST: u64 = 0x040000;
/// `KEVENT_FLAG_USER` and `KEVENT_ID_FLAG_USER`.
pub(crate) const KEVENT_FLAG_USER: u64 = KEVENT_FLAG_IMMEDIATE
    | KEVENT_FLAG_ERROR_EVENTS
    | KEVENT_FLAG_STACK_DATA
    | KEVENT_FLAG_WORKQ
    | KEVENT_FLAG_WORKLOOP
    | KEVENT_FLAG_DYNAMIC_KQ_MUST_EXIST
    | KEVENT_FLAG_DYNAMIC_KQ_MUST_NOT_EXIST;
const KEVENT_ID_FLAG_USER: u64 = KEVENT_FLAG_WORKLOOP
    | KEVENT_FLAG_DYNAMIC_KQ_MUST_EXIST
    | KEVENT_FLAG_DYNAMIC_KQ_MUST_NOT_EXIST;

/// `EV_*` (`sys/event.h`).
pub(crate) const EV_ADD: u16 = 0x0001;
pub(crate) const EV_DELETE: u16 = 0x0002;
pub(crate) const EV_ENABLE: u16 = 0x0004;
pub(crate) const EV_DISABLE: u16 = 0x0008;
pub(crate) const EV_ONESHOT: u16 = 0x0010;
pub(crate) const EV_CLEAR: u16 = 0x0020;
pub(crate) const EV_RECEIPT: u16 = 0x0040;
const EV_DISPATCH: u16 = 0x0080;
const EV_UDATA_SPECIFIC: u16 = 0x0100;
pub(crate) const EV_ERROR: u16 = 0x4000;
const EVFILT_READ: i16 = -1;
pub(crate) const ENOENT: i64 = 2;
const EINTR: i32 = 4;
/// `_pthread_priority_normalize`: the bits a knote's QoS keeps.
const FALLBACK_FLAG: u64 = 0x0400_0000;
const QOS_CLASS_MASK: u64 = 0x0000_3f00;
const PRIORITY_MASK: u64 = 0xff;
/// The watch's `udata`: the owner's tag above the bucket.
const TAG_SHIFT: u32 = 8;
/// The descriptors kept free of the private kqueues at the top of the
/// descriptor table.
const PRIVATE_DESCRIPTOR_RESERVE: u64 = 64;

/// One `struct kevent_qos_s`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Kevent {
    pub(crate) ident: u64,
    pub(crate) filter: i16,
    pub(crate) flags: u16,
    pub(crate) qos: i32,
    pub(crate) udata: u64,
    pub(crate) fflags: u32,
    pub(crate) xflags: u32,
    pub(crate) data: i64,
    pub(crate) ext: [u64; 4],
}

impl Kevent {
    pub(crate) fn decode(bytes: &[u8]) -> Self {
        let u64_at = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
        let u32_at = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let u16_at = |at: usize| u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap());
        Self {
            ident: u64_at(0),
            filter: u16_at(8) as i16,
            flags: u16_at(10),
            qos: u32_at(12) as i32,
            udata: u64_at(16),
            fflags: u32_at(24),
            xflags: u32_at(28),
            data: u64_at(32) as i64,
            ext: [u64_at(40), u64_at(48), u64_at(56), u64_at(64)],
        }
    }

    pub(crate) fn encode(&self) -> [u8; KEVENT_BYTES as usize] {
        let mut bytes = [0; KEVENT_BYTES as usize];
        bytes[0..8].copy_from_slice(&self.ident.to_le_bytes());
        bytes[8..10].copy_from_slice(&self.filter.to_le_bytes());
        bytes[10..12].copy_from_slice(&self.flags.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.qos.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.udata.to_le_bytes());
        bytes[24..28].copy_from_slice(&self.fflags.to_le_bytes());
        bytes[28..32].copy_from_slice(&self.xflags.to_le_bytes());
        bytes[32..40].copy_from_slice(&self.data.to_le_bytes());
        for (index, word) in self.ext.iter().enumerate() {
            let at = 40 + index * 8;
            bytes[at..at + 8].copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    /// Read the change at `index` of a guest list.
    pub(crate) fn read(list: u64, index: u64) -> Option<Self> {
        memory::read(list + index * KEVENT_BYTES, KEVENT_BYTES as usize)
            .map(|bytes| Self::decode(&bytes))
    }

    pub(crate) fn write(&self, list: u64, index: u64) -> bool {
        memory::write(list + index * KEVENT_BYTES, &self.encode())
    }

    /// The knote it names: `udata` is part of the name only for
    /// `EV_UDATA_SPECIFIC` knotes (`kq_find_knote_and_kq_lock`).
    fn key(&self) -> Key {
        Key {
            ident: self.ident,
            filter: self.filter,
            udata: (self.flags & EV_UDATA_SPECIFIC != 0).then_some(self.udata),
        }
    }

    /// This change failed with `errno` (`EV_ERROR`).
    pub(crate) fn failed_with(mut self, errno: u64) -> Self {
        self.flags |= EV_ERROR;
        self.data = errno as i64;
        self
    }

    pub(crate) fn failed(&self) -> bool {
        self.flags & EV_ERROR != 0 && self.data != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    ident: u64,
    filter: i16,
    udata: Option<u64>,
}

/// What a host kqueue set records of a knote: its bucket and the
/// normalized QoS its events carry (`kn_qos`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Knote {
    pub(crate) bucket: u8,
    pub(crate) qos: i32,
}

/// `_pthread_priority_normalize` of a priority with a QoS.
pub(crate) fn normalize(priority: u64) -> u64 {
    let mut normalized = priority;
    let relative = priority::relative_priority(priority);
    if !(priority::MIN_TIER_IMPORTANCE..=0).contains(&relative) {
        normalized |= PRIORITY_MASK;
    }
    normalized & (priority::OVERCOMMIT_FLAG | FALLBACK_FLAG | QOS_CLASS_MASK | PRIORITY_MASK)
}

/// `knote_reset_priority` on a workqueue kqueue: the bucket and `kn_qos`
/// of a knote attached with `qos`.
fn attach_priority(qos: i32) -> Knote {
    let priority = qos as u32 as u64;
    let tier = priority::thread_qos(priority);
    if tier == priority::THREAD_QOS_UNSPECIFIED || priority & priority::EVENT_MANAGER_FLAG != 0 {
        return Knote {
            bucket: MANAGER_BUCKET,
            qos: priority::EVENT_MANAGER_FLAG as i32,
        };
    }
    Knote {
        bucket: tier,
        qos: normalize(priority) as u32 as i32,
    }
}

/// The host kqueue the monitor waits on: each bucket kqueue's readability,
/// named by its owner's tag and its bucket.
pub(crate) struct Watch(i32);

impl Watch {
    /// Watch `descriptor` for the first time (`EV_ADD`) or once more
    /// (`EV_ENABLE`), until it next fires (`EV_DISPATCH`).
    fn change(&self, descriptor: i32, tag: u32, bucket: u8, action: u16) -> Result<()> {
        let change = libc::kevent64_s {
            ident: descriptor as u64,
            filter: EVFILT_READ,
            flags: action | EV_DISPATCH,
            fflags: 0,
            data: 0,
            udata: u64::from(tag) << TAG_SHIFT | u64::from(bucket),
            ext: [0; 2],
        };
        // SAFETY: one change from a local, no events out.
        let changed = unsafe {
            libc::kevent64(
                self.0,
                &change,
                1,
                core::ptr::null_mut(),
                0,
                0,
                core::ptr::null(),
            )
        };
        if changed < 0 {
            return Err(anyhow!(
                "the kevent monitor's watch of bucket {bucket} (tag {tag}) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }
}

/// A private host kqueue, closed on exec and placed near the top of the
/// descriptor table so that the guest's own descriptors number as they
/// would without it.
fn private_kqueue() -> Option<i32> {
    // SAFETY: plain descriptor calls on descriptors this function owns.
    unsafe {
        let descriptor = libc::kqueue();
        if descriptor < 0 {
            return None;
        }
        let mut limit: libc::rlimit = core::mem::zeroed();
        let floor = if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0
            && limit.rlim_cur != libc::RLIM_INFINITY
            && limit.rlim_cur > 2 * PRIVATE_DESCRIPTOR_RESERVE
            && limit.rlim_cur <= i32::MAX as u64
        {
            (limit.rlim_cur - PRIVATE_DESCRIPTOR_RESERVE) as i32
        } else {
            descriptor
        };
        let moved = libc::fcntl(descriptor, libc::F_DUPFD_CLOEXEC, floor);
        if moved >= 0 {
            libc::close(descriptor);
            Some(moved)
        } else {
            libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC);
            Some(descriptor)
        }
    }
}

/// The out-of-line data area of a scan (`kec_data_out`, `kec_data_resid`):
/// filled down from its top for `KEVENT_FLAG_STACK_DATA`, up from its base
/// otherwise.
pub(crate) struct DataBuffer {
    base: u64,
    size: u64,
    pub(crate) remaining: u64,
    stack: bool,
}

impl DataBuffer {
    pub(crate) fn new(base: u64, size: u64, stack: bool) -> Self {
        Self {
            base,
            size: if base == 0 { 0 } else { size },
            remaining: if base == 0 { 0 } else { size },
            stack,
        }
    }

    /// The `data_out` of the next host scan.
    fn next(&self) -> u64 {
        match (self.base, self.stack) {
            (0, _) => 0,
            (base, true) => base,
            (base, false) => base + (self.size - self.remaining),
        }
    }
}

/// Knotes kept on one private host kqueue per bucket, made as the first
/// knote of a bucket attaches, each watched by the monitor.
pub(crate) struct HostBuckets {
    descriptors: Vec<Option<i32>>,
    knotes: HashMap<Key, Knote>,
    /// The owner's tag in the watch.
    tag: u32,
}

impl HostBuckets {
    /// Room for buckets 1 through `buckets`.
    pub(crate) fn new(buckets: u8, tag: u32) -> Self {
        Self {
            descriptors: vec![None; usize::from(buckets)],
            knotes: HashMap::new(),
            tag,
        }
    }

    fn descriptor(&self, bucket: u8) -> Option<i32> {
        self.descriptors[usize::from(bucket - 1)]
    }

    fn make(&mut self, bucket: u8, watch: &Watch) -> Result<Option<i32>> {
        if let Some(descriptor) = self.descriptor(bucket) {
            return Ok(Some(descriptor));
        }
        let Some(descriptor) = private_kqueue() else {
            return Ok(None);
        };
        watch.change(descriptor, self.tag, bucket, EV_ADD)?;
        self.descriptors[usize::from(bucket - 1)] = Some(descriptor);
        Ok(Some(descriptor))
    }

    /// Watch `bucket` again after its events were collected or its kevent
    /// request unbound.
    pub(crate) fn rearm(&self, bucket: u8, watch: &Watch) -> Result<()> {
        match self.descriptor(bucket) {
            Some(descriptor) => watch.change(descriptor, self.tag, bucket, EV_ENABLE),
            None => Ok(()),
        }
    }

    /// The knote a change names, if recorded.
    pub(crate) fn knote(&self, change: &Kevent) -> Option<Knote> {
        self.knotes.get(&change.key()).copied()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.knotes.is_empty()
    }

    /// Apply one change on a bucket's host kqueue, as `kevent_register`
    /// with `KEVENT_FLAG_ERROR_EVENTS`: its `EV_ERROR` result (an errno, or
    /// 0 for `EV_RECEIPT`), or none on a quiet success.
    fn register_on(descriptor: i32, change: &Kevent) -> Option<Kevent> {
        let input = super::timer::qos_change_to_host(change).encode();
        let mut output = [0u8; KEVENT_BYTES as usize];
        let returned = forward::bsd(
            super::number_of("kevent_qos"),
            &[
                descriptor as u64,
                input.as_ptr() as u64,
                1,
                output.as_mut_ptr() as u64,
                1,
                0,
                0,
                KEVENT_FLAG_IMMEDIATE | KEVENT_FLAG_ERROR_EVENTS,
            ],
        );
        if returned.carry {
            return Some(change.failed_with(returned.rax));
        }
        (returned.rax != 0).then(|| {
            let mut result = Kevent::decode(&output);
            super::timer::qos_event_to_guest(&mut result, Some(change));
            result
        })
    }

    /// `kevent_register`. A knote found is touched in its bucket; `EV_ADD`
    /// of a knote not found attaches it as `attach` says. The record of a
    /// knote the host dropped by itself (a closed descriptor, a delivered
    /// `EV_ONESHOT`) is found stale by the touch's ENOENT.
    pub(crate) fn register(
        &mut self,
        change: &Kevent,
        attach: Knote,
        watch: &Watch,
    ) -> Result<Option<Kevent>> {
        let key = change.key();
        let adding = change.flags & EV_ADD != 0 && change.flags & EV_DELETE == 0;
        let recorded = self.knotes.get(&key).copied();
        let attach_on = |buckets: &mut Self| -> Result<Option<Kevent>> {
            Ok(match buckets.make(attach.bucket, watch)? {
                Some(descriptor) => Self::register_on(descriptor, change),
                None => Some(change.failed_with(ENOMEM)),
            })
        };
        let (result, attached) = match recorded.and_then(|knote| {
            self.descriptor(knote.bucket)
                .map(|descriptor| (knote, descriptor))
        }) {
            Some((_, descriptor)) if adding => {
                let mut touch = *change;
                touch.flags &= !EV_ADD;
                match Self::register_on(descriptor, &touch) {
                    Some(result) if result.flags & EV_ERROR != 0 && result.data == ENOENT => {
                        (attach_on(self)?, true)
                    }
                    result => (
                        result.map(|mut result| {
                            result.flags |= EV_ADD;
                            result
                        }),
                        false,
                    ),
                }
            }
            Some((_, descriptor)) => (Self::register_on(descriptor, change), false),
            None if adding => (attach_on(self)?, true),
            // No knote of this name: the host kqueue of the bucket it would
            // attach in reports it (ENOENT, or a soft delete's success).
            None => (
                match self.descriptor(attach.bucket) {
                    Some(descriptor) => Self::register_on(descriptor, change),
                    None => Some(change.failed_with(ENOENT as u64)),
                },
                false,
            ),
        };
        let failed = result.as_ref().is_some_and(Kevent::failed);
        if !failed {
            if change.flags & EV_DELETE != 0 {
                self.knotes.remove(&key);
            } else if attached {
                self.knotes.insert(key, attach);
            }
        }
        Ok(result)
    }

    /// `kqueue_scan` of one bucket: up to `capacity` events at `list`, their
    /// out-of-line data in `data`, each carrying its knote's QoS (`kn_qos`).
    pub(crate) fn scan(
        &mut self,
        bucket: u8,
        list: u64,
        capacity: u64,
        data: &mut DataBuffer,
    ) -> Result<u64, u64> {
        let Some(descriptor) = self.descriptor(bucket) else {
            return Ok(0);
        };
        if capacity == 0 {
            return Ok(0);
        }
        let mut available = data.remaining;
        let flags = KEVENT_FLAG_IMMEDIATE
            | if data.stack {
                KEVENT_FLAG_STACK_DATA
            } else {
                0
            };
        let out = data.next();
        let returned = forward::bsd(
            super::number_of("kevent_qos"),
            &[
                descriptor as u64,
                0,
                0,
                list,
                capacity,
                out,
                if out == 0 {
                    0
                } else {
                    &mut available as *mut u64 as u64
                },
                flags,
            ],
        );
        if returned.carry {
            return Err(returned.rax);
        }
        if out != 0 {
            data.remaining = available;
        }
        let count = returned.rax;
        for index in 0..count {
            let Some(mut event) = Kevent::read(list, index) else {
                return Err(EFAULT);
            };
            super::timer::qos_event_to_guest(&mut event, None);
            let key = event.key();
            if let Some(knote) = self.knotes.get(&key) {
                event.qos = knote.qos;
            }
            if event.flags & EV_ONESHOT != 0 {
                self.knotes.remove(&key);
            }
            if !event.write(list, index) {
                return Err(EFAULT);
            }
        }
        Ok(count)
    }

    /// Close every bucket's host kqueue, which ends its watch.
    pub(crate) fn close(&mut self) {
        for descriptor in self.descriptors.iter_mut().filter_map(Option::take) {
            // SAFETY: a private descriptor this set owns.
            unsafe { libc::close(descriptor) };
        }
        self.knotes.clear();
    }
}

/// The change loop of `kevent_internal`: register `count` changes from
/// `changes` with `register`, writing each `EV_ERROR` result to `events`
/// while there is room and failing with the first error there is not. The
/// events written, or the errno.
pub(crate) fn register_all(
    changes: u64,
    count: i64,
    events: u64,
    capacity: i64,
    mut register: impl FnMut(&Kevent) -> Result<Option<Kevent>>,
) -> Result<Result<u64, u64>> {
    let mut outputs = 0;
    for index in 0..count.max(0) as u64 {
        let Some(change) = Kevent::read(changes, index) else {
            return Ok(Err(EFAULT));
        };
        let Some(result) = register(&change)? else {
            continue;
        };
        if (outputs as i64) < capacity {
            if !result.write(events, outputs) {
                return Ok(Err(EFAULT));
            }
            outputs += 1;
        } else if result.failed() {
            return Ok(Err(result.data as u64));
        }
    }
    Ok(Ok(outputs))
}

/// The process's workqueue kqueue (`p_fd.fd_wqkqueue`) and the monitor's
/// watch, which workloops share.
pub(crate) struct Kqworkq {
    pub(crate) watch: Watch,
    buckets: Mutex<HostBuckets>,
}

/// The workqueue kqueue's tag in the watch; workloops' are above it.
const KQWORKQ_TAG: u32 = 0;

/// The process's workqueue kqueue, once made (`kqworkq_alloc`).
#[derive(Default)]
pub(crate) struct Slot(Mutex<Option<Arc<Kqworkq>>>);

impl Slot {
    /// The workqueue kqueue, made with its monitor on first use; an errno
    /// when the host has no descriptor for it (ENOMEM, as
    /// `kqworkq_alloc`).
    pub(crate) fn get(&self, process: &Arc<Process>) -> Result<Arc<Kqworkq>, u64> {
        let mut slot = lock(&self.0);
        if let Some(kqueue) = slot.as_ref() {
            return Ok(kqueue.clone());
        }
        let watch = Watch(private_kqueue().ok_or(ENOMEM)?);
        let kqueue = Arc::new(Kqworkq {
            watch,
            buckets: Mutex::new(HostBuckets::new(BUCKETS, KQWORKQ_TAG)),
        });
        start_monitor(process.clone(), kqueue.clone());
        *slot = Some(kqueue.clone());
        Ok(kqueue)
    }

    pub(crate) fn existing(&self) -> Option<Arc<Kqworkq>> {
        lock(&self.0).clone()
    }

    pub(crate) fn hold_for_fork(&self) -> Option<SlotHeld<'_>> {
        crate::hosted::threads::try_lock(&self.0).map(SlotHeld)
    }
}

/// The workqueue kqueue's slot, held across a host `fork`.
pub(crate) struct SlotHeld<'a>(std::sync::MutexGuard<'a, Option<Arc<Kqworkq>>>);

impl SlotHeld<'_> {
    /// In the fork child: no workqueue kqueue, as `fdt_fork` copies none.
    /// The parent's is forgotten, never dropped, so that its host
    /// descriptor's number, free in the child, is never closed.
    pub(crate) fn child(mut self) {
        core::mem::forget(self.0.take());
    }
}

impl Kqworkq {
    /// Watch `bucket` again after its kevent request unbound.
    pub(crate) fn rearm(&self, bucket: u8) -> Result<()> {
        lock(&self.buckets).rearm(bucket, &self.watch)
    }

    /// `kevent_register` on the workqueue kqueue.
    fn register(&self, change: &Kevent) -> Result<Option<Kevent>> {
        lock(&self.buckets).register(change, attach_priority(change.qos), &self.watch)
    }

    /// Register a guest change list (`kevent_internal`'s loop).
    pub(crate) fn register_all(
        &self,
        changes: u64,
        count: i64,
        events: u64,
        capacity: i64,
    ) -> Result<Result<u64, u64>> {
        register_all(changes, count, events, capacity, |change| {
            self.register(change)
        })
    }

    /// `kqueue_scan` of one bucket into a kevent thread's stack
    /// (`KEVENT_FLAG_STACK_DATA | KEVENT_FLAG_IMMEDIATE`).
    pub(crate) fn scan(&self, bucket: u8, list: u64, data: &mut DataBuffer) -> Result<u64, u64> {
        lock(&self.buckets).scan(bucket, list, LIST_LEN, data)
    }
}

/// Validate the flags and data size of `kevent_qos` or `kevent_id`
/// (`kevent_get_data_size`): the flags the call keeps.
pub(crate) fn user_flags(flags: u64, data_out: u64, data_available: u64) -> Result<u64, u64> {
    if data_out != 0 && data_available != 0 && memory::read_u64(data_available).is_none() {
        return Err(EFAULT);
    }
    Ok(flags & KEVENT_FLAG_USER)
}

/// `kevent_qos(-1, changelist, nchanges, eventlist, nevents, data_out,
/// data_available, flags)` with `KEVENT_FLAG_WORKQ`: changes only, as
/// `kevent_get_kqwq` refuses a caller asking for events (only the kernel
/// collects a bucket's events, for the thread it binds).
pub(crate) fn kevent(process: &Arc<Process>, arguments: [u64; 8]) -> Result<Result<u64, u64>> {
    let [
        _,
        changes,
        nchanges,
        events,
        nevents,
        data_out,
        data_available,
        flags,
    ] = arguments;
    if flags & KEVENT_FLAG_USER & KEVENT_ID_FLAG_USER != 0 {
        return Ok(Err(EINVAL));
    }
    let flags = match user_flags(flags, data_out, data_available) {
        Ok(flags) => flags,
        Err(errno) => return Ok(Err(errno)),
    };
    let (nchanges, nevents) = (i64::from(nchanges as i32), i64::from(nevents as i32));
    if flags & KEVENT_FLAG_ERROR_EVENTS == 0 && nevents > 0 {
        return Ok(Err(EINVAL));
    }
    let kqueue = match process.kqworkq.get(process) {
        Ok(kqueue) => kqueue,
        Err(errno) => return Ok(Err(errno)),
    };
    kqueue.register_all(changes, nchanges, events, nevents)
}

/// Wait for watched buckets to become readable and tell their owners.
fn start_monitor(process: Arc<Process>, kqueue: Arc<Kqworkq>) {
    let builder = std::thread::Builder::new().name("stela-kevent".into());
    super::signal::host::without_signals(|| {
        builder.spawn(move || {
            const FIRED: usize = 16;
            let mut fired = [libc::kevent64_s {
                ident: 0,
                filter: 0,
                flags: 0,
                fflags: 0,
                data: 0,
                udata: 0,
                ext: [0; 2],
            }; FIRED];
            loop {
                // SAFETY: events out into a local array of its length.
                let count = unsafe {
                    libc::kevent64(
                        kqueue.watch.0,
                        core::ptr::null(),
                        0,
                        fired.as_mut_ptr(),
                        FIRED as i32,
                        0,
                        core::ptr::null(),
                    )
                };
                if count < 0 {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() == Some(EINTR) {
                        continue;
                    }
                    process
                        .runtime
                        .fail(anyhow!("the kevent monitor failed: {error}"));
                    return;
                }
                for event in &fired[..count as usize] {
                    let (tag, bucket) = ((event.udata >> TAG_SHIFT) as u32, event.udata as u8);
                    let delivered = if tag == KQWORKQ_TAG {
                        super::workqueue::request_kevent(&process, bucket)
                    } else {
                        super::kqworkloop::fired(&process, tag, bucket)
                    };
                    if let Err(error) = delivered {
                        process.runtime.fail(error);
                        return;
                    }
                }
            }
        })
    })
    .expect("the kevent monitor thread starts");
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVFILT_USER: i16 = -10;
    const NOTE_TRIGGER: u32 = 0x0100_0000;

    #[test]
    fn events_round_trip_the_kevent_qos_layout() {
        let event = Kevent {
            ident: 1,
            filter: EVFILT_USER,
            flags: EV_ADD | EV_CLEAR,
            qos: priority::EVENT_MANAGER_FLAG as i32,
            udata: 0xffff_ffff_ffff_fff8,
            fflags: NOTE_TRIGGER,
            xflags: 2,
            data: -3,
            ext: [4, 5, 6, 7],
        };
        let bytes = event.encode();
        assert_eq!(&bytes[8..12], &[0xf6, 0xff, 0x21, 0x00]);
        assert_eq!(Kevent::decode(&bytes), event);
        assert_eq!(event.key().udata, None);
    }

    #[test]
    fn knotes_attach_in_their_qos_bucket_or_the_managers() {
        assert_eq!(
            attach_priority(0),
            Knote {
                bucket: MANAGER_BUCKET,
                qos: priority::EVENT_MANAGER_FLAG as i32
            }
        );
        assert_eq!(
            attach_priority(priority::EVENT_MANAGER_FLAG as i32).bucket,
            MANAGER_BUCKET
        );
        let legacy =
            priority::from_thread_qos(priority::THREAD_QOS_LEGACY, 0, priority::OVERCOMMIT_FLAG);
        assert_eq!(
            attach_priority(legacy as i32),
            Knote {
                bucket: priority::THREAD_QOS_LEGACY,
                qos: legacy as i32
            }
        );
        // A relative priority out of range normalizes to 0.
        let user_initiated = priority::from_thread_qos(priority::THREAD_QOS_USER_INITIATED, 0, 0);
        let knote = attach_priority((user_initiated & !PRIORITY_MASK) as i32);
        assert_eq!(knote.bucket, priority::THREAD_QOS_USER_INITIATED);
        assert_eq!(knote.qos as u64, user_initiated);
    }

    #[test]
    fn host_buckets_run_host_filters_and_find_their_knotes() {
        let watch = Watch(private_kqueue().expect("a host kqueue"));
        let mut buckets = HostBuckets::new(BUCKETS, KQWORKQ_TAG);
        let manager = Kevent {
            ident: 1,
            filter: EVFILT_USER,
            flags: EV_ADD | EV_CLEAR,
            qos: priority::EVENT_MANAGER_FLAG as i32,
            udata: 0x55,
            ..Kevent::default()
        };
        let attach = attach_priority(manager.qos);
        assert_eq!(buckets.register(&manager, attach, &watch).unwrap(), None);
        // A trigger names the knote without a QoS and finds its bucket.
        let trigger = Kevent {
            ident: 1,
            filter: EVFILT_USER,
            fflags: NOTE_TRIGGER,
            udata: 0x55,
            ..Kevent::default()
        };
        let no_qos =
            attach_priority(priority::from_thread_qos(priority::THREAD_QOS_LEGACY, 0, 0) as i32);
        assert_eq!(buckets.register(&trigger, no_qos, &watch).unwrap(), None);
        let mut list = [0u8; (KEVENT_BYTES * LIST_LEN) as usize];
        let address = list.as_mut_ptr() as u64;
        let mut data = DataBuffer::new(0, 0, true);
        assert_eq!(
            buckets.scan(MANAGER_BUCKET, address, LIST_LEN, &mut data),
            Ok(1)
        );
        let event = Kevent::decode(&list[..KEVENT_BYTES as usize]);
        assert_eq!((event.ident, event.udata), (1, 0x55));
        assert_eq!(event.qos, priority::EVENT_MANAGER_FLAG as i32);
        assert_eq!(
            buckets.scan(MANAGER_BUCKET, address, LIST_LEN, &mut data),
            Ok(0)
        );
        assert!(buckets.descriptor(MANAGER_BUCKET).is_some());
        assert!(buckets.descriptor(priority::THREAD_QOS_LEGACY).is_none());
        // Deleting an unknown knote reports ENOENT as an error event.
        let missing = Kevent {
            ident: 2,
            filter: EVFILT_USER,
            flags: EV_DELETE,
            ..Kevent::default()
        };
        let result = buckets
            .register(&missing, attach, &watch)
            .unwrap()
            .expect("an error event");
        assert_eq!((result.flags & EV_ERROR, result.data), (EV_ERROR, ENOENT));
        buckets.close();
        // SAFETY: the test's own descriptor.
        unsafe { libc::close(watch.0) };
    }

    #[test]
    fn data_buffers_fill_down_on_the_stack_and_up_otherwise() {
        let mut stack = DataBuffer::new(0x1000, 0x100, true);
        stack.remaining = 0x80;
        assert_eq!(stack.next(), 0x1000);
        let mut heap = DataBuffer::new(0x1000, 0x100, false);
        heap.remaining = 0x80;
        assert_eq!(heap.next(), 0x1080);
        assert_eq!(DataBuffer::new(0, 0x100, false).next(), 0);
    }
}
