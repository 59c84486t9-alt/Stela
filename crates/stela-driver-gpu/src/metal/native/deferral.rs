//! Pipeline creations deferred outside the service's turn
//! ([`crate::metal::deferred`], `service/shared.rs`).
//!
//! While a call may defer, no pipeline is created in its turn: even found in
//! a cache, a creation serializes and hashes each stage's NIR and loads the
//! shaders, which took a large shader 45-55 ms. The call fails with
//! `DEFERRED` and leaves a job that creates the pipeline from its stages'
//! NIR, through the pipeline store's cache while that grows, else the full
//! store's and then the backend's own: NIR to machine code, when no cache
//! holds it, runs in the job too. The job keeps the pipeline, and the call's
//! next run takes it with no driver work.
//!
//! The job shares the compiler's NIR rather than copying it in the turn
//! (copies took 15-35 ms): it pins each stage ([`pin_nir`]), which the
//! driver only reads, until the call takes the pipeline. So a creation's
//! key, which holds its stages by their NIR handles, names the same shaders
//! for as long as its pipeline is kept: a NIR release elsewhere no longer
//! voids it. A key whose job failed creates in its turn, so no call defers
//! forever. Made pipelines no call takes are destroyed, the oldest once
//! [`KEPT`] wait.
//!
//! Pipeline creation is thread-safe and the caches are internally
//! synchronized (none is created `EXTERNALLY_SYNCHRONIZED`), so a job needs
//! no turn; the queue and command pools stay the turn's. The backend holds
//! the job lock while it destroys the device, so no job runs on a destroyed
//! one, and later jobs see it gone.
use super::{NativeBackend, failure, objects, raw};
use crate::metal::{
    compiler::{DEFERRED, PinnedNir, pin_nir},
    deferred::{
        Done, Job, JobLock, Made, Owner,
        kept::{Kept, Taken},
    },
    error::{Error, Result},
    vulkan::object::{ComputePipelineInfo, GraphicsPipelineInfo, PipelineCache, PipelineSource},
};
use alloc::{boxed::Box, collections::BTreeSet, format, sync::Arc, vec::Vec};
use ash::vk;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use stela_crypto::{Sha256, digest::Digest};

/// Pipeline work in the service's turns since the last [`take_turn_work`],
/// of one kind: how many, and the ticks of all and of the longest.
pub(super) struct Counted {
    count: AtomicU64,
    ticks: AtomicU64,
    longest: AtomicU64,
}

impl Counted {
    const fn new() -> Self {
        Self {
            count: AtomicU64::new(0),
            ticks: AtomicU64::new(0),
            longest: AtomicU64::new(0),
        }
    }

    pub(super) fn note(&self, ticks: u64) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.ticks.fetch_add(ticks, Ordering::Relaxed);
        self.longest.fetch_max(ticks, Ordering::Relaxed);
    }

    fn take(&self) -> [u64; 3] {
        [&self.count, &self.ticks, &self.longest].map(|counter| counter.swap(0, Ordering::Relaxed))
    }
}

/// Pipeline jobs a turn left, most of whose time is copying each stage's
/// NIR for the job.
static LEFT: Counted = Counted::new();
/// Pipelines a turn created itself: none deferred, as a call that may not
/// defer, a full store's lookup or a key whose job failed creates.
pub(super) static CREATED: Counted = Counted::new();

/// Since the last call, cleared: the pipeline jobs turns left, then the
/// pipelines turns created, each as count, ticks in all and longest ticks.
pub fn take_turn_work() -> [[u64; 3]; 2] {
    [LEFT.take(), CREATED.take()]
}

/// Keys a backend remembers as failed; past this it forgets them all, which
/// costs at most one more job each.
const REMEMBERED: usize = 1 << 14;

/// Pipelines made for calls that have not run again; past this the oldest
/// is destroyed, and its call, run again, defers once more.
const KEPT: usize = 32;

/// Jobs one call leaves at most, well under [`KEPT`]: a commit that misses
/// more pipelines runs again for the rest.
const LEFT_PER_CALL: usize = 8;

#[derive(Default)]
pub(super) struct Deferral {
    /// Set while the call served now may defer.
    deferring: Option<JobLock>,
    /// The lock of the jobs this backend made.
    jobs: Option<JobLock>,
    /// The jobs the call served now left, at most [`LEFT_PER_CALL`].
    left: Vec<Job>,
    /// Set once the device is destroyed.
    gone: Arc<AtomicBool>,
    /// The cache jobs fill while the store's does not grow.
    own: vk::PipelineCache,
    /// Keys whose calls create in their turns.
    failed: BTreeSet<[u8; 32]>,
    /// Pipelines jobs made, with their stages pinned.
    made: Kept<MadePipeline>,
}

impl Default for Kept<MadePipeline> {
    fn default() -> Self {
        Self::new(KEPT)
    }
}

/// A pipeline a job made, and the pins that keep its key's NIR handles
/// naming its stages until a call takes it.
struct MadePipeline {
    pipeline: vk::Pipeline,
    _pins: Vec<PinnedNir>,
}

/// Kept pipelines are made under one generation: their pins, not a count
/// of NIR releases, keep their keys true.
const GENERATION: u64 = 0;

/// What a pipeline job made, for the backend whose `gone` it holds: the
/// pipeline, and whether the growing store's cache held it. Dropped
/// unadopted, it destroys the pipeline unless the device is gone.
struct Ran {
    pipeline: Option<vk::Pipeline>,
    into_store: bool,
    hit: bool,
    pins: Vec<PinnedNir>,
    gone: Arc<AtomicBool>,
    device: ash::Device,
}

impl Drop for Ran {
    fn drop(&mut self) {
        if let Some(pipeline) = self.pipeline.take()
            && !self.gone.load(Ordering::Acquire)
        {
            // SAFETY: the job's pipeline, which nothing uses.
            unsafe { self.device.destroy_pipeline(pipeline, None) };
        }
    }
}

/// A pipeline creation a call asks for.
#[derive(Clone, Copy)]
pub(super) enum Wanted<'a> {
    Compute(&'a ComputePipelineInfo),
    Graphics(&'a GraphicsPipelineInfo),
}

impl Wanted<'_> {
    fn source(self) -> PipelineSource {
        match self {
            Self::Compute(info) => info.source,
            Self::Graphics(info) => info.source,
        }
    }

    /// The digest of everything the creation reads: its state and its
    /// stages' NIR, by the compiler's handles, which stay while its cache
    /// keeps them.
    fn key(self) -> [u8; 32] {
        let text = match self {
            Self::Compute(info) => format!("compute {info:?}"),
            Self::Graphics(info) => format!("graphics {info:?}"),
        };
        Sha256::digest(text.as_bytes()).into()
    }
}

impl Deferral {
    pub(super) fn set(&mut self, deferring: Option<&JobLock>) {
        if let (Some(lock), None) = (deferring, &self.jobs) {
            self.jobs = Some(lock.clone());
        }
        self.deferring = deferring.cloned();
        self.left.clear();
    }

    pub(super) fn stop(&mut self) {
        if let Some(lock) = self.deferring.take() {
            lock.lock.set_may_defer(false);
        }
    }

    /// Whether the call served now runs again: it left a job, or a host
    /// call of it was withdrawn while it could
    /// ([`CompileLock::defer_for_wait`](crate::metal::compiler::CompileLock::defer_for_wait)).
    pub(super) fn deferred(&self) -> bool {
        !self.left.is_empty()
            || self
                .deferring
                .as_ref()
                .is_some_and(|lock| lock.lock.waited())
    }

    /// The oldest job the call left.
    pub(super) fn take(&mut self) -> Option<Job> {
        (!self.left.is_empty()).then(|| self.left.remove(0))
    }

    /// Whether the call served now may defer.
    pub(super) fn deferring(&self) -> bool {
        self.deferring.is_some()
    }

    /// Leaves `job` for the call served now, which then fails with
    /// `DEFERRED`; false, leaving nothing, unless the call may defer and has
    /// room for another job.
    pub(super) fn defer(&mut self, job: Job) -> bool {
        let Some(lock) = &self.deferring else {
            return false;
        };
        if self.left.len() >= LEFT_PER_CALL {
            return false;
        }
        lock.lock.set_deferred(true);
        self.left.push(job);
        true
    }

    /// The flag set once the device is destroyed, which a job checks before
    /// it uses the device.
    pub(super) fn gone(&self) -> Arc<AtomicBool> {
        self.gone.clone()
    }

    /// Waits out a running job and keeps later ones from the device, which
    /// is about to be destroyed.
    pub(super) fn retire(&self) {
        let held = self.jobs.as_ref().map(|jobs| jobs.lock.hold(jobs.relax));
        self.gone.store(true, Ordering::Release);
        drop(held);
    }

    /// # Safety
    /// The device is idle and no job runs ([`Self::retire`]).
    pub(super) unsafe fn destroy(&mut self, device: &ash::Device) {
        for made in self.made.drain() {
            // SAFETY: the caller's; no call took the pipeline.
            unsafe { device.destroy_pipeline(made.pipeline, None) };
        }
        if self.own != vk::PipelineCache::null() {
            // SAFETY: the caller's.
            unsafe { device.destroy_pipeline_cache(self.own, None) };
            self.own = vk::PipelineCache::null();
        }
    }

    fn remember(set: &mut BTreeSet<[u8; 32]>, key: [u8; 32]) {
        if set.len() >= REMEMBERED {
            set.clear();
        }
        set.insert(key);
    }
}

impl NativeBackend {
    /// A compiled creation: the pipeline a job made for it, else, while the
    /// call may defer, `DEFERRED` with the job that makes it left. `None`
    /// creates in the call as without deferral.
    pub(super) fn deferred_creation(&mut self, wanted: Wanted<'_>) -> Option<Result<vk::Pipeline>> {
        if wanted.source() != PipelineSource::Compiled {
            return None;
        }
        let key = wanted.key();
        // The pins drop here: the key is spent.
        if let Taken::Fresh(made) | Taken::Stale(made) = self.deferral.made.take(&key, GENERATION) {
            return Some(Ok(made.pipeline));
        }
        let lock = self.deferral.deferring.clone()?;
        if self.deferral.failed.contains(&key) {
            return None;
        }
        // A call that goes on past a deferral, as a commit does to find
        // every pipeline it misses, leaves a job for each up to a bound; it
        // runs again, so past the bound nothing it makes would stay.
        if self.deferral.left.len() >= LEFT_PER_CALL
            || self.deferral.left.iter().any(|left| left.key == key)
        {
            return Some(Err(DEFERRED));
        }
        let started = (self.ticks)();
        let job = self.pipeline_job(wanted, key);
        LEFT.note((self.ticks)().wrapping_sub(started));
        self.deferral.left.push(job?);
        lock.lock.set_deferred(true);
        Some(Err(DEFERRED))
    }

    /// Keeps what a pipeline job made for its call's next run.
    pub(super) fn adopt_pipeline(&mut self, done: Done) {
        let Ok(mut ran) = done.made.downcast::<Ran>() else {
            return;
        };
        // A job of a device this backend replaced.
        if !Arc::ptr_eq(&ran.gone, &self.deferral.gone) {
            return;
        }
        let Some(pipeline) = ran.pipeline.take() else {
            Deferral::remember(&mut self.deferral.failed, done.key);
            return;
        };
        if ran.into_store {
            self.store.created(&self.device, ran.hit);
        }
        let made = MadePipeline {
            pipeline,
            _pins: core::mem::take(&mut ran.pins),
        };
        if let Some(oldest) = self.deferral.made.keep(done.key, GENERATION, made) {
            // SAFETY: the job's pipeline, which no call took.
            unsafe { self.device.destroy_pipeline(oldest.pipeline, None) };
        }
    }

    /// The cache jobs fill while the store's does not grow, made at first use.
    fn own_cache(&mut self) -> Option<vk::PipelineCache> {
        if self.deferral.own == vk::PipelineCache::null() {
            let info = vk::PipelineCacheCreateInfo::default();
            // SAFETY: the create info outlives the call.
            self.deferral.own = unsafe { self.device.create_pipeline_cache(&info, None) }.ok()?;
        }
        Some(self.deferral.own)
    }

    /// A job that creates `wanted` from its stages' NIR, pinned, and keeps
    /// the pipeline, or `None` when no cache can be made.
    fn pipeline_job(&mut self, wanted: Wanted<'_>, key: [u8; 32]) -> Option<Job> {
        // A growing store's cache takes what the job compiles; a full one is
        // looked in, and the backend's own takes what it lacks.
        let (first, into_store, then) = match self.store.cache() {
            Some((store, true)) => (
                PipelineSource::Cached(PipelineCache(raw(store))),
                true,
                None,
            ),
            Some((store, false)) => (
                PipelineSource::Archived(PipelineCache(raw(store))),
                false,
                Some(self.own_cache()?),
            ),
            None => (
                PipelineSource::Cached(PipelineCache(raw(self.own_cache()?))),
                false,
                None,
            ),
        };
        let source = first;
        let (owned, pins) = match wanted {
            Wanted::Compute(info) => (
                Owned::Compute(ComputePipelineInfo { source, ..*info }),
                alloc::vec![pin_nir(info.code)],
            ),
            Wanted::Graphics(info) => (
                Owned::Graphics(Box::new(GraphicsPipelineInfo {
                    source,
                    ..info.clone()
                })),
                info.stages.iter().map(|&(_, code)| pin_nir(code)).collect(),
            ),
        };
        let device = self.device.clone();
        let layout = self.layout;
        let gone = self.deferral.gone.clone();
        Some(Job::new(key, Owner::Backend, move || {
            let wanted = owned.wanted();
            let mut feedback = vk::PipelineCreationFeedback::default();
            let mut hit = false;
            let pipeline = (!gone.load(Ordering::Acquire))
                .then(|| {
                    let created = create(&device, layout, wanted, source, &mut feedback);
                    let created = match (created, then) {
                        (Err(Error::NotArchived), Some(own)) => {
                            let own = PipelineSource::Cached(PipelineCache(raw(own)));
                            create(&device, layout, wanted, own, &mut feedback)
                        }
                        (created, _) => created,
                    };
                    hit = feedback.flags.contains(
                        vk::PipelineCreationFeedbackFlags::VALID
                            | vk::PipelineCreationFeedbackFlags::APPLICATION_PIPELINE_CACHE_HIT,
                    );
                    super::pipeline_store::note_lookup(hit, feedback.duration);
                    created.ok()
                })
                .flatten();
            drop(owned);
            Box::new(Ran {
                pipeline,
                into_store,
                hit,
                pins,
                gone,
                device,
            }) as Made
        }))
    }
}

/// A job's copy of a creation, naming its stages' pinned NIR.
enum Owned {
    Compute(ComputePipelineInfo),
    Graphics(Box<GraphicsPipelineInfo>),
}

// SAFETY: plain values but the NIR handles, whose shaders the job's pins
// keep alive and which the driver and every holder only read.
unsafe impl Send for Owned {}

impl Owned {
    fn wanted(&self) -> Wanted<'_> {
        match self {
            Self::Compute(info) => Wanted::Compute(info),
            Self::Graphics(info) => Wanted::Graphics(info),
        }
    }
}

/// Creates `wanted` with `source`'s flags through `cache`.
fn create(
    device: &ash::Device,
    layout: vk::PipelineLayout,
    wanted: Wanted<'_>,
    source: PipelineSource,
    feedback: &mut vk::PipelineCreationFeedback,
) -> Result<vk::Pipeline> {
    let cache = match source {
        PipelineSource::Archived(cache) | PipelineSource::Cached(cache) => super::handle(cache.0),
        PipelineSource::Compiled => vk::PipelineCache::null(),
    };
    let mut chained =
        vk::PipelineCreationFeedbackCreateInfo::default().pipeline_creation_feedback(feedback);
    match wanted {
        Wanted::Compute(info) => {
            let info = ComputePipelineInfo { source, ..*info };
            objects::compute_pipeline(&info, layout, |create| {
                let create = (*create).push_next(&mut chained);
                // SAFETY: the create info, its chain and the NIR outlive the
                // call; the cache is internally synchronized.
                unsafe { device.create_compute_pipelines(cache, &[create], None) }
                    .map(|pipelines| pipelines[0])
                    .map_err(|(_, error)| failure(error))
            })
        }
        Wanted::Graphics(info) => {
            let info = GraphicsPipelineInfo {
                source,
                ..info.clone()
            };
            objects::graphics_pipeline(&info, layout, |create| {
                let create = (*create).push_next(&mut chained);
                // SAFETY: as above.
                unsafe { device.create_graphics_pipelines(cache, &[create], None) }
                    .map(|pipelines| pipelines[0])
                    .map_err(|(_, error)| failure(error))
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Counted;

    #[test]
    fn counted_work_is_taken_once_with_its_longest() {
        let counted = Counted::new();
        counted.note(30);
        counted.note(70);
        assert_eq!(counted.take(), [2, 100, 70]);
        assert_eq!(counted.take(), [0, 0, 0]);
    }
}
