//! Pipeline creations deferred outside the service's turn
//! ([`crate::metal::deferred`], `service/shared.rs`).
//!
//! While a call may defer, no pipeline is created in its turn: even found in
//! a cache, a creation serializes and hashes each stage's NIR and loads the
//! shaders, which took a large shader 45-55 ms. The call fails with
//! `DEFERRED` and leaves a job that creates the pipeline from a copy of its
//! NIR, through the pipeline store's cache while that grows, else the full
//! store's and then the backend's own: NIR to machine code, when no cache
//! holds it, runs in the job too. The job keeps the pipeline, and the call's
//! next run takes it with no driver work.
//!
//! A creation's key holds its stages by their NIR handles, which name the
//! same shaders while no NIR is released ([`nir_releases`]): a made pipeline
//! whose key outlived a release may be another shader's, so it is destroyed
//! and its call creates in its turn. So does a key whose job failed, so no
//! call defers forever. Made pipelines no call takes are destroyed, the
//! oldest once [`KEPT`] wait.
//!
//! Pipeline creation is thread-safe and the caches are internally
//! synchronized (none is created `EXTERNALLY_SYNCHRONIZED`), so a job needs
//! no turn; the queue and command pools stay the turn's. The backend holds
//! the job lock while it destroys the device, so no job runs on a destroyed
//! one, and later jobs see it gone.
use super::{
    NativeBackend, failure,
    kept::{Kept, Taken},
    objects, raw,
};
use crate::metal::{
    compiler::{DEFERRED, clone_nir, free_nir_copy, nir_releases},
    deferred::{Done, Job, JobLock, Made, Owner},
    error::{Error, Result},
    vulkan::object::{ComputePipelineInfo, GraphicsPipelineInfo, PipelineCache, PipelineSource},
};
use alloc::{boxed::Box, collections::BTreeSet, format, sync::Arc, vec::Vec};
use ash::vk;
use core::sync::atomic::{AtomicBool, Ordering};
use stela_crypto::{Sha256, digest::Digest};

/// Keys a backend remembers as failed; past this it forgets them all, which
/// costs at most one more job each.
const REMEMBERED: usize = 1 << 14;

/// Pipelines made for calls that have not run again; past this the oldest
/// is destroyed, and its call, run again, defers once more.
const KEPT: usize = 32;

#[derive(Default)]
pub(super) struct Deferral {
    /// Set while the call served now may defer.
    deferring: Option<JobLock>,
    /// The lock of the jobs this backend made.
    jobs: Option<JobLock>,
    job: Option<Job>,
    /// Set once the device is destroyed.
    gone: Arc<AtomicBool>,
    /// The cache jobs fill while the store's does not grow.
    own: vk::PipelineCache,
    /// Keys whose calls create in their turns.
    failed: BTreeSet<[u8; 32]>,
    /// Pipelines jobs made, under [`nir_releases`] as their keys were taken.
    made: Kept<vk::Pipeline>,
}

impl Default for Kept<vk::Pipeline> {
    fn default() -> Self {
        Self::new(KEPT)
    }
}

/// What a pipeline job made, for the backend whose `gone` it holds: the
/// pipeline, and whether the growing store's cache held it. Dropped
/// unadopted, it destroys the pipeline unless the device is gone.
struct Ran {
    pipeline: Option<vk::Pipeline>,
    into_store: bool,
    hit: bool,
    releases: u64,
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
        self.job = None;
    }

    pub(super) fn stop(&mut self) {
        self.deferring = None;
    }

    pub(super) fn deferred(&self) -> bool {
        self.job.is_some()
    }

    pub(super) fn take(&mut self) -> Option<Job> {
        self.job.take()
    }

    /// Whether the call served now may defer.
    pub(super) fn deferring(&self) -> bool {
        self.deferring.is_some()
    }

    /// Leaves `job` for the call served now, which then fails with
    /// `DEFERRED`; false, leaving nothing, unless the call may defer and has
    /// left no job yet.
    pub(super) fn defer(&mut self, job: Job) -> bool {
        let Some(lock) = &self.deferring else {
            return false;
        };
        if self.job.is_some() {
            return false;
        }
        lock.lock.set_deferred(true);
        self.job = Some(job);
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
        for pipeline in self.made.drain() {
            // SAFETY: the caller's; no call took the pipeline.
            unsafe { device.destroy_pipeline(pipeline, None) };
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
        let releases = nir_releases();
        match self.deferral.made.take(&key, releases) {
            Taken::Fresh(pipeline) => return Some(Ok(pipeline)),
            Taken::Stale(pipeline) => {
                // A release since may have freed a stage the key names,
                // whose handle another shader may hold now.
                // SAFETY: the job's pipeline, which nothing uses.
                unsafe { self.device.destroy_pipeline(pipeline, None) };
                Deferral::remember(&mut self.deferral.failed, key);
            }
            Taken::Missing => {}
        }
        let lock = self.deferral.deferring.clone()?;
        if self.deferral.failed.contains(&key) {
            return None;
        }
        // Deferred already, the call runs again: nothing it makes stays.
        if self.deferral.job.is_some() {
            return Some(Err(DEFERRED));
        }
        let job = self.pipeline_job(wanted, key, releases)?;
        self.deferral.job = Some(job);
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
        if let Some(oldest) = self.deferral.made.keep(done.key, ran.releases, pipeline) {
            // SAFETY: the job's pipeline, which no call took.
            unsafe { self.device.destroy_pipeline(oldest, None) };
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

    /// A job that creates `wanted` from copies of its NIR and keeps the
    /// pipeline, or `None` when its NIR cannot be copied or no cache can be
    /// made. `releases` is [`nir_releases`] as `key` was taken.
    fn pipeline_job(&mut self, wanted: Wanted<'_>, key: [u8; 32], releases: u64) -> Option<Job> {
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
        let owned = match wanted {
            Wanted::Compute(info) => Owned::Compute(ComputePipelineInfo {
                code: clone_nir(info.code)?,
                source,
                ..*info
            }),
            Wanted::Graphics(info) => {
                let mut stages = Vec::with_capacity(info.stages.len());
                for &(stage, code) in &info.stages {
                    let Some(copy) = clone_nir(code) else {
                        stages.into_iter().for_each(|(_, code)| free_nir_copy(code));
                        return None;
                    };
                    stages.push((stage, copy));
                }
                Owned::Graphics(Box::new(GraphicsPipelineInfo {
                    stages,
                    source,
                    ..info.clone()
                }))
            }
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
                releases,
                gone,
                device,
            }) as Made
        }))
    }
}

/// A job's copy of a creation, holding copies of its NIR.
enum Owned {
    Compute(ComputePipelineInfo),
    Graphics(Box<GraphicsPipelineInfo>),
}

// SAFETY: its NIR copies are the job's alone, and the rest is plain values.
unsafe impl Send for Owned {}

impl Owned {
    fn wanted(&self) -> Wanted<'_> {
        match self {
            Self::Compute(info) => Wanted::Compute(info),
            Self::Graphics(info) => Wanted::Graphics(info),
        }
    }
}

/// A job dropped unrun frees its copies too.
impl Drop for Owned {
    fn drop(&mut self) {
        match self {
            Self::Compute(info) => free_nir_copy(info.code),
            Self::Graphics(info) => info
                .stages
                .iter()
                .for_each(|&(_, code)| free_nir_copy(code)),
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
