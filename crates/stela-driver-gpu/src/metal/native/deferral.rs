//! Pipeline creations deferred outside the service's turn
//! ([`crate::metal::deferred`], `service/shared.rs`).
//!
//! While a call may defer, a creation that would compile first looks in the
//! pipeline store's cache, then in this backend's own, without compiling
//! (`VK_PIPELINE_CREATE_FAIL_ON_PIPELINE_COMPILE_REQUIRED_BIT`): found, it is
//! created in the turn. Missing, the call fails with `DEFERRED` and leaves a
//! job that creates it from a copy of its NIR into the store's cache while
//! that grows, else into the backend's own, then destroys it: NIR to machine
//! code runs in the job. The call's next run finds it in that cache.
//!
//! Pipeline creation is thread-safe and the caches are internally
//! synchronized (none is created `EXTERNALLY_SYNCHRONIZED`), so a job needs
//! no turn; the queue and command pools stay the turn's. A key whose job ran
//! or failed and that misses again compiles in its call, so no call defers
//! forever. The backend holds the job lock while it destroys the device, so
//! no job runs on a destroyed one, and later jobs see it gone.
use super::{NativeBackend, failure, objects, raw};
use crate::metal::{
    compiler::{DEFERRED, clone_nir, free_nir_copy},
    deferred::{Done, Job, JobLock, Made, Owner},
    error::{Error, Result},
    vulkan::object::{ComputePipelineInfo, GraphicsPipelineInfo, PipelineCache, PipelineSource},
};
use alloc::{boxed::Box, collections::BTreeSet, format, sync::Arc, vec::Vec};
use ash::vk;
use core::sync::atomic::{AtomicBool, Ordering};
use stela_crypto::{Sha256, digest::Digest};

/// Keys a backend remembers as ran or failed; past this it forgets them all,
/// which costs at most one more job each.
const REMEMBERED: usize = 1 << 14;

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
    ran: BTreeSet<[u8; 32]>,
    failed: BTreeSet<[u8; 32]>,
    /// A pipeline its job made was missed since, which was logged.
    missed: bool,
}

/// What a pipeline job made: whether it created the pipeline, into the
/// store's cache or not, for the backend whose `gone` it holds.
struct Ran {
    created: bool,
    into_store: bool,
    gone: Arc<AtomicBool>,
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
    /// While the call may defer, a creation that would compile: the
    /// pipeline when a cache holds it, else `DEFERRED` with the job left.
    /// `None` creates in the call as without deferral.
    pub(super) fn deferred_creation(&mut self, wanted: Wanted<'_>) -> Option<Result<vk::Pipeline>> {
        let lock = self.deferral.deferring.clone()?;
        if wanted.source() != PipelineSource::Compiled {
            return None;
        }
        let store = self.store.cache();
        let own = self.deferral.own;
        let caches = [
            store.map(|(cache, _)| cache),
            (own != vk::PipelineCache::null()).then_some(own),
        ];
        for cache in caches.into_iter().flatten() {
            match self
                .create_from_cache(wanted, PipelineSource::Archived(PipelineCache(raw(cache))))
            {
                Err(Error::NotArchived) => {}
                Ok(pipeline) => {
                    if let Some((store, true)) = store
                        && store == cache
                    {
                        self.store.created(&self.device, true);
                    }
                    return Some(Ok(pipeline));
                }
                Err(error) => return Some(Err(error)),
            }
        }
        let key = wanted.key();
        if self.deferral.ran.contains(&key) && !core::mem::replace(&mut self.deferral.missed, true)
        {
            (self.store.log())(
                "a pipeline a deferred job created is not in its cache; such pipelines compile \
                 in their calls",
            );
        }
        if self.deferral.ran.contains(&key) || self.deferral.failed.contains(&key) {
            return None;
        }
        let (target, into_store) = match store {
            Some((cache, true)) => (cache, true),
            _ => (self.own_cache()?, false),
        };
        let job = self.pipeline_job(wanted, key, target, into_store)?;
        self.deferral.job = Some(job);
        lock.lock.set_deferred(true);
        Some(Err(DEFERRED))
    }

    /// Keeps what a pipeline job made.
    pub(super) fn adopt_pipeline(&mut self, done: Done) {
        let Ok(ran) = done.made.downcast::<Ran>() else {
            return;
        };
        // A job of a device this backend replaced.
        if !Arc::ptr_eq(&ran.gone, &self.deferral.gone) {
            return;
        }
        if ran.created {
            Deferral::remember(&mut self.deferral.ran, done.key);
            if ran.into_store {
                self.store.created(&self.device, false);
            }
        } else {
            Deferral::remember(&mut self.deferral.failed, done.key);
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

    /// Creates `wanted` from `source` in the turn.
    fn create_from_cache(
        &mut self,
        wanted: Wanted<'_>,
        source: PipelineSource,
    ) -> Result<vk::Pipeline> {
        let cache = match source {
            PipelineSource::Archived(cache) | PipelineSource::Cached(cache) => {
                super::handle(cache.0)
            }
            PipelineSource::Compiled => vk::PipelineCache::null(),
        };
        create(&self.device, self.layout, cache, wanted, source)
    }

    /// A job that creates `wanted` into `target` from copies of its NIR, or
    /// `None` when its NIR cannot be copied.
    fn pipeline_job(
        &self,
        wanted: Wanted<'_>,
        key: [u8; 32],
        target: vk::PipelineCache,
        into_store: bool,
    ) -> Option<Job> {
        let source = PipelineSource::Cached(PipelineCache(raw(target)));
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
            let created = !gone.load(Ordering::Acquire)
                && create(&device, layout, target, wanted, source)
                    // SAFETY: the job's own pipeline, which nothing uses.
                    .map(|pipeline| unsafe { device.destroy_pipeline(pipeline, None) })
                    .is_ok();
            drop(owned);
            Box::new(Ran {
                created,
                into_store,
                gone,
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
    cache: vk::PipelineCache,
    wanted: Wanted<'_>,
    source: PipelineSource,
) -> Result<vk::Pipeline> {
    match wanted {
        Wanted::Compute(info) => {
            let info = ComputePipelineInfo { source, ..*info };
            objects::compute_pipeline(&info, layout, |create| {
                // SAFETY: the create info, its chain and the NIR outlive the
                // call; the cache is internally synchronized.
                unsafe { device.create_compute_pipelines(cache, &[*create], None) }
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
                // SAFETY: as above.
                unsafe { device.create_graphics_pipelines(cache, &[*create], None) }
                    .map(|pipelines| pipelines[0])
                    .map_err(|(_, error)| failure(error))
            })
        }
    }
}
