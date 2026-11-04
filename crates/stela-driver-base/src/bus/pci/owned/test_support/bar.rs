//! Born-register hosted RAM; never relabels configuration or creates a grant.
use super::*;
use core::ops::Deref;

struct State {
    owner: MappingOwner<Arc<Ram>>,
    resource: Option<Resource>,
    retention: Option<MappingRetention<Arc<Ram>>>,
    counters: Arc<Counters>,
}
/// External affine model controller, never kept in Resource or MappingPlatform.
/// Abandonment closes admission and parks the SAME original boxed actor.
pub struct BarFixture {
    state: Option<Box<State>>,
}
impl Drop for BarFixture {
    fn drop(&mut self) {
        if let Some(mut state) = self.state.take() {
            state.owner.abandon_admission();
            core::mem::forget(state);
        }
    }
}
impl Deref for BarFixture {
    type Target = Counters;
    fn deref(&self) -> &Counters {
        &self.state.as_ref().expect("live BAR fixture").counters
    }
}
impl BarFixture {
    /// Retention-only observation of the SAME original fixture counter group.
    pub fn counters(&self) -> Arc<Counters> {
        self.state
            .as_ref()
            .expect("live BAR fixture")
            .counters
            .clone()
    }
    /// # Safety
    /// Every model producer, raw pointer, CPU/callback tail and non-MMIO alias
    /// stopped and cannot restart. Actual mapper completion is still required.
    pub unsafe fn retire(mut self, mapping: Mapping) -> Result<(), BarRetireFailure> {
        self.state
            .as_mut()
            .expect("live BAR fixture")
            .owner
            .abandon_admission();
        let state = self.state.as_ref().expect("live BAR fixture");
        let check = (|| {
            if state.owner.uses() != 1 {
                return Err(MappingError::Busy);
            }
            state
                .retention
                .as_ref()
                .ok_or(MappingError::Retired)?
                .check_context()?;
            if !mapping.retains_resource(state.resource.as_ref().ok_or(MappingError::Retired)?)? {
                return Err(MappingError::InvalidPlatformReply);
            }
            Ok(())
        })();
        if let Err(error) = check {
            return Err(BarRetireFailure {
                error,
                fixture: self,
                remaining: Remaining::Unqualified(mapping),
            });
        }
        // SAFETY: caller supplies actual model exclusion; same-resource
        // qualification above is retained with this SAME mapping through retry.
        unsafe { self.retire_bound(mapping) }
    }
    unsafe fn retire_bound(mut self, mut mapping: Mapping) -> Result<(), BarRetireFailure> {
        self.state
            .as_mut()
            .expect("live BAR fixture")
            .owner
            .abandon_admission();
        // SAFETY: original caller's drain plus the actual privately retained
        // qualified mapping. Busy/uncertain removal keeps this SAME token.
        if let Err(error) = unsafe { mapping.retire() } {
            return Err(BarRetireFailure {
                error,
                fixture: self,
                remaining: Remaining::Qualified(mapping),
            });
        }
        drop(mapping);
        // SAFETY: the SAME actual map acknowledged unmap; original caller
        // excludes raw/callback tails, not just counted MappingViews.
        unsafe { self.finish_unmapped() }
    }
    /// # Safety
    /// This exact original mapping already acknowledged unmap and every raw,
    /// callback and non-MMIO alias is retired. Counts are negative vetoes only.
    pub unsafe fn finish_unmapped(mut self) -> Result<(), BarRetireFailure> {
        let state = self.state.as_mut().expect("live BAR fixture");
        state.owner.abandon_admission();
        if state.owner.uses() != 0 {
            return Err(BarRetireFailure {
                error: MappingError::Busy,
                fixture: self,
                remaining: Remaining::Unmapped,
            });
        }
        if let Some(retention) = &state.retention
            && let Err(error) = retention.check_context()
        {
            return Err(BarRetireFailure {
                error,
                fixture: self,
                remaining: Remaining::Unmapped,
            });
        }
        drop(state.resource.take());
        drop(state.retention.take());
        // SAFETY: original model drain and real mapping ACK above. The actual
        // original assignment separately refuses remaining retained epochs.
        match unsafe { state.owner.retire() } {
            Ok(allocation) => {
                drop(allocation);
                drop(self.state.take());
                Ok(())
            }
            Err(error) => Err(BarRetireFailure {
                error,
                fixture: self,
                remaining: Remaining::Unmapped,
            }),
        }
    }
}
// Privately retains initial qualification with the actual mapping. An uncertain
// token cannot be re-qualified from geometry or a now-unavailable address view.
enum Remaining {
    Unqualified(Mapping),
    Qualified(Mapping),
    Unmapped,
}
/// Same external actor plus exact failed mapping, never reconstructed control.
pub struct BarRetireFailure {
    pub error: MappingError,
    fixture: BarFixture,
    remaining: Remaining,
}
impl core::fmt::Debug for BarRetireFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BarRetireFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
impl BarRetireFailure {
    /// # Safety
    /// Original exclusion remains held; all views/raw users must actually have
    /// ended before retry. This never manufactures an unmap or completion ACK.
    pub unsafe fn retry(self) -> Result<(), Self> {
        let Self {
            fixture, remaining, ..
        } = self;
        match remaining {
            // SAFETY: same caller obligations; normal qualification still runs.
            Remaining::Unqualified(mapping) => unsafe { fixture.retire(mapping) },
            // SAFETY: privately held SAME mapping already qualified above.
            Remaining::Qualified(mapping) => unsafe { fixture.retire_bound(mapping) },
            // SAFETY: same original acknowledged mapping retirement contract.
            Remaining::Unmapped => unsafe { fixture.finish_unmapped() },
        }
    }
}
/// Fresh actual RAM with born Registers provenance, UC/RW and offset zero.
/// Geometry is model data; it grants no native BAR/configuration/Source rights.
pub fn bar_fixture(span: PhysicalSpan, bytes: usize) -> (BarFixture, Mapping) {
    assert!(span.start().is_multiple_of(4096) && span.bytes().is_multiple_of(4096));
    assert!(span.bytes() <= 8192 && bytes != 0 && bytes as u64 <= span.bytes());
    let counters = Arc::new(Counters::default());
    let memory = Arc::new(Ram {
        pages: UnsafeCell::new(Pages([0; 8192])),
    });
    // SAFETY: fresh real hosted RAM and the same isolated pure model guard.
    let owner = unsafe { MappingOwner::from_owned(memory.clone(), ram_context) };
    // Install the actual affine boxed actor BEFORE any fallible provider call.
    let mut fixture = BarFixture {
        state: Some(Box::new(State {
            owner,
            resource: None,
            retention: None,
            counters: counters.clone(),
        })),
    };
    let retention = fixture.state.as_ref().unwrap().owner.retention().unwrap();
    let resource = Resource::new(Box::new(Backing {
        span,
        kind: ResourceKind::Registers,
        counters: counters.clone(),
        mapping: retention.clone(),
    }));
    fixture.state.as_mut().unwrap().retention = Some(retention);
    fixture.state.as_mut().unwrap().resource = Some(resource.clone());
    let platform = Arc::new(Model {
        memory,
        installed: Mutex::new(None),
        unmap_pending: Mutex::new(None),
        counters,
    });
    // SAFETY: same actual isolated RAM/controller; never native source custody.
    let authority = unsafe { Authority::isolated_model(platform, SPACE, Vec::new()) }.unwrap();
    let mapping = authority
        .map(
            resource,
            0,
            bytes,
            CacheAttribute::Uncached,
            Protection::ReadWrite,
        )
        .unwrap();
    drop(authority);
    (fixture, mapping)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn born() -> (BarFixture, Mapping) {
        bar_fixture(PhysicalSpan::new(0x9000_0000, 4096).unwrap(), 4096)
    }
    #[test]
    fn registers_are_born_with_actual_ram_and_unmap_ack_releases_original_graph() {
        let (fixture, mapping) = born();
        let counters = fixture.counters();
        let state = fixture.state.as_ref().unwrap();
        assert_eq!(
            state.resource.as_ref().unwrap().kind(),
            ResourceKind::Registers
        );
        assert_eq!(state.owner.uses(), 1);
        mapping.write32(4, 0x1a2b_3c4d).unwrap();
        assert_eq!(mapping.read32(4).unwrap(), 0x1a2b_3c4d);
        // SAFETY: this exact isolated synchronous model has no outstanding user.
        unsafe { fixture.retire(mapping) }.unwrap();
        assert_eq!(counters.maps.load(Ordering::Relaxed), 1);
        assert_eq!(counters.unmaps.load(Ordering::Relaxed), 1);
        assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 1);
        assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 1);
    }
    #[test]
    fn kept_view_refuses_retirement_without_unmap_then_same_mapping_can_finish() {
        let (fixture, mapping) = born();
        let counters = fixture.counters();
        let view = mapping.view(0..4).unwrap();
        // SAFETY: no raw/callback tail exists; the real kept view must veto.
        let failure = unsafe { fixture.retire(mapping) }.unwrap_err();
        assert_eq!(failure.error, MappingError::Busy);
        assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
        assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
        assert_eq!(view.read32(0).unwrap(), 0);
        drop(view);
        // SAFETY: actual view is now gone; same original exclusion remains.
        unsafe { failure.retry() }.unwrap();
        assert_eq!(counters.unmaps.load(Ordering::Relaxed), 1);
        assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 1);
    }
    #[test]
    fn uncertain_unmap_retry_keeps_same_token_and_never_repeats_removed_effect() {
        let (fixture, mapping) = born();
        let counters = fixture.counters();
        counters.fail_unmap_after_effect.store(1, Ordering::Relaxed);
        // SAFETY: exact isolated source has no outstanding raw/callback user.
        let failure = unsafe { fixture.retire(mapping) }.unwrap_err();
        assert_eq!(failure.error, MappingError::UnmapFailed);
        assert_eq!(counters.unmaps.load(Ordering::Relaxed), 1);
        assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
        assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 0);
        // SAFETY: same stopped epoch and privately retained actual token.
        unsafe { failure.retry() }.unwrap();
        assert_eq!(counters.unmaps.load(Ordering::Relaxed), 1);
        assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 1);
        assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 1);
    }
}
