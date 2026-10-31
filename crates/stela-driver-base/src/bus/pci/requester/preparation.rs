//! Cold requester preparation keeps the original configuration and DMA root
//! until a driver-owned quiescence receipt permits private-domain attachment.
use super::*;
use crate::bus::dma::mapping::{DmaDomain, DmaError};
use alloc::{boxed::Box, sync::Arc};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Claim(ClaimError),
    Dma(DmaError),
    ForeignOwner,
}

/// The original root path, before the requester gets its private domain.
///
/// # Safety
/// This is the original function's kept translation/configuration/routing
/// epoch. `drain` acknowledges earlier translated payload writes through that
/// path; a CPU fence, Bus Master clear or bare command fetch cannot suffice.
/// Bypass/peer traffic must be independently excluded or drained by its owner.
/// `bind` uses the same original root, function and epoch, meets DmaDomain's
/// complete contract and keeps the original root/resources alive. Failure or
/// unwind retains uncertain hardware tables, domain reservations and pins.
/// Dropping an exposed root must retain uncertain hardware resources.
/// Each operation admits only the root's allowed process/processor context.
/// No callback may reset/reassign the requester or reenter its preparation.
pub unsafe trait Root {
    fn drain(&self) -> Result<(), DmaError>;
    /// # Safety
    /// The original paired requester is currently quiescent, this root's
    /// drain completed, and its configuration/reset/routing epoch cannot change
    /// before attachment finishes. The original owners remain kept throughout.
    unsafe fn bind(&self, binding: RequesterBinding) -> Result<Arc<dyn DmaDomain>, DmaError>;
}

struct Resources {
    function: Function<OwnedConfig>,
    retained: ConfigRetention,
    address: Address,
    identity: (u16, u16, [u8; 3]),
    root: Box<dyn Root>,
}

/// Dropping preparation cannot establish device stop or root completion.
/// Keep the whole graph on early exit, error or unwind until boot ends.
struct Owner(Option<Box<Resources>>);
impl Drop for Owner {
    fn drop(&mut self) {
        core::mem::forget(self.0.take());
    }
}
impl Owner {
    fn resources(&mut self) -> &mut Resources {
        self.0.as_deref_mut().expect("owned cold requester")
    }
    fn completed(mut self) -> Resources {
        *self.0.take().expect("owned cold requester")
    }
}

/// Original configuration and root ownership, without a stopped/DMA grant.
/// The driver may perform its cold vendor stop/reset through `function_mut`.
pub struct PreparingRequester {
    owner: Owner,
}

/// A non-cloneable acknowledgement containing the same original owner.
/// It exposes no configuration writer, so reset cannot occur between receipt
/// issuance and consuming finalization through a safe preparation accessor.
pub struct QuiescenceReceipt {
    owner: Owner,
}

/// Rejected construction returns the same original owners without granting
/// device quiescence or permission to retire their resources.
pub struct Rejected {
    pub error: ClaimError,
    pub function: Function<OwnedConfig>,
    pub root: Box<dyn Root>,
}

/// Failure keeps the original configuration/root, even if dropped.
pub struct Failure {
    pub error: Error,
    _owner: Owner,
}

/// A stopped original requester with its newly attached domain.
pub struct BoundRequester {
    pub requester: StoppedRequester,
    pub domain: Arc<dyn DmaDomain>,
}

impl PreparingRequester {
    /// # Safety
    /// `role` comes from the complete PF/VF inventory, never local capability
    /// absence. `function` is the exclusively owned physical function, independently
    /// admitted for coherent WB DMA. `root` is its original root path. Prior
    /// firmware/configuration/IRQ delivery and worker owners are excluded and
    /// kept; no Stela submission/IRQ/work user exists yet. This grants no
    /// endpoint engine stop, posted-payload drain or new DMA domain.
    pub unsafe fn new(
        mut function: Function<OwnedConfig>,
        role: FunctionRole,
        root: Box<dyn Root>,
    ) -> Result<Self, Rejected> {
        if role != FunctionRole::Physical {
            return Err(Rejected {
                error: ClaimError::UnsupportedRole(role),
                function,
                root,
            });
        }
        let address = function.address;
        if address != function.config().address() {
            return Err(Rejected {
                error: ClaimError::IdentityChanged,
                function,
                root,
            });
        }
        let retained = match function.config().retain_epoch() {
            Ok(retained) => retained,
            Err(error) => {
                return Err(Rejected {
                    error: ClaimError::Mapping(error),
                    function,
                    root,
                });
            }
        };
        let identity = (function.vendor, function.device, function.class);
        Ok(Self {
            owner: Owner(Some(Box::new(Resources {
                function,
                retained,
                address,
                identity,
                root,
            }))),
        })
    }

    pub fn function_mut(&mut self) -> &mut Function<OwnedConfig> {
        &mut self.owner.resources().function
    }

    /// # Safety
    /// The owning driver has acknowledged engine stop/reset and submission
    /// exclusion for this original function, with no possibility of restart.
    /// All firmware, IRQ delivery and worker users are retired; bypass/peer
    /// traffic is independently excluded or drained. Keep BARs and all old
    /// DMA backing alongside this receipt until finalization or quarantine.
    /// This does not grant posted-payload completion: finalization asks the
    /// original root for that acknowledgement before binding a new domain.
    pub unsafe fn acknowledge_quiescence(self) -> QuiescenceReceipt {
        QuiescenceReceipt { owner: self.owner }
    }
}

impl QuiescenceReceipt {
    pub fn finalize(mut self) -> Result<BoundRequester, Failure> {
        let result = (|| {
            let resources = self.owner.resources();
            let function = &mut resources.function;
            if function.address != resources.address
                || (function.vendor, function.device, function.class) != resources.identity
                || function.config().address() != resources.address
                || !function
                    .config()
                    .matches_retention(&resources.retained)
                    .map_err(|error| Error::Claim(ClaimError::Mapping(error)))?
            {
                return Err(Error::ForeignOwner);
            }
            resources.root.drain().map_err(Error::Dma)?;
            validate_stopped(function).map_err(Error::Claim)?;
            let retained = function
                .config()
                .retain_epoch()
                .map_err(|error| Error::Claim(ClaimError::Mapping(error)))?;
            // SAFETY: the consumed driver receipt excludes new producers;
            // the original configuration seal still matches, its root drain
            // completed, and all owners stay in this attempt until success.
            unsafe {
                resources.root.bind(RequesterBinding {
                    address: resources.address,
                    retention: retained,
                })
            }
            .map_err(Error::Dma)
        })();
        match result {
            Ok(domain) => {
                let resources = self.owner.completed();
                Ok(BoundRequester {
                    requester: StoppedRequester {
                        function: resources.function,
                        address: resources.address,
                        dma_bound: true,
                    },
                    domain,
                })
            }
            Err(error) => Err(Failure {
                error,
                _owner: self.owner,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::bus::{
        dma::{
            mapping::{Direction, DomainMapping},
            pages::DmaPages,
        },
        pci::{owned::test_support::fixture, regs},
    };
    use alloc::vec::Vec;
    use core::{
        ops::Range,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use std::sync::Mutex;

    const ADDRESS: Address = Address {
        segment: 0,
        bus: 1,
        device: 0,
        function: 0,
    };
    #[derive(Default)]
    struct State {
        events: Mutex<Vec<&'static str>>,
        drops: AtomicUsize,
        panic_drain: AtomicBool,
    }
    struct RootOwner(Arc<State>);
    impl Drop for RootOwner {
        fn drop(&mut self) {
            self.0.drops.fetch_add(1, Ordering::Relaxed);
        }
    }
    struct OldRoot {
        owner: Arc<RootOwner>,
        drain_error: bool,
        bind_error: bool,
    }
    struct Domain {
        _binding: RequesterBinding,
        _owner: Arc<RootOwner>,
    }
    // SAFETY: these roots are isolated synchronous RAM fixtures; no real DMA,
    // IRQ or firmware accessor exists. Events model independent old-root and
    // new-domain completion; binding retains the original configuration epoch.
    unsafe impl Root for OldRoot {
        fn drain(&self) -> Result<(), DmaError> {
            self.owner
                .0
                .events
                .lock()
                .unwrap()
                .push("old root completion");
            assert!(
                !self.owner.0.panic_drain.load(Ordering::Relaxed),
                "injected root drain unwind"
            );
            if self.drain_error {
                Err(DmaError::InvalidationFailed)
            } else {
                Ok(())
            }
        }
        unsafe fn bind(&self, binding: RequesterBinding) -> Result<Arc<dyn DmaDomain>, DmaError> {
            assert_eq!(binding.address(), ADDRESS);
            binding.check_live().unwrap();
            self.owner
                .0
                .events
                .lock()
                .unwrap()
                .push("new domain attachment");
            if self.bind_error {
                return Err(DmaError::MappingFailed);
            }
            Ok(Arc::new(Domain {
                _binding: binding,
                _owner: self.owner.clone(),
            }))
        }
    }
    // SAFETY: this fixture maps nothing; it retains its configuration/root owners.
    unsafe impl DmaDomain for Domain {
        unsafe fn map(
            &self,
            _: &DmaPages,
            _: Direction,
            _: u64,
        ) -> Result<DomainMapping, DmaError> {
            Err(DmaError::MappingFailed)
        }
        unsafe fn unmap(&self, _: DomainMapping) -> Result<(), DmaError> {
            Err(DmaError::Unmapped)
        }
        unsafe fn sync_for_device(
            &self,
            _: DomainMapping,
            _: Range<usize>,
            _: Direction,
        ) -> Result<(), DmaError> {
            Err(DmaError::Unmapped)
        }
        unsafe fn sync_for_cpu(
            &self,
            _: DomainMapping,
            _: Range<usize>,
            _: Direction,
        ) -> Result<(), DmaError> {
            Err(DmaError::Unmapped)
        }
    }
    fn function(address: Address) -> Function<OwnedConfig> {
        let (mut config, _) = fixture(address);
        config.write32(0, 0x12348086);
        config.write16(regs::COMMAND, regs::COMMAND_INTX_DISABLE);
        config.write32(8, 0x02800000);
        config.write32(0x0c, 0);
        config.write32(0x100, 0);
        Function::new(address, config).unwrap()
    }
    fn preparing(drain_error: bool, bind_error: bool) -> (PreparingRequester, Arc<State>) {
        let state = Arc::new(State::default());
        let root = Box::new(OldRoot {
            owner: Arc::new(RootOwner(state.clone())),
            drain_error,
            bind_error,
        });
        // SAFETY: exact isolated function/root, with no firmware/IRQ/work users;
        // the peer starts idle but this construction makes no engine-stop grant.
        let prepared =
            unsafe { PreparingRequester::new(function(ADDRESS), FunctionRole::Physical, root) }
                .unwrap_or_else(|_| panic!("original fixture owners"));
        (prepared, state)
    }
    #[test]
    fn old_root_completion_precedes_attachment_and_owners_follow_the_bound_domain() {
        let (prepared, state) = preparing(false, false);
        assert!(state.events.lock().unwrap().is_empty());
        // SAFETY: the synchronous fixture has no DMA engines, submissions or IRQ/work.
        let receipt = unsafe { prepared.acknowledge_quiescence() };
        assert!(state.events.lock().unwrap().is_empty());
        let bound = receipt
            .finalize()
            .unwrap_or_else(|f| panic!("{:?}", f.error));
        assert_eq!(
            *state.events.lock().unwrap(),
            ["old root completion", "new domain attachment"]
        );
        assert_eq!(state.drops.load(Ordering::Relaxed), 0);
        assert!(matches!(
            bound.requester.into_dma_binding(),
            Err((ClaimError::AlreadyBound, _))
        ));
        assert_eq!(state.drops.load(Ordering::Relaxed), 0);
        drop(bound.domain);
        assert_eq!(state.drops.load(Ordering::Relaxed), 1);
    }
    #[test]
    fn foreign_configuration_is_rejected_before_any_root_operation() {
        for other in [
            Address {
                function: 1,
                ..ADDRESS
            },
            ADDRESS,
        ] {
            let (mut prepared, state) = preparing(false, false);
            let old = core::mem::replace(prepared.function_mut(), function(other));
            // SAFETY: both isolated fixture functions have no active DMA/IRQ/work.
            let receipt = unsafe { prepared.acknowledge_quiescence() };
            let failure = receipt.finalize().err().expect("foreign owner refused");
            assert_eq!(failure.error, Error::ForeignOwner);
            assert!(state.events.lock().unwrap().is_empty());
            drop(failure);
            drop(old);
            assert_eq!(
                state.drops.load(Ordering::Relaxed),
                0,
                "unknown owner graph remains kept"
            );
        }
    }
    #[test]
    fn failed_old_root_or_binding_keeps_the_preparation_graph() {
        for (drain, bind, error, events) in [
            (true, false, DmaError::InvalidationFailed, 1),
            (false, true, DmaError::MappingFailed, 2),
        ] {
            let (prepared, state) = preparing(drain, bind);
            // SAFETY: synchronous idle fixture; no submissions or callbacks exist.
            let receipt = unsafe { prepared.acknowledge_quiescence() };
            let failure = receipt
                .finalize()
                .err()
                .expect("injected completion failure");
            assert_eq!(failure.error, Error::Dma(error));
            assert_eq!(state.events.lock().unwrap().len(), events);
            drop(failure);
            assert_eq!(state.drops.load(Ordering::Relaxed), 0);
        }
    }
    #[test]
    fn abandoning_preparation_does_not_release_an_unstopped_owner() {
        let (prepared, state) = preparing(false, false);
        drop(prepared);
        assert!(state.events.lock().unwrap().is_empty());
        assert_eq!(state.drops.load(Ordering::Relaxed), 0);
    }
    #[test]
    fn configuration_activity_is_rechecked_after_old_root_completion() {
        let (mut prepared, state) = preparing(false, false);
        prepared.function_mut().config().write16(
            regs::COMMAND,
            regs::COMMAND_MASTER | regs::COMMAND_INTX_DISABLE,
        );
        // SAFETY: no modeled engine/submission/IRQ/work exists; the deliberately
        // enabled configuration bit must independently fail stopped validation.
        let receipt = unsafe { prepared.acknowledge_quiescence() };
        let failure = receipt.finalize().err().expect("bus mastering refused");
        assert_eq!(
            failure.error,
            Error::Claim(ClaimError::Active {
                offset: regs::COMMAND
            })
        );
        assert_eq!(*state.events.lock().unwrap(), ["old root completion"]);
    }

    #[test]
    fn root_callback_unwind_keeps_the_whole_preparation_graph() {
        let (prepared, state) = preparing(false, false);
        state.panic_drain.store(true, Ordering::Relaxed);
        // SAFETY: isolated fixture with no DMA, IRQ/work or firmware producers.
        let receipt = unsafe { prepared.acknowledge_quiescence() };
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| receipt.finalize())).is_err()
        );
        assert_eq!(*state.events.lock().unwrap(), ["old root completion"]);
        assert_eq!(state.drops.load(Ordering::Relaxed), 0);
    }
}
