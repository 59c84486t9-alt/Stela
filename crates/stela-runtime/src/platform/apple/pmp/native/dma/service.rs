//! The executing side of the native PMP DMA pair. `Service` runs one queued
//! operation per `dispatch` through the actual DMA `Port`, uses the `Coherence`
//! owner for map, synchronize, unmap and release effects, and records the
//! reply and grant lifetime for the broker.
use super::super::platform::owner::Completion;
use super::broker::{
    Descriptor, Grant, Job, Life, Op, Output, Owners, Reply, ServiceRequest, State, reason,
};
use crate::platform::dma::Port;
use alloc::{rc::Rc, vec};
use core::cell::RefCell;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    Map,
    ReportingSynchronize { offset: u64, bytes: u64 },
    TracePrepare,
    TraceComplete,
    Unmap,
    Release,
}
/// Actual configured native mapping/cache/barrier owner, with the same retained
/// registered RAM generation and stopped producer cohort as the Port. No
/// successful default or generic host fence is supplied here. In a qualified
/// coherent WB implementation, its real ordering/copyout fence may establish
/// visibility of this mapping; that is not MCC eviction, DCS, PTD or MC ACK.
/// Busy/Refused commit no effect; Retired advances before a later diagnostic.
pub trait Coherence {
    fn effect(
        &mut self,
        request: &ServiceRequest,
        owners: &Owners,
        descriptor: Descriptor,
        effect: Effect,
        port: &mut Port<'_, '_>,
    ) -> Completion<()>;
}
/// Sole service endpoint retained by AppleDevices. No Port/reference/callback is
/// stored across calls. State is released before actual Port/cache callbacks,
/// so nested broker submissions cannot reenter a held RefCell borrow.
pub struct Service {
    state: Rc<RefCell<State>>,
    pending: Option<Job>,
}
impl Service {
    pub(super) fn new(state: Rc<RefCell<State>>) -> Self {
        Self {
            state,
            pending: None,
        }
    }
    pub fn route(&self) -> super::Route {
        self.state.borrow().route
    }
    pub fn has_work(&self) -> bool {
        self.pending.is_some() || !self.state.borrow().queue.is_empty()
    }
    /// One actual queued operation per call. The root selects the actual DART
    /// DeviceId/instance and canonical allocator/RAM owners for this pair.
    /// A successful return means service dispatch, not protocol publication.
    pub fn dispatch(
        &mut self,
        owners: &Owners,
        port: &mut Port<'_, '_>,
        coherence: &mut impl Coherence,
    ) -> Completion<()> {
        {
            let state = self.state.borrow();
            if !state.alive || !state.owners.same(owners) || port.stream != state.route.stream {
                return Completion::Refused(
                    "native PMP DMA dispatcher/Port resource identity differs",
                );
            }
            if state.dispatching {
                return Completion::Refused("native PMP DMA service reentry");
            }
            if let Some(job) = &self.pending
                && state.replies.contains_key(&job.request.serial)
            {
                return Completion::Busy { deadline: None };
            }
        }
        let Some(mut job) = self
            .pending
            .take()
            .or_else(|| self.state.borrow_mut().queue.pop_front())
        else {
            return Completion::Busy { deadline: None };
        };
        self.state.borrow_mut().dispatching = true;
        let result = self.execute(&mut job, owners, port, coherence);
        let mut state = self.state.borrow_mut();
        state.dispatching = false;
        match result {
            Completion::Busy { deadline } => {
                self.pending = Some(job);
                Completion::Busy { deadline }
            }
            Completion::Refused(error) => {
                state
                    .replies
                    .insert(job.request.serial, Completion::Refused(error));
                self.pending = Some(job);
                Completion::Refused(error)
            }
            Completion::Retired { value, refusal } => {
                state
                    .replies
                    .insert(job.request.serial, Completion::Retired { value, refusal });
                Completion::Retired { value: (), refusal }
            }
        }
    }
    fn execute(
        &self,
        job: &mut Job,
        owners: &Owners,
        port: &mut Port<'_, '_>,
        coherence: &mut impl Coherence,
    ) -> Completion<Reply> {
        let descriptor = match &job.op {
            Op::Map(d)
            | Op::Read { descriptor: d, .. }
            | Op::Write { descriptor: d, .. }
            | Op::Effect { descriptor: d, .. } => *d,
        };
        if descriptor.route != self.route() {
            return Completion::Refused("native PMP DMA queued route changed");
        }
        if !matches!(&job.op, Op::Map(_)) {
            let state = self.state.borrow();
            let Some(grant) = state.grants.get(&descriptor.id) else {
                return Completion::Refused("native PMP DMA grant disappeared");
            };
            let expected = if matches!(
                &job.op,
                Op::Effect {
                    effect: Effect::Release,
                    ..
                }
            ) {
                Life::Unmapped
            } else {
                Life::Mapped
            };
            if grant.descriptor != descriptor || grant.life != expected {
                return Completion::Refused("native PMP DMA grant lifecycle differs");
            }
        }
        match &job.op {
            Op::Map(_) => {
                if !job.checked {
                    for write in [false, true] {
                        if let Err(fault) =
                            port.check(descriptor.iova, descriptor.bytes as usize, write)
                        {
                            return Completion::Refused(reason(fault.error));
                        }
                    }
                    job.checked = true;
                }
                match coherence.effect(&job.request, owners, descriptor, Effect::Map, port) {
                    Completion::Busy { deadline } => Completion::Busy { deadline },
                    Completion::Refused(error) => Completion::Refused(error),
                    Completion::Retired { value: (), refusal } => {
                        self.state.borrow_mut().grants.insert(
                            descriptor.id,
                            Grant {
                                descriptor,
                                life: Life::Mapped,
                            },
                        );
                        Completion::Retired {
                            value: Reply {
                                output: Output::Mapped(descriptor),
                                refusal: None,
                            },
                            refusal,
                        }
                    }
                }
            }
            Op::Read { offset, bytes, .. } => {
                let mut data = vec![0; *bytes];
                let fault = port
                    .read_progress(descriptor.iova + offset, &mut data)
                    .err();
                if let Some(fault) = fault {
                    if fault.completed > *bytes {
                        self.state.borrow_mut().alive = false;
                        return Completion::Refused("native PMP DMA read returned invalid prefix");
                    }
                    data.truncate(fault.completed);
                }
                Completion::Retired {
                    value: Reply {
                        output: Output::Read { bytes: data, fault },
                        refusal: None,
                    },
                    refusal: None,
                }
            }
            Op::Write { offset, bytes, .. } => {
                let fault = port.write_progress(descriptor.iova + offset, bytes).err();
                let completed = fault.map_or(bytes.len(), |fault| fault.completed);
                if completed > bytes.len() {
                    self.state.borrow_mut().alive = false;
                    return Completion::Refused("native PMP DMA write returned invalid prefix");
                }
                Completion::Retired {
                    value: Reply {
                        output: Output::Written { completed, fault },
                        refusal: None,
                    },
                    refusal: None,
                }
            }
            Op::Effect { effect, .. } => {
                match coherence.effect(&job.request, owners, descriptor, *effect, port) {
                    Completion::Busy { deadline } => Completion::Busy { deadline },
                    Completion::Refused(error) => Completion::Refused(error),
                    Completion::Retired { value: (), refusal } => {
                        let life = match effect {
                            Effect::Unmap => Some(Life::Unmapped),
                            Effect::Release => Some(Life::Released),
                            _ => None,
                        };
                        if let Some(life) = life {
                            self.state
                                .borrow_mut()
                                .grants
                                .get_mut(&descriptor.id)
                                .unwrap()
                                .life = life;
                        }
                        Completion::Retired {
                            value: Reply {
                                output: Output::Unit,
                                refusal: None,
                            },
                            refusal,
                        }
                    }
                }
            }
        }
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        self.state.borrow_mut().alive = false;
    }
}
