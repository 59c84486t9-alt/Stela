//! A current-state LAPIC transition under an actual original controller owner.
//! No register image, vector, feature bit or successful stop is an ingress drain.
use alloc::boxed::Box;
use core::{cell::Cell, mem::ManuallyDrop};
use stela_driver_base::sync::{FaultState, FirstFault};
mod protocol;
#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Xapic,
    X2apic,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Profile {
    pub mode: Mode,
    pub deadline: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Register {
    Id,
    Version,
    Svr,
    Tpr,
    /// 0timer, 1thermal, 2performance, 3LINT0, 4LINT1, 5error, 6CMCI.
    /// CMCI is physical offset0x2f0, NOT0x320+6*0x10.
    Lvt(u8),
    Divide,
    Initial,
    Current,
    Isr(u8),
    Irr(u8),
    Tmr(u8),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    MaskOriginalTimer(u32),
    OrderDeadline,
    DisarmDeadline,
    StopCount,
    ConfigureSvr(u32),
    ConfigureTimer,
    ConfigureDivide,
}
/// Only the selected original CPU/controller custody may implement this.
/// It must keep actual old/new entry/handler, root/cache/code and bank backing.
///
/// # Safety
/// Every call validates the SAME original CPU, IF0/root/cache and mode/base.
/// This owner exclusively controls the original timer and startup SVR subset;
/// no firmware/other writer can change them during the transaction. Mode/base,
/// PIC/LINT/TPR/ICR and other controllers remain outside the write subset.
/// Profile is actual enumerated metadata, never independent authority. Reads
/// are bounded architectural observations; deadline access requires enumeration.
/// `OrderDeadline` executes the real required xAPIC MFENCE; deadline zero is a
/// real same-CPU MSR write. All errors preserve actual custody. Implementations
/// may be independent RAM peers but must not claim native hardware from them.
/// Native abandonment/Drop MUST retain the original old-notification/entry/
/// root/cache/code/bank graph unless a separate genuine retirement joined it.
/// Successful current-state programming alone never permits release. A RAM
/// peer with no autonomous event actor may release its actual model resources.
/// Apply meanings: StopCount writes32-bit INITIAL0; ConfigureTimer writes
/// masked one-shot vector64; ConfigureDivide writes32-bit DCR0xb. DisarmDeadline
/// writes64-bit IA32_TSC_DEADLINE0 only after enumeration and required ordering.
pub unsafe trait OriginalController {
    type Error: Copy + Send + Sync;
    fn check(&self) -> Result<Profile, Self::Error>;
    fn read(&self, register: Register) -> Result<u32, Self::Error>;
    fn read_deadline(&self) -> Result<u64, Self::Error>;
    fn apply(&mut self, operation: Operation) -> Result<(), Self::Error>;
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Effect {
    NotWritten,
    MayHaveWritten { ordinal: u8, operation: Operation },
    ConfirmedCurrentState { ordinal: u8, operation: Operation },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cause<E> {
    Source(E),
    Interrupted,
    InvalidVersion,
    UnsupportedTimer,
    InvalidSvr,
    InvalidTarget,
    NonzeroTpr,
    ActiveService,
    ChangedProfile,
    SpuriousCollision {
        lvt: u8,
        observed: u32,
    },
    Readback {
        register: Register,
        expected: u32,
        observed: u32,
        mask: u32,
    },
    DeadlineReadback {
        observed: u64,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failure<E> {
    pub cause: Cause<E>,
    pub effect: Effect,
}
/// Copied observations only. This cannot construct a transition or IO owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginalImage {
    pub profile: Profile,
    pub id: u32,
    pub version: u32,
    pub svr: u32,
    pub tpr: u32,
    pub lvt: [u32; 7],
    pub divide: u32,
    pub initial: u32,
    pub current: u32,
    pub deadline: Option<u64>,
    pub isr: [u32; 8],
    pub irr: [u32; 8],
    pub tmr: [u32; 8],
}
impl OriginalImage {
    pub fn timer_vector(&self) -> u8 {
        self.lvt[0] as u8
    }
    pub fn timer_lvt(&self) -> u32 {
        self.lvt[0]
    }
    pub fn original_svr(&self) -> u32 {
        self.svr
    }
    pub fn pending_observation(&self) -> &[u32; 8] {
        &self.irr
    }
    pub fn profile(&self) -> Profile {
        self.profile
    }
}
struct Graph<I: OriginalController> {
    io: ManuallyDrop<I>,
    fault: FirstFault<Failure<I::Error>>,
    effect: Cell<Effect>,
    original: Option<OriginalImage>,
    // Returned pre-effect refusal also survives carrier Drop/forget. It is
    // not automatically a shared hardware fault, Busy or publishing relatch.
    outcome: Option<Failure<I::Error>>,
}
/// One-shot original controller transaction. Abandonment keeps the SAME graph;
/// neither Drop nor an uncertain returned error restores/writes any register.
#[must_use]
pub struct Startup<I: OriginalController> {
    graph: ManuallyDrop<Box<Graph<I>>>,
}
pub struct KeptFailure<I: OriginalController> {
    pub error: Failure<I::Error>,
    graph: ManuallyDrop<Box<Graph<I>>>,
}
/// Same original controller and old-notification backing after verified current
/// programming. No no-pending/all-issued/first-interrupt/history claim follows.
#[must_use]
pub struct Configured<I: OriginalController> {
    graph: ManuallyDrop<Box<Graph<I>>>,
}
impl<I: OriginalController> Startup<I> {
    /// Actual ownership is carried by `io`, not its profile or observations.
    pub fn new(io: I) -> Self {
        Self {
            graph: ManuallyDrop::new(Box::new(Graph {
                io: ManuallyDrop::new(io),
                fault: FirstFault::new(),
                effect: Cell::new(Effect::NotWritten),
                original: None,
                outcome: None,
            })),
        }
    }
    pub fn configure(mut self) -> Result<Configured<I>, KeptFailure<I>> {
        let graph = &mut **self.graph;
        let mut unwind = Interrupted {
            fault: &graph.fault,
            effect: &graph.effect,
            settled: false,
        };
        let result = protocol::configure(&mut *graph.io, &graph.effect, &mut graph.original);
        if let Err(cause) = result {
            graph.outcome = Some(Failure {
                cause,
                effect: graph.effect.get(),
            });
            if graph.effect.get() != Effect::NotWritten {
                graph.fault.latch(Failure {
                    cause,
                    effect: graph.effect.get(),
                });
            }
        }
        unwind.settled = true;
        drop(unwind);
        // SAFETY: this consumes the only affine wrapper; no owner/reference
        // escapes a callback. The original Box moves, never its IO/storage.
        let graph = unsafe { ManuallyDrop::take(&mut self.graph) };
        match result {
            Ok(()) => Ok(Configured {
                graph: ManuallyDrop::new(graph),
            }),
            Err(_) => {
                let error = graph.outcome.expect("same retained returned cause");
                Err(KeptFailure {
                    error,
                    graph: ManuallyDrop::new(graph),
                })
            }
        }
    }
}
struct Interrupted<'a, E: Copy + Send + Sync> {
    fault: &'a FirstFault<Failure<E>>,
    effect: &'a Cell<Effect>,
    settled: bool,
}
impl<E: Copy + Send + Sync> Drop for Interrupted<'_, E> {
    fn drop(&mut self) {
        if !self.settled {
            self.fault.latch(Failure {
                cause: Cause::Interrupted,
                effect: self.effect.get(),
            });
        }
    }
}
impl<I: OriginalController> KeptFailure<I> {
    pub fn failure(&self) -> FaultState<Failure<I::Error>> {
        self.graph.fault.observe()
    }
    pub fn effect(&self) -> Effect {
        self.graph.effect.get()
    }
}
impl<I: OriginalController> Configured<I> {
    pub fn original(&self) -> &OriginalImage {
        self.graph
            .original
            .as_ref()
            .expect("successful original capture")
    }
    /// Move the genuine original controller into its disjoint timer/EOI role
    /// split. The returned image is metadata; `I` retains old notification and
    /// current control custody. No failed transition offers this extraction.
    pub fn into_control(mut self) -> (I, OriginalImage) {
        // SAFETY: unique successful wrapper, no borrowed graph or callbacks.
        let mut graph = unsafe { ManuallyDrop::take(&mut self.graph) };
        // SAFETY: the actual control moves once; its ManuallyDrop field cannot
        // run another destructor. All backing remains in the moved control.
        let io = unsafe { ManuallyDrop::take(&mut graph.io) };
        (io, graph.original.expect("successful original capture"))
    }
}
