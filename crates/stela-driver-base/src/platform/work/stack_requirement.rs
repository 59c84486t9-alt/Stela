//! Checked stack geometry and opt-in mixed-worker profiles; no execution permission.
#[cfg(target_arch = "x86_64")]
use super::Stack;
use super::{Lane, MAX_CONTINUATIONS, WorkError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Usable {
    Exact(usize),
    AtLeast(usize),
}
/// A callback's required real usable extent, base alignment and preceding guard.
/// It describes geometry; only the StackBacking supplies ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StackRequirement {
    usable: Usable,
    alignment: usize,
    guard: usize,
}
impl StackRequirement {
    pub fn exact(bytes: usize, alignment: usize, minimum_guard: usize) -> Result<Self, WorkError> {
        Self::checked(Usable::Exact(bytes), alignment, minimum_guard)
    }
    pub fn at_least(
        bytes: usize,
        alignment: usize,
        minimum_guard: usize,
    ) -> Result<Self, WorkError> {
        Self::checked(Usable::AtLeast(bytes), alignment, minimum_guard)
    }
    fn checked(usable: Usable, alignment: usize, guard: usize) -> Result<Self, WorkError> {
        let (Usable::Exact(bytes) | Usable::AtLeast(bytes)) = usable;
        if bytes < 16 * 1024
            || bytes > isize::MAX as usize
            || !bytes.is_multiple_of(4096)
            || alignment < 16
            || !alignment.is_power_of_two()
            || alignment > isize::MAX as usize
            || guard < 4096
            || guard > isize::MAX as usize
            || !guard.is_multiple_of(4096)
        {
            return Err(WorkError::InvalidStack);
        }
        Ok(Self {
            usable,
            alignment,
            guard,
        })
    }
    pub fn usable_bytes(self) -> usize {
        let (Usable::Exact(bytes) | Usable::AtLeast(bytes)) = self.usable;
        bytes
    }
    pub fn is_exact(self) -> bool {
        matches!(self.usable, Usable::Exact(_))
    }
    pub fn alignment(self) -> usize {
        self.alignment
    }
    pub fn minimum_guard_bytes(self) -> usize {
        self.guard
    }
    pub(super) fn accepts(self, shape: Geometry) -> bool {
        let size = match self.usable {
            Usable::Exact(bytes) => shape.bytes == bytes,
            Usable::AtLeast(bytes) => shape.bytes >= bytes,
        };
        size && shape.start.is_multiple_of(self.alignment) && shape.guard >= self.guard
    }
}
/// An observation from an actual native worker transition to reusable Idle.
/// No address, mapping, stack ownership or future admission guarantee is carried.
/// The entry bit matters: an entered stack cannot satisfy cold-only admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleasedStackGeometry {
    bytes: usize,
    alignment: usize,
    guard: usize,
    unstarted: bool,
}
impl ReleasedStackGeometry {
    #[cfg(target_arch = "x86_64")]
    pub(super) fn of(stack: &Stack, unstarted: bool) -> Self {
        // Exact immutable constructor ranges, never an escrow's minimum shape.
        // Zero is divisible by every supported power-of-two alignment; saturate
        // its observation at the largest representable power of two.
        let alignment = 1usize << stack.bounds.start.trailing_zeros().min(usize::BITS - 1);
        Self {
            bytes: stack.bounds.end - stack.bounds.start,
            alignment,
            guard: stack.guard.end - stack.guard.start,
            unstarted,
        }
    }
    pub fn usable_bytes(self) -> usize {
        self.bytes
    }
    pub fn alignment(self) -> usize {
        self.alignment
    }
    pub fn guard_bytes(self) -> usize {
        self.guard
    }
    pub fn unstarted(self) -> bool {
        self.unstarted
    }
    pub fn supports(self, requirement: StackRequirement) -> bool {
        let size = if requirement.is_exact() {
            self.bytes == requirement.usable_bytes()
        } else {
            self.bytes >= requirement.usable_bytes()
        };
        size && self.alignment >= requirement.alignment()
            && self.guard >= requirement.minimum_guard_bytes()
    }
}
/// Expected mixed geometry of the 32-stack pool.
/// General counts are validated against unambiguously matching owners.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StackProfile {
    kernel: StackRequirement,
    ordinary: StackRequirement,
    kernel_general: usize,
    ordinary_general: usize,
}
impl StackProfile {
    pub fn new(
        kernel: StackRequirement,
        ordinary: StackRequirement,
        kernel_general: usize,
        ordinary_general: usize,
    ) -> Result<Self, WorkError> {
        if kernel_general == 0
            || ordinary_general == 0
            || kernel_general.checked_add(ordinary_general) != Some(24)
        {
            return Err(WorkError::Unavailable);
        }
        Ok(Self {
            kernel,
            ordinary,
            kernel_general,
            ordinary_general,
        })
    }
    pub fn kernel(self) -> StackRequirement {
        self.kernel
    }
    pub fn ordinary(self) -> StackRequirement {
        self.ordinary
    }
    pub fn kernel_general(self) -> usize {
        self.kernel_general
    }
    pub fn ordinary_general(self) -> usize {
        self.ordinary_general
    }
    pub(super) fn default_for(self, lane: Lane) -> StackRequirement {
        if lane == Lane::Service {
            self.kernel
        } else {
            self.ordinary
        }
    }
}
#[derive(Clone, Copy)]
pub(super) struct Geometry {
    start: usize,
    bytes: usize,
    guard: usize,
}
impl Geometry {
    #[cfg(target_arch = "x86_64")]
    pub(super) fn of(stack: &Stack) -> Self {
        // Stack::new validated these immutable cached ranges. No provider callback
        // or address reinterpretation occurs inside queue admission/dispatch.
        Self {
            start: stack.bounds.start,
            bytes: stack.bounds.end - stack.bounds.start,
            guard: stack.guard.end - stack.guard.start,
        }
    }
}
#[derive(Clone, Copy)]
struct Worker {
    lane: Lane,
    geometry: Geometry,
}
#[derive(Clone, Copy)]
pub(super) struct Catalog {
    workers: [Option<Worker>; MAX_CONTINUATIONS],
}
impl Catalog {
    pub(super) fn empty() -> Self {
        Self {
            workers: [None; MAX_CONTINUATIONS],
        }
    }
    pub(super) fn supports(&self, lane: Lane, requirement: StackRequirement) -> bool {
        self.workers
            .iter()
            .flatten()
            .any(|worker| worker.lane == lane && requirement.accepts(worker.geometry))
    }
    #[cfg(target_arch = "x86_64")]
    pub(super) fn from_actual(
        stacks: &[Stack],
        profile: StackProfile,
        layout: super::Layout,
    ) -> Result<Self, WorkError> {
        if !matches!(layout, super::Layout::NativeFirmware32Protected(_)) || stacks.len() != 32 {
            return Err(WorkError::Unavailable);
        }
        let mut result = Self::empty();
        let (mut kernel_general, mut ordinary_general) = (0, 0);
        for (index, stack) in stacks.iter().enumerate() {
            let lane = layout.lane(index);
            let shape = Geometry::of(stack);
            if lane == Lane::General {
                match (
                    profile.kernel.accepts(shape),
                    profile.ordinary.accepts(shape),
                ) {
                    (true, false) => kernel_general += 1,
                    (false, true) => ordinary_general += 1,
                    _ => return Err(WorkError::InvalidStack),
                }
            } else if !profile.default_for(lane).accepts(shape) {
                return Err(WorkError::InvalidStack);
            }
            result.workers[index] = Some(Worker {
                lane,
                geometry: shape,
            });
        }
        if kernel_general != profile.kernel_general || ordinary_general != profile.ordinary_general
        {
            return Err(WorkError::InvalidStack);
        }
        Ok(result)
    }
}
#[cfg(any(test, target_arch = "x86_64"))]
pub(super) fn compatible(requirement: Option<StackRequirement>, geometry: Geometry) -> bool {
    requirement.is_none_or(|required| required.accepts(geometry))
}
