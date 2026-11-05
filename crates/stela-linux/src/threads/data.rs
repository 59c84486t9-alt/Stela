//! Actual allocation/code/root lifetime for source task accounting fields.
//! Field observations and this owner do not grant CPU or data write access.
use core::ops::Range;

/// Storage kind fixed by the genuine source TaskBinding constructor. No raw
/// pointer/flag can turn a bare record into either original source product.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskDataStorage {
    /// Exact original init_task in the actual relocated resident DATA image.
    InitialImage,
    /// Actual original fork task_struct allocation in the owned native heap.
    AllocatedTask,
}

/// Original backing projection for an IRQ-retained measured execution sink.
///
/// # Safety
/// Own the actual resident executable allocation, native root/table mapping
/// backing, and the genuine storage allocations needed by both storage kinds.
/// InitialImage is actual resident writable non-executable DATA, never assumed
/// heap. AllocatedTask is the same original native heap allocation, never a
/// raw Region/VA/PFN claim or an unrelated Arc. The actual allocation/mapping
/// roots remain retained through source callback tails, uncertain publication,
/// native writer stop and every IRQ reader join.
///
/// This projection must have NO owning Queue/Runtime/KernelOwner/Platform/task
/// binding edge, including transitively through a captured callback/closure.
/// It retains no borrowed execution permit. It conveys no allocation, reuse,
/// CPU/current/IRQ, cache/root mutation or data-write permission. The original
/// C get_task_struct lease separately retains the particular slab task object;
/// no address-range observation supplies that reference. Only actual native
/// execution/mapping admission may authorize stores through source field views.
pub unsafe trait TaskDataBacking: Send + Sync {
    /// Pure bounded allocation-membership rejection check, with no pointer
    /// dereference, allocation, C call, callback, wait, root switch or owner
    /// release. Require a nonempty checked span entirely inside the actual
    /// retained owner for this source storage kind. True is only lifetime
    /// membership, never task identity or CPU/mapping/write permission.
    fn contains(&self, storage: TaskDataStorage, span: Range<usize>) -> bool;
}
