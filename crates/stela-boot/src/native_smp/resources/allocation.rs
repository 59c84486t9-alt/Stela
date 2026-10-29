//! Firmware task-page ownership, moved once into the engine handoff.
use crate::{handoff::Region, tables::PAGE};
use core::sync::atomic::{AtomicBool, Ordering};
use uefi::boot::{self, AllocateType, MemoryType};

#[derive(Clone, Copy)]
pub(crate) enum TaskPool {
    Uniform,
    Prototype,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AllocationError {
    InvalidSize(u64),
    PageCount(u64),
    Firmware(uefi::Status),
}
impl core::fmt::Display for AllocationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidSize(bytes) => {
                write!(f, "task allocation size {bytes} is not whole pages")
            }
            Self::PageCount(bytes) => {
                write!(f, "task allocation size {bytes} exceeds page-count range")
            }
            Self::Firmware(status) => write!(f, "firmware task allocation: {status:?}"),
        }
    }
}
impl core::error::Error for AllocationError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ClaimError {
    Absent,
    DescriptorMismatch,
    AlreadyOwned,
}
impl core::fmt::Display for ClaimError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Absent => "task allocation is absent",
            Self::DescriptorMismatch => "task allocation descriptor differs from its owner",
            Self::AlreadyOwned => "task allocation was already claimed",
        })
    }
}
impl core::error::Error for ClaimError {}

/// Created only by the firmware allocating call below. Dropping this owner
/// keeps LOADER_DATA: these pages belong to Stela for the entire boot.
#[repr(C)]
struct Allocation {
    region: Region,
    claimed: AtomicBool,
}
impl Allocation {
    fn reserve(bytes: u64) -> Result<Self, AllocationError> {
        if bytes == 0 || !bytes.is_multiple_of(PAGE) {
            return Err(AllocationError::InvalidSize(bytes));
        }
        let count = usize::try_from(bytes / PAGE).map_err(|_| AllocationError::PageCount(bytes))?;
        let page = boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, count)
            .map_err(|error| AllocationError::Firmware(error.status()))?;
        Ok(Self {
            region: Region {
                physical: page.as_ptr() as u64,
                bytes,
            },
            claimed: AtomicBool::new(false),
        })
    }
}

/// Non-Copy allocation owners; Region in Resources remains a description.
/// Appended to Handoff, preserving its earlier field offsets. The firmware
/// reserves these pages before EBS; engine claim never reconstructs an owner.
#[repr(C)]
pub(crate) struct TaskAllocations {
    uniform: Allocation,
    prototype: Option<Allocation>,
}
impl TaskAllocations {
    pub(crate) fn reserve(uniform: u64, prototype: Option<u64>) -> Result<Self, AllocationError> {
        Ok(Self {
            uniform: Allocation::reserve(uniform)?,
            prototype: prototype.map(Allocation::reserve).transpose()?,
        })
    }
    fn allocation(&self, pool: TaskPool) -> Option<&Allocation> {
        match pool {
            TaskPool::Uniform => Some(&self.uniform),
            TaskPool::Prototype => self.prototype.as_ref(),
        }
    }
    pub(crate) fn region(&self, pool: TaskPool) -> Option<Region> {
        self.allocation(pool).map(|owner| owner.region)
    }
    #[cfg(feature = "diagnostics")]
    pub(crate) fn claim_state(&self, pool: TaskPool) -> Result<bool, ClaimError> {
        self.allocation(pool)
            .map(|owner| owner.claimed.load(Ordering::Acquire))
            .ok_or(ClaimError::Absent)
    }
    pub(crate) fn claim(
        &'static self,
        pool: TaskPool,
        expected: Region,
    ) -> Result<AllocationClaim, ClaimError> {
        let owner = self.allocation(pool).ok_or(ClaimError::Absent)?;
        let region = owner.region;
        if region.physical != expected.physical || region.bytes != expected.bytes {
            return Err(ClaimError::DescriptorMismatch);
        }
        owner
            .claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ClaimError::AlreadyOwned)?;
        Ok(AllocationClaim { owner })
    }
}

/// The one engine claim keeps the firmware allocation owner. No Drop path
/// clears its claim or returns its pages to firmware, the guest or an allocator.
pub(crate) struct AllocationClaim {
    owner: &'static Allocation,
}
impl AllocationClaim {
    #[cfg(feature = "diagnostics")]
    pub(crate) fn region(&self) -> Region {
        self.owner.region
    }
    pub(crate) fn contains(&self, physical: u64, bytes: u64) -> bool {
        physical >= self.owner.region.physical
            && physical
                .checked_add(bytes)
                .zip(
                    self.owner
                        .region
                        .physical
                        .checked_add(self.owner.region.bytes),
                )
                .is_some_and(|(end, allocation_end)| bytes != 0 && end <= allocation_end)
    }
}
