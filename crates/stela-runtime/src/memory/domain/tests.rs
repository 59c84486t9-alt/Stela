use super::super::backing::AccessPermissions;
use super::*;
use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::ptr::NonNull;

mod callbacks;
mod checked_finalization;
mod exclusive;
mod quantities;
mod reservations;

const GUEST_BASE: u64 = 0x1000;
const STORAGE_BYTES: usize = 64;
const TEST_PC: u64 = 0x1234;
const TEST_ERG_BYTES: u64 = 16;
const TEST_STRIPES: usize = 4;
const RIGHTS: AccessPermissions = AccessPermissions {
    readable: true,
    writable: true,
    executable: false,
};
const ATTRIBUTES: MappingAttributes = MappingAttributes {
    tagged: false,
    shareable: true,
};

struct Storage {
    pointer: NonNull<u8>,
    layout: Layout,
}

// SAFETY: this owner retains raw storage without lending Rust references.
unsafe impl Send for Storage {}
// SAFETY: byte accesses go through the tested execution domain.
unsafe impl Sync for Storage {}

impl Drop for Storage {
    fn drop(&mut self) {
        // SAFETY: the allocation and layout are owned here.
        unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
    }
}

fn backing() -> Arc<MemoryBacking> {
    let layout = Layout::from_size_align(STORAGE_BYTES, SCA_BYTES).unwrap();
    // SAFETY: valid nonempty layout retained for its matching deallocation.
    let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
    let storage = Arc::new(Storage { pointer, layout });
    // SAFETY: storage owns stable raw bytes and rights; no Rust references
    // alias them and tests access only through the native access boundary.
    unsafe { MemoryBacking::new(pointer, STORAGE_BYTES, RIGHTS, storage) }.unwrap()
}

fn view(
    backing: &Arc<MemoryBacking>,
    offset: usize,
    bytes: usize,
    rights: AccessPermissions,
) -> Arc<MemoryView> {
    MemoryView::new(
        Arc::clone(backing),
        GUEST_BASE + offset as u64,
        offset,
        bytes,
        rights,
    )
    .unwrap()
}

fn domain(views: Vec<Arc<MemoryView>>) -> Arc<MemoryDomain> {
    MemoryDomain::new(
        MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap(),
        views.into_iter().map(|view| (view, ATTRIBUTES)).collect(),
        TargetCpu::detect(),
    )
    .unwrap()
}

#[derive(Default)]
struct Policy {
    unavailable: bool,
    reject: Option<u64>,
    checked: Vec<(u64, usize)>,
    checked_flags: Vec<u32>,
}

impl DataPolicy for Policy {
    fn validate_execution(&self, _required_flags: u32) -> Result<(), MemoryStatus> {
        if self.unavailable {
            Err(MemoryStatus::Unsupported)
        } else {
            Ok(())
        }
    }
    fn translate(&self, raw_address: u64) -> Result<u64, MemoryStatus> {
        Ok(raw_address)
    }

    fn check(&mut self, access: DataAccess<'_>) -> Result<(), MemoryStatus> {
        self.checked.push((access.raw_address, access.bytes));
        self.checked_flags.push(access.flags);
        if self.reject == Some(access.raw_address) {
            Err(MemoryStatus::TagCheck)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
struct Outcome {
    status: u32,
    fault_kind: u32,
    fault_address: u64,
    fault_pc: u64,
    completed: u64,
}

fn invoke(
    thread: &mut MemoryThread<Policy>,
    address: u64,
    bytes: &mut [u8],
    flags: u32,
) -> Outcome {
    let request = MemoryRequest {
        address,
        data: bytes.as_mut_ptr(),
        bytes: bytes.len() as u32,
        flags,
        pc: TEST_PC,
    };
    // SAFETY: the synchronous callback receives valid ABI objects and private
    // staging disjoint from raw guest storage, with no retained pointers.
    unsafe {
        thread.with_view(|context| {
            let status = (context.callback)(context, &request);
            Outcome {
                status,
                fault_kind: context.fault_kind,
                fault_address: context.fault_address,
                fault_pc: context.fault_pc,
                completed: context.completed_bytes,
            }
        })
    }
}

fn snapshot(backing: &MemoryBacking, bytes: usize) -> Vec<u8> {
    (0..bytes)
        .map(|offset| {
            let pointer = backing.host_pointer(offset, 1, AccessKind::Read).unwrap();
            // SAFETY: tests inspect after synchronous execution; no byte access
            // overlaps this exact live one-byte native read.
            unsafe { access::read_part(pointer.as_ptr(), 1, TargetCpu::Baseline) }.unwrap() as u8
        })
        .collect()
}

fn reservation_access(
    domain: &MemoryDomain,
    offset: u64,
) -> monitor::Access<MemoryBacking, MemoryView, MappingAttributes> {
    let registered = &domain.registered_views()[0];
    monitor::Access::new(
        Arc::clone(registered.view.backing()),
        Arc::clone(&registered.monitor),
        offset,
        1,
        monitor::Shape::Scalar,
    )
    .unwrap()
}
