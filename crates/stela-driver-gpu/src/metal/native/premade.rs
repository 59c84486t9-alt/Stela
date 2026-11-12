//! Kernel memory a call's new image needs, made outside the service's turn
//! ([`crate::metal::deferred`], `service/shared.rs`).
//!
//! A new image takes a new kernel buffer object (nouveau's `GEM_NEW`) when
//! it takes memory of its own, which the driver prefers for compressible
//! images, or when no block of its memory type has room. Linux makes the
//! buffer on the boot processor and can take far longer than a frame to:
//! one took 159 ms, which every other call waited out in the turn. While
//! the call may defer, such an image's creation fails with `DEFERRED` and
//! leaves a job instead. For memory of its own, the job creates the image
//! and allocates and binds its memory; for a block, it allocates the block.
//! A mapped request's memory is mapped in the job too. In a later turn the
//! block joins its pool, and the image waits for its call's next run, which
//! takes it ([`Premade::take`]); the call then allocates nothing.
//!
//! Allocation is thread-safe in Vulkan, and the job's image is its own, so
//! a job needs no turn. A key whose job failed allocates in its call, so no
//! call defers forever. What a job made that no turn takes is destroyed:
//! when it is dropped unadopted, when newer images push it out, and when
//! the backend is dropped. A job never runs on a destroyed device
//! ([`super::deferral`]).
use super::{memory, objects};
use crate::metal::{
    deferred::{
        Job, Made, Owner,
        kept::{Kept, Taken},
    },
    vulkan::object::{ImageInfo, MemoryRequest},
};
use alloc::{boxed::Box, collections::BTreeSet, format, sync::Arc, vec::Vec};
use ash::vk;
use core::{
    ptr::NonNull,
    sync::atomic::{AtomicBool, Ordering},
};
use stela_crypto::{Sha256, digest::Digest};

/// Images made for calls that have not run again; past this the oldest is
/// destroyed, and its call, run again, defers once more.
const KEPT: usize = 8;

/// Keys whose jobs failed; past this they are all forgotten, which costs at
/// most one more job each.
const REMEMBERED: usize = 1 << 10;

/// What memory jobs made for later turns.
pub(super) struct Premade {
    /// Images made for calls not yet run again. Their keys are values, so
    /// one generation serves.
    images: Kept<Image>,
    failed: BTreeSet<[u8; 32]>,
}

impl Default for Premade {
    fn default() -> Self {
        Self {
            images: Kept::new(KEPT),
            failed: BTreeSet::new(),
        }
    }
}

/// An image a job created and bound to memory of its own.
pub(super) struct Image {
    pub image: vk::Image,
    pub memory: vk::DeviceMemory,
    pub memory_type: u32,
    /// The image's `VkMemoryRequirements` size, which its memory spans.
    pub size: u64,
    /// The address of the memory mapped whole.
    pub pointer: Option<NonNull<u8>>,
}

/// A block a job allocated.
pub(super) struct Block {
    pub memory_type: u32,
    pub mapped: bool,
    pub memory: vk::DeviceMemory,
    /// The block's size; an unmapped block's allocation is
    /// [`memory::allocation_bytes`] of it, which fill buffers cover.
    pub size: u64,
    pub pointer: Option<NonNull<u8>>,
}

/// What one job made, for the device whose `gone` it holds: an image or a
/// block, or nothing when the allocation failed.
pub(super) enum Kind {
    Image(Image),
    Block(Block),
}

/// What a memory job made. Dropped unadopted, it destroys what it holds
/// unless the device is gone.
pub(super) struct Making {
    pub made: Option<Kind>,
    pub gone: Arc<AtomicBool>,
    device: ash::Device,
}

// SAFETY: its handles and the address of its mapping are the job's alone
// until a turn adopts them; the device's entry points are thread-safe.
unsafe impl Send for Making {}

impl Drop for Making {
    fn drop(&mut self) {
        if let Some(made) = self.made.take()
            && !self.gone.load(Ordering::Acquire)
        {
            destroy(&self.device, made);
        }
    }
}

/// Destroys what a job made, which nothing uses.
pub(super) fn destroy(device: &ash::Device, made: Kind) {
    let (image, memory) = match made {
        Kind::Image(image) => (image.image, image.memory),
        Kind::Block(block) => (vk::Image::null(), block.memory),
    };
    // SAFETY: the job's own image and memory, which no command uses; a null
    // image is ignored.
    unsafe {
        device.destroy_image(image, None);
        device.free_memory(memory, None);
    }
}

impl Premade {
    /// The image made for the call that wants `key`.
    pub(super) fn take(&mut self, key: &[u8; 32]) -> Option<Image> {
        match self.images.take(key, 0) {
            Taken::Fresh(image) | Taken::Stale(image) => Some(image),
            Taken::Missing => None,
        }
    }

    /// Whether `key`'s job failed, so that its call allocates itself.
    pub(super) fn failed(&self, key: &[u8; 32]) -> bool {
        self.failed.contains(key)
    }

    /// Keeps a job's outcome for `key`: an image for its call's next run,
    /// with the oldest kept image past [`KEPT`] for `evict` to destroy, or
    /// the failure. A block is the caller's.
    pub(super) fn keep(
        &mut self,
        key: [u8; 32],
        made: Option<Kind>,
    ) -> (Option<Block>, Option<Image>) {
        match made {
            Some(Kind::Image(image)) => (None, self.images.keep(key, 0, image)),
            Some(Kind::Block(block)) => (Some(block), None),
            None => {
                if self.failed.len() >= REMEMBERED {
                    self.failed.clear();
                }
                self.failed.insert(key);
                (None, None)
            }
        }
    }

    /// Every image kept, for the backend's drop.
    pub(super) fn drain(&mut self) -> impl Iterator<Item = Image> + '_ {
        self.images.drain()
    }
}

/// The key of an image job for `info` and `request`: its call, run again,
/// asks for the same.
pub(super) fn image_key(info: &ImageInfo, request: MemoryRequest) -> [u8; 32] {
    Sha256::digest(format!("image {info:?} {request:?}").as_bytes()).into()
}

/// The key of a block job of `memory_type`, mapped or not.
pub(super) fn block_key(memory_type: u32, mapped: bool) -> [u8; 32] {
    Sha256::digest(format!("block {memory_type} {mapped}").as_bytes()).into()
}

/// A job that creates an image of `info` and binds it to memory of its own
/// of the first of `memory_types` that has room.
pub(super) fn image_job(
    device: &ash::Device,
    gone: Arc<AtomicBool>,
    key: [u8; 32],
    info: ImageInfo,
    memory_types: Vec<u32>,
    mapped: bool,
) -> Job {
    let device = device.clone();
    Job::new(key, Owner::Backend, move || {
        let made = (!gone.load(Ordering::Acquire))
            .then(|| make_image(&device, &info, &memory_types, mapped))
            .flatten()
            .map(Kind::Image);
        Box::new(Making { made, gone, device }) as Made
    })
}

/// A job that allocates a block of `size` bytes of `memory_type`.
pub(super) fn block_job(
    device: &ash::Device,
    gone: Arc<AtomicBool>,
    memory_type: u32,
    size: u64,
    mapped: bool,
) -> Job {
    let device = device.clone();
    let key = block_key(memory_type, mapped);
    Job::new(key, Owner::Backend, move || {
        let made = (!gone.load(Ordering::Acquire))
            .then(|| {
                let bytes = memory::allocation_bytes(size, memory::filled(mapped, false));
                let (memory, pointer) =
                    memory::allocate_raw(&device, memory_type, bytes, None, mapped).ok()?;
                Some(Kind::Block(Block {
                    memory_type,
                    mapped,
                    memory,
                    size,
                    pointer,
                }))
            })
            .flatten();
        Box::new(Making { made, gone, device }) as Made
    })
}

/// Creates an image of `info` bound to memory dedicated to it, as the turn
/// allocates an image's memory of its own
/// ([`super::NativeBackend::create_image`]): such memory has no fill
/// buffers, as images are cleared.
fn make_image(
    device: &ash::Device,
    info: &ImageInfo,
    memory_types: &[u32],
    mapped: bool,
) -> Option<Image> {
    let image = objects::image(info, |create| {
        // SAFETY: the create info and its chain outlive the call.
        unsafe { device.create_image(create, None) }.map_err(super::failure)
    })
    .ok()?;
    let (needs, _) = super::image_requirements(device, image);
    let dedicated = Some(vk::MemoryDedicatedAllocateInfo::default().image(image));
    let allowed = memory_types
        .iter()
        .copied()
        .filter(|&memory_type| needs.memory_type_bits & (1 << memory_type) != 0);
    for memory_type in allowed {
        let Ok((memory, pointer)) =
            memory::allocate_raw(device, memory_type, needs.size, dedicated, mapped)
        else {
            continue;
        };
        // SAFETY: the memory was allocated for this image's requirements.
        if unsafe { device.bind_image_memory(image, memory, 0) }.is_err() {
            // SAFETY: nothing uses the memory just allocated.
            unsafe { device.free_memory(memory, None) };
            break;
        }
        return Some(Image {
            image,
            memory,
            memory_type,
            size: needs.size,
            pointer,
        });
    }
    // SAFETY: nothing uses the image.
    unsafe { device.destroy_image(image, None) };
    None
}
