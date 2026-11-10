//! Zeroing of the memory a new resource takes.
//!
//! Blocks, recycled textures and the kernel's own VRAM hand out memory that
//! another resource, possibly another client's, used before. Metal fills a
//! new buffer with zero (`newBufferWithLength:options:`), and no client may
//! read bytes another resource left. So:
//!
//! - mapped memory is zeroed by the host when a buffer takes it;
//! - other memory a buffer or heap takes is filled with zero at the start of
//!   the next submission, through buffers over each `VkDeviceMemory`;
//! - new and recycled images are cleared there too, except subresources the
//!   submission's leading commands overwrite whole before any command can
//!   read them, or that a host image copy wrote whole. Images clear rather
//!   than fill: a compressed image's zero bytes are not zero texels.
use crate::metal::vulkan::{
    AttachmentLoadOp, AttachmentStoreOp, ImageAspects,
    command::{Command, Rendering, Subresource},
    object::{ImageInfo, SubresourceRange},
};
use alloc::{collections::BTreeMap, vec, vec::Vec};
use ash::vk::{self, Handle};
use core::ops::Range;

/// What unmapped memory without a dedicated resource is allocated in
/// multiples of, so its fill buffers cover it whole; NVK rounds every
/// allocation to its 4 KiB bind alignment anyway.
pub(super) const FILL_ALIGN: u64 = 4096;

/// A buffer over part of a `VkDeviceMemory`, which zero fills write through.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Chunk {
    pub buffer: vk::Buffer,
    /// Its first byte in the memory.
    pub start: u64,
    pub len: u64,
}

/// A range of a `VkDeviceMemory` to fill with zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Fill {
    pub memory: u64,
    pub offset: u64,
    pub size: u64,
}

/// A `vkCmdFillBuffer` of zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct BufferFill {
    pub buffer: vk::Buffer,
    pub offset: u64,
    pub size: u64,
}

/// What a submission zeroes before its commands.
#[derive(Clone, Debug, Default)]
pub(super) struct Pending {
    pub fills: Vec<Fill>,
    /// Buffers in memory dedicated to them, filled whole through themselves.
    pub buffers: Vec<vk::Buffer>,
    pub images: BTreeMap<u64, Unzeroed>,
}

/// A view's image and subresources, which render pass attachments name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ViewRange {
    pub image: u64,
    pub range: SubresourceRange,
}

pub(super) struct Zeroing {
    /// The fill buffers over each unmapped `VkDeviceMemory`, by handle.
    chunks: BTreeMap<u64, Vec<Chunk>>,
    pub pending: Pending,
    pub views: BTreeMap<u64, ViewRange>,
    /// The most one fill buffer spans: `maxBufferSize`, in `FILL_ALIGN`s.
    chunk_bytes: u64,
    log: fn(&str),
    reported: bool,
}

impl Zeroing {
    pub(super) fn new(max_buffer_size: u64, log: fn(&str)) -> Self {
        Self {
            chunks: BTreeMap::new(),
            pending: Pending::default(),
            views: BTreeMap::new(),
            chunk_bytes: (max_buffer_size / FILL_ALIGN * FILL_ALIGN).max(FILL_ALIGN),
            log,
            reported: false,
        }
    }

    fn report(&mut self) {
        if !self.reported {
            self.reported = true;
            (self.log)(
                "Stela GPU: unsupported: memory no transfer buffer can bind is not zeroed \
                 for new resources",
            );
        }
    }

    /// Creates the fill buffers over `size` bytes (a multiple of
    /// [`FILL_ALIGN`]) of `memory`, of `memory_type`. Memory they cannot
    /// cover is reported once and left as it is.
    pub(super) fn cover(
        &mut self,
        device: &ash::Device,
        memory: vk::DeviceMemory,
        memory_type: u32,
        size: u64,
    ) {
        let mut chunks = Vec::new();
        let mut start = 0;
        while start < size {
            let len = (size - start).min(self.chunk_bytes);
            match fill_buffer(device, memory, memory_type, start, len) {
                Some(buffer) => chunks.push(Chunk { buffer, start, len }),
                None => {
                    for chunk in chunks {
                        // SAFETY: no command used the buffer yet.
                        unsafe { device.destroy_buffer(chunk.buffer, None) };
                    }
                    self.report();
                    return;
                }
            }
            start += len;
        }
        self.chunks.insert(memory.as_raw(), chunks);
    }

    /// Forgets `memory`, which is being freed: destroys its fill buffers
    /// and drops its pending fills. Every recorded fill completed, as the
    /// memory is freed only after the work that could use it.
    pub(super) fn forget(&mut self, device: &ash::Device, memory: vk::DeviceMemory) {
        for chunk in self.release(memory.as_raw()) {
            // SAFETY: as above, no pending command uses the buffer.
            unsafe { device.destroy_buffer(chunk.buffer, None) };
        }
    }

    /// Drops the pending fills of memory `raw` and answers its fill
    /// buffers.
    fn release(&mut self, raw: u64) -> Vec<Chunk> {
        self.pending.fills.retain(|fill| fill.memory != raw);
        self.chunks.remove(&raw).unwrap_or_default()
    }

    /// Destroys every fill buffer, once the device idles.
    pub(super) fn destroy(&mut self, device: &ash::Device) {
        for chunk in core::mem::take(&mut self.chunks).into_values().flatten() {
            // SAFETY: the device is idle.
            unsafe { device.destroy_buffer(chunk.buffer, None) };
        }
    }

    /// Fills `size` bytes at `offset` of unmapped `memory` with zero at the
    /// start of the next submission.
    pub(super) fn fill(&mut self, memory: vk::DeviceMemory, offset: u64, size: u64) {
        let raw = memory.as_raw();
        if !self.chunks.contains_key(&raw) {
            self.report();
            return;
        }
        self.pending.fills.push(Fill {
            memory: raw,
            offset,
            size,
        });
    }

    /// The buffer fills of `pending`.
    pub(super) fn buffer_fills(&self, pending: &Pending) -> Vec<BufferFill> {
        let whole = pending.buffers.iter().map(|&buffer| BufferFill {
            buffer,
            offset: 0,
            size: vk::WHOLE_SIZE,
        });
        pending
            .fills
            .iter()
            .flat_map(|fill| {
                split(
                    fill,
                    self.chunks.get(&fill.memory).map_or(&[], Vec::as_slice),
                )
            })
            .chain(whole)
            .collect()
    }

    #[cfg(test)]
    pub(super) fn insert_chunks(&mut self, memory: u64, chunks: Vec<Chunk>) {
        self.chunks.insert(memory, chunks);
    }
}

/// A transfer-destination buffer over `len` bytes of `memory` at `start`;
/// `None` when the memory cannot hold one there.
fn fill_buffer(
    device: &ash::Device,
    memory: vk::DeviceMemory,
    memory_type: u32,
    start: u64,
    len: u64,
) -> Option<vk::Buffer> {
    let info = vk::BufferCreateInfo::default()
        .size(len)
        .usage(vk::BufferUsageFlags::TRANSFER_DST)
        .sharing_mode(vk::SharingMode::EXCLUSIVE);
    // SAFETY: the create info outlives the call.
    let buffer = unsafe { device.create_buffer(&info, None) }.ok()?;
    // SAFETY: the buffer was just created.
    let needs = unsafe { device.get_buffer_memory_requirements(buffer) };
    let fits = needs.memory_type_bits & 1 << memory_type != 0
        && start.is_multiple_of(needs.alignment.max(1))
        && needs.size <= len;
    // SAFETY: the buffer is unbound, and `start + len` lies in the memory.
    if fits && unsafe { device.bind_buffer_memory(buffer, memory, start) }.is_ok() {
        return Some(buffer);
    }
    // SAFETY: no command used the buffer.
    unsafe { device.destroy_buffer(buffer, None) };
    None
}

/// The fills of `fill` through `chunks`, sizes rounded up to whole words:
/// buffer places are word aligned, and whole allocations are rounded to
/// [`FILL_ALIGN`].
pub(super) fn split(fill: &Fill, chunks: &[Chunk]) -> Vec<BufferFill> {
    let end = fill.offset + fill.size;
    chunks
        .iter()
        .filter_map(|chunk| {
            let start = fill.offset.max(chunk.start);
            let stop = end.min(chunk.start + chunk.len);
            (start < stop).then(|| BufferFill {
                buffer: chunk.buffer,
                offset: start - chunk.start,
                size: (stop - start)
                    .next_multiple_of(4)
                    .min(chunk.start + chunk.len - start),
            })
        })
        .collect()
}

/// What a new image's subresource may hold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    /// Bytes another resource left.
    Stale,
    /// Stale, and a command reads it before writing it.
    Read,
    /// Written whole before anything reads it.
    Written,
}

/// A new or recycled image and what of it still needs zeroing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Unzeroed {
    pub aspects: ImageAspects,
    extent: [u32; 3],
    levels: u32,
    layers: u32,
    /// By level, then layer.
    states: Vec<State>,
}

/// Stale layers of one level.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct StaleRun {
    pub level: u32,
    pub layers: Range<u32>,
}

impl Unzeroed {
    pub(super) fn new(info: &ImageInfo) -> Self {
        let levels = info.mip_levels.max(1);
        let layers = info.array_layers.max(1);
        Self {
            aspects: info.format.aspects(),
            extent: info.extent,
            levels,
            layers,
            states: vec![State::Stale; (levels * layers) as usize],
        }
    }

    pub(super) fn level_extent(&self, level: u32) -> [u32; 3] {
        self.extent.map(|extent| (extent >> level.min(31)).max(1))
    }

    fn layers_of(&self, first: u32, count: u32) -> Range<u32> {
        first.min(self.layers)..first.saturating_add(count).min(self.layers)
    }

    /// Moves the stale subresources of `level` and `layers` to `to`.
    fn set(&mut self, level: u32, layers: Range<u32>, to: State) {
        if level >= self.levels {
            return;
        }
        let layers = self.layers_of(layers.start, layers.end.saturating_sub(layers.start));
        for layer in layers {
            let state = &mut self.states[(level * self.layers + layer) as usize];
            if *state == State::Stale {
                *state = to;
            }
        }
    }

    /// A write of `extent` at `offset` in `sub`: it writes whole
    /// subresources when it covers their level and every aspect.
    pub(super) fn write(&mut self, sub: Subresource, offset: [i32; 3], extent: [u32; 3]) {
        if self.whole(sub, offset, extent) {
            let layers = self.layers_of(sub.base_array_layer, sub.layer_count);
            self.set(sub.mip_level, layers, State::Written);
        }
    }

    /// Whether `extent` at `offset` in `sub` covers its level and every
    /// aspect.
    pub(super) fn whole(&self, sub: Subresource, offset: [i32; 3], extent: [u32; 3]) -> bool {
        sub.aspects.contains(self.aspects)
            && offset == [0; 3]
            && extent == self.level_extent(sub.mip_level)
    }

    /// A read of `sub`, which must find zero where nothing wrote.
    pub(super) fn read(&mut self, sub: Subresource) {
        let layers = self.layers_of(sub.base_array_layer, sub.layer_count);
        self.set(sub.mip_level, layers, State::Read);
    }

    /// The stale level and layers of `sub`.
    pub(super) fn stale_in(&self, sub: Subresource) -> Vec<(u32, u32)> {
        if sub.mip_level >= self.levels {
            return Vec::new();
        }
        self.layers_of(sub.base_array_layer, sub.layer_count)
            .filter(|&layer| {
                self.states[(sub.mip_level * self.layers + layer) as usize] != State::Written
            })
            .map(|layer| (sub.mip_level, layer))
            .collect()
    }

    /// Records that the host zeroed or wrote `level` and `layer` whole.
    pub(super) fn written(&mut self, level: u32, layer: u32) {
        self.set(level, layer..layer + 1, State::Written);
    }

    /// The runs of layers nothing wrote whole, which a clear zeroes.
    pub(super) fn stale_runs(&self) -> Vec<StaleRun> {
        let mut runs: Vec<StaleRun> = Vec::new();
        for level in 0..self.levels {
            for layer in 0..self.layers {
                if self.states[(level * self.layers + layer) as usize] == State::Written {
                    continue;
                }
                match runs.last_mut() {
                    Some(run) if run.level == level && run.layers.end == layer => {
                        run.layers.end += 1;
                    }
                    _ => runs.push(StaleRun {
                        level,
                        layers: layer..layer + 1,
                    }),
                }
            }
        }
        runs
    }

    /// Whether nothing of the image was written whole.
    pub(super) fn all_stale(&self) -> bool {
        self.states.iter().all(|&state| state != State::Written)
    }
}

/// Marks what the leading commands of a submission write whole before any
/// command reads it. Draws and dispatches may read any image through the
/// descriptor heap, so the scan stops before the first of them, and at the
/// first render pass once its load operations are seen: a clear that
/// stores covers its attachments' level and layers when the render area is
/// the whole level.
pub(super) fn first_writes(
    commands: &[Command],
    views: &BTreeMap<u64, ViewRange>,
    images: &mut BTreeMap<u64, Unzeroed>,
) {
    for command in commands {
        match command {
            Command::Barrier(_)
            | Command::RegionBarrier(_)
            | Command::BindPipeline { .. }
            | Command::PushConstants(_)
            | Command::SetViewports(_)
            | Command::SetScissors(_)
            | Command::SetDepthBias { .. }
            | Command::SetBlendConstants(_)
            | Command::SetStencilReference { .. }
            | Command::SetDepthStencil(_)
            | Command::SetCullMode(_)
            | Command::SetFrontFace(_)
            | Command::SetPrimitiveTopology(_)
            | Command::SetPrimitiveRestart(_)
            | Command::SetRasterizerDiscard(_)
            | Command::SetPolygonMode(_)
            | Command::SetDepthClamp(_)
            | Command::SetSampleLocations { .. }
            | Command::BindVertexBuffers { .. }
            | Command::BindIndexBuffer { .. }
            | Command::CopyBuffer { .. }
            | Command::CopyBufferRegions { .. }
            | Command::FillBuffer { .. }
            | Command::ResetQueryPool { .. }
            | Command::WriteTimestamp { .. }
            | Command::CopyQueryResults { .. } => {}
            Command::CopyBufferToImage { dst, region, .. } => {
                if let Some(image) = images.get_mut(&dst.0) {
                    image.write(region.subresource, region.offset, region.extent);
                }
            }
            Command::ClearColorImage { image, .. } => {
                if let Some(image) = images.get_mut(&image.0) {
                    let level = Subresource {
                        aspects: ImageAspects::COLOR,
                        mip_level: 0,
                        base_array_layer: 0,
                        layer_count: 1,
                    };
                    let extent = image.level_extent(0);
                    image.write(level, [0; 3], extent);
                }
            }
            Command::CopyImageToBuffer { src, region, .. } => {
                if let Some(image) = images.get_mut(&src.0) {
                    image.read(region.subresource);
                }
            }
            Command::CopyImage { src, dst, regions } => {
                for region in regions {
                    if let Some(image) = images.get_mut(&src.0) {
                        image.read(region.src);
                    }
                }
                for region in regions {
                    if let Some(image) = images.get_mut(&dst.0) {
                        image.write(region.dst, region.dst_offset, region.extent);
                    }
                }
            }
            Command::BlitImage {
                src, dst, regions, ..
            } => {
                for region in regions {
                    if let Some(image) = images.get_mut(&src.0) {
                        image.read(region.src);
                    }
                }
                for region in regions {
                    if let Some(image) = images.get_mut(&dst.0) {
                        let [a, b] = region.dst_bounds;
                        let offset = [0, 1, 2].map(|axis| a[axis].min(b[axis]));
                        let extent = [0, 1, 2].map(|axis| a[axis].abs_diff(b[axis]));
                        image.write(region.dst, offset, extent);
                    }
                }
            }
            Command::BeginRendering(rendering) => {
                pass(rendering, views, images);
                return;
            }
            _ => return,
        }
    }
}

/// Marks the attachments a render pass clears and stores whole.
fn pass(
    rendering: &Rendering,
    views: &BTreeMap<u64, ViewRange>,
    images: &mut BTreeMap<u64, Unzeroed>,
) {
    let attachments = rendering
        .color
        .iter()
        .flatten()
        .map(|attachment| (attachment, ImageAspects::COLOR))
        .chain(rendering.depth.iter().map(|a| (a, ImageAspects::DEPTH)))
        .chain(rendering.stencil.iter().map(|a| (a, ImageAspects::STENCIL)));
    // The aspects cleared whole, by image, level and layers.
    let mut cleared: Vec<(u64, u32, Range<u32>, ImageAspects)> = Vec::new();
    for (attachment, aspect) in attachments {
        let Some(view) = views.get(&attachment.view.0) else {
            continue;
        };
        let Some(image) = images.get(&view.image) else {
            continue;
        };
        let level = view.range.base_mip_level;
        let range = view.range;
        let whole = attachment.load_op == AttachmentLoadOp::Clear
            && attachment.store_op == AttachmentStoreOp::Store
            && image.level_extent(level) == [rendering.extent[0], rendering.extent[1], 1]
            && rendering.layer_count >= range.layer_count;
        if !whole {
            continue;
        }
        let layers = image.layers_of(range.base_array_layer, range.layer_count);
        match cleared
            .iter_mut()
            .find(|(i, l, r, _)| *i == view.image && *l == level && *r == layers)
        {
            Some(entry) => entry.3 |= aspect,
            None => cleared.push((view.image, level, layers, aspect)),
        }
    }
    for (image, level, layers, aspects) in cleared {
        if let Some(image) = images.get_mut(&image)
            && aspects.contains(image.aspects)
        {
            image.set(level, layers, State::Written);
        }
    }
}

#[cfg(test)]
mod tests;
