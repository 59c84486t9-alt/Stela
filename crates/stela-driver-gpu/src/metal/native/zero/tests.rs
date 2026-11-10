use super::{
    BufferFill, Chunk, FILL_ALIGN, Fill, Unzeroed, ViewRange, Zeroing, first_writes, split,
};
use crate::metal::{
    native::blocks::{Blocks, Candidate, Needs, Place, Purpose, Resident, Source, Tiling},
    pass::ClearValue,
    vulkan::{
        AttachmentLoadOp, AttachmentStoreOp, Format, ImageAspects, ImageCreate, ImageTiling,
        ImageType, ImageUsage, SampleCounts,
        command::{Attachment, BufferImageCopy, Command, ImageCopy, Rendering, Subresource},
        object::{Buffer, Image, ImageInfo, ImageView, SubresourceRange},
    },
};
use alloc::{collections::BTreeMap, vec, vec::Vec};
use ash::vk::{self, Handle};

const MIB: u64 = 1 << 20;
const BLOCK: u64 = 16 * MIB;

/// Memory as bytes: a new allocation holds what VRAM the kernel does not
/// clear holds, never zero.
#[derive(Default)]
struct Bytes {
    memories: BTreeMap<u32, Vec<u8>>,
    next: u32,
}

impl Source for Bytes {
    type Memory = u32;
    type Error = ();

    fn allocate(&mut self, _: u32, size: u64, _: Purpose) -> Result<u32, ()> {
        self.next += 1;
        self.memories.insert(self.next, vec![0xee; size as usize]);
        Ok(self.next)
    }

    fn free(&mut self, memory: u32) {
        self.memories.remove(&memory);
    }
}

/// One client's view of the device's blocks, as the native backend hands
/// them out: a buffer's place is filled with zero before the next
/// submission, through the fill buffer over its block.
struct Device {
    blocks: Blocks<u32>,
    bytes: Bytes,
    zeroing: Zeroing,
}

impl Device {
    fn new() -> Self {
        Self {
            blocks: Blocks::new(1024),
            bytes: Bytes::default(),
            zeroing: Zeroing::new(1 << 32, |_| {}),
        }
    }

    fn place(&mut self, size: u64, tiling: Tiling) -> Place {
        let needs = Needs {
            size,
            alignment: 256,
            tiling,
            own: false,
        };
        let candidate = Candidate {
            memory_type: 0,
            block_bytes: BLOCK,
            atom: 1,
        };
        let resident = self
            .blocks
            .allocate(&mut self.bytes, needs, false, &[candidate]);
        let Ok(Resident::Placed(place)) = resident else {
            panic!("not placed: {resident:?}");
        };
        let memory = self.blocks.memory(place.block).unwrap().0;
        let raw = u64::from(memory);
        self.zeroing.insert_chunks(
            raw,
            vec![Chunk {
                buffer: vk::Buffer::from_raw(raw << 8),
                start: 0,
                len: BLOCK,
            }],
        );
        place
    }

    fn new_buffer(&mut self, size: u64) -> Place {
        let place = self.place(size, Tiling::Linear);
        let memory = self.blocks.memory(place.block).unwrap().0;
        self.zeroing.fill(
            vk::DeviceMemory::from_raw(u64::from(memory)),
            place.offset,
            place.size,
        );
        place
    }

    fn bytes(&mut self, place: Place) -> &mut [u8] {
        let memory = self.blocks.memory(place.block).unwrap().0;
        let bytes = self.bytes.memories.get_mut(&memory).unwrap();
        &mut bytes[place.offset as usize..(place.offset + place.size) as usize]
    }

    /// Runs the next submission's zero fills.
    fn submit(&mut self) {
        let pending = core::mem::take(&mut self.zeroing.pending);
        for fill in self.zeroing.buffer_fills(&pending) {
            let memory = (fill.buffer.as_raw() >> 8) as u32;
            let bytes = self.bytes.memories.get_mut(&memory).unwrap();
            bytes[fill.offset as usize..(fill.offset + fill.size) as usize].fill(0);
        }
    }
}

fn info(format: Format, extent: [u32; 3], levels: u32, layers: u32) -> ImageInfo {
    ImageInfo {
        flags: ImageCreate::EMPTY,
        image_type: if extent[2] > 1 {
            ImageType::D3
        } else {
            ImageType::D2
        },
        format,
        extent,
        mip_levels: levels,
        array_layers: layers,
        samples: SampleCounts::C1,
        tiling: ImageTiling::Optimal,
        usage: ImageUsage::TRANSFER_DST,
        view_formats: Vec::new(),
        linear: None,
    }
}

fn color(level: u32, first: u32, count: u32) -> Subresource {
    Subresource {
        aspects: ImageAspects::COLOR,
        mip_level: level,
        base_array_layer: first,
        layer_count: count,
    }
}

#[test]
fn a_freed_range_reads_zero_as_another_client_s_new_buffer() {
    let mut device = Device::new();
    // The first client's buffer, written and freed.
    let first = device.new_buffer(MIB);
    device.submit();
    device.bytes(first).fill(0xa5);
    assert!(device.blocks.release(&mut device.bytes, first));
    // Another client's buffer takes the same range, and a larger one too.
    let second = device.new_buffer(MIB / 2);
    let third = device.new_buffer(3 * MIB);
    assert_eq!(second.offset, first.offset, "first fit reuses the range");
    assert!(device.bytes(second).iter().any(|&byte| byte != 0));
    device.submit();
    assert!(device.bytes(second).iter().all(|&byte| byte == 0));
    assert!(device.bytes(third).iter().all(|&byte| byte == 0));
}

#[test]
fn a_new_block_s_buffer_reads_zero() {
    let mut device = Device::new();
    let place = device.new_buffer(4096);
    assert!(device.bytes(place).iter().all(|&byte| byte == 0xee));
    device.submit();
    assert!(device.bytes(place).iter().all(|&byte| byte == 0));
}

#[test]
fn freeing_memory_drops_its_pending_fills() {
    let mut zeroing = Zeroing::new(1 << 32, |_| {});
    let chunk = Chunk {
        buffer: vk::Buffer::from_raw(70),
        start: 0,
        len: FILL_ALIGN,
    };
    zeroing.insert_chunks(7, vec![chunk]);
    zeroing.insert_chunks(8, Vec::new());
    zeroing.fill(vk::DeviceMemory::from_raw(7), 0, 4096);
    zeroing.fill(vk::DeviceMemory::from_raw(8), 0, 4096);
    assert_eq!(zeroing.release(7), [chunk]);
    assert_eq!(
        zeroing.pending.fills,
        [Fill {
            memory: 8,
            offset: 0,
            size: 4096
        }]
    );
    assert_eq!(zeroing.release(7), []);
}

#[test]
fn memory_without_fill_buffers_is_reported_once() {
    use core::sync::atomic::{AtomicUsize, Ordering};
    static REPORTS: AtomicUsize = AtomicUsize::new(0);
    let mut zeroing = Zeroing::new(1 << 32, |_| {
        REPORTS.fetch_add(1, Ordering::Relaxed);
    });
    zeroing.fill(vk::DeviceMemory::from_raw(3), 0, 4096);
    zeroing.fill(vk::DeviceMemory::from_raw(4), 0, 4096);
    assert!(zeroing.pending.fills.is_empty());
    assert_eq!(REPORTS.load(Ordering::Relaxed), 1);
}

#[test]
fn fills_split_across_chunks_and_cover_the_whole_range() {
    let chunks = [
        Chunk {
            buffer: vk::Buffer::from_raw(1),
            start: 0,
            len: 4 * FILL_ALIGN,
        },
        Chunk {
            buffer: vk::Buffer::from_raw(2),
            start: 4 * FILL_ALIGN,
            len: 2 * FILL_ALIGN,
        },
    ];
    let fill = Fill {
        memory: 9,
        offset: 3 * FILL_ALIGN,
        size: 2 * FILL_ALIGN + 6,
    };
    assert_eq!(
        split(&fill, &chunks),
        [
            BufferFill {
                buffer: vk::Buffer::from_raw(1),
                offset: 3 * FILL_ALIGN,
                size: FILL_ALIGN,
            },
            BufferFill {
                buffer: vk::Buffer::from_raw(2),
                offset: 0,
                size: FILL_ALIGN + 8,
            },
        ]
    );
}

#[test]
fn dedicated_buffers_fill_whole_through_themselves() {
    let mut zeroing = Zeroing::new(1 << 32, |_| {});
    zeroing.pending.buffers.push(vk::Buffer::from_raw(5));
    let pending = core::mem::take(&mut zeroing.pending);
    assert_eq!(
        zeroing.buffer_fills(&pending),
        [BufferFill {
            buffer: vk::Buffer::from_raw(5),
            offset: 0,
            size: vk::WHOLE_SIZE,
        }]
    );
}

/// A private texture in a freed range is cleared whole when the next
/// submission reads it first.
#[test]
fn a_private_texture_in_a_freed_range_is_cleared_before_a_read() {
    let mut device = Device::new();
    let buffer = device.new_buffer(MIB);
    device.submit();
    device.bytes(buffer).fill(0xa5);
    device.blocks.release(&mut device.bytes, buffer);
    let place = device.place(64 * 64 * 4, Tiling::Optimal);
    assert!(device.bytes(place).iter().any(|&byte| byte != 0));
    let image = Unzeroed::new(&info(Format::R8G8B8A8Unorm, [64, 64, 1], 3, 2));
    let mut images = BTreeMap::from([(5, image)]);
    let read = [Command::CopyImageToBuffer {
        src: Image(5),
        dst: Buffer(1),
        region: copy(color(0, 0, 1), [64, 64, 1]),
    }];
    first_writes(&read, &BTreeMap::new(), &mut images);
    assert!(images[&5].all_stale());
    assert_eq!(images[&5].stale_runs().len(), 3, "every level, both layers");
}

fn copy(subresource: Subresource, extent: [u32; 3]) -> BufferImageCopy {
    BufferImageCopy {
        buffer_offset: 0,
        buffer_row_length: 0,
        buffer_image_height: 0,
        subresource,
        offset: [0; 3],
        extent,
    }
}

/// Shared and managed textures the host copies to: a partial write or a
/// read zeroes the subresources it reaches first; a whole write needs none.
#[test]
fn host_copies_zero_what_they_do_not_write_whole() {
    let mut image = Unzeroed::new(&info(Format::R8G8B8A8Unorm, [16, 8, 1], 2, 2));
    assert!(image.whole(color(0, 0, 2), [0; 3], [16, 8, 1]));
    assert!(!image.whole(color(0, 0, 1), [0; 3], [8, 8, 1]));
    image.write(color(0, 0, 1), [0; 3], [16, 8, 1]);
    assert_eq!(image.stale_in(color(0, 0, 2)), [(0, 1)]);
    assert_eq!(image.stale_in(color(1, 0, 2)), [(1, 0), (1, 1)]);
    image.written(1, 0);
    assert_eq!(image.stale_in(color(1, 0, 1)), []);
    assert_eq!(
        image
            .stale_runs()
            .into_iter()
            .map(|run| (run.level, run.layers))
            .collect::<Vec<_>>(),
        [(0, 1..2), (1, 1..2)]
    );
}

fn attachment(view: u64, load_op: AttachmentLoadOp, store_op: AttachmentStoreOp) -> Attachment {
    Attachment {
        view: ImageView(view),
        resolve: None,
        load_op,
        store_op,
        clear: ClearValue::Float([0.0; 4]),
    }
}

fn rendering(extent: [u32; 2], color: Vec<Option<Attachment>>) -> Rendering {
    Rendering {
        extent,
        layer_count: 1,
        color,
        depth: None,
        stencil: None,
    }
}

fn view(image: u64, aspects: ImageAspects, level: u32) -> ViewRange {
    ViewRange {
        image,
        range: SubresourceRange {
            aspects,
            base_mip_level: level,
            level_count: 1,
            base_array_layer: 0,
            layer_count: 1,
        },
    }
}

/// A recycled render target whose first use is a pass that clears and
/// stores it whole needs no clear of its own.
#[test]
fn a_leading_clear_pass_overwrites_its_attachments() {
    let views = BTreeMap::from([
        (10, view(1, ImageAspects::COLOR, 0)),
        (11, view(2, ImageAspects::COLOR, 0)),
        (12, view(3, ImageAspects::COLOR, 0)),
        (13, view(4, ImageAspects::COLOR, 0)),
    ]);
    let target = || Unzeroed::new(&info(Format::R8G8B8A8Unorm, [32, 16, 1], 1, 1));
    let mut images: BTreeMap<_, _> = (1..=4).map(|image| (image, target())).collect();
    let pass = rendering(
        [32, 16],
        vec![
            Some(attachment(
                10,
                AttachmentLoadOp::Clear,
                AttachmentStoreOp::Store,
            )),
            Some(attachment(
                11,
                AttachmentLoadOp::Load,
                AttachmentStoreOp::Store,
            )),
            Some(attachment(
                12,
                AttachmentLoadOp::DontCare,
                AttachmentStoreOp::Store,
            )),
            Some(attachment(
                13,
                AttachmentLoadOp::Clear,
                AttachmentStoreOp::DontCare,
            )),
        ],
    );
    first_writes(&[Command::BeginRendering(pass)], &views, &mut images);
    assert!(images[&1].stale_runs().is_empty(), "cleared and stored");
    for image in 2..=4 {
        assert!(images[&image].all_stale(), "image {image} may expose bytes");
    }
}

#[test]
fn a_clear_pass_over_part_of_a_level_or_after_a_draw_overwrites_nothing() {
    let views = BTreeMap::from([(10, view(1, ImageAspects::COLOR, 0))]);
    let target = Unzeroed::new(&info(Format::R8G8B8A8Unorm, [32, 16, 1], 1, 1));
    let cleared = || {
        rendering(
            [32, 16],
            vec![Some(attachment(
                10,
                AttachmentLoadOp::Clear,
                AttachmentStoreOp::Store,
            ))],
        )
    };
    let mut images = BTreeMap::from([(1, target.clone())]);
    let mut part = cleared();
    part.extent = [16, 16];
    first_writes(&[Command::BeginRendering(part)], &views, &mut images);
    assert!(images[&1].all_stale());

    let mut images = BTreeMap::from([(1, target)]);
    let commands = [
        Command::Dispatch([1, 1, 1]),
        Command::BeginRendering(cleared()),
    ];
    first_writes(&commands, &views, &mut images);
    assert!(images[&1].all_stale(), "the dispatch may read the target");
}

#[test]
fn a_depth_stencil_target_needs_both_aspects_cleared() {
    let views = BTreeMap::from([
        (10, view(1, ImageAspects::DEPTH, 0)),
        (11, view(1, ImageAspects::STENCIL, 0)),
    ]);
    let target = Unzeroed::new(&info(Format::D32SfloatS8Uint, [8, 8, 1], 1, 1));
    let clear = |view| attachment(view, AttachmentLoadOp::Clear, AttachmentStoreOp::Store);
    let mut depth_only = rendering([8, 8], Vec::new());
    depth_only.depth = Some(clear(10));
    let mut images = BTreeMap::from([(1, target.clone())]);
    first_writes(
        &[Command::BeginRendering(depth_only.clone())],
        &views,
        &mut images,
    );
    assert!(images[&1].all_stale());

    let mut both = depth_only;
    both.stencil = Some(clear(11));
    let mut images = BTreeMap::from([(1, target)]);
    first_writes(&[Command::BeginRendering(both)], &views, &mut images);
    assert!(images[&1].stale_runs().is_empty());
}

#[test]
fn whole_copies_overwrite_and_a_read_first_keeps_the_clear() {
    let mut images = BTreeMap::from([
        (
            1,
            Unzeroed::new(&info(Format::R8G8B8A8Unorm, [16, 16, 1], 2, 1)),
        ),
        (
            2,
            Unzeroed::new(&info(Format::R8G8B8A8Unorm, [16, 16, 1], 1, 1)),
        ),
    ]);
    let commands = [
        // Level 0 whole, level 1 in part.
        Command::CopyBufferToImage {
            src: Buffer(9),
            dst: Image(1),
            region: copy(color(0, 0, 1), [16, 16, 1]),
        },
        Command::CopyBufferToImage {
            src: Buffer(9),
            dst: Image(1),
            region: copy(color(1, 0, 1), [4, 8, 1]),
        },
        // Image 2 is read, then written whole.
        Command::CopyImage {
            src: Image(2),
            dst: Image(2),
            regions: vec![ImageCopy {
                src: color(0, 0, 1),
                src_offset: [0; 3],
                dst: color(0, 0, 1),
                dst_offset: [0; 3],
                extent: [16, 16, 1],
            }],
        },
    ];
    first_writes(&commands, &BTreeMap::new(), &mut images);
    assert_eq!(
        images[&1]
            .stale_runs()
            .into_iter()
            .map(|run| run.level)
            .collect::<Vec<_>>(),
        [1]
    );
    assert!(images[&2].all_stale());
}

#[test]
fn layer_ranges_past_the_image_are_clamped() {
    let mut image = Unzeroed::new(&info(Format::R8G8B8A8Unorm, [4, 4, 1], 1, 3));
    image.write(color(0, 1, u32::MAX), [0; 3], [4, 4, 1]);
    assert_eq!(image.stale_in(color(0, 0, u32::MAX)), [(0, 0)]);
}
