use super::*;
use crate::metal::{
    abi::{
        CpuCacheMode, HazardTrackingMode, LoadAction, MultisampleDepthResolveFilter,
        MultisampleStencilResolveFilter, ResourceOptions, StorageMode, StoreAction,
        StoreActionOptions, SwizzleChannels, TextureType, VisibilityResultType,
    },
    command_buffer::blit::Region,
    device::{
        BufferId,
        fixture::{TestDevice, device},
        queue::{AttachmentRequest, RenderPassRequest},
        resources::Strides,
    },
    pipeline::MAX_COLOR_ATTACHMENTS,
    pixel_format::PixelFormat,
    resource::TextureDescriptor,
};

fn shared() -> ResourceOptions {
    ResourceOptions {
        cpu_cache_mode: CpuCacheMode::DefaultCache,
        storage_mode: StorageMode::Shared,
        hazard_tracking_mode: HazardTrackingMode::Default,
    }
}

fn descriptor(
    pixel_format: PixelFormat,
    width: u64,
    height: u64,
    usage: TextureUsage,
) -> TextureDescriptor {
    TextureDescriptor {
        texture_type: TextureType::D2,
        pixel_format,
        width,
        height,
        depth: 1,
        mipmap_level_count: 1,
        sample_count: 1,
        array_length: 1,
        options: shared(),
        usage,
        swizzle: SwizzleChannels::IDENTITY,
    }
}

fn pass(texture: TextureId, load_action: LoadAction) -> RenderPassRequest {
    let mut colors = [None; MAX_COLOR_ATTACHMENTS];
    colors[0] = Some(AttachmentRequest {
        texture,
        level: 0,
        slice: 0,
        depth_plane: 0,
        resolve: None,
        load_action,
        store_action: StoreAction::Store,
        store_action_options: StoreActionOptions::EMPTY,
        clear: [0.0; 4],
        surface: None,
    });
    RenderPassRequest {
        color_attachments: colors,
        depth_attachment: None,
        depth_resolve_filter: MultisampleDepthResolveFilter::Sample0,
        stencil_attachment: None,
        stencil_resolve_filter: MultisampleStencilResolveFilter::Sample0,
        visibility_result_buffer: None,
        visibility_result_type: VisibilityResultType::Reset,
        render_target_array_length: 0,
        render_target_width: 0,
        render_target_height: 0,
        default_raster_sample_count: 0,
        tile_memory: Default::default(),
        sample_positions: Vec::new(),
        rasterization_rate_map: false,
        counter_samples: Vec::new(),
    }
}

/// The copies between rows and aligned copies in the last submission's
/// first segment, in order: `true` into the copy, `false` back into the
/// rows, with each region's offset, row length and extent.
fn row_copies(device: &mut TestDevice) -> Vec<(bool, u64, u32, [u32; 3])> {
    device
        .backend()
        .submissions
        .last()
        .unwrap()
        .iter()
        .flat_map(|segment| segment.commands.iter())
        .filter_map(|command| match command {
            Command::CopyBufferToImage { region, .. } => Some((
                true,
                region.buffer_offset,
                region.buffer_row_length,
                region.extent,
            )),
            Command::CopyImageToBuffer { region, .. } => Some((
                false,
                region.buffer_offset,
                region.buffer_row_length,
                region.extent,
            )),
            _ => None,
        })
        .collect()
}

fn commit_empty(device: &mut TestDevice) {
    let commands = device.new_command_buffer();
    device.commit(commands).unwrap();
}

fn commit_pass(device: &mut TestDevice, texture: TextureId, load: LoadAction) {
    let mut commands = device.new_command_buffer();
    device
        .begin_render(&mut commands, &pass(texture, load))
        .unwrap();
    commands.end_encoding(&mut device.resolver()).unwrap();
    device.commit(commands).unwrap();
}

fn buffer(device: &mut TestDevice, length: u64) -> BufferId {
    device.new_buffer(length, shared()).unwrap()
}

/// WindowServer's '&b38' screen surfaces of a 3440 or 1680 wide screen:
/// the alpha plane's row is the width in bytes, which NVIDIA's linear
/// images cannot take. The texture is made, its alpha plane an aligned
/// copy every commit refreshes from the rows and a pass's encode of the
/// planes refreshes again; the color plane's rows fit and stay in place.
#[test]
fn screen_surfaces_of_odd_widths_sample_their_alpha_through_an_aligned_copy() {
    for (width, height, alpha_offset) in
        [(3440u32, 1440u32, 20_076_544u64), (1680, 1050, 7_227_392)]
    {
        let mut device = device();
        let length = alpha_offset + u64::from(width) * u64::from(height);
        let buffer = buffer(&mut device, length);
        let planes = [
            PlaneLayout {
                offset: 0,
                bytes_per_row: u64::from(width) * 4,
            },
            PlaneLayout {
                offset: alpha_offset,
                bytes_per_row: u64::from(width),
            },
        ];
        let surface = descriptor(
            PixelFormat::Rgb10A8_2pXr10,
            width.into(),
            height.into(),
            TextureUsage::SHADER_READ | TextureUsage::RENDER_TARGET,
        );
        let texture = device
            .new_extended_plane_texture(buffer, &surface, planes)
            .unwrap();
        assert!(device.has_aligned_copy(texture));
        let alpha = (true, alpha_offset, width, [width, height, 1]);
        commit_empty(&mut device);
        assert_eq!(row_copies(&mut device), [alpha], "{width}");
        // The encode writes the rows: they are copied in again after it,
        // and never back, as the planes are what the pass writes.
        commit_pass(&mut device, texture, LoadAction::Clear);
        assert_eq!(row_copies(&mut device), [alpha, alpha], "{width}");
        device.destroy_texture(texture).unwrap();
        commit_empty(&mut device);
        assert_eq!(row_copies(&mut device), [], "{width}");
    }
}

/// A buffer texture whose rows the GPU addresses in place is its linear
/// image, with no copies; one of 1004 BGRA8 pixels a row (4016 bytes) is an
/// aligned copy, refreshed by every commit and copied back by those that
/// write it.
#[test]
fn buffer_textures_of_unaligned_rows_copy_back_what_passes_write() {
    let mut device = device();
    let buffer = buffer(&mut device, 1 << 20);
    let usage = TextureUsage::SHADER_READ | TextureUsage::RENDER_TARGET;
    let fits = descriptor(PixelFormat::Bgra8Unorm, 1000, 10, usage);
    let fitting = device
        .new_texture_from_buffer(buffer, &fits, 0, 4096)
        .unwrap();
    assert!(!device.has_aligned_copy(fitting));
    let odd = descriptor(PixelFormat::Bgra8Unorm, 1004, 10, usage);
    let texture = device
        .new_texture_from_buffer(buffer, &odd, 65_536, 4016)
        .unwrap();
    assert!(device.has_aligned_copy(texture));
    let copy = (65_536, 1004, [1004, 10, 1]);
    commit_empty(&mut device);
    assert_eq!(row_copies(&mut device), [(true, copy.0, copy.1, copy.2)]);
    commit_pass(&mut device, texture, LoadAction::Load);
    assert_eq!(
        row_copies(&mut device),
        [
            (true, copy.0, copy.1, copy.2),
            (false, copy.0, copy.1, copy.2)
        ]
    );
    // A pass on the other texture writes only that one.
    commit_pass(&mut device, fitting, LoadAction::Load);
    assert_eq!(row_copies(&mut device), [(true, copy.0, copy.1, copy.2)]);
    // A pixel is a row's unit; an offset of whole pixels need not fit the
    // GPU's 32 bytes either.
    assert!(
        device
            .new_texture_from_buffer(buffer, &odd, 0, 4018)
            .is_err()
    );
    let offset = device
        .new_texture_from_buffer(buffer, &fits, 4100, 4096)
        .unwrap();
    assert!(device.has_aligned_copy(offset));
}

/// The CPU's copies of an aligned copy's texture go to and from its rows,
/// at their own pitch.
#[test]
fn cpu_copies_of_an_aligned_copy_convert_row_by_row_in_the_rows() {
    let mut device = device();
    let buffer = buffer(&mut device, 1 << 16);
    let odd = descriptor(PixelFormat::R8Unorm, 40, 3, TextureUsage::SHADER_READ);
    let texture = device
        .new_texture_from_buffer(buffer, &odd, 16, 48)
        .unwrap();
    assert!(device.has_aligned_copy(texture));
    let region = Region {
        slice: 0,
        level: 0,
        origin: [2, 1, 0],
        size: [3, 2, 1],
    };
    let tight = Strides {
        bytes_per_row: 3,
        bytes_per_image: 0,
    };
    let written = [1, 2, 3, 4, 5, 6];
    device
        .replace_region(texture, &region, &written, tight)
        .unwrap();
    let memory = device.resources.buffers.get(buffer.0).unwrap().memory;
    let rows: Vec<_> = device
        .backend()
        .writes
        .iter()
        .filter(|(written, ..)| *written == memory)
        .map(|(_, offset, bytes)| (*offset, bytes.clone()))
        .collect();
    // Row 1 starts 16 + 48 bytes in, row 2 48 after it; pixel 2 of each.
    assert_eq!(
        rows,
        [(66, alloc::vec![1, 2, 3]), (114, alloc::vec![4, 5, 6])]
    );
    let mut read = [0; 6];
    device
        .get_bytes(texture, &region, &mut read, tight)
        .unwrap();
    assert_eq!(read, written);
}

/// A two-plane surface whose planes' rows do not fit has an aligned copy
/// of each, refreshed by every commit.
#[test]
fn two_plane_surfaces_copy_each_unaligned_plane() {
    let mut device = device();
    let buffer = buffer(&mut device, 1 << 20);
    let surface = descriptor(
        PixelFormat::Rgb8_420_2p,
        1010,
        10,
        TextureUsage::SHADER_READ,
    );
    let texture = device
        .new_two_plane_texture(
            buffer,
            &surface,
            [
                PlaneLayout {
                    offset: 0,
                    bytes_per_row: 1040,
                },
                PlaneLayout {
                    offset: 1 << 16,
                    bytes_per_row: 1010,
                },
            ],
            0,
        )
        .unwrap();
    commit_empty(&mut device);
    assert_eq!(
        row_copies(&mut device),
        [
            (true, 0, 1040, [1010, 10, 1]),
            (true, 1 << 16, 505, [505, 5, 1])
        ]
    );
    device.destroy_texture(texture).unwrap();
}
