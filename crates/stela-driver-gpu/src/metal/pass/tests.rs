use super::*;
use crate::metal::{
    abi::{CpuCacheMode, HazardTrackingMode, ResourceOptions, StorageMode, SwizzleChannels},
    nvidia::fixture::capabilities,
};

fn texture(
    texture_type: TextureType,
    pixel_format: PixelFormat,
    sample_count: u64,
) -> TextureDescriptor {
    TextureDescriptor {
        texture_type,
        pixel_format,
        width: 640,
        height: 480,
        depth: 1,
        mipmap_level_count: 4,
        sample_count,
        array_length: 4,
        options: ResourceOptions {
            cpu_cache_mode: CpuCacheMode::DefaultCache,
            storage_mode: StorageMode::Private,
            hazard_tracking_mode: HazardTrackingMode::Default,
        },
        usage: TextureUsage::RENDER_TARGET,
        swizzle: SwizzleChannels::IDENTITY,
    }
}

fn target(id: u32, descriptor: &TextureDescriptor) -> Target<'_, u32> {
    Target {
        texture: AttachedTexture {
            texture: id,
            descriptor,
        },
        level: 0,
        slice: 0,
        depth_plane: 0,
    }
}

fn attachment<Clear>(
    target: Target<'_, u32>,
    store_action: StoreAction,
    clear: Clear,
) -> AttachmentDescriptor<'_, u32, Clear> {
    AttachmentDescriptor {
        target,
        resolve: None,
        load_action: LoadAction::Clear,
        store_action,
        store_action_options: StoreActionOptions::EMPTY,
        clear,
    }
}

fn pass<'a>() -> RenderPassDescriptor<'a, u32> {
    RenderPassDescriptor {
        color_attachments: [None; MAX_COLOR_ATTACHMENTS],
        depth_attachment: None,
        depth_resolve_filter: MultisampleDepthResolveFilter::Sample0,
        stencil_attachment: None,
        stencil_resolve_filter: MultisampleStencilResolveFilter::Sample0,
        visibility_results: false,
        render_target_array_length: 0,
        render_target_width: 0,
        render_target_height: 0,
        default_raster_sample_count: 0,
        tile_memory: false,
        sample_positions: Vec::new(),
        rasterization_rate_map: false,
    }
}

#[test]
fn color_depth_and_stencil_attachments() {
    let color = texture(TextureType::D2, PixelFormat::Rgba16Float, 1);
    let integer = texture(TextureType::D2, PixelFormat::Rg32Uint, 1);
    let depth = texture(TextureType::D2, PixelFormat::Depth32FloatStencil8, 1);
    let mut descriptor = pass();
    descriptor.color_attachments[0] = Some(attachment(
        target(1, &color),
        StoreAction::Store,
        [0.5, 0.0, 0.0, 1.0],
    ));
    descriptor.color_attachments[3] = Some(attachment(
        target(2, &integer),
        StoreAction::DontCare,
        [7.0, 3.9, 0.0, 0.0],
    ));
    descriptor.depth_attachment = Some(attachment(target(3, &depth), StoreAction::Store, 1.0));
    descriptor.stencil_attachment =
        Some(attachment(target(3, &depth), StoreAction::DontCare, 0x80));

    let plan = render_pass(&capabilities(), &descriptor).unwrap();
    assert_eq!(plan.extent, [640, 480]);
    assert_eq!((plan.layer_count, plan.sample_count), (1, 1));
    assert_eq!(plan.color.len(), MAX_COLOR_ATTACHMENTS);
    let first = plan.color[0].unwrap();
    assert_eq!(
        (first.load_op, first.store_op),
        (AttachmentLoadOp::Clear, AttachmentStoreOp::Store)
    );
    assert_eq!(first.clear, ClearValue::Float([0.5, 0.0, 0.0, 1.0]));
    assert_eq!(first.view.view_type, ImageViewType::D2);
    assert_eq!(plan.color[3].unwrap().clear, ClearValue::Uint([7, 3, 0, 0]));
    assert_eq!(plan.color[3].unwrap().store_op, AttachmentStoreOp::DontCare);
    assert_eq!(plan.depth.unwrap().view.range.aspects, ImageAspects::DEPTH);
    assert_eq!(
        plan.stencil.unwrap().clear,
        ClearValue::DepthStencil {
            depth: 0.0,
            stencil: 0x80
        }
    );
    assert_eq!(plan.color_formats[3], Some(PixelFormat::Rg32Uint));
    assert_eq!(plan.depth_format, Some(PixelFormat::Depth32FloatStencil8));
    assert_eq!(plan.finish(), Ok(()));
}

#[test]
fn layered_mip_and_depth_plane_targets() {
    let array = texture(TextureType::D2Array, PixelFormat::Rgba8Unorm, 1);
    let mut volume = texture(TextureType::D3, PixelFormat::Rgba8Unorm, 1);
    volume.depth = 32;
    let mut descriptor = pass();
    descriptor.render_target_array_length = 2;
    descriptor.color_attachments[0] = Some(attachment(
        Target {
            level: 2,
            slice: 1,
            ..target(1, &array)
        },
        StoreAction::Store,
        [0.0; 4],
    ));
    descriptor.color_attachments[1] = Some(attachment(
        Target {
            level: 1,
            depth_plane: 14,
            ..target(2, &volume)
        },
        StoreAction::Store,
        [0.0; 4],
    ));
    let plan = render_pass(&capabilities(), &descriptor).unwrap();
    assert_eq!(
        plan.extent,
        [160, 120],
        "the smallest attachment bounds the render area"
    );
    assert_eq!(plan.layer_count, 2);
    let array_view = plan.color[0].unwrap().view;
    assert_eq!(array_view.view_type, ImageViewType::D2Array);
    assert_eq!(
        (
            array_view.range.base_mip_level,
            array_view.range.base_array_layer
        ),
        (2, 1)
    );
    let volume_view = plan.color[1].unwrap().view.range;
    assert_eq!(
        (volume_view.base_array_layer, volume_view.layer_count),
        (14, 2)
    );

    descriptor.color_attachments[1] = Some(attachment(
        Target {
            level: 1,
            depth_plane: 15,
            ..target(2, &volume)
        },
        StoreAction::Store,
        [0.0; 4],
    ));
    assert_eq!(
        render_pass(&capabilities(), &descriptor).unwrap_err(),
        Error::Invalid("attachment layers exceed the texture")
    );
}

#[test]
fn multisample_resolves_choose_vulkan_resolve_modes() {
    let msaa = texture(TextureType::D2Multisample, PixelFormat::Bgra8Unorm, 4);
    let resolved = texture(TextureType::D2, PixelFormat::Bgra8Unorm, 1);
    let depth = texture(TextureType::D2Multisample, PixelFormat::Depth32Float, 4);
    let depth_resolved = texture(TextureType::D2, PixelFormat::Depth32Float, 1);
    let mut descriptor = pass();
    descriptor.color_attachments[0] = Some(AttachmentDescriptor {
        resolve: Some(target(2, &resolved)),
        ..attachment(target(1, &msaa), StoreAction::MultisampleResolve, [0.0; 4])
    });
    descriptor.depth_attachment = Some(AttachmentDescriptor {
        resolve: Some(target(4, &depth_resolved)),
        ..attachment(
            target(3, &depth),
            StoreAction::StoreAndMultisampleResolve,
            1.0,
        )
    });
    descriptor.depth_resolve_filter = MultisampleDepthResolveFilter::Max;
    let plan = render_pass(&capabilities(), &descriptor).unwrap();
    assert_eq!(plan.sample_count, 4);
    let color = plan.color[0].unwrap();
    assert_eq!(color.store_op, AttachmentStoreOp::DontCare);
    assert_eq!(
        color.resolve.map(|(mode, view)| (mode, view.texture)),
        Some((ResolveModes::AVERAGE, 2))
    );
    let depth = plan.depth.unwrap();
    assert_eq!(depth.store_op, AttachmentStoreOp::Store);
    assert_eq!(depth.resolve.unwrap().0, ResolveModes::MAX);

    descriptor.color_attachments[0] = Some(attachment(
        target(1, &msaa),
        StoreAction::MultisampleResolve,
        [0.0; 4],
    ));
    assert!(
        render_pass(&capabilities(), &descriptor).is_err(),
        "a resolve action without a resolve texture"
    );
}

#[test]
fn unknown_store_actions_are_set_before_the_pass_ends() {
    let msaa = texture(TextureType::D2Multisample, PixelFormat::Rgba8Unorm, 4);
    let resolved = texture(TextureType::D2, PixelFormat::Rgba8Unorm, 1);
    let mut descriptor = pass();
    descriptor.color_attachments[0] = Some(AttachmentDescriptor {
        resolve: Some(target(2, &resolved)),
        ..attachment(target(1, &msaa), StoreAction::Unknown, [0.0; 4])
    });
    let mut plan = render_pass(&capabilities(), &descriptor).unwrap();
    assert_eq!(
        plan.finish(),
        Err(Error::Invalid("a store action was never set"))
    );
    plan.set_store_action(AttachmentSlot::Color(0), StoreAction::Store)
        .unwrap();
    assert_eq!(plan.finish(), Ok(()));
    assert!(
        plan.color[0].unwrap().resolve.is_none(),
        "a plain store drops the resolve"
    );
    assert!(
        plan.set_store_action(AttachmentSlot::Color(0), StoreAction::DontCare)
            .is_err(),
        "only Unknown is deferred"
    );
    assert!(
        plan.set_store_action(AttachmentSlot::Depth, StoreAction::Store)
            .is_err()
    );
    assert_eq!(
        plan.set_store_action_options(AttachmentSlot::Color(0), StoreActionOptions::EMPTY),
        Ok(())
    );
    assert_eq!(
        plan.set_store_action_options(
            AttachmentSlot::Color(0),
            StoreActionOptions::CUSTOM_SAMPLE_POSITIONS
        ),
        Err(Error::Invalid(
            "custom sample position stores need sample positions"
        ))
    );
    assert!(
        plan.set_store_action_options(AttachmentSlot::Stencil, StoreActionOptions::EMPTY)
            .is_err()
    );
}

#[test]
fn passes_without_attachments_and_apple_only_features() {
    let mut descriptor = pass();
    assert!(render_pass(&capabilities(), &descriptor).is_err());
    descriptor.render_target_width = 1920;
    descriptor.render_target_height = 1080;
    descriptor.default_raster_sample_count = 4;
    descriptor.sample_positions = alloc::vec![
        [0.375, 0.125],
        [0.875, 0.375],
        [0.125, 0.625],
        [0.625, 0.875]
    ];
    let plan = render_pass(&capabilities(), &descriptor).unwrap();
    assert_eq!((plan.extent, plan.sample_count), ([1920, 1080], 4));
    assert_eq!(plan.sample_locations.len(), 4);

    descriptor.sample_positions.pop();
    assert_eq!(
        render_pass(&capabilities(), &descriptor).unwrap_err(),
        Error::Invalid("one sample position per sample")
    );
    descriptor.sample_positions.clear();
    descriptor.tile_memory = true;
    assert_eq!(
        render_pass(&capabilities(), &descriptor).unwrap_err(),
        Error::Unsupported("tile memory")
    );
}
