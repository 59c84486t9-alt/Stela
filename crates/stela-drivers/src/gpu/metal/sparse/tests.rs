use super::*;
use crate::gpu::metal::abi::{CpuCacheMode, HazardTrackingMode};

const PAGE: u64 = 64 << 10;

fn descriptor(levels: u64, array_length: u64) -> TextureDescriptor {
    TextureDescriptor {
        texture_type: if array_length > 1 {
            TextureType::D2Array
        } else {
            TextureType::D2
        },
        pixel_format: PixelFormat::Rgba8Unorm,
        width: 300,
        height: 256,
        depth: 1,
        mipmap_level_count: levels,
        sample_count: 1,
        array_length,
        options: ResourceOptions {
            cpu_cache_mode: CpuCacheMode::DefaultCache,
            storage_mode: StorageMode::Private,
            hazard_tracking_mode: HazardTrackingMode::Default,
        },
        usage: TextureUsage::SHADER_READ,
        swizzle: SwizzleChannels::IDENTITY,
    }
}

fn requirements(single_mip_tail: bool) -> SparseImageRequirements {
    SparseImageRequirements {
        memory_types: 1,
        granularity: [128, 128, 1],
        mip_tail_first_lod: 2,
        mip_tail_size: 2 * PAGE,
        mip_tail_offset: 1 << 20,
        mip_tail_stride: 2 * PAGE,
        single_mip_tail,
    }
}

fn texture(levels: u64, slices: u64, single_mip_tail: bool) -> SparseTexture {
    let layout = SparseLayout::new(
        &descriptor(levels, slices),
        [128, 128, 1],
        &requirements(single_mip_tail),
        PAGE,
    )
    .unwrap();
    SparseTexture::new(Image(7), layout)
}

fn update(level: u64, slice: u64, origin: [u64; 3], size: [u64; 3]) -> MappingUpdate {
    MappingUpdate {
        level,
        slice,
        region: SparseRegion { origin, size },
    }
}

#[test]
fn pixel_regions_round_outward_or_inward() {
    let region = SparseRegion {
        origin: [100, 0, 0],
        size: [200, 128, 1],
    };
    let tile = [128, 128, 1];
    let outward =
        pixel_to_tile_regions(&[region], tile, SparseTextureRegionAlignmentMode::Outward).unwrap();
    assert_eq!(
        outward,
        [SparseRegion {
            origin: [0, 0, 0],
            size: [3, 1, 1]
        }]
    );
    let inward =
        pixel_to_tile_regions(&[region], tile, SparseTextureRegionAlignmentMode::Inward).unwrap();
    assert_eq!(
        inward,
        [SparseRegion {
            origin: [1, 0, 0],
            size: [1, 1, 1]
        }]
    );
    assert_eq!(
        tile_to_pixel_regions(&outward, tile).unwrap(),
        [SparseRegion {
            origin: [0, 0, 0],
            size: [384, 128, 1]
        }]
    );
    assert!(
        pixel_to_tile_regions(
            &[region],
            [0, 1, 1],
            SparseTextureRegionAlignmentMode::Inward
        )
        .is_err()
    );
}

#[test]
fn mapping_takes_pages_and_binds_clipped_blocks() {
    let mut heap = SparsePages::new(8 * PAGE, PAGE);
    let mut texture = texture(3, 1, false);
    let memory = Memory(3);
    let mut binds = Vec::new();
    texture
        .update(
            SparseTextureMappingMode::Map,
            &update(0, 0, [1, 1, 0], [2, 1, 1]),
            &mut heap,
            memory,
            &mut binds,
        )
        .unwrap();
    assert_eq!(heap.used_bytes(), 2 * PAGE);
    let SparseBind::Block {
        offset,
        extent,
        memory: backing,
        ..
    } = binds[1]
    else {
        panic!("{:?}", binds[1])
    };
    assert_eq!(offset, [256, 128, 0]);
    assert_eq!(
        extent,
        [44, 128, 1],
        "the last column ends at the level's edge"
    );
    assert_eq!(backing, Some((memory, PAGE)), "the second page");

    // Mapping again keeps the pages; unmapping returns them.
    binds.clear();
    let whole = update(0, 0, [1, 1, 0], [2, 1, 1]);
    texture
        .update(
            SparseTextureMappingMode::Map,
            &whole,
            &mut heap,
            memory,
            &mut binds,
        )
        .unwrap();
    assert!(binds.is_empty());
    texture
        .update(
            SparseTextureMappingMode::Unmap,
            &whole,
            &mut heap,
            memory,
            &mut binds,
        )
        .unwrap();
    assert_eq!(heap.used_bytes(), 0);
    assert!(
        binds
            .iter()
            .all(|bind| matches!(bind, SparseBind::Block { memory: None, .. }))
    );
    assert!(
        texture
            .update(
                SparseTextureMappingMode::Map,
                &update(0, 0, [2, 0, 0], [2, 1, 1]),
                &mut heap,
                memory,
                &mut binds
            )
            .is_err(),
        "the level is three tiles wide"
    );
}

#[test]
fn tail_levels_map_each_slices_tail_whole() {
    let mut heap = SparsePages::new(8 * PAGE, PAGE);
    let mut texture = texture(5, 2, false);
    assert_eq!(texture.layout.first_mip_in_tail, 2);
    assert_eq!(texture.layout.tail_bytes, 2 * PAGE);
    let memory = Memory(3);
    let mut binds = Vec::new();
    texture
        .update(
            SparseTextureMappingMode::Map,
            &update(3, 1, [0; 3], [1; 3]),
            &mut heap,
            memory,
            &mut binds,
        )
        .unwrap();
    assert_eq!(
        binds,
        [
            SparseBind::Opaque {
                image: Image(7),
                offset: (1 << 20) + 2 * PAGE,
                size: PAGE,
                memory: Some((memory, 0)),
            },
            SparseBind::Opaque {
                image: Image(7),
                offset: (1 << 20) + 3 * PAGE,
                size: PAGE,
                memory: Some((memory, PAGE)),
            },
        ]
    );
    binds.clear();
    texture
        .update(
            SparseTextureMappingMode::Map,
            &update(2, 1, [0; 3], [1; 3]),
            &mut heap,
            memory,
            &mut binds,
        )
        .unwrap();
    assert!(binds.is_empty(), "every tail level shares the slice's tail");

    let mut shared = self::texture(5, 2, true);
    shared
        .update(
            SparseTextureMappingMode::Map,
            &update(4, 1, [0; 3], [1; 3]),
            &mut heap,
            memory,
            &mut binds,
        )
        .unwrap();
    assert!(matches!(
        binds[0],
        SparseBind::Opaque {
            offset: 0x10_0000,
            ..
        }
    ));
}

#[test]
fn a_full_heap_leaves_tiles_unmapped() {
    let mut heap = SparsePages::new(PAGE, PAGE);
    let mut texture = texture(1, 1, false);
    let mut binds = Vec::new();
    texture
        .update(
            SparseTextureMappingMode::Map,
            &update(0, 0, [0; 3], [2, 1, 1]),
            &mut heap,
            Memory(3),
            &mut binds,
        )
        .unwrap();
    assert_eq!(binds.len(), 1);
    assert_eq!(heap.free_bytes(), 0);
    texture.release(&mut heap);
    assert_eq!(heap.free_bytes(), PAGE);
}

#[test]
fn moves_carry_pages_between_textures() {
    let mut heap = SparsePages::new(8 * PAGE, PAGE);
    let memory = Memory(3);
    let mut source = texture(1, 1, false);
    let mut destination = texture(1, 1, false);
    destination.image = Image(8);
    let mut binds = Vec::new();
    source
        .update(
            SparseTextureMappingMode::Map,
            &update(0, 0, [0; 3], [1; 3]),
            &mut heap,
            memory,
            &mut binds,
        )
        .unwrap();
    destination
        .update(
            SparseTextureMappingMode::Map,
            &update(0, 0, [1, 0, 0], [1; 3]),
            &mut heap,
            memory,
            &mut binds,
        )
        .unwrap();
    binds.clear();
    let from = MoveEnd {
        image: Image(7),
        level: 0,
        slice: 0,
        origin: [0; 3],
    };
    let to = MoveEnd {
        image: Image(8),
        level: 0,
        slice: 0,
        origin: [128, 0, 0],
    };
    let size = [128, 128, 1];
    assert!(
        source
            .check_move(
                &MoveEnd {
                    origin: [64, 0, 0],
                    ..from
                },
                size
            )
            .is_err()
    );
    let moved = source.take_region(&from, size, memory, &mut binds).unwrap();
    destination
        .place_region(&to, size, moved, &mut heap, memory, &mut binds)
        .unwrap();
    assert_eq!(
        heap.used_bytes(),
        PAGE,
        "the destination's own page returned"
    );
    assert_eq!(
        binds.last(),
        Some(&SparseBind::Block {
            image: Image(8),
            subresource: Subresource {
                aspects: ImageAspects::COLOR,
                mip_level: 0,
                base_array_layer: 0,
                layer_count: 1,
            },
            offset: [128, 0, 0],
            extent: [128, 128, 1],
            memory: Some((memory, 0)),
        })
    );
}

#[test]
fn layouts_need_the_standard_block_shape() {
    let mut odd = requirements(false);
    odd.granularity = [64, 64, 1];
    assert_eq!(
        SparseLayout::new(&descriptor(1, 1), [128, 128, 1], &odd, PAGE),
        Err(Error::Unsupported("non-standard sparse block shapes"))
    );
    let layout =
        SparseLayout::new(&descriptor(2, 1), [128, 128, 1], &requirements(false), PAGE).unwrap();
    assert_eq!(
        (layout.first_mip_in_tail, layout.tail_bytes),
        (2, 0),
        "no level in the tail"
    );
}
