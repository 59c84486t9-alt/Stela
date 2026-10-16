use super::*;

fn source(value: u32) -> Vec<u8> {
    [0xd2800000u32 | (value << 5), 0xd65f03c0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect()
}

#[test]
fn cold_and_warm_resolution_preserve_identity_and_instruction_map() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut registry = LeafDispatcher::new(9, root.path().into());
    let entry = GuestAddress(0x1000);
    registry.register(entry, source(42))?;
    let first = registry.resolve(entry)?;
    let second = registry.resolve(entry)?;
    assert!(!first.prepared().cache_hit);
    assert!(second.prepared().cache_hit);
    assert_eq!(first.identity(), second.identity());
    assert!(registry.is_current(&first));
    assert!(!first.prepared().manifest.verified);
    let return_offset = first.prepared().manifest.source_map[1].1;
    assert_eq!(first.guest_instruction_for_native_offset(0), Some(entry));
    assert_eq!(
        first.guest_instruction_for_native_offset(return_offset - 1),
        Some(entry)
    );
    assert_eq!(
        first.guest_instruction_for_native_offset(return_offset),
        Some(GuestAddress(0x1004))
    );
    assert_eq!(
        first.guest_instruction_for_native_offset(first.prepared().manifest.native_bytes),
        None
    );
    assert!(registry.resolve(GuestAddress(0x1004)).is_err());
    assert!(registry.resolve(GuestAddress(0x2000)).is_err());
    Ok(())
}

#[test]
fn replacement_removal_and_identical_address_reuse_invalidate_old_handles() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut registry = LeafDispatcher::new(1, root.path().into());
    let entry = GuestAddress(0x1000);
    registry.register(entry, source(40))?;
    let original = registry.resolve(entry)?;
    registry.register(entry, source(41))?;
    assert!(!registry.is_current(&original));
    let updated = registry.resolve(entry)?;
    assert_ne!(original.prepared().key, updated.prepared().key);
    assert!(registry.unregister(entry));
    assert!(!registry.is_current(&updated));
    assert!(!registry.unregister(entry));
    registry.register(entry, source(40))?;
    let reused = registry.resolve(entry)?;
    assert_eq!(original.prepared().key, reused.prepared().key);
    assert_ne!(
        original.identity().mapping_generation,
        reused.identity().mapping_generation
    );
    assert!(!registry.is_current(&original));
    assert!(registry.is_current(&reused));
    registry.register(entry, source(40))?;
    assert!(!registry.is_current(&reused));
    Ok(())
}

#[test]
fn handles_do_not_transfer_between_registries_even_with_same_address_space_id() -> Result<()> {
    let root = tempfile::tempdir()?;
    let entry = GuestAddress(0x1000);
    let mut first = LeafDispatcher::new(1, root.path().into());
    let mut second = LeafDispatcher::new(1, root.path().into());
    first.register(entry, source(40))?;
    second.register(entry, source(40))?;
    let resolved = first.resolve(entry)?;
    assert!(!second.is_current(&resolved));
    assert!(second.resolve(entry)?.prepared().cache_hit);
    Ok(())
}

#[test]
fn invalid_ranges_and_overlaps_leave_registration_intact() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut registry = LeafDispatcher::new(1, root.path().into());
    let entry = GuestAddress(0x1000);
    registry.register(entry, source(40))?;
    let original = registry.resolve(entry)?;
    for (base, bytes) in [
        (0x1004, source(41)),
        (0xffc, source(41)),
        (1, source(41)),
        (0x2000, vec![]),
        (0x2000, vec![0]),
        (u64::MAX - 3, source(41)),
    ] {
        assert!(registry.register(GuestAddress(base), bytes).is_err());
    }
    assert!(registry.is_current(&original));
    registry.register(GuestAddress(0x1008), source(41))?;
    assert!(registry.is_current(&original));
    Ok(())
}

#[test]
fn unsupported_semantics_never_resolve_or_publish_a_cache_entry() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut registry = LeafDispatcher::new(1, root.path().into());
    let entry = GuestAddress(0x1000);
    registry.register(entry, vec![0; 4])?;
    assert!(registry.resolve(entry).is_err());
    assert_eq!(std::fs::read_dir(root.path())?.count(), 0);
    registry.register(entry, source(40))?;
    assert!(registry.resolve(entry).is_ok());
    Ok(())
}

#[test]
fn warm_lookup_rejects_corruption_instead_of_reusing_a_stale_path() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut registry = LeafDispatcher::new(1, root.path().into());
    let entry = GuestAddress(0x1000);
    registry.register(entry, source(40))?;
    let resolved = registry.resolve(entry)?;
    std::fs::write(resolved.prepared().directory.join("native.bin"), b"changed")?;
    assert!(registry.resolve(entry).is_err());
    // is_current only answers registration identity, never disk integrity.
    assert!(registry.is_current(&resolved));
    Ok(())
}

#[test]
fn malformed_source_maps_fail_even_with_recomputed_manifest_checksum() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut registry = LeafDispatcher::new(1, root.path().into());
    let entry = GuestAddress(0x1000);
    registry.register(entry, source(40))?;
    let resolved = registry.resolve(entry)?;
    let path = resolved.prepared().directory.join("manifest.json");
    let original = std::fs::read(&path)?;
    for variant in 0..5 {
        let mut manifest: crate::Manifest = serde_json::from_slice(&original)?;
        match variant {
            0 => {
                manifest.source_map.pop();
            }
            1 => manifest.source_map[0].0 = GuestAddress(0x1004),
            2 => manifest.source_map[0].1 = 1,
            3 => manifest.source_map[1].1 = manifest.source_map[0].1,
            _ => manifest.source_map[1].1 = manifest.native_bytes,
        }
        stela_core::write_json(&path, &manifest)?;
        stela_core::write_json(
            &resolved.prepared().directory.join("manifest.sha256.json"),
            &sha256(&std::fs::read(&path)?),
        )?;
        assert!(registry.resolve(entry).is_err());
    }
    Ok(())
}

#[test]
fn generation_exhaustion_does_not_replace_a_live_mapping() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut registry = LeafDispatcher::new(1, root.path().into());
    let entry = GuestAddress(0x1000);
    registry.register(entry, source(40))?;
    let original = registry.resolve(entry)?;
    registry.next_generation = u64::MAX;
    assert!(registry.register(entry, source(41)).is_err());
    assert!(registry.is_current(&original));
    Ok(())
}
