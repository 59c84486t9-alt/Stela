use super::*;
use crate::boot_policy::SecurityPolicy;
use crate::kernel_collection::tests::{BASE, Builder};
use alloc::collections::BTreeMap;
use anyhow::Result;
use object::macho;

const PAGE: u64 = PAGE_BYTES;

fn ordered_region_fixture(optional_images: bool) -> Vec<Region> {
    // Spell the ABI fixture independently of the preparer's placement list.
    let names = [
        "TXM-ro",
        "TXM-rx",
        "TXM-bx",
        "TrustCache",
        "AuxKC-ro",
        "AuxKC-rx",
        "BootKC-rx",
        "BootKC-bx",
        "BootKC-ro",
        "BootKC-rs",
        "CL4-rx",
        "CL4-ro",
        "DeviceTree",
        "SPTM-ro",
        "SPTM-rx",
        "SPTM-rw",
    ];
    names
        .into_iter()
        .filter(|name| optional_images || !(name.starts_with("AuxKC") || name.starts_with("CL4")))
        .enumerate()
        .map(|(index, name)| Region {
            name: name.into(),
            file: "fixture".into(),
            file_offset: 0,
            bytes: PAGE,
            guest_pa: 0x8_0000_0000 + index as u64 * PAGE,
            memory_bytes: PAGE,
            sha256: String::new(),
            virtual_address: None,
        })
        .collect()
}

#[test]
fn sptm_order_accepts_optional_images_at_any_address() -> Result<()> {
    for optional_images in [false, true] {
        let mut regions = ordered_region_fixture(optional_images);
        validate_sptm_region_order(&regions)?;
        // SPTM constrains adjacency, not the first image's absolute address.
        for region in &mut regions {
            region.guest_pa += 7 * PAGE;
        }
        validate_sptm_region_order(&regions)?;
    }
    Ok(())
}

#[test]
fn the_physical_slide_admits_carveouts_below_it_but_no_region_in_it() -> Result<()> {
    let mut regions = ordered_region_fixture(false);
    let phys_base = regions[0].guest_pa;
    for region in &mut regions {
        region.guest_pa += 2 * PAGE;
    }
    validate_physical_slide(&regions, phys_base)?;
    let mut carveout = regions[0].clone();
    carveout.name = "BootManifest".into();
    carveout.guest_pa = phys_base - PAGE;
    regions.insert(0, carveout);
    validate_physical_slide(&regions, phys_base)?;
    regions[0].guest_pa = phys_base + PAGE;
    let error = validate_physical_slide(&regions, phys_base)
        .unwrap_err()
        .to_string();
    assert!(error.contains("BootManifest"), "{error}");
    assert!(error.contains("physical slide"), "{error}");
    Ok(())
}

#[test]
fn sptm_order_rejects_a_payload_inserted_inside_the_image_sequence() {
    let mut regions = ordered_region_fixture(false);
    let index = regions.iter().position(|r| r.name == "DeviceTree").unwrap();
    let mut inserted = regions[index].clone();
    inserted.name = "BootManifest".into();
    for region in &mut regions[index..] {
        region.guest_pa += PAGE;
    }
    regions.insert(index, inserted);
    let error = validate_sptm_region_order(&regions)
        .unwrap_err()
        .to_string();
    assert!(error.contains("DeviceTree"), "{error}");
    assert!(error.contains("BootKC-rs"), "{error}");
    assert!(error.contains("not immediately after"), "{error}");
}

#[test]
fn sptm_order_rejects_missing_images_overlap_and_invalid_endpoints() {
    let mut regions = ordered_region_fixture(false);
    regions.retain(|r| r.name != "TrustCache");
    assert!(
        validate_sptm_region_order(&regions)
            .unwrap_err()
            .to_string()
            .contains("missing required region TrustCache")
    );
    let mut regions = ordered_region_fixture(true);
    regions[1].guest_pa -= PAGE;
    assert!(validate_sptm_region_order(&regions).is_err());
    for (start, length) in [(0, PAGE), (u64::MAX, 0), (u64::MAX - 2, PAGE)] {
        let mut regions = ordered_region_fixture(false);
        regions[0].guest_pa = start;
        regions[0].memory_bytes = length;
        assert!(validate_sptm_region_order(&regions).is_err());
    }
}

#[test]
fn sptm_image_span_includes_link_edit_and_rejects_an_intervening_payload() -> Result<()> {
    let mut regions = ordered_region_fixture(false);
    let last = regions.last().unwrap();
    let mut link_edit = last.clone();
    link_edit.name = "SPTM-le".into();
    link_edit.guest_pa += link_edit.memory_bytes;
    regions.push(link_edit);
    let span = sptm_image_span(&regions)?;
    assert_eq!(span.end - span.start, 4 * PAGE);
    assert_eq!(span.end, regions.last().unwrap().guest_pa + PAGE);

    // The original 16-record table ends at SPTM-rw. A later payload
    // before link-edit passes that check but invalidates SPTM-rm.
    for adjustment in [PAGE, 0_u64.wrapping_sub(PAGE)] {
        let mut bad = regions.clone();
        let link_edit = bad.last_mut().unwrap();
        link_edit.guest_pa = link_edit.guest_pa.wrapping_add(adjustment);
        validate_sptm_region_order(&bad)?;
        let error = sptm_image_span(&bad).unwrap_err().to_string();
        assert!(error.contains("SPTM-le"), "{error}");
    }
    regions.pop();
    assert!(
        sptm_image_span(&regions)
            .unwrap_err()
            .to_string()
            .contains("missing region SPTM-le")
    );
    let mut link_edit = regions.last().unwrap().clone();
    link_edit.name = "SPTM-le".into();
    link_edit.guest_pa = u64::MAX - PAGE + 1;
    regions.push(link_edit);
    assert!(
        sptm_image_span(&regions)
            .unwrap_err()
            .to_string()
            .contains("range overflows")
    );
    Ok(())
}

/// SHA-256 over every prepared file, by name, and the manifest.
fn prepared_digest(bundle: &Bundle) -> Result<String> {
    let mut bytes = Vec::new();
    for (name, data) in &bundle.files {
        bytes.extend((name.len() as u64).to_le_bytes());
        bytes.extend(name.as_bytes());
        bytes.extend((data.len() as u64).to_le_bytes());
        bytes.extend(data);
    }
    bytes.extend(serde_json::to_vec(&bundle.manifest)?);
    Ok(sha256(&bytes))
}

fn source(component: &str) -> Source {
    Source {
        component: component.into(),
        member: format!("{component}.im4p"),
        container_sha256: "0".repeat(64),
        payload_type: "test".into(),
        description: "synthetic".into(),
        decoded_bytes: 0,
        decoded_sha256: "0".repeat(64),
    }
}

/// An auxiliary collection as `aux_kc` lays one out, a page a segment.
fn auxiliary_collection() -> Vec<u8> {
    Builder::new(macho::MH_FILESET)
        .segment("__PRELINK_INFO", PAGE, &page(0))
        .segment("__DATA", PAGE, &page(1))
        .segment("__TEXT", PAGE, &page(2))
        .segment("__PRELINK_TEXT", PAGE, &page(3))
        .segment("__DATA_CONST", PAGE, &page(4))
        .segment("__RECEIPT_INFO", PAGE, &page(5))
        .segment("__TEXT_EXEC", PAGE, &page(6))
        .segment("__LINKEDIT", PAGE, &page(7))
        .fileset("com.stela.StelaGPU", BASE + 3 * PAGE)
        .build()
}

fn page(fill: u8) -> Vec<u8> {
    vec![fill; PAGE as usize]
}

fn kernel() -> Vec<u8> {
    Builder::new(macho::MH_FILESET)
        .segment("__TEXT", PAGE, &page(0))
        .segment("__DATA_SPTM", PAGE, &page(1))
        .segment("__TEXT_EXEC", PAGE, &page(2))
        .segment("__TEXT_BOOT_EXEC", PAGE, &page(3))
        .segment("__PRELINK_INFO", PAGE, &page(4))
        .segment("__DATA", PAGE, &page(5))
        .segment("__LINKEDIT", PAGE, &page(6))
        .fileset("com.apple.kernel", BASE)
        .thread(BASE + 3 * PAGE)
        .build()
}

fn sptm() -> Vec<u8> {
    Builder::new(macho::MH_EXECUTE)
        .segment("__TEXT", PAGE, &page(0))
        .segment("__TEXT_EXEC", PAGE, &page(7))
        .segment("__DATA", PAGE, &page(8))
        .segment("__LINKEDIT", PAGE, &[9; 0x20])
        .thread(BASE + PAGE + 0x388)
        .build()
}

fn txm() -> Vec<u8> {
    Builder::new(macho::MH_EXECUTE)
        .segment("__TEXT", PAGE, &page(0))
        .segment("__TEXT_EXEC", PAGE, &page(10))
        .segment("__TEXT_BOOT_EXEC", PAGE, &page(11))
        .segment("__DATA", PAGE, &page(12))
        .segment("__LINKEDIT", PAGE, &[13; 0x20])
        .thread(BASE + 2 * PAGE)
        .build()
}

fn device_tree() -> Vec<u8> {
    let mut tree = DeviceTree {
        root: crate::apple_device_tree::Node::named("device-tree").unwrap(),
    };
    for child in ["chosen", "cpus", "vram", "pram"] {
        tree.ensure_child("/", child).unwrap();
    }
    tree.ensure_child("/chosen", "memory-map").unwrap();
    lock_regs::tests::template(&mut tree, false).unwrap();
    tree.ensure_child("/cpus", "cpu0").unwrap();
    tree.set_property("/cpus/cpu0", "state", b"waiting\0".to_vec())
        .unwrap();
    tree.set_property("/cpus/cpu0", "cluster-type", b"E\0".to_vec())
        .unwrap();
    tree.set_property("/cpus/cpu0", "reg", 0u32.to_le_bytes().to_vec())
        .unwrap();
    tree.set_property("/vram", "reg", vec![0; 16]).unwrap();
    tree.set_property("/pram", "reg", vec![0; 16]).unwrap();
    tree.set_property("/chosen", "random-seed", vec![0; 0x100])
        .unwrap();
    tree.set_property("/chosen", "cl4-entropy", vec![0; 0xc0])
        .unwrap();
    for index in 0..17 {
        tree.set_property(
            "/chosen/memory-map",
            &format!("MemoryMapReserved-{index}"),
            vec![0; 16],
        )
        .unwrap();
    }
    let chosen = tree.node_mut("/chosen").unwrap();
    chosen
        .set_property(
            "software-behavior",
            b"syscfg/SwBh/0x10,zeroes/0x10\0".to_vec(),
        )
        .unwrap();
    chosen
        .set_property(
            "mac-address-wifi0",
            b"macaddr/wifiaddr,syscfg/WMac/6\0".to_vec(),
        )
        .unwrap();
    chosen
        .set_property("repair-status", b"syscfg/rpcp\0".to_vec())
        .unwrap();
    for property in &mut chosen.properties[3..] {
        property.placeholder = true;
    }
    // Security inputs the template carries, with typed manifest slots.
    for (name, bytes) in [
        ("boot-manifest-hash", 48),
        ("effective-production-status-ap", 4),
        ("effective-security-mode-ap", 4),
        ("sepfw-load-at-boot", 4),
        ("osenvironment", 32),
        ("display-rotation", 4),
        ("display-scale", 4),
        ("display-boot-rotation", 4),
    ] {
        tree.set_property("/chosen", name, vec![0; bytes]).unwrap();
    }
    tree.set_property("/chosen", "cs-system-policy", b"default\0".to_vec())
        .unwrap();
    tree.ensure_child("/chosen", "manifest-properties").unwrap();
    for (slot, bytes) in [
        ("UnusedIntegerProperty0", 8),
        ("UnusedIntegerProperty1", 8),
        ("UnusedBooleanProperty0", 4),
        ("UnusedBooleanProperty1", 4),
    ] {
        tree.set_property("/chosen/manifest-properties", slot, vec![0; bytes])
            .unwrap();
    }
    tree.serialize()
}

fn boot_manifest() -> Vec<u8> {
    use crate::im4m::tests::{der, entry, manifest};
    manifest(
        &[
            entry("BORD", &der(&[0x02], &[0x2e])),
            entry("CPRO", &der(&[0x01], &[0xff])),
            entry("CSEC", &der(&[0x01], &[0xff])),
            entry("SDOM", &der(&[0x02], &[1])),
        ],
        &[entry("test", &der(&[0x31], &[]))],
    )
}

#[test]
fn die_count_follows_each_chips_iboot_rule() -> Result<()> {
    let tree = |dies: &[Option<u32>]| -> Result<DeviceTree> {
        let mut tree = DeviceTree {
            root: crate::apple_device_tree::Node::named("device-tree")?,
        };
        tree.ensure_child("/", "cpus")?;
        tree.ensure_child("/", "arm-io")?;
        for (index, die) in dies.iter().enumerate() {
            let cpu = format!("cpu{index}");
            tree.ensure_child("/cpus", &cpu)?;
            let path = format!("/cpus/{cpu}");
            tree.set_property(&path, "state", b"waiting\0".to_vec())?;
            if let Some(die) = die {
                // The templates carry die-id as a 64-bit cell pair.
                tree.set_property(&path, "die-id", u64::from(*die).to_le_bytes().to_vec())?;
            }
        }
        Ok(tree)
    };
    let two = [Some(0), Some(0), Some(1), Some(1)];
    let one = [Some(0), Some(0)];
    let count = |dies: &[Option<u32>], chip| -> Result<Option<u32>> {
        let mut tree = tree(dies)?;
        assert_eq!(set_die_count(&mut tree, Some(chip))?, None);
        Ok(tree
            .property("/arm-io", "die-count")
            .map(|p| u32::from_le_bytes(p.value[..].try_into().unwrap())))
    };
    // The iBoots without the row, and the chip rules of those with it.
    for chip in NO_DIE_COUNT {
        assert_eq!(count(&one, chip)?, None);
    }
    for chip in ULTRAS {
        assert_eq!(count(&two, chip)?, Some(2));
        assert!(count(&one, chip).is_err());
    }
    for chip in [0x6000, 0x6021, 0x6031, 0x8122, 0x8152] {
        assert_eq!(count(&one, chip)?, Some(1));
        assert_eq!(count(&[None, None], chip)?, Some(1));
        assert!(count(&two, chip).is_err());
    }
    // The T6050's fused count is the variant's remaining CPU dies.
    assert_eq!(count(&two, FUSED_DIES)?, Some(2));
    assert_eq!(count(&one, FUSED_DIES)?, Some(1));
    let mut unknown = tree(&one)?;
    assert!(set_die_count(&mut unknown, None)?.is_some());
    assert!(unknown.property("/arm-io", "die-count").is_none());
    let mut malformed = tree(&[Some(1)])?;
    malformed.set_property("/cpus/cpu0", "die-id", vec![1])?;
    assert!(set_die_count(&mut malformed, Some(0x6002)).is_err());
    Ok(())
}

#[test]
fn fill_in_sources_follow_iboots_resolver() -> Result<()> {
    let options = Options {
        syscfg: BTreeMap::from([("ARXN".to_owned(), vec![9; 2])]),
        ..Options::default()
    };
    let value = |alternative: &str| alternative_value(alternative, alternative, &options);
    assert_eq!(value("hex/0200fA")?, Some(vec![2, 0, 0xfa]));
    assert_eq!(value("hex/0102/0x4")?, Some(vec![1, 2, 0, 0]));
    for refused in [
        "hex/012",
        "hex/0x12",
        "hex/+1",
        "hex/010203/0x2",
        "string/x",
    ] {
        assert!(value(refused).is_err(), "{refused}");
    }
    // No keybag provider is modelled: the source yields nothing.
    assert_eq!(value("syscfg-mismatch/ARXN")?, None);
    assert_eq!(value("syscfg/ARXN")?, Some(vec![9; 2]));
    Ok(())
}

#[test]
fn syscfg_recipe_lengths_truncate_pad_and_preserve_the_source() -> Result<()> {
    let options = Options {
        syscfg: BTreeMap::from([("Test".to_owned(), vec![1, 2, 3, 4])]),
        ..Options::default()
    };
    let value = |recipe: &str| alternative_value(recipe, recipe, &options);
    assert_eq!(value("syscfg/Test")?, Some(vec![1, 2, 3, 4]));
    assert_eq!(value("syscfg/Test/0x2")?, Some(vec![1, 2]));
    assert_eq!(value("syscfg/Test/4")?, Some(vec![1, 2, 3, 4]));
    assert_eq!(value("syscfg/Test/0x6")?, Some(vec![1, 2, 3, 4, 0, 0]));
    assert_eq!(value("syscfg/Test/0")?, Some(vec![]));
    assert_eq!(value("syscfg/None/0x2")?, None);
    assert!(value("syscfg/Test/no-size").is_err());
    assert_eq!(options.syscfg["Test"], [1, 2, 3, 4]);
    Ok(())
}

fn cpu_tree(layout: &[(&str, u32, u8)]) -> DeviceTree {
    let mut cpus = crate::apple_device_tree::Node::named("cpus").unwrap();
    for &(name, affinity, kind) in layout {
        let mut cpu = crate::apple_device_tree::Node::named(name).unwrap();
        cpu.set_property("reg", affinity.to_le_bytes().to_vec())
            .unwrap();
        cpu.set_property("cluster-type", vec![kind, 0]).unwrap();
        cpu.set_property("state", CPU_WAITING.to_vec()).unwrap();
        cpus.children.push(cpu);
    }
    let mut root = crate::apple_device_tree::Node::named("device-tree").unwrap();
    root.children.push(cpus);
    DeviceTree { root }
}

#[test]
fn boot_cpu_automatic_selection_preserves_original_order_and_publishes_one_running_node()
-> Result<()> {
    // Names and numeric affinities disagree with DT order.
    let original = cpu_tree(&[
        ("cpu9", 0x902, b'P'),
        ("cpu88", 0, b'E'),
        ("cpu1", 0x100, b'P'),
    ]);
    let mut tree = original.clone();
    tree.set_property("/cpus/cpu88", "state", CPU_RUNNING.to_vec())?;
    tree.set_property("/cpus/cpu1", "state", CPU_RUNNING.to_vec())?;
    let selected = select_boot_cpu(&tree, &original, None)?;
    assert_eq!(
        selected,
        BootCpu {
            path: "/cpus/cpu9".into(),
            affinity: 0x902,
            cluster_type: b'P',
            original_index: 0,
            selection: BootCpuSelection::First,
        }
    );
    mark_boot_cpu(&mut tree, &selected)?;
    verify_boot_cpu(&tree, &original, &selected)?;
    assert_eq!(cpu_identities(&tree)?, cpu_identities(&original)?);
    for (name, state) in [
        ("cpu9", CPU_RUNNING),
        ("cpu88", CPU_WAITING),
        ("cpu1", CPU_WAITING),
    ] {
        assert_eq!(
            tree.property(&format!("/cpus/{name}"), "state")
                .unwrap()
                .value,
            state
        );
    }
    assert_eq!(
        serde_json::to_value(&selected)?,
        serde_json::json!({
            "path": "/cpus/cpu9", "affinity": 0x902, "cluster_type": b'P',
            "original_index": 0, "selection": "first",
        })
    );
    Ok(())
}

#[test]
fn boot_cpu_explicit_override_remains_distinct_from_automatic_selection() -> Result<()> {
    let original = cpu_tree(&[("cpu0", 0, b'E'), ("cpu4", 0x100, b'P')]);
    let mut tree = original.clone();
    let selected = select_boot_cpu(&tree, &original, Some("cpu0"))?;
    assert_eq!(selected.selection, BootCpuSelection::Explicit);
    assert_eq!(
        (
            selected.path.as_str(),
            selected.affinity,
            selected.original_index
        ),
        ("/cpus/cpu0", 0, 0)
    );
    mark_boot_cpu(&mut tree, &selected)?;
    verify_boot_cpu(&tree, &original, &selected)?;
    assert_eq!(
        tree.property("/cpus/cpu4", "state").unwrap().value,
        CPU_WAITING
    );
    for name in ["", ".", "..", "cpu0/child", "/cpus/cpu0", "missing"] {
        assert!(
            select_boot_cpu(&tree, &original, Some(name)).is_err(),
            "{name}"
        );
    }
    let e_only = cpu_tree(&[("cpu0", 0, b'E')]);
    assert_eq!(
        select_boot_cpu(&e_only, &e_only, None)?.selection,
        BootCpuSelection::First
    );
    assert!(select_boot_cpu(&e_only, &e_only, Some("cpu0")).is_ok());
    let empty = cpu_tree(&[]);
    assert!(select_boot_cpu(&empty, &empty, None).is_err());
    Ok(())
}

#[test]
fn boot_cpu_invalid_source_fields_refuse_before_any_state_is_written() -> Result<()> {
    let original = cpu_tree(&[
        ("cpu0", 0, b'E'),
        ("cpu4", 0x100, b'P'),
        ("cpu5", 0x101, b'P'),
    ]);
    let selected = select_boot_cpu(&original, &original, None)?;
    for (property, value) in [
        ("state", b"running".to_vec()),
        ("state", b"unknown\0".to_vec()),
        ("cluster-type", vec![b'P', 0, 0]),
        ("cluster-type", vec![b'X', 0]),
        ("reg", 0x100u64.to_le_bytes().to_vec()),
    ] {
        let mut tree = original.clone();
        tree.set_property("/cpus/cpu4", property, value)?;
        let before = tree.clone();
        assert!(
            select_boot_cpu(&tree, &original, None).is_err(),
            "{property}"
        );
        assert!(mark_boot_cpu(&mut tree, &selected).is_err(), "{property}");
        assert_eq!(tree, before);
    }
    for property in ["state", "reg", "cluster-type"] {
        let mut tree = original.clone();
        tree.node_mut("/cpus/cpu4")
            .unwrap()
            .remove_property(property);
        let before = tree.clone();
        assert!(select_boot_cpu(&tree, &original, None).is_err());
        assert!(mark_boot_cpu(&mut tree, &selected).is_err());
        assert_eq!(tree, before);
    }
    let mut duplicate = original.clone();
    let cpu = duplicate.node("/cpus/cpu4").unwrap().clone();
    duplicate.node_mut("/cpus").unwrap().children.push(cpu);
    assert!(select_boot_cpu(&duplicate, &duplicate, None).is_err());
    let mut aliased = original.clone();
    aliased.set_property("/cpus/cpu5", "reg", 0x100u32.to_le_bytes().to_vec())?;
    assert!(select_boot_cpu(&aliased, &aliased, None).is_err());
    for property in ["name", "state", "reg", "cluster-type"] {
        let mut duplicate = original.clone();
        let repeated = duplicate.property("/cpus/cpu4", property).unwrap().clone();
        duplicate
            .node_mut("/cpus/cpu4")
            .unwrap()
            .properties
            .push(repeated);
        assert!(
            select_boot_cpu(&duplicate, &original, None).is_err(),
            "{property}"
        );
    }
    let mut unresolved = original.clone();
    unresolved
        .node_mut("/cpus/cpu4")
        .unwrap()
        .property_mut("reg")
        .unwrap()
        .placeholder = true;
    assert!(select_boot_cpu(&unresolved, &original, None).is_err());
    Ok(())
}

#[test]
fn boot_cpu_source_index_does_not_become_a_prepared_runtime_index() -> Result<()> {
    let original = cpu_tree(&[("source-removed", 0, b'E'), ("retained", 0x100, b'P')]);
    // A checked earlier variant projection may keep a
    // subset. Selection itself never removes or renames a CPU.
    let mut prepared = cpu_tree(&[("retained", 0x100, b'P')]);
    let selected = select_boot_cpu(&prepared, &original, None)?;
    assert_eq!(selected.original_index, 1);
    assert_eq!(
        prepared.node("/cpus").unwrap().children[0].name(),
        Some("retained")
    );
    mark_boot_cpu(&mut prepared, &selected)?;
    verify_boot_cpu(&prepared, &original, &selected)?;
    let mut forged = selected.clone();
    forged.original_index = 0;
    assert!(verify_boot_cpu(&prepared, &original, &forged).is_err());
    Ok(())
}

#[test]
fn boot_cpu_overlay_cannot_replace_the_selected_state_or_source_identity() -> Result<()> {
    let original = cpu_tree(&[
        ("cpu0", 0, b'E'),
        ("cpu4", 0x100, b'P'),
        ("cpu5", 0x101, b'P'),
    ]);
    let selected = select_boot_cpu(&original, &original, None)?;
    let mut prepared = original.clone();
    mark_boot_cpu(&mut prepared, &selected)?;
    for (path, property, value) in [
        ("/cpus/cpu4", "state", CPU_RUNNING.to_vec()),
        ("/cpus/cpu0", "state", CPU_WAITING.to_vec()),
        ("/cpus/cpu0", "reg", 0x999u32.to_le_bytes().to_vec()),
        ("/cpus/cpu0", "name", b"renamed\0".to_vec()),
        ("/cpus/cpu0", "cluster-type", b"P\0".to_vec()),
    ] {
        let mut tree = prepared.clone();
        apply_overlay(
            &mut tree,
            &[OverlayProperty {
                path: path.into(),
                property: property.into(),
                value,
            }],
        )?;
        assert!(
            verify_boot_cpu(&tree, &original, &selected).is_err(),
            "{path} {property}"
        );
    }
    let mut reordered = prepared.clone();
    reordered.node_mut("/cpus").unwrap().children.swap(0, 1);
    assert!(verify_boot_cpu(&reordered, &original, &selected).is_err());
    Ok(())
}

fn trust_cache() -> Vec<u8> {
    let mut module = 2u32.to_le_bytes().to_vec();
    module.extend([0; 16]);
    module.extend(1u32.to_le_bytes());
    module.extend([0xee; 24]);
    module
}

#[test]
fn unsupported_build_is_refused_before_image_parsing() {
    let input = || Input {
        bytes: &[],
        source: source("unparsed"),
    };
    let inputs = Inputs {
        target: Target {
            product_type: "Mac14,3".into(),
            device_class: "j473ap".into(),
            product_version: "unsupported".into(),
            product_build: "unsupported-build".into(),
            variant: "Customer Erase Install (IPSW)".into(),
            chip_id: Some(0x8112),
            board_id: Some(0x2e),
        },
        kernel_collection: input(),
        auxiliary_collection: None,
        sptm: input(),
        txm: input(),
        device_tree: input(),
        static_trust_cache: input(),
        sep_firmware: None,
        boot_manifest: None,
        cryptex1_manifest: None,
        extra_trust_caches: vec![],
        board_firmware: vec![],
        ramdisk: None,
        root_hash: None,
        pivot_root_hash: None,
        firmware_version: None,
    };
    let options = Options::default();
    let borrowed = prepare(&inputs, &options).err().unwrap();
    let owned = prepare_owned(
        &inputs,
        OwnedRamdisk {
            bytes: vec![],
            source: source("ramdisk"),
        },
        &options,
    )
    .err()
    .unwrap();
    for error in [borrowed, owned] {
        let crate::Error::UnsupportedBuild(error) = error else {
            panic!("expected an unsupported build, got {error}");
        };
        assert_eq!(error.build, "unsupported-build");
        assert!(
            error
                .supported
                .contains(&stela_formats::builds::DEFAULT.build)
        );
    }
}

#[test]
fn lays_out_sptm_regions_and_patch_slots() -> Result<()> {
    let (kernel, sptm, txm, tree, tc) = (kernel(), sptm(), txm(), device_tree(), trust_cache());
    let input = |bytes: &'static [u8], name: &str| Input {
        bytes,
        source: source(name),
    };
    let leak = |v: Vec<u8>| -> &'static [u8] { Box::leak(v.into_boxed_slice()) };
    let mut inputs = Inputs {
        target: Target {
            product_type: "Mac14,3".into(),
            device_class: "j473ap".into(),
            product_version: "27.0.1".into(),
            product_build: "26A434".into(),
            variant: "Customer Erase Install (IPSW)".into(),
            chip_id: Some(0x8112),
            board_id: Some(0x2e),
        },
        kernel_collection: input(leak(kernel), "KernelCache"),
        auxiliary_collection: None,
        sptm: input(leak(sptm), "Ap,SecurePageTableMonitor"),
        txm: input(leak(txm), "Ap,TrustedExecutionMonitor"),
        device_tree: input(leak(tree), "DeviceTree"),
        static_trust_cache: input(leak(tc), "StaticTrustCache"),
        sep_firmware: None,
        boot_manifest: Some(input(leak(boot_manifest()), "BootManifest")),
        cryptex1_manifest: None,
        extra_trust_caches: vec![],
        board_firmware: vec![(
            "USB-C_HPM,47.bin".into(),
            input(leak(vec![1, 2, 3]), "BoardFirmware"),
        )],
        ramdisk: Some(input(leak(vec![0x5a; 100]), "RestoreRamDisk")),
        root_hash: None,
        pivot_root_hash: None,
        firmware_version: None,
    };
    let options = Options {
        dram_base: 0x8_0000_0000,
        dram_size: 0x2_0000_0000,
        phys_base: 0x8_0000_0000,
        load_offset: 0,
        boot_args: "-v".into(),
        boot_cpu: Some("cpu0".into()),
        osenvironment: None,
        boot_command: None,
        root: None,
        ecid: None,
        timebase_frequency: 24_000_000,
        syscfg: BTreeMap::from([("SwBh".to_owned(), vec![7; 4])]),
        mac_addresses: BTreeMap::from([("wifiaddr".to_owned(), vec![2, 0, 0, 0, 0, 1])]),
        security: SecurityPolicy {
            mode: boot_policy::SecurityMode::Reduced,
            sip_bits: 0,
            sepfw_load_at_boot: None,
            kexts: None,
        },
        overlay: vec![OverlayProperty {
            path: "/chosen/lock-regs/amcc".into(),
            property: "aperture-count".into(),
            value: 1u32.to_le_bytes().to_vec(),
        }],
    };
    // DRAM must sit at the target board's base: an M2 Pro's placement is
    // refused for the M2, whose own base `placed_at` restores.
    let elsewhere = options.placed_at(Some(0x100_0000_0000));
    assert_eq!(
        (elsewhere.dram_base, elsewhere.phys_base),
        (0x100_0000_0000, 0x100_0000_0000)
    );
    let refusal = prepare(&inputs, &elsewhere).err().unwrap().to_string();
    assert!(
        refusal.contains("is not ApChipID 0x8112's 0x800000000"),
        "{refusal}"
    );
    assert_eq!(
        elsewhere.placed_at(inputs.dram_base()?).dram_base,
        options.dram_base
    );
    let bundle = prepare(&inputs, &options)?;
    // A change to the prepared content fails here until REVISION is bumped
    // and the new digest pinned with it.
    assert_eq!(
        (REVISION, prepared_digest(&bundle)?),
        (
            35,
            "bc204d9f21be77c04702696ad04180ba5e655d378b824333a3244e628608f17d".to_owned()
        )
    );
    let original = bundle
        .files
        .iter()
        .find(|(name, _)| name == ORIGINAL_DEVICE_TREE_FILE)
        .unwrap();
    assert_eq!(original.1, inputs.device_tree.bytes);
    assert!(
        !bundle
            .manifest
            .regions
            .iter()
            .any(|r| r.file == ORIGINAL_DEVICE_TREE_FILE)
    );
    // Origin is an independent loader input, not inferred from these
    // fixtures' OS environment or verbose-only command line.
    let origin_options = Options {
        boot_command: Some(handoff::BootCommand::TetheredRestore),
        ..options.clone()
    };
    let originated = prepare(&inputs, &origin_options)?;
    let origin_tree = DeviceTree::parse(
        &originated
            .files
            .iter()
            .find(|(name, _)| name == DEVICE_TREE_FILE)
            .unwrap()
            .1,
    )?;
    for (path, name) in [
        ("/chosen", "boot-command"),
        ("/chosen/handoff", "boot_type"),
    ] {
        assert_eq!(origin_tree.property(path, name).unwrap().as_u32(), Some(7));
    }
    assert!(
        !originated
            .manifest
            .unresolved
            .iter()
            .any(|gap| gap.starts_with("/chosen boot-command"))
    );
    // An owned ramdisk moves into the same bundle.
    let borrowed = inputs.ramdisk.take().expect("a ramdisk");
    let owned = OwnedRamdisk {
        bytes: borrowed.bytes.to_vec(),
        source: borrowed.source.clone(),
    };
    let moved = prepare_owned(&inputs, owned, &options)?;
    assert_eq!(
        serde_json::to_string(&moved.manifest)?,
        serde_json::to_string(&bundle.manifest)?
    );
    inputs.ramdisk = Some(borrowed);
    let twice = OwnedRamdisk {
        bytes: vec![1],
        source: source("RestoreRamDisk"),
    };
    assert!(prepare_owned(&inputs, twice, &options).is_err());
    // Board firmware travels unchanged under its guest file name, which
    // must not replace a bundle file.
    let firmware = bundle.files.iter().find(|(n, _)| n == "USB-C_HPM,47.bin");
    assert_eq!(firmware.map(|(_, b)| b.as_slice()), Some(&[1u8, 2, 3][..]));
    let supplied = core::mem::take(&mut inputs.board_firmware);
    inputs.board_firmware = vec![(KERNEL_FILE.into(), input(leak(vec![1]), "BoardFirmware"))];
    assert!(prepare(&inputs, &options).is_err());
    inputs.board_firmware = supplied;
    let manifest = &bundle.manifest;
    let names: Vec<_> = manifest.regions.iter().map(|r| r.name.as_str()).collect();
    // The manifest's carveout lies below the loaded images.
    let expected: Vec<_> = core::iter::once("BootManifest")
        .chain(REGION_ORDER.iter().copied().filter(|n| {
            !["SEPFW", lock_regs::CL4_DUMMY_PAGE].contains(n) && !n.starts_with("AuxKC")
        }))
        .collect();
    assert_eq!(names, expected);
    // The M1 to M3 hand off no core lock registers.
    assert!(manifest.core_locks.is_none());
    // The original input manifest is held byte for byte, with an exact
    // (not page-rounded) guest length.
    let manifest_region = manifest
        .regions
        .iter()
        .find(|r| r.name == "BootManifest")
        .unwrap();
    let original_manifest = inputs.boot_manifest.as_ref().unwrap().bytes;
    assert_eq!(
        bundle
            .files
            .iter()
            .find(|(n, _)| n == BOOT_MANIFEST_FILE)
            .unwrap()
            .1,
        original_manifest
    );
    let prepared_tree = DeviceTree::parse(
        &bundle
            .files
            .iter()
            .find(|(n, _)| n == DEVICE_TREE_FILE)
            .unwrap()
            .1,
    )?;
    assert_eq!(
        prepared_tree
            .property("/chosen/boot-object-manifests", "test")
            .unwrap()
            .value,
        range_value(manifest_region.guest_pa, original_manifest.len() as u64),
    );
    assert_eq!(
        prepared_tree
            .property("/chosen/secure-boot-hashes", "test")
            .unwrap()
            .value,
        im4m::sha384(original_manifest),
    );
    // In iBoot's loaded-object carveout, outside the memory SPTM gives XNU.
    let loaded_objects = manifest
        .carveouts
        .iter()
        .find(|c| c.id == carveouts::LOADED_OBJECTS)
        .unwrap();
    assert_eq!(manifest_region.guest_pa, loaded_objects.base);
    assert!(manifest_region.memory_bytes <= loaded_objects.bytes);
    // Regions are page-aligned, ascending and non-overlapping.
    for pair in manifest.regions.windows(2) {
        assert!(pair[0].guest_pa + pair[0].memory_bytes <= pair[1].guest_pa);
        assert_eq!(pair[1].guest_pa % PAGE, 0);
    }
    let region = |name: &str| manifest.regions.iter().find(|r| r.name == name).unwrap();
    assert_eq!(manifest.entry.image, "SPTM");
    assert_eq!(
        manifest.entry.physical_address,
        region("SPTM-rx").guest_pa + 0x388
    );
    assert_eq!(manifest.entry_x0, region("BootArgs").guest_pa);
    let kc = manifest.images.iter().find(|i| i.name == "BootKC").unwrap();
    assert_eq!(kc.entry.physical_address, region("BootKC-bx").guest_pa);
    assert_eq!(region("SPTM-le").memory_bytes, PAGE);
    // iBoot's carveouts sit below physBase, which starts past them.
    let phys_base = manifest.options.phys_base;
    assert_eq!(phys_base, 0x8_0200_0000);
    assert_eq!(manifest.boot_args.phys_base, phys_base);
    assert_eq!(manifest.boot_args.mem_size, 0xa_0000_0000 - phys_base);
    assert!(
        manifest
            .regions
            .iter()
            .filter(|r| r.name != "BootManifest")
            .all(|r| r.guest_pa >= phys_base)
    );
    assert!(
        manifest
            .carveouts
            .iter()
            .all(|c| c.base >= 0x8_0000_0000 && c.base + c.bytes <= phys_base)
    );
    // CTRR-A covers the read-only run, ending where SPTM's data starts.
    let ctrr = manifest.read_only_region.clone().unwrap();
    assert_eq!(ctrr.base, region("TXM-ro").guest_pa);
    assert_eq!(ctrr.base + ctrr.bytes, region("SPTM-rw").guest_pa);

    let file = |name: &str| &bundle.files.iter().find(|(n, _)| n == name).unwrap().1;
    let tree = DeviceTree::parse(file(DEVICE_TREE_FILE))?;
    let map = tree.node(MEMORY_MAP).unwrap();
    assert!(
        map.properties
            .iter()
            .all(|p| !p.name().starts_with(RESERVED_ENTRY_PREFIX))
    );
    let entry = |name: &str| map.property(name).unwrap().value.clone();
    let nvme = manifest.carveouts.iter().find(|c| c.id == 0x37).unwrap();
    assert_eq!(
        tree.property(carveouts::MEMORY_MAP, "region-id-55")
            .unwrap()
            .value,
        range_value(nvme.base, nvme.bytes)
    );
    // The panic region is XNU's panic buffer, below physBase.
    let panic = manifest.carveouts.iter().find(|c| c.id == 98).unwrap();
    assert_eq!(panic.bytes, 0x18_8000);
    assert_eq!(
        tree.property(carveouts::PRAM, "reg").unwrap().value,
        range_value(panic.base, panic.bytes)
    );
    assert_eq!(
        tree.property("/chosen", carveouts::PANIC_LOG_SIZE)
            .unwrap()
            .as_u32(),
        Some(0x18_8000)
    );
    assert_eq!(
        entry("TrustCache"),
        range_value(region("TrustCache").guest_pa, PAGE)
    );
    assert_eq!(entry("BootKC-entry"), range_value(3 * PAGE, 0));
    for name in ABSENT_SECURE_KERNEL {
        assert_eq!(entry(name), range_value(u64::MAX, u64::MAX));
    }
    assert_eq!(
        entry("SPTM-rm"),
        range_value(region("SPTM-ro").guest_pa, 4 * PAGE)
    );
    assert!(tree.placeholders().is_empty());
    assert_eq!(
        tree.property("/chosen", "mac-address-wifi0").unwrap().value,
        vec![2, 0, 0, 0, 0, 1]
    );
    let mut behavior = vec![7; 4];
    behavior.resize(16, 0);
    assert_eq!(
        tree.property("/chosen", "software-behavior").unwrap().value,
        behavior
    );
    assert!(tree.property("/chosen", "repair-status").is_none());
    for property in CPU_FREQUENCY_PROPERTIES {
        assert_eq!(
            tree.property("/cpus/cpu0", property).unwrap().as_u64(),
            Some(24_000_000)
        );
    }
    assert!(
        manifest
            .patches
            .iter()
            .any(|p| p.field == "/cpus/cpu0 timebase-frequency")
    );
    assert_eq!(
        tree.property("/cpus/cpu0", "state").unwrap().as_str(),
        Some("running")
    );
    assert_eq!(
        manifest.boot_cpu,
        Some(BootCpu {
            path: "/cpus/cpu0".into(),
            affinity: 0,
            cluster_type: b'E',
            original_index: 0,
            selection: BootCpuSelection::Explicit,
        })
    );
    assert_eq!(
        tree.property("/chosen", "chip-id").unwrap().as_u32(),
        Some(0x8112)
    );

    let args = boot_args::decode(file(BOOT_ARGS_FILE))?;
    assert_eq!(
        args.device_tree,
        region("DeviceTree").guest_pa - args.phys_base + args.virt_base
    );
    assert_eq!(
        args.device_tree_length as usize,
        file(DEVICE_TREE_FILE).len()
    );
    assert_eq!(args.top_of_kernel_data, region("BootArgs").guest_pa + PAGE);
    assert_eq!(args.command_line, "-v");

    // Every patch addresses its prepared bytes in its file.
    for patch in &manifest.patches {
        let bytes = file(&patch.file);
        let at = patch.file_offset as usize;
        assert_eq!(
            hex::encode(&bytes[at..at + patch.bytes as usize]),
            patch.prepared_hex,
            "{}",
            patch.field
        );
    }
    // Every region hash covers its file bytes.
    for region in &manifest.regions {
        let at = region.file_offset as usize;
        assert_eq!(
            sha256(&file(&region.file)[at..at + region.bytes as usize]),
            region.sha256
        );
    }
    assert!(manifest.unresolved.iter().any(|u| u.starts_with("SEPFW")));
    let ramdisk = region("RAMDisk");
    assert_eq!((ramdisk.bytes, ramdisk.memory_bytes), (100, PAGE));
    assert_eq!(
        map.property("RAMDisk").unwrap().value,
        range_value(ramdisk.guest_pa, PAGE)
    );
    assert!(!manifest.unresolved.iter().any(|u| u.contains("lock-regs")));
    assert!(manifest.unresolved.iter().any(|u| u.contains("lp-spih")));
    assert_eq!(
        tree.property("/chosen/asmb", "lp-smb0").unwrap().as_u32(),
        Some(1)
    );
    assert_eq!(
        tree.property("/chosen/lock-regs/amcc", "aperture-count")
            .unwrap()
            .as_u32(),
        Some(1)
    );
    assert_eq!(
        tree.property("/chosen/manifest-properties", "BORD")
            .unwrap()
            .as_u64(),
        Some(0x2e)
    );
    assert!(
        manifest
            .security
            .iter()
            .any(|d| d.property == "boot-manifest-hash")
    );
    // The mount's reader accepts the manifest, revision and all, and
    // reproduces the layout.
    assert_eq!(manifest.revision, REVISION);
    let json = serde_json::to_vec(manifest)?;
    let consumed = stela_formats::boot_bundle::Manifest::parse(&json)?;
    let mut changed_source = file(ORIGINAL_DEVICE_TREE_FILE).clone();
    changed_source[0] ^= 1;
    assert!(
        consumed
            .verify(&|name| {
                Some(if name == ORIGINAL_DEVICE_TREE_FILE {
                    changed_source.as_slice()
                } else {
                    file(name).as_slice()
                })
            })
            .is_err()
    );
    let verified = consumed.verify(&|name| Some(file(name).as_slice()))?;
    let span = (manifest.top_of_kernel_data - options.dram_base) as usize;
    let mut ram = vec![0u8; span];
    let machine = stela_formats::boot_bundle::Machine {
        dram_base: options.dram_base,
        ram_bytes: span as u64,
        dram_bytes: span as u64,
        timebase_hz: 24_000_000,
        framebuffer: None,
        boot_args: None,
        nvram: None,
    };
    let image = verified.load(
        &machine,
        &mut |b| {
            b.fill(7);
            Ok(())
        },
        &mut |pa, bytes| {
            let at = (pa - options.dram_base) as usize;
            ram[at..at + bytes.len()].copy_from_slice(bytes);
            true
        },
    )?;
    assert_eq!(image.entry_pa, manifest.entry.physical_address);
    assert_eq!(image.x0, manifest.entry_x0);
    let tc = region("TrustCache");
    let at = (tc.guest_pa - options.dram_base) as usize;
    assert_eq!(
        &ram[at..at + tc.bytes as usize],
        file(TRUST_CACHE_FILE).as_slice()
    );
    assert!(image.kept.iter().all(|field| field.contains("Video")
        || field.contains("vram")
        || field.contains("/chosen display-")
        || field.contains("CommandLine")));

    // An M4 bundle places iBoot's dummy CL4 page and states the core
    // lock registers SPTM checks, which the mount's reader takes.
    let m2 = (inputs.target.clone(), inputs.device_tree.bytes);
    let m2_manifest = inputs.boot_manifest.take();
    let mut m4_tree = DeviceTree::parse(inputs.device_tree.bytes)?;
    m4_tree.ensure_child("/", "arm-io")?;
    m4_tree.ensure_child("/arm-io", "mcc")?;
    m4_tree.set_property(
        "/arm-io/mcc",
        "dram-base",
        0x100_0000_0000u64.to_le_bytes().to_vec(),
    )?;
    inputs.device_tree.bytes = leak(m4_tree.serialize());
    inputs.target.chip_id = Some(0x8132);
    let m4_options = options.placed_at(inputs.dram_base()?);
    let m4_bundle = prepare(&inputs, &m4_options)?;
    inputs.target.chip_id = Some(0x8142);
    let m5_bundle = prepare(&inputs, &m4_options)?;
    // The M6 places no loaded-object carveout, so its manifest goes
    // unpublished, and says so.
    inputs.target.chip_id = Some(0x8152);
    inputs.boot_manifest = Some(input(leak(boot_manifest()), "BootManifest"));
    let m6_manifest = prepare(&inputs, &m4_options)?.manifest;
    assert!(m6_manifest.regions.iter().all(|r| r.name != "BootManifest"));
    assert!(
        m6_manifest
            .unresolved
            .iter()
            .any(|u| u.contains("loaded-object carveout 0x4c"))
    );
    (inputs.target, inputs.device_tree.bytes) = m2;
    inputs.boot_manifest = m2_manifest;
    let m4_manifest = &m4_bundle.manifest;
    let page = m4_manifest
        .regions
        .iter()
        .find(|r| r.name == lock_regs::CL4_DUMMY_PAGE)
        .unwrap();
    assert_eq!(page.memory_bytes, lock_regs::CL4_DUMMY_PAGE_BYTES as u64);
    let core_locks = m4_manifest.core_locks.as_ref().unwrap();
    let ctxr_b = core_locks
        .locked
        .iter()
        .find(|locked| locked.region == stela_formats::boot_bundle::schema::LockRegion::CtxrB)
        .unwrap();
    assert_eq!(
        (ctxr_b.first, ctxr_b.last),
        (page.guest_pa, page.guest_pa + page.memory_bytes - 1)
    );
    // The policy enables kernel CTRR, so CTRR-D is locked too.
    assert_eq!(core_locks.locked.len(), 6);
    let consumed = stela_formats::boot_bundle::Manifest::parse(&serde_json::to_vec(m4_manifest)?)?;
    assert_eq!(consumed.core_locks.as_ref(), Some(core_locks));
    assert_eq!(core_locks.tag_offset, 0);
    // An M5 bundle also locks TAG_OFFSET_EL2 at the top of the managed
    // range, which ends at DRAM's end.
    let dram_end = m4_options.dram_base + m4_options.dram_size;
    assert_eq!(
        m5_bundle.manifest.core_locks.unwrap().tag_offset,
        tag_storage::LOCK | (dram_end - tag_storage::bytes(m4_options.dram_size))
    );

    // A memory-device root cannot pivot to a disk image.
    let ramdisk_pivot = Options {
        boot_args: "-v rd=md0 rp0=file:///a.dmg".into(),
        root: Some(root_selection::Root::Ramdisk),
        ..options.clone()
    };
    let refusal = prepare(&inputs, &ramdisk_pivot).err().unwrap().to_string();
    assert!(refusal.contains("memory device md0"), "{refusal}");

    // With SEP firmware, SEPFW is a reserved, zero-filled staging region
    // between RAMDisk and BootArgs that holds the image's IMG4 container;
    // the image itself travels as a bundle file for the run-time load.
    let sep = vec![0x5e; 3 * PAGE as usize];
    inputs.sep_firmware = Some(input(leak(sep.clone()), "RestoreSEP"));
    let staged = prepare(&inputs, &options)?;
    inputs.sep_firmware = None;
    let names: Vec<_> = staged.manifest.regions.iter().map(|r| &*r.name).collect();
    let expected: Vec<_> = core::iter::once("BootManifest")
        .chain(
            REGION_ORDER
                .iter()
                .copied()
                .filter(|n| *n != lock_regs::CL4_DUMMY_PAGE && !n.starts_with("AuxKC")),
        )
        .collect();
    assert_eq!(names, expected);
    let sepfw = staged
        .manifest
        .regions
        .iter()
        .find(|r| r.name == "SEPFW")
        .unwrap();
    assert_eq!(sepfw.bytes, 0);
    assert_eq!(sepfw.memory_bytes, 4 * PAGE);
    assert!(sepfw.memory_bytes >= stela_formats::img4::container(&sep).len() as u64);
    let file = |name: &str| &staged.files.iter().find(|(n, _)| n == name).unwrap().1;
    assert_eq!(file(SEP_FILE), &sep);
    let tree = DeviceTree::parse(file(DEVICE_TREE_FILE))?;
    assert_eq!(
        tree.property(MEMORY_MAP, "SEPFW").unwrap().value,
        range_value(sepfw.guest_pa, sepfw.memory_bytes)
    );
    assert!(
        !staged
            .manifest
            .unresolved
            .iter()
            .any(|u| u.starts_with("SEPFW"))
    );

    // An auxiliary collection's read-only and executable regions join
    // SPTM's run before the boot collection's; its writable ones follow
    // the boot collection's.
    inputs.auxiliary_collection = Some(input(leak(auxiliary_collection()), "AuxKC"));
    let linked = prepare(&inputs, &options)?;
    let names: Vec<_> = linked
        .manifest
        .regions
        .iter()
        .map(|r| r.name.as_str())
        .collect();
    let at = |name: &str| names.iter().position(|n| *n == name).unwrap();
    assert_eq!(
        names[at("TrustCache")..=at("BootKC-rx")],
        ["TrustCache", "AuxKC-ro", "AuxKC-rx", "BootKC-rx"]
    );
    assert_eq!(
        names[at("BootKC-rw")..=at("AuxKC-le")],
        ["BootKC-rw", "BootKC-le", "AuxKC-rw", "AuxKC-le"]
    );
    let region = |name: &str| {
        linked
            .manifest
            .regions
            .iter()
            .find(|r| r.name == name)
            .unwrap()
    };
    assert_eq!(
        region("AuxKC-ro").guest_pa + 4 * PAGE,
        region("AuxKC-rx").guest_pa
    );
    for (name, offset, bytes) in [
        ("AuxKC-rw", 0, 2 * PAGE),
        ("AuxKC-ro", 2 * PAGE, 4 * PAGE),
        ("AuxKC-rx", 6 * PAGE, PAGE),
        ("AuxKC-le", 7 * PAGE, PAGE),
    ] {
        let piece = region(name);
        assert_eq!(
            (piece.file.as_str(), piece.file_offset, piece.memory_bytes),
            (AUXILIARY_FILE, offset, bytes)
        );
        assert_eq!(piece.virtual_address, Some(BASE + offset));
    }
    let file = |name: &str| &linked.files.iter().find(|(n, _)| n == name).unwrap().1;
    assert_eq!(file(AUXILIARY_FILE).len() as u64, 8 * PAGE);
    let tree = DeviceTree::parse(file(DEVICE_TREE_FILE))?;
    assert_eq!(
        tree.property(MEMORY_MAP, "AuxKC-rx").unwrap().value,
        range_value(region("AuxKC-rx").guest_pa, PAGE)
    );
    assert!(
        linked
            .manifest
            .sources
            .iter()
            .any(|source| source.component == "AuxKC")
    );
    inputs.auxiliary_collection = None;

    // A manifest for another board is refused.
    let mut other = Inputs { ..inputs };
    other.target.board_id = Some(0x24);
    assert!(prepare(&other, &options).is_err());
    Ok(())
}

mod metadata;
