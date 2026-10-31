use super::*;
use crate::apple_device_tree::Node;
use crate::im4m;
use crate::im4m::tests::{der, entry, manifest};
use anyhow::Result;

fn tree() -> DeviceTree {
    let mut tree = DeviceTree {
        root: Node::named("device-tree").unwrap(),
    };
    tree.ensure_child("/", "chosen").unwrap();
    tree.ensure_child("/chosen", "manifest-properties").unwrap();
    tree.ensure_child("/", "product").unwrap();
    for (name, bytes) in [
        ("boot-manifest-hash", 48),
        ("effective-production-status-ap", 4),
        ("effective-security-mode-ap", 4),
        ("sepfw-load-at-boot", 4),
        ("osenvironment", 32),
        ("certificate-production-status", 4),
        ("certificate-security-mode", 4),
    ] {
        tree.set_property("/chosen", name, vec![0; bytes]).unwrap();
    }
    tree.set_property("/chosen", "cs-system-policy", b"default\0".to_vec())
        .unwrap();
    for (slot, bytes) in [(INTEGER_SLOT, 8), (BOOLEAN_SLOT, 4), (STRING_SLOT, 0x40)] {
        for index in 0..3 {
            tree.set_property(
                MANIFEST_PROPERTIES,
                &format!("{slot}{index}"),
                vec![0; bytes],
            )
            .unwrap();
        }
    }
    tree
}

fn boot_manifest() -> Manifest {
    im4m::parse(&manifest(
        &[
            entry("CPRO", &der(&[0x01], &[0xff])),
            entry("CSEC", &der(&[0x01], &[0xff])),
            entry("SDOM", &der(&[0x02], &[1])),
            entry("CEPO", &der(&[0x02], &[1])),
            entry("love", &der(&[0x04], b"26.1.434.0.0,0")),
        ],
        &[],
    ))
    .unwrap()
}

#[test]
fn a_kext_grant_relaxes_only_the_kext_flags_and_names_its_digests() -> Result<()> {
    let digest = |byte: u8| hex::encode([byte; 48]);
    let mut tree = tree();
    let policy = SecurityPolicy {
        sip_bits: 0x10,
        kexts: Some(KextGrant {
            approved: digest(1),
            collection: digest(2),
            receipt: digest(3),
        }),
        ..SecurityPolicy::default()
    };
    apply(&mut tree, &policy, None, None)?;
    let value = |name: &str| tree.property(ASMB, name).unwrap().value.clone();
    assert_eq!(value("lp-sip0"), integer(0x211));
    assert_eq!(value("lp-smb2"), boolean(true));
    assert_eq!(value("lp-auxp"), [1; 48]);
    assert_eq!(value("lp-auxi"), [2; 48]);
    assert_eq!(value("lp-auxr"), [3; 48]);

    let mut tree = self::tree();
    let refused = SecurityPolicy {
        kexts: Some(KextGrant {
            approved: "ab".into(),
            collection: digest(2),
            receipt: digest(3),
        }),
        ..SecurityPolicy::default()
    };
    assert!(apply(&mut tree, &refused, None, None).is_err());
    Ok(())
}

#[test]
fn reduced_security_is_expressed_as_device_tree_data() -> Result<()> {
    let mut tree = tree();
    let boot = boot_manifest();
    let cryptex = im4m::parse(&manifest(&[entry("SDOM", &der(&[0x02], &[1]))], &[]))?;
    let policy = SecurityPolicy {
        mode: SecurityMode::Reduced,
        sip_bits: 0,
        sepfw_load_at_boot: Some(false),
        kexts: None,
    };
    let (decisions, unresolved) = apply(&mut tree, &policy, Some(&boot), Some(&cryptex))?;
    assert!(unresolved.is_empty());
    let value = |path: &str, name: &str| tree.property(path, name).unwrap().value.clone();
    assert_eq!(value(ASMB, "lp-smb0"), boolean(true));
    assert_eq!(value(ASMB, "lp-smb1"), boolean(false));
    assert_eq!(value(ASMB, "lp-sip0"), integer(0));
    assert_eq!(hex::encode(value(ASMB, "lp-spih")), cryptex.sha384);
    assert_eq!(
        hex::encode(value(CHOSEN, "boot-manifest-hash")),
        boot.sha384
    );
    assert_eq!(value(CHOSEN, "effective-security-mode-ap"), boolean(true));
    assert_eq!(value(CHOSEN, "security-domain"), 1u32.to_le_bytes());
    assert_eq!(value(CHOSEN, "sepfw-load-at-boot"), boolean(false));
    assert_eq!(value(MANIFEST_PROPERTIES, "CPRO"), boolean(true));
    // The fused state and epoch of an undemoted production chip.
    assert_eq!(
        value(CHOSEN, "certificate-production-status"),
        boolean(true)
    );
    assert_eq!(value(CHOSEN, "certificate-security-mode"), boolean(true));
    assert_eq!(value(CHOSEN, "chip-epoch"), 1u32.to_le_bytes());
    for flag in UNIT_FLAGS {
        assert_eq!(value(CHOSEN, flag), boolean(false));
    }
    assert_eq!(value(CHOSEN, "kernel-ctrr-to-be-enabled"), boolean(true));
    assert_eq!(value(PRODUCT, "allow-hactivation"), boolean(false));
    assert_eq!(value(CHOSEN, "boot-nonce-hash-method"), b"sha2-384\0");
    assert_eq!(value(MANIFEST_PROPERTIES, "love"), b"26.1.434.0.0,0");
    // The slots keep their place; one of each kind remains.
    assert!(
        tree.property(MANIFEST_PROPERTIES, "UnusedIntegerProperty0")
            .is_none()
    );
    assert!(
        tree.property(MANIFEST_PROPERTIES, "UnusedIntegerProperty2")
            .is_some()
    );
    assert!(decisions.iter().any(|d| d.property == "cs-system-policy"));
    Ok(())
}

#[test]
fn a_custom_kernel_or_sip2_turns_kernel_ctrr_off() {
    let mut tree = tree();
    tree.ensure_child(CHOSEN, "asmb").unwrap();
    assert!(kernel_ctrr(&tree).0);
    tree.set_property(ASMB, "lp-sip2", boolean(true)).unwrap();
    assert!(!kernel_ctrr(&tree).0);
    tree.set_property(ASMB, "lp-sip2", boolean(false)).unwrap();
    tree.set_property(ASMB, "lp-coih", vec![0; 48]).unwrap();
    assert!(!kernel_ctrr(&tree).0);
}

#[test]
fn a_development_chip_leaves_its_unit_fuses_and_epoch_unresolved() -> Result<()> {
    let development = im4m::parse(&manifest(
        &[
            entry("CPRO", &der(&[0x01], &[0x00])),
            entry("CSEC", &der(&[0x01], &[0xff])),
            entry("SDOM", &der(&[0x02], &[1])),
        ],
        &[],
    ))?;
    let mut tree = tree();
    let policy = SecurityPolicy {
        mode: SecurityMode::Reduced,
        sip_bits: 0,
        sepfw_load_at_boot: None,
        kexts: None,
    };
    let (_, unresolved) = apply(&mut tree, &policy, Some(&development), None)?;
    assert!(unresolved.iter().any(|gap| gap.contains("chip-epoch")));
    assert!(
        unresolved
            .iter()
            .any(|gap| gap.contains("internal-use-only-unit"))
    );
    assert!(tree.property(CHOSEN, "internal-use-only-unit").is_none());
    assert_eq!(
        tree.property(CHOSEN, "certificate-production-status")
            .unwrap()
            .value,
        boolean(false)
    );
    Ok(())
}

#[test]
fn a_root_snapshot_is_named_in_chosen_as_a_string() -> Result<()> {
    let mut tree = tree();
    let (decisions, unresolved) = apply_root_snapshot(&mut tree, "com.apple.os.update-9A91")?;
    assert!(unresolved.is_empty());
    assert_eq!(decisions.len(), 1);
    assert_eq!(
        tree.property(CHOSEN, "root-snapshot-name").unwrap().value,
        b"com.apple.os.update-9A91\0"
    );
    Ok(())
}

#[test]
fn a_base_system_root_needs_a_file_image_boot_argument() {
    let image = "rp0=file:///usr/standalone/firmware/arm64eBaseSystem.dmg";
    assert!(require_image_boot(&format!("-v {image}")).is_ok());
    assert!(require_image_boot("root-dmg=file:///a.dmg").is_ok());
    // A ramdisk root alone, another scheme or another argument is refused.
    assert!(require_image_boot("-v rd=md0").is_err());
    assert!(require_image_boot("rp0=http://host/a.dmg").is_err());
    assert!(require_image_boot("xrp0=file:///a.dmg").is_err());
}

#[test]
fn a_memory_device_root_cannot_pivot_to_an_image() {
    let image = "rp0=file:///usr/standalone/firmware/arm64eBaseSystem.dmg";
    // The rec-r5 boot-args: APFS took md0 again for the image root.
    let error = require_image_boot(&format!("-v rd=md0 {image}"))
        .unwrap_err()
        .to_string();
    assert!(error.contains("memory device md0"), "{error}");
    assert!(refuse_ramdisk_image_root(&format!("rootdev=mdf {image}")).is_err());
    assert!(refuse_ramdisk_image_root(&format!("{image} rd=md1")).is_err());
    // APFS reads `rd=` before `rootdev=`, and only `md` and one character.
    assert_eq!(ramdisk_root_device("rd=disk1s1 rootdev=md0"), None);
    assert_eq!(ramdisk_root_device("rd=md10"), None);
    assert_eq!(ramdisk_root_device("rootdev=md0"), Some("md0"));
    assert_eq!(ramdisk_root_device("rd=md0 rd=disk0"), Some("md0"));
    // A memory-device root without an image (a restore) stays allowed.
    assert!(refuse_ramdisk_image_root("-v rd=md0 -restore").is_ok());
    assert!(refuse_ramdisk_image_root(image).is_ok());
}

#[test]
fn os_environments_are_named_as_iboot_names_them() {
    for environment in OsEnvironment::ALL {
        assert_eq!(os_environment(environment.name()).unwrap(), environment);
    }
    assert_eq!(OsEnvironment::Recoveryos.node(), "recoveryos-environment");
    assert!(os_environment("recovery-environment").is_err());
}

fn environment_entry(tree: &mut DeviceTree, entry: &str, values: &[(&str, &[u8])]) {
    let path = format!("{ENVIRONMENTS}/darwinos-ramdisk-environment");
    tree.ensure_child(&path, entry).unwrap();
    for (property, value) in values {
        tree.set_property(&format!("{path}/{entry}"), property, value.to_vec())
            .unwrap();
    }
}

#[test]
fn environment_overlays_set_properties_and_replace_nodes() -> Result<()> {
    let mut tree = tree();
    tree.ensure_child("/", "osenvironments")?;
    tree.ensure_child(ENVIRONMENTS, "darwinos-ramdisk-environment")?;
    environment_entry(
        &mut tree,
        "no-sepfw-load-at-boot",
        &[
            ("node_path", b"chosen\0"),
            ("property_name", b"sepfw-load-at-boot\0"),
            ("value", &[0, 0, 0, 0]),
        ],
    );
    environment_entry(
        &mut tree,
        "data-volume",
        &[
            ("node", b"fstab\0"),
            ("replacement", b"fstab-ephemeral\0"),
            ("parent", b"/filesystems\0"),
        ],
    );
    environment_entry(
        &mut tree,
        "absent",
        &[
            ("node", b"fstab\0"),
            ("replacement", b"fstab-other\0"),
            ("parent", b"/nowhere\0"),
        ],
    );
    tree.ensure_child("/", "filesystems")?;
    tree.ensure_child("/filesystems", "fstab")?;
    tree.ensure_child("/filesystems", "fstab-ephemeral")?;
    tree.set_property("/filesystems/fstab-ephemeral", "marker", vec![1])?;
    tree.set_property("/chosen", "sepfw-load-at-boot", boolean(true))?;
    let (decisions, unresolved) = apply_environment(&mut tree, OsEnvironment::DarwinosRamdisk)?;
    assert_eq!(
        tree.property(CHOSEN, "sepfw-load-at-boot").unwrap().value,
        boolean(false)
    );
    assert_eq!(
        tree.property(CHOSEN, OSENVIRONMENT).unwrap().value,
        b"darwinos-ramdisk\0"
    );
    assert_eq!(
        tree.property("/filesystems/fstab", "marker").unwrap().value,
        vec![1]
    );
    assert!(tree.node("/filesystems/fstab-ephemeral").is_none());
    assert_eq!(decisions.len(), 3);
    assert_eq!(unresolved.len(), 1);
    assert!(apply_environment(&mut tree, OsEnvironment::Kcgen).is_err());
    Ok(())
}

#[test]
fn missing_manifests_stay_visible_and_permissive_sets_smb1() -> Result<()> {
    let mut tree = tree();
    let policy = SecurityPolicy {
        mode: SecurityMode::Permissive,
        sip_bits: 0x7f,
        sepfw_load_at_boot: None,
        kexts: None,
    };
    let (_, unresolved) = apply(&mut tree, &policy, None, None)?;
    assert_eq!(unresolved.len(), 2);
    assert_eq!(tree.property(ASMB, "lp-smb1").unwrap().value, boolean(true));
    assert_eq!(tree.property(ASMB, "lp-sip0").unwrap().as_u64(), Some(0x7f));
    assert_eq!(
        tree.property(CHOSEN, "boot-manifest-hash").unwrap().value,
        vec![0; 48]
    );
    Ok(())
}

#[test]
fn the_root_hash_record_is_forwarded_once_the_boot_manifest_signs_it() -> Result<()> {
    let im4p = der(
        &[0x30],
        &[
            der(&[0x16], b"IM4P"),
            der(&[0x16], b"csys"),
            der(&[0x16], b"root hash"),
            der(&[0x04], &[0x5a; 208]),
        ]
        .concat(),
    );
    let signed = manifest(
        &[entry("SDOM", &der(&[0x02], &[1]))],
        &[entry(
            "csys",
            &der(&[0x31], &entry("DGST", &der(&[0x04], &im4m::sha384(&im4p)))),
        )],
    );
    let parsed = im4m::parse(&signed)?;
    let mut tree = tree();
    let (decisions, unresolved) = apply_root_hash(
        &mut tree,
        SealedVolume::BaseSystem,
        Some(&im4p),
        Some((&signed, &parsed)),
    )?;
    assert!(unresolved.is_empty());
    assert_eq!(decisions.len(), 1);
    let blob = &tree
        .property(SECURE_BOOT_HASHES, "base-system-volume-auth-blob")
        .unwrap()
        .value;
    assert_eq!(blob, &[0x5a; 208]);

    // Without the object the gap is reported; a manifest that does not
    // sign it, or the wrong payload type, is refused.
    let (_, unresolved) = apply_root_hash(
        &mut tree,
        SealedVolume::System,
        None,
        Some((&signed, &parsed)),
    )?;
    assert!(unresolved[0].contains("system-volume-auth-blob"));
    let unsigned = boot_manifest();
    assert!(
        apply_root_hash(
            &mut tree,
            SealedVolume::BaseSystem,
            Some(&im4p),
            Some((&signed, &unsigned))
        )
        .is_err()
    );
    assert!(
        apply_root_hash(
            &mut tree,
            SealedVolume::System,
            Some(&im4p),
            Some((&signed, &parsed))
        )
        .is_err()
    );
    Ok(())
}
