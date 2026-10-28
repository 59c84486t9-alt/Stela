//! Verified selected-bundle provenance, distinct from its post-load live ADT.
//! No hash chooses a source family, creates hardware ownership or authenticates
//! an Apple container/signature. The actual resource factory checks geometry.
#[path = "source/clpc.rs"]
mod clpc;
#[path = "source/cpus.rs"]
mod cpus;
use alloc::{collections::BTreeSet, format, string::String, vec::Vec};
use sha2::Digest;
use stela_crypto::Sha256;
use stela_loader::{apple_device_tree::DeviceTree, boot_bundle::ORIGINAL_DEVICE_TREE_FILE};
use {
    stela_contracts::Chip, stela_formats::boot_bundle::Manifest,
    stela_formats::boot_bundle::Source, stela_formats::boot_bundle::Target,
    stela_formats::boot_bundle::Verified, stela_runtime::machine::soc::assigned::ResourceProfile,
    stela_runtime::machine::soc::assigned::SourceIdentity,
};

/// Retains the verified original and exact selected metadata. Original bytes
/// are never exposed mutably or installed as a guest memory region. Live ADT
/// bytes stay in Entry.live_tree, after all runtime fixed-offset patches.
pub(crate) struct Intake {
    original: Vec<u8>,
    original_sha256: [u8; 32],
    manifest_sha256: [u8; 32],
    manifest: Manifest,
    tree_source: usize,
    soc: u32,
    board: u32,
    cpus: cpus::Prepared,
    hidden_clpc: Vec<String>,
}

fn digest(value: &str) -> Result<[u8; 32], String> {
    fn nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }
    if value.len() != 64 {
        return Err("source provenance digest is not SHA-256".into());
    }
    let mut bytes = [0; 32];
    for (slot, pair) in bytes.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
        let high = nibble(pair[0]).ok_or("source provenance digest is not hexadecimal")?;
        let low = nibble(pair[1]).ok_or("source provenance digest is not hexadecimal")?;
        *slot = high * 16 + low;
    }
    if bytes == [0; 32] {
        return Err("source provenance digest is unknown/zero".into());
    }
    Ok(bytes)
}
fn text(value: &str) -> bool {
    !value.trim().is_empty() && !value.contains('\0')
}
fn word(tree: &DeviceTree, field: &str) -> Result<u32, String> {
    tree.property("/chosen", field)
        .filter(|p| !p.placeholder)
        .and_then(|p| p.as_u32())
        .ok_or_else(|| format!("live selected bundle requires complete /chosen/{field}"))
}

#[allow(
    dead_code,
    reason = "retained provenance getters also serve the parent Plan and owner join"
)]
impl Intake {
    /// Called only with the SAME json parsed into `verified.manifest` by the
    /// enclosing load_named path. Every file/region has already been verified;
    /// source metadata validation precedes Verified::load and its RAM effects.
    pub(super) fn from_verified<'a>(
        json: &[u8],
        verified: &Verified<'_>,
        named: &impl Fn(&str) -> Option<&'a [u8]>,
    ) -> Result<Self, String> {
        let manifest = verified.manifest;
        let target = manifest.target.as_ref().ok_or(
            "selected Apple bundle requires target/source provenance; reprepare with schema4",
        )?;
        let boot_cpu = manifest
            .boot_cpu
            .as_ref()
            .ok_or("selected Apple bundle requires boot_cpu provenance; reprepare with schema4")?;
        if [
            &target.product_type,
            &target.device_class,
            &target.product_version,
            &target.product_build,
            &target.variant,
        ]
        .into_iter()
        .any(|value| !text(value))
        {
            return Err("selected bundle target identity is incomplete".into());
        }
        let soc = target
            .chip_id
            .filter(|chip| *chip != 0)
            .ok_or("selected bundle lacks an explicit restore chip identity")?;
        // Board0 is a legitimate explicitly selected value, not a missing-ID
        // fallback. An absent board is independently refused.
        let board = target
            .board_id
            .ok_or("selected bundle lacks a restore board identity")?;
        let mut names = BTreeSet::new();
        for file in &manifest.files {
            if !names.insert(file.name.as_str()) {
                return Err("selected bundle repeats a file identity".into());
            }
        }
        let original_file = manifest
            .files
            .iter()
            .find(|file| file.name == ORIGINAL_DEVICE_TREE_FILE)
            .ok_or(
                "selected bundle lacks unchanged original-devicetree.adt; reprepare with schema4",
            )?;
        if manifest
            .regions
            .iter()
            .any(|region| region.file == ORIGINAL_DEVICE_TREE_FILE)
            || manifest
                .patches
                .iter()
                .any(|patch| patch.file == ORIGINAL_DEVICE_TREE_FILE)
        {
            return Err(
                "original DeviceTree metadata cannot be loaded or patched as guest RAM".into(),
            );
        }
        let original = named(ORIGINAL_DEVICE_TREE_FILE)
            .ok_or("verified original DeviceTree source disappeared")?;
        let original_sha256: [u8; 32] = Sha256::digest(original).into();
        if original.len() as u64 != original_file.bytes
            || original_sha256 != digest(&original_file.sha256)?
        {
            return Err("original DeviceTree differs from its verified whole-file identity".into());
        }
        let original_tree =
            DeviceTree::parse(original).map_err(|e| format!("original source ADT: {e}"))?;
        let mut selected = None;
        if manifest.sources.is_empty() {
            return Err("selected bundle has no original input source identities".into());
        }
        for (index, source) in manifest.sources.iter().enumerate() {
            if !text(&source.component)
                || !text(&source.member)
                || !text(&source.payload_type)
                || source.description.contains('\0')
                || source.decoded_bytes == 0
            {
                return Err("selected bundle input source identity is incomplete".into());
            }
            digest(&source.container_sha256)?;
            let decoded = digest(&source.decoded_sha256)?;
            // dtre is the actual Image4 payload tag; normal/restore component
            // names are retained verbatim rather than rewritten or guessed.
            if source.payload_type == "dtre" {
                if selected.replace(index).is_some() {
                    return Err("selected bundle has ambiguous DeviceTree source identities".into());
                }
                if source.decoded_bytes != original.len() as u64 || decoded != original_sha256 {
                    return Err(
                        "original DeviceTree does not match its selected decoded source".into(),
                    );
                }
            }
        }
        let tree_source = selected.ok_or("selected bundle has no dtre input provenance")?;
        let mut kept = Vec::new();
        kept.try_reserve_exact(original.len())
            .map_err(|_| "original DeviceTree source allocation failed")?;
        kept.extend_from_slice(original);
        let mut regions = manifest
            .regions
            .iter()
            .filter(|region| region.name == "DeviceTree");
        let region = regions
            .next()
            .ok_or("selected bundle lacks its prepared DeviceTree region")?;
        if regions.next().is_some() {
            return Err("selected bundle repeats its prepared DeviceTree region".into());
        }
        let file = named(&region.file).ok_or("verified prepared DeviceTree file disappeared")?;
        let start =
            usize::try_from(region.file_offset).map_err(|_| "prepared ADT offset overflows")?;
        let size = usize::try_from(region.bytes).map_err(|_| "prepared ADT length overflows")?;
        let end = start
            .checked_add(size)
            .ok_or("prepared ADT range overflows")?;
        let prepared = file
            .get(start..end)
            .ok_or("prepared ADT range is outside verified file")?;
        let prepared_tree =
            DeviceTree::parse(prepared).map_err(|e| format!("prepared selected ADT: {e}"))?;
        let cpus = cpus::Prepared::verify(&original_tree, &prepared_tree, boot_cpu)?;
        let hidden_clpc = clpc::verify(
            &original_tree,
            &prepared_tree,
            &manifest.hidden_devices,
            soc,
            board,
        )?;
        let intake = Self {
            original: kept,
            original_sha256,
            manifest_sha256: Sha256::digest(json).into(),
            manifest: manifest.clone(),
            tree_source,
            soc,
            board,
            cpus,
            hidden_clpc,
        };
        intake.validate_live(prepared)?;
        Ok(intake)
    }

    pub(crate) fn original(&self) -> &[u8] {
        &self.original
    }
    /// Logical PE in the verified prepared CPU order, independently derived
    /// from the selected original identity rather than its source index.
    pub(crate) fn boot_processor(&self) -> usize {
        self.cpus.processor()
    }
    pub(crate) fn hidden_clpc(&self) -> &[String] {
        &self.hidden_clpc
    }
    pub(crate) fn selected(&self) -> &Target {
        self.manifest
            .target
            .as_ref()
            .expect("validated selected target")
    }
    pub(crate) fn sources(&self) -> &[Source] {
        &self.manifest.sources
    }
    pub(crate) fn tree_source(&self) -> &Source {
        &self.manifest.sources[self.tree_source]
    }
    /// Exact parsed resource declarations used by file verification/load.
    pub(crate) fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    /// Exact raw selected bundle.json digest, not a digest fabricated from a
    /// filename/model or a reserialization that loses ignored source fields.
    pub(crate) fn manifest_sha256(&self) -> [u8; 32] {
        self.manifest_sha256
    }
    /// Caller supplies its actual runtime profile chip. The source-family
    /// factory must cross-check it against these selected IDs and source/live
    /// geometry. This operation grants no lifecycle or native executor state.
    pub(crate) fn topology_identity(&self, chip: Chip) -> Result<SourceIdentity, String> {
        if stela_runtime::machine::soc::chip(self.soc) != Some(chip) {
            return Err("selected restore chip differs from the actual runtime profile".into());
        }
        Ok(SourceIdentity {
            profile: ResourceProfile {
                chip,
                soc: self.soc,
                board: self.board,
                // Artifact/input-set binding is the exact selected manifest.
                // The actual live tree gets its own SourceBindings digest.
                input_set_sha256: self.manifest_sha256,
                adapted_set_sha256: None,
            },
            original_tree_sha256: self.original_sha256,
        })
    }
    /// Recheck selected identity and the entire verified prepared CPU sequence
    /// after runtime patches. PMGR/resource qualification remains independent.
    pub(super) fn validate_live(&self, bytes: &[u8]) -> Result<(), String> {
        let tree = DeviceTree::parse(bytes).map_err(|e| format!("live selected ADT: {e}"))?;
        if word(&tree, "chip-id")? != self.soc || word(&tree, "board-id")? != self.board {
            return Err("live DeviceTree differs from selected restore chip/board identity".into());
        }
        self.cpus.validate_live(&tree)?;
        clpc::validate_live(&tree, &self.hidden_clpc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use serde_json::{Value, json};
    use stela_loader::apple_device_tree::Node;

    fn tree(chip: u32, board: u32) -> Vec<u8> {
        let mut tree = DeviceTree {
            root: Node::named("device-tree").unwrap(),
        };
        tree.ensure_child("/", "chosen").unwrap();
        tree.set_property("/chosen", "chip-id", chip.to_le_bytes().to_vec())
            .unwrap();
        tree.set_property("/chosen", "board-id", board.to_le_bytes().to_vec())
            .unwrap();
        tree.ensure_child("/", "cpus").unwrap();
        for (name, affinity, kind) in [("cpu0", 0u32, b'E'), ("cpu4", 0x100, b'P')] {
            tree.ensure_child("/cpus", name).unwrap();
            let path = format!("/cpus/{name}");
            for (key, value) in [
                ("reg", affinity.to_le_bytes().to_vec()),
                ("cluster-type", vec![kind, 0]),
                (
                    "state",
                    if chip != 0 && kind == b'P' {
                        b"running\0".to_vec()
                    } else {
                        b"waiting\0".to_vec()
                    },
                ),
            ] {
                tree.set_property(&path, key, value).unwrap();
            }
        }
        tree.serialize()
    }
    fn fixture(original: &[u8], prepared: &[u8]) -> Value {
        json!({
            "schema_version": 4,
            "boot_cpu": {
                "path": "/cpus/cpu4", "affinity": 0x100, "cluster_type": 80,
                "original_index": 1, "selection": "first-performance"
            },
            "target": {
                "product_type": "declared-test", "device_class": "declared-test",
                "product_version": "test", "product_build": "test", "variant": "test",
                "chip_id": 0x6000, "board_id": 8
            },
            "sources": [{
                "component": "RestoreDeviceTree", "member": "Firmware/test.im4p",
                "container_sha256": stela_formats::sha256(b"synthetic container"),
                "payload_type": "dtre", "description": "",
                "decoded_bytes": original.len(), "decoded_sha256": stela_formats::sha256(original)
            }],
            "options": {"dram_base": 0x800000000u64, "dram_size": 0x40000000, "phys_base": 0x800000000u64},
            "files": [
                {"name": ORIGINAL_DEVICE_TREE_FILE, "bytes": original.len(), "sha256": stela_formats::sha256(original)},
                {"name": "devicetree.adt", "bytes": prepared.len(), "sha256": stela_formats::sha256(prepared)}
            ],
            "regions": [{
                "name": "DeviceTree", "file": "devicetree.adt", "file_offset": 0,
                "bytes": prepared.len(), "guest_pa": 0x800000000u64, "memory_bytes": 0x4000,
                "sha256": stela_formats::sha256(prepared)
            }],
            "entry": {"image": "synthetic", "virtual_address": 0, "physical_address": 0x800000000u64},
            "entry_x0": 0x800004000u64, "boot_args": {"command_line": "-v"},
            "top_of_kernel_data": 0x800008000u64, "patches": []
        })
    }
    fn intake_raw(json: &[u8], original: &[u8], prepared: &[u8]) -> Result<Intake, String> {
        let manifest = Manifest::parse(json).map_err(|e| format!("{e}"))?;
        let named = |name: &str| match name {
            ORIGINAL_DEVICE_TREE_FILE => Some(original),
            "devicetree.adt" => Some(prepared),
            _ => None,
        };
        let verified = manifest.verify(&named).map_err(|e| format!("{e}"))?;
        Intake::from_verified(json, &verified, &named)
    }
    fn intake(json: &Value, original: &[u8], prepared: &[u8]) -> Result<Intake, String> {
        intake_raw(&serde_json::to_vec(json).unwrap(), original, prepared)
    }

    #[test]
    fn exact_original_selected_metadata_and_manifest_artifact_survive_live_patches() {
        let original = tree(0, 0);
        let prepared = tree(0x6000, 8);
        let json = fixture(&original, &prepared);
        let raw = serde_json::to_vec(&json).unwrap();
        let source = intake_raw(&raw, &original, &prepared).unwrap();
        assert_eq!(source.original(), original);
        assert_eq!(source.boot_processor(), 1);
        assert_eq!(source.selected().chip_id, Some(0x6000));
        assert_eq!(source.selected().board_id, Some(8));
        assert_eq!(source.sources().len(), 1);
        assert_eq!(source.tree_source().component, "RestoreDeviceTree");
        assert_eq!(source.manifest().regions[0].file, "devicetree.adt");
        assert_eq!(
            source.manifest_sha256(),
            <[u8; 32]>::from(Sha256::digest(&raw))
        );
        let identity = source.topology_identity(Chip::AppleM1).unwrap();
        assert_eq!(
            identity.original_tree_sha256,
            <[u8; 32]>::from(Sha256::digest(&original))
        );
        assert_eq!(identity.profile.input_set_sha256, source.manifest_sha256());
        assert_eq!(identity.profile.adapted_set_sha256, None);
        assert!(source.topology_identity(Chip::AppleM2).is_err());
        let mut live = DeviceTree::parse(&prepared).unwrap();
        live.set_property("/chosen", "random-seed", vec![0x37; 64])
            .unwrap();
        assert!(source.validate_live(&live.serialize()).is_ok());
        assert_eq!(source.original(), original);
        live.set_property("/chosen", "board-id", 9u32.to_le_bytes().to_vec())
            .unwrap();
        assert!(source.validate_live(&live.serialize()).is_err());
        // Original template0 never becomes an observed selected identity.
        assert!(source.validate_live(&original).is_err());
        let mut changed = json;
        changed["ignored_input_annotation"] = json!("preserved by exact raw digest");
        let changed = intake(&changed, &original, &prepared).unwrap();
        assert_ne!(source.manifest_sha256(), changed.manifest_sha256());
        assert_eq!(source.selected(), changed.selected());
    }

    #[test]
    fn missing_old_or_ambiguous_provenance_refuses_after_real_file_verification() {
        let original = tree(0, 0);
        let prepared = tree(0x6000, 8);
        let base = fixture(&original, &prepared);
        for missing in ["target", "sources", "boot_cpu"] {
            let mut changed = base.clone();
            changed.as_object_mut().unwrap().remove(missing);
            assert!(intake(&changed, &original, &prepared).is_err());
        }
        for missing in ["chip_id", "board_id", "product_build"] {
            let mut changed = base.clone();
            changed["target"].as_object_mut().unwrap().remove(missing);
            assert!(intake(&changed, &original, &prepared).is_err());
        }
        for schema in 0..4 {
            let mut old = base.clone();
            old["schema_version"] = json!(schema);
            assert!(intake(&old, &original, &prepared).is_err());
        }
        let mut missing = base.clone();
        missing["files"].as_array_mut().unwrap().remove(0);
        assert!(intake(&missing, &original, &prepared).is_err());
        let mut repeated = base.clone();
        let file = repeated["files"][0].clone();
        repeated["files"].as_array_mut().unwrap().push(file);
        assert!(intake(&repeated, &original, &prepared).is_err());
        let mut repeated = base.clone();
        let source = repeated["sources"][0].clone();
        repeated["sources"].as_array_mut().unwrap().push(source);
        assert!(intake(&repeated, &original, &prepared).is_err());
        let mut repeated = base;
        let region = repeated["regions"][0].clone();
        repeated["regions"].as_array_mut().unwrap().push(region);
        assert!(intake(&repeated, &original, &prepared).is_err());
    }

    #[test]
    fn verified_boot_cpu_record_binds_source_identity_and_retained_runtime_position() {
        let original = tree(0, 0);
        let prepared = tree(0x6000, 8);
        let base = fixture(&original, &prepared);
        for (field, value) in [
            ("path", json!("/cpus/cpu0")),
            ("affinity", json!(0)),
            ("cluster_type", json!(b'E')),
            ("original_index", json!(0)),
            ("selection", json!("unknown")),
        ] {
            let mut changed = base.clone();
            changed["boot_cpu"][field] = value;
            assert!(intake(&changed, &original, &prepared).is_err(), "{field}");
        }
        let mut retained = DeviceTree::parse(&prepared).unwrap();
        retained.node_mut("/cpus").unwrap().children.remove(0);
        let retained = retained.serialize();
        let source = intake(&fixture(&original, &retained), &original, &retained).unwrap();
        assert_eq!(
            source.manifest().boot_cpu.as_ref().unwrap().original_index,
            1
        );
        assert_eq!(source.boot_processor(), 0);
        assert!(source.validate_live(&retained).is_ok());
        assert!(source.validate_live(&prepared).is_err());
        let mut live = DeviceTree::parse(&retained).unwrap();
        live.set_property("/cpus/cpu4", "state", b"waiting\0".to_vec())
            .unwrap();
        assert!(source.validate_live(&live.serialize()).is_err());
    }

    #[test]
    fn hidden_clpc_is_bound_to_verified_source_prepared_ledger_and_live_absence() {
        let mut original = DeviceTree::parse(&tree(0, 0)).unwrap();
        original.ensure_child("/", "counter-control").unwrap();
        original
            .set_property("/counter-control", "compatible", b"clpc,t8112\0".to_vec())
            .unwrap();
        let original = original.serialize();
        let mut prepared = DeviceTree::parse(&tree(0x6000, 8)).unwrap();
        prepared.ensure_child("/", "counter-control").unwrap();
        let prepared = prepared.serialize();
        let mut json = fixture(&original, &prepared);
        assert!(intake(&json, &original, &prepared).is_err());
        json["hidden_devices"] = json!(["/counter-control"]);
        let source = intake(&json, &original, &prepared).unwrap();
        assert_eq!(source.hidden_clpc(), ["/counter-control"]);
        let mut removed = DeviceTree::parse(&prepared).unwrap();
        removed
            .root
            .children
            .retain(|node| node.name() != Some("counter-control"));
        let removed = removed.serialize();
        let mut removed_manifest = fixture(&original, &removed);
        removed_manifest["hidden_devices"] = json!(["/counter-control"]);
        assert!(intake(&removed_manifest, &original, &removed).is_err());
        let mut live = DeviceTree::parse(&prepared).unwrap();
        live.set_property("/counter-control", "compatible", b"clpc,t8112\0".to_vec())
            .unwrap();
        assert!(source.validate_live(&live.serialize()).is_err());
        json["hidden_devices"] = json!(["/counter-control", "/counter-control"]);
        assert!(intake(&json, &original, &prepared).is_err());
    }

    #[test]
    fn unchanged_source_hash_extent_and_no_guest_loading_are_independent_requirements() {
        let original = tree(0, 0);
        let prepared = tree(0x6000, 8);
        let base = fixture(&original, &prepared);
        for (key, value) in [
            (
                "decoded_sha256",
                json!(stela_formats::sha256(b"different source")),
            ),
            ("decoded_bytes", json!(original.len() + 1)),
            ("container_sha256", json!("0".repeat(64))),
            ("payload_type", json!("krnl")),
        ] {
            let mut changed = base.clone();
            changed["sources"][0][key] = value;
            assert!(intake(&changed, &original, &prepared).is_err());
        }
        let mut loaded = base.clone();
        loaded["regions"][0]["file"] = json!(ORIGINAL_DEVICE_TREE_FILE);
        loaded["regions"][0]["bytes"] = json!(original.len());
        loaded["regions"][0]["sha256"] = json!(stela_formats::sha256(&original));
        assert!(intake(&loaded, &original, &prepared).is_err());
        let mut patched = base.clone();
        patched["patches"] = json!([{
            "source": "entropy", "required": true, "region": "DeviceTree",
            "file": ORIGINAL_DEVICE_TREE_FILE, "file_offset": 0, "bytes": 4,
            "encoding": "bytes", "field": "test"
        }]);
        assert!(intake(&patched, &original, &prepared).is_err());
        assert!(intake(&base, b"tampered original", &prepared).is_err());
        assert!(intake(&fixture(b"not an ADT", &prepared), b"not an ADT", &prepared).is_err());
        let other_board = tree(0x6000, 9);
        assert!(intake(&fixture(&original, &other_board), &original, &other_board).is_err());
    }
}
