//! The boot-policy inputs iBoot hands SPTM, TXM and XNU as DeviceTree data.
//!
//! After verifying a LocalPolicy, iBoot publishes it as `/chosen/asmb`
//! `lp-*` values, summarizes the boot manifest as `/chosen`
//! `boot-manifest-hash`, the `effective-*-ap` state and
//! `/chosen/manifest-properties`, and records the SEP load decision. The names
//! are those SPTM, TXM and the kernel read (their own strings); LocalPolicy
//! fields and types follow Apple Platform Security, "Contents of a LocalPolicy
//! file for a Mac with Apple silicon". Integers are 8 bytes, as m1n1 writes
//! `lp-sip0`; booleans are 4 bytes, as the template's
//! `UnusedBooleanProperty` slots are.
//!
//! Full Security needs a manifest personalized to one device, which Stela does
//! not have; Reduced Security admits Apple's global manifests in the IPSW.
use crate::apple_device_tree::DeviceTree;
use crate::im4m::{Manifest, Value};
use anyhow::{Context, Result, ensure};
use serde::Serialize;

const ASMB: &str = "/chosen/asmb";
const CHOSEN: &str = "/chosen";
const MANIFEST_PROPERTIES: &str = "/chosen/manifest-properties";
/// Template `UnusedStringProperty` slots hold 64 bytes.
const STRING_SLOT_BYTES: usize = 0x40;
const INTEGER_SLOT: &str = "UnusedIntegerProperty";
const BOOLEAN_SLOT: &str = "UnusedBooleanProperty";
const STRING_SLOT: &str = "UnusedStringProperty";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityMode {
    /// `smb0`: globally signed boot objects are admitted.
    Reduced,
    /// `smb0` and `smb1`: objects signed with the LocalPolicy key as well.
    Permissive,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityPolicy {
    pub mode: SecurityMode,
    /// `sip0`: System Integrity Protection bits (`csr-active-config`).
    pub sip_bits: u64,
    /// Overrides the template's `/chosen sepfw-load-at-boot`.
    pub sepfw_load_at_boot: Option<bool>,
}

/// One `/chosen` value written or deliberately kept, and why.
#[derive(Debug, Clone, Serialize)]
pub struct Decision {
    pub path: String,
    pub property: String,
    pub value_hex: String,
    pub source: String,
}

fn boolean(value: bool) -> Vec<u8> {
    u32::from(value).to_le_bytes().to_vec()
}

fn integer(value: u64) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

struct Writer<'a> {
    tree: &'a mut DeviceTree,
    decisions: Vec<Decision>,
}

impl Writer<'_> {
    fn set(&mut self, path: &str, property: &str, value: Vec<u8>, source: &str) -> Result<()> {
        self.decisions.push(Decision {
            path: path.into(),
            property: property.into(),
            value_hex: hex::encode(&value),
            source: source.into(),
        });
        self.tree.set_property(path, property, value)
    }

    /// Replace a template value, keeping the template's width.
    fn fill(&mut self, path: &str, property: &str, value: Vec<u8>, source: &str) -> Result<()> {
        let width = self
            .tree
            .property(path, property)
            .with_context(|| format!("DeviceTree has no {path} {property}"))?
            .value
            .len();
        ensure!(
            width == value.len(),
            "{path} {property} is {width} bytes; the value is {}",
            value.len()
        );
        self.set(path, property, value, source)
    }

    fn keep(&mut self, path: &str, property: &str, source: &str) -> Result<()> {
        let value = self
            .tree
            .property(path, property)
            .with_context(|| format!("DeviceTree has no {path} {property}"))?
            .value
            .clone();
        self.decisions.push(Decision {
            path: path.into(),
            property: property.into(),
            value_hex: hex::encode(value),
            source: source.into(),
        });
        Ok(())
    }
}

fn manifest_flag(manifest: &Manifest, name: &str) -> Result<bool> {
    match manifest.property(name) {
        Some(Value::Boolean(value)) => Ok(*value),
        other => anyhow::bail!("boot manifest {name} is {other:?}, expected a boolean"),
    }
}

fn manifest_integer(manifest: &Manifest, name: &str) -> Result<u64> {
    match manifest.property(name) {
        Some(Value::Integer(value)) => Ok(*value),
        other => anyhow::bail!("boot manifest {name} is {other:?}, expected an integer"),
    }
}

/// Fill the template's typed `manifest-properties` slots with `MANP`.
fn manifest_properties(writer: &mut Writer, manifest: &Manifest) -> Result<()> {
    for property in &manifest.properties {
        let (slot, value) = match &property.value {
            Value::Integer(value) => (INTEGER_SLOT, integer(*value)),
            Value::Boolean(value) => (BOOLEAN_SLOT, boolean(*value)),
            Value::Data(bytes) => {
                ensure!(
                    bytes.len() <= STRING_SLOT_BYTES,
                    "manifest property {} exceeds a {STRING_SLOT_BYTES}-byte slot",
                    property.name
                );
                let mut value = bytes.clone();
                value.resize(STRING_SLOT_BYTES, 0);
                (STRING_SLOT, value)
            }
        };
        let node = writer
            .tree
            .node_mut(MANIFEST_PROPERTIES)
            .context("DeviceTree has no /chosen/manifest-properties")?;
        let free = node
            .properties
            .iter()
            .find(|p| p.name().starts_with(slot))
            .map(|p| p.name().to_owned())
            .with_context(|| format!("no free {slot} slot for {}", property.name))?;
        writer.decisions.push(Decision {
            path: MANIFEST_PROPERTIES.into(),
            property: property.name.clone(),
            value_hex: hex::encode(&value),
            source: format!("boot manifest MANP, in slot {free}"),
        });
        node.replace_property(&free, &property.name, value)?;
    }
    Ok(())
}

/// Apply the policy and manifest summaries; returns the decisions and the
/// inputs that remain unknown.
pub fn apply(
    tree: &mut DeviceTree,
    policy: &SecurityPolicy,
    boot_manifest: Option<&Manifest>,
    cryptex1_manifest: Option<&Manifest>,
) -> Result<(Vec<Decision>, Vec<String>)> {
    let mut unresolved = vec![];
    tree.ensure_child(CHOSEN, "asmb")?;
    let mut writer = Writer {
        tree,
        decisions: vec![],
    };
    let mode = match policy.mode {
        SecurityMode::Reduced => "Reduced Security",
        SecurityMode::Permissive => "Permissive Security",
    };
    writer.set(ASMB, "lp-smb0", boolean(true), mode)?;
    writer.set(
        ASMB,
        "lp-smb1",
        boolean(policy.mode == SecurityMode::Permissive),
        mode,
    )?;
    writer.set(ASMB, "lp-sip0", integer(policy.sip_bits), "SIP bits")?;
    writer.set(
        ASMB,
        "lp-sip1",
        boolean(false),
        "signed system volume enforced",
    )?;
    match cryptex1_manifest {
        Some(manifest) => {
            writer.set(
                ASMB,
                "lp-spih",
                manifest.digest.to_vec(),
                "SHA-384 of the global Cryptex1 manifest",
            )?;
            writer.set(ASMB, "lp-stng", integer(0), "first spih generation")?;
        }
        None => unresolved.push("/chosen/asmb lp-spih, lp-stng: no Cryptex1 manifest".into()),
    }

    match boot_manifest {
        Some(manifest) => {
            writer.fill(
                CHOSEN,
                "boot-manifest-hash",
                manifest.digest.to_vec(),
                "SHA-384 of the global boot manifest",
            )?;
            writer.fill(
                CHOSEN,
                "effective-production-status-ap",
                boolean(manifest_flag(manifest, "CPRO")?),
                "boot manifest CPRO",
            )?;
            writer.fill(
                CHOSEN,
                "effective-security-mode-ap",
                boolean(manifest_flag(manifest, "CSEC")?),
                "boot manifest CSEC",
            )?;
            let domain = u32::try_from(manifest_integer(manifest, "SDOM")?)?;
            writer.set(
                CHOSEN,
                "security-domain",
                domain.to_le_bytes().to_vec(),
                "boot manifest SDOM",
            )?;
            manifest_properties(&mut writer, manifest)?;
        }
        None => unresolved.push(
            "/chosen boot-manifest-hash, effective-*-ap, security-domain, manifest-properties: no boot manifest"
                .into(),
        ),
    }

    match policy.sepfw_load_at_boot {
        Some(load) => writer.fill(CHOSEN, "sepfw-load-at-boot", boolean(load), "policy")?,
        None => writer.keep(CHOSEN, "sepfw-load-at-boot", "template value")?,
    }
    writer.keep(CHOSEN, "cs-system-policy", "template value")?;
    writer.keep(CHOSEN, "osenvironment", "template value: normal macOS boot")?;
    Ok((writer.decisions, unresolved))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apple_device_tree::Node;
    use crate::im4m;
    use crate::im4m::tests::{der, entry, manifest};

    fn tree() -> DeviceTree {
        let mut tree = DeviceTree {
            root: Node::named("device-tree").unwrap(),
        };
        tree.ensure_child("/", "chosen").unwrap();
        tree.ensure_child("/chosen", "manifest-properties").unwrap();
        for (name, bytes) in [
            ("boot-manifest-hash", 48),
            ("effective-production-status-ap", 4),
            ("effective-security-mode-ap", 4),
            ("sepfw-load-at-boot", 4),
            ("osenvironment", 32),
        ] {
            tree.set_property("/chosen", name, vec![0; bytes]).unwrap();
        }
        tree.set_property("/chosen", "cs-system-policy", b"default\0".to_vec())
            .unwrap();
        for (slot, bytes) in [(INTEGER_SLOT, 8), (BOOLEAN_SLOT, 4), (STRING_SLOT, 0x40)] {
            for index in 0..2 {
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
                entry("love", &der(&[0x04], b"26.1.434.0.0,0")),
            ],
            &[],
        ))
        .unwrap()
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
        let mut love = b"26.1.434.0.0,0".to_vec();
        love.resize(STRING_SLOT_BYTES, 0);
        assert_eq!(value(MANIFEST_PROPERTIES, "love"), love);
        // The slots keep their place and size; one of each kind remains.
        assert!(
            tree.property(MANIFEST_PROPERTIES, "UnusedIntegerProperty0")
                .is_none()
        );
        assert!(
            tree.property(MANIFEST_PROPERTIES, "UnusedIntegerProperty1")
                .is_some()
        );
        assert!(decisions.iter().any(|d| d.property == "cs-system-policy"));
        Ok(())
    }

    #[test]
    fn missing_manifests_stay_visible_and_permissive_sets_smb1() -> Result<()> {
        let mut tree = tree();
        let policy = SecurityPolicy {
            mode: SecurityMode::Permissive,
            sip_bits: 0x7f,
            sepfw_load_at_boot: None,
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
}
