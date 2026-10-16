//! Inspect restore identities without guessing which disk image is the OS.
use anyhow::{Context, Result, ensure};
use plist::Value;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Serialize)]
pub struct Component {
    pub path: String,
    pub declared_digest_hex: Option<String>,
    pub declared_hash_method: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Identity {
    pub product_type: Option<String>,
    pub device_class: String,
    pub variant: String,
    pub components: BTreeMap<String, Component>,
    pub components_without_paths: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct RestoreManifest {
    pub schema_version: u32,
    pub manifest_sha256: String,
    pub product_version: String,
    pub product_build: String,
    pub supported_models: Vec<String>,
    pub identities: Vec<Identity>,
}

fn required(dict: &plist::Dictionary, field: &str) -> Result<String> {
    dict.get(field)
        .and_then(Value::as_string)
        .map(str::to_owned)
        .with_context(|| format!("restore manifest missing {field}"))
}

pub fn safe_member(path: &str) -> bool {
    !path.is_empty()
        && !path.contains(['\\', '\0', ':'])
        && path.split('/').all(|part| !matches!(part, "" | "." | ".."))
}

pub fn inspect(bytes: &[u8], model: Option<&str>) -> Result<RestoreManifest> {
    let value = Value::from_reader(std::io::Cursor::new(bytes))?;
    let root = value
        .as_dictionary()
        .context("restore manifest root is not a dictionary")?;
    let mut identities = vec![];
    for identity in root
        .get("BuildIdentities")
        .and_then(Value::as_array)
        .context("missing restore identities")?
    {
        let identity = identity
            .as_dictionary()
            .context("invalid restore identity")?;
        let product_type = identity
            .get("Ap,ProductType")
            .and_then(Value::as_string)
            .map(str::to_owned);
        if model.is_some_and(|model| product_type.as_deref() != Some(model)) {
            continue;
        }
        let info = identity
            .get("Info")
            .and_then(Value::as_dictionary)
            .context("missing identity info")?;
        let mut components = BTreeMap::new();
        let mut components_without_paths = vec![];
        for (name, component) in identity
            .get("Manifest")
            .and_then(Value::as_dictionary)
            .context("missing component manifest")?
        {
            let component = component.as_dictionary().context("invalid component")?;
            let info = component.get("Info").and_then(Value::as_dictionary);
            let Some(path) = info.and_then(|i| i.get("Path")).and_then(Value::as_string) else {
                components_without_paths.push(name.clone());
                continue;
            };
            ensure!(
                safe_member(path),
                "unsafe archive member in component {name}"
            );
            components.insert(
                name.clone(),
                Component {
                    path: path.into(),
                    declared_digest_hex: component
                        .get("Digest")
                        .and_then(Value::as_data)
                        .map(hex::encode),
                    declared_hash_method: info
                        .and_then(|i| i.get("HashMethod"))
                        .and_then(Value::as_string)
                        .map(str::to_owned),
                },
            );
        }
        identities.push(Identity {
            product_type,
            device_class: required(info, "DeviceClass")?,
            variant: required(info, "Variant")?,
            components,
            components_without_paths,
        });
    }
    ensure!(!identities.is_empty(), "no matching restore identities");
    let supported_models = root
        .get("SupportedProductTypes")
        .and_then(Value::as_array)
        .context("missing supported models")?
        .iter()
        .map(|v| v.as_string().map(str::to_owned).context("invalid model"))
        .collect::<Result<_>>()?;
    Ok(RestoreManifest {
        schema_version: 1,
        manifest_sha256: stela_core::sha256(bytes),
        product_version: required(root, "ProductVersion")?,
        product_build: required(root, "ProductBuildVersion")?,
        supported_models,
        identities,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn filters_restore_models_and_preserves_opaque_digest_metadata() -> Result<()> {
        let bytes = include_bytes!("../../tests/fixtures/restore.plist");
        let report = inspect(bytes, Some("TestMac1,1"))?;
        assert_eq!(report.identities.len(), 1);
        assert_eq!(report.identities[0].components["OS"].path, "os.dmg.aea");
        assert_eq!(
            report.identities[0].components["OS"]
                .declared_hash_method
                .as_deref(),
            Some("sha2-384")
        );
        assert_eq!(
            report.identities[0].components_without_paths,
            vec!["Opaque"]
        );
        assert!(inspect(bytes, Some("MissingMac")).is_err());
        for bad in ["../a", "/absolute", "a//b", "a\\b", "C:/a", "a/./b"] {
            assert!(!safe_member(bad));
        }
        Ok(())
    }
}
