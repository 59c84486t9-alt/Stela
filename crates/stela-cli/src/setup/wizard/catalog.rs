//! Sort and cache the complete release/model catalog and optional model names.
use crate::{restore, setup::download_dir};
use anyhow::{Context, Result, ensure};
use std::{collections::BTreeMap, fs::File, io::Read};

pub(super) fn load() -> Result<Vec<restore::Image>> {
    let path = download_dir().join("catalog.json");
    let mut images = match restore::catalog() {
        Ok(images) => {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(bytes) = serde_json::to_vec(&images) {
                let _ = crate::efi::write_atomic(&path, &bytes, false);
            }
            images
        }
        Err(error) => {
            let file = File::open(&path).with_context(|| format!("could not load the macOS catalog ({error}); choose a local IPSW to work without catalog access"))?;
            let mut bytes = Vec::new();
            file.take(16 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() <= 16 * 1024 * 1024,
                "cached catalog exceeds its bound"
            );
            cliclack::log::warning(
                "The macOS catalog is unavailable; showing the last saved catalog",
            )?;
            serde_json::from_slice(&bytes)?
        }
    };
    images.retain(|image| {
        !image.models.is_empty()
            && reqwest::Url::parse(&image.url).is_ok_and(|url| restore::apple_url(&url))
    });
    images.sort_by(|a, b| {
        version_key(&b.version)
            .cmp(&version_key(&a.version))
            .then_with(|| b.build.cmp(&a.build))
    });
    images.dedup_by(|a, b| a.build == b.build && a.models == b.models);
    ensure!(
        !images.is_empty(),
        "The catalog lists no usable macOS images; use a local IPSW"
    );
    Ok(images)
}

fn version_key(version: &str) -> Vec<u64> {
    version
        .split('.')
        .map(|part| part.parse().unwrap_or(0))
        .collect()
}

pub(super) fn model_names() -> Result<BTreeMap<String, String>> {
    let names = restore::model_names()?;
    let path = download_dir().join("model-names.json");
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(bytes) = serde_json::to_vec(&names) {
        let _ = crate::efi::write_atomic(&path, &bytes, false);
    }
    Ok(shown(names))
}

/// Setup capitalizes "Mac Mini" like its other families; identifiers stay keys.
fn shown(names: BTreeMap<String, String>) -> BTreeMap<String, String> {
    names
        .into_iter()
        .map(|(model, name)| (model, name.replace("Mac mini", "Mac Mini")))
        .collect()
}

pub(super) fn cached_names() -> BTreeMap<String, String> {
    #[derive(serde::Deserialize)]
    struct Bundled {
        models: BTreeMap<String, String>,
    }
    let mut names = serde_json::from_str::<Bundled>(include_str!("models.json"))
        .expect("bundled model names")
        .models;
    let path = download_dir().join("model-names.json");
    let read = || -> Result<BTreeMap<String, String>> {
        let file = File::open(path)?;
        ensure!(
            file.metadata()?.len() <= 4 * 1024 * 1024,
            "names cache exceeds its bound"
        );
        Ok(serde_json::from_reader(file)?)
    };
    names.extend(read().unwrap_or_default());
    shown(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_sort_numerically_including_double_digit_minor_releases() {
        assert!(version_key("15.10.1") > version_key("15.9.9"));
        assert!(version_key("27.0") > version_key("26.9"));
    }

    #[test]
    fn model_names_capitalize_mac_mini_and_keep_identifiers_as_keys() {
        let names = shown(BTreeMap::from([(
            "Macmini9,1".to_owned(),
            "Mac mini (M1)".to_owned(),
        )]));
        assert_eq!(names["Macmini9,1"], "Mac Mini (M1)");
        assert!(
            cached_names()
                .values()
                .all(|name| !name.contains("Mac mini"))
        );
    }
}
