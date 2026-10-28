//! Group the version and device pickers without changing their compatibility sets.
use crate::restore::Image;
use anyhow::{Result, ensure};
use std::collections::BTreeMap;

fn majors(images: &[Image]) -> Vec<(String, Vec<usize>)> {
    let mut groups: Vec<(String, Vec<usize>)> = Vec::new();
    for (index, image) in images.iter().enumerate() {
        let major = image.version.split('.').next().unwrap_or(&image.version);
        match groups.iter_mut().find(|(name, _)| name == major) {
            Some((_, entries)) => entries.push(index),
            None => groups.push((major.into(), vec![index])),
        }
    }
    groups
}

/// Whether Stela supports `image`'s build (`stela_runtime::builds`).
fn supported(image: &Image) -> bool {
    stela_runtime::builds::find(&image.build).is_ok()
}

/// The major-version group the release picker opens on: `preferred`'s, else
/// the first holding a supported build.
fn initial_group(groups: &[(String, Vec<usize>)], images: &[Image], preferred: &str) -> usize {
    groups
        .iter()
        .position(|(_, entries)| entries.iter().any(|&i| images[i].build == preferred))
        .or_else(|| {
            groups
                .iter()
                .position(|(_, entries)| entries.iter().any(|&i| supported(&images[i])))
        })
        .unwrap_or(0)
}

pub(super) fn release(images: &[Image], preferred: &str) -> Result<usize> {
    let groups = majors(images);
    let mut initial = initial_group(&groups, images, preferred);
    loop {
        let mut picker = cliclack::select("3 / 6  Choose a macOS version").max_rows(8);
        for (index, (major, _)) in groups.iter().enumerate() {
            picker = picker.item(index, format!("macOS {major}"), "");
        }
        initial = picker.initial_value(initial).interact()?;
        let (major, entries) = &groups[initial];
        let rows: Vec<_> = entries
            .iter()
            .map(|&index| super::menu::Item {
                value: index,
                label: images[index].version.clone(),
                hint: if supported(&images[index]) {
                    images[index].build.clone()
                } else {
                    format!("{} · unsupported", images[index].build)
                },
                enabled: supported(&images[index]),
            })
            .collect();
        let preferred = entries
            .iter()
            .copied()
            .find(|&i| images[i].build == preferred)
            .or_else(|| entries.iter().copied().find(|&i| supported(&images[i])))
            .unwrap_or(entries[0]);
        if let Some(index) = super::menu::submenu(
            &format!("macOS {major} · Choose a release"),
            &rows,
            preferred,
        )? {
            return Ok(index);
        }
        console::Term::stderr().clear_last_lines(3)?;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Family {
    Studio,
    Mini,
    Pro,
    IMac,
    MacBookPro,
    MacBookAir,
    MacBookNeo,
    MacBook,
    Other,
}

impl Family {
    fn label(self) -> &'static str {
        match self {
            Self::Studio => "Mac Studio",
            Self::Mini => "Mac Mini",
            Self::Pro => "Mac Pro",
            Self::IMac => "iMac",
            Self::MacBookPro => "MacBook Pro",
            Self::MacBookAir => "MacBook Air",
            Self::MacBookNeo => "MacBook Neo",
            Self::MacBook => "MacBook",
            Self::Other => "Other Mac models",
        }
    }
}

fn family(model: &str, name: &str) -> Option<Family> {
    if model.to_ascii_lowercase().contains("virtual")
        || name.to_ascii_lowercase().contains("virtual")
    {
        return None;
    }
    Some(if name.starts_with("Mac Studio") {
        Family::Studio
    } else if name.starts_with("Mac Mini") || model.starts_with("Macmini") {
        Family::Mini
    } else if name.starts_with("Mac Pro") || model.starts_with("MacPro") {
        Family::Pro
    } else if name.starts_with("iMac") || model.starts_with("iMac") {
        Family::IMac
    } else if name.starts_with("MacBook Pro") || model.starts_with("MacBookPro") {
        Family::MacBookPro
    } else if name.starts_with("MacBook Air") || model.starts_with("MacBookAir") {
        Family::MacBookAir
    } else if name.starts_with("MacBook Neo") {
        Family::MacBookNeo
    } else if name.starts_with("MacBook") || model.starts_with("MacBook") {
        Family::MacBook
    } else {
        Family::Other
    })
}

fn chip(name: &str) -> (u32, u8) {
    let name = name.split_once('(').map_or(name, |(_, details)| details);
    let generation = name
        .split(|c: char| !c.is_ascii_alphanumeric())
        .find_map(|word| {
            word.strip_prefix('M')
                .or_else(|| word.strip_prefix('A'))?
                .parse()
                .ok()
        })
        .unwrap_or(0);
    let variant = if name.contains("Ultra") {
        3
    } else if name.contains("Max") {
        2
    } else if name.contains("Pro") {
        1
    } else {
        0
    };
    (generation, variant)
}

fn model_name<'a>(model: &'a str, names: &'a BTreeMap<String, String>) -> &'a str {
    names.get(model).map_or(model, String::as_str)
}

pub(super) fn model(
    models: &[String],
    names: &BTreeMap<String, String>,
    preferred: Option<&str>,
) -> Result<String> {
    let mut groups: BTreeMap<Family, Vec<&String>> = BTreeMap::new();
    for model in models {
        if let Some(family) = family(model, model_name(model, names)) {
            groups.entry(family).or_default().push(model);
        }
    }
    ensure!(
        !groups.is_empty(),
        "this image lists no physical Mac models"
    );
    let groups: Vec<_> = groups
        .into_iter()
        .map(|(family, mut models)| {
            models.sort_by(|a, b| {
                chip(model_name(b, names))
                    .cmp(&chip(model_name(a, names)))
                    .then_with(|| model_name(a, names).cmp(model_name(b, names)))
                    .then_with(|| a.cmp(b))
            });
            (family, models)
        })
        .collect();
    let mut initial = groups
        .iter()
        .position(|(_, models)| models.iter().any(|model| Some(model.as_str()) == preferred))
        .unwrap_or(0);
    loop {
        let mut picker = cliclack::select("4 / 6  Choose a Mac family");
        for (index, (family, _)) in groups.iter().enumerate() {
            picker = picker.item(index, family.label(), "");
        }
        initial = picker.initial_value(initial).interact()?;
        let (family, models) = &groups[initial];
        let rows: Vec<_> = models
            .iter()
            .enumerate()
            .map(|(index, model)| super::menu::Item {
                value: index,
                label: model_name(model, names).into(),
                hint: String::new(),
                enabled: true,
            })
            .collect();
        let initial_model = models
            .iter()
            .position(|model| Some(model.as_str()) == preferred)
            .unwrap_or(0);
        if let Some(index) = super::menu::submenu(
            &format!("{} · Choose a chip and model", family.label()),
            &rows,
            initial_model,
        )? {
            return Ok(models[index].to_string());
        }
        console::Term::stderr().clear_last_lines(3)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_families_are_ordered_and_virtual_macs_are_excluded() {
        assert!(Family::Studio < Family::Mini && Family::Mini < Family::Pro);
        assert!(Family::Pro < Family::MacBookPro && Family::MacBookPro < Family::MacBookAir);
        assert_eq!(
            family("Mac13,1", "Mac Studio (M1 Max)"),
            Some(Family::Studio)
        );
        assert_eq!(family("Macmini9,1", "Mac Mini (M1)"), Some(Family::Mini));
        assert_eq!(family("Mac14,3", "Mac Mini (M2, 2023)"), Some(Family::Mini));
        assert_eq!(family("VirtualMac2,1", "Virtual Mac"), None);
        assert_eq!(
            family("Mac17,5", "MacBook Neo (A18 Pro)"),
            Some(Family::MacBookNeo)
        );
        assert!(chip("Mac Studio (M4 Max)") > chip("Mac Studio (M3 Ultra)"));
    }

    #[test]
    fn release_picker_defaults_to_supported_build() {
        let image = |version: &str, build: &str| Image {
            version: version.into(),
            build: build.into(),
            models: vec!["MacBookPro18,3".into()],
            url: String::new(),
            sha1: None,
        };
        let supported = stela_runtime::builds::DEFAULT;
        let images = [
            image("28.1", "28B70"),
            image("27.1", "27B74"),
            image(supported.version, supported.build),
        ];
        let groups = majors(&images);
        assert_eq!(initial_group(&groups, &images, ""), 1);
        assert_eq!(initial_group(&groups, &images, "28B70"), 0);
        assert!(!super::supported(&images[1]) && super::supported(&images[2]));
    }
}
