//! Recognize the boot manager on a USB's EFI system partition. Stela adds
//! itself only to OpenCore, which starts tools from its boot picker; every
//! other layout is reported and left untouched.
use plist::Value;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BootManager {
    OpenCore,
    Clover,
    /// A volume made by `createinstallmedia` or holding an installer app.
    AppleInstaller,
    /// Another EFI layout, such as a Windows or Linux boot loader.
    Unknown,
    /// No `EFI` folder.
    Empty,
}

pub(crate) fn detect(root: &Path) -> BootManager {
    let exists = |path: &str| root.join(path).exists();
    if exists("EFI/OC/config.plist") && exists("EFI/OC/OpenCore.efi") {
        BootManager::OpenCore
    } else if exists("EFI/CLOVER") {
        BootManager::Clover
    } else if exists(".IAProductInfo")
        || exists("System/Library/CoreServices/boot.efi")
        || std::fs::read_dir(root).is_ok_and(|entries| {
            entries.flatten().any(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                name.starts_with("Install macOS") && name.ends_with(".app")
            })
        })
    {
        BootManager::AppleInstaller
    } else if exists("EFI") {
        BootManager::Unknown
    } else {
        BootManager::Empty
    }
}

/// Why Stela will not change a USB with this boot manager.
pub(crate) fn refusal(manager: &BootManager, root: &Path) -> String {
    let what = match manager {
        BootManager::OpenCore => return String::new(),
        BootManager::Clover => "uses Clover",
        BootManager::AppleInstaller => {
            "is an Apple installer volume without OpenCore on its EFI partition"
        }
        BootManager::Unknown => "has an EFI folder from a boot manager Stela does not know",
        BootManager::Empty => "has no EFI folder",
    };
    format!(
        "{} {what}. Stela adds itself only to an OpenCore USB (EFI/OC/OpenCore.efi \
         and EFI/OC/config.plist), as a boot-picker tool, and does not change other \
         boot managers. Put OpenCore on the USB's EFI partition first (for example with \
         the OpenCore Install Guide), check that the USB boots, then run setup again.",
        root.display()
    )
}

/// Enabled `UEFI.Drivers` paths of an OpenCore configuration, lower-cased.
pub(crate) fn opencore_drivers(esp: &Path) -> Vec<String> {
    let Ok(config) = Value::from_file(esp.join("EFI/OC/config.plist")) else {
        return Vec::new();
    };
    config
        .as_dictionary()
        .and_then(|root| root.get("UEFI"))
        .and_then(Value::as_dictionary)
        .and_then(|uefi| uefi.get("Drivers"))
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
        .iter()
        .filter_map(|driver| match driver {
            // Older configurations list drivers as plain strings.
            Value::String(path) => Some(path.to_lowercase()),
            Value::Dictionary(driver) => {
                let enabled = driver.get("Enabled").and_then(Value::as_boolean) != Some(false);
                enabled
                    .then(|| driver.get("Path").and_then(Value::as_string))
                    .flatten()
                    .map(str::to_lowercase)
            }
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn boot_managers_are_told_apart_by_their_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        assert_eq!(detect(root), BootManager::Empty);
        fs::create_dir_all(root.join("EFI/BOOT")).unwrap();
        assert_eq!(detect(root), BootManager::Unknown);
        fs::create_dir_all(root.join("Install macOS Tahoe.app")).unwrap();
        assert_eq!(detect(root), BootManager::AppleInstaller);
        fs::create_dir_all(root.join("EFI/CLOVER")).unwrap();
        assert_eq!(detect(root), BootManager::Clover);
        fs::create_dir_all(root.join("EFI/OC")).unwrap();
        fs::write(root.join("EFI/OC/config.plist"), "").unwrap();
        // A configuration without OpenCore itself is not OpenCore.
        assert_eq!(detect(root), BootManager::Clover);
        fs::write(root.join("EFI/OC/OpenCore.efi"), "MZ").unwrap();
        assert_eq!(detect(root), BootManager::OpenCore);
        assert!(refusal(&BootManager::Clover, root).contains("Clover"));
        assert!(refusal(&BootManager::OpenCore, root).is_empty());
    }
}
