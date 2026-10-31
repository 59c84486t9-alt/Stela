//! The collection's `__PRELINK_INFO,__info`: the XML property list XNU's
//! `OSKext` reads each kext's identity and placement from. Keys follow XNU
//! `libkern/libkern/prelink.h` at `xnu-12377.121.6`.
use crate::Result;
use plist::{Dictionary, Value};
use stela_contracts::refuse;

/// Where a kext lies in the collection, at unslid addresses.
#[derive(Debug, Clone, Copy)]
pub struct Placement {
    /// Its Mach-O header: the start of its `__TEXT`.
    pub load: u64,
    /// Its `__TEXT`'s length, which XNU records as the executable's.
    pub size: u64,
    pub kmod_info: u64,
}

impl Placement {
    /// A placement whose numbers are at least as long as any real one's.
    pub const WIDEST: Self = Self {
        load: u64::MAX,
        size: u64::MAX,
        kmod_info: u64::MAX,
    };
}

#[derive(Clone, Copy)]
pub struct Entry<'a> {
    pub info: &'a Dictionary,
    pub bundle_path: &'a str,
    pub placement: Placement,
}

/// The NUL-terminated XML XNU parses with `OSUnserializeXML`.
pub fn info(entries: &[Entry<'_>], collection: [u8; 16], boot: [u8; 16]) -> Result<Vec<u8>> {
    let mut kexts = Vec::with_capacity(entries.len());
    for entry in entries {
        let mut kext = entry.info.clone();
        kext.insert("_PrelinkBundlePath".into(), entry.bundle_path.into());
        if let Some(executable) = entry.info.get("CFBundleExecutable") {
            kext.insert("_PrelinkExecutableRelativePath".into(), executable.clone());
        }
        let placement = entry.placement;
        for (key, value) in [
            ("_PrelinkExecutableLoadAddr", placement.load),
            ("_PrelinkExecutableSourceAddr", placement.load),
            ("_PrelinkExecutableSize", placement.size),
            ("_PrelinkKmodInfo", placement.kmod_info),
        ] {
            kext.insert(key.into(), value.into());
        }
        kexts.push(Value::Dictionary(kext));
    }
    let mut root = Dictionary::new();
    root.insert("_PrelinkInfoDictionary".into(), Value::Array(kexts));
    root.insert("_PrelinkKCID".into(), Value::Data(collection.to_vec()));
    root.insert("_BootKCID".into(), Value::Data(boot.to_vec()));
    let mut xml = Vec::new();
    plist::to_writer_xml(&mut xml, &Value::Dictionary(root))
        .map_err(|error| refuse!("cannot write the prelink information", %error))?;
    xml.push(0);
    Ok(xml)
}

/// Refuses values `OSUnserializeXML` has no form for.
pub fn check(name: &str, value: &Value) -> Result<()> {
    match value {
        Value::Array(values) => values.iter().try_for_each(|value| check(name, value)),
        Value::Dictionary(dictionary) => dictionary
            .iter()
            .try_for_each(|(key, value)| check(key, value)),
        Value::Boolean(_) | Value::Data(_) | Value::Integer(_) | Value::String(_) => Ok(()),
        _ => Err(refuse!(
            "Info.plist key {name} holds a value the kernel cannot read: {value}",
            name,
            ?value
        )
        .into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn records_each_kexts_placement_and_both_collections() -> Result<()> {
        let mut dictionary = Dictionary::new();
        dictionary.insert("CFBundleIdentifier".into(), "com.stela.Test".into());
        dictionary.insert("CFBundleExecutable".into(), "Test".into());
        let placement = Placement {
            load: 0x8000,
            size: 0x1234,
            kmod_info: 0x40,
        };
        let entry = Entry {
            info: &dictionary,
            bundle_path: "/Library/Extensions/Test.kext",
            placement,
        };
        let xml = info(&[entry], [1; 16], [2; 16])?;
        assert_eq!(xml.last(), Some(&0));
        let root = Value::from_reader_xml(&xml[..xml.len() - 1])?;
        let root = root.as_dictionary().unwrap();
        assert_eq!(root["_PrelinkKCID"].as_data(), Some(&[1; 16][..]));
        assert_eq!(root["_BootKCID"].as_data(), Some(&[2; 16][..]));
        let kext = root["_PrelinkInfoDictionary"].as_array().unwrap()[0]
            .as_dictionary()
            .unwrap();
        assert_eq!(
            kext["_PrelinkExecutableLoadAddr"].as_unsigned_integer(),
            Some(0x8000)
        );
        assert_eq!(
            kext["_PrelinkExecutableSize"].as_unsigned_integer(),
            Some(0x1234)
        );
        assert_eq!(kext["_PrelinkKmodInfo"].as_unsigned_integer(), Some(0x40));
        assert_eq!(
            kext["_PrelinkExecutableRelativePath"].as_string(),
            Some("Test")
        );

        let widest = Entry {
            placement: Placement::WIDEST,
            ..entry
        };
        assert!(info(&[widest], [1; 16], [2; 16])?.len() >= xml.len());
        Ok(())
    }

    #[test]
    fn refuses_dates_and_reals() {
        let nested = Value::Array(vec![Value::Real(1.5)]);
        assert!(check("Root", &nested).is_err());
        assert!(check("Root", &Value::String("ok".into())).is_ok());
    }
}
