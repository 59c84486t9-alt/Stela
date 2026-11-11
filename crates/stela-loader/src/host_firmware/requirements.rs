//! Exact requirements observed at a native driver's Provider boundary. This
//! inventory is separate from a firmware manifest and never infers hardware
//! identity from the computer running setup.
use super::{
    Error, MAX_IMAGE_BYTES, MAX_IMAGES, MAX_MANIFEST_BYTES, fail, logical_path, valid_label,
};
use alloc::{format, string::String, vec::Vec};
use core::cell::RefCell;
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, SeqAccess, Visitor},
};
use stela_driver_core::firmware::{self, ErrorKind, Image, Provider, Requirement, Target};

/// What starts the boot log line that holds the inventory of a boot whose
/// drivers asked for firmware the USB lacks ([`RecordingProvider::log_line`]).
/// `stela setup repair` adds the files of the newest such line ([`newest`]).
pub const LOG_LINE: &str = "HOST FIRMWARE REQUESTS ";

/// Whether boot reads the resource for `target` from the PC's own firmware
/// (UEFI variables and the SMBIOS table) rather than from the USB. Such a
/// resource is absent on many PCs and no download stands in for it.
pub fn read_by_boot(target: &Target<'_>) -> bool {
    target.hardware.starts_with("uefi:") || *target == firmware::smbios::TARGET
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub driver: String,
    pub hardware: String,
    pub revision: String,
    pub board: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub name: String,
    pub target: Identity,
    pub minimum_bytes: usize,
}

impl Request {
    pub fn view(&self) -> Requirement<'_> {
        Requirement {
            name: &self.name,
            target: Target {
                driver: &self.target.driver,
                hardware: &self.target.hardware,
                revision: &self.target.revision,
                board: self.target.board.as_deref(),
            },
            minimum_bytes: self.minimum_bytes,
        }
    }
    fn capture(request: Requirement<'_>) -> Result<Self, Error> {
        validate(request)?;
        Ok(Self {
            name: request.name.into(),
            minimum_bytes: request.minimum_bytes,
            target: Identity {
                driver: request.target.driver.into(),
                hardware: request.target.hardware.into(),
                revision: request.target.revision.into(),
                board: request.target.board.map(String::from),
            },
        })
    }
}

fn validate(request: Requirement<'_>) -> Result<(), Error> {
    if !logical_path(request.name)
        || request.minimum_bytes == 0
        || request.minimum_bytes > MAX_IMAGE_BYTES
        || [
            request.target.driver,
            request.target.hardware,
            request.target.revision,
        ]
        .iter()
        .any(|s| !valid_label(s))
        || request.target.board.is_some_and(|s| !valid_label(s))
    {
        return Err(fail("invalid observed host firmware requirement"));
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    schema: u32,
    complete: bool,
    #[serde(deserialize_with = "bounded_requests")]
    requirements: Vec<Request>,
}

fn bounded_requests<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<Request>, D::Error> {
    struct Requests;
    impl<'de> Visitor<'de> for Requests {
        type Value = Vec<Request>;
        fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "at most {MAX_IMAGES} exact firmware requirements")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut requests = Vec::new();
            while let Some(request) = seq.next_element()? {
                if requests.len() == MAX_IMAGES {
                    return Err(de::Error::custom("too many host firmware requirements"));
                }
                requests.push(request);
            }
            Ok(requests)
        }
    }
    deserializer.deserialize_seq(Requests)
}

impl From<Requirement<'_>> for Request {
    fn from(request: Requirement<'_>) -> Self {
        let target = request.target;
        Self {
            name: request.name.into(),
            target: Identity {
                driver: target.driver.into(),
                hardware: target.hardware.into(),
                revision: target.revision.into(),
                board: target.board.map(Into::into),
            },
            minimum_bytes: request.minimum_bytes,
        }
    }
}

impl Default for Inventory {
    fn default() -> Self {
        Self {
            schema: 1,
            complete: true,
            requirements: Vec::new(),
        }
    }
}

impl Inventory {
    pub fn requests(&self) -> &[Request] {
        &self.requirements
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(fail("host firmware requirement inventory exceeds 128 KiB"));
        }
        let inventory: Self = serde_json::from_slice(bytes)
            .map_err(|e| Error(alloc::format!("host firmware requirements: {e}")))?;
        if inventory.schema != 1 || !inventory.complete || inventory.requirements.len() > MAX_IMAGES
        {
            return Err(fail(
                "incomplete, unsupported or oversized host firmware requirement inventory",
            ));
        }
        for (index, request) in inventory.requirements.iter().enumerate() {
            validate(request.view())?;
            if inventory.requirements[..index]
                .iter()
                .any(|other| other.name == request.name && other.target == request.target)
            {
                return Err(fail("duplicate observed host firmware requirement"));
            }
        }
        Ok(inventory)
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let bytes = serde_json::to_vec(self)
            .map_err(|e| Error(alloc::format!("host firmware requirements: {e}")))?;
        Self::parse(&bytes)?;
        Ok(bytes)
    }

    /// Adds `request`, or raises the size an existing one needs.
    pub fn observe(&mut self, request: Requirement<'_>) -> Result<(), Error> {
        validate(request)?;
        if let Some(existing) = self.requirements.iter_mut().find(|existing| {
            let view = existing.view();
            view.name == request.name && view.target == request.target
        }) {
            existing.minimum_bytes = existing.minimum_bytes.max(request.minimum_bytes);
            return Ok(());
        }
        if self.requirements.len() == MAX_IMAGES {
            return Err(fail(
                "host firmware requirement inventory exceeds 64 bindings",
            ));
        }
        self.requirements.push(Request::capture(request)?);
        Ok(())
    }
}

/// Capture before delegation, including requests that return Missing. Capture
/// failures latch explicitly for snapshot(), while the driver's original result
/// remains unchanged. Metadata alone is copied; images stay borrowed.
pub struct RecordingProvider<'a> {
    inner: &'a dyn Provider,
    inventory: RefCell<Result<Inventory, String>>,
    /// The requests the inner provider answered `Missing` for, without
    /// those [`read_by_boot`], each once.
    missing: RefCell<Inventory>,
}

impl<'a> RecordingProvider<'a> {
    pub fn new(inner: &'a dyn Provider) -> Self {
        Self {
            inner,
            inventory: RefCell::new(Ok(Inventory::default())),
            missing: RefCell::new(Inventory::default()),
        }
    }
    pub fn snapshot(&self) -> Result<Inventory, Error> {
        self.inventory
            .borrow()
            .as_ref()
            .cloned()
            .map_err(|e| Error(e.clone()))
    }

    /// How many distinct requests found no file, of those the USB supplies.
    pub fn missing_count(&self) -> usize {
        self.missing.borrow().requests().len()
    }

    /// The missing requests from the `skip`th on, in the order the drivers
    /// asked for them.
    pub fn missing_since(&self, skip: usize) -> Vec<Request> {
        self.missing
            .borrow()
            .requests()
            .iter()
            .skip(skip)
            .cloned()
            .collect()
    }

    /// One line for the boot log: [`LOG_LINE`] and the complete inventory in
    /// its schema 1 encoding, or why there is none. It holds firmware names
    /// and driver target labels only.
    pub fn log_line(&self) -> String {
        match self.snapshot().and_then(|inventory| inventory.encode()) {
            Ok(json) => format!("{LOG_LINE}{}", String::from_utf8_lossy(&json)),
            Err(error) => format!("{LOG_LINE}{UNAVAILABLE}{error}"),
        }
    }
}

/// What follows [`LOG_LINE`] when a boot could not record its inventory.
const UNAVAILABLE: &str = "unavailable: ";

/// The inventory of the newest [`LOG_LINE`] in a boot log's text, whose
/// lines may carry a time stamp before it: `None` without one, and an error
/// for a line that holds no complete inventory.
pub fn newest(log: &[u8]) -> Option<Result<Inventory, Error>> {
    let prefix = LOG_LINE.as_bytes();
    log.split(|&byte| byte == b'\n').rev().find_map(|line| {
        let at = line
            .windows(prefix.len())
            .position(|window| window == prefix)?;
        let rest = &line[at + prefix.len()..];
        let rest = rest.strip_suffix(b"\r").unwrap_or(rest);
        Some(match rest.strip_prefix(UNAVAILABLE.as_bytes()) {
            Some(why) => Err(Error(format!(
                "the boot recorded no complete firmware inventory: {}",
                String::from_utf8_lossy(why)
            ))),
            None => Inventory::parse(rest),
        })
    })
}

impl Provider for RecordingProvider<'_> {
    fn load(&self, request: Requirement<'_>) -> Result<Image<'_>, firmware::Error> {
        {
            let mut inventory = self.inventory.borrow_mut();
            if let Ok(captured) = &mut *inventory
                && let Err(error) = captured.observe(request)
            {
                *inventory = Err(error.0);
            }
        }
        let result = self.inner.load(request);
        if let Err(error) = &result
            && error.kind == ErrorKind::Missing
            && !read_by_boot(&request.target)
        {
            // An invalid or excessive request already latched the
            // inventory's error; the count stays what it was.
            let _ = self.missing.borrow_mut().observe(request);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_driver_core::firmware::{Catalog, ErrorKind};
    fn request() -> Requirement<'static> {
        Requirement {
            name: "rtl_nic/rtl8168e-3.fw",
            target: Target {
                driver: "realtek",
                hardware: "10ec:8168",
                revision: "xid-2c8",
                board: None,
            },
            minimum_bytes: 4,
        }
    }
    #[test]
    fn missing_requests_are_captured_exactly_and_repeated_bounds_strengthen() {
        let empty = Catalog::from_handoff(Vec::new()).unwrap();
        let observer = RecordingProvider::new(&empty);
        for minimum_bytes in [4, 8, 4] {
            let wanted = Requirement {
                minimum_bytes,
                ..request()
            };
            assert_eq!(
                observer.load(wanted).unwrap_err(),
                empty.load(wanted).unwrap_err()
            );
        }
        let inventory = observer.snapshot().unwrap();
        assert_eq!(inventory.requests().len(), 1);
        assert_eq!(inventory.requests()[0].view().target, request().target);
        assert_eq!(inventory.requests()[0].minimum_bytes, 8);
        let decoded = Inventory::parse(&inventory.encode().unwrap()).unwrap();
        assert_eq!(decoded.requests(), inventory.requests());
        for field in ["driver", "hardware", "revision", "board"] {
            let mut value = serde_json::to_value(&inventory).unwrap();
            value["requirements"][0]["target"][field] = serde_json::json!("different");
            let changed = Inventory::parse(&serde_json::to_vec(&value).unwrap()).unwrap();
            assert_ne!(changed.requests()[0].target, inventory.requests()[0].target);
        }
    }
    #[test]
    fn capture_overflow_and_invalid_requests_never_replace_provider_results() {
        let empty = Catalog::from_handoff(Vec::new()).unwrap();
        let observer = RecordingProvider::new(&empty);
        for n in 0..=MAX_IMAGES {
            let label = alloc::format!("xid-{n:03x}");
            let wanted = Requirement {
                target: Target {
                    revision: &label,
                    ..request().target
                },
                ..request()
            };
            assert_eq!(observer.load(wanted).unwrap_err().kind, ErrorKind::Missing);
        }
        assert!(observer.snapshot().is_err());
        let observer = RecordingProvider::new(&empty);
        let invalid = Requirement {
            name: "../bad",
            ..request()
        };
        assert_eq!(
            observer.load(invalid).unwrap_err(),
            empty.load(invalid).unwrap_err()
        );
        assert!(observer.snapshot().is_err());
        assert!(Inventory::parse(br#"{"schema":1,"complete":false,"requirements":[]}"#).is_err());
        assert!(Inventory::parse(&alloc::vec![b' '; MAX_MANIFEST_BYTES + 1]).is_err());
    }

    #[test]
    fn missing_requests_count_once_and_skip_what_boot_reads_itself() {
        use stela_driver_core::firmware::{Provenance, Resource};
        let present = Requirement {
            name: "rtl_nic/rtl8168d-1.fw",
            ..request()
        };
        let catalog = Catalog::from_handoff(alloc::vec![Resource {
            name: present.name,
            target: present.target,
            provenance: Provenance {
                source: "synthetic-fixtures",
                revision: "v1",
                member: "fixtures/abc.bin",
                license: "CC0-1.0",
            },
            expected_length: 3,
            expected_sha256: {
                use stela_crypto::{Sha256, digest::Digest};
                Sha256::digest(b"abc").into()
            },
            bytes: b"abc".to_vec(),
        }])
        .unwrap();
        let observer = RecordingProvider::new(&catalog);
        assert!(
            observer
                .load(Requirement {
                    minimum_bytes: 3,
                    ..present
                })
                .is_ok()
        );
        let variable = Requirement {
            name: "intel/wifi/uefi/UefiCnvWlanUATS.bin",
            target: Target {
                driver: "wifi-intel",
                hardware: "uefi:92daaf2f-c02b-455b-b2ec-f5a3594f4aea",
                revision: "CnvUefiWlanUATS",
                board: None,
            },
            minimum_bytes: 1,
        };
        for wanted in [
            request(),
            variable,
            firmware::smbios::REQUIREMENT,
            request(),
        ] {
            assert_eq!(observer.load(wanted).unwrap_err().kind, ErrorKind::Missing);
        }
        // A wrong length is no missing file.
        assert!(
            observer
                .load(Requirement {
                    minimum_bytes: 4,
                    ..present
                })
                .is_err()
        );
        assert_eq!(observer.missing_count(), 1);
        let missing = observer.missing_since(0);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].name, request().name);
        assert_eq!(missing[0].view().target, request().target);
        assert!(observer.missing_since(1).is_empty());
        // The line holds the complete inventory, present files included.
        let line = observer.log_line();
        assert!(line.starts_with(LOG_LINE), "{line}");
        assert!(!line.contains('\n'), "{line}");
        let decoded = Inventory::parse(&line.as_bytes()[LOG_LINE.len()..]).unwrap();
        assert_eq!(decoded.requests(), observer.snapshot().unwrap().requests());
        assert_eq!(decoded.requests().len(), 4);
        assert_eq!(
            line,
            alloc::format!(
                "{LOG_LINE}{}",
                core::str::from_utf8(&observer.snapshot().unwrap().encode().unwrap()).unwrap()
            )
        );
    }

    #[test]
    fn the_newest_log_line_names_the_inventory() {
        let empty = Catalog::from_handoff(Vec::new()).unwrap();
        let first = RecordingProvider::new(&empty);
        let _ = first.load(request());
        let second = RecordingProvider::new(&empty);
        let other = Requirement {
            name: "rtl_nic/rtl8168f-1.fw",
            target: Target {
                revision: "xid-480",
                ..request().target
            },
            ..request()
        };
        let _ = second.load(other);
        let log = alloc::format!(
            "=== STELA BOOT 1 ===\n[    1.000] {}\nUSB added 1-2\n=== STELA BOOT 2 ===\n\
             [    2.500] {}\r\n[    2.600] HOST WARNING something else\n",
            first.log_line(),
            second.log_line()
        );
        let inventory = newest(log.as_bytes()).unwrap().unwrap();
        assert_eq!(inventory.requests().len(), 1);
        assert_eq!(inventory.requests()[0].name, "rtl_nic/rtl8168f-1.fw");
        assert!(newest(b"=== STELA BOOT 1 ===\nnothing\n").is_none());
        // A line cut short, or one whose capture failed, holds no inventory.
        let cut = alloc::format!("{}\n", &second.log_line()[..40]);
        assert!(newest(cut.as_bytes()).unwrap().is_err());
        let failed = RecordingProvider::new(&empty);
        let _ = failed.load(Requirement {
            name: "../bad",
            ..request()
        });
        let line = failed.log_line();
        assert!(
            line.starts_with("HOST FIRMWARE REQUESTS unavailable: "),
            "{line}"
        );
        let error = newest(line.as_bytes()).unwrap().unwrap_err();
        assert!(
            error.0.contains("no complete firmware inventory"),
            "{error:?}"
        );
    }
}
