//! Exact requirements observed at a native driver's Provider boundary. This
//! inventory is separate from a firmware manifest and never infers hardware
//! identity from the computer running setup.
use super::{
    Error, MAX_IMAGE_BYTES, MAX_IMAGES, MAX_MANIFEST_BYTES, fail, logical_path, valid_label,
};
use alloc::{string::String, vec::Vec};
use core::cell::RefCell;
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, SeqAccess, Visitor},
};
use stela_driver_core::firmware::{self, Image, Provider, Requirement, Target};

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

    fn observe(&mut self, request: Requirement<'_>) -> Result<(), Error> {
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
}

impl<'a> RecordingProvider<'a> {
    pub fn new(inner: &'a dyn Provider) -> Self {
        Self {
            inner,
            inventory: RefCell::new(Ok(Inventory::default())),
        }
    }
    pub fn snapshot(&self) -> Result<Inventory, Error> {
        self.inventory
            .borrow()
            .as_ref()
            .cloned()
            .map_err(|e| Error(e.clone()))
    }
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
        self.inner.load(request)
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
}
