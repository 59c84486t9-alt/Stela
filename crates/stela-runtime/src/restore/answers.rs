//! Manifest-driven offline answers. Firmware updater support is keyed to its
//! protocol arguments, never an application/build identity. Unknown updater
//! formats and nonce-bound ticket requests retain their full refusal context.
use super::{
    Error, Result,
    asr::Sender,
    plist::{self, Limits, Value},
    store::{Identity, Store},
    ticket::Ticket,
    tss,
};
use crate::payload::{ReadAt, safe_path};
use alloc::{
    boxed::Box,
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec::Vec,
};
use sha2::{Digest, Sha384};
const MAX_STAGED_ANSWERS: usize = 128;
const MAX_STAGED_BYTES: usize = 16 * 1024 * 1024;
const MAX_REPLY_BYTES: usize = 8 * 1024 * 1024;
/// A transfer is a bounded recipe. A scheduler opens DataPort and polls a Job;
/// control-only responses use the control stream at its next frame boundary.
pub enum Plan {
    Reply(Value),
    File(Vec<Segment>),
    Raw(Vec<Segment>),
    /// A whole framed reply (length and binary plist) too large to hold in
    /// memory, whose data objects stream from IPSW members.
    Message(Vec<Segment>),
    Asr(Sender),
}
#[derive(Clone)]
pub enum Segment {
    Bytes(Vec<u8>),
    Member {
        path: String,
        offset: u64,
        bytes: u64,
    },
}
impl Segment {
    pub fn len(&self) -> u64 {
        match self {
            Self::Bytes(b) => b.len() as u64,
            Self::Member { bytes, .. } => *bytes,
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
/// Prefetched HTTP responses bind the entire Arguments dictionary (method,
/// URL, headers and body), not just a URL. The expected response digest is
/// supplied by the immutable staging inventory, never inferred from a peer.
#[derive(Default)]
pub struct Staged {
    answers: BTreeMap<(String, String), Value>,
    bytes: usize,
}
impl Staged {
    pub fn insert(
        &mut self,
        kind: &str,
        args: &Value,
        response_bytes: &[u8],
        sha256: &str,
    ) -> Result<()> {
        if !matches!(kind, "URLAsset" | "StreamedImageDecryptionKey") {
            return Err(Error::Invalid("staged answer kind"));
        }
        if self.answers.len() >= MAX_STAGED_ANSWERS
            || response_bytes.len() > MAX_STAGED_BYTES - self.bytes
        {
            return Err(Error::Limit("staged answers"));
        }
        if crate::sha256(response_bytes) != sha256 {
            return Err(Error::Invalid("staged response digest"));
        }
        validate_http_args(kind, args)?;
        let response = plist::decode(response_bytes, Limits::default())?;
        response.required("ResponseBody")?.data()?;
        response.required("ResponseHeaders")?;
        if !response.required("ResponseBodyDone")?.boolean()?
            || !(200..300).contains(&response.required("ResponseStatus")?.uint()?)
        {
            return Err(Error::Invalid(
                "staged HTTP answer is incomplete/unsuccessful",
            ));
        }
        let key = (kind.into(), fingerprint(args)?);
        if self.answers.contains_key(&key) {
            return Err(Error::Invalid("duplicate staged answer"));
        }
        self.answers.insert(key, response);
        self.bytes += response_bytes.len();
        Ok(())
    }
    fn get(&self, kind: &str, args: &Value) -> Result<Value> {
        validate_http_args(kind, args)?;
        self.answers
            .get(&(kind.into(), fingerprint(args)?))
            .cloned()
            .ok_or(Error::Invalid("exact prefetched HTTP response unavailable"))
    }
}
/// SHA-256 of the staged `URLAsset` reply for a recipient key PEM, for the
/// inventory to record so the restore host serves the identical answer.
pub fn staged_system_image_key_digest(pem: &str) -> Result<String> {
    Ok(crate::sha256(&plist::encode_binary(
        &url_asset_reply(pem),
        Limits::default(),
    )?))
}
/// The `URLAsset` reply that serves a recipient key PEM as the public FCS
/// key server returns it: a complete, successful HTTP response.
fn url_asset_reply(pem: &str) -> Value {
    Value::dict([
        ("ResponseBody", Value::Data(pem.as_bytes().to_vec())),
        ("ResponseBodyDone", Value::Boolean(true)),
        ("ResponseHeaders", Value::dict([])),
        ("ResponseStatus", Value::Integer(200)),
    ])
}
fn fingerprint(v: &Value) -> Result<String> {
    Ok(crate::sha256(&plist::encode_binary(v, Limits::default())?))
}
fn validate_http_args(kind: &str, args: &Value) -> Result<()> {
    let method = args.required("RequestMethod")?.string()?;
    if method != if kind == "URLAsset" { "GET" } else { "POST" } {
        return Err(Error::Invalid("offline HTTP request method"));
    }
    args.required("RequestURL")?.string()?;
    if kind == "StreamedImageDecryptionKey" {
        args.required("RequestAdditionalHeaders")?;
        args.required("RequestBody")?.data()?;
    }
    Ok(())
}
/// Every data type the host understands, with the value the public host
/// sends for it (idevicerestore 4b3e847e `restore_supported_data_types`,
/// "extracted from ac2"). Restored's `is_host_compatible` checkpoint fails
/// the restore (AMRError 10) when a type it marks required is missing, so
/// this is the host's vocabulary, not a promise of an answer: a request
/// Stela cannot answer refuses with the whole request when it arrives.
const DATA_TYPES: [(&str, bool); 69] = [
    ("AuthInstallCACert", true),
    ("BasebandBootData", false),
    ("BasebandData", false),
    ("BasebandStackData", false),
    ("BasebandUpdaterOutputData", false),
    ("BootabilityBundle", false),
    ("BootabilityBundleV2", false),
    ("BuildIdentityDict", false),
    ("BuildIdentityDictV2", false),
    ("Cryptex1LocalPolicy", true),
    ("DataType", false),
    ("DeviceRestoreInfoPreflight", false),
    ("DiagData", false),
    ("EANData", false),
    ("FDRMemoryCommit", false),
    ("FDRTrustData", false),
    ("FUDData", false),
    ("FileData", false),
    ("FileDataDone", false),
    ("FirmwareUpdaterData", false),
    ("FirmwareUpdaterDataV2", false),
    ("FirmwareUpdaterDataV3", true),
    ("FirmwareUpdaterPreflight", true),
    ("GrapeFWData", false),
    ("HPMFWData", false),
    ("HostSystemTime", true),
    ("KernelCache", false),
    ("MessageUseStreamedImageFile", true),
    ("NORData", false),
    ("NitrogenFWData", true),
    ("OpalFWData", false),
    ("OverlayRootDataCount", false),
    ("OverlayRootDataForKey", true),
    ("OverlayRootDataForKeyIndex", true),
    ("PeppyFWData", true),
    ("PersonalizedBootObjectV3", false),
    ("PersonalizedData", true),
    ("ProvisioningData", false),
    ("RamdiskFWData", true),
    ("ReceiptManifest", true),
    ("RecoveryOSASRImage", true),
    ("RecoveryOSAppleLogo", true),
    ("RecoveryOSDeviceTree", true),
    ("RecoveryOSFileAssetImage", true),
    ("RecoveryOSIBEC", true),
    ("RecoveryOSIBootFWFilesImages", true),
    ("RecoveryOSImage", true),
    ("RecoveryOSKernelCache", true),
    ("RecoveryOSLocalPolicy", true),
    ("RecoveryOSOverlayRootDataCount", false),
    ("RecoveryOSRootTicketData", true),
    ("RecoveryOSStaticTrustCache", true),
    ("RecoveryOSVersionData", true),
    ("RestoreLocalPolicy", true),
    ("RootData", false),
    ("RootTicket", false),
    ("S3EOverride", false),
    ("SourceBootObjectV3", false),
    ("SourceBootObjectV4", false),
    ("SourceBootObjectV5", false),
    ("SsoServiceTicket", false),
    ("StockholmPostflight", false),
    ("SystemImageCanonicalMetadata", false),
    ("SystemImageData", false),
    ("SystemImageRootHash", false),
    ("URLAsset", true),
    ("USBCFWData", false),
    ("USBCOverride", false),
    ("UpdateVolumeOverlayRootDataCount", true),
];
pub struct Answers<R> {
    pub store: Store<R>,
    pub staged: Staged,
    /// Apple's signing service, only when the user enables it (`tss`).
    pub signer: Option<tss::Signer>,
    /// The host's wall clock, in seconds since the Unix epoch.
    pub clock: Option<Box<dyn FnMut() -> u64>>,
}
impl<R: ReadAt> Answers<R> {
    pub fn new(store: Store<R>) -> Self {
        Self {
            store,
            staged: Staged::default(),
            signer: None,
            clock: None,
        }
    }
    /// Stage the offline `URLAsset` answer for each AEA member's
    /// `fcs-key-url` GET from the inventory's recorded recipient key, so the
    /// guest fetches the system-image content key without the network. The
    /// reply is the PEM as the public key server returns it; restored unwraps
    /// the archive key from the image's own `fcs-response` (see
    /// `docs/research/restore-client.md`). A recorded digest that disagrees
    /// with the rebuilt reply, as a swapped key would, refuses by member.
    pub fn stage_system_image_keys(&mut self) -> Result<()> {
        // Several images can share one recipient key and `fcs-key-url`; stage
        // each URL once, and refuse a URL claimed by two different keys.
        let mut staged: BTreeMap<String, String> = BTreeMap::new();
        for key in self.store.manifest().aea_keys.clone() {
            let args = Value::dict([
                ("RequestMethod", Value::from("GET")),
                ("RequestURL", Value::from(key.url.as_str())),
            ]);
            let bytes = plist::encode_binary(&url_asset_reply(&key.key_pem), Limits::default())?;
            let digest = crate::sha256(&bytes);
            if key.url_asset_sha256.as_deref().is_some_and(|s| s != digest) {
                return Err(Error::Invalid("staged key does not match its member"));
            }
            match staged.get(&key.url) {
                Some(seen) if *seen == digest => continue,
                Some(_) => return Err(Error::Invalid("two keys for one fcs-key-url")),
                None => {}
            }
            self.staged.insert("URLAsset", &args, &bytes, &digest)?;
            staged.insert(key.url, digest);
        }
        Ok(())
    }
    pub fn supported(&self) -> Value {
        Value::Dict(
            DATA_TYPES
                .into_iter()
                .map(|(name, value)| (name.into(), Value::Boolean(value)))
                .collect(),
        )
    }
    fn identity(&self, args: &Value) -> Result<Identity> {
        let current = self.store.identity();
        if !args
            .get("IsRecoveryOS")
            .map(Value::boolean)
            .transpose()?
            .unwrap_or(false)
        {
            return Ok(current.clone());
        }
        let matches: Vec<_> = self
            .store
            .identities()
            .iter()
            .filter(|i| {
                i.variant().ok() == Some("macOS Customer")
                    && i.number("ApChipID").ok() == current.number("ApChipID").ok()
                    && i.number("ApBoardID").ok() == current.number("ApBoardID").ok()
            })
            .collect();
        let [identity] = matches.as_slice() else {
            return Err(Error::Invalid("recovery identity is missing/ambiguous"));
        };
        Ok((*identity).clone())
    }
    fn global_path(&self, identity: &Identity, args: &Value, cryptex: bool) -> Result<String> {
        let variant = manifest_variant(identity.info()?, args)?;
        let prefix = args
            .get("GlobalManifestPrefix")
            .map(Value::string)
            .transpose()?
            .unwrap_or("apticket");
        let suffix = args
            .get("GlobalManifestSuffix")
            .map(Value::string)
            .transpose()?
            .unwrap_or("");
        let class = identity.info()?.required("DeviceClass")?.string()?;
        let path = format!(
            "Firmware/Manifests/restore/{}{variant}/{prefix}.{class}{suffix}.im4m",
            if cryptex { "cryptex1/" } else { "" }
        );
        if !safe_path(&path) || !self.store.manifest().global_manifests.contains(&path) {
            return Err(Error::Invalid("global manifest not in immutable inventory"));
        }
        Ok(path)
    }
    fn global(&mut self, identity: &Identity, args: &Value, cryptex: bool) -> Result<Ticket> {
        let path = self.global_path(identity, args, cryptex)?;
        Ticket::global(self.store.read_small(&path)?, identity)
    }
    fn member_bytes(&mut self, path: &str) -> Result<Vec<u8>> {
        let size = self.store.member_len(path)?;
        if size > MAX_REPLY_BYTES as u64 {
            return Err(Error::Limit("dictionary component bytes"));
        }
        let mut bytes = Vec::new();
        let mut offset = 0;
        while offset < size {
            let n = (size - offset).min(super::store::MAX_READ_BYTES as u64) as usize;
            bytes.extend(self.store.read_at(path, offset, n)?);
            offset += n as u64;
        }
        Ok(bytes)
    }
    fn personalized_stream(
        &mut self,
        identity: &Identity,
        name: &str,
        args: &Value,
    ) -> Result<Vec<Segment>> {
        let path = identity.path(name)?.to_string();
        let size = self.store.member_len(&path)?;
        let head = self.store.read_at(&path, 0, size.min(64) as usize)?;
        let (stored, at) = bare_type(&head, size)?;
        let digest = identity.component(name)?.required("Digest")?.data()?;
        let global = self.global(identity, args, name.starts_with("Cryptex1,"))?;
        // Image4 finds the object by its IM4P type: send the type under which
        // the ticket covers the manifest digest (`Ticket::retype_covered`).
        let tag = if self.store.digest384(&path)?.as_slice() == digest {
            stored
        } else {
            let tags = global.tags_with(digest);
            if tags.is_empty() {
                return Err(Error::Invalid(
                    "global manifest does not cover exact component digest",
                ));
            }
            let mut found = None;
            for tag in tags {
                if self.retyped_digest(&path, &head, at, tag)?.as_slice() == digest {
                    found = Some(tag);
                    break;
                }
            }
            found.ok_or(Error::Invalid("IM4P differs from BuildManifest digest"))?
        };
        let (prefix, suffix) = global.envelope(tag, digest, size)?;
        let mut head = head;
        head[at..at + 4].copy_from_slice(&tag);
        let sent = head.len() as u64;
        Ok(vec![
            Segment::Bytes(prefix),
            Segment::Bytes(head),
            Segment::Member {
                path,
                offset: sent,
                bytes: size - sent,
            },
            Segment::Bytes(suffix),
        ])
    }
    /// SHA-384 of a member with its IM4P type, at `at` in `head`, replaced.
    fn retyped_digest(
        &mut self,
        path: &str,
        head: &[u8],
        at: usize,
        tag: [u8; 4],
    ) -> Result<[u8; 48]> {
        let size = self.store.member_len(path)?;
        let mut hash = Sha384::new();
        let mut first = head.to_vec();
        first[at..at + 4].copy_from_slice(&tag);
        hash.update(&first);
        let mut offset = head.len() as u64;
        while offset < size {
            let n = (size - offset).min(super::store::MAX_READ_BYTES as u64) as usize;
            hash.update(self.store.read_at(path, offset, n)?);
            offset += n as u64;
        }
        Ok(hash.finalize().into())
    }
    /// The component's IM4P stitched with the global ticket, typed as the
    /// ticket covers it (`Ticket::retype_covered`).
    fn personalized(&mut self, identity: &Identity, name: &str, args: &Value) -> Result<Vec<u8>> {
        let path = identity.path(name)?;
        let mut bytes = self.member_bytes(path)?;
        let digest = identity.component(name)?.required("Digest")?.data()?;
        let global = self.global(identity, args, name.starts_with("Cryptex1,"))?;
        global.retype_covered(&mut bytes, digest)?;
        global.wrap(&bytes, digest)
    }
    pub fn plan(&mut self, request: &Value) -> Result<Plan> {
        self.plan_inner(request)
            .map_err(|e| super::refuse(format!("{e}"), request))
    }
    fn plan_inner(&mut self, r: &Value) -> Result<Plan> {
        let kind = r.required("DataType")?.string()?;
        let empty = Value::dict([]);
        let args = r.get("Arguments").unwrap_or(&empty);
        let identity = self.identity(args)?;
        match kind {
            "BuildIdentityDict" => Ok(Plan::Reply(Value::dict([
                ("BuildIdentityDict", identity.value),
                (
                    "Variant",
                    args.get("Variant").cloned().unwrap_or(Value::from("Erase")),
                ),
            ]))),
            "RootTicket" | "RecoveryOSRootTicketData" => {
                let g = self.global(&identity, args, false)?;
                Ok(Plan::Reply(Value::dict([(
                    "RootTicketData",
                    Value::Data(g.bytes().to_vec()),
                )])))
            }
            "ReceiptManifest" => Ok(Plan::Reply(Value::dict([(
                "ReceiptManifest",
                identity.value.required("Manifest")?.clone(),
            )]))),
            "FDRTrustData" => Ok(Plan::Reply(Value::dict([]))),
            "RecoveryOSLocalPolicy" => self.recovery_local_policy(&identity, args),
            // restored's `set_device_time` (R 0x10003172c..0x100031778) reads
            // `SetHostTimeOnDevice` as a 64-bit CFNumber and keeps it only
            // within a day after its own estimate.
            "HostSystemTime" => {
                let clock = self
                    .clock
                    .as_mut()
                    .ok_or(Error::Invalid("the host has no wall clock"))?;
                Ok(Plan::Reply(Value::dict([(
                    "SetHostTimeOnDevice",
                    Value::Integer(clock()),
                )])))
            }
            "RestoreAttestation" => Ok(Plan::Reply(Value::dict([(
                "RestoreShouldAttest",
                Value::Boolean(false),
            )]))),
            "URLAsset" | "StreamedImageDecryptionKey" => {
                Ok(Plan::Reply(self.staged.get(kind, args)?))
            }
            "SystemImageData" | "RecoveryOSASRImage" => {
                let path = identity.path("OS")?.to_string();
                Ok(Plan::Asr(Sender::new(path, &self.store)?))
            }
            "SystemImageRootHash" | "SystemImageCanonicalMetadata" => {
                let component = if kind == "SystemImageRootHash" {
                    "SystemVolume"
                } else {
                    "Ap,SystemVolumeCanonicalMetadata"
                };
                let data = if kind == "SystemImageCanonicalMetadata" {
                    let path = identity.path(component)?;
                    let bytes = self.store.member_len(path)?;
                    if bytes > MAX_REPLY_BYTES as u64 {
                        // The 26A434 mtree is 78 MB: stream it from the IPSW.
                        let member = Segment::Member {
                            path: path.into(),
                            offset: 0,
                            bytes,
                        };
                        return Ok(Plan::Message(framed_binary(&Streamed::Dict(
                            [(format!("{kind}File"), Streamed::Data(vec![member]))].into(),
                        ))?));
                    }
                    self.member_bytes(path)?
                } else {
                    self.personalized(&identity, component, args)?
                };
                Ok(Plan::Reply(Value::Dict(
                    [(format!("{kind}File"), Value::Data(data))].into(),
                )))
            }
            "SourceBootObjectV4" | "SourceBootObjectV5" | "PersonalizedBootObjectV3" => {
                let name = args.required("ImageName")?.string()?;
                let path = match name {
                    "__GlobalManifest__" => self.global_path(&identity, args, false)?,
                    "__RestoreVersion__" => "RestoreVersion.plist".into(),
                    "__SystemVersion__" => "SystemVersion.plist".into(),
                    _ => identity.path(name)?.into(),
                };
                if kind == "PersonalizedBootObjectV3" && !name.starts_with("__") {
                    return Ok(Plan::File(self.personalized_stream(&identity, name, args)?));
                }
                let bytes = self.store.member_len(&path)?;
                self.store.verify(&path)?;
                Ok(Plan::File(vec![Segment::Member {
                    path,
                    offset: 0,
                    bytes,
                }]))
            }
            "FUDData" | "PersonalizedData" => self.image_data(&identity, args, kind),
            "FirmwareUpdaterData" => self.updater(&identity, args),
            "FirmwareUpdaterPreflight" | "DeviceRestoreInfoPreflight" => Err(Error::Invalid(
                "updater-specific preflight semantics unqualified; no empty success",
            )),
            "NORData" => self.nor(&identity, args),
            "BootabilityBundle" | "BootabilityBundleV2" => self.bootability(kind),
            // Advertised for restored's compatibility check (`DATA_TYPES`).
            _ if DATA_TYPES.iter().any(|(name, _)| *name == kind) => {
                Err(Error::Invalid("advertised data type without a host answer"))
            }
            _ => Err(Error::Invalid("unknown required restore DataType")),
        }
    }
    /// libbootpolicy accepts only an Apple-signed recoveryOS policy
    /// (`docs/research/restore-trust.md`): Apple's ticket for the bare
    /// policy, stitched unchanged, or a refusal without the signing service.
    fn recovery_local_policy(&mut self, identity: &Identity, args: &Value) -> Result<Plan> {
        let signer = self.signer.as_mut().ok_or(Error::Invalid(
            "recoveryOS LocalPolicy needs Apple's signing service (opt-in --tss); a Stela-signed policy fails libbootpolicy's Apple root",
        ))?;
        let bytes = tss::request_local_policy(signer, identity, args)?;
        let ticket = Ticket::personalized(bytes, identity, signer.ecid)?;
        let policy = ticket.wrap(&tss::LOCAL_POLICY, &Sha384::digest(tss::LOCAL_POLICY))?;
        Ok(Plan::Reply(Value::dict([(
            "Ap,LocalPolicy",
            Value::Data(policy),
        )])))
    }
    fn nor(&mut self, identity: &Identity, args: &Value) -> Result<Plan> {
        let llb = self.personalized(identity, "LLB", &Value::dict([]))?;
        let Value::Dict(manifest) = identity.value.required("Manifest")? else {
            return Err(Error::Invalid("NOR manifest dictionary"));
        };
        let mut names = Vec::new();
        for (name, entry) in manifest {
            let info = entry.required("Info")?;
            let flag = |key| {
                info.get(key)
                    .map(Value::boolean)
                    .transpose()
                    .map(|b| b.unwrap_or(false))
            };
            if (flag("IsFirmwarePayload")?
                || (flag("IsSecondaryFirmwarePayload")? && flag("IsLoadedByiBoot")?))
                && !matches!(name.as_str(), "LLB" | "RestoreSEP")
            {
                names.push(name.clone());
            }
        }
        if names.is_empty() {
            return Err(Error::Invalid("NOR firmware set absent"));
        }
        // Public host places iBoot first in the array. Remaining members have
        // stable component-name order; FlashVersion1 uses a dictionary instead.
        names.sort_by_key(|name| (!name.starts_with("iBoot"), name.clone()));
        let dict_mode = args.get("FlashVersion1").is_some();
        let mut dict = BTreeMap::new();
        let mut array = Vec::new();
        let mut total = llb.len();
        for name in names {
            let b = self.personalized(identity, &name, &Value::dict([]))?;
            total += b.len();
            if total > MAX_REPLY_BYTES {
                return Err(Error::Limit("NOR response bytes"));
            }
            if dict_mode {
                dict.insert(name, Value::Data(b));
            } else {
                array.push(Value::Data(b));
            }
        }
        let mut response: BTreeMap<String, Value> = [
            ("LlbImageData".into(), Value::Data(llb)),
            (
                "NorImageData".into(),
                if dict_mode {
                    Value::Dict(dict)
                } else {
                    Value::Array(array)
                },
            ),
        ]
        .into();
        for (component, key) in [
            ("RestoreSEP", "RestoreSEPImageData"),
            ("SEP", "SEPImageData"),
            ("SepStage1", "SEPPatchImageData"),
        ] {
            if manifest.contains_key(component) {
                let b = self.personalized(identity, component, &Value::dict([]))?;
                total += b.len();
                if total > MAX_REPLY_BYTES {
                    return Err(Error::Limit("NOR response bytes"));
                }
                response.insert(key.into(), Value::Data(b));
            }
        }
        Ok(Plan::Reply(Value::Dict(response)))
    }
    /// `NORData` when nothing flashes NOR: only the restore SEP images, each its
    /// identity's IM4P unchanged and digest-verified. No global ticket covers
    /// them (the root ticket has no `rsep` or `sepi`), and Stela's SEP model
    /// is their authenticator (`docs/research/sep.md`), as SEPROM is a Mac's.
    /// The firmware set and LLB are absent, so a reader of them fails.
    pub fn sep_firmware(&mut self, request: &Value) -> Result<Plan> {
        self.sep_firmware_inner(request)
            .map_err(|e| super::refuse(format!("{e}"), request))
    }
    fn sep_firmware_inner(&mut self, request: &Value) -> Result<Plan> {
        let empty = Value::dict([]);
        let identity = self.identity(request.get("Arguments").unwrap_or(&empty))?;
        let mut response = BTreeMap::new();
        let mut total = 0usize;
        // `load_sep_os` reads only these (R 0x2d514); the installed `SEP`
        // image is not sent.
        //
        // `RestoreSEP` names the `SEP` image file, and its manifest digest
        // covers that IM4P retyped `rsep` (the 26A434 J473 identity's
        // `RestoreSEP` digest is SHA-384 of `sep-firmware.j473.RELEASE.im4p`
        // with `sepi` replaced by `rsep`), so the image is sent retyped. No
        // `SepStage1` type is recorded: one is sent unchanged, and a digest
        // that does not cover it refuses.
        for (component, key, kind) in [
            ("RestoreSEP", "RestoreSEPImageData", Some(*b"rsep")),
            ("SepStage1", "SEPPatchImageData", None),
        ] {
            if identity.component(component).is_err() {
                continue;
            }
            let path = identity.path(component)?.to_string();
            let mut bytes = self.member_bytes(&path)?;
            let digest = identity.component(component)?.required("Digest")?.data()?;
            let parts = crate::img4::parse(&bytes)
                .map_err(|_| Error::Invalid("SEP firmware is not an IM4P"))?;
            if parts.manifest.is_some() {
                return Err(Error::Invalid("SEP firmware is not a bare IM4P"));
            }
            if let Some(kind) = kind {
                crate::img4::set_payload_type(&mut bytes, kind)
                    .map_err(|_| Error::Invalid("SEP firmware type cannot be set"))?;
            }
            if Sha384::digest(&bytes).as_slice() != digest {
                return Err(Error::Invalid(
                    "SEP firmware differs from its BuildManifest digest",
                ));
            }
            total += bytes.len();
            if total > MAX_REPLY_BYTES {
                return Err(Error::Limit("NOR response bytes"));
            }
            response.insert(key.to_string(), Value::Data(bytes));
        }
        if !response.contains_key("RestoreSEPImageData") {
            return Err(Error::Invalid("identity has no RestoreSEP image"));
        }
        Ok(Plan::Reply(Value::Dict(response)))
    }
    fn updater(&mut self, identity: &Identity, args: &Value) -> Result<Plan> {
        let updater = args.required("MessageArgUpdaterName")?.string()?;
        if updater != "Cryptex1" {
            return Err(Error::Invalid(
                "unsupported firmware updater/ticket trust boundary",
            ));
        }
        let request = args.required("DeviceGeneratedRequest")?;
        // Explicit nonce or ECID requests cannot be answered with a non-nonce
        // global. Retain all device-generated context in the caller's refusal.
        if let Value::Dict(d) = request
            && d.keys().any(|k| k.contains("Nonce") || k.contains("ECID"))
        {
            return Err(Error::Invalid(
                "cryptex updater requires personalized ticket",
            ));
        }
        let response_tags = args
            .required("DeviceGeneratedTags")?
            .required("ResponseTags")?
            .array()?;
        if response_tags.len() != 1 || response_tags[0].string()? != "Cryptex1,Ticket" {
            return Err(Error::Invalid("unsupported cryptex response tags"));
        }
        let global = self.global(identity, &Value::dict([]), true)?;
        Ok(Plan::Reply(Value::dict([(
            "FirmwareResponseData",
            Value::dict([("Cryptex1,Ticket", Value::Data(global.bytes().to_vec()))]),
        )])))
    }
    fn image_data(&mut self, identity: &Identity, args: &Value, kind: &str) -> Result<Plan> {
        let (list_key, data_key, flag) = if kind == "FUDData" {
            ("FUDImageList", "FUDImageData", "IsFUDFirmware")
        } else {
            (
                "ImageList",
                "ImageData",
                args.required("ImageType")?.string()?,
            )
        };
        let Value::Dict(manifest) = identity.value.required("Manifest")? else {
            return Err(Error::Invalid("manifest dictionary"));
        };
        let list = args
            .get(list_key)
            .map(Value::boolean)
            .transpose()?
            .unwrap_or(false);
        let name = args.get("ImageName").map(Value::string).transpose()?;
        let mut matches = Vec::new();
        for (component, entry) in manifest {
            if entry
                .required("Info")?
                .get(flag)
                .map(Value::boolean)
                .transpose()?
                .unwrap_or(false)
            {
                matches.push(component.clone());
            }
        }
        if list {
            return Ok(Plan::Reply(Value::Dict(
                [(
                    list_key.into(),
                    Value::Array(matches.into_iter().map(Value::String).collect()),
                )]
                .into(),
            )));
        }
        if let Some(name) = name {
            if !matches.iter().any(|s| s == name) {
                return Err(Error::Invalid(
                    "requested image does not match manifest ImageType",
                ));
            }
            if self.store.member_len(identity.path(name)?)? > MAX_REPLY_BYTES as u64 {
                let data = self.personalized_stream(identity, name, &Value::dict([]))?;
                return Ok(Plan::Message(framed_binary(&Streamed::Dict(
                    [
                        (data_key.into(), Streamed::Data(data)),
                        ("ImageName".into(), Streamed::String(name.into())),
                    ]
                    .into(),
                ))?));
            }
            let data = self.personalized(identity, name, &Value::dict([]))?;
            return Ok(Plan::Reply(Value::dict([
                (data_key, Value::Data(data)),
                ("ImageName", Value::from(name)),
            ])));
        }
        if matches.is_empty() {
            return Err(Error::Invalid(
                "no manifest images match required image request",
            ));
        }
        let mut data = BTreeMap::new();
        let mut total = 0;
        for name in &matches {
            let bytes = self.personalized(identity, name, &Value::dict([]))?;
            total += bytes.len();
            if total > MAX_REPLY_BYTES {
                // Too large to hold: stream every image from its member.
                let mut streamed = BTreeMap::new();
                for name in &matches {
                    let data = self.personalized_stream(identity, name, &Value::dict([]))?;
                    streamed.insert(name.clone(), Streamed::Data(data));
                }
                return Ok(Plan::Message(framed_binary(&Streamed::Dict(
                    [(data_key.into(), Streamed::Dict(streamed))].into(),
                ))?));
            }
            data.insert(name.clone(), Value::Data(bytes));
        }
        Ok(Plan::Reply(Value::Dict(
            [(data_key.into(), Value::Dict(data))].into(),
        )))
    }
    fn bootability(&mut self, kind: &str) -> Result<Plan> {
        let prefix = format!("{kind}/Restore/Bootability/");
        let cache = format!("{kind}/Restore/Firmware/Bootability.dmg.trustcache");
        let mut segments = Vec::new();
        for entry in self.store.zip_entries() {
            let name = if entry.name == cache {
                "Bootability.trustcache"
            } else if let Some(s) = entry.name.strip_prefix(&prefix) {
                s
            } else {
                continue;
            };
            let name = name.trim_end_matches('/');
            if name.is_empty() {
                continue;
            }
            if !safe_path(name) {
                return Err(Error::Invalid("unsafe Bootability path"));
            }
            let mode = bootability_mode(entry.unix_mode, entry.bytes, || {
                self.store.member_len(&entry.name)
            })?;
            segments.push(Segment::Bytes(cpio_header(name, mode as u64, entry.bytes)?));
            if entry.bytes != 0 {
                segments.push(Segment::Member {
                    path: entry.name.clone(),
                    offset: 0,
                    bytes: entry.bytes,
                });
            }
        }
        if segments.is_empty() {
            return Err(Error::Invalid("Bootability bundle absent"));
        }
        segments.push(Segment::Bytes(cpio_header("TRAILER!!!", 0, 0)?));
        Ok(Plan::Raw(segments))
    }
}
/// The cpio mode of a Bootability ZIP entry: a file or link the inventory
/// lists at its ZIP size, or an empty directory, which has no bytes to verify
/// and so no inventory entry.
fn bootability_mode(
    mode: Option<u16>,
    bytes: u64,
    listed: impl FnOnce() -> Result<u64>,
) -> Result<u16> {
    let mode = mode.ok_or(Error::Invalid("Bootability ZIP Unix mode absent"))?;
    match u32::from(mode) & 0o170000 {
        0o040000 if bytes != 0 => Err(Error::Invalid("nonempty Bootability directory")),
        0o040000 => Ok(mode),
        0o100000 | 0o120000 => {
            if listed()? != bytes {
                return Err(Error::Invalid("Bootability inventory size"));
            }
            Ok(mode)
        }
        _ => Err(Error::Invalid("unsupported Bootability file type")),
    }
}
/// A reply value whose data objects may stream from IPSW members.
enum Streamed {
    String(String),
    Data(Vec<Segment>),
    Dict(BTreeMap<String, Streamed>),
}
/// Frame `v` as the control stream frames a reply: a big-endian length and
/// `plist::encode_binary`'s exact layout, with each data object's bytes left
/// as its segments.
fn framed_binary(v: &Streamed) -> Result<Vec<Segment>> {
    fn marker(out: &mut Vec<u8>, tag: u8, n: u64) {
        if n < 15 {
            out.push(tag | n as u8);
        } else {
            out.extend_from_slice(&[tag | 15, 0x13]);
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
    fn emit(v: &Streamed, objects: &mut Vec<Vec<Segment>>) -> u64 {
        let mut head = Vec::new();
        let mut body = Vec::new();
        match v {
            Streamed::String(s) if s.is_ascii() => {
                marker(&mut head, 0x50, s.len() as u64);
                head.extend_from_slice(s.as_bytes());
            }
            Streamed::String(s) => {
                marker(&mut head, 0x60, s.encode_utf16().count() as u64);
                for c in s.encode_utf16() {
                    head.extend_from_slice(&c.to_be_bytes());
                }
            }
            Streamed::Data(segments) => {
                marker(&mut head, 0x40, segments.iter().map(Segment::len).sum());
                body = segments.clone();
            }
            Streamed::Dict(d) => {
                marker(&mut head, 0xd0, d.len() as u64);
                for k in d.keys() {
                    let key = emit(&Streamed::String(k.clone()), objects);
                    head.extend_from_slice(&key.to_be_bytes());
                }
                for v in d.values() {
                    head.extend_from_slice(&emit(v, objects).to_be_bytes());
                }
            }
        }
        let mut object = vec![Segment::Bytes(head)];
        object.extend(body);
        objects.push(object);
        objects.len() as u64 - 1
    }
    let mut objects = Vec::new();
    let root = emit(v, &mut objects);
    let mut segments = vec![Segment::Bytes(b"bplist00".to_vec())];
    let mut at = 8u64;
    let mut tail = Vec::new();
    for object in objects.iter() {
        tail.extend_from_slice(&at.to_be_bytes());
        for segment in object {
            at += segment.len();
        }
    }
    let table = at;
    segments.extend(objects.into_iter().flatten());
    tail.extend_from_slice(&[0, 0, 0, 0, 0, 0, 8, 8]);
    tail.extend_from_slice(&((tail.len() / 8 - 1) as u64).to_be_bytes());
    tail.extend_from_slice(&root.to_be_bytes());
    tail.extend_from_slice(&table.to_be_bytes());
    let length = u32::try_from(table + tail.len() as u64)
        .map_err(|_| Error::Limit("plist frame u32 length"))?;
    segments.push(Segment::Bytes(tail));
    segments.insert(0, Segment::Bytes(length.to_be_bytes().to_vec()));
    Ok(segments)
}
/// The variant directory of a global manifest: the request's `Variant`, else
/// the identity's macOS variant. An erase or upgrade identity names it as
/// `MacOSVariant`; the `macOS Customer` identity restored selects with
/// `IsRecoveryOS` has none and is that variant itself.
fn manifest_variant<'a>(info: &'a Value, args: &'a Value) -> Result<&'a str> {
    match args.get("Variant") {
        Some(v) => v.string(),
        None => match info.get("MacOSVariant") {
            Some(v) => v.string(),
            None => info.required("Variant")?.string(),
        },
    }
}
/// Check the outer IM4P header and its exact extent without loading the body;
/// returns the type and its offset.
fn bare_type(prefix: &[u8], bytes: u64) -> Result<([u8; 4], usize)> {
    if prefix.first() != Some(&0x30) {
        return Err(Error::Invalid("IM4P sequence"));
    }
    let first = *prefix.get(1).ok_or(Error::Invalid("short IM4P header"))?;
    let (header, length) = if first < 128 {
        (2, first as u64)
    } else {
        let width = (first & 127) as usize;
        if !(1..=4).contains(&width) {
            return Err(Error::Invalid("IM4P length width"));
        }
        let b = prefix
            .get(2..2 + width)
            .ok_or(Error::Invalid("short IM4P length"))?;
        (2 + width, b.iter().fold(0u64, |n, &v| (n << 8) | v as u64))
    };
    if length + header as u64 != bytes || prefix.get(header..header + 6) != Some(b"\x16\x04IM4P") {
        return Err(Error::Invalid("source must be exactly one bare IM4P"));
    }
    let tag = crate::img4::peek_payload_type(prefix)
        .map_err(|_| Error::Invalid("IM4P streaming type"))?;
    // `IA5String "IM4P"` is followed by the four-character type's IA5String.
    let at = header + 8;
    if prefix.get(header + 6..at) != Some(b"\x16\x04") || prefix.get(at..at + 4) != Some(&tag[..]) {
        return Err(Error::Invalid("IM4P streaming type"));
    }
    Ok((tag, at))
}
/// odc cpio, as public restore.c emits it. UID/GID zero, one link; deterministic
/// archive metadata is a host archive choice, not a guest firmware identity.
fn cpio_header(name: &str, mode: u64, size: u64) -> Result<Vec<u8>> {
    if size > 0o77777777777 || name.len() + 1 > 0o777777 || mode > 0o777777 {
        return Err(Error::Limit("odc header field"));
    }
    let header = format!(
        "070707{:06o}{:06o}{mode:06o}{:06o}{:06o}{:06o}{:06o}{:011o}{:06o}{size:011o}",
        0,
        0,
        0,
        0,
        1,
        0,
        0,
        name.len() + 1
    );
    let mut out = header.into_bytes();
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nor_data_without_flashing_carries_only_the_unchanged_restore_sep_image() {
        let sep = [
            0x30, 0x11, 0x16, 0x04, b'I', b'M', b'4', b'P', 0x16, 0x04, b'r', b's', b'e', b'p',
            0x16, 0x00, 0x04, 0x01, 0x07,
        ];
        let store = super::super::store::tests::with_components(
            b"x",
            false,
            &[("RestoreSEP", "sep.im4p", &sep)],
        );
        let mut answers = Answers::new(store);
        let request = Value::dict([("DataType", Value::from("NORData"))]);
        let Plan::Reply(reply) = answers.sep_firmware(&request).unwrap() else {
            panic!()
        };
        let Value::Dict(fields) = &reply else {
            panic!()
        };
        assert_eq!(fields.keys().collect::<Vec<_>>(), ["RestoreSEPImageData"]);
        assert_eq!(
            reply
                .required("RestoreSEPImageData")
                .unwrap()
                .data()
                .unwrap(),
            sep
        );
        let mut bare = Answers::new(super::super::store::tests::fixture(b"x", false));
        assert!(bare.sep_firmware(&request).is_err());
    }
    /// As in the 26A434 J473 identity: `RestoreSEP` and `SEP` name one
    /// `sepi` file, and `RestoreSEP`'s digest covers it retyped `rsep`.
    #[test]
    fn nor_data_sends_the_sep_image_retyped_rsep_that_its_digest_covers() {
        use sha2::{Digest, Sha384};
        let sepi = [
            0x30, 0x11, 0x16, 0x04, b'I', b'M', b'4', b'P', 0x16, 0x04, b's', b'e', b'p', b'i',
            0x16, 0x00, 0x04, 0x01, 0x07,
        ];
        let mut rsep = sepi;
        rsep[10..14].copy_from_slice(b"rsep");
        let components: [(&str, &str, &[u8]); 2] = [
            ("SEP", "sep.im4p", &sepi),
            ("RestoreSEP", "sep.im4p", &sepi),
        ];
        let request = Value::dict([("DataType", Value::from("NORData"))]);
        let store = super::super::store::tests::with_digests(
            b"x",
            false,
            &components,
            &[("RestoreSEP", Sha384::digest(rsep).into())],
        );
        let Plan::Reply(reply) = Answers::new(store).sep_firmware(&request).unwrap() else {
            panic!()
        };
        assert_eq!(
            reply
                .required("RestoreSEPImageData")
                .unwrap()
                .data()
                .unwrap(),
            rsep
        );
        // A digest of the file as stored does not cover the retyped image.
        let store = super::super::store::tests::with_components(b"x", false, &components);
        let Err(error) = Answers::new(store).sep_firmware(&request) else {
            panic!("a digest of the stored file must not cover the retyped image")
        };
        assert!(format!("{error}").contains("differs from its BuildManifest digest"));
    }
    /// A streamed IM4P is retyped in place: its type sits right after the
    /// `IM4P` label, whatever the outer length's width.
    #[test]
    fn a_streamed_im4p_names_its_type_and_where_it_is() {
        let short = [
            0x30, 0x11, 0x16, 0x04, b'I', b'M', b'4', b'P', 0x16, 0x04, b'd', b't', b'r', b'e',
            0x16, 0x00, 0x04, 0x01, 0x07,
        ];
        assert_eq!(bare_type(&short, 19).unwrap(), (*b"dtre", 10));
        let mut long = vec![0x30, 0x82, 0x01, 0x0e];
        long.extend_from_slice(b"\x16\x04IM4P\x16\x04dcpf\x16\x00\x04\x82\x01\x00");
        long.resize(4 + 0x10e, 0);
        assert_eq!(
            bare_type(&long[..64], long.len() as u64).unwrap(),
            (*b"dcpf", 12)
        );
        assert!(bare_type(&long[..64], long.len() as u64 + 1).is_err());
    }
    #[test]
    fn a_global_manifest_lives_under_the_identitys_macos_variant() {
        let erase = Value::dict([
            ("Variant", Value::from("Customer Erase Install (IPSW)")),
            ("MacOSVariant", Value::from("macOS Customer")),
        ]);
        let recovery = Value::dict([("Variant", Value::from("macOS Customer"))]);
        let none = Value::dict([]);
        assert_eq!(manifest_variant(&erase, &none).unwrap(), "macOS Customer");
        assert_eq!(
            manifest_variant(&recovery, &none).unwrap(),
            "macOS Customer"
        );
        let named = Value::dict([("Variant", Value::from("Other"))]);
        assert_eq!(manifest_variant(&erase, &named).unwrap(), "Other");
        assert!(manifest_variant(&none, &none).is_err());
    }
    /// An advertised type with no answer and a type outside the vocabulary
    /// refuse with distinct reasons, each with the whole request.
    #[test]
    fn unanswered_and_unknown_data_types_refuse_by_name() {
        let mut answers = Answers::new(super::super::store::tests::fixture(b"x", false));
        for (kind, reason) in [
            ("KernelCache", "advertised data type without a host answer"),
            ("NoSuchType", "unknown required restore DataType"),
        ] {
            let request = Value::dict([("DataType", Value::from(kind))]);
            let Err(Error::Refused {
                reason: got,
                request: kept,
            }) = answers.plan(&request)
            else {
                panic!("{kind} must refuse")
            };
            assert!(got.contains(reason), "{kind}: {got}");
            assert_eq!(*kept, request);
        }
    }
    /// A streamed reply is byte for byte the frame of the same value held in
    /// memory, however its data is split.
    #[test]
    fn a_streamed_reply_frames_as_the_reply_held_in_memory() {
        let image = vec![7; 300];
        let held = Value::dict([
            (
                "FUDImageData",
                Value::dict([
                    ("Ap,Big", Value::Data(image.clone())),
                    ("S\u{e9}", Value::Data(b"tiny".to_vec())),
                ]),
            ),
            ("ImageName", Value::from("Ap,Big")),
        ]);
        let streamed = Streamed::Dict(
            [
                (
                    "FUDImageData".into(),
                    Streamed::Dict(
                        [
                            (
                                "Ap,Big".into(),
                                Streamed::Data(vec![
                                    Segment::Bytes(image[..10].to_vec()),
                                    Segment::Bytes(Vec::new()),
                                    Segment::Bytes(image[10..].to_vec()),
                                ]),
                            ),
                            (
                                "S\u{e9}".into(),
                                Streamed::Data(vec![Segment::Bytes(b"tiny".to_vec())]),
                            ),
                        ]
                        .into(),
                    ),
                ),
                ("ImageName".into(), Streamed::String("Ap,Big".into())),
            ]
            .into(),
        );
        let body = plist::encode_binary(&held, Limits::default()).unwrap();
        let mut framed = (body.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(&body);
        let mut got = Vec::new();
        for segment in framed_binary(&streamed).unwrap() {
            let Segment::Bytes(bytes) = segment else {
                panic!("only byte segments were given")
            };
            got.extend(bytes);
        }
        assert_eq!(got, framed);
    }
    /// The staged system-image key answer serves the recorded PEM for its
    /// member's exact `fcs-key-url` GET; a recorded digest for a different key
    /// refuses by member.
    #[test]
    fn the_system_image_key_answers_the_fcs_key_url_get_offline() {
        use crate::payload::AeaKey;
        let pem = "-----BEGIN PRIVATE KEY-----\nMIGHA==\n-----END PRIVATE KEY-----\n";
        let url = "https://wkms-public.apple.com/fcs-keys/mIR-wHh7FG0=";
        let key = AeaKey {
            member: "043-70867-640.dmg.aea".into(),
            header_sha256: "a".repeat(64),
            url: url.into(),
            key_pem: pem.into(),
            key_sha256: crate::sha256(pem.as_bytes()),
            url_asset_sha256: Some(crate::sha256(
                &plist::encode_binary(&url_asset_reply(pem), Limits::default()).unwrap(),
            )),
        };
        let mut store = super::super::store::tests::fixture(b"x", false);
        super::super::store::tests::set_aea_keys(&mut store, alloc::vec![key]);
        let mut answers = Answers::new(store);
        answers.stage_system_image_keys().unwrap();
        let args = Value::dict([
            ("RequestMethod", Value::from("GET")),
            ("RequestURL", Value::from(url)),
        ]);
        let Plan::Reply(reply) = answers
            .plan(&Value::dict([
                ("DataType", Value::from("URLAsset")),
                ("Arguments", args),
            ]))
            .unwrap()
        else {
            panic!("URLAsset must reply")
        };
        assert_eq!(
            reply.required("ResponseBody").unwrap().data().unwrap(),
            pem.as_bytes()
        );

        // A recorded digest for another key refuses by member.
        let mut store = super::super::store::tests::fixture(b"x", false);
        let other = "-----BEGIN PRIVATE KEY-----\nOTHER==\n-----END PRIVATE KEY-----\n";
        super::super::store::tests::set_aea_keys(
            &mut store,
            alloc::vec![AeaKey {
                member: "043-70867-640.dmg.aea".into(),
                header_sha256: "a".repeat(64),
                url: url.into(),
                key_pem: other.into(),
                key_sha256: crate::sha256(other.as_bytes()),
                url_asset_sha256: Some("0".repeat(64)),
            }],
        );
        let error = Answers::new(store).stage_system_image_keys().unwrap_err();
        assert!(format!("{error}").contains("does not match its member"));
    }
    #[test]
    fn exact_http_arguments_digest_and_post_body_are_bound() {
        let args = Value::dict([
            ("RequestMethod", Value::from("GET")),
            ("RequestURL", Value::from("https://example.invalid/key")),
        ]);
        let response = Value::dict([
            ("ResponseBody", Value::Data(b"key".to_vec())),
            ("ResponseBodyDone", Value::Boolean(true)),
            ("ResponseHeaders", Value::dict([])),
            ("ResponseStatus", Value::Integer(200)),
        ]);
        let bytes = plist::encode_binary(&response, Limits::default()).unwrap();
        let mut staged = Staged::default();
        assert!(
            staged
                .insert("URLAsset", &args, &bytes, &"0".repeat(64))
                .is_err()
        );
        staged
            .insert("URLAsset", &args, &bytes, &crate::sha256(&bytes))
            .unwrap();
        assert_eq!(staged.get("URLAsset", &args).unwrap(), response);
        let mut changed = args.clone();
        let Value::Dict(d) = &mut changed else {
            unreachable!()
        };
        d.insert("RequestURL".into(), Value::from("https://else.invalid/key"));
        assert!(staged.get("URLAsset", &changed).is_err());
        assert!(staged.get("StreamedImageDecryptionKey", &args).is_err());
    }
    /// Directories need no inventory entry; files and links need one of
    /// their ZIP size.
    #[test]
    fn bootability_directories_need_no_inventory_entry() {
        let absent = || {
            Err(Error::Invalid(
                "member absent from immutable payload inventory",
            ))
        };
        assert_eq!(bootability_mode(Some(0o40755), 0, absent).unwrap(), 0o40755);
        assert!(bootability_mode(Some(0o40755), 1, || Ok(1)).is_err());
        assert!(bootability_mode(Some(0o100644), 5, absent).is_err());
        assert!(bootability_mode(Some(0o100644), 5, || Ok(4)).is_err());
        assert_eq!(
            bootability_mode(Some(0o120755), 1, || Ok(1)).unwrap(),
            0o120755
        );
        assert!(bootability_mode(Some(0o10644), 0, || Ok(0)).is_err());
        assert!(bootability_mode(None, 0, || Ok(0)).is_err());
    }
    #[test]
    fn cpio_header_has_the_public_wire_layout() {
        let h = cpio_header("a/b", 0o100644, 123).unwrap();
        assert_eq!(h.len(), 76 + 4);
        assert_eq!(&h[..6], b"070707");
        assert_eq!(&h[18..24], b"100644");
        assert_eq!(&h[59..65], b"000004");
        assert_eq!(&h[65..76], b"00000000173");
        assert_eq!(&h[76..], b"a/b\0");
    }
}
