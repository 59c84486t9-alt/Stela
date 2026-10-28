//! The opt-in requests to Apple's signing service (TSS): the personalized AP
//! root tickets a restore installs, and the recoveryOS LocalPolicy, the one
//! object restored verifies against Apple's fixed roots
//! (`docs/research/restore-trust.md`), so no Stela key can sign it.
//!
//! Wire: libtatsu `tss.c` (`tss_request_new`, `tss_parameters_add_from_manifest`,
//! `tss_request_add_common_tags`, `tss_request_add_ap_tags`,
//! `tss_request_add_ap_recovery_tags`, `tss_request_add_ap_img4_tags`,
//! `tss_entry_apply_restore_request_rules`, `tss_request_add_local_policy_tags`,
//! `tss_request_send`) and idevicerestore 4b3e847e `idevicerestore.c`
//! (`get_tss_response`, `get_recoveryos_root_ticket_tss_response`,
//! `get_recovery_os_local_policy_tss_response`, `lpol_file`). A request carries
//! the device's ECID, its chip, board and security domain, the build's
//! component digests and the boot's nonces; nothing is sent without a
//! [`Transport`], which the user enables explicitly. The answer is Apple's
//! ticket, unchanged: the guest authenticates it.
use super::{Error, Result, plist, plist::Value, store::Identity};
use alloc::{format, string::String, vec::Vec};
use sha2::{Digest, Sha256, Sha384};

pub const HOST: &str = "gs.apple.com";
/// libtatsu's plain-HTTP URL; the ticket it returns is signed, and the guest
/// checks the signature.
pub const PATH: &str = "/TSS/controller?action=2";
pub const CONTENT_TYPE: &str = "text/xml; charset=\"utf-8\"";
/// libtatsu's request headers. The service answers a request without its
/// User-Agent with HTTP 401 (2026-10-24), and one with it normally.
pub const HEADERS: [(&str, &str); 2] =
    [("User-Agent", "InetURL/1.0"), ("Cache-Control", "no-cache")];
/// libtatsu's `TSS_CLIENT_VERSION_STRING` (`AUTH_VERSION` 1104.0.9).
const VERSION: &str = "libauthinstall-1104.0.9";
/// The bare policy IM4P the ticket's `lpol` entry covers (idevicerestore
/// `lpol_file`): type `lpol`, version `1.0`, a one-byte zero payload.
pub const LOCAL_POLICY: [u8; 22] = [
    0x30, 0x14, 0x16, 0x04, 0x49, 0x4d, 0x34, 0x50, 0x16, 0x04, 0x6c, 0x70, 0x6f, 0x6c, 0x16, 0x03,
    0x31, 0x2e, 0x30, 0x04, 0x01, 0x00,
];
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// One HTTP POST to the signing service with `headers` besides its
/// content type, returning the response body.
pub trait Transport {
    fn post(
        &mut self,
        host: &str,
        path: &str,
        headers: &[(&str, &str)],
        content_type: &str,
        body: &[u8],
    ) -> Result<Vec<u8>>;
}

/// The device the request personalizes for, and the way out to Apple.
pub struct Signer {
    pub ecid: u64,
    pub nonces: Nonces,
    pub transport: alloc::boxed::Box<dyn Transport>,
}

/// The nonces a root ticket binds (`BNCH`, `snon`). On a Mac the boot ROM
/// and iBEC hold the AP nonce and the SEP ROM its own when the host asks for
/// the restore's tickets; under Stela, which plays both roles, they are drawn
/// once for the restore, and a ticket naming any other refuses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nonces {
    /// The AP nonce: 32 bytes under `boot-nonce-hash-method` sha2-384.
    pub ap: [u8; 32],
    /// The SEP nonce, a 20-byte ROM nonce (`generateROMNonce`).
    pub sep: [u8; 20],
}

/// Which root ticket a restore asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Root {
    /// The AP ticket (`RootTicket`): every trusted component of the restore
    /// identity, restore-only firmware and the FDR trust objects included.
    Ap,
    /// The recoveryOS root ticket (`RecoveryOSRootTicketData`): the same
    /// identity without the components libtatsu leaves out of it.
    RecoveryOs,
}

/// Build-identity keys libtatsu copies from the identity into every AP
/// request (`tss_parameters_add_from_manifest`, then
/// `tss_request_add_ap_img4_tags`), when present.
const IDENTITY_STRINGS: [&str; 8] = [
    "Ap,OSLongVersion",
    "Ap,OSReleaseType",
    "Ap,ProductMarketingVersion",
    "Ap,ProductType",
    "Ap,SDKPlatform",
    "Ap,Target",
    "Ap,TargetType",
    "Ap,Timestamp",
];
/// Components no AP request carries (`tss_request_add_ap_tags`).
const AP_SKIPPED: [&str; 5] = [
    "BasebandFirmware",
    "SE,UpdatePayload",
    "BaseSystem",
    "Diags",
    "Ap,ExclaveOS",
];
/// Components the recoveryOS root ticket also leaves out
/// (`tss_request_add_ap_recovery_tags`); it keeps `Ap,ExclaveOS`.
const RECOVERY_SKIPPED: [&str; 30] = [
    "BasebandFirmware",
    "SE,UpdatePayload",
    "BaseSystem",
    "ANS",
    "Ap,AudioBootChime",
    "Ap,CIO",
    "Ap,RestoreCIO",
    "Ap,RestoreTMU",
    "Ap,TMU",
    "Ap,rOSLogo1",
    "Ap,rOSLogo2",
    "AppleLogo",
    "DCP",
    "LLB",
    "RecoveryMode",
    "RestoreANS",
    "RestoreDCP",
    "RestoreDeviceTree",
    "RestoreKernelCache",
    "RestoreLogo",
    "RestoreRamDisk",
    "RestoreSEP",
    "SEP",
    "ftap",
    "ftsp",
    "iBEC",
    "iBSS",
    "rfta",
    "rfts",
    "Diags",
];

/// The TSS request for `root` over the restore identity, as
/// idevicerestore's `get_tss_response` (AP) and
/// `get_recoveryos_root_ticket_tss_response` build it for an Image4 device
/// in production and security mode.
pub fn root_ticket_request(
    identity: &Identity,
    ecid: u64,
    nonces: &Nonces,
    root: Root,
) -> Result<Value> {
    if ecid == 0 {
        return Err(Error::Invalid("TSS needs the machine's nonzero ECID"));
    }
    let mut request = Value::dict([
        ("@HostPlatformInfo", Value::from("mac")),
        ("@VersionInfo", Value::from(VERSION)),
        ("@ApImg4Ticket", Value::Boolean(true)),
        ("ApECID", Value::Integer(ecid)),
        (
            "UniqueBuildID",
            Value::Data(identity.value.required("UniqueBuildID")?.data()?.to_vec()),
        ),
        ("ApChipID", Value::Integer(identity.number("ApChipID")?)),
        ("ApBoardID", Value::Integer(identity.number("ApBoardID")?)),
        (
            "ApSecurityDomain",
            Value::Integer(identity.number("ApSecurityDomain")?),
        ),
        ("ApNonce", Value::Data(nonces.ap.to_vec())),
        ("SepNonce", Value::Data(nonces.sep.to_vec())),
        ("ApSecurityMode", Value::Boolean(true)),
        ("ApProductionMode", Value::Boolean(true)),
    ]);
    let Value::Dict(fields) = &mut request else {
        unreachable!()
    };
    for key in IDENTITY_STRINGS {
        if let Some(value) = identity.value.get(key) {
            fields.insert(key.into(), Value::from(value.string()?));
        }
    }
    let Value::Dict(manifest) = identity.value.required("Manifest")? else {
        return Err(Error::Invalid("identity Manifest dictionary"));
    };
    let skipped: &[&str] = match root {
        Root::Ap => &AP_SKIPPED,
        Root::RecoveryOs => &RECOVERY_SKIPPED,
    };
    for (name, entry) in manifest {
        if skipped.contains(&name.as_str()) {
            continue;
        }
        if let Some(component) = component_entry(entry, root)? {
            fields.insert(name.clone(), component);
        }
    }
    // libtatsu sends a random GUID that only names the request; this one
    // names it by its contents, so a retry of the same request keeps it.
    let id = guid(&plist::encode_xml(&request, plist::Limits::default())?);
    if let Value::Dict(fields) = &mut request {
        fields.insert("@UUID".into(), Value::String(id));
    }
    Ok(request)
}

/// One manifest entry as an AP request carries it, or `None` for one it
/// leaves out: the entry without its `Info`, its `RestoreRequestRules`
/// applied, and an empty `Digest` for a trusted entry that has none.
fn component_entry(entry: &Value, root: Root) -> Result<Option<Value>> {
    let Value::Dict(fields) = entry else {
        return Err(Error::Invalid("BuildManifest entry dictionary"));
    };
    let Some(info) = entry.get("Info") else {
        return Ok(None);
    };
    let trusted = entry
        .get("Trusted")
        .map(Value::boolean)
        .transpose()?
        .unwrap_or(false);
    let rules = info.get("RestoreRequestRules");
    if root == Root::Ap {
        let ftab = info
            .get("IsFTAB")
            .map(Value::boolean)
            .transpose()?
            .unwrap_or(false);
        if (rules.is_none() && !trusted) || ftab {
            return Ok(None);
        }
    }
    let mut out = fields.clone();
    out.remove("Info");
    match rules {
        Some(rules) => apply_rules(&mut out, rules)?,
        None if root == Root::Ap => {
            out.insert("EPRO".into(), Value::Boolean(true));
            out.insert("ESEC".into(), Value::Boolean(true));
        }
        None => {}
    }
    if trusted && !fields.contains_key("Digest") {
        out.insert("Digest".into(), Value::Data(Vec::new()));
    }
    // The AP request drops an empty entry; the recovery request keeps it.
    Ok((root == Root::RecoveryOs || !out.is_empty()).then_some(Value::Dict(out)))
}

/// `tss_entry_apply_restore_request_rules` for a production, security-mode
/// Image4 request: a rule applies when each of its conditions names one of
/// those parameters with an equal value; the Boolean actions of each rule
/// that applies are set, in order. A condition on a parameter this request
/// does not have (`ApDemotionPolicyOverride`, `ApInRomDFU`) never holds.
fn apply_rules(
    entry: &mut alloc::collections::BTreeMap<String, Value>,
    rules: &Value,
) -> Result<()> {
    for rule in rules.array()? {
        let Value::Dict(conditions) = rule.required("Conditions")? else {
            return Err(Error::Invalid("RestoreRequestRules conditions"));
        };
        let holds = conditions.iter().all(|(key, value)| {
            matches!(
                key.as_str(),
                "ApRawProductionMode"
                    | "ApCurrentProductionMode"
                    | "ApRawSecurityMode"
                    | "ApRequiresImage4"
            ) && *value == Value::Boolean(true)
        });
        if !holds {
            continue;
        }
        let Value::Dict(actions) = rule.required("Actions")? else {
            return Err(Error::Invalid("RestoreRequestRules actions"));
        };
        for (key, value) in actions {
            if let Value::Boolean(_) = value {
                entry.insert(key.clone(), value.clone());
            }
        }
    }
    Ok(())
}

/// Ask Apple for `root`'s ticket.
pub fn request_root_ticket(
    signer: &mut Signer,
    identity: &Identity,
    root: Root,
) -> Result<Vec<u8>> {
    let request = root_ticket_request(identity, signer.ecid, &signer.nonces, root)?;
    send(signer, &request)
}

/// The TSS request for a recoveryOS LocalPolicy, from restored's
/// `RecoveryOSLocalPolicy` arguments (`Ap,NextStageIM4MHash`,
/// `Ap,RecoveryOSPolicyNonceHash`, `Ap,VolumeUUID`).
pub fn local_policy_request(identity: &Identity, ecid: u64, args: &Value) -> Result<Value> {
    if ecid == 0 {
        return Err(Error::Invalid("TSS needs the machine's nonzero ECID"));
    }
    let next_stage = args.required("Ap,NextStageIM4MHash")?.data()?.to_vec();
    let nonce = args
        .get("Ap,RecoveryOSPolicyNonceHash")
        .map(|v| v.data().map(<[u8]>::to_vec))
        .transpose()?;
    let volume = args
        .get("Ap,VolumeUUID")
        .map(|v| v.string().and_then(volume_uuid))
        .transpose()?;
    let mut request = Value::dict([
        ("@HostPlatformInfo", Value::from("mac")),
        ("@VersionInfo", Value::from(VERSION)),
        ("@ApImg4Ticket", Value::Boolean(true)),
        ("Ap,LocalBoot", Value::Boolean(true)),
        (
            "Ap,LocalPolicy",
            Value::dict([
                ("Digest", Value::Data(Sha384::digest(LOCAL_POLICY).to_vec())),
                ("Trusted", Value::Boolean(true)),
            ]),
        ),
        ("Ap,NextStageIM4MHash", Value::Data(next_stage)),
        ("ApECID", Value::Integer(ecid)),
        ("ApChipID", Value::Integer(identity.number("ApChipID")?)),
        ("ApBoardID", Value::Integer(identity.number("ApBoardID")?)),
        (
            "ApSecurityDomain",
            Value::Integer(identity.number("ApSecurityDomain")?),
        ),
        ("ApSecurityMode", Value::Boolean(true)),
        ("ApProductionMode", Value::Boolean(true)),
    ]);
    let Value::Dict(fields) = &mut request else {
        unreachable!()
    };
    if let Some(nonce) = nonce {
        fields.insert("Ap,RecoveryOSPolicyNonceHash".into(), Value::Data(nonce));
    }
    if let Some(volume) = volume {
        fields.insert("Ap,VolumeUUID".into(), Value::Data(volume.to_vec()));
    }
    // libtatsu sends a random GUID that only names the request; this one
    // names it by its contents, so a retry of the same request keeps it.
    let id = guid(&plist::encode_xml(&request, plist::Limits::default())?);
    if let Value::Dict(fields) = &mut request {
        fields.insert("@UUID".into(), Value::String(id));
    }
    Ok(request)
}

/// Apple's ticket from a TSS response (`STATUS=0&MESSAGE=SUCCESS&REQUEST_STRING=<plist>`);
/// any other status refuses with the server's message.
pub fn ticket(response: &[u8]) -> Result<Vec<u8>> {
    if response.len() > MAX_RESPONSE_BYTES {
        return Err(Error::Limit("TSS response bytes"));
    }
    let text = core::str::from_utf8(response).map_err(|_| Error::Invalid("TSS response text"))?;
    let field = |name: &str| {
        text.split('&')
            .find_map(|f| f.strip_prefix(name)?.strip_prefix('='))
    };
    let status = field("STATUS").ok_or(Error::Invalid("TSS response has no STATUS"))?;
    if status != "0" || !text.contains("MESSAGE=SUCCESS") {
        let message = field("MESSAGE").unwrap_or("");
        let message = message.split("&REQUEST_STRING").next().unwrap_or(message);
        return Err(Error::Transport(format!(
            "TSS refused: STATUS={status} MESSAGE={message}"
        )));
    }
    let start = text
        .find("<?xml")
        .ok_or(Error::Invalid("TSS response has no plist"))?;
    let answer = plist::decode(&response[start..], plist::Limits::default())?;
    Ok(answer.required("ApImg4Ticket")?.data()?.to_vec())
}

/// Ask Apple for the recoveryOS policy ticket.
pub fn request_local_policy(
    signer: &mut Signer,
    identity: &Identity,
    args: &Value,
) -> Result<Vec<u8>> {
    let request = local_policy_request(identity, signer.ecid, args)?;
    send(signer, &request)
}

fn send(signer: &mut Signer, request: &Value) -> Result<Vec<u8>> {
    let body = plist::encode_xml(request, plist::Limits::default())?;
    let response = signer
        .transport
        .post(HOST, PATH, &HEADERS, CONTENT_TYPE, &body)?;
    ticket(&response)
}

/// `Ap,VolumeUUID` as restored sends it, canonical 8-4-4-4-12 hex.
fn volume_uuid(text: &str) -> Result<[u8; 16]> {
    let bytes = text.as_bytes();
    let dashes = [8, 13, 18, 23];
    if bytes.len() != 36 || dashes.iter().any(|&i| bytes[i] != b'-') {
        return Err(Error::Invalid("Ap,VolumeUUID is not a canonical UUID"));
    }
    let digits: Vec<u8> = bytes.iter().copied().filter(|&b| b != b'-').collect();
    let mut out = [0; 16];
    for (i, pair) in digits.chunks(2).enumerate() {
        let pair = core::str::from_utf8(pair).map_err(|_| Error::Invalid("Ap,VolumeUUID"))?;
        out[i] = u8::from_str_radix(pair, 16).map_err(|_| Error::Invalid("Ap,VolumeUUID hex"))?;
    }
    Ok(out)
}

/// An uppercase 8-4-4-4-12 GUID from a digest of `seed`.
fn guid(seed: &[u8]) -> String {
    let digest = Sha256::digest(seed);
    let hex: String = digest[..16].iter().map(|b| format!("{b:02X}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> Value {
        Value::dict([
            ("Ap,NextStageIM4MHash", Value::Data(vec![1; 48])),
            ("Ap,RecoveryOSPolicyNonceHash", Value::Data(vec![2; 48])),
            (
                "Ap,VolumeUUID",
                Value::from("15C1EDB0-A414-43F8-9AF6-4E28F13D8956"),
            ),
        ])
    }

    #[test]
    fn the_request_carries_exactly_libtatsus_local_policy_tags() {
        let store = super::super::store::tests::fixture(b"x", false);
        let request = local_policy_request(store.identity(), 0x1122_3344_5566, &args()).unwrap();
        let Value::Dict(fields) = &request else {
            panic!()
        };
        let keys: Vec<_> = fields.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "@ApImg4Ticket",
                "@HostPlatformInfo",
                "@UUID",
                "@VersionInfo",
                "Ap,LocalBoot",
                "Ap,LocalPolicy",
                "Ap,NextStageIM4MHash",
                "Ap,RecoveryOSPolicyNonceHash",
                "Ap,VolumeUUID",
                "ApBoardID",
                "ApChipID",
                "ApECID",
                "ApProductionMode",
                "ApSecurityDomain",
                "ApSecurityMode",
            ]
        );
        assert_eq!(
            request.required("ApECID").unwrap().uint().unwrap(),
            0x1122_3344_5566
        );
        assert_eq!(
            request.required("Ap,VolumeUUID").unwrap().data().unwrap()[..4],
            [0x15, 0xc1, 0xed, 0xb0]
        );
        let policy = request.required("Ap,LocalPolicy").unwrap();
        assert_eq!(
            policy.required("Digest").unwrap().data().unwrap(),
            Sha384::digest(LOCAL_POLICY).as_slice()
        );
        assert_eq!(
            request.required("@UUID").unwrap().string().unwrap().len(),
            36
        );
        assert!(local_policy_request(store.identity(), 0, &args()).is_err());
    }

    fn nonces() -> Nonces {
        Nonces {
            ap: [0xa5; 32],
            sep: [0x5a; 20],
        }
    }

    /// An identity with one component of each kind libtatsu treats apart.
    fn root_identity() -> Identity {
        let rule = |conditions: Value, actions: Value| {
            Value::dict([("Conditions", conditions), ("Actions", actions)])
        };
        let trusted = |info: Value, digest: Option<u8>| {
            let mut entry = Value::dict([("Info", info), ("Trusted", Value::Boolean(true))]);
            if let (Value::Dict(fields), Some(byte)) = (&mut entry, digest) {
                fields.insert("Digest".into(), Value::Data(vec![byte; 48]));
            }
            entry
        };
        let rules = Value::dict([(
            "RestoreRequestRules",
            Value::Array(vec![
                rule(
                    Value::dict([
                        ("ApRawProductionMode", Value::Boolean(true)),
                        ("ApRequiresImage4", Value::Boolean(true)),
                    ]),
                    Value::dict([("EPRO", Value::Boolean(true))]),
                ),
                rule(
                    Value::dict([("ApInRomDFU", Value::Boolean(true))]),
                    Value::dict([("ESEC", Value::Boolean(false))]),
                ),
            ]),
        )]);
        let manifest = Value::dict([
            ("KernelCache", trusted(rules, Some(1))),
            ("ftap", trusted(Value::dict([]), Some(2))),
            ("SEP", trusted(Value::dict([]), None)),
            ("BaseSystem", trusted(Value::dict([]), Some(3))),
            ("Logo", Value::dict([("Info", Value::dict([]))])),
            ("NoInfo", Value::dict([("Trusted", Value::Boolean(true))])),
        ]);
        Identity {
            index: 20,
            value: Value::dict([
                ("ApChipID", Value::from("0x8112")),
                ("ApBoardID", Value::from("0x24")),
                ("ApSecurityDomain", Value::from("0x01")),
                ("UniqueBuildID", Value::Data(vec![0x12; 8])),
                ("Ap,ProductType", Value::from("Mac14,3")),
                ("Manifest", manifest),
            ]),
        }
    }

    #[test]
    fn the_ap_request_carries_libtatsus_tags_and_applies_the_rules() {
        let request = root_ticket_request(&root_identity(), 0x77, &nonces(), Root::Ap).unwrap();
        let Value::Dict(fields) = &request else {
            panic!()
        };
        let keys: Vec<_> = fields.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "@ApImg4Ticket",
                "@HostPlatformInfo",
                "@UUID",
                "@VersionInfo",
                "Ap,ProductType",
                "ApBoardID",
                "ApChipID",
                "ApECID",
                "ApNonce",
                "ApProductionMode",
                "ApSecurityDomain",
                "ApSecurityMode",
                "KernelCache",
                "SEP",
                "SepNonce",
                "UniqueBuildID",
                "ftap",
            ]
        );
        let kernel = request.required("KernelCache").unwrap();
        assert_eq!(kernel.get("EPRO"), Some(&Value::Boolean(true)));
        assert_eq!(kernel.get("ESEC"), None);
        assert!(kernel.get("Info").is_none());
        let ftap = request.required("ftap").unwrap();
        assert_eq!(ftap.get("ESEC"), Some(&Value::Boolean(true)));
        assert_eq!(ftap.required("Digest").unwrap().data().unwrap(), [2; 48]);
        let sep = request.required("SEP").unwrap();
        assert_eq!(sep.required("Digest").unwrap().data().unwrap(), b"");
        assert_eq!(
            request.required("ApNonce").unwrap().data().unwrap(),
            nonces().ap
        );
        assert_eq!(
            request.required("ApChipID").unwrap().uint().unwrap(),
            0x8112
        );
        assert!(root_ticket_request(&root_identity(), 0, &nonces(), Root::Ap).is_err());
    }

    #[test]
    fn the_recovery_request_leaves_out_restore_only_components() {
        let request =
            root_ticket_request(&root_identity(), 0x77, &nonces(), Root::RecoveryOs).unwrap();
        for absent in ["ftap", "SEP", "BaseSystem", "NoInfo"] {
            assert!(request.get(absent).is_none(), "{absent}");
        }
        // Without the AP request's defaults, an untrusted entry is sent empty.
        assert_eq!(request.get("Logo"), Some(&Value::dict([])));
        let kernel = request.required("KernelCache").unwrap();
        assert_eq!(kernel.get("EPRO"), Some(&Value::Boolean(true)));
    }

    struct Signing {
        posts: alloc::rc::Rc<core::cell::Cell<usize>>,
        nonces: Nonces,
    }
    impl Transport for Signing {
        fn post(
            &mut self,
            _: &str,
            _: &str,
            _: &[(&str, &str)],
            _: &str,
            body: &[u8],
        ) -> Result<Vec<u8>> {
            self.posts.set(self.posts.get() + 1);
            let request = plist::decode(body, plist::Limits::default())?;
            assert_eq!(request.required("ApNonce")?.data()?, nonces().ap);
            let ticket = super::super::ticket::tests::bound_ticket(
                b"krnl",
                b"k",
                Some(request.required("ApECID")?.uint()?),
                Some(&self.nonces),
            );
            let answer = Value::dict([("ApImg4Ticket", Value::Data(ticket))]);
            let mut response = b"STATUS=0&MESSAGE=SUCCESS&REQUEST_STRING=".to_vec();
            response.extend(plist::encode_xml(&answer, plist::Limits::default())?);
            Ok(response)
        }
    }

    #[test]
    fn the_root_ticket_is_apples_personalized_one_asked_once() {
        use super::super::answers::{Answers, Plan};
        let store = super::super::store::tests::fixture(b"x", false);
        let mut answers = Answers::new(store);
        let posts = alloc::rc::Rc::new(core::cell::Cell::new(0));
        answers.signer = Some(Signer {
            ecid: 0x77,
            nonces: nonces(),
            transport: alloc::boxed::Box::new(Signing {
                posts: posts.clone(),
                nonces: nonces(),
            }),
        });
        let request = Value::dict([("DataType", Value::from("RootTicket"))]);
        for _ in 0..2 {
            let Plan::Reply(reply) = answers.plan(&request).unwrap() else {
                panic!()
            };
            let ticket = reply.required("RootTicketData").unwrap().data().unwrap();
            assert!(ticket.windows(4).any(|w| w == b"BNCH"));
        }
        assert_eq!(posts.get(), 1);
        // A ticket bound to nonces this restore never sent refuses.
        let mut answers = Answers::new(super::super::store::tests::fixture(b"x", false));
        answers.signer = Some(Signer {
            ecid: 0x77,
            nonces: nonces(),
            transport: alloc::boxed::Box::new(Signing {
                posts,
                nonces: Nonces {
                    sep: [0; 20],
                    ..nonces()
                },
            }),
        });
        assert!(answers.plan(&request).is_err());
    }

    #[test]
    fn the_root_ticket_is_the_one_the_restore_booted_under() {
        use super::super::answers::{Answers, Plan};
        let mut answers = Answers::new(super::super::store::tests::fixture(b"x", false));
        let posts = alloc::rc::Rc::new(core::cell::Cell::new(0));
        answers.signer = Some(Signer {
            ecid: 0x77,
            nonces: Nonces {
                ap: [0; 32],
                sep: [0; 20],
            },
            transport: alloc::boxed::Box::new(Signing {
                posts: posts.clone(),
                nonces: nonces(),
            }),
        });
        let booted =
            super::super::ticket::tests::bound_ticket(b"krnl", b"k", Some(0x77), Some(&nonces()));
        // A ticket for another machine refuses.
        let other =
            super::super::ticket::tests::bound_ticket(b"krnl", b"k", Some(0x78), Some(&nonces()));
        assert!(answers.boot_with(other).is_err());
        answers.boot_with(booted.clone()).unwrap();
        assert_eq!(answers.signer.as_ref().unwrap().nonces, nonces());
        let request = Value::dict([("DataType", Value::from("RootTicket"))]);
        let Plan::Reply(reply) = answers.plan(&request).unwrap() else {
            panic!()
        };
        assert_eq!(
            reply.required("RootTicketData").unwrap().data().unwrap(),
            booted
        );
        assert_eq!(posts.get(), 0);
    }

    #[test]
    fn a_volume_uuid_must_be_canonical() {
        assert!(volume_uuid("15C1EDB0A41443F89AF64E28F13D8956").is_err());
        assert!(volume_uuid("15C1EDB0-A414-43F8-9AF6-4E28F13D895G").is_err());
        assert_eq!(
            volume_uuid("00000000-0000-0000-0000-0000000000ff").unwrap()[15],
            0xff
        );
    }

    struct Apple {
        sent: Vec<u8>,
        ecid: u64,
    }
    impl Transport for Apple {
        fn post(
            &mut self,
            host: &str,
            path: &str,
            headers: &[(&str, &str)],
            content_type: &str,
            body: &[u8],
        ) -> Result<Vec<u8>> {
            assert_eq!((host, path, content_type), (HOST, PATH, CONTENT_TYPE));
            assert_eq!(headers, HEADERS);
            self.sent = body.to_vec();
            let ticket =
                super::super::ticket::tests::ticket_for(b"lpol", &LOCAL_POLICY, Some(self.ecid));
            let answer = Value::dict([("ApImg4Ticket", Value::Data(ticket))]);
            let mut response = b"STATUS=0&MESSAGE=SUCCESS&REQUEST_STRING=".to_vec();
            response.extend(plist::encode_xml(&answer, plist::Limits::default())?);
            Ok(response)
        }
    }

    #[test]
    fn the_policy_answer_is_apples_ticket_stitched_to_the_bare_policy() {
        use super::super::answers::{Answers, Plan};
        let store = super::super::store::tests::fixture(b"x", false);
        let mut answers = Answers::new(store);
        let request = Value::dict([
            ("DataType", Value::from("RecoveryOSLocalPolicy")),
            ("Arguments", args()),
        ]);
        assert!(answers.plan(&request).is_err());
        answers.signer = Some(Signer {
            ecid: 0x77,
            nonces: nonces(),
            transport: alloc::boxed::Box::new(Apple {
                sent: vec![],
                ecid: 0x77,
            }),
        });
        let Plan::Reply(reply) = answers.plan(&request).unwrap() else {
            panic!()
        };
        let policy = reply.required("Ap,LocalPolicy").unwrap().data().unwrap();
        let parts = stela_formats::img4::parse(policy).unwrap();
        assert_eq!(parts.payload, LOCAL_POLICY);
        assert!(parts.manifest.is_some());
        answers.signer = Some(Signer {
            ecid: 0x77,
            nonces: nonces(),
            transport: alloc::boxed::Box::new(Apple {
                sent: vec![],
                ecid: 0x78,
            }),
        });
        assert!(answers.plan(&request).is_err());
    }

    #[test]
    fn host_system_time_answers_from_the_host_clock_or_refuses() {
        use super::super::answers::{Answers, Plan};
        let store = super::super::store::tests::fixture(b"x", false);
        let mut answers = Answers::new(store);
        let request = Value::dict([("DataType", Value::from("HostSystemTime"))]);
        assert!(answers.plan(&request).is_err());
        answers.clock = Some(alloc::boxed::Box::new(|| 1_792_437_226));
        let Plan::Reply(reply) = answers.plan(&request).unwrap() else {
            panic!()
        };
        assert_eq!(
            reply
                .required("SetHostTimeOnDevice")
                .unwrap()
                .uint()
                .unwrap(),
            1_792_437_226
        );
    }

    #[test]
    fn only_a_successful_response_yields_its_ticket() {
        let body = b"STATUS=0&MESSAGE=SUCCESS&REQUEST_STRING=<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict><key>ApImg4Ticket</key><data>AQID</data></dict></plist>";
        assert_eq!(ticket(body).unwrap(), [1, 2, 3]);
        let refused = b"STATUS=94&MESSAGE=This device isn't eligible for the requested build.";
        let Err(Error::Transport(message)) = ticket(refused) else {
            panic!()
        };
        assert!(message.contains("STATUS=94"));
        assert!(ticket(b"<?xml").is_err());
    }
}
