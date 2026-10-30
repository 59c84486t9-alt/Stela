//! The opt-in requests to Apple's signing service (TSS): the personalized AP
//! root tickets a restore installs, the Cryptex1 ticket the restore's
//! cryptex updater asks for with its own nonce, and the recoveryOS
//! LocalPolicy, the one object restored verifies against Apple's fixed roots
//! (`docs/research/restore-trust.md`), so no Stela key can sign it.
//!
//! Wire: libtatsu `tss.c` (`tss_request_new`, `tss_parameters_add_from_manifest`,
//! `tss_request_add_common_tags`, `tss_request_add_ap_tags`,
//! `tss_request_add_ap_recovery_tags`, `tss_request_add_ap_img4_tags`,
//! `tss_entry_apply_restore_request_rules`, `tss_request_add_local_policy_tags`,
//! `tss_request_send`) and idevicerestore 4b3e847e `idevicerestore.c`
//! (`get_tss_response`, `get_recoveryos_root_ticket_tss_response`,
//! `get_recovery_os_local_policy_tss_response`, `lpol_file`) and `restore.c`
//! (`restore_get_cryptex1_firmware_data`). A request carries
//! the device's ECID, its chip, board and security domain, the build's
//! component digests and the boot's nonces; nothing is sent without a
//! [`Transport`], which the user enables explicitly. The answer is Apple's
//! ticket, unchanged: the guest authenticates it.
use super::{Error, Result, plist, plist::Value, store::Identity};
use alloc::{format, string::String, vec::Vec};
use sha2::{Digest, Sha384};
use stela_contracts::refuse;
use stela_crypto::Sha256;

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

/// The Cryptex1 TSS request for a restore's `FirmwareUpdaterData` arguments,
/// as idevicerestore's `restore_get_cryptex1_firmware_data` builds it.
/// Parameters gather the device's `MessageArgInfo`, the identity's values
/// for its `BuildIdentityTags`, `ApProductionMode` and `ApSecurityMode`
/// (true when absent) and the identity's `ApChipID` and `ApBoardID`, then
/// the `DeviceGeneratedRequest` over them. libtatsu's
/// `tss_request_add_cryptex_tags` builds the request from them: the common
/// tags (`ApECID`, `ApChipID`, `ApBoardID` and `ApSecurityDomain` as
/// integers, which libplist parses from the manifest's hex strings, and
/// `UniqueBuildID` as data), `@Cryptex1,Ticket`, both modes as Booleans and
/// every parameter whose key starts with `Cryptex1`, the cryptex nonce
/// among them. The device's ECID must be the signer's, so a ticket never
/// names another machine.
pub fn cryptex_request(identity: &Identity, ecid: u64, args: &Value) -> Result<Value> {
    let Value::Dict(info) = args.required("MessageArgInfo")? else {
        return Err(Error::Invalid("MessageArgInfo dictionary"));
    };
    let mut parameters = info.clone();
    for tag in args
        .required("DeviceGeneratedTags")?
        .required("BuildIdentityTags")?
        .array()?
    {
        let tag = tag.string()?;
        if let Some(value) = identity.value.get(tag) {
            parameters.insert(tag.into(), value.clone());
        }
    }
    for mode in ["ApProductionMode", "ApSecurityMode"] {
        parameters
            .entry(mode.into())
            .or_insert(Value::Boolean(true));
    }
    for key in ["ApChipID", "ApBoardID"] {
        if let Some(value) = identity.value.get(key) {
            parameters.insert(key.into(), value.clone());
        }
    }
    let Value::Dict(generated) = args.required("DeviceGeneratedRequest")? else {
        return Err(Error::Invalid("DeviceGeneratedRequest dictionary"));
    };
    parameters.extend(generated.iter().map(|(k, v)| (k.clone(), v.clone())));
    let device = parameters
        .get("ApECID")
        .ok_or(Error::Invalid("cryptex request has no ECID"))?;
    if ecid == 0 || device.bits()? != ecid {
        return Err(Error::Invalid(
            "cryptex request names another machine's ECID",
        ));
    }
    let mut request = Value::dict([
        ("@HostPlatformInfo", Value::from("mac")),
        ("@VersionInfo", Value::from(VERSION)),
        ("@Cryptex1,Ticket", Value::Boolean(true)),
        ("ApECID", Value::Integer(ecid)),
    ]);
    let Value::Dict(fields) = &mut request else {
        unreachable!()
    };
    for key in ["ApChipID", "ApBoardID", "ApSecurityDomain"] {
        if let Some(value) = parameters.get(key) {
            fields.insert(key.into(), Value::Integer(integer(value)?));
        }
    }
    if let Some(build) = parameters.get("UniqueBuildID") {
        fields.insert("UniqueBuildID".into(), Value::Data(build.data()?.to_vec()));
    }
    for mode in ["ApSecurityMode", "ApProductionMode"] {
        fields.insert(mode.into(), Value::Boolean(parameters[mode].boolean()?));
    }
    let mut cryptex = false;
    for (key, value) in &parameters {
        if key.starts_with("Cryptex1") {
            fields.insert(key.clone(), value.clone());
            cryptex = true;
        }
    }
    if !cryptex {
        return Err(Error::Invalid("cryptex request names no cryptex"));
    }
    let id = guid(&plist::encode_xml(&request, plist::Limits::default())?);
    if let Value::Dict(fields) = &mut request {
        fields.insert("@UUID".into(), Value::String(id));
    }
    Ok(request)
}

/// An integer parameter as libplist's `plist_dict_get_uint` reads it: an
/// integer's bits, or a manifest's hexadecimal or decimal string.
fn integer(value: &Value) -> Result<u64> {
    match value {
        Value::String(text) => match text.strip_prefix("0x") {
            Some(hex) => u64::from_str_radix(hex, 16),
            None => text.parse(),
        }
        .map_err(|_| Error::Invalid("cryptex request integer string")),
        other => other.bits(),
    }
}

/// Ask Apple for the cryptex ticket the device's request names in its one
/// `ResponseTags` entry.
pub fn request_cryptex_ticket(
    signer: &mut Signer,
    identity: &Identity,
    args: &Value,
    response_tag: &str,
) -> Result<Vec<u8>> {
    let request = cryptex_request(identity, signer.ecid, args)?;
    let body = plist::encode_xml(&request, plist::Limits::default())?;
    let response = signer
        .transport
        .post(HOST, PATH, &HEADERS, CONTENT_TYPE, &body)?;
    answer(&response, response_tag)
}

/// Apple's ticket from a TSS response (`STATUS=0&MESSAGE=SUCCESS&REQUEST_STRING=<plist>`);
/// any other status refuses with the server's message.
pub fn ticket(response: &[u8]) -> Result<Vec<u8>> {
    answer(response, "ApImg4Ticket")
}

/// The data under `key` in a successful TSS response.
fn answer(response: &[u8], key: &str) -> Result<Vec<u8>> {
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
        return Err(Error::Transport(refuse!(
            "TSS refused: STATUS={status} MESSAGE={message}",
            status,
            message
        )));
    }
    let start = text
        .find("<?xml")
        .ok_or(Error::Invalid("TSS response has no plist"))?;
    let answer = plist::decode(&response[start..], plist::Limits::default())?;
    Ok(answer.required(key)?.data()?.to_vec())
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
mod tests;
