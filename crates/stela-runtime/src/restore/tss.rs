//! The opt-in request to Apple's signing service (TSS) for the recoveryOS
//! LocalPolicy, the one object restored verifies against Apple's fixed roots
//! (`docs/research/restore-trust.md`), so no Stela key can sign it.
//!
//! Wire: libtatsu `tss.c` (`tss_request_new`,
//! `tss_request_add_local_policy_tags`, `tss_request_send`) and idevicerestore
//! 4b3e847e `idevicerestore.c` (`get_recovery_os_local_policy_tss_response`,
//! `lpol_file`). The request carries the device's ECID, its chip, board and
//! security domain, and the hashes restored supplies; nothing is sent without
//! a [`Transport`], which the user enables explicitly. The answer is Apple's
//! ticket, unchanged: the guest's libbootpolicy authenticates it.
use super::{Error, Result, plist, plist::Value, store::Identity};
use alloc::{format, string::String, vec::Vec};
use sha2::{Digest, Sha256, Sha384};

pub const HOST: &str = "gs.apple.com";
/// libtatsu's plain-HTTP URL; the ticket it returns is signed, and the guest
/// checks the signature.
pub const PATH: &str = "/TSS/controller?action=2";
pub const CONTENT_TYPE: &str = "text/xml; charset=\"utf-8\"";
/// libtatsu's `TSS_CLIENT_VERSION_STRING` (`AUTH_VERSION` 1104.0.9).
const VERSION: &str = "libauthinstall-1104.0.9";
/// The bare policy IM4P the ticket's `lpol` entry covers (idevicerestore
/// `lpol_file`): type `lpol`, version `1.0`, a one-byte zero payload.
pub const LOCAL_POLICY: [u8; 22] = [
    0x30, 0x14, 0x16, 0x04, 0x49, 0x4d, 0x34, 0x50, 0x16, 0x04, 0x6c, 0x70, 0x6f, 0x6c, 0x16, 0x03,
    0x31, 0x2e, 0x30, 0x04, 0x01, 0x00,
];
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// One HTTP POST to the signing service, returning the response body.
pub trait Transport {
    fn post(&mut self, host: &str, path: &str, content_type: &str, body: &[u8]) -> Result<Vec<u8>>;
}

/// The device the request personalizes for, and the way out to Apple.
pub struct Signer {
    pub ecid: u64,
    pub transport: alloc::boxed::Box<dyn Transport>,
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
    let body = plist::encode_xml(&request, plist::Limits::default())?;
    let response = signer.transport.post(HOST, PATH, CONTENT_TYPE, &body)?;
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
            content_type: &str,
            body: &[u8],
        ) -> Result<Vec<u8>> {
            assert_eq!((host, path, content_type), (HOST, PATH, CONTENT_TYPE));
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
            transport: alloc::boxed::Box::new(Apple {
                sent: vec![],
                ecid: 0x77,
            }),
        });
        let Plan::Reply(reply) = answers.plan(&request).unwrap() else {
            panic!()
        };
        let policy = reply.required("Ap,LocalPolicy").unwrap().data().unwrap();
        let parts = crate::img4::parse(policy).unwrap();
        assert_eq!(parts.payload, LOCAL_POLICY);
        assert!(parts.manifest.is_some());
        answers.signer = Some(Signer {
            ecid: 0x77,
            transport: alloc::boxed::Box::new(Apple {
                sent: vec![],
                ecid: 0x78,
            }),
        });
        assert!(answers.plan(&request).is_err());
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
