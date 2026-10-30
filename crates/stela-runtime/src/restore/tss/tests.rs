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
    let request = root_ticket_request(&root_identity(), 0x77, &nonces(), Root::RecoveryOs).unwrap();
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
    fn exchange(
        &mut self,
        _: &str,
        _: &str,
        _: &[(&str, &str)],
        _: &str,
        body: &[u8],
    ) -> Result<Option<Vec<u8>>> {
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
        Ok(Some(response))
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

/// A transport whose response takes `waits` more calls to arrive, each
/// asking for the same request.
struct Slow<T> {
    inner: T,
    waits: usize,
    body: Option<Vec<u8>>,
}
impl<T: Transport> Transport for Slow<T> {
    fn exchange(
        &mut self,
        host: &str,
        path: &str,
        headers: &[(&str, &str)],
        content_type: &str,
        body: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        assert_eq!(self.body.get_or_insert_with(|| body.to_vec()), body);
        if self.waits > 0 {
            self.waits -= 1;
            return Ok(None);
        }
        self.inner.exchange(host, path, headers, content_type, body)
    }
}

#[test]
fn an_answer_waits_for_its_signing_exchange_without_blocking() {
    use super::super::answers::{Answers, Plan};
    let mut answers = Answers::new(super::super::store::tests::fixture(b"x", false));
    let posts = alloc::rc::Rc::new(core::cell::Cell::new(0));
    answers.signer = Some(Signer {
        ecid: 0x77,
        nonces: nonces(),
        transport: alloc::boxed::Box::new(Slow {
            inner: Signing {
                posts: posts.clone(),
                nonces: nonces(),
            },
            waits: 2,
            body: None,
        }),
    });
    let request = Value::dict([("DataType", Value::from("RootTicket"))]);
    for _ in 0..2 {
        assert_eq!(answers.plan(&request).err(), Some(Error::Pending));
    }
    let Ok(Plan::Reply(reply)) = answers.plan(&request) else {
        panic!()
    };
    assert!(reply.required("RootTicketData").is_ok());
    assert_eq!(posts.get(), 1);
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
    fn exchange(
        &mut self,
        host: &str,
        path: &str,
        headers: &[(&str, &str)],
        content_type: &str,
        body: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        assert_eq!((host, path, content_type), (HOST, PATH, CONTENT_TYPE));
        assert_eq!(headers, HEADERS);
        self.sent = body.to_vec();
        let ticket =
            super::super::ticket::tests::ticket_for(b"lpol", &LOCAL_POLICY, Some(self.ecid));
        let answer = Value::dict([("ApImg4Ticket", Value::Data(ticket))]);
        let mut response = b"STATUS=0&MESSAGE=SUCCESS&REQUEST_STRING=".to_vec();
        response.extend(plist::encode_xml(&answer, plist::Limits::default())?);
        Ok(Some(response))
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
    assert!(message.to_string().contains("STATUS=94"));
    assert!(ticket(b"<?xml").is_err());
}

/// A restore's `FirmwareUpdaterData` arguments for a nonce-bound cryptex.
fn cryptex_args(ecid: u64) -> Value {
    Value::dict([
        ("MessageArgUpdaterName", Value::from("Cryptex1")),
        (
            "MessageArgInfo",
            Value::dict([
                ("ApChipId", Value::Integer(0x8112)),
                ("ApECID", Value::Signed(ecid as i64)),
                ("ApProductionMode", Value::Boolean(true)),
                ("Nonce", Value::Data(vec![3; 32])),
            ]),
        ),
        (
            "DeviceGeneratedRequest",
            Value::dict([
                ("@Cryptex1,Ticket", Value::Boolean(true)),
                ("ApSecurityDomain", Value::from("0x01")),
                ("Cryptex1,Nonce", Value::Data(vec![3; 32])),
                ("Cryptex1,ChipID", Value::from("0xFF10")),
            ]),
        ),
        (
            "DeviceGeneratedTags",
            Value::dict([
                (
                    "BuildIdentityTags",
                    Value::Array(vec![
                        Value::from("ApBoardID"),
                        Value::from("Cryptex1,LiveNonceDomain"),
                    ]),
                ),
                (
                    "ResponseTags",
                    Value::Array(vec![Value::from("Cryptex1,Ticket")]),
                ),
            ]),
        ),
    ])
}

#[test]
fn the_cryptex_request_merges_identity_tags_common_tags_and_the_devices_request() {
    let store = super::super::store::tests::fixture(b"x", false);
    let ecid = 0xfedc_ba98_7654_3210;
    let request = cryptex_request(store.identity(), ecid, &cryptex_args(ecid)).unwrap();
    let Value::Dict(fields) = &request else {
        panic!()
    };
    let keys: Vec<_> = fields.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        [
            "@Cryptex1,Ticket",
            "@HostPlatformInfo",
            "@UUID",
            "@VersionInfo",
            "ApBoardID",
            "ApChipID",
            "ApECID",
            "ApProductionMode",
            "ApSecurityDomain",
            "ApSecurityMode",
            "Cryptex1,ChipID",
            "Cryptex1,Nonce",
        ]
    );
    assert_eq!(request.required("ApECID").unwrap().uint().unwrap(), ecid);
    // The device's security domain string is sent as libplist reads it.
    assert_eq!(
        request
            .required("ApSecurityDomain")
            .unwrap()
            .uint()
            .unwrap(),
        1
    );
    assert!(
        request
            .required("ApSecurityMode")
            .unwrap()
            .boolean()
            .unwrap()
    );
    assert!(cryptex_request(store.identity(), ecid + 1, &cryptex_args(ecid)).is_err());
}

struct CryptexSigner(Vec<u8>);
impl Transport for CryptexSigner {
    fn exchange(
        &mut self,
        _host: &str,
        _path: &str,
        _headers: &[(&str, &str)],
        _content_type: &str,
        body: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        self.0 = body.to_vec();
        let answer = Value::dict([("Cryptex1,Ticket", Value::Data(vec![9, 8, 7]))]);
        let mut response = b"STATUS=0&MESSAGE=SUCCESS&REQUEST_STRING=".to_vec();
        response.extend(plist::encode_xml(&answer, plist::Limits::default())?);
        Ok(Some(response))
    }
}

#[test]
fn a_nonce_bound_cryptex_takes_apples_ticket_only_with_the_signing_service() {
    use super::super::answers::{Answers, Plan};
    let store = super::super::store::tests::fixture(b"x", false);
    let mut answers = Answers::new(store);
    let request = Value::dict([
        ("DataType", Value::from("FirmwareUpdaterData")),
        ("Arguments", cryptex_args(0x77)),
    ]);
    assert!(answers.plan(&request).is_err());
    answers.signer = Some(Signer {
        ecid: 0x77,
        nonces: nonces(),
        transport: alloc::boxed::Box::new(CryptexSigner(vec![])),
    });
    let Plan::Reply(reply) = answers.plan(&request).unwrap() else {
        panic!()
    };
    let data = reply.required("FirmwareResponseData").unwrap();
    assert_eq!(
        data.required("Cryptex1,Ticket").unwrap().data().unwrap(),
        [9, 8, 7]
    );
}
