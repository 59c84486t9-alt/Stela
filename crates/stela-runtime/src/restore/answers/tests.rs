use super::*;

#[test]
fn recovery_version_metadata_preserves_original_fields_and_xml_types() {
    let info = Value::dict([
        ("BuildNumber", Value::from("fixture-build")),
        ("Variant", Value::from("fixture-recovery")),
        ("BuildTrain", Value::from("fixture-train")),
        ("ProductMarketingVersion", Value::from("1.2.3")),
        ("ProductVersion", Value::from("unrelated source field")),
    ]);
    let bytes = recovery_version_data(&info).unwrap();
    assert!(bytes.starts_with(b"<?xml"));
    assert_eq!(
        plist::decode(&bytes, Limits::default()).unwrap(),
        Value::dict([
            ("BuildNumber", Value::from("fixture-build")),
            ("Variant", Value::from("fixture-recovery")),
            ("BuildTrain", Value::from("fixture-train")),
            ("ProductVersion", Value::from("1.2.3")),
        ])
    );
    assert!(recovery_version_data(&Value::dict([])).is_err());
    assert!(recovery_version_data(&Value::dict([("BuildNumber", Value::Integer(1))])).is_err());
}

#[test]
fn ean_uses_early_access_flags_and_preserves_ticket_checks() {
    use super::super::store::tests::{fixture, set_component_info};
    let request = |args| Value::dict([("DataType", Value::from("EANData")), ("Arguments", args)]);
    let list = request(Value::dict([("EANImageList", Value::Boolean(true))]));
    let mut store = fixture(b"x", false);
    set_component_info(&mut store, "OS", "IsiBootEANFirmware", Value::Boolean(true));
    let mut answers = Answers::new(store);
    let Plan::Reply(empty) = answers.plan(&list).unwrap() else {
        panic!("EAN list must be a reply")
    };
    assert_eq!(empty, Value::dict([("EANImageList", Value::Array(vec![]))]));
    let Plan::Reply(empty_data) = answers.plan(&request(Value::dict([]))).unwrap() else {
        panic!("an empty manifest set must have an empty data dictionary")
    };
    assert_eq!(empty_data, Value::dict([("EANData", Value::dict([]))]));

    set_component_info(
        &mut answers.store,
        "OS",
        "IsEarlyAccessFirmware",
        Value::Boolean(true),
    );
    let Plan::Reply(names) = answers.plan(&list).unwrap() else {
        panic!("EAN list must be a reply")
    };
    assert_eq!(
        names,
        Value::dict([("EANImageList", Value::Array(vec![Value::from("OS")]))])
    );
    // A listed component still needs a real covered image; listing must
    // not substitute an empty successful firmware transfer.
    let data = request(Value::dict([("ImageName", Value::from("OS"))]));
    let Err(Error::Refused { request: kept, .. }) = answers.plan(&data) else {
        panic!("an uncovered component must refuse")
    };
    assert_eq!(*kept, data);
}

#[test]
fn a_payload_has_the_system_image_only_while_its_inventory_holds_the_os_member() {
    use super::super::store::tests::{drop_member, fixture};
    assert!(Answers::new(fixture(b"x", false)).has_system_image());
    let mut store = fixture(b"x", false);
    drop_member(&mut store, "os.dmg");
    assert!(!Answers::new(store).has_system_image());
}

#[test]
fn nor_data_without_flashing_carries_only_the_unchanged_restore_sep_image_in_an_img4() {
    let sep = [
        0x30, 0x11, 0x16, 0x04, b'I', b'M', b'4', b'P', 0x16, 0x04, b'r', b's', b'e', b'p', 0x16,
        0x00, 0x04, 0x01, 0x07,
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
        stela_formats::img4::container(&sep)
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
        0x30, 0x11, 0x16, 0x04, b'I', b'M', b'4', b'P', 0x16, 0x04, b's', b'e', b'p', b'i', 0x16,
        0x00, 0x04, 0x01, 0x07,
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
        stela_formats::img4::container(&rsep)
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
        0x30, 0x11, 0x16, 0x04, b'I', b'M', b'4', b'P', 0x16, 0x04, b'd', b't', b'r', b'e', 0x16,
        0x00, 0x04, 0x01, 0x07,
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
#[test]
fn an_absent_optional_source_global_manifest_finishes_an_empty_file() {
    use super::super::store::tests::{fixture, set_info};

    let request = |optional: Option<Value>| {
        let mut arguments = BTreeMap::from([
            ("ImageName".into(), Value::from("__GlobalManifest__")),
            ("Variant".into(), Value::from("macOS Customer")),
            (
                "GlobalManifestPrefix".into(),
                Value::from("centauri/centauri"),
            ),
        ]);
        if let Some(optional) = optional {
            arguments.insert("GlobalManifestOptional".into(), optional);
        }
        Value::dict([
            ("DataType", Value::from("SourceBootObjectV4")),
            ("Arguments", Value::Dict(arguments)),
        ])
    };

    // Reference restore hosts treat a variant that does not advertise
    // global signing as optional even without an explicit request flag.
    let Plan::File(segments) = Answers::new(fixture(b"x", false))
        .plan(&request(None))
        .unwrap()
    else {
        panic!("missing optional manifest must be an empty file transfer")
    };
    assert!(segments.is_empty());

    // A signing variant normally requires the requested manifest.
    let mut required = fixture(b"x", false);
    set_info(
        &mut required,
        "VariantSupportsGlobalSigning",
        Value::Boolean(true),
    );
    let Err(error) = Answers::new(required).plan(&request(None)) else {
        panic!("missing required manifest must refuse")
    };
    assert!(format!("{error}").contains("global manifest not in immutable inventory"));

    // The device can explicitly make that same request optional. The
    // empty File plan is framed by Job as FileDataDone with no FileData.
    let mut optional = fixture(b"x", false);
    set_info(
        &mut optional,
        "VariantSupportsGlobalSigning",
        Value::Boolean(true),
    );
    let Plan::File(segments) = Answers::new(optional)
        .plan(&request(Some(Value::Boolean(true))))
        .unwrap()
    else {
        panic!("explicitly optional manifest must be an empty file transfer")
    };
    assert!(segments.is_empty());
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
        assert!(got.to_string().contains(reason), "{kind}: {got}");
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
        (
            "NorImageData",
            Value::Array(vec![Value::Data(b"iBoot".to_vec()), Value::from("x")]),
        ),
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
            (
                "NorImageData".into(),
                Streamed::Array(vec![
                    Streamed::Data(vec![Segment::Bytes(b"iBoot".to_vec())]),
                    Streamed::String("x".into()),
                ]),
            ),
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
    use stela_formats::payload::AeaKey;
    let pem = "-----BEGIN PRIVATE KEY-----\nMIGHA==\n-----END PRIVATE KEY-----\n";
    let url = "https://wkms-public.apple.com/fcs-keys/mIR-wHh7FG0=";
    let key = AeaKey {
        member: "043-70867-640.dmg.aea".into(),
        header_sha256: "a".repeat(64),
        url: url.into(),
        key_pem: pem.into(),
        key_sha256: stela_formats::sha256(pem.as_bytes()),
        url_asset_sha256: Some(stela_formats::sha256(
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
            key_sha256: stela_formats::sha256(other.as_bytes()),
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
        .insert("URLAsset", &args, &bytes, &stela_formats::sha256(&bytes))
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
