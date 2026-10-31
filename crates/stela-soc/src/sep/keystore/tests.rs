use super::*;
use crate::Result;
use stela_contracts::refuse;

struct Buffers {
    input: Vec<u8>,
    output: Vec<u8>,
}

impl Payload for Buffers {
    fn input(&mut self, bytes: &mut [u8]) -> Result<()> {
        let source = self
            .input
            .get(..bytes.len())
            .ok_or(refuse!("short input"))?;
        bytes.copy_from_slice(source);
        Ok(())
    }
    fn output(&mut self, bytes: &[u8]) -> Result<()> {
        self.output = bytes.to_vec();
        Ok(())
    }
}

/// A startup request as the kernel codecs lay it out: header, variant 0,
/// u64 argument and one blob, protected by the truncated digest.
pub(crate) fn message(version: u32, flags: u32, argument: u64, blob: &[u8]) -> Vec<u8> {
    let header = if version == 1 { HEADER_V1 } else { HEADER_V2 };
    let mut bytes = vec![0; LENGTH_BYTES + header];
    bytes[..4].copy_from_slice(&(header as u32).to_le_bytes());
    bytes[VERSION..VERSION + 4].copy_from_slice(&version.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x1234_5678u64.to_le_bytes());
    bytes[FLAGS..FLAGS + 4].copy_from_slice(&flags.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&argument.to_le_bytes());
    bytes.extend_from_slice(&(blob.len() as u32).to_le_bytes());
    bytes.extend_from_slice(blob);
    bytes.resize(bytes.len().next_multiple_of(4), 0);
    let digest = digest(&bytes);
    bytes[DIGEST_START..DIGEST_START + DIGEST_BYTES].copy_from_slice(&digest);
    bytes
}

fn frame(command: u8, sequence: u8, length: usize) -> Frame {
    Frame {
        service: ID,
        tag: command,
        opcode: sequence,
        parameter: 0,
        data: (length as u32) << LENGTH_SHIFT,
    }
}

fn environment(cpx: u32, mode: u32) -> Vec<u8> {
    let mut bytes = vec![0; ENVIRONMENT_BYTES];
    bytes[..4].copy_from_slice(&1u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&cpx.to_le_bytes());
    bytes[8..12].copy_from_slice(&mode.to_le_bytes());
    bytes
}

// Authored encoding of the source-recovered public SIK dictionary:
// SET { SEQUENCE { "skg", 1 }, { "skt", 1 }, { "o", "oskgp" } }.
/// As run12's restore ramdisk sent it: ascending keys `o`, `skg`, `skt`.
pub(crate) const SIK_QUERY: &[u8] = b"\x31\x20\x30\x0a\x0c\x01o\x0c\x05oskgp\x30\x08\x0c\x03skg\x02\x01\x01\x30\x08\x0c\x03skt\x02\x01\x01";
/// The same pairs in DER's encoded-pair order, which the AP never sends.
const DER_ORDER_QUERY: &[u8] = b"\x31\x20\x30\x08\x0c\x03skg\x02\x01\x01\x30\x08\x0c\x03skt\x02\x01\x01\x30\x0a\x0c\x01o\x0c\x05oskgp";

pub(crate) fn system_request(version: u32, query: &[u8]) -> Vec<u8> {
    system_request_with_operation(version, 2, query)
}

pub(crate) fn system_request_with_operation(version: u32, operation: u32, query: &[u8]) -> Vec<u8> {
    let mut request = message(version, 0, 1, &[]);
    let body = Message::parse(&request).unwrap().body;
    request.truncate(body);
    request.extend_from_slice(&0u32.to_le_bytes()); // variant
    request.extend_from_slice(&0x1234_5678_9abc_def0u64.to_le_bytes());
    request.extend_from_slice(&u32::MAX.to_le_bytes());
    request.extend_from_slice(&operation.to_le_bytes());
    request.extend_from_slice(&(query.len() as u32).to_le_bytes());
    request.extend_from_slice(query);
    request.resize(request.len().next_multiple_of(4), 0);
    let hash = digest(&request);
    request[DIGEST_START..DIGEST_START + DIGEST_BYTES].copy_from_slice(&hash);
    request
}

// Authored from libFDR arm64e 8ae18..8aff8, its resolved outlined
// helpers and the caller at 1630..1974. Ascending UTF8 key names:
// {bc: 13, kt: 5, o: "oc", rko: 1}; no captured secrets or Apple bytes.
const REFERENCE_CREATE: &[u8] = b"\x31\x25\x30\x07\x0c\x02bc\x02\x01\x0d\x30\x07\x0c\x02kt\x02\x01\x05\x30\x07\x0c\x01o\x0c\x02oc\x30\x08\x0c\x03rko\x02\x01\x01";

#[test]
fn source_shaped_constructor_returns_reopenable_keys_and_advances_to_attestation() {
    for version in [1, 2] {
        for kind in [4, 5] {
            let root = Zeroizing::new([1; 32]);
            let mut keystore = KeyStore::with_system_keys(root.clone());
            let mut query = REFERENCE_CREATE.to_vec();
            query[19] = kind;
            let request = system_request_with_operation(version, 0, &query);
            let sent = frame(system_key::PERFORM_OPERATION, 26, request.len());
            let (reply, output) =
                ask_with_entropy(&mut keystore, sent, request, &mut |bytes: &mut [u8]| {
                    bytes.fill(2);
                    Ok(())
                });
            let reply = reply.unwrap();
            assert_eq!(reply.parameter, 0);
            assert_eq!(reply.opcode, sent.opcode);
            assert_eq!(reply.data as usize >> LENGTH_SHIFT, output.len());
            let parsed = Message::parse(&output).unwrap();
            assert_eq!(parsed.variant(), 0);
            let mut fields = parsed.fields();
            let blob = fields.blob().unwrap();
            fields.end().unwrap();
            reference_key::ReferenceKey::open(&root, blob).unwrap();
            assert_eq!(keystore.diagnostics().count(), 0);
            // Source helper 5c61c inserts the ENTIRE constructor reply
            // as rk, not just its nested public metadata dictionary.
            let params = reference_key::tests::attestation_parameters(blob);
            let request = system_request_with_operation(version, 0, &params);
            let sent = frame(system_key::PERFORM_OPERATION, 27, request.len());
            let (reply, output) = ask(&mut keystore, sent, request);
            assert_eq!(reply.unwrap().parameter, 0);
            let parsed = Message::parse(&output).unwrap();
            let mut fields = parsed.fields();
            let signature = p256::ecdsa::Signature::from_der(fields.blob().unwrap()).unwrap();
            fields.end().unwrap();
            let key = reference_key::ReferenceKey::open(&root, blob).unwrap();
            let public = keystore
                .system_keys
                .as_mut()
                .unwrap()
                .public(system_key::PublicQuery::Identity)
                .unwrap();
            let verifier = p256::ecdsa::VerifyingKey::from_sec1_bytes(public).unwrap();
            use p256::ecdsa::signature::Verifier;
            verifier.verify(&key.public(), &signature).unwrap();
            let mut wrong = key.public();
            wrong[10] ^= 1;
            assert!(verifier.verify(&wrong, &signature).is_err());
            assert_eq!(keystore.diagnostics().count(), 0);
            // A fresh owner with the same machine roots signs the same
            // reference. The signature never authorizes another root.
            let params = reference_key::tests::attestation_parameters(blob);
            let mut reopened = KeyStore::with_system_keys(Zeroizing::new([1; 32]));
            let request = system_request_with_operation(version, 0, &params);
            let (reply, repeated) = ask(
                &mut reopened,
                frame(system_key::PERFORM_OPERATION, 28, request.len()),
                request,
            );
            assert_eq!(reply.unwrap().parameter, 0);
            assert_eq!(output, repeated);
            let mut other = KeyStore::with_system_keys(Zeroizing::new([2; 32]));
            let request = system_request_with_operation(version, 0, &params);
            let (reply, output) = ask(
                &mut other,
                frame(system_key::PERFORM_OPERATION, 29, request.len()),
                request,
            );
            assert_eq!(
                reply.unwrap_err().reason,
                refuse!("SEP reference-key authentication failed")
            );
            assert!(output.is_empty());
        }
    }
}

#[test]
fn reference_signing_roundtrips_original_dictionary_in_both_ipc_versions() {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use sha2::Digest;
    for version in [1, 2] {
        let root = Zeroizing::new([1; 32]);
        let blob = reference_key::ReferenceKey::create(&root, 5, &mut |bytes: &mut [u8]| {
            bytes.fill(2);
            Ok(())
        })
        .unwrap();
        let digest: [u8; 32] = sha2::Sha256::digest(b"CSR data to be hashed by libFDR").into();
        let params = reference_key::tests::signing_parameters(&blob, &digest);
        let request = system_request_with_operation(version, 0, &params);
        let sent = frame(system_key::PERFORM_OPERATION, 30, request.len());
        let mut keystore = KeyStore::with_system_keys(root.clone());
        let (reply, output) = ask(&mut keystore, sent, request);
        assert_eq!(reply.unwrap().parameter, 0);
        let message = Message::parse(&output).unwrap();
        let mut fields = message.fields();
        let result = fields.blob().unwrap();
        fields.end().unwrap();
        let mut outer = stela_formats::der::Cursor(result);
        let signature = p256::ecdsa::Signature::from_der(outer.take(4).unwrap().value).unwrap();
        outer.end().unwrap();
        let key = reference_key::ReferenceKey::open(&root, &blob).unwrap();
        let verifying = p256::ecdsa::VerifyingKey::from_sec1_bytes(&key.public()).unwrap();
        verifying.verify_prehash(&digest, &signature).unwrap();
        assert_eq!(keystore.diagnostics().count(), 0);
        let mut wrong_root = KeyStore::with_system_keys(Zeroizing::new([2; 32]));
        let params = reference_key::tests::signing_parameters(&blob, &digest);
        let request = system_request_with_operation(version, 0, &params);
        let (reply, output) = ask(
            &mut wrong_root,
            frame(system_key::PERFORM_OPERATION, 31, request.len()),
            request,
        );
        assert_eq!(
            reply.unwrap_err().reason,
            refuse!("SEP reference-key authentication failed")
        );
        assert!(output.is_empty());
        for bad_digest in [&digest[..31], &digest[..0]] {
            let params = reference_key::tests::signing_parameters(&blob, bad_digest);
            let request = system_request_with_operation(version, 0, &params);
            let (reply, output) = ask(
                &mut keystore,
                frame(system_key::PERFORM_OPERATION, 32, request.len()),
                request,
            );
            assert_eq!(
                reply.unwrap_err().reason,
                refuse!("SEP reference-key digest must be SHA-256 sized")
            );
            assert!(output.is_empty());
        }
    }
}

#[test]
fn reference_creation_requires_entropy_without_mutating_identity() {
    let mut keystore = KeyStore::with_system_keys(Zeroizing::new([1; 32]));
    let request = system_request(2, SIK_QUERY);
    let (_, identity_before) = ask(
        &mut keystore,
        frame(system_key::PERFORM_OPERATION, 19, request.len()),
        request.clone(),
    );
    for version in [1, 2] {
        let create = system_request_with_operation(version, 0, REFERENCE_CREATE);
        let sent = frame(system_key::PERFORM_OPERATION, 23, create.len());
        let (reply, output) = ask(&mut keystore, sent, create);
        let refusal = reply.unwrap_err();
        assert_eq!(refusal.reason, refuse!("test entropy unavailable"));
        assert_eq!(refusal.answer.unwrap().frame, failure(sent));
        assert!(output.is_empty());
        assert!(keystore.environment().is_none());
        let diagnostics = keystore.diagnostics().collect::<Vec<_>>();
        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].contains("parameter_operation=oc"));
        assert!(diagnostics[0].contains("reference_key_type=Some(5)"));
        assert!(diagnostics[0].contains("keys=bc,kt,o,rko parsed=true"));
        assert!(
            diagnostics[0].contains("reference_key_class=Some(13) reference_key_options=Some(1)")
        );
    }
    let (_, identity_after) = ask(
        &mut keystore,
        frame(system_key::PERFORM_OPERATION, 19, request.len()),
        request,
    );
    assert_eq!(identity_after, identity_before);
    // Generation cannot proceed without provisioned machine roots.
    let create = system_request_with_operation(2, 0, REFERENCE_CREATE);
    let (reply, output) = ask(
        &mut KeyStore::default(),
        frame(system_key::PERFORM_OPERATION, 24, create.len()),
        create,
    );
    assert_eq!(
        reply.unwrap_err().reason,
        refuse!("SEP keystore requires provisioned machine roots")
    );
    assert!(output.is_empty());
}

#[test]
fn creation_rejects_bad_dictionary_and_public_query_transport_before_semantics() {
    let mut bad = vec![REFERENCE_CREATE[..REFERENCE_CREATE.len() - 1].to_vec()];
    let mut duplicate = REFERENCE_CREATE.to_vec();
    duplicate[15..17].copy_from_slice(b"bc");
    bad.push(duplicate);
    let mut unsorted = REFERENCE_CREATE.to_vec();
    unsorted[2..11].copy_from_slice(&REFERENCE_CREATE[11..20]);
    unsorted[11..20].copy_from_slice(&REFERENCE_CREATE[2..11]);
    bad.push(unsorted);
    let mut missing = REFERENCE_CREATE[..29].to_vec();
    missing[1] = 27;
    bad.push(missing);
    for index in [10, 19, 38] {
        // negative class/type/options are not u32
        let mut negative = REFERENCE_CREATE.to_vec();
        negative[index] = 0x80;
        bad.push(negative);
    }
    for (index, value) in [(10, 12), (19, 7), (38, 2)] {
        let mut unsupported = REFERENCE_CREATE.to_vec();
        unsupported[index] = value;
        bad.push(unsupported);
    }
    let mut mixed = REFERENCE_CREATE.to_vec();
    mixed[1] += 10;
    mixed.extend_from_slice(&SIK_QUERY[24..]); // public-only skt
    bad.push(mixed);
    let mut requests: Vec<_> = bad
        .iter()
        .map(|q| system_request_with_operation(2, 0, q))
        .collect();
    // The read-only kernel SIK transport cannot authorize creation.
    requests.push(system_request(2, REFERENCE_CREATE));
    let mut forged = system_request_with_operation(2, 0, REFERENCE_CREATE);
    forged[DIGEST_START] ^= 1;
    requests.push(forged);
    for request in requests {
        let mut keystore = KeyStore::with_system_keys(Zeroizing::new([1; 32]));
        let sent = frame(system_key::PERFORM_OPERATION, 25, request.len());
        let (reply, output) = ask(&mut keystore, sent, request);
        let refusal = reply.unwrap_err();
        assert_ne!(refusal.reason.what(), "test entropy unavailable");
        assert_eq!(refusal.answer.unwrap().frame, failure(sent));
        assert!(output.is_empty());
        assert!(keystore.environment().is_none());
    }
}

#[test]
fn userspace_and_kernel_public_queries_return_the_same_identity() {
    let mut keystore = KeyStore::with_system_keys(Zeroizing::new([1; 32]));
    let mut expected = None;
    for version in [1, 2] {
        for operation in [0, 2] {
            let request = system_request_with_operation(version, operation, SIK_QUERY);
            let (reply, output) = ask(
                &mut keystore,
                frame(system_key::PERFORM_OPERATION, 19, request.len()),
                request,
            );
            assert_eq!(reply.unwrap().parameter, 0);
            let message = Message::parse(&output).unwrap();
            let mut fields = message.fields();
            let public = fields.blob().unwrap();
            p256::PublicKey::from_sec1_bytes(public).unwrap();
            if let Some(expected) = &expected {
                assert_eq!(public, expected);
            } else {
                expected = Some(public.to_vec());
            }
            fields.end().unwrap();
            assert_eq!(keystore.diagnostics().count(), 0);
        }
    }
}

#[test]
fn unsupported_system_metadata_is_sanitized_and_keeps_failure_semantics() {
    let mut keystore = KeyStore::with_system_keys(Zeroizing::new([1; 32]));
    let mut query = SIK_QUERY.to_vec();
    query[23] = 4;
    query[33] = 3;
    let request = system_request_with_operation(2, 7, &query);
    let (reply, output) = ask(
        &mut keystore,
        frame(system_key::PERFORM_OPERATION, 20, request.len()),
        request,
    );
    assert_eq!(reply.unwrap_err().answer.unwrap().frame.parameter, FAILURE);
    assert!(output.is_empty());
    assert_eq!(
        keystore.diagnostics().collect::<Vec<_>>(),
        [
            "sks refused command=0x22 variant=0 handle=Some(4294967295) operation=Some(7) parameter_operation=oskgp system_key_type=Some(3) reference_key_type=None generation=Some(4) keys=o,skg,skt parsed=true reference_key_class=None reference_key_options=None"
        ]
    );
    // The encoder's pair order is reported, not refused, so a request
    // the strict parser rejects as unsorted still shows which it was.
    let request = system_request_with_operation(2, 0, DER_ORDER_QUERY);
    let (reply, _) = ask(
        &mut keystore,
        frame(system_key::PERFORM_OPERATION, 20, request.len()),
        request,
    );
    assert!(reply.is_err());
    let diagnostics = keystore.diagnostics().collect::<Vec<_>>();
    assert_eq!(diagnostics.len(), 1);
    assert!(diagnostics[0].contains("keys=skg,skt,o parsed=true"));
    // Guest-controlled unknown strings and opaque parameter data must
    // never be copied into diagnostics, even when DER parsing succeeds.
    let query = b"\x31\x11\x30\x0f\x0c\x01o\x0c\x0aDO-NOT-LOG";
    let request = system_request_with_operation(2, 0, query);
    let (_, output) = ask(
        &mut keystore,
        frame(system_key::PERFORM_OPERATION, 21, request.len()),
        request,
    );
    assert!(output.is_empty());
    let diagnostics = keystore.diagnostics().collect::<Vec<_>>();
    assert_eq!(diagnostics.len(), 1);
    assert!(diagnostics[0].contains("parameter_operation=unknown"));
    assert!(diagnostics[0].contains("keys=o parsed=true"));
    assert!(!diagnostics[0].contains("DO-NOT-LOG"));
    assert!(!diagnostics[0].contains("1311768467463790320")); // session
    assert_eq!(keystore.diagnostics().count(), 0);
}

#[test]
fn unauthenticated_and_malformed_requests_do_not_expose_parameter_bytes() {
    let mut keystore = KeyStore::with_system_keys(Zeroizing::new([1; 32]));
    let mut request = system_request_with_operation(2, 7, SIK_QUERY);
    request[DIGEST_START] ^= 1;
    let (reply, output) = ask(
        &mut keystore,
        frame(system_key::PERFORM_OPERATION, 20, request.len()),
        request,
    );
    assert!(reply.is_err());
    assert!(output.is_empty());
    assert_eq!(keystore.diagnostics().count(), 0);
    let request = system_request_with_operation(2, 7, b"DO-NOT-LOG");
    let (reply, output) = ask(
        &mut keystore,
        frame(system_key::PERFORM_OPERATION, 21, request.len()),
        request,
    );
    assert!(reply.is_err());
    assert!(output.is_empty());
    let diagnostics = keystore.diagnostics().collect::<Vec<_>>();
    assert_eq!(diagnostics.len(), 1);
    assert!(diagnostics[0].contains("operation=Some(7)"));
    assert!(diagnostics[0].contains("parsed=false"));
    assert!(!diagnostics[0].contains("DO-NOT-LOG"));
}

#[test]
fn system_identity_query_returns_one_raw_public_point_in_both_ipc_versions() {
    let mut expected = None;
    for version in [1, 2] {
        let mut keystore = KeyStore::with_system_keys(Zeroizing::new([1; 32]));
        let request = system_request(version, SIK_QUERY);
        let before = request.clone();
        let (reply, output) = ask(
            &mut keystore,
            frame(system_key::PERFORM_OPERATION, 19, request.len()),
            request,
        );
        let reply = reply.unwrap();
        assert_eq!(reply.tag, system_key::PERFORM_OPERATION | REPLY);
        assert_eq!(reply.opcode, 19);
        assert_eq!(reply.parameter, 0);
        assert_eq!(reply.data as usize >> LENGTH_SHIFT, output.len());
        let parsed = Message::parse(&output).unwrap();
        assert_eq!(parsed.variant(), 0);
        assert_eq!(output[VERSION..parsed.body], before[VERSION..parsed.body]);
        let mut fields = parsed.fields();
        let public = fields.blob().unwrap();
        p256::PublicKey::from_sec1_bytes(public).unwrap();
        assert_eq!(public.len(), 65);
        if let Some(expected) = &expected {
            assert_eq!(public, expected);
        } else {
            expected = Some(public.to_vec());
        }
        fields.end().unwrap();
        assert!(keystore.environment().is_none());
    }
}

#[test]
fn unsupported_or_malformed_system_queries_never_publish_success() {
    let mut dictionaries = vec![vec![], SIK_QUERY[..SIK_QUERY.len() - 1].to_vec()];
    for index in [23, 33, 13] {
        // generation, type and operation
        let mut bad = SIK_QUERY.to_vec();
        bad[index] ^= 1;
        dictionaries.push(bad);
    }
    let mut duplicate = SIK_QUERY.to_vec();
    duplicate[28..31].copy_from_slice(b"skg");
    dictionaries.push(duplicate);
    let mut unsorted = SIK_QUERY.to_vec();
    unsorted[14..24].copy_from_slice(&SIK_QUERY[24..34]);
    unsorted[24..34].copy_from_slice(&SIK_QUERY[14..24]);
    dictionaries.push(unsorted);
    dictionaries.push(DER_ORDER_QUERY.to_vec());
    let mut trailing = SIK_QUERY.to_vec();
    trailing.push(0);
    dictionaries.push(trailing);
    let mut nonminimal = SIK_QUERY.to_vec();
    nonminimal.insert(2, 0x20);
    nonminimal[1] = 0x81;
    dictionaries.push(nonminimal);
    let mut requests: Vec<_> = dictionaries.iter().map(|q| system_request(2, q)).collect();
    // Even a valid digest cannot authorize different framing operands.
    for index in [84, 96, 100] {
        // variant, handle and operation
        let mut bad = system_request(2, SIK_QUERY);
        bad[index] ^= 1;
        let hash = digest(&bad);
        bad[DIGEST_START..DIGEST_START + DIGEST_BYTES].copy_from_slice(&hash);
        requests.push(bad);
    }
    for request in requests {
        let mut keystore = KeyStore::with_system_keys(Zeroizing::new([1; 32]));
        let (result, output) = ask(
            &mut keystore,
            frame(system_key::PERFORM_OPERATION, 20, request.len()),
            request,
        );
        assert_eq!(result.unwrap_err().answer.unwrap().frame.parameter, FAILURE);
        assert!(output.is_empty());
        assert!(keystore.environment().is_none());
    }
    let request = system_request(2, SIK_QUERY);
    let (result, output) = ask(
        &mut KeyStore::default(),
        frame(system_key::PERFORM_OPERATION, 21, request.len()),
        request,
    );
    assert_eq!(
        result.unwrap_err().reason,
        refuse!("SEP keystore requires provisioned machine roots")
    );
    assert!(output.is_empty());
}

fn ask(keystore: &mut KeyStore, frame: Frame, input: Vec<u8>) -> (Result<Frame, Refusal>, Vec<u8>) {
    ask_with_entropy(keystore, frame, input, &mut |_: &mut [u8]| {
        Err(refuse!("test entropy unavailable"))
    })
}

fn ask_with_entropy(
    keystore: &mut KeyStore,
    frame: Frame,
    input: Vec<u8>,
    entropy: &mut dyn super::super::Entropy,
) -> (Result<Frame, Refusal>, Vec<u8>) {
    let mut buffers = Buffers {
        input,
        output: Vec::new(),
    };
    (
        keystore.request(frame, &mut buffers, entropy),
        buffers.output,
    )
}

#[test]
fn capabilities_report_header_version_two_in_the_requests_header() {
    for (version, length) in [(1, 92), (2, 100)] {
        let request = message(version, 0, 1, &[]);
        let (reply, output) = ask(
            &mut KeyStore::default(),
            frame(GET_CAPABILITIES, 9, request.len()),
            request.clone(),
        );
        assert_eq!(
            reply.unwrap(),
            Frame {
                tag: GET_CAPABILITIES | REPLY,
                data: (length as u32) << LENGTH_SHIFT,
                ..frame(GET_CAPABILITIES, 9, 0)
            }
        );
        assert_eq!(output.len(), length);
        // The kernel's decoder accepts it: same header, valid digest,
        // variant 0, the version as u64 and an empty blob.
        let parsed = Message::parse(&output).unwrap();
        assert_eq!(output[..DIGEST_START], request[..DIGEST_START]);
        assert_eq!(output[VERSION..parsed.body], request[VERSION..parsed.body]);
        let mut fields = parsed.fields();
        assert_eq!(fields.lword(), Ok(2));
        assert_eq!(fields.blob(), Ok(&[][..]));
        assert_eq!(fields.end(), Ok(()));
    }
}

#[test]
fn the_environment_is_recorded_and_answered_with_the_result_alone() {
    let mut keystore = KeyStore::default();
    let request = message(2, 0, 1, &environment(3, 4));
    assert_eq!(request.len(), 84 + 4 + 8 + 4 + ENVIRONMENT_BYTES);
    let (reply, output) = ask(
        &mut keystore,
        frame(SET_ENVIRONMENT, 1, request.len()),
        request,
    );
    assert_eq!(reply.unwrap().data >> LENGTH_SHIFT, 88);
    assert_eq!(output.len(), 88);
    assert!(Message::parse(&output).is_ok());
    assert_eq!(
        keystore.environment(),
        Some(Environment {
            cpx_encryption_mode: 3,
            mode: 4,
        })
    );
    // Mode 6 replaces it.
    let request = message(2, 0, 1, &environment(0, 6));
    ask(
        &mut keystore,
        frame(SET_ENVIRONMENT, 2, request.len()),
        request,
    )
    .0
    .unwrap();
    assert_eq!(keystore.environment().unwrap().mode, 6);
}

#[test]
fn a_null_d_key_request_is_acknowledged_with_the_variant_alone() {
    // Variant 0 and u64 1, without a blob.
    let mut request = message(2, 0, 1, &[]);
    request.truncate(request.len() - 4);
    let digest = digest(&request);
    request[DIGEST_START..DIGEST_START + DIGEST_BYTES].copy_from_slice(&digest);
    let (reply, output) = ask(
        &mut KeyStore::default(),
        frame(NULL_D_KEY, 3, request.len()),
        request.clone(),
    );
    assert_eq!(reply.unwrap().data >> LENGTH_SHIFT, 88);
    let parsed = Message::parse(&output).unwrap();
    assert_eq!(parsed.variant(), 0);
    assert_eq!(parsed.fields().end(), Ok(()));
    // Another argument, or a trailing blob, refuses.
    let (reply, _) = ask(
        &mut KeyStore::default(),
        frame(NULL_D_KEY, 3, request.len() + 4),
        message(2, 0, 1, &[]),
    );
    assert!(reply.is_err());
}

/// A request of `variant` with `fields` after its variant word.
fn request_with(variant: u32, fields: &[u8]) -> Vec<u8> {
    let mut request = message(2, 0, 1, &[]);
    let body = Message::parse(&request).unwrap().body;
    request.truncate(body);
    request.extend_from_slice(&variant.to_le_bytes());
    request.extend_from_slice(fields);
    let hash = digest(&request);
    request[DIGEST_START..DIGEST_START + DIGEST_BYTES].copy_from_slice(&hash);
    request
}

#[test]
fn device_state_says_unlocked_without_a_passcode_in_both_variants() {
    let head = |rest: &[u8]| {
        let mut fields = 1u64.to_le_bytes().to_vec();
        fields.extend_from_slice(&u32::MAX.to_le_bytes());
        fields.extend_from_slice(rest);
        fields
    };
    let mut keystore = KeyStore::default();
    for (variant, fields) in [
        (0, head(&[0; 4])),
        (1, head(&[0; 8])), // An empty blob and the u32.
    ] {
        let request = request_with(variant, &fields);
        let (reply, output) = ask(
            &mut keystore,
            frame(GET_DEVICE_STATE, 3, request.len()),
            request,
        );
        reply.unwrap();
        let parsed = Message::parse(&output).unwrap();
        assert_eq!(parsed.variant(), variant);
        let mut fields = parsed.fields();
        let state = fields.blob().unwrap();
        fields.end().unwrap();
        // The state, after every key below `ss`: SET, SEQUENCE, "ss", 10.
        assert_eq!(state[0], 0x31);
        assert_eq!(state[state.len() - 9..], *b"\x30\x07\x0c\x02ss\x02\x01\x0a");
    }
    assert_eq!(
        keystore.diagnostics().collect::<Vec<_>>(),
        ["SEP keystore: every keybag reports unlocked without a passcode"]
    );
    let unknown = request_with(2, &head(&[0; 4]));
    let (reply, _) = ask(
        &mut keystore,
        frame(GET_DEVICE_STATE, 4, unknown.len()),
        unknown,
    );
    assert!(reply.is_err());
}

#[test]
fn a_client_terminating_is_acknowledged_with_the_variant_alone() {
    let mut fields = [7u64, 8, 9].map(u64::to_le_bytes).concat();
    fields.extend_from_slice(&5u32.to_le_bytes());
    let request = request_with(1, &fields);
    let (reply, output) = ask(
        &mut KeyStore::default(),
        frame(CLIENT_TERMINATE, 3, request.len()),
        request,
    );
    reply.unwrap();
    let parsed = Message::parse(&output).unwrap();
    assert_eq!(parsed.variant(), 1);
    assert_eq!(parsed.fields().end(), Ok(()));
    let request = request_with(0, &fields);
    let (reply, _) = ask(
        &mut KeyStore::default(),
        frame(CLIENT_TERMINATE, 3, request.len()),
        request,
    );
    assert!(reply.is_err());
}

#[test]
fn an_unimplemented_command_is_named_once() {
    let mut keystore = KeyStore::default();
    let request = message(2, 0, 1, &[]);
    for sequence in [1, 2] {
        let (reply, _) = ask(
            &mut keystore,
            frame(0x7f, sequence, request.len()),
            request.clone(),
        );
        assert!(reply.is_err());
    }
    assert_eq!(
        keystore.diagnostics().collect::<Vec<_>>(),
        ["SEP keystore: command 0x7f is not implemented"]
    );
}

#[test]
fn decoded_keybags_and_malformed_bodies_never_publish_success_or_change_environment() {
    let mut keystore = KeyStore::default();
    let env = message(2, 0, 1, &environment(3, 4));
    ask(&mut keystore, frame(SET_ENVIRONMENT, 1, env.len()), env)
        .0
        .unwrap();
    let before = keystore.environment();
    for command in [
        keybag::CREATE,
        keybag::COPY,
        keybag::LOAD,
        keybag::UNLOAD,
        keybag::UUID,
    ] {
        let (variant, body) = keybag::tests::body(command);
        for version in [1, 2] {
            let mut request = message(version, 0, 1, &[]);
            let start = Message::parse(&request).unwrap().body;
            request.truncate(start);
            request.extend_from_slice(&variant.to_le_bytes());
            request.extend_from_slice(&body);
            let hash = digest(&request);
            request[DIGEST_START..DIGEST_START + DIGEST_BYTES].copy_from_slice(&hash);
            // A complete source-shaped request reaches the semantic
            // refusal, including create/copy's nonzero variants.
            let (result, output) = ask(
                &mut keystore,
                frame(command, 42, request.len()),
                request.clone(),
            );
            let refusal = result.unwrap_err();
            assert_eq!(refusal.reason, keybag::UNIMPLEMENTED.into());
            assert_eq!(
                refusal.answer.unwrap().frame,
                failure(frame(command, 42, request.len()))
            );
            assert!(output.is_empty());
            assert_eq!(keystore.environment(), before);
            // A valid message digest does not authorize a truncated
            // body, a trailer or a different variant.
            for change in 0..3 {
                let mut bad = request.clone();
                match change {
                    0 => {
                        bad.pop();
                    }
                    1 => bad.extend_from_slice(&[0; 4]),
                    _ => bad[start..start + 4].copy_from_slice(&(variant + 1).to_le_bytes()),
                }
                let hash = digest(&bad);
                bad[DIGEST_START..DIGEST_START + DIGEST_BYTES].copy_from_slice(&hash);
                let (result, output) = ask(&mut keystore, frame(command, 42, bad.len()), bad);
                assert_ne!(result.unwrap_err().reason.what(), keybag::UNIMPLEMENTED);
                assert!(output.is_empty());
                assert_eq!(keystore.environment(), before);
            }
        }
    }
    let mut request = message(2, 0, 1, &[]);
    request[84..88].copy_from_slice(&1u32.to_le_bytes());
    let hash = digest(&request);
    request[DIGEST_START..DIGEST_START + DIGEST_BYTES].copy_from_slice(&hash);
    let (result, output) = ask(
        &mut keystore,
        frame(GET_CAPABILITIES, 1, request.len()),
        request,
    );
    assert_eq!(
        result.unwrap_err().reason,
        refuse!("SEP keystore startup command variant is not zero")
    );
    assert!(output.is_empty());
    assert_eq!(keystore.environment(), before);
}

#[test]
fn other_commands_and_malformed_messages_refuse_with_the_failure_status() {
    let good = message(1, 0, 1, &[]);
    let mut tampered = good.clone();
    tampered[30] ^= 1;
    let mut bad_environment = environment(0, 5);
    let mut cases = vec![
        // Keybag creation and the rest are not implemented.
        (frame(0x01, 1, good.len()), good.clone()),
        (frame(GET_CAPABILITIES, 1, good.len()), tampered),
        (
            frame(GET_CAPABILITIES, 1, good.len() - 4),
            good[..good.len() - 4].to_vec(),
        ),
        (
            frame(GET_CAPABILITIES, 1, good.len()),
            message(1, 1, 1, &[]),
        ),
        (
            frame(GET_CAPABILITIES, 1, good.len()),
            message(1, 0, 2, &[]),
        ),
        (frame(GET_CAPABILITIES, 1, good.len() + 4), {
            let mut long = good.clone();
            long.extend_from_slice(&[0; 4]);
            long
        }),
    ];
    let request = message(1, 0, 1, &bad_environment);
    cases.push((frame(SET_ENVIRONMENT, 1, request.len()), request));
    bad_environment = environment(0, 4);
    bad_environment[100] = 1;
    let request = message(1, 0, 1, &bad_environment);
    cases.push((frame(SET_ENVIRONMENT, 1, request.len()), request));
    let mut flagged = frame(GET_CAPABILITIES, 1, good.len());
    flagged.data |= 1;
    cases.push((flagged, good.clone()));
    for (request, input) in cases {
        let mut keystore = KeyStore::default();
        let (reply, output) = ask(&mut keystore, request, input);
        let refusal = reply.unwrap_err();
        let answer = refusal.answer.unwrap().frame;
        assert_eq!(
            (answer.tag, answer.opcode, answer.parameter, answer.data),
            (request.tag | REPLY, 1, FAILURE, 0),
            "{}",
            refusal.reason
        );
        assert!(output.is_empty());
        assert!(keystore.environment().is_none());
    }
    // A frame already carrying the reply bit is not a request to answer.
    let (reply, _) = ask(
        &mut KeyStore::default(),
        frame(GET_CAPABILITIES | REPLY, 1, good.len()),
        good,
    );
    assert_eq!(reply.unwrap_err().answer, None);
}
