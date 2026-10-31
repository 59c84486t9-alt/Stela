use super::super::{BootPolicy, ID, NOT_SUPPORTED, TAG};
use super::*;
use crate::sep::{keys::Roots, store::Volatile};
use core::sync::atomic::{AtomicU8, Ordering};

struct Buffers {
    input: Vec<u8>,
    output: Vec<u8>,
}

impl Payload for Buffers {
    fn input(&mut self, bytes: &mut [u8]) -> Result<()> {
        if self.input.len() < bytes.len() {
            return Err(refuse!("short input"));
        }
        let rest = self.input.split_off(bytes.len());
        bytes.copy_from_slice(&self.input);
        self.input = rest;
        Ok(())
    }
    fn output(&mut self, bytes: &[u8]) -> Result<()> {
        self.output = bytes.to_vec();
        Ok(())
    }
}

fn store() -> Nonces<Volatile> {
    let roots = Roots::provisioned([7; 32], [8; 32], 0xbeef_0001).unwrap();
    Nonces::provision(&roots, Volatile::default()).unwrap()
}

/// A different nonce for every update.
fn entropy(bytes: &mut [u8]) -> Result<()> {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    bytes.fill(NEXT.fetch_add(1, Ordering::Relaxed));
    Ok(())
}

fn ask(
    policy: &mut BootPolicy,
    store: &mut Nonces<Volatile>,
    input: Vec<u8>,
) -> (core::result::Result<Frame, Refusal>, Vec<u8>) {
    let frame = Frame {
        service: ID,
        tag: TAG,
        opcode: 0,
        parameter: 0,
        data: input.len() as u32,
    };
    let mut buffers = Buffers {
        input,
        output: Vec::new(),
    };
    let reply = policy.request(frame, &mut buffers, store, &mut entropy);
    (reply, buffers.output)
}

fn header(command: u32) -> Vec<u8> {
    let mut bytes = vec![0; HEADER_BYTES];
    bytes[..4].copy_from_slice(b"hcPB");
    bytes[4..8].copy_from_slice(&command.to_le_bytes());
    bytes
}

fn context(tag: u8, value: &[u8]) -> Vec<u8> {
    der::encode(CONTEXT | tag, value)
}

/// A request as libbootpolicy lays it out, with `fields` in order.
fn encoded(command: u32, fields: &[Vec<u8>]) -> Vec<u8> {
    let encoded = fields.concat();
    let mut bytes = header(command);
    bytes.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
    bytes.extend(encoded);
    bytes
}

const GROUP: [u8; UUID_BYTES] = [9; UUID_BYTES];

fn paired_request(boot_policy: u8) -> Vec<u8> {
    encoded(
        CREATE_PAIRED,
        &[
            context(FORMAT as u8, &[1]),
            context(OS_MANIFEST as u8, b"manifest"),
            context(VOLUME_GROUP as u8, &GROUP),
            context(BOOT_POLICY as u8, &[boot_policy]),
            context(AUTHORIZATION as u8, &[]),
        ],
    )
}

fn macos_request(paired: &[u8], splat: bool, boot_policy: u8) -> Vec<u8> {
    let mut fields = vec![
        context(FORMAT as u8, &[1]),
        context(OS_MANIFEST as u8, b"manifest"),
    ];
    if splat {
        fields.push(context(SPLAT_MANIFEST as u8, b"splat"));
    }
    fields.extend([
        context(PAIRED_POLICY as u8, paired),
        context(VOLUME_GROUP as u8, &GROUP),
        context(BOOT_POLICY as u8, &[boot_policy]),
        context(AUTHORIZATION as u8, &[]),
    ]);
    encoded(if splat { CREATE_WITH_SPLAT } else { CREATE }, &fields)
}

/// The policy file and nonce digest of a successful reply.
fn created(reply: &[u8]) -> (Vec<u8>, [u8; DIGEST_BYTES]) {
    assert_eq!(reply[..4], *b"hrPB");
    assert_eq!(reply[4..8], SUCCESS.to_le_bytes());
    let length = u32::from_le_bytes(reply[32..36].try_into().unwrap()) as usize;
    assert_eq!(reply.len(), 36 + length);
    let mut cursor = Cursor(&reply[36..]);
    let file = cursor.next_element().unwrap();
    assert_eq!((file.class, file.tag), (2, 7));
    let nonce = cursor.next_element().unwrap();
    assert_eq!((nonce.class, nonce.tag), (2, 6));
    cursor.end().unwrap();
    (file.value.to_vec(), nonce.value.try_into().unwrap())
}

fn mutation(command: u32) -> Vec<u8> {
    let mut bytes = header(command);
    bytes.resize(0x124, 0);
    bytes
}

/// Run restored's order up to the paired policy.
fn begun(policy: &mut BootPolicy, store: &mut Nonces<Volatile>) -> (Vec<u8>, [u8; DIGEST_BYTES]) {
    assert!(ask(policy, store, mutation(2)).0.is_ok());
    let (reply, output) = ask(policy, store, paired_request(1));
    assert_eq!(reply.unwrap().data as usize, output.len());
    created(&output)
}

#[test]
fn restoreds_order_signs_both_policies_under_the_proposed_nonce() {
    let mut store = store();
    let mut boot_policy = BootPolicy::default();
    let key = PolicyKey::derive(&store.policy_key_seed().unwrap()).unwrap();
    let (paired, nonce) = begun(&mut boot_policy, &mut store);
    let shown = local_policy::verify(&paired, key.public()).unwrap();
    assert_eq!(shown.volume_group, GROUP);
    assert_eq!(shown.nonce, nonce);
    assert_eq!(shown.security, Security::Full);
    assert_eq!(shown.paired, None);
    assert_eq!(
        shown.next_stage,
        <[u8; DIGEST_BYTES]>::from(Sha384::digest(b"manifest"))
    );
    // The local nonce's proposed digest is the one the policy binds.
    let (_, digest) = ask(&mut boot_policy, &mut store, header(11));
    assert_eq!(digest[HEADER_BYTES..], nonce);

    let (reply, output) = ask(
        &mut boot_policy,
        &mut store,
        macos_request(&paired, true, 3),
    );
    assert!(reply.is_ok());
    let (file, macos_nonce) = created(&output);
    assert_eq!(macos_nonce, nonce);
    let macos = local_policy::verify(&file, key.public()).unwrap();
    assert_eq!(macos.security, Security::Permissive);
    assert_eq!(
        macos.splat,
        Some(<[u8; DIGEST_BYTES]>::from(Sha384::digest(b"splat")))
    );
    assert_eq!(
        macos.paired,
        Some(<[u8; DIGEST_BYTES]>::from(Sha384::digest(&paired)))
    );

    // Ending the update makes the proposed digest the blessed one.
    assert!(ask(&mut boot_policy, &mut store, mutation(3)).0.is_ok());
    let (_, blessed) = ask(&mut boot_policy, &mut store, header(14));
    assert_eq!(blessed[HEADER_BYTES..], nonce);
}

#[test]
fn a_macos_policy_without_a_splat_binds_none() {
    let mut store = store();
    let mut boot_policy = BootPolicy::default();
    let key = PolicyKey::derive(&store.policy_key_seed().unwrap()).unwrap();
    let (paired, _) = begun(&mut boot_policy, &mut store);
    let (reply, output) = ask(
        &mut boot_policy,
        &mut store,
        macos_request(&paired, false, 1),
    );
    assert!(reply.is_ok());
    let macos = local_policy::verify(&created(&output).0, key.public()).unwrap();
    assert_eq!(macos.splat, None);
    assert_eq!(macos.security, Security::Full);
}

/// A tag read as libbootpolicy lays it out.
fn read_request(command: u32, file: &[u8], tag: [u8; 4]) -> Vec<u8> {
    let mut bytes = header(command);
    bytes.resize(HEADER_BYTES + READ_BYTES, 0);
    let body = &mut bytes[HEADER_BYTES..];
    body[..4].copy_from_slice(&(file.len() as u32).to_le_bytes());
    body[FILE_AT..FILE_AT + file.len()].copy_from_slice(file);
    body[TAG_AT..TAG_AT + 4].copy_from_slice(&u32::from_be_bytes(tag).to_le_bytes());
    bytes
}

#[test]
fn a_macos_policy_carries_the_machines_kext_grant_and_reads_it_back() {
    let kexts = Kexts {
        approved: [1; DIGEST_BYTES],
        collection: [2; DIGEST_BYTES],
        receipt: [3; DIGEST_BYTES],
    };
    let mut store = store();
    let mut boot_policy = BootPolicy::new(Some(kexts));
    let (paired, _) = begun(&mut boot_policy, &mut store);
    let request = macos_request(&paired, false, 2);
    let (reply, output) = ask(&mut boot_policy, &mut store, request);
    reply.unwrap();
    let (file, _) = created(&output);

    let mut read = |command, file: &[u8], tag: [u8; 4]| {
        let request = read_request(command, file, tag);
        let (reply, output) = ask(&mut boot_policy, &mut store, request);
        assert_eq!(reply.unwrap().data as usize, output.len());
        assert_eq!(output[..4], *b"hrPB");
        let result = u32::from_le_bytes(output[4..8].try_into().unwrap());
        (result, output[HEADER_BYTES..].to_vec())
    };
    assert_eq!(
        read(READ_BOOLEAN, &file, *b"smb2"),
        (SUCCESS, vec![1, 0, 0, 0])
    );
    assert_eq!(
        read(READ_INTEGER, &file, *b"sip0"),
        (SUCCESS, 0x201u64.to_le_bytes().to_vec())
    );
    assert_eq!(
        read(READ_DIGEST, &file, *b"auxp"),
        (SUCCESS, vec![1; DIGEST_BYTES])
    );
    assert_eq!(read(READ_BOOLEAN, &file, *b"love"), (TAG_ABSENT, vec![]));
    // The paired recoveryOS policy grants nothing.
    assert_eq!(read(READ_BOOLEAN, &paired, *b"smb2"), (TAG_ABSENT, vec![]));
    assert_eq!(read(READ_INTEGER, &paired, *b"sip0"), (TAG_ABSENT, vec![]));
}

#[test]
fn a_tag_read_refuses_a_policy_of_another_machine() {
    let mut store = store();
    let mut boot_policy = BootPolicy::default();
    let key = PolicyKey::derive(&[1; 32]).unwrap();
    let foreign = key.sign(&Policy {
        volume_group: GROUP,
        next_stage: [1; DIGEST_BYTES],
        nonce: [2; DIGEST_BYTES],
        splat: None,
        paired: None,
        security: Security::Full,
        kexts: None,
    });
    let request = read_request(READ_DIGEST, &foreign, *b"nsih");
    refused(&mut boot_policy, &mut store, request);
    let mut oversized = header(READ_BOOLEAN);
    oversized.resize(HEADER_BYTES + READ_BYTES, 0);
    oversized[HEADER_BYTES..HEADER_BYTES + 4].copy_from_slice(&0x4001u32.to_le_bytes());
    refused(&mut boot_policy, &mut store, oversized);
}

fn refused(boot_policy: &mut BootPolicy, store: &mut Nonces<Volatile>, input: Vec<u8>) {
    let (reply, output) = ask(boot_policy, store, input);
    let answer = reply.unwrap_err().answer.unwrap();
    assert_eq!(answer.output[4..8], NOT_SUPPORTED.to_le_bytes());
    assert!(output.is_empty());
}

#[test]
fn a_policy_needs_a_local_nonce_update_in_progress() {
    let mut store = store();
    let mut boot_policy = BootPolicy::default();
    refused(&mut boot_policy, &mut store, paired_request(1));
    // A recoveryOS nonce update is not a local one.
    assert!(ask(&mut boot_policy, &mut store, mutation(8)).0.is_ok());
    refused(&mut boot_policy, &mut store, paired_request(1));
}

#[test]
fn a_macos_policy_refuses_a_paired_policy_that_is_not_this_updates() {
    let mut store = store();
    let mut boot_policy = BootPolicy::default();
    let (paired, _) = begun(&mut boot_policy, &mut store);
    // Not a policy, and altered.
    let mut altered = paired.clone();
    *altered.last_mut().unwrap() ^= 1;
    for shown in [b"forged".to_vec(), altered] {
        refused(
            &mut boot_policy,
            &mut store,
            macos_request(&shown, false, 1),
        );
    }
    // One of an earlier nonce update.
    assert!(ask(&mut boot_policy, &mut store, mutation(4)).0.is_ok());
    assert!(ask(&mut boot_policy, &mut store, mutation(2)).0.is_ok());
    refused(
        &mut boot_policy,
        &mut store,
        macos_request(&paired, false, 1),
    );
}

#[test]
fn requests_outside_the_recovered_shape_refuse() {
    let mut store = store();
    let mut boot_policy = BootPolicy::default();
    begun(&mut boot_policy, &mut store);
    let field = |tag: usize, value: &[u8]| context(tag as u8, value);
    let good = [
        field(FORMAT, &[1]),
        field(OS_MANIFEST, b"manifest"),
        field(VOLUME_GROUP, &GROUP),
        field(BOOT_POLICY, &[1]),
        field(AUTHORIZATION, &[]),
    ];
    let with = |at: usize, value: Vec<u8>| {
        let mut fields = good.to_vec();
        fields[at] = value;
        encoded(CREATE_PAIRED, &fields)
    };
    // The DER's length, a format, an ACM, a Permissive paired policy, a short
    // UUID, a repeated field, an unknown field and a constructed one.
    let mut wrong_length = encoded(CREATE_PAIRED, &good);
    wrong_length[32] += 1;
    for input in [
        wrong_length,
        with(0, field(FORMAT, &[2])),
        with(4, field(AUTHORIZATION, &[1])),
        with(3, field(BOOT_POLICY, &[3])),
        with(2, field(VOLUME_GROUP, &[1; 15])),
        with(1, field(FORMAT, &[1])),
        encoded(CREATE_PAIRED, &[good.concat(), field(9, &[])]),
        encoded(CREATE_PAIRED, &[good.concat(), der::encode(0xa9, &[])]),
    ] {
        refused(&mut boot_policy, &mut store, input);
    }
}
