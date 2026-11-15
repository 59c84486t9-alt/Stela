use super::*;
use {
    stela_formats::payload::IdentitySet, stela_formats::payload::Member,
    stela_formats::payload::test_support::Memory, stela_formats::payload::test_support::manifest,
    stela_formats::payload::zip::test_support::archive,
};
pub(crate) fn fixture(data: &[u8], deflate: bool) -> Store<Memory> {
    with_components(data, deflate, &[])
}
/// Give a store's manifest AEA keys, for the staged-answer tests.
pub(crate) fn set_aea_keys(store: &mut Store<Memory>, keys: Vec<stela_formats::payload::AeaKey>) {
    store.manifest.aea_keys = keys;
}
/// Set one Info field on the selected fixture identity.
pub(crate) fn set_info<R>(store: &mut Store<R>, key: &str, value: Value) {
    let Value::Dict(identity) = &mut store.identities[store.current].value else {
        panic!("fixture identity is not a dictionary")
    };
    let Value::Dict(info) = identity.get_mut("Info").expect("fixture Info") else {
        panic!("fixture Info is not a dictionary")
    };
    info.insert(key.into(), value);
}
pub(crate) fn set_component_info<R>(
    store: &mut Store<R>,
    component: &str,
    key: &str,
    value: Value,
) {
    let Value::Dict(identity) = &mut store.identities[store.current].value else {
        panic!("fixture identity")
    };
    let Value::Dict(manifest) = identity.get_mut("Manifest").unwrap() else {
        panic!("fixture manifest")
    };
    let Value::Dict(entry) = manifest.get_mut(component).unwrap() else {
        panic!("fixture component")
    };
    let Value::Dict(info) = entry.get_mut("Info").unwrap() else {
        panic!("fixture component Info")
    };
    info.insert(key.into(), value);
}
/// Drop a member from a store's inventory, as a trimmed medium leaves it.
pub(crate) fn drop_member(store: &mut Store<Memory>, name: &str) {
    store.manifest.members.retain(|m| m.name != name);
}
/// The fixture with more BuildManifest components, each `(name, path,
/// bytes)` with its SHA-384 as the Digest.
pub(crate) fn with_components(
    data: &[u8],
    deflate: bool,
    extra: &[(&str, &str, &[u8])],
) -> Store<Memory> {
    with_digests(data, deflate, extra, &[])
}
/// `with_components` with the named components' Digest replaced, for a
/// manifest whose digest covers something other than the member's
/// bytes. Components naming one path share one member.
pub(crate) fn with_digests(
    data: &[u8],
    deflate: bool,
    extra: &[(&str, &str, &[u8])],
    digests: &[(&str, [u8; 48])],
) -> Store<Memory> {
    let (reader, manifest) = parts(data, deflate, extra, digests, ERASE);
    Store::open(reader, manifest, 0).unwrap()
}
/// A BuildManifest identity's variant and behavior, and the purpose the
/// inventory records for it.
pub(crate) type Behavior = (&'static str, &'static str, Purpose);
pub(crate) const ERASE: Behavior = (
    "Customer Erase Install (IPSW)",
    ERASE_BEHAVIOR,
    Purpose::Erase,
);
pub(crate) const UPDATE: Behavior = (
    "Customer Upgrade Install (IPSW)",
    UPDATE_BEHAVIOR,
    Purpose::Update,
);
/// The fixture's IPSW and inventory, its one identity `behavior`'s.
pub(crate) fn parts(
    data: &[u8],
    deflate: bool,
    extra: &[(&str, &str, &[u8])],
    digests: &[(&str, [u8; 48])],
    behavior: Behavior,
) -> (Memory, PayloadManifest) {
    use sha2::{Digest, Sha384};
    let (variant, restore_behavior, purpose) = behavior;
    let mut components: BTreeMap<String, Value> = [(
        "OS".into(),
        Value::dict([
            ("Info", Value::dict([("Path", Value::from("os.dmg"))])),
            ("Digest", Value::Data(vec![1; 48])),
        ]),
    )]
    .into();
    for (name, path, bytes) in extra {
        components.insert(
            (*name).into(),
            Value::dict([
                ("Info", Value::dict([("Path", Value::from(*path))])),
                (
                    "Digest",
                    Value::Data(
                        digests
                            .iter()
                            .find(|(component, _)| component == name)
                            .map_or_else(|| Sha384::digest(bytes).to_vec(), |(_, d)| d.to_vec()),
                    ),
                ),
            ]),
        );
    }
    let identity = Value::dict([
        (
            "Info",
            Value::dict([
                ("Variant", Value::from(variant)),
                ("MacOSVariant", Value::from("macOS Customer")),
                ("RestoreBehavior", Value::from(restore_behavior)),
                ("DeviceClass", Value::from("testap")),
                ("OSDiskImageSize", Value::Integer(123)),
            ]),
        ),
        ("ApChipID", Value::from("0x8112")),
        ("ApBoardID", Value::from("0x24")),
        ("ApSecurityDomain", Value::from("0x1")),
        ("UniqueBuildID", Value::Data(vec![0x12; 8])),
        ("Manifest", Value::Dict(components)),
    ]);
    let build = plist::encode_xml(
        &Value::dict([("BuildIdentities", Value::Array(vec![identity]))]),
        Limits::default(),
    )
    .unwrap();
    let (mut m, _) = manifest();
    m.device_class = "testap".into();
    m.source.build_manifest_sha256 = stela_formats::sha256(&build);
    m.global_manifests.clear();
    m.aea_keys.clear();
    let mut files: Vec<(&str, &[u8])> = vec![("os.dmg", data)];
    for (_, path, bytes) in extra {
        if !files.iter().any(|(name, _)| name == path) {
            files.push((*path, *bytes));
        }
    }
    m.members = files
        .iter()
        .map(|(name, bytes)| Member {
            name: (*name).into(),
            bytes: bytes.len() as u64,
            sha256: Some(stela_formats::sha256(bytes)),
            sha384: None,
        })
        .collect();
    m.identities = vec![IdentitySet {
        index: 0,
        variant: variant.into(),
        purpose,
        members: files.iter().map(|(name, _)| (*name).into()).collect(),
    }];
    let entries: Vec<(&str, &[u8], bool)> =
        core::iter::once(("BuildManifest.plist", build.as_slice(), false))
            .chain(files.iter().map(|(name, bytes)| (*name, *bytes, deflate)))
            .collect();
    (Memory(archive(&entries, true)), m)
}
/// `s`'s member hashes as a block hash file, its manifest naming it.
fn precomputed(s: &mut Store<Memory>, data: &[u8]) -> Vec<u8> {
    let file: Vec<u8> = data
        .chunks(BLOCK_BYTES)
        .flat_map(|block| Sha256::digest(block).to_vec())
        .collect();
    s.manifest.members[0].sha384 = Some(hex::encode(Sha384::digest(data)));
    s.manifest.block_hashes = Some(stela_formats::payload::BlockHashes {
        file: stela_formats::payload::BLOCK_HASHES_FILE.into(),
        block_bytes: stela_formats::payload::HASH_BLOCK_BYTES,
        sha256: stela_formats::sha256(&file),
    });
    s.manifest.validate().unwrap();
    file
}

#[test]
fn recorded_hashes_check_every_member_before_the_restore_by_default() {
    let data: Vec<u8> = (0..MAX_READ_BYTES + 5).map(|i| (i * 7) as u8).collect();
    let mut s = fixture(&data, true);
    let file = precomputed(&mut s, &data);
    s.adopt_block_hashes(&file).unwrap();
    assert!(!s.prepared(), "the whole member is still to be checked");
    s.prepare().unwrap();
    assert!(s.prepared());
    assert_eq!(s.read_at("os.dmg", 5, 10).unwrap(), data[5..15]);

    // The same records refuse a changed block or SHA-384 by name.
    let mut s = fixture(&data, true);
    let mut file = precomputed(&mut s, &data);
    let last = file.len() - 32;
    file[last] ^= 1;
    s.manifest.block_hashes.as_mut().unwrap().sha256 = stela_formats::sha256(&file);
    s.adopt_block_hashes(&file).unwrap();
    let error = s.prepare().unwrap_err().to_string();
    assert!(
        error.contains("os.dmg: source changed at block 16"),
        "{error}"
    );
    let mut s = fixture(&data, false);
    let file = precomputed(&mut s, &data);
    s.manifest.members[0].sha384 = Some("0".repeat(96));
    s.adopt_block_hashes(&file).unwrap();
    let error = s.prepare().unwrap_err().to_string();
    assert!(error.contains("os.dmg: SHA-384 differs"), "{error}");
    assert!(!s.prepared());
}

#[test]
fn verify_on_read_checks_recorded_hashes_as_reads_reach_them() {
    let data: Vec<u8> = (0..BLOCK_BYTES * 2 + 5).map(|i| (i * 3) as u8).collect();
    let mut s = fixture(&data, false);
    let file = alloc::boxed::Box::leak(precomputed(&mut s, &data).into_boxed_slice());
    assert!(!s.prepared());
    let error = s
        .adopt_static_block_hashes(&file[1..])
        .unwrap_err()
        .to_string();
    assert!(error.contains("blocks.bin"), "{error}");
    s.set_verify(Verify::OnRead);
    s.adopt_static_block_hashes(file).unwrap();
    assert!(core::ptr::eq(
        s.verified["os.dmg"].blocks.as_ref(),
        file.as_chunks::<32>().0
    ));
    // Nothing is left to read before the restore.
    assert!(s.prepared());
    s.prepare().unwrap();
    assert_eq!(
        s.digest384("os.dmg").unwrap().unwrap(),
        &Sha384::digest(&data)[..]
    );
    let mut buffer = Vec::with_capacity(BLOCK_BYTES);
    buffer.extend_from_slice(b"old");
    let pointer = buffer.as_ptr();
    let bytes = s.read_at_reusing("os.dmg", 10, 20, buffer).unwrap();
    assert_eq!(bytes, data[10..30], "a random read");
    assert_eq!(bytes.as_ptr(), pointer);
    // Read in order from the start, the whole member meets its SHA-384.
    let mut whole = s.read_at("os.dmg", 0, BLOCK_BYTES).unwrap();
    whole.extend(
        s.read_at("os.dmg", BLOCK_BYTES as u64, data.len() - BLOCK_BYTES)
            .unwrap(),
    );
    assert_eq!(whole, data);

    // A block hash that differs refuses that block by number.
    let mut s = fixture(&data, true);
    let mut file = precomputed(&mut s, &data);
    file[32] ^= 1;
    s.manifest.block_hashes.as_mut().unwrap().sha256 = stela_formats::sha256(&file);
    s.set_verify(Verify::OnRead);
    s.adopt_block_hashes(&file).unwrap();
    s.prepare().unwrap();
    s.read_at("os.dmg", 0, 10).unwrap();
    let error = s
        .read_at("os.dmg", BLOCK_BYTES as u64, 1)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("os.dmg: source changed at block 1"),
        "{error}"
    );

    // A SHA-384 that differs refuses the member once it is read whole.
    let mut s = fixture(&data, false);
    let file = precomputed(&mut s, &data);
    s.manifest.members[0].sha384 = Some("0".repeat(96));
    s.set_verify(Verify::OnRead);
    s.adopt_block_hashes(&file).unwrap();
    s.read_at("os.dmg", 0, BLOCK_BYTES).unwrap();
    let error = s
        .read_at("os.dmg", BLOCK_BYTES as u64, data.len() - BLOCK_BYTES)
        .unwrap_err()
        .to_string();
    assert!(error.contains("os.dmg: SHA-384 differs"), "{error}");
}

#[test]
fn random_reads_refuse_changed_bytes() {
    let data: Vec<_> = (0..BLOCK_BYTES * 3 + 7).map(|i| i as u8).collect();
    for deflate in [false, true] {
        let mut s = fixture(&data, deflate);
        assert_eq!(s.identity().index, 0);
        assert_eq!(
            s.read_component("OS", BLOCK_BYTES as u64 - 3, 12).unwrap(),
            data[BLOCK_BYTES - 3..BLOCK_BYTES + 9]
        );
        assert!(s.read_at("os.dmg", u64::MAX, 2).is_err());
        assert!(s.read_at("unknown", 0, 0).is_err());
        assert!(s.read_at("os.dmg", 0, MAX_READ_BYTES + 1).is_err());
        assert_eq!(
            s.read_at("os.dmg", data.len() as u64, 0).unwrap(),
            Vec::<u8>::new()
        );
        if !deflate {
            let at = s
                .reader
                .0
                .windows(16)
                .position(|w| w == &data[..16])
                .unwrap();
            s.reader.0[at] ^= 1;
            assert!(
                s.read_at_reusing("os.dmg", 0, 1, Vec::with_capacity(BLOCK_BYTES))
                    .is_err()
            );
        }
    }
}
#[test]
fn a_restore_opens_an_erase_or_update_identity_its_inventory_names_alike() {
    let (reader, manifest) = parts(b"os", false, &[], &[], UPDATE);
    let store = Store::open(reader, manifest, 0).unwrap();
    assert_eq!(
        store
            .identity()
            .info()
            .unwrap()
            .required("RestoreBehavior")
            .unwrap()
            .string()
            .unwrap(),
        UPDATE_BEHAVIOR
    );
    // The inventory's purpose must name the identity's behavior.
    let (reader, mut manifest) = parts(b"os", false, &[], &[], UPDATE);
    manifest.identities[0].purpose = Purpose::Erase;
    let error = Store::open(reader, manifest, 0).err().unwrap().to_string();
    assert!(error.contains("identity mismatch"), "{error}");
    // An installed-system identity is no restore.
    let (reader, manifest) = parts(
        b"os",
        false,
        &[],
        &[],
        ("macOS Customer", "Install", Purpose::Installed),
    );
    let error = Store::open(reader, manifest, 0).err().unwrap().to_string();
    assert!(error.contains("neither erase nor update"), "{error}");
}
#[test]
fn a_remote_images_device_verified_member_passes_through_unhashed() {
    let data = b"bytes the device verifies";
    let mut s = fixture(data, true);
    s.manifest.layout = stela_formats::payload::Layout::Remote {
        url: "http://updates-http.cdn-apple.com/a.ipsw".into(),
        etag: "\"e\"".into(),
    };
    s.manifest.source.sha256 = None;
    s.manifest.members[0].sha256 = None;
    s.prepare().unwrap();
    assert!(s.prepared());
    assert_eq!(s.read_at("os.dmg", 6, 3).unwrap(), &data[6..9]);
    assert_eq!(s.read_at("os.dmg", 0, data.len()).unwrap(), data);
    assert_eq!(s.digest384("os.dmg").unwrap(), None);
}
#[test]
fn corrupt_inventory_fails_before_any_bytes_are_returned() {
    let mut s = fixture(b"hello", false);
    s.manifest.members[0].sha256 = Some("0".repeat(64));
    assert!(s.read_at("os.dmg", 0, 1).is_err());
    assert!(s.verified.is_empty());
}

#[test]
fn interleaved_deflated_members_resume_without_replaying_prefixes() {
    struct Counting {
        source: Memory,
        bytes: usize,
    }
    impl ReadAt for Counting {
        type Error = &'static str;

        fn len(&self) -> u64 {
            self.source.len()
        }

        fn read_at(
            &mut self,
            offset: u64,
            buffer: &mut [u8],
        ) -> core::result::Result<(), Self::Error> {
            self.bytes += buffer.len();
            self.source.read_at(offset, buffer)
        }
    }

    let contents = |mut state: u32| -> Vec<u8> {
        (0..8 * BLOCK_BYTES)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect()
    };
    let data = contents(0x5a);
    let other = contents(0x61);
    let (source, manifest) = parts(&data, true, &[("Extra", "extra.dmg", &other)], &[], ERASE);
    let mut store = Store::open(Counting { source, bytes: 0 }, manifest, 0).unwrap();
    store.prepare().unwrap();
    let mut read_both = |discard_cursors| {
        store.reader.bytes = 0;
        for offset in (0..data.len()).step_by(BLOCK_BYTES) {
            for (path, expected) in [("os.dmg", &data), ("extra.dmg", &other)] {
                if discard_cursors {
                    store.cursors.0.clear();
                }
                assert_eq!(
                    store.read_at(path, offset as u64, BLOCK_BYTES).unwrap(),
                    expected[offset..offset + BLOCK_BYTES]
                );
            }
        }
        store.reader.bytes
    };

    let resumed = read_both(false);
    let replayed = read_both(true);
    assert!(
        replayed >= 4 * resumed,
        "resumed {resumed}, replayed {replayed}"
    );
}

#[test]
fn a_read_whose_source_ran_out_of_time_is_pending_and_goes_on_later() {
    /// A network source bounded for its caller: its next `stalls` reads
    /// run out of time; `broken` fails every read for another reason.
    struct Stalling {
        source: Memory,
        stalls: usize,
        broken: bool,
        blocked: bool,
    }
    impl ReadAt for Stalling {
        type Error = &'static str;

        fn len(&self) -> u64 {
            self.source.len()
        }

        fn read_at(
            &mut self,
            offset: u64,
            buffer: &mut [u8],
        ) -> core::result::Result<(), Self::Error> {
            if self.stalls > 0 {
                self.stalls -= 1;
                self.blocked = true;
                return Err("the read's time ran out");
            }
            if self.broken {
                return Err("connection refused");
            }
            self.source.read_at(offset, buffer)
        }

        fn blocked(&mut self) -> bool {
            core::mem::take(&mut self.blocked)
        }
    }

    let data: Vec<u8> = (0..3 * BLOCK_BYTES).map(|n| (n % 251) as u8).collect();
    for deflate in [false, true] {
        let (source, manifest) = parts(&data, deflate, &[], &[], ERASE);
        let reader = Stalling {
            source,
            stalls: 0,
            broken: false,
            blocked: false,
        };
        let mut store = Store::open(reader, manifest, 0).unwrap();
        store.prepare().unwrap();
        store.reader.stalls = 2;
        for _ in 0..2 {
            assert!(matches!(
                store.read_at("os.dmg", 5, BLOCK_BYTES),
                Err(Error::Pending)
            ));
        }
        assert_eq!(
            store.read_at("os.dmg", 5, BLOCK_BYTES).unwrap(),
            data[5..5 + BLOCK_BYTES]
        );
        // Any other failure stays the payload's refusal.
        store.cursors.0.clear();
        store.reader.broken = true;
        let error = store.read_at("os.dmg", 2 * BLOCK_BYTES as u64, 16);
        assert!(matches!(error, Err(Error::Payload(_))), "{error:?}");
    }
}

#[test]
fn a_scan_a_pending_read_stops_goes_on_without_reading_again() {
    /// Every third read runs out of time; counts the bytes it serves.
    struct Stalling {
        source: Memory,
        reads: usize,
        served: u64,
        blocked: bool,
        /// Reads are bounded once the store is open.
        bounded: bool,
    }
    impl ReadAt for Stalling {
        type Error = &'static str;

        fn len(&self) -> u64 {
            self.source.len()
        }

        fn read_at(
            &mut self,
            offset: u64,
            buffer: &mut [u8],
        ) -> core::result::Result<(), Self::Error> {
            self.reads += 1;
            if self.bounded && self.reads.is_multiple_of(3) {
                self.blocked = true;
                return Err("the read's time ran out");
            }
            self.served += buffer.len() as u64;
            self.source.read_at(offset, buffer)
        }

        fn blocked(&mut self) -> bool {
            core::mem::take(&mut self.blocked)
        }
    }

    // Barely compressible, so a deflate member refills its input often.
    let mut state = 0x2545_f491_u32;
    let data: Vec<u8> = (0..16 * BLOCK_BYTES + 777)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state >> 24) as u8
        })
        .collect();
    for deflate in [false, true] {
        let mut clean = fixture(&data, deflate);
        clean.prepare().unwrap();
        let (source, manifest) = parts(&data, deflate, &[], &[], ERASE);
        let archive = source.len();
        let reader = Stalling {
            source,
            reads: 0,
            served: 0,
            blocked: false,
            bounded: false,
        };
        let mut store = Store::open(reader, manifest, 0).unwrap();
        store.reader.served = 0;
        store.reader.bounded = true;
        let mut pending = 0;
        loop {
            match store.prepare() {
                Ok(()) => break,
                Err(Error::Pending) => pending += 1,
                Err(error) => panic!("deflate={deflate}: {error:?}"),
            }
            assert!(pending < 10_000);
        }
        assert!(pending > 2, "deflate={deflate}");
        // Each byte is read once, plus member headers.
        assert!(
            store.reader.served < archive + 64 * 1024,
            "deflate={deflate}: served {} of {archive}",
            store.reader.served
        );
        assert_eq!(
            store.verified["os.dmg"].blocks,
            clean.verified["os.dmg"].blocks
        );
        assert_eq!(
            store.digest384("os.dmg").unwrap(),
            clean.digest384("os.dmg").unwrap()
        );
    }
}

/// A request that is asked again after a pending read reads its member's
/// head again and then goes on with its read to the member's end: that read
/// keeps what it has, and its own place in a deflated member, so a member
/// longer than one bounded turn reads is read once, not from its start at
/// every turn.
#[test]
fn a_whole_member_read_asked_again_goes_on_and_reads_no_byte_twice() {
    use sha2::{Digest, Sha384};
    /// Every fifth read runs out of time; counts the bytes it serves.
    struct Stalling {
        source: Memory,
        reads: usize,
        served: u64,
        blocked: bool,
        bounded: bool,
    }
    impl ReadAt for Stalling {
        type Error = &'static str;

        fn len(&self) -> u64 {
            self.source.len()
        }

        fn read_at(
            &mut self,
            offset: u64,
            buffer: &mut [u8],
        ) -> core::result::Result<(), Self::Error> {
            self.reads += 1;
            if self.bounded && self.reads.is_multiple_of(5) {
                self.blocked = true;
                return Err("the read's time ran out");
            }
            self.served += buffer.len() as u64;
            self.source.read_at(offset, buffer)
        }

        fn blocked(&mut self) -> bool {
            core::mem::take(&mut self.blocked)
        }
    }

    let mut state = 0x9e37_79b9_u32;
    let data: Vec<u8> = (0..3 * MAX_READ_BYTES + 777)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state >> 24) as u8
        })
        .collect();
    let digest: [u8; 48] = Sha384::digest(&data).into();
    for deflate in [false, true] {
        for gather in [false, true] {
            let (source, manifest) = parts(&data, deflate, &[], &[], ERASE);
            let archive = source.len();
            let reader = Stalling {
                source,
                reads: 0,
                served: 0,
                blocked: false,
                bounded: false,
            };
            let mut store = Store::open(reader, manifest, 0).unwrap();
            store.prepare().unwrap();
            store.reader.served = 0;
            store.reader.bounded = true;
            let mut pending = 0u64;
            loop {
                assert!(pending < 1000, "deflate={deflate} gather={gather}");
                let head = match store.read_at("os.dmg", 0, 64) {
                    Ok(head) => head,
                    Err(Error::Pending) => {
                        pending += 1;
                        continue;
                    }
                    Err(error) => panic!("{error:?}"),
                };
                let done = match gather {
                    true => store.read_whole("os.dmg").map(|bytes| bytes == data),
                    false => store
                        .digest_after("os.dmg", &head)
                        .map(|hash| hash == digest),
                };
                match done {
                    Ok(same) => break assert!(same, "deflate={deflate} gather={gather}"),
                    Err(Error::Pending) => pending += 1,
                    Err(error) => panic!("{error:?}"),
                }
            }
            assert!(pending >= 2, "deflate={deflate} gather={gather}");
            // The member once, and its first block for each time it was
            // asked again.
            let heads = (pending + 1) * (BLOCK_BYTES as u64 + 2 * 64 * 1024);
            assert!(
                store.reader.served < archive + heads,
                "deflate={deflate} gather={gather}: served {} of {archive}, asked {pending}",
                store.reader.served
            );
            assert!(store.passes.is_empty());
        }
    }
}

/// A remote image's device-verified members have no scan: their reads go
/// straight to the cursors. A read longer than a few network refills that
/// runs out of time again and again still goes on where it stopped, and
/// reads each compressed byte once; any other failure drops the cursor.
#[test]
fn a_pending_device_verified_read_goes_on_from_its_bytes_so_far() {
    /// Every third read runs out of time once reads are bounded; counts
    /// the bytes it serves.
    struct Stalling {
        source: Memory,
        reads: usize,
        served: u64,
        blocked: bool,
        bounded: bool,
        broken: bool,
    }
    impl ReadAt for Stalling {
        type Error = &'static str;

        fn len(&self) -> u64 {
            self.source.len()
        }

        fn read_at(
            &mut self,
            offset: u64,
            buffer: &mut [u8],
        ) -> core::result::Result<(), Self::Error> {
            self.reads += 1;
            if self.broken {
                return Err("connection refused");
            }
            if self.bounded && self.reads.is_multiple_of(3) {
                self.blocked = true;
                return Err("the read's time ran out");
            }
            self.served += buffer.len() as u64;
            self.source.read_at(offset, buffer)
        }

        fn blocked(&mut self) -> bool {
            core::mem::take(&mut self.blocked)
        }
    }

    // Barely compressible, so one read spans many input refills.
    let mut state = 0x1b87_3593_u32;
    let data: Vec<u8> = (0..3 * MAX_READ_BYTES + 777)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state >> 24) as u8
        })
        .collect();
    for deflate in [false, true] {
        let (source, mut manifest) = parts(&data, deflate, &[], &[], ERASE);
        manifest.layout = stela_formats::payload::Layout::Remote {
            url: "http://updates-http.cdn-apple.com/a.ipsw".into(),
            etag: "\"e\"".into(),
        };
        manifest.source.sha256 = None;
        manifest.members[0].sha256 = None;
        let archive = source.len();
        let reader = Stalling {
            source,
            reads: 0,
            served: 0,
            blocked: false,
            bounded: false,
            broken: false,
        };
        let mut store = Store::open(reader, manifest, 0).unwrap();
        store.prepare().unwrap();
        store.reader.served = 0;
        store.reader.bounded = true;
        let mut pending = 0;
        let mut offset = 0;
        while offset < data.len() {
            let len = MAX_READ_BYTES.min(data.len() - offset);
            let bytes = loop {
                match store.read_at("os.dmg", offset as u64, len) {
                    Ok(bytes) => break bytes,
                    Err(Error::Pending) => pending += 1,
                    Err(error) => panic!("deflate={deflate}: {error:?}"),
                }
                assert!(pending < 1000, "deflate={deflate}");
            };
            assert!(bytes == data[offset..offset + len], "deflate={deflate}");
            offset += len;
        }
        assert!(pending >= 2, "deflate={deflate}");
        assert!(
            store.reader.served < archive + 64 * 1024,
            "deflate={deflate}: served {} of {archive}",
            store.reader.served
        );
        // A failure that is not the source's time running out drops the
        // cursor: the next read starts the member again.
        store.reader.bounded = false;
        assert!(store.read_at("os.dmg", 0, 16).is_ok());
        store.reader.broken = true;
        let error = store.read_at("os.dmg", 16, MAX_READ_BYTES);
        assert!(matches!(error, Err(Error::Payload(_))), "{error:?}");
        assert!(store.cursors.0.is_empty(), "deflate={deflate}");
    }
}

use crate::platform::net::{
    NetError,
    ranges::{AHEAD, BUDGET_MS, KEEP, RangeSource, Ranges, SKIP, STREAMS},
};

/// A remote image's network for [`Ranges`]: an open range's body arrives
/// only while the reader waits, `per_wait` bytes each wait, and every wait
/// takes a whole turn's budget. Counts the times each image byte arrives.
pub(crate) struct Network {
    image: Vec<u8>,
    per_wait: u64,
    now: u64,
    bodies: Vec<Option<Body>>,
    arrivals: Vec<u8>,
}
impl Network {
    /// `image` over a network that brings `per_wait` bytes to each open
    /// range at each wait.
    pub(crate) fn new(image: Vec<u8>, per_wait: u64) -> Self {
        Self {
            arrivals: vec![0; image.len()],
            image,
            per_wait,
            now: 0,
            bodies: Vec::new(),
        }
    }
    /// The bytes that arrived, counting each time one arrived.
    pub(crate) fn arrived(&self) -> u64 {
        self.arrivals.iter().map(|&count| u64::from(count)).sum()
    }
}
/// An open range: handed over up to `next`, arrived up to `arrived`.
struct Body {
    next: u64,
    arrived: u64,
    last: u64,
}
impl RangeSource for Network {
    type Range = usize;

    fn open(&mut self, first: u64, last: u64) -> core::result::Result<usize, NetError> {
        self.bodies.push(Some(Body {
            next: first,
            arrived: first,
            last,
        }));
        Ok(self.bodies.len() - 1)
    }

    fn read(
        &mut self,
        range: &mut usize,
        take: &mut dyn FnMut(&[u8]),
    ) -> core::result::Result<bool, NetError> {
        let body = self.bodies[*range].as_mut().expect("an open range");
        let (from, to) = (body.next as usize, body.arrived as usize);
        body.next = body.arrived;
        let done = body.next > body.last;
        for count in &mut self.arrivals[from..to] {
            *count = count.saturating_add(1);
        }
        take(&self.image[from..to]);
        Ok(done)
    }

    fn close(&mut self, range: usize) {
        self.bodies[range] = None;
    }

    fn wait(&mut self, _: u64) -> core::result::Result<(), NetError> {
        self.now += BUDGET_MS;
        for body in self.bodies.iter_mut().flatten() {
            body.arrived = (body.arrived + self.per_wait).min(body.last + 1);
        }
        Ok(())
    }

    fn millis(&mut self) -> u64 {
        self.now
    }

    fn note(&mut self, _: core::fmt::Arguments<'_>) {}
}

/// Bytes like an Image4 payload's that deflate barely shrinks.
pub(crate) fn noise(len: usize, mut state: u32) -> Vec<u8> {
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state >> 24) as u8
        })
        .collect()
}

/// A remote image read in service turns, as the restore host reads it:
/// each turn bounds the reads, the system image's stream reads on, and the
/// request asked again reads a component's head and then digests the
/// component to its end. The component is far larger than one turn
/// delivers and than a stream keeps behind its reads. The request goes on
/// each turn from what earlier turns received (the pass, the inflater and
/// the range's buffer), so it ends in about as many turns as its bytes
/// take, not never. Bytes arrive twice only where the ranges read ahead
/// for the head's own stream or fill a skipped gap, and a hashed member's
/// scan and read each read it.
#[test]
fn a_remote_component_longer_than_a_turn_is_read_across_turns_once() {
    use sha2::{Digest, Sha384};
    use stela_formats::payload::zip::Archive;

    const PER_WAIT: u64 = 256 << 10;
    // Past what a stream keeps behind its reads and the gap a read skips.
    let component = noise(KEEP + SKIP as usize + 3 * MAX_READ_BYTES + 777, 0x2545_f491);
    let digest: [u8; 48] = Sha384::digest(&component).into();
    // Stored, and long enough that its stream stays far from the component.
    let system: Vec<u8> = (0..2 * (KEEP + SKIP as usize) + AHEAD)
        .map(|at| (at ^ (at >> 9)) as u8)
        .collect();
    for (beside, hashed, deflate) in [
        (false, false, true),
        (true, false, true),
        (true, true, true),
        (true, false, false),
        (false, false, false),
    ] {
        let case = format!("beside={beside} hashed={hashed} deflate={deflate}");
        let (mut stored, mut manifest) = parts(
            &system,
            false,
            &[("KernelCache", "kernelcache", &component)],
            &[],
            ERASE,
        );
        let build = {
            let archive = Archive::open(&mut stored).unwrap();
            let entry = archive.find("BuildManifest.plist").unwrap().clone();
            let mut bytes = vec![0; entry.bytes as usize];
            archive
                .read_member_resuming(&mut stored, &entry, &mut None, 0, &mut bytes)
                .unwrap();
            bytes
        };
        let image = archive(
            &[
                ("BuildManifest.plist", &build, false),
                ("os.dmg", &system, false),
                ("kernelcache", &component, deflate),
            ],
            true,
        );
        manifest.layout = stela_formats::payload::Layout::Remote {
            url: "http://updates-http.cdn-apple.com/a.ipsw".into(),
            etag: "\"e\"".into(),
        };
        manifest.source.sha256 = None;
        for member in &mut manifest.members {
            if !hashed || member.name == "os.dmg" {
                member.sha256 = None;
            }
        }
        let len = image.len() as u64;
        let network = Network {
            arrivals: vec![0; image.len()],
            image,
            per_wait: PER_WAIT,
            now: 0,
            bodies: Vec::new(),
        };
        let mut store = Store::open(Ranges::new(network, len), manifest, 0).unwrap();
        store.reader.source_mut().arrivals.fill(0);
        let mut turns = 0u64;
        let mut system_at = 0;
        loop {
            turns += 1;
            assert!(turns < 4000, "{case}: no end after {turns} turns");
            store.reader.bound();
            // The system image's stream, as ASR reads it ahead.
            if beside && system_at < system.len() {
                let n = (64 << 10).min(system.len() - system_at);
                match store.read_at("os.dmg", system_at as u64, n) {
                    Ok(bytes) => {
                        assert!(bytes == system[system_at..system_at + n], "{case}");
                        system_at += n;
                    }
                    Err(Error::Pending) => {}
                    Err(error) => panic!("{case}: {error:?}"),
                }
            }
            let request = store.prepare().and_then(|()| {
                let head = store.read_at("kernelcache", 0, 64)?;
                store.digest_after("kernelcache", &head)
            });
            match request {
                Ok(hash) => {
                    assert_eq!(hash, digest, "{case}");
                    break;
                }
                Err(Error::Pending) => {}
                Err(error) => panic!("{case}: {error:?}"),
            }
            store.reader.pump();
        }
        let network = store.reader.source();
        // Each turn's one wait brings PER_WAIT to the read's range; a
        // hashed member is read twice, by its scan and by the request.
        let passes = if hashed { 2 } else { 1 };
        let needed = passes * (component.len() as u64).div_ceil(PER_WAIT);
        let refills = 2 * SKIP / PER_WAIT;
        assert!(
            turns <= needed + refills + 8,
            "{case}: {turns} turns for {needed} turns' bytes"
        );
        let twice: u64 = network
            .arrivals
            .iter()
            .map(|&count| u64::from(count.saturating_sub(1)))
            .sum();
        let scan = if hashed { component.len() as u64 } else { 0 };
        let allowed = scan + (AHEAD / STREAMS) as u64 + 2 * SKIP;
        assert!(
            twice <= allowed,
            "{case}: {twice} bytes arrived again in {turns} turns, allowed {allowed}"
        );
    }
}

/// The time a service turn's reads may wait in all, as the install medium's
/// bound (`READ_WAIT_MICROS`) and a remote image's (`BUDGET_MS`).
pub(crate) const TURN_US: u64 = 20_000;
/// The most one of the stick's commands moves.
const COMMAND_BYTES: usize = 64 << 10;
/// Reads started or done that the stick keeps for their callers, as the
/// install medium's bounded reads keep them.
const STICK_KEPT: usize = 8;

/// A USB stick read in service turns, as the install medium's bounded
/// reads are: its one queue works on the oldest started read, a command of
/// up to 64 KiB at a time, only while a read waits; past the turn's
/// [`TURN_US`] a read starts its command and fails as blocked, and the same
/// read asked in a later turn takes its result. Every `slow.0`th command
/// takes `slow.1` microseconds, as one behind the stick's own slow write.
/// Before [`Stick::turn`] bounds them, reads are served whole at once; the
/// device time they would take is counted all the same.
pub(crate) struct Stick {
    source: Memory,
    command_us: u64,
    slow: Option<(u64, u64)>,
    bounded: bool,
    blocked: bool,
    /// Device time the turn's reads waited.
    spent: u64,
    /// Reads started: offset, length and device time left.
    running: VecDeque<(u64, usize, u64)>,
    /// Reads done that no read took yet.
    done: VecDeque<(u64, usize)>,
    /// Commands started, bytes the reads returned, and the device time
    /// they took, in all.
    pub commands: u64,
    pub served: u64,
    pub busy_us: u64,
}
impl Stick {
    pub(crate) fn new(source: Memory, command_us: u64, slow: Option<(u64, u64)>) -> Self {
        Self {
            source,
            command_us,
            slow,
            bounded: false,
            blocked: false,
            spent: 0,
            running: VecDeque::new(),
            done: VecDeque::new(),
            commands: 0,
            served: 0,
            busy_us: 0,
        }
    }
    /// Begin a service turn: the reads from here wait [`TURN_US`] in all.
    pub(crate) fn turn(&mut self) {
        self.bounded = true;
        self.spent = 0;
    }
    /// Serve every later read at once, as before the guest runs.
    pub(crate) fn unbound(&mut self) {
        self.bounded = false;
    }
    /// The device time a read of `bytes` takes.
    fn cost(&mut self, bytes: usize) -> u64 {
        let mut cost = 0;
        for _ in 0..bytes.div_ceil(COMMAND_BYTES).max(1) {
            self.commands += 1;
            cost += match self.slow {
                Some((every, us)) if self.commands.is_multiple_of(every) => us,
                _ => self.command_us,
            };
        }
        cost
    }
    fn serve(&mut self, offset: u64, buffer: &mut [u8]) -> core::result::Result<(), &'static str> {
        self.served += buffer.len() as u64;
        self.source.read_at(offset, buffer)
    }
}
impl ReadAt for Stick {
    type Error = &'static str;

    fn len(&self) -> u64 {
        self.source.len()
    }

    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> core::result::Result<(), Self::Error> {
        let read = (offset, buffer.len());
        if !self.bounded {
            self.busy_us += self.cost(buffer.len());
            return self.serve(offset, buffer);
        }
        loop {
            if let Some(at) = self.done.iter().position(|done| *done == read) {
                self.done.remove(at);
                return self.serve(offset, buffer);
            }
            let started = self
                .running
                .iter()
                .any(|&(at, bytes, _)| (at, bytes) == read);
            if !started && self.running.len() < STICK_KEPT {
                let cost = self.cost(buffer.len());
                self.running.push_back((offset, buffer.len(), cost));
            }
            if self.spent >= TURN_US {
                self.blocked = true;
                return Err("the turn's time ran out");
            }
            let (_, _, left) = self.running.front_mut().expect("a read runs");
            let step = (*left).min(TURN_US - self.spent);
            *left -= step;
            self.spent += step;
            self.busy_us += step;
            if *left == 0 {
                let (at, bytes, _) = self.running.pop_front().expect("a read runs");
                if self.done.len() == STICK_KEPT {
                    self.done.pop_front();
                }
                self.done.push_back((at, bytes));
            }
        }
    }

    fn blocked(&mut self) -> bool {
        core::mem::take(&mut self.blocked)
    }
}

/// The global manifest the firmware fixture's identity names.
pub(crate) const GLOBAL: &str = "Firmware/Manifests/restore/macOS Customer/apticket.testap.im4m";

/// A bare IM4P typed `tag` with a `body`-byte payload of noise.
pub(crate) fn im4p(tag: &[u8; 4], body: usize, seed: u32) -> Vec<u8> {
    fn der(tag: u8, bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if bytes.len() < 128 {
            out.push(bytes.len() as u8);
        } else {
            let n = (bytes.len() as u32).to_be_bytes();
            let skip = n.iter().take_while(|&&b| b == 0).count();
            out.push(0x80 | (4 - skip) as u8);
            out.extend_from_slice(&n[skip..]);
        }
        out.extend_from_slice(bytes);
        out
    }
    der(
        0x30,
        &[
            der(0x16, b"IM4P"),
            der(0x16, tag),
            der(0x16, b""),
            der(4, &noise(body, seed)),
        ]
        .concat(),
    )
}

/// A Mac-like firmware set read through `reader`: LLB, iBoot and ten
/// firmware images flashed with it, a large one (`big` payload bytes,
/// also an FUD image with two of the ten), the SEP image (`sep` bytes)
/// that `SEP` names and `RestoreSEP` names retyped `rsep`, `SepStage1`,
/// and a global ticket that covers each. The hashes are recorded and
/// checked on read, as the install medium's are.
pub(crate) fn firmware<R: ReadAt>(
    sep: usize,
    big: usize,
    deflate: bool,
    reader: impl FnOnce(Memory) -> R,
) -> Store<R> {
    use sha2::{Digest, Sha384};
    // Component, path, flags, and the file.
    let mut images: Vec<(String, String, &[&str], Vec<u8>)> = vec![
        (
            "LLB".into(),
            "llb.im4p".into(),
            &[],
            im4p(b"illb", 40_000, 1),
        ),
        (
            "iBoot".into(),
            "iboot.im4p".into(),
            &["IsFirmwarePayload"],
            im4p(b"ibot", 300_000, 2),
        ),
    ];
    for index in 0..10u8 {
        let flags: &[&str] = match index {
            1 | 3 => &["IsFirmwarePayload", "IsFUDFirmware"],
            _ if index % 2 == 0 => &["IsSecondaryFirmwarePayload", "IsLoadedByiBoot"],
            _ => &["IsFirmwarePayload"],
        };
        images.push((
            format!("Ap,Fw{index}"),
            format!("fw{index}.im4p"),
            flags,
            im4p(
                &[b'f', b'w', b'0', b'0' + index],
                9_000 + 7_000 * index as usize,
                10 + index as u32,
            ),
        ));
    }
    images.push((
        "Ap,Big".into(),
        "big.im4p".into(),
        &["IsFirmwarePayload", "IsFUDFirmware"],
        im4p(b"bigf", big, 3),
    ));
    let sepi = im4p(b"sepi", sep, 4);
    images.push(("SEP".into(), "sep.im4p".into(), &[], sepi.clone()));
    images.push(("RestoreSEP".into(), "sep.im4p".into(), &[], sepi.clone()));
    images.push((
        "SepStage1".into(),
        "sep1.im4p".into(),
        &[],
        im4p(b"sep1", 30_000, 5),
    ));
    let mut rsep = sepi.clone();
    stela_formats::img4::set_payload_type(&mut rsep, *b"rsep").unwrap();
    let restore_sep: [u8; 48] = Sha384::digest(&rsep).into();
    let mut covered: Vec<([u8; 4], [u8; 48])> = images
        .iter()
        .filter(|(name, ..)| name != "RestoreSEP")
        .map(|(.., file)| {
            let tag = stela_formats::img4::payload_type(file).unwrap();
            (tag, Sha384::digest(file).into())
        })
        .collect();
    covered.push((*b"rsep", restore_sep));
    let ticket = super::super::ticket::tests::covering(&covered);
    images.push(("ApTicket".into(), GLOBAL.into(), &[], ticket));
    let extra: Vec<(&str, &str, &[u8])> = images
        .iter()
        .map(|(name, path, _, file)| (name.as_str(), path.as_str(), file.as_slice()))
        .collect();
    let (memory, mut manifest) =
        parts(b"x", deflate, &extra, &[("RestoreSEP", restore_sep)], ERASE);
    manifest.global_manifests.push(GLOBAL.into());
    // The recorded hashes, in member order.
    let mut blocks = Vec::new();
    for member in &mut manifest.members {
        let file = match member.name.as_str() {
            "os.dmg" => b"x".as_slice(),
            name => extra.iter().find(|(_, path, _)| *path == name).unwrap().2,
        };
        for block in file.chunks(BLOCK_BYTES) {
            blocks.extend(Sha256::digest(block).to_vec());
        }
        member.sha384 = Some(hex::encode(Sha384::digest(file)));
    }
    manifest.block_hashes = Some(stela_formats::payload::BlockHashes {
        file: stela_formats::payload::BLOCK_HASHES_FILE.into(),
        block_bytes: stela_formats::payload::HASH_BLOCK_BYTES,
        sha256: stela_formats::sha256(&blocks),
    });
    manifest.validate().unwrap();
    let mut store = Store::open(reader(memory), manifest, 0).unwrap();
    store.set_verify(Verify::OnRead);
    store.adopt_block_hashes(&blocks).unwrap();
    for (name, _, flags, _) in &images {
        for flag in *flags {
            set_component_info(&mut store, name, flag, Value::Boolean(true));
        }
    }
    store
}

/// A request's answer asked again after a pending read reads nothing it
/// read before: its heads and its finished digest are kept, and the turn
/// goes on with the read that ran out of time. The answer to another
/// request, and a finished one, keep nothing.
#[test]
fn an_answer_asked_again_goes_on_from_what_it_read() {
    use sha2::{Digest, Sha384};
    let mut store = firmware(300_000, 1_000, false, |memory| {
        Stick::new(memory, 1_300, None)
    });
    let request = Value::dict([("DataType", Value::from("NORData"))]);
    let other = Value::dict([("DataType", Value::from("FUDData"))]);
    let head_of = |store: &mut Store<Stick>, path: &str| store.read_at(path, 0, 64).unwrap();
    // An unbounded answer: a head, a digest, and the next head.
    store.answering(&request);
    let head = head_of(&mut store, "sep.im4p");
    let digest = store.digest_after("sep.im4p", &head).unwrap();
    let mut whole = store.read_whole("sep.im4p").unwrap();
    assert_eq!(Sha384::digest(&whole).as_slice(), digest);
    whole.truncate(64);
    assert_eq!(whole, head);
    // Its next read runs out of time.
    store.reader.turn();
    store.reader.spent = TURN_US;
    assert!(matches!(
        store.read_at("sep1.im4p", 0, 64),
        Err(Error::Pending)
    ));
    store.answered(true);
    let progress = store.answer_progress().unwrap();
    assert_eq!((progress.data_type, progress.turns), ("NORData", 1));
    assert!(progress.read >= 2 * 300_000, "{}", progress.read);
    assert!(progress.kept > 300_000 && !progress.full);
    // Asked again, it reads only the read that ran out of time.
    let served = store.reader.served;
    store.reader.turn();
    store.answering(&request);
    assert_eq!(head_of(&mut store, "sep.im4p"), head);
    assert_eq!(store.digest_after("sep.im4p", &head).unwrap(), digest);
    let size = store.member_len("sep.im4p").unwrap() as usize;
    assert_eq!(store.read_whole("sep.im4p").unwrap().len(), size);
    assert_eq!(store.reader.served, served);
    head_of(&mut store, "sep1.im4p");
    assert!(store.reader.served > served);
    store.answered(true);
    assert_eq!(store.answer_progress().unwrap().turns, 2);
    // Reads outside the answer, such as a transfer's, are not kept.
    let kept = store.answer_progress().unwrap().kept;
    head_of(&mut store, "llb.im4p");
    assert_eq!(store.answer_progress().unwrap().kept, kept);
    // Another request's answer starts afresh.
    store.answering(&other);
    let served = store.reader.served;
    head_of(&mut store, "sep.im4p");
    assert!(store.reader.served > served);
    let serial = store.answer_progress().unwrap().serial;
    store.answered(false);
    assert!(store.answer_progress().is_none());
    // So does the same request once its answer ended.
    store.answering(&other);
    assert_ne!(store.answer_progress().unwrap().serial, serial);
    let served = store.reader.served;
    head_of(&mut store, "sep.im4p");
    assert!(store.reader.served > served);
    store.answered(false);
}
