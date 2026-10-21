use super::*;
use alloc::{vec, vec::Vec};

fn w32(b: &mut [u8], at: usize, value: u32) {
    b[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn w64(b: &mut [u8], at: usize, value: u64) {
    b[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn name(b: &mut [u8], at: usize, s: &str) {
    b[at..at + s.len()].copy_from_slice(s.as_bytes());
}
fn fixture() -> Vec<u8> {
    let mut b = vec![0; 0x2010];
    for (at, v) in [
        (0, 0xfeedfacf),
        (4, 0x100000c),
        (8, 0x80000002),
        (12, 5),
        (16, 4),
        (20, 616),
    ] {
        w32(&mut b, at, v);
    }
    // Two segments, two sections in TEXT. Header remains outside the loaded map.
    let s = 32;
    w32(&mut b, s, 0x19);
    w32(&mut b, s + 4, 232);
    name(&mut b, s + 8, "__TEXT");
    for (o, v) in [(24, 0), (32, 0x1000), (40, 0x1000), (48, 0x1000)] {
        w64(&mut b, s + o, v);
    }
    for (o, v) in [(56, 5), (60, 5), (64, 2)] {
        w32(&mut b, s + o, v);
    }
    for (at, n, addr, size, off, reserved) in [
        (s + 72, "__text", 0, 4, 0x1000, 0),
        (s + 152, "__chain_starts", 0x100, 16, 0x1100, 2),
    ] {
        name(&mut b, at, n);
        name(&mut b, at + 16, "__TEXT");
        w64(&mut b, at + 32, addr);
        w64(&mut b, at + 40, size);
        w32(&mut b, at + 48, off);
        w32(&mut b, at + 52, 2);
        w32(&mut b, at + 68, reserved);
    }
    let s = 264;
    w32(&mut b, s, 0x19);
    w32(&mut b, s + 4, 72);
    name(&mut b, s + 8, "__DATA");
    for (o, v) in [(24, 0x2000), (32, 0x100), (40, 0x2000), (48, 16)] {
        w64(&mut b, s + o, v);
    }
    w32(&mut b, s + 56, 3);
    w32(&mut b, s + 60, 3);
    let t = 336;
    w32(&mut b, t, 5);
    w32(&mut b, t + 4, 288);
    w32(&mut b, t + 8, 6);
    w32(&mut b, t + 12, 68);
    w32(&mut b, 624, 0x1b);
    w32(&mut b, 628, 24);
    b[632..648].copy_from_slice(&[1; 16]);
    w32(&mut b, 0x1000, 0xd503201f);
    for (o, v) in [(0, 7), (4, 1), (8, 0x2000)] {
        w32(&mut b, 0x1100 + o, v);
    }
    w64(
        &mut b,
        0x2000,
        (1 << 63) | (2 << 49) | (1 << 48) | (0x1234 << 32) | (2 << 51) | 8,
    );
    w64(&mut b, 0x2008, 0xabu64 << 43);
    b
}
fn der(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if data.len() < 128 {
        out.push(data.len() as u8);
    } else {
        let bytes = data.len().to_be_bytes();
        let first = bytes.iter().position(|&x| x != 0).unwrap();
        out.push(0x80 | (bytes.len() - first) as u8);
        out.extend_from_slice(&bytes[first..]);
    }
    out.extend_from_slice(data);
    out
}
fn input(decoded: &[u8]) -> (Vec<u8>, Source) {
    let mut body = vec![];
    for s in ["IM4P", "dcpf", "1"] {
        body.extend(der(0x16, s.as_bytes()));
    }
    body.extend(der(4, decoded));
    let container = der(0x30, &body);
    let source = Source {
        component: "RestoreDCP".into(),
        member: "firmware.im4p".into(),
        container_sha256: sha256(&container),
        payload_type: "dcpf".into(),
        description: "1".into(),
        decoded_bytes: decoded.len(),
        decoded_sha256: sha256(decoded),
    };
    (container, source)
}
fn prepare(decoded: &[u8]) -> Result<Prepared> {
    let (c, s) = input(decoded);
    prepare_im4p(&c, s, "fixture-build".into(), hardware(), Limits::default())
}
fn hardware() -> HardwareIdentity {
    HardwareIdentity {
        role: "external-display0".into(),
        compatible: "iop,ascwrap-v4".into(),
    }
}
fn context() -> pauth::Context {
    pauth::Context::new(123, pauth::Keys::from_words([1, 2], [3, 4], [5, 6], [7, 8]))
        .with_translation_regime(16)
}

#[test]
fn source_map_entry_zero_and_owned_staging() -> Result<()> {
    let decoded = fixture();
    let p = prepare(&decoded)?;
    assert_eq!(p.plan().thread.pc, 0);
    assert_eq!(p.plan().image_bytes, 0x2100);
    assert_eq!(
        p.plan().uuid.as_deref(),
        Some("01010101010101010101010101010101")
    );
    assert!(!p.plan().decode.signature_validated);
    let s = p.stage(0x800000, 0x3000)?;
    assert_eq!(s.placement().entry_physical_address, 0x800000);
    assert_eq!(&s.bytes()[..4], &decoded[0x1000..0x1004]);
    assert!(s.bytes()[0x1000..0x2000].iter().all(|&v| v == 0));
    assert!(s.bytes()[0x2010..].iter().all(|&v| v == 0));
    assert_eq!(
        s.placement().zeroes.iter().map(|r| r.bytes).sum::<u64>(),
        0x10f0
    );
    assert_eq!(s.placement().copies.len(), 2);
    let second = prepare(&decoded)?.stage(0x1000000, 0x2100)?;
    assert_eq!(second.placement().entry_physical_address, 0x1000000);
    assert_eq!(second.bytes(), s.bytes());
    Ok(())
}
#[test]
fn full_chains_rebase_and_sign_under_explicit_context() -> Result<()> {
    let s = prepare(&fixture())?.stage(0x800000, 0x3000)?;
    assert_eq!(s.plan().chains.pointers.len(), 2);
    let ctx = context();
    let expected = ctx.sign(pauth::Key::Da, 8, 0x1234_0000_0000_2000)?;
    let r = s.relocate(0, ctx, 16)?;
    let signed = u64::from_le_bytes(r.bytes()[0x2000..0x2008].try_into()?);
    assert_eq!(signed, expected);
    assert_eq!(
        u64::from_le_bytes(r.bytes()[0x2008..0x2010].try_into()?),
        0xab00_0000_0000_0000
    );
    assert_eq!(r.receipt().authenticated_pointer_count, 1);
    assert!(
        prepare(&fixture())?
            .stage(0x800000, 0x3000)?
            .relocate(0x1000, context(), 16)
            .is_err()
    );
    let missing = pauth::Context::new(123, pauth::Keys::from_ib_words(3, 4));
    assert!(
        prepare(&fixture())?
            .stage(0x800000, 0x3000)?
            .relocate(0, missing, 16)
            .is_err()
    );
    Ok(())
}
#[test]
fn integrity_placement_and_limits_fail_closed() -> Result<()> {
    let raw = fixture();
    let (c, mut s) = input(&raw);
    s.decoded_sha256 = "0".repeat(64);
    assert!(prepare_im4p(&c, s, "test".into(), hardware(), Limits::default()).is_err());
    let (c, mut s) = input(&raw);
    s.payload_type = "krnl".into();
    assert!(prepare_im4p(&c, s, "test".into(), hardware(), Limits::default()).is_err());
    for (base, bytes) in [
        (0, 0x3000),
        (1, 0x3000),
        (0x800000, 0x2000),
        (u64::MAX - 3, 0x3000),
    ] {
        assert!(prepare(&raw)?.stage(base, bytes).is_err());
    }
    let (c, s) = input(&raw);
    assert!(
        prepare_im4p(
            &c,
            s,
            "test".into(),
            hardware(),
            Limits {
                fixups: 1,
                ..Limits::default()
            }
        )
        .is_err()
    );
    Ok(())
}
#[test]
fn malformed_loads_and_chain_effects_are_refused() {
    // All mutations retain correct outer hashes, reaching structural validation.
    for (at, width, v) in [
        (12, 4, 2),
        (16, 4, 5),
        (20, 4, 608),
        (32 + 24, 8, u64::MAX),
        (264 + 24, 8, 0x800),
        (32 + 72 + 56, 4, 1),
        (32 + 72 + 64, 4, 0x12),
        (336 + 8, 4, 0),
        (336 + 272, 8, 0x1000),
        (0x1100, 4, 10),
        (0x1104, 4, 5),
        (0x1108, 4, 0x2004),
        (0x110c, 4, 1),
        (0x2000, 8, 1u64 << 62),
        (0x2000, 8, (1u64 << 63) | (1u64 << 51)),
        (0x2000, 8, 0x1800),
        (624, 4, 0x80000034),
    ] {
        let mut raw = fixture();
        if width == 4 {
            w32(&mut raw, at, v as u32);
        } else {
            w64(&mut raw, at, v);
        }
        assert!(
            prepare(&raw).is_err(),
            "accepted mutation {at:x} width {width} value {v:x}"
        );
    }
}

#[test]
#[ignore = "requires immutable original fixture directory; does not execute firmware"]
#[cfg(feature = "std")]
fn original_t6000_restore_firmware() -> Result<()> {
    let dir = std::env::var("STELA_COPROCESSOR_FIXTURE_DIR")
        .context("set STELA_COPROCESSOR_FIXTURE_DIR to immutable original inputs")?;
    let container = std::fs::read(std::path::Path::new(&dir).join("t600xdcp_restore.im4p"))?;
    let source = Source {
        component: "RestoreDCP".into(),
        member: "Firmware/dcp/t600xdcp_restore.im4p".into(),
        container_sha256: "9a071477954b6888a98fb801a1112ba8be4ff1dfe4f6fe84dc57580fa941ccb9".into(),
        payload_type: "dcpf".into(),
        description: "1".into(),
        decoded_bytes: 11685888,
        decoded_sha256: "976b952c0e36d34af7912b115feef2d3982053133055bb93bcbca54a423f0a10".into(),
    };
    let prepared = prepare_im4p(
        &container,
        source,
        "26A434".into(),
        hardware(),
        Limits::default(),
    )?;
    let p = prepared.plan();
    assert_eq!(p.cpu_subtype, 0x80000002);
    assert_eq!(p.thread.pc, 0);
    assert_eq!(p.uuid.as_deref(), Some("643ec3de5fef38769cd1ddeebc9a9e7e"));
    assert_eq!(
        (p.segments.len(), p.image_bytes, p.minimum_alignment),
        (4, 0xb24000, 0x100000)
    );
    assert_eq!(
        p.chains.starts,
        [
            0x801000, 0x8404f8, 0x9039c8, 0x95ede8, 0xa34168, 0xa41200, 0xb00050
        ]
    );
    assert_eq!(p.chains.pointers.len(), 26103);
    assert_eq!(
        p.chains
            .pointers
            .iter()
            .filter(|p| p.authentication.is_some())
            .count(),
        23858
    );
    let staged = prepared.stage(0x80000000, 0xc00000)?;
    assert_eq!(staged.placement().entry_physical_address, 0x80000000);
    assert!(staged.placement().zeroes.is_empty());
    let r = staged.relocate(0, context(), 16)?;
    assert_eq!(r.receipt().pointer_count, 26103);
    // Synthetic PAC keys test complete format handling; they are not original trust/key provenance.
    assert_eq!(r.receipt().authenticated_pointer_count, 23858);
    assert_eq!(r.bytes().len(), 0xb24000);
    assert_ne!(r.receipt().relocated_sha256, r.placement().staged_sha256);
    std::println!(
        "original source={} uuid={} image={:#x} pointers={}",
        r.plan().source.decoded_sha256,
        r.plan().uuid.as_deref().unwrap(),
        r.bytes().len(),
        r.receipt().pointer_count
    );
    Ok(())
}
