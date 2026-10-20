//! The BootabilityBundle archive restored unpacks: odc cpio, as the public
//! host writes it, each entry an IPSW member under
//! `BootabilityBundle/Restore/Bootability/` plus the bundle's trust cache.
use super::context::Ctx;
use anyhow::{Context, Result, ensure};
use std::collections::BTreeSet;

const PREFIX: &str = "BootabilityBundle/Restore/Bootability/";
const TRUST_CACHE: &str = "BootabilityBundle/Restore/Firmware/Bootability.dmg.trustcache";

fn octal(field: &[u8]) -> Result<u64> {
    u64::from_str_radix(std::str::from_utf8(field)?, 8).context("cpio octal field")
}

pub fn check(ctx: &mut Ctx, bytes: &[u8]) -> Result<String> {
    let mut at = 0;
    let mut seen = BTreeSet::new();
    loop {
        ensure!(at + 76 <= bytes.len(), "cpio header past the end at {at}");
        let h = &bytes[at..at + 76];
        ensure!(&h[..6] == b"070707", "cpio magic at {at}");
        let mode = octal(&h[18..24])?;
        let names = octal(&h[59..65])? as usize;
        let size = octal(&h[65..76])? as usize;
        let name_at = at + 76;
        ensure!(
            names >= 1 && name_at + names <= bytes.len(),
            "cpio name at {at}"
        );
        ensure!(
            bytes[name_at + names - 1] == 0,
            "cpio name is not terminated"
        );
        let name = std::str::from_utf8(&bytes[name_at..name_at + names - 1])?.to_string();
        let data_at = name_at + names;
        ensure!(
            data_at + size <= bytes.len(),
            "cpio data of {name} past the end"
        );
        if name == "TRAILER!!!" {
            ensure!(data_at == bytes.len(), "bytes after the cpio trailer");
            break;
        }
        let member = if name == "Bootability.trustcache" {
            TRUST_CACHE.to_string()
        } else {
            let dir = mode & 0o170000 == 0o040000;
            format!("{PREFIX}{name}{}", if dir { "/" } else { "" })
        };
        let listed = ctx.member_size(&member);
        ensure!(listed.is_some(), "{name}: no IPSW member {member}");
        if size > 0 {
            let want = ctx.member(&member)?;
            ensure!(
                &bytes[data_at..data_at + size] == want.as_slice(),
                "{name}: bytes differ from {member}"
            );
        }
        seen.insert(member);
        at = data_at + size;
    }
    let expected: BTreeSet<_> = ctx
        .zip
        .keys()
        .filter(|k| (k.starts_with(PREFIX) && k.len() > PREFIX.len()) || *k == TRUST_CACHE)
        .cloned()
        .collect();
    let missing: Vec<_> = expected.difference(&seen).collect();
    ensure!(missing.is_empty(), "cpio lacks {missing:?}");
    Ok(format!(
        "odc cpio of {} IPSW entries, bytes unchanged",
        seen.len()
    ))
}
