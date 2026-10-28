//! What the dry run knows about the input without asking the host: the
//! selected identity and its board's other identities, decoded with the
//! `plist` crate; IPSW members, read with the `zip` crate; and the global
//! tickets. Checks compare the host's answers against these.
use super::{
    image4::{self, Im4m, Property},
    tss,
};
use anyhow::{Context, Result, anyhow, bail, ensure};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs::File,
    io::{Cursor, Read, Seek, SeekFrom},
    path::PathBuf,
    rc::Rc,
};
use stela_cli::restore::archive;
use {stela_formats::payload::PayloadManifest, stela_runtime::restore::tss::Nonces};

/// Members read whole for comparison; larger ones are only streamed.
pub const SMALL: u64 = 96 << 20;

pub struct Ticket {
    pub path: String,
    pub bytes: Vec<u8>,
    pub manifest: Im4m,
}

/// An image Image4 would accept for a component: the IM4P typed as the
/// manifest digest covers it, and the ticket tag that covers it, if any.
pub struct Covered {
    pub image: Rc<Vec<u8>>,
    pub kind: String,
    pub retyped: bool,
    pub ticket: Option<&'static str>,
}

pub struct Ctx {
    pub ipsw: PathBuf,
    pub identity: plist::Dictionary,
    /// This board's `macOS Customer` identity, which restored names with
    /// `IsRecoveryOS`.
    pub recovery: Option<(usize, plist::Dictionary)>,
    pub inventory: PayloadManifest,
    pub zip: BTreeMap<String, (u64, bool)>,
    /// The IPSW's global AP ticket, or under `--tss` the synthetic signing
    /// service's personalization of it ([`Ctx::personalize`]).
    pub global: Option<Ticket>,
    pub cryptex: Option<Ticket>,
    pub ecid: u64,
    /// The nonces the AP ticket binds, once personalized.
    pub nonces: Option<Nonces>,
    pub full: bool,
    cache: HashMap<String, Rc<Vec<u8>>>,
}

fn number(v: Option<&plist::Value>) -> Option<u64> {
    match v? {
        plist::Value::String(s) => u64::from_str_radix(s.trim_start_matches("0x"), 16).ok(),
        plist::Value::Integer(i) => i.as_unsigned(),
        _ => None,
    }
}

impl Ctx {
    pub fn open(
        ipsw: PathBuf,
        inventory: PayloadManifest,
        index: usize,
        ecid: u64,
        full: bool,
    ) -> Result<Self> {
        let bytes = archive::read_member(&ipsw, "BuildManifest.plist", 64 << 20)?;
        let manifest = plist::Value::from_reader(Cursor::new(bytes))
            .context("BuildManifest.plist (plist crate)")?;
        let identities = manifest
            .as_dictionary()
            .and_then(|d| d.get("BuildIdentities"))
            .and_then(plist::Value::as_array)
            .context("BuildIdentities")?;
        let identity = identities
            .get(index)
            .and_then(plist::Value::as_dictionary)
            .with_context(|| format!("BuildIdentities[{index}]"))?
            .clone();
        let key = |d: &plist::Dictionary, k: &str| number(d.get(k));
        let recovery: Vec<_> = identities
            .iter()
            .enumerate()
            .filter_map(|(i, v)| Some((i, v.as_dictionary()?.clone())))
            .filter(|(_, d)| {
                info(d, "Variant").as_deref() == Some("macOS Customer")
                    && key(d, "ApChipID") == key(&identity, "ApChipID")
                    && key(d, "ApBoardID") == key(&identity, "ApBoardID")
            })
            .collect();
        let recovery = match recovery.len() {
            1 => recovery.into_iter().next(),
            _ => None,
        };
        let mut zip = BTreeMap::new();
        {
            let mut a = zip::ZipArchive::new(File::open(&ipsw)?)?;
            for i in 0..a.len() {
                let f = a.by_index_raw(i)?;
                zip.insert(
                    f.name().to_string(),
                    (f.size(), f.compression() == zip::CompressionMethod::Stored),
                );
            }
        }
        let mut ctx = Self {
            ipsw,
            identity,
            recovery,
            inventory,
            zip,
            global: None,
            cryptex: None,
            ecid,
            nonces: None,
            full,
            cache: HashMap::new(),
        };
        let class = info(&ctx.identity, "DeviceClass").context("DeviceClass")?;
        let variant = info(&ctx.identity, "MacOSVariant").context("MacOSVariant")?;
        for (cryptex, slot) in [(false, 0), (true, 1)] {
            let path = format!(
                "Firmware/Manifests/restore/{}{variant}/apticket.{class}.im4m",
                if cryptex { "cryptex1/" } else { "" }
            );
            if !ctx.zip.contains_key(&path) {
                continue;
            }
            let bytes = archive::read_member(&ctx.ipsw, &path, 1 << 20)?;
            let manifest = image4::im4m(&bytes).with_context(|| path.clone())?;
            let t = Some(Ticket {
                path,
                bytes,
                manifest,
            });
            if slot == 0 {
                ctx.global = t;
            } else {
                ctx.cryptex = t;
            }
        }
        Ok(ctx)
    }
    pub fn chosen(&self, recovery: bool) -> Option<&plist::Dictionary> {
        if recovery {
            self.recovery.as_ref().map(|(_, d)| d)
        } else {
            Some(&self.identity)
        }
    }
    pub fn components(&self, recovery: bool) -> Vec<String> {
        self.chosen(recovery)
            .and_then(|d| d.get("Manifest"))
            .and_then(plist::Value::as_dictionary)
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default()
    }
    pub fn component(&self, name: &str, recovery: bool) -> Option<&plist::Dictionary> {
        self.chosen(recovery)?
            .get("Manifest")?
            .as_dictionary()?
            .get(name)?
            .as_dictionary()
    }
    pub fn path(&self, name: &str, recovery: bool) -> Option<String> {
        Some(
            self.component(name, recovery)?
                .get("Info")?
                .as_dictionary()?
                .get("Path")?
                .as_string()?
                .to_string(),
        )
    }
    pub fn digest(&self, name: &str, recovery: bool) -> Option<Vec<u8>> {
        Some(
            self.component(name, recovery)?
                .get("Digest")?
                .as_data()?
                .to_vec(),
        )
    }
    pub fn flag(&self, name: &str, flag: &str) -> bool {
        self.component(name, false)
            .and_then(|c| c.get("Info"))
            .and_then(plist::Value::as_dictionary)
            .and_then(|i| i.get(flag))
            .and_then(plist::Value::as_boolean)
            .unwrap_or(false)
    }
    pub fn number(&self, key: &str) -> Option<u64> {
        number(self.identity.get(key))
    }
    pub fn member_size(&self, path: &str) -> Option<u64> {
        self.zip.get(path).map(|(n, _)| *n)
    }
    /// A member read independently of the host, whole.
    pub fn member(&mut self, path: &str) -> Result<Rc<Vec<u8>>> {
        if let Some(b) = self.cache.get(path) {
            return Ok(b.clone());
        }
        let size = self
            .member_size(path)
            .ok_or_else(|| anyhow!("{path} is not in the IPSW"))?;
        ensure!(size <= SMALL, "{path}: {size} bytes are not read whole");
        let bytes = Rc::new(archive::read_member(&self.ipsw, path, SMALL)?);
        if self.cache.len() > 64 {
            self.cache.clear();
        }
        self.cache.insert(path.to_string(), bytes.clone());
        Ok(bytes)
    }
    /// `len` bytes at `offset` of a stored member, straight from the file.
    pub fn stored_range(&self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>> {
        let mut a = zip::ZipArchive::new(File::open(&self.ipsw)?)?;
        let f = a.by_name(path)?;
        ensure!(
            f.compression() == zip::CompressionMethod::Stored,
            "{path} is not stored"
        );
        ensure!(
            offset + len as u64 <= f.size(),
            "{path}: range past the end"
        );
        let start = f.data_start();
        drop(f);
        let mut out = vec![0; len];
        let mut file = File::open(&self.ipsw)?;
        file.seek(SeekFrom::Start(start + offset))?;
        file.read_exact(&mut out)?;
        Ok(out)
    }
    pub fn ticket_for(&self, name: &str) -> Option<&Ticket> {
        if name.starts_with("Cryptex1,") {
            self.cryptex.as_ref()
        } else {
            self.global.as_ref()
        }
    }
    /// The image Image4 accepts for `name`: its file, typed so that SHA-384
    /// of the whole IM4P is the manifest digest. The candidate types are the
    /// file's own, the global ticket's tags for that digest, and the restore
    /// counterpart `r` + the first three letters (`sepi` → `rsep`).
    pub fn covered(&mut self, name: &str, recovery: bool) -> Result<Covered> {
        let path = self
            .path(name, recovery)
            .ok_or_else(|| anyhow!("{name} has no Path"))?;
        let digest = self
            .digest(name, recovery)
            .ok_or_else(|| anyhow!("{name} has no Digest"))?;
        let file = self.member(&path)?;
        let header = image4::im4p(&file).map_err(|e| anyhow!("{path}: {e}"))?;
        let mut candidates = vec![header.kind.clone()];
        let tags = self
            .ticket_for(name)
            .map(|t| t.manifest.tags_with(&digest))
            .unwrap_or_default();
        candidates.extend(tags);
        candidates.push(format!("r{}", &header.kind[..3]));
        for kind in candidates {
            let image = if kind == header.kind {
                file.clone()
            } else {
                Rc::new(image4::retype(&file, &kind)?)
            };
            if image4::sha384(&image) != digest {
                continue;
            }
            let ticket = self
                .ticket_for(name)
                .filter(|t| t.manifest.covers(&kind, &digest))
                .map(|_| {
                    if name.starts_with("Cryptex1,") {
                        "cryptex1 apticket"
                    } else {
                        "apticket"
                    }
                });
            return Ok(Covered {
                retyped: kind != header.kind,
                image,
                kind,
                ticket,
            });
        }
        bail!("{name}: the manifest digest covers no candidate type of {path}")
    }
    /// Replace the global AP ticket with the synthetic signing service's
    /// personalization of it for this ECID and `nonces`: the root ticket a
    /// `--tss` host serves and stitches.
    pub fn personalize(&mut self, nonces: Nonces) -> Result<Vec<u8>> {
        let global = self.global.as_mut().ok_or_else(|| anyhow!("no apticket"))?;
        let bytes = tss::personalize(&global.manifest, self.ecid, &nonces);
        global.manifest = image4::im4m(&bytes)?;
        global.path = format!("the synthetic personalization of {}", global.path);
        global.bytes = bytes.clone();
        self.nonces = Some(nonces);
        Ok(bytes)
    }
    /// An AP root ticket: personalized for this ECID and nonces once
    /// [`Ctx::personalize`]d, else global.
    pub fn check_root(&self, m: &Im4m) -> Result<()> {
        let Some(nonces) = &self.nonces else {
            return self.check_ticket(m, None);
        };
        self.check_ticket(m, Some(self.ecid))?;
        for (tag, sent) in [("BNCH", &nonces.ap[..]), ("snon", &nonces.sep[..])] {
            ensure!(
                m.manp(tag) == Some(&Property::Data(sent.to_vec())),
                "the root ticket's {tag} is not the restore's nonce"
            );
        }
        Ok(())
    }
    /// A ticket for this board: chip, board and security domain match the
    /// identity; a global one names no ECID or nonce.
    pub fn check_ticket(&self, m: &Im4m, ecid: Option<u64>) -> Result<()> {
        for (tag, key) in [
            ("CHIP", "ApChipID"),
            ("BORD", "ApBoardID"),
            ("SDOM", "ApSecurityDomain"),
        ] {
            let got = m.manp(tag).and_then(Property::integer);
            ensure!(
                got == self.number(key),
                "ticket MANP {tag}={got:x?}, identity {key}={:x?}",
                self.number(key)
            );
        }
        let named = m.manp("ECID").and_then(Property::integer);
        match ecid {
            None => {
                ensure!(named.is_none(), "a global ticket names ECID {named:x?}");
                for (tag, props) in &m.entries {
                    ensure!(
                        !props.contains_key("BNCH") && !props.contains_key("snon"),
                        "a global ticket binds a nonce in {tag}"
                    );
                }
            }
            Some(ecid) => ensure!(
                named == Some(ecid),
                "ticket ECID {named:x?}, device {ecid:x}"
            ),
        }
        Ok(())
    }
    /// Check an IMG4 the host sent for `name` against what Image4 accepts.
    pub fn check_img4(&mut self, name: &str, recovery: bool, bytes: &[u8]) -> Result<String> {
        let (payload, ticket) = image4::img4(bytes)?;
        let want = self.covered(name, recovery)?;
        let kind = image4::im4p(payload)?.kind;
        ensure!(
            payload == want.image.as_slice(),
            "IM4P typed {kind} differs from the image the manifest digest covers (typed {})",
            want.kind
        );
        let m = image4::im4m(ticket)?;
        match name.starts_with("Cryptex1,") {
            true => self.check_ticket(&m, None)?,
            false => self.check_root(&m)?,
        }
        let digest = image4::sha384(payload);
        ensure!(
            m.covers(&kind, &digest),
            "the stitched ticket has no {kind} DGST for the IM4P"
        );
        let expected = self.ticket_for(name).map(|t| t.bytes.as_slice());
        ensure!(
            Some(ticket) == expected,
            "the stitched ticket is not the AP or cryptex1 root ticket"
        );
        Ok(format!(
            "IMG4 {kind}{} covered by the {}",
            if want.retyped { " (retyped)" } else { "" },
            want.ticket.unwrap_or("ticket")
        ))
    }
}

pub fn info(d: &plist::Dictionary, key: &str) -> Option<String> {
    Some(
        d.get("Info")?
            .as_dictionary()?
            .get(key)?
            .as_string()?
            .to_string(),
    )
}

/// `BTreeSet` of a plist array of strings.
pub fn strings(v: Option<&plist::Value>) -> Option<BTreeSet<String>> {
    v?.as_array()?
        .iter()
        .map(|s| s.as_string().map(str::to_string))
        .collect()
}
