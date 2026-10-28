//! Reproducible vendor resources selected by exact observed consumer requests.
//! Firmware is downloaded separately; no vendor image is embedded here.
use super::{
    Error, MAX_TOTAL_BYTES, fail,
    requirements::{Inventory, Request},
};
use alloc::{format, vec::Vec};

pub const LINUX_FIRMWARE: &str = "https://gitlab.com/kernel-firmware/linux-firmware";
pub const REALTEK_RELEASE: &str = "20250917";
pub const REALTEK_REVISION: &str = "add225168d0d1ba4c174d5eb15272b53de01ad5a";
pub const INTEL_RSA_REVISION: &str = "711d3297bac870af42088a467459a0634c1970ca";
/// wireless-regdb, the source of the regulatory database every Wi-Fi
/// adapter's scans and transmissions answer to.
pub const WIRELESS_REGDB: &str =
    "https://git.kernel.org/pub/scm/linux/kernel/git/wens/wireless-regdb.git";
const KERNEL_ORG_GIT: &str = "https://git.kernel.org/";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Artifact {
    pub source: &'static str,
    pub revision: &'static str,
    pub member: &'static str,
    pub length: usize,
    pub sha256: &'static str,
}

impl Artifact {
    /// The member at the pinned revision: cgit's `plain` form on
    /// git.kernel.org, GitLab's `raw` form elsewhere.
    pub fn url(&self) -> alloc::string::String {
        if self.source.starts_with(KERNEL_ORG_GIT) {
            format!("{}/plain/{}?h={}", self.source, self.member, self.revision)
        } else {
            format!("{}/-/raw/{}/{}", self.source, self.revision, self.member)
        }
    }
    pub fn verify(&self, bytes: &[u8]) -> Result<(), Error> {
        use sha2::{Digest, Sha256};
        if bytes.len() != self.length || hex::encode(Sha256::digest(bytes)) != self.sha256 {
            return Err(Error(format!(
                "pinned host firmware artifact differs: {}",
                self.member
            )));
        }
        Ok(())
    }
}

const LICENSE: Artifact = Artifact {
    source: LINUX_FIRMWARE,
    revision: REALTEK_REVISION,
    member: "LICENSE.r8169",
    length: 219,
    sha256: "f9689ba2640d61e7b4527ad84cbfa6a9f0ec11484e2c9f6b5500197e22c27ecd",
};

#[derive(Clone, Copy, Debug)]
pub struct Recipe {
    pub image: Artifact,
    pub license: &'static Artifact,
    // The ordered consumer predicates mirror the currently implemented native
    // Realtek revision table. They validate an observed XID, never manufacture
    // manifest bindings for all values a mask could match.
    consumer: Consumer,
}

#[derive(Clone, Copy, Debug)]
enum Consumer {
    Realtek { mask: u16, value: u16 },
    IntelRsa,
}

const fn realtek(
    member: &'static str,
    length: usize,
    sha256: &'static str,
    xid_mask: u16,
    xid_value: u16,
) -> Recipe {
    Recipe {
        image: Artifact {
            source: LINUX_FIRMWARE,
            revision: REALTEK_REVISION,
            member,
            length,
            sha256,
        },
        license: &LICENSE,
        consumer: Consumer::Realtek {
            mask: xid_mask,
            value: xid_value,
        },
    }
}

pub const REALTEK: &[Recipe] = &[
    realtek(
        "rtl_nic/rtl8411-1.fw",
        2112,
        "e66a3183787c80987e1e36c9f7d4b2c3cd5d976640b83f462702f914febc4b38",
        0x7c8,
        0x488,
    ),
    realtek(
        "rtl_nic/rtl8168f-2.fw",
        1232,
        "5586b2093502f7dec762f23091fa90d6d8731e7d873509072ce2eae23ab8ee99",
        0x7cf,
        0x481,
    ),
    realtek(
        "rtl_nic/rtl8168f-1.fw",
        3424,
        "ed3794c651d38b807168c7c49431bb8036922b16766588c520a20287f277615d",
        0x7cf,
        0x480,
    ),
    realtek(
        "rtl_nic/rtl8168e-1.fw",
        5500,
        "c38d6818a99336c8e43883bbc136f9fab3b1b470ec0e86c61bf5dac617fe94bd",
        0x7cf,
        0x2c1,
    ),
    realtek(
        "rtl_nic/rtl8168e-2.fw",
        3920,
        "0a489929b270df1533645a75d55ff357fd66e42057aa4e198ab738930de39386",
        0x7c8,
        0x2c0,
    ),
    realtek(
        "rtl_nic/rtl8168d-1.fw",
        1492,
        "ded779f55b3fc5bb8576b2d2b6c724581c72160b3c2f88e33b42dc6c2c4e70b0",
        0x7cf,
        0x281,
    ),
    realtek(
        "rtl_nic/rtl8168d-2.fw",
        1324,
        "35dd68c01a7b24f6e554bd2c0b9cf57cf962a826651f66e75ffcea37cf2c3bb9",
        0x7c8,
        0x280,
    ),
    realtek(
        "rtl_nic/rtl8168e-3.fw",
        3872,
        "1287fdd82ff2f60d75c9970c108b49cfd11456ad3fe29c9666b8539a35777dbf",
        0x7c8,
        0x2c8,
    ),
];

const INTEL_LICENSE: Artifact = Artifact {
    source: LINUX_FIRMWARE,
    revision: INTEL_RSA_REVISION,
    member: "LICENCE.ibt_firmware",
    length: 2040,
    sha256: "5181b0b51efc79d5acb2c9bb92042878fdbad97a92114d4ab5e32e2b5b52fce4",
};
pub const INTEL_RSA: &[Recipe] = &[
    Recipe {
        image: Artifact {
            source: LINUX_FIRMWARE,
            revision: INTEL_RSA_REVISION,
            member: "intel/ibt-20-1-3.sfi",
            length: 716180,
            sha256: "1c8f0dac48d108c0d36f4297119857465d2830b35f3b4f697995f94a32f36db0",
        },
        license: &INTEL_LICENSE,
        consumer: Consumer::IntelRsa,
    },
    Recipe {
        image: Artifact {
            source: LINUX_FIRMWARE,
            revision: INTEL_RSA_REVISION,
            member: "intel/ibt-20-1-3.ddc",
            length: 70,
            sha256: "597f26161c81a2ba899d42c1aafdedc427b20b00cb6ce157587814166ff178a0",
        },
        license: &INTEL_LICENSE,
        consumer: Consumer::IntelRsa,
    },
];

/// Pinned wireless-regdb releases of `regulatory.db`, each with its ISC
/// LICENSE, from [`WIRELESS_REGDB`].
pub const REGULATORY: &[Recipe] = &[];

/// The drivers' request for the version-20 database
/// (`stela_drivers::net::wifi::regulatory::database::REQUIREMENT`).
fn select_regulatory(request: &Request) -> Option<&'static Recipe> {
    if request.target.hardware != "wireless-regdb" || request.target.revision != "v20" {
        return None;
    }
    REGULATORY
        .iter()
        .find(|recipe| recipe.image.member == request.name)
}

fn hex_field(value: &str, digits: usize) -> bool {
    value.len() == digits
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn select_realtek(request: &Request) -> Option<&'static Recipe> {
    if !matches!(request.target.hardware.as_str(), "10ec:8161" | "10ec:8168") {
        return None;
    }
    let xid = request
        .target
        .revision
        .strip_prefix("xid-")
        .filter(|s| hex_field(s, 3))
        .and_then(|s| u16::from_str_radix(s, 16).ok())
        .filter(|xid| xid & !0xfcf == 0)?;
    REALTEK.iter().find(|recipe| matches!(recipe.consumer, Consumer::Realtek { mask, value } if xid & mask == value))
        .filter(|recipe| recipe.image.member == request.name)
}

fn select_intel_rsa(request: &Request) -> Option<&'static Recipe> {
    let usb: Vec<_> = request.target.hardware.split(':').collect();
    if usb.len() != 4
        || usb[0] != "usb"
        || usb[1] != "8087"
        || !matches!(usb[2], "0a2b" | "0aaa" | "0025" | "0026" | "0029")
        || !hex_field(usb[3], 4)
    {
        return None;
    }
    // These filenames are selected only by observed variant0x14/hw1/fw3.
    // Retain every other exact boot-loader field verbatim in the manifest.
    let fields: Vec<_> = request.target.revision.split(':').collect();
    if fields.len() != 11 || fields[..4] != ["37", "14", "01", "03"] {
        return None;
    }
    for (field, (prefix, count, digits)) in fields[4..].iter().zip([
        ("dev-", 1, 4),
        ("otp-", 3, 2),
        ("key-", 2, 2),
        ("locks-", 3, 2),
        ("min-", 3, 2),
        ("loader-", 4, 2),
        ("unlock-", 1, 2),
    ]) {
        let parts: Vec<_> = field.strip_prefix(prefix)?.split('-').collect();
        if parts.len() != count || parts.iter().any(|part| !hex_field(part, digits)) {
            return None;
        }
    }
    INTEL_RSA.iter().find(|recipe| {
        recipe.image.member == request.name && matches!(recipe.consumer, Consumer::IntelRsa)
    })
}

#[derive(Clone, Debug)]
pub struct Selection {
    pub request: Request,
    pub recipe: &'static Recipe,
}

pub struct Plan {
    selections: Vec<Selection>,
}

impl Plan {
    pub fn selections(&self) -> &[Selection] {
        &self.selections
    }
    pub fn select(inventory: &Inventory) -> Result<Self, Error> {
        let mut selections = Vec::with_capacity(inventory.requests().len());
        let mut total = 0usize;
        for request in inventory.requests() {
            let target = &request.target;
            if target.board.is_some() {
                return Err(fail(
                    "no pinned recipe for the exact observed host firmware target",
                ));
            }
            let recipe = match target.driver.as_str() {
                "realtek" => select_realtek(request),
                "intel-bluetooth-usb-rsa" => select_intel_rsa(request),
                "wifi-regulatory" => select_regulatory(request),
                _ => None,
            }.ok_or_else(|| fail("no pinned recipe for the exact observed firmware driver/hardware/revision/name"))?;
            if request.minimum_bytes > recipe.image.length {
                return Err(fail(
                    "pinned firmware is shorter than the driver's requirement",
                ));
            }
            total = total
                .checked_add(recipe.image.length)
                .filter(|n| *n <= MAX_TOTAL_BYTES)
                .ok_or_else(|| fail("planned host firmware exceeds 64 MiB"))?;
            selections.push(Selection {
                request: request.clone(),
                recipe,
            });
        }
        Ok(Self { selections })
    }

    /// Exact immutable artifacts to fetch. A shared license is fetched once.
    pub fn artifacts(&self) -> Vec<&'static Artifact> {
        let mut artifacts = Vec::new();
        for selection in &self.selections {
            for artifact in [&selection.recipe.image, selection.recipe.license] {
                if !artifacts.contains(&artifact) {
                    artifacts.push(artifact);
                }
            }
        }
        artifacts
    }

    /// Fetch/validate every pinned artifact before constructing anything that
    /// can be published. The caller owns transport/cache policy; no alternate
    /// source, member, target or firmware revision is tried on failure.
    #[cfg(feature = "std")]
    pub fn package(
        &self,
        mut fetch: impl FnMut(&Artifact) -> Result<Vec<u8>, Error>,
    ) -> Result<super::Package, Error> {
        let artifacts = self.artifacts();
        let fetched = artifacts
            .iter()
            .map(|artifact| {
                let bytes = fetch(artifact)?;
                artifact.verify(&bytes)?;
                Ok(bytes)
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let bytes_for = |artifact: &Artifact| -> &[u8] {
            &fetched[artifacts
                .iter()
                .position(|candidate| **candidate == *artifact)
                .expect("planned artifact")]
        };
        let mut files = Vec::with_capacity(self.selections.len());
        let images = self.selections.iter().enumerate().map(|(index, selection)| {
            let image = selection.recipe.image;
            files.push(bytes_for(&image).to_vec());
            serde_json::json!({"name":selection.request.name,"path":format!("{index}.bin"),
                "target":selection.request.target,"length":image.length,"sha256":image.sha256,
                "provenance":{"source":image.source,"revision":image.revision,"member":image.member,"license":format!("{}{}", super::package::NOTICE_MARKER, selection.recipe.license.member)}})
        }).collect::<Vec<_>>();
        let mut notices = Vec::new();
        let mut notice_records = Vec::new();
        for artifact in artifacts.iter().filter(|artifact| {
            self.selections
                .iter()
                .any(|selection| selection.recipe.license == **artifact)
        }) {
            let name = format!("license-{}.txt", notices.len());
            notices.push((name.clone(), bytes_for(artifact).to_vec()));
            notice_records.push(serde_json::json!({"path":name,"source":artifact.source,"revision":artifact.revision,
                "member":artifact.member,"length":artifact.length,"sha256":artifact.sha256}));
        }
        let notice =
            serde_json::to_vec_pretty(&serde_json::json!({"schema":1,"notices":notice_records}))
                .map_err(|e| Error(format!("firmware notices: {e}")))?;
        notices.push(("provenance.json".into(), notice));
        let manifest = serde_json::to_vec_pretty(&serde_json::json!({"schema":1,"images":images}))
            .map_err(|e| Error(format!("firmware manifest: {e}")))?;
        super::Package::assembled(manifest, files, notices)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn inventory(name: &str, hardware: &str, revision: &str, board: Option<&str>) -> Inventory {
        Inventory::parse(&serde_json::to_vec(&serde_json::json!({"schema":1,"complete":true,"requirements":[{
            "name":name,"target":{"driver":"realtek","hardware":hardware,"revision":revision,"board":board},"minimum_bytes":4
        }]})).unwrap()).unwrap()
    }
    #[test]
    fn recipes_select_only_observed_exact_bindings_without_xid_expansion() {
        for (name, revision) in [
            ("rtl_nic/rtl8168d-1.fw", "xid-281"),
            ("rtl_nic/rtl8168d-2.fw", "xid-282"),
            ("rtl_nic/rtl8168e-3.fw", "xid-2c9"),
        ] {
            let selected = Plan::select(&inventory(name, "10ec:8168", revision, None)).unwrap();
            assert_eq!(selected.selections.len(), 1);
            assert_eq!(selected.selections[0].request.target.revision, revision);
            assert_eq!(selected.selections[0].recipe.image.member, name);
            assert_eq!(selected.artifacts().len(), 2);
            assert!(
                selected.selections[0]
                    .recipe
                    .image
                    .url()
                    .contains(REALTEK_REVISION)
            );
        }
    }
    #[test]
    fn recipes_refuse_wrong_hardware_board_revision_name_and_no_fallback() {
        for (name, hardware, revision, board) in [
            ("rtl_nic/rtl8168e-3.fw", "10ec:8169", "xid-2c8", None),
            (
                "rtl_nic/rtl8168e-3.fw",
                "10ec:8168",
                "xid-2c8",
                Some("board"),
            ),
            ("rtl_nic/rtl8168e-3.fw", "10ec:8168", "xid-281", None),
            ("rtl_nic/rtl8168d-2.fw", "10ec:8168", "xid-281", None),
            ("rtl_nic/rtl8168e-2.fw", "10ec:8168", "xid-2c8", None),
            ("rtl_nic/rtl8168e-3.fw", "10ec:8168", "xid-2C8", None),
        ] {
            assert!(Plan::select(&inventory(name, hardware, revision, board)).is_err());
        }
        assert!(LICENSE.verify(b"changed license").is_err());
    }

    #[test]
    fn kernel_org_artifacts_use_cgit_plain_urls_and_an_unpinned_regdb_is_refused() {
        let artifact = Artifact {
            source: WIRELESS_REGDB,
            revision: "master-2025-01-01",
            member: "regulatory.db",
            length: 1,
            sha256: "00",
        };
        assert_eq!(
            artifact.url(),
            "https://git.kernel.org/pub/scm/linux/kernel/git/wens/wireless-regdb.git/plain/regulatory.db?h=master-2025-01-01"
        );
        assert_eq!(
            LICENSE.url(),
            format!("{LINUX_FIRMWARE}/-/raw/{REALTEK_REVISION}/LICENSE.r8169")
        );
        let value = serde_json::json!({"schema":1,"complete":true,"requirements":[{
            "name":"regulatory.db", "target":{"driver":"wifi-regulatory","hardware":"wireless-regdb","revision":"v20","board":null},"minimum_bytes":8
        }]});
        let inventory = Inventory::parse(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(
            Plan::select(&inventory).is_ok(),
            REGULATORY
                .iter()
                .any(|recipe| recipe.image.member == "regulatory.db")
        );
    }

    #[test]
    fn intel_rsa_recipes_retain_complete_observed_usb_and_loader_identity() {
        let revision = "37:14:01:03:dev-0005:otp-00-00-00:key-00-00:locks-00-00-00:min-00-00-00:loader-01-1e-1a-00:unlock-00";
        let value = serde_json::json!({"schema":1,"complete":true,"requirements":[{
            "name":"intel/ibt-20-1-3.sfi", "target":{"driver":"intel-bluetooth-usb-rsa","hardware":"usb:8087:0029:0001","revision":revision,"board":null},"minimum_bytes":645
        }]});
        let observed = Inventory::parse(&serde_json::to_vec(&value).unwrap()).unwrap();
        let plan = Plan::select(&observed).unwrap();
        assert_eq!(plan.selections()[0].request.target.revision, revision);
        assert_eq!(plan.selections()[0].recipe.image.length, 716180);
        assert_eq!(
            plan.selections()[0].recipe.image.revision,
            INTEL_RSA_REVISION
        );
        for (pointer, changed) in [
            ("/requirements/0/name", "intel/ibt-20-1-4.sfi"),
            ("/requirements/0/target/hardware", "usb:8086:0029:0001"),
            ("/requirements/0/target/hardware", "usb:8087:ffff:0001"),
            ("/requirements/0/target/revision", "37:14:01:04"),
            ("/requirements/0/target/board", "some-board"),
        ] {
            let mut changed_value = value.clone();
            *changed_value.pointer_mut(pointer).unwrap() = serde_json::json!(changed);
            let changed = Inventory::parse(&serde_json::to_vec(&changed_value).unwrap()).unwrap();
            assert!(Plan::select(&changed).is_err());
        }
        let mut other_loader = value.clone();
        other_loader["requirements"][0]["target"]["revision"] =
            serde_json::json!(revision.replace("dev-0005", "dev-0006"));
        let other = Inventory::parse(&serde_json::to_vec(&other_loader).unwrap()).unwrap();
        let other = Plan::select(&other).unwrap();
        assert_ne!(
            plan.selections()[0].request.target,
            other.selections()[0].request.target
        );
        assert_eq!(
            other.selections()[0].request.target.revision,
            revision.replace("dev-0005", "dev-0006")
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn generated_package_validates_notices_and_publishes_them_before_manifest() {
        const SHA: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        static NOTICE: Artifact = Artifact {
            source: "https://vendor.invalid",
            revision: "synthetic-v1",
            member: "NOTICE",
            length: 3,
            sha256: SHA,
        };
        static SYNTHETIC: Recipe = Recipe {
            image: Artifact {
                source: "https://vendor.invalid",
                revision: "synthetic-v1",
                member: "fixture.bin",
                length: 3,
                sha256: SHA,
            },
            license: &NOTICE,
            consumer: Consumer::Realtek { mask: 0, value: 0 },
        };
        let request = inventory("fixture.bin", "10ec:8168", "xid-2c8", None).requests()[0].clone();
        let plan = Plan {
            selections: alloc::vec![Selection {
                request,
                recipe: &SYNTHETIC
            }],
        };
        assert!(
            plan.package(|artifact| Ok(if artifact.member == "NOTICE" {
                b"bad".to_vec()
            } else {
                b"abc".to_vec()
            }))
            .is_err()
        );
        let package = plan.package(|_| Ok(b"abc".to_vec())).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("firmware");
        let mut before_manifest = false;
        package
            .publish_checkpointed(&target, |path| {
                if path.file_name().is_some_and(|name| name == "manifest.json") {
                    let objects = std::fs::read_dir(target.join("objects"))
                        .unwrap()
                        .next()
                        .unwrap()
                        .unwrap()
                        .path();
                    assert_eq!(
                        std::fs::read(objects.join("license-0.txt")).unwrap(),
                        b"abc"
                    );
                    assert!(objects.join("provenance.json").is_file());
                    assert!(!target.join("manifest.json").exists());
                    before_manifest = true;
                }
                Ok(())
            })
            .unwrap();
        assert!(before_manifest);
        assert_eq!(
            super::super::Package::read(&target).unwrap().inventory(),
            (1, 3)
        );
        let original_manifest = std::fs::read(target.join("manifest.json")).unwrap();
        let parsed = super::super::Manifest::parse(&original_manifest).unwrap();
        let objects = target
            .join(parsed.images[0].path)
            .parent()
            .unwrap()
            .to_path_buf();
        let original_notice = std::fs::read(objects.join("license-0.txt")).unwrap();
        let original_index = std::fs::read(objects.join("provenance.json")).unwrap();
        let imported = super::super::Package::read(&target).unwrap();
        let destination = dir.path().join("imported");
        imported.publish(&destination).unwrap();
        let imported_manifest = std::fs::read(destination.join("manifest.json")).unwrap();
        let imported = super::super::Manifest::parse(&imported_manifest).unwrap();
        let imported_objects = destination
            .join(imported.images[0].path)
            .parent()
            .unwrap()
            .to_path_buf();
        assert_eq!(
            std::fs::read(imported_objects.join("license-0.txt")).unwrap(),
            original_notice
        );
        assert_eq!(
            std::fs::read(imported_objects.join("provenance.json")).unwrap(),
            original_index
        );
        assert_eq!(
            parsed.images[0].provenance.license,
            imported.images[0].provenance.license
        );
        assert_eq!(parsed.images[0].sha256, imported.images[0].sha256);
        assert_eq!(
            super::super::Package::read(&destination)
                .unwrap()
                .inventory(),
            (1, 3)
        );
        std::fs::remove_file(objects.join("provenance.json")).unwrap();
        assert!(super::super::Package::read(&target).is_err());
        std::fs::write(objects.join("provenance.json"), &original_index).unwrap();
        std::fs::write(objects.join("license-0.txt"), b"bad").unwrap();
        assert!(super::super::Package::read(&target).is_err());
        std::fs::write(objects.join("license-0.txt"), &original_notice).unwrap();
        for (key, value) in [
            ("path", "../escape.txt"),
            ("member", "another-license"),
            (
                "sha256",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
        ] {
            let mut changed: serde_json::Value = serde_json::from_slice(&original_index).unwrap();
            changed["notices"][0][key] = serde_json::json!(value);
            std::fs::write(
                objects.join("provenance.json"),
                serde_json::to_vec(&changed).unwrap(),
            )
            .unwrap();
            assert!(super::super::Package::read(&target).is_err(), "{key}");
        }
        std::fs::write(objects.join("provenance.json"), &original_index).unwrap();
        #[cfg(unix)]
        {
            std::fs::remove_file(objects.join("license-0.txt")).unwrap();
            std::os::unix::fs::symlink(objects.join("0.bin"), objects.join("license-0.txt"))
                .unwrap();
            assert!(super::super::Package::read(&target).is_err());
        }
    }
}
