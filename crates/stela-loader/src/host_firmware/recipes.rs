//! Reproducible vendor resources selected by exact observed consumer requests.
//! Firmware is downloaded separately; no vendor image is embedded here.
use super::{
    Error, MAX_TOTAL_BYTES, fail,
    requirements::{Inventory, Request},
};
use alloc::{format, vec::Vec};
use stela_driver_core::firmware::{Requirement, Target};

pub const LINUX_FIRMWARE: &str = "https://gitlab.com/kernel-firmware/linux-firmware";
pub const REALTEK_RELEASE: &str = "20250917";
pub const REALTEK_REVISION: &str = "add225168d0d1ba4c174d5eb15272b53de01ad5a";
pub const INTEL_RSA_REVISION: &str = "711d3297bac870af42088a467459a0634c1970ca";
pub const WIFI_FIRMWARE_REVISION: &str = "59f9fc2ef8d1e312d2a613d4e1ffad2ff31a0a01";
pub const GSP_REVISION: &str = "1987bb2044a6c2d68c39d01c360bdbe17f1eb60c";
/// The GSP-RM release nouveau's newest interface takes.
const GSP_RELEASE: &str = "570.144";
/// The files of a release, of which each chip family has some.
const GSP_KINDS: [&str; 5] = [
    "booter_load",
    "booter_unload",
    "bootloader",
    "gen_bootloader",
    "gsp",
];
/// wireless-regdb, the source of the regulatory database every Wi-Fi
/// adapter's scans and transmissions answer to.
pub const WIRELESS_REGDB: &str =
    "https://git.kernel.org/pub/scm/linux/kernel/git/wens/wireless-regdb.git";
pub const WIRELESS_REGDB_RELEASE: &str = "master-2026-09-03";
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
        use stela_crypto::{Sha256, digest::Digest};
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
    Wifi,
    Nouveau,
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

const WIFI_FIRMWARE_LICENSE: Artifact = Artifact {
    source: LINUX_FIRMWARE,
    revision: WIFI_FIRMWARE_REVISION,
    member: "LICENSES/LICENCE.iwlwifi_firmware",
    length: 2046,
    sha256: "16d5040c7cf851fc693b7542e20870935b99802533ea1bfd231c377a2305e5c5",
};
const MEDIATEK_LICENSE: Artifact = Artifact {
    source: LINUX_FIRMWARE,
    revision: WIFI_FIRMWARE_REVISION,
    member: "LICENSES/LICENCE.mediatek",
    length: 561,
    sha256: "a90d3f66704d85889945fec5525ea77622549da83aced1aac99828383f8f1805",
};

const fn wifi(
    member: &'static str,
    length: usize,
    sha256: &'static str,
    license: &'static Artifact,
) -> Recipe {
    Recipe {
        image: Artifact {
            source: LINUX_FIRMWARE,
            revision: WIFI_FIRMWARE_REVISION,
            member,
            length,
            sha256,
        },
        license,
        consumer: Consumer::Wifi,
    }
}
const fn intel_wifi(member: &'static str, length: usize, sha256: &'static str) -> Recipe {
    wifi(member, length, sha256, &WIFI_FIRMWARE_LICENSE)
}
const fn mediatek_wifi(member: &'static str, length: usize, sha256: &'static str) -> Recipe {
    wifi(member, length, sha256, &MEDIATEK_LICENSE)
}

/// Each image the Intel driver asks for, with the PNVM beside it. The driver
/// names a bare file, as `iwlwifi` does.
pub const INTEL_WIFI: &[Recipe] = &[
    intel_wifi(
        "intel/iwlwifi/iwlwifi-cc-a0-77.ucode",
        1368100,
        "1866a58a1daee56b120362122d5f7548b443b53d33f2558a7e4407d58fd27dab",
    ),
    intel_wifi(
        "intel/iwlwifi/iwlwifi-Qu-b0-hr-b0-77.ucode",
        1406576,
        "df005896aafdf5eb9c427033781890a58c7ab97a8dc1e1ea6b8df4eefc033a9d",
    ),
    intel_wifi(
        "intel/iwlwifi/iwlwifi-Qu-c0-hr-b0-77.ucode",
        1406592,
        "a250e179666288396e19ff15c307edfe8f089341c8713a22b457b7304fc1a6fe",
    ),
    intel_wifi(
        "intel/iwlwifi/iwlwifi-QuZ-a0-hr-b0-77.ucode",
        1406720,
        "39d79587dd035bc84172b6bcf6de81217560088b0ceb06304d5121ba56db8d83",
    ),
    intel_wifi(
        "intel/iwlwifi/iwlwifi-so-a0-hr-b0-89.ucode",
        1527004,
        "6c4a1b2b4720865ee954a055b5aac19377187b142e1b7c5567524c61445bde20",
    ),
    intel_wifi(
        "intel/iwlwifi/iwlwifi-ty-a0-gf-a0-89.ucode",
        1679080,
        "792478ef7752595525379a5068e2d47e310a2c344636b7df866c54746ced1dc0",
    ),
    intel_wifi(
        "intel/iwlwifi/iwlwifi-ty-a0-gf-a0.pnvm",
        55020,
        "9697e327f8171454b3c19b1ec9449753d5b934d4e91722f469616818a6d477b0",
    ),
    intel_wifi(
        "intel/iwlwifi/iwlwifi-so-a0-gf-a0-89.ucode",
        1737012,
        "fae8230ebd1426dfb7d5b5594fdd89e346af5144080659d010b8d2a2fd2f7d4a",
    ),
    intel_wifi(
        "intel/iwlwifi/iwlwifi-so-a0-gf-a0.pnvm",
        55152,
        "78abe08cf33bc209b96a887c7e3db8855a1d9650edacf849c4fa0d4596bcfac5",
    ),
    intel_wifi(
        "intel/iwlwifi/iwlwifi-ma-b0-gf-a0-89.ucode",
        1752976,
        "83c358a33c66bd41f753ee8e0e4fff5c9741694a397ac13a61e851e6bcf5dd6b",
    ),
    intel_wifi(
        "intel/iwlwifi/iwlwifi-ma-b0-gf-a0.pnvm",
        55072,
        "65ccc7ed05c0ecb3ea0374b607ecacfdc693df4e5cbf825a4c91f71ce8fa9b7b",
    ),
    intel_wifi(
        "intel/iwlwifi/iwlwifi-bz-b0-fm-c0-c106.ucode",
        2150968,
        "a0f8fb464c7203a18b28d966f0565835c8744f21ed9e53fc9a1ae9a33ed52cd3",
    ),
    intel_wifi(
        "intel/iwlwifi/iwlwifi-bz-b0-fm-c0.pnvm",
        295356,
        "2da92f02418fbde8d8210eb582d9697faa222f8ee2da229e29b8a108ea5c4c5c",
    ),
    intel_wifi(
        "intel/iwlwifi/iwlwifi-gl-c0-fm-c0-c106.ucode",
        2134660,
        "39a016632105fb327ba45f084a9d7f3775f3d238c20830ec9825d1773affde4d",
    ),
    intel_wifi(
        "intel/iwlwifi/iwlwifi-gl-c0-fm-c0.pnvm",
        295036,
        "f481e3b0403ca43a0a444b01c04fa4d1582868afcb026b1e697905f0039ccfa3",
    ),
    intel_wifi(
        "intel/iwlwifi/iwlwifi-sc-a0-fm-c0-c106.ucode",
        2226844,
        "7a4b428edf7dfc5ec1573bc1b8f98804b52e3a469aeec8187cae9aae66b583fd",
    ),
];
pub const MEDIATEK_WIFI: &[Recipe] = &[
    mediatek_wifi(
        "mediatek/WIFI_MT7961_patch_mcu_1_2_hdr.bin",
        92192,
        "a276c06c2b772adb50b86639d33c82824ff4c21d617feb78caea74c040b873f6",
    ),
    mediatek_wifi(
        "mediatek/WIFI_RAM_CODE_MT7961_1.bin",
        792036,
        "b94217a951518a9c14095765f367bc5dd7698f2dc033941d6f18fc2ebd6a2ab9",
    ),
    mediatek_wifi(
        "mediatek/WIFI_MT7922_patch_mcu_1_1_hdr.bin",
        137632,
        "7fc9075d6d54b31e0539734614ca971fa52caf41b642a3000c8a4501591a4d98",
    ),
    mediatek_wifi(
        "mediatek/WIFI_RAM_CODE_MT7922_1.bin",
        1231252,
        "d100e5e04c324fc8da6302112d1e0b4fac952286447d2419eabcd8fb0a1f5b93",
    ),
    mediatek_wifi(
        "mediatek/mt7925/WIFI_MT7925_PATCH_MCU_1_1_hdr.bin",
        188192,
        "67ff85f1a39d1a100a51abd8e2a26edd2f198d7052514b6b8981948b231e5016",
    ),
    mediatek_wifi(
        "mediatek/mt7925/WIFI_RAM_CODE_MT7925_1_1.bin",
        1390712,
        "329c0e27f780550789e4eba47452731b1723f69f9e67f525d0e50bf3cd2978ac",
    ),
];

const REGULATORY_LICENSE: Artifact = Artifact {
    source: WIRELESS_REGDB,
    revision: WIRELESS_REGDB_RELEASE,
    member: "LICENSE",
    length: 880,
    sha256: "678b0df753c86198fc496d1f1033429bbd57f101472132ee7eaaf9f5e0a7fae1",
};
/// Pinned wireless-regdb releases of `regulatory.db`, each with its ISC
/// LICENSE, from [`WIRELESS_REGDB`].
pub const REGULATORY: &[Recipe] = &[Recipe {
    image: Artifact {
        source: WIRELESS_REGDB,
        revision: WIRELESS_REGDB_RELEASE,
        member: "regulatory.db",
        length: 6348,
        sha256: "7e236caecd939c8ec98be4870bf30422f28ffef2565a38aaaa2d9ddabd0c2641",
    },
    license: &REGULATORY_LICENSE,
    consumer: Consumer::Wifi,
}];

const GSP_LICENSE: Artifact = Artifact {
    source: LINUX_FIRMWARE,
    revision: GSP_REVISION,
    member: "LICENSES/LICENCE.nvidia",
    length: 6212,
    sha256: "bc5225a57f49c5249dcf238e4ae6437811677a2a8a7f579c3d839e058653ee44",
};

const fn gsp(member: &'static str, length: usize, sha256: &'static str) -> Recipe {
    Recipe {
        image: Artifact {
            source: LINUX_FIRMWARE,
            revision: GSP_REVISION,
            member,
            length,
            sha256,
        },
        license: &GSP_LICENSE,
        consumer: Consumer::Nouveau,
    }
}

/// Every GSP-RM file linux-firmware holds for [`GSP_RELEASE`].
pub const GSP: &[Recipe] = &[
    gsp(
        "nvidia/ad102/gsp/booter_load-570.144.bin",
        57720,
        "8b293e19b637c5e22c87a2428d1c71bb13e0904e8a88ac6b3c6c1f2679c6e37a",
    ),
    gsp(
        "nvidia/ad102/gsp/booter_unload-570.144.bin",
        41592,
        "975b85a14ded8e430d30f000c3c1afdd55c15dee04f35ff9dfd876acd7e67186",
    ),
    gsp(
        "nvidia/ad102/gsp/bootloader-570.144.bin",
        36972,
        "65ab2e6b6e0fca95365c4deac79a34582abcfeb15b6ae234138f22e7183118a8",
    ),
    gsp(
        "nvidia/ad102/gsp/scrubber-570.144.bin",
        8312,
        "c397358e5c4258dab070966589c7b172eb00771fd15d0bb74b8e22f327c1909b",
    ),
    gsp(
        "nvidia/ga100/gsp/booter_load-570.144.bin",
        60664,
        "46bafe32b2d1f59713fc8369b5e59e7267d7da4413ad6486aef69d50daa764cd",
    ),
    gsp(
        "nvidia/ga100/gsp/booter_unload-570.144.bin",
        40440,
        "33bea24690c3880a82b47b1a67cbd3cb48707d1c9c26a5db40df6e9682de4da6",
    ),
    gsp(
        "nvidia/ga100/gsp/bootloader-570.144.bin",
        4196,
        "e7670009c98791b8030953ab1d22ecdbf3e073744d928fa15f6267de4eceaad3",
    ),
    gsp(
        "nvidia/ga102/gsp/booter_load-570.144.bin",
        61304,
        "4497e3eff7e95c774b8a569d17b27c08c9650158d10b229d2be81cdcad9a085b",
    ),
    gsp(
        "nvidia/ga102/gsp/booter_unload-570.144.bin",
        41080,
        "8e63db5b78d7d3e349f20a2d11099c3d7109081393cb09ffc0a28133324ae009",
    ),
    gsp(
        "nvidia/ga102/gsp/bootloader-570.144.bin",
        24684,
        "82428f532240727e95bb3083fbaaba9b2cc7b937314323f2d546ce7245f27fad",
    ),
    gsp(
        "nvidia/ga102/gsp/gsp-570.144.bin",
        63571696,
        "a8c3ebeed280323aedb51c061f321e73379cce7a9ae643a33dd03915df027f7f",
    ),
    gsp(
        "nvidia/gb100/gsp/bootloader-570.144.bin",
        200812,
        "daebc2235c9756f2418c2116815a4bb94fc330506f5af60d883e4a740d397062",
    ),
    gsp(
        "nvidia/gb100/gsp/fmc-570.144.bin",
        198028,
        "bc7497c2d8116cceec2fe5638081d60b8f9c0e3dceb0b57dc93950c84909ce21",
    ),
    gsp(
        "nvidia/gb202/gsp/bootloader-570.144.bin",
        200812,
        "d40b48e431d1707dc77af3605db358ed7a32ebfc2830eb74de2eddb4d3025071",
    ),
    gsp(
        "nvidia/gb202/gsp/fmc-570.144.bin",
        199820,
        "cb59a35c1d4bd1274d7267fd10243c29f843ff41c851b9cbd59f5af2ddd7fece",
    ),
    gsp(
        "nvidia/gh100/gsp/bootloader-570.144.bin",
        168044,
        "2176e42f05729ac4dd93ed6cd1b4c6c5650b6aa79c115dfcd9f26a71c1d8d82e",
    ),
    gsp(
        "nvidia/gh100/gsp/fmc-570.144.bin",
        166600,
        "f3ce25f3897c860e4cdde183ebf09b254d94a5d8191d666c12afb33cc7121107",
    ),
    gsp(
        "nvidia/tu102/gsp/booter_load-570.144.bin",
        59272,
        "7bb181f544a942299bbf4642da6d9bb58bfed8459725094e2ace56647cd3ec8c",
    ),
    gsp(
        "nvidia/tu102/gsp/booter_unload-570.144.bin",
        39304,
        "5c7f1aa37d045cc20bb81584a830e8dfa4483f1cd63943de83a58c4be19a1782",
    ),
    gsp(
        "nvidia/tu102/gsp/bootloader-570.144.bin",
        4196,
        "12e987b636c2f00fa40f42fd95097515c0817b158119c584049a37faf38f8f96",
    ),
    gsp(
        "nvidia/tu102/gsp/gen_bootloader-570.144.bin",
        816,
        "b37776a511b4a00901e4e3ac568db917086d3bf439f85bc9b3e4adc7338a0aff",
    ),
    gsp(
        "nvidia/tu102/gsp/gsp-570.144.bin",
        28542040,
        "3052aee2872182a14d8d7c069e3a14fe4642405894b24692c4aca4101dfb1809",
    ),
    gsp(
        "nvidia/tu116/gsp/booter_load-570.144.bin",
        59016,
        "9bd01804b4b91d92904e7735b025e07a3c935bc6fb92e3833e85c297546025b9",
    ),
    gsp(
        "nvidia/tu116/gsp/booter_unload-570.144.bin",
        39048,
        "bf4a2b778722dde57850839bb9f7651ae29592ce85d6df4160d2d228ff430156",
    ),
];

/// The chip whose `gsp` directory linux-firmware's `WHENCE` links `chip`'s to.
fn gsp_directory(chip: &str) -> Option<&'static str> {
    Some(match chip {
        "tu102" | "tu104" | "tu106" => "tu102",
        "tu116" | "tu117" => "tu116",
        "ga100" => "ga100",
        "ga102" | "ga103" | "ga104" | "ga106" | "ga107" => "ga102",
        "ad102" | "ad103" | "ad104" | "ad106" | "ad107" => "ad102",
        "gh100" => "gh100",
        "gb100" | "gb102" => "gb100",
        "gb202" | "gb203" | "gb205" | "gb206" | "gb207" => "gb202",
        _ => return None,
    })
}

/// nouveau's request for a chip's GSP-RM file, through `WHENCE`'s links: the
/// firmware itself runs on families of chips, and only the signed booters
/// differ between them.
fn select_gsp(request: &Request) -> Option<&'static Recipe> {
    if request.target.hardware != "nvidia" || request.target.revision != "linux-firmware" {
        return None;
    }
    let (chip, file) = request.name.strip_prefix("nvidia/")?.split_once("/gsp/")?;
    let directory = gsp_directory(chip)?;
    let (kind, release) = file.strip_suffix(".bin")?.split_once('-')?;
    if release != GSP_RELEASE {
        return None;
    }
    let owner = match (directory, kind) {
        ("tu116" | "ga100", "gen_bootloader" | "gsp") | ("tu116", "bootloader") => "tu102",
        ("ad102" | "gh100" | "gb100" | "gb202", "gsp") => "ga102",
        _ => directory,
    };
    let member = format!("nvidia/{owner}/gsp/{file}");
    GSP.iter().find(|recipe| recipe.image.member == member)
}

/// Requires the GSP-RM files nouveau asks for on `chip`, named as it names
/// chips: `tu104`, `ga104`, `ad104`.
pub fn require_gsp(inventory: &mut Inventory, chip: &str) -> Result<(), Error> {
    let target = Target {
        driver: "nouveau",
        hardware: "nvidia",
        revision: "linux-firmware",
        board: None,
    };
    let mut found = false;
    for kind in GSP_KINDS {
        let name = format!("nvidia/{chip}/gsp/{kind}-{GSP_RELEASE}.bin");
        let request = Requirement {
            name: &name,
            target,
            minimum_bytes: 1,
        };
        if select_gsp(&Request::from(request)).is_some() {
            inventory.observe(request)?;
            found = true;
        }
    }
    if found {
        Ok(())
    } else {
        Err(Error(format!("{chip} is no chip nouveau runs GSP-RM on")))
    }
}

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

fn select_intel_wifi(request: &Request) -> Option<&'static Recipe> {
    if !request.target.hardware.starts_with("pci:8086:") {
        return None;
    }
    INTEL_WIFI.iter().find(|recipe| {
        recipe.image.member.strip_prefix("intel/iwlwifi/") == Some(request.name.as_str())
    })
}

fn select_mediatek_wifi(request: &Request) -> Option<&'static Recipe> {
    if !request.target.hardware.starts_with("pci:14c3:") {
        return None;
    }
    MEDIATEK_WIFI
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
    // Keep every other exact boot-loader field verbatim in the manifest.
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
            // Boot reads these from UEFI variables itself; nothing downloaded
            // stands in for them.
            if target.driver == "wifi-intel" && target.hardware.starts_with("uefi:") {
                continue;
            }
            let recipe = match target.driver.as_str() {
                "realtek" => select_realtek(request),
                "intel-bluetooth-usb-rsa" => select_intel_rsa(request),
                "wifi-regulatory" => select_regulatory(request),
                "wifi-intel" => select_intel_wifi(request),
                "wifi-mt792x" => select_mediatek_wifi(request),
                "nouveau" => select_gsp(request),
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
                .ok_or_else(|| fail("planned host firmware exceeds its budget"))?;
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

    fn gsp_member(name: &str) -> Option<&'static str> {
        let request = serde_json::json!({"schema":1,"complete":true,"requirements":[{
            "name":name,"target":{"driver":"nouveau","hardware":"nvidia",
            "revision":"linux-firmware","board":null},"minimum_bytes":1}]});
        let inventory = Inventory::parse(&serde_json::to_vec(&request).unwrap()).unwrap();
        Plan::select(&inventory)
            .ok()
            .map(|plan| plan.selections[0].recipe.image.member)
    }

    #[test]
    fn a_chip_requires_the_gsp_files_of_its_family() {
        let names = |chip| {
            let mut inventory = Inventory::default();
            require_gsp(&mut inventory, chip).unwrap();
            let requests = inventory.requests().iter();
            requests
                .map(|request| request.name.clone())
                .collect::<Vec<_>>()
        };
        for name in names("tu104") {
            assert!(gsp_member(&name).is_some(), "{name}");
            assert!(name.starts_with("nvidia/tu104/gsp/"), "{name}");
        }
        assert!(names("tu104").iter().any(|name| name.contains("/gsp-")));
        assert!(
            names("ad104")
                .iter()
                .any(|name| name.contains("/booter_load-"))
        );
        let mut inventory = Inventory::default();
        assert!(require_gsp(&mut inventory, "gp104").is_err());
        assert!(inventory.requests().is_empty());
    }

    #[test]
    fn a_chips_gsp_file_follows_linux_firmwares_links() {
        for (name, member) in [
            (
                "nvidia/ga104/gsp/gsp-570.144.bin",
                "nvidia/ga102/gsp/gsp-570.144.bin",
            ),
            (
                "nvidia/ad103/gsp/gsp-570.144.bin",
                "nvidia/ga102/gsp/gsp-570.144.bin",
            ),
            (
                "nvidia/ad106/gsp/booter_load-570.144.bin",
                "nvidia/ad102/gsp/booter_load-570.144.bin",
            ),
            (
                "nvidia/tu117/gsp/gsp-570.144.bin",
                "nvidia/tu102/gsp/gsp-570.144.bin",
            ),
            (
                "nvidia/tu117/gsp/booter_unload-570.144.bin",
                "nvidia/tu116/gsp/booter_unload-570.144.bin",
            ),
            (
                "nvidia/gb207/gsp/fmc-570.144.bin",
                "nvidia/gb202/gsp/fmc-570.144.bin",
            ),
        ] {
            assert_eq!(gsp_member(name), Some(member), "{name}");
        }
        for name in [
            "nvidia/ga104/gsp/gsp-535.113.01.bin",
            "nvidia/gk104/gsp/gsp-570.144.bin",
            "nvidia/ga102/gsp/fmc-570.144.bin",
            "nvidia/ga102/acr/bl-570.144.bin",
        ] {
            assert_eq!(gsp_member(name), None, "{name}");
        }
    }

    #[test]
    fn every_chip_finds_each_file_nouveau_boots_it_with() {
        let booters = [
            "tu102", "tu104", "tu106", "tu116", "tu117", "ga100", "ga102",
        ]
        .into_iter()
        .chain(["ga103", "ga104", "ga106", "ga107", "ad102", "ad103"])
        .chain(["ad104", "ad106", "ad107"]);
        for chip in booters {
            for kind in ["booter_load", "booter_unload", "bootloader", "gsp"] {
                let name = format!("nvidia/{chip}/gsp/{kind}-570.144.bin");
                assert!(gsp_member(&name).is_some(), "{name}");
            }
        }
        for chip in [
            "gh100", "gb100", "gb102", "gb202", "gb203", "gb205", "gb206", "gb207",
        ] {
            for kind in ["fmc", "bootloader", "gsp"] {
                let name = format!("nvidia/{chip}/gsp/{kind}-570.144.bin");
                assert!(gsp_member(&name).is_some(), "{name}");
            }
        }
    }

    #[test]
    fn kernel_org_artifacts_use_cgit_plain_urls_and_the_regdb_is_pinned() {
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
        let plan = Plan::select(&inventory).unwrap();
        assert_eq!(
            plan.selections[0].recipe.image.url(),
            format!("{WIRELESS_REGDB}/plain/regulatory.db?h={WIRELESS_REGDB_RELEASE}")
        );
    }

    fn wifi_inventory(driver: &str, name: &str, hardware: &str) -> Inventory {
        let value = serde_json::json!({"schema":1,"complete":true,"requirements":[{
            "name":name, "target":{"driver":driver,"hardware":hardware,"revision":"observed","board":null},"minimum_bytes":12
        }]});
        Inventory::parse(&serde_json::to_vec(&value).unwrap()).unwrap()
    }

    #[test]
    fn wifi_images_are_pinned_by_the_name_each_driver_asks_for() {
        for (driver, name, hardware, member) in [
            (
                "wifi-intel",
                "iwlwifi-ty-a0-gf-a0.pnvm",
                "pci:8086:2725:8086:0084",
                "intel/iwlwifi/iwlwifi-ty-a0-gf-a0.pnvm",
            ),
            (
                "wifi-intel",
                "iwlwifi-Qu-c0-hr-b0-77.ucode",
                "pci:8086:a0f0:8086:0070",
                "intel/iwlwifi/iwlwifi-Qu-c0-hr-b0-77.ucode",
            ),
            (
                "wifi-mt792x",
                "mediatek/mt7925/WIFI_RAM_CODE_MT7925_1_1.bin",
                "pci:14c3:7925:subsys:14c3:7925:rev:00",
                "mediatek/mt7925/WIFI_RAM_CODE_MT7925_1_1.bin",
            ),
        ] {
            let plan = Plan::select(&wifi_inventory(driver, name, hardware)).unwrap();
            assert_eq!(plan.selections[0].recipe.image.member, member);
            assert_eq!(plan.selections[0].request.name, name);
            assert_eq!(plan.artifacts().len(), 2);
        }
    }

    #[test]
    fn wifi_recipes_refuse_another_vendor_or_an_unpinned_image() {
        for (driver, name, hardware) in [
            (
                "wifi-intel",
                "iwlwifi-ty-a0-gf-a0-89.ucode",
                "pci:14c3:7925",
            ),
            (
                "wifi-intel",
                "iwlwifi-ty-a0-gf-a0-88.ucode",
                "pci:8086:2725",
            ),
            (
                "wifi-mt792x",
                "mediatek/WIFI_RAM_CODE_MT7922_1.bin",
                "pci:8086:2725",
            ),
        ] {
            assert!(Plan::select(&wifi_inventory(driver, name, hardware)).is_err());
        }
    }

    #[test]
    fn intel_uefi_variables_need_no_download() {
        let inventory = wifi_inventory(
            "wifi-intel",
            "uefi/UefiCnvWlanOemSignedPnvm",
            "uefi:92daaf2f-c02b-455b-b2ec-f5a3594f4aea",
        );
        assert!(Plan::select(&inventory).unwrap().selections.is_empty());
    }

    #[test]
    fn intel_rsa_recipes_keep_complete_observed_usb_and_loader_identity() {
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
