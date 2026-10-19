//! The devices a boot bundle presents: only those the machine models.
//!
//! The board's DeviceTree describes every device of the real SoC. SPTM's
//! bootstrap (DART instances by `compatible`, `dart-mapper` restrictions
//! through their DART's `compatible`) and the kernel's drivers bind to a
//! device through its `compatible`, and would then program hardware the
//! machine does not have. A node whose `compatible` names no modeled device
//! (`stela_runtime::machine::soc::models`) loses that property and keeps the
//! rest, so its `reg`, phandle and children stay where software that only
//! reads them expects them. The root, `/arm-io` and each `/cpus` child keep
//! theirs: they describe the board, its I/O fabric and the PEs the engine
//! runs. darwin-vm `dt_fixup.py` (MIT, commit `edfc1943`) boots the same
//! SPTM kernels to a shell in QEMU after removing `compatible` the same way.
//!
//! A modeled DART (`dart,t8110`) presents only the streams visible devices
//! use: an `iommu-mapper` child stays only while a device that keeps its
//! `compatible` names it as `iommu-parent`, and the DART itself only while
//! one of its mappers stays. SPTM initializes every DART the tree shows, and
//! XNU starts an IODARTMapper per mapper; a DART no visible device reaches
//! would only be programmed for clients the machine does not have.
//!
//! A selection of a hidden device goes with it: XNU `pe_serial.c` (`xnu-12377`)
//! takes `/defaults` `serial-device`, a phandle, as its console and panics
//! when that node has no `compatible`. On J473AP it names the unmodeled
//! `dockchannel-uart`, so the property is removed and the kernel runs without
//! a console unless the `serial-device-name` boot-arg selects one.
//!
//! So does the root's `secure-root-prefix` once no AES accelerator (a node of
//! `device_type` `aes`) stays visible. `AppleARMPE::start` (26A434 J473AP
//! kernelcache) reads it from the platform node: without it the platform
//! records the root as secure and `SecureRootName` returns at once; with it,
//! `SecureRootName`, which `IOSecureBSDRoot` calls from `bsd_init`, compares
//! the root device's name against the prefix and then sleeps until a
//! `SecureRoot` call without a result buffer consumes the verdict.
//! `IOAESAccelerator::start` makes that call to install its
//! `SecureRootCallBack`, so on J473AP (`aes,s8000`, root `md0`, prefix `md`)
//! a hidden AES engine leaves the kernel asleep before `launchd` forever.
//! Removing the prefix keeps the verdict a matching root gets (secure); only
//! the callback into the absent driver goes.
//!
//! A watchdog whose board shows no PMU says so. `AppleARMWatchdogTimer::start`
//! (26A434 J473AP kernelcache file 0x1ca4458..0x1ca4488) waits without a
//! timeout for an `IOPMU` service unless its node has `no-pmu`; a PMU
//! driver binds to a `pmu,*` node (J473AP's SPMI `pmu,spmi`). With every PMU
//! hidden, that wait never ends, `IOWatchdog` never registers and
//! `restored_external` fails its `disable_watchdog` step, so a visible
//! watchdog gets an empty `no-pmu`, the board fact the kernel tests for.
//!
//! A role-claimed coprocessor node, and each child its model owns, also gets
//! the boot-chain facts that model declares (`soc::model_boot_properties`,
//! `soc::ChildModel`), such as a native RTKit's preloaded state or ANS2's
//! empty register tuning lists.
use crate::apple_device_tree::{DeviceTree, Node};
use alloc::{format, string::String, vec::Vec};
use stela_runtime::machine::soc;

const COMPATIBLE: &str = "compatible";
const DEFAULTS: &str = "/defaults";
const SERIAL_DEVICE: &str = "serial-device";
const PHANDLE: &str = "AAPL,phandle";
const SECURE_ROOT_PREFIX: &str = "secure-root-prefix";
const DEVICE_TYPE: &str = "device_type";
const IOMMU_PARENT: &str = "iommu-parent";
const NO_PMU: &str = "no-pmu";
/// The prefix of a button's platform function: the provider's phandle, the
/// function code and its arguments (`function-button_hold`).
const BUTTON_FUNCTION: &str = "function-button_";
/// The GPU TTBAT the boot stage hands off (`gpu-region-base`), published as
/// `AGXSecureMonitor::init` (KC file 0x1b8c5c4..0x1b8c6b4) reads it: the
/// presence of `gptbat-ready`, then `ttbat-phys-addr-base` as one 32-bit
/// page number of 16 KiB.
const GPU_REGION_BASE: &str = "gpu-region-base";
const GPTBAT_READY: &str = "gptbat-ready";
const TTBAT_BASE: &str = "ttbat-phys-addr-base";
const TTBAT_PAGE_SHIFT: u32 = 14;

/// Paths that keep their `compatible` whatever it names.
fn structural(path: &str) -> bool {
    path == "/"
        || path == "/arm-io"
        || path
            .strip_prefix("/cpus/")
            .is_some_and(|cpu| !cpu.contains('/'))
}

fn compatibles(node: &Node) -> impl Iterator<Item = &str> {
    node.property(COMPATIBLE)
        .into_iter()
        .flat_map(|property| property.value.split(|&byte| byte == 0))
        .filter_map(|name| core::str::from_utf8(name).ok())
}

fn named(node: &Node, model: &str) -> bool {
    compatibles(node).any(|name| name == model)
}

/// A modeled device that is not part of an IOMMU.
fn modeled_client(node: &Node) -> bool {
    // Only NOR-backed controllers have a modeled SPI slave. Other SPI
    // controllers must not bind drivers for absent peripherals.
    if named(node, soc::SPI) && !node.children.iter().any(|child| named(child, soc::NOR)) {
        return false;
    }
    !named(node, soc::DART)
        && !named(node, soc::IOMMU_MAPPER)
        && compatibles(node)
            .any(|name| soc::models(name, |key| node.property(key).map(|p| p.value.as_slice())))
}

/// The IOMMU, GPIO and interrupt-controller phandles that visible clients
/// under `node` require.
fn client_providers(node: &Node, parents: &mut Vec<u32>) {
    if modeled_client(node)
        && let Some(parent) = node.property("interrupt-parent").and_then(|p| p.as_u32())
    {
        parents.push(parent);
    }
    if modeled_client(node)
        && named(node, soc::SPI)
        && let Some(phandle) = node
            .property("function-spi_cs0")
            .and_then(|p| p.value.get(..4))
    {
        parents.push(u32::from_le_bytes(phandle.try_into().expect("4 bytes")));
    }
    if modeled_client(node)
        && let Some(property) = node.property(IOMMU_PARENT)
    {
        let cells = property.value.as_chunks::<4>().0;
        parents.extend(cells.iter().map(|cell| u32::from_le_bytes(*cell)));
    }
    for child in &node.children {
        client_providers(child, parents);
    }
}

fn kept_mapper(node: &Node, parents: &[u32]) -> bool {
    named(node, soc::IOMMU_MAPPER)
        && node
            .property(PHANDLE)
            .and_then(|property| property.as_u32())
            .is_some_and(|phandle| parents.contains(&phandle))
}

/// Whether the machine models `node` and it serves a visible device.
fn modeled(node: &Node, parents: &[u32]) -> bool {
    if named(node, soc::GPIO) {
        node.property(PHANDLE)
            .and_then(|p| p.as_u32())
            .is_some_and(|p| parents.contains(&p))
    } else if named(node, soc::DART) {
        node.children
            .iter()
            .any(|child| kept_mapper(child, parents))
    } else if named(node, soc::SART) {
        node.property(PHANDLE)
            .and_then(|p| p.as_u32())
            .is_some_and(|p| parents.contains(&p))
    } else if named(node, soc::IOMMU_MAPPER) {
        kept_mapper(node, parents)
    } else {
        modeled_client(node)
    }
}

/// Removes `compatible` from every device the machine does not model, a
/// `/defaults serial-device` that selects one and a `secure-root-prefix`
/// that no AES accelerator can acknowledge, marks visible watchdogs
/// `no-pmu` when no PMU is visible, and returns their paths in tree order,
/// then the selections and marks (`PATH +no-pmu`).
pub fn hide_unmodeled(tree: &mut DeviceTree) -> Vec<String> {
    let mut parents = Vec::new();
    client_providers(&tree.root, &mut parents);
    let mut hidden = Vec::new();
    visit(&mut tree.root, "", &parents, &[], &mut hidden);
    hide_unprovided_buttons(tree, &mut hidden);
    let selected = tree
        .property(DEFAULTS, SERIAL_DEVICE)
        .and_then(|property| property.as_u32())
        .and_then(|phandle| path_of(&tree.root, "", phandle));
    if selected.is_some_and(|path| hidden.contains(&path)) {
        if let Some(defaults) = tree.node_mut(DEFAULTS) {
            defaults.remove_property(SERIAL_DEVICE);
        }
        hidden.push(format!("{DEFAULTS} {SERIAL_DEVICE}"));
    }
    if tree.root.property(SECURE_ROOT_PREFIX).is_some() && !visible_aes(&tree.root) {
        tree.root.remove_property(SECURE_ROOT_PREFIX);
        hidden.push(format!("/ {SECURE_ROOT_PREFIX}"));
    }
    if !visible(&tree.root, &|node| {
        compatibles(node).any(|name| name.starts_with("pmu,"))
    }) {
        let mut watchdogs = Vec::new();
        visible_paths(
            &tree.root,
            "",
            &|node| named(node, soc::WATCHDOG),
            &mut watchdogs,
        );
        for path in watchdogs {
            let node = tree.node_mut(&path).expect("visited path");
            if node.property(NO_PMU).is_none() {
                node.set_property(NO_PMU, Vec::new())
                    .expect("empty property");
                hidden.push(format!("{path} +{NO_PMU}"));
            }
        }
    }
    publish_gpu_ttbat(tree, &mut hidden);
    hidden
}

/// Hides each visible `/buttons` node that names no `function-button_*`
/// provider, or one whose provider lost its `compatible`. AppleM68Buttons
/// reads its buttons through those platform functions (`function-button_hold`
/// = `smc-pmu`, `btnR`, `bHLD` on J473AP); with the provider hidden it would
/// bind to buttons no model drives.
fn hide_unprovided_buttons(tree: &mut DeviceTree, hidden: &mut Vec<String>) {
    let mut buttons = Vec::new();
    visible_paths(
        &tree.root,
        "",
        &|node| named(node, soc::BUTTONS),
        &mut buttons,
    );
    for path in buttons {
        let node = tree.node(&path).expect("visited path");
        let providers: Vec<u32> = node
            .properties
            .iter()
            .filter(|property| property.name().starts_with(BUTTON_FUNCTION))
            .filter_map(|property| property.value.get(..4))
            .map(|cell| u32::from_le_bytes(cell.try_into().expect("4 bytes")))
            .collect();
        let provided = !providers.is_empty()
            && providers.iter().all(|&phandle| {
                path_of(&tree.root, "", phandle)
                    .and_then(|provider| tree.property(&provider, COMPATIBLE))
                    .is_some()
            });
        if !provided {
            tree.node_mut(&path)
                .expect("visited path")
                .remove_property(COMPATIBLE);
            hidden.push(path);
        }
    }
}

/// Publish on each visible GPU the TTBAT the machine hands it off with: its
/// MMU is rooted at `gpu-region-base`, as the boot stage that starts the GFX
/// firmware leaves it. Without the published table the kext roots its own,
/// which the running firmware never walks.
fn publish_gpu_ttbat(tree: &mut DeviceTree, notes: &mut Vec<String>) {
    let mut gpus = Vec::new();
    visible_paths(&tree.root, "", &|node| named(node, soc::SGX), &mut gpus);
    for path in gpus {
        let node = tree.node_mut(&path).expect("visited path");
        if node.property(GPTBAT_READY).is_some() {
            continue;
        }
        let page = node
            .property(GPU_REGION_BASE)
            .and_then(|p| <[u8; 8]>::try_from(p.value.as_slice()).ok())
            .map(u64::from_le_bytes)
            .filter(|base| base.trailing_zeros() >= TTBAT_PAGE_SHIFT)
            .and_then(|base| u32::try_from(base >> TTBAT_PAGE_SHIFT).ok());
        if let Some(page) = page {
            node.set_property(GPTBAT_READY, Vec::new())
                .expect("empty property");
            node.set_property(TTBAT_BASE, page.to_le_bytes().to_vec())
                .expect("u32 property");
            notes.push(format!("{path} +{GPTBAT_READY}"));
        }
    }
}

/// Whether a node under `node` that `test` selects keeps its `compatible`.
fn visible(node: &Node, test: &dyn Fn(&Node) -> bool) -> bool {
    test(node) && node.property(COMPATIBLE).is_some()
        || node.children.iter().any(|child| visible(child, test))
}

/// The paths of the visible nodes under `node` that `test` selects.
fn visible_paths(node: &Node, path: &str, test: &dyn Fn(&Node) -> bool, paths: &mut Vec<String>) {
    if test(node) && node.property(COMPATIBLE).is_some() {
        paths.push(path.into());
    }
    for child in &node.children {
        let name = child.name().unwrap_or("?");
        visible_paths(child, &format!("{path}/{name}"), test, paths);
    }
}

/// Whether an AES accelerator under `node` keeps its `compatible`.
fn visible_aes(node: &Node) -> bool {
    let aes = node
        .property(DEVICE_TYPE)
        .is_some_and(|property| property.value.split(|&byte| byte == 0).next() == Some(b"aes"));
    aes && node.property(COMPATIBLE).is_some() || node.children.iter().any(visible_aes)
}

/// The path of the node whose phandle is `phandle`.
fn path_of(node: &Node, path: &str, phandle: u32) -> Option<String> {
    if node.property(PHANDLE).and_then(|p| p.as_u32()) == Some(phandle) {
        return Some(if path.is_empty() {
            "/".into()
        } else {
            path.into()
        });
    }
    node.children.iter().find_map(|child| {
        let name = child.name().unwrap_or("?");
        path_of(child, &format!("{path}/{name}"), phandle)
    })
}

fn visit(
    node: &mut Node,
    path: &str,
    parents: &[u32],
    inherited: &[&soc::ChildModel],
    hidden: &mut Vec<String>,
) {
    let inherited_model = inherited
        .iter()
        .copied()
        .find(|model| named(node, model.compatible));
    if let Some(model) = inherited_model {
        for &(key, value) in model.boot_properties {
            node.set_property(key, value.to_vec())
                .expect("static native boot property");
        }
    }
    let own: Vec<(&str, &[u8])> = compatibles(node)
        .flat_map(|name| {
            soc::model_boot_properties(name, |key| node.property(key).map(|p| p.value.as_slice()))
                .iter()
                .copied()
        })
        .collect();
    for (key, value) in own {
        node.set_property(key, value.to_vec())
            .expect("static native boot property");
    }
    let owned: Vec<&soc::ChildModel> = compatibles(node)
        .flat_map(|name| {
            soc::model_children(name, |key| node.property(key).map(|p| p.value.as_slice())).iter()
        })
        .chain(inherited_model.into_iter().flat_map(|model| model.children))
        .collect();
    let here = if path.is_empty() { "/" } else { path };
    if node.property(COMPATIBLE).is_some()
        && !structural(here)
        && !modeled(node, parents)
        && !inherited.iter().any(|model| named(node, model.compatible))
    {
        node.remove_property(COMPATIBLE);
        hidden.push(here.into());
    }
    for child in &mut node.children {
        let name = child.name().unwrap_or("?");
        let path = format!("{path}/{name}");
        visit(child, &path, parents, &owned, hidden);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str, compatible: Option<&[u8]>, children: Vec<Node>) -> Node {
        let mut node = Node::named(name).unwrap();
        if let Some(value) = compatible {
            node.set_property(COMPATIBLE, value.to_vec()).unwrap();
        }
        node.children = children;
        node
    }

    #[test]
    fn a_watchdog_without_a_visible_pmu_says_no_pmu() {
        let tree = |pmu: Option<&[u8]>| DeviceTree {
            root: node(
                "device-tree",
                None,
                vec![node(
                    "arm-io",
                    None,
                    vec![
                        node("wdt", Some(b"wdt,t8101\0wdt,s5l8960x\0"), vec![]),
                        node(
                            "nub-spmi0",
                            Some(b"aapl,spmi\0"),
                            vec![node("pmu-main", pmu, vec![])],
                        ),
                    ],
                )],
            ),
        };
        // The modeled Dialog PMU stays visible and the watchdog waits for it.
        let mut modeled = tree(Some(b"pmu,spmi\0pmu,stowe\0"));
        assert_eq!(hide_unmodeled(&mut modeled), Vec::<String>::new());
        assert!(modeled.property("/arm-io/wdt", NO_PMU).is_none());
        let mut hidden = tree(Some(b"pmu,acme\0"));
        let paths = hide_unmodeled(&mut hidden);
        assert_eq!(paths, ["/arm-io/nub-spmi0/pmu-main", "/arm-io/wdt +no-pmu"]);
        let no_pmu = hidden.property("/arm-io/wdt", NO_PMU).unwrap();
        assert!(no_pmu.value.is_empty());
        // Already marked: nothing more to say.
        assert_eq!(hide_unmodeled(&mut hidden), Vec::<String>::new());
        // A tree without any PMU node at all is marked the same way.
        let mut absent = tree(None);
        assert_eq!(hide_unmodeled(&mut absent), ["/arm-io/wdt +no-pmu"]);
    }

    #[test]
    fn role_claim_retains_only_its_nub_and_referenced_provider() {
        let mut ans = node(
            "ans",
            Some(soc::ASC.as_bytes()),
            vec![node("iop-ans-nub", Some(soc::RTBUDDY.as_bytes()), vec![])],
        );
        ans.set_property("role", b"ANS2\0".to_vec()).unwrap();
        ans.set_property(IOMMU_PARENT, 142u32.to_le_bytes().to_vec())
            .unwrap();
        let mut sart = node("sart-ans", Some(soc::SART.as_bytes()), vec![]);
        sart.set_property(PHANDLE, 142u32.to_le_bytes().to_vec())
            .unwrap();
        let other = node(
            "other",
            Some(soc::ASC.as_bytes()),
            vec![node("nub", Some(soc::RTBUDDY.as_bytes()), vec![])],
        );
        let mut tree = DeviceTree {
            root: node(
                "",
                None,
                vec![node(
                    "arm-io",
                    None,
                    vec![
                        ans,
                        sart,
                        other,
                        node("unused-sart", Some(soc::SART.as_bytes()), vec![]),
                    ],
                )],
            ),
        };
        assert_eq!(
            hide_unmodeled(&mut tree),
            ["/arm-io/other", "/arm-io/other/nub", "/arm-io/unused-sart"]
        );
        assert!(
            tree.property("/arm-io/ans/iop-ans-nub", COMPATIBLE)
                .is_some()
        );
        assert!(tree.property("/arm-io/sart-ans", COMPATIBLE).is_some());
        for key in [
            "pre-loaded",
            "running",
            "no-firmware-service",
            "segment-ranges",
            "segment-names",
        ] {
            assert!(
                tree.property("/arm-io/ans/iop-ans-nub", key)
                    .unwrap()
                    .value
                    .is_empty()
            );
            assert!(tree.property("/arm-io/other/nub", key).is_none());
        }
        // The claimed ANS2 node carries its own boot-chain facts: the empty
        // register tuning lists its driver requires.
        for key in [
            "afc-aiu-ans-dual-tunables",
            "command-accelerator-tunables",
            "storage-lane-common-tunables",
            "ccu-security-interrupt-tunables",
        ] {
            assert!(tree.property("/arm-io/ans", key).unwrap().value.is_empty());
            assert!(tree.property("/arm-io/other", key).is_none());
        }
        tree.node_mut("/arm-io/ans")
            .unwrap()
            .set_property("role", b"ANS3\0".to_vec())
            .unwrap();
        assert_eq!(
            hide_unmodeled(&mut tree),
            ["/arm-io/ans", "/arm-io/ans/iop-ans-nub", "/arm-io/sart-ans"]
        );
    }

    /// J473AP's SMC subtree: the claimed wrapper, its native nub, the nub's
    /// `smc-pmu` child and `/buttons`, whose hold button `smc-pmu` provides.
    #[test]
    fn the_smc_claim_keeps_its_pmu_and_the_buttons_it_provides() {
        let smc = |role: &[u8]| {
            let mut pmu = node("smc-pmu", Some(b"smc-pmu\0"), vec![]);
            pmu.set_property(PHANDLE, 0x91u32.to_le_bytes().to_vec())
                .unwrap();
            let mut smc = node(
                "smc",
                Some(soc::ASC.as_bytes()),
                vec![node(
                    "iop-smc-nub",
                    Some(soc::RTBUDDY.as_bytes()),
                    vec![pmu, node("smc-socd", Some(b"smc-socd\0"), vec![])],
                )],
            );
            smc.set_property("role", role.to_vec()).unwrap();
            smc
        };
        let buttons = |provider: u32| {
            let mut buttons = node("buttons", Some(b"buttons\0"), vec![]);
            let hold = [provider, four_char_code(b"btnR"), four_char_code(b"bHLD")];
            buttons
                .set_property(
                    "function-button_hold",
                    hold.iter().flat_map(|cell| cell.to_le_bytes()).collect(),
                )
                .unwrap();
            buttons
        };
        let tree = |role: &[u8], provider: u32| DeviceTree {
            root: node(
                "",
                None,
                vec![node("arm-io", None, vec![smc(role)]), buttons(provider)],
            ),
        };
        let mut modeled = tree(b"SMC\0", 0x91);
        // Only the unmodeled grandchild goes.
        assert_eq!(
            hide_unmodeled(&mut modeled),
            ["/arm-io/smc/iop-smc-nub/smc-socd"]
        );
        for kept in [
            "/arm-io/smc",
            "/arm-io/smc/iop-smc-nub",
            "/arm-io/smc/iop-smc-nub/smc-pmu",
            "/buttons",
        ] {
            assert!(modeled.property(kept, COMPATIBLE).is_some(), "{kept}");
        }
        // The PMU child carries no RTKit hand-off facts of its own.
        assert!(
            modeled
                .property("/arm-io/smc/iop-smc-nub/smc-pmu", "pre-loaded")
                .is_none()
        );
        // Without the SMC claim the PMU goes, and so do the buttons it
        // provides; buttons naming a missing provider go too.
        let mut unclaimed = tree(b"PMU\0", 0x91);
        let hidden = hide_unmodeled(&mut unclaimed);
        assert_eq!(hidden.last().map(String::as_str), Some("/buttons"));
        assert!(
            hidden
                .iter()
                .any(|path| path == "/arm-io/smc/iop-smc-nub/smc-pmu")
        );
        let mut orphaned = tree(b"SMC\0", 0x42);
        assert!(hide_unmodeled(&mut orphaned).contains(&"/buttons".into()));
    }

    fn four_char_code(name: &[u8; 4]) -> u32 {
        u32::from_be_bytes(*name)
    }

    #[test]
    fn a_visible_gpu_gets_the_handed_off_ttbat_published() {
        let gpu = |base: u64| {
            let mut sgx = node("sgx", Some(soc::SGX.as_bytes()), vec![]);
            sgx.set_property(GPU_REGION_BASE, base.to_le_bytes().to_vec())
                .unwrap();
            DeviceTree {
                root: node("", None, vec![node("arm-io", None, vec![sgx])]),
            }
        };
        let mut tree = gpu(0x8_0004_4000);
        let mut notes = Vec::new();
        publish_gpu_ttbat(&mut tree, &mut notes);
        assert_eq!(notes, ["/arm-io/sgx +gptbat-ready"]);
        assert!(
            tree.property("/arm-io/sgx", GPTBAT_READY)
                .unwrap()
                .value
                .is_empty()
        );
        assert_eq!(
            tree.property("/arm-io/sgx", TTBAT_BASE).unwrap().value,
            0x20_0011u32.to_le_bytes()
        );
        // Published once; a misaligned base gets nothing.
        notes.clear();
        publish_gpu_ttbat(&mut tree, &mut notes);
        assert!(notes.is_empty());
        let mut misaligned = gpu(0x8_0004_4100);
        publish_gpu_ttbat(&mut misaligned, &mut notes);
        assert!(misaligned.property("/arm-io/sgx", GPTBAT_READY).is_none());
        // Until the GPU is admitted the loader hides it and publishes nothing.
        let mut hidden = gpu(0x8_0004_4000);
        hide_unmodeled(&mut hidden);
        assert_eq!(
            hidden.property("/arm-io/sgx", GPTBAT_READY).is_some(),
            soc::GPU_ADMITTED
        );
    }

    #[test]
    fn spi_requires_a_nor_slave_and_retains_its_gpio_provider() {
        let mut gpio = node("gpio", Some(soc::GPIO.as_bytes()), vec![]);
        gpio.set_property(PHANDLE, 106u32.to_le_bytes().to_vec())
            .unwrap();
        let mut spi = node(
            "spi1",
            Some(soc::SPI.as_bytes()),
            vec![node(
                "spinor",
                Some(soc::NOR.as_bytes()),
                vec![node("anvram", Some(soc::NVRAM.as_bytes()), vec![])],
            )],
        );
        spi.set_property(
            "function-spi_cs0",
            [106u32, soc::GPIO_FUNCTION, 49, 0x10001]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect(),
        )
        .unwrap();
        let mut tree = DeviceTree {
            root: node(
                "device-tree",
                None,
                vec![node(
                    "arm-io",
                    None,
                    vec![gpio, spi, node("spi0", Some(soc::SPI.as_bytes()), vec![])],
                )],
            ),
        };
        assert_eq!(hide_unmodeled(&mut tree), ["/arm-io/spi0"]);
        assert!(tree.property("/arm-io/gpio", COMPATIBLE).is_some());
        tree.node_mut("/arm-io/spi1").unwrap().children.clear();
        assert_eq!(hide_unmodeled(&mut tree), ["/arm-io/gpio", "/arm-io/spi1"]);
    }

    #[test]
    fn a_visible_client_retains_the_gpio_bank_its_interrupt_names() {
        let mut gpio = node("gpio", Some(soc::GPIO.as_bytes()), vec![]);
        gpio.set_property(PHANDLE, 106u32.to_le_bytes().to_vec())
            .unwrap();
        let mut manager = node("hpmBusManager", Some(b"usbc,manager\0"), vec![]);
        manager
            .set_property("interrupt-parent", 106u32.to_le_bytes().to_vec())
            .unwrap();
        let i2c = node("i2c0", Some(b"i2c,t8101\0"), vec![manager]);
        let mut tree = DeviceTree {
            root: node(
                "device-tree",
                None,
                vec![node("arm-io", None, vec![gpio, i2c])],
            ),
        };
        assert_eq!(hide_unmodeled(&mut tree), Vec::<String>::new());
        tree.node_mut("/arm-io/i2c0").unwrap().children.clear();
        assert_eq!(hide_unmodeled(&mut tree), ["/arm-io/gpio"]);
    }

    #[test]
    fn keeps_the_board_cpus_fabric_and_modeled_devices_and_hides_the_rest() {
        let mut tree = DeviceTree {
            root: secure_root(node(
                "device-tree",
                Some(b"J473AP\0AppleARM\0"),
                vec![
                    node(
                        "cpus",
                        None,
                        vec![node("cpu0", Some(b"apple,blizzard\0ARM,v8\0"), vec![])],
                    ),
                    node(
                        "arm-io",
                        Some(b"arm-io,t8110\0"),
                        vec![
                            node("uart0", Some(b"uart-1,samsung\0"), vec![]),
                            node("wdt", Some(b"wdt,t8101\0wdt,s5l8960x\0"), vec![]),
                            node("aic", Some(b"aic,2\0"), vec![]),
                            {
                                let mut sep = node(
                                    "sep",
                                    Some(b"iop-sep,ascwrap-v4\0"),
                                    vec![node("iop-sep-nub", Some(b"iop-nub,sep\0"), vec![])],
                                );
                                sep.set_property("role", b"SEP\0".to_vec()).unwrap();
                                sep.set_property(IOMMU_PARENT, 0x84u32.to_le_bytes().to_vec())
                                    .unwrap();
                                sep
                            },
                            node(
                                "dart-sep",
                                Some(b"dart,t8110\0"),
                                vec![phandle(
                                    node("mapper-sep", Some(b"iommu-mapper\0"), vec![]),
                                    0x84,
                                )],
                            ),
                            aes(b"aes,s5l8960x\0"),
                            phandle(
                                node("dockchannel-uart", Some(b"aapl,dock-channels\0"), vec![]),
                                0x4d,
                            ),
                        ],
                    ),
                    node("buttons", Some(b"buttons\0"), vec![]),
                    serial_default(0x4d),
                ],
            )),
        };
        let hidden = hide_unmodeled(&mut tree);
        assert_eq!(
            hidden,
            [
                "/arm-io/aes",
                "/arm-io/dockchannel-uart",
                "/buttons",
                "/defaults serial-device",
                "/ secure-root-prefix",
                "/arm-io/wdt +no-pmu",
            ]
        );
        for kept in [
            "/",
            "/cpus/cpu0",
            "/arm-io",
            "/arm-io/uart0",
            "/arm-io/wdt",
            "/arm-io/aic",
            // The SEP (role = SEP), its native nub and its DART are admitted.
            "/arm-io/sep",
            "/arm-io/sep/iop-sep-nub",
            "/arm-io/dart-sep",
            "/arm-io/dart-sep/mapper-sep",
        ] {
            assert!(tree.property(kept, COMPATIBLE).is_some(), "{kept}");
        }
        assert!(tree.property(DEFAULTS, SERIAL_DEVICE).is_none());
        assert!(tree.root.property(SECURE_ROOT_PREFIX).is_none());
    }

    fn secure_root(mut root: Node) -> Node {
        root.set_property(SECURE_ROOT_PREFIX, b"md\0".to_vec())
            .unwrap();
        root
    }

    #[test]
    fn only_an_aes_node_with_its_compatible_is_a_visible_accelerator() {
        let mut root = node(
            "device-tree",
            None,
            vec![node("arm-io", None, vec![aes(b"aes,s8000\0")])],
        );
        assert!(visible_aes(&root));
        root.children[0].children[0].remove_property(COMPATIBLE);
        assert!(!visible_aes(&root));
        let other = node(
            "device-tree",
            None,
            vec![node("sio", Some(b"iop,ascwrap-v4\0"), vec![])],
        );
        assert!(!visible_aes(&other));
    }

    fn aes(compatible: &[u8]) -> Node {
        let mut aes = node("aes", Some(compatible), vec![]);
        aes.set_property(DEVICE_TYPE, b"aes\0".to_vec()).unwrap();
        aes
    }

    fn phandle(mut node: Node, value: u32) -> Node {
        node.set_property(PHANDLE, value.to_le_bytes().to_vec())
            .unwrap();
        node
    }

    fn serial_default(value: u32) -> Node {
        let mut defaults = node("defaults", None, vec![]);
        defaults
            .set_property(SERIAL_DEVICE, value.to_le_bytes().to_vec())
            .unwrap();
        defaults
    }

    fn mapper(name: &str, phandle_value: u32) -> Node {
        phandle(node(name, Some(b"iommu-mapper\0"), vec![]), phandle_value)
    }

    /// J473AP's AES engine reaches RAM through `dart-sio` `mapper-aes`
    /// (phandle 0x8a): that DART and mapper stay, its other mappers and the
    /// DARTs no visible device names go.
    #[test]
    fn darts_stay_only_for_the_streams_of_visible_devices() {
        let mut engine = aes(b"aes,s8000\0");
        engine
            .set_property(IOMMU_PARENT, 0x8a_u32.to_le_bytes().to_vec())
            .unwrap();
        let mut sio = node("sio", Some(b"iop,ascwrap-v4\0"), vec![]);
        sio.set_property(IOMMU_PARENT, 0x89_u32.to_le_bytes().to_vec())
            .unwrap();
        let mut tree = DeviceTree {
            root: secure_root(node(
                "device-tree",
                None,
                vec![node(
                    "arm-io",
                    None,
                    vec![
                        node(
                            "dart-sio",
                            Some(b"dart,t8110\0"),
                            vec![mapper("mapper-sio", 0x89), mapper("mapper-aes", 0x8a)],
                        ),
                        node(
                            "dart-sep",
                            Some(b"dart,t8110\0"),
                            vec![mapper("mapper-sep", 0x90)],
                        ),
                        engine,
                        sio,
                    ],
                )],
            )),
        };
        assert_eq!(
            hide_unmodeled(&mut tree),
            [
                "/arm-io/dart-sio/mapper-sio",
                "/arm-io/dart-sep",
                "/arm-io/dart-sep/mapper-sep",
                "/arm-io/sio",
            ]
        );
        for kept in [
            "/arm-io/dart-sio",
            "/arm-io/dart-sio/mapper-aes",
            "/arm-io/aes",
        ] {
            assert!(tree.property(kept, COMPATIBLE).is_some(), "{kept}");
        }
        // A visible AES engine keeps the secure root prefix.
        assert!(tree.root.property(SECURE_ROOT_PREFIX).is_some());
    }

    #[test]
    fn a_modeled_serial_device_stays_selected() {
        let mut tree = DeviceTree {
            root: node(
                "device-tree",
                None,
                vec![
                    node(
                        "arm-io",
                        None,
                        vec![phandle(node("uart0", Some(b"uart-1,samsung\0"), vec![]), 7)],
                    ),
                    serial_default(7),
                ],
            ),
        };
        assert!(hide_unmodeled(&mut tree).is_empty());
        assert!(tree.property(DEFAULTS, SERIAL_DEVICE).is_some());
    }
}
