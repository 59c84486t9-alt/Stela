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
//! A modeled native DART presents only the streams visible devices
//! use: an `iommu-mapper` child stays only while a device that keeps its
//! `compatible` names it as `iommu-parent`, and the DART itself only while
//! one of its mappers stays. SPTM initializes every DART the tree shows, and
//! XNU starts an IODARTMapper per mapper; a DART no visible device reaches
//! would only be programmed for clients the machine does not have.
//! A modeled device whose `iommu-parent` names a mapper of a DART the
//! machine does not model (including unqualified legacy filter, remap or
//! routing variants) goes too, before its streams are counted: its DMA would
//! have no translation to reach RAM through, so its driver must not bind.
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
//!
//! Some peripherals bind by `name`/`device_type` without a `compatible`.
//! Removing `compatible` cannot hide those clients. Declared required
//! platform-function dependencies are resolved after ordinary admission;
//! a client without its provider gets `AAPL,ignore`, which XNU's
//! `IODTFindMatchingEntries` skips. Its name, phandle and properties remain
//! available as DeviceTree data. Optional functions are not dependencies.
//!
//! A final pass also retires audited service-advertising `device_type`
//! values on hidden devices: raw DeviceTree display discovery does not
//! honor `compatible` or `AAPL,ignore`. The existing admission ledger keeps
//! the hidden paths; original inputs retain the removed identity bytes.
//! Structural and unaudited type metadata remain.
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
const IGNORE: &str = "AAPL,ignore";
/// Raw DeviceTree consumers use these physical display classes as service
/// advertisements even after `compatible` is removed. Only audited class
/// identities are retired; unknown `device_type` metadata stays intact.
/// See `installer-warnings.md#display-service-admission` for both consumers.
const SERVICE_IDENTITIES: &[&[u8]] = &[b"display-subsystem\0", b"ext-display-subsystem\0"];
/// Required functions of name-matched hardware classes, not optional
/// callbacks inferred from arbitrary `function-*` properties. The original
/// AMFM requires its PCIe platform function. Other WLAN interfaces need
/// their active bus established before imposing a direct PCIe requirement;
/// the original driver also has a serial-provider personality.
const REQUIRED_FUNCTIONS: &[(&str, &[&str])] = &[("amfm", &["function-pcie_port_control"])];
/// A service-selected hardware interface replaces the direct platform
/// function, rather than making it optional. AppleOLYHAL's withProvider
/// (26A434 0xfffffe0009b465a8..0x9b465dc) selects its AMFM implementation
/// when this marker exists; its init waits for AppleMultiFunctionManager
/// (0x9b34d64..0x9b34dac), whose original IONameMatch is `amfm`.
const REQUIRED_SERVICES: &[(&str, &str, &str)] = &[("wlan", "amfm-managed-port-control", "amfm")];
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

fn is_dart(node: &Node) -> bool {
    compatibles(node).any(|name| name.starts_with("dart,"))
}

fn modeled_dart(node: &Node) -> bool {
    use stela_runtime::machine::apple::DartProfile as Profile;
    let Some(profile) = node
        .property(COMPATIBLE)
        .and_then(|property| Profile::from_compatible(&property.value))
    else {
        return false;
    };
    if !compatibles(node)
        .any(|name| soc::models(name, |key| node.property(key).map(|p| p.value.as_slice())))
    {
        return false;
    }
    if profile == Profile::T8110 {
        return true;
    }
    // A capture descriptor does not create another translating owner.
    let descriptors = &node
        .property("instance")
        .expect("qualified native descriptors")
        .value;
    let translations = descriptors
        .as_chunks::<12>()
        .0
        .iter()
        .filter(|d| &d[..4] == b"TRAD")
        .count();
    let mappers = node
        .children
        .iter()
        .filter(|child| named(child, soc::IOMMU_MAPPER));
    if translations != 1 && mappers.clone().next().is_some() {
        return false;
    }
    let streams = node
        .property("sid-count")
        .and_then(|p| p.as_u32())
        .unwrap_or(16) as usize;
    let remaps = node
        .property("remap")
        .map(|p| p.value.as_slice())
        .unwrap_or_default()
        .as_chunks::<2>()
        .0
        .iter()
        .filter(|p| **p != [0, 0])
        .map(|p| (p[0], p[1]))
        .collect::<Vec<_>>();
    // The source mapper names a context, not an incoming remapped SID.
    mappers.into_iter().all(|mapper| {
        let Some(context) = mapper
            .property("reg")
            .and_then(|p| <[u8; 4]>::try_from(p.value.as_slice()).ok())
            .map(u32::from_le_bytes)
        else {
            return false;
        };
        profile
            .mapper_input_stream(streams, context as usize, &remaps)
            .is_ok()
    })
}

/// A modeled device that is not part of an IOMMU.
fn modeled_client(node: &Node) -> bool {
    // Only NOR-backed controllers have a modeled SPI slave. Other SPI
    // controllers must not bind drivers for absent peripherals.
    if named(node, soc::SPI) && !node.children.iter().any(|child| named(child, soc::NOR)) {
        return false;
    }
    !is_dart(node)
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
    } else if is_dart(node) {
        modeled_dart(node)
            && node
                .children
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

/// The phandles of the `iommu-mapper` nodes under `node` whose DART the
/// machine does not model.
fn unmodeled_mappers(node: &Node, mappers: &mut Vec<u32>) {
    for child in &node.children {
        if !modeled_dart(node)
            && named(child, soc::IOMMU_MAPPER)
            && let Some(phandle) = child.property(PHANDLE).and_then(|p| p.as_u32())
        {
            mappers.push(phandle);
        }
        unmodeled_mappers(child, mappers);
    }
}

/// Removes `compatible` from each modeled device under `node` whose
/// `iommu-parent` names one of `mappers`, in tree order.
fn hide_unserved_clients(node: &mut Node, path: &str, mappers: &[u32], hidden: &mut Vec<String>) {
    let unserved = modeled_client(node)
        && node.property(IOMMU_PARENT).is_some_and(|property| {
            property
                .value
                .as_chunks::<4>()
                .0
                .iter()
                .any(|cell| mappers.contains(&u32::from_le_bytes(*cell)))
        });
    if unserved {
        node.remove_property(COMPATIBLE);
        hidden.push(path.into());
    }
    for child in &mut node.children {
        let name = child.name().unwrap_or("?");
        let path = format!("{path}/{name}");
        hide_unserved_clients(child, &path, mappers, hidden);
    }
}

/// Removes `compatible` from every device the machine does not model, a
/// `/defaults serial-device` that selects one and a `secure-root-prefix`
/// that no AES accelerator can acknowledge, marks visible watchdogs
/// `no-pmu` when no PMU is visible, and returns their paths, those behind
/// an unmodeled DART first and then the rest in tree order, then the
/// selections and marks (`PATH +no-pmu`). Name-matched clients whose
/// declared required function providers are unavailable get `AAPL,ignore`
/// and an entry in that same ledger.
pub fn hide_unmodeled(tree: &mut DeviceTree) -> Vec<String> {
    let mut mappers = Vec::new();
    unmodeled_mappers(&tree.root, &mut mappers);
    let mut hidden = Vec::new();
    hide_unserved_clients(&mut tree.root, "", &mappers, &mut hidden);
    hide_incomplete_external_outputs(tree, &mut hidden);
    let mut parents = Vec::new();
    client_providers(&tree.root, &mut parents);
    visit(&mut tree.root, "", &parents, &[], &mut hidden);
    hide_unprovided_buttons(tree, &mut hidden);
    hide_unprovided_clients(tree, &mut hidden);
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
    retire_hidden_service_identities(tree, &hidden);
    hidden
}

/// Admit the external controller, same-role expert and selected pipe as one
/// source-backed graph. IOMMU failures above cannot leave an expert advertising
/// a service for a controller that was removed. The final retirement pass also
/// removes raw display-subsystem advertisements for a hidden pipe.
fn hide_incomplete_external_outputs(tree: &mut DeviceTree, hidden: &mut Vec<String>) {
    for profile in soc::EXTERNAL_OUTPUTS {
        let paths = [profile.controller, profile.expert, profile.pipe]
            .map(|name| format!("/arm-io/{name}"));
        if tree.node(&paths[0]).is_none()
            && tree.node(&paths[1]).is_none()
            && tree
                .node(&paths[2])
                .is_none_or(|n| !named(n, profile.compatible))
        {
            continue;
        }
        let controller = tree.node(&paths[0]);
        let expert = tree.node(&paths[1]);
        let pipe = tree.node(&paths[2]);
        let qualified = profile.admitted
            && controller.is_some_and(|n| {
                named(n, soc::ASC)
                    && n.property("role")
                        .is_some_and(|p| p.value == profile.role_property)
                    && n.children.iter().filter(|c| named(c, soc::RTBUDDY)).count() == 1
                    && n.children
                        .iter()
                        .find(|c| named(c, soc::RTBUDDY))
                        .is_some_and(|nub| {
                            profile.external_index.is_none_or(|index| {
                                nub.property("external-index").and_then(|p| p.as_u32())
                                    == Some(index)
                            })
                        })
            })
            && expert.is_some_and(|n| {
                named(n, soc::DCP_EXPERT)
                    && n.property("role")
                        .is_some_and(|p| p.value == profile.role_property)
                    && n.property("join-power-plane").and_then(|p| p.as_u32()) == Some(1)
                    && n.property("reg").is_none()
                    && soc::DCP_EXPERT_HARDWARE_FEATURES
                        .iter()
                        .all(|key| n.property(key).is_none())
            })
            && pipe.is_some_and(|n| {
                named(n, profile.compatible)
                    && profile
                        .external_index
                        .is_none_or(|_| n.property("external").and_then(|p| p.as_u32()) == Some(1))
            });
        if !qualified {
            for path in paths {
                if let Some(node) = tree.node_mut(&path)
                    && node.remove_property(COMPATIBLE).is_some()
                    && !hidden.contains(&path)
                {
                    hidden.push(path);
                }
            }
        }
    }
}

/// Retire a proven service-advertising class only after the admission pass
/// has established that its physical device is unavailable. The path ledger
/// stays unchanged; the original input and its source provenance retain the
/// identity bytes separately from this prepared tree. Names and phandles
/// stay usable by metadata readers; structural and unaudited types stay intact.
fn retire_hidden_service_identities(tree: &mut DeviceTree, hidden: &[String]) {
    for path in hidden {
        if structural(path) {
            continue;
        }
        let Some(node) = tree.node_mut(path) else {
            continue;
        };
        if node
            .property(DEVICE_TYPE)
            .is_some_and(|property| SERVICE_IDENTITIES.contains(&property.value.as_slice()))
        {
            node.remove_property(DEVICE_TYPE);
        }
    }
}

fn required_service(node: &Node) -> Option<&'static str> {
    let kind = node.property(DEVICE_TYPE).and_then(|p| p.as_str());
    REQUIRED_SERVICES
        .iter()
        .find_map(|&(client, selector, service)| {
            (kind == Some(client) && node.property(selector).is_some()).then_some(service)
        })
}

fn required_functions(node: &Node) -> &'static [&'static str] {
    if required_service(node).is_some() {
        return &[];
    }
    let kind = node.property(DEVICE_TYPE).and_then(|p| p.as_str());
    REQUIRED_FUNCTIONS
        .iter()
        .find_map(|&(name, functions)| (kind == Some(name)).then_some(functions))
        .unwrap_or_default()
}

struct PlatformClient {
    path: String,
    phandle: Option<u32>,
    providers: Option<Vec<u32>>,
    /// Hardware class of the service this admitted client supplies.
    kind: Option<String>,
    service: Option<&'static str>,
    provided: bool,
}

/// Collect trusted provider roots and clients whose required dependencies
/// still need to be proven. An ignored subtree supplies no IOKit service.
fn platform_clients(
    node: &Node,
    path: &str,
    clients: &mut Vec<PlatformClient>,
    roots: &mut Vec<u32>,
) {
    if node.property(IGNORE).is_some() {
        return;
    }
    let required = required_functions(node);
    let phandle = node.property(PHANDLE).and_then(|p| p.as_u32());
    let service = required_service(node);
    let here = if path.is_empty() { "/" } else { path };
    if (!required.is_empty() || service.is_some()) && !structural(here) {
        let providers = required
            .iter()
            .map(|name| {
                // Every platform function begins with a provider phandle
                // and a four-character operation code; trailing arguments
                // belong to that function's own protocol.
                let value = &node.property(name)?.value;
                let prefix = value.get(..8)?;
                Some(u32::from_le_bytes(prefix[..4].try_into().expect("4 bytes")))
            })
            .collect();
        clients.push(PlatformClient {
            path: path.into(),
            phandle,
            providers,
            kind: node
                .property(DEVICE_TYPE)
                .and_then(|p| p.as_str())
                .map(String::from),
            service,
            provided: false,
        });
    } else if node.property(COMPATIBLE).is_some()
        && let Some(phandle) = phandle
    {
        roots.push(phandle);
    }
    for child in &node.children {
        let name = child.name().unwrap_or("?");
        platform_clients(child, &format!("{path}/{name}"), clients, roots);
    }
}

/// Prove required-provider and service chains from admitted roots. At most
/// one pass per client can add a provider or service, so a cycle without an
/// admitted root stays unprovided and terminates. Optional functions never
/// hide a client.
fn hide_unprovided_clients(tree: &mut DeviceTree, hidden: &mut Vec<String>) {
    let mut clients = Vec::new();
    let mut provided = Vec::new();
    platform_clients(&tree.root, "", &mut clients, &mut provided);
    let mut services = Vec::new();
    for _ in 0..clients.len() {
        let mut changed = false;
        for client in &mut clients {
            if !client.provided
                && client
                    .service
                    .is_none_or(|required| services.iter().any(|kind| kind == required))
                && client.providers.as_ref().is_some_and(|providers| {
                    providers.iter().all(|provider| provided.contains(provider))
                })
            {
                client.provided = true;
                if let Some(kind) = &client.kind {
                    services.push(kind.clone());
                }
                if let Some(phandle) = client.phandle {
                    provided.push(phandle);
                }
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    for client in clients.into_iter().filter(|client| !client.provided) {
        tree.node_mut(&client.path)
            .expect("visited path")
            .set_property(IGNORE, Vec::new())
            .expect("empty property");
        if !hidden.contains(&client.path) {
            hidden.push(client.path);
        }
    }
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
    visible_paths(
        &tree.root,
        "",
        &|node| compatibles(node).any(soc::admitted_gpu),
        &mut gpus,
    );
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

    fn function_client(name: &str, phandle_value: u32, provider: u32) -> Node {
        let mut client = phandle(node(name, None, vec![]), phandle_value);
        client
            .set_property(DEVICE_TYPE, b"amfm\0".to_vec())
            .unwrap();
        client
            .set_property(
                "function-pcie_port_control",
                [provider, four_char_code(b"PrtC"), 0x36]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect(),
            )
            .unwrap();
        client
    }

    #[test]
    fn name_matched_clients_require_an_admitted_function_provider() {
        let tree = |provider| DeviceTree {
            root: node(
                "",
                None,
                vec![function_client("radio", 0x24, 0x35), provider],
            ),
        };
        let mut hidden = tree(phandle(node("pcie", Some(b"apcie,t8112\0"), vec![]), 0x35));
        let original = hidden.node("/radio").unwrap().clone();
        assert_eq!(hide_unmodeled(&mut hidden), ["/pcie", "/radio"]);
        assert!(hidden.property("/radio", IGNORE).is_some());
        let mut retained = hidden.node("/radio").unwrap().clone();
        retained.remove_property(IGNORE);
        assert_eq!(retained, original);
        assert!(hide_unmodeled(&mut hidden).is_empty());

        let mut absent = tree(phandle(node("other", Some(b"uart-1,samsung\0"), vec![]), 7));
        assert_eq!(hide_unmodeled(&mut absent), ["/radio"]);
        // Availability follows the declared provider, never its node name.
        let mut provided = tree(phandle(
            node("device", Some(b"uart-1,samsung\0"), vec![]),
            0x35,
        ));
        assert!(hide_unmodeled(&mut provided).is_empty());
        assert!(provided.property("/radio", IGNORE).is_none());
        provided
            .node_mut("/device")
            .unwrap()
            .set_property(IGNORE, vec![])
            .unwrap();
        assert_eq!(hide_unmodeled(&mut provided), ["/radio"]);
    }

    #[test]
    fn required_function_chains_are_proven_and_unrooted_cycles_are_hidden() {
        let mut tree = DeviceTree {
            root: node(
                "",
                None,
                vec![
                    function_client("first", 1, 2),
                    function_client("second", 2, 3),
                    phandle(node("provider", Some(b"uart-1,samsung\0"), vec![]), 3),
                ],
            ),
        };
        assert!(hide_unmodeled(&mut tree).is_empty());
        tree.root.children.pop();
        tree.node_mut("/second")
            .unwrap()
            .set_property(
                "function-pcie_port_control",
                [1u32, four_char_code(b"PrtC")]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect(),
            )
            .unwrap();
        assert_eq!(hide_unmodeled(&mut tree), ["/first", "/second"]);
        assert!(tree.property("/first", IGNORE).is_some());
        assert!(tree.property("/second", IGNORE).is_some());
        assert!(hide_unmodeled(&mut tree).is_empty());
    }

    #[test]
    fn undeclared_optional_functions_do_not_hide_clients_but_required_records_must_exist() {
        let mut optional = node("optional", None, vec![]);
        optional
            .set_property(DEVICE_TYPE, b"metadata\0".to_vec())
            .unwrap();
        optional
            .set_property("function-send_disp_clock", vec![])
            .unwrap();
        let mut required = function_client("required", 1, 2);
        required.remove_property("function-pcie_port_control");
        let mut tree = DeviceTree {
            root: node("", None, vec![optional, required]),
        };
        assert_eq!(hide_unmodeled(&mut tree), ["/required"]);
        assert!(tree.property("/optional", IGNORE).is_none());
        // A phandle alone is not a complete platform function.
        let mut malformed = function_client("bad", 3, 2);
        malformed
            .set_property("function-pcie_port_control", 2u32.to_le_bytes().to_vec())
            .unwrap();
        let mut tree = DeviceTree {
            root: node(
                "",
                None,
                vec![
                    malformed,
                    phandle(node("provider", Some(b"uart-1,samsung\0"), vec![]), 2),
                ],
            ),
        };
        assert_eq!(hide_unmodeled(&mut tree), ["/bad"]);
    }

    fn wlan(managed: bool) -> Node {
        let mut client = node("wlan", None, vec![]);
        client
            .set_property(DEVICE_TYPE, b"wlan\0".to_vec())
            .unwrap();
        if managed {
            client
                .set_property("amfm-managed-port-control", vec![])
                .unwrap();
        }
        client
    }

    #[test]
    fn managed_wlan_requires_the_amfm_service_and_its_admitted_provider_chain() {
        // The WLAN nub is independent of /amfm, matches by name and has
        // no compatible. Put it first to exercise transitive convergence.
        let tree = |provider| DeviceTree {
            root: node(
                "",
                None,
                vec![wlan(true), function_client("amfm", 0x24, 0x35), provider],
            ),
        };
        let mut provided = tree(phandle(
            node("provider", Some(b"uart-1,samsung\0"), vec![]),
            0x35,
        ));
        assert!(hide_unmodeled(&mut provided).is_empty());
        assert!(provided.property("/wlan", IGNORE).is_none());
        let mut hidden = tree(phandle(
            node("provider", Some(b"apcie,t8112\0"), vec![]),
            0x35,
        ));
        assert_eq!(hide_unmodeled(&mut hidden), ["/provider", "/wlan", "/amfm"]);
        for path in ["/wlan", "/amfm"] {
            assert!(hidden.property(path, IGNORE).is_some());
        }
        assert!(
            hidden
                .property("/wlan", "amfm-managed-port-control")
                .is_some()
        );
        assert!(hide_unmodeled(&mut hidden).is_empty());
        provided
            .node_mut("/amfm")
            .unwrap()
            .set_property(IGNORE, vec![])
            .unwrap();
        assert_eq!(hide_unmodeled(&mut provided), ["/wlan"]);
        let mut missing = DeviceTree {
            root: node("", None, vec![wlan(true)]),
        };
        assert_eq!(hide_unmodeled(&mut missing), ["/wlan"]);
    }

    #[test]
    fn unmarked_wlan_does_not_infer_a_pcie_requirement_from_its_hardware_class() {
        let mut direct = wlan(false);
        direct
            .set_property(
                "function-pcie_port_control",
                [0x35u32, four_char_code(b"PrtC")]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect(),
            )
            .unwrap();
        let mut tree = DeviceTree {
            root: node(
                "",
                None,
                vec![
                    direct,
                    phandle(node("provider", Some(b"uart-1,samsung\0"), vec![]), 0x35),
                ],
            ),
        };
        assert!(hide_unmodeled(&mut tree).is_empty());
        tree.node_mut("/wlan")
            .unwrap()
            .set_property("amfm-managed-port-control", vec![])
            .unwrap();
        // The marker selects a different required interface: the direct
        // function cannot make a missing AMFM service available.
        assert_eq!(hide_unmodeled(&mut tree), ["/wlan"]);
        let mut absent = DeviceTree {
            root: node("", None, vec![wlan(false)]),
        };
        assert!(hide_unmodeled(&mut absent).is_empty());
        // The driver has an AppleOnboardSerialSync personality too. A
        // WLAN type alone does not establish which bus interface it uses.
        absent
            .node_mut("/wlan")
            .unwrap()
            .set_property(COMPATIBLE, b"uart-1,samsung\0".to_vec())
            .unwrap();
        assert!(hide_unmodeled(&mut absent).is_empty());
        assert!(absent.property("/wlan", COMPATIBLE).is_some());
    }

    fn typed(mut node: Node, kind: &[u8]) -> Node {
        node.set_property(DEVICE_TYPE, kind.to_vec()).unwrap();
        node
    }

    #[test]
    fn only_hidden_audited_service_classes_retire_their_raw_tree_identity() {
        let original = typed(
            phandle(node("unavailable", Some(b"unmodeled-display\0"), vec![]), 9),
            b"display-subsystem\0",
        );
        let mut tree = DeviceTree {
            root: node(
                "",
                None,
                vec![
                    original.clone(),
                    typed(
                        node("admitted", Some(soc::DISPEXT.as_bytes()), vec![]),
                        b"ext-display-subsystem\0",
                    ),
                    typed(
                        node("unmodeled", Some(b"unknown\0"), vec![]),
                        b"unaudited-device\0",
                    ),
                ],
            ),
        };
        let hidden = hide_unmodeled(&mut tree);
        assert_eq!(hidden, ["/unavailable", "/unmodeled"]);
        assert!(tree.property("/unavailable", DEVICE_TYPE).is_none());
        let mut expected = original.clone();
        expected.remove_property(COMPATIBLE);
        expected.remove_property(DEVICE_TYPE);
        // Retirement preserves names, phandles, remaining property order
        // and every other datum. The original input remains unchanged.
        assert_eq!(tree.node("/unavailable").unwrap(), &expected);
        assert_eq!(
            tree.property("/admitted", DEVICE_TYPE).unwrap().value,
            b"ext-display-subsystem\0"
        );
        assert!(tree.property("/admitted", COMPATIBLE).is_some());
        assert_eq!(
            tree.property("/unmodeled", DEVICE_TYPE).unwrap().value,
            b"unaudited-device\0"
        );
        assert!(hide_unmodeled(&mut tree).is_empty());
    }

    #[test]
    fn identity_retirement_requires_a_hidden_ledger_entry_and_preserves_structural_metadata() {
        let mut tree = DeviceTree {
            root: typed(
                node(
                    "",
                    None,
                    vec![
                        typed(
                            node(
                                "arm-io",
                                None,
                                vec![typed(
                                    node("unavailable", None, vec![]),
                                    b"ext-display-subsystem\0",
                                )],
                            ),
                            b"display-subsystem\0",
                        ),
                        node(
                            "cpus",
                            None,
                            vec![typed(node("cpu0", None, vec![]), b"display-subsystem\0")],
                        ),
                        typed(node("memory", None, vec![]), b"memory\0"),
                        typed(node("metadata", None, vec![]), b"display-subsystem\0"),
                    ],
                ),
                b"display-subsystem\0",
            ),
        };
        let original = tree.clone();
        let mut ledger = vec![
            "/".into(),
            "/arm-io".into(),
            "/cpus/cpu0".into(),
            "/memory".into(),
        ];
        retire_hidden_service_identities(&mut tree, &ledger);
        assert_eq!(tree, original);
        ledger.push("/arm-io/unavailable".into());
        retire_hidden_service_identities(&mut tree, &ledger);
        assert!(tree.property("/arm-io/unavailable", DEVICE_TYPE).is_none());
        assert_eq!(
            tree.property("/metadata", DEVICE_TYPE).unwrap().value,
            b"display-subsystem\0"
        );
        assert_eq!(ledger.last().unwrap(), "/arm-io/unavailable");
        let prior = ledger.clone();
        retire_hidden_service_identities(&mut tree, &ledger);
        assert_eq!(ledger, prior);
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
            let mut sgx = node("sgx", Some(b"gpu,t8112".as_slice()), vec![]);
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
    #[ignore = "requires original 26A434 J314s DT through STELA_TEST_DART_DT"]
    fn original_j314s_preparation_keeps_the_complete_external_display_graph() {
        let bytes = std::fs::read(std::env::var("STELA_TEST_DART_DT").unwrap()).unwrap();
        assert_eq!(
            stela_runtime::sha256(&bytes),
            "44fa41bfd0fe0027fd862b8615ae956885614636625d44a59cab226d682558ad"
        );
        let mut tree = DeviceTree::parse(&bytes).unwrap();
        hide_unmodeled(&mut tree);
        for path in [
            "/arm-io/dcpext0",
            "/arm-io/dcpext0-expert",
            "/arm-io/dispext0",
            "/arm-io/dart-dcpext0",
            "/arm-io/dart-dcpext0/mapper-dcpext0",
            "/arm-io/dart-dispext0",
            "/arm-io/dart-dispext0/mapper-dispext0",
        ] {
            assert!(tree.property(path, COMPATIBLE).is_some(), "{path}");
        }
        let surface = tree.node("/arm-io/dart-dispext0").unwrap();
        assert_eq!(surface.property("instance").unwrap().value.len(), 24);
        assert_eq!(surface.property("never-lock").unwrap().value, []);
        assert_eq!(
            surface
                .property("ignore-inconsistent-hw-locks")
                .unwrap()
                .value,
            []
        );
        assert!(tree.property("/arm-io/dcpext1", COMPATIBLE).is_none());
        assert!(tree.property("/arm-io/usb-drd0", COMPATIBLE).is_none());
    }

    #[test]
    fn native_legacy_dart_preparation_preserves_qualified_mapper_dependencies_only() {
        for compatible in [b"dart,t8020\0".as_slice(), b"dart,t6000\0"] {
            let mut engine = aes(b"aes,s8000\0");
            engine
                .set_property(IOMMU_PARENT, 0x8au32.to_le_bytes().to_vec())
                .unwrap();
            let mut stream = mapper("mapper-aes", 0x8a);
            stream
                .set_property("reg", 0u32.to_le_bytes().to_vec())
                .unwrap();
            let mut dart = node("dart-sio", Some(compatible), vec![stream]);
            for (key, bytes) in [
                ("instance", b"TRADDART\0\0\0\0".to_vec()),
                (
                    "reg",
                    [0x235004000u64, 0x4000]
                        .into_iter()
                        .flat_map(u64::to_le_bytes)
                        .collect(),
                ),
                ("page-size", 0x4000u32.to_le_bytes().to_vec()),
                ("sids", 1u32.to_le_bytes().to_vec()),
                ("vm-base", 0u32.to_le_bytes().to_vec()),
            ] {
                dart.set_property(key, bytes).unwrap();
            }
            let original = DeviceTree {
                root: secure_root(node(
                    "device-tree",
                    None,
                    vec![node("arm-io", None, vec![dart, engine])],
                )),
            };
            let mut prepared = original.clone();
            hide_unmodeled(&mut prepared);
            for path in [
                "/arm-io/dart-sio",
                "/arm-io/dart-sio/mapper-aes",
                "/arm-io/aes",
            ] {
                assert!(prepared.property(path, COMPATIBLE).is_some(), "{path}");
            }
            for key in ["instance", "reg", "sids", "vm-base"] {
                assert_eq!(
                    prepared.property("/arm-io/dart-sio", key),
                    original.property("/arm-io/dart-sio", key)
                );
            }
            for unsupported in ["remap", "routing"] {
                let mut prepared = original.clone();
                let dart = prepared.node_mut("/arm-io/dart-sio").unwrap();
                if unsupported == "remap" {
                    dart.set_property("remap", vec![0, 1, 0, 0]).unwrap();
                } else {
                    dart.set_property(
                        "instance",
                        [b"TRADDART\0\0\0\0".as_slice(), b"TRADDARTBLK\0"].concat(),
                    )
                    .unwrap();
                    dart.set_property(
                        "reg",
                        [0x235004000u64, 0x4000, 0x235008000, 0x4000]
                            .into_iter()
                            .flat_map(u64::to_le_bytes)
                            .collect(),
                    )
                    .unwrap();
                }
                hide_unmodeled(&mut prepared);
                for path in [
                    "/arm-io/dart-sio",
                    "/arm-io/dart-sio/mapper-aes",
                    "/arm-io/aes",
                ] {
                    assert!(
                        prepared.property(path, COMPATIBLE).is_none(),
                        "{unsupported}: {path}"
                    );
                }
                assert!(prepared.property("/arm-io/dart-sio", "instance").is_some());
            }
        }
    }

    /// A legacy family without the required native topology/page contract
    /// remains unmodeled, and its DMA clients go with it.
    #[test]
    fn a_device_behind_an_unmodeled_dart_is_hidden_with_it() {
        let mut engine = aes(b"aes,s8000\0");
        engine
            .set_property(IOMMU_PARENT, 0x8a_u32.to_le_bytes().to_vec())
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
                            Some(b"dart,t8020\0"),
                            vec![mapper("mapper-aes", 0x8a)],
                        ),
                        engine,
                    ],
                )],
            )),
        };
        assert_eq!(
            hide_unmodeled(&mut tree),
            [
                "/arm-io/aes",
                "/arm-io/dart-sio",
                "/arm-io/dart-sio/mapper-aes",
                "/ secure-root-prefix",
            ]
        );
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
