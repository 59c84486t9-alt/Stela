//! Authored publication fixture on the actual retained loader allocation.
use super::{RegisteredSystemRam, source};
use crate::engine::bundle::live_tree::{LiveTree, Ram, registered::ColdRam};
use alloc::vec;
use stela_loader::{
    apple_device_tree::{DeviceTree, Node},
    boot_args::{self, BootArgs, Video},
};
use stela_formats::boot_bundle::LoadedRegion;

/// # Safety
/// Cold fixture owns this exact registered RAM; no frames or producers exist.
pub(super) unsafe fn check(ram: &RegisteredSystemRam) -> Result<(), &'static str> {
    const ARGS: u64 = source::BASE + 0x1000;
    const TREE: u64 = source::BASE + 0x2000;
    const VIRTUAL: u64 = 0xfffffe0000000000;
    let mut tree = DeviceTree {
        root: Node::named("device-tree").map_err(|_| "cold ADT root refused")?,
    };
    let mut chosen = Node::named("chosen").map_err(|_| "cold ADT chosen refused")?;
    chosen
        .set_property("authored-padding", vec![0x91; 64])
        .map_err(|_| "cold ADT padding refused")?;
    let mut map = Node::named("memory-map").map_err(|_| "cold ADT memory-map refused")?;
    let reservation = [TREE.to_le_bytes(), 4096u64.to_le_bytes()].concat();
    map.set_property("DeviceTree", reservation)
        .map_err(|_| "cold ADT reservation refused")?;
    chosen.children.push(map);
    tree.root.children.push(chosen);
    let original = tree.serialize();
    let args = boot_args::encode(&BootArgs {
        revision: boot_args::REVISION,
        version: boot_args::VERSION,
        virt_base: VIRTUAL,
        phys_base: source::BASE,
        mem_size: source::BYTES as u64,
        top_of_kernel_data: source::BASE + source::BYTES as u64,
        video: Video::default(),
        machine_type: 0,
        device_tree: VIRTUAL + TREE - source::BASE,
        device_tree_length: original.len() as u32,
        command_line: "-v".into(),
        boot_flags: 0,
        mem_size_actual: source::BYTES as u64,
    })
    .map_err(|_| "cold boot_args encoding refused")?;
    // SAFETY: caller excludes every other producer until this borrow ends.
    let mut input = unsafe { ColdRam::new(ram) };
    if !input.write(TREE, &original) || !input.write(ARGS, &args) {
        return Err("cold canonical ADT input publication refused");
    }
    let regions = [
        LoadedRegion {
            name: "DeviceTree".into(),
            guest_pa: TREE,
            bytes: original.len() as u64,
            memory_bytes: 4096,
        },
        LoadedRegion {
            name: "BootArgs".into(),
            guest_pa: ARGS,
            bytes: args.len() as u64,
            memory_bytes: 4096,
        },
    ];
    let live = LiveTree::capture(&mut input, &regions, ARGS)
        .map_err(|_| "cold canonical ADT capture refused")?;
    live.require_no_harvesting_override()
        .map_err(|_| "cold actual boot_args check refused")?;
    tree.node_mut("/chosen")
        .ok_or("cold authored chosen missing")?
        .remove_property("authored-padding");
    let live = live
        .publish(&mut input, &tree)
        .map_err(|_| "cold canonical ADT shrink publication refused")?;
    let mut actual = vec![0; original.len()];
    let mut actual_args = vec![0; args.len()];
    if !input.read(TREE, &mut actual)
        || !input.read(ARGS, &mut actual_args)
        || actual[..live.bytes().len()] != *live.bytes()
        || actual[live.bytes().len()..].iter().any(|&byte| byte != 0)
    {
        return Err("cold canonical ADT readback/tail mismatch");
    }
    let mut expected_args = args;
    expected_args[boot_args::offset::DEVICE_TREE_LENGTH..boot_args::offset::DEVICE_TREE_LENGTH + 4]
        .copy_from_slice(&(live.bytes().len() as u32).to_le_bytes());
    if actual_args != expected_args {
        return Err("cold canonical boot_args unrelated bytes changed");
    }
    crate::output::arguments(format_args!(
        "NATIVE COLD ADT actual_registered_RAM=same before={} after={} reservation=4096 tail=zero boot_args=length-only original_macOS=unqualified\n",
        original.len(),
        live.bytes().len()
    ));
    Ok(())
}
