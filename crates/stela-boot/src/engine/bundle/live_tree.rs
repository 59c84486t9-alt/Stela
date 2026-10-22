//! The actual post-patch ADT in guest RAM, before any guest entry.
//!
//! Region byte offsets remain valid until Verified::load finishes. Projection
//! happens afterwards. Its shorter encoding changes boot_args' data length,
//! while /chosen/memory-map continues to reserve the original whole allocation.
use alloc::{format, string::String, vec::Vec};
use stela_loader::{
    apple_device_tree::DeviceTree,
    boot_args::{self, BootArgs},
};
use stela_runtime::{boot_bundle::LoadedRegion, machine::Host};

pub(crate) trait Ram {
    fn read(&mut self, physical: u64, bytes: &mut [u8]) -> bool;
    fn write(&mut self, physical: u64, bytes: &[u8]) -> bool;
    fn fence(&mut self);
}
impl<H: Host> Ram for H {
    fn read(&mut self, physical: u64, bytes: &mut [u8]) -> bool {
        self.read_ram(physical, bytes)
    }
    fn write(&mut self, physical: u64, bytes: &[u8]) -> bool {
        self.write_ram(physical, bytes)
    }
    fn fence(&mut self) {
        self.memory_barrier();
    }
}

// The live bytes include fresh entropy slots; never expose them through Debug.
pub(crate) struct LiveTree {
    physical: u64,
    reservation_bytes: u64,
    args_physical: u64,
    args: [u8; boot_args::BYTES],
    bytes: Vec<u8>,
}

fn buffer(length: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| "live DeviceTree allocation failed")?;
    bytes.resize(length, 0);
    Ok(bytes)
}
fn region<'a>(regions: &'a [LoadedRegion], name: &str) -> Result<&'a LoadedRegion, String> {
    let mut selected = regions.iter().filter(|r| r.name == name);
    let r = selected
        .next()
        .ok_or_else(|| format!("loaded bundle has no {name} region"))?;
    if selected.next().is_some()
        || r.bytes == 0
        || r.bytes > r.memory_bytes
        || r.guest_pa.checked_add(r.memory_bytes).is_none()
    {
        return Err(format!("loaded {name} region is ambiguous or invalid"));
    }
    Ok(r)
}
fn reservation(tree: &DeviceTree, physical: u64, bytes: u64) -> Result<(), String> {
    let p = tree
        .node("/chosen/memory-map")
        .and_then(|n| n.property("DeviceTree"))
        .ok_or("live DeviceTree has no retained memory-map allocation")?;
    if p.placeholder
        || p.value.len() != 16
        || p.value[..8] != physical.to_le_bytes()
        || p.value[8..] != bytes.to_le_bytes()
    {
        return Err("live DeviceTree memory-map differs from its loaded allocation".into());
    }
    Ok(())
}

impl LiveTree {
    /// The caller excludes guest entry, guest DMA and changes to the loaded RAM
    /// mapping throughout capture, projection and consuming publication.
    pub(crate) fn capture(
        ram: &mut impl Ram,
        regions: &[LoadedRegion],
        x0: u64,
    ) -> Result<Self, String> {
        let tree = region(regions, "DeviceTree")?;
        let args_region = region(regions, "BootArgs")?;
        if x0 != args_region.guest_pa
            || args_region.bytes < boot_args::BYTES as u64
            || !(tree.guest_pa + tree.memory_bytes <= args_region.guest_pa
                || args_region.guest_pa + args_region.memory_bytes <= tree.guest_pa)
        {
            return Err("loaded DeviceTree and boot_args allocations disagree or overlap".into());
        }
        let mut args = [0; boot_args::BYTES];
        if !ram.read(x0, &mut args) {
            return Err("loaded boot_args could not be read from guest RAM".into());
        }
        let decoded = BootArgs::decode(&args).map_err(|e| format!("live boot_args: {e}"))?;
        let physical = decoded
            .device_tree
            .checked_sub(decoded.virt_base)
            .and_then(|offset| decoded.phys_base.checked_add(offset));
        if decoded.revision != boot_args::REVISION
            || decoded.version != boot_args::VERSION
            || physical != Some(tree.guest_pa)
            || u64::from(decoded.device_tree_length) != tree.bytes
        {
            return Err(
                "live boot_args DeviceTree pointer/length/layout differs from the loaded region"
                    .into(),
            );
        }
        let mut bytes =
            buffer(usize::try_from(tree.bytes).map_err(|_| "live DeviceTree length overflows")?)?;
        if !ram.read(tree.guest_pa, &mut bytes) {
            return Err("loaded DeviceTree could not be read from guest RAM".into());
        }
        let parsed = DeviceTree::parse(&bytes).map_err(|e| format!("live DeviceTree: {e}"))?;
        reservation(&parsed, tree.guest_pa, tree.memory_bytes)?;
        Ok(Self {
            physical: tree.guest_pa,
            reservation_bytes: tree.memory_bytes,
            args_physical: x0,
            args,
            bytes,
        })
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the old snapshot. Any reached write failure is terminal before
    /// guest entry: a later boot_args failure does not undo an earlier ADT write.
    /// This supplies no new RAM reservation, physical resource or CPU authority.
    #[allow(dead_code)] // Adoption also needs the actual Plan/RAM/device owners.
    pub(crate) fn publish(
        mut self,
        ram: &mut impl Ram,
        projected: &DeviceTree,
    ) -> Result<Self, String> {
        reservation(projected, self.physical, self.reservation_bytes)?;
        let bytes = projected.serialize();
        if bytes.len() > self.bytes.len() {
            return Err(
                "assigned DeviceTree projection grows beyond its original data span".into(),
            );
        }
        let length =
            u32::try_from(bytes.len()).map_err(|_| "projected DeviceTree length overflows")?;
        let mut old = buffer(self.bytes.len())?;
        let mut args = [0; boot_args::BYTES];
        if !ram.read(self.physical, &mut old)
            || !ram.read(self.args_physical, &mut args)
            || old != self.bytes
            || args != self.args
        {
            return Err("live DeviceTree publication snapshot is stale or inaccessible".into());
        }
        old.fill(0);
        old[..bytes.len()].copy_from_slice(&bytes);
        if !ram.write(self.physical, &old) {
            return Err("DeviceTree publication failed; guest entry is forbidden".into());
        }
        let length_at = self.args_physical + boot_args::offset::DEVICE_TREE_LENGTH as u64;
        if !ram.write(length_at, &length.to_le_bytes()) {
            return Err("DeviceTree was written but boot_args length publication failed; guest entry is forbidden".into());
        }
        self.args[boot_args::offset::DEVICE_TREE_LENGTH..boot_args::offset::DEVICE_TREE_LENGTH + 4]
            .copy_from_slice(&length.to_le_bytes());
        ram.fence();
        let mut actual = buffer(old.len())?;
        if !ram.read(self.physical, &mut actual)
            || actual != old
            || !ram.read(self.args_physical, &mut args)
            || args != self.args
        {
            return Err("DeviceTree publication readback failed; guest entry is forbidden".into());
        }
        self.bytes = bytes;
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use stela_loader::{
        apple_device_tree::{Node, Property},
        boot_args::Video,
    };
    const BASE: u64 = 0x10000;
    const ARGS: u64 = BASE + 0x1000;
    const TREE: u64 = BASE + 0x2000;
    struct Memory {
        bytes: Vec<u8>,
        writes: usize,
        fail_write: Option<usize>,
        fences: usize,
    }
    impl Ram for Memory {
        fn read(&mut self, pa: u64, out: &mut [u8]) -> bool {
            let Some(offset) = pa.checked_sub(BASE).and_then(|v| usize::try_from(v).ok()) else {
                return false;
            };
            let Some(end) = offset.checked_add(out.len()) else {
                return false;
            };
            let Some(source) = self.bytes.get(offset..end) else {
                return false;
            };
            out.copy_from_slice(source);
            true
        }
        fn write(&mut self, pa: u64, bytes: &[u8]) -> bool {
            let next = self.writes;
            self.writes += 1;
            if self.fail_write == Some(next) {
                return false;
            }
            let Some(offset) = pa.checked_sub(BASE).and_then(|v| usize::try_from(v).ok()) else {
                return false;
            };
            let Some(end) = offset.checked_add(bytes.len()) else {
                return false;
            };
            let Some(target) = self.bytes.get_mut(offset..end) else {
                return false;
            };
            target.copy_from_slice(bytes);
            true
        }
        fn fence(&mut self) {
            self.fences += 1;
        }
    }
    fn fixture() -> (Memory, Vec<LoadedRegion>, DeviceTree) {
        let mut tree = DeviceTree {
            root: Node::named("device-tree").unwrap(),
        };
        tree.ensure_child("/", "chosen").unwrap();
        let chosen = tree.node_mut("/chosen").unwrap();
        chosen
            .properties
            .push(Property::new("live-entropy", vec![0x57; 32]).unwrap());
        tree.ensure_child("/chosen", "memory-map").unwrap();
        let map = tree.node_mut("/chosen/memory-map").unwrap();
        let mut allocation = TREE.to_le_bytes().to_vec();
        allocation.extend(4096u64.to_le_bytes());
        map.set_property("DeviceTree", allocation).unwrap();
        let bytes = tree.serialize();
        let args = BootArgs {
            revision: boot_args::REVISION,
            version: boot_args::VERSION,
            virt_base: 0xfffffe0000000000,
            phys_base: BASE,
            mem_size: 0x5000,
            top_of_kernel_data: BASE + 0x4000,
            video: Video::default(),
            machine_type: 0,
            device_tree: 0xfffffe0000002000,
            device_tree_length: bytes.len() as u32,
            command_line: "-v".into(),
            boot_flags: 0,
            mem_size_actual: 0x5000,
        }
        .encode()
        .unwrap();
        let mut memory = Memory {
            bytes: vec![0; 0x5000],
            writes: 0,
            fail_write: None,
            fences: 0,
        };
        memory.bytes[0x1000..0x1000 + args.len()].copy_from_slice(&args);
        memory.bytes[0x1004] = 0x7e; // Preserve unrelated boot_args padding too.
        memory.bytes[0x2000..0x2000 + bytes.len()].copy_from_slice(&bytes);
        let regions = vec![
            LoadedRegion {
                name: "DeviceTree".into(),
                guest_pa: TREE,
                bytes: bytes.len() as u64,
                memory_bytes: 4096,
            },
            LoadedRegion {
                name: "BootArgs".into(),
                guest_pa: ARGS,
                bytes: args.len() as u64,
                memory_bytes: 4096,
            },
        ];
        (memory, regions, tree)
    }
    #[test]
    fn actual_live_bytes_and_nonidentity_boot_pointer_are_captured() {
        let (mut ram, regions, mut tree) = fixture();
        tree.node_mut("/chosen")
            .unwrap()
            .set_property("live-entropy", vec![0xa1; 32])
            .unwrap();
        let bytes = tree.serialize();
        ram.bytes[0x2000..0x2000 + bytes.len()].copy_from_slice(&bytes);
        let live = LiveTree::capture(&mut ram, &regions, ARGS).unwrap();
        assert_eq!(live.bytes(), bytes);
        assert_eq!(ram.writes, 0);
    }
    #[test]
    fn shrink_updates_only_data_length_and_keeps_full_allocation_and_clears_old_tail() {
        let (mut ram, regions, mut tree) = fixture();
        let live = LiveTree::capture(&mut ram, &regions, ARGS).unwrap();
        let old_length = live.bytes().len();
        tree.node_mut("/chosen")
            .unwrap()
            .remove_property("live-entropy");
        let before = ram.bytes[0x1000..0x1000 + boot_args::BYTES].to_vec();
        let live = live.publish(&mut ram, &tree).unwrap();
        assert_eq!(live.bytes(), tree.serialize());
        assert_eq!(ram.writes, 2);
        assert_eq!(ram.fences, 1);
        assert!(
            ram.bytes[0x2000 + live.bytes().len()..0x2000 + old_length]
                .iter()
                .all(|&v| v == 0)
        );
        reservation(&tree, TREE, 4096).unwrap();
        let mut expected = before;
        expected[104..108].copy_from_slice(&(live.bytes().len() as u32).to_le_bytes());
        assert_eq!(&ram.bytes[0x1000..0x1000 + boot_args::BYTES], expected);
    }
    #[test]
    fn invalid_addresses_lengths_regions_or_reservation_refuse_without_writes() {
        for fault in 0..5 {
            let (mut ram, mut regions, _) = fixture();
            match fault {
                0 => ram.bytes[0x1000 + 96..0x1000 + 104].fill(0),
                1 => ram.bytes[0x1000 + 104..0x1000 + 108].copy_from_slice(&u32::MAX.to_le_bytes()),
                2 => regions.push(regions[0].clone()),
                3 => regions[1].guest_pa = TREE,
                _ => regions[0].memory_bytes = 8192,
            }
            assert!(LiveTree::capture(&mut ram, &regions, ARGS).is_err());
            assert_eq!(ram.writes, 0);
        }
    }
    #[test]
    fn stale_snapshot_or_changed_allocation_refuses_before_any_write() {
        for fault in 0..3 {
            let (mut ram, regions, mut tree) = fixture();
            let live = LiveTree::capture(&mut ram, &regions, ARGS).unwrap();
            match fault {
                0 => ram.bytes[0x1004] ^= 1,
                1 => ram.bytes[0x2020] ^= 1,
                _ => tree
                    .node_mut("/chosen/memory-map")
                    .unwrap()
                    .set_property("DeviceTree", vec![0; 16])
                    .unwrap(),
            }
            assert!(live.publish(&mut ram, &tree).is_err());
            assert_eq!(ram.writes, 0);
        }
    }
    #[test]
    fn second_write_failure_preserves_reached_tree_and_refuses_guest_entry() {
        let (mut ram, regions, mut tree) = fixture();
        let live = LiveTree::capture(&mut ram, &regions, ARGS).unwrap();
        let old_args = ram.bytes[0x1000..0x1000 + boot_args::BYTES].to_vec();
        tree.node_mut("/chosen")
            .unwrap()
            .remove_property("live-entropy");
        ram.fail_write = Some(1);
        assert!(
            live.publish(&mut ram, &tree)
                .err()
                .expect("a failed boot_args publication must refuse entry")
                .contains("guest entry is forbidden")
        );
        assert_eq!(
            &ram.bytes[0x2000..0x2000 + tree.serialize().len()],
            tree.serialize()
        );
        assert_eq!(&ram.bytes[0x1000..0x1000 + boot_args::BYTES], old_args);
    }
}
