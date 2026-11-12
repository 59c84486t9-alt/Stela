//! The block devices the running Linux system stands on, which setup never
//! erases. The mount table says what each system mount stands on: a block
//! device by number, a device node (btrfs reports an anonymous number), a ZFS
//! dataset's pool, or an overlay's layers, which are directories on other
//! mounts. sysfs says what each block device stands on in turn: a
//! device-mapper or RAID device's members (LVM, LUKS, md), a loop device's
//! backing file, which is on another mount again. Every device on the way
//! down counts, so the disks under them do.
use std::collections::BTreeSet;

/// One line of `/proc/self/mountinfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Mount {
    /// The device number `st_dev` reports; major 0 is anonymous (overlay,
    /// tmpfs, btrfs, ZFS, network file systems).
    pub(super) major: u32,
    pub(super) minor: u32,
    pub(super) point: String,
    pub(super) kind: String,
    pub(super) source: String,
    /// The file system's own options, which name an overlay's layers.
    pub(super) options: String,
}

/// The mounts `mountinfo` lists, in mount order: a later mount on the same
/// point covers an earlier one.
pub(super) fn mounts(mountinfo: &str) -> Vec<Mount> {
    mountinfo
        .lines()
        .filter_map(|line| {
            let (mount, filesystem) = line.split_once(" - ")?;
            let fields: Vec<&str> = mount.split(' ').collect();
            let (major, minor) = fields.get(2)?.split_once(':')?;
            let mut filesystem = filesystem.split(' ');
            Some(Mount {
                major: major.parse().ok()?,
                minor: minor.parse().ok()?,
                point: unescape(fields.get(4)?),
                kind: unescape(filesystem.next()?),
                source: unescape(filesystem.next()?),
                options: unescape(filesystem.next().unwrap_or_default()),
            })
        })
        .collect()
}

/// The kernel writes space, tab, newline and backslash in mountinfo as octal
/// escapes.
fn unescape(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let octal = bytes.get(i + 1..i + 4).filter(|digits| {
            bytes[i] == b'\\' && digits.iter().all(|digit| (b'0'..=b'7').contains(digit))
        });
        match octal.and_then(|digits| u8::from_str_radix(std::str::from_utf8(digits).ok()?, 8).ok())
        {
            Some(byte) => {
                out.push(byte);
                i += 4;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// What sysfs (and, for ZFS, the pool labels) say about block devices, by
/// kernel name such as `nvme0n1p2`, `dm-0`, `md127` or `loop3`.
pub(super) trait Blocks {
    /// The device numbered `major:minor`.
    fn by_number(&self, major: u32, minor: u32) -> Option<String>;
    /// The device a node such as `/dev/mapper/root` names.
    fn by_node(&self, node: &str) -> Option<String>;
    /// The devices `name` is made of: sysfs's `slaves`.
    fn members(&self, name: &str) -> Vec<String>;
    /// A loop device's backing file.
    fn backing_file(&self, name: &str) -> Option<String>;
    /// Every device of the btrfs file system on `name`, which may span
    /// several.
    fn btrfs_devices(&self, name: &str) -> Vec<String>;
    /// The devices of ZFS pool `pool`.
    fn zfs_members(&self, pool: &str) -> Vec<String>;
}

/// What the system mounts stand on.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct SystemDevices {
    /// Every block device under a system mount, by kernel name.
    pub(super) names: BTreeSet<String>,
    /// Why the root file system's devices are unknown, or `None` when they
    /// were found.
    pub(super) unknown_root: Option<String>,
}

/// File systems held in memory: a root of this kind is rebuilt each boot,
/// and the system itself is in `/usr` or a package store.
const MEMORY: [&str; 3] = ["tmpfs", "ramfs", "rootfs"];
/// Where a system with its root in memory keeps the system itself.
const SYSTEM_TREES: [&str; 4] = ["/usr", "/nix/store", "/nix", "/gnu/store"];
/// OSTree's physical root, under an overlay or bind-mounted root.
const OSTREE_ROOT: &str = "/sysroot";

/// The devices under each mount of `points` that `mounts` lists.
pub(super) fn system_devices(
    mounts: &[Mount],
    blocks: &dyn Blocks,
    points: &[&str],
) -> SystemDevices {
    let mut resolver = Resolver {
        mounts,
        blocks,
        names: BTreeSet::new(),
        visiting: Vec::new(),
    };
    let mut found = BTreeSet::new();
    for point in points {
        if let Some(index) = top(mounts, point)
            && resolver.mount(index)
        {
            found.insert(*point);
        }
    }
    let root = top(mounts, "/").map(|index| &mounts[index]);
    let unknown_root = match root {
        _ if found.contains("/") => None,
        Some(root)
            if MEMORY.contains(&root.kind.as_str())
                && SYSTEM_TREES.iter().any(|tree| found.contains(tree)) =>
        {
            None
        }
        Some(root) if root.kind == "overlay" && found.contains(OSTREE_ROOT) => None,
        Some(root) => Some(format!("/ is {} {}", root.kind, root.source)),
        None => Some("the mount table lists no /".into()),
    };
    SystemDevices {
        names: resolver.names,
        unknown_root,
    }
}

/// The mount that covers mount point `point`.
fn top(mounts: &[Mount], point: &str) -> Option<usize> {
    mounts.iter().rposition(|mount| mount.point == point)
}

/// The mount holding `path`: the deepest mount point above it, the latest of
/// those on the same point.
fn containing(mounts: &[Mount], path: &str) -> Option<usize> {
    let under = |point: &str| {
        point == "/"
            || path == point
            || path
                .strip_prefix(point)
                .is_some_and(|rest| rest.starts_with('/'))
    };
    mounts
        .iter()
        .enumerate()
        .filter(|(_, mount)| path.starts_with('/') && under(&mount.point))
        .max_by_key(|(index, mount)| (mount.point.len(), *index))
        .map(|(index, _)| index)
}

/// An overlay's layer directories: `lowerdir` (layers split by `:`, data-only
/// layers after `::`), `lowerdir+`, `datadir+` and `upperdir`. A backslash
/// escapes a separator.
fn layers(options: &str) -> Vec<String> {
    let mut layers = Vec::new();
    for option in split_escaped(options, ',') {
        let Some((key, value)) = option.split_once('=') else {
            continue;
        };
        match key {
            "lowerdir" => layers.extend(
                split_escaped(value, ':')
                    .iter()
                    .filter(|layer| !layer.is_empty())
                    .map(|layer| unescaped(layer)),
            ),
            "lowerdir+" | "datadir+" | "upperdir" => layers.push(unescaped(value)),
            _ => {}
        }
    }
    layers
}

/// `text`'s parts between unescaped `separator`s, escapes kept.
fn split_escaped(text: &str, separator: char) -> Vec<String> {
    let mut parts = vec![String::new()];
    let mut characters = text.chars();
    while let Some(character) = characters.next() {
        let part = parts.last_mut().expect("one part");
        match character {
            '\\' => {
                part.push('\\');
                part.extend(characters.next());
            }
            _ if character == separator => parts.push(String::new()),
            _ => part.push(character),
        }
    }
    parts
}

/// `text` with each backslash escape replaced by the character it escapes.
fn unescaped(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut characters = text.chars();
    while let Some(character) = characters.next() {
        match character {
            '\\' => out.extend(characters.next()),
            _ => out.push(character),
        }
    }
    out
}

struct Resolver<'a> {
    mounts: &'a [Mount],
    blocks: &'a dyn Blocks,
    names: BTreeSet<String>,
    /// Mounts being resolved, which a loop device's backing file or an
    /// overlay layer may lead back to.
    visiting: Vec<usize>,
}

impl Resolver<'_> {
    /// Adds the devices under mount `index`; whether there were any.
    fn mount(&mut self, index: usize) -> bool {
        if self.visiting.contains(&index) {
            return false;
        }
        self.visiting.push(index);
        let mount = &self.mounts[index];
        let mut devices = Vec::new();
        if mount.kind == "zfs" {
            let pool = mount.source.split('/').next().unwrap_or_default();
            devices.extend(self.blocks.zfs_members(pool));
        } else if mount.major != 0 {
            devices.extend(self.blocks.by_number(mount.major, mount.minor));
        } else if mount.source.starts_with("/dev/") {
            devices.extend(self.blocks.by_node(&mount.source));
        }
        if mount.kind == "btrfs" {
            let all: Vec<_> = devices
                .iter()
                .flat_map(|device| self.blocks.btrfs_devices(device))
                .collect();
            devices.extend(all);
        }
        let mut found = !devices.is_empty();
        for device in devices {
            self.device(&device);
        }
        if mount.kind == "overlay" {
            for layer in layers(&mount.options) {
                if let Some(holder) = containing(self.mounts, &layer) {
                    found |= self.mount(holder);
                }
            }
        }
        self.visiting.pop();
        found
    }

    /// Adds `name` and the devices and mounts it stands on.
    fn device(&mut self, name: &str) {
        if !self.names.insert(name.to_owned()) {
            return;
        }
        for member in self.blocks.members(name) {
            self.device(&member);
        }
        if let Some(file) = self.blocks.backing_file(name) {
            let file = file.strip_suffix(" (deleted)").unwrap_or(&file).to_owned();
            if let Some(holder) = containing(self.mounts, &file) {
                self.mount(holder);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// A sysfs and pool listing of a test's choosing.
    #[derive(Default)]
    struct Fake {
        numbers: BTreeMap<(u32, u32), &'static str>,
        nodes: BTreeMap<&'static str, &'static str>,
        members: BTreeMap<&'static str, Vec<&'static str>>,
        backing: BTreeMap<&'static str, &'static str>,
        btrfs: Vec<Vec<&'static str>>,
        zfs: BTreeMap<&'static str, Vec<&'static str>>,
    }

    impl Blocks for Fake {
        fn by_number(&self, major: u32, minor: u32) -> Option<String> {
            self.numbers
                .get(&(major, minor))
                .map(|name| name.to_string())
        }
        fn by_node(&self, node: &str) -> Option<String> {
            self.nodes.get(node).map(|name| name.to_string())
        }
        fn members(&self, name: &str) -> Vec<String> {
            let members = self.members.get(name).into_iter().flatten();
            members.map(|member| member.to_string()).collect()
        }
        fn backing_file(&self, name: &str) -> Option<String> {
            self.backing.get(name).map(|file| file.to_string())
        }
        fn btrfs_devices(&self, name: &str) -> Vec<String> {
            let devices = self.btrfs.iter().find(|devices| devices.contains(&name));
            devices
                .into_iter()
                .flatten()
                .map(|device| device.to_string())
                .collect()
        }
        fn zfs_members(&self, pool: &str) -> Vec<String> {
            let members = self.zfs.get(pool).into_iter().flatten();
            members.map(|member| member.to_string()).collect()
        }
    }

    const POINTS: [&str; 6] = ["/", "/sysroot", "/usr", "/boot", "/nix/store", "/home"];

    fn resolve(mountinfo: &str, blocks: &Fake) -> SystemDevices {
        system_devices(&mounts(mountinfo), blocks, &POINTS)
    }

    fn names(devices: &SystemDevices) -> Vec<&str> {
        devices.names.iter().map(String::as_str).collect()
    }

    #[test]
    fn mountinfo_fields_and_escapes() {
        let parsed = mounts(
            "36 35 98:0 /mnt1 /mnt\\040two rw,noatime master:1 - ext3 /dev/root rw,errors=continue\n\
             garbage\n",
        );
        assert_eq!(
            parsed,
            [Mount {
                major: 98,
                minor: 0,
                point: "/mnt two".into(),
                kind: "ext3".into(),
                source: "/dev/root".into(),
                options: "rw,errors=continue".into(),
            }]
        );
    }

    #[test]
    fn a_plain_partition_root() {
        let blocks = Fake {
            numbers: [((259, 2), "nvme0n1p2"), ((259, 1), "nvme0n1p1")].into(),
            ..Fake::default()
        };
        let devices = resolve(
            "1 0 259:2 / / rw - ext4 /dev/nvme0n1p2 rw\n\
             2 1 259:1 / /boot rw - vfat /dev/nvme0n1p1 rw\n",
            &blocks,
        );
        assert_eq!(names(&devices), ["nvme0n1p1", "nvme0n1p2"]);
        assert_eq!(devices.unknown_root, None);
    }

    #[test]
    fn btrfs_subvolumes_and_every_device_of_the_file_system() {
        // btrfs reports an anonymous number; its source names the device,
        // and the file system spans two.
        let blocks = Fake {
            nodes: [("/dev/sda2", "sda2")].into(),
            btrfs: vec![vec!["sda2", "sdb1"]],
            ..Fake::default()
        };
        let devices = resolve(
            "1 0 0:30 /@ / rw - btrfs /dev/sda2 rw,subvol=/@\n\
             2 1 0:30 /@home /home rw - btrfs /dev/sda2 rw,subvol=/@home\n",
            &blocks,
        );
        assert_eq!(names(&devices), ["sda2", "sdb1"]);
        assert_eq!(devices.unknown_root, None);
    }

    #[test]
    fn lvm_on_luks_on_a_partition() {
        let blocks = Fake {
            numbers: [((253, 1), "dm-1")].into(),
            members: [("dm-1", vec!["dm-0"]), ("dm-0", vec!["nvme0n1p3"])].into(),
            ..Fake::default()
        };
        let devices = resolve("1 0 253:1 / / rw - xfs /dev/mapper/vg-root rw\n", &blocks);
        assert_eq!(names(&devices), ["dm-0", "dm-1", "nvme0n1p3"]);
        assert_eq!(devices.unknown_root, None);
    }

    #[test]
    fn raid_members() {
        let blocks = Fake {
            numbers: [((9, 127), "md127")].into(),
            members: [("md127", vec!["sda1", "sdb1"])].into(),
            ..Fake::default()
        };
        let devices = resolve("1 0 9:127 / / rw - ext4 /dev/md127 rw\n", &blocks);
        assert_eq!(names(&devices), ["md127", "sda1", "sdb1"]);
    }

    #[test]
    fn zfs_root_by_its_pool() {
        let blocks = Fake {
            zfs: [("rpool", vec!["nvme0n1p4", "nvme1n1p4"])].into(),
            ..Fake::default()
        };
        let devices = resolve(
            "1 0 0:25 / / rw - zfs rpool/ROOT/ubuntu_abc rw,xattr,posixacl\n",
            &blocks,
        );
        assert_eq!(names(&devices), ["nvme0n1p4", "nvme1n1p4"]);
        assert_eq!(devices.unknown_root, None);
        // Without the pool's labels, the root is unknown.
        let unknown = resolve(
            "1 0 0:25 / / rw - zfs rpool/ROOT/ubuntu_abc rw\n",
            &Fake::default(),
        );
        assert_eq!(
            unknown.unknown_root.as_deref(),
            Some("/ is zfs rpool/ROOT/ubuntu_abc")
        );
    }

    #[test]
    fn ostree_composefs_root_stands_on_sysroot() {
        // The overlay's lower layer was mounted privately and is gone; its
        // data-only layer and /sysroot are on the disk.
        let blocks = Fake {
            numbers: [((259, 3), "nvme0n1p3")].into(),
            ..Fake::default()
        };
        let mountinfo = "\
            20 1 259:3 / /sysroot ro - btrfs /dev/nvme0n1p3 ro\n\
            1 0 0:40 / / ro - overlay composefs ro,lowerdir=/run/ostree/.private/cfsroot-lower::/sysroot/ostree/repo/objects,redirect_dir=on\n\
            21 1 0:26 / /run rw - tmpfs tmpfs rw\n";
        let devices = resolve(mountinfo, &blocks);
        assert_eq!(names(&devices), ["nvme0n1p3"]);
        assert_eq!(devices.unknown_root, None);
        // Without the layer in the options, /sysroot still identifies it.
        let devices = resolve(
            "20 1 259:3 / /sysroot ro - ext4 /dev/vda3 ro\n\
             1 0 0:40 / / ro - overlay composefs ro\n",
            &blocks,
        );
        assert_eq!(names(&devices), ["nvme0n1p3"]);
        assert_eq!(devices.unknown_root, None);
    }

    #[test]
    fn ostree_bind_mounted_deployment() {
        let blocks = Fake {
            numbers: [((8, 3), "sda3")].into(),
            ..Fake::default()
        };
        let devices = resolve(
            "1 0 8:3 /ostree/deploy/fedora/deploy/abc.0 / rw - xfs /dev/sda3 rw\n\
             2 1 8:3 / /sysroot rw - xfs /dev/sda3 rw\n",
            &blocks,
        );
        assert_eq!(names(&devices), ["sda3"]);
        assert_eq!(devices.unknown_root, None);
    }

    #[test]
    fn live_usb_overlay_on_a_squashfs_on_the_stick() {
        // An overlay of a RAM upper layer on a squashfs, looped from a file
        // on the stick's partition.
        let blocks = Fake {
            numbers: [((7, 0), "loop0"), ((8, 17), "sdb1")].into(),
            backing: [("loop0", "/run/archiso/bootmnt/arch/x86_64/airootfs.sfs")].into(),
            ..Fake::default()
        };
        let devices = resolve(
            "10 1 8:17 / /run/archiso/bootmnt ro - iso9660 /dev/sdb1 ro\n\
             11 1 0:29 / /run/archiso/cowspace rw - tmpfs cowspace rw\n\
             12 1 7:0 / /run/archiso/airootfs ro - squashfs /dev/loop0 ro\n\
             1 0 0:31 / / rw - overlay airootfs rw,lowerdir=/run/archiso/airootfs,upperdir=/run/archiso/cowspace/upperdir,workdir=/run/archiso/cowspace/workdir\n",
            &blocks,
        );
        assert_eq!(names(&devices), ["loop0", "sdb1"]);
        assert_eq!(devices.unknown_root, None);
    }

    #[test]
    fn a_volatile_root_runs_from_usr_or_the_store() {
        let blocks = Fake {
            numbers: [((259, 2), "nvme0n1p2")].into(),
            ..Fake::default()
        };
        let devices = resolve(
            "1 0 0:24 / / rw - tmpfs none rw,mode=755\n\
             2 1 259:2 /nix/store /nix/store ro - ext4 /dev/nvme0n1p2 ro\n",
            &blocks,
        );
        assert_eq!(names(&devices), ["nvme0n1p2"]);
        assert_eq!(devices.unknown_root, None);
    }

    #[test]
    fn roots_that_name_no_disk_are_unknown() {
        for (mountinfo, reason) in [
            ("1 0 0:24 / / rw - tmpfs none rw\n", "/ is tmpfs none"),
            (
                "1 0 0:50 / / rw - nfs4 server:/export rw\n",
                "/ is nfs4 server:/export",
            ),
            (
                // A container's overlay, whose layers are another namespace's.
                "1 0 0:60 / / rw - overlay overlay rw,lowerdir=/var/lib/x/l,upperdir=/var/lib/x/u\n",
                "/ is overlay overlay",
            ),
            ("", "the mount table lists no /"),
        ] {
            let devices = resolve(mountinfo, &Fake::default());
            assert_eq!(devices.unknown_root.as_deref(), Some(reason));
            assert!(devices.names.is_empty());
        }
    }

    #[test]
    fn a_loop_cycle_ends() {
        // A loop device backed by a file on its own file system.
        let blocks = Fake {
            numbers: [((7, 1), "loop1")].into(),
            backing: [("loop1", "/image (deleted)")].into(),
            ..Fake::default()
        };
        let devices = resolve("1 0 7:1 / / rw - ext4 /dev/loop1 rw\n", &blocks);
        assert_eq!(names(&devices), ["loop1"]);
    }

    #[test]
    fn layers_split_on_unescaped_separators() {
        assert_eq!(
            layers("rw,lowerdir=/a:/b\\:c::/d,upperdir=/u,workdir=/w,lowerdir+=/e,datadir+=/f"),
            ["/a", "/b:c", "/d", "/u", "/e", "/f"]
        );
    }
}
