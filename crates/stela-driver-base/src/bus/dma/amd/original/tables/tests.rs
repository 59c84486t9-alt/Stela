extern crate std;
use super::*;
use alloc::{boxed::Box, vec};
use std::collections::BTreeMap;
struct Ram {
    frames: BTreeMap<u64, Box<[u64; 512]>>,
    os: Vec<u64>,
}
impl Ram {
    fn table(&mut self, base: u64) {
        self.frames.insert(base, Box::new([0; 512]));
        self.os.push(base);
    }
    fn device(&mut self, base: u64) {
        let mut words = Box::new([0; 512]);
        for rid in 0..128 {
            words[rid * 4] = 1;
        }
        self.frames.insert(base, words);
        self.os.push(base);
    }
    fn dte(&mut self, base: u64, rid: usize, words: [u64; 4]) {
        self.frames.get_mut(&base).unwrap()[rid * 4..rid * 4 + 4].copy_from_slice(&words);
    }
}
// SAFETY: exact synchronous owned frame objects in this model. No firmware,
// device or CPU writer exists except the test's serialized explicit mutations.
// The OS set comes from this model's actual device-frame ownership constructor.
unsafe impl Memory for Ram {
    fn contains(&self, start: u64, bytes: u64) -> bool {
        bytes != 0
            && start.checked_add(bytes).is_some_and(|end| {
                (start & !4095..end.next_multiple_of(4096))
                    .step_by(4096)
                    .all(|p| self.frames.contains_key(&p))
            })
    }
    fn owns_os_ram(&self, start: u64, bytes: u64) -> bool {
        self.contains(start, bytes)
            && (start..start + bytes)
                .step_by(4096)
                .all(|p| self.os.contains(&p))
    }
    fn read(&self, physical: u64) -> Result<u64, Error> {
        let page = physical & !4095;
        let index = ((physical & 4095) / 8) as usize;
        self.frames
            .get(&page)
            .map(|p| p[index])
            .ok_or(Error::Memory)
    }
}
fn ram() -> Ram {
    let mut r = Ram {
        frames: BTreeMap::new(),
        os: vec![],
    };
    r.device(0x1000);
    r.table(0x2000);
    r.table(0x3000);
    r.table(0x10000);
    r.dte(
        0x1000,
        8,
        [1 | 2 | (2 << 9) | READ | WRITE | 0x2000, 1, 0, 0],
    );
    r.frames.get_mut(&0x2000).unwrap()[0] = 1 | (1 << 9) | READ | WRITE | 0x3000;
    r.frames.get_mut(&0x3000).unwrap()[2] = 1 | READ | WRITE | FC | 0x10000;
    r
}
fn description(base: u64) -> Description {
    Description {
        base,
        bytes: 4096,
        physical_bits: 48,
        maximum_levels: 4,
    }
}
#[test]
fn actual_dte_and_pt_words_validate_without_inventing_memory_ownership() {
    let r = ram();
    let i = inspect(&r, description(0x1000), &[8]).unwrap();
    assert_eq!(i.dtes().len(), 128);
    assert_eq!(validate_all(&[i], &[]), Ok(()));
    let mut reserved = ram();
    reserved.os.clear();
    assert!(matches!(
        inspect(&reserved, description(0x1000), &[8]),
        Err(Error::Memory)
    ));
}
#[test]
fn zero_dte_identity_unknown_source_and_nonram_leaf_refuse() {
    let mut r = ram();
    r.dte(0x1000, 7, [0; 4]);
    assert!(matches!(
        inspect(&r, description(0x1000), &[8]),
        Err(Error::Profile)
    ));
    let mut r = ram();
    r.dte(0x1000, 8, [1 | 2 | READ | WRITE, 1, 0, 0]);
    assert!(matches!(
        inspect(&r, description(0x1000), &[8]),
        Err(Error::Profile)
    ));
    let r = ram();
    assert!(matches!(
        inspect(&r, description(0x1000), &[]),
        Err(Error::Source)
    ));
    let mut r = ram();
    r.frames.remove(&0x10000);
    assert!(matches!(
        inspect(&r, description(0x1000), &[8]),
        Err(Error::Memory)
    ));
}

#[test]
fn actual_table_extent_and_physical_width_bound_every_source_and_leaf() {
    let r = ram();
    assert!(matches!(
        inspect(&r, description(0x1000), &[8, 128]),
        Err(Error::Source)
    ));
    let mut r = ram();
    r.table(1 << 48);
    r.frames.get_mut(&0x3000).unwrap()[2] = 1 | READ | WRITE | (1 << 48);
    assert!(matches!(
        inspect(&r, description(0x1000), &[8]),
        Err(Error::Memory)
    ));
}
#[test]
fn complete_union_rejects_another_units_device_control_and_real_queue_backing() {
    let mut r = ram();
    r.device(0x5000);
    r.table(0x6000);
    r.table(0x7000);
    r.dte(
        0x5000,
        8,
        [1 | 2 | (2 << 9) | READ | WRITE | 0x6000, 2, 0, 0],
    );
    r.frames.get_mut(&0x6000).unwrap()[0] = 1 | (1 << 9) | READ | WRITE | 0x7000;
    r.frames.get_mut(&0x7000).unwrap()[0] = 1 | READ | WRITE | 0x10000;
    r.frames.get_mut(&0x3000).unwrap()[2] = 1 | READ | WRITE | 0x5000;
    let a = inspect(&r, description(0x1000), &[8]).unwrap();
    let b = inspect(&r, description(0x5000), &[8]).unwrap();
    assert_eq!(validate_all(&[a, b], &[]), Err(Error::ControlWritable));
    let r = ram();
    let a = inspect(&r, description(0x1000), &[8]).unwrap();
    assert_eq!(
        validate_all(&[a], &[(0x10000, 4096, ControlKind::Command)]),
        Err(Error::ControlWritable)
    );
}
#[test]
fn ancestor_permissions_and_shared_write_revisit_are_effective() {
    let mut r = ram();
    r.frames.get_mut(&0x2000).unwrap()[0] &= !WRITE;
    r.frames.get_mut(&0x3000).unwrap()[2] = 1 | READ | WRITE | 0x2000;
    let a = inspect(&r, description(0x1000), &[8]).unwrap();
    assert_eq!(validate_all(&[a], &[]), Ok(()));
    r.table(0x4000);
    r.frames.get_mut(&0x4000).unwrap()[0] = 1 | (1 << 9) | READ | WRITE | 0x3000;
    r.dte(
        0x1000,
        9,
        [1 | 2 | (2 << 9) | READ | WRITE | 0x4000, 2, 0, 0],
    );
    let a = inspect(&r, description(0x1000), &[8, 9]).unwrap();
    assert_eq!(validate_all(&[a], &[]), Err(Error::ControlWritable));
}
#[test]
fn cycles_and_unimplemented_large_or_skipped_levels_are_explicit() {
    let mut r = ram();
    r.frames.get_mut(&0x2000).unwrap()[0] = 1 | (1 << 9) | READ | WRITE | 0x2000;
    assert!(matches!(
        inspect(&r, description(0x1000), &[8]),
        Err(Error::Cycle)
    ));
    let mut r = ram();
    r.frames.get_mut(&0x2000).unwrap()[0] = 1 | READ | WRITE | 0x10000;
    assert!(matches!(
        inspect(&r, description(0x1000), &[8]),
        Err(Error::UnsupportedLeaf)
    ));
}
