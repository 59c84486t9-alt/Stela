//! Initial offline-AP memory types, copied from the live BSP configuration.
//! This is not an update protocol for an already participating processor.
use super::topology::Snapshot;

pub(crate) const CAP: u32 = 0xfe;
pub(crate) const DEFAULT: u32 = 0x2ff;
pub(crate) const VARIABLE_BASE: u32 = 0x200;
pub(crate) const MAX_VARIABLE: usize = 16;
pub(crate) const FIXED: [u32; 11] = [
    0x250, 0x258, 0x259, 0x268, 0x269, 0x26a, 0x26b, 0x26c, 0x26d, 0x26e, 0x26f,
];
pub(crate) const MAX_WRITABLE: usize = FIXED.len() + 2 * MAX_VARIABLE;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct Write {
    pub index: u32,
    pub low: u32,
    pub high: u32,
}

pub(crate) struct Image {
    pub cap: u64,
    pub physical_bits: u8,
    pub default: u64,
    pub writes: [Write; MAX_WRITABLE],
    pub count: usize,
}

fn register(snapshot: &Snapshot, index: u32) -> Result<u64, &'static str> {
    let mut values = snapshot
        .msrs
        .get(..snapshot.msr_count as usize)
        .ok_or("invalid memory-type observation")?
        .iter()
        .filter(|msr| msr.index == index);
    let value = values.next().ok_or("incomplete memory-type observation")?;
    if values.next().is_some() {
        return Err("duplicate memory-type observation");
    }
    Ok(value.value)
}

fn intel(snapshot: &Snapshot) -> bool {
    snapshot.get(0, 0).is_some_and(|leaf| {
        (leaf.ebx, leaf.edx, leaf.ecx) == (0x756e_6547, 0x4965_6e69, 0x6c65_746e)
    })
}

fn memory_type(value: u8, cap: u64) -> bool {
    matches!(value, 0 | 4 | 5 | 6) || (value == 1 && cap & (1 << 10) != 0)
}

impl Image {
    pub(crate) fn from_snapshot(snapshot: &Snapshot) -> Result<Self, &'static str> {
        if !intel(snapshot) {
            return Err("native initial MTRR recipe requires qualified Intel controls");
        }
        let cap = register(snapshot, CAP)?;
        let variables = (cap & 0xff) as usize;
        if variables > MAX_VARIABLE {
            return Err("native MTRR capacity exceeds captured image");
        }
        let physical_bits = snapshot
            .get(0x8000_0008, 0)
            .map(|leaf| leaf.eax as u8)
            .filter(|bits| (36..=52).contains(bits))
            .ok_or("native MTRRs need source physical-address width")?;
        let default = register(snapshot, DEFAULT)?;
        if default & !0xcff != 0
            || !memory_type(default as u8, cap)
            || (default & (1 << 10) != 0 && cap & (1 << 8) == 0)
        {
            return Err("unsupported BSP memory-type controls");
        }
        if default & (1 << 11) == 0 {
            return Err("BSP memory types must be enabled before AP admission");
        }
        let mut image = Self {
            cap,
            physical_bits,
            default,
            writes: [Write::default(); MAX_WRITABLE],
            count: 0,
        };
        for index in FIXED
            .into_iter()
            .filter(|_| cap & (1 << 8) != 0)
            .chain((0..variables as u32 * 2).map(|offset| VARIABLE_BASE + offset))
        {
            let value = register(snapshot, index)?;
            let physical_mask = ((1u64 << physical_bits) - 1) & !0xfff;
            let supported = if FIXED.contains(&index) {
                value
                    .to_le_bytes()
                    .into_iter()
                    .all(|kind| memory_type(kind, cap))
            } else if (index - VARIABLE_BASE).is_multiple_of(2) {
                value & !(physical_mask | 0xff) == 0 && memory_type(value as u8, cap)
            } else {
                value & !(physical_mask | (1 << 11)) == 0
            };
            if !supported {
                return Err("unsupported BSP memory-type register fields");
            }
            image.writes[image.count] = Write {
                index,
                low: value as u32,
                high: (value >> 32) as u32,
            };
            image.count += 1;
        }
        Ok(image)
    }

    /// Old contents may be uninitialized on a never-admitted AP. Hardware
    /// capacity/physical-width differences may not be normalized away.
    pub(crate) fn compatible(&self, snapshot: &Snapshot) -> Result<(), &'static str> {
        if !intel(snapshot)
            || register(snapshot, CAP)? != self.cap
            || snapshot.get(0x8000_0008, 0).map(|leaf| leaf.eax as u8) != Some(self.physical_bits)
        {
            return Err("physical cores have incompatible MTRR capabilities");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_smp::topology::{Cpuid, Msr};

    fn source() -> Snapshot {
        let mut value = Snapshot::default();
        value.records[0] = Cpuid {
            leaf: 0,
            ebx: 0x756e_6547,
            edx: 0x4965_6e69,
            ecx: 0x6c65_746e,
            ..Cpuid::default()
        };
        value.records[1] = Cpuid {
            leaf: 0x8000_0008,
            eax: 40,
            ..Cpuid::default()
        };
        value.count = 2;
        value.msrs[0] = Msr {
            index: CAP,
            value: (1 << 8) | (1 << 10) | 2,
        };
        value.msrs[1] = Msr {
            index: DEFAULT,
            value: 0xc06,
        };
        value.msr_count = 2;
        for index in FIXED.into_iter().chain(VARIABLE_BASE..VARIABLE_BASE + 4) {
            value.msrs[value.msr_count as usize] = Msr {
                index,
                value: if FIXED.contains(&index) {
                    0x0104_0506_0001_0406
                } else if index.is_multiple_of(2) {
                    6
                } else {
                    0xff_ffff_f800
                },
            };
            value.msr_count += 1;
        }
        value
    }

    #[test]
    fn complete_image_contains_only_writable_registers_with_exact_values() {
        let snapshot = source();
        let image = Image::from_snapshot(&snapshot).unwrap();
        assert_eq!(image.count, 15);
        for (write, original) in image.writes[..image.count].iter().zip(&snapshot.msrs[2..]) {
            assert_eq!(write.index, original.index);
            assert_eq!(
                u64::from(write.low) | (u64::from(write.high) << 32),
                original.value
            );
        }
        assert_eq!(image.default, 0xc06);
    }

    #[test]
    fn initial_ap_contents_may_differ_but_capacity_and_width_must_match() {
        let source = source();
        let image = Image::from_snapshot(&source).unwrap();
        let mut ap = source;
        for msr in &mut ap.msrs[1..ap.msr_count as usize] {
            msr.value = 0;
        }
        assert_eq!(image.compatible(&ap), Ok(()));
        ap.msrs[0].value += 1;
        assert!(image.compatible(&ap).is_err());
        ap = source;
        ap.records[1].eax = 48;
        assert!(image.compatible(&ap).is_err());
    }

    #[test]
    fn incomplete_duplicate_disabled_or_excess_images_refuse() {
        let source = source();
        let mut changed = source;
        changed.msr_count -= 1;
        assert!(Image::from_snapshot(&changed).is_err());
        changed = source;
        changed.msrs[2] = changed.msrs[1];
        assert!(Image::from_snapshot(&changed).is_err());
        changed = source;
        changed.msrs[1].value = 0;
        assert!(Image::from_snapshot(&changed).is_err());
        changed = source;
        changed.records[0].ebx = 0;
        assert!(Image::from_snapshot(&changed).is_err());
        changed = source;
        changed.msrs[2].value |= 0x80;
        assert!(Image::from_snapshot(&changed).is_err());
        changed = source;
        changed.msrs[0].value = (MAX_VARIABLE + 1) as u64;
        assert!(Image::from_snapshot(&changed).is_err());
    }
}
