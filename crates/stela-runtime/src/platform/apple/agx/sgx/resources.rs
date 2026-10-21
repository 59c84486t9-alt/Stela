//! The actual SGX resource-window register owner. Original fixed-family
//! firmware programs type-17 PIO at logical offset zero, using 64-bit native
//! stores. RAM resource records never substitute for these device effects.
//! MCache completion belongs to a separately configured physical owner.

use super::FirmwarePower;
use crate::platform::apple::agx::{
    generation::Family,
    pio::{Kind, Region},
    ring::Shared,
    work_decode::resources::{Access, NativeWrite, Policy},
};
use crate::platform::apple::amcc::firmware::FirmwareCache;
use crate::platform::dma::{DmaError, Port};
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Window {
    pub address: u64,
    pub control: u64,
}
#[derive(Debug, Default)]
pub(super) struct Windows {
    #[cfg(test)]
    pub(super) committed_writes: u64,
    rows: [Window; 32],
    legacy_controls: [u64; 16],
}

#[derive(Clone, Copy)]
enum Word {
    Address(usize),
    Control(usize),
    Legacy(usize),
}
fn word(family: &Family, offset: u64) -> Result<Word, &'static str> {
    let policy = Policy::for_family(family)?;
    for index in 0..32u8 {
        let base = u64::from(policy.window(index)?);
        if offset == base {
            return Ok(Word::Address(usize::from(index)));
        }
        if offset == base + 8 {
            return Ok(Word::Control(usize::from(index)));
        }
    }
    if policy == Policy::G13X
        && (0x17148..=0x17238).contains(&offset)
        && (offset - 0x17148).is_multiple_of(16)
    {
        return Ok(Word::Legacy(((offset - 0x17148) / 16) as usize));
    }
    Err("GFX native resource-window offset is not qualified")
}
impl Windows {
    pub(super) fn active(&self) -> bool {
        self.rows.iter().any(|row| row.control != 0)
    }
    pub(super) fn write(
        &mut self,
        family: &Family,
        offset: u64,
        value: u64,
    ) -> Result<(), &'static str> {
        match word(family, offset)? {
            Word::Address(index) => {
                if self.rows[index].control != 0 {
                    return Err("GFX resource address changed before disabling its native window");
                }
                if value & (1 << 47) == 0 || value >> 57 != 0 {
                    return Err("GFX resource address lacks its source-native validity bit");
                }
                self.rows[index].address = value;
            }
            Word::Control(index) => {
                if value != 0
                    && (value & (1 << 33) == 0 || value >> 58 != 0 || self.rows[index].address == 0)
                {
                    return Err(
                        "GFX resource control enables an unprogrammed or invalid native window",
                    );
                }
                self.rows[index].control = value;
            }
            Word::Legacy(index) => {
                if value != 0 {
                    return Err("GFX G13X legacy resource-control programming is not qualified");
                }
                self.legacy_controls[index] = 0;
            }
        }
        #[cfg(test)]
        {
            self.committed_writes += 1;
        }
        Ok(())
    }
}

/// Holds source geometry and the same native state served by the AP SGX
/// device. Construction qualifies physical ownership; writes still require
/// the real firmware UAT translation for the complete eight-byte target.
#[derive(Clone)]
pub struct FirmwareResources {
    power: FirmwarePower,
    region: Region,
    cache: Option<CacheBinding>,
}

impl FirmwarePower {
    /// Complete eight-byte native targets for the mount's final bus-route
    /// check. This includes G13X's source-required legacy control clears.
    pub fn resource_window_targets(&self) -> Result<Vec<u64>, &'static str> {
        let policy = Policy::for_family(self.family)?;
        let mut targets = Vec::new();
        let mut logical = Vec::new();
        for slot in 0..32 {
            let offset = policy.window(slot)?;
            logical.extend([offset, offset + 8]);
            if policy == Policy::G13X && slot >= 16 {
                logical.push(0x17048 + u32::from(slot) * 16);
            }
        }
        for offset in logical {
            let physical = self
                .banks
                .iter()
                .find_map(|&(base, bytes, start)| {
                    let at = u64::from(offset).checked_sub(start)?;
                    (at.checked_add(8)? <= bytes).then_some(base + at)
                })
                .ok_or("GFX native resource window is not wholly inside an actual SGX bank")?;
            targets.push(physical);
        }
        Ok(targets)
    }
}
#[derive(Clone)]
struct CacheBinding {
    region: Region,
    native: FirmwareCache,
    bases: Vec<u64>,
}
impl CacheBinding {
    fn new(family: &Family, region: Region, native: FirmwareCache) -> Result<Self, &'static str> {
        if region.kind != Kind::MCache || region.relative != 0 {
            return Err("GFX DSID completion requires the original MCache PIO type");
        }
        let (_, bytes, range_bytes) = region.geometry();
        let policy = Policy::for_family(family)?;
        let count = bytes / range_bytes;
        let bases = match policy {
            Policy::G14G if count == 1 && range_bytes == 0x18000 => alloc::vec![0x200f04000],
            Policy::G13G if count == 4 && range_bytes == 0x14000 => {
                alloc::vec![0x200004000, 0x200044000, 0x200084000, 0x2000c4000]
            }
            Policy::G13X if [8, 16, 32, 64].contains(&count) && range_bytes == 0x14000 => {
                let mut bases = Vec::with_capacity(count as usize);
                for group in 0..count / 4 {
                    let base = (if group < 8 { 0x200004000 } else { 0x2200004000 })
                        | (u64::from(group & 7) << 24);
                    for bank in [0, 0x40000, 0x80000, 0xc0000] {
                        bases.push(base | bank);
                    }
                }
                bases
            }
            _ => return Err("GFX MCache mapping is outside its original family producer geometry"),
        };
        // Full physical-list ownership is qualified before any release
        // effect. G13 mappings are scattered; their first base is insufficient.
        for index in 0..count {
            for dsid in [0, 255] {
                let (_, physical) =
                    region.listed_word(index * range_bytes + 0xfffc + dsid * 4, &bases)?;
                native.check(physical)?;
            }
        }
        Ok(Self {
            region,
            native,
            bases,
        })
    }
    fn target(&self, offset: u32) -> Result<(u64, u64), &'static str> {
        let (va, physical) = self.region.listed_word(offset, &self.bases)?;
        self.native.check(physical)?;
        Ok((va, physical))
    }
}
impl FirmwareResources {
    pub(super) fn check_compute_owner(
        &self,
        power: &FirmwarePower,
        cache: &FirmwareCache,
    ) -> Result<(), &'static str> {
        if self.power.family != power.family
            || !alloc::rc::Rc::ptr_eq(&self.power.native, &power.native)
        {
            return Err("GFX CL parameters and resource windows belong to different SGX owners");
        }
        if !self
            .cache
            .as_ref()
            .is_some_and(|binding| binding.native.same_owner(cache))
        {
            return Err("GFX CL parameters and resource RAM lack the same actual MCC owner");
        }
        Ok(())
    }
    pub fn new(power: FirmwarePower, region: Region) -> Result<Self, &'static str> {
        let policy = Policy::for_family(power.family)?;
        power.resource_window_targets()?;
        if region.kind != Kind::ResourceWindows || region.relative != 0 {
            return Err("GFX resource PIO does not have its source-qualified type/relative base");
        }
        let last = policy.window(31)? + 8;
        for offset in [0, last] {
            let (_, physical) = region.range(offset, 8, true)?;
            if power.logical_range(physical, 8)? != u64::from(offset) {
                return Err("GFX resource PIO does not target the actual SGX primary aperture");
            }
        }
        Ok(Self {
            power,
            region,
            cache: None,
        })
    }
    /// Bind source-qualified scattered or broadcast MCache mappings to
    /// the actual MCC owner, with a real UAT check on every command.
    pub fn with_cache(
        mut self,
        region: Region,
        cache: FirmwareCache,
    ) -> Result<Self, &'static str> {
        self.cache = Some(CacheBinding::new(self.power.family, region, cache)?);
        Ok(self)
    }
    /// Internal resource ownership, not an invented hardware MMIO readback.
    pub fn window(&self, slot: u8) -> Result<Window, &'static str> {
        self.power
            .native
            .borrow()
            .resources
            .rows
            .get(usize::from(slot))
            .copied()
            .ok_or("GFX native resource window index exceeds thirty-two slots")
    }
    pub fn access<'a, 'b, 'c>(&'a self, port: &'a mut Port<'b, 'c>) -> ResourceAccess<'a, 'b, 'c> {
        ResourceAccess { owner: self, port }
    }
    pub(super) fn check_native(&self, write: NativeWrite) -> Result<(), &'static str> {
        match write {
            NativeWrite::Window { .. } => self.qualify(write).map(|_| ()),
            NativeWrite::MCache { offset } => {
                let cache = self.cache.as_ref().ok_or(
                    "GFX MCache DSID completion requires its separately qualified physical owner",
                )?;
                cache.target(offset).map(|_| ())
            }
        }
    }
    fn qualify(&self, write: NativeWrite) -> Result<(u32, u64, u64), &'static str> {
        let NativeWrite::Window { offset, value } = write else {
            return Err(
                "GFX MCache DSID completion requires its separately qualified physical owner",
            );
        };
        word(self.power.family, u64::from(offset))?;
        let (_, physical) = self.region.range(offset, 8, true)?;
        if self.power.logical_range(physical, 8)? != u64::from(offset) {
            return Err("GFX resource PIO targets a different native register bank");
        }
        Ok((offset, value, physical))
    }
}

pub struct ResourceAccess<'a, 'b, 'c> {
    owner: &'a FirmwareResources,
    port: &'a mut Port<'b, 'c>,
}
impl Access for ResourceAccess<'_, '_, '_> {
    fn memory(&mut self) -> &mut dyn Shared {
        self.port
    }
    fn check_available(&self) -> Result<(), &'static str> {
        if !self.owner.power.native.borrow().available {
            return Err("GFX resources while PMGR inhibits SGX execution");
        }
        if let Some(cache) = &self.owner.cache {
            cache.native.check_ram_access()?;
        }
        Ok(())
    }
    fn check_native(&self, write: NativeWrite) -> Result<(), &'static str> {
        self.owner.check_native(write)
    }
    fn write_native(&mut self, write: NativeWrite) -> Result<(), &'static str> {
        self.check_available()?;
        if let NativeWrite::MCache { offset } = write {
            let cache = self.owner.cache.as_ref().ok_or(
                "GFX MCache DSID completion requires its separately qualified physical owner",
            )?;
            let (va, expected) = cache.target(offset)?;
            let physical = translated(self.port, va, 4)?;
            if physical != expected {
                return Err("GFX MCache PIO translation disagrees with its physical descriptor");
            }
            return cache.native.invalidate(physical);
        }
        let (offset, value, expected) = self.owner.qualify(write)?;
        let (va, _) = self.owner.region.range(offset, 8, true)?;
        let physical = translated(self.port, va, 8)?;
        if physical != expected {
            return Err("GFX resource PIO translation disagrees with its physical descriptor");
        }
        self.owner.power.native.borrow_mut().resources.write(
            self.owner.power.family,
            u64::from(offset),
            value,
        )
    }
}

fn translated(port: &mut Port<'_, '_>, va: u64, bytes: u64) -> Result<u64, &'static str> {
    port.iommu
        .translate(
            port.memory,
            port.stream,
            va,
            va + bytes - 1,
            true,
            port.access,
        )
        .map_err(|error| match error {
            DmaError::Fault(_) => "GFX resource PIO faults in the UAT",
            DmaError::Memory => "GFX resource PIO page table is not RAM",
            DmaError::Unsupported(reason) => reason,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::{
        agx::{
            generation::{self, GPUS},
            initdata::{CONFIG_BYTES, Root},
            ring::tests::Flat,
            sgx::Sgx,
            uat,
            work_decode::resources::{Attachment, Lease, Outcome, Pool},
        },
        amcc::{Amcc, Cache, Layout, LockGroup, Register},
        bus::{Access as BusAccess, Lifecycle, LifecycleState, MmioDevice, Width},
        interrupt::InterruptLatch,
    };
    use crate::platform::dma::{Memory, tests::Ram};
    use alloc::vec;

    const BASE: u64 = 0x800000000;
    const SGX: u64 = 0x204000000;
    const MCC: u64 = 0x200000000;
    const NATIVE: u64 = 0x100000;
    const CACHE_VA: u64 = 0x200000;

    fn region(kind: Kind, physical: u64, va: u64, bytes: u32) -> Region {
        scattered_region(kind, physical, va, bytes, bytes)
    }
    fn scattered_region(
        kind: Kind,
        physical: u64,
        va: u64,
        bytes: u32,
        range_bytes: u32,
    ) -> Region {
        let mut memory = Flat::new(0x1000, 0x4000);
        let at = 0x1000 + 0x640 + kind as u64 * 0x28;
        memory.put_u64(at, physical);
        memory.put_u64(at + 8, va);
        memory.put_u32(at + 0x10, bytes);
        memory.put_u32(at + 0x14, range_bytes);
        memory.put_u32(at + 0x20, 2);
        Region::read(&mut memory, 0x1000, kind).unwrap()
    }
    fn cache() -> Amcc {
        cache_for(1)
    }
    fn cache_for(apertures: usize) -> Amcc {
        let bit = |offset| Register {
            offset,
            mask: 1,
            value: 1,
        };
        let limit = |offset| Register {
            offset,
            mask: u32::MAX,
            value: 0,
        };
        Amcc::new(
            Layout {
                aperture_bytes: 0xf40000,
                planes: 4,
                stride: 0x40000,
                cache_status: bit(0x424),
                group: LockGroup {
                    page_size_shift: 14,
                    lower_limit: limit(0x680),
                    upper_limit: limit(0x684),
                    enable: bit(0x688),
                    write_disable: bit(0x7f0),
                    lock: bit(0x68c),
                },
                dram_base: BASE,
            },
            apertures,
            None,
            Some(Cache {
                shared: (0x100000, 0x80000),
                broadcast: 0xf00000,
                bytes: 8 << 20,
                ways: 16,
            }),
        )
        .unwrap()
    }
    struct FaultRam {
        ram: Ram,
        fail: Option<(u64, usize)>,
    }
    impl Memory for FaultRam {
        fn read(&mut self, physical: u64, out: &mut [u8]) -> bool {
            self.ram.read(physical, out)
        }
        fn write(&mut self, physical: u64, data: &[u8]) -> bool {
            if self.fail == Some((physical, data.len())) {
                self.fail = None;
                return false;
            }
            self.ram.write(physical, data)
        }
    }
    fn mapping(memory: &mut Ram, va: u64, physical: u64, device: bool) {
        let flags = uat::Flags {
            access: uat::Access::Firmware,
            memory: if device {
                uat::MemoryAttr::Device
            } else {
                uat::MemoryAttr::Cached
            },
            global: true,
            pxn: true,
            uxn: true,
            gpu_access: true,
        };
        memory.put_u64(
            BASE + 0xc000 + ((va >> 14) & 0x7ff) * 8,
            uat::encode_pte(physical, &flags),
        );
    }
    fn ram() -> Ram {
        let mut memory = Ram::new(BASE, 0x18000);
        let [ttbr0, ttbr1] = uat::encode_gptbat(0, BASE + 0x4000, 0);
        memory.put_u64(BASE, ttbr0);
        memory.put_u64(BASE + 8, ttbr1);
        memory.put_u64(BASE + 0x4000, uat::encode_table(BASE + 0x8000));
        memory.put_u64(BASE + 0x8000, uat::encode_table(BASE + 0xc000));
        mapping(&mut memory, 0, BASE + 0x10000, false);
        mapping(&mut memory, 0x4000, BASE + 0x14000, false);
        mapping(&mut memory, NATIVE + 0x14000, SGX + 0x14000, true);
        mapping(&mut memory, CACHE_VA + 0x10000, MCC + 0xf14000, true);
        memory
    }
    fn root() -> Root {
        Root {
            page_1660: 1,
            rings: 0x1000,
            object_358: 2,
            object_848: 3,
            object_928: 4,
            object_930: 5,
            object_368: 6,
            config: [0; CONFIG_BYTES],
        }
    }
    fn gpu(family: &'static Family) -> Sgx {
        let gpu = GPUS
            .iter()
            .find(|gpu| gpu.family == family && gpu.admitted().is_ok())
            .unwrap();
        Sgx::handed_off(gpu, BASE, BASE + 0x8000).unwrap()
    }

    #[test]
    fn fixed_family_native_windows_share_ap_state_and_reject_foreign_geometry_or_protocol() {
        for family in [&generation::G13G, &generation::G13X, &generation::G14G] {
            let mut sgx = gpu(family);
            let power = sgx.firmware_power(&[(SGX, 0x4000000, 0)]).unwrap();
            assert_eq!(
                power.resource_window_targets().unwrap().len(),
                if family == &generation::G13X { 80 } else { 64 }
            );
            let owner = FirmwareResources::new(
                power.clone(),
                region(Kind::ResourceWindows, SGX, NATIVE, 0x20000),
            )
            .unwrap();
            let mut memory = ram();
            let mut latch = InterruptLatch::new();
            let mut access = BusAccess::new(0, 0, &mut latch);
            let policy = Policy::for_family(family).unwrap();
            let offset = policy.window(31).unwrap();
            for (at, value) in [
                (offset + 8, 0),
                (offset, (1 << 47) | 0x100),
                (offset + 8, (1 << 33) | 0x200),
            ] {
                let mut iommu = sgx.uat().agent(uat::Agent::Firmware);
                let mut port = Port {
                    iommu: &mut iommu,
                    stream: 0,
                    memory: &mut memory,
                    access: &mut access,
                };
                owner
                    .access(&mut port)
                    .write_native(NativeWrite::Window { offset: at, value })
                    .unwrap();
            }
            assert_eq!(owner.window(31).unwrap().address, (1 << 47) | 0x100);
            assert!(
                sgx.read(u64::from(offset), Width::Double, &mut access)
                    .is_err()
            );
            assert!(power.check_reset().is_err());
            assert!(
                sgx.write(u64::from(offset), Width::Double, 1 << 47, &mut access)
                    .is_err()
            );
            assert!(
                sgx.read(u64::from(offset), Width::Word, &mut access)
                    .is_err()
            );
            sgx.write(u64::from(offset + 8), Width::Double, 0, &mut access)
                .unwrap();
            power.check_reset().unwrap();
            assert!(
                FirmwareResources::new(
                    power.clone(),
                    region(Kind::ResourceWindows, SGX + 8, NATIVE, 0x20000)
                )
                .is_err()
            );
            assert!(
                FirmwareResources::new(
                    power.clone(),
                    region(Kind::ResourceWindows, 0x304000000, NATIVE, 0x20000)
                )
                .is_err()
            );
            let short = sgx
                .firmware_power(&[(SGX, 0x10000, 0), (SGX + 0xd00000, 0x800000, 0xd00000)])
                .unwrap();
            assert!(
                FirmwareResources::new(short, region(Kind::ResourceWindows, SGX, NATIVE, 0x20000))
                    .is_err()
            );
            let split = sgx
                .firmware_power(&[
                    (SGX, 0x17100, 0),
                    (SGX + 0x17300, 0x100, 0x17300),
                    (SGX + 0xd00000, 0x800000, 0xd00000),
                ])
                .unwrap();
            assert!(split.resource_window_targets().is_err());
        }
    }

    fn check_post_native_faults(disable_mcc: bool) {
        let mut sgx = gpu(&generation::G14G);
        let power = sgx.firmware_power(&[(SGX, 0x4000000, 0)]).unwrap();
        let mut mcc = cache();
        let cache = mcc.firmware_cache(&[MCC]).unwrap();
        let owner = FirmwareResources::new(
            power.clone(),
            region(Kind::ResourceWindows, SGX, NATIVE, 0x20000),
        )
        .unwrap()
        .with_cache(
            region(Kind::MCache, MCC + 0xf04000, CACHE_VA, 0x18000),
            cache.clone(),
        )
        .unwrap();
        let mut memory = FaultRam {
            ram: ram(),
            fail: None,
        };
        memory.ram.put_u64(BASE + 0x11000 + 0x2c8, 0x4000);
        memory.ram.put_u64(BASE + 0x11000 + 0x2d0, 0x6000);
        memory.ram.put_u64(BASE + 0x11000 + 0x2d8, 0x7000);
        let mut latch = InterruptLatch::new();
        let mut access = BusAccess::new(0, 0, &mut latch);
        let mut iommu = sgx.uat().agent(uat::Agent::Firmware);
        let mut port = Port {
            iommu: &mut iommu,
            stream: 0,
            memory: &mut memory,
            access: &mut access,
        };
        let mut pool = Pool::bind(&mut port, &root(), &generation::G14G, 1).unwrap();
        let lease = Lease { pipe: 0, slot: 0 };
        pool.acquire(
            &mut port,
            lease,
            3,
            &[Attachment {
                address: 0x8000,
                units: 8,
                dsid: 4,
                reserved: 0,
                parameter: 1,
            }],
        )
        .unwrap();
        pool.advance(&mut owner.access(&mut port)).unwrap();
        pool.finish().unwrap();
        assert!(power.check_reset().is_err());
        port.write(0x4040, &1u32.to_le_bytes()).unwrap();
        pool.release(&mut port, lease, Some([1 << 4, 0, 0, 0]))
            .unwrap();
        // A missing native PTE commits no invalidation. Earlier RAM/SGX
        // release phases remain owned and are not replayed.
        port.memory
            .write(BASE + 0xc000 + 0x84 * 8, &0u64.to_le_bytes());
        assert_eq!(
            pool.advance(&mut owner.access(&mut port)),
            Err("GFX resource PIO faults in the UAT")
        );
        assert_eq!(cache.completions(4), vec![0; 4]);
        mapping(&mut memory.ram, CACHE_VA + 0x10000, MCC + 0xf14000, true);
        memory.fail = Some((BASE + 0x14040, 8));
        let mut iommu = sgx.uat().agent(uat::Agent::Firmware);
        let mut port = Port {
            iommu: &mut iommu,
            stream: 0,
            memory: &mut memory,
            access: &mut access,
        };
        assert!(pool.advance(&mut owner.access(&mut port)).is_err());
        assert_eq!(cache.completions(4), vec![1; 4]);
        assert!(pool.finish().is_err());
        port.write(0x4040, &0xdeadbeefdeadbeefu64.to_le_bytes())
            .unwrap();
        if disable_mcc {
            let mut stop_latch = InterruptLatch::new();
            let mut stop = BusAccess::new(0, 0, &mut stop_latch);
            mcc.write(0xf00000 + 0x410, Width::Word, 0, &mut stop)
                .unwrap();
            assert_eq!(
                pool.advance(&mut owner.access(&mut port)),
                Err("MCC resource RAM after DRAM access disable")
            );
            assert_eq!(cache.completions(4), vec![1; 4]);
            assert!(pool.finish().is_err());
            // Inspect the backing RAM without advancing the device owner.
            let mut held = [0; 8];
            assert!(port.memory.read(BASE + 0x14040, &mut held));
            assert_eq!(u64::from_le_bytes(held), 0xdeadbeefdeadbeef);
            return;
        }
        let active = LifecycleState {
            powered: true,
            clocked: true,
            quiesced: false,
            reset: false,
            retention: false,
        };
        sgx.check_lifecycle(LifecycleState {
            clocked: false,
            ..active
        })
        .unwrap();
        sgx.set_lifecycle(
            LifecycleState {
                clocked: false,
                ..active
            },
            &mut access,
        );
        let mut iommu = sgx.uat().agent(uat::Agent::Firmware);
        let mut port = Port {
            iommu: &mut iommu,
            stream: 0,
            memory: &mut memory,
            access: &mut access,
        };
        assert_eq!(
            pool.advance(&mut owner.access(&mut port)),
            Err("GFX resources while PMGR inhibits SGX execution")
        );
        assert_eq!(cache.completions(4), vec![1; 4]);
        sgx.set_lifecycle(active, &mut access);
        let mut iommu = sgx.uat().agent(uat::Agent::Firmware);
        let mut port = Port {
            iommu: &mut iommu,
            stream: 0,
            memory: &mut memory,
            access: &mut access,
        };
        assert_eq!(
            pool.advance(&mut owner.access(&mut port)).unwrap(),
            Some(&Outcome::Released)
        );
        assert_eq!(pool.finish(), Ok(Outcome::Released));
        assert_eq!(cache.completions(4), vec![1; 4]);
        assert_eq!(port.read_u64(0x4040), Ok(0));
        power.check_reset().unwrap();
        mcc.write(0xf00000 + 0x410, Width::Word, 0, &mut access)
            .unwrap();
        assert!(cache.check(MCC + 0xf13ffc).is_err());
    }
    #[test]
    fn real_uat_faults_after_native_mcc_completion_retain_the_ram_clear_and_gate_its_retry() {
        check_post_native_faults(false);
    }
    #[test]
    fn actual_mcc_disable_vetoes_uncommitted_ram_tails_without_repeating_native_completion() {
        check_post_native_faults(true);
    }
    #[test]
    fn original_scattered_cache_lists_resolve_every_bank_to_the_actual_owner() {
        // Explicit coherent-controller fixtures qualify physical-list
        // arithmetic; they do not admit an unmodeled G13 MCC platform.
        for (family, groups) in [
            (&generation::G13G, 1),
            (&generation::G13X, 2),
            (&generation::G13X, 4),
            (&generation::G13X, 8),
            (&generation::G13X, 16),
        ] {
            let apertures: Vec<_> = (0..groups)
                .map(|group| {
                    (if group < 8 { 0x200000000 } else { 0x2200000000 }) | ((group & 7) << 24)
                })
                .collect();
            let model = cache_for(groups as usize);
            let native = model.firmware_cache(&apertures).unwrap();
            let region = scattered_region(
                Kind::MCache,
                0x200004000,
                CACHE_VA,
                groups as u32 * 0x50000,
                0x14000,
            );
            let binding = CacheBinding::new(family, region, native.clone()).unwrap();
            for group in 0..groups {
                for (bank, offset) in [0xfffc, 0x23ffc, 0x37ffc, 0x4bffc].into_iter().enumerate() {
                    let (va, physical) = binding
                        .target(group as u32 * 0x50000 + offset + 255 * 4)
                        .unwrap();
                    assert_eq!(va, CACHE_VA + group * 0x50000 + u64::from(offset) + 255 * 4);
                    assert_eq!(
                        physical,
                        apertures[group as usize] + bank as u64 * 0x40000 + 0x143f8
                    );
                    native.invalidate(physical).unwrap();
                }
            }
            assert_eq!(native.completions(255), vec![1; groups as usize * 4]);
            assert!(binding.target(groups as u32 * 0x50000 + 0xfffc).is_err());
            assert!(
                CacheBinding::new(
                    family,
                    scattered_region(
                        Kind::MCache,
                        0x200004008,
                        CACHE_VA,
                        groups as u32 * 0x50000,
                        0x14000
                    ),
                    native.clone()
                )
                .is_err()
            );
            let foreign = cache().firmware_cache(&[MCC + 0x100000000]).unwrap();
            assert!(CacheBinding::new(family, binding.region.clone(), foreign).is_err());
        }
    }
}
