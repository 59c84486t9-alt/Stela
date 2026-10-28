//! Original T6000 ACC/CPM register ownership, independent of T8112 layout.
//!
//! Offsets are the driver's logical ACC coordinates, routed by
//! `pmgr::t6000::Layout` through the actual E/P0/P1 DT views. Every readable
//! value is an actual supplied image word or a committed software write.
//! Native performance/APSC, DVMR, throttling and autonomous counter execution
//! require their actual controller owner; neither zero nor a cleared BUSY is
//! manufactured to satisfy the driver's polls.
use super::super::bus::{Access, Direction, MmioDevice, MmioError, Width, refuse};
use alloc::{collections::BTreeMap, vec::Vec};

const NAME: &str = "t6000-cpu-cluster";
pub const COMMAND: u64 = 0xe20020;
pub const TABLE: u64 = 0xe70000;
pub const STATE_BYTES: u64 = 0x20;
pub const STATE_CAPACITY: usize = 16;
const GLOBAL: u64 = 0xe20000;
const SNOOZE: u64 = 0xe200f8;
const DVMR_CONTROL: u64 = 0xe206b8;
const COUNTER_ENABLE: u64 = 0xe20660;
const ENERGY_ENABLE: u64 = 0xe48080;
const ENERGY: u64 = 0xe48000;
const STATE: u64 = 0xf;
const APSC_PENDING: u64 = 1 << 7;
const DVMR_PENDING: u64 = 1 << 5;
const APSC_DISABLE: u64 = 1 << 22;
const SET: u64 = 1 << 25;
const BUSY: u64 = 1 << 31;
const DVMR_ENABLE: u64 = 1 << 63;
const COUNTERS: u64 = 0x15;
const ENERGY_COUNTERS: u64 = (1 << 61) | (1 << 63);
const THROTTLERS: [u64; 3] = [0xe40250, 0xe40240, 0xe48400];

/// Actual first-die hardware complex, not a CPU kind shared by two P banks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Complex {
    Efficiency,
    Performance0,
    Performance1,
}
impl Complex {
    pub const fn index(self) -> usize {
        match self {
            Self::Efficiency => 0,
            Self::Performance0 => 1,
            Self::Performance1 => 2,
        }
    }
    const fn dvmr_mask(self) -> u64 {
        match self {
            Self::Efficiency => DVMR_ENABLE,
            _ => DVMR_ENABLE | (1 << 32) | (1 << 31),
        }
    }
    const fn cores(self) -> usize {
        match self {
            Self::Efficiency => 2,
            _ => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Command,
    Autonomous,
    StateTable,
    Weight,
    Dvmr,
    CounterEnable,
    Counter,
    EnergyEnable,
    Energy,
    Throttler,
    Restore,
}

/// Known words only. The caller retains their handoff provenance separately;
/// source metadata, an enclosing aperture and a missing row supply no value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub complex: Complex,
    pub states: usize,
    pub words: Vec<(u64, u64)>,
}

pub struct T6000 {
    complex: Complex,
    #[cfg(test)]
    states: usize,
    roles: BTreeMap<u64, Role>,
    words: BTreeMap<u64, u64>,
}
impl T6000 {
    pub fn new(
        complex: Complex,
        states: usize,
        image: &[(u64, u64)],
    ) -> Result<Self, &'static str> {
        if states == 0 || states > STATE_CAPACITY {
            return Err("T6000 state table exceeds the native four-bit selector");
        }
        let mut roles = BTreeMap::new();
        roles.insert(COMMAND, Role::Command);
        for offset in [GLOBAL, SNOOZE] {
            roles.insert(offset, Role::Autonomous);
        }
        for index in 0..states as u64 * STATE_BYTES / 8 {
            roles.insert(TABLE + index * 8, Role::StateTable);
        }
        for offset in [0xe206a8, 0xe206b0, 0xe206e0, 0xe206e8] {
            if complex != Complex::Efficiency || offset == 0xe206a8 {
                roles.insert(offset, Role::Weight);
            }
        }
        roles.insert(DVMR_CONTROL, Role::Dvmr);
        for index in 0..16 {
            roles.insert(0xe20400 + 8 * index, Role::Counter);
            roles.insert(0xe20480 + 8 * index, Role::Counter);
        }
        // Native accessor permits all27 special indices, each a paired64
        // register, independently of the DT events a driver publishes.
        for index in 0..27 {
            roles.insert(0xe20580 + 8 * index, Role::Counter);
            roles.insert(0xe20588 + 8 * index, Role::Counter);
        }
        roles.insert(COUNTER_ENABLE, Role::CounterEnable);
        roles.insert(ENERGY_ENABLE, Role::EnergyEnable);
        roles.insert(ENERGY, Role::Energy);
        roles.insert(0xe440f8, Role::Restore);
        for core in 0..complex.cores() {
            roles.insert(0x59000 + core as u64 * 0x100000, Role::Energy);
        }
        for offset in THROTTLERS {
            roles.insert(offset, Role::Throttler);
        }
        let mut model = Self {
            complex,
            #[cfg(test)]
            states,
            roles,
            words: BTreeMap::new(),
        };
        for &(offset, value) in image {
            let role = model.role(offset, Width::Double)?;
            if model.words.contains_key(&offset) {
                return Err("T6000 cluster image repeats a physical word");
            }
            match role {
                Role::Restore => {
                    return Err("T6000 CPM restore command has no qualified image/readback");
                }
                Role::Command if value & (BUSY | SET | APSC_PENDING | DVMR_PENDING) != 0 => {
                    return Err(
                        "T6000 cluster image has pending work without native controller context",
                    );
                }
                Role::Command if value & APSC_DISABLE == 0 => {
                    return Err(
                        "T6000 enabled APSC requires its actual controller execution owner",
                    );
                }
                Role::Dvmr if value & complex.dvmr_mask() != 0 => {
                    return Err(
                        "T6000 enabled DVMR requires its actual controller execution owner",
                    );
                }
                Role::CounterEnable if value & COUNTERS != 0 => {
                    return Err("T6000 enabled residency counters require actual event ownership");
                }
                Role::EnergyEnable if value & ENERGY_COUNTERS != 0 => {
                    return Err("T6000 enabled energy counters require actual event ownership");
                }
                Role::Throttler if value >> 63 != 0 => {
                    return Err("T6000 enabled throttling requires actual clock/thermal ownership");
                }
                _ => {}
            }
            if role == Role::Command && value & STATE >= states as u64 {
                return Err("T6000 image selects a state outside its actual table");
            }
            model.words.insert(offset, value);
        }
        Ok(model)
    }

    #[cfg(test)]
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            complex: self.complex,
            states: self.states,
            words: self
                .words
                .iter()
                .map(|(&offset, &value)| (offset, value))
                .collect(),
        }
    }
    pub fn restore(image: &Snapshot) -> Result<Self, &'static str> {
        Self::new(image.complex, image.states, &image.words)
    }
    /// Actual full64 logical words only; the mount routes each whole word
    /// through the source-qualified physical view, never a synthetic span.
    pub fn offsets(&self) -> impl Iterator<Item = u64> + '_ {
        self.roles.keys().copied()
    }

    fn role(&self, offset: u64, width: Width) -> Result<Role, &'static str> {
        if width != Width::Double {
            return Err("T6000 ACC/CPM access is not full64");
        }
        self.roles
            .get(&offset)
            .copied()
            .ok_or("T6000 ACC/CPM logical register is not qualified")
    }
    fn known(&self, offset: u64) -> Result<u64, &'static str> {
        self.words
            .get(&offset)
            .copied()
            .ok_or("T6000 ACC/CPM handoff word is unknown")
    }
    fn disabled(&self, offset: u64, mask: u64) -> Result<(), &'static str> {
        if self.known(offset)? & mask != 0 {
            return Err("T6000 autonomous register source is not disabled");
        }
        Ok(())
    }
    fn inactive_apsc(&self) -> Result<(), &'static str> {
        let command = self.known(COMMAND)?;
        if command & (BUSY | SET | APSC_PENDING | DVMR_PENDING) != 0 || command & APSC_DISABLE == 0
        {
            return Err("T6000 state-table update requires actual quiescent disabled APSC");
        }
        Ok(())
    }
    fn readable(&self, role: Role) -> Result<(), &'static str> {
        match role {
            Role::Counter => self.disabled(COUNTER_ENABLE, COUNTERS),
            Role::Energy => self.disabled(ENERGY_ENABLE, ENERGY_COUNTERS),
            Role::Restore => Err("T6000 CPM restore command readback is not qualified"),
            _ => Ok(()),
        }
    }
    /// Pure whole-word preflight. No trigger is accepted without its actual
    /// native execution/retirement owner, and no status bit is cleared here.
    pub fn check_write(&self, offset: u64, width: Width, value: u64) -> Result<(), &'static str> {
        let role = self.role(offset, width)?;
        match role {
            Role::Command => {
                let old = self.known(offset)?;
                if value != old {
                    return Err(
                        "T6000 performance/APSC request requires actual native controller effects and retirement",
                    );
                }
            }
            Role::Autonomous => {
                if value != self.known(offset)? {
                    return Err(
                        "T6000 autonomous or cross-complex control effects are not qualified",
                    );
                }
            }
            Role::Dvmr | Role::Throttler => {
                let old = self.known(offset)?;
                if value != old {
                    return Err(
                        "T6000 DVMR/throttler control requires actual controller ownership",
                    );
                }
            }
            Role::StateTable => self.inactive_apsc()?,
            Role::Weight => self.disabled(DVMR_CONTROL, self.complex.dvmr_mask())?,
            Role::CounterEnable => {
                if value & COUNTERS != 0 {
                    return Err("T6000 residency counter events are not connected");
                }
                if (value ^ self.known(offset)?) & !COUNTERS != 0 {
                    return Err("T6000 counter write changes unqualified preserved fields");
                }
            }
            Role::EnergyEnable => {
                if value & ENERGY_COUNTERS != 0 {
                    return Err("T6000 energy counter events are not connected");
                }
                if (value ^ self.known(offset)?) & !ENERGY_COUNTERS != 0 {
                    return Err("T6000 energy enable write changes unqualified preserved fields");
                }
            }
            Role::Counter | Role::Energy => self.readable(role)?,
            Role::Restore => {
                return Err("T6000 CPM restore requires actual electrical effects and retirement");
            }
        }
        Ok(())
    }
}
impl MmioDevice for T6000 {
    fn name(&self) -> &'static str {
        NAME
    }
    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        let fail = |reason| refuse(NAME, offset, width, Direction::Read, reason);
        let role = self.role(offset, width).map_err(fail)?;
        self.readable(role).map_err(fail)?;
        self.known(offset).map_err(fail)
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        _: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        self.check_write(offset, width, value)
            .map_err(|reason| refuse(NAME, offset, width, Direction::Write, reason))?;
        self.words.insert(offset, value);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::interrupt::InterruptLatch;
    #[test]
    fn all_three_banks_preserve_unknownness_actual_table_stride_and_disabled_samples() {
        let mut irq = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut irq);
        for complex in [
            Complex::Efficiency,
            Complex::Performance0,
            Complex::Performance1,
        ] {
            let mut model = T6000::new(
                complex,
                16,
                &[
                    (COMMAND, APSC_DISABLE | 3),
                    (DVMR_CONTROL, 0x321),
                    (COUNTER_ENABLE, 0),
                    (ENERGY_ENABLE, 0),
                    (0xe20400, 1234),
                ],
            )
            .unwrap();
            assert!(model.read(TABLE + 0x10, Width::Double, &mut a).is_err());
            model
                .write(
                    TABLE + 3 * STATE_BYTES + 0x10,
                    Width::Double,
                    0x12345678,
                    &mut a,
                )
                .unwrap();
            assert_eq!(
                model.read(TABLE + 3 * STATE_BYTES + 0x10, Width::Double, &mut a),
                Ok(0x12345678)
            );
            assert!(
                model
                    .read(TABLE + 3 * 0x40 + 0x10, Width::Double, &mut a)
                    .is_err()
            );
            model
                .write(0xe206a8, Width::Double, 0x1122334455667788, &mut a)
                .unwrap();
            assert_eq!(
                model.read(0xe206a8, Width::Double, &mut a),
                Ok(0x1122334455667788)
            );
            assert_eq!(model.read(0xe20400, Width::Double, &mut a), Ok(1234));
            model.write(0xe20400, Width::Double, 5678, &mut a).unwrap();
            assert_eq!(model.read(0xe20400, Width::Double, &mut a), Ok(5678));
            assert!(model.read(0xe20408, Width::Double, &mut a).is_err());
            assert!(model.read(0xe20400, Width::Word, &mut a).is_err());
            assert!(model.read(0xe20500, Width::Double, &mut a).is_err()); // M2 map is not inherited
            let saved = model.snapshot();
            for (offset, value) in [
                (COMMAND, APSC_DISABLE | SET | 4),
                (COMMAND, APSC_DISABLE | 4),
                (COMMAND, 3),
                (COUNTER_ENABLE, COUNTERS),
                (ENERGY_ENABLE, ENERGY_COUNTERS),
                (DVMR_CONTROL, 0x321 | DVMR_ENABLE),
            ] {
                assert!(model.write(offset, Width::Double, value, &mut a).is_err());
                assert_eq!(model.snapshot(), saved);
            }
            let restored = T6000::restore(&saved).unwrap();
            assert_eq!(restored.snapshot(), saved);
            assert!(model.lifecycle().is_none()); // actual CPU/cache execution sink is separate
        }
    }
    #[test]
    fn incomplete_or_pending_handoff_never_becomes_idle_or_zero() {
        let mut irq = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut irq);
        let mut model = T6000::new(Complex::Efficiency, 16, &[]).unwrap();
        assert!(model.read(COMMAND, Width::Double, &mut a).is_err());
        assert!(model.write(TABLE, Width::Double, 0, &mut a).is_err());
        assert!(model.write(0xe20400, Width::Double, 0, &mut a).is_err());
        assert!(model.write(0xe206a8, Width::Double, 0, &mut a).is_err());
        assert!(model.snapshot().words.is_empty());
        for words in [
            &[(COMMAND, APSC_DISABLE | BUSY)][..],
            &[(COMMAND, APSC_DISABLE | APSC_PENDING)],
            &[(COMMAND, APSC_DISABLE | DVMR_PENDING)],
            &[(COMMAND, APSC_DISABLE | SET)],
            &[(COMMAND, 0)],
            &[(COMMAND, APSC_DISABLE | 15)],
            &[(COUNTER_ENABLE, 1)],
            &[(ENERGY_ENABLE, 1 << 63)],
            &[(DVMR_CONTROL, 1 << 63)],
            &[(0xe40250, 1 << 63)],
            &[(0xe20500, 0)],
            &[(COMMAND, APSC_DISABLE), (COMMAND, APSC_DISABLE)],
        ] {
            assert!(T6000::new(Complex::Efficiency, 4, words).is_err());
        }
        assert!(T6000::new(Complex::Efficiency, 17, &[]).is_err());
        assert!(T6000::new(Complex::Efficiency, 0, &[]).is_err());
    }
}

#[cfg(all(test, feature = "std"))]
mod original {
    use super::*;
    use crate::{
        machine::adt::Node,
        platform::apple::{bus::Bus, interrupt::InterruptLatch, pmgr::t6000::Layout},
    };
    use alloc::boxed::Box;
    use sha2::{Digest, Sha256};
    fn original(variable: &str, digest: &str) -> Vec<u8> {
        let bytes = std::fs::read(std::env::var(variable).expect("pinned J314s original")).unwrap();
        assert_eq!(hex::encode(Sha256::digest(&bytes)), digest);
        bytes
    }
    fn word(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
    }
    #[test]
    #[ignore = "requires original J314s ADT/kernelcache; actual three-bank ACC/CPM mount"]
    fn original_three_complexes_mount_actual_views_and_preserve_a_committed_prefix() {
        let bytes = original(
            "STELA_TEST_PMGR_M1_KERNELCACHE",
            "5109fca5209bdbb89cec29e3241cc42a90418cb737d65e31962b059b9879af90",
        );
        for (lo, hi, digest) in [
            (
                0x2ef5590,
                0x2ef569c,
                "e20f6fc5111e461ecebe06169d528da39905b47f46e2e22f7341f1ddf333925e",
            ),
            (
                0x2ef7104,
                0x2ef71e8,
                "c9c06f74bb4db5c6221c99ad20fd35f8bd165a18797ce2ca563f2fd34d2bee6f",
            ),
            (
                0x2f04fc4,
                0x2f053c0,
                "d23196698841bbeae4baa4d3105e20f32262f16d29c333ad17a1fa6ba26861a5",
            ),
            (
                0x2f05ba4,
                0x2f06b60,
                "e5a79e0b786c48507e5c2587661907bb77adb6a9ebededa8b6623697a757e9f2",
            ),
            (
                0x2f06b60,
                0x2f07df4,
                "5b39dc5c21f47dedb5f47d456c3399a7b21a43c0facfb6d44107af0dec6bbe7d",
            ),
            (
                0x2f07df4,
                0x2f081c4,
                "57d00ac43417463eef66af0108dea16f892e8a91f95fed8c7480cd9524d50029",
            ),
            (
                0x76d3e0,
                0x76d3f0,
                "7822e7b0ccc151e841623ccc5e30c509762d48a020af02ee49791ceb86d30d77",
            ),
        ] {
            assert_eq!(hex::encode(Sha256::digest(&bytes[lo..hi])), digest);
        }
        for (offset, opcode) in [
            (0x2f05240, 0x0b001502), // actual table stride32
            (0x2f05354, 0x0b001502),
            (0x2f06f8c, 0x927cec08), // preserve all but low4 state bits
            (0x2f06f90, 0x52a04009), // SET25
            (0x2f06f94, 0x33000f29), // native low4 selector replacement
            (0x2f0733c, 0x37fffca0), // actual BUSY31 poll, no completion proof
            (0x2f07624, 0x7100405f), //16 paired state indices
            (0x2f0764c, 0x71006c5f), //27 special indices
            (0x2f0756c, 0x528002a9), //counter enables0/2/4
            (0x2f06690, 0x372ffea0), //DVMR pending bit5 poll
        ] {
            assert_eq!(word(&bytes, offset), opcode, "original source {offset:x}");
        }
        let data = original(
            "STELA_TEST_PMGR_M1_ADT",
            "44fa41bfd0fe0027fd862b8615ae956885614636625d44a59cab226d682558ad",
        );
        let root = Node::root(&data).unwrap();
        let io = root.child("arm-io").unwrap();
        let pmgr = io.child("pmgr").unwrap();
        let ranges = io.ranges().unwrap();
        let regs = pmgr
            .pairs("reg")
            .unwrap()
            .into_iter()
            .map(|(address, bytes)| {
                ranges.iter().find_map(|&(child, parent, length)| {
                    (address >= child && address - child < length)
                        .then(|| (parent + address - child, bytes))
                })
            })
            .collect::<Vec<_>>();
        let layout = Layout::new(&regs, 48, 193).unwrap();
        let mut bus = Bus::new();
        let mut devices = Vec::new();
        for complex in [
            Complex::Efficiency,
            Complex::Performance0,
            Complex::Performance1,
        ] {
            // Explicit test-supplied quiescent image, not an Apple cold-state
            // observation. Every other register remains unknown.
            let model = T6000::new(complex, 16, &[(COMMAND, APSC_DISABLE | 3)]).unwrap();
            let offsets = model.offsets().collect::<Vec<_>>();
            let device = bus.add(Box::new(model));
            for offset in offsets {
                let physical = layout.acc(complex.index(), offset as u32, 8).unwrap();
                bus.map(device, physical, 8, offset).unwrap();
            }
            devices.push(device);
        }
        let mut irq = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut irq);
        let logical = TABLE + 3 * STATE_BYTES + 0x10;
        let physical = layout.acc(1, logical as u32, 8).unwrap();
        assert_eq!(physical, 0x211e70070);
        assert!(bus.read(physical, Width::Double, &mut a).is_err());
        bus.write(physical, Width::Double, 0x1122334455667788, &mut a)
            .unwrap();
        let before = bus.device::<T6000>(devices[1]).unwrap().snapshot();
        let command = layout.acc(1, COMMAND as u32, 8).unwrap();
        assert!(
            bus.write(command, Width::Double, APSC_DISABLE | SET | 4, &mut a)
                .is_err()
        );
        assert_eq!(bus.device::<T6000>(devices[1]).unwrap().snapshot(), before);
        assert_eq!(
            bus.read(physical, Width::Double, &mut a),
            Ok(0x1122334455667788)
        );
        for complex in [0, 2] {
            let other = layout.acc(complex, logical as u32, 8).unwrap();
            assert!(bus.read(other, Width::Double, &mut a).is_err());
        }
        assert_eq!(
            bus.read(command, Width::Double, &mut a),
            Ok(APSC_DISABLE | 3)
        );
        assert!(bus.read(physical, Width::Word, &mut a).is_err());
    }
}
