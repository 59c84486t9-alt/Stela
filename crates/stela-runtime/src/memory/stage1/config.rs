use super::{AccessKind, Shareability, Unsupported};

pub(super) const DESCRIPTOR_BYTES_LOG2: u32 = 3;
pub(super) const FINAL_LEVEL: u8 = 3;
pub(super) const LEGACY_OA_BITS: u32 = 48;
pub(super) const ADDRESS_MASK: u64 = (1 << LEGACY_OA_BITS) - 1;
const REGION_SELECT_BIT: u32 = 55;
const TOP_ADDRESS_BIT: u32 = u64::BITS - 1;
const TOP_UNTAGGED_BIT: u32 = REGION_SELECT_BIT;
const SCTLR_M: u64 = 1 << 0;
const SCTLR_C: u64 = 1 << 2;
const SCTLR_I: u64 = 1 << 12;
const SCTLR_WXN: u64 = 1 << 19;
const SCTLR_E0E: u64 = 1 << 24;
const SCTLR_EE: u64 = 1 << 25;
const SCTLR_EPAN: u64 = 1 << 57;
const TCR_EPD0: u64 = 1 << 7;
const TCR_A1: u64 = 1 << 22;
const TCR_EPD1: u64 = 1 << 23;
const TCR_AS: u64 = 1 << 36;
const TCR_TBI0: u64 = 1 << 37;
const TCR_TBI1: u64 = 1 << 38;
const TCR_TBID0: u64 = 1 << 51;
const TCR_TBID1: u64 = 1 << 52;
const TCR_MTX0: u64 = 1 << 60;
const TCR_MTX1: u64 = 1 << 61;
const TTBR_CNP: u64 = 1 << 0;
const TTBR_ASID_SHIFT: u32 = 48;
const ASID8_MASK: u16 = u8::MAX as u16;
const LOW_REGION_SHIFT: u32 = 0;
const HIGH_REGION_SHIFT: u32 = 16;
const SIZE_MASK: u64 = 0x3f;
const INNER_CACHE_SHIFT: u32 = 8;
const OUTER_CACHE_SHIFT: u32 = 10;
const SHAREABILITY_SHIFT: u32 = 12;
const GRANULE0_SHIFT: u32 = 14;
const GRANULE1_SHIFT: u32 = 30;
const TG0_4K: u64 = 0b00;
const TG0_64K: u64 = 0b01;
const TG0_16K: u64 = 0b10;
const TG1_16K: u64 = 0b01;
const TG1_4K: u64 = 0b10;
const TG1_64K: u64 = 0b11;
const TWO_BIT_MASK: u64 = 3;
const IPS_SHIFT: u32 = 32;
const IPS_MASK: u64 = 7;
const LOWER_FIELDS: u64 = SIZE_MASK
    | TCR_EPD0
    | (TWO_BIT_MASK << INNER_CACHE_SHIFT)
    | (TWO_BIT_MASK << OUTER_CACHE_SHIFT)
    | (TWO_BIT_MASK << SHAREABILITY_SHIFT)
    | (TWO_BIT_MASK << GRANULE0_SHIFT);
const UPPER_FIELDS: u64 = (SIZE_MASK << HIGH_REGION_SHIFT)
    | TCR_A1
    | TCR_EPD1
    | (TWO_BIT_MASK << (INNER_CACHE_SHIFT + HIGH_REGION_SHIFT))
    | (TWO_BIT_MASK << (OUTER_CACHE_SHIFT + HIGH_REGION_SHIFT))
    | (TWO_BIT_MASK << (SHAREABILITY_SHIFT + HIGH_REGION_SHIFT))
    | (TWO_BIT_MASK << GRANULE1_SHIFT);
const TCR_SUPPORTED_MASK: u64 = LOWER_FIELDS
    | UPPER_FIELDS
    | (IPS_MASK << IPS_SHIFT)
    | TCR_AS
    | TCR_TBI0
    | TCR_TBI1
    | TCR_TBID0
    | TCR_TBID1;
const SUPPORTED_VA_BITS: [u32; 2] = [47, 48];

/// Effective inputs borrowed from the one architectural register owner.
/// These values are snapshots, never a second writable register bank.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Controls {
    pub ttbr0_el1: u64,
    pub ttbr1_el1: u64,
    pub tcr_el1: u64,
    pub sctlr_el1: u64,
    pub mair_el1: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaRegion {
    Lower,
    Upper,
}
impl VaRegion {
    pub(super) const fn remaining_bytes(address: u64) -> u64 {
        let region_bytes = 1_u64 << REGION_SELECT_BIT;
        region_bytes - (address & (region_bytes - 1))
    }
    pub(super) const fn from_address(address: u64) -> Self {
        if address & (1 << REGION_SELECT_BIT) == 0 {
            Self::Lower
        } else {
            Self::Upper
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Granule {
    KiB4,
    KiB16,
    KiB64,
}
impl Granule {
    pub(super) const fn bits(self) -> u32 {
        match self {
            Self::KiB4 => 12,
            Self::KiB16 => 14,
            Self::KiB64 => 16,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsidBits {
    Bits8,
    Bits16,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PaBits {
    Bits32 = 32,
    Bits36 = 36,
    Bits40 = 40,
    Bits42 = 42,
    Bits44 = 44,
    Bits48 = 48,
    Bits52 = 52,
    Bits56 = 56,
}
impl PaBits {
    pub const fn bits(self) -> u32 {
        self as u32
    }
    fn requested(ips: u64) -> Self {
        // TCR.IPS's three-bit architectural encoding order.
        const IPS_PA_BITS: [PaBits; (IPS_MASK + 1) as usize] = [
            PaBits::Bits32,
            PaBits::Bits36,
            PaBits::Bits40,
            PaBits::Bits42,
            PaBits::Bits44,
            PaBits::Bits48,
            PaBits::Bits52,
            PaBits::Bits56,
        ];
        IPS_PA_BITS[ips as usize]
    }
}
/// Actual CPU availability plus its selected TG0/TG1 fallback. Every value must
/// come from the CPU owner; no default/reset or firmware inference is supplied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GranuleSupport {
    pub kib4: bool,
    pub kib16: bool,
    pub kib64: bool,
    pub lower_fallback: Granule,
    pub upper_fallback: Granule,
}
impl GranuleSupport {
    fn supports(self, granule: Granule) -> bool {
        match granule {
            Granule::KiB4 => self.kib4,
            Granule::KiB16 => self.kib16,
            Granule::KiB64 => self.kib64,
        }
    }
    fn select(self, region: VaRegion, encoded: u64) -> Granule {
        let decoded = match (region, encoded) {
            (VaRegion::Lower, TG0_4K) | (VaRegion::Upper, TG1_4K) => Some(Granule::KiB4),
            (VaRegion::Lower, TG0_16K) | (VaRegion::Upper, TG1_16K) => Some(Granule::KiB16),
            (VaRegion::Lower, TG0_64K) | (VaRegion::Upper, TG1_64K) => Some(Granule::KiB64),
            _ => None,
        };
        decoded
            .filter(|granule| self.supports(*granule))
            .unwrap_or(match region {
                VaRegion::Lower => self.lower_fallback,
                VaRegion::Upper => self.upper_fallback,
            })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuProfile {
    pub pa_max: PaBits,
    pub asid_bits: AsidBits,
    pub granules: GranuleSupport,
    pub pauth: bool,
    pub pan: bool,
    pub pan3: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableConfig {
    pub(super) table_base: u64,
    pub(super) va_bits: u32,
    pub(super) granule: Granule,
    pub(super) start_level: u8,
    pub(super) table_shareability: Shareability,
}
impl TableConfig {
    pub const fn table_base(self) -> u64 {
        self.table_base
    }
    pub const fn granule(self) -> Granule {
        self.granule
    }
    pub const fn start_level(self) -> u8 {
        self.start_level
    }
    pub const fn table_shareability(self) -> Shareability {
        self.table_shareability
    }
    pub(super) const fn index_bits(self) -> u32 {
        self.granule.bits() - DESCRIPTOR_BYTES_LOG2
    }
    pub(super) const fn offset_bits(self, level: u8) -> u32 {
        self.granule.bits() + self.index_bits() * ((FINAL_LEVEL - level) as u32)
    }
    pub(super) fn contains(self, va: u64, top: u32, region: VaRegion) -> bool {
        let checked = (u64::MAX >> (TOP_ADDRESS_BIT - top)) & !((1_u64 << self.va_bits) - 1);
        match region {
            VaRegion::Lower => va & checked == 0,
            VaRegion::Upper => va & checked == checked,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionConfig {
    WalkDisabled,
    Tables(TableConfig),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Disabled,
    Enabled {
        lower: RegionConfig,
        upper: RegionConfig,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AddressPolicy {
    tbi: bool,
    tbid: bool,
}
impl AddressPolicy {
    const fn top(self, kind: AccessKind) -> u32 {
        if self.tbi && !(self.tbid && matches!(kind, AccessKind::Fetch)) {
            TOP_UNTAGGED_BIT
        } else {
            TOP_ADDRESS_BIT
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    pub(super) mode: Mode,
    pub(super) pa_mask: u64,
    pub(super) pa_max_mask: u64,
    pub(super) mair: u64,
    pub(super) asid: u16,
    pub(super) wxn: bool,
    pub(super) epan: bool,
    pub(super) pan: bool,
    pub(super) instruction_cache: bool,
    lower_address: AddressPolicy,
    upper_address: AddressPolicy,
}
impl Config {
    /// Derive from source-selected effective values and authentic CPU facts.
    /// Intermediate M=0 walk controls remain dormant rather than blocking writes.
    pub fn from_controls_for_cpu(controls: Controls, cpu: CpuProfile) -> Result<Self, Unsupported> {
        if !cpu.granules.supports(cpu.granules.lower_fallback)
            || !cpu.granules.supports(cpu.granules.upper_fallback)
        {
            return Err(Unsupported::Control(
                "unimplemented granule fallback witness",
            ));
        }
        if cpu.pan3 && !cpu.pan {
            return Err(Unsupported::Control("PAN3 without PAN CPU witness"));
        }
        let tcr = controls.tcr_el1;
        if tcr & (TCR_MTX0 | TCR_MTX1) != 0 {
            return Err(Unsupported::Control("MTE address transformations"));
        }
        let enabled = controls.sctlr_el1 & SCTLR_M != 0;
        let pa_bits = PaBits::requested((tcr >> IPS_SHIFT) & IPS_MASK)
            .bits()
            .min(cpu.pa_max.bits());
        let mode = if enabled {
            if controls.sctlr_el1 & (SCTLR_E0E | SCTLR_EE) != 0 {
                return Err(Unsupported::Control("big-endian data or table walks"));
            }
            if controls.sctlr_el1 & (SCTLR_C | SCTLR_I) != (SCTLR_C | SCTLR_I) {
                return Err(Unsupported::Control(
                    "enabled-stage1 cache-disabled attributes",
                ));
            }
            if tcr & !TCR_SUPPORTED_MASK != 0 {
                return Err(Unsupported::Control(
                    "unsupported effective TCR translation extensions",
                ));
            }
            if pa_bits > LEGACY_OA_BITS {
                return Err(Unsupported::Control("enabled-stage1 output above 48 bits"));
            }
            Mode::Enabled {
                lower: derive_region(controls, cpu, VaRegion::Lower)?,
                upper: derive_region(controls, cpu, VaRegion::Upper)?,
            }
        } else {
            Mode::Disabled
        };
        let asid_register = if tcr & TCR_A1 != 0 {
            controls.ttbr1_el1
        } else {
            controls.ttbr0_el1
        };
        let asid = (asid_register >> TTBR_ASID_SHIFT) as u16;
        Ok(Self {
            mode,
            pa_mask: (1 << pa_bits) - 1,
            pa_max_mask: (1 << cpu.pa_max.bits()) - 1,
            mair: controls.mair_el1,
            asid: if cpu.asid_bits == AsidBits::Bits16 && tcr & TCR_AS != 0 {
                asid
            } else {
                asid & ASID8_MASK
            },
            wxn: controls.sctlr_el1 & SCTLR_WXN != 0,
            epan: cpu.pan3 && controls.sctlr_el1 & SCTLR_EPAN != 0,
            pan: cpu.pan,
            instruction_cache: controls.sctlr_el1 & SCTLR_I != 0,
            lower_address: AddressPolicy {
                tbi: tcr & TCR_TBI0 != 0,
                tbid: cpu.pauth && tcr & TCR_TBID0 != 0,
            },
            upper_address: AddressPolicy {
                tbi: tcr & TCR_TBI1 != 0,
                tbid: cpu.pauth && tcr & TCR_TBID1 != 0,
            },
        })
    }
    pub const fn mode(self) -> Mode {
        self.mode
    }
    pub const fn asid(self) -> Option<u16> {
        if matches!(self.mode, Mode::Disabled) {
            None
        } else {
            Some(self.asid)
        }
    }
    pub const fn region(self, region: VaRegion) -> Option<RegionConfig> {
        match self.mode {
            Mode::Disabled => None,
            Mode::Enabled { lower, upper } => Some(match region {
                VaRegion::Lower => lower,
                VaRegion::Upper => upper,
            }),
        }
    }
    pub(super) const fn address_top(self, region: VaRegion, kind: AccessKind) -> u32 {
        match region {
            VaRegion::Lower => self.lower_address.top(kind),
            VaRegion::Upper => self.upper_address.top(kind),
        }
    }
}
fn derive_region(
    controls: Controls,
    cpu: CpuProfile,
    region: VaRegion,
) -> Result<RegionConfig, Unsupported> {
    let tcr = controls.tcr_el1;
    let (shift, epd, ttbr, granule_shift) = match region {
        VaRegion::Lower => (
            LOW_REGION_SHIFT,
            TCR_EPD0,
            controls.ttbr0_el1,
            GRANULE0_SHIFT,
        ),
        VaRegion::Upper => (
            HIGH_REGION_SHIFT,
            TCR_EPD1,
            controls.ttbr1_el1,
            GRANULE1_SHIFT,
        ),
    };
    // An EPD region always returns a level0 translation fault without walking;
    // dormant root/granule/cache values are not constructor failures.
    if tcr & epd != 0 {
        return Ok(RegionConfig::WalkDisabled);
    }
    let va_bits = u64::BITS - ((tcr >> shift) & SIZE_MASK) as u32;
    if !SUPPORTED_VA_BITS.contains(&va_bits) {
        return Err(Unsupported::Control(
            "stage1 input size outside 47/48-bit profile",
        ));
    }
    let granule = cpu
        .granules
        .select(region, (tcr >> granule_shift) & TWO_BIT_MASK);
    if granule == Granule::KiB64 {
        return Err(Unsupported::Control("64KiB translation tables"));
    }
    if !matches!((tcr >> (INNER_CACHE_SHIFT + shift)) & TWO_BIT_MASK, 1 | 3)
        || !matches!((tcr >> (OUTER_CACHE_SHIFT + shift)) & TWO_BIT_MASK, 1 | 3)
    {
        return Err(Unsupported::Control("Normal-WB inner/outer table walks"));
    }
    let table_shareability = match (tcr >> (SHAREABILITY_SHIFT + shift)) & TWO_BIT_MASK {
        0 => Shareability::NonShareable,
        2 => Shareability::Outer,
        3 => Shareability::Inner,
        _ => return Err(Unsupported::Control("reserved table shareability")),
    };
    if ttbr & TTBR_CNP != 0 {
        return Err(Unsupported::Control(
            "common-not-private translation tables",
        ));
    }
    let stride = granule.bits() - DESCRIPTOR_BYTES_LOG2;
    let start_level = FINAL_LEVEL - ((va_bits - 1 - granule.bits()) / stride) as u8;
    let root_alignment_bits = va_bits
        - (u32::from(FINAL_LEVEL - start_level) * stride + granule.bits())
        + DESCRIPTOR_BYTES_LOG2;
    let table_base = ttbr & ADDRESS_MASK & !((1 << root_alignment_bits) - 1);
    Ok(RegionConfig::Tables(TableConfig {
        table_base,
        va_bits,
        granule,
        start_level,
        table_shareability,
    }))
}
