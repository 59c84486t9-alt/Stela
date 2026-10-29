//! Host CPU feature requirements, detection and generated-code target identities.

use alloc::borrow::ToOwned;
use alloc::string::String;

const CPUID_AVX_HARDWARE: u32 = 1 << 28;
/// CPUID.1:ECX bit 27: the OS set CR4.OSXSAVE, so XGETBV reads XCR0.
const CPUID_OSXSAVE: u32 = 1 << 27;
/// XCR0 bits 1 and 2: the OS saves XMM and YMM state.
const XCR0_AVX_STATE: u64 = 0x6;
/// XCR0 bits 5 to 7: the OS saves opmask, ZMM_Hi256 and Hi16_ZMM state.
const XCR0_AVX512_STATE: u64 = 0xe0;
/// XCR0 bit 19: the OS saves the extended GPRs R16..R31.
const XCR0_APX_STATE: u64 = 1 << 19;

/// Explicit host requirements bind generated code and persistent cache identity.
/// SSE tiers are nested; every other capability is independent.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TargetCpu {
    tier: SseTier,
    /// One bit per [`Feature`].
    features: u64,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SseTier {
    #[default]
    Baseline,
    Ssse3,
    Sse41,
    Sse42,
}

/// The CPUID leaves and XCR0 value host feature detection reads. Leaves above
/// the maximum CPUID leaf 0 reports read as zero.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct HostCpuid {
    /// Leaf 0 EBX, EDX and ECX: the vendor string.
    pub vendor: [u32; 3],
    /// Leaf 1 ECX.
    pub leaf1_ecx: u32,
    /// Leaf 1 EDX.
    pub leaf1_edx: u32,
    /// Leaf 1 EAX: family, model and stepping.
    pub leaf1_eax: u32,
    /// Leaf 7 subleaf 0 EBX.
    pub leaf7_ebx: u32,
    /// Leaf 7 subleaf 0 ECX.
    pub leaf7_ecx: u32,
    /// Leaf 7 subleaf 0 EDX.
    pub leaf7_edx: u32,
    /// Leaf 7 subleaf 1 EAX.
    pub leaf7_1_eax: u32,
    /// Leaf 7 subleaf 1 EDX.
    pub leaf7_1_edx: u32,
    /// Leaf 29H subleaf 0 EBX: APX conditional, NDD and NF capabilities.
    pub leaf29_ebx: u32,
    /// Leaf 8000_0001H ECX.
    pub extended1_ecx: u32,
    /// XCR0, or zero when the OS has not enabled XSAVE ([`CPUID_OSXSAVE`]).
    pub xcr0: u64,
    /// The OS enables AVX-512 state on a thread's first EVEX instruction, so
    /// XCR0 lacks it until then (xnu, which reports usable support in
    /// `hw.optional.avx512f`).
    pub avx512_on_demand: bool,
}

impl HostCpuid {
    /// Read this processor's CPUID leaves and XCR0, querying leaf 0 once.
    #[cfg(target_arch = "x86_64")]
    pub fn read() -> Self {
        use core::arch::x86_64::{__cpuid, __cpuid_count, CpuidResult};
        let identity = __cpuid(0);
        let leaf = |leaf: u32| {
            if identity.eax >= leaf {
                __cpuid_count(leaf, 0)
            } else {
                CpuidResult {
                    eax: 0,
                    ebx: 0,
                    ecx: 0,
                    edx: 0,
                }
            }
        };
        let (leaf1, leaf7) = (leaf(1), leaf(7));
        let leaf7_1 = if identity.eax >= 7 && leaf7.eax >= 1 {
            __cpuid_count(7, 1)
        } else {
            CpuidResult {
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
            }
        };
        let extended1_ecx = if __cpuid(0x8000_0000).eax >= 0x8000_0001 {
            __cpuid(0x8000_0001).ecx
        } else {
            0
        };
        let xcr0 = if leaf1.ecx & CPUID_OSXSAVE != 0 {
            // SAFETY: CR4.OSXSAVE is set, so XGETBV with ECX = 0 is defined.
            unsafe { core::arch::x86_64::_xgetbv(0) }
        } else {
            0
        };
        Self {
            vendor: [identity.ebx, identity.edx, identity.ecx],
            leaf1_ecx: leaf1.ecx,
            leaf1_edx: leaf1.edx,
            leaf1_eax: leaf1.eax,
            leaf7_ebx: leaf7.ebx,
            leaf7_ecx: leaf7.ecx,
            leaf7_edx: leaf7.edx,
            leaf7_1_eax: leaf7_1.eax,
            leaf7_1_edx: leaf7_1.edx,
            leaf29_ebx: leaf(0x29).ebx,
            extended1_ecx,
            xcr0,
            avx512_on_demand: false,
        }
    }

    const fn bit(register: u32, bit: u32) -> bool {
        register & (1 << bit) != 0
    }
    /// AVX hardware with OS-enabled XMM and YMM state.
    const fn avx(&self) -> bool {
        Self::bit(self.leaf1_ecx, 28) && self.xcr0 & XCR0_AVX_STATE == XCR0_AVX_STATE
    }
    /// The display family: the base family plus, for family 0FH, the
    /// extended family (SDM Vol. 2A, CPUID leaf 1).
    const fn family(&self) -> u32 {
        let base = (self.leaf1_eax >> 8) & 0xf;
        if base == 0xf {
            base + ((self.leaf1_eax >> 20) & 0xff)
        } else {
            base
        }
    }
    /// BMI2. Intel's Pentium and Celeron parts without AVX enumerate BMI1
    /// and BMI2 but fault on their VEX encodings, so an Intel host needs AVX
    /// for them (as Rust's `std_detect`).
    const fn bmi2(&self) -> bool {
        Self::bit(self.leaf7_ebx, 8)
            && (!matches!(Vendor::from_cpuid(self.vendor), Vendor::Intel) || self.avx())
    }
    /// APX EGPRs are available only with XSAVE support and OS-enabled state.
    const fn apx(&self) -> bool {
        Self::bit(self.leaf1_ecx, 26)
            && Self::bit(self.leaf1_ecx, 27)
            && Self::bit(self.leaf7_1_edx, 21)
            && self.xcr0 & XCR0_APX_STATE != 0
    }
    /// [`Self::avx512_state`] with AVX-512F.
    const fn avx512f(&self) -> bool {
        self.avx512_state() && Self::bit(self.leaf7_ebx, 16)
    }
    /// [`Self::avx`] with OS-enabled opmask and ZMM state.
    const fn avx512_state(&self) -> bool {
        self.avx() && (self.xcr0 & XCR0_AVX512_STATE == XCR0_AVX512_STATE || self.avx512_on_demand)
    }
}

/// The vendor of a host CPU as its documented memory-ordering guarantees
/// apply, from the CPUID leaf 0 vendor string. This is the compiler's one
/// vendor policy:
///
/// - Intel (`GenuineIntel`): an unaligned load within one cache line is
///   single-copy atomic (SDM Vol. 3A 9.1.1, [`TargetCpu::LineAtomic`]), and
///   with AVX an aligned 16-byte load is ([`TargetCpu::AtomicLoad16`]).
/// - AMD (`AuthenticAMD`) and Hygon (`HygonGenuine`): with AVX an aligned
///   16-byte load is single-copy atomic (APM 24593 rev. 3.44 7.3.2); an
///   unaligned load is atomic only inside an aligned quadword. Hygon's cores
///   are licensed AMD Zen designs that follow AMD's manuals, as Linux treats
///   them (`arch/x86/kernel/cpu/hygon.c`).
/// - Zhaoxin (`  Shanghai  `), Centaur (`CentaurHauls`) and every other
///   vendor: no published guarantee for either, so their hosts take the
///   CMPXCHG16B and split-load paths until one is documented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vendor {
    Intel,
    Amd,
    Other,
}

impl Vendor {
    /// The vendor of the CPUID leaf 0 EBX, EDX and ECX values `vendor`.
    pub const fn from_cpuid(vendor: [u32; 3]) -> Self {
        match vendor {
            TargetCpu::INTEL_VENDOR => Self::Intel,
            TargetCpu::AMD_VENDOR | TargetCpu::HYGON_VENDOR => Self::Amd,
            _ => Self::Other,
        }
    }
}

/// A feature that detection leaves to the caller: the bare-metal boot
/// declares it, or it is a compilation mode.
const fn declared(_: &HostCpuid) -> bool {
    false
}

/// Declares the optional features, in canonical identity order: each one's
/// `TargetCpu` constant, `with_*` builder, `+name` in [`TargetCpu::id`] and
/// CPUID probe. Each feature's bit is its position. The names and their order
/// spell the target identities that persistent caches and users key on; the
/// compilation modes stay last.
macro_rules! features {
    ($($(#[$doc:meta])* $constant:ident, $with:ident, $name:literal, $probe:expr;)*) => {
        /// One optional feature of a [`TargetCpu`], numbered by its bit.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum Feature {
            $($constant,)*
        }

        /// Each feature with its `+name` and probe, in identity order.
        const FEATURES: &[(Feature, &str, fn(&HostCpuid) -> bool)] =
            &[$((Feature::$constant, $name, $probe),)*];

        // Keep the published feature names and their cache identities.
        #[allow(non_upper_case_globals, reason = "Target selectors use the same names as the instruction-set variants they replace.")]
        impl TargetCpu {
            $(
                $(#[$doc])*
                pub const $constant: Self = Self::Baseline.with_feature(Feature::$constant);
                pub const fn $with(self) -> Self {
                    self.with_feature(Feature::$constant)
                }
            )*
        }
    };
}

features! {
    /// Minimum requirements for legacy XMM PCLMULQDQ, independent of SSE tiers.
    Pclmulqdq, with_pclmulqdq, "+pclmulqdq", |cpu| HostCpuid::bit(cpu.leaf1_ecx, 1);
    /// Minimum requirements for VEX FMA3, including OS-enabled AVX register state.
    Fma, with_fma, "+fma", |cpu| cpu.avx() && HostCpuid::bit(cpu.leaf1_ecx, 12);
    /// Minimum requirements for F16C, including OS-enabled AVX register state.
    F16c, with_f16c, "+f16c", |cpu| cpu.avx() && HostCpuid::bit(cpu.leaf1_ecx, 29);
    Popcnt, with_popcnt, "+popcnt", |cpu| HostCpuid::bit(cpu.leaf1_ecx, 23);
    /// BMI1. Intel's Pentium and Celeron parts without AVX enumerate BMI1 but
    /// fault on its VEX encodings, so an Intel host needs AVX for it (as
    /// Rust's `std_detect`).
    Bmi1, with_bmi1, "+bmi1", |cpu| {
        HostCpuid::bit(cpu.leaf7_ebx, 3)
            && (!matches!(Vendor::from_cpuid(cpu.vendor), Vendor::Intel) || cpu.avx())
    };
    /// Minimum requirements for legacy XMM AES instructions, independent of SSE tiers.
    Aes, with_aes, "+aes", |cpu| HostCpuid::bit(cpu.leaf1_ecx, 25);
    /// Minimum requirements for legacy XMM SHA instructions, independent of SSE tiers.
    Sha, with_sha, "+sha", |cpu| HostCpuid::bit(cpu.leaf7_ebx, 29);
    /// Aligned 16-byte atomic loads: the [`Vendor`] guarantee with AVX hardware.
    /// Lowering uses legacy SSE2, independently of OS-enabled AVX state.
    AtomicLoad16, with_atomic_load16, "+atomic-load16", |cpu| {
        TargetCpu::atomic_load16_guaranteed(cpu.vendor, cpu.leaf1_ecx)
    };
    /// CMPXCHG8B, independently enumerated for the W-pair optimized recipe.
    Cx8, with_cx8, "+cx8", |cpu| HostCpuid::bit(cpu.leaf1_edx, 8);
    /// CMPXCHG16B, independent of aligned16 load atomicity and AVX state.
    Cx16, with_cx16, "+cx16", |cpu| HostCpuid::bit(cpu.leaf1_ecx, 13);
    /// AVX2 integer recipes, including OS-enabled XMM/YMM register state.
    Avx2, with_avx2, "+avx2", |cpu| cpu.avx() && HostCpuid::bit(cpu.leaf7_ebx, 5);
    /// EVEX.512 AVX-512 Foundation, including OS-enabled opmask and ZMM state.
    Avx512f, with_avx512f, "+avx512f", |cpu| {
        cpu.avx512_state() && HostCpuid::bit(cpu.leaf7_ebx, 16)
    };
    /// LZCNT (ABM on AMD).
    Lzcnt, with_lzcnt, "+lzcnt", |cpu| HostCpuid::bit(cpu.extended1_ecx, 5);
    /// BMI2: SHLX/SHRX/SARX/RORX, BZHI, MULX and PDEP/PEXT.
    Bmi2, with_bmi2, "+bmi2", HostCpuid::bmi2;
    /// BMI2 whose PDEP and PEXT run in hardware: AMD's Zen 1 and Zen 2 (and
    /// Hygon's Zen-derived cores) microcode them at tens of cycles.
    FastPdep, with_fast_pdep, "+fast-pdep", |cpu| {
        let amd = matches!(Vendor::from_cpuid(cpu.vendor), Vendor::Amd);
        cpu.bmi2() && !(amd && cpu.family() < 0x19)
    };
    /// MOVBE: byte-swapping loads and stores.
    Movbe, with_movbe, "+movbe", |cpu| HostCpuid::bit(cpu.leaf1_ecx, 22);
    /// GFNI in its legacy SSE encoding (GF2P8AFFINEQB and relatives).
    Gfni, with_gfni, "+gfni", |cpu| HostCpuid::bit(cpu.leaf7_ecx, 8);
    /// AVX-512VL: EVEX forms on XMM and YMM registers.
    Avx512vl, with_avx512vl, "+avx512vl", |cpu| cpu.avx512f() && HostCpuid::bit(cpu.leaf7_ebx, 31);
    /// AVX-512BW: byte and word elements and 64-bit opmasks.
    Avx512bw, with_avx512bw, "+avx512bw", |cpu| cpu.avx512f() && HostCpuid::bit(cpu.leaf7_ebx, 30);
    /// AVX-512CD: VPLZCNTD/Q and VPCONFLICTD/Q.
    Avx512cd, with_avx512cd, "+avx512cd", |cpu| cpu.avx512f() && HostCpuid::bit(cpu.leaf7_ebx, 28);
    /// AVX-512DQ: quadword multiplies and FP-integer conversions.
    Avx512dq, with_avx512dq, "+avx512dq", |cpu| cpu.avx512f() && HostCpuid::bit(cpu.leaf7_ebx, 17);
    /// AVX-512 VPOPCNTD/Q.
    Avx512vpopcntdq, with_avx512vpopcntdq, "+avx512vpopcntdq", |cpu| {
        cpu.avx512f() && HostCpuid::bit(cpu.leaf7_ecx, 14)
    };
    /// AVX-512 BITALG: VPOPCNTB/W and VPSHUFBITQMB.
    Avx512bitalg, with_avx512bitalg, "+avx512bitalg", |cpu| {
        cpu.avx512f() && HostCpuid::bit(cpu.leaf7_ecx, 12)
    };
    /// AVX-512 VNNI: VPDPBUSD and VPDPWSSD.
    Avx512vnni, with_avx512vnni, "+avx512vnni", |cpu| {
        cpu.avx512f() && HostCpuid::bit(cpu.leaf7_ecx, 11)
    };
    /// AVX-VNNI: the VEX forms of VPDPBUSD and VPDPWSSD.
    AvxVnni, with_avx_vnni, "+avxvnni", |cpu| cpu.avx() && HostCpuid::bit(cpu.leaf7_1_eax, 4);
    /// AVX-512 BF16: VDPBF16PS and VCVTNE2PS2BF16.
    Avx512bf16, with_avx512bf16, "+avx512bf16", |cpu| {
        cpu.avx512f() && HostCpuid::bit(cpu.leaf7_1_eax, 5)
    };
    /// AVX-NE-CONVERT: VEX BF16 and FP16 conversions.
    AvxNeConvert, with_avx_ne_convert, "+avxneconvert", |cpu| {
        cpu.avx() && HostCpuid::bit(cpu.leaf7_1_edx, 5)
    };
    /// AVX-512 FP16: half-precision arithmetic.
    Avx512fp16, with_avx512fp16, "+avx512fp16", |cpu| {
        cpu.avx512f() && HostCpuid::bit(cpu.leaf7_edx, 23)
    };
    /// VAES: VEX and EVEX AES rounds on wide vectors.
    Vaes, with_vaes, "+vaes", |cpu| cpu.avx() && HostCpuid::bit(cpu.leaf7_ecx, 9);
    /// VPCLMULQDQ: carry-less multiplies on wide vectors.
    Vpclmulqdq, with_vpclmulqdq, "+vpclmulqdq", |cpu| {
        cpu.avx() && HostCpuid::bit(cpu.leaf7_ecx, 10)
    };
    /// SHA512: VSHA512RNDS2, VSHA512MSG1 and VSHA512MSG2.
    Sha512, with_sha512, "+sha512", |cpu| cpu.avx() && HostCpuid::bit(cpu.leaf7_1_eax, 0);
    /// SM3: VSM3RNDS2, VSM3MSG1 and VSM3MSG2.
    Sm3, with_sm3, "+sm3", |cpu| cpu.avx() && HostCpuid::bit(cpu.leaf7_1_eax, 1);
    /// SM4: VSM4KEY4 and VSM4RNDS4.
    Sm4, with_sm4, "+sm4", |cpu| cpu.avx() && HostCpuid::bit(cpu.leaf7_1_eax, 2);
    /// APX: sixteen more general-purpose registers (R16..R31) and the
    /// REX2 and extended EVEX encodings, with OS-enabled APX state (XCR0
    /// bit 19).
    Apx, with_apx, "+apx", |cpu| {
        cpu.apx()
    };
    /// APX new conditional instructions, new destinations and flag suppression
    /// (Intel APX rev. 7, CPUID.29H:EBX[0]), with usable EGPR state.
    ApxNdd, with_apx_ndd, "+apx-ndd", |cpu| {
        cpu.apx() && HostCpuid::bit(cpu.leaf29_ebx, 0)
    };
    /// An unaligned load that lies within one cache line is single-copy
    /// atomic: an Intel processor since the P6 family ([`Vendor`]). A 16-byte
    /// granule never crosses a line, so an ordered load inside one is a
    /// plain load.
    LineAtomic, with_line_atomic, "+line-atomic", |cpu| {
        matches!(Vendor::from_cpuid(cpu.vendor), Vendor::Intel)
    };
    /// The host runs the instructions on Intel's data operand independent
    /// timing list with timing independent of their data: Intel's
    /// IA32_UARCH_MISC_CTL.DOITM (MSR 1B01H bit 0, enumerated by
    /// IA32_ARCH_CAPABILITIES bit 12) is set on every logical processor that
    /// runs guest code, or the processor predates Ice Lake (Core) or
    /// Gracemont (Atom) and does not enumerate it. A hosted process can
    /// neither read nor set it; the bare-metal boot declares it. AMD
    /// documents no equivalent.
    Doit, with_doit, "+doit", declared;
    /// Code lowered for FEAT_DIT's PSTATE.DIT: the listed instructions that
    /// have a data-independent lowering (CLZ, CLS, CTZ, CNT, CRC32, CRC32C)
    /// compile to instructions on Intel's list, without a branch on or a
    /// memory index by their data, at a cost in speed. The LSE atomics,
    /// acquire loads, store-releases and barriers become plain loads and
    /// stores (no LOCK, XCHG or MFENCE), as for a single agent, so the mode
    /// requires that no other agent accesses guest memory while its code
    /// runs: the system engine runs one PE at a time, and a multi-threaded
    /// process must not use it. A compilation mode, not a host capability,
    /// honored on the [`Self::DATA_INDEPENDENT_TIMING_TIERS`].
    DataIndependentTiming, with_data_independent_timing, "+dit", declared;
}

/// Features that are compilation modes: part of the identity, not host
/// requirements.
const MODES: u64 = 1 << Feature::DataIndependentTiming as u32;

// Keep the published tier names and their cache identities.
#[allow(
    non_upper_case_globals,
    reason = "Tier selectors use the same names as the instruction-set variants they replace."
)]
impl TargetCpu {
    pub const Baseline: Self = Self {
        tier: SseTier::Baseline,
        features: 0,
    };
    pub const Ssse3: Self = Self {
        tier: SseTier::Ssse3,
        ..Self::Baseline
    };
    pub const Sse41: Self = Self {
        tier: SseTier::Sse41,
        ..Self::Baseline
    };
    pub const Sse42: Self = Self {
        tier: SseTier::Sse42,
        ..Self::Baseline
    };
    /// `GenuineIntel` as CPUID leaf 0 returns it in EBX, EDX and ECX, which
    /// identifies a [`Self::line_atomic`] host.
    pub const INTEL_VENDOR: [u32; 3] = [
        u32::from_le_bytes(*b"Genu"),
        u32::from_le_bytes(*b"ineI"),
        u32::from_le_bytes(*b"ntel"),
    ];
    /// AMD's vendor identity in CPUID0 EBX, EDX, ECX order.
    pub const AMD_VENDOR: [u32; 3] = [
        u32::from_le_bytes(*b"Auth"),
        u32::from_le_bytes(*b"enti"),
        u32::from_le_bytes(*b"cAMD"),
    ];
    /// Hygon's vendor identity in CPUID0 EBX, EDX, ECX order.
    pub const HYGON_VENDOR: [u32; 3] = [
        u32::from_le_bytes(*b"Hygo"),
        u32::from_le_bytes(*b"nGen"),
        u32::from_le_bytes(*b"uine"),
    ];

    /// Classify the documented aligned cacheable 16-byte load guarantee from
    /// CPUID.0 vendor and CPUID.1 ECX ([`Vendor`]): it requires AVX hardware;
    /// OS AVX state is separate. These raw values alone are not permission to
    /// enter native code or RAM.
    pub const fn atomic_load16_guaranteed(vendor: [u32; 3], leaf1_ecx: u32) -> bool {
        matches!(Vendor::from_cpuid(vendor), Vendor::Intel | Vendor::Amd)
            && leaf1_ecx & CPUID_AVX_HARDWARE != 0
    }

    /// x86-64-v2 of the x86-64 psABI (SSE4.2, POPCNT, CMPXCHG8B,
    /// CMPXCHG16B): the least host Stela runs on. Every other feature is
    /// optional and has a fallback.
    pub const X86_64_V2: Self = Self::Sse42.with_popcnt().with_cx8().with_cx16();
    /// x86-64-v3: x86-64-v2 with AVX, AVX2, BMI1, BMI2, F16C, FMA, LZCNT and
    /// MOVBE. The AVX features' probes include OS-enabled XSAVE state.
    pub const X86_64_V3: Self = Self::X86_64_V2
        .with_fma()
        .with_f16c()
        .with_bmi1()
        .with_avx2()
        .with_lzcnt()
        .with_bmi2()
        .with_movbe();
    /// x86-64-v4: x86-64-v3 with AVX-512F, BW, CD, DQ and VL.
    pub const X86_64_V4: Self = Self::X86_64_V3
        .with_avx512f()
        .with_avx512vl()
        .with_avx512bw()
        .with_avx512cd()
        .with_avx512dq();
    /// The host tiers whose data-independent-timing lowerings the DIT unit
    /// tests check (`x86_64::{integer_math, integer_unary, crc}`), largest
    /// first: each psABI level with PCLMULQDQ, AES, SHA and aligned 16-byte
    /// atomic loads, and x86-64-v2 also with BMI1.
    pub const DATA_INDEPENDENT_TIMING_TIERS: [Self; 3] = [
        Self::X86_64_V4.with_audited_extras(),
        Self::X86_64_V3.with_audited_extras(),
        Self::X86_64_V2.with_bmi1().with_audited_extras(),
    ];

    const fn with_audited_extras(self) -> Self {
        self.with_pclmulqdq()
            .with_aes()
            .with_sha()
            .with_atomic_load16()
    }

    const fn with_feature(self, feature: Feature) -> Self {
        Self {
            features: self.features | 1 << feature as u32,
            ..self
        }
    }
    const fn has(self, feature: Feature) -> bool {
        self.features & 1 << feature as u32 != 0
    }
    pub const fn doit(self) -> bool {
        self.has(Feature::Doit)
    }
    pub const fn data_independent_timing(self) -> bool {
        self.has(Feature::DataIndependentTiming)
    }
    /// The target to compile PSTATE.DIT code for on this host: the largest
    /// audited tier ([`Self::DATA_INDEPENDENT_TIMING_TIERS`]) it supports, in
    /// the data-independent-timing mode. `None` unless the host declares
    /// Intel's data operand independent timing ([`Self::doit`]) and supports
    /// one of them, as no audit covers another tier's lowerings.
    pub fn data_independent_timing_target(self) -> Option<Self> {
        if !self.doit() {
            return None;
        }
        Self::DATA_INDEPENDENT_TIMING_TIERS
            .into_iter()
            .find(|tier| self.supports(*tier))
            .map(|tier| tier.with_doit().with_data_independent_timing())
    }
    /// True only when every required feature is present in this target.
    /// The data-independent-timing mode is not a host feature.
    pub const fn supports(self, required: Self) -> bool {
        self.tier as u8 >= required.tier as u8 && required.features & !MODES & !self.features == 0
    }
    /// The target CPUID values describe: every feature whose probe holds.
    /// Declared features ([`Self::doit`]) are left to the caller.
    pub fn from_cpuid(cpu: &HostCpuid) -> Self {
        let bit = |bit| HostCpuid::bit(cpu.leaf1_ecx, bit);
        let tier = match (bit(9), bit(19), bit(20)) {
            (false, _, _) => SseTier::Baseline,
            (true, false, _) => SseTier::Ssse3,
            (true, true, false) => SseTier::Sse41,
            (true, true, true) => SseTier::Sse42,
        };
        FEATURES
            .iter()
            .filter(|(_, _, probe)| probe(cpu))
            .fold(Self { tier, features: 0 }, |target, (feature, _, _)| {
                target.with_feature(*feature)
            })
    }
    /// Detect the host's usable CPU features. Freestanding callers supply a
    /// target explicitly.
    #[cfg(any(feature = "std", test))]
    pub fn detect() -> Self {
        static DETECTED: std::sync::OnceLock<TargetCpu> = std::sync::OnceLock::new();
        *DETECTED.get_or_init(Self::probe)
    }

    #[cfg(any(feature = "std", test))]
    fn probe() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            Self::from_cpuid(&HostCpuid {
                avx512_on_demand: darwin_on_demand_avx512f(),
                ..HostCpuid::read()
            })
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            Self::Baseline
        }
    }
    /// Canonical metadata identity; serialization is outside emitted execution.
    pub fn id(self) -> String {
        let mut id = match self.tier {
            SseTier::Baseline => "x86_64-baseline",
            SseTier::Ssse3 => "x86_64-baseline+ssse3",
            SseTier::Sse41 => "x86_64-baseline+ssse3+sse4.1",
            SseTier::Sse42 => "x86_64-baseline+ssse3+sse4.1+sse4.2",
        }
        .to_owned();
        for (feature, name, _) in FEATURES {
            if self.has(*feature) {
                id.push_str(name);
            }
        }
        id
    }
    /// Check this target against the hosted process's usable capabilities.
    #[cfg(any(feature = "std", test))]
    pub fn supported(self) -> bool {
        cfg!(target_arch = "x86_64") && Self::detect().supports(self)
    }
}

#[cfg(all(
    any(feature = "std", test),
    target_arch = "x86_64",
    target_os = "macos"
))]
fn darwin_on_demand_avx512f() -> bool {
    use core::ffi::{c_char, c_int, c_void};
    unsafe extern "C" {
        fn sysctlbyname(
            name: *const c_char,
            old: *mut c_void,
            old_length: *mut usize,
            new: *mut c_void,
            new_length: usize,
        ) -> c_int;
    }
    let mut value: c_int = 0;
    let mut length = size_of::<c_int>();
    // SAFETY: a NUL-terminated name and a correctly sized output buffer.
    let result = unsafe {
        sysctlbyname(
            c"hw.optional.avx512f".as_ptr(),
            (&raw mut value).cast(),
            &mut length,
            core::ptr::null_mut(),
            0,
        )
    };
    result == 0 && length == size_of::<c_int>() && value == 1
}

#[cfg(all(
    any(feature = "std", test),
    target_arch = "x86_64",
    not(target_os = "macos")
))]
fn darwin_on_demand_avx512f() -> bool {
    false
}

// Ordering means feature containment, not an arbitrary rank. The timing
// mode orders as one more feature, so a target compares equal only to
// itself, while `supports` leaves the mode out of the host requirements.
impl PartialOrd for TargetCpu {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        let contains = |outer: &Self, inner: &Self| {
            outer.tier >= inner.tier && inner.features & !outer.features == 0
        };
        match (contains(self, other), contains(other, self)) {
            (true, true) => Some(core::cmp::Ordering::Equal),
            (true, false) => Some(core::cmp::Ordering::Greater),
            (false, true) => Some(core::cmp::Ordering::Less),
            (false, false) => None,
        }
    }
}

/// An invalid target identity, including unknown or incorrectly ordered suffixes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetParseError {
    pub identity: String,
}
impl core::fmt::Display for TargetParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "unknown x86-64 CPU target {}", self.identity)
    }
}
impl core::error::Error for TargetParseError {}

impl core::str::FromStr for TargetCpu {
    type Err = TargetParseError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut target = Self::Baseline;
        let mut tier_name = value;
        // Strip each optional suffix once, in reverse order. A duplicate,
        // unknown or out-of-order suffix is left behind and fails parsing.
        for (feature, name, _) in FEATURES.iter().rev() {
            if let Some(prefix) = tier_name.strip_suffix(name) {
                tier_name = prefix;
                target = target.with_feature(*feature);
            }
        }
        target.tier = match tier_name {
            "baseline" | "x86_64-baseline" => SseTier::Baseline,
            "ssse3" | "x86_64-baseline+ssse3" => SseTier::Ssse3,
            "sse4.1" | "x86_64-baseline+ssse3+sse4.1" => SseTier::Sse41,
            "sse4.2" | "x86_64-baseline+ssse3+sse4.1+sse4.2" => SseTier::Sse42,
            _ => {
                return Err(TargetParseError {
                    identity: value.to_owned(),
                });
            }
        };
        Ok(target)
    }
}

impl serde::Serialize for TargetCpu {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.id())
    }
}

impl<'de> serde::Deserialize<'de> for TargetCpu {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let id = <alloc::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        id.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests;
