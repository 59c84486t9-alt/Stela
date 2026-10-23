//! Destination-local extended-state geometry and descriptor lifetime.
//!
//! This unit enables no processor feature and admits no compiler target. The
//! real entry stub must save the whole actual enabled state before Rust runs.
//! Standard XSAVE64/XRSTOR64 only; every entry owns a separate IST image.
use core::marker::PhantomData;

const LEGACY_BYTES: usize = 512;
pub(crate) const STANDARD_HEADER_OFFSET: usize = LEGACY_BYTES;
pub(crate) const STANDARD_HEADER_BYTES: usize = 64;
const HEADER_BYTES: usize = STANDARD_HEADER_BYTES;
const EXTENDED_OFFSET: usize = LEGACY_BYTES + HEADER_BYTES;
pub(crate) const IMAGE_ALIGNMENT: usize = 64;
// Explicit descriptor/stack resource policy, not an architectural XSAVE limit.
pub(crate) const MAX_IMAGE_BYTES: usize = 16 * 1024;
pub(crate) const FORMAT_FXSAVE: u64 = 0;
pub(crate) const FORMAT_XSAVE: u64 = 1;
pub(crate) const FORMAT_XSAVE_LEGACY_SSE: u64 = 2;
#[repr(C)]
pub(crate) struct EntryMetadata {
    format: u64,
    mask: u64,
}
pub(crate) const ENTRY_METADATA_BYTES: usize = core::mem::size_of::<EntryMetadata>();
pub(crate) const ENTRY_FORMAT_OFFSET: usize = core::mem::offset_of!(EntryMetadata, format);
pub(crate) const ENTRY_MASK_OFFSET: usize = core::mem::offset_of!(EntryMetadata, mask);
const X87: u64 = 1;
const SSE: u64 = 1 << 1;
const AVX: u64 = 1 << 2;
const MPX: u64 = (1 << 3) | (1 << 4);
// Geometry records all supported user components; this unit admits only the
// vector family whose handler environment is owned here. No PKRU/AMX policy.
pub(crate) const ADMITTED_MASK: u64 = X87 | SSE | AVX | AVX512;
const AVX512: u64 = (1 << 5) | (1 << 6) | (1 << 7);
const XSAVE: u32 = 1 << 26;
const XSAVES: u32 = 1 << 3;
const XFD: u32 = 1 << 4;
const CR0_FP_DISABLED: u64 = (1 << 2) | (1 << 3);
const CR4_FP_REQUIRED: u64 = (1 << 9) | (1 << 10);
const CR4_OSXSAVE: u64 = 1 << 18;
const CR4_CET: u64 = 1 << 23;
const FXSR_SSE_SSE2: u32 = (1 << 24) | (1 << 25) | (1 << 26);
const EFER: u32 = 0xc000_0080;
const EFER_FAST_FXSR: u64 = 1 << 14;
const IA32_XSS: u32 = 0xda0;
const IA32_XFD: u32 = 0x1c4;
const SAVE_ERROR_POINTERS: u32 = 1 << 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LayoutError {
    #[cfg(not(target_arch = "x86_64"))]
    UnsupportedHost,
    Privilege,
    InterruptsEnabled,
    ProcessorChanged,
    MissingCpuFeatures,
    ErrorPointers,
    Controls,
    Geometry,
    ResourceLimit,
    SupervisorState,
    DynamicState,
    ImageExtent,
    AlreadyInstalled,
}

#[derive(Debug, Default, Clone, Copy)]
struct Registers {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
}

#[derive(Debug, Default, Clone, Copy)]
struct Component {
    bit: u8,
    offset: usize,
    bytes: usize,
}

/// Assembly metadata is installed only with its actual descriptor owner. A
/// copied number/ABI record is not a CPU, backing or entry authority.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct EntryAbi {
    /// Rounded image capacity; includes standard header when XSAVE exists.
    pub(crate) image_bytes: u64,
    pub(crate) supported_mask: u64,
    pub(crate) xsave_available: u64,
    /// Bit0 qualifies IA32_XSS; bit1 qualifies IA32_XFD.
    pub(crate) msr_flags: u64,
    /// Space from the original frame needed for image, saved format/mask and
    /// worst-case downward alignment. The original Frame remains untouched.
    pub(crate) entry_bytes: u64,
}

impl EntryAbi {
    /// Private descriptor initialization only; never a usable save contract.
    pub(crate) const EMPTY: Self = Self { image_bytes: 0, supported_mask: 0, xsave_available: 0, msr_flags: 0, entry_bytes: 0 };
}

#[derive(Debug)]
struct Layout {
    abi: EntryAbi,
    components: [Component; 62],
    count: usize,
    xss: bool,
    xfd: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SaveFormat {
    Fxsave,
    Xsave { mask: u64 },
    /// XCR0.SSE does not disable legacy SSE execution. Preserve the shared
    /// legacy region with FXSAVE before XSAVE, then restore it after XRSTOR.
    XsaveLegacySse { mask: u64 },
}

#[derive(Debug, Clone, Copy)]
struct Controls {
    cr0: u64,
    cr4: u64,
    efer: u64,
    xcr0: Option<u64>,
    xss: Option<u64>,
    xfd: Option<u64>,
}

impl Layout {
    fn discover(
        maximum: u32,
        leaf1_ecx: u32,
        mut cpuid: impl FnMut(u32, u32) -> Registers,
    ) -> Result<Self, LayoutError> {
        let mut layout = Self {
            abi: EntryAbi {
                image_bytes: LEGACY_BYTES as u64,
                supported_mask: X87 | SSE,
                xsave_available: 0,
                msr_flags: 0,
                entry_bytes: (LEGACY_BYTES + ENTRY_METADATA_BYTES + IMAGE_ALIGNMENT - 1) as u64,
            },
            components: [Component::default(); 62],
            count: 0,
            xss: false,
            xfd: false,
        };
        if leaf1_ecx & XSAVE == 0 {
            return Ok(layout);
        }
        if maximum < 0xd {
            return Err(LayoutError::MissingCpuFeatures);
        }
        let base = cpuid(0xd, 0);
        let supported = u64::from(base.eax) | u64::from(base.edx) << 32;
        if supported & (X87 | SSE) != X87 | SSE || supported & (1 << 63) != 0 {
            return Err(LayoutError::Geometry);
        }
        let capacity = base.ecx as usize;
        if capacity < EXTENDED_OFFSET || base.ebx as usize > capacity
            || (base.ebx as usize) < EXTENDED_OFFSET
        {
            return Err(LayoutError::Geometry);
        }
        let rounded = capacity.checked_add(IMAGE_ALIGNMENT - 1)
            .ok_or(LayoutError::ResourceLimit)? & !(IMAGE_ALIGNMENT - 1);
        if rounded > MAX_IMAGE_BYTES {
            return Err(LayoutError::ResourceLimit);
        }
        for bit in 2..63 {
            if supported & (1u64 << bit) == 0 { continue; }
            let record = cpuid(0xd, bit);
            let component = Component { bit: bit as u8, offset: record.ebx as usize, bytes: record.eax as usize };
            let end = component.offset.checked_add(component.bytes).ok_or(LayoutError::Geometry)?;
            if component.bytes == 0 || component.offset < EXTENDED_OFFSET
                || end > capacity || record.ecx & 1 != 0
            {
                return Err(LayoutError::Geometry);
            }
            for prior in &layout.components[..layout.count] {
                if component.offset < prior.offset + prior.bytes && prior.offset < end {
                    return Err(LayoutError::Geometry);
                }
            }
            layout.components[layout.count] = component;
            layout.count += 1;
        }
        let extra = cpuid(0xd, 1);
        layout.xss = extra.eax & XSAVES != 0;
        layout.xfd = extra.eax & XFD != 0;
        layout.abi = EntryAbi {
            image_bytes: rounded as u64,
            supported_mask: supported,
            xsave_available: 1,
            msr_flags: u64::from(layout.xss) | (u64::from(layout.xfd) << 1),
            entry_bytes: rounded.checked_add(ENTRY_METADATA_BYTES + IMAGE_ALIGNMENT - 1)
                .ok_or(LayoutError::ResourceLimit)? as u64,
        };
        Ok(layout)
    }

    fn format(&self, controls: Controls) -> Result<SaveFormat, LayoutError> {
        if controls.cr0 & CR0_FP_DISABLED != 0
            || controls.cr4 & CR4_FP_REQUIRED != CR4_FP_REQUIRED
            || controls.cr4 & CR4_CET != 0 || controls.efer & EFER_FAST_FXSR != 0
        {
            return Err(LayoutError::Controls);
        }
        if controls.xss.is_some_and(|value| value != 0) {
            return Err(LayoutError::SupervisorState);
        }
        if controls.xfd.is_some_and(|value| value != 0) {
            return Err(LayoutError::DynamicState);
        }
        if controls.cr4 & CR4_OSXSAVE == 0 {
            return Ok(SaveFormat::Fxsave);
        }
        if self.abi.xsave_available == 0 {
            return Err(LayoutError::Controls);
        }
        let mask = controls.xcr0.ok_or(LayoutError::Controls)?;
        if mask & X87 == 0 || mask & !self.abi.supported_mask != 0
            || mask & !ADMITTED_MASK != 0
            || mask & AVX != 0 && mask & SSE == 0
            || mask & MPX != 0 && mask & MPX != MPX
            || mask & AVX512 != 0 && (mask & AVX512 != AVX512 || mask & (SSE | AVX) != SSE | AVX)
        {
            return Err(LayoutError::Controls);
        }
        Ok(if mask & SSE == 0 { SaveFormat::XsaveLegacySse { mask } } else { SaveFormat::Xsave { mask } })
    }

    fn enabled_extent(&self, mask: u64) -> usize {
        self.components[..self.count].iter()
            .filter(|component| mask & (1u64 << component.bit) != 0)
            .map(|component| component.offset + component.bytes)
            .max().unwrap_or(EXTENDED_OFFSET)
    }
}

/// One actual physical CPU's descriptor-owned layout. Not Send/Sync; no safe
/// constructor accepts CPUID records, IDs, masks or caller-supplied booleans.
/// Retain it and every real IST allocation through the last possible entry,
/// including terminal NMI/MCE after Host state retirement.
#[derive(Debug)]
#[must_use = "retain the actual xstate owner with its descriptor and IST resources"]
pub(crate) struct XstateOwner {
    processor: u32,
    layout: Layout,
    _local: PhantomData<*mut ()>,
}

impl XstateOwner {
    /// # Safety
    /// The caller exclusively owns this actual processor and its pinned
    /// descriptor/IST resources, without migration through retirement. All
    /// relevant declarations/layouts remain stable under the same trusted
    /// firmware/VMM lifetime contract as NativeCpuOwner. No physical reset,
    /// resume, microcode or state reconfiguration may overlap an entry image.
    /// This capture changes no controls and cannot qualify the entry stub.
    #[cfg(target_arch = "x86_64")]
    pub(crate) unsafe fn capture() -> Result<Self, LayoutError> {
        privilege()?;
        let identity = cpuid(0, 0);
        if identity.eax < 1 { return Err(LayoutError::MissingCpuFeatures); }
        let features = cpuid(1, 0);
        if features.edx & FXSR_SSE_SSE2 != FXSR_SSE_SSE2 {
            return Err(LayoutError::MissingCpuFeatures);
        }
        qualify_error_pointers(identity)?;
        let processor = actual_processor()?;
        let layout = Layout::discover(identity.eax, features.ecx, cpuid)?;
        let controls = read_controls(&layout);
        if let SaveFormat::Xsave { mask } | SaveFormat::XsaveLegacySse { mask } = layout.format(controls)? {
            if (cpuid(0xd, 0).ebx as usize) < layout.enabled_extent(mask) {
                return Err(LayoutError::Geometry);
            }
        }
        Ok(Self { processor, layout, _local: PhantomData })
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub(crate) unsafe fn capture() -> Result<Self, LayoutError> { Err(LayoutError::UnsupportedHost) }

    pub(crate) fn abi(&self) -> &EntryAbi { &self.layout.abi }

    /// Validate actual controls before preparing an entry/transition. The
    /// assembly entry itself must independently use actual CR4/XCR0 before
    /// saving, without calling Rust first and clobbering interrupted state.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn check(&self) -> Result<SaveFormat, LayoutError> {
        privilege()?;
        if actual_processor()? != self.processor { return Err(LayoutError::ProcessorChanged); }
        self.layout.format(read_controls(&self.layout))
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub(crate) fn check(&self) -> Result<SaveFormat, LayoutError> { Err(LayoutError::UnsupportedHost) }

    /// Pure extent check only: numbers do not grant backing ownership. The
    /// descriptor installer must retain its actual pinned IST allocation and
    /// prove mapping/guard/stack budget across every real execution root.
    pub(crate) fn check_entry_extent(&self, frame: usize, stack_bottom: usize, stack_top: usize) -> Result<(), LayoutError> {
        let bytes = self.layout.abi.entry_bytes as usize;
        if stack_bottom >= stack_top || frame > stack_top
            || frame.checked_sub(bytes).is_none_or(|bottom| bottom < stack_bottom)
        {
            return Err(LayoutError::ImageExtent);
        }
        Ok(())
    }
}

#[cfg(target_arch = "x86_64")]
fn privilege() -> Result<(), LayoutError> {
    use core::arch::asm;
    let cs: u16;
    let flags: u64;
    // SAFETY: unprivileged observations precede every privileged access.
    unsafe {
        asm!("mov {0:x}, cs", out(reg) cs, options(nostack, preserves_flags));
        asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
    }
    if cs & 3 != 0 { return Err(LayoutError::Privilege); }
    if flags & (1 << 9) != 0 { return Err(LayoutError::InterruptsEnabled); }
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn cpuid(leaf: u32, subleaf: u32) -> Registers {
    let result = core::arch::x86_64::__cpuid_count(leaf, subleaf);
    Registers { eax: result.eax, ebx: result.ebx, ecx: result.ecx, edx: result.edx }
}

#[cfg(target_arch = "x86_64")]
fn msr(index: u32) -> u64 {
    let (low, high): (u32, u32);
    // SAFETY: internal callers have checked CPL0 and this exact MSR's
    // architectural enumeration; no caller-supplied index is exposed.
    unsafe { core::arch::asm!("rdmsr", in("ecx") index, out("eax") low, out("edx") high, options(nostack, preserves_flags)); }
    u64::from(low) | u64::from(high) << 32
}

#[cfg(target_arch = "x86_64")]
fn read_controls(layout: &Layout) -> Controls {
    let (cr0, cr4): (u64, u64);
    // SAFETY: internal caller performed the actual privilege/IF preflight.
    unsafe {
        core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nostack, preserves_flags));
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nostack, preserves_flags));
    }
    let xcr0 = if cr4 & CR4_OSXSAVE != 0 && layout.abi.xsave_available != 0 {
        let (low, high): (u32, u32);
        // SAFETY: actual XSAVE hardware and current CR4.OSXSAVE qualify ECX0.
        unsafe { core::arch::asm!("xgetbv", in("ecx") 0u32, out("eax") low, out("edx") high, options(nostack, preserves_flags)); }
        Some(u64::from(low) | u64::from(high) << 32)
    } else { None };
    Controls { cr0, cr4, efer: msr(EFER), xcr0,
        xss: layout.xss.then(|| msr(IA32_XSS)),
        xfd: layout.xfd.then(|| msr(IA32_XFD)),
    }
}

#[cfg(target_arch = "x86_64")]
fn qualify_error_pointers(identity: Registers) -> Result<(), LayoutError> {
    use stela_compiler::TargetCpu;
    let vendor = [identity.ebx, identity.edx, identity.ecx];
    const HYGON: [u32; 3] = [u32::from_le_bytes(*b"Hygo"), u32::from_le_bytes(*b"nGen"), u32::from_le_bytes(*b"uine")];
    if vendor == TargetCpu::INTEL_VENDOR { return Ok(()); }
    if matches!(vendor, TargetCpu::AMD_VENDOR | HYGON)
        && cpuid(0x8000_0000, 0).eax >= 0x8000_0008
        && cpuid(0x8000_0008, 0).ebx & SAVE_ERROR_POINTERS != 0
    { return Ok(()); }
    Err(LayoutError::ErrorPointers)
}

#[cfg(target_arch = "x86_64")]
fn actual_processor() -> Result<u32, LayoutError> {
    #[cfg(not(test))]
    use crate::native_smp::topology;
    #[cfg(test)]
    use crate::boot_native_topology as topology;
    let maximum = cpuid(0, 0).eax;
    let extended = cpuid(0x8000_0000, 0).eax;
    let mut snapshot = topology::Snapshot::default();
    for leaf in [0, 1, 0xb, 0x1f, 0x8000_0000, 0x8000_0001, 0x8000_001e] {
        if leaf > if leaf & 0x8000_0000 == 0 { maximum } else { extended } { continue; }
        let record = cpuid(leaf, 0);
        snapshot.records[snapshot.count as usize] = topology::Cpuid {
            leaf, subleaf: 0, eax: record.eax, ebx: record.ebx, ecx: record.ecx, edx: record.edx,
        };
        snapshot.count += 1;
    }
    snapshot.apic_id().ok_or(LayoutError::ProcessorChanged)
}

// Shared scalar-only boundary routines. Their raw buffer arguments are not
// authority: callers must retain the actual destination owner and real mapped
// private stack image through restoration or terminal abandonment. No Rust
// runs before saving. The routines preserve SysV callee-saved GPRs; FP state
// is deliberately handled by this explicit ABI, never by a Rust prologue.
#[cfg(all(target_arch = "x86_64", not(test)))]
core::arch::global_asm!(
    r#"
.global stela_xstate_save_owned
stela_xstate_save_owned:
    test rdi, 63
    jnz stela_xstate_boundary_refuse
    mov r11, gs:[{image_bytes}]
    cmp r11, 512
    jb stela_xstate_boundary_refuse
    cmp r11, {max_image_bytes}
    ja stela_xstate_boundary_refuse
    lea rax, [rdi + r11]
    cmp rsi, rax
    jne stela_xstate_boundary_refuse
    mov rax, cr0
    test rax, 12
    jnz stela_xstate_boundary_refuse
    mov rax, cr4
    mov r8, rax
    and eax, 1536
    cmp eax, 1536
    jne stela_xstate_boundary_refuse
    test r8, 8388608
    jnz stela_xstate_boundary_refuse
    mov ecx, 0xc0000080
    rdmsr
    test eax, 16384
    jnz stela_xstate_boundary_refuse
    test qword ptr gs:[{msr_flags}], 1
    jz stela_xstate_boundary_no_xss
    mov ecx, 0xda0
    rdmsr
    or eax, edx
    jnz stela_xstate_boundary_refuse
stela_xstate_boundary_no_xss:
    test qword ptr gs:[{msr_flags}], 2
    jz stela_xstate_boundary_no_xfd
    mov ecx, 0x1c4
    rdmsr
    or eax, edx
    jnz stela_xstate_boundary_refuse
stela_xstate_boundary_no_xfd:
    test r8, 262144
    jnz stela_xstate_boundary_save_extended
    mov qword ptr [rsi + {format}], {fxsave}
    mov qword ptr [rsi + {mask}], 0
    fxsave64 [rdi]
    ret
stela_xstate_boundary_save_extended:
    cmp qword ptr gs:[{available}], 1
    jne stela_xstate_boundary_refuse
    xor ecx, ecx
    xgetbv
    mov r9d, eax
    shl rdx, 32
    or r9, rdx
    test r9, 1
    jz stela_xstate_boundary_refuse
    mov rax, gs:[{supported_mask}]
    not rax
    test r9, rax
    jnz stela_xstate_boundary_refuse
    mov rax, {refused_mask}
    test r9, rax
    jnz stela_xstate_boundary_refuse
    mov [rsi + {mask}], r9
    mov qword ptr [rsi + {format}], {xsave}
    test r9, 2
    jnz stela_xstate_boundary_header
    fxsave64 [rdi]
    mov qword ptr [rsi + {format}], {xsave_legacy}
stela_xstate_boundary_header:
    xor eax, eax
    mov [rdi + {header} + 0], rax
    mov [rdi + {header} + 8], rax
    mov [rdi + {header} + 16], rax
    mov [rdi + {header} + 24], rax
    mov [rdi + {header} + 32], rax
    mov [rdi + {header} + 40], rax
    mov [rdi + {header} + 48], rax
    mov [rdi + {header} + 56], rax
    mov rax, r9
    mov rdx, r9
    shr rdx, 32
    xsave64 [rdi]
    ret

.global stela_xstate_restore_owned
stela_xstate_restore_owned:
    test rdi, 63
    jnz stela_xstate_boundary_refuse
    mov r11, gs:[{image_bytes}]
    cmp r11, 512
    jb stela_xstate_boundary_refuse
    cmp r11, {max_image_bytes}
    ja stela_xstate_boundary_refuse
    lea rax, [rdi + r11]
    cmp rsi, rax
    jne stela_xstate_boundary_refuse
    mov rax, cr0
    test rax, 12
    jnz stela_xstate_boundary_refuse
    mov rax, cr4
    mov r8, rax
    and eax, 1536
    cmp eax, 1536
    jne stela_xstate_boundary_refuse
    test r8, 8388608
    jnz stela_xstate_boundary_refuse
    mov ecx, 0xc0000080
    rdmsr
    test eax, 16384
    jnz stela_xstate_boundary_refuse
    test qword ptr gs:[{msr_flags}], 1
    jz stela_xstate_boundary_restore_no_xss
    mov ecx, 0xda0
    rdmsr
    or eax, edx
    jnz stela_xstate_boundary_refuse
stela_xstate_boundary_restore_no_xss:
    test qword ptr gs:[{msr_flags}], 2
    jz stela_xstate_boundary_restore_no_xfd
    mov ecx, 0x1c4
    rdmsr
    or eax, edx
    jnz stela_xstate_boundary_refuse
stela_xstate_boundary_restore_no_xfd:
    cmp qword ptr [rsi + {format}], {fxsave}
    je stela_xstate_boundary_restore_legacy
    test r8, 262144
    jz stela_xstate_boundary_refuse
    cmp qword ptr gs:[{available}], 1
    jne stela_xstate_boundary_refuse
    xor ecx, ecx
    xgetbv
    mov r9d, eax
    shl rdx, 32
    or r9, rdx
    cmp r9, [rsi + {mask}]
    jne stela_xstate_boundary_refuse
    cmp qword ptr [rsi + {format}], {xsave}
    je stela_xstate_boundary_sse_tag
    cmp qword ptr [rsi + {format}], {xsave_legacy}
    jne stela_xstate_boundary_refuse
    test r9, 2
    jnz stela_xstate_boundary_refuse
    jmp stela_xstate_boundary_restore_extended
stela_xstate_boundary_sse_tag:
    test r9, 2
    jz stela_xstate_boundary_refuse
stela_xstate_boundary_restore_extended:
    mov rax, r9
    mov rdx, r9
    shr rdx, 32
    xrstor64 [rdi]
    cmp qword ptr [rsi + {format}], {xsave_legacy}
    jne stela_xstate_boundary_restored
    fxrstor64 [rdi]
stela_xstate_boundary_restored:
    ret
stela_xstate_boundary_restore_legacy:
    test r8, 262144
    jnz stela_xstate_boundary_refuse
    cmp qword ptr [rsi + {mask}], 0
    jne stela_xstate_boundary_refuse
    fxrstor64 [rdi]
    ret
.global stela_xstate_boundary_refuse
stela_xstate_boundary_refuse:
    cli
stela_xstate_boundary_halt:
    hlt
    jmp stela_xstate_boundary_halt
"#,
    image_bytes = const super::host::local::XSTATE_IMAGE_BYTES_OFFSET,
    supported_mask = const super::host::local::XSTATE_SUPPORTED_MASK_OFFSET,
    available = const super::host::local::XSTATE_AVAILABLE_OFFSET,
    msr_flags = const super::host::local::XSTATE_MSR_FLAGS_OFFSET,
    max_image_bytes = const MAX_IMAGE_BYTES,
    refused_mask = const !ADMITTED_MASK,
    format = const ENTRY_FORMAT_OFFSET,
    mask = const ENTRY_MASK_OFFSET,
    header = const STANDARD_HEADER_OFFSET,
    fxsave = const FORMAT_FXSAVE,
    xsave = const FORMAT_XSAVE,
    xsave_legacy = const FORMAT_XSAVE_LEGACY_SSE,
);

#[cfg(all(target_arch = "x86_64", not(test)))]
unsafe extern "sysv64" {
    /// # Safety
    /// Current CPL0 pinned Local/owner, IF clear and actual mapped stack owns
    /// image plus adjacent metadata; retain both until restore or abandonment.
    pub(crate) fn stela_xstate_save_owned(image: *mut u8, metadata: *mut EntryMetadata);
    /// # Safety
    /// Exactly that still-owned image/metadata and unchanged actual destination
    /// contract. Cannot be a copied pointer or caller-synthesized format/mask.
    pub(crate) fn stela_xstate_restore_owned(image: *const u8, metadata: *const EntryMetadata);
    pub(crate) fn stela_xstate_boundary_refuse() -> !;
}

pub(crate) static DEFAULT_MXCSR: u32 = 0x1f80;

#[cfg(test)]
mod tests {
    use super::*;
    fn controls() -> Controls {
        Controls { cr0: 0, cr4: CR4_FP_REQUIRED, efer: 0, xcr0: None, xss: Some(0), xfd: Some(0) }
    }
    fn record(subleaf: u32) -> Registers {
        match subleaf {
            0 => Registers { eax: (X87 | SSE | AVX | AVX512) as u32, ebx: 576, ecx: 2688, ..Registers::default() },
            1 => Registers { eax: XSAVES | XFD, ..Registers::default() },
            2 => Registers { eax: 256, ebx: 576, ..Registers::default() },
            5 => Registers { eax: 64, ebx: 1088, ..Registers::default() },
            6 => Registers { eax: 512, ebx: 1152, ..Registers::default() },
            7 => Registers { eax: 1024, ebx: 1664, ..Registers::default() },
            _ => panic!("unselected component"),
        }
    }
    fn layout() -> Layout { Layout::discover(0xd, XSAVE, |leaf, subleaf| { assert_eq!(leaf, 0xd); record(subleaf) }).unwrap() }

    #[test]
    fn legacy_route_never_queries_xsave_or_requires_newer_cpu_state() {
        let layout = Layout::discover(1, 0, |_, _| panic!("legacy CPU has no leaf D")).unwrap();
        assert_eq!(layout.abi.image_bytes, LEGACY_BYTES as u64);
        assert_eq!(layout.format(controls()), Ok(SaveFormat::Fxsave));
        let mut active = controls(); active.cr4 |= CR4_OSXSAVE;
        assert_eq!(layout.format(active), Err(LayoutError::Controls));
        assert_eq!(Layout::discover(1, XSAVE, |_, _| panic!("invalid maximum")).unwrap_err(), LayoutError::MissingCpuFeatures);
    }

    #[test]
    fn standard_geometry_retains_every_supported_user_component_and_full_size() {
        let layout = layout();
        assert_eq!(layout.abi.image_bytes, 2688);
        assert_eq!(layout.abi.entry_bytes, 2688 + ENTRY_METADATA_BYTES as u64 + IMAGE_ALIGNMENT as u64 - 1);
        assert_eq!(layout.enabled_extent(X87 | SSE), 576);
        assert_eq!(layout.enabled_extent(X87 | SSE | AVX), 832);
        assert_eq!(layout.enabled_extent(X87 | SSE | AVX | AVX512), 2688);
        assert_eq!(layout.format(controls()), Ok(SaveFormat::Fxsave));
        for mask in [X87 | SSE, X87 | SSE | AVX, X87 | SSE | AVX | AVX512] {
            let mut actual = controls(); actual.cr4 |= CR4_OSXSAVE; actual.xcr0 = Some(mask);
            assert_eq!(layout.format(actual), Ok(SaveFormat::Xsave { mask }));
        }
    }

    #[test]
    fn osxsave_enable_boundary_retains_legacy_sse_without_manufacturing_xcr0() {
        let layout = layout();
        let mut actual = controls(); actual.cr4 |= CR4_OSXSAVE; actual.xcr0 = Some(X87);
        assert_eq!(layout.format(actual), Ok(SaveFormat::XsaveLegacySse { mask: X87 }));
        // The physical entry must execute FXSAVE before XSAVE(mask1), then
        // XRSTOR(mask1) before FXRSTOR. This pure selector is not that gate.
        assert_eq!(actual.xcr0, Some(X87));
    }

    #[test]
    fn incomplete_or_changed_live_controls_refuse_instead_of_truncating_state() {
        let layout = layout();
        for mask in [0, SSE, X87 | AVX, X87 | SSE | (1 << 5), X87 | SSE | AVX512, X87 | SSE | (1 << 9), X87 | SSE | MPX, X87 | SSE | (1 << 18)] {
            let mut actual = controls(); actual.cr4 |= CR4_OSXSAVE; actual.xcr0 = Some(mask);
            assert_eq!(layout.format(actual), Err(LayoutError::Controls));
        }
        let mut actual = controls(); actual.cr4 |= CR4_OSXSAVE;
        assert_eq!(layout.format(actual), Err(LayoutError::Controls));
        for disabled in [1 << 2, 1 << 3] {
            let mut actual = controls(); actual.cr0 |= disabled;
            assert_eq!(layout.format(actual), Err(LayoutError::Controls));
        }
        for required in [1 << 9, 1 << 10] {
            let mut actual = controls(); actual.cr4 &= !required;
            assert_eq!(layout.format(actual), Err(LayoutError::Controls));
        }
        let mut actual = controls(); actual.efer |= EFER_FAST_FXSR;
        assert_eq!(layout.format(actual), Err(LayoutError::Controls));
        let mut actual = controls(); actual.cr4 |= CR4_CET;
        assert_eq!(layout.format(actual), Err(LayoutError::Controls));
        let mut actual = controls(); actual.xss = Some(1 << 8);
        assert_eq!(layout.format(actual), Err(LayoutError::SupervisorState));
        let mut actual = controls(); actual.xfd = Some(1 << 18);
        assert_eq!(layout.format(actual), Err(LayoutError::DynamicState));
        let mut foreign = layout;
        foreign.abi.supported_mask |= MPX | (1 << 9) | (1 << 18);
        for mask in [X87 | SSE | MPX, X87 | SSE | (1 << 9), X87 | SSE | (1 << 18)] {
            let mut actual = controls(); actual.cr4 |= CR4_OSXSAVE; actual.xcr0 = Some(mask);
            assert_eq!(foreign.format(actual), Err(LayoutError::Controls));
        }
    }

    #[test]
    fn malformed_component_bounds_overlap_and_supervisor_records_refuse() {
        for (subleaf, replacement) in [
            (0, Registers { eax: 0, ..record(0) }),
            (0, Registers { edx: 1 << 31, ..record(0) }),
            (0, Registers { ebx: 2689, ..record(0) }),
            (0, Registers { ecx: 575, ..record(0) }),
            (2, Registers { eax: 0, ..record(2) }),
            (2, Registers { ebx: 512, ..record(2) }),
            (2, Registers { eax: u32::MAX, ..record(2) }),
            (2, Registers { ecx: 1, ..record(2) }),
            (5, Registers { ebx: 600, ..record(5) }),
        ] {
            let result = Layout::discover(0xd, XSAVE, |_, current| if current == subleaf { replacement } else { record(current) });
            assert_eq!(result.unwrap_err(), LayoutError::Geometry);
        }
        assert_eq!(Layout::discover(0xd, XSAVE, |_, current| if current == 0 { Registers { ecx: MAX_IMAGE_BYTES as u32 + 1, ..record(0) } } else { record(current) }).unwrap_err(), LayoutError::ResourceLimit);
    }

    #[test]
    fn each_entry_accounts_for_its_own_image_metadata_and_alignment_slop() {
        // Private layout/extent model only, not an actual CPU owner or save.
        let owner = XstateOwner { processor: 0, layout: layout(), _local: PhantomData };
        let bytes = owner.abi().entry_bytes as usize;
        assert_eq!(owner.check_entry_extent(bytes, 0, bytes), Ok(()));
        assert_eq!(owner.check_entry_extent(bytes - 1, 0, bytes), Err(LayoutError::ImageExtent));
        assert_eq!(owner.check_entry_extent(bytes, 1, bytes), Err(LayoutError::ImageExtent));
        assert_eq!(owner.check_entry_extent(0, 0, bytes), Err(LayoutError::ImageExtent));
        assert_eq!(owner.check_entry_extent(bytes + 1, 0, bytes), Err(LayoutError::ImageExtent));
        assert_eq!(owner.check_entry_extent(bytes, bytes, 0), Err(LayoutError::ImageExtent));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn actual_mask_one_interoperability_preserves_unrequested_legacy_sse() {
        let identity = cpuid(0, 0);
        if identity.eax < 0xd || cpuid(1, 0).ecx & (XSAVE | (1 << 27)) != XSAVE | (1 << 27)
            || qualify_error_pointers(identity).is_err()
        { return; }
        #[repr(C, align(64))]
        struct Image([u8; EXTENDED_OFFSET]);
        let (mut original, mut expected, mut image, mut restored) = (
            Image([0; EXTENDED_OFFSET]), Image([0; EXTENDED_OFFSET]),
            Image([0; EXTENDED_OFFSET]), Image([0; EXTENDED_OFFSET]),
        );
        let seed = [0x35u8; 16];
        let control = 0x3f80u32;
        let default_control = 0x1f80u32;
        // SAFETY: actual hosted OSXSAVE qualifies these instructions, mask1 is
        // always enabled x87, buffers are aligned/sized and header is zero.
        // The complete original legacy state is restored within this one asm
        // boundary. No privileged control changes or unsupported wider opcodes.
        // This exercises real mask1 overlap, not the native IRQ/control gate.
        unsafe {
            core::arch::asm!(
                "fxsave64 [{original}]",
                "fninit",
                "fld1",
                "movdqu xmm0, [{seed}]",
                "movdqu xmm15, [{seed}]",
                "ldmxcsr [{control}]",
                "fxsave64 [{expected}]",
                "fxsave64 [{image}]",
                "mov eax, 1",
                "xor edx, edx",
                "xsave64 [{image}]",
                "fninit",
                "fldz",
                "pxor xmm0, xmm0",
                "pxor xmm15, xmm15",
                "ldmxcsr [{default_control}]",
                "mov eax, 1",
                "xor edx, edx",
                "xrstor64 [{image}]",
                "fxrstor64 [{image}]",
                "fxsave64 [{restored}]",
                "fxrstor64 [{original}]",
                original = in(reg) original.0.as_mut_ptr(),
                expected = in(reg) expected.0.as_mut_ptr(),
                image = in(reg) image.0.as_mut_ptr(),
                restored = in(reg) restored.0.as_mut_ptr(),
                seed = in(reg) seed.as_ptr(),
                control = in(reg) &control,
                default_control = in(reg) &default_control,
                out("eax") _, out("edx") _, out("xmm0") _, out("xmm15") _,
            );
        }
        // Compare architectural fields only; FXSAVE reserved bytes are not a
        // register value. Padding within each 80-bit x87 slot is also reserved.
        assert_eq!(&expected.0[..5], &restored.0[..5]);
        assert_eq!(&expected.0[6..32], &restored.0[6..32]);
        for register in 0..8 {
            let offset = 32 + register * 16;
            assert_eq!(&expected.0[offset..offset + 10], &restored.0[offset..offset + 10]);
        }
        assert_eq!(&expected.0[160..416], &restored.0[160..416]);
    }

    #[test]
    fn hosted_capture_never_reads_privileged_registers() {
        // SAFETY: even on a hosted test process, capture's first preflight must
        // refuse CPL3 before CR/MSR/XGETBV. This establishes no native owner.
        let refused = unsafe { XstateOwner::capture() }.unwrap_err();
        #[cfg(target_arch = "x86_64")]
        assert_eq!(refused, LayoutError::Privilege);
        #[cfg(not(target_arch = "x86_64"))]
        assert_eq!(refused, LayoutError::UnsupportedHost);
    }
}
