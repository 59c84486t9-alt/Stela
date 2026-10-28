//! Destination-local extended-state geometry and descriptor lifetime.
//!
//! This unit enables no processor feature and admits no compiler target. The
//! real entry stub must save the whole actual enabled state before Rust runs.
//! Standard XSAVE64/XRSTOR64 only; every entry owns a separate IST image.
#[cfg(all(test, target_arch = "x86_64"))]
use crate::boot_msr as msr;
#[cfg(all(not(test), target_arch = "x86_64"))]
use crate::cpu::msr;
use core::marker::PhantomData;

pub(crate) use stela_boot_core::xstate::*;

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
        if identity.eax < 1 {
            return Err(LayoutError::MissingCpuFeatures);
        }
        let features = cpuid(1, 0);
        if features.edx & FXSR_SSE_SSE2 != FXSR_SSE_SSE2 {
            return Err(LayoutError::MissingCpuFeatures);
        }
        qualify_error_pointers(identity)?;
        let processor = actual_processor()?;
        let layout = Layout::discover(identity.eax, features.ecx, cpuid)?;
        let controls = read_controls(&layout);
        if let SaveFormat::Xsave { mask } | SaveFormat::XsaveLegacySse { mask } =
            layout.format(controls)?
            && (cpuid(0xd, 0).ebx as usize) < layout.enabled_extent(mask)
        {
            return Err(LayoutError::Geometry);
        }
        Ok(Self {
            processor,
            layout,
            _local: PhantomData,
        })
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub(crate) unsafe fn capture() -> Result<Self, LayoutError> {
        Err(LayoutError::UnsupportedHost)
    }

    pub(crate) fn abi(&self) -> &EntryAbi {
        &self.layout.abi
    }

    /// Validate actual controls before preparing an entry/transition. The
    /// assembly entries use the controls this qualified at configuration
    /// ([`EntryAbi::extended`]) and the actual XCR0, without calling Rust
    /// first and clobbering interrupted state.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn check(&self) -> Result<SaveFormat, LayoutError> {
        privilege()?;
        if actual_processor()? != self.processor {
            return Err(LayoutError::ProcessorChanged);
        }
        self.layout.format(read_controls(&self.layout))
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub(crate) fn check(&self) -> Result<SaveFormat, LayoutError> {
        Err(LayoutError::UnsupportedHost)
    }

    /// Pure extent check only: numbers do not grant backing ownership. The
    /// descriptor installer must retain its actual pinned IST allocation and
    /// prove mapping/guard/stack budget across every real execution root.
    pub(crate) fn check_entry_extent(
        &self,
        frame: usize,
        stack_bottom: usize,
        stack_top: usize,
    ) -> Result<(), LayoutError> {
        let bytes = self.layout.abi.entry_bytes as usize;
        if stack_bottom >= stack_top
            || frame > stack_top
            || frame
                .checked_sub(bytes)
                .is_none_or(|bottom| bottom < stack_bottom)
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
    if cs & 3 != 0 {
        return Err(LayoutError::Privilege);
    }
    if flags & (1 << 9) != 0 {
        return Err(LayoutError::InterruptsEnabled);
    }
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn cpuid(leaf: u32, subleaf: u32) -> Registers {
    let result = core::arch::x86_64::__cpuid_count(leaf, subleaf);
    Registers {
        eax: result.eax,
        ebx: result.ebx,
        ecx: result.ecx,
        edx: result.edx,
    }
}

#[cfg(target_arch = "x86_64")]
fn msr(register: msr::Msr) -> u64 {
    // SAFETY: internal callers have checked CPL0 and this register's
    // architectural enumeration; no caller-supplied index is exposed.
    unsafe { register.read() }
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
        unsafe {
            core::arch::asm!("xgetbv", in("ecx") 0u32, out("eax") low, out("edx") high, options(nostack, preserves_flags));
        }
        Some(u64::from(low) | u64::from(high) << 32)
    } else {
        None
    };
    Controls {
        cr0,
        cr4,
        efer: msr(msr::EFER),
        xcr0,
        xss: layout.xss.then(|| msr(msr::XSS)),
        xfd: layout.xfd.then(|| msr(msr::XFD)),
    }
}

#[cfg(target_arch = "x86_64")]
fn qualify_error_pointers(identity: Registers) -> Result<(), LayoutError> {
    use stela_compiler::TargetCpu;
    let vendor = [identity.ebx, identity.edx, identity.ecx];
    const HYGON: [u32; 3] = [
        u32::from_le_bytes(*b"Hygo"),
        u32::from_le_bytes(*b"nGen"),
        u32::from_le_bytes(*b"uine"),
    ];
    if vendor == TargetCpu::INTEL_VENDOR {
        return Ok(());
    }
    if matches!(vendor, TargetCpu::AMD_VENDOR | HYGON)
        && cpuid(0x8000_0000, 0).eax >= 0x8000_0008
        && cpuid(0x8000_0008, 0).ebx & SAVE_ERROR_POINTERS != 0
    {
        return Ok(());
    }
    Err(LayoutError::ErrorPointers)
}

#[cfg(target_arch = "x86_64")]
fn actual_processor() -> Result<u32, LayoutError> {
    use stela_boot_core::topology;
    let maximum = cpuid(0, 0).eax;
    let extended = cpuid(0x8000_0000, 0).eax;
    let mut snapshot = topology::Snapshot::default();
    for leaf in [0, 1, 0xb, 0x1f, 0x8000_0000, 0x8000_0001, 0x8000_001e] {
        if leaf
            > if leaf & 0x8000_0000 == 0 {
                maximum
            } else {
                extended
            }
        {
            continue;
        }
        let record = cpuid(leaf, 0);
        snapshot.records[snapshot.count as usize] = topology::Cpuid {
            leaf,
            subleaf: 0,
            eax: record.eax,
            ebx: record.ebx,
            ecx: record.ecx,
            edx: record.edx,
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
    cmp qword ptr gs:[{extended}], 0
    jne stela_xstate_boundary_save_extended
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
    cmp qword ptr [rsi + {format}], {fxsave}
    je stela_xstate_boundary_restore_legacy
    cmp qword ptr gs:[{extended}], 0
    je stela_xstate_boundary_refuse
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
    cmp qword ptr gs:[{extended}], 0
    jne stela_xstate_boundary_refuse
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
    extended = const super::host::local::XSTATE_EXTENDED_OFFSET,
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
        Controls {
            cr0: 0,
            cr4: CR4_FP_REQUIRED,
            efer: 0,
            xcr0: None,
            xss: Some(0),
            xfd: Some(0),
        }
    }
    fn record(subleaf: u32) -> Registers {
        match subleaf {
            0 => Registers {
                eax: (X87 | SSE | AVX | AVX512) as u32,
                ebx: 576,
                ecx: 2688,
                ..Registers::default()
            },
            1 => Registers {
                eax: XSAVES | XFD,
                ..Registers::default()
            },
            2 => Registers {
                eax: 256,
                ebx: 576,
                ..Registers::default()
            },
            5 => Registers {
                eax: 64,
                ebx: 1088,
                ..Registers::default()
            },
            6 => Registers {
                eax: 512,
                ebx: 1152,
                ..Registers::default()
            },
            7 => Registers {
                eax: 1024,
                ebx: 1664,
                ..Registers::default()
            },
            _ => panic!("unselected component"),
        }
    }
    fn layout() -> Layout {
        Layout::discover(0xd, XSAVE, |leaf, subleaf| {
            assert_eq!(leaf, 0xd);
            record(subleaf)
        })
        .unwrap()
    }

    #[test]
    fn each_entry_accounts_for_its_own_image_metadata_and_alignment_slop() {
        // Private layout/extent model only, not an actual CPU owner or save.
        let owner = XstateOwner {
            processor: 0,
            layout: layout(),
            _local: PhantomData,
        };
        let bytes = owner.abi().entry_bytes as usize;
        assert_eq!(owner.check_entry_extent(bytes, 0, bytes), Ok(()));
        assert_eq!(
            owner.check_entry_extent(bytes - 1, 0, bytes),
            Err(LayoutError::ImageExtent)
        );
        assert_eq!(
            owner.check_entry_extent(bytes, 1, bytes),
            Err(LayoutError::ImageExtent)
        );
        assert_eq!(
            owner.check_entry_extent(0, 0, bytes),
            Err(LayoutError::ImageExtent)
        );
        assert_eq!(
            owner.check_entry_extent(bytes + 1, 0, bytes),
            Err(LayoutError::ImageExtent)
        );
        assert_eq!(
            owner.check_entry_extent(bytes, bytes, 0),
            Err(LayoutError::ImageExtent)
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn actual_mask_one_interoperability_preserves_unrequested_legacy_sse() {
        let identity = cpuid(0, 0);
        if identity.eax < 0xd
            || cpuid(1, 0).ecx & (XSAVE | (1 << 27)) != XSAVE | (1 << 27)
            || qualify_error_pointers(identity).is_err()
        {
            return;
        }
        #[repr(C, align(64))]
        struct Image([u8; EXTENDED_OFFSET]);
        let (mut original, mut expected, mut image, mut restored) = (
            Image([0; EXTENDED_OFFSET]),
            Image([0; EXTENDED_OFFSET]),
            Image([0; EXTENDED_OFFSET]),
            Image([0; EXTENDED_OFFSET]),
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
            assert_eq!(
                &expected.0[offset..offset + 10],
                &restored.0[offset..offset + 10]
            );
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
