//! A CPU's captured extended-state layout and the controls it was captured
//! under. Capture and checks need CPL0 with interrupts masked.
use super::*;
#[cfg(target_arch = "x86_64")]
use crate::msr;
use core::marker::PhantomData;

/// One physical CPU's descriptor-owned layout. Not Send/Sync; no safe
/// constructor accepts CPUID records, IDs, masks or caller-supplied booleans.
/// Keep it and every real IST allocation through the last possible entry,
/// including terminal NMI/MCE after Host state retirement.
#[derive(Debug)]
#[must_use = "retain the actual xstate owner with its descriptor and IST resources"]
pub struct XstateOwner {
    processor: u32,
    layout: Layout,
    _local: PhantomData<*mut ()>,
}

impl XstateOwner {
    /// # Safety
    /// The caller exclusively owns this processor and its pinned
    /// descriptor/IST resources, without migration through retirement. All
    /// relevant declarations/layouts remain stable under the same trusted
    /// firmware/VMM lifetime contract as NativeCpuOwner. No physical reset,
    /// resume, microcode or state reconfiguration may overlap an entry image.
    /// This capture changes no controls and cannot check the entry stub.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn capture() -> Result<Self, LayoutError> {
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
    pub unsafe fn capture() -> Result<Self, LayoutError> {
        Err(LayoutError::UnsupportedHost)
    }

    pub fn extended_gprs(&self, image: &[u8], mask: u64) -> Result<Option<[u64; 16]>, ImageError> {
        self.layout
            .extended_gprs(image, mask, ImageFormat::Standard)
    }

    pub fn abi(&self) -> &EntryAbi {
        &self.layout.abi
    }

    /// Validate controls before preparing an entry/transition. The
    /// assembly entries use the controls this checked at configuration
    /// ([`EntryAbi::extended`]) and the XCR0, without calling Rust
    /// first and clobbering interrupted state.
    #[cfg(target_arch = "x86_64")]
    pub fn check(&self) -> Result<SaveFormat, LayoutError> {
        privilege()?;
        if actual_processor()? != self.processor {
            return Err(LayoutError::ProcessorChanged);
        }
        self.layout.format(read_controls(&self.layout))
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn check(&self) -> Result<SaveFormat, LayoutError> {
        Err(LayoutError::UnsupportedHost)
    }

    /// Pure extent check only: numbers do not grant backing ownership. The
    /// descriptor installer must keep its pinned IST allocation and
    /// prove mapping/guard/stack budget across every real execution root.
    pub fn check_entry_extent(
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
    // SAFETY: internal caller performed the privilege/IF preflight.
    unsafe {
        core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nostack, preserves_flags));
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nostack, preserves_flags));
    }
    let xcr0 = if cr4 & CR4_OSXSAVE != 0 && layout.abi.xsave_available != 0 {
        let (low, high): (u32, u32);
        // SAFETY: XSAVE hardware and current CR4.OSXSAVE check ECX0.
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
    use crate::topology;
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

#[cfg(test)]
mod tests {
    use super::*;
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
        // Private layout/extent model only, not a CPU owner or save.
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
    fn mask_one_interoperability_preserves_unrequested_legacy_sse() {
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
        // SAFETY: hosted OSXSAVE checks these instructions, mask1 is
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
