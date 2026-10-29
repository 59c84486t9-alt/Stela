//! Extended-state geometry and control validation for the boot entry ABI.
mod image;
pub use image::{ImageError, ImageFormat};
pub const LEGACY_BYTES: usize = 512;
pub const STANDARD_HEADER_OFFSET: usize = LEGACY_BYTES;
pub const STANDARD_HEADER_BYTES: usize = 64;
pub const HEADER_BYTES: usize = STANDARD_HEADER_BYTES;
pub const EXTENDED_OFFSET: usize = LEGACY_BYTES + HEADER_BYTES;
pub const IMAGE_ALIGNMENT: usize = 64;
// Explicit descriptor/stack resource policy, not an architectural XSAVE limit.
pub const MAX_IMAGE_BYTES: usize = 16 * 1024;
pub const FORMAT_FXSAVE: u64 = 0;
pub const FORMAT_XSAVE: u64 = 1;
pub const FORMAT_XSAVE_LEGACY_SSE: u64 = 2;
#[repr(C)]
pub struct EntryMetadata {
    format: u64,
    mask: u64,
}
impl EntryMetadata {
    /// Decode only the tags emitted by the actual standard-save entry. This
    /// pure operation grants no CPU, stack or image ownership.
    pub fn save_format(&self) -> Option<SaveFormat> {
        match (self.format, self.mask) {
            (FORMAT_FXSAVE, 0) => Some(SaveFormat::Fxsave),
            (FORMAT_XSAVE, mask) if mask & (X87 | SSE) == X87 | SSE => {
                Some(SaveFormat::Xsave { mask })
            }
            (FORMAT_XSAVE_LEGACY_SSE, mask) if mask & X87 != 0 && mask & SSE == 0 => {
                Some(SaveFormat::XsaveLegacySse { mask })
            }
            _ => None,
        }
    }
}
pub const ENTRY_METADATA_BYTES: usize = core::mem::size_of::<EntryMetadata>();
pub const ENTRY_FORMAT_OFFSET: usize = core::mem::offset_of!(EntryMetadata, format);
pub const ENTRY_MASK_OFFSET: usize = core::mem::offset_of!(EntryMetadata, mask);
pub const X87: u64 = 1;
pub const SSE: u64 = 1 << 1;
pub const AVX: u64 = 1 << 2;
pub const APX: u64 = 1 << 19;
pub const MPX: u64 = (1 << 3) | (1 << 4);
// Geometry records all supported user components; this unit admits only the
// vector family whose handler environment is owned here. No PKRU/AMX policy.
pub const ADMITTED_MASK: u64 = X87 | SSE | AVX | AVX512;
pub const AVX512: u64 = (1 << 5) | (1 << 6) | (1 << 7);
pub const XSAVE: u32 = 1 << 26;
pub const XSAVES: u32 = 1 << 3;
pub const XFD: u32 = 1 << 4;
pub const CR0_FP_DISABLED: u64 = (1 << 2) | (1 << 3);
pub const CR4_FP_REQUIRED: u64 = (1 << 9) | (1 << 10);
pub const CR4_OSXSAVE: u64 = 1 << 18;
pub const CR4_CET: u64 = 1 << 23;
pub const FXSR_SSE_SSE2: u32 = (1 << 24) | (1 << 25) | (1 << 26);
pub const EFER_FAST_FXSR: u64 = 1 << 14;
pub const SAVE_ERROR_POINTERS: u32 = 1 << 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutError {
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
pub struct Registers {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

#[derive(Debug, Default, Clone, Copy)]
struct Component {
    bit: u8,
    offset: usize,
    bytes: usize,
    compact_alignment: bool,
}

/// Assembly metadata is installed only with its actual descriptor owner. A
/// copied number/ABI record is not a CPU, backing or entry authority.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EntryAbi {
    /// Rounded image capacity; includes standard header when XSAVE exists.
    pub image_bytes: u64,
    pub supported_mask: u64,
    pub xsave_available: u64,
    /// 1 when the controls `configure_xstate` qualified enable XSAVE
    /// (CR4.OSXSAVE). Entries use these qualified controls, which stay fixed
    /// for the owner's lifetime, instead of reading CR0, CR4, EFER, IA32_XSS
    /// and IA32_XFD again: under a hypervisor each read is a VM exit, and
    /// every native block entry and return crosses this boundary.
    pub extended: u64,
    /// Space from the original frame needed for image, saved format/mask and
    /// worst-case downward alignment. The original Frame remains untouched.
    pub entry_bytes: u64,
}

impl EntryAbi {
    /// Private descriptor initialization only; never a usable save contract.
    pub const EMPTY: Self = Self {
        image_bytes: 0,
        supported_mask: 0,
        xsave_available: 0,
        extended: 0,
        entry_bytes: 0,
    };
}

#[derive(Debug)]
pub struct Layout {
    pub abi: EntryAbi,
    components: [Component; 62],
    count: usize,
    pub xss: bool,
    pub xfd: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaveFormat {
    Fxsave,
    Xsave {
        mask: u64,
    },
    /// XCR0.SSE does not disable legacy SSE execution. Preserve the shared
    /// legacy region with FXSAVE before XSAVE, then restore it after XRSTOR.
    XsaveLegacySse {
        mask: u64,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct Controls {
    pub cr0: u64,
    pub cr4: u64,
    pub efer: u64,
    pub xcr0: Option<u64>,
    pub xss: Option<u64>,
    pub xfd: Option<u64>,
}

impl Layout {
    pub fn discover(
        maximum: u32,
        leaf1_ecx: u32,
        mut cpuid: impl FnMut(u32, u32) -> Registers,
    ) -> Result<Self, LayoutError> {
        let mut layout = Self {
            abi: EntryAbi {
                image_bytes: LEGACY_BYTES as u64,
                supported_mask: X87 | SSE,
                xsave_available: 0,
                extended: 0,
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
        if capacity < EXTENDED_OFFSET
            || base.ebx as usize > capacity
            || (base.ebx as usize) < EXTENDED_OFFSET
        {
            return Err(LayoutError::Geometry);
        }
        let rounded = capacity
            .checked_add(IMAGE_ALIGNMENT - 1)
            .ok_or(LayoutError::ResourceLimit)?
            & !(IMAGE_ALIGNMENT - 1);
        if rounded > MAX_IMAGE_BYTES {
            return Err(LayoutError::ResourceLimit);
        }
        for bit in 2..63 {
            if supported & (1u64 << bit) == 0 {
                continue;
            }
            let record = cpuid(0xd, bit);
            let component = Component {
                bit: bit as u8,
                offset: record.ebx as usize,
                bytes: record.eax as usize,
                compact_alignment: record.ecx & 2 != 0,
            };
            let end = component
                .offset
                .checked_add(component.bytes)
                .ok_or(LayoutError::Geometry)?;
            if component.bytes == 0
                || component.offset < EXTENDED_OFFSET
                || end > capacity
                || record.ecx & 1 != 0
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
            extended: 0,
            entry_bytes: rounded
                .checked_add(ENTRY_METADATA_BYTES + IMAGE_ALIGNMENT - 1)
                .ok_or(LayoutError::ResourceLimit)? as u64,
        };
        Ok(layout)
    }

    pub fn format(&self, controls: Controls) -> Result<SaveFormat, LayoutError> {
        if controls.cr0 & CR0_FP_DISABLED != 0
            || controls.cr4 & CR4_FP_REQUIRED != CR4_FP_REQUIRED
            || controls.cr4 & CR4_CET != 0
            || controls.efer & EFER_FAST_FXSR != 0
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
        if mask & X87 == 0
            || mask & !self.abi.supported_mask != 0
            || mask & !ADMITTED_MASK != 0
            || mask & AVX != 0 && mask & SSE == 0
            || mask & MPX != 0 && mask & MPX != MPX
            || mask & AVX512 != 0 && (mask & AVX512 != AVX512 || mask & (SSE | AVX) != SSE | AVX)
        {
            return Err(LayoutError::Controls);
        }
        Ok(if mask & SSE == 0 {
            SaveFormat::XsaveLegacySse { mask }
        } else {
            SaveFormat::Xsave { mask }
        })
    }

    pub fn enabled_extent(&self, mask: u64) -> usize {
        self.components[..self.count]
            .iter()
            .filter(|component| mask & (1u64 << component.bit) != 0)
            .map(|component| component.offset + component.bytes)
            .max()
            .unwrap_or(EXTENDED_OFFSET)
    }
}

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
    pub(super) fn record(subleaf: u32) -> Registers {
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
    fn legacy_route_never_queries_xsave_or_requires_newer_cpu_state() {
        let layout = Layout::discover(1, 0, |_, _| panic!("legacy CPU has no leaf D")).unwrap();
        assert_eq!(layout.abi.image_bytes, LEGACY_BYTES as u64);
        assert_eq!(layout.format(controls()), Ok(SaveFormat::Fxsave));
        let mut active = controls();
        active.cr4 |= CR4_OSXSAVE;
        assert_eq!(layout.format(active), Err(LayoutError::Controls));
        assert_eq!(
            Layout::discover(1, XSAVE, |_, _| panic!("invalid maximum")).unwrap_err(),
            LayoutError::MissingCpuFeatures
        );
    }

    #[test]
    fn standard_geometry_retains_every_supported_user_component_and_full_size() {
        let layout = layout();
        assert_eq!(layout.abi.image_bytes, 2688);
        assert_eq!(
            layout.abi.entry_bytes,
            2688 + ENTRY_METADATA_BYTES as u64 + IMAGE_ALIGNMENT as u64 - 1
        );
        assert_eq!(layout.enabled_extent(X87 | SSE), 576);
        assert_eq!(layout.enabled_extent(X87 | SSE | AVX), 832);
        assert_eq!(layout.enabled_extent(X87 | SSE | AVX | AVX512), 2688);
        assert_eq!(layout.format(controls()), Ok(SaveFormat::Fxsave));
        for mask in [X87 | SSE, X87 | SSE | AVX, X87 | SSE | AVX | AVX512] {
            let mut actual = controls();
            actual.cr4 |= CR4_OSXSAVE;
            actual.xcr0 = Some(mask);
            assert_eq!(layout.format(actual), Ok(SaveFormat::Xsave { mask }));
        }
    }

    #[test]
    fn osxsave_enable_boundary_retains_legacy_sse_without_manufacturing_xcr0() {
        let layout = layout();
        let mut actual = controls();
        actual.cr4 |= CR4_OSXSAVE;
        actual.xcr0 = Some(X87);
        assert_eq!(
            layout.format(actual),
            Ok(SaveFormat::XsaveLegacySse { mask: X87 })
        );
        // The physical entry must execute FXSAVE before XSAVE(mask1), then
        // XRSTOR(mask1) before FXRSTOR. This pure selector is not that gate.
        assert_eq!(actual.xcr0, Some(X87));
    }

    #[test]
    fn incomplete_or_changed_live_controls_refuse_instead_of_truncating_state() {
        let layout = layout();
        for mask in [
            0,
            SSE,
            X87 | AVX,
            X87 | SSE | (1 << 5),
            X87 | SSE | AVX512,
            X87 | SSE | (1 << 9),
            X87 | SSE | MPX,
            X87 | SSE | (1 << 18),
        ] {
            let mut actual = controls();
            actual.cr4 |= CR4_OSXSAVE;
            actual.xcr0 = Some(mask);
            assert_eq!(layout.format(actual), Err(LayoutError::Controls));
        }
        let mut actual = controls();
        actual.cr4 |= CR4_OSXSAVE;
        assert_eq!(layout.format(actual), Err(LayoutError::Controls));
        for disabled in [1 << 2, 1 << 3] {
            let mut actual = controls();
            actual.cr0 |= disabled;
            assert_eq!(layout.format(actual), Err(LayoutError::Controls));
        }
        for required in [1 << 9, 1 << 10] {
            let mut actual = controls();
            actual.cr4 &= !required;
            assert_eq!(layout.format(actual), Err(LayoutError::Controls));
        }
        let mut actual = controls();
        actual.efer |= EFER_FAST_FXSR;
        assert_eq!(layout.format(actual), Err(LayoutError::Controls));
        let mut actual = controls();
        actual.cr4 |= CR4_CET;
        assert_eq!(layout.format(actual), Err(LayoutError::Controls));
        let mut actual = controls();
        actual.xss = Some(1 << 8);
        assert_eq!(layout.format(actual), Err(LayoutError::SupervisorState));
        let mut actual = controls();
        actual.xfd = Some(1 << 18);
        assert_eq!(layout.format(actual), Err(LayoutError::DynamicState));
        let mut foreign = layout;
        foreign.abi.supported_mask |= MPX | (1 << 9) | (1 << 18);
        for mask in [X87 | SSE | MPX, X87 | SSE | (1 << 9), X87 | SSE | (1 << 18)] {
            let mut actual = controls();
            actual.cr4 |= CR4_OSXSAVE;
            actual.xcr0 = Some(mask);
            assert_eq!(foreign.format(actual), Err(LayoutError::Controls));
        }
    }

    #[test]
    fn malformed_component_bounds_overlap_and_supervisor_records_refuse() {
        for (subleaf, replacement) in [
            (
                0,
                Registers {
                    eax: 0,
                    ..record(0)
                },
            ),
            (
                0,
                Registers {
                    edx: 1 << 31,
                    ..record(0)
                },
            ),
            (
                0,
                Registers {
                    ebx: 2689,
                    ..record(0)
                },
            ),
            (
                0,
                Registers {
                    ecx: 575,
                    ..record(0)
                },
            ),
            (
                2,
                Registers {
                    eax: 0,
                    ..record(2)
                },
            ),
            (
                2,
                Registers {
                    ebx: 512,
                    ..record(2)
                },
            ),
            (
                2,
                Registers {
                    eax: u32::MAX,
                    ..record(2)
                },
            ),
            (
                2,
                Registers {
                    ecx: 1,
                    ..record(2)
                },
            ),
            (
                5,
                Registers {
                    ebx: 600,
                    ..record(5)
                },
            ),
        ] {
            let result = Layout::discover(0xd, XSAVE, |_, current| {
                if current == subleaf {
                    replacement
                } else {
                    record(current)
                }
            });
            assert_eq!(result.unwrap_err(), LayoutError::Geometry);
        }
        assert_eq!(
            Layout::discover(0xd, XSAVE, |_, current| if current == 0 {
                Registers {
                    ecx: MAX_IMAGE_BYTES as u32 + 1,
                    ..record(0)
                }
            } else {
                record(current)
            })
            .unwrap_err(),
            LayoutError::ResourceLimit
        );
    }
}

#[cfg(test)]
mod metadata_tests {
    use super::*;
    #[test]
    fn saved_metadata_tags_keep_legacy_and_extended_images_distinct() {
        assert_eq!(
            EntryMetadata {
                format: FORMAT_FXSAVE,
                mask: 0
            }
            .save_format(),
            Some(SaveFormat::Fxsave)
        );
        assert_eq!(
            EntryMetadata {
                format: FORMAT_XSAVE,
                mask: X87 | SSE | AVX
            }
            .save_format(),
            Some(SaveFormat::Xsave {
                mask: X87 | SSE | AVX
            })
        );
        assert_eq!(
            EntryMetadata {
                format: FORMAT_XSAVE_LEGACY_SSE,
                mask: X87
            }
            .save_format(),
            Some(SaveFormat::XsaveLegacySse { mask: X87 })
        );
        for (format, mask) in [
            (FORMAT_FXSAVE, X87),
            (FORMAT_XSAVE, X87),
            (FORMAT_XSAVE_LEGACY_SSE, X87 | SSE),
            (FORMAT_XSAVE, 0),
            (3, X87 | SSE),
        ] {
            assert_eq!(EntryMetadata { format, mask }.save_format(), None);
        }
    }
}
