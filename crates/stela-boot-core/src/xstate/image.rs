//! Pure interpretation of a kept, source-checked XSAVE image.
use super::*;
use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFormat {
    Standard,
    Compacted,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageError {
    Header,
    Mask {
        enabled: u64,
        supported: u64,
        present: u64,
    },
    Format {
        expected: ImageFormat,
        xcomp_bv: u64,
    },
    Component {
        bit: u8,
        bytes: usize,
    },
    Extent {
        required: usize,
        available: usize,
    },
}
impl fmt::Display for ImageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Header => f.write_str("XSAVE image has an incomplete or reserved header"),
            Self::Mask {
                enabled,
                supported,
                present,
            } => write!(
                f,
                "XSAVE image masks differ: enabled={enabled:#x}, supported={supported:#x}, present={present:#x}"
            ),
            Self::Format { expected, xcomp_bv } => write!(
                f,
                "XSAVE image format differs from {expected:?}: XCOMP_BV={xcomp_bv:#x}"
            ),
            Self::Component { bit, bytes } => {
                write!(f, "XSAVE component {bit} has invalid extent {bytes}")
            }
            Self::Extent {
                required,
                available,
            } => write!(f, "XSAVE image needs {required} bytes, owns {available}"),
        }
    }
}
impl core::error::Error for ImageError {}
impl Layout {
    /// Interpret R16..R31 only when component19 is enabled in this checked
    /// layout. No CPU admission, backing ownership or capture permission follows
    /// from parsing bytes. The entry owner must supply the exact saved
    /// mask/format and keep the complete image through this operation.
    ///
    /// A disabled bank is unavailable. An enabled bank whose XSTATE_BV bit is
    /// clear is architecturally initial zero, regardless of stale payload bytes.
    pub fn extended_gprs(
        &self,
        image: &[u8],
        enabled: u64,
        format: ImageFormat,
    ) -> Result<Option<[u64; 16]>, ImageError> {
        if enabled & APX == 0 {
            return Ok(None);
        }
        let header = image
            .get(STANDARD_HEADER_OFFSET..EXTENDED_OFFSET)
            .ok_or(ImageError::Header)?;
        let present = u64::from_le_bytes(header[..8].try_into().map_err(|_| ImageError::Header)?);
        let xcomp = u64::from_le_bytes(header[8..16].try_into().map_err(|_| ImageError::Header)?);
        if enabled & !self.abi.supported_mask != 0 || present & !enabled != 0 {
            return Err(ImageError::Mask {
                enabled,
                supported: self.abi.supported_mask,
                present,
            });
        }
        if header[16..].iter().any(|byte| *byte != 0) {
            return Err(ImageError::Header);
        }
        let compacted = xcomp & (1 << 63) != 0;
        if matches!(format, ImageFormat::Standard) && xcomp != 0
            || matches!(format, ImageFormat::Compacted)
                && (!compacted || xcomp & !(1 << 63) != enabled)
        {
            return Err(ImageError::Format {
                expected: format,
                xcomp_bv: xcomp,
            });
        }
        let component = self.components[..self.count]
            .iter()
            .find(|component| component.bit == 19)
            .ok_or(ImageError::Component { bit: 19, bytes: 0 })?;
        if component.bytes != 16 * 8 {
            return Err(ImageError::Component {
                bit: 19,
                bytes: component.bytes,
            });
        }
        let offset = if compacted {
            let mut offset = EXTENDED_OFFSET;
            for bit in 2..=19 {
                if enabled & (1 << bit) == 0 {
                    continue;
                }
                let part = self.components[..self.count]
                    .iter()
                    .find(|part| part.bit == bit)
                    .ok_or(ImageError::Component { bit, bytes: 0 })?;
                if part.compact_alignment {
                    offset = offset.checked_add(63).ok_or(ImageError::Extent {
                        required: usize::MAX,
                        available: image.len(),
                    })? & !63;
                }
                if bit == 19 {
                    break;
                }
                offset = offset.checked_add(part.bytes).ok_or(ImageError::Extent {
                    required: usize::MAX,
                    available: image.len(),
                })?;
            }
            offset
        } else {
            component.offset
        };
        let end = offset
            .checked_add(component.bytes)
            .ok_or(ImageError::Extent {
                required: usize::MAX,
                available: image.len(),
            })?;
        let bytes = image.get(offset..end).ok_or(ImageError::Extent {
            required: end,
            available: image.len(),
        })?;
        if present & APX == 0 {
            return Ok(Some([0; 16]));
        }
        let mut registers = [0; 16];
        for (register, bytes) in registers.iter_mut().zip(bytes.as_chunks::<8>().0) {
            *register = u64::from_le_bytes(*bytes);
        }
        Ok(Some(registers))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn discovered_layout() -> Layout {
        Layout::discover(0xd, XSAVE, |leaf, sub| {
            assert_eq!(leaf, 0xd);
            if sub == 0 {
                let mut record = super::super::tests::record(sub);
                record.eax |= APX as u32;
                record
            } else if sub == 19 {
                Registers {
                    eax: 128,
                    ebx: 960,
                    ecx: 2,
                    ..Default::default()
                }
            } else {
                super::super::tests::record(sub)
            }
        })
        .unwrap()
    }
    fn make_image(mask: u64, format: ImageFormat) -> alloc::vec::Vec<u8> {
        let mut image = alloc::vec![0;2688];
        image[512..520].copy_from_slice(&mask.to_le_bytes());
        if format == ImageFormat::Compacted {
            image[520..528].copy_from_slice(&(mask | 1 << 63).to_le_bytes());
        }
        image
    }
    #[test]
    fn standard_and_compacted_banks_follow_actual_component_geometry() {
        let layout = discovered_layout();
        let mask = X87 | SSE | AVX | AVX512 | APX;
        for (format, offset) in [(ImageFormat::Standard, 960), (ImageFormat::Compacted, 2432)] {
            let mut image = make_image(mask, format);
            for index in 0..16 {
                image[offset + index * 8..offset + (index + 1) * 8]
                    .copy_from_slice(&(0x1000 + index as u64).to_le_bytes());
            }
            assert_eq!(
                layout.extended_gprs(&image, mask, format).unwrap(),
                Some(core::array::from_fn(|i| 0x1000 + i as u64))
            );
        }
    }
    #[test]
    fn qualified_init_bank_is_zero_but_a_disabled_bank_is_unavailable() {
        let layout = discovered_layout();
        let mask = X87 | SSE | APX;
        let mut image = make_image(mask, ImageFormat::Standard);
        image[960..1088].fill(0x7e);
        image[512..520].copy_from_slice(&(X87 | SSE).to_le_bytes());
        assert_eq!(
            layout
                .extended_gprs(&image, mask, ImageFormat::Standard)
                .unwrap(),
            Some([0; 16])
        );
        assert_eq!(
            layout.extended_gprs(&[], X87 | SSE, ImageFormat::Standard),
            Ok(None)
        );
    }
    #[test]
    fn malformed_format_header_mask_or_extent_cannot_publish_a_bank() {
        let layout = discovered_layout();
        let mask = X87 | SSE | APX;
        let image = make_image(mask, ImageFormat::Standard);
        assert!(matches!(
            layout.extended_gprs(&image[..1024], mask, ImageFormat::Standard),
            Err(ImageError::Extent { .. })
        ));
        let mut reserved = image.clone();
        reserved[528] = 1;
        assert_eq!(
            layout.extended_gprs(&reserved, mask, ImageFormat::Standard),
            Err(ImageError::Header)
        );
        let mut unsupported = image.clone();
        unsupported[512..520].copy_from_slice(&(mask | 1 << 18).to_le_bytes());
        assert!(matches!(
            layout.extended_gprs(&unsupported, mask, ImageFormat::Standard),
            Err(ImageError::Mask { .. })
        ));
        assert!(matches!(
            layout.extended_gprs(&image, mask, ImageFormat::Compacted),
            Err(ImageError::Format { .. })
        ));
        let compact = make_image(mask, ImageFormat::Compacted);
        assert!(matches!(
            layout.extended_gprs(&compact, mask, ImageFormat::Standard),
            Err(ImageError::Format { .. })
        ));
        let mut malformed = discovered_layout();
        let part = malformed.components[..malformed.count]
            .iter_mut()
            .find(|part| part.bit == 19)
            .unwrap();
        part.bytes = 64;
        assert!(matches!(
            malformed.extended_gprs(&image, mask, ImageFormat::Standard),
            Err(ImageError::Component { bit: 19, bytes: 64 })
        ));
    }
}
