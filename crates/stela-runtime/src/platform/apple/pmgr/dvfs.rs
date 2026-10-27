//! Original native PMP's T8112 DVFS bank protocol, without a bank backend.
//!
//! 26A434 t8112pmp SHA256 b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c:
//! vtable VM1043b58, methods1008310..100844c, hardware rows10462d8 and
//! domain rows1046428. Native1017a50 issues a request;1017370 requires the
//! controller's interrupt-pending method (+0x68, full status == 1), then ACKs
//! via +0x60 before publishing settled state. BUSY polling (+0x48) occurs at
//! initialization1016df0 and an optional pre-request path1017a08, not as that
//! IRQ completion predicate. A physical PMGR domain's ACTIVE value and DPE
//! sample registers establish no DVFS progress.
//!
//! These immutable descriptors decode supplied observations and describe the
//! original driver's physical operations. They neither execute those operations
//! nor implement MMIO. There is no initial state, current-state setter, BUSY
//! clear, IRQ wire or completion receipt. Each descriptor retains the missing
//! native effect-owner requirement, which machine admission must report.

use super::sequencer::{PhysicalWrite, poll::PhysicalRead};
use crate::platform::apple::bus::Width;

/// Physical-controller ordinal in the original hardware table. Domain+0x9c
/// selects this ordinal independently of PMGR power-domain IDs and names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Controller {
    Dcs = 0,
    Soc = 1,
    Display = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Current,
    Requested,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    LogicalState {
        controller: Controller,
        logical: u8,
    },
    UnknownRaw {
        controller: Controller,
        field: Field,
        raw: u8,
    },
}

/// Decoded supplied data, without proof of a physical observation or effects.
/// It is intentionally not an applied-state or settlement token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation {
    pub current: u8,
    pub requested: u8,
    pub busy: bool,
}

/// A source-qualified protocol with an explicitly unqualified effect owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnqualifiedEffects {
    pub controller: Controller,
    pub physical: u64,
}

impl UnqualifiedEffects {
    pub const fn reason(self) -> &'static str {
        "DVFS request sequencing, current/BUSY progression, interrupt effects and initial controller state have no qualified native owner"
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Descriptor {
    controller: Controller,
    physical: u64,
    codes: &'static [u8],
    irq_control: u64,
}

/// Qualified geometry of the common T8112 PMP image. No other family's
/// register geometry, code map or interrupt semantics is inferred from it.
pub const T8112: [Descriptor; 3] = [
    Descriptor {
        controller: Controller::Dcs,
        physical: 0x23b05c000,
        codes: &[3, 4, 5, 6, 7],
        irq_control: 0x20,
    },
    Descriptor {
        controller: Controller::Soc,
        physical: 0x23b058000,
        codes: &[3, 4, 5],
        irq_control: 0x10,
    },
    Descriptor {
        controller: Controller::Display,
        physical: 0x23b060000,
        codes: &[1, 2, 3, 4],
        irq_control: 0xc,
    },
];

impl Descriptor {
    pub const fn controller(self) -> Controller {
        self.controller
    }
    pub const fn aperture(self) -> (u64, u64) {
        (self.physical, 0x4000)
    }
    pub const fn codes(self) -> &'static [u8] {
        self.codes
    }
    pub const fn refusal(self) -> UnqualifiedEffects {
        UnqualifiedEffects {
            controller: self.controller,
            physical: self.physical,
        }
    }

    pub const fn control_read(self) -> PhysicalRead {
        PhysicalRead {
            address: self.physical,
            width: Width::Word,
        }
    }
    pub const fn interrupt_control_read(self) -> PhysicalRead {
        PhysicalRead {
            address: self.physical + self.irq_control,
            width: Width::Word,
        }
    }
    pub const fn interrupt_status_read(self) -> PhysicalRead {
        PhysicalRead {
            address: self.physical + self.irq_control + 4,
            width: Width::Word,
        }
    }

    fn logical(self, field: Field, raw: u8) -> Result<u8, Error> {
        self.codes
            .iter()
            .position(|&code| code == raw)
            .map(|index| index as u8)
            .ok_or(Error::UnknownRaw {
                controller: self.controller,
                field,
                raw,
            })
    }

    /// The original lookup falls back to logical zero for an unknown raw code.
    /// That fallback is not qualified controller state: preserve the unknown
    /// field explicitly rather than letting it grant a native vote or ACK.
    pub fn decode(self, control: u32) -> Result<Observation, Error> {
        Ok(Observation {
            current: self.logical(Field::Current, ((control >> 8) & 15) as u8)?,
            requested: self.logical(Field::Requested, (control & 15) as u8)?,
            busy: control & (1 << 31) != 0,
        })
    }

    /// Exact driver store, not an RMW and not an issued/applied request. Only
    /// a separately qualified physical sink may execute or complete this write.
    pub fn request_write(self, logical: u8) -> Result<PhysicalWrite, Error> {
        let code = self
            .codes
            .get(usize::from(logical))
            .ok_or(Error::LogicalState {
                controller: self.controller,
                logical,
            })?;
        Ok(PhysicalWrite {
            address: self.physical,
            width: Width::Word,
            value: u64::from(*code & 15),
        })
    }

    /// Driver enable/disable RMW against an actually supplied control word.
    /// Describing it supplies no initial mask, local IRQ or AIC-wire ownership.
    pub fn interrupt_control_write(self, observed: u32, enabled: bool) -> PhysicalWrite {
        PhysicalWrite {
            address: self.interrupt_control_read().address,
            width: Width::Word,
            value: u64::from(if enabled { observed | 1 } else { observed & !1 }),
        }
    }

    /// The original ack reads status and writes the complete same word back.
    /// The receiving bank must qualify its effects; no W1C state is fabricated.
    pub fn acknowledgment_write(self, observed: u32) -> PhysicalWrite {
        PhysicalWrite {
            address: self.interrupt_status_read().address,
            width: Width::Word,
            value: u64::from(observed),
        }
    }

    /// Source method100842c tests whole-word equality, not merely bit zero.
    pub const fn interrupt_pending(self, observed: u32) -> bool {
        observed == 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observations_keep_current_requested_and_busy_separate_and_unknowns_explicit() {
        for descriptor in T8112 {
            for (current, &raw_current) in descriptor.codes().iter().enumerate() {
                for (requested, &raw_requested) in descriptor.codes().iter().enumerate() {
                    let word = (1 << 31) | u32::from(raw_current) << 8 | u32::from(raw_requested);
                    assert_eq!(
                        descriptor.decode(word),
                        Ok(Observation {
                            current: current as u8,
                            requested: requested as u8,
                            busy: true,
                        })
                    );
                    let write = descriptor.request_write(requested as u8).unwrap();
                    assert_eq!(
                        (write.address, write.width, write.value),
                        (
                            descriptor.aperture().0,
                            Width::Word,
                            u64::from(raw_requested)
                        )
                    );
                }
            }
            assert!(matches!(
                descriptor.decode(0),
                Err(Error::UnknownRaw {
                    field: Field::Current,
                    raw: 0,
                    ..
                })
            ));
            assert!(matches!(
                descriptor.decode(u32::from(descriptor.codes()[0]) << 8),
                Err(Error::UnknownRaw {
                    field: Field::Requested,
                    raw: 0,
                    ..
                })
            ));
            assert!(matches!(
                descriptor.request_write(descriptor.codes().len() as u8),
                Err(Error::LogicalState { .. })
            ));
            let refusal = descriptor.refusal();
            assert_eq!(
                (refusal.controller, refusal.physical),
                (descriptor.controller(), descriptor.aperture().0)
            );
        }
        // A raw code absent from native PMP's advertised map remains unknown.
        // The original helper's fallback zero cannot authorize a native vote.
        assert!(matches!(
            T8112[0].decode(0x103),
            Err(Error::UnknownRaw {
                field: Field::Current,
                raw: 1,
                ..
            })
        ));
    }

    #[test]
    fn interrupt_operations_preserve_source_words_without_inventing_effects_or_wires() {
        for (descriptor, offset) in T8112.into_iter().zip([0x20, 0x10, 0xc]) {
            assert_eq!(
                descriptor.interrupt_control_write(0xabc0, true).value,
                0xabc1
            );
            assert_eq!(
                descriptor.interrupt_control_write(0xabc1, false).value,
                0xabc0
            );
            let ack = descriptor.acknowledgment_write(0xa5a5_0003);
            assert_eq!(
                (ack.address, ack.width, ack.value),
                (
                    descriptor.aperture().0 + offset + 4,
                    Width::Word,
                    0xa5a5_0003
                )
            );
            assert!(descriptor.interrupt_pending(1));
            for status in [0, 2, 3, u32::MAX] {
                assert!(!descriptor.interrupt_pending(status));
            }
        }
    }

    #[test]
    #[ignore = "requires original 26A434 t8112pmp through STELA_TEST_PMGR_PMP"]
    fn original_native_protocol_keeps_hardware_identity_and_request_settlement_distinct() {
        let bytes = std::fs::read(std::env::var("STELA_TEST_PMGR_PMP").unwrap()).unwrap();
        assert_eq!(
            crate::sha256(&bytes),
            "b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c"
        );
        // Complete source methods/tables, including the separate issue and
        // busy-clear settlement paths. These fixtures execute no firmware.
        for (offset, length, expected) in [
            (
                0x9300,
                0x164,
                "d15136b110ccfd6682fde2318ba0450f1dc661e7cdef1aa6558bcca40e087a2f",
            ),
            (
                0x18370,
                0x1c4,
                "193a3547805d0b7ba55a818fec5228aeaa397cc5aef9410e7ce842d31defbb81",
            ),
            (
                0x18600,
                0x5a4,
                "91383d1f1483aa04490c8ccaff5cb3a0debc1be54c77873b5240b1d173282d69",
            ),
            (
                0x472d8,
                0x150,
                "b84ed42a5b0a8b4f2f7955cf089251a3ec96ab80de42ec64eb61b74ef215904b",
            ),
            (
                0x47428,
                0x270,
                "8de57c92421aefc6e58f316ab479b2481f58e8c32ebdce0c1c76cf3a37d228b6",
            ),
            (
                0x45730,
                0xa8,
                "04bbcf304ec1f27f164ddf583472635dfa228181acf27666fc51f6002c07a374",
            ),
            (
                0x44240,
                0x108,
                "e680810fc0bc4f5c20151eaaab76aa24f93a03d571ab6a8529318c983b2510e0",
            ),
            (
                0x35c78,
                0x60,
                "4befcac752d421c415db3cbde8ee00b8dc52e5e40eeba58a23b48aaba4cce5cd",
            ),
        ] {
            assert_eq!(crate::sha256(&bytes[offset..offset + length]), expected);
        }
        let word =
            |offset: usize| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        let quad =
            |offset: usize| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        for (index, descriptor) in T8112.into_iter().enumerate() {
            let (window, codes, layout) = [
                (0x45768, 0x44298, 0x35c98),
                (0x45730, 0x44240, 0x35c78),
                (0x457a0, 0x442f0, 0x35cb8),
            ][index];
            let object = 0xfff000 + window as u64 + 0x20;
            assert_eq!(quad(0x472d8 + 0x70 * index), object);
            assert_eq!(quad(window + 0x20), 0x1043b58);
            assert_eq!(quad(window + 0x28), 0xfff000 + window as u64);
            assert_eq!(quad(window + 0x30), 0xfff000 + codes as u64);
            assert_eq!((quad(window), quad(window + 8)), descriptor.aperture());
            assert_eq!(
                word(0x47428 + 0xd0 * index + 0x9c),
                descriptor.controller() as u32
            );
            assert_eq!(word(codes) as usize, descriptor.codes().len());
            for (state, &code) in descriptor.codes().iter().enumerate() {
                assert_eq!(word(codes + 4 + state * 4), u32::from(code));
            }
            assert_eq!(quad(codes + 0x50), 0xfff000 + layout as u64);
            assert_eq!(word(layout + 0x1c), 8);
            assert_eq!(u64::from(word(layout + 0x18)), descriptor.irq_control);
        }
    }
}
