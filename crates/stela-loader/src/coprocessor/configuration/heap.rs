//! Native external runtime heap request and mapped RHB1/RHS1 fields.
//!
//! Allocation and mapping remain with the boot resource owner. These operations
//! check source policy and geometry; coordinates/provenance are not ownership
//! or execution permission. The owners must survive firmware heap use.
use super::{Action, Field, Provenance, source_record};
use crate::Result;
use crate::coprocessor::Staged;
use stela_contracts::{refuse, require};

const BASE: u32 = u32::from_be_bytes(*b"RHB1");
const SIZE: u32 = u32::from_be_bytes(*b"RHS1");
const MINIMUM: u64 = 0x400;

/// Selected native bank state, independent of the image allocation.
#[derive(Debug, Clone, Copy)]
pub enum BankState {
    Allocate,
    /// Available bytes in the real reserved bank, before request clamping.
    Reserved {
        bytes: u64,
    },
}

/// Source-selected inputs; none is inferred from a Mach-O segment alignment.
pub struct Policy {
    pub bank: u16,
    pub alignment: u64,
    pub state: BankState,
    /// Covers selected bank identity/state and allocator alignment.
    pub provenance: Provenance,
}

/// Resource demand for the caller's allocator and selected mapper.
/// This value carries no allocation, mapping or backend permission.
#[derive(Debug, Clone, Copy)]
pub struct Request {
    pub bank: u16,
    pub alignment: u64,
    pub bytes: u64,
}

/// Coordinates returned by the allocation and selected mapping owners.
/// The PA interval must be independent of the staged image. IOP is separate.
pub struct Mapping {
    pub bank: u16,
    pub physical: u64,
    pub iop: u64,
    pub bytes: u64,
    /// Covers both allocation and complete readable/writable IOP mapping.
    pub provenance: Provenance,
}

pub struct Fields {
    pub base: Field,
    pub size: Field,
}

impl Staged {
    /// iBoot ceb34 reads the original RHS1 request; only an absent tag takes
    /// its 64MiB fallback. This operation requires the present original family.
    /// ceb98 clamps a reserved bank to the request; eebd0 rounds an allocation
    /// to the allocator granule, obtained by the same native lookup as
    /// alignment (ee5e0, d020c). Real allocator bounds/security remain required.
    pub fn heap_request(&self, policy: &Policy) -> Result<Request> {
        policy.provenance.validate()?;
        require!(
            policy.bank != 0 && policy.bank <= 0x27d,
            "invalid native heap bank"
        );
        require!(
            policy.alignment.is_power_of_two(),
            "invalid native heap alignment"
        );
        let (base, _) = source_record(self, BASE)?;
        let (size, raw) = source_record(self, SIZE)?;
        require!(
            base.bytes == 8 && size.bytes == 4,
            "unqualified native heap record widths"
        );
        let requested = u64::from(u32::from_le_bytes(raw.try_into().unwrap()));
        require!(
            requested != 0,
            "zero native heap request requires separate bank policy"
        );
        let bytes = match policy.state {
            BankState::Allocate => requested
                .checked_add(policy.alignment - 1)
                .map(|n| n & !(policy.alignment - 1))
                .ok_or_else(|| refuse!("native heap allocation size overflows"))?,
            BankState::Reserved { bytes } => requested.min(bytes),
        };
        require!(
            bytes >= MINIMUM && bytes <= u64::from(u32::MAX),
            "native heap size cannot initialize firmware"
        );
        Ok(Request {
            bank: policy.bank,
            alignment: policy.alignment,
            bytes,
        })
    }

    /// cec28 takes mapping result+0x28, not its physical+0x20. cec94/cecb0
    /// install that IOP base and length. FW12470 refuses zero base/size
    /// and maps the range before initializing the heap. Produce both fields
    /// together for the still-required complete configuration transaction.
    pub fn heap_fields(&self, policy: &Policy, mapping: Mapping) -> Result<Fields> {
        let request = self.heap_request(policy)?;
        mapping.provenance.validate()?;
        require!(
            mapping.bank == request.bank,
            "native heap allocation uses a different bank"
        );
        require!(
            mapping.bytes == request.bytes,
            "native heap mapping length disagrees with bank policy"
        );
        require!(
            mapping.iop != 0,
            "native firmware cannot initialize a zero-address heap"
        );
        let physical_end = mapping
            .physical
            .checked_add(mapping.bytes)
            .ok_or_else(|| refuse!("native heap physical range overflows"))?;
        mapping
            .iop
            .checked_add(mapping.bytes)
            .ok_or_else(|| refuse!("native heap IOP range overflows"))?;
        if matches!(policy.state, BankState::Allocate) {
            require!(
                mapping.physical & (request.alignment - 1) == 0,
                "native allocated heap is misaligned"
            );
        }
        let image = self.placement();
        let image_end = image
            .physical_base
            .checked_add(image.backing_bytes)
            .ok_or_else(|| refuse!("staged image allocation overflows"))?;
        require!(
            physical_end <= image.physical_base || mapping.physical >= image_end,
            "native external heap overlaps staged firmware allocation"
        );
        Ok(Fields {
            base: Field {
                tag: BASE,
                action: Action::Replace(mapping.iop.to_le_bytes().to_vec()),
                provenance: mapping.provenance.clone(),
            },
            size: Field {
                tag: SIZE,
                action: Action::Replace((mapping.bytes as u32).to_le_bytes().to_vec()),
                provenance: mapping.provenance,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coprocessor::{
        configuration::tests::{config_policy, provenance},
        tests::{fixture, prepare, w32, w64},
    };
    use anyhow::Result;

    fn image(requested: u32) -> alloc::vec::Vec<u8> {
        let mut b = fixture();
        w64(&mut b, 32 + 232 + 40, 28);
        w32(&mut b, 0x1200, BASE);
        w32(&mut b, 0x1204, 8);
        w64(&mut b, 0x1208, 0);
        w32(&mut b, 0x1210, SIZE);
        w32(&mut b, 0x1214, 4);
        w32(&mut b, 0x1218, requested);
        b
    }
    fn policy(state: BankState) -> Policy {
        Policy {
            bank: 0x4a,
            alignment: 0x4000,
            state,
            provenance: provenance(),
        }
    }
    fn mapping(bytes: u64) -> Mapping {
        Mapping {
            bank: 0x4a,
            physical: 0x1000000,
            iop: 0x2000000,
            bytes,
            provenance: provenance(),
        }
    }

    #[test]
    fn source_request_allocated_rounding_and_reserved_clamping() -> Result<()> {
        let staged = prepare(&image(0x4001))?.stage(0x800000, 0x3000)?;
        assert_eq!(
            staged.heap_request(&policy(BankState::Allocate))?.bytes,
            0x8000
        );
        assert_eq!(
            staged
                .heap_request(&policy(BankState::Reserved { bytes: 0x3000 }))?
                .bytes,
            0x3000
        );
        assert_eq!(
            staged
                .heap_request(&policy(BankState::Reserved { bytes: 0x10000 }))?
                .bytes,
            0x4001
        );
        assert!(
            staged
                .heap_request(&policy(BankState::Reserved { bytes: 0x3ff }))
                .is_err()
        );
        for n in [0, u32::MAX] {
            assert!(
                prepare(&image(n))?
                    .stage(0x800000, 0x3000)?
                    .heap_request(&policy(BankState::Allocate))
                    .is_err()
            );
        }
        let mut p = policy(BankState::Allocate);
        p.alignment = 3;
        assert!(staged.heap_request(&p).is_err());
        p.alignment = 0;
        assert!(staged.heap_request(&p).is_err());
        p.alignment = 0x4000;
        p.provenance.coordinates.clear();
        assert!(staged.heap_request(&p).is_err());
        assert!(
            prepare(&fixture())?
                .stage(0x800000, 0x3000)?
                .heap_request(&policy(BankState::Allocate))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn mapped_iop_fields_join_complete_transaction_and_keep_encoded_chains() -> Result<()> {
        let prepared = prepare(&image(0x4001))?;
        let mut complete = config_policy(prepared.plan());
        let staged = prepared.stage(0x800000, 0x3000)?;
        let hash = stela_formats::sha256(staged.bytes());
        let fields = staged.heap_fields(&policy(BankState::Allocate), mapping(0x8000))?;
        assert_eq!(stela_formats::sha256(staged.bytes()), hash);
        for field in [fields.base, fields.size] {
            let tag = field.tag;
            *complete.fields.iter_mut().find(|f| f.tag == tag).unwrap() = field;
        }
        let configured = staged.configure(complete)?;
        assert_eq!(
            u64::from_le_bytes(configured.bytes()[0x208..0x210].try_into().unwrap()),
            0x2000000
        );
        assert_eq!(
            u32::from_le_bytes(configured.bytes()[0x218..0x21c].try_into().unwrap()),
            0x8000
        );
        for f in &configured.plan().chains.pointers {
            assert_eq!(
                &configured.bytes()[f.image_offset as usize..f.image_offset as usize + 8],
                &f.raw.to_le_bytes()
            );
        }
        Ok(())
    }

    #[test]
    fn invalid_bank_mapping_geometry_refuses_both_fields() -> Result<()> {
        let staged = prepare(&image(0x4000))?.stage(0x800000, 0x3000)?;
        for case in 0..8 {
            let mut m = mapping(0x4000);
            match case {
                0 => m.bank = 0x49,
                1 => m.bytes -= 1,
                2 => m.iop = 0,
                3 => m.physical = u64::MAX - 1,
                4 => m.iop = u64::MAX - 1,
                5 => m.physical += 1,
                6 => m.physical = 0x800000,
                _ => m.provenance.coordinates.clear(),
            }
            assert!(staged.heap_fields(&policy(BankState::Allocate), m).is_err());
        }
        // Reserved policy does not invent the allocated branch's base alignment.
        let mut m = mapping(0x4000);
        m.physical += 1;
        assert!(
            staged
                .heap_fields(&policy(BankState::Reserved { bytes: 0x8000 }), m)
                .is_ok()
        );
        Ok(())
    }

    #[test]
    #[ignore = "oracle: STELA_TEST_J314S_IBOOT"]
    #[cfg(feature = "std")]
    fn original_t6000_heap_policy_coordinates() -> Result<()> {
        let b = std::fs::read(std::env::var("STELA_TEST_J314S_IBOOT")?)?;
        assert_eq!(
            stela_formats::sha256(&b),
            "20dfa3a5e6d4e4b2844c7558e6d4f8ab74397d11eae63312f00a559cf9612b03"
        );
        let q = |at| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
        let w = |at| u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
        // d01e0 -> f9c34/f9c84 -> table1ec180, key1600,type3,inline u64.
        assert_eq!(q(0x1ec1e0), 0x102001cefd8);
        assert_eq!(
            (w(0x1cefd8), w(0x1cefdc), q(0x1cefe0)),
            (0x1600, 0x30000, 0x4000)
        );
        assert_eq!(q(0x196298 + 0x6c8) & 0xffff_ffff, 0x4a);
        // 3c7d0 returns112 records at1ffce8, stride40. Bank4a has unset
        // physical base/length (-1), group9 and flags8000, not a reserved PA.
        assert_eq!(q(0x2004e8), u64::MAX);
        assert_eq!(q(0x2004f8), u64::MAX);
        assert_eq!(w(0x200500), 0x0009_004a);
        assert_eq!(w(0x200504), 0x8000);
        Ok(())
    }
}
