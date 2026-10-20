//! Spooled offers: the blocks a process compiled but did not prove, which
//! it leaves for the store's service (`stelad`) instead of proving them on
//! its own way out (`docs/design/runtime.md#stelad`).
//!
//! A spool file is written whole through a sibling file and `rename`, and
//! read and removed by the service:
//!
//! | Field | Bytes |
//! | --- | ---: |
//! | magic `STLTSPOL` | 8 |
//! | schema | 4 |
//! | translator id | 32 |
//! | offers | … |
//! | SHA-256 of every preceding byte | 32 |
//!
//! Each offer: page key (32), page address (u64), entry PC (u64), context
//! (32), preparation description length (u32) and its JSON
//! (`machine::Description`), input length (u32) and the admitted input
//! words. A file of another translator, or damaged, is discarded.
use crate::machine::{Description, Offer, Preparation};
use crate::translations::Digest;
use sha2::{Digest as _, Sha256};
use std::sync::Arc;

const MAGIC: [u8; 8] = *b"STLTSPOL";
const SCHEMA: u32 = 1;
const HEADER_BYTES: usize = 8 + 4 + 32;
const TRAILER_BYTES: usize = 32;
/// The longest description or input a spooled offer carries.
const MAX_FIELD_BYTES: usize = 64 << 10;

/// One offer as the service recompiles it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Spooled {
    pub(super) key: Digest,
    pub(super) page: u64,
    pub(super) pc: u64,
    pub(super) context: Digest,
    pub(super) description: Description,
    pub(super) input: Vec<u8>,
}

impl Spooled {
    pub(super) fn of(offer: &Offer) -> Self {
        Self {
            key: offer.key,
            page: offer.page,
            pc: offer.pc,
            context: offer.context,
            description: offer.preparation.description(),
            input: offer.input.clone(),
        }
    }

    /// The offer again, its block compiled from its input; `None` when the
    /// input no longer compiles or the context is not the description's.
    pub(super) fn offer(&self, preparation: Arc<Preparation>) -> Option<Offer> {
        if preparation.context(self.page) != self.context {
            return None;
        }
        let block = preparation.compile_input(&self.input, self.pc).ok()?;
        Some(Offer {
            key: self.key,
            page: self.page,
            pc: self.pc,
            context: self.context,
            input: self.input.clone(),
            preparation,
            block,
            successors: Vec::new(),
        })
    }
}

pub(super) fn encode(translator: &Digest, offers: &[Spooled]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(MAGIC);
    out.extend(SCHEMA.to_le_bytes());
    out.extend(translator.0);
    for offer in offers {
        let description = serde_json::to_vec(&offer.description).expect("a description serializes");
        out.extend(offer.key.0);
        out.extend(offer.page.to_le_bytes());
        out.extend(offer.pc.to_le_bytes());
        out.extend(offer.context.0);
        out.extend((description.len() as u32).to_le_bytes());
        out.extend(description);
        out.extend((offer.input.len() as u32).to_le_bytes());
        out.extend(&offer.input);
    }
    let checksum = Sha256::digest(&out);
    out.extend(checksum);
    out
}

/// The offers of a spool file of `translator`, or `None`.
pub(super) fn decode(bytes: &[u8], translator: &Digest) -> Option<Vec<Spooled>> {
    if bytes.len() < HEADER_BYTES + TRAILER_BYTES {
        return None;
    }
    let (body, trailer) = bytes.split_at(bytes.len() - TRAILER_BYTES);
    if Sha256::digest(body).as_slice() != trailer
        || body[..8] != MAGIC
        || body[8..12] != SCHEMA.to_le_bytes()
        || body[12..44] != translator.0
    {
        return None;
    }
    let mut rest = &body[HEADER_BYTES..];
    let mut take = |length: usize| -> Option<&[u8]> {
        if rest.len() < length {
            return None;
        }
        let (taken, after) = rest.split_at(length);
        rest = after;
        Some(taken)
    };
    let mut offers = Vec::new();
    while let Some(key) = take(32) {
        let key = Digest(key.try_into().ok()?);
        let page = u64::from_le_bytes(take(8)?.try_into().ok()?);
        let pc = u64::from_le_bytes(take(8)?.try_into().ok()?);
        let context = Digest(take(32)?.try_into().ok()?);
        let length = u32::from_le_bytes(take(4)?.try_into().ok()?) as usize;
        if length > MAX_FIELD_BYTES {
            return None;
        }
        let description = serde_json::from_slice(take(length)?).ok()?;
        let length = u32::from_le_bytes(take(4)?.try_into().ok()?) as usize;
        if length > MAX_FIELD_BYTES {
            return None;
        }
        let input = take(length)?.to_vec();
        offers.push(Spooled {
            key,
            page,
            pc,
            context,
            description,
            input,
        });
    }
    Some(offers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::test_preparation;

    #[test]
    fn spooled_offers_round_trip_and_compile_to_the_block_they_were() {
        let preparation = test_preparation();
        let page = 0x1_0000_4000;
        // add x0, x0, #1; ret
        let mut input: Vec<u8> = [0x9100_0400u32, 0xd65f_03c0]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        preparation.admit(&mut input);
        let spooled = Spooled {
            key: Digest::of(b"page"),
            page,
            pc: page + 8,
            context: preparation.context(page),
            description: preparation.description(),
            input,
        };
        let translator = Digest::of(b"translator");
        let bytes = encode(&translator, &[spooled.clone(), spooled.clone()]);
        let decoded = decode(&bytes, &translator).unwrap();
        assert_eq!(decoded, [spooled.clone(), spooled.clone()]);
        assert_eq!(decode(&bytes, &Digest::default()), None);
        let mut damaged = bytes.clone();
        damaged[50] ^= 1;
        assert_eq!(decode(&damaged, &translator), None);
        let again = Arc::new(Preparation::from_description(&spooled.description));
        let offer = spooled.offer(again).unwrap();
        let compiled = preparation
            .compile_input(&spooled.input, spooled.pc)
            .unwrap();
        assert_eq!(offer.block.native.x86_64_code, compiled.native.x86_64_code);
        // Another context is refused.
        let mut other = spooled;
        other.context = Digest::default();
        assert!(
            other
                .offer(Arc::new(Preparation::from_description(&other.description)))
                .is_none()
        );
    }
}
