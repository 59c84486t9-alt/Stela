//! Actual shared101ba6c provider-frame cache and G540 read masks.
//!
//! Original26A434 T8112 PMP b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c:
//!100cab4..100cb30 selects PTD slots4..7 and initializes four bank tuples;
//!100d8f8..100d90c binds every platform P250 to G500. Thus cache masks at
//! P250+40 are the SAME G540 bytes cleared by100f924..100f930 before Capture.
//!101ba6c consumes each first bank/index read and returns retained native tuple.
//! No firmware executes, hardware events, samples, eligibility or ACKs arise.
use super::super::counters::{CaptureIdentity, Captured, Frame, Frames};
use super::{ingestion, owner::Completion};
use crate::platform::apple::{
    bus::Access,
    ptd::{Range, transport::notifications::LocalNotifications},
};
use alloc::{rc::Rc, vec::Vec};
use core::cell::{Cell, RefCell};

type Error = &'static str;
/// Unique native PMP allocation claim. Dropping it never permits another cache
/// on this source recipient or changes the actual PTD publication owner.
pub struct Claim {
    recipient: Rc<()>,
    local: LocalNotifications,
    ranges: [Option<Range>; 4],
    alive: Rc<Cell<bool>>,
}
impl Claim {
    pub(in crate::platform::apple::pmp::native) fn new(
        recipient: Rc<()>,
        local: LocalNotifications,
        ranges: [Option<Range>; 4],
        alive: Rc<Cell<bool>>,
    ) -> Self {
        Self {
            recipient,
            local,
            ranges,
            alive,
        }
    }
    fn check(&self) -> Result<(), Error> {
        if self.alive.get() {
            Ok(())
        } else {
            Err("native provider-frame owner abandoned")
        }
    }
}
/// Unique binding from the actual native recipient to its manager's G540.
/// It proves neither physical controller geometry nor configuration provenance.
pub struct ManagerClaim {
    recipient: Rc<()>,
    local: LocalNotifications,
    alive: Rc<Cell<bool>>,
}
impl ManagerClaim {
    pub(in crate::platform::apple::pmp::native) fn new(
        recipient: Rc<()>,
        local: LocalNotifications,
        alive: Rc<Cell<bool>>,
    ) -> Self {
        Self {
            recipient,
            local,
            alive,
        }
    }
    fn check(&self) -> Result<(), Error> {
        if self.alive.get() {
            Ok(())
        } else {
            Err("native manager-mask owner abandoned")
        }
    }
}
struct MaskState {
    recipient: Option<ManagerClaim>,
    bytes: [u8; 32],
    generation: u64,
    bound: bool,
}
/// Identity of the actual G540 software storage, shared with the manager
/// controller owner. No public constructor/reset/set-mask interface exists.
#[derive(Clone)]
pub struct ReadMasks(Rc<RefCell<MaskState>>);
impl ReadMasks {
    pub(super) fn initialized() -> Self {
        Self(Rc::new(RefCell::new(MaskState {
            recipient: None,
            bytes: [0; 32],
            generation: 0,
            bound: false,
        })))
    }
    pub(super) fn initialized_for_native(claim: ManagerClaim) -> Result<Self, Error> {
        claim.check()?;
        let masks = Self::initialized();
        masks.0.borrow_mut().recipient = Some(claim);
        Ok(masks)
    }
    fn check_recipient(&self, cache: &Claim) -> Result<(), Error> {
        let state = self.0.borrow();
        let manager = state
            .recipient
            .as_ref()
            .ok_or("provider cache requires a native-bound manager G540")?;
        manager.check()?;
        if !Rc::ptr_eq(&manager.recipient, &cache.recipient)
            || !manager.local.owns(cache.local.bank())
        {
            return Err("provider cache and manager G540 have different native recipients");
        }
        Ok(())
    }
    pub fn bytes(&self) -> [u8; 32] {
        self.0.borrow().bytes
    }
    pub fn generation(&self) -> u64 {
        self.0.borrow().generation
    }
    pub(super) fn preflight_reset(&self) -> Result<(), Error> {
        let state = self.0.borrow();
        if let Some(recipient) = &state.recipient {
            recipient.check()?;
        }
        state
            .generation
            .checked_add(1)
            .map(|_| ())
            .ok_or("native provider-mask generation exhausted before effects")
    }
    pub(super) fn reset(&self) -> Result<(), Error> {
        let mut state = self.0.borrow_mut();
        if let Some(recipient) = &state.recipient {
            recipient.check()?;
        }
        let next = state
            .generation
            .checked_add(1)
            .ok_or("native provider-mask generation exhausted before reset")?;
        state.bytes.fill(0);
        state.generation = next;
        Ok(())
    }
    fn claim(&self) -> Result<(), Error> {
        let mut s = self.0.borrow_mut();
        if s.bound {
            return Err("native G540 storage already has its provider cache");
        }
        s.bound = true;
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn test_bytes_mut(&self) -> core::cell::RefMut<'_, [u8; 32]> {
        core::cell::RefMut::map(self.0.borrow_mut(), |s| &mut s.bytes)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    pub bank: u32,
    pub start: u32,
    pub count: u32,
}
struct Bank {
    layout: Layout,
    cells: Vec<Frame>,
}
/// The real shared global cache. Source per-instance block rows are DATA from
/// a still-required actual configuration producer, not range lengths or a SKU.
/// Each product row contains the four banks' source words at G3d0+58/+60/+68/+70
/// plus the source instance index*4; the Rust array is not a raw structure cast. Source allocation uses sum(blocks)*8 and skips
/// absent/zero-start/zero-count banks. Top bytes are explicit native software
/// initialization, not observations of Apple heap contents or hardware events.
pub struct Cache {
    claim: Claim,
    masks: ReadMasks,
    banks: [Option<Bank>; 4],
    capture: Option<CaptureIdentity>,
    generation: u64,
    consumed: u64,
    fault: Option<Error>,
}
impl Cache {
    pub fn initialized(
        claim: Claim,
        source_block_rows: &[[u32; 4]],
        masks: ReadMasks,
        preserved_top_bytes: [Vec<u8>; 4],
    ) -> Result<Self, Error> {
        claim.check()?;
        masks.check_recipient(&claim)?;
        let mut banks: [Option<Bank>; 4] = core::array::from_fn(|_| None);
        for (i, top) in preserved_top_bytes.into_iter().enumerate() {
            let mut blocks = 0u32;
            for row in source_block_rows {
                blocks = blocks
                    .checked_add(row[i])
                    .ok_or("native provider source block sum overflows")?;
            }
            let allocated = claim.ranges[i]
                .as_ref()
                .filter(|r| r.start != 0 && blocks != 0 && !source_block_rows.is_empty());
            let Some(range) = allocated else {
                if !top.is_empty() {
                    return Err("native absent provider bank has invented storage");
                }
                continue;
            };
            let count = blocks
                .checked_mul(8)
                .ok_or("native provider source entry count overflows")?;
            if count > range.count
                || range.start.checked_add(count).is_none()
                || top.len() != count as usize
            {
                return Err("native provider source count/image exceeds actual selected PTD range");
            }
            banks[i] = Some(Bank {
                layout: Layout {
                    bank: i as u32,
                    start: range.start,
                    count,
                },
                cells: top.into_iter().map(Frame::initialized).collect(),
            });
        }
        masks.claim()?;
        Ok(Self {
            claim,
            masks,
            banks,
            capture: None,
            generation: 0,
            consumed: 0,
            fault: None,
        })
    }
    pub fn layout(&self, bank: u32) -> Option<Layout> {
        self.banks
            .get(bank as usize)
            .and_then(|b| b.as_ref().map(|b| b.layout))
    }
    pub fn consumed(&self) -> u64 {
        self.consumed
    }
    pub fn read_masks(&self) -> ReadMasks {
        self.masks.clone()
    }
    /// Join one actual latest manager capture to an actual source G540 reset.
    /// This neither resets the mask nor manufactures a capture/cycle. Rebinding
    /// another capture without the source reset refuses, even on the same bank.
    pub fn bind_capture(&mut self, frames: &Frames, captured: &Captured) -> Result<(), Error> {
        self.claim.check()?;
        self.masks.check_recipient(&self.claim)?;
        if let Some(e) = self.fault {
            return Err(e);
        }
        if !self.claim.local.owns(frames.notifications().bank()) {
            return Err("provider cache and manager capture have different PTD owners");
        }
        frames.validate_capture(captured)?;
        let generation = self.masks.generation();
        if generation == 0 {
            return Err("provider cache requires actual manager BeforeCapture mask reset");
        }
        if generation == self.generation {
            return frames.validate_capture_identity(
                self.capture
                    .as_ref()
                    .ok_or("provider cache lost actual capture identity")?,
            );
        }
        let identity = frames.capture_identity(captured)?;
        self.capture = Some(identity);
        self.generation = generation;
        Ok(())
    }
    fn check_bound(&self, frames: &Frames) -> Result<(), Error> {
        self.claim.check()?;
        self.masks.check_recipient(&self.claim)?;
        if let Some(e) = self.fault {
            return Err(e);
        }
        if !self.claim.local.owns(frames.notifications().bank()) {
            return Err("provider-cache consumer has a foreign actual PTD bank");
        }
        frames.validate_capture_identity(
            self.capture
                .as_ref()
                .ok_or("provider cache has no manager capture")?,
        )?;
        if self.generation == 0 || self.masks.generation() != self.generation {
            return Err("provider cache is not bound to current actual G540 reset");
        }
        Ok(())
    }
    pub fn read(
        &mut self,
        frames: &Frames,
        captured: &Captured,
        bank: u32,
        index: u32,
        access: &mut Access<'_>,
    ) -> Completion<Frame> {
        if let Err(e) = frames.validate_capture(captured) {
            return Completion::Refused(e);
        }
        self.read_bound(frames, bank, index, access)
    }
    /// Revalidates the retained non-Clone identity from actual bind_capture.
    /// This lets nested provider callbacks share that same capture across Busy
    /// without cloning Captured or turning numeric masks into new authority.
    pub fn read_bound(
        &mut self,
        frames: &Frames,
        bank: u32,
        index: u32,
        access: &mut Access<'_>,
    ) -> Completion<Frame> {
        if let Err(e) = self.check_bound(frames) {
            return Completion::Refused(e);
        }
        let Some(source) = self.banks.get_mut(bank as usize).and_then(Option::as_mut) else {
            return Completion::Refused("native source provider bank has no actual allocation");
        };
        let Some(cell) = source.cells.get_mut(index as usize) else {
            return Completion::Refused("native source provider index exceeds initialized bank");
        };
        // Exact A64 LSL X index semantics: indices64+ alias the mask bit. The
        // source then returns that index's retained cell without a consume.
        let bit = 1u64.wrapping_shl(index);
        let offset = bank as usize * 8;
        let mask = u64::from_le_bytes(
            self.masks.0.borrow().bytes[offset..offset + 8]
                .try_into()
                .unwrap(),
        );
        if mask & bit != 0 {
            return Completion::Retired {
                value: *cell,
                refusal: None,
            };
        }
        let Some(next) = self.consumed.checked_add(1) else {
            return Completion::Refused(
                "native provider consume count exhausted before PTD effect",
            );
        };
        let entry = match self
            .claim
            .local
            .bank()
            .consume_entry(source.layout.start + index, access)
        {
            Ok(entry) => entry,
            Err(e) => return Completion::Refused(e),
        };
        // No fallible operation lies between this actual consumption and its
        // retained tuple/progress. A post-consumption reset race poisons reuse,
        // while returning the actual value with a retired-prefix diagnostic.
        cell.copy(entry);
        self.consumed = next;
        let mut state = self.masks.0.borrow_mut();
        if state.generation != self.generation {
            let e = "native G540 reset changed during actual provider consumption";
            self.fault = Some(e);
            return Completion::Retired {
                value: *cell,
                refusal: Some(e),
            };
        }
        state.bytes[offset..offset + 8].copy_from_slice(&(mask | bit).to_le_bytes());
        Completion::Retired {
            value: *cell,
            refusal: None,
        }
    }
    pub fn count(&self, bank: u32) -> Result<u32, Error> {
        self.claim.check()?;
        self.banks
            .get(bank as usize)
            .map(|b| b.as_ref().map_or(0, |b| b.layout.count))
            .ok_or("native provider bank selector exceeds source four-bank table")
    }
    /// Shared routing for generic ingestion. Other provider classes require
    /// their actual owners; this is not a successful catch-all Backend.
    pub fn ingestion_call(
        &mut self,
        _: &ingestion::Request,
        call: &ingestion::Call,
        frames: &Frames,
        access: &mut Access<'_>,
    ) -> Completion<ingestion::Value> {
        match *call {
            ingestion::Call::ExtendedCount { bank } => match self.count(bank) {
                Ok(n) => Completion::Retired {
                    value: ingestion::Value::Word(u64::from(n)),
                    refusal: None,
                },
                Err(e) => Completion::Refused(e),
            },
            ingestion::Call::ExtendedFrame { bank, index } => {
                map(self.read_bound(frames, bank, index, access), |f| {
                    ingestion::Value::Pair(ingestion::Pair {
                        value: f.value,
                        tick: f.metadata,
                    })
                })
            }
            _ => Completion::Refused("generic call requires another actual native provider owner"),
        }
    }
    /// Auxiliary bank2 reads MUST borrow this same instance as ingestion.
    pub fn auxiliary_call(
        &mut self,
        _: &ingestion::control::ResourceRequest,
        operation: ingestion::control::Operation,
        frames: &Frames,
        access: &mut Access<'_>,
    ) -> Completion<ingestion::control::ResourceValue> {
        match operation {
            ingestion::control::Operation::ExtendedFrame { bank, index } => {
                map(self.read_bound(frames, bank, index, access), |f| {
                    ingestion::control::ResourceValue::Pair(ingestion::Pair {
                        value: f.value,
                        tick: f.metadata,
                    })
                })
            }
            _ => {
                Completion::Refused("auxiliary call requires another actual native resource owner")
            }
        }
    }
}
fn map<T, U>(c: Completion<T>, f: impl FnOnce(T) -> U) -> Completion<U> {
    match c {
        Completion::Busy { deadline } => Completion::Busy { deadline },
        Completion::Refused(e) => Completion::Refused(e),
        Completion::Retired { value, refusal } => Completion::Retired {
            value: f(value),
            refusal,
        },
    }
}

#[cfg(all(test, feature = "std"))]
mod source_tests {
    #[test]
    #[ignore = "requires original T8112 PMP via STELA_TEST_PMP_T8112"]
    fn original_shared_provider_cache_windows_and_operands() {
        use sha2::{Digest, Sha256};
        let bytes = std::fs::read(std::env::var("STELA_TEST_PMP_T8112").unwrap()).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            "b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c"
        );
        // Independent direct input slicing, without the research extractor.
        for (start, end, expected) in [
            (
                0x100caa0,
                0x100cb34,
                "4350fb0cdd70067a87d9e95e835c41d5e6ddce689a5c1f174276f498f573738a",
            ),
            (
                0x100d8f8,
                0x100d914,
                "baa8febeeb28b729b4616668e321555addcec7fa518f13262d245aa45a70ecf2",
            ),
            (
                0x100f8cc,
                0x100f934,
                "6ac27489029c34d2adf6d9a44cef95a31501b5a1963bd61b54895dff7234032b",
            ),
            (
                0x101ba6c,
                0x101bb08,
                "930ad1f6e136e0810c24c3dbcb5e39b4db551775dbf77e06832d7868ac5d00cb",
            ),
            (
                0x1012c8c,
                0x1012d5c,
                "994d42bb5735e2ccdbea3fe6ec4c02beb86493045b5c2f60ef3dfdca1a7fff4f",
            ),
            (
                0x100ed1c,
                0x100ed58,
                "7ffe4a5fa87458f7a30897cbc2bfcd73f4c2ab34886950224e8dffe00f7c5789",
            ),
            (
                0x1035194,
                0x10351a4,
                "baed642339816affb3fe8719792d0e4ce82f12db72b7373d244eaa65445800fe",
            ),
            (
                0x10798c0,
                0x1079920,
                "2ea9ab9198d1638007400cd2c3bef1cc745b864b76011a0e1bc52180ac6452d4",
            ),
        ] {
            assert_eq!(
                hex::encode(Sha256::digest(&bytes[start - 0xfff000..end - 0xfff000])),
                expected
            );
        }
        for (va, word) in [
            (0x100d90c, 0xf9012909u32),
            (0x101ba7c, 0xf9412808u32),
            (0x101ba8c, 0x9ac22156u32),
            (0x101ba94, 0xf9402129u32),
            (0x101bac8, 0xb020161u32),
            (0x101bae4, 0xf900212au32),
            (0x101bb00, 0xa9400500u32),
        ] {
            let offset = va - 0xfff000;
            assert_eq!(
                u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()),
                word
            );
        }
        assert_eq!(&bytes[0x7a8c0..0x7a920], &[0; 96]);
    }
}
