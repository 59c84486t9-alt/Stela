//! Original gen3 software mapping contexts and table geometry.
//!
//! T8152 SPTM constructs end/start page bounds at VA 0270d5280..d52a0,
//! selects TCR bit3 at d7af0..d7b10, validates map ranges at d1648..d16dc,
//! and validates map-table requests at d32c8..d3318. Those are software
//! request rules. They do not establish native out-of-window fault codes,
//! upper TCR security fields, or permission to alias distinct fill regions.
use crate::Result;
use stela_contracts::Refusal;
use stela_contracts::refuse;

pub const PAGE_SHIFT: u32 = 14;
pub const PAGE_BYTES: u64 = 1 << PAGE_SHIFT;
const VA_BITS: u32 = 42;
const VA_LIMIT: u64 = 1 << VA_BITS;
const MIN_VM_BYTES: u64 = 1 << 20;
const MAX_VM_BYTES: u64 = 3 << 40;
const MAX_ALIGNMENT_PAGES: u32 = 64;
const TWO_LEVEL_END_PAGE: u32 = 0x0440_0000;
const SEGMENT_SHIFT: u32 = 25;
const SEGMENT_BYTES: u64 = 1 << SEGMENT_SHIFT;
const CONTEXT_SHIFT: u32 = 36;
const INDEX: u64 = 0x7ff;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Geometry {
    TwoLevel,
    ThreeLevel,
}

/// The map-table ABI's target level, distinct from fault-header levels.
/// Two-level mode starts at Segment; three-level mode starts at Context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TableLevel {
    Context = 0,
    Segment = 1,
    Page = 2,
}

impl TryFrom<u8> for TableLevel {
    type Error = Refusal;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Context),
            1 => Ok(Self::Segment),
            2 => Ok(Self::Page),
            _ => Err(refuse!(
                "gen3 DART map-table target level is outside the native ABI"
            )),
        }
    }
}

/// The explicit original exception to the software VM-bound check. This
/// never authorizes DMA outside a context or weakens its native fault gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundsPolicy {
    Strict,
    NoncompliantDeadMappings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Indices {
    context: Option<u16>,
    segment: u16,
    page: u16,
    offset: u16,
}

impl Indices {
    pub const fn context(self) -> Option<u16> {
        self.context
    }

    pub const fn segment(self) -> u16 {
        self.segment
    }

    pub const fn page(self) -> u16 {
        self.page
    }

    pub const fn offset(self) -> u16 {
        self.offset
    }
}

impl Geometry {
    pub const fn from_tcr(config: u32) -> Self {
        if config & (1 << 3) != 0 {
            Self::ThreeLevel
        } else {
            Self::TwoLevel
        }
    }

    fn indices(self, dva: u64) -> Indices {
        Indices {
            context: (self == Self::ThreeLevel).then_some(((dva >> CONTEXT_SHIFT) & INDEX) as u16),
            segment: ((dva >> SEGMENT_SHIFT) & INDEX) as u16,
            page: ((dva >> PAGE_SHIFT) & INDEX) as u16,
            offset: (dva & (PAGE_BYTES - 1)) as u16,
        }
    }

    /// The existing component's explicitly bounded zero-context form.
    pub(super) fn zero_indices(self, dva: u64) -> Result<Indices> {
        let bits = match self {
            Self::TwoLevel => CONTEXT_SHIFT,
            Self::ThreeLevel => VA_BITS,
        };
        if dva >> bits != 0 {
            return Err(refuse!(
                "gen3 DART address context is outside the recovered table form"
            ));
        }
        Ok(self.indices(dva))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context {
    start_page: u32,
    end_page: u32,
    geometry: Geometry,
    alignment_trim: u32,
}

impl Context {
    /// The original global VM construction with no vm-alignment property.
    pub fn from_vm_range(base: u64, bytes: u64) -> Result<Self> {
        Self::from_vm_range_aligned(base, bytes, None)
    }

    /// The original global VM construction, including page rounding and
    /// explicit vm-alignment. Alignment rounds start up and trims the same
    /// number of pages from end; it does not expand the VM window.
    pub fn from_vm_range_aligned(
        base: u64,
        bytes: u64,
        alignment_pages: Option<u32>,
    ) -> Result<Self> {
        if base >= VA_LIMIT || !(MIN_VM_BYTES..=MAX_VM_BYTES).contains(&bytes) {
            return Err(refuse!(
                "gen3 DART VM range exceeds the original global construction bounds"
            ));
        }
        let end = base
            .checked_add(bytes)
            .filter(|&end| end <= VA_LIMIT)
            .ok_or(refuse!(
                "gen3 DART VM range end exceeds its native address width"
            ))?;
        let start_page = (base >> PAGE_SHIFT) as u32;
        let end_page = (end >> PAGE_SHIFT) as u32;
        let alignment_trim = match alignment_pages {
            None => 0,
            Some(alignment) if alignment.is_power_of_two() && alignment <= MAX_ALIGNMENT_PAGES => {
                let remainder = start_page % alignment;
                if remainder == 0 {
                    0
                } else {
                    alignment - remainder
                }
            }
            Some(_) => {
                return Err(refuse!(
                    "gen3 DART vm-alignment must be a power of two in 1..64 pages"
                ));
            }
        };
        let start_page = start_page + alignment_trim;
        let end_page = end_page
            .checked_sub(alignment_trim)
            .ok_or(refuse!("gen3 DART vm-alignment exhausts its VM window"))?;
        Self::from_pages(start_page, end_page, alignment_trim)
    }

    fn from_pages(start_page: u32, end_page: u32, alignment_trim: u32) -> Result<Self> {
        if start_page >= end_page || u64::from(end_page) > VA_LIMIT >> PAGE_SHIFT {
            return Err(refuse!("gen3 DART context has invalid native page bounds"));
        }
        Ok(Self {
            start_page,
            end_page,
            geometry: if end_page > TWO_LEVEL_END_PAGE {
                Geometry::ThreeLevel
            } else {
                Geometry::TwoLevel
            },
            alignment_trim,
        })
    }

    /// Derive one SID's shadow bounds from the original 64-bit per-SID
    /// vm-base/vm-size values. Dynamic SID assignment permits only the
    /// inherited bounds. A changed range must fit inside the global range,
    /// then keep the original end-padding adjustment for vm-alignment.
    pub fn for_sid(
        self,
        base: Option<u64>,
        bytes: Option<u64>,
        dynamic_assignment: bool,
    ) -> Result<Self> {
        if base.is_some_and(|base| base >= VA_LIMIT)
            || bytes.is_some_and(|bytes| bytes >> PAGE_SHIFT > MAX_VM_BYTES >> PAGE_SHIFT)
        {
            return Err(refuse!(
                "gen3 DART per-SID VM fields exceed the native construction width"
            ));
        }
        let start = base.map_or(self.start_page, |base| (base >> PAGE_SHIFT) as u32);
        let count = bytes.map_or(self.end_page - self.start_page, |bytes| {
            (bytes >> PAGE_SHIFT) as u32
        });
        if start == self.start_page && count == self.end_page - self.start_page {
            return Ok(self);
        }
        if dynamic_assignment {
            return Err(refuse!(
                "gen3 DART dynamic SID assignment forbids per-SID VM overrides"
            ));
        }
        let end = start
            .checked_add(count)
            .ok_or(refuse!("gen3 DART per-SID VM endpoint overflows"))?;
        if start < self.start_page
            || end > self.end_page
            || !(MIN_VM_BYTES >> PAGE_SHIFT..=MAX_VM_BYTES >> PAGE_SHIFT)
                .contains(&u64::from(count))
        {
            return Err(refuse!(
                "gen3 DART per-SID VM override exceeds its global bounds or native size"
            ));
        }
        let end = end.checked_sub(self.alignment_trim).ok_or(refuse!(
            "gen3 DART per-SID alignment exhausts its VM window"
        ))?;
        Self::from_pages(start, end, self.alignment_trim)
    }

    pub const fn geometry(self) -> Geometry {
        self.geometry
    }

    pub const fn start_page(self) -> u32 {
        self.start_page
    }

    pub const fn end_page(self) -> u32 {
        self.end_page
    }

    fn validate_address(self, dva: u64, policy: BoundsPolicy) -> Result<()> {
        if dva >= VA_LIMIT {
            return Err(refuse!(
                "gen3 DART request exceeds its native virtual address width"
            ));
        }
        let page = (dva >> PAGE_SHIFT) as u32;
        if policy == BoundsPolicy::Strict && !(self.start_page..self.end_page).contains(&page) {
            return Err(refuse!(
                "gen3 DART request is outside its software VM page bounds"
            ));
        }
        Ok(())
    }

    /// Validate the original MAP ABI's start and exclusive endpoint. The
    /// original checks both endpoint pages strictly below end_page, including
    /// when the endpoint is page aligned. No hardware fault is inferred.
    pub fn map(self, dva: u64, bytes: u64, policy: BoundsPolicy) -> Result<MapRequest> {
        if bytes == 0 || bytes > SEGMENT_BYTES {
            return Err(refuse!(
                "gen3 DART map size is outside the original 1..32 MiB bounds"
            ));
        }
        self.validate_address(dva, policy)?;
        let end = dva
            .checked_add(bytes)
            .ok_or(refuse!("gen3 DART map endpoint overflows"))?;
        self.validate_address(end, policy)?;
        let segment_end = (dva & !(SEGMENT_BYTES - 1)) + SEGMENT_BYTES;
        if end > segment_end {
            return Err(refuse!("gen3 DART map crosses a segment table boundary"));
        }
        let entries = (bytes + (dva & (PAGE_BYTES - 1))).div_ceil(PAGE_BYTES);
        if entries * 8 > PAGE_BYTES {
            return Err(refuse!(
                "gen3 DART map exceeds the original page-sized scratch table"
            ));
        }
        Ok(MapRequest {
            dva,
            end,
            entries: entries as u16,
            indices: self.geometry.indices(dva),
        })
    }

    pub fn map_table(
        self,
        dva: u64,
        level: TableLevel,
        policy: BoundsPolicy,
    ) -> Result<TableRequest> {
        self.validate_address(dva, policy)?;
        let indices = self.geometry.indices(dva);
        // MAP_TABLE names the table being installed, so its slot belongs
        // to the parent level. The root slot is the SID shadow's entry0,
        // not another RAM lookup or a CTE index.
        let (slot, root) = match (self.geometry, level) {
            (Geometry::TwoLevel, TableLevel::Context) => {
                return Err(refuse!("gen3 DART two-level mode has no context table"));
            }
            (Geometry::ThreeLevel, TableLevel::Context)
            | (Geometry::TwoLevel, TableLevel::Segment) => (0, true),
            (Geometry::ThreeLevel, TableLevel::Segment) => {
                (indices.context.expect("three-level indices"), false)
            }
            (_, TableLevel::Page) => (indices.segment, false),
        };
        Ok(TableRequest {
            dva,
            level,
            slot,
            root,
            indices,
        })
    }

    /// Check a single DMA page before extracting any index. Absolute DVA
    /// indices match the original walk: vm-base is never subtracted. Refuse
    /// two-level windows spanning different upper fill regions rather than
    /// silently folding their addresses. Native handling there is unresolved.
    pub(super) fn transfer(self, dva: u64, last: u64) -> Result<Indices> {
        if last < dva || dva / PAGE_BYTES != last / PAGE_BYTES {
            return Err(refuse!(
                "gen3 DART transfer is not within one ordered translation page"
            ));
        }
        self.validate_address(dva, BoundsPolicy::Strict)?;
        self.validate_address(last, BoundsPolicy::Strict)?;
        if self.geometry == Geometry::TwoLevel {
            let first_region = u64::from(self.start_page) >> (CONTEXT_SHIFT - PAGE_SHIFT);
            let last_region = u64::from(self.end_page - 1) >> (CONTEXT_SHIFT - PAGE_SHIFT);
            if first_region != last_region {
                return Err(refuse!(
                    "gen3 DART two-level window spans unqualified upper fill regions"
                ));
            }
        }
        Ok(self.geometry.indices(dva))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapRequest {
    dva: u64,
    end: u64,
    entries: u16,
    indices: Indices,
}

impl MapRequest {
    pub const fn dva(self) -> u64 {
        self.dva
    }
    pub const fn end(self) -> u64 {
        self.end
    }
    pub const fn entries(self) -> u16 {
        self.entries
    }
    pub const fn indices(self) -> Indices {
        self.indices
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableRequest {
    dva: u64,
    level: TableLevel,
    slot: u16,
    root: bool,
    indices: Indices,
}

impl TableRequest {
    /// The original publication path is selected by PARAMS@4 bit4, TCR
    /// three-level mode and target Segment. This extracts that capability;
    /// it does not validate unrelated PARAMS fields or admit a native profile.
    pub fn context_invalidation(
        self,
        sid: usize,
        parameters4: u32,
    ) -> Result<Option<super::tlbi::ContextCommand>> {
        if sid > usize::from(u8::MAX) {
            return Err(refuse!(
                "gen3 DART publication SID exceeds its native command field"
            ));
        }
        if parameters4 & (1 << 4) == 0 || self.level != TableLevel::Segment || self.root {
            return Ok(None);
        }
        super::tlbi::ContextCommand::new(sid, self.slot).map(Some)
    }

    pub const fn dva(self) -> u64 {
        self.dva
    }
    pub const fn slot(self) -> u16 {
        self.slot
    }
    pub const fn is_root(self) -> bool {
        self.root
    }
    pub const fn indices(self) -> Indices {
        self.indices
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_global_ranges_select_geometry_from_end_pages_and_keep_page_rounding() {
        let usb = Context::from_vm_range(0x10000004000, 0xffff0000).unwrap();
        assert_eq!(usb.geometry(), Geometry::TwoLevel);
        assert_eq!(usb.start_page(), 0x0400_0001);
        let display = Context::from_vm_range(0x10000000000, 0x30000000000).unwrap();
        assert_eq!(display.geometry(), Geometry::ThreeLevel);
        assert_eq!(display.end_page(), 1 << 28);
        let below = Context::from_pages(TWO_LEVEL_END_PAGE - 64, TWO_LEVEL_END_PAGE, 0).unwrap();
        let above =
            Context::from_pages(TWO_LEVEL_END_PAGE - 64, TWO_LEVEL_END_PAGE + 1, 0).unwrap();
        assert_eq!(below.geometry(), Geometry::TwoLevel);
        assert_eq!(above.geometry(), Geometry::ThreeLevel);
        let rounded = Context::from_vm_range(0x10000004001, MIN_VM_BYTES + 2).unwrap();
        assert_eq!(rounded.start_page(), usb.start_page());
        assert_eq!(rounded.end_page(), usb.start_page() + 64);
        for (base, bytes) in [
            (0, 0),
            (0, MIN_VM_BYTES - 1),
            (0, MAX_VM_BYTES + 1),
            (VA_LIMIT, MIN_VM_BYTES),
            (VA_LIMIT - PAGE_BYTES, MIN_VM_BYTES),
            (u64::MAX, u64::MAX),
        ] {
            assert!(Context::from_vm_range(base, bytes).is_err());
        }
        assert!(Context::from_pages(2, 2, 0).is_err());
        assert!(Context::from_pages(2, (1 << 28) + 1, 0).is_err());
    }

    #[test]
    fn original_alignment_trims_both_bounds_and_survives_per_sid_construction() {
        let base = 0x10000004000;
        let bytes = 16 * MIN_VM_BYTES;
        let plain = Context::from_vm_range(base, bytes).unwrap();
        let aligned = Context::from_vm_range_aligned(base, bytes, Some(64)).unwrap();
        assert_eq!(aligned.start_page(), plain.start_page() + 63);
        assert_eq!(aligned.end_page(), plain.end_page() - 63);
        assert_eq!(aligned.start_page() % 64, 0);
        assert_eq!(aligned.for_sid(None, None, false), Ok(aligned));
        let sid = aligned
            .for_sid(None, Some(2 * MIN_VM_BYTES), false)
            .unwrap();
        assert_eq!(sid.start_page(), aligned.start_page());
        assert_eq!(sid.end_page(), aligned.start_page() + 128 - 63);
        // Per-SID overrides preserve the global trim; they do not round
        // their start to a newly chosen boundary.
        let sid = aligned
            .for_sid(Some(base + 64 * PAGE_BYTES), Some(2 * MIN_VM_BYTES), false)
            .unwrap();
        assert_eq!(sid.start_page() % 64, 1);
        assert_eq!(sid.end_page() - sid.start_page(), 65);
        for alignment in [0, 3, 63, 65, 128] {
            assert!(Context::from_vm_range_aligned(base, bytes, Some(alignment)).is_err());
        }
        for alignment in [1, 2, 4, 8, 16, 32, 64] {
            let aligned_base = base - PAGE_BYTES;
            assert_eq!(
                Context::from_vm_range_aligned(aligned_base, bytes, Some(alignment)),
                Context::from_vm_range(aligned_base, bytes)
            );
        }
        assert!(Context::from_vm_range_aligned(base, MIN_VM_BYTES, Some(64)).is_err());
    }

    #[test]
    fn original_per_sid_bounds_select_their_own_geometry_and_dynamic_assignment_policy() {
        let base = 0x10000000000;
        let display = Context::from_vm_range(base, MAX_VM_BYTES).unwrap();
        let sid = display.for_sid(Some(base), Some(1 << 36), false).unwrap();
        assert_eq!(display.geometry(), Geometry::ThreeLevel);
        assert_eq!(sid.geometry(), Geometry::TwoLevel);
        assert_eq!(sid.end_page(), TWO_LEVEL_END_PAGE);
        assert_eq!(display.for_sid(None, None, true), Ok(display));
        assert_eq!(
            display.for_sid(Some(base), Some(MAX_VM_BYTES + PAGE_BYTES - 1), true),
            Ok(display)
        );
        assert!(display.for_sid(None, Some(1 << 36), true).is_err());
        let rounded = display
            .for_sid(Some(base + PAGE_BYTES + 1), Some(MIN_VM_BYTES + 1), false)
            .unwrap();
        assert_eq!(rounded.start_page(), display.start_page() + 1);
        assert_eq!(rounded.end_page() - rounded.start_page(), 64);
        for (base, bytes) in [
            (Some(base - PAGE_BYTES), Some(MIN_VM_BYTES)),
            (Some(VA_LIMIT - PAGE_BYTES), Some(MIN_VM_BYTES)),
            (Some(VA_LIMIT), None),
            (None, Some(0)),
            (None, Some(MIN_VM_BYTES - 1)),
            (None, Some(MAX_VM_BYTES + PAGE_BYTES)),
            (None, Some(u64::MAX)),
        ] {
            assert!(display.for_sid(base, bytes, false).is_err());
        }
        assert!(sid.transfer(base + (1 << 36), base + (1 << 36)).is_err());
        assert_eq!(display.geometry(), Geometry::ThreeLevel);
    }

    #[test]
    fn original_map_endpoint_and_segment_rules_are_distinct_from_dma_page_qualification() {
        let base = 0x10000000000;
        let context = Context::from_vm_range(base, 4 * SEGMENT_BYTES).unwrap();
        let request = context
            .map(base + PAGE_BYTES - 1, 2, BoundsPolicy::Strict)
            .unwrap();
        assert_eq!(request.dva(), base + PAGE_BYTES - 1);
        assert_eq!(request.end(), base + PAGE_BYTES + 1);
        assert_eq!(request.entries(), 2);
        assert_eq!(request.indices().page(), 0);
        assert!(context.map(base, 0, BoundsPolicy::Strict).is_err());
        assert!(
            context
                .map(base, SEGMENT_BYTES + 1, BoundsPolicy::Strict)
                .is_err()
        );
        assert!(
            context
                .map(base + SEGMENT_BYTES - 1, 2, BoundsPolicy::Strict)
                .is_err()
        );
        assert_eq!(
            context
                .map(base, SEGMENT_BYTES, BoundsPolicy::Strict)
                .unwrap()
                .entries(),
            2048
        );
        let end = u64::from(context.end_page()) << PAGE_SHIFT;
        assert!(context.map(end - 1, 1, BoundsPolicy::Strict).is_err());
        assert!(context.transfer(end - 1, end - 1).is_ok());
        assert!(context.map(base - 1, 1, BoundsPolicy::Strict).is_err());
        assert!(
            context
                .map(base - PAGE_BYTES, 1, BoundsPolicy::NoncompliantDeadMappings)
                .is_ok()
        );
        assert!(
            context
                .transfer(base - PAGE_BYTES, base - PAGE_BYTES)
                .is_err()
        );
        assert!(
            context
                .map(VA_LIMIT - 1, 1, BoundsPolicy::NoncompliantDeadMappings)
                .is_err()
        );
    }

    #[test]
    fn map_table_targets_use_absolute_indices_and_the_native_geometry_level_set() {
        let dva = 0x10000100000;
        let context = Context::from_vm_range(dva, 0x3fe00000).unwrap();
        assert!(
            context
                .map_table(dva, TableLevel::Context, BoundsPolicy::Strict)
                .is_err()
        );
        let segment = context
            .map_table(dva, TableLevel::Segment, BoundsPolicy::Strict)
            .unwrap();
        let page = context
            .map_table(dva, TableLevel::Page, BoundsPolicy::Strict)
            .unwrap();
        assert!(segment.is_root());
        assert_eq!(segment.slot(), 0);
        assert!(!page.is_root());
        assert_eq!(page.slot(), 0);
        assert_eq!(page.indices().page(), 64);
        assert_eq!(page.dva(), dva);
        assert!(
            context
                .map_table(dva - PAGE_BYTES, TableLevel::Page, BoundsPolicy::Strict)
                .is_err()
        );
        let context = Context::from_vm_range(0x10000000000, 0x30000000000).unwrap();
        let request = context
            .map_table(0x21002004000, TableLevel::Context, BoundsPolicy::Strict)
            .unwrap();
        assert!(request.is_root());
        assert_eq!(request.slot(), 0);
        assert_eq!(request.indices().context(), Some(33));
        assert_eq!(request.indices().segment(), 1);
        assert_eq!(request.indices().page(), 1);
        assert_eq!(
            context
                .map_table(request.dva(), TableLevel::Segment, BoundsPolicy::Strict)
                .unwrap()
                .slot(),
            33
        );
        assert_eq!(
            context
                .map_table(request.dva(), TableLevel::Page, BoundsPolicy::Strict)
                .unwrap()
                .slot(),
            1
        );
        for raw in [3, 255] {
            assert!(TableLevel::try_from(raw).is_err());
        }
    }

    #[test]
    fn upper_fill_region_aliases_refuse_before_indices_can_escape_the_context() {
        let context = Context::from_vm_range(0x10000004000, 0xffff0000).unwrap();
        let dva = 0x10002004007;
        let indices = context.transfer(dva, dva + 3).unwrap();
        assert_eq!(indices.context(), None);
        assert_eq!(
            (indices.segment(), indices.page(), indices.offset()),
            (1, 1, 7)
        );
        assert!(
            context
                .transfer(dva ^ (1 << 40), (dva ^ (1 << 40)) + 3)
                .is_err()
        );
        assert!(context.transfer(dva, dva - 1).is_err());
        assert!(context.transfer(dva, dva + PAGE_BYTES).is_err());
        let crossing = Context::from_vm_range((1 << 40) - PAGE_BYTES, MIN_VM_BYTES).unwrap();
        assert_eq!(crossing.geometry(), Geometry::TwoLevel);
        assert!(crossing.map(1 << 40, 1, BoundsPolicy::Strict).is_ok());
        assert_eq!(
            crossing.transfer(1 << 40, 1 << 40),
            Err(refuse!(
                "gen3 DART two-level window spans unqualified upper fill regions"
            ))
        );
    }

    #[test]
    fn publication_invalidation_requires_the_recovered_capability_and_parent_table() {
        let context = Context::from_vm_range(0x10000000000, 0x30000000000).unwrap();
        for slot in [16, 33, 63] {
            let dva = (slot as u64) << CONTEXT_SHIFT;
            let segment = context
                .map_table(dva, TableLevel::Segment, BoundsPolicy::Strict)
                .unwrap();
            for sid in [0, 1, 255] {
                let command = segment.context_invalidation(sid, 1 << 4).unwrap().unwrap();
                assert_eq!(command.sid() as usize, sid);
                assert_eq!(u16::from(command.slot()), segment.slot());
                assert_eq!(
                    command.word(),
                    (sid as u32) << 24 | (slot as u32) << 12 | slot as u32
                );
                assert_eq!(segment.context_invalidation(sid, 0), Ok(None));
            }
            for target in [TableLevel::Context, TableLevel::Page] {
                let request = context
                    .map_table(dva, target, BoundsPolicy::Strict)
                    .unwrap();
                assert_eq!(request.context_invalidation(255, 1 << 4), Ok(None));
            }
            assert!(segment.context_invalidation(256, 0).is_err());
        }
        let context = context.for_sid(None, Some(1 << 36), false).unwrap();
        let request = context
            .map_table(0x10000000000, TableLevel::Segment, BoundsPolicy::Strict)
            .unwrap();
        assert_eq!(request.context_invalidation(255, 1 << 4), Ok(None));
    }
}
