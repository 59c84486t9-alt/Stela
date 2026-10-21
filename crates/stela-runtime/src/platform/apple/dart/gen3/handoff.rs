//! Recovered native-client root construction, distinct from full admission.
//!
//! J873g mBoot file159834..1598d0 validates the configured first-level
//! index before returning root-shadow slot0. The ordinary two-level form
//! requires index16; its explicit three-level flag requires index0. The
//! flag also publishes TCR bit3 at158568..158588. This qualifies the root
//! used by a table walk, not native security, filters or generated faults.
use super::{
    context::{Context, Geometry, PAGE_SHIFT, TableLevel},
    descriptor::Encoding,
};

const TRANSLATE: u32 = 1;
const THREE_LEVEL: u32 = 1 << 3;
const ROOT_SHIFT: u32 = 36;
const ORDINARY_ROOT: u64 = 16;
const ORDINARY_BASE: u64 = ORDINARY_ROOT << ROOT_SHIFT;
const ORDINARY_END: u64 = (ORDINARY_ROOT + 1) << ROOT_SHIFT;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Handoff {
    context: Context,
    encoding: Encoding,
    config: u32,
}

impl Handoff {
    /// Bind the recovered original client revision, complete supported TCR
    /// form and software bounds to a representable root. Unknown controls,
    /// compact handoff modes and bypass still require their own contracts.
    pub fn new(revision: u16, config: u32, context: Context) -> Result<Self, &'static str> {
        let encoding = Encoding::handoff_revision(revision)?;
        if config & !(TRANSLATE | THREE_LEVEL) != 0 {
            return Err("gen3 DART native handoff has unqualified TCR fields");
        }
        if config & TRANSLATE == 0 {
            return Err("gen3 DART native handoff requires the untranslated/BPF contract");
        }
        if Geometry::from_tcr(config) != context.geometry() {
            return Err("gen3 DART native handoff geometry disagrees with its context");
        }
        if context.geometry() == Geometry::TwoLevel {
            let start = u64::from(context.start_page()) << PAGE_SHIFT;
            let end = u64::from(context.end_page()) << PAGE_SHIFT;
            if start < ORDINARY_BASE || end > ORDINARY_END {
                return Err("gen3 DART native two-level root requires the original upper index16");
            }
        }
        // Context already enforces the original 42-bit construction limit.
        // Its three-level addresses therefore have first-level index0 at
        // DVA bits51:47, before CTE/STE/PTE slots are extracted normally.
        Ok(Self {
            context,
            encoding,
            config,
        })
    }

    pub const fn context(self) -> Context {
        self.context
    }

    pub const fn encoding(self) -> Encoding {
        self.encoding
    }

    pub const fn config(self) -> u32 {
        self.config
    }

    pub const fn first_level(self) -> TableLevel {
        match self.context.geometry() {
            Geometry::TwoLevel => TableLevel::Segment,
            Geometry::ThreeLevel => TableLevel::Context,
        }
    }

    /// The original root-index validator returns shadow slot0 after checking
    /// the upper index. It never subtracts vm-base from lower RAM indices.
    pub const fn root_slot(self) -> u16 {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_root_qualification_distinguishes_software_bounds_from_native_roots() {
        for (base, bytes) in [
            (ORDINARY_BASE, 1 << ROOT_SHIFT),
            (ORDINARY_BASE + 0x4000, 0xffff_0000),
            (ORDINARY_END - (1 << 20), 1 << 20),
        ] {
            let context = Context::from_vm_range(base, bytes).unwrap();
            let handoff = Handoff::new(0x300, TRANSLATE, context).unwrap();
            assert_eq!(handoff.context(), context);
            assert_eq!(handoff.encoding(), Encoding::Shift4);
            assert_eq!(handoff.first_level(), TableLevel::Segment);
            assert_eq!(handoff.root_slot(), 0);
        }
        // All are legal software contexts, including a single upper region;
        // none has the original native two-level root index16 throughout.
        for base in [0, ORDINARY_BASE - (1 << 20), ORDINARY_BASE - 0x4000] {
            let context = Context::from_vm_range(base, 1 << 20).unwrap();
            assert!(Handoff::new(0x300, TRANSLATE, context).is_err());
        }
        let context = Context::from_vm_range(ORDINARY_BASE, 3 << 40).unwrap();
        let handoff = Handoff::new(0x300, TRANSLATE | THREE_LEVEL, context).unwrap();
        assert_eq!(handoff.first_level(), TableLevel::Context);
        assert_eq!(handoff.root_slot(), 0);
        assert!(Handoff::new(0x300, TRANSLATE, context).is_err());
    }

    #[test]
    fn root_qualification_does_not_select_a_revision_mode_or_clear_unknown_tcr_fields() {
        let context = Context::from_vm_range(ORDINARY_BASE, 1 << 20).unwrap();
        for revision in [0, 0x101, 0x204, 0x301, 0x302, 0x303, 0xffff] {
            assert!(Handoff::new(revision, TRANSLATE, context).is_err());
        }
        for config in [0, THREE_LEVEL, TRANSLATE | THREE_LEVEL] {
            assert!(Handoff::new(0x300, config, context).is_err());
        }
        for bit in (1..32).filter(|bit| *bit != 3) {
            assert!(Handoff::new(0x300, TRANSLATE | 1 << bit, context).is_err());
        }
    }
}
