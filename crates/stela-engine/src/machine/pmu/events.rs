//! Checked events and counter affinities, independent of event names on
//! later generations. Source pins are in `docs/research/core-pmu.md`.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Event {
    None,
    Cycles,
    Instructions,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum Set {
    M1M2,
    Unqualified,
}

impl Set {
    pub fn programmable(self, counter: usize, selectors: &[Option<u64>; 2]) -> Option<Event> {
        if !matches!(self, Self::M1M2) || !(2..10).contains(&counter) {
            return None;
        }
        // PMESR0: PMC2–5; PMESR1: PMC6–9, four 8-bit selectors each.
        let ordinal = counter - 2;
        let selector = (selectors[ordinal / 4]? >> ((ordinal % 4) * 8)) as u8;
        match selector {
            // XNU's explicit NONE, not a fallback for an unknown event.
            0 => Some(Event::None),
            // Linux's original experimental affinity: every PMC2–9.
            0x02 => Some(Event::Cycles),
            // INST_ALL shares the fixed instruction event only on PMC7.
            0x8c if counter == 7 => Some(Event::Instructions),
            _ => None,
        }
    }
}
