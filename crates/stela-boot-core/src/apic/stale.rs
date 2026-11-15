//! Vectors left in service with no handler running.
//!
//! The engine's interrupt entry never nests: a second ordinary entry while
//! one runs halts (`stela_xstate_refuse`). So inside the timer's handler,
//! after its own EOI, and in process code, every bit still set in the
//! in-service registers belongs to no running handler. Such a bit holds
//! every vector of its class and below until something ends it: a timer
//! below it never arrives. Linux ends in-service bits it finds when it sets
//! a local APIC up (`apic_pending_intr_clear`, arch/x86/kernel/apic/apic.c),
//! one EOI each, at most 512; the engine does the same wherever it finds
//! one, and reports each vector once.

/// Processor priority: the higher of the task priority's class and that of
/// the highest vector in service (Intel SDM Vol. 3A 11.8.3.1).
pub const PPR: u32 = 0xa0;

/// Whether the processor priority `ppr` is in a higher class than the task
/// priority `tpr`: then a vector is in service. A caller that runs no
/// handler, or only its own whose EOI it already wrote, has found one left
/// behind. One register read, so the timer can ask each time.
pub fn holds_stale(ppr: u32, tpr: u32) -> bool {
    ppr & 0xf0 > tpr & 0xf0
}

/// End every vector in service, highest first, one EOI each as Linux does,
/// at most 256: `read` reads a local APIC register by offset, `eoi` writes
/// the EOI register. Returns the vectors ended, vector 0 in bit 0 of the
/// first word. An unreadable register (all ones) ends nothing more.
///
/// The caller runs no handler whose EOI is still due (see the module).
pub fn end_stale(mut read: impl FnMut(u32) -> u32, mut eoi: impl FnMut()) -> [u32; 8] {
    let mut ended = [0u32; 8];
    for _ in 0..256 {
        let Some(vector) = highest(&mut read) else {
            break;
        };
        eoi();
        ended[usize::from(vector / 32)] |= 1 << (vector % 32);
    }
    ended
}

/// The highest vector in service, `None` when none is or a word is
/// unreadable.
fn highest(read: &mut impl FnMut(u32) -> u32) -> Option<u8> {
    for word in (0..8u32).rev() {
        let bits = read(super::ISR + 0x10 * word);
        if bits == u32::MAX {
            return None;
        }
        if bits != 0 {
            return Some((word * 32 + 31 - bits.leading_zeros()) as u8);
        }
    }
    None
}

/// The vectors set in `bits` (vector 0 in bit 0 of the first word),
/// lowest first.
pub fn vectors(bits: &[u32; 8]) -> impl Iterator<Item = u8> + '_ {
    (0..=255u8).filter(|&vector| bits[usize::from(vector / 32)] & 1 << (vector % 32) != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    /// A local APIC's in-service registers, whose EOI ends the highest.
    struct InService(Cell<[u32; 8]>);

    impl InService {
        fn new(vectors: &[u8]) -> Self {
            let mut bits = [0; 8];
            for &vector in vectors {
                bits[usize::from(vector / 32)] |= 1 << (vector % 32);
            }
            Self(Cell::new(bits))
        }
        fn read(&self, offset: u32) -> u32 {
            let word = offset.checked_sub(super::super::ISR).unwrap() / 0x10;
            self.0.get()[word as usize]
        }
        fn eoi(&self) {
            let mut bits = self.0.get();
            if let Some(word) = (0..8).rev().find(|&word| bits[word] != 0) {
                bits[word] &= !(1 << (31 - bits[word].leading_zeros()));
            }
            self.0.set(bits);
        }
    }

    #[test]
    fn a_device_vector_left_in_service_is_ended_and_named() {
        // The report: 0x62 in service, nothing running its handler.
        let apic = InService::new(&[0x62]);
        let ended = end_stale(|offset| apic.read(offset), || apic.eoi());
        assert_eq!(vectors(&ended).collect::<Vec<_>>(), [0x62]);
        assert_eq!(apic.0.get(), [0; 8]);
    }

    #[test]
    fn every_vector_in_service_is_ended_highest_first() {
        let apic = InService::new(&[0x40, 0x62, 0xfd]);
        let mut order = Vec::new();
        let ended = end_stale(
            |offset| apic.read(offset),
            || {
                order.push(highest(&mut |offset| apic.read(offset)).unwrap());
                apic.eoi();
            },
        );
        assert_eq!(order, [0xfd, 0x62, 0x40]);
        assert_eq!(vectors(&ended).collect::<Vec<_>>(), [0x40, 0x62, 0xfd]);
    }

    #[test]
    fn nothing_in_service_writes_no_eoi_and_an_unreadable_register_stops() {
        let apic = InService::new(&[]);
        let mut eois = 0;
        assert_eq!(end_stale(|offset| apic.read(offset), || eois += 1), [0; 8]);
        assert_eq!(eois, 0);
        // A register that reads all ones is no vector: no EOI is written.
        assert_eq!(end_stale(|_| u32::MAX, || eois += 1), [0; 8]);
        assert_eq!(eois, 0);
        // A register an EOI never changes ends after 256 EOIs, as Linux's
        // bounded loop does.
        let ended = end_stale(|offset| u32::from(offset == 0x130) << 2, || eois += 1);
        assert_eq!(eois, 256);
        assert_eq!(vectors(&ended).collect::<Vec<_>>(), [0x62]);
    }

    #[test]
    fn the_processor_priority_shows_a_vector_in_service_above_the_task_priority() {
        // Nothing in service: PPR is the task priority.
        assert!(!holds_stale(0x00, 0x00));
        assert!(!holds_stale(0xe0, 0xe0));
        // 0x62 in service with TPR 0: PPR 0x60 (its low nibble undefined).
        assert!(holds_stale(0x60, 0x00));
        assert!(holds_stale(0x6f, 0x05));
        // A task priority at or above the vector's class hides it, and also
        // already blocks that class.
        assert!(!holds_stale(0x60, 0x60));
    }
}
