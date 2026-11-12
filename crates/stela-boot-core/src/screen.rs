//! Geometry, colours and text the mount's screens compute before drawing.
use alloc::{format, string::String};
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, AtomicU8, Ordering},
};

const IDLE: u8 = 0;
const ACTIVE: u8 = 1;
const RETIRED: u8 = 2;

/// Exclusive, nonblocking admission for a framebuffer shared by copied views.
/// The actual writer must finish its CPU stores before dropping its permit.
pub struct Access(AtomicU8);

impl Access {
    pub const fn new() -> Self {
        Self(AtomicU8::new(IDLE))
    }

    pub fn enter(&self) -> Option<Permit<'_>> {
        self.0
            .compare_exchange(IDLE, ACTIVE, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| Permit { gate: self })
    }

    pub fn is_retired(&self) -> bool {
        self.0.load(Ordering::Acquire) == RETIRED
    }

    /// Close admission only after the current writer has acknowledged return.
    pub fn retire(&self) -> bool {
        matches!(
            self.0
                .compare_exchange(IDLE, RETIRED, Ordering::AcqRel, Ordering::Acquire),
            Ok(_) | Err(RETIRED)
        )
    }
}

impl Default for Access {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Permit<'a> {
    gate: &'a Access,
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        self.gate.0.store(IDLE, Ordering::Release);
    }
}

/// The screen's text state, which any processor may reach: the boot PE's
/// reports, and the host drivers' waits on whichever processor runs them.
/// One at a time: a marker tick that finds it in use skips its frame, as a
/// firmware timer tick that interrupts a draw does, while a report waits a
/// bounded time for another processor's turn to end. A `RefCell` is not
/// enough, as two processors updating its borrow count at once can leave
/// it counting a borrow nobody holds, which freezes the screen for the
/// rest of the boot.
pub struct Exclusive<T> {
    busy: AtomicBool,
    value: UnsafeCell<T>,
}

// SAFETY: `busy` admits one processor at a time to `value`, which moves
// between them only through `with_until`'s exclusive borrow.
unsafe impl<T: Send> Sync for Exclusive<T> {}

impl<T> Exclusive<T> {
    pub const fn new(value: T) -> Self {
        Self {
            busy: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    /// Run `f` on the value unless another processor, or this one further
    /// up its stack, has it now.
    pub fn try_with<R>(&self, f: impl FnOnce(&mut T) -> R) -> Option<R> {
        self.with_until(|| true, f)
    }

    /// Run `f` on the value once it is free, asking `give_up` after each
    /// failed try whether to stop waiting: the holder may be this processor
    /// further up its stack, which never lets it go while this one waits.
    pub fn with_until<R>(
        &self,
        mut give_up: impl FnMut() -> bool,
        f: impl FnOnce(&mut T) -> R,
    ) -> Option<R> {
        struct Release<'a>(&'a AtomicBool);
        impl Drop for Release<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        while self
            .busy
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            if give_up() {
                return None;
            }
            core::hint::spin_loop();
        }
        let _release = Release(&self.busy);
        // SAFETY: `busy` was false and is now ours until `_release` drops,
        // so this is the only reference to the value.
        Some(f(unsafe { &mut *self.value.get() }))
    }
}

/// Screen pixels per page unit: pages are laid out for about 720 rows.
pub fn scale(rows: usize) -> usize {
    (rows / 720).clamp(1, 4)
}

/// The first of `count` rows to show so that `selected` is among `fits`.
pub fn window(selected: usize, count: usize, fits: usize) -> usize {
    selected
        .saturating_sub(fits - 1)
        .min(count.saturating_sub(fits))
}

/// `completed` of `total` as a percentage rounded down, so 100 needs
/// completion; `None` for an unknown or inconsistent total. Wide
/// intermediates keep full-width byte counts exact.
pub fn percentage(completed: u64, total: u64) -> Option<u8> {
    if total == 0 || completed > total {
        return None;
    }
    let completed = u128::from(completed);
    let total = u128::from(total);
    Some((completed * 100 / total) as u8)
}

const GB: u64 = 1_000_000_000;

/// `bytes` as people read disk sizes: decimal units, three figures.
pub fn disk_size(bytes: u64) -> String {
    let tenths = |unit: u64| (bytes * 10 + unit / 2) / unit;
    match bytes {
        b if b >= 1000 * GB => {
            let t = tenths(1000 * GB);
            format!("{}.{} TB", t / 10, t % 10)
        }
        b if b >= 10 * GB => format!("{} GB", (b + GB / 2) / GB),
        b if b >= GB => {
            let t = tenths(GB);
            format!("{}.{} GB", t / 10, t % 10)
        }
        b => format!("{} MB", (b + 500_000) / 1_000_000),
    }
}

/// The logo at (`u`, `v`) of its unit square: a rounded square split by an
/// S curve into a blue half and an orange half, each lighter at the top.
/// `None` outside it and in the gap between the halves.
pub fn logo_pixel(u: f32, v: f32) -> Option<u32> {
    const RADIUS: f32 = 0.2;
    // Outside a rounded corner.
    let cx = u.clamp(RADIUS, 1.0 - RADIUS);
    let cy = v.clamp(RADIUS, 1.0 - RADIUS);
    let (dx, dy) = (u - cx, v - cy);
    if !(0.0..1.0).contains(&u) || !(0.0..1.0).contains(&v) || dx * dx + dy * dy > RADIUS * RADIUS {
        return None;
    }
    // One period of a sine, from two parabolas.
    let t = 2.0 * v;
    let wave = if t < 1.0 {
        4.0 * t * (1.0 - t)
    } else {
        -4.0 * (t - 1.0) * (2.0 - t)
    };
    let side = u - (0.5 - 0.12 * wave);
    if side.abs() < 0.022 {
        return None;
    }
    let (top, bottom) = if side < 0.0 {
        (0x5fe3c8, 0x2f6fe0)
    } else {
        (0xffc46b, 0xe2522a)
    };
    Some(mix(top, bottom, v))
}

/// `from` blended toward `to` by `amount`, channel by channel.
fn mix(from: u32, to: u32, amount: f32) -> u32 {
    (0..3).fold(0, |pixel, channel| {
        let shift = 16 - 8 * channel;
        let (a, b) = (
            ((from >> shift) & 0xff) as f32,
            ((to >> shift) & 0xff) as f32,
        );
        (pixel << 8) | (a + (b - a) * amount + 0.5) as u32
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retirement_requires_the_writer_to_return_and_permanently_closes_admission() {
        let access = Access::new();
        let writer = access.enter().unwrap();
        assert!(access.enter().is_none());
        assert!(!access.retire());
        assert!(!access.is_retired());
        drop(writer);
        assert!(access.retire());
        assert!(access.is_retired());
        assert!(access.enter().is_none());
        assert!(access.retire());
    }

    #[test]
    fn exclusive_state_skips_a_nested_change_and_is_free_again_after_one() {
        let state = Exclusive::new(0u32);
        let nested = state.try_with(|value| {
            *value += 1;
            state.try_with(|value| *value += 10)
        });
        assert_eq!(nested, Some(None));
        assert_eq!(state.try_with(|value| *value), Some(1));
    }

    /// A report waits out another processor's turn instead of skipping,
    /// and gives up on a holder that never lets go.
    #[test]
    fn exclusive_state_waits_for_a_turn_and_gives_up_on_a_stuck_holder() {
        use std::{sync::Arc, sync::mpsc, thread};
        let state = Arc::new(Exclusive::new(0u32));
        let (taken, take) = mpsc::channel();
        let (release, released) = mpsc::channel::<()>();
        let holder = {
            let state = Arc::clone(&state);
            thread::spawn(move || {
                state.try_with(|value| {
                    taken.send(()).unwrap();
                    released.recv().unwrap();
                    *value += 1;
                })
            })
        };
        take.recv().unwrap();
        assert_eq!(state.try_with(|value| *value), None);
        let mut tries = 0;
        let stuck = state.with_until(
            || {
                tries += 1;
                tries > 3
            },
            |value| *value,
        );
        assert_eq!((stuck, tries), (None, 4));
        let mut release = Some(release);
        let seen = state.with_until(
            || {
                if let Some(release) = release.take() {
                    release.send(()).unwrap();
                }
                false
            },
            |value| *value,
        );
        assert_eq!(seen, Some(1));
        assert_eq!(holder.join().unwrap(), Some(()));
    }

    /// Processors that update the state at once never lose it: every
    /// change either lands or is skipped, and the state is free after all
    /// of them, where a `RefCell`'s count could stay borrowed for good.
    #[test]
    fn exclusive_state_stays_usable_after_processors_race_for_it() {
        use std::{sync::Arc, thread, vec::Vec};
        let state = Arc::new(Exclusive::new(0u64));
        let landed: u64 = (0..8)
            .map(|_| {
                let state = Arc::clone(&state);
                thread::spawn(move || {
                    (0..20_000)
                        .filter(|_| state.try_with(|value| *value += 1).is_some())
                        .count() as u64
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .sum();
        assert!(landed > 0);
        assert_eq!(state.try_with(|value| *value), Some(landed));
    }

    #[test]
    fn pages_are_laid_out_for_about_720_rows() {
        assert_eq!(scale(800), 1);
        assert_eq!(scale(1080), 1);
        assert_eq!(scale(1440), 2);
        assert_eq!(scale(2160), 3);
    }

    #[test]
    fn the_window_keeps_the_selection_in_view() {
        assert_eq!(window(0, 10, 4), 0);
        assert_eq!(window(5, 10, 4), 2);
        assert_eq!(window(9, 10, 4), 6);
        assert_eq!(window(1, 2, 4), 0);
    }

    #[test]
    fn percentages_need_a_consistent_total_and_complete_only_at_the_end() {
        assert_eq!(percentage(0, 0), None);
        assert_eq!(percentage(1, 0), None);
        assert_eq!(percentage(11, 10), None);
        assert_eq!(percentage(0, 3), Some(0));
        assert_eq!(percentage(1, 3), Some(33));
        assert_eq!(percentage(2, 3), Some(66));
        assert_eq!(percentage(99, 100), Some(99));
        assert_eq!(percentage(3, 3), Some(100));
    }

    #[test]
    fn full_width_byte_counts_do_not_overflow_or_round_up_to_completion() {
        assert_eq!(percentage(u64::MAX - 1, u64::MAX), Some(99));
        assert_eq!(percentage(u64::MAX, u64::MAX), Some(100));
    }

    #[test]
    fn sizes_read_as_three_figures_in_decimal_units() {
        assert_eq!(disk_size(1_000_204_886_016), "1.0 TB");
        assert_eq!(disk_size(512 * GB), "512 GB");
        assert_eq!(disk_size(8_600_000_000), "8.6 GB");
        assert_eq!(disk_size(260 * 1_000_000), "260 MB");
    }

    #[test]
    fn the_logo_is_blue_left_orange_right_split_by_a_gap() {
        assert_eq!(logo_pixel(0.0, 0.0), None);
        assert_eq!(logo_pixel(0.5, 0.0), None);
        let blue = logo_pixel(0.15, 0.5).unwrap();
        let orange = logo_pixel(0.85, 0.5).unwrap();
        assert!(blue & 0xff > blue >> 16);
        assert!(orange >> 16 > orange & 0xff);
        // The curve bulges left in the upper half and right in the lower.
        assert!(logo_pixel(0.45, 0.25).unwrap() >> 16 > 0xc0);
        assert!(logo_pixel(0.55, 0.75).unwrap() >> 16 < 0x80);
    }
}
