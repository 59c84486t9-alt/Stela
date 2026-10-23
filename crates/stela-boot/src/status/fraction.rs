//! Stack-only display of a finite operation's known completed/total counts.

/// Round down so 100% requires actual completion. Unknown or
/// inconsistent totals are indeterminate. Wider intermediates preserve these
/// semantics even for full-width byte counts.
pub fn percentage(completed: u64, total: u64) -> Option<u8> {
    if total == 0 || completed > total {
        return None;
    }
    let completed = u128::from(completed);
    let total = u128::from(total);
    Some((completed * 100 / total) as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fractions_require_known_consistent_totals_and_only_complete_at_the_end() {
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
}
