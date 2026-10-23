//! Stack-only display of a finite operation's known completed/total counts.

pub const WIDTH: usize = 6;

/// Round down so the last cell and 100% require actual completion. Unknown or
/// inconsistent totals are indeterminate. Wider intermediates preserve these
/// semantics even for full-width byte counts.
pub fn marker(completed: u64, total: u64) -> Option<([u8; WIDTH], u8)> {
    if total == 0 || completed > total {
        return None;
    }
    let completed = u128::from(completed);
    let total = u128::from(total);
    let filled = (completed * WIDTH as u128 / total) as usize;
    let percentage = (completed * 100 / total) as u8;
    let mut marker = [b'-'; WIDTH];
    marker[..filled].fill(b'#');
    Some((marker, percentage))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fractions_require_known_consistent_totals_and_only_complete_at_the_end() {
        assert_eq!(marker(0, 0), None);
        assert_eq!(marker(1, 0), None);
        assert_eq!(marker(11, 10), None);
        assert_eq!(marker(0, 3), Some((*b"------", 0)));
        assert_eq!(marker(1, 3), Some((*b"##----", 33)));
        assert_eq!(marker(2, 3), Some((*b"####--", 66)));
        assert_eq!(marker(99, 100), Some((*b"#####-", 99)));
        assert_eq!(marker(3, 3), Some((*b"######", 100)));
    }

    #[test]
    fn full_width_byte_counts_do_not_overflow_or_round_up_to_completion() {
        assert_eq!(marker(u64::MAX - 1, u64::MAX), Some((*b"#####-", 99)));
        assert_eq!(marker(u64::MAX, u64::MAX), Some((*b"######", 100)));
    }
}
