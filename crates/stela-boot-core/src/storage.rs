//! The host-storage options of `stela.cfg`: `split` separates the
//! `--storage` and `--storage-check` targets from the rest of the line, and
//! the USB check requests are validated against them.
use crate::Result;
use alloc::{string::String, vec::Vec};
use stela_contracts::refuse;
use stela_runtime::pc::storage::Target;

/// The storage options, and the rest of `stela.cfg` for the mount.
pub fn split(options: &str) -> Result<(Vec<Target>, Vec<Target>, String)> {
    let mut open = Vec::new();
    let mut check = Vec::new();
    let mut rest = String::new();
    let mut words = options.split_ascii_whitespace();
    while let Some(word) = words.next() {
        if matches!(word, "--usb-reset-check" | "--usb-media-check") {
            continue;
        }
        let list = match word {
            "--storage" => &mut open,
            "--storage-check" => &mut check,
            _ => {
                rest.push_str(word);
                rest.push(' ');
                continue;
            }
        };
        list.push(
            words
                .next()
                .ok_or(refuse!("missing storage target"))?
                .parse()?,
        );
    }
    Ok((open, check, rest))
}

pub fn reset_requested(text: &str, open: &[Target], check: &[Target]) -> Result<bool> {
    let reset_count = text
        .split_ascii_whitespace()
        .filter(|word| *word == "--usb-reset-check")
        .count();
    if reset_count > 1 || reset_count == 1 && (check.len() != 1 || !open.is_empty()) {
        return Err(refuse!(
            "USB reset check requires exactly one storage-check target"
        ));
    }
    Ok(reset_count == 1)
}

pub fn media_requested(text: &str, open: &[Target], check: &[Target]) -> Result<bool> {
    let count = text
        .split_ascii_whitespace()
        .filter(|word| *word == "--usb-media-check")
        .count();
    if count > 1
        || count == 1
            && (check.len() != 1
                || !open.is_empty()
                || text
                    .split_ascii_whitespace()
                    .any(|word| word == "--usb-reset-check"))
    {
        return Err(refuse!(
            "USB media check requires one storage-check target and excludes reset check"
        ));
    }
    Ok(count == 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    const TARGET: &str = "TEST:02020202-0202-0202-0202-020202020202";

    #[test]
    fn explicit_reset_has_one_write_target_and_is_not_a_guest_option() {
        let text = alloc::format!("--usb-reset-check --storage-check {TARGET} --arg unchanged");
        let (open, check, rest) = split(&text).unwrap();
        assert!(open.is_empty());
        assert_eq!(check.len(), 1);
        assert_eq!(check[0].serial, "TEST");
        assert_eq!(rest, "--arg unchanged ");
        assert!(reset_requested(&text, &open, &check).unwrap());
    }

    #[test]
    fn reset_refuses_absent_ambiguous_read_only_and_duplicate_requests() {
        for text in [
            String::from("--usb-reset-check"),
            alloc::format!("--usb-reset-check --storage {TARGET}"),
            alloc::format!("--usb-reset-check --storage-check {TARGET} --storage-check {TARGET}"),
            alloc::format!("--usb-reset-check --storage-check {TARGET} --storage {TARGET}"),
            alloc::format!("--usb-reset-check --usb-reset-check --storage-check {TARGET}"),
        ] {
            let (open, check, _) = split(&text).unwrap();
            assert!(reset_requested(&text, &open, &check).is_err(), "{text}");
        }
        assert!(split("--usb-reset-check --storage-check").is_err());
    }

    #[test]
    fn ordinary_storage_options_preserve_targets_and_guest_arguments() {
        let text = alloc::format!("--storage {TARGET} --storage-check {TARGET} --arg unchanged");
        let (open, check, rest) = split(&text).unwrap();
        assert_eq!(open.len(), 1);
        assert_eq!(check.len(), 1);
        assert_eq!(open[0].serial, check[0].serial);
        assert_eq!(rest, "--arg unchanged ");
        assert!(!reset_requested(&text, &open, &check).unwrap());
    }

    #[test]
    fn explicit_media_check_has_one_write_target_and_is_not_a_guest_option() {
        let text = alloc::format!("--usb-media-check --storage-check {TARGET} --arg unchanged");
        let (open, check, rest) = split(&text).unwrap();
        assert_eq!(check[0].serial, "TEST");
        assert_eq!(rest, "--arg unchanged ");
        assert!(media_requested(&text, &open, &check).unwrap());
        assert!(!reset_requested(&text, &open, &check).unwrap());
    }

    #[test]
    fn media_check_refuses_absent_ambiguous_read_only_duplicate_and_reset_requests() {
        for text in [
            String::from("--usb-media-check"),
            alloc::format!("--usb-media-check --storage {TARGET}"),
            alloc::format!("--usb-media-check --storage-check {TARGET} --storage-check {TARGET}"),
            alloc::format!("--usb-media-check --storage-check {TARGET} --storage {TARGET}"),
            alloc::format!("--usb-media-check --usb-media-check --storage-check {TARGET}"),
            alloc::format!("--usb-media-check --usb-reset-check --storage-check {TARGET}"),
            alloc::format!("--usb-reset-check --storage-check {TARGET} --usb-media-check"),
        ] {
            let (open, check, _) = split(&text).unwrap();
            assert!(media_requested(&text, &open, &check).is_err(), "{text}");
        }
        assert!(split("--usb-media-check --storage-check").is_err());
    }

    #[test]
    fn ordinary_and_reset_storage_do_not_enable_media_diagnostic() {
        for text in [
            alloc::format!("--storage {TARGET}"),
            alloc::format!("--storage-check {TARGET}"),
            alloc::format!("--usb-reset-check --storage-check {TARGET}"),
            String::from("--arg unchanged"),
        ] {
            let (open, check, _) = split(&text).unwrap();
            assert!(!media_requested(&text, &open, &check).unwrap());
        }
    }
}
