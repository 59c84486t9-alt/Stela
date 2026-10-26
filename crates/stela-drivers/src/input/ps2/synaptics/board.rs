// SPDX-License-Identifier: GPL-2.0-only
// Original Synaptics notices: ../synaptics.rs and input/THIRD_PARTY.md.
//! Source PnP/board coordinate corrections, separate from observed firmware data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bounds {
    pub minimum: (u16, u16),
    pub maximum: (u16, u16),
}
pub(super) fn bounds(firmware_id: &str, board: Option<u16>) -> Option<Bounds> {
    let ids = firmware_id.strip_prefix("PNP: ")?;
    let matches = |names: &[&str]| {
        ids.split(' ')
            .any(|id| names.iter().any(|name| id.eq_ignore_ascii_case(name)))
    };
    // Source info is zero-initialized when firmware predates the board query.
    // Preserve board=None publicly; zero here is only that source policy input.
    let board = board.unwrap_or(0);
    let (x_min, x_max, y_min, y_max) = if matches(&["LEN0033"]) {
        (1024, 5052, 2258, 4832)
    } else if matches(&["LEN0042"]) {
        (1232, 5710, 1156, 4696)
    } else if board <= 2961
        && matches(&[
            "LEN0034", "LEN0036", "LEN0037", "LEN0039", "LEN2002", "LEN2004",
        ])
    {
        (1024, 5112, 2024, 4832)
    } else if matches(&["LEN2000"]) {
        (1024, 5113, 2021, 4832)
    } else if matches(&["LEN2001"]) {
        (1024, 5022, 2508, 4832)
    } else if matches(&["LEN2006"]) {
        if board == 2691 {
            (1024, 5045, 2457, 4832)
        } else {
            (1264, 5675, 1171, 4688)
        }
    } else {
        return None;
    };
    Some(Bounds {
        minimum: (x_min, y_min),
        maximum: (x_max, y_max),
    })
}
