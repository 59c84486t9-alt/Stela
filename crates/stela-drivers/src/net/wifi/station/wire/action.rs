// SPDX-License-Identifier: GPL-2.0-only
//! Linux generic ACTION/HIGHEST IE error projection for ordinary ADDBA.
//!
//! This is structural parsing, separate from association/security policy.
//! The source wrapper uses HIGHEST (UHR), BSS=NULL and link_id=-1. Any generic
//! parse error suppresses the extension; it does not refuse the base request.
//! See THIRD_PARTY.md for the pinned parser and mesh size helpers.

const ADDBA_EXTENSION: u8 = 159;
const ADDRESS_EXTENSION: u8 = 0x40;

fn unique(id: u8) -> bool {
    matches!(
        id,
        0 | 1
            | 2
            | 3
            | 4
            | 5
            | 6
            | 7
            | 16
            | 32
            | 37
            | 42
            | 45
            | 48
            | 50
            | 56
            | 60
            | 61
            | 62
            | 90
            | 101
            | 104
            | 113
            | 114
            | 117
            | 118
            | 126
            | 127
            | 130
            | 131
            | 132
            | 191
            | 192
            | 194
            | 211
            | 213
            | 214
            | 217
            | 232
            | 244
    )
}

fn preq(body: &[u8]) -> bool {
    if body.len() < 17 {
        return false;
    }
    let extra = if body[0] & ADDRESS_EXTENSION != 0 {
        6
    } else {
        0
    };
    let Some(&count) = body.get(25 + extra) else {
        return false;
    };
    count != 0 && body.len() == 26 + extra + 11 * usize::from(count)
}

fn prep(body: &[u8]) -> bool {
    body.len() >= 13
        && body.len()
            == 31
                + if body[0] & ADDRESS_EXTENSION != 0 {
                    6
                } else {
                    0
                }
}

fn perr(body: &[u8]) -> bool {
    let Some(&count) = body.get(1) else {
        return false;
    };
    let mut offset = 2;
    for _ in 0..count {
        let Some(destination) = body.get(offset..offset + 11) else {
            return false;
        };
        offset += 13
            + if destination[0] & ADDRESS_EXTENSION != 0 {
                6
            } else {
                0
            };
    }
    body.len() == offset
}

fn valid_body(id: u8, body: &[u8]) -> bool {
    let length = body.len();
    match id {
        3 | 42 | 159 | 199 => length >= 1,
        5 | 104 => length >= 4,
        45 => length >= 26,
        61 => length >= 22,
        191 => length >= 12,
        56 | 192 => length >= 5,
        101 => length >= 18,
        113 => length >= 7,
        118 => length >= 6,
        126 => length >= 21,
        130 => preq(body),
        131 => prep(body),
        132 => perr(body),
        37 => length == 3,
        60 => length == 4,
        32 | 62 => length == 1,
        194 => length >= 3,
        // The source rejects the wrapper itself in ACTION frames. Its nested
        // parsing is only applicable to other frame types.
        196 => false,
        150 => length >= 4 && (body[..4] != [0, 0x40, 0x96, 0] || length == 6),
        // Unknown/vendor/extension/TPE contents do not set parse_error. S1G
        // body rules are skipped at HIGHEST; duplicate rules still apply.
        _ => true,
    }
}

pub(in crate::net::wifi::station) fn addba_extension(bytes: &[u8], he: bool) -> u8 {
    if !he {
        return 0;
    }
    let Ok(elements) = super::elements(bytes) else {
        return 0;
    };
    let mut seen = [0u64; 4];
    let mut value = 0;
    for (id, body) in elements {
        let word = usize::from(id / 64);
        let bit = 1u64 << (id % 64);
        if (unique(id) && seen[word] & bit != 0) || !valid_body(id, body) {
            return 0;
        }
        seen[word] |= bit;
        if id == ADDBA_EXTENSION {
            value = body[0];
        }
    }
    value
}

#[cfg(test)]
mod tests;
