// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2015 Endless Mobile, Inc.
//! EPATCH v2 adapted from the pinned btrtl iovec/section/priority-list parser.
//! Unknown section bodies are skipped by that format policy, with metadata and
//! whole-body hashes retained. Nonzero key/security selection is not implemented.
use super::{Configuration, FormatError, Project, Staged};
use alloc::vec::Vec;
use core::cmp::Reverse;
use sha2::{Digest, Sha256};
const HEADER: usize = 20;
const MAX_IMAGE: usize = 4 * 1024 * 1024;
const SNIPPETS: u32 = 1;
const DUMMY: u32 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtensionRecord {
    pub opcode: u8,
    pub value: u8,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubsectionObservation {
    pub eco: u8,
    pub priority: u8,
    pub control: [u8; 2],
    pub length: u32,
    pub sha256: [u8; 32],
    pub selected: bool,
}
/// An unknown opcode, or a security section with key0, is opaque and excluded
/// from upload under the donor's explicit skip policy. Its complete body hash,
/// length and opcode remain bound to the immutable source image receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SectionObservation {
    pub opcode: u32,
    pub length: u32,
    pub sha256: [u8; 32],
    pub skipped: bool,
    pub subsections: Vec<SubsectionObservation>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2Metadata {
    pub version: [u8; 8],
    pub project: Project,
    pub rom_version: u8,
    pub key_id: u8,
    pub sections: Vec<SectionObservation>,
    pub extensions: Vec<ExtensionRecord>,
}
/// Full bounded v2 input and its selected real ROM payloads. Metadata preserves
/// all format controls, including opaque skipped sections and extension records.
#[derive(Debug)]
pub struct V2Patch<'a> {
    pub metadata: V2Metadata,
    ordered: Vec<&'a [u8]>,
}
impl<'a> V2Patch<'a> {
    pub fn parse(
        bytes: &'a [u8],
        project: Project,
        rom_version: u8,
        key_id: u8,
    ) -> Result<Self, FormatError> {
        if !(HEADER + 8..=MAX_IMAGE).contains(&bytes.len()) {
            return Err(FormatError::Size);
        }
        if &bytes[..8] != b"RTBTCore" {
            return Err(FormatError::Signature);
        }
        if project != Project::Rtl8852Bu {
            return Err(FormatError::Project);
        }
        if key_id != 0 {
            return Err(FormatError::Security);
        }
        let tail = bytes.len() - 7;
        if bytes[tail..tail + 3] != [project.id(), 1, 0]
            || bytes[tail + 3..] != [0x51, 4, 0xfd, 0x77]
        {
            return Err(FormatError::Extension);
        }
        let version = bytes[8..16].try_into().unwrap();
        let count = dword(bytes, 16) as usize;
        if count == 0 || count > (tail - HEADER) / 8 {
            return Err(FormatError::Section);
        }
        let mut at = HEADER;
        let mut sections = Vec::with_capacity(count);
        let mut selected = Vec::new();
        for _ in 0..count {
            let header = bytes
                .get(at..at + 8)
                .filter(|_| at + 8 <= tail)
                .ok_or(FormatError::Section)?;
            let opcode = dword(header, 0);
            let length = dword(header, 4);
            at += 8;
            let end = at
                .checked_add(length as usize)
                .filter(|end| *end <= tail)
                .ok_or(FormatError::Section)?;
            let data = &bytes[at..end];
            let skipped = !matches!(opcode, SNIPPETS | DUMMY);
            let mut subsection_info = Vec::new();
            // Key0 explicitly skips all security bodies, not just their payload.
            // Unknown opcodes have the same opaque source-defined treatment.
            if !skipped {
                if data.len() < 4 || data[2..4] != [0, 0] {
                    return Err(FormatError::Subsection);
                }
                let num = usize::from(u16::from_le_bytes([data[0], data[1]]));
                if num > (data.len() - 4) / 8 {
                    return Err(FormatError::Subsection);
                }
                let mut pos = 4;
                for _ in 0..num {
                    let header = data.get(pos..pos + 8).ok_or(FormatError::Subsection)?;
                    let length = dword(header, 4);
                    pos += 8;
                    let end = pos
                        .checked_add(length as usize)
                        .filter(|end| *end <= data.len())
                        .ok_or(FormatError::Subsection)?;
                    let body = &data[pos..end];
                    let matches = u16::from(header[0]) == u16::from(rom_version) + 1;
                    subsection_info.push(SubsectionObservation {
                        eco: header[0],
                        priority: header[1],
                        control: [header[2], header[3]],
                        length,
                        sha256: Sha256::digest(body).into(),
                        selected: matches,
                    });
                    if matches {
                        selected.push((header[1], selected.len(), body));
                    }
                    pos = end;
                }
                if pos != data.len() {
                    return Err(FormatError::Subsection);
                }
            }
            sections.push(SectionObservation {
                opcode,
                length,
                sha256: Sha256::digest(data).into(),
                skipped,
                subsections: subsection_info,
            });
            at = end;
        }
        // This slice supports the actually observed one-byte extension records,
        // completely, followed by the canonical terminal project instruction.
        // Other extension programs are explicit unsupported input, not guessed.
        if bytes.get(at) != Some(&0xff) || at >= tail {
            return Err(FormatError::Extension);
        }
        let extension = &bytes[at + 1..tail];
        let (records, remainder) = extension.as_chunks::<3>();
        if !remainder.is_empty() {
            return Err(FormatError::Extension);
        }
        let mut extensions = Vec::new();
        for record in records {
            if record[1] != 1 || record[2] == 0 || record[2] == 0xff {
                return Err(FormatError::Extension);
            }
            extensions.push(ExtensionRecord {
                opcode: record[2],
                value: record[0],
            });
        }
        extensions.push(ExtensionRecord {
            opcode: 0,
            value: project.id(),
        });
        // btrtl_insert_ordered_subsec inserts BEFORE existing equal priority:
        // ascending priority, reverse source order for ties, including sections.
        selected.sort_by_key(|(priority, order, _)| (*priority, Reverse(*order)));
        let ordered: Vec<_> = selected.into_iter().map(|(_, _, body)| body).collect();
        if ordered.iter().all(|body| body.is_empty()) {
            return Err(FormatError::MissingRom);
        }
        Ok(Self {
            metadata: V2Metadata {
                version,
                project,
                rom_version,
                key_id,
                sections,
                extensions,
            },
            ordered,
        })
    }
    pub fn stage(&self, configuration: Option<&Configuration<'_>>) -> Staged {
        let config = configuration.map_or(&[][..], Configuration::bytes);
        let size = self.ordered.iter().map(|b| b.len()).sum::<usize>() + config.len();
        let mut bytes = Vec::with_capacity(size);
        for body in &self.ordered {
            bytes.extend_from_slice(body);
        }
        bytes.extend_from_slice(config);
        Staged::new(bytes)
    }
}
fn dword(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn image() -> Vec<u8> {
        let mut b = b"RTBTCore".to_vec();
        b.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        b.extend_from_slice(&3u32.to_le_bytes());
        let mut section = vec![4, 0, 0, 0];
        for (eco, prio, byte) in [(1, 3, 11), (1, 1, 22), (2, 0, 33), (1, 3, 44)] {
            section.extend_from_slice(&[eco, prio, 0x12, 0x34]);
            section.extend_from_slice(&1u32.to_le_bytes());
            section.push(byte);
        }
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&(section.len() as u32).to_le_bytes());
        b.extend_from_slice(&section);
        // Unknown opaque body must be observed without being uploaded.
        b.extend_from_slice(&8u32.to_le_bytes());
        b.extend_from_slice(&2u32.to_le_bytes());
        b.extend_from_slice(&[99, 98]);
        // Explicitly skipped security body with key0 need not be a common header.
        b.extend_from_slice(&3u32.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes());
        b.push(97);
        b.extend_from_slice(&[0xff, 2, 1, 1, 20, 1, 0, 0x51, 4, 0xfd, 0x77]);
        b
    }
    #[test]
    fn complete_version_controls_unknown_sections_and_donor_reverse_ties_are_retained() {
        let b = image();
        let p = V2Patch::parse(&b, Project::Rtl8852Bu, 0, 0).unwrap();
        assert_eq!(p.metadata.version, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(p.stage(None).bytes(), [22, 44, 11]);
        assert_eq!(p.metadata.sections[0].subsections[0].control, [0x12, 0x34]);
        assert!(p.metadata.sections[1].skipped);
        assert_eq!(
            p.metadata.sections[1].sha256,
            <[u8; 32]>::from(Sha256::digest([99, 98]))
        );
        assert!(p.metadata.sections[2].skipped);
        assert_eq!(
            p.metadata.extensions,
            vec![
                ExtensionRecord {
                    opcode: 1,
                    value: 2
                },
                ExtensionRecord {
                    opcode: 0,
                    value: 20
                }
            ]
        );
        assert_eq!(
            V2Patch::parse(&b, Project::Rtl8852Bu, 1, 0)
                .unwrap()
                .stage(None)
                .bytes(),
            [33]
        );
    }
    #[test]
    fn malformed_full_hierarchy_extensions_and_security_never_stage_partial_payload() {
        let base = image();
        for len in 0..base.len() {
            assert!(V2Patch::parse(&base[..len], Project::Rtl8852Bu, 0, 0).is_err());
        }
        assert_eq!(
            V2Patch::parse(&base, Project::Rtl8852Bu, 0, 1).unwrap_err(),
            FormatError::Security
        );
        assert_eq!(
            V2Patch::parse(&base, Project::Rtl8852Bu, 2, 0).unwrap_err(),
            FormatError::MissingRom
        );
        assert_eq!(
            V2Patch::parse(&base, Project::Rtl8761Bu, 0, 0).unwrap_err(),
            FormatError::Project
        );
        for (at, value, expected) in [
            (16, 99, FormatError::Section),
            (24, 255, FormatError::Section),
            (28, 99, FormatError::Subsection),
            (30, 1, FormatError::Subsection),
            (36, 255, FormatError::Subsection),
            // A different ECO still needs a complete in-bounds body.
            (54, 255, FormatError::Subsection),
            (base.len() - 9, 2, FormatError::Extension),
        ] {
            let mut b = base.clone();
            b[at] = value;
            assert_eq!(
                V2Patch::parse(&b, Project::Rtl8852Bu, 0, 0).unwrap_err(),
                expected,
                "at {at}"
            );
        }
    }
    #[test]
    fn priorities_apply_across_snippet_and_dummy_sections_before_exact_configuration() {
        let mut b = b"RTBTCore".to_vec();
        b.extend_from_slice(&[0; 8]);
        b.extend_from_slice(&2u32.to_le_bytes());
        for (opcode, byte) in [(SNIPPETS, 11), (DUMMY, 22)] {
            b.extend_from_slice(&opcode.to_le_bytes());
            b.extend_from_slice(&13u32.to_le_bytes());
            b.extend_from_slice(&[1, 0, 0, 0, 1, 7, 0, 0, 1, 0, 0, 0, byte]);
        }
        b.extend_from_slice(&[0xff, 20, 1, 0, 0x51, 4, 0xfd, 0x77]);
        let config = Configuration::parse(&[0x55, 0xab, 0x23, 0x87, 0, 0]).unwrap();
        let p = V2Patch::parse(&b, Project::Rtl8852Bu, 0, 0).unwrap();
        assert_eq!(
            p.stage(Some(&config)).bytes(),
            [22, 11, 0x55, 0xab, 0x23, 0x87, 0, 0]
        );
        assert!(!p.metadata.sections[1].skipped);
    }
}
