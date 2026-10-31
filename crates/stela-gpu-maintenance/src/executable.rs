//! Keep the native on-disk kext and Stela's prelinked source identity together.
use anyhow::{Result, ensure};

pub(super) fn set_uuid(file: &mut [u8], uuid: [u8; 16]) -> Result<()> {
    fn word(file: &[u8], at: usize) -> Result<u32> {
        Ok(u32::from_le_bytes(
            file.get(at..at + 4)
                .ok_or_else(|| anyhow::anyhow!("truncated kext header"))?
                .try_into()?,
        ))
    }
    ensure!(
        file.len() >= 32
            && word(file, 0)? == 0xfeed_facf
            && word(file, 4)? == 0x0100_000c
            && word(file, 8)? & 0x00ff_ffff == 2
            && word(file, 12)? == 11,
        "native linker did not produce an arm64e MH_KEXT_BUNDLE"
    );
    let end = 32usize
        .checked_add(word(file, 20)? as usize)
        .ok_or_else(|| anyhow::anyhow!("kext load commands overflow"))?;
    ensure!(end <= file.len(), "kext load commands exceed file");
    let mut cursor = 32;
    let mut location = None;
    for _ in 0..word(file, 16)? {
        ensure!(cursor + 8 <= end, "kext load command is truncated");
        let command = word(file, cursor)?;
        let size = word(file, cursor + 4)? as usize;
        ensure!(
            size >= 8 && size.is_multiple_of(8) && size <= end - cursor,
            "invalid kext load command extent"
        );
        ensure!(
            command != 0x1d,
            "native kext must be signed after its UUID is set"
        );
        if command == 0x1b {
            ensure!(
                size == 24 && location.is_none(),
                "invalid or repeated kext UUID"
            );
            location = Some(cursor + 8);
        }
        cursor += size;
    }
    ensure!(
        cursor == end,
        "kext load command count differs from its extent"
    );
    let at = location.ok_or_else(|| anyhow::anyhow!("native linker omitted the kext UUID"))?;
    file[at..at + 16].copy_from_slice(&uuid);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn image(command: u32, size: u32) -> Vec<u8> {
        [
            0xfeed_facfu32,
            0x0100_000c,
            0x8000_0002,
            11,
            1,
            24,
            0,
            0,
            command,
            size,
            0,
            0,
            0,
            0,
        ]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect()
    }

    #[test]
    fn changes_only_the_uuid_of_an_unsigned_arm64e_kext() -> Result<()> {
        let mut file = image(0x1b, 24);
        let before = file.clone();
        set_uuid(&mut file, [0xab; 16])?;
        assert_eq!(&file[..40], &before[..40]);
        assert_eq!(&file[40..], &[0xab; 16]);
        Ok(())
    }

    #[test]
    fn signed_truncated_and_malformed_outputs_are_refused_without_mutation() {
        for mut file in [
            image(0x1d, 24),
            image(0x1b, 8),
            image(0x1b, 32),
            vec![0; 20],
        ] {
            let before = file.clone();
            assert!(set_uuid(&mut file, [1; 16]).is_err());
            assert_eq!(file, before);
        }
    }
}
