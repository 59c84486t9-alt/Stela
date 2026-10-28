//! Synthetic ZIP archives used by downstream streaming tests.
use super::*;

/// Build an archive; `zip64` forces the ZIP64 end records and extra fields.
pub fn archive(members: &[(&str, &[u8], bool)], zip64: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data, deflate) in members {
        let body = if *deflate {
            miniz_oxide::deflate::compress_to_vec(data, 6)
        } else {
            data.to_vec()
        };
        let offset = out.len() as u64;
        let crc = crate::payload::gpt::crc32(data);
        let method: u16 = if *deflate { 8 } else { 0 };
        let small = |v: u64| if zip64 { 0xffff_ffff } else { v as u32 };
        out.extend_from_slice(&LOCAL.to_le_bytes());
        out.extend_from_slice(&[20, 0, 0, 0]);
        out.extend_from_slice(&method.to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&[3, 0]);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b"xyz");
        out.extend_from_slice(&body);
        let extra: Vec<u8> = if zip64 {
            [1u16.to_le_bytes(), 24u16.to_le_bytes()]
                .concat()
                .into_iter()
                .chain((data.len() as u64).to_le_bytes())
                .chain((body.len() as u64).to_le_bytes())
                .chain(offset.to_le_bytes())
                .collect()
        } else {
            Vec::new()
        };
        central.extend_from_slice(&CENTRAL.to_le_bytes());
        central.extend_from_slice(&[45, 0, 45, 0, 0, 0]);
        central.extend_from_slice(&method.to_le_bytes());
        central.extend_from_slice(&[0; 4]);
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&small(body.len() as u64).to_le_bytes());
        central.extend_from_slice(&small(data.len() as u64).to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&(extra.len() as u16).to_le_bytes());
        central.extend_from_slice(&[0; 10]);
        central.extend_from_slice(&small(offset).to_le_bytes());
        central.extend_from_slice(name.as_bytes());
        central.extend_from_slice(&extra);
    }
    let start = out.len() as u64;
    out.extend_from_slice(&central);
    let count = members.len() as u64;
    if zip64 {
        let record = out.len() as u64;
        out.extend_from_slice(&END64.to_le_bytes());
        out.extend_from_slice(&44u64.to_le_bytes());
        out.extend_from_slice(&[45, 0, 45, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&(central.len() as u64).to_le_bytes());
        out.extend_from_slice(&start.to_le_bytes());
        out.extend_from_slice(&LOCATOR64.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&record.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
    }
    out.extend_from_slice(&END.to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    let n = if zip64 { 0xffff } else { count as u16 };
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(&n.to_le_bytes());
    let (size, offset) = if zip64 {
        (0xffff_ffffu32, 0xffff_ffffu32)
    } else {
        (central.len() as u32, start as u32)
    };
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&offset.to_le_bytes());
    out.extend_from_slice(&5u16.to_le_bytes());
    out.extend_from_slice(b"notes");
    out
}
