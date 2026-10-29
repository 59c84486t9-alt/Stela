//! IDENTIFY DEVICE page fixture encoding.
use super::*;

/// IDENTIFY DEVICE data for an LBA48 disk.
pub(super) fn identify_page(serial: &str, blocks: u64) -> [u8; 512] {
    let mut page = [0u8; 512];
    let mut put = |index: usize, value: u16| {
        page[2 * index..2 * index + 2].copy_from_slice(&value.to_le_bytes())
    };
    for (words, text) in [(IDENTIFY_SERIAL, serial), (IDENTIFY_MODEL, "Fixture SSD")] {
        let mut bytes = text.as_bytes().to_vec();
        bytes.resize(2 * words.len(), b' ');
        for (index, pair) in words.zip(bytes.chunks(2)) {
            put(index, u16::from_be_bytes([pair[0], pair[1]]));
        }
    }
    put(IDENTIFY_COMMANDS_2, WORD_VALID | COMMANDS_2_LBA48);
    put(IDENTIFY_CAPABILITY, CAPABILITY_IORDY);
    put(IDENTIFY_FIELD_VALID, FIELD_VALID_PIO | FIELD_VALID_UDMA);
    put(IDENTIFY_PIO_MODES, 0x03);
    put(IDENTIFY_UDMA_MODES, 0x7f);
    for (offset, index) in IDENTIFY_LBA48_SECTORS.enumerate() {
        put(index, (blocks >> (16 * offset)) as u16);
    }
    page
}
