//! This machine's compressed page format for WKDMC and WKDMD.
//!
//! The hardware's format is not public, and nothing needs it: the 26A434
//! kernel decompresses what WKDMC wrote only with WKDMD on the same machine
//! (the VM compressor's slots, which live in memory or this boot's swap,
//! and the hibernation image, which the same kernel's restore path reads
//! back with WKDMD); `-vm_compressor_wk_sw` switches both directions to
//! software WKdm for the whole boot. So the format only has to be
//! self-consistent, deterministic, within a page and at most 255 units, as
//! the size field requires.
//!
//! It follows the published WKdm design (Wilson, Kaplan and Smaragdakis)
//! and the stream layout XNU's software WKdm documents
//! (`osfmk/arm64/WKdmCompress_16k.s`), so its three header words are word
//! offsets below 0x10000 as XNU's DEVELOPMENT header check expects. Each
//! 32-bit word is tagged against a 16-entry direct-mapped dictionary,
//! initially zero, indexed by a hash of its high 22 bits:
//!
//! | Tag | Word | Encoded as |
//! | --- | --- | --- |
//! | 0 | zero | the tag |
//! | 3 | equals its dictionary entry | the tag and a 4-bit index |
//! | 1 | high 22 bits equal the entry's (the entry becomes the word) | the tag, the index and its low 10 bits |
//! | 2 | anything else (the entry becomes the word) | the tag and the whole word |
//!
//! In memory order, in 32-bit little-endian words:
//!
//! 1. three header words: the word offsets where the indices start, where
//!    the low bits start and where the data ends;
//! 2. the 4096 tags, 2 bits each, 16 per word, tag `16w + 4j + k` at bit
//!    `8k + 2j` of word `w`;
//! 3. the whole words, in page order;
//! 4. the indices, 8 per word, index `8w + 4h + k` at bit `8k + 4h`;
//! 5. the low bits, 3 per word, item `3w + i` at bit `10i`.
//!
//! Unused index and low-bit positions are zero, and the data is padded with
//! zero bytes to a whole unit. Unlike XNU's software format, the dictionary
//! hash is this module's own ([`index`]), so XNU's software decompressor
//! cannot read this format, and no consumer needs it to.
use super::{PAGE_BYTES, PAGE_WORDS, UNIT_BYTES};
use alloc::vec::Vec;

const WORD_BYTES: usize = 4;
pub const HEADER_BYTES: usize = 3 * WORD_BYTES;
const HEADER_WORDS: usize = HEADER_BYTES / WORD_BYTES;
const TAGS_PER_WORD: usize = 16;
const TAG_WORDS: usize = PAGE_WORDS / TAGS_PER_WORD;
/// Where the whole words start.
const WHOLE_START: usize = HEADER_WORDS + TAG_WORDS;
const INDICES_PER_WORD: usize = 8;
const LOW_PER_WORD: usize = 3;
const LOW_BITS: u32 = 10;
const LOW_MASK: u32 = (1 << LOW_BITS) - 1;
const DICTIONARY_ENTRIES: usize = 16;
/// The most a compressed page may take: 255 units, since 256 units (a
/// whole page) is how the kernel reads "did not compress".
pub const MAX_COMPRESSED_BYTES: usize = PAGE_BYTES - UNIT_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tag {
    Zero = 0,
    Partial = 1,
    Whole = 2,
    Exact = 3,
}

impl Tag {
    const fn from_bits(bits: u32) -> Self {
        match bits & 3 {
            0 => Self::Zero,
            1 => Self::Partial,
            2 => Self::Whole,
            _ => Self::Exact,
        }
    }
}

/// What WKDMC makes of a page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Compressed {
    /// Every word is the same value; nothing is written.
    SingleValue,
    /// The compressed data, a whole number of units below a page.
    Data(Vec<u8>),
    /// More than [`MAX_COMPRESSED_BYTES`]; nothing is written.
    Incompressible,
}

/// The dictionary entry of `word`, from its high 22 bits only, so a partial
/// match always shares the entry.
const fn index(word: u32) -> usize {
    let high = word >> LOW_BITS;
    ((high ^ high >> 4 ^ high >> 12) as usize) % DICTIONARY_ENTRIES
}

fn words(bytes: &[u8]) -> impl Iterator<Item = u32> + '_ {
    let (chunks, _) = bytes.as_chunks::<WORD_BYTES>();
    chunks.iter().copied().map(u32::from_le_bytes)
}

pub fn compress(page: &[u8; PAGE_BYTES]) -> Compressed {
    let mut input = words(page);
    let first = input.next().expect("a page has words");
    if input.all(|word| word == first) {
        return Compressed::SingleValue;
    }
    let mut dictionary = [0u32; DICTIONARY_ENTRIES];
    let mut tags = [Tag::Zero; PAGE_WORDS];
    let mut whole = Vec::new();
    let mut indices = Vec::new();
    let mut low = Vec::new();
    for (tag, word) in tags.iter_mut().zip(words(page)) {
        if word == 0 {
            continue;
        }
        let entry = index(word);
        let current = dictionary[entry];
        *tag = if current == word {
            indices.push(entry as u32);
            Tag::Exact
        } else if current >> LOW_BITS == word >> LOW_BITS {
            indices.push(entry as u32);
            low.push(word & LOW_MASK);
            Tag::Partial
        } else {
            whole.push(word);
            Tag::Whole
        };
        dictionary[entry] = word;
    }
    let indices_start = WHOLE_START + whole.len();
    let low_start = indices_start + indices.len().div_ceil(INDICES_PER_WORD);
    let end = low_start + low.len().div_ceil(LOW_PER_WORD);
    let bytes = (end * WORD_BYTES).next_multiple_of(UNIT_BYTES);
    if bytes > MAX_COMPRESSED_BYTES {
        return Compressed::Incompressible;
    }
    let mut stream = alloc::vec![0u32; end];
    stream[0] = indices_start as u32;
    stream[1] = low_start as u32;
    stream[2] = end as u32;
    for (position, &tag) in tags.iter().enumerate() {
        stream[HEADER_WORDS + position / TAGS_PER_WORD] |= (tag as u32) << tag_shift(position);
    }
    stream[WHOLE_START..indices_start].copy_from_slice(&whole);
    for (position, &entry) in indices.iter().enumerate() {
        stream[indices_start + position / INDICES_PER_WORD] |= entry << index_shift(position);
    }
    for (position, &bits) in low.iter().enumerate() {
        stream[low_start + position / LOW_PER_WORD] |= bits << low_shift(position);
    }
    let mut data: Vec<u8> = stream.iter().flat_map(|word| word.to_le_bytes()).collect();
    data.resize(bytes, 0);
    Compressed::Data(data)
}

const fn tag_shift(position: usize) -> u32 {
    (8 * (position % 4) + 2 * (position % TAGS_PER_WORD / 4)) as u32
}

const fn index_shift(position: usize) -> u32 {
    let slot = position % INDICES_PER_WORD;
    (8 * (slot % 4) + 4 * (slot / 4)) as u32
}

const fn low_shift(position: usize) -> u32 {
    LOW_BITS * (position % LOW_PER_WORD) as u32
}

/// The header's three word offsets, when they are ordered and the data fits
/// in [`MAX_COMPRESSED_BYTES`].
fn sections(header: &[u8]) -> Option<[usize; 3]> {
    let mut offsets = words(header.get(..HEADER_BYTES)?).map(|word| word as usize);
    let [indices, low, end] = core::array::from_fn(|_| offsets.next().expect("three words"));
    (WHOLE_START <= indices
        && indices <= low
        && low <= end
        && end * WORD_BYTES <= MAX_COMPRESSED_BYTES)
        .then_some([indices, low, end])
}

/// The bytes WKDMD reads for compressed data starting with `header`: the
/// data rounded up to whole units, or `None` when the header is not this
/// format's.
pub fn compressed_length(header: &[u8; HEADER_BYTES]) -> Option<usize> {
    let [_, _, end] = sections(header)?;
    Some((end * WORD_BYTES).next_multiple_of(UNIT_BYTES))
}

/// The page `data` encodes, or `None` when it is not data [`compress`]
/// could have written: its sections must have exactly the sizes its tags
/// imply.
pub fn decompress(data: &[u8]) -> Option<Vec<u8>> {
    let [indices_start, low_start, end] = sections(data)?;
    let stream: Vec<u32> = words(data.get(..end * WORD_BYTES)?).collect();
    let tag = |position: usize| {
        Tag::from_bits(stream[HEADER_WORDS + position / TAGS_PER_WORD] >> tag_shift(position))
    };
    let count = |wanted: &[Tag]| {
        (0..PAGE_WORDS)
            .filter(|&p| wanted.contains(&tag(p)))
            .count()
    };
    let partial = count(&[Tag::Partial]);
    if count(&[Tag::Whole]) != indices_start - WHOLE_START
        || count(&[Tag::Partial, Tag::Exact]).div_ceil(INDICES_PER_WORD)
            != low_start - indices_start
        || partial.div_ceil(LOW_PER_WORD) != end - low_start
    {
        return None;
    }
    let mut dictionary = [0u32; DICTIONARY_ENTRIES];
    let (mut whole, mut indices, mut low) = (WHOLE_START, 0, 0);
    let mut page = Vec::with_capacity(PAGE_BYTES);
    for position in 0..PAGE_WORDS {
        let word = match tag(position) {
            Tag::Zero => 0,
            Tag::Whole => {
                let word = stream[whole];
                whole += 1;
                dictionary[index(word)] = word;
                word
            }
            kind @ (Tag::Exact | Tag::Partial) => {
                let entry = (stream[indices_start + indices / INDICES_PER_WORD]
                    >> index_shift(indices)) as usize
                    % DICTIONARY_ENTRIES;
                indices += 1;
                let mut word = dictionary[entry];
                if kind == Tag::Partial {
                    let bits = stream[low_start + low / LOW_PER_WORD] >> low_shift(low) & LOW_MASK;
                    low += 1;
                    word = word & !LOW_MASK | bits;
                    dictionary[entry] = word;
                }
                word
            }
        };
        page.extend_from_slice(&word.to_le_bytes());
    }
    Some(page)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;

    fn page_of(words: impl Fn(usize) -> u32) -> Box<[u8; PAGE_BYTES]> {
        let bytes: Vec<u8> = (0..PAGE_WORDS)
            .flat_map(|i| words(i).to_le_bytes())
            .collect();
        bytes.into_boxed_slice().try_into().unwrap()
    }

    /// A deterministic xorshift stream.
    fn noise(seed: u64) -> impl FnMut() -> u32 {
        let mut state = seed | 1;
        move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u32
        }
    }

    fn data(page: &[u8; PAGE_BYTES]) -> Vec<u8> {
        match compress(page) {
            Compressed::Data(data) => data,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn single_value_pages_write_nothing() {
        for value in [0, 1, 0xdead_beef] {
            assert_eq!(compress(&page_of(|_| value)), Compressed::SingleValue);
        }
    }

    #[test]
    fn exact_layout_of_a_small_page() {
        // Word 1 is a whole word, word 2 an exact repeat, word 3 a partial
        // match (same high 22 bits) and the rest zero.
        let page = page_of(|i| match i {
            1 => 0x1234_5400,
            2 => 0x1234_5400,
            3 => 0x1234_5401,
            _ => 0,
        });
        let data = data(&page);
        let word = |i: usize| u32::from_le_bytes(data[4 * i..4 * i + 4].try_into().unwrap());
        // One whole word, two indices (one word), one low item (one word).
        assert_eq!([word(0), word(1), word(2)], [260, 261, 262]);
        // Tags 1, 2, 3 are Whole, Exact, Partial: bits 8, 16 and 24 of the
        // first tag word.
        assert_eq!(word(3), 2 << 8 | 3 << 16 | 1 << 24);
        assert!((4..259).all(|i| word(i) == 0));
        assert_eq!(word(259), 0x1234_5400);
        let entry = index(0x1234_5400) as u32;
        assert_eq!(word(260), entry | entry << 8);
        assert_eq!(word(261), 1);
        assert_eq!(data.len(), 1088, "262 words padded to 17 units");
        assert!(data[262 * 4..].iter().all(|&byte| byte == 0));
        assert_eq!(decompress(&data).unwrap(), page.to_vec());
    }

    #[test]
    fn round_trips_typical_pages() {
        let mut next = noise(0x5eed);
        let sparse = page_of(|i| if i % 7 == 0 { i as u32 * 3 } else { 0 });
        let pointers = page_of(|i| 0xfffffe00u32.wrapping_add((i as u32 % 64) << 4));
        let mixed = {
            let values: Vec<u32> = (0..PAGE_WORDS)
                .map(|i| match i % 5 {
                    0 => next(),
                    1 | 2 => 0,
                    _ => 0x4000_0000 | next() & 0x3ff,
                })
                .collect();
            page_of(|i| values[i])
        };
        for page in [sparse, pointers, mixed] {
            let data = data(&page);
            assert_eq!(data.len() % UNIT_BYTES, 0);
            assert!(data.len() <= MAX_COMPRESSED_BYTES);
            let header: [u8; HEADER_BYTES] = data[..HEADER_BYTES].try_into().unwrap();
            assert_eq!(compressed_length(&header), Some(data.len()));
            assert!(words(&header).all(|word| word < 0x1_0000));
            assert_eq!(decompress(&data).unwrap(), page.to_vec());
        }
    }

    #[test]
    fn random_pages_do_not_compress() {
        let mut next = noise(7);
        let values: Vec<u32> = (0..PAGE_WORDS).map(|_| next()).collect();
        assert_eq!(
            compress(&page_of(|i| values[i])),
            Compressed::Incompressible
        );
    }

    #[test]
    fn the_largest_compressible_page_is_255_units() {
        // n whole words cost 259 + n words: 255 units hold 4080 words, so
        // 3821 whole words fit and 3822 do not.
        let mut next = noise(11);
        let values: Vec<u32> = (0..PAGE_WORDS).map(|_| next() | 1 << 31).collect();
        for (whole, fits) in [(3821, true), (3822, false)] {
            let page = page_of(|i| if i < whole { values[i] } else { 0 });
            let compressed = compress(&page);
            assert_eq!(matches!(compressed, Compressed::Data(_)), fits, "{whole}");
            if let Compressed::Data(data) = compressed {
                assert_eq!(data.len(), MAX_COMPRESSED_BYTES);
            }
        }
    }

    #[test]
    fn rejects_data_this_format_cannot_hold() {
        let page = page_of(|i| (i as u32 % 3) << 12);
        let good = data(&page);
        let with_header = |header: [u32; 3]| {
            let mut data = good.clone();
            for (i, word) in header.iter().enumerate() {
                data[4 * i..4 * i + 4].copy_from_slice(&word.to_le_bytes());
            }
            data
        };
        let header: Vec<u32> = words(&good[..HEADER_BYTES]).collect();
        let [indices, low, end] = [header[0], header[1], header[2]];
        for bad in [
            [258, low, end],
            [low + 1, low, end],
            [indices, end + 1, end],
            [indices, low, 4081],
            [indices + 1, low + 1, end + 1],
            [indices, low, end + 1],
        ] {
            let data = with_header(bad);
            assert_eq!(decompress(&data), None, "{bad:?}");
        }
        assert_eq!(compressed_length(&[0; HEADER_BYTES]), None);
        assert_eq!(decompress(&good[..good.len() - UNIT_BYTES]), None);
    }
}
