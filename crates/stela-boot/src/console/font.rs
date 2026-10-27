//! The console's bitmap font: Spleen 2.1.0 8x16, Copyright (c) 2018-2024,
//! Frederic Cambus (BSD-2-Clause, `LICENSES/BSD-2-Clause.txt`), in the Linux
//! console's PSF1 or PSF2 format. Each glyph is `height` rows of `width` bits,
//! MSB first, each row padded to whole bytes. Spleen's first 256 glyphs are in code
//! point order, so ASCII indexes them directly.

/// One font, parsed from its PSF file.
pub struct Font {
    pub width: usize,
    pub height: usize,
    row_bytes: usize,
    glyph_bytes: usize,
    glyphs: &'static [u8],
}

const PSF1_MAGIC: [u8; 2] = [0x36, 0x04];
const PSF1_512: u8 = 1;
const PSF2_MAGIC: [u8; 4] = [0x72, 0xb5, 0x4a, 0x86];
/// The glyphs the console draws: printable ASCII and below.
const GLYPHS: usize = 0x80;

fn word(file: &[u8], offset: usize) -> Option<usize> {
    let bytes = file.get(offset..offset + 4)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?) as usize)
}

impl Font {
    pub fn parse(file: &'static [u8]) -> Option<Self> {
        let (width, height, header, count, glyph_bytes) = if file.starts_with(&PSF1_MAGIC) {
            let height = usize::from(*file.get(3)?);
            let count = if file.get(2)? & PSF1_512 != 0 {
                512
            } else {
                256
            };
            (8, height, 4, count, height)
        } else if file.starts_with(&PSF2_MAGIC) {
            let header = word(file, 8)?;
            (
                word(file, 28)?,
                word(file, 24)?,
                header,
                word(file, 16)?,
                word(file, 20)?,
            )
        } else {
            return None;
        };
        let row_bytes = width.div_ceil(8);
        if width == 0 || height == 0 || glyph_bytes != row_bytes * height || count < GLYPHS {
            return None;
        }
        let glyphs = file.get(header..header + GLYPHS * glyph_bytes)?;
        Some(Self {
            width,
            height,
            row_bytes,
            glyph_bytes,
            glyphs,
        })
    }

    /// Whether pixel (`x`, `y`) of `character`'s glyph is set; anything
    /// outside ASCII draws as `?`.
    pub fn pixel(&self, character: u8, x: usize, y: usize) -> bool {
        let index = if usize::from(character) < GLYPHS {
            character
        } else {
            b'?'
        };
        let row = usize::from(index) * self.glyph_bytes + y * self.row_bytes;
        self.glyphs[row + x / 8] & (0x80 >> (x % 8)) != 0
    }
}

/// The one font, drawn at whole multiples of its pixels.
static SPLEEN: &[u8] = include_bytes!("spleen-8x16.psfu");

pub fn console() -> Option<Font> {
    Font::parse(SPLEEN)
}
