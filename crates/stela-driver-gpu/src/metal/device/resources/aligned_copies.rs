//! Aligned copies of linear textures whose rows the GPU cannot address in
//! place.
//!
//! Metal takes a buffer's or IOSurface's rows at any whole number of pixels
//! a row that the device's linear alignment allows, and macOS lays out
//! IOSurface planes to Apple GPUs' 16 bytes: an '&b38' screen surface's
//! alpha plane is one byte a pixel, its row the screen's width, as 3440 or
//! 1680. NVIDIA's linear images need 32-byte row pitches and offsets
//! ([`resource::linear_layout_fits`]). Such a plane's texture is an image in
//! the GPU's own layout instead, its aligned copy, which copies keep equal
//! to the rows, the guest's memory, where the CPU, the display and other
//! textures read and write them:
//!
//! - every command buffer begins by copying each aligned copy's rows into
//!   it, as anything may have written the rows since (the CPU, the display,
//!   another texture over the same surface);
//! - a command buffer that writes a texture (attaches it to a pass, blits
//!   into it, binds it for shader writes) ends by copying the aligned copy
//!   back into its rows;
//! - a pass that encodes a two-plane extended-range texture's planes, which
//!   it writes in the rows themselves, copies the rows into the aligned
//!   copies after it, for the command buffer's later reads;
//! - the CPU's copies of such a texture convert row by row in the rows.
//!
//! A texture whose rows fit keeps its linear image placed in the rows: no
//! copy at all.
use super::{Device, TextureId};
use crate::metal::{
    abi::TextureUsage,
    command_buffer::CommandBuffer,
    error::{Error, Result},
    hazard::FULL,
    pixel_format::Encoding,
    resource::{self, PlaneLayout, TexturePlan},
    shader::Compiler,
    vulkan::{
        ImageAspects, MemoryProperties,
        backend::Backend,
        command::{BufferImageCopy, Command, Subresource},
        object::{Buffer, Image, Memory, MemoryRequest},
    },
};
use alloc::vec::Vec;

/// A plane's aligned copy: its image and memory, and the copy between it
/// and the plane's rows.
#[derive(Debug)]
pub(in crate::metal::device) struct AlignedCopy {
    memory: Memory,
    bytes: u64,
    rows: RowCopy,
    /// The rows' memory and where they start in it, for the CPU's copies.
    rows_memory: Memory,
    place: u64,
    bytes_per_row: u64,
    texel_bytes: u64,
}

/// A copy between a plane's rows in `buffer` and its aligned copy `image`,
/// both ways: `region` names the rows by their offset and their pitch in
/// texels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RowCopy {
    pub buffer: Buffer,
    pub image: Image,
    pub region: BufferImageCopy,
}

impl RowCopy {
    /// The copy into the aligned copy, which reads the rows.
    pub fn refresh(&self) -> Command {
        Command::CopyBufferToImage {
            src: self.buffer,
            dst: self.image,
            region: self.region,
        }
    }

    /// The copy back into the rows.
    pub fn write_back(&self) -> Command {
        Command::CopyImageToBuffer {
            src: self.image,
            dst: self.buffer,
            region: self.region,
        }
    }
}

/// Where a plane's rows lie: in `buffer`, bound `memory_offset` bytes into
/// `memory`, at `layout`, of `texel_bytes` pixels.
#[derive(Clone, Copy, Debug)]
pub(in crate::metal::device) struct Rows {
    pub buffer: Buffer,
    pub memory: Memory,
    pub memory_offset: u64,
    pub layout: PlaneLayout,
    pub texel_bytes: u64,
}

impl<B: Backend, C: Compiler> Device<B, C> {
    /// The image of a linear plane `plan` over `rows`: its linear image
    /// placed in the rows when the GPU addresses them in place, else its
    /// aligned copy, which the caller keeps with the texture
    /// ([`Self::keep_aligned_copies`]) or releases
    /// ([`Self::release_aligned_copies`]) once it destroyed the image.
    pub(in crate::metal::device) fn plane_image(
        &mut self,
        plan: &TexturePlan,
        rows: Rows,
    ) -> Result<(Image, Option<AlignedCopy>)> {
        let Rows {
            buffer,
            memory,
            memory_offset,
            layout,
            texel_bytes,
        } = rows;
        let place = memory_offset
            .checked_add(layout.offset)
            .ok_or(Error::Invalid("the rows lie past the memory"))?;
        if resource::linear_layout_fits(&self.capabilities, place, layout.bytes_per_row) {
            let image = self
                .backend
                .create_placed_image(&plan.image, memory, place)?;
            return Ok((image, None));
        }
        let row_length = u32::try_from(layout.bytes_per_row / texel_bytes.max(1))
            .map_err(|_| Error::Invalid("bytesPerRow exceeds the row pitch range"))?;
        let info = resource::aligned_copy(&plan.image);
        let request = MemoryRequest {
            required: MemoryProperties::DEVICE_LOCAL,
            preferred: MemoryProperties::EMPTY,
            mapped: false,
        };
        let (image, copy_memory, bytes) = self.backend.create_image(&info, request)?;
        self.allocated += bytes;
        let [width, height, _] = info.extent;
        let region = BufferImageCopy {
            buffer_offset: layout.offset,
            buffer_row_length: row_length,
            buffer_image_height: 0,
            subresource: Subresource {
                aspects: ImageAspects::COLOR,
                mip_level: 0,
                base_array_layer: 0,
                layer_count: 1,
            },
            offset: [0; 3],
            extent: [width, height, 1],
        };
        Ok((
            image,
            Some(AlignedCopy {
                memory: copy_memory,
                bytes,
                rows: RowCopy {
                    buffer,
                    image,
                    region,
                },
                rows_memory: memory,
                place,
                bytes_per_row: layout.bytes_per_row,
                texel_bytes,
            }),
        ))
    }

    /// Releases the memory of aligned copies whose images are destroyed.
    pub(in crate::metal::device) fn release_aligned_copies(
        &mut self,
        copies: impl IntoIterator<Item = AlignedCopy>,
    ) {
        for copy in copies {
            self.release_memory(copy.memory, copy.bytes);
        }
    }

    /// Keeps texture `id`'s aligned copies, which commits then refresh.
    pub(in crate::metal::device) fn keep_aligned_copies(
        &mut self,
        id: TextureId,
        copies: Vec<AlignedCopy>,
    ) {
        if copies.is_empty() {
            return;
        }
        // Shader writes reach the rows from command buffers that bind the
        // texture or attach it; one written only through an argument
        // buffer leaves them in the aligned copy.
        let writable = self.resources.textures.get(id.0).is_ok_and(|texture| {
            texture
                .descriptor
                .usage
                .contains(TextureUsage::SHADER_WRITE)
        });
        if writable {
            self.unsupported(
                "shader writes through argument buffers alone to textures in rows the GPU \
                 cannot address in place",
            );
        }
        self.resources.aligned_copies.insert(id.0, copies);
    }

    /// Takes texture `id`'s aligned copies as it is destroyed.
    pub(in crate::metal::device) fn take_aligned_copies(
        &mut self,
        id: TextureId,
    ) -> Option<Vec<AlignedCopy>> {
        self.resources.aligned_copies.remove(&id.0)
    }

    /// Whether texture `id`, or the texture it views, is an aligned copy.
    pub fn has_aligned_copy(&self, id: TextureId) -> bool {
        self.aligned_root(id).is_some()
    }

    /// The texture with aligned copies that `id` is or views.
    fn aligned_root(&self, id: TextureId) -> Option<TextureId> {
        let mut root = id;
        loop {
            if self.resources.aligned_copies.contains_key(&root.0) {
                return Some(root);
            }
            root = self.resources.textures.get(root.0).ok()?.parent?;
        }
    }

    /// Notes that `commands` writes texture `id`, which its end then copies
    /// back into the rows when it is an aligned copy. An extended-range
    /// IOSurface texture writes its rows itself.
    pub fn note_texture_write(&self, commands: &mut CommandBuffer, id: TextureId) {
        let Some(root) = self.aligned_root(id) else {
            return;
        };
        if self.has_extended_planes(root) {
            return;
        }
        if !commands.aligned_writes.contains(&root) {
            commands.aligned_writes.push(root);
        }
    }

    /// Notes a texture bound for shaders: one they may write is written.
    pub fn note_texture_binding(&self, commands: &mut CommandBuffer, id: TextureId) {
        let writes = self.resources.textures.get(id.0).is_ok_and(|texture| {
            texture
                .descriptor
                .usage
                .contains(TextureUsage::SHADER_WRITE)
        });
        if writes {
            self.note_texture_write(commands, id);
        }
    }

    /// The copies a command buffer begins with, each aligned copy's rows
    /// into it, and those it ends with, back into the rows of the textures
    /// it wrote (`written`); each followed by a full barrier, and empty when
    /// there are none.
    pub(in crate::metal::device) fn aligned_copy_commands(
        &self,
        written: &[TextureId],
    ) -> (Vec<Command>, Vec<Command>) {
        let copies = &self.resources.aligned_copies;
        let mut lead: Vec<Command> = copies
            .values()
            .flatten()
            .map(|copy| copy.rows.refresh())
            .collect();
        let mut tail: Vec<Command> = written
            .iter()
            .filter_map(|id| copies.get(&id.0))
            .flatten()
            .map(|copy| copy.rows.write_back())
            .collect();
        for commands in [&mut lead, &mut tail] {
            if !commands.is_empty() {
                commands.push(Command::Barrier(FULL));
            }
        }
        (lead, tail)
    }

    /// The copies that refresh an extended-range IOSurface texture's
    /// planes' aligned copies after a pass encodes the planes: the first
    /// plane's and the second's.
    pub(in crate::metal::device) fn plane_refreshes(&self, id: TextureId) -> [Option<RowCopy>; 2] {
        let mut refreshes = [None; 2];
        let Some(copies) = self.resources.aligned_copies.get(&id.0) else {
            return refreshes;
        };
        let Ok(texture) = self.resources.textures.get(id.0) else {
            return refreshes;
        };
        for copy in copies {
            if Some(copy.rows.image) == texture.image {
                refreshes[0] = Some(copy.rows);
            } else if Some(copy.rows.image) == texture.second_plane {
                refreshes[1] = Some(copy.rows);
            }
        }
        refreshes
    }

    /// Writes `region` of an aligned copy's texture from tightly packed
    /// `bytes` into its rows, which the next commit copies into it.
    /// `Ok(false)` for a texture without an aligned copy.
    pub(super) fn write_aligned_rows(
        &mut self,
        id: TextureId,
        region: &BufferImageCopy,
        bytes: &[u8],
    ) -> Result<bool> {
        let Some((memory, rows)) = self.aligned_rows(id, region, bytes.len())? else {
            return Ok(false);
        };
        for (offset, packed) in rows {
            self.backend.write_memory(memory, offset, &bytes[packed])?;
        }
        Ok(true)
    }

    /// Reads `region` of an aligned copy's texture into tightly packed
    /// `bytes` from its rows. `Ok(false)` for a texture without an aligned
    /// copy.
    pub(super) fn read_aligned_rows(
        &mut self,
        id: TextureId,
        region: &BufferImageCopy,
        bytes: &mut [u8],
    ) -> Result<bool> {
        let Some((memory, rows)) = self.aligned_rows(id, region, bytes.len())? else {
            return Ok(false);
        };
        for (offset, packed) in rows {
            self.backend
                .read_memory(memory, offset, &mut bytes[packed])?;
        }
        Ok(true)
    }

    /// The rows' memory and each row of `region` in it, with its bytes in
    /// a packed copy of `length` bytes; `None` for a texture without an
    /// aligned copy. Only formats whose texels the rows hold as the image
    /// does are copied.
    #[allow(clippy::type_complexity)]
    fn aligned_rows(
        &self,
        id: TextureId,
        region: &BufferImageCopy,
        length: usize,
    ) -> Result<Option<(Memory, Vec<(u64, core::ops::Range<usize>)>)>> {
        if !self.resources.aligned_copies.contains_key(&id.0) {
            return Ok(None);
        }
        let texture = self.resources.textures.get(id.0)?;
        let copy = self
            .resources
            .aligned_copies
            .get(&id.0)
            .and_then(|copies| {
                copies
                    .iter()
                    .find(|copy| Some(copy.rows.image) == texture.image)
            })
            .ok_or(Error::Invalid(
                "the texture's image is not its aligned copy",
            ))?;
        if !matches!(
            texture.descriptor.pixel_format.describe().encoding(),
            Encoding::Exact
        ) {
            return Err(Error::Unsupported(
                "CPU copies of converted formats in rows the GPU cannot address in place",
            ));
        }
        let [x, y, _] = region.offset;
        let [width, height, depth] = region.extent;
        let (x, y) = (
            u64::try_from(x).map_err(|_| Error::Invalid("negative region origin"))?,
            u64::try_from(y).map_err(|_| Error::Invalid("negative region origin"))?,
        );
        let row_bytes = u64::from(width) * copy.texel_bytes;
        let rows = u64::from(height) * u64::from(depth.max(1));
        let packed = row_bytes
            .checked_mul(rows)
            .and_then(|bytes| usize::try_from(bytes).ok())
            .ok_or(Error::Invalid("the region overflows"))?;
        if packed > length {
            return Err(Error::Invalid("the bytes end before the region"));
        }
        let ranges = (0..u64::from(height))
            .map(|row| {
                let offset = copy.place + (y + row) * copy.bytes_per_row + x * copy.texel_bytes;
                let start = (row * row_bytes) as usize;
                (offset, start..start + row_bytes as usize)
            })
            .collect();
        Ok(Some((copy.rows_memory, ranges)))
    }
}

#[cfg(test)]
mod tests;
