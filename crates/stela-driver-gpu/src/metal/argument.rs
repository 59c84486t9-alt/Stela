//! `newArgumentEncoderWithArguments:`: an argument buffer's layout from its
//! `MTLArgumentDescriptor`s, as the MSL structure declaring the same
//! arguments in `[[id]]` order lays it out. A resource is its 8-byte
//! address or `MTLResourceID`; data takes its type's size and alignment, a
//! three-lane vector those of four lanes.
use super::{
    abi::DataType,
    error::{Error, Result, ensure},
};
use alloc::vec::Vec;

/// Bytes and alignment of a resource's address or ID.
const RESOURCE_BYTES: u32 = 8;

/// An `MTLArgumentDescriptor`; an `array_length` of zero is one argument.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArgumentDescriptor {
    pub data_type: DataType,
    pub index: u32,
    pub array_length: u32,
    /// `constantBlockAlignment`: the least alignment of inline data.
    pub constant_block_alignment: u32,
}

/// Where each argument's first element is, in the descriptors' order, and
/// the encoder's `encodedLength` and `alignment`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArgumentLayout {
    pub offsets: Vec<u32>,
    pub encoded_length: u32,
    pub alignment: u32,
}

pub fn layout(arguments: &[ArgumentDescriptor]) -> Result<ArgumentLayout> {
    let mut order: Vec<usize> = (0..arguments.len()).collect();
    order.sort_unstable_by_key(|&argument| arguments[argument].index);
    let mut offsets = alloc::vec![0; arguments.len()];
    let (mut end, mut alignment, mut next_index) = (0u32, 1u32, 0u64);
    for argument in order {
        let descriptor = &arguments[argument];
        let elements = descriptor.array_length.max(1);
        ensure(
            u64::from(descriptor.index) >= next_index,
            "argument indices overlap",
        )?;
        next_index = u64::from(descriptor.index) + u64::from(elements);
        let (size, natural) = footprint(descriptor.data_type)?;
        let block = descriptor.constant_block_alignment;
        ensure(
            block == 0 || block.is_power_of_two(),
            "a constant block alignment is a power of two",
        )?;
        let aligned = natural.max(block);
        let offset = end
            .checked_next_multiple_of(aligned)
            .ok_or(Error::Invalid("arguments exceed an argument buffer"))?;
        end = size
            .checked_mul(elements)
            .and_then(|bytes| offset.checked_add(bytes))
            .ok_or(Error::Invalid("arguments exceed an argument buffer"))?;
        offsets[argument] = offset;
        alignment = alignment.max(aligned);
    }
    Ok(ArgumentLayout {
        offsets,
        encoded_length: end
            .checked_next_multiple_of(alignment)
            .ok_or(Error::Invalid("arguments exceed an argument buffer"))?,
        alignment,
    })
}

/// The size and alignment of one element of `data_type`.
fn footprint(data_type: DataType) -> Result<(u32, u32)> {
    // A vector's storage: three lanes take four.
    let vector = |bytes: usize, lanes: usize| {
        let stored = (bytes * if lanes == 3 { 4 } else { lanes }) as u32;
        (stored, stored)
    };
    if let Some((bytes, lanes)) = data_type.lanes() {
        return Ok(vector(bytes, lanes));
    }
    // `MTLDataType{Float,Half}{columns}x{rows}`: columns of `rows`-lane
    // vectors.
    let matrix = |first: DataType, bytes| {
        let at = (data_type.raw() - first.raw()) as usize;
        let (columns, rows) = (at / 3 + 2, at % 3 + 2);
        let (column, alignment) = vector(bytes, rows);
        (column * columns as u32, alignment)
    };
    Ok(match data_type.raw() {
        7..=15 => matrix(DataType::Float2x2, 4),
        20..=28 => matrix(DataType::Half2x2, 2),
        _ => match data_type {
            DataType::Texture
            | DataType::Sampler
            | DataType::Pointer
            | DataType::RenderPipeline
            | DataType::ComputePipeline
            | DataType::IndirectCommandBuffer
            | DataType::VisibleFunctionTable
            | DataType::IntersectionFunctionTable
            | DataType::PrimitiveAccelerationStructure
            | DataType::InstanceAccelerationStructure => (RESOURCE_BYTES, RESOURCE_BYTES),
            _ => return Err(Error::Invalid("an argument descriptor's data type")),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argument(data_type: DataType, index: u32, array_length: u32) -> ArgumentDescriptor {
        ArgumentDescriptor {
            data_type,
            index,
            array_length,
            constant_block_alignment: 0,
        }
    }

    #[test]
    fn arguments_lay_out_as_their_structure_in_index_order() {
        // struct { texture2d t[2] [[id(0)]]; float k [[id(2)]];
        //          float3 v [[id(3)]]; device float *d [[id(4)]];
        //          half3x3 m [[id(5)]]; }, given out of order.
        let arguments = [
            argument(DataType::Pointer, 4, 0),
            argument(DataType::Texture, 0, 2),
            argument(DataType::Float, 2, 0),
            argument(DataType::Float3, 3, 0),
            argument(DataType::Half3x3, 5, 0),
        ];
        assert_eq!(
            layout(&arguments),
            Ok(ArgumentLayout {
                offsets: alloc::vec![48, 0, 16, 32, 56],
                encoded_length: 80,
                alignment: 16,
            })
        );
    }

    #[test]
    fn constant_blocks_take_their_alignment() {
        let mut block = argument(DataType::UChar, 1, 12);
        block.constant_block_alignment = 64;
        let layout = layout(&[argument(DataType::Sampler, 0, 0), block]).unwrap();
        assert_eq!(
            (layout.offsets, layout.encoded_length, layout.alignment),
            (alloc::vec![0, 64], 128, 64)
        );
    }

    #[test]
    fn malformed_descriptors_are_refused() {
        let overlapping = [
            argument(DataType::Texture, 0, 2),
            argument(DataType::Float, 1, 0),
        ];
        assert_eq!(
            layout(&overlapping),
            Err(Error::Invalid("argument indices overlap"))
        );
        assert_eq!(
            layout(&[argument(DataType::Struct, 0, 0)]),
            Err(Error::Invalid("an argument descriptor's data type"))
        );
        let mut unaligned = argument(DataType::Float, 0, 0);
        unaligned.constant_block_alignment = 12;
        assert!(layout(&[unaligned]).is_err());
        assert!(layout(&[argument(DataType::Float4, 0, u32::MAX)]).is_err());
    }
}
