//! Bind native TIB allocation to each original shader's USC Shared view.
//! Firmware allocates blocks; it does not provide a lossless per-sample
//! stride by dividing that rounded capacity. The shader supplies the view.

use super::super::WorkError;
use crate::platform::apple::agx::stream::usc::{Shared, layout};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeStorage {
    capacity: u64,
    stride: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleStorage {
    /// The explicit whole-pass helper's input, without native authority.
    Explicit(u32),
    Native(NativeStorage),
}
impl SampleStorage {
    pub(crate) fn native(blocks: u32) -> Self {
        Self::Native(NativeStorage {
            capacity: u64::from(blocks) * 2048,
            stride: None,
        })
    }
    pub(super) fn observe(
        &mut self,
        shared: Option<&Shared>,
        tile: (u32, u32),
        samples: u32,
    ) -> Result<(), WorkError> {
        let Some(shared) = shared.filter(|shared| shared.uses_shared_memory) else {
            return Ok(());
        };
        let shape = match shared.layout {
            layout::TILE_32X32 => (32, 32),
            layout::TILE_32X16 => (32, 16),
            layout::TILE_16X16 => (16, 16),
            _ => {
                return Err(WorkError::Refused(
                    "3D threadgroup Shared storage is not qualified",
                ));
            }
        };
        if shape != tile || shared.samples != samples {
            return Err(WorkError::Refused(
                "3D shader Shared layout differs from native tile/samples",
            ));
        }
        let stride = shared.sample_stride_bytes;
        if stride == 0 {
            return Err(WorkError::Refused("zero USC tile stride is not qualified"));
        }
        let bytes = u64::from(tile.0) * u64::from(tile.1) * u64::from(samples) * u64::from(stride);
        if bytes > u64::from(shared.bytes_per_threadgroup) {
            return Err(WorkError::Refused(
                "3D tile view exceeds shader Shared allocation",
            ));
        }
        match self {
            Self::Explicit(bytes) if *bytes != stride => {
                return Err(WorkError::Refused(
                    "3D shader Shared stride differs from the explicit tile view",
                ));
            }
            Self::Native(native) => {
                if bytes > native.capacity {
                    return Err(WorkError::Refused(
                        "3D shader Shared view exceeds native TIB allocation",
                    ));
                }
                if native.stride.is_some_and(|old| old != stride) {
                    return Err(WorkError::Refused(
                        "inconsistent 3D shader Shared strides are not qualified",
                    ));
                }
                native.stride = Some(stride);
            }
            _ => {}
        }
        Ok(())
    }
    pub(super) fn bytes(&self) -> Result<u32, WorkError> {
        match self {
            Self::Explicit(bytes) => Ok(*bytes),
            Self::Native(native) => {
                native
                    .stride
                    .or((native.capacity == 0).then_some(0))
                    .ok_or(WorkError::Refused(
                        "native 3D sample stride has no shader Shared binding",
                    ))
            }
        }
    }
    pub(super) fn tile_access(&self, shared: Option<&Shared>) -> bool {
        match shared {
            Some(shared) => {
                shared.uses_shared_memory
                    && matches!(
                        shared.layout,
                        layout::TILE_32X32 | layout::TILE_32X16 | layout::TILE_16X16
                    )
            }
            None => matches!(self, Self::Explicit(_)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn shared(tile: (u32, u32), samples: u32, stride: u32) -> Shared {
        Shared {
            uses_shared_memory: true,
            layout: match tile {
                (32, 32) => layout::TILE_32X32,
                (32, 16) => layout::TILE_32X16,
                (16, 16) => layout::TILE_16X16,
                _ => panic!(),
            },
            samples,
            sample_stride_bytes: stride,
            bytes_per_threadgroup: tile.0 * tile.1 * samples * stride,
        }
    }
    #[test]
    fn native_allocation_does_not_invent_stride_and_shader_views_must_agree() {
        for tile in [(32, 32), (32, 16), (16, 16)] {
            for samples in [1, 2, 4] {
                let bytes: u32 = tile.0 * tile.1 * samples * 8;
                let mut storage = SampleStorage::native(bytes.div_ceil(2048));
                assert!(storage.bytes().is_err());
                assert!(!storage.tile_access(None));
                let view = shared(tile, samples, 8);
                storage.observe(Some(&view), tile, samples).unwrap();
                assert_eq!(storage.bytes(), Ok(8));
                assert!(storage.tile_access(Some(&view)));
                storage.observe(Some(&view), tile, samples).unwrap();
                let before = storage;
                for invalid in [
                    shared(tile, samples, 16),
                    shared(tile, samples, 0),
                    shared(tile, 8, 8),
                    Shared {
                        bytes_per_threadgroup: 256,
                        ..view
                    },
                ] {
                    assert!(storage.observe(Some(&invalid), tile, samples).is_err());
                    assert_eq!(storage, before);
                }
                let mut too_small = SampleStorage::native((bytes - 1) / 2048);
                let before = too_small;
                assert!(too_small.observe(Some(&view), tile, samples).is_err());
                assert_eq!(too_small, before);
            }
        }
        let no_tile = Shared {
            uses_shared_memory: false,
            layout: layout::VERTEX_COMPUTE,
            samples: 1,
            sample_stride_bytes: 0,
            bytes_per_threadgroup: 65536,
        };
        let mut empty = SampleStorage::native(0);
        empty.observe(Some(&no_tile), (32, 32), 1).unwrap();
        assert_eq!(empty.bytes(), Ok(0));
        assert!(!empty.tile_access(Some(&no_tile)));
        let helper = SampleStorage::Explicit(4);
        assert!(helper.tile_access(None));
        assert!(!helper.tile_access(Some(&no_tile)));
    }
}
