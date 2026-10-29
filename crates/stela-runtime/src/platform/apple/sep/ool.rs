//! SEP control's OOL registration prefix, without invented acknowledgements.
//!
//! `AppleSEPControl::cmsgSET_OOL_IN` (kernel file 0x2d85754) sends opcode
//! 4 (byte length), then 2 (IOVA >>12). OUT (0x2d858b0) uses 5 then 3.
//! Param selects the application service and each transaction has a nonzero
//! command-pool tag (`_cmsgSend`, 0x2d85250). IN is AP-to-SEP; OUT is SEP-to-AP.
//! This records the recovered prefix and performs bounded DMA for a future
//! implemented service. This prefix codec sends no reply; the active control
//! endpoint owns acknowledgements after its catalog and lifecycle checks.
//! Clear, relay and DMA-descriptor protocols remain explicit refusals.
use super::{
    message::{self, Frame},
    shared::Region,
};
use {stela_contracts::dma::DmaError, stela_contracts::dma::Port};

const SET_INPUT_ADDRESS: u8 = 2;
const SET_OUTPUT_ADDRESS: u8 = 3;
const SET_INPUT_LENGTH: u8 = 4;
const SET_OUTPUT_LENGTH: u8 = 5;
const PAGE_SHIFT: u32 = 12;
/// A Stela resource bound; discovery capacity bytes are not treated as sizes.
const MAX_BYTES: u32 = 32 * 1024 * 1024;

#[derive(Default)]
struct Buffer {
    pending: Option<u32>,
    region: Option<Region>,
}

impl Buffer {
    fn range(&self, offset: u64, bytes: usize) -> Result<Region, &'static str> {
        if self.pending.is_some() {
            return Err("SEP OOL registration is incomplete");
        }
        self.region
            .ok_or("SEP OOL buffer is not registered")?
            .subregion(offset, bytes as u64)
    }
}

pub struct Buffers {
    service: u8,
    input: Buffer,
    output: Buffer,
}

impl Buffers {
    /// The application service that owns these buffers.
    pub fn service(&self) -> u8 {
        self.service
    }

    /// The registered AP-to-SEP (input) buffer length in bytes, or zero when
    /// no input buffer has been registered yet. For observation only.
    pub fn input_len(&self) -> u64 {
        self.input.region.map_or(0, |region| region.bytes)
    }

    pub fn new(service: u8) -> Result<Self, &'static str> {
        if service == message::CONTROL || service > super::endpoint::MAX_SERVICE {
            return Err("SEP OOL owner is not an application service");
        }
        Ok(Self {
            service,
            input: Buffer::default(),
            output: Buffer::default(),
        })
    }

    /// Record only; returning Ok does not authorize sending an AP reply.
    /// The caller must separately implement the control transaction contract.
    /// No registration probes memory by overwriting guest bytes. Translation
    /// permissions and faults are checked on every DMA operation.
    pub fn record(&mut self, frame: Frame) -> Result<(), &'static str> {
        if frame.service != message::CONTROL || frame.tag == 0 || frame.parameter != self.service {
            return Err("SEP OOL setup service, tag or owner is invalid");
        }
        let (buffer, length) = match frame.opcode {
            SET_INPUT_LENGTH => (&mut self.input, true),
            SET_OUTPUT_LENGTH => (&mut self.output, true),
            SET_INPUT_ADDRESS => (&mut self.input, false),
            SET_OUTPUT_ADDRESS => (&mut self.output, false),
            _ => return Err("SEP OOL clear, relay or DMA command is not modeled"),
        };
        if length {
            if frame.data == 0 || frame.data > MAX_BYTES {
                return Err("SEP OOL length is zero or exceeds the resource bound");
            }
            if buffer.pending.is_some() {
                return Err("SEP OOL length is already awaiting an address");
            }
            buffer.pending = Some(frame.data);
        } else {
            let bytes = buffer
                .pending
                .ok_or("SEP OOL address arrived before its length")?;
            if frame.data == 0 {
                return Err("SEP OOL address is zero");
            }
            let region = Region {
                address: u64::from(frame.data) << PAGE_SHIFT,
                bytes: u64::from(bytes),
            };
            region
                .address
                .checked_add(region.bytes)
                .ok_or("SEP OOL extent overflows")?;
            buffer.region = Some(region);
            buffer.pending = None;
        }
        Ok(())
    }

    pub fn read_input(
        &self,
        port: &mut Port<'_, '_>,
        offset: u64,
        bytes: &mut [u8],
    ) -> Result<(), DmaError> {
        let region = self
            .input
            .range(offset, bytes.len())
            .map_err(DmaError::Unsupported)?;
        port.read(region.address, bytes)
    }

    /// As with Port::write, a later-page fault may follow earlier-page writes.
    /// Service state/replies must not be committed after such a failure.
    pub fn write_output(
        &self,
        port: &mut Port<'_, '_>,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), DmaError> {
        let region = self
            .output
            .range(offset, bytes.len())
            .map_err(DmaError::Unsupported)?;
        port.write(region.address, bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use {
        stela_contracts::bus::Access, stela_contracts::dma::Iommu, stela_contracts::dma::Memory,
        stela_contracts::dma::test_support::Ram, stela_contracts::interrupt::InterruptLatch,
    };
    fn frame(opcode: u8, data: u32) -> Frame {
        Frame {
            service: 0,
            tag: 1,
            opcode,
            parameter: 7,
            data,
        }
    }
    #[test]
    fn registrations_are_ordered_per_owner_and_direction_and_refusals_preserve_state() {
        assert!(Buffers::new(0).is_err());
        assert!(Buffers::new(0x20).is_err());
        assert!(Buffers::new(0xfc).is_err());
        assert!(Buffers::new(0xfd).is_err());
        let mut buffers = Buffers::new(7).unwrap();
        assert!(buffers.record(frame(2, 1)).is_err());
        assert!(buffers.record(frame(4, 0)).is_err());
        buffers.record(frame(4, 4097)).unwrap();
        assert!(buffers.record(frame(4, 10)).is_err());
        assert!(buffers.record(frame(2, 0)).is_err());
        assert!(
            buffers
                .record(Frame {
                    tag: 0,
                    ..frame(2, 1)
                })
                .is_err()
        );
        assert!(
            buffers
                .record(Frame {
                    parameter: 8,
                    ..frame(2, 1)
                })
                .is_err()
        );
        assert!(buffers.input.range(0, 1).is_err());
        buffers.record(frame(2, 1)).unwrap();
        assert_eq!(
            buffers.input.range(4096, 1),
            Ok(Region {
                address: 8192,
                bytes: 1
            })
        );
        assert!(buffers.input.range(4096, 2).is_err());
        assert!(buffers.output.range(0, 1).is_err());
        assert!(buffers.record(frame(6, 0)).is_err());
        assert_eq!(buffers.input.range(0, 1).unwrap().address, 4096);
        buffers.record(frame(5, 32)).unwrap();
        buffers.record(frame(3, 2)).unwrap();
        assert_eq!(buffers.output.range(0, 32).unwrap().address, 8192);
    }
    struct Mapper {
        deny_write: bool,
    }
    impl Iommu for Mapper {
        fn page(&self) -> u64 {
            16
        }
        fn translate(
            &mut self,
            _: &mut dyn Memory,
            stream: usize,
            iova: u64,
            last: u64,
            write: bool,
            _: &mut Access<'_>,
        ) -> Result<u64, DmaError> {
            assert_eq!(stream, 0);
            assert_eq!(iova / 16, last / 16);
            if write && self.deny_write {
                Err(DmaError::Fault(5))
            } else {
                Ok(iova + 0x10000)
            }
        }
    }
    #[test]
    fn input_reads_and_output_writes_use_dart_permissions_and_byte_bounds() {
        let mut buffers = Buffers::new(7).unwrap();
        buffers.record(frame(4, 32)).unwrap();
        buffers.record(frame(2, 1)).unwrap();
        buffers.record(frame(5, 32)).unwrap();
        buffers.record(frame(3, 2)).unwrap();
        let mut ram = Ram::new(0x11000, 0x2000);
        ram.bytes[..32].fill(0xaa);
        let mut mapper = Mapper { deny_write: false };
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut port = Port {
            iommu: &mut mapper,
            stream: 0,
            memory: &mut ram,
            access: &mut access,
        };
        let mut bytes = [0; 24];
        buffers.read_input(&mut port, 8, &mut bytes).unwrap();
        assert_eq!(bytes, [0xaa; 24]);
        buffers.write_output(&mut port, 8, &bytes).unwrap();
        assert!(buffers.read_input(&mut port, 9, &mut bytes).is_err());
        mapper.deny_write = true;
        let mut port = Port {
            iommu: &mut mapper,
            stream: 0,
            memory: &mut ram,
            access: &mut access,
        };
        assert_eq!(
            buffers.write_output(&mut port, 0, &[1]),
            Err(DmaError::Fault(5))
        );
        assert_eq!(&ram.bytes[0x1008..0x1020], &[0xaa; 24]);
        assert_eq!(ram.bytes[0x1000], 0);
    }
}
