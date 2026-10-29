// SPDX-License-Identifier: GPL-2.0-only
//! Adapter from the UAS engine to the shared storage discovery contract.
use super::*;

impl crate::usb::storage::Scsi for ScsiModel {
    type Lun = Lun;
    fn command(&mut self, lun: Lun, cdb: &[u8], data: Data<'_>) -> Result<Vec<u8>, BlockError> {
        execute(&mut self.engine, self.flags, lun.bytes(), cdb, data)
    }
    fn delay(&self, micros: u64) {
        self.engine
            .io
            .clock
            .set(self.engine.io.clock.get() + micros);
    }
    fn now_us(&self) -> u64 {
        self.engine.io.clock.get()
    }
    fn poisoned(&self) -> bool {
        self.engine.poisoned
    }
    fn take_failed_data(&mut self) -> Option<Vec<u8>> {
        self.engine.failed_data.take()
    }
    fn write_protect_page(&self) -> Option<u8> {
        (!self.flags.always_sync()).then_some(crate::usb::storage::scsi::ALL_PAGES)
    }
    fn caching(&self) -> crate::usb::storage::Caching {
        match self.flags.always_sync() {
            true => crate::usb::storage::Caching::WriteBack,
            false => crate::usb::storage::Caching::Query,
        }
    }
    fn report_luns_permitted(&self) -> bool {
        self.flags.report_luns_permitted()
    }
    fn read_before_mode_sense(&mut self, lun: Lun, block_size: usize) -> Result<(), BlockError> {
        read_block_zero(&mut self.engine, self.flags, lun.bytes(), block_size)
    }
    fn max_transfer_bytes(&self) -> usize {
        self.flags.max_transfer_bytes()
    }
}
