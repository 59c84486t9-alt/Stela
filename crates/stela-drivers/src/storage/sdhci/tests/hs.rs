//! Generic four-pin hosts use the shared ordinary-MMC procedure without fast hooks.
use super::*;

#[test]
fn generic_four_pin_mmc_hs_validates_width_at_hs_clock_and_selects_low_power_nibble() {
    for card_type in [1, 3] {
        for pio in [false, true] {
            let mut backing = vec![0u64; 128 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: backing outlives every controller/card and its DMA aliases.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut host, model) = host(&mut dma, Kind::Mmc, true, pio);
            {
                let mut hardware = model.borrow_mut();
                hardware.ext[196] = card_type;
                hardware.ext[200..204].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
                hardware.mmc_sdr_hs_checks = true;
            }
            let mut disk = host.poll().unwrap().unwrap();
            assert_eq!(disk.info().bus_width, 4);
            assert_eq!(
                disk.info().clock_hz,
                if card_type == 1 {
                    25_000_000
                } else {
                    50_000_000
                }
            );
            assert_eq!(model.borrow().ext[187], if card_type == 1 { 8 } else { 6 });
            let mut bytes = vec![0xa5; 1024];
            disk.read(3, &mut bytes).unwrap();
            assert_eq!(bytes, model.borrow().disk[3 * 512..5 * 512]);
            bytes.fill(0xd3);
            disk.write(6, &bytes).unwrap();
            disk.flush().unwrap();
            assert_eq!(bytes, model.borrow().disk[6 * 512..8 * 512]);
            let mut alias = disk.clone();
            disk.shutdown(true).unwrap();
            assert_eq!(alias.flush(), Err(BlockError::Unsupported(STALE)));
        }
    }
}
