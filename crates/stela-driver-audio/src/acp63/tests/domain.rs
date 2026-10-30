// SPDX-License-Identifier: GPL-2.0-only
//! DMA translation, coherency and retirement for the synchronous model.
use super::*;

// SAFETY: isolated synchronous model, real owned CPU RAM and symbolic
// physical/IOVA labels. Device accesses walk programmed ACP PTEs
// through this domain; no identity DMA or production hardware is claimed.
unsafe impl DmaDomain for Domain {
    unsafe fn map(
        &self,
        pages: &DmaPages,
        direction: DmaDirection,
        limit: u64,
    ) -> Result<DomainMapping, DmaError> {
        assert_eq!(direction, DmaDirection::FromDevice);
        if IOVA + pages.bytes() as u64 - 1 > limit {
            return Err(DmaError::AddressLimit);
        }
        let mut device = self.0.lock().unwrap();
        assert!(device.translation.is_none());
        device.published_reset = None;
        device.maps += 1;
        let token = DomainMapping {
            id: device.maps as u64,
            address: IOVA,
            bytes: pages.bytes(),
        };
        device.translation = Some(Translation {
            token,
            cpu: pages
                .as_single()
                .unwrap()
                .cpu_mapping(CacheAttribute::WriteBack)
                .unwrap(),
            pages: pages.clone(),
        });
        Ok(token)
    }
    unsafe fn unmap(&self, token: DomainMapping) -> Result<(), DmaError> {
        let mut device = self.0.lock().unwrap();
        assert_eq!(device.words[0x2c08 / 4], 0);
        assert!(!device.master);
        assert_eq!(device.words[0x2c04 / 4], 0);
        assert_eq!(device.words[0xc04 / 4] & 0x8000_0000, 0);
        if let Some(published) = device.published_reset {
            assert!(device.resets > published, "release requires a fresh reset");
            let last = |effect| {
                device
                    .retirement
                    .iter()
                    .rposition(|e| *e == effect)
                    .unwrap()
            };
            assert!(last(Retirement::ResetAcknowledged) < last(Retirement::GroupDisabled));
            assert!(last(Retirement::GroupDisabled) < last(Retirement::BusMaster(false)));
            assert!(last(Retirement::BusMaster(false)) < last(Retirement::PayloadDrained));
        }
        assert_eq!(device.translation.as_ref().unwrap().token, token);
        assert!(
            device.posted.is_empty(),
            "unmap before actual payload drain"
        );
        if device.unmap_fail {
            return Err(DmaError::InvalidationFailed);
        }
        device.translation = None;
        device.unmaps += 1;
        Ok(())
    }
    unsafe fn sync_for_device(
        &self,
        token: DomainMapping,
        range: Range<usize>,
        direction: DmaDirection,
    ) -> Result<(), DmaError> {
        let mut device = self.0.lock().unwrap();
        assert_eq!(direction, DmaDirection::FromDevice);
        assert_eq!(device.words[0x2c08 / 4], 0);
        assert_eq!(device.translation.as_ref().unwrap().token, token);
        assert!(range.end <= token.bytes);
        if device.sync_fail {
            return Err(DmaError::VisibilityFailed);
        }
        device.device_syncs += 1;
        device.device_owns = true;
        Ok(())
    }
    unsafe fn sync_for_cpu(
        &self,
        token: DomainMapping,
        range: Range<usize>,
        direction: DmaDirection,
    ) -> Result<(), DmaError> {
        let mut device = self.0.lock().unwrap();
        assert_eq!(direction, DmaDirection::FromDevice);
        assert_eq!(device.words[0x2c08 / 4], 0);
        assert_eq!(device.words[0x2c04 / 4], 0);
        assert_eq!(device.translation.as_ref().unwrap().token, token);
        assert!(range.end <= token.bytes);
        if device.sync_fail {
            return Err(DmaError::VisibilityFailed);
        }
        assert!(
            device.posted.is_empty(),
            "CPU handoff before actual payload drain"
        );
        device.cpu_syncs += 1;
        device.device_owns = false;
        Ok(())
    }
    unsafe fn read_coherent_u32(
        &self,
        token: DomainMapping,
        offset: usize,
        direction: DmaDirection,
    ) -> Result<u32, DmaError> {
        let mut device = self.0.lock().unwrap();
        assert_eq!(direction, DmaDirection::FromDevice);
        assert!(offset.is_multiple_of(4));
        assert!(offset + 4 <= token.bytes);
        assert_eq!(device.translation.as_ref().unwrap().token, token);
        assert!(device.device_owns);
        if device.coherence_unavailable {
            return Err(DmaError::CoherenceUnavailable);
        }
        let pointer = device
            .translation
            .as_ref()
            .unwrap()
            .cpu
            .address(offset, 4)
            .unwrap();
        // SAFETY: model-owned kept mapping, per-word coherent
        // observation; no CPU writers or ownership transfer are invented.
        let observed = unsafe { pointer.as_ptr().cast::<u32>().read_volatile() };
        device.coherent_reads += 1;
        if let Some((at, frames)) = device.advance_on_coherent
            && at == device.coherent_reads
        {
            device.advance_on_coherent = None;
            // Source-completed producer progress races this individual
            // word observation, including wrap into its oldest period.
            device.advance(frames);
        }
        Ok(u32::from_le(observed))
    }
    unsafe fn drain_posted_writes(&self) -> Result<(), DmaError> {
        let mut device = self.0.lock().unwrap();
        assert_eq!(device.words[0x2c08 / 4], 0);
        assert_eq!(device.words[0x2c04 / 4], 0);
        if device.drain_unavailable {
            return Err(DmaError::DrainUnavailable);
        }
        if device.drain_fail {
            return Err(DmaError::InvalidationFailed);
        }
        device.drains += 1;
        device.retirement.push(Retirement::PayloadDrained);
        let pending = core::mem::take(&mut device.posted);
        for (offset, sample) in pending {
            let translation = device.translation.as_ref().unwrap();
            let pointer = translation.cpu.address(offset, 4).unwrap();
            // SAFETY: this independent fabric completion finishes its
            // queued writes into the exact domain mapping.
            unsafe { pointer.as_ptr().cast::<i32>().write_volatile(sample) };
        }
        Ok(())
    }
}
