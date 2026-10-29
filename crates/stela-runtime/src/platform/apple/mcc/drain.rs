//! Original DCS flush preserves opaque high16 and clears both low bytes.
//! KC2e4971c..2e497f4 reads at778, masks at784/790 and writes at7ac.
//! Only Prepared may associate this control image with a live RAM drain.
use super::*;

impl Controller {
    pub(crate) fn drain_control(&self, aperture: u8, offset: u64) -> Result<u32, &'static str> {
        let state = self
            .0
            .try_borrow()
            .map_err(|_| "DCS control image is borrowed")?;
        state.accessible()?;
        if state.origin != Origin::StelaInitialized
            || state.resource != CacheResource::Cacheless
            || !matches!(role(offset), Ok(Role::Drain))
        {
            return Err("DCS drain has no initialized cacheless control image");
        }
        let word = state
            .words
            .get(&(aperture, offset))
            .ok_or("DCS drain aperture is absent")?;
        if word.known & 0xffff_0000 != 0xffff_0000 {
            return Err("DCS drain opaque high control bits are unknown");
        }
        Ok(word.value as u32 & 0xffff_0000)
    }

    /// Records a completed synchronous flush only after Prepared checks the
    /// same RAM owner and producer exclusion. This does not settle a
    /// channel-configuration, clock, power or external DMA request.
    pub(crate) fn record_ram_drain(
        &self,
        aperture: u8,
        offset: u64,
        written: u32,
        at: u64,
    ) -> Result<(), &'static str> {
        if written != self.drain_control(aperture, offset)? {
            return Err("DCS flush must preserve high16 and clear both low bytes");
        }
        let mut state = self
            .0
            .try_borrow_mut()
            .map_err(|_| "DCS control image is borrowed")?;
        let serial = state
            .serial
            .checked_add(1)
            .ok_or("MCC request serial exhausted")?;
        let previous = state.words[&(aperture, offset)];
        state.requests.push(Request {
            serial,
            aperture,
            offset,
            previous,
            written,
            at,
            kind: RequestKind::Drain {
                channel: ((offset - DCS_BASE) / DCS_STRIDE) as u8,
            },
        });
        state.serial = serial;
        // Never leave a saved low-field completion behind. Ordinary reads
        // remain refused and a later flush needs a new live RAM service.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn controller() -> Controller {
        Controller::initialized_cacheless(
            Configuration {
                dram: alloc::vec![[0; CHANNELS as usize]; 2],
                weights: [1; GROUPS as usize],
            },
            LifecycleState {
                powered: true,
                clocked: true,
                reset: false,
                retention: true,
                quiesced: false,
            },
        )
        .unwrap()
    }

    #[test]
    fn opaque_high_bits_are_kept_and_invalid_flushes_have_no_prefix() {
        let controller = controller();
        let offset = DCS_BASE + DCS_STRIDE + DCS_DRAIN;
        // An explicit software-owned control image, not a hardware sample.
        controller
            .0
            .borrow_mut()
            .words
            .get_mut(&(1, offset))
            .unwrap()
            .value = 0x91ab_ffff;
        assert_eq!(controller.drain_control(1, offset), Ok(0x91ab_0000));
        for written in [0, 0x91aa_0000, 0x91ab_0001, 0x91ab_0100] {
            assert!(controller.record_ram_drain(1, offset, written, 9).is_err());
        }
        assert!(controller.requests().is_empty());
        controller
            .record_ram_drain(1, offset, 0x91ab_0000, 9)
            .unwrap();
        let requests = controller.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].kind, RequestKind::Drain { channel: 1 });
        assert_eq!(requests[0].previous.value, 0x91ab_ffff);
        assert_eq!(requests[0].written, 0x91ab_0000);
        assert_eq!(controller.drain_control(1, offset), Ok(0x91ab_0000));
    }

    #[test]
    fn unknown_or_physical_control_images_never_acquire_zero_high_bits() {
        let controller = controller();
        let offset = DCS_BASE + DCS_DRAIN;
        assert!(controller.drain_control(2, offset).is_err());
        assert!(controller.drain_control(0, offset + 4).is_err());
        controller.0.borrow_mut().origin = Origin::RetainedObservation;
        assert!(controller.drain_control(0, offset).is_err());
        controller.0.borrow_mut().origin = Origin::StelaInitialized;
        controller
            .0
            .borrow_mut()
            .words
            .get_mut(&(0, offset))
            .unwrap()
            .known = 0;
        assert!(controller.drain_control(0, offset).is_err());
    }
}
