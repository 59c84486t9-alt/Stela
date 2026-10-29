//! A display's broad physical windows keep their nested devices.
use super::*;

impl AppleDevices {
    /// Mount all original physical display views in one transaction, leaving
    /// the selected coprocessor and explicitly supplied complete DART groups
    /// at their existing routes. A declared update subview also keeps the
    /// canonical Prepared PTD owner, offsets, lifecycle and unknown tail.
    /// No display register gains invented meaning.
    pub fn add_display_with_darts(
        &mut self,
        regions: &[(&'static str, Range)],
        role: &'static str,
        darts: &[DartId],
    ) -> Result<(), String> {
        let mut controllers = self.coprocessors.iter().filter(|(name, _)| *name == role);
        let &(_, asc) = controllers
            .next()
            .ok_or("display has no mounted coprocessor")?;
        if controllers.next().is_some() {
            return Err("display coprocessor role is ambiguous".into());
        }
        let master = self
            .dcp_masters
            .iter()
            .find(|master| master.asc == asc)
            .ok_or("display coprocessor has no actual DMA owner")?;
        if !darts.iter().any(|id| id.0 == master.dart)
            || master
                .surface
                .is_some_and(|(owner, _)| !darts.iter().any(|id| id.0 == owner))
        {
            return Err("display container omits a selected DART owner".into());
        }
        let mut children = vec![asc];
        for dart in darts {
            if self.bus.device::<Dart>(dart.0).is_none() {
                return Err("display container child is not an actual DART".into());
            }
            if !children.contains(&dart.0) {
                children.push(dart.0);
            }
        }
        let views = regions
            .iter()
            .map(|&(name, range)| (name, range.physical, range.bytes))
            .collect();
        let model = display_hw::Region::physical(views).map_err(String::from)?;
        let spans = regions
            .iter()
            .map(|(_, range)| (range.physical, range.bytes))
            .collect::<Vec<_>>();
        // The PMGR/AP full PTD bank and display's update view name the same
        // physical resource. Only the prepared owner can supply this
        // subview; a bare overlap or matching name never checks it.
        let mut shared: Vec<stela_contracts::bus::SharedView> = Vec::new();
        if let Some(device) = self.memory_publication.or(self.memory_controller)
            && let Some(owner) = memory_resources::resource_for(&self.bus, device)
        {
            let (bank_start, bank_bytes, _) = owner.publication_footprint();
            let bank_end = bank_start + bank_bytes;
            if spans
                .iter()
                .any(|&(physical, bytes)| physical < bank_end && bank_start < physical + bytes)
            {
                let (bank_start, bank_bytes, bank_offset) = owner.publication_binding()?;
                // The original parent owns the full publication bank, including
                // LDP entries and IRQs outside display's narrower update view.
                self.bus
                    .shared_view(device, bank_start, bank_bytes, bank_offset)
                    .map_err(|error| format!("display full PTD owner: {error:?}"))?;
            }
            for &(physical, bytes) in &spans {
                // Region::physical has already checked these ends.
                if physical < bank_end && bank_start < physical + bytes {
                    let (start, bytes, offset) = owner.display_publication_view(physical, bytes)?;
                    shared.push(
                        self.bus
                            .shared_view(device, start, bytes, offset)
                            .map_err(|error| format!("display PTD shared view: {error:?}"))?,
                    );
                }
            }
        }
        // A view strictly inside one larger placed window is a sub-block of
        // that window's owner, which keeps it: J473AP `dispext0` reaches into
        // the PMP's ASC wrapper at +0x3c000 and into the PMGR. The prepared
        // memory owner's PTD views check only above; an equal window is a
        // conflicting owner.
        for &(physical, bytes) in &spans {
            let Some((start, end, owner, offset)) = self.bus.window_at(physical) else {
                continue;
            };
            let inside = physical + bytes <= end && end - start > bytes;
            if !inside
                || children.contains(&owner)
                || memory_resources::resource_for(&self.bus, owner).is_some()
            {
                continue;
            }
            shared.push(
                self.bus
                    .shared_view(owner, physical, bytes, offset + (physical - start))
                    .map_err(|error| format!("display sub-block view: {error:?}"))?,
            );
        }
        let plan = if shared.is_empty() {
            self.bus.container_bindings(&spans, &children)
        } else {
            self.bus
                .container_bindings_with_shared(&spans, &children, &shared)
        };
        let bindings = plan.map_err(|error| {
            let owner = match error {
                MapError::Overlap { existing } => self.bus.device_name(existing).unwrap_or("unknown"),
                _ => "none",
            };
            format!("display container placement: {error:?}; existing owner={owner}; requested={spans:#x?}")
        })?;
        if !bindings.is_empty() {
            self.bus
                .install(Box::new(model), &bindings)
                .map_err(|error| format!("display container publication: {error:?}"))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
