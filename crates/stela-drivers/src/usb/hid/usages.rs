// SPDX-License-Identifier: GPL-2.0-or-later
// Linux HID reference: see ../THIRD_PARTY.md.
//! Local Usage environment shared by the complete and legacy report readers.
//! Like Linux hid_parser_local, branch zero and the first delimiter branch
//! form the selected interpretation. Later branches are validated, never merged.
//! HID 1.11 6.2.2.8 makes alternate exposure optional and prohibits delimiters
//! on Application Collections and Array items. Raw bytes remain with UsbInput.
use alloc::vec::Vec;

const LIMIT: usize = 12_288;

#[derive(Default)]
pub(super) struct Local {
    selected: Vec<(u32, bool)>,
    minimum: Option<(u32, bool)>,
    open: bool,
    branch: usize,
    usage_count: usize,
}

impl Local {
    fn qualified(value: u32, size: usize, page: u32) -> (u32, bool) {
        (
            if size == 4 { value } else { page << 16 | value },
            size == 4,
        )
    }

    fn reserve(&mut self, count: usize) -> Result<(), &'static str> {
        self.usage_count = self
            .usage_count
            .checked_add(count)
            .filter(|n| *n <= LIMIT)
            .ok_or("too many HID usages")?;
        Ok(())
    }

    pub(super) fn usage(&mut self, value: u32, size: usize, page: u32) -> Result<(), &'static str> {
        self.reserve(1)?;
        if self.branch <= 1 {
            self.selected.push(Self::qualified(value, size, page));
        }
        Ok(())
    }

    pub(super) fn minimum(
        &mut self,
        value: u32,
        size: usize,
        page: u32,
    ) -> Result<(), &'static str> {
        if self
            .minimum
            .replace(Self::qualified(value, size, page))
            .is_some()
        {
            return Err("HID nested usage minimum");
        }
        Ok(())
    }

    pub(super) fn maximum(
        &mut self,
        value: u32,
        size: usize,
        page: u32,
    ) -> Result<(), &'static str> {
        let (first, extended) = self
            .minimum
            .take()
            .ok_or("HID usage maximum without minimum")?;
        let (last, last_extended) = Self::qualified(value, size, page);
        if extended != last_extended || first >> 16 != last >> 16 || first > last {
            return Err("invalid HID usage range");
        }
        self.reserve((last - first) as usize + 1)?;
        if self.branch <= 1 {
            self.selected.extend((first..=last).map(|v| (v, extended)));
        }
        Ok(())
    }

    pub(super) fn delimiter(&mut self, value: u32, size: usize) -> Result<(), &'static str> {
        if self.minimum.is_some() {
            return Err("unfinished HID usage range");
        }
        match (value, size != 0, self.open) {
            (1, true, false) => {
                self.branch = self
                    .branch
                    .checked_add(1)
                    .filter(|n| *n <= LIMIT)
                    .ok_or("too many HID delimiter sets")?;
                self.open = true;
            }
            (0, true, true) => self.open = false,
            (1, true, true) => return Err("nested HID delimiter"),
            (0, true, false) => return Err("HID delimiter close without open"),
            _ => return Err("invalid HID delimiter value"),
        }
        Ok(())
    }

    pub(super) fn complete(&self) -> Result<(), &'static str> {
        if self.open {
            return Err("unclosed HID delimiter");
        }
        if self.minimum.is_some() {
            return Err("unfinished HID usage range");
        }
        Ok(())
    }

    /// Only Main items reset local state; global Push/Pop never touches it.
    pub(super) fn main(
        &mut self,
        tag: u8,
        value: u32,
        page: u32,
    ) -> Result<Vec<u32>, &'static str> {
        self.complete()?;
        if self.branch != 0
            && ((tag == 0xa0 && value == 1)
                || (matches!(tag, 0x80 | 0x90 | 0xb0) && value & 2 == 0))
        {
            return Err("HID delimiter on Application Collection or Array");
        }
        // Linux hid_concatenate_last_usage_page: complete trailing short
        // usages using the final page, stopping at an already completed page.
        // Extended usages retain their own page and do not stop the walk.
        for (usage, extended) in self.selected.iter_mut().rev() {
            if *extended {
                continue;
            }
            if *usage >> 16 == page {
                break;
            }
            *usage = page << 16 | (*usage & 0xffff);
        }
        let selected = core::mem::take(&mut self.selected)
            .into_iter()
            .map(|(v, _)| v)
            .collect();
        *self = Self::default();
        Ok(selected)
    }
}
