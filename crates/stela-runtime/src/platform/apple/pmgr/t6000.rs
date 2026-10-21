//! T6000 PMGR address routing, qualified by original 26A434 J314s sources.
//!
//! `AppleT6000PMGR::initRegMaps` (kernel file 0x2ef4f44) binds forty-four
//! RegMap selectors. `readACCReg` (0x2f087f4) selects E/P0/P1 mapping lists
//! (0x76d088/0x76d0c0/0x76d108), then subtracts the selected logical base.
//! Bridge IDs 0..=0xc0 select consecutive DT views beginning at the actual
//! `bridge-reg-index` (48 on J314s). These are routing rules, not register
//! access permissions, reset values, tuning, power state or command completion.
//! A caller must still use an actual device owner for every physical effect.

pub mod tunables;

pub const COMPLEXES: usize = 3;
pub const BRIDGE_COUNT: usize = 193;
pub const BRIDGE_REG_INDEX: usize = 48;

/// Original RegMap selector and DT `reg` index, not a physical address.
pub const BINDINGS: [(u8, usize); 44] = [
    (0x00, 0),
    (0x01, 1),
    (0x02, 2),
    (0x5b, 4),
    (0x5d, 5),
    (0x42, 7),
    (0x09, 8),
    (0x0d, 9),
    (0x0a, 10),
    (0x0b, 11),
    (0x0c, 12),
    (0x0e, 13),
    (0x0f, 14),
    (0x15, 15),
    (0x19, 16),
    (0x16, 17),
    (0x17, 18),
    (0x18, 19),
    (0x1a, 20),
    (0x1b, 21),
    (0x1c, 22),
    (0x1d, 23),
    (0x21, 24),
    (0x25, 25),
    (0x22, 26),
    (0x23, 27),
    (0x24, 28),
    (0x26, 29),
    (0x27, 30),
    (0x28, 31),
    (0x29, 32),
    (0x07, 33),
    (0x4d, 34),
    (0x43, 35),
    (0x04, 36),
    (0x05, 37),
    (0x5c, 38),
    (0x71, 39),
    (0x73, 40),
    (0x08, 41),
    (0x4e, 42),
    (0x53, 43),
    (0x4f, 46),
    (0x50, 47),
];

/// One original ACC mapping row. Its span comes from the actual DT view,
/// just as the original driver queries the selected RegMap's size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccRange {
    pub map: u8,
    pub logical: u32,
}

pub const E_ACC: [AccRange; 7] = ranges([
    (0x0b, 0xe50000),
    (0x09, 0xe20000),
    (0x0c, 0xe70000),
    (0x0e, 0x050000),
    (0x0f, 0x150000),
    (0x0d, 0xf00000),
    (0x0a, 0xe40000),
]);
pub const P0_ACC: [AccRange; 9] = ranges([
    (0x17, 0xe50000),
    (0x15, 0xe20000),
    (0x18, 0xe70000),
    (0x1a, 0x050000),
    (0x1b, 0x150000),
    (0x1c, 0x250000),
    (0x1d, 0x350000),
    (0x19, 0xf00000),
    (0x16, 0xe40000),
]);
pub const P1_ACC: [AccRange; 9] = ranges([
    (0x23, 0xe50000),
    (0x21, 0xe20000),
    (0x24, 0xe70000),
    (0x26, 0x050000),
    (0x27, 0x150000),
    (0x28, 0x250000),
    (0x29, 0x350000),
    (0x25, 0xf00000),
    (0x22, 0xe40000),
]);

const fn ranges<const N: usize>(rows: [(u8, u32); N]) -> [AccRange; N] {
    let mut result = [AccRange { map: 0, logical: 0 }; N];
    let mut i = 0;
    while i < N {
        result[i] = AccRange {
            map: rows[i].0,
            logical: rows[i].1,
        };
        i += 1;
    }
    result
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct View {
    pub physical: u64,
    pub bytes: u64,
}

impl View {
    fn route(self, offset: u64, bytes: u64) -> Result<u64, &'static str> {
        if bytes == 0 || offset.checked_add(bytes).is_none_or(|end| end > self.bytes) {
            return Err("T6000 PMGR access exceeds the actual register view");
        }
        self.physical
            .checked_add(offset)
            .ok_or("T6000 PMGR address overflows")
    }
}

/// Borrowed, translated original register geometry. This validates the whole
/// routing family before any view is exposed. It supplies no initial bytes.
pub struct Layout<'a> {
    registers: &'a [Option<(u64, u64)>],
}

impl<'a> Layout<'a> {
    pub fn new(
        registers: &'a [Option<(u64, u64)>],
        bridge_reg_index: usize,
        bridge_count: usize,
    ) -> Result<Self, &'static str> {
        if bridge_reg_index != BRIDGE_REG_INDEX
            || bridge_count != BRIDGE_COUNT
            || registers.len() != BRIDGE_REG_INDEX + BRIDGE_COUNT
        {
            return Err("T6000 PMGR register/bridge topology is not qualified");
        }
        let layout = Self { registers };
        for (_, index) in BINDINGS {
            layout.view(index)?;
        }
        for index in BRIDGE_REG_INDEX..registers.len() {
            layout.view(index)?;
        }
        for rows in [&E_ACC[..], &P0_ACC[..], &P1_ACC[..]] {
            for (i, row) in rows.iter().enumerate() {
                let bytes = layout.register(row.map)?.bytes;
                let end = u64::from(row.logical)
                    .checked_add(bytes)
                    .filter(|end| *end <= u64::from(u32::MAX) + 1)
                    .ok_or("T6000 ACC logical range overflows")?;
                for prior in &rows[..i] {
                    let prior_end = u64::from(prior.logical) + layout.register(prior.map)?.bytes;
                    if u64::from(row.logical) < prior_end && u64::from(prior.logical) < end {
                        return Err("T6000 ACC logical register views overlap");
                    }
                }
            }
        }
        Ok(layout)
    }

    fn view(&self, index: usize) -> Result<View, &'static str> {
        let (physical, bytes) = self
            .registers
            .get(index)
            .copied()
            .flatten()
            .ok_or("T6000 PMGR required register view is not mapped")?;
        if bytes == 0 || physical.checked_add(bytes).is_none() {
            return Err("T6000 PMGR required register view is empty or overflows");
        }
        Ok(View { physical, bytes })
    }

    pub fn register(&self, map: u8) -> Result<View, &'static str> {
        let (_, index) = BINDINGS
            .iter()
            .find(|(selector, _)| *selector == map)
            .ok_or("T6000 PMGR RegMap selector is not qualified")?;
        self.view(*index)
    }

    /// Route the first die's actual E/P0/P1 complex. Multi-die projection,
    /// harvesting and additional PE ownership require their own actual plan.
    pub fn acc(&self, complex: usize, logical: u32, bytes: u64) -> Result<u64, &'static str> {
        let rows = match complex {
            0 => &E_ACC[..],
            1 => &P0_ACC[..],
            2 => &P1_ACC[..],
            _ => return Err("T6000 ACC complex has no qualified physical die binding"),
        };
        for row in rows {
            if let Some(offset) = logical.checked_sub(row.logical) {
                let view = self.register(row.map)?;
                if u64::from(offset) < view.bytes {
                    return view.route(u64::from(offset), bytes);
                }
            }
        }
        Err("T6000 ACC logical address is outside every original mapping")
    }

    pub fn bridge(&self, id: usize) -> Result<View, &'static str> {
        if id >= BRIDGE_COUNT {
            return Err("T6000 bridge ID is outside the original controller family");
        }
        self.view(BRIDGE_REG_INDEX + id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn registers() -> alloc::vec::Vec<Option<(u64, u64)>> {
        let mut regs = vec![Some((0x100000000, 0x1000)); BRIDGE_REG_INDEX + BRIDGE_COUNT];
        for (complex, rows) in [&E_ACC[..], &P0_ACC[..], &P1_ACC[..]]
            .into_iter()
            .enumerate()
        {
            for row in rows {
                let index = BINDINGS.iter().find(|(map, _)| *map == row.map).unwrap().1;
                regs[index] = Some((
                    0x210000000 + complex as u64 * 0x1000000 + u64::from(row.logical),
                    0x1000,
                ));
            }
        }
        regs
    }

    #[test]
    fn all_three_complexes_route_separately_and_reject_cross_view_effects() {
        let regs = registers();
        let layout = Layout::new(&regs, BRIDGE_REG_INDEX, BRIDGE_COUNT).unwrap();
        for complex in 0..COMPLEXES {
            assert_eq!(
                layout.acc(complex, 0xe20660, 8),
                Ok(0x210e20660 + complex as u64 * 0x1000000)
            );
            assert!(layout.acc(complex, 0xe20ffc, 8).is_err());
            assert!(layout.acc(complex, 0xe21000, 4).is_err());
        }
        assert!(layout.acc(3, 0xe20660, 8).is_err());
        assert!(layout.acc(0, 0x250000, 4).is_err());
        assert_eq!(layout.acc(2, 0x250000, 4), Ok(0x212250000));
        assert!(layout.acc(0, 0xe20660, 0).is_err());
        assert!(layout.register(0xff).is_err());
        for id in 0..BRIDGE_COUNT {
            assert!(layout.bridge(id).is_ok());
        }
        assert!(layout.bridge(BRIDGE_COUNT).is_err());
    }

    #[test]
    fn complete_layout_rejects_missing_overflowing_and_ambiguous_actual_geometry() {
        let mut regs = registers();
        assert!(Layout::new(&regs, 48, 32).is_err());
        assert!(Layout::new(&regs[..240], 48, 193).is_err());
        regs[240] = None;
        assert!(Layout::new(&regs, 48, 193).is_err());
        regs[240] = Some((u64::MAX - 3, 8));
        assert!(Layout::new(&regs, 48, 193).is_err());
        regs[240] = Some((0x100000000, 0x1000));
        regs[8] = Some((0x210e20000, 0x40000));
        assert!(Layout::new(&regs, 48, 193).is_err());
        regs[8] = Some((0x210e20000, 0x15000));
        assert!(Layout::new(&regs, 48, 193).is_ok());
    }
}

#[cfg(all(test, feature = "std"))]
mod original {
    use crate::machine::adt::Node;
    use alloc::vec::Vec;
    use sha2::{Digest, Sha256};

    fn original(variable: &str, digest: &str) -> Vec<u8> {
        let bytes = std::fs::read(std::env::var(variable).expect("pinned J314s input")).unwrap();
        assert_eq!(hex::encode(Sha256::digest(&bytes)), digest);
        bytes
    }
    fn kernelcache() -> Vec<u8> {
        original(
            "STELA_TEST_PMGR_M1_KERNELCACHE",
            "5109fca5209bdbb89cec29e3241cc42a90418cb737d65e31962b059b9879af90",
        )
    }
    fn adt() -> Vec<u8> {
        original(
            "STELA_TEST_PMGR_M1_ADT",
            "44fa41bfd0fe0027fd862b8615ae956885614636625d44a59cab226d682558ad",
        )
    }
    fn word(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
    }
    fn quad(bytes: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
    }
    fn branch_target(bytes: &[u8], offset: usize) -> usize {
        offset.wrapping_add_signed(((word(bytes, offset) << 6) as i32 >> 4) as isize)
    }

    #[test]
    #[ignore = "requires original J314s ADT/kernelcache; full T6000 PMGR routing is not initial state"]
    fn original_t6000_layout_routes_all_bindings_three_complexes_and_193_bridges() {
        use super as t6000;
        let bytes = kernelcache();
        for (start, end, digest) in [
            (
                0x2ef4f44,
                0x2ef5390,
                "f725c351fb0128d50ec225a545380d5b1b2fe26a0a413c8bb9eb4ec945b5fc7e",
            ),
            (
                0x76d088,
                0x76d1bc,
                "fc33b26ffea4fd46435c0ff14631040f8d6b68ce3fe16a1c3b69eb734446e9a9",
            ),
            (
                0x76d3c8,
                0x76d3d4,
                "e453d46c75c100139bf70bef9023f2c5df18e65c44b82019983e3d1b9b6efdb5",
            ),
            (
                0x1316360,
                0x1316378,
                "7825c0918d1d700b7dd74b4ca57412320395aab49e47bbb0411f8a9cac6f235e",
            ),
            (
                0x2f085ec,
                0x2f08c70,
                "4713ee56c4873574cc0687d2519b890b5c39e6a070ff213dbad7406e7d3822dc",
            ),
            (
                0x2ef72fc,
                0x2ef7510,
                "19309e8c3f347936e67ecc1f6956cbd4c26d2309fea6fcff5d3e2d92c45fce94",
            ),
            (
                0x2f04cc0,
                0x2f04fc4,
                "f8aaab08cb007a7f72e7e8cdf8d65cd081ed6f8122680290753f66bdfa60eda1",
            ),
        ] {
            assert_eq!(hex::encode(Sha256::digest(&bytes[start..end])), digest);
        }
        let mut arguments = [None; 5];
        let mut bindings = Vec::new();
        for offset in (0x2ef4f44..0x2ef5390).step_by(4) {
            let opcode = word(&bytes, offset);
            // The complete pinned constructor uses MOVZ Wn for every argument.
            if opcode & 0xff800000 == 0x52800000 {
                let destination = (opcode & 31) as usize;
                if destination < arguments.len() {
                    arguments[destination] =
                        Some((opcode >> 5 & 0xffff) << (16 * (opcode >> 21 & 3)));
                }
            }
            if matches!(opcode >> 26, 0b000101 | 0b100101)
                && branch_target(&bytes, offset) == 0x2f25704
            {
                assert_eq!(arguments[3], Some(0));
                assert_eq!(arguments[4], Some(0));
                bindings.push((arguments[1].unwrap() as u8, arguments[2].unwrap() as usize));
            }
        }
        assert_eq!(bindings, t6000::BINDINGS);
        for (complex, (offset, rows)) in [
            (0x76d088, &t6000::E_ACC[..]),
            (0x76d0c0, &t6000::P0_ACC[..]),
            (0x76d108, &t6000::P1_ACC[..]),
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(word(&bytes, 0x76d3c8 + 4 * complex) as usize, rows.len());
            // Chained-fixup payload supplies the actual list's file coordinate;
            // its authenticated pointer metadata is not an executable PAC value.
            assert_eq!(
                quad(&bytes, 0x1316360 + complex * 8) & 0xffffffff,
                offset as u64
            );
            for (index, row) in rows.iter().enumerate() {
                assert_eq!(word(&bytes, offset + index * 8), u32::from(row.map));
                assert_eq!(word(&bytes, offset + index * 8 + 4), row.logical);
            }
        }
        let data = adt();
        let root = Node::root(&data).unwrap();
        let io = root.child("arm-io").unwrap();
        let pmgr = io.child("pmgr").unwrap();
        assert_eq!(pmgr.cells32("#bridges").unwrap(), [193]);
        assert_eq!(pmgr.cells32("bridge-reg-index").unwrap(), [48]);
        let ranges = io.ranges().unwrap();
        let registers = pmgr
            .pairs("reg")
            .unwrap()
            .into_iter()
            .map(|(address, bytes)| {
                ranges.iter().find_map(|&(child, parent, length)| {
                    (address >= child && address - child < length)
                        .then(|| (parent + address - child, bytes))
                })
            })
            .collect::<Vec<_>>();
        let layout = t6000::Layout::new(&registers, 48, 193).unwrap();
        for complex in 0..3 {
            assert_eq!(
                layout.acc(complex, 0xe20660, 8),
                Ok(0x210e20660 + complex as u64 * 0x1000000)
            );
            assert_eq!(
                layout.acc(complex, 0xe34ff8, 8),
                Ok(0x210e34ff8 + complex as u64 * 0x1000000)
            );
            assert!(layout.acc(complex, 0xe34ffc, 8).is_err());
        }
        assert_eq!(word(&bytes, 0x2ef74e4), 0x710302bf); // complete bridge switch 0..=0xc0
        for id in 0..193 {
            let view = layout.bridge(id).unwrap();
            assert_eq!(Some((view.physical, view.bytes)), registers[48 + id]);
            let target = 0x2ef7504_i64 + i64::from(word(&bytes, 0x2f04cc0 + id * 4) as i32);
            assert!((0x2ef7510..0x2f04cc0).contains(&target));
        }
    }
}
