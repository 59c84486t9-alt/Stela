//! Authored synthetic inputs for one new MMU-off software-machine load.
//! No Apple image bytes, captured state, original output or original-equality claim.
use crate::memory::source_ram::{
    MaterializedSourceRam, OwnedRamExtent, PhysicalRamRange, SourceRamBuildError,
    SourceRamDeclaration, SourceRamPermissions, SourceRamSystemConfig, materialize_source_ram,
};
use stela_compiler::{GuestAddress, GuestState, TargetCpu};

pub(super) const SOURCE_PC: GuestAddress = GuestAddress(0x0010_0000);
pub(super) const EXPECTED_PC: GuestAddress = GuestAddress(SOURCE_PC.0 + size_of::<u32>() as u64);
pub(super) const DATA_PA: u64 = 0x0020_0000;
pub(super) const READ_PA: u64 = DATA_PA + size_of::<u64>() as u64;
pub(super) const SP_EL0: u64 = 0x002e_0000;
pub(super) const SP_EL1: u64 = 0x002f_0000;
const NZCV: u32 = 0xa000_0000;
pub(super) const PSTATE_LOW32: u64 =
    NZCV as u64 | crate::system::state::PSTATE_EL1H | crate::system::pstate::DAIF_MASK;
pub(super) const SCTLR_EL1: u64 = 0;
const A64_LDR_X_UNSIGNED_OFFSET: u32 = 0xf940_0000;
const UNSIGNED_IMM12_SHIFT: u32 = 10;
const BASE_REGISTER_SHIFT: u32 = 5;
const BASE_REGISTER: usize = 20;
const DESTINATION_REGISTER: usize = 22;
const SCALED_OFFSET: u32 = 1;
const SOURCE_WORD: u32 = A64_LDR_X_UNSIGNED_OFFSET
    | (SCALED_OFFSET << UNSIGNED_IMM12_SHIFT)
    | ((BASE_REGISTER as u32) << BASE_REGISTER_SHIFT)
    | DESTINATION_REGISTER as u32;
pub(super) const SOURCE: &[u8; 4] = &SOURCE_WORD.to_le_bytes();
const EXPECTED_READ: u64 = 0xa1b2_c3d4_e5f6_0718;
const DATA_WORDS: [u64; 4] = [
    0x1020_3040_5060_7080,
    EXPECTED_READ,
    0x89ab_cdef_0123_4567,
    0x7654_3210_fedc_ba98,
];
const fn initialized_data() -> [u8; 32] {
    let mut result = [0; 32];
    let mut word = 0;
    while word < DATA_WORDS.len() {
        let bytes = DATA_WORDS[word].to_le_bytes();
        let mut byte = 0;
        while byte < bytes.len() {
            result[word * bytes.len() + byte] = bytes[byte];
            byte += 1;
        }
        word += 1;
    }
    result
}
pub(super) const DATA: &[u8; 32] = &initialized_data();

pub(super) fn before() -> GuestState {
    let mut result = GuestState {
        sp: SP_EL1,
        nzcv: NZCV,
        reserved: 0xdec0_de00,
        ..GuestState::default()
    };
    for (index, value) in result.x.iter_mut().enumerate() {
        *value = 0x1111_0000_0000_0000 | index as u64;
    }
    result.x[BASE_REGISTER] = DATA_PA;
    for (index, value) in result.v.iter_mut().enumerate() {
        *value = [
            0x2222_0000_0000_0000 | index as u64,
            0x3333_0000_0000_0000 | index as u64,
        ];
    }
    result
}
pub(super) fn expected() -> GuestState {
    let mut result = before();
    result.x[DESTINATION_REGISTER] = EXPECTED_READ;
    result
}

/// Two actual owned extents only; unassigned capacity holes stay unassigned.
pub(super) fn materialize_inputs(
    address_space: u64,
) -> Result<MaterializedSourceRam, SourceRamBuildError> {
    materialize_source_ram(
        SourceRamDeclaration {
            address_space,
            target: TargetCpu::Baseline,
            declared_capacity: vec![PhysicalRamRange {
                source_pa: 0,
                bytes: 0x0040_0000,
            }],
            initialized: vec![
                OwnedRamExtent {
                    source_pa: SOURCE_PC.0,
                    bytes: SOURCE.to_vec(),
                    permissions: SourceRamPermissions {
                        readable: true,
                        writable: false,
                        executable: true,
                    },
                },
                OwnedRamExtent {
                    source_pa: DATA_PA,
                    bytes: DATA.to_vec(),
                    permissions: SourceRamPermissions {
                        readable: true,
                        writable: false,
                        executable: false,
                    },
                },
            ],
        },
        SourceRamSystemConfig {
            reservation_granule_bytes: 16,
            reservation_stripe_count: 8,
        },
    )
}

#[test]
fn authored_inputs_have_explicit_model_and_complete_state() {
    assert_eq!(
        u32::from_le_bytes(*SOURCE),
        A64_LDR_X_UNSIGNED_OFFSET | (1 << 10) | (20 << 5) | 22
    );
    assert_eq!(
        u64::from_le_bytes(DATA[8..16].try_into().unwrap()),
        EXPECTED_READ
    );
    let before = before();
    let after = expected();
    assert_ne!(
        before.x[DESTINATION_REGISTER],
        after.x[DESTINATION_REGISTER]
    );
    let mut restored = after;
    restored.x[DESTINATION_REGISTER] = before.x[DESTINATION_REGISTER];
    assert_eq!(before, restored);
    assert_eq!(before.sp, SP_EL1);
    assert_eq!(before.x[BASE_REGISTER] + 8, READ_PA);
}
