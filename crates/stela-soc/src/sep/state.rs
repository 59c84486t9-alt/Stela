//! Where the SEP keeps its state between power cycles: the UID/GID roots
//! ([`super::keys`]) and the anti-replay store ([`super::store`]).
//!
//! On an installed machine it is the machine-state partition, after the NOR
//! image (one small partition holds the NOR, NVRAM and the SEP's
//! anti-replay storage). Its first [`ROOTS_BYTES`] hold the
//! roots record, the rest the store's two banks ([`super::store::persist`]).
//! An all-zero area is one never used, which the SEP provisions on its first
//! activation, as a new Mac's SEP has fresh state; any other content must
//! hold valid roots and a store, so a damaged area refuses instead of being
//! silently recreated. A boot without the partition keeps the state for one
//! power cycle ([`Location::Volatile`]).
//!
//! The roots open only under the ECID they were provisioned with, and the
//! installed macOS is bound to it too (its tickets, and the name of the
//! gigalocker `seputil` looks for). That ECID is an option of the USB that
//! installed, which can be made again with another, so the area also names
//! it ([`recorded_ecid`]) and a boot of the install takes it from there.
use super::{
    Entropy,
    keys::{ROOT_BYTES, Roots},
    store::{Backend, Nonces, Volatile, persist::HostStore},
};
use crate::Result;
use alloc::{boxed::Box, vec, vec::Vec};
use stela_contracts::refuse;
use stela_crypto::Sha256;
use stela_crypto::digest::Digest;
use stela_drivers::block::{BlockDevice, Shared};
use zeroize::Zeroizing;

use stela_formats::machine_state::{
    SEP_BANK_BYTES as BANK_BYTES, SEP_BYTES as BYTES, SEP_ROOTS_BYTES as ROOTS_BYTES,
};
const MAGIC: &[u8; 8] = b"STSEPR01";
const RECORD_BYTES: usize = MAGIC.len() + 2 * ROOT_BYTES + 32;

/// The identity record, in the roots area past the roots record and in a
/// block of its own at 512-byte blocks: magic, the ECID big-endian, and a
/// SHA-256 of both.
const IDENTITY_MAGIC: &[u8; 8] = b"STSEPI01";
const IDENTITY_AT: usize = 0x800;
const IDENTITY_BYTES: usize = IDENTITY_MAGIC.len() + 8 + 32;
const _: () = assert!(RECORD_BYTES <= IDENTITY_AT && IDENTITY_AT + IDENTITY_BYTES <= ROOTS_BYTES);

type Root = Zeroizing<[u8; ROOT_BYTES]>;
/// The opened store and whether it was provisioned now.
pub type Opened = (Nonces<Box<dyn Backend>>, bool);

/// Where the SEP's state lives.
#[derive(Clone)]
pub enum Location {
    /// Nowhere durable: fresh roots and a store that end at power-off.
    Volatile,
    /// [`BYTES`] bytes of `disk` from block `first`.
    Partition { disk: Shared, first: u64 },
}

/// The roots record: magic, the machine and group roots, and a SHA-256 of
/// what precedes it, which catches a torn or foreign area.
fn record(machine: &[u8; ROOT_BYTES], group: &[u8; ROOT_BYTES], ecid: u64) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(vec![0; ROOTS_BYTES]);
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..8 + ROOT_BYTES].copy_from_slice(machine);
    bytes[8 + ROOT_BYTES..8 + 2 * ROOT_BYTES].copy_from_slice(group);
    let sum: [u8; 32] = Sha256::digest(&bytes[..8 + 2 * ROOT_BYTES]).into();
    bytes[8 + 2 * ROOT_BYTES..RECORD_BYTES].copy_from_slice(&sum);
    bytes[IDENTITY_AT..IDENTITY_AT + IDENTITY_BYTES].copy_from_slice(&identity(ecid));
    bytes
}

fn identity(ecid: u64) -> [u8; IDENTITY_BYTES] {
    let mut bytes = [0; IDENTITY_BYTES];
    bytes[..8].copy_from_slice(IDENTITY_MAGIC);
    bytes[8..16].copy_from_slice(&ecid.to_be_bytes());
    let sum: [u8; 32] = Sha256::digest(&bytes[..16]).into();
    bytes[16..].copy_from_slice(&sum);
    bytes
}

/// The ECID the roots area `roots` names as its machine's, when it names
/// one: an area provisioned before the record existed names none until its
/// first open under its ECID.
pub fn recorded_ecid(roots: &[u8]) -> Option<u64> {
    let bytes = roots.get(IDENTITY_AT..IDENTITY_AT + IDENTITY_BYTES)?;
    let sum: [u8; 32] = Sha256::digest(&bytes[..16]).into();
    if &bytes[..8] != IDENTITY_MAGIC || bytes[16..] != sum {
        return None;
    }
    let ecid = u64::from_be_bytes(bytes[8..16].try_into().expect("ECID"));
    (ecid != 0).then_some(ecid)
}

/// The byte offset of the roots area in a machine state, after the NOR
/// image of `nor_bytes`, and its length: what [`recorded_ecid`] reads.
pub const fn roots_area(nor_bytes: u64) -> (u64, usize) {
    (nor_bytes, ROOTS_BYTES)
}

/// Whose state a location holds, for the ECID a boot would open it under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Owner {
    /// Never used, or kept nowhere: any ECID provisions it.
    Unused,
    /// This ECID's.
    This,
    /// Another machine's: the ECID it names, or none when it was
    /// provisioned before the record existed and its store does not
    /// authenticate under this ECID.
    Other(Option<u64>),
}

/// Whose state `location` holds for `ecid`, without changing it. A damaged
/// area or a lost store refuses as [`open`] does.
pub fn owner(location: &Location, ecid: u64) -> Result<Owner> {
    let Location::Partition { disk, first } = location else {
        return Ok(Owner::Unused);
    };
    let (mut roots_area, banks) = areas(disk, *first)?;
    let mut bytes = Zeroizing::new(vec![0; ROOTS_BYTES]);
    roots_area.read(0, &mut bytes).map_err(fault)?;
    if bytes.iter().all(|&b| b == 0) {
        return Ok(Owner::Unused);
    }
    well_formed(&bytes)?;
    match recorded_ecid(&bytes) {
        Some(recorded) if recorded == ecid => return Ok(Owner::This),
        Some(recorded) => return Ok(Owner::Other(Some(recorded))),
        None => {}
    }
    let roots = parse(&bytes, ecid)?;
    let store = HostStore::new(Box::new(banks))
        .map_err(|_| refuse!("the SEP store banks do not fit their area"))?;
    Ok(match Nonces::authentic(&roots, store)? {
        true => Owner::This,
        false => Owner::Other(None),
    })
}

fn fault(_: stela_drivers::block::BlockError) -> stela_contracts::Refusal {
    refuse!("the SEP state area of the machine-state partition is unreadable or too small")
}

/// The roots area and the store's banks at block `first` of `disk`.
fn areas(
    disk: &Shared,
    first: u64,
) -> Result<(stela_drivers::block::Window, stela_drivers::block::Window)> {
    let probe = disk.window(first, 1).map_err(fault)?;
    let block = u64::from(probe.identity().block_size);
    if block == 0 || !BYTES.is_multiple_of(block) || !(ROOTS_BYTES as u64).is_multiple_of(block) {
        return Err(refuse!(
            "the machine-state partition's blocks do not divide the SEP state area"
        ));
    }
    let roots_blocks = ROOTS_BYTES as u64 / block;
    let roots_area = disk.window(first, roots_blocks).map_err(fault)?;
    let banks = disk
        .window(first + roots_blocks, (BYTES - ROOTS_BYTES as u64) / block)
        .map_err(fault)?;
    Ok((roots_area, banks))
}

/// Check the record's magic and checksum; the roots themselves bind to the
/// ECID only when opened for use ([`parse`]).
fn well_formed(bytes: &[u8]) -> Result<()> {
    let sum: [u8; 32] = Sha256::digest(&bytes[..8 + 2 * ROOT_BYTES]).into();
    if &bytes[..8] != MAGIC || bytes[8 + 2 * ROOT_BYTES..RECORD_BYTES] != sum {
        return Err(refuse!(
            "the SEP state area is neither blank nor a Stela SEP roots record"
        ));
    }
    Ok(())
}

fn parse(bytes: &[u8], ecid: u64) -> Result<Roots> {
    well_formed(bytes)?;
    let root =
        |at: usize| -> [u8; ROOT_BYTES] { bytes[at..at + ROOT_BYTES].try_into().expect("root") };
    Roots::provisioned(root(8), root(8 + ROOT_BYTES), ecid)
}

/// Whether `roots`, the first [`ROOTS_BYTES`] of an area, are blank (an area
/// never used); a valid roots record is `false` and anything else refuses.
/// Setup uses it to keep a SEP's state and to find a foreign area.
pub fn blank(roots: &[u8]) -> Result<bool> {
    if roots.len() < RECORD_BYTES {
        return Err(refuse!("the SEP roots area is shorter than a roots record"));
    }
    if roots.iter().all(|&b| b == 0) {
        return Ok(true);
    }
    well_formed(roots).map(|()| false)
}

fn fresh_roots(entropy: &mut dyn Entropy) -> Result<[Root; 2]> {
    let mut machine = Zeroizing::new([0; ROOT_BYTES]);
    let mut group = Zeroizing::new([0; ROOT_BYTES]);
    entropy.fill(&mut *machine)?;
    entropy.fill(&mut *group)?;
    Ok([machine, group])
}

/// The anti-replay store at `location`, provisioning a never-used one, and
/// whether it was provisioned now. `ecid` is the machine's `/chosen`
/// `unique-chip-id`, bound into the key hierarchy ([`Roots`]). The area
/// names it beside the roots record from its provisioning, or from its first
/// open under it when it was provisioned before that record existed; an
/// area that names another ECID refuses.
pub fn open(location: Location, ecid: u64, entropy: &mut dyn Entropy) -> Result<Opened> {
    let (disk, first) = match location {
        Location::Volatile => {
            let [machine, group] = fresh_roots(entropy)?;
            let roots = Roots::provisioned(*machine, *group, ecid)?;
            let backend: Box<dyn Backend> = Box::new(Volatile::default());
            return Ok((Nonces::provision(&roots, backend)?, true));
        }
        Location::Partition { disk, first } => (disk, first),
    };
    let (mut roots_area, banks) = areas(&disk, first)?;
    debug_assert!(BYTES - ROOTS_BYTES as u64 >= 2 * BANK_BYTES as u64);
    let mut bytes = Zeroizing::new(vec![0; ROOTS_BYTES]);
    roots_area.read(0, &mut bytes).map_err(fault)?;
    let store = HostStore::new(Box::new(banks))
        .map_err(|_| refuse!("the SEP store banks do not fit their area"))?;
    let backend: Box<dyn Backend> = Box::new(store);
    if bytes.iter().all(|&b| b == 0) {
        let [machine, group] = fresh_roots(entropy)?;
        let roots = Roots::provisioned(*machine, *group, ecid)?;
        // The store first: a store without roots refuses on the next boot,
        // while roots without a store would read as a lost store.
        let nonces = Nonces::provision(&roots, backend)?;
        roots_area
            .write(0, &record(&machine, &group, ecid))
            .and_then(|()| roots_area.flush())
            .map_err(|_| refuse!("the SEP roots record could not be written"))?;
        return Ok((nonces, true));
    }
    let recorded = recorded_ecid(&bytes);
    if recorded.is_some_and(|recorded| recorded != ecid) {
        well_formed(&bytes)?;
        return Err(refuse!(
            "the SEP state on the machine-state partition is another machine's: it names another ECID than this boot's"
        ));
    }
    let roots = parse(&bytes, ecid)?;
    let nonces = Nonces::open(&roots, backend)?;
    if recorded.is_none() {
        // State provisioned before the record existed and now opened under
        // its ECID: name it. Only the record's own blocks are written, and a
        // disk that refuses the write keeps a state that works as before.
        bytes[IDENTITY_AT..IDENTITY_AT + IDENTITY_BYTES].copy_from_slice(&identity(ecid));
        let block = roots_area.identity().block_size as usize;
        let from = IDENTITY_AT / block * block;
        let to = (IDENTITY_AT + IDENTITY_BYTES).div_ceil(block) * block;
        let _ = roots_area
            .write((from / block) as u64, &bytes[from..to])
            .and_then(|()| roots_area.flush());
    }
    Ok((nonces, false))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_drivers::block::RamDisk;

    const ECID: u64 = 0xa5a5_0001;

    fn entropy(bytes: &mut [u8]) -> Result<()> {
        for (n, byte) in bytes.iter_mut().enumerate() {
            *byte = n as u8 ^ 0x5a;
        }
        Ok(())
    }

    fn disk() -> Shared {
        Shared::new(Box::new(RamDisk::new("nor", 2048 + 128, 512)))
    }

    fn at(disk: &Shared) -> Location {
        Location::Partition {
            disk: disk.clone(),
            first: 2048,
        }
    }

    #[test]
    fn the_state_is_provisioned_once_and_reopened_across_power_cycles() {
        let disk = disk();
        let (mut store, fresh) = open(at(&disk), ECID, &mut entropy).unwrap();
        assert!(fresh);
        let identity_root = store.system_key_root().unwrap();
        let nonce = store.generate(0, &mut entropy).unwrap();
        drop(store);
        let (mut store, fresh) = open(at(&disk), ECID, &mut entropy).unwrap();
        assert!(!fresh);
        assert_eq!(store.read(0).unwrap(), nonce);
        assert_eq!(*store.system_key_root().unwrap(), *identity_root);
        store.erase().unwrap();
        drop(store);
        let (store, fresh) = open(at(&disk), ECID, &mut entropy).unwrap();
        assert!(!fresh);
        assert_eq!(*store.system_key_root().unwrap(), *identity_root);
        // Moving roots to a different ECID cannot reopen authenticated state.
        assert!(open(at(&disk), ECID + 1, &mut entropy).is_err());
        // The NOR image before the area is untouched.
        let mut nor = [0u8; 512];
        disk.window(2047, 1).unwrap().read(0, &mut nor).unwrap();
        assert_eq!(nor, [0; 512]);
    }

    #[test]
    fn a_damaged_or_foreign_area_refuses() {
        let disk = disk();
        open(at(&disk), ECID, &mut entropy).unwrap();
        let mut roots = disk.window(2048, 8).unwrap();
        let mut block = [0u8; 512];
        roots.read(0, &mut block).unwrap();
        block[20] ^= 1;
        roots.write(0, &block).unwrap();
        assert!(open(at(&disk), ECID, &mut entropy).is_err());
        // Roots without their store read as a lost store.
        let lost = Shared::new(Box::new(RamDisk::new("nor", 2048 + 128, 512)));
        let [machine, group] = fresh_roots(&mut entropy).unwrap();
        lost.window(2048, 8)
            .unwrap()
            .write(0, &record(&machine, &group, ECID))
            .unwrap();
        assert!(open(at(&lost), ECID, &mut entropy).is_err());
        // Setup tells the three apart from the roots area alone.
        let mut area = vec![0u8; ROOTS_BYTES];
        assert_eq!(blank(&area), Ok(true));
        area[..RECORD_BYTES].copy_from_slice(&record(&machine, &group, ECID)[..RECORD_BYTES]);
        assert_eq!(blank(&area), Ok(false));
        area[9] ^= 1;
        assert!(blank(&area).is_err());
    }

    #[test]
    fn the_area_names_its_ecid_and_another_ecid_is_told_apart() {
        let disk = disk();
        assert_eq!(owner(&at(&disk), ECID), Ok(Owner::Unused));
        open(at(&disk), ECID, &mut entropy).unwrap();
        let mut area = vec![0u8; ROOTS_BYTES];
        let mut roots = disk.window(2048, 8).unwrap();
        roots.read(0, &mut area).unwrap();
        assert_eq!(recorded_ecid(&area), Some(ECID));
        assert_eq!(blank(&area), Ok(false));
        assert_eq!(owner(&at(&disk), ECID), Ok(Owner::This));
        assert_eq!(owner(&at(&disk), ECID + 1), Ok(Owner::Other(Some(ECID))));
        assert!(open(at(&disk), ECID + 1, &mut entropy).is_err());
        // A record that is damaged names nothing.
        area[IDENTITY_AT + 9] ^= 1;
        assert_eq!(recorded_ecid(&area), None);
    }

    #[test]
    fn state_from_before_the_record_is_named_at_its_first_open_under_its_ecid() {
        let disk = disk();
        let (mut store, _) = open(at(&disk), ECID, &mut entropy).unwrap();
        let nonce = store.generate(0, &mut entropy).unwrap();
        drop(store);
        // As an earlier release left it: the roots record alone.
        let mut roots = disk.window(2048, 8).unwrap();
        let mut area = vec![0u8; ROOTS_BYTES];
        roots.read(0, &mut area).unwrap();
        area[IDENTITY_AT..IDENTITY_AT + IDENTITY_BYTES].fill(0);
        roots.write(0, &area).unwrap();
        assert_eq!(recorded_ecid(&area), None);
        // Another ECID neither opens nor names it.
        assert_eq!(owner(&at(&disk), ECID + 1), Ok(Owner::Other(None)));
        assert!(open(at(&disk), ECID + 1, &mut entropy).is_err());
        roots.read(0, &mut area).unwrap();
        assert_eq!(recorded_ecid(&area), None);
        // Its own does both, and keeps the store.
        assert_eq!(owner(&at(&disk), ECID), Ok(Owner::This));
        let (store, fresh) = open(at(&disk), ECID, &mut entropy).unwrap();
        assert!(!fresh);
        assert_eq!(store.read(0).unwrap(), nonce);
        roots.read(0, &mut area).unwrap();
        assert_eq!(recorded_ecid(&area), Some(ECID));
        assert_eq!(owner(&at(&disk), ECID + 1), Ok(Owner::Other(Some(ECID))));
    }

    #[test]
    fn a_volatile_store_is_fresh_each_time() {
        let (store, fresh) = open(Location::Volatile, ECID, &mut entropy).unwrap();
        assert!(fresh);
        assert!(store.read(0).is_err());
    }
}
