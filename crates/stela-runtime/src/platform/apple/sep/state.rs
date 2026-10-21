//! Where the SEP keeps its state between power cycles: the UID/GID roots
//! ([`super::keys`]) and the anti-replay store ([`super::store`]).
//!
//! On an installed machine it is the machine-state partition, after the NOR
//! image (docs/research/installation.md: one small partition holds the NOR,
//! NVRAM and the SEP's anti-replay storage). Its first [`ROOTS_BYTES`] hold the
//! roots record, the rest the store's two banks ([`super::store::persist`]).
//! An all-zero area is one never used, which the SEP provisions on its first
//! activation, as a new Mac's SEP has fresh state; any other content must
//! hold valid roots and a store, so a damaged area refuses instead of being
//! silently recreated. A boot without the partition keeps the state for one
//! power cycle ([`Location::Volatile`]).
use super::{
    Entropy,
    keys::{ROOT_BYTES, Roots},
    store::{
        Backend, Nonces, Volatile,
        persist::{BANK_BYTES, HostStore},
    },
};
use alloc::{boxed::Box, vec, vec::Vec};
use sha2::{Digest, Sha256};
use stela_drivers::block::{BlockDevice, Shared};
use zeroize::Zeroizing;

/// The SEP's area of the machine-state partition.
pub const BYTES: u64 = 0x10000;
/// The roots record's area at its start.
pub const ROOTS_BYTES: usize = 0x1000;
const MAGIC: &[u8; 8] = b"STSEPR01";
const RECORD_BYTES: usize = MAGIC.len() + 2 * ROOT_BYTES + 32;

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
fn record(machine: &[u8; ROOT_BYTES], group: &[u8; ROOT_BYTES]) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(vec![0; ROOTS_BYTES]);
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..8 + ROOT_BYTES].copy_from_slice(machine);
    bytes[8 + ROOT_BYTES..8 + 2 * ROOT_BYTES].copy_from_slice(group);
    let sum: [u8; 32] = Sha256::digest(&bytes[..8 + 2 * ROOT_BYTES]).into();
    bytes[8 + 2 * ROOT_BYTES..RECORD_BYTES].copy_from_slice(&sum);
    bytes
}

/// Check the record's magic and checksum; the roots themselves bind to the
/// ECID only when opened for use ([`parse`]).
fn well_formed(bytes: &[u8]) -> Result<(), &'static str> {
    let sum: [u8; 32] = Sha256::digest(&bytes[..8 + 2 * ROOT_BYTES]).into();
    if &bytes[..8] != MAGIC || bytes[8 + 2 * ROOT_BYTES..RECORD_BYTES] != sum {
        return Err("the SEP state area is neither blank nor a Stela SEP roots record");
    }
    Ok(())
}

fn parse(bytes: &[u8], ecid: u64) -> Result<Roots, &'static str> {
    well_formed(bytes)?;
    let root =
        |at: usize| -> [u8; ROOT_BYTES] { bytes[at..at + ROOT_BYTES].try_into().expect("root") };
    Roots::provisioned(root(8), root(8 + ROOT_BYTES), ecid)
}

/// Whether `roots`, the first [`ROOTS_BYTES`] of an area, are blank (an area
/// never used); a valid roots record is `false` and anything else refuses.
/// Setup uses it to keep a SEP's state and to find a foreign area.
pub fn blank(roots: &[u8]) -> Result<bool, &'static str> {
    if roots.len() < RECORD_BYTES {
        return Err("the SEP roots area is shorter than a roots record");
    }
    if roots.iter().all(|&b| b == 0) {
        return Ok(true);
    }
    well_formed(roots).map(|()| false)
}

fn fresh_roots(entropy: &mut dyn Entropy) -> Result<[Root; 2], &'static str> {
    let mut machine = Zeroizing::new([0; ROOT_BYTES]);
    let mut group = Zeroizing::new([0; ROOT_BYTES]);
    entropy.fill(&mut *machine)?;
    entropy.fill(&mut *group)?;
    Ok([machine, group])
}

/// The anti-replay store at `location`, provisioning a never-used one, and
/// whether it was provisioned now. `ecid` is the machine's `/chosen`
/// `unique-chip-id`, bound into the key hierarchy ([`Roots`]); it is not
/// stored in the roots record (it is public and comes from `/chosen` on every
/// boot), so the roots record alone cannot reconstruct the keys.
pub fn open(
    location: Location,
    ecid: u64,
    entropy: &mut dyn Entropy,
) -> Result<Opened, &'static str> {
    let (disk, first) = match location {
        Location::Volatile => {
            let [machine, group] = fresh_roots(entropy)?;
            let roots = Roots::provisioned(*machine, *group, ecid)?;
            let backend: Box<dyn Backend> = Box::new(Volatile::default());
            return Ok((Nonces::provision(&roots, backend)?, true));
        }
        Location::Partition { disk, first } => (disk, first),
    };
    let fault = |_| "the SEP state area of the machine-state partition is unreadable or too small";
    let probe = disk.window(first, 1).map_err(fault)?;
    let block = u64::from(probe.identity().block_size);
    if block == 0 || !BYTES.is_multiple_of(block) || !(ROOTS_BYTES as u64).is_multiple_of(block) {
        return Err("the machine-state partition's blocks do not divide the SEP state area");
    }
    let roots_blocks = ROOTS_BYTES as u64 / block;
    let mut roots_area = disk.window(first, roots_blocks).map_err(fault)?;
    let banks = disk
        .window(first + roots_blocks, (BYTES - ROOTS_BYTES as u64) / block)
        .map_err(fault)?;
    debug_assert!(BYTES - ROOTS_BYTES as u64 >= 2 * BANK_BYTES as u64);
    let mut bytes = Zeroizing::new(vec![0; ROOTS_BYTES]);
    roots_area.read(0, &mut bytes).map_err(fault)?;
    let store =
        HostStore::new(Box::new(banks)).map_err(|_| "the SEP store banks do not fit their area")?;
    let backend: Box<dyn Backend> = Box::new(store);
    if bytes.iter().all(|&b| b == 0) {
        let [machine, group] = fresh_roots(entropy)?;
        let roots = Roots::provisioned(*machine, *group, ecid)?;
        // The store first: a store without roots refuses on the next boot,
        // while roots without a store would read as a lost store.
        let nonces = Nonces::provision(&roots, backend)?;
        roots_area
            .write(0, &record(&machine, &group))
            .and_then(|()| roots_area.flush())
            .map_err(|_| "the SEP roots record could not be written")?;
        return Ok((nonces, true));
    }
    let roots = parse(&bytes, ecid)?;
    Ok((Nonces::open(&roots, backend)?, false))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_drivers::block::RamDisk;

    const ECID: u64 = 0xa5a5_0001;

    fn entropy(bytes: &mut [u8]) -> Result<(), &'static str> {
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
        let nonce = store.generate(0, &mut entropy).unwrap();
        drop(store);
        let (store, fresh) = open(at(&disk), ECID, &mut entropy).unwrap();
        assert!(!fresh);
        assert_eq!(store.read(0).unwrap(), nonce);
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
            .write(0, &record(&machine, &group))
            .unwrap();
        assert!(open(at(&lost), ECID, &mut entropy).is_err());
        // Setup tells the three apart from the roots area alone.
        let mut area = vec![0u8; ROOTS_BYTES];
        assert_eq!(blank(&area), Ok(true));
        area[..RECORD_BYTES].copy_from_slice(&record(&machine, &group)[..RECORD_BYTES]);
        assert_eq!(blank(&area), Ok(false));
        area[9] ^= 1;
        assert!(blank(&area).is_err());
    }

    #[test]
    fn a_volatile_store_is_fresh_each_time() {
        let (store, fresh) = open(Location::Volatile, ECID, &mut entropy).unwrap();
        assert!(fresh);
        assert!(store.read(0).is_err());
    }
}
