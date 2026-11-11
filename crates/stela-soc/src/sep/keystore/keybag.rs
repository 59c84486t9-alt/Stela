//! User keybags: create, save, load, unload and UUID; session binding, lock
//! state, unlock and passcode change.
//!
//! **Callers.** At login `applekeystored` (26A434 `/usr/libexec/applekeystored`,
//! x86_64 slice 0x100031f87..0x1000320c9; the arm64e slice has the same calls)
//! looks for the user's saved bag; without one it calls
//! `aks_create_bag(passcode, length, 0, &handle)` (bag type 0, `xor edx,edx`
//! at 0x100031fa2), `aks_save_bag` and writes the bytes to the user's bag
//! file, binds the bag to the user's session with `aks_set_system(handle,
//! uid)`, unlocks the session bag with the passcode and unloads `handle`.
//! With a saved bag it calls `aks_load_bag` (0x10003302b) instead.
//!
//! **libaks.** `aks_create_bag` (0x187d73994) calls the generic builder
//! 0x187dc6e74 with parent -1, an empty second blob and Boolean 0; the
//! builder sends selector 2 with seven scalars: type, parent, passcode
//! pointer and length, second pointer and length, Boolean.
//!
//! **Kernel** (26A434 file offsets; VAs in the kernelcache for the wrappers).
//! `AppleKeyStore::create_keybag` (VA 0xfffffe0009d29350) sends variant 4
//! (`__ipc_create_keybag_v4` 0x2d5840c) with the extension and descriptor
//! blobs empty and flags 0x100 only when its Boolean is set; it discards the
//! reply's descriptor blob (null output at 0xfffffe0009d5c520). Copy at
//! 0x2d253dc calls `__ipc_copy_keybag_v1` (0x2d5880c). Load (0x2d25688),
//! unload (0x2d25430) and UUID (0x2d25710) use variant 0. Codec ranges are
//! below.
//!
//! **Model.** A bag has two random 32-byte seeds: the device seed, sealed
//! under the bag key, and the passcode seed, sealed under the bag key and the
//! passcode KEK (or the bag key alone when the passcode is empty). The bag
//! key is HMAC(keybag root, UUID); the keybag root derives from the machine's
//! system-key root, so a saved bag opens on this machine only. The KEK is
//! PBKDF2-HMAC-SHA256 of HMAC(bag key, passcode) over the bag's salt and
//! iteration count, run [`SLICE`] iterations per SEP step ([`Pending`]) so
//! no processor stalls in one exit. The saved blob carries a MAC under the
//! bag key over everything: a blob that does not open is refused, and no new
//! bag ever replaces it. The SEP keeps no copy: the AP stores the blob.
//! Class keys, lock state and session binding build on these seeds.
//!
//! **At rest.** The machine roots are on this disk, so the bag protects
//! against a wrong passcode at the login window, not against someone who
//! reads the disk; [`AT_REST`] says so once per boot.
use super::Fields;
use crate::Result;
use crate::inline_key::{KEY_BYTES, SEALED_BYTES, open, seal};
use alloc::{format, string::String, vec::Vec};
use hmac::{Hmac, Mac};
use stela_contracts::refuse;
use stela_crypto::Sha256;
use zeroize::Zeroizing;

pub(super) const CREATE: u8 = 1;
pub(super) const COPY: u8 = 2;
pub(super) const LOAD: u8 = 3;
pub(super) const UNLOAD: u8 = 5;
pub(super) const UUID: u8 = 6;
/// `__ipc_change_lock_state_v1` (VA 0xfffffe0009d5c8f8): session, handle,
/// operation, secret, then a u64 of flags; reply u32 and u64
/// (`change_lock_state` VA 0xfffffe0009d28870 passes the u64 to
/// `handle_device_state_return`). The flags are 0x100 and 0x800 from the
/// function's two Booleans (0xfffffe0009d288a4..0xfffffe0009d288b4); every
/// selector but sel 12 passes both false, and sel 12 takes them from its
/// fifth scalar, which `aks_unlock_bag` (0x187d7398c) sends as 0. The
/// 26B123 kernel the guest runs (`_code_ipc_change_lock_state` VA
/// 0xfffffe0009d5c1ac) has the same layout. Operations from the callers:
/// -1 asks whether a bag is bound (sel 14, `aks_get_system`, VA
/// 0xfffffe0009d37f68), 0 unlocks with the secret (`aks_unlock_bag`), 1
/// locks (`aks_lock_bag` 0x187d73ec0).
pub(super) const CHANGE_LOCK_STATE: u8 = 4;
/// `__ipc_make_system_keybag_v1` (VA 0xfffffe0009d3e72c from
/// `set_device_keybag` VA 0xfffffe0009d2a694): session, the bag's handle,
/// the special handle (-uid; sel 5 logs "set handle %d as special bag %d"),
/// the secret (empty from `aks_set_system`) and flags (0x100 only when the
/// selector's fifth scalar is set); no reply fields.
pub(super) const MAKE_SYSTEM: u8 = 0x0d;
/// `__ipc_device_state_transition` (VA 0xfffffe0009d5da4c), variant 0:
/// session, handle, transition, u64, secret; reply two u64s, which
/// `device_state_transition` (VA 0xfffffe0009d26590) passes to
/// `handle_device_state_return` as flags and deadline. `unlock_the_device`
/// (sel 9) sends transition 0 with the passcode.
pub(super) const DEVICE_STATE_TRANSITION: u8 = 0x18;
/// `__ipc_change_secret_v3` (VA 0xfffffe0009d5cabc from `change_password`
/// VA 0xfffffe0009d28908, sel 15): session, handle, old secret, new secret,
/// two more blobs, then u32s for a byte, the generation option and flags
/// (args struct +0xa4, +0xa8, +0xac); reply a u32 (+0xb0, the caller's
/// `int *`, sent in and returned) and the fv-data descriptor blob (+0xb8).
/// `aks_change_secret` (0x187d73d18) sends the byte 0xff, its generation
/// option, empty third and fourth blobs and flags 0; applekeystored's
/// password change (0x1000327ee..0x100032868) passes generation 0, then
/// saves the bag (`aks_save_bag`) and writes the file. It does not verify
/// (0x21) first: the old secret is checked here.
pub(super) const CHANGE_SECRET: u8 = 7;
/// `aks_change_secret`'s byte (0x187d73d2c, `mov w8, #0xff`).
const CHANGE_BYTE: u32 = 0xff;

/// The one bag type a login creates (applekeystored 0x100031fa2).
const DEVICE_BAG: u32 = 0;
/// `aks_create_bag`'s parent (0x187d739a8, `mov w6, #-1`).
const NO_PARENT: u32 = u32::MAX;
/// Stela's first bag handle: positive, as `set_device_keybag` requires of
/// the bag it binds (VA 0xfffffe0009d38aa8, handle >= 1), and clear of the
/// small numbers the kernel gives its own meanings.
const FIRST_HANDLE: i32 = 16;
/// At most this many bags are loaded at once: a bound for a loop that
/// loads without unloading, far above a login's two or three.
const MAX_BAGS: usize = 64;

/// Iterations of the passcode KEK. Stela's choice: about 30-60 ms of one
/// core on a current PC, spread over SEP steps. Stored in each bag.
pub(super) const ITERATIONS: u32 = 100_000;
/// Iterations per SEP step: well under a millisecond on a slow PC.
pub(super) const SLICE: u32 = 1024;
const MAX_ITERATIONS: u32 = 10_000_000;

const MAGIC: [u8; 4] = *b"SKB1";
const VERSION: u32 = 1;
const UUID_BYTES: usize = 16;
const SALT_BYTES: usize = 16;
/// The bag has a nonempty passcode.
const HAS_PASSCODE: u32 = 1;
const HEADER_BYTES: usize = 4 + 4 + 4 + 4 + UUID_BYTES + 4 + 4 + SALT_BYTES;
const MAC_BYTES: usize = 32;
const NO_PIN: u32 = 1 << 1;
const BEEN_UNLOCKED: u32 = 1 << 3;
/// `handle_device_state_return` bit 2: notify a lock-state change (device
/// state 5) on the handle (VA 0xfffffe0009d263b8..0xfffffe0009d263d8).
const NOTIFY_LOCK_STATE: u64 = 1 << 2;
/// Change lock state's query operation, -1.
const QUERY: u32 = u32::MAX;
const UNLOCK: u32 = 0;
const LOCK: u32 = 1;
/// Status -8: the kernel maps it to 0xe007c008 (`err_sks_to_aks`, table VA
/// 0xfffffe0007729990 + 4 * (status + 0x27)), the one code
/// `verify_password` treats apart; libaks's name for it, from memory and
/// not yet confirmed, is kAKSReturnBadPassword.
pub(super) const BAD_PASSCODE_STATUS: u8 = 0xf8;
pub(super) const BAD_PASSCODE: &str = "SEP keybag passcode does not open the bag";
pub(super) const BLOB_BYTES: usize = HEADER_BYTES + 2 * SEALED_BYTES + MAC_BYTES;

const ROOT_DOMAIN: &[u8] = b"Stela SEP keybags v1\0";
const BAG_DOMAIN: &[u8] = b"Stela SEP keybag key v1\0";
const SECRET_DOMAIN: &[u8] = b"Stela SEP keybag passcode v1\0";
const KEK_DOMAIN: &[u8] = b"Stela SEP keybag KEK v1\0";
const DEVICE_DOMAIN: &[u8] = b"Stela SEP keybag device seed v1\0";
const PASSCODE_DOMAIN: &[u8] = b"Stela SEP keybag passcode seed v1\0";
const MAC_DOMAIN: &[u8] = b"Stela SEP keybag blob v1\0";

/// Said once per boot, when the first bag is created or loaded.
pub(super) const AT_REST: &str = "user data protection uses a key stored on this disk; it stops a wrong passcode at the login window, but not someone who reads the disk.";
/// Progress, once per boot each, for the guest check.
pub(super) const CREATED: &str = "SEP keybag: created a user keybag";
pub(super) const LOADED: &str = "SEP keybag: loaded a saved user keybag";
pub(super) const BOUND: &str = "SEP keybag: bound a user keybag to its session";
pub(super) const UNLOCKED: &str = "SEP keybag: the passcode unlocked a user keybag";
pub(super) const CHANGED: &str = "SEP keybag: a user keybag's passcode was changed";
pub(super) const REPLACED: &str = "SEP keybag: a new user keybag replaced a session's bound keybag";
const UNOPENABLE: &str = "SEP keybag: a saved keybag does not open under this machine's keys; it is refused and nothing replaces it";

pub(super) fn recognizes(command: u8) -> bool {
    matches!(
        command,
        CREATE
            | COPY
            | LOAD
            | UNLOAD
            | UUID
            | CHANGE_LOCK_STATE
            | MAKE_SYSTEM
            | DEVICE_STATE_TRANSITION
            | CHANGE_SECRET
    )
}

/// A decoded request of a variant the current AP wrappers use. Field names
/// follow the AP's argument flow.
pub(super) enum Request<'a> {
    Create {
        kind: u32,
        parent: u32,
        passcode: &'a [u8],
        acm: &'a [u8],
        extension: &'a [u8],
        descriptor: &'a [u8],
        flags: u64,
    },
    Copy {
        handle: i32,
        query: &'a [u8],
    },
    Load {
        blob: &'a [u8],
    },
    Unload {
        handle: i32,
    },
    Uuid {
        handle: i32,
    },
    LockState {
        handle: i32,
        operation: u32,
        secret: &'a [u8],
        flags: u64,
    },
    Bind {
        handle: i32,
        special: i32,
        secret: &'a [u8],
        flags: u64,
    },
    ChangeSecret {
        handle: i32,
        old: &'a [u8],
        new: &'a [u8],
        third: &'a [u8],
        fourth: &'a [u8],
        byte: u32,
        generation: u32,
        flags: u32,
    },
    Transition {
        handle: i32,
        transition: u32,
        argument: u64,
        secret: &'a [u8],
    },
}

impl<'a> Request<'a> {
    pub(super) fn parse(command: u8, variant: u32, fields: &mut Fields<'a>) -> Result<Self> {
        let expected = match command {
            CREATE => 4,
            COPY => 1,
            LOAD | UNLOAD | UUID | DEVICE_STATE_TRANSITION => 0,
            CHANGE_LOCK_STATE | MAKE_SYSTEM => 1,
            CHANGE_SECRET => 3,
            _ => {
                return Err(refuse!(
                    "SEP keystore command has no recovered keybag codec"
                ));
            }
        };
        if variant != expected {
            return Err(refuse!(
                "SEP keystore keybag command variant is not modeled"
            ));
        }
        let _session = fields.lword()?;
        let handle = |fields: &mut Fields<'a>| fields.word().map(|word| word as i32);
        let request = match command {
            // _code_ipc_create_keybag, variant 4 request: 0x2d3cf28..0x2d3d010.
            // The fourth blob uses a descriptor helper; its wire form is still
            // length + bytes + pad4. The reply is variant 4, a handle and a blob.
            CREATE => Self::Create {
                kind: fields.word()?,
                parent: fields.word()?,
                passcode: fields.blob()?,
                acm: fields.blob()?,
                extension: fields.blob()?,
                descriptor: fields.blob()?,
                flags: fields.lword()?,
            },
            // _code_ipc_copy_keybag v1: 0x2d3d278..0x2d3d2d4; reply one blob.
            COPY => Self::Copy {
                handle: handle(fields)?,
                query: fields.blob()?,
            },
            // _code_ipc_load_keybag: 0x2d3d458..0x2d3d48c; reply one handle.
            LOAD => Self::Load {
                blob: fields.blob()?,
            },
            // _code_ipc_unload_keybag: 0x2d3d8f0..0x2d3d924; reply no fields.
            UNLOAD => Self::Unload {
                handle: handle(fields)?,
            },
            // _code_ipc_copy_keybag_uuid: 0x2d3daa4..0x2d3dad4; reply one blob.
            UUID => Self::Uuid {
                handle: handle(fields)?,
            },
            // _code_ipc_change_lock_state v1 (VA 0xfffffe0009d41544): u64,
            // u32, u32, blob, u64 (0xfffffe0009d416a8..0xfffffe0009d41770);
            // reply u32, u64. Variant 0 has no trailing u64 and is not sent.
            CHANGE_LOCK_STATE => Self::LockState {
                handle: handle(fields)?,
                operation: fields.word()?,
                secret: fields.blob()?,
                flags: fields.lword()?,
            },
            // _code_ipc_make_system_keybag v1 (VA 0xfffffe0009d42b7c): u64,
            // u32, u32, blob, u64; no reply fields.
            MAKE_SYSTEM => Self::Bind {
                handle: handle(fields)?,
                special: handle(fields)?,
                secret: fields.blob()?,
                flags: fields.lword()?,
            },
            // _code_ipc_change_secret v3 request (VA 0xfffffe0009d41e48..
            // 0xfffffe0009d41f3c): u64, u32, four blobs, three u32s; reply
            // (0xfffffe0009d41d78..0xfffffe0009d41da4) a u32 and a blob.
            CHANGE_SECRET => Self::ChangeSecret {
                handle: handle(fields)?,
                old: fields.blob()?,
                new: fields.blob()?,
                third: fields.blob()?,
                fourth: fields.blob()?,
                byte: fields.word()?,
                generation: fields.word()?,
                flags: fields.word()?,
            },
            // _code_ipc_device_state_transition v0 (VA 0xfffffe0009d447e8):
            // u64, u32, u32, u64, blob; reply u64, u64.
            _ => Self::Transition {
                handle: handle(fields)?,
                transition: fields.word()?,
                argument: fields.lword()?,
                secret: fields.blob()?,
            },
        };
        fields.end()?;
        Ok(request)
    }
}

/// What a keybag request produced: its reply fields, or a passcode
/// derivation the SEP runs over its next steps before replying.
pub(super) enum Outcome {
    Reply(Vec<u8>),
    Derive(alloc::boxed::Box<Pending>),
}

/// PBKDF2-HMAC-SHA256 with one 32-byte output block, run in slices: the
/// state between slices is the keyed MAC, the last U and the running XOR.
pub(super) struct Derivation {
    mac: Hmac<Sha256>,
    last: Zeroizing<[u8; 32]>,
    sum: Zeroizing<[u8; 32]>,
    left: u32,
}

impl Derivation {
    fn new(password: &[u8], salt: &[u8], iterations: u32) -> Self {
        let mac = Hmac::<Sha256>::new_from_slice(password).expect("HMAC accepts any key length");
        let mut first = mac.clone();
        first.update(salt);
        first.update(&1u32.to_be_bytes());
        let last: Zeroizing<[u8; 32]> = Zeroizing::new(first.finalize().into_bytes().into());
        Self {
            mac,
            sum: last.clone(),
            last,
            left: iterations.saturating_sub(1),
        }
    }

    /// Run at most `slice` more iterations; true once all have run.
    fn step(&mut self, slice: u32) -> bool {
        for _ in 0..slice.min(self.left) {
            let mut next = self.mac.clone();
            next.update(&*self.last);
            *self.last = next.finalize().into_bytes().into();
            for (sum, byte) in self.sum.iter_mut().zip(self.last.iter()) {
                *sum ^= byte;
            }
        }
        self.left -= slice.min(self.left);
        self.left == 0
    }

    fn key(&self) -> &[u8; 32] {
        &self.sum
    }
}

/// A request waiting for its passcode KEK.
pub(super) struct Pending {
    derivation: Derivation,
    then: Option<Then>,
}

enum Then {
    /// Seal a new bag with the derived KEK and give it a handle.
    Create(Bag),
    /// Open the passcode seed of the bag at `handle` with the derived KEK,
    /// then answer as `reply` lays out.
    Unlock {
        handle: i32,
        uuid: [u8; UUID_BYTES],
        reply: Unlocked,
    },
    /// The old secret's KEK is derived: open the passcode seed with it, then
    /// derive the new secret's KEK over `salt`.
    ChangeOld {
        handle: i32,
        uuid: [u8; UUID_BYTES],
        new: Zeroizing<Vec<u8>>,
        salt: [u8; SALT_BYTES],
    },
    /// The new KEK is derived: re-seal `seed` under `header` in every loaded
    /// instance of the bag.
    ChangeNew {
        uuid: [u8; UUID_BYTES],
        header: Header,
        seed: Zeroizing<[u8; KEY_BYTES]>,
    },
}

/// The reply an unlock gives: change lock state's u32 state and u64 flags,
/// or the transition's u64 flags and u64 deadline.
#[derive(Clone, Copy)]
enum Unlocked {
    LockState,
    Transition,
}

#[derive(Clone, PartialEq, Eq)]
struct Header {
    kind: u32,
    flags: u32,
    uuid: [u8; UUID_BYTES],
    iterations: u32,
    generation: u32,
    salt: [u8; SALT_BYTES],
}

impl Header {
    fn bytes(&self) -> [u8; HEADER_BYTES] {
        let mut bytes = [0; HEADER_BYTES];
        bytes[0..4].copy_from_slice(&MAGIC);
        bytes[4..8].copy_from_slice(&VERSION.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.kind.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.flags.to_le_bytes());
        bytes[16..32].copy_from_slice(&self.uuid);
        bytes[32..36].copy_from_slice(&self.iterations.to_le_bytes());
        bytes[36..40].copy_from_slice(&self.generation.to_le_bytes());
        bytes[40..56].copy_from_slice(&self.salt);
        bytes
    }

    fn parse(bytes: &[u8; HEADER_BYTES]) -> Result<Self> {
        let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        if bytes[0..4] != MAGIC || word(4) != VERSION {
            return Err(refuse!("SEP keybag blob is not a Stela keybag version 1"));
        }
        let header = Self {
            kind: word(8),
            flags: word(12),
            uuid: bytes[16..32].try_into().unwrap(),
            iterations: word(32),
            generation: word(36),
            salt: bytes[40..56].try_into().unwrap(),
        };
        if header.kind != DEVICE_BAG
            || header.flags & !HAS_PASSCODE != 0
            || !(1..=MAX_ITERATIONS).contains(&header.iterations)
        {
            return Err(refuse!("SEP keybag blob header is outside version 1"));
        }
        Ok(header)
    }

    fn has_passcode(&self) -> bool {
        self.flags & HAS_PASSCODE != 0
    }

    /// This header after a secret change: a new salt, the next generation
    /// and the new secret's passcode flag.
    fn changed(&self, salt: [u8; SALT_BYTES], passcode: bool) -> Result<Self> {
        Ok(Self {
            salt,
            generation: self
                .generation
                .checked_add(1)
                .ok_or(refuse!("SEP keybag passcode generation is exhausted"))?,
            flags: if passcode { HAS_PASSCODE } else { 0 },
            ..self.clone()
        })
    }
}

/// One loaded bag.
struct Bag {
    header: Header,
    device_sealed: [u8; SEALED_BYTES],
    passcode_sealed: [u8; SEALED_BYTES],
    /// The opened device seed; every loaded bag has it.
    device: Zeroizing<[u8; KEY_BYTES]>,
    /// The opened passcode seed, while the bag is unlocked.
    passcode: Option<Zeroizing<[u8; KEY_BYTES]>>,
    /// Whether the passcode opened this instance since it was loaded.
    been_unlocked: bool,
}

impl Bag {
    /// The keybag state flags (`ss`): `keybag_state_locked` (bit 0),
    /// `keybag_state_no_pin` (bit 1), `keybag_state_been_unlocked` (bit 3).
    fn state(&self) -> u32 {
        let locked = self.passcode.is_none();
        u32::from(locked)
            | if self.header.has_passcode() {
                0
            } else {
                NO_PIN
            }
            | if self.been_unlocked || !self.header.has_passcode() {
                BEEN_UNLOCKED
            } else {
                0
            }
    }

    /// The same bag, locked as if just loaded: a bound instance answers to
    /// its own passcode check.
    fn reopened(&self) -> Self {
        Self {
            header: self.header.clone(),
            device_sealed: self.device_sealed,
            passcode_sealed: self.passcode_sealed,
            device: self.device.clone(),
            passcode: if self.header.has_passcode() {
                None
            } else {
                self.passcode.clone()
            },
            been_unlocked: !self.header.has_passcode(),
        }
    }
}

pub(super) struct Keybags {
    root: Zeroizing<[u8; 32]>,
    iterations: u32,
    bags: Vec<(i32, Bag)>,
    next: i32,
    /// Reports already made this boot.
    reported: Vec<&'static str>,
    /// Once-per-boot progress lines waiting for [`Keybags::drain`].
    queued: Vec<String>,
}

fn mac(key: &[u8; 32], parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts 256-bit keys");
    for part in parts {
        mac.update(part);
    }
    Zeroizing::new(mac.finalize().into_bytes().into())
}

fn random<const N: usize>(entropy: &mut dyn super::super::Entropy) -> Result<Zeroizing<[u8; N]>> {
    let mut bytes = Zeroizing::new([0; N]);
    entropy.fill(&mut *bytes)?;
    Ok(bytes)
}

impl Keybags {
    /// Bags under the machine's system-key `root`.
    pub(super) fn new(root: &[u8; 32]) -> Self {
        Self::with_iterations(root, ITERATIONS)
    }

    /// Bags created with `iterations` passcode iterations (tests).
    pub(super) fn with_iterations(root: &[u8; 32], iterations: u32) -> Self {
        Self {
            root: mac(root, &[ROOT_DOMAIN]),
            iterations,
            bags: Vec::new(),
            next: FIRST_HANDLE,
            reported: Vec::new(),
            queued: Vec::new(),
        }
    }

    /// Record that a login step succeeded, once per boot; no values.
    fn progress(&mut self, line: &'static str) {
        if !self.reported.contains(&line) {
            self.reported.push(line);
            self.queued.push(String::from(line));
        }
    }

    /// The queued progress lines.
    pub(super) fn drain(&mut self) -> impl Iterator<Item = String> + '_ {
        self.queued.drain(..)
    }

    fn report(&mut self, line: &'static str, note: &mut dyn FnMut(String)) {
        if !self.reported.contains(&line) {
            self.reported.push(line);
            note(String::from(line));
        }
    }

    /// Report a refused request shape once, with its value; never secrets.
    fn refuse_shape(
        &mut self,
        what: &'static str,
        value: u64,
        note: &mut dyn FnMut(String),
    ) -> stela_contracts::Refusal {
        if !self.reported.contains(&what) {
            self.reported.push(what);
            note(format!("SEP keybag: {what} {value:#x} is not modeled"));
        }
        refuse!("SEP keybag request is outside the modeled login flow")
    }

    fn bag_key(&self, uuid: &[u8; UUID_BYTES]) -> Zeroizing<[u8; 32]> {
        mac(&self.root, &[BAG_DOMAIN, uuid])
    }

    /// The key the passcode seed is sealed under: the bag key with the KEK,
    /// or the bag key alone when the passcode is empty.
    fn passcode_key(&self, header: &Header, kek: Option<&[u8; 32]>) -> Zeroizing<[u8; 32]> {
        let key = self.bag_key(&header.uuid);
        match kek {
            Some(kek) => mac(&key, &[KEK_DOMAIN, kek]),
            None => key,
        }
    }

    /// The KEK derivation for `secret` in the bag with `header`.
    fn derivation(&self, header: &Header, secret: &[u8]) -> Derivation {
        let password = mac(&self.bag_key(&header.uuid), &[SECRET_DOMAIN, secret]);
        Derivation::new(&*password, &header.salt, header.iterations)
    }

    fn find(&self, handle: i32) -> Result<&Bag> {
        self.bags
            .iter()
            .find(|(h, _)| *h == handle)
            .map(|(_, bag)| bag)
            .ok_or(refuse!("SEP keybag handle is not loaded"))
    }

    fn insert(&mut self, bag: Bag) -> Result<i32> {
        if self.bags.len() >= MAX_BAGS {
            return Err(refuse!("SEP keybag table is full"));
        }
        // Handles stay positive and unique while their bags are loaded.
        while self.bags.iter().any(|(h, _)| *h == self.next) {
            self.next = self.next.checked_add(1).unwrap_or(FIRST_HANDLE);
        }
        let handle = self.next;
        self.next = self.next.checked_add(1).unwrap_or(FIRST_HANDLE);
        self.bags.push((handle, bag));
        Ok(handle)
    }

    fn blob(&self, bag: &Bag) -> Vec<u8> {
        let header = bag.header.bytes();
        let mut blob = Vec::with_capacity(BLOB_BYTES);
        blob.extend_from_slice(&header);
        blob.extend_from_slice(&bag.device_sealed);
        blob.extend_from_slice(&bag.passcode_sealed);
        let tag = mac(&self.bag_key(&bag.header.uuid), &[MAC_DOMAIN, &blob]);
        blob.extend_from_slice(&*tag);
        blob
    }

    /// Open a saved blob: its MAC and device seed under this machine's
    /// keys. The passcode seed stays sealed unless the passcode is empty.
    fn open_blob(&self, blob: &[u8]) -> Result<Bag> {
        if blob.len() != BLOB_BYTES {
            return Err(refuse!("SEP keybag blob is not a Stela keybag"));
        }
        let header_bytes: &[u8; HEADER_BYTES] = blob[..HEADER_BYTES].try_into().unwrap();
        let uuid: [u8; UUID_BYTES] = header_bytes[16..32].try_into().unwrap();
        let key = self.bag_key(&uuid);
        let body = BLOB_BYTES - MAC_BYTES;
        let mut check = Hmac::<Sha256>::new_from_slice(&*key).expect("HMAC accepts 256-bit keys");
        check.update(MAC_DOMAIN);
        check.update(&blob[..body]);
        check
            .verify_slice(&blob[body..])
            .map_err(|_| refuse!("SEP keybag blob does not authenticate"))?;
        let header = Header::parse(header_bytes)?;
        let device_sealed: [u8; SEALED_BYTES] = blob[HEADER_BYTES..HEADER_BYTES + SEALED_BYTES]
            .try_into()
            .unwrap();
        let passcode_sealed: [u8; SEALED_BYTES] = blob
            [HEADER_BYTES + SEALED_BYTES..HEADER_BYTES + 2 * SEALED_BYTES]
            .try_into()
            .unwrap();
        let device = open(&key, DEVICE_DOMAIN, header_bytes, &device_sealed)?;
        let passcode = if header.has_passcode() {
            None
        } else {
            Some(open(
                &self.passcode_key(&header, None),
                PASSCODE_DOMAIN,
                header_bytes,
                &passcode_sealed,
            )?)
        };
        Ok(Bag {
            been_unlocked: passcode.is_some(),
            header,
            device_sealed,
            passcode_sealed,
            device,
            passcode,
        })
    }

    /// Serve one keybag request.
    pub(super) fn request(
        &mut self,
        command: u8,
        variant: u32,
        fields: &mut Fields<'_>,
        entropy: &mut dyn super::super::Entropy,
        note: &mut dyn FnMut(String),
    ) -> Result<Outcome> {
        match Request::parse(command, variant, fields)? {
            Request::Create {
                kind,
                parent,
                passcode,
                acm,
                extension,
                descriptor,
                flags,
            } => {
                // Only the shape applekeystored's login sends; ACM-bound
                // secrets, parents, extensions and flagged bags refuse.
                if kind != DEVICE_BAG {
                    return Err(self.refuse_shape("create bag type", kind.into(), note));
                }
                if parent != NO_PARENT {
                    return Err(self.refuse_shape("create parent", parent.into(), note));
                }
                if flags != 0 {
                    return Err(self.refuse_shape("create flags", flags, note));
                }
                for (what, blob) in [
                    ("create ACM blob length", acm),
                    ("create extension blob length", extension),
                    ("create descriptor blob length", descriptor),
                ] {
                    if !blob.is_empty() {
                        return Err(self.refuse_shape(what, blob.len() as u64, note));
                    }
                }
                if self.bags.len() >= MAX_BAGS {
                    return Err(refuse!("SEP keybag table is full"));
                }
                self.report(AT_REST, note);
                let uuid = random::<UUID_BYTES>(entropy)?;
                let salt = random::<SALT_BYTES>(entropy)?;
                let device = random::<KEY_BYTES>(entropy)?;
                let seed = random::<KEY_BYTES>(entropy)?;
                let header = Header {
                    kind,
                    flags: if passcode.is_empty() { 0 } else { HAS_PASSCODE },
                    uuid: *uuid,
                    iterations: self.iterations,
                    generation: 0,
                    salt: *salt,
                };
                let device_sealed = seal(
                    &self.bag_key(&header.uuid),
                    DEVICE_DOMAIN,
                    &header.bytes(),
                    &device,
                );
                let bag = Bag {
                    header,
                    device_sealed,
                    passcode_sealed: [0; SEALED_BYTES],
                    device,
                    passcode: Some(seed),
                    been_unlocked: true,
                };
                if passcode.is_empty() {
                    return self.finish(Then::Create(bag), None);
                }
                Ok(Outcome::Derive(alloc::boxed::Box::new(Pending {
                    derivation: self.derivation(&bag.header, passcode),
                    then: Some(Then::Create(bag)),
                })))
            }
            Request::Copy { handle, query } => {
                if !query.is_empty() {
                    return Err(self.refuse_shape("save query length", query.len() as u64, note));
                }
                let blob = self.blob(self.find(handle)?);
                Ok(Outcome::Reply(reply_blob(&blob)))
            }
            Request::Load { blob } => {
                self.report(AT_REST, note);
                let bag = match self.open_blob(blob) {
                    Ok(bag) => bag,
                    Err(reason) => {
                        self.report(UNOPENABLE, note);
                        return Err(reason);
                    }
                };
                let handle = self.insert(bag)?;
                self.progress(LOADED);
                Ok(Outcome::Reply(handle.to_le_bytes().to_vec()))
            }
            Request::Unload { handle } => {
                self.find(handle)?;
                self.bags.retain(|(h, _)| *h != handle);
                Ok(Outcome::Reply(Vec::new()))
            }
            Request::Uuid { handle } => {
                let uuid = self.find(handle)?.header.uuid;
                Ok(Outcome::Reply(reply_blob(&uuid)))
            }
            Request::Bind {
                handle,
                special,
                secret,
                flags,
            } => {
                if !secret.is_empty() {
                    return Err(self.refuse_shape("bind secret length", secret.len() as u64, note));
                }
                if flags != 0 {
                    return Err(self.refuse_shape("bind flags", flags, note));
                }
                // A user session's special handle, -uid, as sel 5 forms it
                // for uid >= 3 (VA 0xfffffe0009d38a84..0xfffffe0009d38a90);
                // the device bag (0) is not modeled.
                if handle < 1 || special > -3 {
                    return Err(self.refuse_shape(
                        "bind handles",
                        (u64::from(handle as u32) << 32) | u64::from(special as u32),
                        note,
                    ));
                }
                let bound = self.find(handle)?.reopened();
                if let Ok(existing) = self.find(special) {
                    // The same bag again changes nothing. Another bag
                    // replaces it, locked: applekeystored's reset path
                    // (0x10003294f..0x100032a46: "resetting keybag for uid",
                    // create, save, set_system, unlock) binds a new bag
                    // over the old one when the old one no longer opens
                    // with the user's passcode. The AP decides that; the
                    // SEP never makes a bag of its own.
                    if existing.header.uuid == bound.header.uuid {
                        return Ok(Outcome::Reply(Vec::new()));
                    }
                    self.bags.retain(|(h, _)| *h != special);
                    self.progress(REPLACED);
                }
                if self.bags.len() >= MAX_BAGS {
                    return Err(refuse!("SEP keybag table is full"));
                }
                self.bags.push((special, bound));
                self.progress(BOUND);
                Ok(Outcome::Reply(Vec::new()))
            }
            Request::LockState {
                handle,
                operation,
                secret,
                flags,
            } => match operation {
                _ if flags != 0 => Err(self.refuse_shape("lock-state flags", flags, note)),
                QUERY | LOCK if !secret.is_empty() => {
                    Err(self.refuse_shape("lock-state secret length", secret.len() as u64, note))
                }
                QUERY => {
                    let state = self.find(handle)?.state();
                    Ok(Outcome::Reply(lock_state_reply(state, 0)))
                }
                LOCK => {
                    let bag = self.find_mut(handle)?;
                    let changed = bag.header.has_passcode() && bag.passcode.is_some();
                    if bag.header.has_passcode() {
                        bag.passcode = None;
                    }
                    let state = bag.state();
                    Ok(Outcome::Reply(lock_state_reply(
                        state,
                        if changed { NOTIFY_LOCK_STATE } else { 0 },
                    )))
                }
                UNLOCK => self.unlock(handle, secret, Unlocked::LockState),
                _ => Err(self.refuse_shape("lock-state operation", operation.into(), note)),
            },
            Request::ChangeSecret {
                handle,
                old,
                new,
                third,
                fourth,
                byte,
                generation,
                flags,
            } => {
                for (what, value) in [
                    ("change third blob length", third.len() as u64),
                    ("change fourth blob length", fourth.len() as u64),
                    ("change generation option", generation.into()),
                    ("change flags", flags.into()),
                ] {
                    if value != 0 {
                        return Err(self.refuse_shape(what, value, note));
                    }
                }
                if byte != CHANGE_BYTE {
                    return Err(self.refuse_shape("change byte", byte.into(), note));
                }
                let bag = self.find(handle)?;
                let uuid = bag.header.uuid;
                if !bag.header.has_passcode() {
                    // No passcode: the old secret must be empty, and the
                    // open seed is re-sealed for the new one.
                    if !old.is_empty() {
                        return Err(BAD_PASSCODE.into());
                    }
                    let seed = bag
                        .passcode
                        .clone()
                        .ok_or(refuse!("SEP keybag without a passcode is not open"))?;
                    let header = bag.header.clone();
                    let salt = *random::<SALT_BYTES>(entropy)?;
                    let header = header.changed(salt, !new.is_empty())?;
                    return self.change_new(uuid, header, seed, new);
                }
                let derivation = self.derivation(&bag.header, old);
                let salt = *random::<SALT_BYTES>(entropy)?;
                Ok(Outcome::Derive(alloc::boxed::Box::new(Pending {
                    derivation,
                    then: Some(Then::ChangeOld {
                        handle,
                        uuid,
                        new: Zeroizing::new(new.to_vec()),
                        salt,
                    }),
                })))
            }
            Request::Transition {
                handle,
                transition,
                argument,
                secret,
            } => {
                if transition != 0 {
                    return Err(self.refuse_shape(
                        "device state transition",
                        transition.into(),
                        note,
                    ));
                }
                if argument != 0 {
                    return Err(self.refuse_shape("unlock transition argument", argument, note));
                }
                self.unlock(handle, secret, Unlocked::Transition)
            }
        }
    }

    fn find_mut(&mut self, handle: i32) -> Result<&mut Bag> {
        self.bags
            .iter_mut()
            .find(|(h, _)| *h == handle)
            .map(|(_, bag)| bag)
            .ok_or(refuse!("SEP keybag handle is not loaded"))
    }

    /// The `ss` state of the bag at `handle`, when one is loaded there.
    pub(super) fn state(&self, handle: i32) -> Option<u32> {
        self.find(handle).ok().map(Bag::state)
    }

    /// Unlock the bag at `handle` with `secret`: at once for a bag without
    /// a passcode, after the KEK derivation otherwise.
    fn unlock(&mut self, handle: i32, secret: &[u8], reply: Unlocked) -> Result<Outcome> {
        let bag = self.find(handle)?;
        if !bag.header.has_passcode() {
            if !secret.is_empty() {
                return Err(BAD_PASSCODE.into());
            }
            return Ok(Outcome::Reply(unlocked_reply(reply, bag.state(), 0)));
        }
        Ok(Outcome::Derive(alloc::boxed::Box::new(Pending {
            derivation: self.derivation(&bag.header, secret),
            then: Some(Then::Unlock {
                handle,
                uuid: bag.header.uuid,
                reply,
            }),
        })))
    }

    /// Run one slice of `pending`'s derivation; once it is complete, finish
    /// the request and return its reply fields, once.
    pub(super) fn step(&mut self, pending: &mut Pending) -> Option<Result<Vec<u8>>> {
        if !pending.derivation.step(SLICE) {
            return None;
        }
        let then = pending.then.take()?;
        match self.finish(then, Some(pending.derivation.key())) {
            Ok(Outcome::Reply(fields)) => Some(Ok(fields)),
            // A second derivation follows in later steps.
            Ok(Outcome::Derive(next)) => {
                *pending = *next;
                None
            }
            Err(reason) => Some(Err(reason)),
        }
    }

    fn finish(&mut self, then: Then, kek: Option<&[u8; 32]>) -> Result<Outcome> {
        match then {
            Then::Create(mut bag) => {
                let seed = bag
                    .passcode
                    .as_ref()
                    .ok_or(refuse!("SEP keybag create lost its seed"))?;
                bag.passcode_sealed = seal(
                    &self.passcode_key(&bag.header, kek),
                    PASSCODE_DOMAIN,
                    &bag.header.bytes(),
                    seed,
                );
                let handle = self.insert(bag)?;
                self.progress(CREATED);
                // Variant 4 reply: the handle, then the descriptor blob,
                // empty, which create_keybag discards.
                let mut fields = handle.to_le_bytes().to_vec();
                fields.extend_from_slice(&0u32.to_le_bytes());
                Ok(Outcome::Reply(fields))
            }
            Then::Unlock {
                handle,
                uuid,
                reply,
            } => {
                let kek = kek.ok_or(refuse!("SEP keybag unlock has no KEK"))?;
                let bag = self.find(handle)?;
                if bag.header.uuid != uuid {
                    return Err(refuse!("SEP keybag handle changed during its unlock"));
                }
                let seed = open(
                    &self.passcode_key(&bag.header, Some(kek)),
                    PASSCODE_DOMAIN,
                    &bag.header.bytes(),
                    &bag.passcode_sealed,
                )
                .map_err(|_| stela_contracts::Refusal::from(BAD_PASSCODE))?;
                let bag = self.find_mut(handle)?;
                let changed = bag.passcode.is_none();
                bag.passcode = Some(seed);
                bag.been_unlocked = true;
                let state = bag.state();
                self.progress(UNLOCKED);
                Ok(Outcome::Reply(unlocked_reply(
                    reply,
                    state,
                    if changed { NOTIFY_LOCK_STATE } else { 0 },
                )))
            }
            Then::ChangeOld {
                handle,
                uuid,
                new,
                salt,
            } => {
                let kek = kek.ok_or(refuse!("SEP keybag change has no KEK"))?;
                let bag = self.find(handle)?;
                if bag.header.uuid != uuid {
                    return Err(refuse!("SEP keybag handle changed during its change"));
                }
                let seed = open(
                    &self.passcode_key(&bag.header, Some(kek)),
                    PASSCODE_DOMAIN,
                    &bag.header.bytes(),
                    &bag.passcode_sealed,
                )
                .map_err(|_| stela_contracts::Refusal::from(BAD_PASSCODE))?;
                let header = bag.header.changed(salt, !new.is_empty())?;
                self.change_new(uuid, header, seed, &new)
            }
            Then::ChangeNew { uuid, header, seed } => self.commit_change(uuid, header, &seed, kek),
        }
    }

    /// The old secret checked: derive the new KEK, or re-seal at once when
    /// the new secret is empty.
    fn change_new(
        &mut self,
        uuid: [u8; UUID_BYTES],
        header: Header,
        seed: Zeroizing<[u8; KEY_BYTES]>,
        new: &[u8],
    ) -> Result<Outcome> {
        if new.is_empty() {
            return self.commit_change(uuid, header, &seed, None);
        }
        Ok(Outcome::Derive(alloc::boxed::Box::new(Pending {
            derivation: self.derivation(&header, new),
            then: Some(Then::ChangeNew { uuid, header, seed }),
        })))
    }

    /// Re-seal the unchanged seeds under `header` (new salt, generation and
    /// passcode flag) in every loaded instance of bag `uuid`: unlocked
    /// instances stay unlocked, locked ones now open with the new secret.
    fn commit_change(
        &mut self,
        uuid: [u8; UUID_BYTES],
        header: Header,
        seed: &[u8; KEY_BYTES],
        kek: Option<&[u8; 32]>,
    ) -> Result<Outcome> {
        let header_bytes = header.bytes();
        let passcode_sealed = seal(
            &self.passcode_key(&header, kek),
            PASSCODE_DOMAIN,
            &header_bytes,
            seed,
        );
        let key = self.bag_key(&uuid);
        let mut changed = false;
        for (_, bag) in self
            .bags
            .iter_mut()
            .filter(|(_, bag)| bag.header.uuid == uuid)
        {
            bag.device_sealed = seal(&key, DEVICE_DOMAIN, &header_bytes, &bag.device);
            bag.passcode_sealed = passcode_sealed;
            bag.header = header.clone();
            if !header.has_passcode() {
                bag.passcode = Some(Zeroizing::new(*seed));
                bag.been_unlocked = true;
            }
            changed = true;
        }
        if !changed {
            return Err(refuse!("SEP keybag was unloaded during its change"));
        }
        self.progress(CHANGED);
        // The caller's u32 back as the new passcode generation (Stela's
        // reading; applekeystored passes no pointer), then an empty
        // descriptor blob.
        let mut fields = header.generation.to_le_bytes().to_vec();
        fields.extend_from_slice(&0u32.to_le_bytes());
        Ok(Outcome::Reply(fields))
    }
}

/// Change lock state's reply: the u32 keybag state (Stela's reading of the
/// field the kernel stores through its `int *`), then the u64 flags for
/// `handle_device_state_return`.
fn lock_state_reply(state: u32, flags: u64) -> Vec<u8> {
    let mut fields = state.to_le_bytes().to_vec();
    fields.extend_from_slice(&flags.to_le_bytes());
    fields
}

fn unlocked_reply(reply: Unlocked, state: u32, flags: u64) -> Vec<u8> {
    match reply {
        Unlocked::LockState => lock_state_reply(state, flags),
        // Flags, then a deadline: none, as no timer is scheduled (bit 0
        // clear).
        Unlocked::Transition => {
            let mut fields = flags.to_le_bytes().to_vec();
            fields.extend_from_slice(&0u64.to_le_bytes());
            fields
        }
    }
}

/// A reply blob: u32 length, the bytes, zero padding to four.
fn reply_blob(bytes: &[u8]) -> Vec<u8> {
    let mut fields = (bytes.len() as u32).to_le_bytes().to_vec();
    fields.extend_from_slice(bytes);
    fields.resize(fields.len().next_multiple_of(4), 0);
    fields
}

#[cfg(test)]
pub(super) mod tests;
