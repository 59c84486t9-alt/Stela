//! User pointers the kernel signs for, and authenticates from, a process
//! whose user JOP is enabled (xnu `osfmk/arm64/status.c`): function
//! pointers a system call registers and the pointers of a thread state.
//!
//! The kernel authenticates with the process's own keys
//! (`pmap_auth_user_ptr`) and never traps: a pointer that fails is
//! poisoned (`ml_poison_ptr`), so it faults only when the process uses it.
//! Without a signer (an arm64 image, or user JOP disabled) the pointers
//! pass through unchanged, as `ARM_MACHINE_THREAD_DISABLE_USER_JOP` makes
//! the conversions return early.
use crate::pauth::{AuthenticationError, Context, Key};
use anyhow::{Result, bail};

/// `ptrauth_key_function_pointer`'s discriminator: none.
const FUNCTION_POINTER_DISCRIMINATOR: u64 = 0;
/// Bit 55 selects the kernel's half of the address space.
const KERNEL_HALF: u64 = 1 << 55;
/// `ml_poison_ptr`'s error-code field: bits 54:53 of a top-byte-ignored
/// user data pointer, bits 62:61 otherwise.
const POISON_SHIFT_TAGGED: u32 = 53;
const POISON_SHIFT: u32 = 61;

/// `ml_poison_ptr`: the pointer with its two error-code bits replaced by
/// 1 for an A key or 2 for a B key, so that using it faults.
pub(super) fn poison(pointer: u64, key: Key) -> u64 {
    let error_code: u64 = match key {
        Key::Ia | Key::Da => 1,
        Key::Ib | Key::Db => 2,
    };
    // With PAC, only user data pointers ignore their top byte.
    let data = matches!(key, Key::Da | Key::Db);
    let shift = if data && pointer & KERNEL_HALF == 0 {
        POISON_SHIFT_TAGGED
    } else {
        POISON_SHIFT
    };
    (pointer & !(3 << shift)) | (error_code << shift)
}

/// `pmap_auth_user_ptr`: `pointer` authenticated with `key` and
/// `discriminator`, or poisoned when it fails.
pub(super) fn authenticate(
    signer: &Context,
    key: Key,
    pointer: u64,
    discriminator: u64,
) -> Result<u64> {
    match signer.authenticate_operation(key, pointer, discriminator, false) {
        Ok(result) if result.authenticated => Ok(result.pointer),
        Ok(_) | Err(AuthenticationError::Failure { .. }) => Ok(poison(pointer, key)),
        Err(error @ AuthenticationError::KeyUnavailable { .. }) => {
            bail!("the process's user pointers cannot be authenticated: {error}")
        }
    }
}

/// `machine_thread_function_pointers_convert_from_user`: a nonzero
/// function pointer a system call registers, authenticated with the
/// function-pointer key (IA) and no discriminator.
pub(super) fn function_pointer_from_user(signer: Option<&Context>, pointer: u64) -> Result<u64> {
    match signer {
        Some(signer) if pointer != 0 => {
            authenticate(signer, Key::Ia, pointer, FUNCTION_POINTER_DISCRIMINATOR)
        }
        _ => Ok(pointer),
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::pauth;

    /// A signer laid out for the hosted PE's translation regime.
    pub(crate) fn signer() -> Context {
        Context::new_with_version(
            0,
            pauth::Keys::from_words([1, 2], [3, 4], [5, 6], [7, 8]),
            pauth::Version::FaultingCombined,
        )
        .with_translation_regime(crate::hosted::pe::TCR_EL1)
    }

    #[test]
    fn function_pointers_authenticate_or_poison_as_the_kernel_does() {
        let signer = signer();
        let target = 0x1_0342_efd4;
        let signed = signer.sign(Key::Ia, target, 0).unwrap();
        assert_ne!(signed, target);
        assert_eq!(
            function_pointer_from_user(Some(&signer), signed).unwrap(),
            target
        );
        // A pointer signed otherwise is poisoned, not refused.
        let other = signer.sign(Key::Ia, target, 0x1234).unwrap();
        let poisoned = function_pointer_from_user(Some(&signer), other).unwrap();
        assert_eq!(poisoned, (other & !(3 << 61)) | 1 << 61);
        // Nothing is converted without user JOP, and null stays null.
        assert_eq!(function_pointer_from_user(None, signed).unwrap(), signed);
        assert_eq!(function_pointer_from_user(Some(&signer), 0).unwrap(), 0);
    }

    #[test]
    fn poisoning_follows_the_key_and_the_top_byte_rule() {
        let pointer = 0x0000_0001_0000_4000;
        assert_eq!(poison(pointer, Key::Ia), pointer | 1 << 61);
        assert_eq!(poison(pointer, Key::Ib), pointer | 2 << 61);
        assert_eq!(poison(pointer, Key::Da), pointer | 1 << 53);
        assert_eq!(poison(pointer, Key::Db), pointer | 2 << 53);
        let kernel = 0xffff_fe00_0000_4000;
        assert_eq!(poison(kernel, Key::Da), (kernel & !(3 << 61)) | 1 << 61);
    }
}
