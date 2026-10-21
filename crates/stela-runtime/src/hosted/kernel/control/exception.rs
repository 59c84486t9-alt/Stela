//! `exception_deliver`'s user-state conversion: `TSSF_RANDOM_USER_DIV`,
//! `TSSF_TASK_USER_DIV`, `TSSF_ALLOW_ONLY_USER_PTRS` and `TSSF_ONLY_PC`
//! (`kern/exception.c`, `arm64/status.c`). The captured state and its
//! opaque diversifier belong to one RPC, never to the handler's reply.
use super::*;

/// A state actually sent to one exception handler and the policy under
/// which its reply may replace the thread's current state.
pub(crate) struct ExceptionState {
    flavor: u32,
    words: Vec<u32>,
    only_pc: bool,
    task_diversifier: Option<u32>,
}

/// The ARM general-state payload, respecting the set-state count rules.
fn general(flavor: u32, words: &[u32]) -> Option<&[u32]> {
    match flavor {
        ARM_THREAD_STATE64 if words.len() == THREAD_STATE64_COUNT as usize => Some(words),
        ARM_THREAD_STATE
            if words.len() >= UNIFIED_THREAD_STATE_COUNT as usize
                && words[0] == ARM_THREAD_STATE64 =>
        {
            Some(&words[2..2 + THREAD_STATE64_COUNT as usize])
        }
        _ => None,
    }
}

impl ExceptionState {
    /// The default release-kernel `pac_replace_ptrs_user` policy. A task
    /// diversifier is used only for hardened identity-protected state;
    /// other state behaviors use the random diversifier of this RPC.
    pub(crate) fn capture(
        state: &UserState,
        flavor: u32,
        signer: Option<&Context>,
        only_pc: bool,
        task_diversifier: Option<u32>,
    ) -> Result<std::result::Result<Self, u32>> {
        let mut words = match get_state(state, flavor, THREAD_STATE_MAX, signer)? {
            Ok(words) => words,
            Err(code) => return Ok(Err(code)),
        };
        if signer.is_some() && general(flavor, &words).is_some() {
            let mut diversifier = 0u32;
            while diversifier == 0 {
                // SAFETY: one word in this frame, within getentropy's bound.
                let status = unsafe {
                    libc::getentropy((&raw mut diversifier).cast(), std::mem::size_of::<u32>())
                };
                anyhow::ensure!(status == 0, "exception-state getentropy failed");
                diversifier &= USER_DIVERSIFIER_MASK;
            }
            let flags = words.len() - 1;
            // PC/LR remain kernel-signed with their ordinary discriminators.
            // Even TASK_USER_DIV exposes fresh randomness, never the task key.
            words[flags] |= diversifier;
        }
        Ok(Ok(Self {
            flavor,
            words,
            only_pc,
            task_diversifier,
        }))
    }

    pub(crate) fn words(&self) -> &[u32] {
        &self.words
    }

    /// Convert the reply against the original, already user-signed state,
    /// then set it over the thread state that exists when the RPC ends.
    pub(crate) fn apply(
        &self,
        current: &UserState,
        flavor: u32,
        words: &[u32],
        signer: Option<&Context>,
    ) -> Result<std::result::Result<UserState, u32>> {
        let Some(payload) = general(flavor, words) else {
            return set_state(current, flavor, words, signer);
        };
        if flavor != self.flavor {
            crate::hosted::unsupported::refuse!(
                crate::hosted::unsupported::Failure::Kern(KERN_INVALID_ARGUMENT),
                "an exception reply changing its general-state encoding: \
                 the captured state has a different flavor"
            );
        }
        let Some(old) = general(self.flavor, &self.words) else {
            crate::hosted::unsupported::refuse!(
                crate::hosted::unsupported::Failure::Kern(KERN_INVALID_ARGUMENT),
                "an exception reply changing a non-general ARM state to general state: \
                 no matching captured general state"
            );
        };
        let old = ThreadState64::from_words(old);
        let mut new = ThreadState64::from_words(payload);
        if self.only_pc {
            let (pc, flags) = (new.pc, new.flags);
            new = old;
            new.pc = pc;
            new.flags = flags;
        }
        if let Some(signer) = signer {
            new.flags &= !FLAGS_NO_PTRAUTH;
            if new.flags & FLAGS_IB_SIGNED_LR != 0 && signer.strip(Key::Ib, new.lr)? == new.lr {
                new.flags &= !FLAGS_IB_SIGNED_LR;
            }
            let kernel_pc = new.flags & FLAGS_KERNEL_SIGNED_PC != 0;
            let kernel_lr = new.flags & FLAGS_KERNEL_SIGNED_LR != 0;
            // TSSF_CHECK_USER_FLAGS | TSSF_ALLOW_ONLY_USER_PTRS.
            if kernel_pc && words.len() == self.words.len() {
                new.pc = old.pc;
            }
            if kernel_lr && new.flags & FLAGS_IB_SIGNED_LR == 0 && words.len() == self.words.len() {
                new.lr = old.lr;
                new.flags = new.flags & !FLAGS_IB_SIGNED_LR | old.flags & FLAGS_IB_SIGNED_LR;
            }
            let diversifier = self.task_diversifier.unwrap_or(old.flags) & USER_DIVERSIFIER_MASK;
            let modifier = |kernel_signed: bool, discriminator: u64| {
                if !kernel_signed && diversifier != 0 {
                    blend_discriminator(u64::from(diversifier), discriminator)
                } else {
                    discriminator
                }
            };
            if new.pc != 0 {
                new.pc = status::authenticate(
                    signer,
                    Key::Ia,
                    new.pc,
                    modifier(kernel_pc, DISCRIMINATOR_PC),
                )?;
            }
            if new.lr != 0 && new.flags & FLAGS_IB_SIGNED_LR == 0 {
                new.lr = status::authenticate(
                    signer,
                    Key::Ia,
                    new.lr,
                    modifier(kernel_lr, DISCRIMINATOR_LR),
                )?;
            }
            for (pointer, discriminator) in [
                (&mut new.sp, DISCRIMINATOR_SP),
                (&mut new.fp, DISCRIMINATOR_FP),
            ] {
                if *pointer != 0 {
                    *pointer = status::authenticate(signer, Key::Da, *pointer, discriminator)?;
                }
            }
        }
        let mut set = *current;
        new.into(&mut set);
        Ok(Ok(set))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> UserState {
        let mut state = UserState::default();
        for (index, word) in state.x.iter_mut().enumerate() {
            *word = 0x10_0000 + index as u64 * 16;
        }
        state.pc = 0x10_4000;
        state.sp = 0x20_8000;
        state.cpsr = 0x6000_0000;
        state.v[0] = [0x1234, 0xabcd];
        state.fpcr = 0x0300_0000;
        state
    }

    fn signer() -> Context {
        Context::new(
            0x4000,
            crate::pauth::Keys::from_words([1, 2], [3, 4], [5, 6], [7, 8]),
        )
    }

    fn payload_mut(flavor: u32, words: &mut [u32]) -> &mut [u32] {
        let offset = usize::from(flavor == ARM_THREAD_STATE) * 2;
        &mut words[offset..offset + THREAD_STATE64_COUNT as usize]
    }

    #[test]
    fn hardened_unsigned_replies_replace_only_the_captured_pc() {
        for flavor in [ARM_THREAD_STATE64, ARM_THREAD_STATE] {
            let before = state();
            let snapshot = ExceptionState::capture(&before, flavor, None, true, Some(0))
                .unwrap()
                .unwrap();
            let mut reply = snapshot.words().to_vec();
            let mut changed = ThreadState64::from_words(general(flavor, &reply).unwrap());
            changed.x.fill(!0);
            changed.pc += 4;
            changed.sp = 0;
            changed.lr = 0;
            changed.fp = 0;
            changed.cpsr = 0;
            payload_mut(flavor, &mut reply).copy_from_slice(&changed.words());
            let mut current = before;
            current.x.fill(7);
            current.v[0] = [8, 9];
            let set = snapshot
                .apply(&current, flavor, &reply, None)
                .unwrap()
                .unwrap();
            let mut expected = before;
            expected.pc += 4;
            // ONLY_PC restricts the general-state payload; unrelated
            // current NEON state is not overwritten by that payload.
            expected.v[0] = current.v[0];
            assert_eq!(set, expected);
            for count in 0..THREAD_STATE64_COUNT as usize {
                assert_eq!(
                    snapshot
                        .apply(&current, ARM_THREAD_STATE64, &reply[..count], None)
                        .unwrap(),
                    Err(KERN_INVALID_ARGUMENT)
                );
            }
        }
    }

    #[test]
    fn hardened_pc_authentication_uses_the_task_key_and_keeps_it_out_of_flags() {
        let signer = signer();
        for flavor in [ARM_THREAD_STATE64, ARM_THREAD_STATE] {
            for task_key in [0, 0xa800_0000, 0xa812_3456] {
                let before = state();
                let snapshot =
                    ExceptionState::capture(&before, flavor, Some(&signer), true, Some(task_key))
                        .unwrap()
                        .unwrap();
                let old = ThreadState64::from_words(general(flavor, snapshot.words()).unwrap());
                assert_ne!(old.flags & USER_DIVERSIFIER_MASK, 0);
                let key = task_key & USER_DIVERSIFIER_MASK;
                let modifier = if key == 0 {
                    DISCRIMINATOR_PC
                } else {
                    blend_discriminator(u64::from(key), DISCRIMINATOR_PC)
                };
                let mut changed = old;
                changed.pc = signer.sign(Key::Ia, before.pc + 4, modifier).unwrap();
                changed.flags &= !FLAGS_KERNEL_SIGNED_PC;
                changed.x.fill(99);
                changed.fp = 0;
                changed.lr = 0;
                changed.sp = 0;
                changed.cpsr = 0;
                let mut reply = snapshot.words().to_vec();
                payload_mut(flavor, &mut reply).copy_from_slice(&changed.words());
                let actual = snapshot
                    .apply(&before, flavor, &reply, Some(&signer))
                    .unwrap()
                    .unwrap();
                let mut expected = before;
                expected.pc += 4;
                assert_eq!(actual, expected);
                // A signature using a different key must not redirect PC.
                changed.pc = signer
                    .sign(Key::Ia, before.pc + 4, modifier ^ (1 << 48))
                    .unwrap();
                payload_mut(flavor, &mut reply).copy_from_slice(&changed.words());
                let failed = snapshot
                    .apply(&before, flavor, &reply, Some(&signer))
                    .unwrap()
                    .unwrap();
                assert_ne!(failed.pc, expected.pc);
                assert_eq!(signer.strip(Key::Ia, failed.pc).unwrap(), expected.pc);
            }
        }
    }

    #[test]
    fn ordinary_exception_replies_use_the_captured_random_diversifier_and_kernel_flags() {
        let signer = signer();
        let before = state();
        let snapshot =
            ExceptionState::capture(&before, ARM_THREAD_STATE64, Some(&signer), false, None)
                .unwrap()
                .unwrap();
        let mut changed = ThreadState64::from_words(snapshot.words());
        let diversifier = changed.flags & USER_DIVERSIFIER_MASK;
        // A kernel-signed pointer is preserved even if its supplied
        // contents were replaced with another valid kernel signature.
        changed.pc = signer
            .sign(Key::Ia, before.pc + 4, DISCRIMINATOR_PC)
            .unwrap();
        let unchanged = snapshot
            .apply(&before, ARM_THREAD_STATE64, &changed.words(), Some(&signer))
            .unwrap()
            .unwrap();
        assert_eq!(unchanged, before);
        // Clearing the kernel flag selects the captured user diversifier,
        // not a diversifier the untrusted reply supplied in its flags.
        changed.flags &= !FLAGS_KERNEL_SIGNED_PC;
        changed.flags ^= USER_DIVERSIFIER_MASK;
        changed.pc = signer
            .sign(
                Key::Ia,
                before.pc + 4,
                blend_discriminator(u64::from(diversifier), DISCRIMINATOR_PC),
            )
            .unwrap();
        changed.x[0] = 42;
        let set = snapshot
            .apply(&before, ARM_THREAD_STATE64, &changed.words(), Some(&signer))
            .unwrap()
            .unwrap();
        let mut expected = before;
        expected.pc += 4;
        expected.x[0] = 42;
        assert_eq!(set, expected);
    }
}
