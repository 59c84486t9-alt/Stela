//! Four SM4 encryption or key-schedule rounds, preserving every source alias.
mod sbox;
use super::commit;
use super::sha32::{RESULT, Rotate32, Scalar32, pack_state};
use crate::{
    aarch64::simd::sm4::{Kind, Operand},
    x86_64::asm::Code,
};
const STATE: [u8; 4] = [0, 1, 2, 6];
const VALUE: u8 = 8;
const ROTATE: u8 = 9;

pub(super) fn emit(code: &mut Code, operand: &Operand, target: crate::TargetCpu) {
    let selection = false;
    #[cfg(all(
        test,
        target_arch = "x86_64",
        any(target_os = "macos", target_os = "linux")
    ))]
    let selection = FORCED_SBOX.with(|forced| forced.get()).unwrap_or(selection);
    let _ = target;
    emit_with_sbox(code, operand, selection);
}
#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
std::thread_local! { static FORCED_SBOX: core::cell::Cell<Option<bool>> = const { core::cell::Cell::new(None) }; }
#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
fn with_sbox<T>(gfni: bool, emit: impl FnOnce() -> T) -> T {
    struct Restore(Option<bool>);
    impl Drop for Restore {
        fn drop(&mut self) {
            FORCED_SBOX.with(|forced| forced.set(self.0));
        }
    }
    let old = FORCED_SBOX.with(|forced| forced.replace(Some(gfni)));
    let _restore = Restore(old);
    emit()
}
fn emit_with_sbox(code: &mut Code, operand: &Operand, gfni: bool) {
    use Scalar32::*;
    let mut state = STATE;
    for (lane, register) in state.into_iter().enumerate() {
        Move.state(code, register, operand.input, lane as u8);
    }
    // All keys are read from the original frame before the single final store,
    // so input/key/destination aliases cannot observe a partially written round.
    for lane in 0..4 {
        let [a, b, c, d] = state;
        Move.register(code, VALUE, b);
        Xor.register(code, VALUE, c);
        Xor.register(code, VALUE, d);
        Xor.state(code, VALUE, operand.keys, lane);
        sbox::emit(code, gfni);
        Move.register(code, ROTATE, VALUE);
        let rotations: &[u8] = if operand.kind == Kind::Encrypt {
            &[2, 10, 18, 24]
        } else {
            &[13, 23]
        };
        // Successive rotates reuse the original substituted value without extra
        // GPRs; their differences sum to each required absolute rotation.
        let mut previous = 0;
        for &rotation in rotations {
            Rotate32::Left.emit(code, ROTATE, rotation - previous);
            Xor.register(code, VALUE, ROTATE);
            previous = rotation;
        }
        Xor.register(code, a, VALUE);
        state = [b, c, d, a];
    }
    pack_state(code, state);
    commit(code, operand.destination, RESULT);
}
#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
mod tests;
