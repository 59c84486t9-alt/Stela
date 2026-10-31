//! A failed maintenance update never commits the proposed nonce, or resets
//! the blessed nonce (reset is destructive, not transaction cancellation).
use anyhow::Result;

pub(super) trait Update {
    fn begin(&mut self) -> Result<()>;
    fn write_and_verify(&mut self) -> Result<()>;
    fn commit(&mut self) -> Result<()>;
}

pub(super) fn transact(update: &mut impl Update) -> Result<()> {
    update.begin()?;
    update.write_and_verify().map_err(|error| error.context("LocalPolicy was not committed; reboot maintenance before retrying to discard the outstanding proposal"))?;
    // An error here may have followed a durable SEP write. Do not roll back
    // installed files or retry/end/reset behind the caller's back.
    update.commit().map_err(|error| error.context("LocalPolicy nonce commit has an uncertain outcome; keep the installed files and inspect the next boot"))
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fake {
        fail: usize,
        calls: Vec<usize>,
    }
    impl Fake {
        fn step(&mut self, step: usize) -> Result<()> {
            self.calls.push(step);
            anyhow::ensure!(self.fail != step, "injected failure");
            Ok(())
        }
    }
    impl Update for Fake {
        fn begin(&mut self) -> Result<()> {
            self.step(1)
        }
        fn write_and_verify(&mut self) -> Result<()> {
            self.step(2)
        }
        fn commit(&mut self) -> Result<()> {
            self.step(3)
        }
    }
    #[test]
    fn failures_do_not_commit_an_unverified_policy_or_retry_an_uncertain_commit() {
        for failure in 1..=3 {
            let mut update = Fake {
                fail: failure,
                calls: vec![],
            };
            assert!(transact(&mut update).is_err());
            assert_eq!(update.calls, (1..=failure).collect::<Vec<_>>());
        }
        let mut update = Fake {
            fail: 0,
            calls: vec![],
        };
        transact(&mut update).unwrap();
        assert_eq!(update.calls, [1, 2, 3]);
    }
}
