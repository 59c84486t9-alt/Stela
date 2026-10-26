//! Host requirements of the real Darwin process and fault-recovery adapters.
pub const AVAILABLE: bool = cfg!(all(target_os = "macos", target_arch = "x86_64"));

pub fn require(operation: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        AVAILABLE,
        "{operation} requires an Intel Mac (macOS on x86_64); this host is {} on {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    Ok(())
}

#[cfg(all(test, not(all(target_os = "macos", target_arch = "x86_64"))))]
mod tests {
    use clap::Parser;

    fn dispatch(words: &[&str]) -> anyhow::Result<()> {
        let task =
            crate::Cli::try_parse_from(std::iter::once("xtask").chain(words.iter().copied()))?.task;
        match task {
            crate::Task::Bench(task) => task.run(),
            crate::Task::Differential(task) => task.run(),
            _ => panic!("expected an execution task"),
        }
    }

    #[test]
    fn unavailable_hosted_execution_preserves_reports_and_creates_no_work() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let report = directory.path().join("evidence.json");
        std::fs::write(&report, b"existing evidence")?;
        let report_name = report.to_str().unwrap();
        let missing = directory.path().join("missing");
        let missing_name = missing.to_str().unwrap();
        for words in [
            vec!["bench"],
            vec![
                "bench",
                "hosted",
                "--work-dir",
                missing_name,
                "--report",
                report_name,
            ],
            vec!["differential", "--qemu", missing_name],
            vec![
                "differential",
                "--system-matrix",
                "--qemu",
                missing_name,
                "--report",
                report_name,
            ],
            vec![
                "differential",
                "--regions",
                "0",
                "--form",
                "XPACI_64Z_dp_1src",
                "--qemu",
                missing_name,
            ],
        ] {
            let error = dispatch(&words).unwrap_err();
            assert!(
                error.to_string().contains("requires an Intel Mac"),
                "{words:?}: {error:#}"
            );
            assert_eq!(std::fs::read(&report)?, b"existing evidence");
            assert!(!missing.exists());
        }
        assert_eq!(std::fs::read_dir(directory.path())?.count(), 1);
        Ok(())
    }

    #[test]
    fn portable_workers_and_checked_differential_reach_their_own_validation() -> anyhow::Result<()>
    {
        let directory = tempfile::tempdir()?;
        let missing = directory.path().join("missing");
        let missing_name = missing.to_str().unwrap();
        for words in [
            vec![
                "bench",
                "--worker",
                missing_name,
                "--dump-native",
                missing_name,
            ],
            vec![
                "bench",
                "--worker",
                missing_name,
                "--native-code",
                missing_name,
            ],
            vec!["differential", "--checked-memory", "--qemu", missing_name],
        ] {
            let error = dispatch(&words).unwrap_err();
            assert!(
                !error.to_string().contains("requires an Intel Mac"),
                "{words:?}: {error:#}"
            );
        }
        assert!(!missing.exists());
        Ok(())
    }
}
