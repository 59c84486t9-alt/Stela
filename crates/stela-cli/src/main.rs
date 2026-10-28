//! The `stela` binary's entry point: runs `stela_cli::main` and returns its
//! exit code.
fn main() -> std::process::ExitCode {
    stela_cli::main()
}
