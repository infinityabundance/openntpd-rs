//! xtask entry point.
//!
//! Usage: `cargo xtask <command> [args...]`

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: cargo xtask <command>");
        eprintln!();
        eprintln!("Commands:");
        eprintln!("  gen          Generate documentation");
        eprintln!("  check        Verify generated docs are fresh");
        eprintln!("  parity       Compare against real ntpd oracle");
        eprintln!("  no-orig      Verify no original C source is present");
        eprintln!("  completions  Generate shell completions");
        return ExitCode::FAILURE;
    }

    match args[1].as_str() {
        "gen" => {
            if let Err(e) = xtask::gen::run() {
                eprintln!("gen failed: {e}");
                return ExitCode::FAILURE;
            }
        }
        "check" => {
            if let Err(e) = xtask::check::run() {
                eprintln!("check failed: {e}");
                return ExitCode::FAILURE;
            }
        }
        "parity" => {
            if let Err(e) = xtask::parity::run(&args[2..]) {
                eprintln!("parity check failed: {e}");
                return ExitCode::FAILURE;
            }
        }
        "forensic" => {
            if let Err(e) = xtask::forensic::run() {
                eprintln!("forensic audit failed: {e}");
                return ExitCode::FAILURE;
            }
        }
        "no-orig" => {
            if let Err(e) = xtask::no_orig::run() {
                eprintln!("no-orig check failed: {e}");
                return ExitCode::FAILURE;
            }
        }
        "help" | "--help" | "-h" => {
            eprintln!("Usage: cargo xtask <command>");
            eprintln!();
            eprintln!("Commands:");
            eprintln!("  gen          Generate documentation");
            eprintln!("  check        Verify generated docs are fresh");
            eprintln!("  parity       Compare against real ntpd oracle");
            eprintln!("  no-orig      Verify no original C source is present");
            eprintln!("  forensic     Generate Doxygen-based forensic parity audit");
            eprintln!("  completions  Generate shell completions");
            return ExitCode::SUCCESS;
        }
        other => {
            eprintln!("unknown command: '{other}'");
            return ExitCode::FAILURE;
        }
    }

    ExitCode::SUCCESS
}
