//! # Oracle parity check
//!
//! Runs a live `ntpd` daemon instance in a Docker container and
//! compares its behavior against `openntpd-rs`.
//!
//! This checks:
//! - CLI flag parsing (-d, -f, -n, -s, -S, -v, -P)
//! - Config file acceptance (parse known-good and known-bad configs)
//! - NTP packet send/receive (byte-level comparison)
//! - Control socket protocol (ntpctl -s all|peers|status|sensors)

/// Run the parity check.
///
/// Optional args:
/// - `--oracle-image <name>` — Docker image for the oracle (default: `openntpd:7.9p1`)
/// - `--skip-network` — Skip NTP packet-level tests
pub fn run(args: &[String]) -> anyhow::Result<()> {
    let mut oracle_image = "openntpd:7.9p1".to_string();
    let mut skip_network = false;
    let no_tests_wired = true;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--oracle-image" => {
                i += 1;
                if i < args.len() {
                    oracle_image = args[i].clone();
                }
            }
            "--skip-network" => skip_network = true,
            other => {
                anyhow::bail!("unknown parity flag: {other}");
            }
        }
        i += 1;
    }

    eprintln!("Oracle image: {oracle_image}");
    if skip_network {
        eprintln!("Network tests: skipped");
    }

    if no_tests_wired {
        anyhow::bail!(
            "no parity tests are wired yet.  Refusing to claim success.\n\
             Implement at least one oracle comparison before removing this guard."
        );
    }

    Ok(())
}
