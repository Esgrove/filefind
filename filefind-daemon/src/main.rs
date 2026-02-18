//! Filefind daemon - background file indexing service.
//!
//! This daemon monitors file systems and keeps the file index up to date.

mod daemon;
mod ipc_server;
mod mft;
mod pruner;
mod scanner;
mod usn;
mod watcher;

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use filefind::{Config, LogLevel, format_number, get_log_directory, print_cyan, print_success};

/// Background file indexing daemon for filefind
#[derive(Parser)]
#[command(about, author, version, name = env!("CARGO_BIN_NAME"))]
struct DaemonCli {
    /// Subcommand to execute
    #[command(subcommand)]
    command: Option<Command>,

    /// Set the log level
    #[arg(short = 'l', long = "log", value_enum, global = true)]
    log_level: Option<LogLevel>,

    /// Print verbose output
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the daemon and begin indexing
    Start {
        /// Run in foreground instead of daemonizing
        #[arg(short, long)]
        foreground: bool,

        /// Force a full rescan of all volumes
        #[arg(short, long)]
        rescan: bool,
    },

    /// Stop the running daemon
    Stop,

    /// Check daemon status
    Status,

    /// Perform a one-time scan without starting the daemon
    Scan {
        /// Specific path to scan (defaults to all configured drives)
        #[arg(value_hint = clap::ValueHint::DirPath)]
        path: Option<PathBuf>,

        /// Force a clean scan (delete existing entries before inserting new ones)
        #[arg(short, long)]
        force: bool,
    },

    /// Show index statistics
    Stats,

    /// List indexed volumes
    Volumes {
        /// Show detailed information
        #[arg(short, long)]
        detailed: bool,
    },

    /// Detect available drives and their types
    Detect,

    /// Delete the database and start fresh
    Reset {
        /// Skip confirmation prompt
        #[arg(short, long)]
        force: bool,
    },

    /// Remove database entries for files/directories that no longer exist
    Prune,

    /// Generate shell completion scripts
    Completion {
        /// Shell to generate completion for
        #[arg(value_enum)]
        shell: Shell,

        /// Install the completion script to the appropriate location
        #[arg(short = 'I', long)]
        install: bool,
    },
}

fn main() -> Result<()> {
    let args = DaemonCli::parse();

    if let Some(Command::Completion { shell, install }) = &args.command {
        return filefind::generate_shell_completion(*shell, DaemonCli::command(), *install, env!("CARGO_BIN_NAME"));
    }

    // Determine if we're running in foreground mode
    let foreground = matches!(args.command, Some(Command::Start { foreground: true, .. }) | None)
        || !matches!(args.command, Some(Command::Start { .. }));

    // Extract force flag from Scan command if present
    let force_clean_scan = match &args.command {
        Some(Command::Scan { force, .. }) => Some(*force),
        _ => None,
    };

    // Load config and apply CLI args (CLI takes precedence)
    let mut config = Config::load();
    apply_cli_args(&mut config, args.log_level, args.verbose, force_clean_scan);

    // Initialize logging based on mode
    init_logging(config.daemon.log_level, foreground)?;

    tracing::debug!("Loaded configuration");
    tracing::trace!("{config:#?}");

    match args.command {
        Some(Command::Start { foreground, rescan }) => {
            let options = daemon::DaemonOptions {
                foreground,
                rescan,
                ..Default::default()
            };
            daemon::start_daemon(&options, &config)
        }
        Some(Command::Stop) => {
            daemon::stop_daemon();
            Ok(())
        }
        Some(Command::Status) => daemon::show_status(&config),
        Some(Command::Scan { path, .. }) => tokio::runtime::Runtime::new()?.block_on(scanner::run_scan(path, &config)),
        Some(Command::Stats) => daemon::show_stats(&config),
        Some(Command::Volumes { detailed }) => daemon::list_volumes(&config.database_path(), detailed),
        Some(Command::Detect) => {
            daemon::detect_drives();
            Ok(())
        }
        Some(Command::Reset { force }) => reset_database(&config.database_path(), force),
        Some(Command::Prune) => run_prune(&config),
        Some(Command::Completion { .. }) => unreachable!("Handled above"),
        None => {
            // Default: show status.
            daemon::show_status(&config)
        }
    }
}

/// Initialize logging based on log level and foreground mode.
///
/// In foreground mode with a terminal attached, logs go to stdout.
/// In background mode, or when stdout is not a terminal (e.g. spawned as a
/// detached process by `spawn_background_daemon` or a scheduled task), logs go
/// to rolling files in `~/logs/filefind/`.
fn init_logging(log_level: LogLevel, foreground: bool) -> Result<()> {
    let filter = EnvFilter::new(log_level.as_filter_str());

    let use_stdout = foreground && std::io::stdout().is_terminal();

    if use_stdout {
        // Interactive foreground mode: log to stdout
        tracing_subscriber::fmt().with_env_filter(filter).init();
    } else {
        // Background or detached mode: log to file
        let log_dir = get_log_directory()?;
        std::fs::create_dir_all(&log_dir).context("Failed to create log directory")?;

        // Create a rolling file appender (daily rotation)
        // Use builder to get proper filename format: filefindd.2024-01-15.log
        let file_appender = RollingFileAppender::builder()
            .rotation(Rotation::DAILY)
            .filename_prefix("filefindd")
            .filename_suffix("log")
            .build(&log_dir)
            .context("Failed to create log file appender")?;

        tracing_subscriber::registry()
            .with(filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(file_appender)
                    .with_ansi(false),
            )
            .init();
    }

    Ok(())
}

/// Apply CLI arguments to the config, with CLI args taking precedence.
const fn apply_cli_args(
    config: &mut Config,
    log_level: Option<LogLevel>,
    verbose: bool,
    force_clean_scan: Option<bool>,
) {
    if let Some(level) = log_level {
        config.daemon.log_level = level;
    }
    if verbose {
        config.daemon.verbose = true;
        // Only upgrade log level if current level is less verbose than Debug
        if matches!(
            config.daemon.log_level,
            LogLevel::Error | LogLevel::Warn | LogLevel::Info
        ) {
            config.daemon.log_level = LogLevel::Debug;
        }
    }
    if let Some(force) = force_clean_scan
        && force
    {
        config.daemon.force_clean_scan = true;
    }
}

/// Delete the database file and start fresh.
fn reset_database(database_path: &Path, force: bool) -> Result<()> {
    if !database_path.exists() {
        tracing::debug!("Database does not exist at: {}", database_path.display());
        return Ok(());
    }

    if !force {
        println!("This will delete the database at: {}", database_path.display());
        print!("Are you sure? [y/N] ");
        std::io::Write::flush(&mut std::io::stdout())?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted");
            return Ok(());
        }
    }

    std::fs::remove_file(database_path).context("Failed to delete database")?;
    println!("Database deleted: {}", database_path.display());

    Ok(())
}

/// Prune database entries for files/directories that no longer exist.
fn run_prune(config: &Config) -> Result<()> {
    let database_path = config.database_path();

    if !database_path.exists() {
        print_cyan!("Database does not exist at: {}", database_path.display());
        return Ok(());
    }

    let database = filefind::Database::open(&database_path)?;

    print_cyan!("Pruning database entries for missing files and directories...");

    let stats = pruner::prune_missing_entries(&database, config.daemon.verbose)?;

    print_success!(
        "Prune complete: removed {} files and {} directories ({} entries checked, {} checks skipped)",
        format_number(stats.files_removed),
        format_number(stats.directories_removed),
        format_number(stats.entries_checked),
        format_number(stats.checks_skipped)
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    /// Helper to parse daemon CLI args from a string slice.
    fn parse(args: &[&str]) -> DaemonCli {
        let mut full_args = vec!["filefindd"];
        full_args.extend_from_slice(args);
        DaemonCli::try_parse_from(full_args).expect("Failed to parse args")
    }

    /// Helper that expects parsing to fail.
    fn parse_err(args: &[&str]) {
        let mut full_args = vec!["filefindd"];
        full_args.extend_from_slice(args);
        assert!(
            DaemonCli::try_parse_from(full_args).is_err(),
            "Expected parse to fail for args: {args:?}"
        );
    }

    // ── No arguments ──────────────────────────────────────────────

    #[test]
    fn test_no_args_defaults() {
        let cli = parse(&[]);
        assert!(cli.command.is_none());
        assert!(cli.log_level.is_none());
        assert!(!cli.verbose);
    }

    // ── Start subcommand ──────────────────────────────────────────

    #[test]
    fn test_start_defaults() {
        let cli = parse(&["start"]);
        match cli.command {
            Some(Command::Start { foreground, rescan }) => {
                assert!(!foreground);
                assert!(!rescan);
            }
            other => panic!("Expected Start command, got {other:?}"),
        }
    }

    #[test]
    fn test_start_foreground() {
        let cli = parse(&["start", "--foreground"]);
        match cli.command {
            Some(Command::Start { foreground, .. }) => assert!(foreground),
            other => panic!("Expected Start command, got {other:?}"),
        }
    }

    #[test]
    fn test_start_foreground_short() {
        let cli = parse(&["start", "-f"]);
        match cli.command {
            Some(Command::Start { foreground, .. }) => assert!(foreground),
            other => panic!("Expected Start command, got {other:?}"),
        }
    }

    #[test]
    fn test_start_rescan() {
        let cli = parse(&["start", "--rescan"]);
        match cli.command {
            Some(Command::Start { rescan, .. }) => assert!(rescan),
            other => panic!("Expected Start command, got {other:?}"),
        }
    }

    #[test]
    fn test_start_rescan_short() {
        let cli = parse(&["start", "-r"]);
        match cli.command {
            Some(Command::Start { rescan, .. }) => assert!(rescan),
            other => panic!("Expected Start command, got {other:?}"),
        }
    }

    #[test]
    fn test_start_foreground_and_rescan() {
        let cli = parse(&["start", "-f", "-r"]);
        match cli.command {
            Some(Command::Start { foreground, rescan }) => {
                assert!(foreground);
                assert!(rescan);
            }
            other => panic!("Expected Start command, got {other:?}"),
        }
    }

    // ── Stop subcommand ───────────────────────────────────────────

    #[test]
    fn test_stop() {
        let cli = parse(&["stop"]);
        assert!(matches!(cli.command, Some(Command::Stop)));
    }

    // ── Status subcommand ─────────────────────────────────────────

    #[test]
    fn test_status() {
        let cli = parse(&["status"]);
        assert!(matches!(cli.command, Some(Command::Status)));
    }

    // ── Scan subcommand ───────────────────────────────────────────

    #[test]
    fn test_scan_defaults() {
        let cli = parse(&["scan"]);
        match cli.command {
            Some(Command::Scan { path, force }) => {
                assert!(path.is_none());
                assert!(!force);
            }
            other => panic!("Expected Scan command, got {other:?}"),
        }
    }

    #[test]
    fn test_scan_with_path() {
        let cli = parse(&["scan", "C:\\Users"]);
        match cli.command {
            Some(Command::Scan { path, .. }) => {
                assert_eq!(path, Some(PathBuf::from("C:\\Users")));
            }
            other => panic!("Expected Scan command, got {other:?}"),
        }
    }

    #[test]
    fn test_scan_force() {
        let cli = parse(&["scan", "--force"]);
        match cli.command {
            Some(Command::Scan { force, .. }) => assert!(force),
            other => panic!("Expected Scan command, got {other:?}"),
        }
    }

    #[test]
    fn test_scan_force_short() {
        let cli = parse(&["scan", "-f"]);
        match cli.command {
            Some(Command::Scan { force, .. }) => assert!(force),
            other => panic!("Expected Scan command, got {other:?}"),
        }
    }

    #[test]
    fn test_scan_force_with_path() {
        let cli = parse(&["scan", "-f", "D:\\"]);
        match cli.command {
            Some(Command::Scan { path, force }) => {
                assert!(force);
                assert_eq!(path, Some(PathBuf::from("D:\\")));
            }
            other => panic!("Expected Scan command, got {other:?}"),
        }
    }

    // ── Stats subcommand ──────────────────────────────────────────

    #[test]
    fn test_stats() {
        let cli = parse(&["stats"]);
        assert!(matches!(cli.command, Some(Command::Stats)));
    }

    // ── Volumes subcommand ────────────────────────────────────────

    #[test]
    fn test_volumes_defaults() {
        let cli = parse(&["volumes"]);
        match cli.command {
            Some(Command::Volumes { detailed }) => assert!(!detailed),
            other => panic!("Expected Volumes command, got {other:?}"),
        }
    }

    #[test]
    fn test_volumes_detailed() {
        let cli = parse(&["volumes", "--detailed"]);
        match cli.command {
            Some(Command::Volumes { detailed }) => assert!(detailed),
            other => panic!("Expected Volumes command, got {other:?}"),
        }
    }

    #[test]
    fn test_volumes_detailed_short() {
        let cli = parse(&["volumes", "-d"]);
        match cli.command {
            Some(Command::Volumes { detailed }) => assert!(detailed),
            other => panic!("Expected Volumes command, got {other:?}"),
        }
    }

    // ── Detect subcommand ─────────────────────────────────────────

    #[test]
    fn test_detect() {
        let cli = parse(&["detect"]);
        assert!(matches!(cli.command, Some(Command::Detect)));
    }

    // ── Reset subcommand ──────────────────────────────────────────

    #[test]
    fn test_reset_defaults() {
        let cli = parse(&["reset"]);
        match cli.command {
            Some(Command::Reset { force }) => assert!(!force),
            other => panic!("Expected Reset command, got {other:?}"),
        }
    }

    #[test]
    fn test_reset_force() {
        let cli = parse(&["reset", "--force"]);
        match cli.command {
            Some(Command::Reset { force }) => assert!(force),
            other => panic!("Expected Reset command, got {other:?}"),
        }
    }

    #[test]
    fn test_reset_force_short() {
        let cli = parse(&["reset", "-f"]);
        match cli.command {
            Some(Command::Reset { force }) => assert!(force),
            other => panic!("Expected Reset command, got {other:?}"),
        }
    }

    // ── Prune subcommand ──────────────────────────────────────────

    #[test]
    fn test_prune() {
        let cli = parse(&["prune"]);
        assert!(matches!(cli.command, Some(Command::Prune)));
    }

    // ── Completion subcommand ─────────────────────────────────────

    #[test]
    fn test_completion_bash() {
        let cli = parse(&["completion", "bash"]);
        match cli.command {
            Some(Command::Completion { shell, install }) => {
                assert!(matches!(shell, Shell::Bash));
                assert!(!install);
            }
            other => panic!("Expected Completion command, got {other:?}"),
        }
    }

    #[test]
    fn test_completion_powershell() {
        let cli = parse(&["completion", "powershell"]);
        match cli.command {
            Some(Command::Completion { shell, .. }) => {
                assert!(matches!(shell, Shell::PowerShell));
            }
            other => panic!("Expected Completion command, got {other:?}"),
        }
    }

    #[test]
    fn test_completion_with_install() {
        let cli = parse(&["completion", "bash", "--install"]);
        match cli.command {
            Some(Command::Completion { install, .. }) => assert!(install),
            other => panic!("Expected Completion command, got {other:?}"),
        }
    }

    #[test]
    fn test_completion_install_short() {
        let cli = parse(&["completion", "bash", "-I"]);
        match cli.command {
            Some(Command::Completion { install, .. }) => assert!(install),
            other => panic!("Expected Completion command, got {other:?}"),
        }
    }

    #[test]
    fn test_completion_missing_shell_arg() {
        parse_err(&["completion"]);
    }

    #[test]
    fn test_completion_invalid_shell() {
        parse_err(&["completion", "invalid"]);
    }

    // ── Global flags ──────────────────────────────────────────────

    #[test]
    fn test_verbose_flag() {
        let cli = parse(&["-v"]);
        assert!(cli.verbose);
    }

    #[test]
    fn test_verbose_long_flag() {
        let cli = parse(&["--verbose"]);
        assert!(cli.verbose);
    }

    #[test]
    fn test_verbose_with_subcommand() {
        let cli = parse(&["-v", "start"]);
        assert!(cli.verbose);
        assert!(matches!(cli.command, Some(Command::Start { .. })));
    }

    #[test]
    fn test_verbose_after_subcommand() {
        let cli = parse(&["start", "-v"]);
        assert!(cli.verbose);
        assert!(matches!(cli.command, Some(Command::Start { .. })));
    }

    #[test]
    fn test_log_level_error() {
        let cli = parse(&["-l", "error"]);
        assert_eq!(cli.log_level, Some(LogLevel::Error));
    }

    #[test]
    fn test_log_level_warn() {
        let cli = parse(&["--log", "warn"]);
        assert_eq!(cli.log_level, Some(LogLevel::Warn));
    }

    #[test]
    fn test_log_level_info() {
        let cli = parse(&["-l", "info"]);
        assert_eq!(cli.log_level, Some(LogLevel::Info));
    }

    #[test]
    fn test_log_level_debug() {
        let cli = parse(&["-l", "debug"]);
        assert_eq!(cli.log_level, Some(LogLevel::Debug));
    }

    #[test]
    fn test_log_level_trace() {
        let cli = parse(&["-l", "trace"]);
        assert_eq!(cli.log_level, Some(LogLevel::Trace));
    }

    #[test]
    fn test_log_level_invalid() {
        parse_err(&["-l", "invalid"]);
    }

    #[test]
    fn test_log_level_with_subcommand() {
        let cli = parse(&["-l", "debug", "scan"]);
        assert_eq!(cli.log_level, Some(LogLevel::Debug));
        assert!(matches!(cli.command, Some(Command::Scan { .. })));
    }

    #[test]
    fn test_log_level_after_subcommand() {
        let cli = parse(&["scan", "-l", "trace"]);
        assert_eq!(cli.log_level, Some(LogLevel::Trace));
    }

    #[test]
    fn test_verbose_and_log_level() {
        let cli = parse(&["-v", "-l", "warn"]);
        assert!(cli.verbose);
        assert_eq!(cli.log_level, Some(LogLevel::Warn));
    }

    // ── Invalid arguments ─────────────────────────────────────────

    #[test]
    fn test_unknown_subcommand() {
        parse_err(&["unknown"]);
    }

    #[test]
    fn test_unknown_flag() {
        parse_err(&["--nonexistent"]);
    }

    // ── command_factory ───────────────────────────────────────────

    #[test]
    fn test_command_factory_debug_assert() {
        DaemonCli::command().debug_assert();
    }

    // ── apply_cli_args ────────────────────────────────────────────

    #[test]
    fn test_apply_cli_args_no_overrides_preserves_defaults() {
        let mut config = Config::default();
        let default_config = Config::default();

        apply_cli_args(&mut config, None, false, None);

        assert_eq!(
            config.daemon.log_level, default_config.daemon.log_level,
            "Log level should remain at default when no override provided"
        );
        assert_eq!(
            config.daemon.verbose, default_config.daemon.verbose,
            "Verbose should remain at default when no override provided"
        );
        assert!(
            !config.daemon.force_clean_scan,
            "Force clean scan should remain false when no override provided"
        );
        assert!(!config.daemon.verbose, "Verbose should be false by default");
    }

    #[test]
    fn test_apply_cli_args_log_level_override() {
        let mut config = Config::default();
        apply_cli_args(&mut config, Some(LogLevel::Trace), false, None);
        assert_eq!(config.daemon.log_level, LogLevel::Trace);
    }

    #[test]
    fn test_apply_cli_args_verbose_sets_debug() {
        let mut config = Config::default();
        config.daemon.log_level = LogLevel::Info;
        apply_cli_args(&mut config, None, true, None);
        assert!(config.daemon.verbose);
        assert_eq!(config.daemon.log_level, LogLevel::Debug);
    }

    #[test]
    fn test_apply_cli_args_verbose_does_not_downgrade_from_trace() {
        let mut config = Config::default();
        config.daemon.log_level = LogLevel::Trace;
        apply_cli_args(&mut config, None, true, None);
        assert!(config.daemon.verbose);
        // Trace is more verbose than Debug, so it should stay as Trace
        assert_eq!(config.daemon.log_level, LogLevel::Trace);
    }

    #[test]
    fn test_apply_cli_args_verbose_does_not_downgrade_from_debug() {
        let mut config = Config::default();
        config.daemon.log_level = LogLevel::Debug;
        apply_cli_args(&mut config, None, true, None);
        assert!(config.daemon.verbose);
        assert_eq!(config.daemon.log_level, LogLevel::Debug);
    }

    #[test]
    fn test_apply_cli_args_verbose_upgrades_from_error() {
        let mut config = Config::default();
        config.daemon.log_level = LogLevel::Error;
        apply_cli_args(&mut config, None, true, None);
        assert_eq!(config.daemon.log_level, LogLevel::Debug);
    }

    #[test]
    fn test_apply_cli_args_verbose_upgrades_from_warn() {
        let mut config = Config::default();
        config.daemon.log_level = LogLevel::Warn;
        apply_cli_args(&mut config, None, true, None);
        assert_eq!(config.daemon.log_level, LogLevel::Debug);
    }

    #[test]
    fn test_apply_cli_args_force_clean_scan_true() {
        let mut config = Config::default();
        apply_cli_args(&mut config, None, false, Some(true));
        assert!(config.daemon.force_clean_scan);
    }

    #[test]
    fn test_apply_cli_args_force_clean_scan_false_does_not_enable() {
        let mut config = Config::default();
        assert!(!config.daemon.force_clean_scan, "Default should be false");
        apply_cli_args(&mut config, None, false, Some(false));
        assert!(
            !config.daemon.force_clean_scan,
            "Passing Some(false) should not enable force_clean_scan"
        );
    }

    #[test]
    fn test_apply_cli_args_force_clean_scan_none_preserves_existing_true() {
        let mut config = Config::default();
        config.daemon.force_clean_scan = true;
        apply_cli_args(&mut config, None, false, None);
        assert!(
            config.daemon.force_clean_scan,
            "Passing None should preserve existing force_clean_scan=true"
        );
    }

    #[test]
    fn test_apply_cli_args_all_overrides() {
        let mut config = Config::default();
        apply_cli_args(&mut config, Some(LogLevel::Trace), true, Some(true));
        // Log level from explicit arg takes precedence, verbose won't downgrade
        assert_eq!(config.daemon.log_level, LogLevel::Trace);
        assert!(config.daemon.verbose);
        assert!(config.daemon.force_clean_scan);
    }

    #[test]
    fn test_apply_cli_args_log_level_then_verbose() {
        // When both log_level and verbose are set, log_level is applied first,
        // then verbose may upgrade it
        let mut config = Config::default();
        apply_cli_args(&mut config, Some(LogLevel::Warn), true, None);
        // Warn is less verbose than Debug, so verbose should upgrade to Debug
        assert_eq!(config.daemon.log_level, LogLevel::Debug);
    }

    // ── reset_database ────────────────────────────────────────────

    #[test]
    fn test_reset_database_nonexistent_path_is_noop() {
        let nonexistent = Path::new("Z:\\nonexistent\\db.sqlite");
        assert!(!nonexistent.exists(), "Path should not exist before test");
        reset_database(nonexistent, true).expect("reset_database should succeed for nonexistent path");
        assert!(
            !nonexistent.exists(),
            "Nonexistent path should still not exist after reset"
        );
    }

    #[test]
    fn test_reset_database_force_deletes_file() {
        let temp = tempfile::tempdir().expect("Failed to create temp directory");
        let db_path = temp.path().join("test.db");
        std::fs::write(&db_path, "dummy database content").expect("Failed to write file");
        assert!(db_path.exists(), "Database file should exist before reset");

        reset_database(&db_path, true).expect("reset_database with force should succeed");
        assert!(!db_path.exists(), "Database file should be deleted after forced reset");
        // Parent directory should still exist
        assert!(temp.path().exists(), "Parent directory should not be deleted");
    }

    #[test]
    fn test_reset_database_force_only_deletes_target_file() {
        let temp = tempfile::tempdir().expect("Failed to create temp directory");
        let db_path = temp.path().join("test.db");
        let other_file = temp.path().join("other.txt");
        std::fs::write(&db_path, "database").expect("Failed to write db file");
        std::fs::write(&other_file, "keep me").expect("Failed to write other file");

        reset_database(&db_path, true).expect("reset_database should succeed");
        assert!(!db_path.exists(), "Database should be deleted");
        assert!(other_file.exists(), "Other files should not be affected");
        assert_eq!(
            std::fs::read_to_string(&other_file).expect("Failed to read other file"),
            "keep me",
            "Other file content should be untouched"
        );
    }
}
