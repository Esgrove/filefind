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

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use filefind::{Config, LogLevel, format_number, get_log_directory, print_info, print_success};

/// Background file indexing daemon for filefind
#[derive(Parser)]
#[command(about, author, version, name = env!("CARGO_BIN_NAME"))]
struct Args {
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

#[derive(Subcommand)]
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

fn main() -> Result<()> {
    let args = Args::parse();

    if let Some(Command::Completion { shell, install }) = &args.command {
        return filefind::generate_shell_completion(*shell, Args::command(), *install, env!("CARGO_BIN_NAME"));
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
/// In foreground mode, logs go to stdout.
/// In background mode, logs go to a file in ~/logs/filefind/.
fn init_logging(log_level: LogLevel, foreground: bool) -> Result<()> {
    let filter = EnvFilter::new(log_level.as_filter_str());

    if foreground {
        // Foreground mode: log to stdout
        tracing_subscriber::fmt().with_env_filter(filter).init();
    } else {
        // Background mode: log to file
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
        print_info!("Database does not exist at: {}", database_path.display());
        return Ok(());
    }

    let database = filefind::Database::open(&database_path)?;

    print_info!("Pruning database entries for missing files and directories...");

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
