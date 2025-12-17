//! Filefind daemon - background file indexing service.
//!
//! This daemon monitors file systems and keeps the file index up to date.

mod daemon;
mod ipc_server;
mod mft;
mod scanner;
mod usn;
mod watcher;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use filefind::Config;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::writer::MakeWriterExt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Background file indexing daemon for filefind.
#[derive(Parser)]
#[command(author, version, name = env!("CARGO_BIN_NAME"), about = "Background file indexing daemon")]
struct Args {
    /// Subcommand to execute.
    #[command(subcommand)]
    command: Option<Command>,

    /// Generate shell completion.
    #[arg(long, value_name = "SHELL")]
    completion: Option<Shell>,

    /// Print verbose output.
    #[arg(short, long, global = true)]
    verbose: bool,
}

/// Daemon subcommands.
#[derive(Subcommand)]
enum Command {
    /// Start the daemon and begin indexing.
    Start {
        /// Run in foreground instead of daemonizing.
        #[arg(short, long)]
        foreground: bool,

        /// Force a full rescan of all volumes.
        #[arg(short, long)]
        rescan: bool,
    },

    /// Stop the running daemon.
    Stop,

    /// Check daemon status.
    Status,

    /// Perform a one-time scan without starting the daemon.
    Scan {
        /// Specific path to scan (defaults to all configured drives).
        #[arg(value_hint = clap::ValueHint::DirPath)]
        path: Option<PathBuf>,

        /// Force a full rescan even if already indexed.
        #[arg(short, long)]
        force: bool,
    },

    /// Show index statistics.
    Stats,

    /// List indexed volumes.
    Volumes {
        /// Show detailed information.
        #[arg(short, long)]
        detailed: bool,
    },

    /// Detect available drives and their types.
    Detect,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Handle shell completion generation.
    if let Some(shell) = args.completion {
        clap_complete::generate(
            shell,
            &mut Args::command(),
            env!("CARGO_BIN_NAME"),
            &mut std::io::stdout(),
        );
        return Ok(());
    }

    // Determine if we're running in foreground mode
    let foreground = matches!(args.command, Some(Command::Start { foreground: true, .. }) | None)
        || !matches!(args.command, Some(Command::Start { .. }));

    // Initialize logging based on mode
    init_logging(args.verbose, foreground)?;

    let config = Config::load();
    tracing::debug!("Loaded configuration");

    // Execute the requested command.
    match args.command {
        Some(Command::Start { foreground, rescan }) => daemon::start_daemon(foreground, rescan, &config),
        Some(Command::Stop) => daemon::stop_daemon(),
        Some(Command::Status) => daemon::show_status(&config),
        Some(Command::Scan { path, force }) => {
            // Use tokio runtime for async scan
            tokio::runtime::Runtime::new()?.block_on(scanner::run_scan(path, force, &config))
        }
        Some(Command::Stats) => daemon::show_stats(&config),
        Some(Command::Volumes { detailed }) => daemon::list_volumes(detailed, &config),
        Some(Command::Detect) => {
            daemon::detect_drives();
            Ok(())
        }
        None => {
            // Default: show status.
            daemon::show_status(&config)
        }
    }
}

/// Initialize logging based on verbosity and foreground mode.
///
/// In foreground mode, logs go to stdout.
/// In background mode, logs go to a file in ~/logs/filefind/.
fn init_logging(verbose: bool, foreground: bool) -> Result<()> {
    let filter = if verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("info")
    };

    if foreground {
        // Foreground mode: log to stdout
        tracing_subscriber::fmt().with_env_filter(filter).init();
    } else {
        // Background mode: log to file
        let log_dir = get_log_directory()?;
        std::fs::create_dir_all(&log_dir).context("Failed to create log directory")?;

        // Create a rolling file appender (daily rotation)
        let file_appender = RollingFileAppender::new(Rotation::DAILY, &log_dir, "filefindd.log");

        // Also log errors to stderr
        let stderr = std::io::stderr.with_max_level(tracing::Level::WARN);

        tracing_subscriber::registry()
            .with(filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(file_appender.and(stderr))
                    .with_ansi(false),
            )
            .init();

        tracing::info!("Logging to {}", log_dir.display());
    }

    Ok(())
}

/// Get the log directory path: ~/logs/filefind/
fn get_log_directory() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Could not determine home directory")?;
    Ok(home.join("logs").join(filefind::PROJECT_NAME))
}
