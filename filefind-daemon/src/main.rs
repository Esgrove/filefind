//! Filefind daemon - background file indexing service.
//!
//! This daemon monitors file systems and keeps the file index up to date.

mod daemon;
mod mft;
mod scanner;
mod usn;
mod watcher;

use std::path::PathBuf;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use filefind::Config;
use tracing_subscriber::EnvFilter;

/// Background file indexing daemon for filefind.
#[derive(Parser)]
#[command(author, version, name = "filefindd", about = "Background file indexing daemon")]
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
        let mut command = Args::command();
        clap_complete::generate(shell, &mut command, "filefindd", &mut std::io::stdout());
        return Ok(());
    }

    // Initialize logging.
    let filter = if args.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("info")
    };

    tracing_subscriber::fmt().with_env_filter(filter).init();

    // Load configuration.
    let config = Config::load();
    tracing::info!("Loaded configuration");

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
        Some(Command::Detect) => daemon::detect_drives(),
        None => {
            // Default: show status.
            daemon::show_status(&config)
        }
    }
}
