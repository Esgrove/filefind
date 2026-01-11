//! System tray application for filefind daemon.
//!
//! This provides a minimal system tray interface for controlling the filefind daemon,
//! including start/stop controls and status display.

// Hide console window on Windows release builds
#![cfg_attr(all(target_os = "windows", not(debug_assertions)), windows_subsystem = "windows")]

mod app;
mod icons;

use anyhow::{Context, Result};
use clap::Parser;
use filefind::get_log_directory;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Parser)]
#[command(
    about,
    author,
    name = env!("CARGO_BIN_NAME"),
    version,
)]
pub struct Args {
    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging to file
    init_logging(args.verbose)?;

    tracing::info!("Starting filefind tray application");

    app::run()
}

/// Initialize logging to a file in the same directory as daemon logs.
///
/// Logs are written to ~/logs/filefind/filefind-tray.log with daily rotation.
fn init_logging(verbose: bool) -> Result<()> {
    let filter = if verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("info")
    };

    let log_dir = get_log_directory()?;
    std::fs::create_dir_all(&log_dir).context("Failed to create log directory")?;

    // Create a rolling file appender (daily rotation)
    let file_appender = RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix("filefind-tray")
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

    Ok(())
}
