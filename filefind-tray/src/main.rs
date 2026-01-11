//! System tray application for filefind daemon.
//!
//! This provides a minimal system tray interface for controlling the filefind daemon,
//! including start/stop controls and status display.

mod app;
mod icons;

use anyhow::{Context, Result};
use clap::Parser;
use filefind::{LogLevel, get_log_directory};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Parser)]
#[command(
    about,
    author,
    name = env!("CARGO_BIN_NAME"),
    version,
)]
pub struct TrayArgs {
    /// Run in foreground with console logging
    #[arg(short, long)]
    foreground: bool,

    /// Set the log level
    #[arg(short = 'l', long = "log", value_enum, name = "LEVEL")]
    log_level: Option<LogLevel>,

    /// Enable verbose logging (shortcut for --log debug)
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> Result<()> {
    let args = TrayArgs::parse();

    let log_level = args
        .log_level
        .unwrap_or(if args.verbose { LogLevel::Debug } else { LogLevel::Info });

    if args.foreground {
        init_logging_console(log_level.to_level_filter());
    } else {
        init_logging_file(log_level.to_level_filter())?;
    }

    if args.foreground || !has_console() {
        app::run()
    } else {
        spawn_background_tray(&args)
    }
}

/// Check if this process has a console attached.
#[cfg(windows)]
fn has_console() -> bool {
    use windows_sys::Win32::System::Console::GetConsoleWindow;
    unsafe { !GetConsoleWindow().is_null() }
}

#[cfg(not(windows))]
fn has_console() -> bool {
    std::io::IsTerminal::is_terminal(&std::io::stdin())
}

/// Spawn the tray app as a detached background process.
#[cfg(windows)]
fn spawn_background_tray(args: &TrayArgs) -> Result<()> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let exe_path = std::env::current_exe().context("Failed to get current executable path")?;

    let mut command = Command::new(&exe_path);
    if let Some(level) = args.log_level {
        command.arg("--log").arg(level.as_filter_str());
    } else if args.verbose {
        command.arg("--verbose");
    }
    command.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
    command.spawn().context("Failed to spawn background tray process")?;

    Ok(())
}

/// Spawn the tray app as a detached background process (non-Windows).
#[cfg(not(windows))]
fn spawn_background_tray(args: &TrayArgs) -> Result<()> {
    use std::process::Command;

    let exe_path = std::env::current_exe().context("Failed to get current executable path")?;

    let mut command = Command::new(&exe_path);
    if let Some(level) = args.log_level {
        command.arg("--log").arg(level.as_filter_str());
    } else if args.verbose {
        command.arg("--verbose");
    }
    command.spawn().context("Failed to spawn background tray process")?;

    Ok(())
}

/// Initialize logging to console for foreground mode.
fn init_logging_console(filter: LevelFilter) {
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_ansi(true))
        .init();
}

/// Initialize logging to a file.
///
/// Logs are written to ~/logs/filefind/filefind-tray.log with daily rotation.
fn init_logging_file(filter: LevelFilter) -> Result<()> {
    let log_dir = get_log_directory()?;
    std::fs::create_dir_all(&log_dir).context("Failed to create log directory")?;

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
