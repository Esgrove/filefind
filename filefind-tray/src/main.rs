//! System tray application for filefind daemon.
//!
//! This provides a minimal system tray interface for controlling the filefind daemon,
//! including start/stop controls and status display.

mod app;
mod icons;

use std::process::Command;

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use filefind::{LogLevel, generate_shell_completion, get_log_directory};

#[derive(Parser)]
#[command(
    about,
    author,
    name = env!("CARGO_BIN_NAME"),
    version,
)]
/// Command-line arguments for the filefind tray application.
pub struct TrayArgs {
    /// Subcommand to run
    #[command(subcommand)]
    command: Option<TrayCommand>,

    /// Run in foreground with console logging
    #[arg(short, long)]
    foreground: bool,

    /// Set the log level
    #[arg(short = 'l', long = "log", value_enum, name = "LEVEL")]
    log_level: Option<LogLevel>,

    /// Enable verbose logging (shortcut for --log debug)
    #[arg(short, long, global = true)]
    verbose: bool,
}

/// Subcommands for the filefind tray application.
#[derive(Debug, Subcommand)]
pub enum TrayCommand {
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
    let args = TrayArgs::parse();

    if let Some(TrayCommand::Completion { shell, install }) = &args.command {
        return generate_shell_completion(
            *shell,
            TrayArgs::command(),
            *install,
            args.verbose,
            env!("CARGO_BIN_NAME"),
        );
    }

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

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    /// Helper to parse tray CLI args from a string slice.
    fn parse(args: &[&str]) -> TrayArgs {
        let mut full_args = vec!["filefind-tray"];
        full_args.extend_from_slice(args);
        TrayArgs::try_parse_from(full_args).expect("Failed to parse args")
    }

    /// Helper that expects parsing to fail.
    fn parse_err(args: &[&str]) {
        let mut full_args = vec!["filefind-tray"];
        full_args.extend_from_slice(args);
        assert!(
            TrayArgs::try_parse_from(full_args).is_err(),
            "Expected parse to fail for args: {args:?}"
        );
    }

    // ── No arguments ──────────────────────────────────────────────

    #[test]
    fn test_no_args_defaults() {
        let args = parse(&[]);
        assert!(!args.foreground);
        assert!(!args.verbose);
        assert!(args.log_level.is_none());
    }

    // ── Foreground flag ───────────────────────────────────────────

    #[test]
    fn test_foreground_short() {
        let args = parse(&["-f"]);
        assert!(args.foreground);
    }

    #[test]
    fn test_foreground_long() {
        let args = parse(&["--foreground"]);
        assert!(args.foreground);
    }

    // ── Verbose flag ──────────────────────────────────────────────

    #[test]
    fn test_verbose_short() {
        let args = parse(&["-v"]);
        assert!(args.verbose);
    }

    #[test]
    fn test_verbose_long() {
        let args = parse(&["--verbose"]);
        assert!(args.verbose);
    }

    // ── Log level ─────────────────────────────────────────────────

    #[test]
    fn test_log_level_error() {
        let args = parse(&["-l", "error"]);
        assert_eq!(args.log_level, Some(LogLevel::Error));
    }

    #[test]
    fn test_log_level_warn() {
        let args = parse(&["--log", "warn"]);
        assert_eq!(args.log_level, Some(LogLevel::Warn));
    }

    #[test]
    fn test_log_level_info() {
        let args = parse(&["-l", "info"]);
        assert_eq!(args.log_level, Some(LogLevel::Info));
    }

    #[test]
    fn test_log_level_debug() {
        let args = parse(&["-l", "debug"]);
        assert_eq!(args.log_level, Some(LogLevel::Debug));
    }

    #[test]
    fn test_log_level_trace() {
        let args = parse(&["-l", "trace"]);
        assert_eq!(args.log_level, Some(LogLevel::Trace));
    }

    #[test]
    fn test_log_level_invalid() {
        parse_err(&["-l", "invalid"]);
    }

    #[test]
    fn test_log_level_missing_value() {
        parse_err(&["-l"]);
    }

    // ── Combined flags ────────────────────────────────────────────

    #[test]
    fn test_foreground_and_verbose() {
        let args = parse(&["-f", "-v"]);
        assert!(args.foreground);
        assert!(args.verbose);
    }

    #[test]
    fn test_foreground_and_log_level() {
        let args = parse(&["-f", "-l", "debug"]);
        assert!(args.foreground);
        assert_eq!(args.log_level, Some(LogLevel::Debug));
    }

    #[test]
    fn test_verbose_and_log_level() {
        let args = parse(&["-v", "-l", "warn"]);
        assert!(args.verbose);
        assert_eq!(args.log_level, Some(LogLevel::Warn));
    }

    #[test]
    fn test_all_flags_combined() {
        let args = parse(&["-f", "-v", "-l", "trace"]);
        assert!(args.foreground);
        assert!(args.verbose);
        assert_eq!(args.log_level, Some(LogLevel::Trace));
    }

    #[test]
    fn test_all_flags_long_form() {
        let args = parse(&["--foreground", "--verbose", "--log", "error"]);
        assert!(args.foreground);
        assert!(args.verbose);
        assert_eq!(args.log_level, Some(LogLevel::Error));
    }

    // ── Flag order independence ───────────────────────────────────

    #[test]
    fn test_log_level_before_foreground() {
        let args = parse(&["-l", "info", "-f"]);
        assert!(args.foreground);
        assert_eq!(args.log_level, Some(LogLevel::Info));
    }

    #[test]
    fn test_verbose_before_foreground() {
        let args = parse(&["-v", "-f"]);
        assert!(args.foreground);
        assert!(args.verbose);
    }

    // ── Invalid arguments ─────────────────────────────────────────

    #[test]
    fn test_unknown_flag() {
        parse_err(&["--nonexistent"]);
    }

    #[test]
    fn test_unknown_subcommand() {
        parse_err(&["start"]);
    }

    #[test]
    fn test_positional_arg_rejected() {
        parse_err(&["somefile.txt"]);
    }

    // ── Log level resolution logic ────────────────────────────────

    #[test]
    fn test_log_level_default_is_info() {
        let args = parse(&[]);
        let log_level = args
            .log_level
            .unwrap_or(if args.verbose { LogLevel::Debug } else { LogLevel::Info });
        assert_eq!(log_level.to_level_filter(), LogLevel::Info.to_level_filter());
    }

    #[test]
    fn test_log_level_verbose_resolves_to_debug() {
        let args = parse(&["-v"]);
        let log_level = args
            .log_level
            .unwrap_or(if args.verbose { LogLevel::Debug } else { LogLevel::Info });
        assert_eq!(log_level.to_level_filter(), LogLevel::Debug.to_level_filter());
    }

    #[test]
    fn test_log_level_explicit_overrides_verbose() {
        let args = parse(&["-v", "-l", "error"]);
        let log_level = args
            .log_level
            .unwrap_or(if args.verbose { LogLevel::Debug } else { LogLevel::Info });
        assert_eq!(log_level.to_level_filter(), LogLevel::Error.to_level_filter());
    }

    // ── Completion subcommand ─────────────────────────────────────

    #[test]
    fn test_completion_bash() {
        let args = parse(&["completion", "bash"]);
        match args.command {
            Some(TrayCommand::Completion { shell, install }) => {
                assert!(matches!(shell, Shell::Bash));
                assert!(!install);
            }
            other => panic!("Expected Completion command, got {other:?}"),
        }
    }

    #[test]
    fn test_completion_powershell() {
        let args = parse(&["completion", "powershell"]);
        match args.command {
            Some(TrayCommand::Completion { shell, .. }) => {
                assert!(matches!(shell, Shell::PowerShell));
            }
            other => panic!("Expected Completion command, got {other:?}"),
        }
    }

    #[test]
    fn test_completion_with_install() {
        let args = parse(&["completion", "bash", "--install"]);
        match args.command {
            Some(TrayCommand::Completion { shell, install }) => {
                assert!(matches!(shell, Shell::Bash));
                assert!(install);
            }
            other => panic!("Expected Completion command, got {other:?}"),
        }
    }

    #[test]
    fn test_completion_install_short() {
        let args = parse(&["completion", "zsh", "-I"]);
        match args.command {
            Some(TrayCommand::Completion { shell, install }) => {
                assert!(matches!(shell, Shell::Zsh));
                assert!(install);
            }
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

    // ── command_factory ───────────────────────────────────────────

    #[test]
    fn test_command_factory_debug_assert() {
        TrayArgs::command().debug_assert();
    }
}
