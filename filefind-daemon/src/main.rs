//! Filefind daemon - background file indexing service.
//!
//! This daemon monitors file systems and keeps the file index up to date.

mod mft;
mod usn;
mod watcher;

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use colored::Colorize;
use filefind_common::{Config, Database, print_error, print_info, print_success, print_warning};
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::mft::{MftScanner, detect_ntfs_volumes};
use crate::watcher::scan_directory;

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
    info!("Loaded configuration");

    // Execute the requested command.
    match args.command {
        Some(Command::Start { foreground, rescan }) => start_daemon(foreground, rescan, &config),
        Some(Command::Stop) => stop_daemon(),
        Some(Command::Status) => show_status(),
        Some(Command::Scan { path, force }) => {
            // Use tokio runtime for async scan
            tokio::runtime::Runtime::new()?.block_on(run_scan(path, force, &config))
        }
        Some(Command::Stats) => show_stats(&config),
        Some(Command::Volumes { detailed }) => list_volumes(detailed, &config),
        Some(Command::Detect) => detect_drives(),
        None => {
            // Default: show status.
            show_status()
        }
    }
}

/// Start the daemon process.
#[allow(clippy::unnecessary_wraps)]
fn start_daemon(foreground: bool, rescan: bool, _config: &Config) -> Result<()> {
    if foreground {
        print_info!("Starting daemon in foreground mode...");
    } else {
        print_info!("Starting daemon...");
    }

    if rescan {
        print_info!("Full rescan requested");
    }

    // TODO: Implement full daemon startup logic.
    // - Initialize database
    // - Detect available volumes
    // - Start MFT scanner for NTFS volumes
    // - Start USN journal monitor
    // - Start file watcher for non-NTFS volumes

    print_warning!("Full daemon mode not yet implemented. Use 'filefindd scan' for one-time indexing.");

    Ok(())
}

/// Stop the running daemon.
#[allow(clippy::unnecessary_wraps)]
fn stop_daemon() -> Result<()> {
    print_info!("Stopping daemon...");

    // TODO: Implement daemon stop logic.
    // - Send stop signal to daemon process
    // - Wait for graceful shutdown

    print_warning!("Daemon stop not yet implemented");

    Ok(())
}

/// Show daemon status.
#[allow(clippy::unnecessary_wraps)]
fn show_status() -> Result<()> {
    println!("{}", "Filefind Daemon Status".bold());
    println!();

    // TODO: Implement status check.
    // - Check if daemon process is running
    // - Show uptime, memory usage
    // - Show indexing progress if active

    print_warning!("Status check not yet implemented");

    Ok(())
}

/// Run a one-time scan.
async fn run_scan(path: Option<PathBuf>, force: bool, config: &Config) -> Result<()> {
    let database_path = config.database_path();

    // Create parent directory if needed
    if let Some(parent) = database_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut database = Database::open(&database_path)?;
    print_info!("Database: {}", database_path.display());

    if let Some(ref scan_path) = path {
        // Scan a specific path
        print_info!("Scanning: {}", scan_path.display());

        if !scan_path.exists() {
            print_error!("Path does not exist: {}", scan_path.display());
            return Ok(());
        }

        let start_time = Instant::now();

        // Check if this is an NTFS volume root (e.g., "C:\")
        let is_ntfs_root = is_ntfs_drive_root(scan_path);

        if is_ntfs_root {
            // Use MFT scanner for NTFS root
            let drive_letter = scan_path.to_string_lossy().chars().next().unwrap_or('C');

            print_info!("Detected NTFS volume, using MFT scanner...");

            match scan_ntfs_volume(&mut database, drive_letter, force) {
                Ok(count) => {
                    let elapsed = start_time.elapsed();
                    print_success!(
                        "Indexed {} entries from {}:\\ in {:.2}s",
                        format_number(count as u64),
                        drive_letter,
                        elapsed.as_secs_f64()
                    );
                }
                Err(error) => {
                    print_error!("MFT scan failed: {}", error);
                    print_info!("Falling back to directory scan...");

                    // Fall back to directory scan
                    let count = scan_directory_to_db(&mut database, scan_path, &config.daemon.exclude).await?;
                    let elapsed = start_time.elapsed();
                    print_success!(
                        "Indexed {} entries in {:.2}s",
                        format_number(count as u64),
                        elapsed.as_secs_f64()
                    );
                }
            }
        } else {
            // Use directory scanner for non-NTFS or subdirectories
            let count = scan_directory_to_db(&mut database, scan_path, &config.daemon.exclude).await?;
            let elapsed = start_time.elapsed();
            print_success!(
                "Indexed {} entries in {:.2}s",
                format_number(count as u64),
                elapsed.as_secs_f64()
            );
        }
    } else {
        // Scan all configured drives or detect automatically
        let drives_to_scan = if config.daemon.drives.is_empty() {
            // Auto-detect NTFS volumes
            print_info!("Auto-detecting NTFS volumes...");
            detect_ntfs_volumes()?
        } else {
            // Use configured drives
            config.daemon.drives.iter().filter_map(|d| d.chars().next()).collect()
        };

        if drives_to_scan.is_empty() {
            print_warning!("No drives to scan. Specify a path or configure drives in the config file.");
            return Ok(());
        }

        print_info!("Scanning drives: {:?}", drives_to_scan);

        let total_start = Instant::now();
        let mut total_entries = 0usize;

        for drive_letter in drives_to_scan {
            print_info!("Scanning {}:\\...", drive_letter);
            let drive_start = Instant::now();

            match scan_ntfs_volume(&mut database, drive_letter, force) {
                Ok(count) => {
                    let elapsed = drive_start.elapsed();
                    print_success!(
                        "  {}:\\ - {} entries in {:.2}s",
                        drive_letter,
                        format_number(count as u64),
                        elapsed.as_secs_f64()
                    );
                    total_entries += count;
                }
                Err(error) => {
                    print_error!("  {}:\\ - Failed: {}", drive_letter, error);
                }
            }
        }

        let total_elapsed = total_start.elapsed();
        println!();
        print_success!(
            "Total: {} entries indexed in {:.2}s",
            format_number(total_entries as u64),
            total_elapsed.as_secs_f64()
        );
    }

    Ok(())
}

/// Check if a path is an NTFS drive root (e.g., "C:\").
fn is_ntfs_drive_root(path: &Path) -> bool {
    let path_str = path.to_string_lossy();

    // Check if it's a drive root like "C:\" or "C:"
    if path_str.len() <= 3 {
        let chars: Vec<char> = path_str.chars().collect();
        if !chars.is_empty() && chars[0].is_ascii_alphabetic() {
            if chars.len() == 2 && chars[1] == ':' {
                return true;
            }
            if chars.len() == 3 && chars[1] == ':' && (chars[2] == '\\' || chars[2] == '/') {
                return true;
            }
        }
    }

    false
}

/// Scan an NTFS volume using the MFT scanner.
fn scan_ntfs_volume(database: &mut Database, drive_letter: char, _force: bool) -> Result<usize> {
    let scanner = MftScanner::new(drive_letter)?;

    // Get volume info
    let volume_info = scanner.get_volume_info()?;
    let volume_id = database.upsert_volume(&volume_info)?;

    // Scan the MFT
    let mut entries = scanner.scan()?;

    // Update volume_id for all entries
    for entry in &mut entries {
        entry.volume_id = volume_id;
    }

    // Insert entries into database
    let count = entries.len();
    database.insert_files_batch(&entries)?;

    Ok(count)
}

/// Scan a directory and insert entries into the database.
async fn scan_directory_to_db(database: &mut Database, path: &Path, exclude_patterns: &[String]) -> Result<usize> {
    // Create a dummy volume entry for non-NTFS paths
    let volume_info = filefind_common::types::IndexedVolume::new(
        format!("path:{}", path.display()),
        path.to_string_lossy().into_owned(),
        filefind_common::types::VolumeType::Local,
    );
    let volume_id = database.upsert_volume(&volume_info)?;

    // Scan the directory
    let scan_entries = scan_directory(path, exclude_patterns).await?;

    // Convert to file entries
    let file_entries: Vec<_> = scan_entries.iter().map(|e| e.to_file_entry(volume_id)).collect();

    let count = file_entries.len();
    database.insert_files_batch(&file_entries)?;

    Ok(count)
}

/// Detect available drives and show their types.
#[allow(clippy::unnecessary_wraps)]
fn detect_drives() -> Result<()> {
    println!("{}", "Detected Drives".bold());
    println!();

    match detect_ntfs_volumes() {
        Ok(volumes) => {
            if volumes.is_empty() {
                println!("  No NTFS volumes detected.");
            } else {
                println!("  NTFS volumes (fast MFT scanning available):");
                for letter in &volumes {
                    println!("    {letter}:\\");
                }
            }
        }
        Err(error) => {
            print_error!("Failed to detect volumes: {}", error);
        }
    }

    println!();
    print_info!("Run 'filefindd scan' to index all detected NTFS volumes.");
    print_info!("Run 'filefindd scan <path>' to scan a specific directory.");

    Ok(())
}

/// Show index statistics.
fn show_stats(config: &Config) -> Result<()> {
    let database_path = config.database_path();

    if !database_path.exists() {
        print_error!("Database not found at: {}", database_path.display());
        println!("Run 'filefindd scan' to create the index.");
        return Ok(());
    }

    let database = Database::open(&database_path)?;
    let stats = database.get_stats()?;

    println!("{}", "Index Statistics".bold());
    println!();
    println!("  Files:        {}", format_number(stats.total_files));
    println!("  Directories:  {}", format_number(stats.total_directories));
    println!("  Volumes:      {}", stats.volume_count);
    println!("  Total size:   {}", filefind_common::format_size(stats.total_size));
    println!();
    println!("  Database:     {}", database_path.display());

    // Show database file size
    if let Ok(metadata) = std::fs::metadata(&database_path) {
        println!("  DB file size: {}", filefind_common::format_size(metadata.len()));
    }

    Ok(())
}

/// List indexed volumes.
fn list_volumes(detailed: bool, config: &Config) -> Result<()> {
    let database_path = config.database_path();

    if !database_path.exists() {
        print_error!("Database not found at: {}", database_path.display());
        println!("Run 'filefindd scan' to create the index.");
        return Ok(());
    }

    let database = Database::open(&database_path)?;
    let volumes = database.get_all_volumes()?;

    if volumes.is_empty() {
        println!("No volumes indexed yet.");
        println!("Run 'filefindd scan' to index your drives.");
        return Ok(());
    }

    println!("{}", "Indexed Volumes".bold());
    println!();

    for volume in &volumes {
        let status = if volume.is_online {
            "online".green()
        } else {
            "offline".red()
        };

        println!("  {} ({}) - {}", volume.mount_point.bold(), volume.volume_type, status);

        if detailed {
            if let Some(ref label) = volume.label {
                println!("    Label: {label}");
            }
            println!("    Serial: {}", volume.serial_number);
            if let Some(last_scan) = volume.last_scan_time {
                println!("    Last scan: {last_scan:?}");
            }
            if let Some(usn) = volume.last_usn {
                println!("    Last USN: {usn}");
            }
            println!();
        }
    }

    Ok(())
}

/// Format a large number with thousands separators.
fn format_number(number: u64) -> String {
    let string = number.to_string();
    let mut result = String::new();

    for (count, character) in string.chars().rev().enumerate() {
        if count > 0 && count % 3 == 0 {
            result.insert(0, ',');
        }
        result.insert(0, character);
    }

    result
}
