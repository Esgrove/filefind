//! Filefind daemon - background file indexing service.
//!
//! This daemon monitors file systems and keeps the file index up to date.

mod mft;
mod usn;
mod watcher;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use colored::Colorize;
use filefind::{Config, Database, PathType, classify_path, print_error, print_info, print_success, print_warning};
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
        // Scan a specific path provided via command line
        scan_single_path(&mut database, scan_path, force, config).await?;
    } else {
        // Scan all configured paths or auto-detect NTFS volumes
        scan_configured_paths(&mut database, force, config).await?;
    }

    Ok(())
}

/// Scan a single path, automatically detecting the appropriate scanning strategy.
async fn scan_single_path(database: &mut Database, scan_path: &Path, force: bool, config: &Config) -> Result<()> {
    print_info!("Scanning: {}", scan_path.display());

    if !scan_path.exists() {
        print_error!("Path does not exist: {}", scan_path.display());
        return Ok(());
    }

    let start_time = Instant::now();
    let path_type = classify_path(scan_path);

    print_info!("Detected path type: {}", path_type);

    let count = match path_type {
        PathType::NtfsDriveRoot => {
            // Use MFT scanner for NTFS root drives (no filtering needed)
            let drive_letter = scan_path
                .to_string_lossy()
                .chars()
                .next()
                .expect("Drive path should have at least one character");

            print_info!("Using fast MFT scanner...");

            match scan_ntfs_volume(database, drive_letter, force) {
                Ok(count) => count,
                Err(error) => {
                    print_error!("MFT scan failed: {}", error);
                    print_info!("Falling back to directory scan...");
                    scan_directory_to_db(database, scan_path, &config.daemon.exclude).await?
                }
            }
        }
        PathType::LocalDirectory => {
            // Use MFT scanner with path filter for local directories
            let drive_letter = scan_path
                .to_string_lossy()
                .chars()
                .next()
                .expect("Path should have at least one character");

            let path_filter = scan_path.to_string_lossy().to_string();
            print_info!("Using fast MFT scanner with path filter...");

            match scan_ntfs_volume_filtered(database, drive_letter, &[path_filter], force) {
                Ok(count) => count,
                Err(error) => {
                    print_error!("MFT scan failed: {}", error);
                    print_info!("Falling back to directory scan...");
                    scan_directory_to_db(database, scan_path, &config.daemon.exclude).await?
                }
            }
        }
        PathType::MappedNetworkDrive => {
            // Try MFT scanner for mapped network drives - some NAS devices support it
            let drive_letter = scan_path
                .to_string_lossy()
                .chars()
                .next()
                .expect("Drive path should have at least one character");

            print_info!("Attempting MFT scanner for mapped network drive...");

            match scan_ntfs_volume(database, drive_letter, force) {
                Ok(count) => count,
                Err(error) => {
                    print_info!("MFT scan not available: {}", error);
                    print_info!("Using directory scanner...");
                    scan_directory_to_db(database, scan_path, &config.daemon.exclude).await?
                }
            }
        }
        PathType::UncPath => {
            // Use directory scanner for UNC paths (no drive letter for MFT)
            print_info!("Using directory scanner for UNC path...");
            scan_directory_to_db(database, scan_path, &config.daemon.exclude).await?
        }
    };

    let elapsed = start_time.elapsed();
    print_success!(
        "Indexed {} entries in {:.2}s",
        format_number(count as u64),
        elapsed.as_secs_f64()
    );

    Ok(())
}

/// Scan all configured paths, or auto-detect NTFS volumes if none are configured.
async fn scan_configured_paths(database: &mut Database, force: bool, config: &Config) -> Result<()> {
    let total_start = Instant::now();
    let mut total_entries = 0usize;

    if config.daemon.paths.is_empty() {
        // Auto-detect NTFS volumes when no paths are configured
        print_info!("No paths configured, auto-detecting NTFS volumes...");
        let ntfs_drives = detect_ntfs_volumes()?;

        if ntfs_drives.is_empty() {
            print_warning!("No NTFS volumes detected. Configure paths in the config file.");
            return Ok(());
        }

        print_info!("Found NTFS volumes: {:?}", ntfs_drives);

        for drive_letter in ntfs_drives {
            let count = scan_ntfs_drive(database, drive_letter, force);
            total_entries += count;
        }
    } else {
        // Group paths by type and drive letter for efficient scanning
        let mut ntfs_drive_roots: Vec<char> = Vec::new();
        let mut local_paths_by_drive: HashMap<char, Vec<String>> = HashMap::new();
        let mut mapped_network_drives: Vec<(char, PathBuf)> = Vec::new();
        let mut unc_paths: Vec<PathBuf> = Vec::new();

        for path_str in &config.daemon.paths {
            let scan_path = PathBuf::from(path_str);

            if !scan_path.exists() {
                print_warning!("Skipping non-existent path: {}", scan_path.display());
                continue;
            }

            let path_type = classify_path(&scan_path);

            match path_type {
                PathType::NtfsDriveRoot => {
                    let drive_letter = scan_path
                        .to_string_lossy()
                        .chars()
                        .next()
                        .expect("Drive path should have at least one character");
                    ntfs_drive_roots.push(drive_letter);
                }
                PathType::LocalDirectory => {
                    let drive_letter = scan_path
                        .to_string_lossy()
                        .chars()
                        .next()
                        .expect("Path should have at least one character");
                    local_paths_by_drive
                        .entry(drive_letter)
                        .or_default()
                        .push(path_str.clone());
                }
                PathType::MappedNetworkDrive => {
                    let drive_letter = scan_path
                        .to_string_lossy()
                        .chars()
                        .next()
                        .expect("Drive path should have at least one character");
                    mapped_network_drives.push((drive_letter, scan_path));
                }
                PathType::UncPath => {
                    unc_paths.push(scan_path);
                }
            }
        }

        print_info!("Scanning {} configured path(s)...", config.daemon.paths.len());

        // Scan full NTFS drives (no filtering)
        for drive_letter in ntfs_drive_roots {
            // Remove this drive from local_paths_by_drive since we're scanning the whole drive
            local_paths_by_drive.remove(&drive_letter);

            print_info!("Scanning {}:\\ (full drive)...", drive_letter);
            let count = scan_ntfs_drive(database, drive_letter, force);
            total_entries += count;
        }

        // Scan local directories grouped by drive using filtered MFT scanning
        for (drive_letter, paths) in &local_paths_by_drive {
            let path_start = Instant::now();

            print_info!(
                "Scanning {} path(s) on {}:\\ using MFT with filtering...",
                paths.len(),
                drive_letter
            );

            for path in paths {
                print_info!("  - {}", path);
            }

            match scan_ntfs_volume_filtered(database, *drive_letter, paths, force) {
                Ok(count) => {
                    let elapsed = path_start.elapsed();
                    print_success!(
                        "  {}:\\ (filtered) - {} entries in {:.2}s",
                        drive_letter,
                        format_number(count as u64),
                        elapsed.as_secs_f64()
                    );
                    total_entries += count;
                }
                Err(error) => {
                    print_error!("  MFT scan failed for {}:\\: {}", drive_letter, error);
                    print_info!("  Falling back to directory scan...");

                    // Fall back to scanning each path individually
                    for path_str in paths {
                        let scan_path = PathBuf::from(path_str);
                        match scan_directory_to_db(database, &scan_path, &config.daemon.exclude).await {
                            Ok(count) => {
                                print_success!("    {} - {} entries", path_str, format_number(count as u64));
                                total_entries += count;
                            }
                            Err(error) => {
                                print_error!("    {} - Failed: {}", path_str, error);
                            }
                        }
                    }
                }
            }
        }

        // Scan mapped network drives - try MFT first, fall back to directory walking
        for (drive_letter, scan_path) in &mapped_network_drives {
            let path_start = Instant::now();

            print_info!("Scanning {} (mapped network drive)...", scan_path.display());
            print_info!("  Attempting MFT scanner...");

            match scan_ntfs_volume(database, *drive_letter, force) {
                Ok(count) => {
                    let elapsed = path_start.elapsed();
                    print_success!(
                        "  {} - {} entries in {:.2}s (MFT)",
                        scan_path.display(),
                        format_number(count as u64),
                        elapsed.as_secs_f64()
                    );
                    total_entries += count;
                }
                Err(error) => {
                    print_info!("  MFT not available: {}", error);
                    print_info!("  Falling back to directory scanner...");

                    match scan_directory_to_db(database, scan_path, &config.daemon.exclude).await {
                        Ok(count) => {
                            let elapsed = path_start.elapsed();
                            print_success!(
                                "  {} - {} entries in {:.2}s",
                                scan_path.display(),
                                format_number(count as u64),
                                elapsed.as_secs_f64()
                            );
                            total_entries += count;
                        }
                        Err(error) => {
                            print_error!("  {} - Failed: {}", scan_path.display(), error);
                        }
                    }
                }
            }
        }

        // Scan UNC paths using directory walking (no drive letter for MFT)
        for scan_path in &unc_paths {
            let path_start = Instant::now();

            print_info!("Scanning {} (UNC path)...", scan_path.display());

            match scan_directory_to_db(database, scan_path, &config.daemon.exclude).await {
                Ok(count) => {
                    let elapsed = path_start.elapsed();
                    print_success!(
                        "  {} - {} entries in {:.2}s",
                        scan_path.display(),
                        format_number(count as u64),
                        elapsed.as_secs_f64()
                    );
                    total_entries += count;
                }
                Err(error) => {
                    print_error!("  {} - Failed: {}", scan_path.display(), error);
                }
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

    Ok(())
}

/// Scan an NTFS drive using MFT scanner, logging results.
fn scan_ntfs_drive(database: &mut Database, drive_letter: char, force: bool) -> usize {
    let drive_start = Instant::now();

    match scan_ntfs_volume(database, drive_letter, force) {
        Ok(count) => {
            let elapsed = drive_start.elapsed();
            print_success!(
                "  {}:\\ - {} entries in {:.2}s",
                drive_letter,
                format_number(count as u64),
                elapsed.as_secs_f64()
            );
            count
        }
        Err(error) => {
            print_error!("  {}:\\ - Failed: {}", drive_letter, error);
            0
        }
    }
}

/// Scan an NTFS volume using the MFT scanner.
fn scan_ntfs_volume(database: &mut Database, drive_letter: char, force: bool) -> Result<usize> {
    scan_ntfs_volume_filtered(database, drive_letter, &[], force)
}

/// Scan an NTFS volume using the MFT scanner with path filtering.
///
/// If `path_filters` is empty, indexes the entire drive.
/// Otherwise, only indexes files under the specified paths.
fn scan_ntfs_volume_filtered(
    database: &mut Database,
    drive_letter: char,
    path_filters: &[String],
    _force: bool,
) -> Result<usize> {
    let scanner = MftScanner::new(drive_letter)?;

    // Get volume info
    let volume_info = scanner.get_volume_info()?;
    let volume_id = database.upsert_volume(&volume_info)?;

    // Scan the MFT with optional path filtering
    let mut entries = scanner.scan_filtered(path_filters)?;

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
    let volume_info = filefind::types::IndexedVolume::new(
        format!("path:{}", path.display()),
        path.to_string_lossy().into_owned(),
        filefind::types::VolumeType::Local,
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
    println!("  Total size:   {}", filefind::format_size(stats.total_size));
    println!();
    println!("  Database:     {}", database_path.display());

    // Show database file size
    if let Ok(metadata) = std::fs::metadata(&database_path) {
        println!("  DB file size: {}", filefind::format_size(metadata.len()));
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
