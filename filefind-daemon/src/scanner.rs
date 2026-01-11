//! File scanning and indexing functionality.
//!
//! This module provides functions for scanning file systems and indexing
//! files into the database. It supports multiple scanning strategies:
//! - MFT scanning for NTFS volumes (fast)
//! - Directory walking for non-NTFS volumes (fallback)
//!
//! Scans support two modes:
//! - **Normal/Incremental** (default): Scans drives and UPSERTs entries, then
//!   cleans up stale entries. For NTFS volumes, uses USN journal to efficiently
//!   identify deleted/renamed files. For non-NTFS, runs pruning after scan.
//! - **Clean/Force** (with `--force` flag): Deletes all existing entries for a
//!   volume before inserting new ones. Use when you want a complete rebuild.
//!
//! Clean scan is automatically used when the database is new or empty.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use filefind::types::{IndexedVolume, VolumeType};
use filefind::{Config, Database, FileEntry, PathType, classify_path, format_number, is_network_path};
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use tracing::{debug, error, info, warn};

use crate::mft::{MftScanner, detect_ntfs_volumes};
use crate::pruner::prune_multiple_volumes;
use crate::usn::UsnMonitor;
use crate::watcher::scan_directory;

/// Categorized paths for scanning.
struct CategorizedPaths {
    ntfs_drive_roots: Vec<char>,
    local_paths_by_drive: HashMap<char, Vec<String>>,
    mapped_network_drives: Vec<(char, PathBuf)>,
    unc_paths: Vec<PathBuf>,
}

/// Result from a scan operation.
enum ScanResult {
    /// Successful scan with volume info and entries.
    Success {
        label: String,
        volume_info: IndexedVolume,
        entries: Vec<FileEntry>,
        elapsed: std::time::Duration,
        /// Current USN for NTFS volumes (to store after scan).
        current_usn: Option<i64>,
    },
    /// Scan failed.
    Failed { label: String, error: String },
}

impl CategorizedPaths {
    /// Total number of scan tasks.
    fn task_count(&self) -> usize {
        self.ntfs_drive_roots.len()
            + self.local_paths_by_drive.len()
            + self.mapped_network_drives.len()
            + self.unc_paths.len()
    }
}

/// Run a one-time scan.
///
/// If a path is provided, scans that specific path.
/// Otherwise, scans all configured paths or auto-detects NTFS volumes.
///
/// ## Scan Modes
///
/// - **Normal mode** (default): Scans and UPSERTs entries, then cleans up stale
///   entries using USN journal (NTFS) or pruning (non-NTFS).
/// - **Clean mode** (`force_clean_scan`): Deletes all existing entries before
///   inserting. Used for complete rebuilds.
///
/// Clean scan is automatically used when the database is new or empty.
pub async fn run_scan(path: Option<PathBuf>, config: &Config) -> Result<()> {
    let database_path = config.database_path();

    // Create parent directory if needed
    if let Some(parent) = database_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut database = Database::open(&database_path)?;
    debug!("Database: {}", database_path.display());

    if let Some(ref scan_path) = path {
        // Scan a specific path provided via command line
        scan_single_path(&mut database, scan_path, config).await?;
    } else {
        // Scan all configured paths or auto-detect NTFS volumes
        scan_configured_paths(&mut database, config).await?;
    }

    Ok(())
}

/// Determine if we should do a clean scan based on config and database state.
///
/// Returns `true` if:
/// - `force_clean_scan` is set in config, or
/// - The database is empty (no files or directories)
fn should_clean_scan(database: &Database, config: &Config) -> Result<bool> {
    let stats = database.get_stats()?;
    let is_empty_db = stats.total_files == 0 && stats.total_directories == 0;
    let clean_scan = config.daemon.force_clean_scan || is_empty_db;

    if clean_scan {
        if config.daemon.force_clean_scan {
            info!("Performing clean scan");
        } else {
            info!("Performing clean scan for empty database");
        }
    } else {
        debug!("Performing incremental scan");
    }

    Ok(clean_scan)
}

/// Scan a single path, automatically detecting the appropriate scanning strategy.
///
/// # Arguments
/// * `database` - Database to store entries in
/// * `scan_path` - Path to scan
/// * `config` - Configuration settings
pub async fn scan_single_path(database: &mut Database, scan_path: &Path, config: &Config) -> Result<()> {
    let clean_scan = should_clean_scan(database, config)?;

    debug!("Scanning: {}", scan_path.display());

    if !is_path_accessible(scan_path) {
        if is_drive_letter_path(scan_path) {
            error!(
                "Path not accessible: {} (if this is a mapped network drive, try using a UNC path instead)",
                scan_path.display()
            );
        } else {
            error!("Path not accessible: {}", scan_path.display());
        }
        return Ok(());
    }

    let start_time = Instant::now();
    let path_type = classify_path(scan_path);
    debug!("Detected path type: {}", path_type);

    let exclude_patterns = &config.daemon.exclude;

    let count = match path_type {
        PathType::NtfsDriveRoot => {
            // Use MFT scanner for NTFS root drives (no filtering needed)
            let drive_letter = extract_drive_letter(scan_path).expect("NtfsDriveRoot should have a drive letter");

            debug!("Using MFT scanner for NTFS drive root");
            try_mft_with_fallback(database, drive_letter, &[], scan_path, exclude_patterns, clean_scan).await?
        }
        PathType::LocalDirectory => {
            // Use MFT scanner with path filter for local directories
            let drive_letter = extract_drive_letter(scan_path).expect("LocalDirectory should have a drive letter");

            let path_filter = scan_path.to_string_lossy().into_owned();
            debug!("Using MFT scanner with path filter: {}", path_filter);
            try_mft_with_fallback(
                database,
                drive_letter,
                &[path_filter],
                scan_path,
                exclude_patterns,
                clean_scan,
            )
            .await?
        }
        PathType::MappedNetworkDrive => {
            // Try MFT scanner for mapped network drives - some NAS devices support it
            let drive_letter = extract_drive_letter(scan_path).expect("MappedNetworkDrive should have a drive letter");

            debug!("Attempting MFT scanner for mapped network drive");
            try_mft_with_fallback(database, drive_letter, &[], scan_path, exclude_patterns, clean_scan).await?
        }
        PathType::UncPath => {
            // Use directory scanner for UNC paths (no drive letter for MFT)
            debug!("Using directory scanner for UNC path");
            scan_directory_to_db(database, scan_path, exclude_patterns, clean_scan).await?
        }
    };

    let elapsed = start_time.elapsed();
    info!(
        "Indexed {} entries in {:.2}s",
        format_number(count as u64),
        elapsed.as_secs_f64()
    );

    Ok(())
}

/// Collect paths to scan from config or auto-detect NTFS volumes.
///
/// Returns `None` if no valid paths are found.
fn collect_paths_to_scan(config: &Config) -> Option<CategorizedPaths> {
    let paths_to_scan: Vec<String> = if config.daemon.paths.is_empty() {
        // Auto-detect NTFS volumes when no paths are configured
        let ntfs_drives = detect_ntfs_volumes();

        if ntfs_drives.is_empty() {
            warn!("No NTFS volumes detected. Configure paths in the config file.");
            return None;
        }

        ntfs_drives.iter().map(|d| format!("{d}:")).collect()
    } else {
        config.daemon.paths.clone()
    };

    let categorized = categorize_paths(paths_to_scan);

    if categorized.task_count() == 0 {
        warn!("No valid paths to scan");
        return None;
    }

    Some(categorized)
}

/// Scan all configured paths, or auto-detect NTFS volumes if none are configured.
///
/// # Arguments
/// * `database` - Database to store entries in
/// * `config` - Configuration settings
pub async fn scan_configured_paths(database: &mut Database, config: &Config) -> Result<()> {
    let clean_scan = should_clean_scan(database, config)?;
    let total_start = Instant::now();

    let Some(categorized) = collect_paths_to_scan(config) else {
        return Ok(());
    };

    let total_tasks = categorized.task_count();
    if total_tasks == 1 {
        info!("Scanning 1 path...");
    } else {
        info!("Scanning {} paths...", total_tasks);
    }

    let exclude_patterns: Arc<[String]> = config.daemon.exclude.clone().into();

    // Track which volumes need pruning (non-NTFS volumes in incremental mode)
    let mut non_ntfs_volume_ids: Vec<i64> = Vec::new();

    // Build all scan tasks - each task fully handles its path
    let mut tasks: Vec<tokio::task::JoinHandle<ScanResult>> = Vec::with_capacity(total_tasks);

    // NTFS drive roots (blocking, no fallback needed)
    for drive_letter in categorized.ntfs_drive_roots {
        tasks.push(tokio::task::spawn_blocking(move || scan_ntfs_drive(drive_letter)));
    }

    // Local directories (MFT with filtering, fallback to directory walk)
    for (drive_letter, paths) in categorized.local_paths_by_drive {
        let exclude = Arc::clone(&exclude_patterns);
        tasks.push(tokio::spawn(async move {
            scan_local_directories(drive_letter, paths, exclude).await
        }));
    }

    // Mapped network drives (try MFT, fallback to directory walk)
    for (drive_letter, scan_path) in categorized.mapped_network_drives {
        let exclude = Arc::clone(&exclude_patterns);
        tasks.push(tokio::spawn(async move {
            scan_mapped_drive(drive_letter, scan_path, exclude).await
        }));
    }

    // UNC paths (directory walk only)
    for scan_path in categorized.unc_paths {
        let label = scan_path.to_string_lossy().into_owned();
        let exclude = Arc::clone(&exclude_patterns);
        tasks.push(tokio::spawn(async move {
            scan_path_directory(scan_path, label, exclude).await
        }));
    }

    // Capture the maximum file ID before processing any results.
    // This allows the pruner to skip entries that are inserted during this scan.
    let max_id_before_scan = database.get_max_file_id().unwrap_or_else(|error| {
        warn!("Failed to get max file ID, pruner will check all entries: {}", error);
        0
    });
    if max_id_before_scan > 0 {
        debug!("Max file ID before scan: {}", max_id_before_scan);
    }

    // Process results as they complete using FuturesUnordered
    let mut futures: FuturesUnordered<_> = tasks.into_iter().collect();
    let mut total_entries = 0usize;

    while let Some(result) = futures.next().await {
        match result {
            Ok(scan_result) => {
                // Track non-NTFS volumes for pruning in incremental mode
                if !clean_scan
                    && let ScanResult::Success {
                        ref volume_info,
                        current_usn: None,
                        ..
                    } = scan_result
                {
                    // No USN means non-NTFS - will need pruning
                    if let Some(existing_volume) = database.get_volume_by_serial(&volume_info.serial_number)?
                        && let Some(vol_id) = existing_volume.id
                    {
                        non_ntfs_volume_ids.push(vol_id);
                    }
                }
                total_entries += process_scan_result(database, scan_result, clean_scan)?;
            }
            Err(error) => {
                error!("Scan task panicked: {}", error);
            }
        }
    }

    // For incremental scan, prune non-NTFS volumes that don't have USN support
    // Only check entries that existed before this scan started (id <= max_id_before_scan)
    if !clean_scan && !non_ntfs_volume_ids.is_empty() {
        info!("Pruning {} non-NTFS volume(s)...", non_ntfs_volume_ids.len());
        prune_non_ntfs_volumes(
            database,
            &non_ntfs_volume_ids,
            max_id_before_scan,
            config.daemon.verbose,
        );
    }

    let total_elapsed = total_start.elapsed();

    info!(
        "Scan complete: {} entries in {:.2}s",
        format_number(total_entries as u64),
        total_elapsed.as_secs_f64()
    );

    Ok(())
}

/// Scan an NTFS volume using the MFT scanner.
pub fn scan_ntfs_volume(database: &mut Database, drive_letter: char) -> Result<usize> {
    scan_ntfs_volume_filtered(database, drive_letter, &[])
}

/// Scan an NTFS volume using the MFT scanner with path filtering.
///
/// If `path_filters` is empty, indexes the entire drive.
/// Otherwise, only indexes files under the specified paths.
pub fn scan_ntfs_volume_filtered(
    database: &mut Database,
    drive_letter: char,
    path_filters: &[String],
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

    // Get and store current USN for future incremental updates
    if let Ok(usn_monitor) = UsnMonitor::new(drive_letter, 0)
        && let Ok(journal_info) = usn_monitor.query_journal()
    {
        database.update_volume_usn(volume_id, journal_info.next_usn)?;
        debug!("Stored USN {} for volume {}", journal_info.next_usn, drive_letter);
    }

    Ok(count)
}

/// Scan a directory and insert entries into the database.
///
/// # Arguments
/// * `database` - Database to store entries in
/// * `path` - Directory path to scan
/// * `exclude_patterns` - Patterns to exclude from scanning
/// * `clean_scan` - If true, deletes existing entries before inserting new ones
pub async fn scan_directory_to_db(
    database: &mut Database,
    path: &Path,
    exclude_patterns: &[String],
    clean_scan: bool,
) -> Result<usize> {
    let volume_info = create_directory_volume_info(path);
    let volume_id = database.upsert_volume(&volume_info)?;

    // Delete existing entries for this volume if doing a clean scan
    if clean_scan {
        let deleted = database.delete_files_for_volume(volume_id)?;
        if deleted > 0 {
            debug!(
                "Deleted {} existing entries for {} before scan",
                deleted,
                path.display()
            );
        }
    }

    // Scan the directory
    let scan_entries = scan_directory(path, exclude_patterns).await?;

    // Convert to file entries
    let file_entries: Vec<_> = scan_entries
        .into_iter()
        .map(|entry| entry.into_file_entry(volume_id))
        .collect();

    let count = file_entries.len();
    database.insert_files_batch(&file_entries)?;

    Ok(count)
}

/// Extract the drive letter from a path.
///
/// Returns `None` if the path doesn't start with a drive letter.
fn extract_drive_letter(path: &Path) -> Option<char> {
    let path_str = path.to_string_lossy();
    let mut chars = path_str.chars();
    let first = chars.next()?;
    let second = chars.next()?;
    (first.is_ascii_alphabetic() && second == ':').then_some(first.to_ascii_uppercase())
}

/// Check if a path looks like a drive letter path (e.g., "X:", "X:\", "X:\Data").
fn is_drive_letter_path(path: &Path) -> bool {
    extract_drive_letter(path).is_some()
}

/// Check if a path is accessible.
///
/// This function handles the case where `Path::exists()` returns false for mapped
/// network drives when running in an elevated process. On Windows, network drive
/// mappings are per-session and per-elevation level, so an admin process won't see
/// drives mapped in the non-elevated user session.
///
/// For drive letter paths, we attempt to read the directory to verify accessibility
/// rather than relying solely on `exists()`.
fn is_path_accessible(path: &Path) -> bool {
    // First try the simple exists check
    if path.exists() {
        return true;
    }

    // For drive letter paths, try to actually access the drive
    // This can succeed even when exists() returns false for network drives
    if is_drive_letter_path(path) {
        // Normalize to root if it's just "X:" without trailing backslash
        let root_path = if path.to_string_lossy().len() == 2 {
            PathBuf::from(format!("{}\\", path.display()))
        } else {
            path.to_path_buf()
        };

        // Try to read the directory - this is more reliable than exists()
        if std::fs::read_dir(&root_path).is_ok() {
            return true;
        }
    }

    false
}

/// Create volume info for a directory-based scan.
fn create_directory_volume_info(path: &Path) -> IndexedVolume {
    let volume_type = if is_network_path(path) {
        VolumeType::Network
    } else {
        VolumeType::Local
    };
    IndexedVolume::new(
        format!("path:{}", path.display()),
        path.to_string_lossy().into_owned(),
        volume_type,
    )
}

/// Try MFT scan, falling back to directory scan on failure.
async fn try_mft_with_fallback(
    database: &mut Database,
    drive_letter: char,
    path_filters: &[String],
    scan_path: &Path,
    exclude_patterns: &[String],
    clean_scan: bool,
) -> Result<usize> {
    let mft_result = if path_filters.is_empty() {
        scan_ntfs_volume(database, drive_letter)
    } else {
        scan_ntfs_volume_filtered(database, drive_letter, path_filters)
    };

    match mft_result {
        Ok(count) => Ok(count),
        Err(err) => {
            debug!("MFT scan failed: {}, falling back to directory scan", err);
            scan_directory_to_db(database, scan_path, exclude_patterns, clean_scan).await
        }
    }
}

/// Categorize paths by type for scanning.
fn categorize_paths(paths_to_scan: Vec<String>) -> CategorizedPaths {
    let mut ntfs_drive_roots: Vec<char> = Vec::new();
    let mut local_paths_by_drive: HashMap<char, Vec<String>> = HashMap::new();
    let mut mapped_network_drives: Vec<(char, PathBuf)> = Vec::new();
    let mut unc_paths: Vec<PathBuf> = Vec::new();

    for path_str in paths_to_scan {
        let scan_path = PathBuf::from(&path_str);

        if !is_path_accessible(&scan_path) {
            if is_drive_letter_path(&scan_path) {
                warn!(
                    "Skipping inaccessible path: {} (if this is a mapped network drive, try using a UNC path instead)",
                    scan_path.display()
                );
            } else {
                warn!("Skipping inaccessible path: {}", scan_path.display());
            }
            continue;
        }

        match classify_path(&scan_path) {
            PathType::NtfsDriveRoot => {
                if let Some(drive_letter) = extract_drive_letter(&scan_path) {
                    ntfs_drive_roots.push(drive_letter);
                }
            }
            PathType::LocalDirectory => {
                if let Some(drive_letter) = extract_drive_letter(&scan_path) {
                    local_paths_by_drive.entry(drive_letter).or_default().push(path_str);
                }
            }
            PathType::MappedNetworkDrive => {
                if let Some(drive_letter) = extract_drive_letter(&scan_path) {
                    mapped_network_drives.push((drive_letter, scan_path));
                }
            }
            PathType::UncPath => {
                unc_paths.push(scan_path);
            }
        }
    }

    // Remove local paths if we're scanning the whole drive
    for drive_letter in &ntfs_drive_roots {
        local_paths_by_drive.remove(drive_letter);
    }

    CategorizedPaths {
        ntfs_drive_roots,
        local_paths_by_drive,
        mapped_network_drives,
        unc_paths,
    }
}

/// Scan a path using directory walking.
async fn scan_path_directory(scan_path: PathBuf, label: String, exclude: Arc<[String]>) -> ScanResult {
    let start = Instant::now();
    match scan_directory(&scan_path, &exclude).await {
        Ok(scan_entries) => {
            let volume_info = create_directory_volume_info(&scan_path);
            let entries: Vec<FileEntry> = scan_entries.into_iter().map(|entry| entry.into_file_entry(0)).collect();
            ScanResult::Success {
                label,
                volume_info,
                entries,
                elapsed: start.elapsed(),
                current_usn: None,
            }
        }
        Err(error) => ScanResult::Failed {
            label,
            error: error.to_string(),
        },
    }
}

/// Scan an NTFS drive root (full drive, no filtering).
fn scan_ntfs_drive(drive_letter: char) -> ScanResult {
    let label = format!("{drive_letter}:");
    let start = Instant::now();
    match scan_ntfs_volume_sync(drive_letter, &[]) {
        Ok((volume_info, entries, current_usn)) => ScanResult::Success {
            label,
            volume_info,
            entries,
            elapsed: start.elapsed(),
            current_usn,
        },
        Err(error) => ScanResult::Failed {
            label,
            error: error.to_string(),
        },
    }
}

/// Scan local directories using MFT with path filtering, fallback to directory walking.
async fn scan_local_directories(drive_letter: char, paths: Vec<String>, exclude: Arc<[String]>) -> ScanResult {
    let label = format!("{drive_letter}:");
    let start = Instant::now();

    // Try MFT scan first
    match scan_ntfs_volume_sync(drive_letter, &paths) {
        Ok((volume_info, entries, current_usn)) => ScanResult::Success {
            label,
            volume_info,
            entries,
            elapsed: start.elapsed(),
            current_usn,
        },
        Err(mft_error) => {
            // Fallback to directory walking for each path
            debug!(
                "{}: MFT scan failed ({}), falling back to directory scan",
                label, mft_error
            );

            let mut all_entries = Vec::new();
            let mut volume_info = None;

            for path_str in &paths {
                let scan_path = PathBuf::from(path_str);
                match scan_directory(&scan_path, &exclude).await {
                    Ok(scan_entries) => {
                        if volume_info.is_none() {
                            volume_info = Some(create_directory_volume_info(&scan_path));
                        }
                        all_entries.extend(scan_entries.into_iter().map(|entry| entry.into_file_entry(0)));
                    }
                    Err(error) => {
                        warn!("{}: Directory scan failed: {}", path_str, error);
                    }
                }
            }

            match volume_info {
                Some(info) => ScanResult::Success {
                    label,
                    volume_info: info,
                    entries: all_entries,
                    elapsed: start.elapsed(),
                    current_usn: None,
                },
                None => ScanResult::Failed {
                    label,
                    error: "All paths failed to scan".to_string(),
                },
            }
        }
    }
}

/// Scan a mapped network drive using MFT, fallback to directory walking.
async fn scan_mapped_drive(drive_letter: char, scan_path: PathBuf, exclude: Arc<[String]>) -> ScanResult {
    let label = scan_path.to_string_lossy().into_owned();
    let start = Instant::now();

    // Try MFT scan first
    match scan_ntfs_volume_sync(drive_letter, &[]) {
        Ok((volume_info, entries, current_usn)) => ScanResult::Success {
            label,
            volume_info,
            entries,
            elapsed: start.elapsed(),
            current_usn,
        },
        Err(mft_error) => {
            // Fallback to directory walking
            debug!(
                "{}: MFT scan failed ({}), falling back to directory scan",
                label, mft_error
            );

            match scan_directory(&scan_path, &exclude).await {
                Ok(scan_entries) => {
                    let volume_info = create_directory_volume_info(&scan_path);
                    let entries: Vec<FileEntry> =
                        scan_entries.into_iter().map(|entry| entry.into_file_entry(0)).collect();
                    ScanResult::Success {
                        label,
                        volume_info,
                        entries,
                        elapsed: start.elapsed(),
                        current_usn: None,
                    }
                }
                Err(error) => ScanResult::Failed {
                    label,
                    error: error.to_string(),
                },
            }
        }
    }
}

/// Process a single scan result and write it to the database.
///
/// # Arguments
/// * `database` - Database to store entries in
/// * `result` - Scan result to process
/// * `clean_scan` - If true, deletes existing entries before inserting new ones.
///   If false, performs incremental update with stale entry cleanup.
fn process_scan_result(database: &mut Database, result: ScanResult, clean_scan: bool) -> Result<usize> {
    match result {
        ScanResult::Success {
            label,
            volume_info,
            mut entries,
            elapsed,
            current_usn,
        } => {
            // Get the previous USN before upserting the volume (which may update it)
            let previous_usn = database.get_volume_last_usn(volume_info.mount_point.chars().next().unwrap_or('C'))?;

            let volume_id = database.upsert_volume(&volume_info)?;

            if clean_scan {
                // Clean scan: delete all existing entries first
                let deleted = database.delete_files_for_volume(volume_id)?;
                if deleted > 0 {
                    debug!("{} - Clean scan: deleted {} existing entries", label, deleted);
                }
            } else if let (Some(prev_usn), Some(_curr_usn)) = (previous_usn, current_usn) {
                // Incremental scan for NTFS: use USN journal to clean up stale entries
                let drive_letter = volume_info.mount_point.chars().next().unwrap_or('C');
                let stale_removed = cleanup_stale_entries_usn(database, volume_id, drive_letter, prev_usn)?;
                if stale_removed > 0 {
                    debug!("{} - Removed {} stale entries via USN journal", label, stale_removed);
                }
            }
            // For non-NTFS without USN, pruning will be done after all scans complete

            for entry in &mut entries {
                entry.volume_id = volume_id;
            }
            let count = entries.len();
            database.insert_files_batch(&entries)?;

            // Store the current USN for future incremental updates
            if let Some(usn) = current_usn {
                database.update_volume_usn(volume_id, usn)?;
                debug!("{} - Stored USN {} for future updates", label, usn);
            }

            info!(
                "{} - {} entries in {:.2}s",
                label,
                format_number(count as u64),
                elapsed.as_secs_f64()
            );
            Ok(count)
        }
        ScanResult::Failed { label, error } => {
            error!("{} - Failed: {}", label, error);
            Ok(0)
        }
    }
}

/// Clean up stale database entries using USN journal changes.
///
/// Reads USN changes since `last_usn` and removes entries that were deleted
/// or renamed (old name) from the database.
fn cleanup_stale_entries_usn(database: &Database, volume_id: i64, drive_letter: char, last_usn: i64) -> Result<usize> {
    // Create USN monitor starting from the last known USN
    let mut usn_monitor = match UsnMonitor::new(drive_letter, last_usn) {
        Ok(monitor) => monitor,
        Err(error) => {
            debug!(
                "Could not open USN journal for {}: - skipping USN-based cleanup: {}",
                drive_letter, error
            );
            return Ok(0);
        }
    };

    // Read changes since last scan
    let (changes, _new_usn) = usn_monitor.read_changes()?;

    if changes.is_empty() {
        return Ok(0);
    }

    // Collect MFT references for entries that were deleted or renamed (old name)
    let stale_refs: Vec<u64> = changes
        .iter()
        .filter(|change| change.is_delete() || change.is_rename_old())
        .map(|change| change.file_reference)
        .collect();

    if stale_refs.is_empty() {
        return Ok(0);
    }

    debug!(
        "{}: Found {} stale entries from USN journal ({} total changes)",
        drive_letter,
        stale_refs.len(),
        changes.len()
    );

    // Delete stale entries from database by MFT reference
    let deleted = database.delete_files_by_mft_references(volume_id, &stale_refs)?;

    Ok(deleted)
}

/// Run volume pruning for non-NTFS volumes after incremental scan.
///
/// This is called after scanning to clean up stale entries for volumes
/// that don't support USN journal. Uses parallel filesystem checks across
/// all volumes for maximum I/O throughput.
fn prune_non_ntfs_volumes(database: &Database, volume_ids_to_prune: &[i64], max_id: i64, verbose: bool) {
    if volume_ids_to_prune.is_empty() {
        return;
    }

    debug!(
        "Running parallel pruning for {} non-NTFS volume(s) (entries with id <= {})",
        volume_ids_to_prune.len(),
        max_id
    );

    match prune_multiple_volumes(database, volume_ids_to_prune, Some(max_id), verbose) {
        Ok(stats) => {
            if stats.files_removed > 0 || stats.directories_removed > 0 {
                info!(
                    "Non-NTFS volumes pruned: {} files, {} directories removed",
                    stats.files_removed, stats.directories_removed
                );
            }
        }
        Err(error) => {
            warn!("Failed to prune non-NTFS volumes: {}", error);
        }
    }
}

/// Synchronous NTFS volume scan that returns volume info, entries, and current USN.
fn scan_ntfs_volume_sync(
    drive_letter: char,
    path_filters: &[String],
) -> Result<(IndexedVolume, Vec<FileEntry>, Option<i64>)> {
    let scanner = MftScanner::new(drive_letter)?;
    let volume_info = scanner.get_volume_info()?;
    let entries = scanner.scan_filtered(path_filters)?;

    // Get current USN for future incremental updates
    let current_usn = UsnMonitor::new(drive_letter, 0)
        .ok()
        .and_then(|monitor| monitor.query_journal().ok())
        .map(|info| info.next_usn);

    Ok((volume_info, entries, current_usn))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_scan_directory_to_db() {
        let temp = tempdir().expect("Failed to create temp directory");
        let scan_dir = temp.path().join("scan_test");
        fs::create_dir(&scan_dir).expect("Failed to create scan directory");

        // Create some test files
        fs::write(scan_dir.join("file1.txt"), "content1").expect("Failed to write file1");
        fs::write(scan_dir.join("file2.txt"), "content2").expect("Failed to write file2");

        // Create a subdirectory with files
        let sub_dir = scan_dir.join("subdir");
        fs::create_dir(&sub_dir).expect("Failed to create subdirectory");
        fs::write(sub_dir.join("file3.txt"), "content3").expect("Failed to write file3");

        // Open database and scan
        let db_path = temp.path().join("test.db");
        let mut database = Database::open(&db_path).expect("Failed to open database");

        let count = scan_directory_to_db(&mut database, &scan_dir, &[], true)
            .await
            .expect("Scan failed");

        // Should have: scan_dir, file1.txt, file2.txt, subdir, file3.txt = 5 entries
        assert_eq!(
            count, 5,
            "Expected 5 entries (1 root dir + 2 files + 1 subdir + 1 file)"
        );

        // Verify we can search for the files
        let results = database.search_by_name("file1", 10).expect("Search failed");
        assert_eq!(results.len(), 1, "Should find file1.txt");
        assert_eq!(results[0].name, "file1.txt");
    }

    #[tokio::test]
    async fn test_scan_directory_to_db_with_exclusions() {
        let temp = tempdir().expect("Failed to create temp directory");
        let scan_dir = temp.path().join("scan_exclude_test");
        fs::create_dir(&scan_dir).expect("Failed to create scan directory");

        fs::write(scan_dir.join("keep.txt"), "keep").expect("Failed to write keep.txt");
        fs::write(scan_dir.join("skip.tmp"), "skip").expect("Failed to write skip.tmp");

        let db_path = temp.path().join("test.db");
        let mut database = Database::open(&db_path).expect("Failed to open database");

        let count = scan_directory_to_db(&mut database, &scan_dir, &["*.tmp".to_string()], true)
            .await
            .expect("Scan failed");

        // Should have: scan_dir + keep.txt = 2 entries (skip.tmp excluded)
        assert_eq!(count, 2, "Expected 2 entries (tmp file should be excluded)");
    }

    #[tokio::test]
    async fn test_scan_directory_to_db_empty_directory() {
        let temp = tempdir().expect("Failed to create temp directory");
        let scan_dir = temp.path().join("empty_test");
        fs::create_dir(&scan_dir).expect("Failed to create scan directory");

        let db_path = temp.path().join("test.db");
        let mut database = Database::open(&db_path).expect("Failed to open database");

        let count = scan_directory_to_db(&mut database, &scan_dir, &[], true)
            .await
            .expect("Scan failed");

        // Should have just the root directory
        assert_eq!(count, 1, "Expected 1 entry (just the root directory)");
    }

    #[tokio::test]
    async fn test_scan_directory_to_db_creates_volume() {
        let temp = tempdir().expect("Failed to create temp directory");
        let scan_dir = temp.path().join("volume_test");
        fs::create_dir(&scan_dir).expect("Failed to create scan directory");

        let db_path = temp.path().join("test.db");
        let mut database = Database::open(&db_path).expect("Failed to open database");

        scan_directory_to_db(&mut database, &scan_dir, &[], true)
            .await
            .expect("Scan failed");

        // Check that a volume was created
        let stats = database.get_stats().expect("Failed to get stats");
        assert_eq!(stats.volume_count, 1, "Should have created one volume");
    }

    #[tokio::test]
    async fn test_scan_directory_to_db_file_sizes() {
        let temp = tempdir().expect("Failed to create temp directory");
        let scan_dir = temp.path().join("size_test");
        fs::create_dir(&scan_dir).expect("Failed to create scan directory");

        // Create files with known sizes
        fs::write(scan_dir.join("small.txt"), "hello").expect("Failed to write small.txt"); // 5 bytes
        fs::write(scan_dir.join("medium.txt"), "hello world!").expect("Failed to write medium.txt"); // 12 bytes

        let db_path = temp.path().join("test.db");
        let mut database = Database::open(&db_path).expect("Failed to open database");

        scan_directory_to_db(&mut database, &scan_dir, &[], true)
            .await
            .expect("Scan failed");

        let results = database.search_by_name("small", 10).expect("Search failed");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].size, 5, "small.txt should be 5 bytes");

        let results = database.search_by_name("medium", 10).expect("Search failed");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].size, 12, "medium.txt should be 12 bytes");
    }

    #[tokio::test]
    async fn test_scan_directory_to_db_directories_have_zero_size() {
        let temp = tempdir().expect("Failed to create temp directory");
        let scan_dir = temp.path().join("dir_size_test");
        fs::create_dir(&scan_dir).expect("Failed to create scan directory");
        fs::create_dir(scan_dir.join("subdir")).expect("Failed to create subdir");

        let db_path = temp.path().join("test.db");
        let mut database = Database::open(&db_path).expect("Failed to open database");

        scan_directory_to_db(&mut database, &scan_dir, &[], true)
            .await
            .expect("Scan failed");

        let results = database.search_by_name("subdir", 10).expect("Search failed");
        assert_eq!(results.len(), 1);
        assert!(results[0].is_directory, "subdir should be a directory");
        assert_eq!(results[0].size, 0, "Directories should have size 0");
    }

    #[tokio::test]
    async fn test_scan_directory_to_db_nested_structure() {
        let temp = tempdir().expect("Failed to create temp directory");
        let scan_dir = temp.path().join("nested_test");
        fs::create_dir_all(scan_dir.join("a").join("b").join("c")).expect("Failed to create nested dirs");
        fs::write(scan_dir.join("a").join("b").join("c").join("deep.txt"), "deep").expect("Failed to write deep.txt");

        let db_path = temp.path().join("test.db");
        let mut database = Database::open(&db_path).expect("Failed to open database");

        scan_directory_to_db(&mut database, &scan_dir, &[], true)
            .await
            .expect("Scan failed");

        let results = database.search_by_name("deep", 10).expect("Search failed");
        assert_eq!(results.len(), 1);
        assert!(results[0].full_path.contains("deep.txt"));
    }

    #[test]
    fn test_is_drive_letter_path() {
        assert!(is_drive_letter_path(Path::new("C:")));
        assert!(is_drive_letter_path(Path::new("C:\\")));
        assert!(is_drive_letter_path(Path::new("D:\\Users")));
        assert!(is_drive_letter_path(Path::new("Z:\\Network\\Share")));

        assert!(!is_drive_letter_path(Path::new("\\\\server\\share")));
        assert!(!is_drive_letter_path(Path::new("/unix/path")));
        assert!(!is_drive_letter_path(Path::new("relative\\path")));
    }

    #[test]
    fn test_extract_drive_letter() {
        assert_eq!(extract_drive_letter(Path::new("C:")), Some('C'));
        assert_eq!(extract_drive_letter(Path::new("c:\\")), Some('C'));
        assert_eq!(extract_drive_letter(Path::new("D:\\Users")), Some('D'));

        assert_eq!(extract_drive_letter(Path::new("\\\\server\\share")), None);
        assert_eq!(extract_drive_letter(Path::new("/unix")), None);
    }

    #[test]
    fn test_is_path_accessible_existing_directory() {
        let temp = tempdir().expect("Failed to create temp directory");
        assert!(is_path_accessible(temp.path()));

        // Create a subdirectory and test it
        let sub_dir = temp.path().join("subdir");
        fs::create_dir(&sub_dir).expect("Failed to create subdirectory");
        assert!(is_path_accessible(&sub_dir));
    }

    #[test]
    fn test_is_path_accessible_non_existent() {
        assert!(!is_path_accessible(Path::new(
            "Z:\\NonExistent\\Path\\That\\Should\\Not\\Exist"
        )));
    }

    #[test]
    fn test_is_path_accessible_existing_file() {
        let temp = tempdir().expect("Failed to create temp directory");
        let file_path = temp.path().join("test.txt");
        fs::write(&file_path, "test").expect("Failed to write test file");

        // Files should also be accessible
        assert!(is_path_accessible(&file_path));
    }

    #[test]
    fn test_create_directory_volume_info() {
        let path = Path::new("C:\\Users\\Test");
        let volume = create_directory_volume_info(path);

        assert_eq!(volume.serial_number, "path:C:\\Users\\Test");
        assert_eq!(volume.mount_point, "C:\\Users\\Test");
    }

    #[test]
    fn test_create_directory_volume_info_network_path() {
        let path = Path::new("\\\\server\\share");
        let volume = create_directory_volume_info(path);

        assert_eq!(volume.volume_type, VolumeType::Network);
    }
}
