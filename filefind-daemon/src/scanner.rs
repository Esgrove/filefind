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
use filefind::{
    Config, Database, FileEntry, PathType, classify_path, format_number, get_persistent_drive_mapping, is_network_path,
    is_unc_path,
};
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

/// Categorize paths by type for scanning.
fn categorize_paths(paths_to_scan: Vec<String>) -> CategorizedPaths {
    let mut ntfs_drive_roots: Vec<char> = Vec::new();
    let mut local_paths_by_drive: HashMap<char, Vec<String>> = HashMap::new();
    let mut mapped_network_drives: Vec<(char, PathBuf)> = Vec::new();
    let mut unc_paths: Vec<PathBuf> = Vec::new();

    for path_str in paths_to_scan {
        let scan_path = PathBuf::from(&path_str);

        if !is_path_accessible(&scan_path) {
            log_inaccessible_scan_path(&scan_path);
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

/// Log a descriptive warning for a scan path that could not be accessed.
///
/// Distinguishes between UNC network paths, mapped network drives (including
/// offline persistent mappings), and regular local paths so the user gets an
/// actionable message instead of a generic "inaccessible" warning.
fn log_inaccessible_scan_path(path: &Path) {
    if is_unc_path(path) {
        warn!(
            "Network path is not reachable (host may be offline), skipping: {}",
            path.display()
        );
        return;
    }

    if let Some(drive_letter) = extract_drive_letter(path)
        && let Some(remote_path) = get_persistent_drive_mapping(drive_letter)
    {
        warn!(
            "Mapped network drive is offline ({}: -> {}), skipping: {}",
            drive_letter,
            remote_path,
            path.display()
        );
        return;
    }

    if is_drive_letter_path(path) {
        warn!(
            "Skipping inaccessible path: {} (if this is a mapped network drive, try using a UNC path instead)",
            path.display()
        );
    } else {
        warn!("Skipping inaccessible path: {}", path.display());
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
                "{} Scanned {} entries in {:.2}s",
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

    // ── CategorizedPaths::task_count ──────────────────────────────

    #[test]
    fn test_task_count_empty() {
        let paths = CategorizedPaths {
            ntfs_drive_roots: Vec::new(),
            local_paths_by_drive: HashMap::new(),
            mapped_network_drives: Vec::new(),
            unc_paths: Vec::new(),
        };
        assert_eq!(paths.task_count(), 0);
    }

    #[test]
    fn test_task_count_ntfs_only() {
        let paths = CategorizedPaths {
            ntfs_drive_roots: vec!['C', 'D'],
            local_paths_by_drive: HashMap::new(),
            mapped_network_drives: Vec::new(),
            unc_paths: Vec::new(),
        };
        assert_eq!(paths.task_count(), 2);
    }

    #[test]
    fn test_task_count_mixed() {
        let mut local = HashMap::new();
        local.insert('E', vec!["E:\\Data".to_string()]);
        let paths = CategorizedPaths {
            ntfs_drive_roots: vec!['C'],
            local_paths_by_drive: local,
            mapped_network_drives: vec![('Z', PathBuf::from("Z:\\"))],
            unc_paths: vec![PathBuf::from("\\\\server\\share")],
        };
        assert_eq!(paths.task_count(), 4);
    }

    #[test]
    fn test_task_count_local_paths_grouped_by_drive() {
        let mut local = HashMap::new();
        // Two paths on the same drive count as one task
        local.insert('E', vec!["E:\\Data".to_string(), "E:\\Users".to_string()]);
        local.insert('F', vec!["F:\\Backup".to_string()]);
        let paths = CategorizedPaths {
            ntfs_drive_roots: Vec::new(),
            local_paths_by_drive: local,
            mapped_network_drives: Vec::new(),
            unc_paths: Vec::new(),
        };
        assert_eq!(paths.task_count(), 2);
    }

    // ── categorize_paths ──────────────────────────────────────────

    #[test]
    fn test_categorize_paths_empty() {
        let categorized = categorize_paths(Vec::new());
        assert_eq!(categorized.task_count(), 0);
        assert!(categorized.ntfs_drive_roots.is_empty());
        assert!(categorized.local_paths_by_drive.is_empty());
        assert!(categorized.mapped_network_drives.is_empty());
        assert!(categorized.unc_paths.is_empty());
    }

    #[test]
    fn test_categorize_paths_inaccessible_skipped() {
        // Non-existent paths should be skipped entirely
        let categorized = categorize_paths(vec![
            "Z:\\NonExistent\\Path\\AbcXyz123".to_string(),
            "Y:\\Another\\Fake\\Path".to_string(),
        ]);
        assert_eq!(categorized.task_count(), 0, "Inaccessible paths should produce 0 tasks");
        assert!(
            categorized.ntfs_drive_roots.is_empty(),
            "No NTFS roots from inaccessible paths"
        );
        assert!(
            categorized.local_paths_by_drive.is_empty(),
            "No local paths from inaccessible paths"
        );
        assert!(
            categorized.mapped_network_drives.is_empty(),
            "No mapped drives from inaccessible paths"
        );
        assert!(categorized.unc_paths.is_empty(), "No UNC paths from inaccessible paths");
    }

    #[test]
    fn test_categorize_paths_unc_path_inaccessible() {
        // UNC paths that don't exist should be skipped
        let categorized = categorize_paths(vec!["\\\\nonexistent_server_xyz\\share".to_string()]);
        assert!(
            categorized.unc_paths.is_empty(),
            "Inaccessible UNC path should be skipped"
        );
        assert_eq!(categorized.task_count(), 0, "Inaccessible UNC should produce 0 tasks");
        // It should not end up in any other category either
        assert!(categorized.ntfs_drive_roots.is_empty());
        assert!(categorized.local_paths_by_drive.is_empty());
        assert!(categorized.mapped_network_drives.is_empty());
    }

    #[test]
    fn test_categorize_paths_accessible_temp_dir() {
        let temp = tempdir().expect("Failed to create temp directory");
        let temp_path = temp.path().to_string_lossy().to_string();
        let drive_letter = extract_drive_letter(temp.path());
        let categorized = categorize_paths(vec![temp_path.clone()]);
        // Temp dir has a drive letter, so it should be categorized as a local directory
        assert_eq!(
            categorized.task_count(),
            1,
            "Single accessible temp dir should produce exactly 1 task"
        );
        assert!(categorized.ntfs_drive_roots.is_empty(), "Temp dir is not a drive root");
        assert!(categorized.unc_paths.is_empty(), "Temp dir is not a UNC path");
        assert!(
            categorized.mapped_network_drives.is_empty(),
            "Temp dir is not a mapped network drive"
        );
        if let Some(letter) = drive_letter {
            let paths = categorized
                .local_paths_by_drive
                .get(&letter)
                .expect("Temp dir should be under its drive letter in local_paths_by_drive");
            assert_eq!(paths.len(), 1, "Should have exactly one path for this drive");
            assert_eq!(paths[0], temp_path, "The stored path should match the input");
        }
    }

    #[test]
    fn test_categorize_paths_drive_root_removes_local_duplicates() {
        // When we scan a full drive root, local subdirectory paths on that
        // same drive should be removed to avoid double-scanning.
        // We can only test the logic with accessible paths, so use the temp dir drive.
        let temp = tempdir().expect("Failed to create temp directory");
        let sub_path = temp.path().join("subdir");
        fs::create_dir(&sub_path).expect("Failed to create subdirectory");

        // Extract the drive letter from the temp path
        let drive_letter = extract_drive_letter(temp.path());
        if let Some(letter) = drive_letter {
            let drive_root = format!("{letter}:");
            let sub_str = sub_path.to_string_lossy().to_string();

            let categorized = categorize_paths(vec![drive_root, sub_str]);

            // The drive root is present as an NTFS root, so local paths on
            // the same drive must be removed to prevent double-scanning
            if categorized.ntfs_drive_roots.contains(&letter) {
                assert!(
                    !categorized.local_paths_by_drive.contains_key(&letter),
                    "Local paths on drive {letter}: should be removed when the full drive root is scanned"
                );
            }
            // Regardless of how the drive root was categorized, the subdirectory
            // should never appear as a separate task alongside the root
            let local_count = categorized.local_paths_by_drive.get(&letter).map_or(0, Vec::len);
            let root_present = categorized.ntfs_drive_roots.contains(&letter);
            assert!(
                !root_present || local_count == 0,
                "Drive root and local paths on the same drive should not coexist: root={root_present}, local_paths={local_count}"
            );
        }
    }

    #[test]
    fn test_categorize_paths_two_dirs_on_same_drive_grouped() {
        let temp1 = tempdir().expect("Failed to create temp directory 1");
        let temp2 = tempdir().expect("Failed to create temp directory 2");

        let drive1 = extract_drive_letter(temp1.path());
        let drive2 = extract_drive_letter(temp2.path());

        // This test is only meaningful if both temps are on the same drive
        if drive1 == drive2
            && let Some(letter) = drive1
        {
            let path1 = temp1.path().to_string_lossy().to_string();
            let path2 = temp2.path().to_string_lossy().to_string();

            let categorized = categorize_paths(vec![path1.clone(), path2.clone()]);

            // Two dirs on the same drive should be grouped into one entry
            assert_eq!(
                categorized.local_paths_by_drive.len(),
                1,
                "Two dirs on the same drive should produce one drive group"
            );
            let paths = categorized
                .local_paths_by_drive
                .get(&letter)
                .expect("Should have an entry for the drive letter");
            assert_eq!(paths.len(), 2, "Both paths should be stored under the drive");
            assert!(paths.contains(&path1), "First path should be in the group");
            assert!(paths.contains(&path2), "Second path should be in the group");
            assert_eq!(categorized.task_count(), 1, "Grouped paths count as 1 task");
        }
    }

    // ── should_clean_scan ─────────────────────────────────────────

    #[test]
    fn test_should_clean_scan_empty_db() {
        let config = Config::default();
        let db_path = tempdir()
            .expect("Failed to create temp directory")
            .path()
            .join("test.db");
        let database = Database::open(&db_path).expect("Failed to open database");

        let result = should_clean_scan(&database, &config).expect("should_clean_scan failed");
        assert!(result, "Empty database should trigger clean scan");
    }

    #[test]
    fn test_should_clean_scan_force_flag() {
        let mut config = Config::default();
        config.daemon.force_clean_scan = true;
        let database = Database::open_in_memory().expect("Failed to open in-memory database");

        let result = should_clean_scan(&database, &config).expect("should_clean_scan failed");
        assert!(result, "force_clean_scan config should trigger clean scan");
    }

    #[test]
    fn test_should_clean_scan_populated_db_no_force() {
        let config = Config::default();
        let mut database = Database::open_in_memory().expect("Failed to open in-memory database");

        // Insert some data so the database is not empty
        let volume = IndexedVolume::new("serial1".to_string(), "C:".to_string(), VolumeType::Ntfs);
        let volume_id = database.upsert_volume(&volume).expect("Failed to upsert volume");

        let file = FileEntry {
            id: None,
            volume_id,
            parent_id: None,
            name: "test.txt".to_string(),
            full_path: "C:\\test.txt".to_string(),
            is_directory: false,
            size: 100,
            created_time: None,
            modified_time: None,
            mft_reference: None,
        };
        database.insert_files_batch(&[file]).expect("Failed to insert file");

        let result = should_clean_scan(&database, &config).expect("should_clean_scan failed");
        assert!(
            !result,
            "Populated database without force flag should do incremental scan"
        );
    }

    #[test]
    fn test_should_clean_scan_populated_db_with_force() {
        let mut config = Config::default();
        config.daemon.force_clean_scan = true;
        let mut database = Database::open_in_memory().expect("Failed to open in-memory database");

        // Insert some data
        let volume = IndexedVolume::new("serial2".to_string(), "D:".to_string(), VolumeType::Ntfs);
        let volume_id = database.upsert_volume(&volume).expect("Failed to upsert volume");

        let file = FileEntry {
            id: None,
            volume_id,
            parent_id: None,
            name: "data.bin".to_string(),
            full_path: "D:\\data.bin".to_string(),
            is_directory: false,
            size: 500,
            created_time: None,
            modified_time: None,
            mft_reference: None,
        };
        database.insert_files_batch(&[file]).expect("Failed to insert file");

        let result = should_clean_scan(&database, &config).expect("should_clean_scan failed");
        assert!(
            result,
            "force_clean_scan should trigger clean scan even with populated database"
        );
    }

    #[test]
    fn test_should_clean_scan_only_directories_no_files() {
        let config = Config::default();
        let mut database = Database::open_in_memory().expect("Failed to open in-memory database");

        let volume = IndexedVolume::new("serial3".to_string(), "E:".to_string(), VolumeType::Ntfs);
        let volume_id = database.upsert_volume(&volume).expect("Failed to upsert volume");

        let dir = FileEntry {
            id: None,
            volume_id,
            parent_id: None,
            name: "folder".to_string(),
            full_path: "E:\\folder".to_string(),
            is_directory: true,
            size: 0,
            created_time: None,
            modified_time: None,
            mft_reference: None,
        };
        database.insert_files_batch(&[dir]).expect("Failed to insert directory");

        let result = should_clean_scan(&database, &config).expect("should_clean_scan failed");
        assert!(
            !result,
            "Database with directories (but no files) should do incremental scan"
        );
    }

    // ── ScanResult variants ───────────────────────────────────────

    #[test]
    fn test_scan_result_success_variant() {
        let result = ScanResult::Success {
            label: "C:".to_string(),
            volume_info: IndexedVolume::new("serial_test".to_string(), "C:".to_string(), VolumeType::Ntfs),
            entries: vec![FileEntry {
                id: None,
                volume_id: 1,
                parent_id: None,
                name: "file.txt".to_string(),
                full_path: "C:\\file.txt".to_string(),
                is_directory: false,
                size: 42,
                created_time: None,
                modified_time: None,
                mft_reference: None,
            }],
            elapsed: std::time::Duration::from_millis(100),
            current_usn: Some(12345),
        };
        match result {
            ScanResult::Success {
                label,
                entries,
                current_usn,
                ..
            } => {
                assert_eq!(label, "C:");
                assert_eq!(entries.len(), 1);
                assert_eq!(current_usn, Some(12345));
            }
            ScanResult::Failed { .. } => panic!("Expected Success variant"),
        }
    }

    #[test]
    fn test_scan_result_success_no_usn() {
        let result = ScanResult::Success {
            label: "Z:".to_string(),
            volume_info: IndexedVolume::new("net_serial".to_string(), "Z:".to_string(), VolumeType::Network),
            entries: Vec::new(),
            elapsed: std::time::Duration::from_secs(1),
            current_usn: None,
        };
        match result {
            ScanResult::Success {
                current_usn, entries, ..
            } => {
                assert!(current_usn.is_none());
                assert!(entries.is_empty());
            }
            ScanResult::Failed { .. } => panic!("Expected Success variant"),
        }
    }

    #[test]
    fn test_scan_result_failed_variant() {
        let result = ScanResult::Failed {
            label: "X:".to_string(),
            error: "Access denied".to_string(),
        };
        match result {
            ScanResult::Failed { label, error } => {
                assert_eq!(label, "X:");
                assert_eq!(error, "Access denied");
            }
            ScanResult::Success { .. } => panic!("Expected Failed variant"),
        }
    }

    // ── collect_paths_to_scan ─────────────────────────────────────

    #[test]
    fn test_collect_paths_to_scan_all_inaccessible_returns_none() {
        let mut config = Config::default();
        config.daemon.paths = vec!["Z:\\NonExistent1".to_string(), "Y:\\NonExistent2".to_string()];
        let result = collect_paths_to_scan(&config);
        assert!(
            result.is_none(),
            "All inaccessible paths should return None, got Some with {} tasks",
            result.map_or(0, |c| c.task_count())
        );
    }

    #[test]
    fn test_collect_paths_to_scan_with_accessible_temp() {
        let temp = tempdir().expect("Failed to create temp directory");
        let temp_path = temp.path().to_string_lossy().to_string();
        let mut config = Config::default();
        config.daemon.paths = vec![temp_path];
        let result = collect_paths_to_scan(&config);
        let categorized = result.expect("Accessible path should return Some(CategorizedPaths)");
        assert_eq!(
            categorized.task_count(),
            1,
            "Single accessible path should produce exactly 1 task"
        );
        // A temp dir is a local directory, not a drive root or UNC
        assert!(
            categorized.ntfs_drive_roots.is_empty(),
            "Temp dir should not be categorized as NTFS drive root"
        );
        assert!(
            categorized.unc_paths.is_empty(),
            "Temp dir should not be categorized as UNC path"
        );
        assert!(
            categorized.mapped_network_drives.is_empty(),
            "Temp dir should not be categorized as mapped network drive"
        );
        assert_eq!(
            categorized.local_paths_by_drive.len(),
            1,
            "Temp dir should be categorized as a local directory path"
        );
    }

    #[test]
    fn test_collect_paths_to_scan_mixed_accessible_and_not() {
        let temp = tempdir().expect("Failed to create temp directory");
        let temp_path = temp.path().to_string_lossy().to_string();
        let mut config = Config::default();
        config.daemon.paths = vec![temp_path, "Z:\\NonExistent\\AbcXyz123".to_string()];
        let categorized =
            collect_paths_to_scan(&config).expect("Should return Some when at least one path is accessible");
        assert_eq!(
            categorized.task_count(),
            1,
            "Only the accessible path should produce a task; inaccessible path should be skipped"
        );
    }

    #[test]
    fn test_collect_paths_to_scan_multiple_accessible_temps() {
        let temp1 = tempdir().expect("Failed to create temp directory 1");
        let temp2 = tempdir().expect("Failed to create temp directory 2");
        let drive1 = extract_drive_letter(temp1.path());
        let drive2 = extract_drive_letter(temp2.path());

        let mut config = Config::default();
        config.daemon.paths = vec![
            temp1.path().to_string_lossy().to_string(),
            temp2.path().to_string_lossy().to_string(),
        ];
        let categorized = collect_paths_to_scan(&config).expect("Two accessible paths should return Some");

        if drive1 == drive2 {
            // Same drive: both paths grouped under one drive entry = 1 task
            assert_eq!(
                categorized.task_count(),
                1,
                "Two paths on the same drive should be grouped into 1 task"
            );
            let drive = drive1.expect("Should have a drive letter");
            let paths = categorized
                .local_paths_by_drive
                .get(&drive)
                .expect("Should have entry for the drive");
            assert_eq!(paths.len(), 2, "Both paths should be listed under the same drive");
        } else {
            // Different drives: 2 tasks
            assert_eq!(
                categorized.task_count(),
                2,
                "Two paths on different drives should produce 2 tasks"
            );
        }
    }

    // ── scan_directory_to_db additional tests ─────────────────────

    #[tokio::test]
    async fn test_scan_directory_to_db_clean_vs_incremental() {
        let temp = tempdir().expect("Failed to create temp directory");
        let scan_dir = temp.path().join("clean_test");
        fs::create_dir(&scan_dir).expect("Failed to create scan directory");
        fs::write(scan_dir.join("file1.txt"), "content1").expect("Failed to write file1");

        let db_path = temp.path().join("test.db");
        let mut database = Database::open(&db_path).expect("Failed to open database");

        // First scan (clean)
        let count1 = scan_directory_to_db(&mut database, &scan_dir, &[], true)
            .await
            .expect("First scan failed");
        assert_eq!(count1, 2); // scan_dir + file1.txt

        // Add another file
        fs::write(scan_dir.join("file2.txt"), "content2").expect("Failed to write file2");

        // Second scan (incremental - should upsert)
        let count2 = scan_directory_to_db(&mut database, &scan_dir, &[], false)
            .await
            .expect("Second scan failed");
        assert_eq!(count2, 3); // scan_dir + file1.txt + file2.txt
    }

    #[tokio::test]
    async fn test_scan_directory_to_db_exclusion_pattern_glob() {
        let temp = tempdir().expect("Failed to create temp directory");
        let scan_dir = temp.path().join("exclude_glob");
        fs::create_dir(&scan_dir).expect("Failed to create scan directory");
        fs::write(scan_dir.join("keep.rs"), "fn main() {}").expect("Failed to write keep.rs");
        fs::write(scan_dir.join("skip1.log"), "log1").expect("Failed to write skip1.log");
        fs::write(scan_dir.join("skip2.log"), "log2").expect("Failed to write skip2.log");

        let db_path = temp.path().join("test.db");
        let mut database = Database::open(&db_path).expect("Failed to open database");

        let count = scan_directory_to_db(&mut database, &scan_dir, &["*.log".to_string()], true)
            .await
            .expect("Scan failed");

        // Should have: scan_dir + keep.rs = 2 (skip1.log and skip2.log excluded)
        assert_eq!(count, 2, "Expected 2 entries (dir + keep.rs), log files excluded");
    }

    // ── process_scan_result ───────────────────────────────────────

    #[test]
    fn test_process_scan_result_failed_returns_zero() {
        let mut database = Database::open_in_memory().expect("Failed to open in-memory database");
        let result = ScanResult::Failed {
            label: "X:".to_string(),
            error: "Drive not found".to_string(),
        };
        let count = process_scan_result(&mut database, result, false).expect("process_scan_result failed");
        assert_eq!(count, 0, "Failed scan result should return 0 entries");
    }

    #[test]
    fn test_process_scan_result_success_inserts_entries() {
        let mut database = Database::open_in_memory().expect("Failed to open in-memory database");
        let volume_info = IndexedVolume::new("serial_proc".to_string(), "C:".to_string(), VolumeType::Local);
        let entries = vec![
            FileEntry {
                id: None,
                volume_id: 0,
                parent_id: None,
                name: "hello.txt".to_string(),
                full_path: "C:\\hello.txt".to_string(),
                is_directory: false,
                size: 10,
                created_time: None,
                modified_time: None,
                mft_reference: None,
            },
            FileEntry {
                id: None,
                volume_id: 0,
                parent_id: None,
                name: "world.txt".to_string(),
                full_path: "C:\\world.txt".to_string(),
                is_directory: false,
                size: 20,
                created_time: None,
                modified_time: None,
                mft_reference: None,
            },
        ];
        let result = ScanResult::Success {
            label: "C:".to_string(),
            volume_info,
            entries,
            elapsed: std::time::Duration::from_millis(50),
            current_usn: None,
        };
        let count = process_scan_result(&mut database, result, false).expect("process_scan_result failed");
        assert_eq!(count, 2, "Should insert 2 entries");

        let found = database.search_by_name("hello", 10).expect("Search failed");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "hello.txt");
    }

    #[test]
    fn test_process_scan_result_clean_scan_deletes_existing() {
        let mut database = Database::open_in_memory().expect("Failed to open in-memory database");

        // First, insert some entries under a volume
        let volume = IndexedVolume::new("serial_clean".to_string(), "D:".to_string(), VolumeType::Local);
        let volume_id = database.upsert_volume(&volume).expect("Failed to upsert volume");
        let old_file = FileEntry {
            id: None,
            volume_id,
            parent_id: None,
            name: "old_file.txt".to_string(),
            full_path: "D:\\old_file.txt".to_string(),
            is_directory: false,
            size: 100,
            created_time: None,
            modified_time: None,
            mft_reference: None,
        };
        database
            .insert_files_batch(&[old_file])
            .expect("Failed to insert old file");

        // Verify old file exists
        let found = database.search_by_name("old_file", 10).expect("Search failed");
        assert_eq!(found.len(), 1, "Old file should exist before clean scan");

        // Now process a clean scan result with new entries only
        let volume_info = IndexedVolume::new("serial_clean".to_string(), "D:".to_string(), VolumeType::Local);
        let new_entries = vec![FileEntry {
            id: None,
            volume_id: 0,
            parent_id: None,
            name: "new_file.txt".to_string(),
            full_path: "D:\\new_file.txt".to_string(),
            is_directory: false,
            size: 200,
            created_time: None,
            modified_time: None,
            mft_reference: None,
        }];
        let result = ScanResult::Success {
            label: "D:".to_string(),
            volume_info,
            entries: new_entries,
            elapsed: std::time::Duration::from_millis(30),
            current_usn: None,
        };
        let count = process_scan_result(&mut database, result, true).expect("process_scan_result failed");
        assert_eq!(count, 1, "Should insert 1 new entry");

        // Old file should be gone after clean scan
        let found_old = database.search_by_name("old_file", 10).expect("Search failed");
        assert!(found_old.is_empty(), "Old file should be deleted by clean scan");

        // New file should exist
        let found_new = database.search_by_name("new_file", 10).expect("Search failed");
        assert_eq!(found_new.len(), 1, "New file should be present after clean scan");
    }

    #[test]
    fn test_process_scan_result_incremental_no_usn_no_cleanup() {
        let mut database = Database::open_in_memory().expect("Failed to open in-memory database");

        // Insert an existing entry
        let volume = IndexedVolume::new("serial_inc".to_string(), "E:".to_string(), VolumeType::Local);
        let volume_id = database.upsert_volume(&volume).expect("Failed to upsert volume");
        let existing = FileEntry {
            id: None,
            volume_id,
            parent_id: None,
            name: "existing.txt".to_string(),
            full_path: "E:\\existing.txt".to_string(),
            is_directory: false,
            size: 50,
            created_time: None,
            modified_time: None,
            mft_reference: None,
        };
        database
            .insert_files_batch(&[existing])
            .expect("Failed to insert existing file");

        // Process incremental scan (no USN = no USN-based cleanup)
        let volume_info = IndexedVolume::new("serial_inc".to_string(), "E:".to_string(), VolumeType::Local);
        let new_entries = vec![FileEntry {
            id: None,
            volume_id: 0,
            parent_id: None,
            name: "added.txt".to_string(),
            full_path: "E:\\added.txt".to_string(),
            is_directory: false,
            size: 75,
            created_time: None,
            modified_time: None,
            mft_reference: None,
        }];
        let result = ScanResult::Success {
            label: "E:".to_string(),
            volume_info,
            entries: new_entries,
            elapsed: std::time::Duration::from_millis(25),
            current_usn: None,
        };
        let count = process_scan_result(&mut database, result, false).expect("process_scan_result failed");
        assert_eq!(count, 1, "Should insert 1 new entry");

        // Both old and new files should exist (incremental, no cleanup)
        let found_existing = database.search_by_name("existing", 10).expect("Search failed");
        assert_eq!(
            found_existing.len(),
            1,
            "Existing file should remain in incremental mode"
        );

        let found_added = database.search_by_name("added", 10).expect("Search failed");
        assert_eq!(found_added.len(), 1, "New file should be added");
    }

    #[test]
    fn test_process_scan_result_creates_volume() {
        let mut database = Database::open_in_memory().expect("Failed to open in-memory database");

        let volume_info = IndexedVolume::new("new_vol_serial".to_string(), "F:".to_string(), VolumeType::Ntfs);
        let result = ScanResult::Success {
            label: "F:".to_string(),
            volume_info,
            entries: Vec::new(),
            elapsed: std::time::Duration::from_millis(5),
            current_usn: None,
        };
        process_scan_result(&mut database, result, false).expect("process_scan_result failed");

        let stats = database.get_stats().expect("Failed to get stats");
        assert_eq!(stats.volume_count, 1, "Volume should be created by process_scan_result");
    }

    #[test]
    fn test_process_scan_result_stores_usn() {
        let mut database = Database::open_in_memory().expect("Failed to open in-memory database");

        let volume_info = IndexedVolume::new("usn_serial".to_string(), "G:".to_string(), VolumeType::Ntfs);
        let result = ScanResult::Success {
            label: "G:".to_string(),
            volume_info,
            entries: Vec::new(),
            elapsed: std::time::Duration::from_millis(10),
            current_usn: Some(99999),
        };
        process_scan_result(&mut database, result, false).expect("process_scan_result failed");

        let usn = database.get_volume_last_usn('G').expect("Failed to get USN");
        assert_eq!(usn, Some(99999), "USN should be stored after scan");
    }

    #[test]
    fn test_process_scan_result_sets_volume_id_on_entries() {
        let mut database = Database::open_in_memory().expect("Failed to open in-memory database");

        let volume_info = IndexedVolume::new("vid_serial".to_string(), "H:".to_string(), VolumeType::Local);
        let entries = vec![FileEntry {
            id: None,
            volume_id: 0, // Will be overwritten
            parent_id: None,
            name: "assigned.txt".to_string(),
            full_path: "H:\\assigned.txt".to_string(),
            is_directory: false,
            size: 42,
            created_time: None,
            modified_time: None,
            mft_reference: None,
        }];
        let result = ScanResult::Success {
            label: "H:".to_string(),
            volume_info,
            entries,
            elapsed: std::time::Duration::from_millis(5),
            current_usn: None,
        };
        let count = process_scan_result(&mut database, result, false).expect("process_scan_result failed");
        assert_eq!(count, 1);

        // The entry should be searchable, which means volume_id was set correctly
        let found = database.search_by_name("assigned", 10).expect("Search failed");
        assert_eq!(found.len(), 1, "Entry should be findable after volume_id assignment");
    }

    #[test]
    fn test_process_scan_result_empty_entries() {
        let mut database = Database::open_in_memory().expect("Failed to open in-memory database");

        let volume_info = IndexedVolume::new("empty_serial".to_string(), "I:".to_string(), VolumeType::Ntfs);
        let result = ScanResult::Success {
            label: "I:".to_string(),
            volume_info,
            entries: Vec::new(),
            elapsed: std::time::Duration::from_millis(1),
            current_usn: Some(500),
        };
        let count = process_scan_result(&mut database, result, true).expect("process_scan_result failed");
        assert_eq!(count, 0, "Empty entries should return 0 count");
    }

    // ── scan_path_directory ───────────────────────────────────────

    #[tokio::test]
    async fn test_scan_path_directory_success() {
        let temp = tempdir().expect("Failed to create temp directory");
        let scan_dir = temp.path().join("scan_path_test");
        fs::create_dir(&scan_dir).expect("Failed to create scan directory");
        fs::write(scan_dir.join("doc.txt"), "hello").expect("Failed to write doc.txt");
        fs::write(scan_dir.join("image.png"), "fake png").expect("Failed to write image.png");

        let label = scan_dir.to_string_lossy().into_owned();
        let exclude: Arc<[String]> = Arc::from(Vec::<String>::new().into_boxed_slice());

        let result = scan_path_directory(scan_dir.clone(), label.clone(), exclude).await;
        match result {
            ScanResult::Success {
                label: result_label,
                volume_info,
                entries,
                current_usn,
                ..
            } => {
                assert_eq!(result_label, label);
                assert!(current_usn.is_none(), "Directory scan should have no USN");
                // scan_dir + doc.txt + image.png = 3 entries
                assert_eq!(entries.len(), 3, "Should have 3 entries (1 dir + 2 files)");
                assert_eq!(volume_info.volume_type, VolumeType::Local);
            }
            ScanResult::Failed { error, .. } => panic!("Expected Success, got Failed: {error}"),
        }
    }

    #[tokio::test]
    async fn test_scan_path_directory_with_exclusions() {
        let temp = tempdir().expect("Failed to create temp directory");
        let scan_dir = temp.path().join("scan_path_exclude");
        fs::create_dir(&scan_dir).expect("Failed to create scan directory");
        fs::write(scan_dir.join("keep.txt"), "keep").expect("Failed to write keep.txt");
        fs::write(scan_dir.join("skip.bak"), "skip").expect("Failed to write skip.bak");

        let label = scan_dir.to_string_lossy().into_owned();
        let exclude: Arc<[String]> = Arc::from(vec!["*.bak".to_string()].into_boxed_slice());

        let result = scan_path_directory(scan_dir, label, exclude).await;
        match result {
            ScanResult::Success { entries, .. } => {
                // scan_dir + keep.txt = 2 entries (skip.bak excluded)
                assert_eq!(entries.len(), 2, "Should have 2 entries (.bak excluded)");
                let names: Vec<&str> = entries.iter().map(|entry| entry.name.as_str()).collect();
                assert!(names.contains(&"keep.txt"), "keep.txt should be present");
                assert!(!names.contains(&"skip.bak"), "skip.bak should be excluded");
            }
            ScanResult::Failed { error, .. } => panic!("Expected Success, got Failed: {error}"),
        }
    }

    #[tokio::test]
    async fn test_scan_path_directory_nonexistent_path() {
        let path = PathBuf::from("Z:\\NonExistent\\Path\\For\\Testing\\12345");
        let label = path.to_string_lossy().into_owned();
        let exclude: Arc<[String]> = Arc::from(Vec::<String>::new().into_boxed_slice());

        let result = scan_path_directory(path, label, exclude).await;
        match result {
            ScanResult::Failed { label, error } => {
                assert!(!label.is_empty(), "Label should be preserved in failed result");
                assert!(!error.is_empty(), "Error message should describe the failure");
            }
            ScanResult::Success { entries, .. } => {
                // On some platforms scan_directory may succeed with an empty
                // result instead of returning an error for nonexistent paths.
                assert!(
                    entries.is_empty(),
                    "Nonexistent path should produce no entries if it does not error"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_scan_path_directory_empty_dir() {
        let temp = tempdir().expect("Failed to create temp directory");
        let scan_dir = temp.path().join("empty_scan");
        fs::create_dir(&scan_dir).expect("Failed to create scan directory");

        let label = scan_dir.to_string_lossy().into_owned();
        let exclude: Arc<[String]> = Arc::from(Vec::<String>::new().into_boxed_slice());

        let result = scan_path_directory(scan_dir, label, exclude).await;
        match result {
            ScanResult::Success { entries, .. } => {
                // Just the root directory
                assert_eq!(entries.len(), 1, "Empty dir should have 1 entry (itself)");
                assert!(entries[0].is_directory, "Single entry should be the directory");
            }
            ScanResult::Failed { error, .. } => panic!("Expected Success, got Failed: {error}"),
        }
    }

    // ── prune_non_ntfs_volumes ────────────────────────────────────

    #[test]
    fn test_prune_non_ntfs_volumes_empty_list() {
        let database = Database::open_in_memory().expect("Failed to open in-memory database");
        // Should return immediately without error
        prune_non_ntfs_volumes(&database, &[], 0, false);
    }

    #[test]
    fn test_prune_non_ntfs_volumes_nonexistent_volume_ids() {
        let database = Database::open_in_memory().expect("Failed to open in-memory database");
        // Volume IDs that don't exist - should not panic
        prune_non_ntfs_volumes(&database, &[999, 1000], 0, false);
    }

    // ── extract_drive_letter edge cases ───────────────────────────

    #[test]
    fn test_extract_drive_letter_empty_path() {
        assert_eq!(extract_drive_letter(Path::new("")), None);
    }

    #[test]
    fn test_extract_drive_letter_single_char() {
        assert_eq!(extract_drive_letter(Path::new("C")), None);
    }

    #[test]
    fn test_extract_drive_letter_numeric_prefix() {
        assert_eq!(
            extract_drive_letter(Path::new("1:")),
            None,
            "Numeric prefix should not be a valid drive letter"
        );
    }

    #[test]
    fn test_extract_drive_letter_lowercase_normalized() {
        assert_eq!(
            extract_drive_letter(Path::new("d:\\Users")),
            Some('D'),
            "Lowercase drive letters should be uppercased"
        );
    }

    #[test]
    fn test_extract_drive_letter_just_colon() {
        assert_eq!(extract_drive_letter(Path::new(":")), None);
    }

    // ── is_drive_letter_path edge cases ───────────────────────────

    #[test]
    fn test_is_drive_letter_path_empty() {
        assert!(!is_drive_letter_path(Path::new("")));
    }

    #[test]
    fn test_is_drive_letter_path_dot() {
        assert!(!is_drive_letter_path(Path::new(".")));
    }

    #[test]
    fn test_is_drive_letter_path_just_letter() {
        assert!(!is_drive_letter_path(Path::new("C")));
    }

    // ── is_path_accessible edge cases ─────────────────────────────

    #[test]
    fn test_is_path_accessible_empty_path() {
        assert!(!is_path_accessible(Path::new("")));
    }

    #[test]
    fn test_is_path_accessible_relative_nonexistent() {
        assert!(!is_path_accessible(Path::new("definitely_not_a_real_path_xyz123")));
    }

    #[test]
    fn test_is_path_accessible_drive_letter_fallback_inaccessible() {
        // A drive letter path that doesn't exist should exercise the read_dir fallback
        assert!(!is_path_accessible(Path::new("Q:\\")));
    }

    // ── create_directory_volume_info edge cases ───────────────────

    #[test]
    fn test_create_directory_volume_info_local_type() {
        let path = Path::new("D:\\Projects\\MyApp");
        let volume = create_directory_volume_info(path);

        assert_eq!(volume.volume_type, VolumeType::Local);
        assert_eq!(volume.serial_number, "path:D:\\Projects\\MyApp");
        assert_eq!(volume.mount_point, "D:\\Projects\\MyApp");
        assert!(volume.is_online);
        assert!(volume.id.is_none());
        assert!(volume.last_usn.is_none());
    }

    #[test]
    fn test_create_directory_volume_info_unc_is_network() {
        let path = Path::new("\\\\nas\\share\\docs");
        let volume = create_directory_volume_info(path);

        assert_eq!(volume.volume_type, VolumeType::Network);
        assert_eq!(volume.serial_number, "path:\\\\nas\\share\\docs");
        assert_eq!(volume.mount_point, "\\\\nas\\share\\docs");
    }

    // ── scan_directory_to_db additional edge cases ────────────────

    #[tokio::test]
    async fn test_scan_directory_to_db_clean_scan_removes_deleted_files() {
        let temp = tempdir().expect("Failed to create temp directory");
        let scan_dir = temp.path().join("clean_delete_test");
        fs::create_dir(&scan_dir).expect("Failed to create scan directory");

        let db_path = temp.path().join("test.db");
        let mut database = Database::open(&db_path).expect("Failed to open database");

        // First scan with two files
        fs::write(scan_dir.join("keep.txt"), "keep").expect("Failed to write keep.txt");
        fs::write(scan_dir.join("remove.txt"), "remove").expect("Failed to write remove.txt");
        let count1 = scan_directory_to_db(&mut database, &scan_dir, &[], true)
            .await
            .expect("First scan failed");
        assert_eq!(count1, 3, "Expected 3 entries (dir + 2 files)");

        // Delete one file from disk
        fs::remove_file(scan_dir.join("remove.txt")).expect("Failed to remove file");

        // Clean scan should reflect the deletion
        let count2 = scan_directory_to_db(&mut database, &scan_dir, &[], true)
            .await
            .expect("Second scan failed");
        assert_eq!(count2, 2, "Expected 2 entries after deleting one file");

        // Verify the removed file is no longer in the database
        let found = database.search_by_name("remove", 10).expect("Search failed");
        assert!(
            found.is_empty(),
            "Deleted file should not be in database after clean scan"
        );
    }

    #[tokio::test]
    async fn test_scan_directory_to_db_multiple_exclusion_patterns() {
        let temp = tempdir().expect("Failed to create temp directory");
        let scan_dir = temp.path().join("multi_exclude");
        fs::create_dir(&scan_dir).expect("Failed to create scan directory");

        fs::write(scan_dir.join("code.rs"), "fn main() {}").expect("Failed to write code.rs");
        fs::write(scan_dir.join("notes.tmp"), "temp").expect("Failed to write notes.tmp");
        fs::write(scan_dir.join("debug.log"), "log entry").expect("Failed to write debug.log");
        fs::write(scan_dir.join("data.bak"), "backup").expect("Failed to write data.bak");

        let db_path = temp.path().join("test.db");
        let mut database = Database::open(&db_path).expect("Failed to open database");

        let exclusions = vec!["*.tmp".to_string(), "*.log".to_string(), "*.bak".to_string()];
        let count = scan_directory_to_db(&mut database, &scan_dir, &exclusions, true)
            .await
            .expect("Scan failed");

        // Should have: scan_dir + code.rs = 2
        assert_eq!(
            count, 2,
            "Only code.rs and dir should remain after multi-pattern exclusion"
        );

        let found = database.search_by_name("code", 10).expect("Search failed");
        assert_eq!(found.len(), 1, "code.rs should be present");
    }

    #[tokio::test]
    async fn test_scan_directory_to_db_preserves_directory_flag() {
        let temp = tempdir().expect("Failed to create temp directory");
        let scan_dir = temp.path().join("dir_flag_test");
        fs::create_dir(&scan_dir).expect("Failed to create scan directory");
        fs::create_dir(scan_dir.join("child_dir")).expect("Failed to create child_dir");
        fs::write(scan_dir.join("file.txt"), "content").expect("Failed to write file.txt");

        let db_path = temp.path().join("test.db");
        let mut database = Database::open(&db_path).expect("Failed to open database");

        scan_directory_to_db(&mut database, &scan_dir, &[], true)
            .await
            .expect("Scan failed");

        let dirs = database.search_by_name("child_dir", 10).expect("Search failed");
        assert_eq!(dirs.len(), 1);
        assert!(dirs[0].is_directory, "child_dir should be marked as directory");

        let files = database.search_by_name("file.txt", 10).expect("Search failed");
        assert_eq!(files.len(), 1);
        assert!(!files[0].is_directory, "file.txt should not be marked as directory");
    }

    #[tokio::test]
    async fn test_scan_directory_to_db_unicode_filenames() {
        let temp = tempdir().expect("Failed to create temp directory");
        let scan_dir = temp.path().join("unicode_test");
        fs::create_dir(&scan_dir).expect("Failed to create scan directory");
        fs::write(scan_dir.join("日本語.txt"), "japanese").expect("Failed to write unicode file");
        fs::write(scan_dir.join("café.txt"), "french").expect("Failed to write accented file");

        let db_path = temp.path().join("test.db");
        let mut database = Database::open(&db_path).expect("Failed to open database");

        let count = scan_directory_to_db(&mut database, &scan_dir, &[], true)
            .await
            .expect("Scan failed");
        assert_eq!(count, 3, "Expected dir + 2 unicode files");

        let found = database.search_by_name("日本語", 10).expect("Search failed");
        assert_eq!(found.len(), 1, "Should find Japanese filename");

        let found = database.search_by_name("café", 10).expect("Search failed");
        assert_eq!(found.len(), 1, "Should find accented filename");
    }

    #[tokio::test]
    async fn test_scan_directory_to_db_deeply_nested() {
        let temp = tempdir().expect("Failed to create temp directory");
        let scan_dir = temp.path().join("deep_nest");
        let deep = scan_dir.join("l1").join("l2").join("l3").join("l4").join("l5");
        fs::create_dir_all(&deep).expect("Failed to create deeply nested dirs");
        fs::write(deep.join("leaf.txt"), "leaf").expect("Failed to write leaf.txt");

        let db_path = temp.path().join("test.db");
        let mut database = Database::open(&db_path).expect("Failed to open database");

        let count = scan_directory_to_db(&mut database, &scan_dir, &[], true)
            .await
            .expect("Scan failed");
        // scan_dir + l1 + l2 + l3 + l4 + l5 + leaf.txt = 7
        assert_eq!(count, 7, "Expected 6 directories + 1 file");

        let found = database.search_by_name("leaf", 10).expect("Search failed");
        assert_eq!(found.len(), 1);
        assert!(
            found[0].full_path.contains("l5"),
            "Leaf file path should contain deepest dir"
        );
    }

    #[tokio::test]
    async fn test_scan_directory_to_db_repeated_scans_idempotent_count() {
        let temp = tempdir().expect("Failed to create temp directory");
        let scan_dir = temp.path().join("idempotent_test");
        fs::create_dir(&scan_dir).expect("Failed to create scan directory");
        fs::write(scan_dir.join("stable.txt"), "stable").expect("Failed to write stable.txt");

        let db_path = temp.path().join("test.db");
        let mut database = Database::open(&db_path).expect("Failed to open database");

        let count1 = scan_directory_to_db(&mut database, &scan_dir, &[], true)
            .await
            .expect("First scan failed");
        let count2 = scan_directory_to_db(&mut database, &scan_dir, &[], true)
            .await
            .expect("Second scan failed");
        let count3 = scan_directory_to_db(&mut database, &scan_dir, &[], true)
            .await
            .expect("Third scan failed");

        assert_eq!(count1, count2, "Repeated clean scans should return same count");
        assert_eq!(count2, count3, "Repeated clean scans should return same count");
    }

    // ── collect_paths_to_scan edge cases ──────────────────────────

    #[test]
    fn test_collect_paths_to_scan_empty_config_paths() {
        let mut config = Config::default();
        config.daemon.paths = Vec::new();
        // With empty paths, it auto-detects NTFS volumes.
        // We can't predict the result, but it should not panic.
        let _result = collect_paths_to_scan(&config);
    }

    #[test]
    fn test_collect_paths_to_scan_single_nonexistent() {
        let mut config = Config::default();
        config.daemon.paths = vec!["Q:\\Nonexistent\\Drive\\Path\\12345".to_string()];
        let result = collect_paths_to_scan(&config);
        assert!(result.is_none(), "Single nonexistent path should return None");
    }

    // ── categorize_paths edge cases ───────────────────────────────

    #[test]
    fn test_categorize_paths_single_accessible_dir() {
        let temp = tempdir().expect("Failed to create temp directory");
        let temp_path = temp.path().to_string_lossy().to_string();
        let categorized = categorize_paths(vec![temp_path]);
        assert_eq!(categorized.task_count(), 1);
        assert!(categorized.ntfs_drive_roots.is_empty());
        assert!(categorized.unc_paths.is_empty());
        assert!(categorized.mapped_network_drives.is_empty());
    }

    #[test]
    fn test_categorize_paths_all_nonexistent() {
        let categorized = categorize_paths(vec![
            "Q:\\FakePath1".to_string(),
            "R:\\FakePath2".to_string(),
            "S:\\FakePath3".to_string(),
        ]);
        assert_eq!(categorized.task_count(), 0);
        assert!(categorized.ntfs_drive_roots.is_empty());
        assert!(categorized.local_paths_by_drive.is_empty());
        assert!(categorized.mapped_network_drives.is_empty());
        assert!(categorized.unc_paths.is_empty());
    }

    #[test]
    fn test_categorize_paths_duplicate_paths() {
        let temp = tempdir().expect("Failed to create temp directory");
        let temp_path = temp.path().to_string_lossy().to_string();
        let categorized = categorize_paths(vec![temp_path.clone(), temp_path]);

        // Both paths are on the same drive, so they get grouped together
        let drive_letter = extract_drive_letter(temp.path());
        if let Some(letter) = drive_letter {
            let paths = categorized
                .local_paths_by_drive
                .get(&letter)
                .expect("Should have paths for this drive");
            assert_eq!(
                paths.len(),
                2,
                "Duplicate paths are both stored (dedup is caller's job)"
            );
        }
    }

    // ── should_clean_scan edge cases ──────────────────────────────

    #[test]
    fn test_should_clean_scan_with_volumes_only() {
        let config = Config::default();
        let database = Database::open_in_memory().expect("Failed to open in-memory database");

        // Create a volume but insert no files or directories
        let volume = IndexedVolume::new("vol_only".to_string(), "V:".to_string(), VolumeType::Ntfs);
        database.upsert_volume(&volume).expect("Failed to upsert volume");

        let result = should_clean_scan(&database, &config).expect("should_clean_scan failed");
        assert!(
            result,
            "Database with volumes but no files or directories should trigger clean scan"
        );
    }

    #[test]
    fn test_should_clean_scan_default_config_empty_db() {
        let config = Config::default();
        assert!(
            !config.daemon.force_clean_scan,
            "Default config should not force clean scan"
        );
        let database = Database::open_in_memory().expect("Failed to open in-memory database");
        let result = should_clean_scan(&database, &config).expect("should_clean_scan failed");
        assert!(result, "Empty database always triggers clean scan");
    }

    // ── CategorizedPaths::task_count edge cases ───────────────────

    #[test]
    fn test_task_count_all_categories_populated() {
        let mut local = HashMap::new();
        local.insert('C', vec!["C:\\Data".to_string()]);
        local.insert('D', vec!["D:\\Stuff".to_string(), "D:\\More".to_string()]);
        let paths = CategorizedPaths {
            ntfs_drive_roots: vec!['E', 'F', 'G'],
            local_paths_by_drive: local,
            mapped_network_drives: vec![('X', PathBuf::from("X:\\")), ('Y', PathBuf::from("Y:\\"))],
            unc_paths: vec![
                PathBuf::from("\\\\server1\\share"),
                PathBuf::from("\\\\server2\\share"),
                PathBuf::from("\\\\server3\\share"),
            ],
        };
        // 3 NTFS roots + 2 local drive groups + 2 mapped drives + 3 UNC = 10
        assert_eq!(paths.task_count(), 10);
    }

    #[test]
    fn test_task_count_only_unc() {
        let paths = CategorizedPaths {
            ntfs_drive_roots: Vec::new(),
            local_paths_by_drive: HashMap::new(),
            mapped_network_drives: Vec::new(),
            unc_paths: vec![PathBuf::from("\\\\server\\share")],
        };
        assert_eq!(paths.task_count(), 1);
    }

    #[test]
    fn test_task_count_only_mapped() {
        let paths = CategorizedPaths {
            ntfs_drive_roots: Vec::new(),
            local_paths_by_drive: HashMap::new(),
            mapped_network_drives: vec![('Z', PathBuf::from("Z:\\"))],
            unc_paths: Vec::new(),
        };
        assert_eq!(paths.task_count(), 1);
    }
}
