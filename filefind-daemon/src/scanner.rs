//! File scanning and indexing functionality.
//!
//! This module provides functions for scanning file systems and indexing
//! files into the database. It supports multiple scanning strategies:
//! - MFT scanning for NTFS volumes (fast)
//! - Directory walking for non-NTFS volumes (fallback)

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use filefind::types::{IndexedVolume, VolumeType};
use filefind::{Config, Database, FileEntry, PathType, classify_path, format_number, is_network_path};
use tracing::{debug, error, info, warn};

use crate::mft::{MftScanner, detect_ntfs_volumes};
use crate::watcher::scan_directory;

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
    fallback_path: &Path,
    exclude_patterns: &[String],
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
            scan_directory_to_db(database, fallback_path, exclude_patterns).await
        }
    }
}

/// Run a one-time scan.
///
/// If a path is provided, scans that specific path.
/// Otherwise, scans all configured paths or auto-detects NTFS volumes.
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
pub async fn scan_single_path(database: &mut Database, scan_path: &Path, config: &Config) -> Result<()> {
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
            try_mft_with_fallback(database, drive_letter, &[], scan_path, exclude_patterns).await?
        }
        PathType::LocalDirectory => {
            // Use MFT scanner with path filter for local directories
            let drive_letter = extract_drive_letter(scan_path).expect("LocalDirectory should have a drive letter");

            let path_filter = scan_path.to_string_lossy().to_string();
            debug!("Using MFT scanner with path filter: {}", path_filter);
            try_mft_with_fallback(database, drive_letter, &[path_filter], scan_path, exclude_patterns).await?
        }
        PathType::MappedNetworkDrive => {
            // Try MFT scanner for mapped network drives - some NAS devices support it
            let drive_letter = extract_drive_letter(scan_path).expect("MappedNetworkDrive should have a drive letter");

            debug!("Attempting MFT scanner for mapped network drive");
            try_mft_with_fallback(database, drive_letter, &[], scan_path, exclude_patterns).await?
        }
        PathType::UncPath => {
            // Use directory scanner for UNC paths (no drive letter for MFT)
            debug!("Using directory scanner for UNC path");
            scan_directory_to_db(database, scan_path, exclude_patterns).await?
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

/// Result from a parallel scan operation.
enum ScanResult {
    /// Successful NTFS scan with volume info and entries.
    Ntfs {
        label: String,
        volume_info: IndexedVolume,
        entries: Vec<FileEntry>,
        elapsed: std::time::Duration,
    },
    /// Successful directory scan with volume info and entries.
    Directory {
        label: String,
        volume_info: IndexedVolume,
        entries: Vec<FileEntry>,
        elapsed: std::time::Duration,
    },
    /// Scan failed.
    Failed { label: String, error: String },
    /// NTFS scan failed, need fallback to directory scan.
    NeedsFallback {
        paths: Vec<String>,
        exclude: Arc<[String]>,
        reason: String,
    },
}

/// Scan a directory and return a `ScanResult`.
///
/// This is extracted as a named async function so that all directory scan tasks
/// have the same concrete future type, avoiding the need for `dyn Future`.
async fn scan_directory_task(scan_path: PathBuf, path_label: String, exclude: Arc<[String]>) -> ScanResult {
    let start = Instant::now();
    match scan_directory(&scan_path, &exclude).await {
        Ok(scan_entries) => {
            let volume_info = create_directory_volume_info(&scan_path);
            let entries: Vec<FileEntry> = scan_entries.into_iter().map(|e| e.to_file_entry(0)).collect();
            ScanResult::Directory {
                label: path_label,
                volume_info,
                entries,
                elapsed: start.elapsed(),
            }
        }
        Err(error) => ScanResult::Failed {
            label: path_label,
            error: error.to_string(),
        },
    }
}

/// Categorized paths for scanning.
struct CategorizedPaths {
    /// NTFS drive roots to scan entirely.
    ntfs_drive_roots: Vec<char>,
    /// Local directories grouped by drive letter.
    local_paths_by_drive: HashMap<char, Vec<String>>,
    /// Mapped network drives with their paths.
    mapped_network_drives: Vec<(char, PathBuf)>,
    /// UNC paths to scan.
    unc_paths: Vec<PathBuf>,
}

/// Categorize paths by their type for efficient scanning.
fn categorize_paths(paths_to_scan: &[String]) -> CategorizedPaths {
    let mut ntfs_drive_roots: Vec<char> = Vec::new();
    let mut local_paths_by_drive: HashMap<char, Vec<String>> = HashMap::new();
    let mut mapped_network_drives: Vec<(char, PathBuf)> = Vec::new();
    let mut unc_paths: Vec<PathBuf> = Vec::new();

    for path_str in paths_to_scan {
        let scan_path = PathBuf::from(path_str);

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

        let path_type = classify_path(&scan_path);

        match path_type {
            PathType::NtfsDriveRoot => {
                if let Some(drive_letter) = extract_drive_letter(&scan_path) {
                    ntfs_drive_roots.push(drive_letter);
                }
            }
            PathType::LocalDirectory => {
                if let Some(drive_letter) = extract_drive_letter(&scan_path) {
                    local_paths_by_drive
                        .entry(drive_letter)
                        .or_default()
                        .push(path_str.clone());
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

    // Remove drives from local_paths_by_drive if we're scanning the whole drive
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

/// Build scan tasks for all categorized paths.
fn build_scan_tasks(
    categorized: CategorizedPaths,
    exclude_patterns: &Arc<[String]>,
) -> Vec<tokio::task::JoinHandle<ScanResult>> {
    let mut scan_handles = Vec::new();

    // Task for NTFS drive roots (full drive scans)
    for drive_letter in categorized.ntfs_drive_roots {
        scan_handles.push(tokio::task::spawn_blocking(move || {
            let start = Instant::now();
            match scan_ntfs_volume_sync(drive_letter, &[]) {
                Ok((volume_info, entries)) => ScanResult::Ntfs {
                    label: format!("{drive_letter}:"),
                    volume_info,
                    entries,
                    elapsed: start.elapsed(),
                },
                Err(error) => ScanResult::Failed {
                    label: format!("{drive_letter}:"),
                    error: error.to_string(),
                },
            }
        }));
    }

    // Task for local directories with MFT filtering
    for (drive_letter, paths) in categorized.local_paths_by_drive {
        let exclude = Arc::clone(exclude_patterns);
        scan_handles.push(tokio::task::spawn_blocking(move || {
            let start = Instant::now();
            match scan_ntfs_volume_sync(drive_letter, &paths) {
                Ok((volume_info, entries)) => ScanResult::Ntfs {
                    label: format!("{drive_letter}:"),
                    volume_info,
                    entries,
                    elapsed: start.elapsed(),
                },
                Err(error) => {
                    // MFT failed, signal that we need fallback
                    ScanResult::NeedsFallback {
                        paths,
                        exclude,
                        reason: error.to_string(),
                    }
                }
            }
        }));
    }

    // Task for mapped network drives - try MFT first
    for (drive_letter, scan_path) in categorized.mapped_network_drives {
        let exclude = Arc::clone(exclude_patterns);
        let path_display = scan_path.to_string_lossy().into_owned();
        scan_handles.push(tokio::task::spawn_blocking(move || {
            let start = Instant::now();
            match scan_ntfs_volume_sync(drive_letter, &[]) {
                Ok((volume_info, entries)) => ScanResult::Ntfs {
                    label: path_display,
                    volume_info,
                    entries,
                    elapsed: start.elapsed(),
                },
                Err(error) => {
                    // MFT failed, signal that we need fallback
                    ScanResult::NeedsFallback {
                        paths: vec![path_display],
                        exclude,
                        reason: error.to_string(),
                    }
                }
            }
        }));
    }

    scan_handles
}

/// Process scan results and write them to the database.
fn process_scan_results(database: &mut Database, results: Vec<ScanResult>) -> Result<usize> {
    let mut total_entries = 0usize;

    for result in results {
        match result {
            ScanResult::Ntfs {
                label,
                volume_info,
                mut entries,
                elapsed,
            }
            | ScanResult::Directory {
                label,
                volume_info,
                mut entries,
                elapsed,
            } => {
                let volume_id = database.upsert_volume(&volume_info)?;
                for entry in &mut entries {
                    entry.volume_id = volume_id;
                }
                let count = entries.len();
                database.insert_files_batch(&entries)?;
                total_entries += count;
                info!(
                    "{} - {} entries in {:.2}s",
                    label,
                    format_number(count as u64),
                    elapsed.as_secs_f64()
                );
            }
            ScanResult::Failed { label, error } => {
                error!("{} - Failed: {}", label, error);
            }
            ScanResult::NeedsFallback { .. } => {
                // Should not happen here, already processed
            }
        }
    }

    Ok(total_entries)
}

/// Scan all configured paths, or auto-detect NTFS volumes if none are configured.
pub async fn scan_configured_paths(database: &mut Database, config: &Config) -> Result<()> {
    let total_start = Instant::now();

    // Collect all paths to scan
    let paths_to_scan: Vec<String> = if config.daemon.paths.is_empty() {
        // Auto-detect NTFS volumes when no paths are configured
        let ntfs_drives = detect_ntfs_volumes();

        if ntfs_drives.is_empty() {
            warn!("No NTFS volumes detected. Configure paths in the config file.");
            return Ok(());
        }

        ntfs_drives.iter().map(|d| format!("{d}:")).collect()
    } else {
        config.daemon.paths.clone()
    };

    // Categorize paths by type
    let categorized = categorize_paths(&paths_to_scan);

    // Count total scan tasks for logging
    let total_tasks = categorized.ntfs_drive_roots.len()
        + categorized.local_paths_by_drive.len()
        + categorized.mapped_network_drives.len()
        + categorized.unc_paths.len();

    if total_tasks == 0 {
        warn!("No valid paths to scan.");
        return Ok(());
    }

    info!("Starting scan of {} path(s)...", total_tasks);

    // Use Arc for exclude_patterns to avoid cloning in loops
    let exclude_patterns: Arc<[String]> = config.daemon.exclude.clone().into();

    // Extract UNC paths before moving categorized
    let unc_paths = categorized.unc_paths.clone();

    // Build all scan tasks
    let scan_handles = build_scan_tasks(categorized, &exclude_patterns);

    // Collect results from blocking tasks
    let mut results = Vec::new();
    let mut fallback_tasks = Vec::new();

    for handle in scan_handles {
        match handle.await {
            Ok(result) => match result {
                ScanResult::NeedsFallback { paths, exclude, reason } => {
                    debug!("MFT scan failed, falling back to directory scan: {}", reason);
                    // Queue up fallback directory scans
                    for path_str in paths {
                        let scan_path = PathBuf::from(&path_str);
                        fallback_tasks.push(scan_directory_task(scan_path, path_str, Arc::clone(&exclude)));
                    }
                }
                other => results.push(other),
            },
            Err(error) => {
                error!("Scan task panicked: {}", error);
            }
        }
    }

    // Run UNC path scans in parallel (async)
    for scan_path in unc_paths {
        let path_str = scan_path.to_string_lossy().into_owned();
        fallback_tasks.push(scan_directory_task(scan_path, path_str, Arc::clone(&exclude_patterns)));
    }

    // Run all fallback/UNC tasks in parallel
    let fallback_results = futures::future::join_all(fallback_tasks).await;
    results.extend(fallback_results);

    // Write all results to database sequentially
    let total_entries = process_scan_results(database, results)?;

    let total_elapsed = total_start.elapsed();

    info!(
        "Scan complete: {} entries in {:.2}s",
        format_number(total_entries as u64),
        total_elapsed.as_secs_f64()
    );

    Ok(())
}

/// Synchronous NTFS volume scan that returns volume info and entries.
fn scan_ntfs_volume_sync(drive_letter: char, path_filters: &[String]) -> Result<(IndexedVolume, Vec<FileEntry>)> {
    let scanner = MftScanner::new(drive_letter)?;
    let volume_info = scanner.get_volume_info()?;
    let entries = scanner.scan_filtered(path_filters)?;
    Ok((volume_info, entries))
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

    Ok(count)
}

/// Scan a directory and insert entries into the database.
pub async fn scan_directory_to_db(database: &mut Database, path: &Path, exclude_patterns: &[String]) -> Result<usize> {
    let volume_info = create_directory_volume_info(path);
    let volume_id = database.upsert_volume(&volume_info)?;

    // Scan the directory
    let scan_entries = scan_directory(path, exclude_patterns).await?;

    // Convert to file entries
    let file_entries: Vec<_> = scan_entries
        .iter()
        .map(|entry| entry.to_file_entry(volume_id))
        .collect();

    let count = file_entries.len();
    database.insert_files_batch(&file_entries)?;

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_scan_directory_to_db() {
        let temp = tempdir().expect("create temp dir");
        let root = temp.path();

        // Create some test files and directories
        fs::write(root.join("file1.txt"), "content1").expect("write file1");
        fs::write(root.join("file2.txt"), "content2").expect("write file2");
        fs::create_dir_all(root.join("subdir")).expect("create subdir");
        fs::write(root.join("subdir").join("nested.txt"), "nested").expect("write nested");

        let mut database = Database::open_in_memory().expect("open db");

        // Scan directory to database
        let count = scan_directory_to_db(&mut database, root, &[]).await.expect("scan");

        // Should have found files and directories
        assert!(
            count >= 4,
            "Should find at least 4 entries (root, subdir, 3 files), got {count}"
        );

        // Verify files are in database
        let results = database.search_by_name("file1", 10).expect("search");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "file1.txt");

        let results = database.search_by_name("nested", 10).expect("search");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "nested.txt");
    }

    #[tokio::test]
    async fn test_scan_directory_to_db_with_exclusions() {
        let temp = tempdir().expect("create temp dir");
        let root = temp.path();

        fs::write(root.join("keep.txt"), "keep").expect("write keep");
        fs::write(root.join("exclude.tmp"), "exclude").expect("write exclude");

        let mut database = Database::open_in_memory().expect("open db");

        // Scan with exclusion pattern
        let _count = scan_directory_to_db(&mut database, root, &["*.tmp".to_string()])
            .await
            .expect("scan");

        // Verify that the excluded file is not in the database
        let results = database.search_by_exact_name("exclude.tmp", 10).expect("search");
        assert!(results.is_empty(), "Excluded file should not be in database");
    }

    #[tokio::test]
    async fn test_scan_directory_to_db_empty_directory() {
        let temp = tempdir().expect("create temp dir");
        let root = temp.path();

        let mut database = Database::open_in_memory().expect("open db");

        // Scan empty directory
        let count = scan_directory_to_db(&mut database, root, &[]).await.expect("scan");

        // Should have at least the root directory itself
        assert!(count >= 1);
    }

    #[tokio::test]
    async fn test_scan_directory_to_db_creates_volume() {
        let temp = tempdir().expect("create temp dir");
        let root = temp.path();

        fs::write(root.join("test.txt"), "test").expect("write file");

        let mut database = Database::open_in_memory().expect("open db");

        scan_directory_to_db(&mut database, root, &[]).await.expect("scan");

        // Verify a volume was created
        let volumes = database.get_all_volumes().expect("get volumes");
        assert!(!volumes.is_empty(), "Should have created a volume");

        // Volume serial should contain the path
        let volume = &volumes[0];
        assert!(
            volume.serial_number.contains("path:"),
            "Volume serial should be path-based"
        );
    }

    #[tokio::test]
    async fn test_scan_directory_to_db_file_sizes() {
        let temp = tempdir().expect("create temp dir");
        let root = temp.path();

        // Create files with known sizes
        fs::write(root.join("small.txt"), "x").expect("write small");
        fs::write(root.join("medium.txt"), "x".repeat(1000)).expect("write medium");

        let mut database = Database::open_in_memory().expect("open db");

        scan_directory_to_db(&mut database, root, &[]).await.expect("scan");

        // Check that sizes are recorded correctly
        let small_results = database.search_by_exact_name("small.txt", 10).expect("search small");
        assert!(!small_results.is_empty());
        assert_eq!(small_results[0].size, 1);

        let medium_results = database.search_by_exact_name("medium.txt", 10).expect("search medium");
        assert!(!medium_results.is_empty());
        assert_eq!(medium_results[0].size, 1000);
    }

    #[tokio::test]
    async fn test_scan_directory_to_db_directories_have_zero_size() {
        let temp = tempdir().expect("create temp dir");
        let root = temp.path();

        fs::create_dir_all(root.join("mydir")).expect("create dir");
        fs::write(root.join("mydir").join("file.txt"), "content").expect("write file");

        let mut database = Database::open_in_memory().expect("open db");

        scan_directory_to_db(&mut database, root, &[]).await.expect("scan");

        // Directories should have size 0
        let dir_results = database.search_by_exact_name("mydir", 10).expect("search mydir");
        let dir_entry = dir_results.iter().find(|e| e.is_directory);
        assert!(dir_entry.is_some(), "Should find directory");
        assert_eq!(dir_entry.unwrap().size, 0, "Directory size should be 0");
    }

    #[tokio::test]
    async fn test_scan_directory_to_db_nested_structure() {
        let temp = tempdir().expect("create temp dir");
        let root = temp.path();

        // Create deeply nested structure
        fs::create_dir_all(root.join("a").join("b").join("c").join("d")).expect("create dirs");
        fs::write(root.join("a").join("b").join("c").join("d").join("deep.txt"), "deep").expect("write deep file");

        let mut database = Database::open_in_memory().expect("open db");

        scan_directory_to_db(&mut database, root, &[]).await.expect("scan");

        // Should be able to find the deeply nested file
        let results = database.search_by_exact_name("deep.txt", 10).expect("search deep");
        assert!(!results.is_empty(), "Should find deeply nested file");
    }

    #[test]
    fn test_is_drive_letter_path() {
        assert!(is_drive_letter_path(Path::new("C:")));
        assert!(is_drive_letter_path(Path::new("C:\\")));
        assert!(is_drive_letter_path(Path::new("D:\\Data")));
        assert!(is_drive_letter_path(Path::new("Z:\\Network\\Share")));

        // Lowercase should also work
        assert!(is_drive_letter_path(Path::new("c:")));
        assert!(is_drive_letter_path(Path::new("c:\\Users")));

        // These should NOT be drive letter paths
        assert!(!is_drive_letter_path(Path::new("\\\\server\\share")));
        assert!(!is_drive_letter_path(Path::new("/unix/path")));
        assert!(!is_drive_letter_path(Path::new("relative\\path")));
        assert!(!is_drive_letter_path(Path::new("")));
        assert!(!is_drive_letter_path(Path::new("C"))); // Missing colon
    }

    #[test]
    fn test_extract_drive_letter() {
        assert_eq!(extract_drive_letter(Path::new("C:")), Some('C'));
        assert_eq!(extract_drive_letter(Path::new("C:\\")), Some('C'));
        assert_eq!(extract_drive_letter(Path::new("D:\\Data")), Some('D'));
        assert_eq!(extract_drive_letter(Path::new("z:\\path")), Some('Z'));

        assert_eq!(extract_drive_letter(Path::new("\\\\server\\share")), None);
        assert_eq!(extract_drive_letter(Path::new("/unix/path")), None);
        assert_eq!(extract_drive_letter(Path::new("")), None);
        assert_eq!(extract_drive_letter(Path::new("C")), None);
    }

    #[test]
    fn test_is_path_accessible_existing_directory() {
        let temp = tempdir().expect("create temp dir");
        let root = temp.path();

        // Create a subdirectory
        let subdir = root.join("accessible");
        fs::create_dir_all(&subdir).expect("create subdir");

        assert!(is_path_accessible(&subdir));
        assert!(is_path_accessible(root));
    }

    #[test]
    fn test_is_path_accessible_non_existent() {
        let non_existent = Path::new("Z:\\NonExistent\\Path\\That\\Should\\Not\\Exist");
        assert!(!is_path_accessible(non_existent));
    }

    #[test]
    fn test_is_path_accessible_existing_file() {
        let temp = tempdir().expect("create temp dir");
        let file_path = temp.path().join("test_file.txt");
        fs::write(&file_path, "test").expect("write file");

        // Files should also be accessible
        assert!(is_path_accessible(&file_path));
    }

    #[test]
    fn test_create_directory_volume_info() {
        let path = Path::new("C:\\Users\\Test");
        let volume_info = create_directory_volume_info(path);

        assert!(volume_info.serial_number.contains("path:"));
        assert!(volume_info.serial_number.contains("C:\\Users\\Test"));
        assert_eq!(volume_info.volume_type, VolumeType::Local);
    }

    #[test]
    fn test_create_directory_volume_info_network_path() {
        let path = Path::new("\\\\server\\share");
        let volume_info = create_directory_volume_info(path);

        assert!(volume_info.serial_number.contains("path:"));
        assert_eq!(volume_info.volume_type, VolumeType::Network);
    }
}
