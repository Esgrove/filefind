//! File scanning and indexing functionality.
//!
//! This module provides functions for scanning file systems and indexing
//! files into the database. It supports multiple scanning strategies:
//! - MFT scanning for NTFS volumes (fast)
//! - Directory walking for non-NTFS volumes (fallback)

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::Result;
use filefind::{Config, Database, PathType, classify_path, print_error, print_info, print_success, print_warning};

use crate::mft::{MftScanner, detect_ntfs_volumes};
use crate::watcher::scan_directory;

/// Run a one-time scan.
///
/// If a path is provided, scans that specific path.
/// Otherwise, scans all configured paths or auto-detects NTFS volumes.
pub async fn run_scan(path: Option<PathBuf>, force: bool, config: &Config) -> Result<()> {
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
pub async fn scan_single_path(database: &mut Database, scan_path: &Path, force: bool, config: &Config) -> Result<()> {
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
#[allow(clippy::too_many_lines)]
pub async fn scan_configured_paths(database: &mut Database, force: bool, config: &Config) -> Result<()> {
    let total_start = Instant::now();
    let mut total_entries = 0usize;

    if config.daemon.paths.is_empty() {
        // Auto-detect NTFS volumes when no paths are configured
        print_info!("No paths configured, auto-detecting NTFS volumes...");
        let ntfs_drives = detect_ntfs_volumes();

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
pub fn scan_ntfs_volume(database: &mut Database, drive_letter: char, force: bool) -> Result<usize> {
    scan_ntfs_volume_filtered(database, drive_letter, &[], force)
}

/// Scan an NTFS volume using the MFT scanner with path filtering.
///
/// If `path_filters` is empty, indexes the entire drive.
/// Otherwise, only indexes files under the specified paths.
pub fn scan_ntfs_volume_filtered(
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
pub async fn scan_directory_to_db(database: &mut Database, path: &Path, exclude_patterns: &[String]) -> Result<usize> {
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
    let file_entries: Vec<_> = scan_entries
        .iter()
        .map(|entry| entry.to_file_entry(volume_id))
        .collect();

    let count = file_entries.len();
    database.insert_files_batch(&file_entries)?;

    Ok(count)
}

/// Format a large number with thousands separators.
#[must_use]
pub fn format_number(number: u64) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_format_number() {
        assert_eq!(format_number(0), "0");
        assert_eq!(format_number(123), "123");
        assert_eq!(format_number(1234), "1,234");
        assert_eq!(format_number(12345), "12,345");
        assert_eq!(format_number(123_456), "123,456");
        assert_eq!(format_number(1_234_567), "1,234,567");
        assert_eq!(format_number(1_234_567_890), "1,234,567,890");
    }

    #[test]
    fn test_format_number_edge_cases() {
        // Single digit
        assert_eq!(format_number(1), "1");
        assert_eq!(format_number(9), "9");

        // Two digits
        assert_eq!(format_number(10), "10");
        assert_eq!(format_number(99), "99");

        // Three digits (no comma)
        assert_eq!(format_number(100), "100");
        assert_eq!(format_number(999), "999");

        // Exactly 1000
        assert_eq!(format_number(1000), "1,000");

        // Large numbers
        assert_eq!(format_number(1_000_000), "1,000,000");
        assert_eq!(format_number(1_000_000_000), "1,000,000,000");
        assert_eq!(format_number(1_000_000_000_000), "1,000,000,000,000");
    }

    #[test]
    fn test_format_number_max_u64() {
        // Test with maximum u64 value
        let result = format_number(u64::MAX);
        // u64::MAX = 18446744073709551615
        assert_eq!(result, "18,446,744,073,709,551,615");
    }

    #[test]
    fn test_format_number_powers_of_ten() {
        assert_eq!(format_number(10), "10");
        assert_eq!(format_number(100), "100");
        assert_eq!(format_number(1_000), "1,000");
        assert_eq!(format_number(10_000), "10,000");
        assert_eq!(format_number(100_000), "100,000");
        assert_eq!(format_number(1_000_000), "1,000,000");
    }

    #[test]
    fn test_format_number_preserves_all_digits() {
        // Verify no digits are lost
        let number = 123_456_789u64;
        let formatted = format_number(number);

        // Remove commas and parse back
        let stripped: String = formatted.chars().filter(|c| *c != ',').collect();
        let parsed: u64 = stripped.parse().expect("Should parse back to number");

        assert_eq!(parsed, number);
    }

    #[tokio::test]
    async fn test_scan_directory_to_db() {
        let temp = tempdir().expect("create temp dir");
        let root = temp.path();

        // Create test files
        fs::create_dir_all(root.join("subdir")).expect("create subdir");
        fs::write(root.join("file1.txt"), "content1").expect("write file1");
        fs::write(root.join("file2.txt"), "content2").expect("write file2");
        fs::write(root.join("subdir").join("nested.txt"), "nested").expect("write nested");

        // Create in-memory database
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

        // Create test files
        fs::write(root.join("keep.txt"), "keep").expect("write keep");
        fs::write(root.join("skip.tmp"), "skip").expect("write skip");

        let mut database = Database::open_in_memory().expect("open db");

        // Scan with exclusion pattern
        let _count = scan_directory_to_db(&mut database, root, &["*.tmp".to_string()])
            .await
            .expect("scan");

        // keep.txt should be found
        let results = database.search_by_name("keep", 10).expect("search");
        assert_eq!(results.len(), 1);

        // skip.tmp should not be found
        let results = database.search_by_name("skip", 10).expect("search");
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
        assert_eq!(volumes.len(), 1);

        // Volume serial should contain "path:"
        assert!(
            volumes[0].serial_number.starts_with("path:"),
            "Volume serial should start with 'path:', got: {}",
            volumes[0].serial_number
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

        // Check file sizes
        let results = database.search_by_exact_name("small.txt", 10).expect("search");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].size, 1);

        let results = database.search_by_exact_name("medium.txt", 10).expect("search");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].size, 1000);
    }

    #[tokio::test]
    async fn test_scan_directory_to_db_directories_have_zero_size() {
        let temp = tempdir().expect("create temp dir");
        let root = temp.path();

        fs::create_dir_all(root.join("mydir")).expect("create dir");
        fs::write(root.join("mydir").join("file.txt"), "content").expect("write file");

        let mut database = Database::open_in_memory().expect("open db");

        scan_directory_to_db(&mut database, root, &[]).await.expect("scan");

        // Find the directory
        let results = database.search_by_exact_name("mydir", 10).expect("search");
        assert_eq!(results.len(), 1);
        assert!(results[0].is_directory);
        assert_eq!(results[0].size, 0, "Directory should have size 0");
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

        // Verify deep file is found
        let results = database.search_by_exact_name("deep.txt", 10).expect("search");
        assert_eq!(results.len(), 1);
        assert!(results[0].full_path.contains('d'));
    }
}
