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

    #[test]
    fn test_format_number() {
        assert_eq!(format_number(0), "0");
        assert_eq!(format_number(123), "123");
        assert_eq!(format_number(1234), "1,234");
        assert_eq!(format_number(12345), "12,345");
        assert_eq!(format_number(123456), "123,456");
        assert_eq!(format_number(1234567), "1,234,567");
        assert_eq!(format_number(1234567890), "1,234,567,890");
    }
}
