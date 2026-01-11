//! Database pruning functionality.
//!
//! This module provides functions for removing database entries
//! that reference files or directories that no longer exist on disk.
//! It optimizes by first checking parent directories to avoid
//! unnecessary filesystem queries for children of missing directories.
//!
//! Pruning is parallelized by volume/drive to maximize throughput.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use filefind::Database;
use rayon::prelude::*;
use tracing::{debug, info, trace};

/// Batch size for delete operations to avoid SQL statement size limits.
const DELETE_BATCH_SIZE: usize = 500;

/// Statistics from a prune operation.
#[derive(Debug, Default, Clone)]
pub struct PruneStats {
    /// Number of files removed from the database.
    pub files_removed: u64,
    /// Number of directories removed from the database.
    pub directories_removed: u64,
    /// Number of entries checked.
    pub entries_checked: u64,
    /// Number of filesystem checks skipped due to missing parent directories.
    pub checks_skipped: u64,
}

/// Entry from the database to check for existence.
struct EntryToCheck {
    /// Database row ID.
    id: i64,
    /// Full path of the entry.
    full_path: String,
    /// Whether this is a directory.
    is_directory: bool,
}

/// Results from checking a single volume's entries.
struct VolumeCheckResult {
    /// IDs of entries to delete.
    ids_to_delete: Vec<i64>,
    /// Count of directories to be removed.
    directories_removed: u64,
    /// Count of files to be removed.
    files_removed: u64,
    /// Count of entries checked.
    entries_checked: u64,
    /// Count of filesystem checks skipped due to missing parent.
    checks_skipped: u64,
}

/// Prune database entries for files and directories that no longer exist.
///
/// This function efficiently removes stale entries by:
/// 1. Grouping entries by volume/drive for parallel processing
/// 2. For each volume, checking directories first (sorted by path length, shortest first)
/// 3. Tracking which directories are known to be missing
/// 4. For files, skipping filesystem checks if their parent directory is missing
///
/// # Arguments
/// * `database` - The database to prune
/// * `verbose` - Whether to print verbose progress information
///
/// # Errors
/// Returns an error if database operations fail.
pub fn prune_missing_entries(database: &Database, verbose: bool) -> Result<PruneStats> {
    // Get all entries from the database
    let all_entries = get_all_entries(database)?;

    if all_entries.is_empty() {
        info!("Prune complete: no entries to check");
        return Ok(PruneStats::default());
    }

    // Group entries by volume (drive letter or UNC root)
    let entries_by_volume = group_entries_by_volume(all_entries);
    let volume_count = entries_by_volume.len();

    if verbose {
        let total_entries: usize = entries_by_volume.values().map(Vec::len).sum();
        info!(
            "Checking {} entries across {} volume(s) in parallel...",
            total_entries, volume_count
        );
    }

    // Process each volume in parallel using rayon
    let volume_results: Vec<VolumeCheckResult> = entries_by_volume
        .into_par_iter()
        .map(|(volume_key, entries)| {
            trace!("Processing volume: {}", volume_key);
            check_volume_entries(entries)
        })
        .collect();

    // Aggregate results
    let mut stats = PruneStats::default();
    let mut all_ids_to_delete: Vec<i64> = Vec::new();

    for result in volume_results {
        stats.directories_removed += result.directories_removed;
        stats.files_removed += result.files_removed;
        stats.entries_checked += result.entries_checked;
        stats.checks_skipped += result.checks_skipped;
        all_ids_to_delete.extend(result.ids_to_delete);
    }

    // Delete all missing entries from database
    if !all_ids_to_delete.is_empty() {
        let deleted = delete_entries_by_ids(database, &all_ids_to_delete)?;
        debug!("Deleted {} entries from database", deleted);
    }

    info!(
        "Prune complete: checked {} entries, removed {} files and {} directories ({} checks skipped)",
        stats.entries_checked, stats.files_removed, stats.directories_removed, stats.checks_skipped
    );

    Ok(stats)
}

/// Prune entries for a specific volume only.
///
/// This is useful for targeted cleanup after changes to a specific drive.
///
/// # Arguments
/// * `database` - The database to prune
/// * `volume_id` - The volume ID to prune entries for
/// * `verbose` - Whether to print verbose progress information
///
/// # Errors
/// Returns an error if database operations fail.
pub fn prune_volume_entries(database: &Database, volume_id: i64, verbose: bool) -> Result<PruneStats> {
    let entries = get_entries_for_volume(database, volume_id)?;

    if entries.is_empty() {
        if verbose {
            info!("No entries to prune for volume {}", volume_id);
        }
        return Ok(PruneStats::default());
    }

    if verbose {
        info!("Checking {} entries for volume {}...", entries.len(), volume_id);
    }

    let result = check_volume_entries(entries);

    let stats = PruneStats {
        directories_removed: result.directories_removed,
        files_removed: result.files_removed,
        entries_checked: result.entries_checked,
        checks_skipped: result.checks_skipped,
    };

    if !result.ids_to_delete.is_empty() {
        delete_entries_by_ids(database, &result.ids_to_delete)?;
    }

    info!(
        "Volume {} prune: checked {} entries, removed {} files and {} directories",
        volume_id, stats.entries_checked, stats.files_removed, stats.directories_removed
    );

    Ok(stats)
}

/// Parallel prune that processes multiple volumes concurrently with progress reporting.
///
/// # Arguments
/// * `database` - The database to prune
/// * `verbose` - Whether to print verbose progress information
///
/// # Errors
/// Returns an error if database operations fail.
#[allow(dead_code, reason = "public API for parallel pruning with progress")]
pub fn prune_missing_entries_parallel(database: &Database, verbose: bool) -> Result<PruneStats> {
    // Get all entries from the database
    let all_entries = get_all_entries(database)?;

    if all_entries.is_empty() {
        info!("Prune complete: no entries to check");
        return Ok(PruneStats::default());
    }

    // Group entries by volume
    let entries_by_volume = group_entries_by_volume(all_entries);
    let volume_count = entries_by_volume.len();

    let total_entries: usize = entries_by_volume.values().map(Vec::len).sum();

    if verbose {
        info!(
            "Checking {} entries across {} volume(s) in parallel...",
            total_entries, volume_count
        );
    }

    // Atomic counters for progress tracking
    let checked_counter = AtomicU64::new(0);
    let removed_counter = AtomicU64::new(0);

    // Process volumes in parallel
    let volume_results: Vec<VolumeCheckResult> = entries_by_volume
        .into_par_iter()
        .map(|(volume_key, entries)| {
            let entry_count = entries.len();
            debug!("Processing volume {} ({} entries)", volume_key, entry_count);

            let result = check_volume_entries(entries);

            // Update progress counters
            checked_counter.fetch_add(result.entries_checked, Ordering::Relaxed);
            removed_counter.fetch_add(result.files_removed + result.directories_removed, Ordering::Relaxed);

            if verbose {
                debug!(
                    "Volume {} complete: {} checked, {} to remove",
                    volume_key,
                    result.entries_checked,
                    result.ids_to_delete.len()
                );
            }

            result
        })
        .collect();

    // Aggregate results
    let mut stats = PruneStats::default();
    let mut all_ids_to_delete: Vec<i64> = Vec::new();

    for result in volume_results {
        stats.directories_removed += result.directories_removed;
        stats.files_removed += result.files_removed;
        stats.entries_checked += result.entries_checked;
        stats.checks_skipped += result.checks_skipped;
        all_ids_to_delete.extend(result.ids_to_delete);
    }

    // Delete all missing entries from database
    if !all_ids_to_delete.is_empty() {
        if verbose {
            info!("Deleting {} stale entries from database...", all_ids_to_delete.len());
        }
        delete_entries_by_ids(database, &all_ids_to_delete)?;
    }

    info!(
        "Prune complete: checked {} entries, removed {} files and {} directories ({} checks skipped)",
        stats.entries_checked, stats.files_removed, stats.directories_removed, stats.checks_skipped
    );

    Ok(stats)
}

/// Check entries for a single volume and return IDs to delete.
///
/// This function processes directories first (sorted by path length) to enable
/// parent-directory optimization for files.
fn check_volume_entries(entries: Vec<EntryToCheck>) -> VolumeCheckResult {
    let mut result = VolumeCheckResult {
        ids_to_delete: Vec::new(),
        directories_removed: 0,
        files_removed: 0,
        entries_checked: 0,
        checks_skipped: 0,
    };

    // Separate directories and files
    let (mut directories, files): (Vec<_>, Vec<_>) = entries.into_iter().partition(|e| e.is_directory);

    // Sort directories by path length (shortest first) for parent-first checking
    directories.sort_by_key(|entry| entry.full_path.len());

    // Track missing and existing directories for optimization
    let mut missing_directories: HashSet<String> = HashSet::new();
    let mut existing_directories: HashSet<String> = HashSet::new();

    // Check directories first
    for entry in directories {
        result.entries_checked += 1;

        // Check if any parent directory is known to be missing
        if is_parent_missing(&entry.full_path, &missing_directories) {
            trace!("Skipping {} - parent directory is missing", entry.full_path);
            result.checks_skipped += 1;
            result.ids_to_delete.push(entry.id);
            result.directories_removed += 1;
            missing_directories.insert(entry.full_path);
            continue;
        }

        // Check if the directory exists on disk
        let path = Path::new(&entry.full_path);
        if path.exists() {
            existing_directories.insert(entry.full_path);
        } else {
            debug!("Directory no longer exists: {}", entry.full_path);
            result.ids_to_delete.push(entry.id);
            result.directories_removed += 1;
            missing_directories.insert(entry.full_path);
        }
    }

    // Check files
    for entry in files {
        result.entries_checked += 1;

        // Check if the parent directory is known to be missing
        if is_parent_missing(&entry.full_path, &missing_directories) {
            trace!("Skipping {} - parent directory is missing", entry.full_path);
            result.checks_skipped += 1;
            result.ids_to_delete.push(entry.id);
            result.files_removed += 1;
            continue;
        }

        // Check if the parent directory is known to exist (optimization)
        let parent = Path::new(&entry.full_path)
            .parent()
            .map(|p| p.to_string_lossy().to_string());

        let parent_exists = match &parent {
            Some(parent_path) if existing_directories.contains(parent_path) => true,
            Some(parent_path) if missing_directories.contains(parent_path) => false,
            Some(parent_path) => {
                // Check if parent exists and cache the result
                let exists = Path::new(parent_path).exists();
                if exists {
                    existing_directories.insert(parent_path.clone());
                } else {
                    missing_directories.insert(parent_path.clone());
                }
                exists
            }
            None => true, // Root paths - check the file directly
        };

        if !parent_exists {
            trace!("Skipping {} - parent directory doesn't exist", entry.full_path);
            result.checks_skipped += 1;
            result.ids_to_delete.push(entry.id);
            result.files_removed += 1;
            continue;
        }

        // Check if the file exists on disk
        let path = Path::new(&entry.full_path);
        if !path.exists() {
            debug!("File no longer exists: {}", entry.full_path);
            result.ids_to_delete.push(entry.id);
            result.files_removed += 1;
        }
    }

    result
}

/// Check if any parent directory of the given path is in the missing set.
fn is_parent_missing(path: &str, missing_directories: &HashSet<String>) -> bool {
    let path = Path::new(path);
    let mut current = path.parent();

    while let Some(parent) = current {
        let parent_str = parent.to_string_lossy();
        if missing_directories.contains(parent_str.as_ref()) {
            return true;
        }
        current = parent.parent();
    }

    false
}

/// Extract volume key from a path (drive letter or UNC root).
fn extract_volume_key(path: &str) -> String {
    // Handle UNC paths: \\server\share -> \\server\share
    if path.starts_with("\\\\") {
        let parts: Vec<&str> = path.trim_start_matches("\\\\").splitn(3, '\\').collect();
        if parts.len() >= 2 {
            return format!("\\\\{}\\{}", parts[0], parts[1]);
        }
        return path.to_string();
    }

    // Handle drive letters: C:\... -> C:
    if path.len() >= 2 && path.chars().nth(1) == Some(':') {
        return path[..2].to_uppercase();
    }

    // Fallback for unknown path formats
    "UNKNOWN".to_string()
}

/// Group entries by their volume (drive letter or UNC root).
fn group_entries_by_volume(entries: Vec<EntryToCheck>) -> HashMap<String, Vec<EntryToCheck>> {
    let mut grouped: HashMap<String, Vec<EntryToCheck>> = HashMap::new();

    for entry in entries {
        let volume_key = extract_volume_key(&entry.full_path);
        grouped.entry(volume_key).or_default().push(entry);
    }

    grouped
}

/// Get all entries from the database.
fn get_all_entries(database: &Database) -> Result<Vec<EntryToCheck>> {
    let connection = database.connection();

    let mut statement = connection
        .prepare(
            r"
            SELECT id, full_path, is_directory
            FROM files
            ",
        )
        .context("Failed to prepare entries query")?;

    let entries = statement
        .query_map([], |row| {
            Ok(EntryToCheck {
                id: row.get(0)?,
                full_path: row.get(1)?,
                is_directory: row.get(2)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to query entries")?;

    Ok(entries)
}

/// Get entries for a specific volume from the database.
fn get_entries_for_volume(database: &Database, volume_id: i64) -> Result<Vec<EntryToCheck>> {
    let connection = database.connection();

    let mut statement = connection
        .prepare(
            r"
            SELECT id, full_path, is_directory
            FROM files
            WHERE volume_id = ?1
            ",
        )
        .context("Failed to prepare volume entries query")?;

    let entries = statement
        .query_map([volume_id], |row| {
            Ok(EntryToCheck {
                id: row.get(0)?,
                full_path: row.get(1)?,
                is_directory: row.get(2)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to query volume entries")?;

    Ok(entries)
}

/// Delete entries from the database by their IDs.
fn delete_entries_by_ids(database: &Database, ids: &[i64]) -> Result<u64> {
    if ids.is_empty() {
        return Ok(0);
    }

    let connection = database.connection();

    // Use a transaction for better performance
    let transaction = connection.unchecked_transaction()?;

    let mut deleted = 0u64;

    for chunk in ids.chunks(DELETE_BATCH_SIZE) {
        // Build a parameterized query with placeholders
        let placeholders: Vec<&str> = chunk.iter().map(|_| "?").collect();
        let query = format!("DELETE FROM files WHERE id IN ({})", placeholders.join(", "));

        let mut statement = transaction.prepare(&query)?;

        // Bind all the IDs
        for (index, id) in chunk.iter().enumerate() {
            statement.raw_bind_parameter(index + 1, *id)?;
        }

        let rows = statement.raw_execute()?;
        deleted += rows as u64;
    }

    transaction.commit()?;

    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};

    use filefind::FileEntry;
    use filefind::types::{IndexedVolume, VolumeType};
    use tempfile::tempdir;

    use super::*;

    fn setup_test_database() -> (Database, tempfile::TempDir) {
        let database = Database::open_in_memory().expect("Failed to create in-memory database");
        let temp_dir = tempdir().expect("Failed to create temp directory");
        (database, temp_dir)
    }

    fn insert_test_volume(database: &Database) -> i64 {
        let volume = IndexedVolume::new("TEST_SERIAL".to_string(), "T:".to_string(), VolumeType::Local);

        database.upsert_volume(&volume).expect("Failed to insert volume")
    }

    fn insert_test_file(database: &mut Database, volume_id: i64, path: &str, is_directory: bool) {
        let name = Path::new(path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        let entry = FileEntry::new(volume_id, name, path.to_string(), is_directory);

        let entries = vec![entry];
        database.insert_files_batch(&entries).expect("Failed to insert file");
    }

    #[test]
    fn test_prune_removes_missing_files() {
        let (mut database, temp_dir) = setup_test_database();
        let volume_id = insert_test_volume(&database);

        // Create a real file
        let existing_file_path = temp_dir.path().join("existing.txt");
        File::create(&existing_file_path).expect("Failed to create file");

        // Add entries to the database
        insert_test_file(&mut database, volume_id, &existing_file_path.to_string_lossy(), false);
        insert_test_file(
            &mut database,
            volume_id,
            &temp_dir.path().join("missing.txt").to_string_lossy(),
            false,
        );

        // Also add the temp dir itself as an existing directory
        insert_test_file(&mut database, volume_id, &temp_dir.path().to_string_lossy(), true);

        let stats = prune_missing_entries(&database, false).expect("Prune failed");

        assert_eq!(stats.files_removed, 1);
        assert_eq!(stats.directories_removed, 0);
    }

    #[test]
    fn test_prune_removes_missing_directories() {
        let (mut database, temp_dir) = setup_test_database();
        let volume_id = insert_test_volume(&database);

        // Create a real directory
        let existing_dir_path = temp_dir.path().join("existing_dir");
        fs::create_dir(&existing_dir_path).expect("Failed to create directory");

        // Add entries to the database
        insert_test_file(&mut database, volume_id, &existing_dir_path.to_string_lossy(), true);
        insert_test_file(
            &mut database,
            volume_id,
            &temp_dir.path().join("missing_dir").to_string_lossy(),
            true,
        );

        let stats = prune_missing_entries(&database, false).expect("Prune failed");

        assert_eq!(stats.directories_removed, 1);
    }

    #[test]
    fn test_prune_skips_children_of_missing_directories() {
        let (mut database, _temp_dir) = setup_test_database();
        let volume_id = insert_test_volume(&database);

        // Add a missing parent directory and several children
        let missing_parent = "Z:\\nonexistent_parent";
        insert_test_file(&mut database, volume_id, missing_parent, true);
        insert_test_file(&mut database, volume_id, "Z:\\nonexistent_parent\\child1.txt", false);
        insert_test_file(&mut database, volume_id, "Z:\\nonexistent_parent\\child2.txt", false);
        insert_test_file(&mut database, volume_id, "Z:\\nonexistent_parent\\subdir", true);
        insert_test_file(
            &mut database,
            volume_id,
            "Z:\\nonexistent_parent\\subdir\\nested.txt",
            false,
        );

        let stats = prune_missing_entries(&database, false).expect("Prune failed");

        // All entries should be removed
        assert_eq!(stats.directories_removed, 2); // parent + subdir
        assert_eq!(stats.files_removed, 3); // child1, child2, nested

        // Most checks should be skipped due to missing parent
        assert!(
            stats.checks_skipped >= 3,
            "Expected at least 3 skipped checks, got {}",
            stats.checks_skipped
        );
    }

    #[test]
    fn test_prune_empty_database() {
        let (database, _temp_dir) = setup_test_database();

        let stats = prune_missing_entries(&database, false).expect("Prune failed");

        assert_eq!(stats.files_removed, 0);
        assert_eq!(stats.directories_removed, 0);
        assert_eq!(stats.entries_checked, 0);
    }

    #[test]
    fn test_is_parent_missing() {
        let mut missing: HashSet<String> = HashSet::new();
        missing.insert("C:\\parent".to_string());

        assert!(is_parent_missing("C:\\parent\\child.txt", &missing));
        assert!(is_parent_missing("C:\\parent\\sub\\deep.txt", &missing));
        assert!(!is_parent_missing("C:\\other\\file.txt", &missing));
        assert!(!is_parent_missing("C:\\parent", &missing)); // The path itself, not its parent
    }

    #[test]
    fn test_prune_stats_default() {
        let stats = PruneStats::default();

        assert_eq!(stats.files_removed, 0);
        assert_eq!(stats.directories_removed, 0);
        assert_eq!(stats.entries_checked, 0);
        assert_eq!(stats.checks_skipped, 0);
    }

    #[test]
    fn test_extract_volume_key_drive_letter() {
        assert_eq!(extract_volume_key("C:\\Users\\test.txt"), "C:");
        assert_eq!(extract_volume_key("D:\\folder\\file.txt"), "D:");
        assert_eq!(extract_volume_key("c:\\lowercase"), "C:");
    }

    #[test]
    fn test_extract_volume_key_unc_path() {
        assert_eq!(extract_volume_key("\\\\server\\share\\file.txt"), "\\\\server\\share");
        assert_eq!(extract_volume_key("\\\\nas\\data\\docs"), "\\\\nas\\data");
    }

    #[test]
    fn test_group_entries_by_volume() {
        let entries = vec![
            EntryToCheck {
                id: 1,
                full_path: "C:\\file1.txt".to_string(),
                is_directory: false,
            },
            EntryToCheck {
                id: 2,
                full_path: "C:\\file2.txt".to_string(),
                is_directory: false,
            },
            EntryToCheck {
                id: 3,
                full_path: "D:\\file3.txt".to_string(),
                is_directory: false,
            },
        ];

        let grouped = group_entries_by_volume(entries);

        assert_eq!(grouped.len(), 2);
        assert_eq!(grouped.get("C:").map(|v| v.len()), Some(2));
        assert_eq!(grouped.get("D:").map(|v| v.len()), Some(1));
    }

    #[test]
    fn test_prune_parallel_matches_sequential() {
        let (mut database, temp_dir) = setup_test_database();
        let volume_id = insert_test_volume(&database);

        // Create some real files
        let existing_file = temp_dir.path().join("existing.txt");
        File::create(&existing_file).expect("Failed to create file");

        // Add entries
        insert_test_file(&mut database, volume_id, &existing_file.to_string_lossy(), false);
        insert_test_file(&mut database, volume_id, &temp_dir.path().to_string_lossy(), true);
        insert_test_file(
            &mut database,
            volume_id,
            &temp_dir.path().join("missing.txt").to_string_lossy(),
            false,
        );

        let stats = prune_missing_entries_parallel(&database, false).expect("Parallel prune failed");

        assert_eq!(stats.files_removed, 1);
        assert_eq!(stats.directories_removed, 0);
    }

    #[test]
    fn test_prune_volume_entries() {
        let (mut database, temp_dir) = setup_test_database();
        let volume_id = insert_test_volume(&database);

        // Create a real file
        let existing_file = temp_dir.path().join("existing.txt");
        File::create(&existing_file).expect("Failed to create file");

        // Add entries
        insert_test_file(&mut database, volume_id, &existing_file.to_string_lossy(), false);
        insert_test_file(&mut database, volume_id, &temp_dir.path().to_string_lossy(), true);
        insert_test_file(
            &mut database,
            volume_id,
            &temp_dir.path().join("missing.txt").to_string_lossy(),
            false,
        );

        let stats = prune_volume_entries(&database, volume_id, false).expect("Volume prune failed");

        assert_eq!(stats.files_removed, 1);
        assert_eq!(stats.directories_removed, 0);
    }
}
