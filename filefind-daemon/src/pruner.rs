//! Database pruning functionality.
//!
//! This module provides functions for removing database entries
//! that reference files or directories that no longer exist on disk.
//! It optimizes by first checking parent directories to avoid
//! unnecessary filesystem queries for children of missing directories.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result};
use filefind::Database;
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
}

/// Prune database entries for files and directories that no longer exist.
///
/// This function efficiently removes stale entries by:
/// 1. First checking directories (sorted by path length, shortest first)
/// 2. Tracking which directories are known to be missing
/// 3. For files, skipping filesystem checks if their parent directory is missing
///
/// # Arguments
/// * `database` - The database to prune
/// * `verbose` - Whether to print verbose progress information
///
/// # Errors
/// Returns an error if database operations fail.
pub fn prune_missing_entries(database: &Database, verbose: bool) -> Result<PruneStats> {
    let mut stats = PruneStats::default();

    // Track directories that are known to be missing
    let mut missing_directories: HashSet<String> = HashSet::new();
    // Track directories that are known to exist (cache for efficiency)
    let mut existing_directories: HashSet<String> = HashSet::new();

    // First pass: Check all directories (sorted by path length, shortest first)
    // This ensures we check parent directories before children
    let directories = get_all_directories_sorted(database)?;
    let directory_count = directories.len();

    if verbose {
        info!("Checking {} directories...", directory_count);
    }

    let mut directories_to_delete: Vec<i64> = Vec::new();

    for entry in directories {
        stats.entries_checked += 1;

        // Check if any parent directory is known to be missing
        if is_parent_missing(&entry.full_path, &missing_directories) {
            trace!("Skipping {} - parent directory is missing", entry.full_path);
            stats.checks_skipped += 1;
            directories_to_delete.push(entry.id);
            missing_directories.insert(entry.full_path);
            continue;
        }

        // Check if the directory exists on disk
        let path = Path::new(&entry.full_path);
        if path.exists() {
            existing_directories.insert(entry.full_path);
        } else {
            debug!("Directory no longer exists: {}", entry.full_path);
            directories_to_delete.push(entry.id);
            missing_directories.insert(entry.full_path);
        }
    }

    // Delete missing directories from database
    if !directories_to_delete.is_empty() {
        stats.directories_removed = delete_entries_by_ids(database, &directories_to_delete)?;
        if verbose {
            info!("Removed {} directories", stats.directories_removed);
        }
    }

    // Second pass: Check all files
    let files = get_all_files(database)?;
    let file_count = files.len();

    if verbose {
        info!("Checking {} files...", file_count);
    }

    let mut files_to_delete: Vec<i64> = Vec::new();

    for entry in files {
        stats.entries_checked += 1;

        // Check if the parent directory is known to be missing
        if is_parent_missing(&entry.full_path, &missing_directories) {
            trace!("Skipping {} - parent directory is missing", entry.full_path);
            stats.checks_skipped += 1;
            files_to_delete.push(entry.id);
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
            stats.checks_skipped += 1;
            files_to_delete.push(entry.id);
            continue;
        }

        // Check if the file exists on disk
        let path = Path::new(&entry.full_path);
        if !path.exists() {
            debug!("File no longer exists: {}", entry.full_path);
            files_to_delete.push(entry.id);
        }
    }

    // Delete missing files from database
    if !files_to_delete.is_empty() {
        stats.files_removed = delete_entries_by_ids(database, &files_to_delete)?;
        if verbose {
            info!("Removed {} files", stats.files_removed);
        }
    }

    info!(
        "Prune complete: checked {} entries, removed {} files and {} directories ({} checks skipped)",
        stats.entries_checked, stats.files_removed, stats.directories_removed, stats.checks_skipped
    );

    Ok(stats)
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

/// Get all directories from the database, sorted by path length (shortest first).
fn get_all_directories_sorted(database: &Database) -> Result<Vec<EntryToCheck>> {
    let connection = database.connection();

    let mut statement = connection
        .prepare(
            r"
            SELECT id, full_path
            FROM files
            WHERE is_directory = 1
            ORDER BY LENGTH(full_path) ASC
            ",
        )
        .context("Failed to prepare directory query")?;

    let entries = statement
        .query_map([], |row| {
            Ok(EntryToCheck {
                id: row.get(0)?,
                full_path: row.get(1)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to query directories")?;

    Ok(entries)
}

/// Get all files from the database.
fn get_all_files(database: &Database) -> Result<Vec<EntryToCheck>> {
    let connection = database.connection();

    let mut statement = connection
        .prepare(
            r"
            SELECT id, full_path
            FROM files
            WHERE is_directory = 0
            ",
        )
        .context("Failed to prepare file query")?;

    let entries = statement
        .query_map([], |row| {
            Ok(EntryToCheck {
                id: row.get(0)?,
                full_path: row.get(1)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to query files")?;

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
}
