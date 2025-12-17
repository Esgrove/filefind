//! `SQLite` database operations for filefind.
//!
//! Handles storing and querying the file index.

use std::path::Path;
use std::time::SystemTime;

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};
use tracing::{debug, info};

use crate::types::{FileEntry, IndexedVolume, VolumeType};

/// Database wrapper for file index operations.
pub struct Database {
    connection: Connection,
}

/// Statistics about the database contents.
#[derive(Debug, Default, Clone)]
pub struct DatabaseStats {
    /// Total number of indexed files.
    pub total_files: u64,
    /// Total number of indexed directories.
    pub total_directories: u64,
    /// Number of indexed volumes.
    pub volume_count: u64,
    /// Total size of all indexed files in bytes.
    pub total_size: u64,
}

impl Database {
    /// Open or create a database at the specified path.
    ///
    /// # Errors
    /// Returns an error if the database cannot be opened or initialized.
    pub fn open(path: &Path) -> Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create database directory: {}", parent.display()))?;
        }

        let connection =
            Connection::open(path).with_context(|| format!("Failed to open database: {}", path.display()))?;

        let database = Self { connection };
        database.initialize()?;

        Ok(database)
    }

    /// Open an in-memory database (useful for testing).
    ///
    /// # Errors
    /// Returns an error if the database cannot be created.
    pub fn open_in_memory() -> Result<Self> {
        let connection = Connection::open_in_memory().context("Failed to open in-memory database")?;

        let database = Self { connection };
        database.initialize()?;

        Ok(database)
    }

    /// Initialize the database schema.
    fn initialize(&self) -> Result<()> {
        self.connection
            .execute_batch(
                r"
                -- Indexed volumes/drives
                CREATE TABLE IF NOT EXISTS volumes (
                    id INTEGER PRIMARY KEY,
                    serial_number TEXT NOT NULL UNIQUE,
                    label TEXT,
                    mount_point TEXT NOT NULL,
                    volume_type TEXT NOT NULL,
                    last_scan_time INTEGER,
                    last_usn INTEGER,
                    is_online INTEGER NOT NULL DEFAULT 1
                );

                -- Indexed files and directories
                CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY,
                    volume_id INTEGER NOT NULL,
                    parent_id INTEGER,
                    name TEXT NOT NULL,
                    full_path TEXT NOT NULL,
                    is_directory INTEGER NOT NULL,
                    size INTEGER NOT NULL DEFAULT 0,
                    created_time INTEGER,
                    modified_time INTEGER,
                    mft_reference INTEGER,
                    FOREIGN KEY (volume_id) REFERENCES volumes(id) ON DELETE CASCADE
                );

                -- Indexes for fast searching
                CREATE INDEX IF NOT EXISTS idx_files_name ON files(name COLLATE NOCASE);
                CREATE INDEX IF NOT EXISTS idx_files_volume ON files(volume_id);
                CREATE INDEX IF NOT EXISTS idx_files_parent ON files(parent_id);
                CREATE INDEX IF NOT EXISTS idx_files_path ON files(full_path);
                CREATE INDEX IF NOT EXISTS idx_files_is_directory ON files(is_directory);
                CREATE INDEX IF NOT EXISTS idx_files_modified ON files(modified_time);

                -- Enable foreign keys
                PRAGMA foreign_keys = ON;

                -- Performance optimizations
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = NORMAL;
                PRAGMA cache_size = -64000;
                ",
            )
            .context("Failed to initialize database schema")?;

        debug!("Database schema initialized");
        Ok(())
    }

    /// Add or update a volume in the database.
    ///
    /// # Errors
    /// Returns an error if the database operation fails.
    pub fn upsert_volume(&self, volume: &IndexedVolume) -> Result<i64> {
        let volume_type_str = volume.volume_type.as_str();

        self.connection
            .execute(
                r"
                INSERT INTO volumes (serial_number, label, mount_point, volume_type, last_scan_time, last_usn, is_online)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                ON CONFLICT(serial_number) DO UPDATE SET
                    label = excluded.label,
                    mount_point = excluded.mount_point,
                    volume_type = excluded.volume_type,
                    last_scan_time = excluded.last_scan_time,
                    last_usn = excluded.last_usn,
                    is_online = excluded.is_online
                ",
                params![
                    volume.serial_number,
                    volume.label,
                    volume.mount_point,
                    volume_type_str,
                    volume.last_scan_time.map(system_time_to_unix),
                    volume.last_usn,
                    volume.is_online,
                ],
            )
            .context("Failed to upsert volume")?;

        let volume_id = self.connection.last_insert_rowid();
        Ok(volume_id)
    }

    /// Get a volume by its serial number.
    ///
    /// # Errors
    /// Returns an error if the database operation fails.
    pub fn get_volume_by_serial(&self, serial_number: &str) -> Result<Option<IndexedVolume>> {
        let mut statement = self.connection.prepare(
            r"
            SELECT id, serial_number, label, mount_point, volume_type, last_scan_time, last_usn, is_online
            FROM volumes
            WHERE serial_number = ?1
            ",
        )?;

        let volume = statement
            .query_row(params![serial_number], |row| {
                Ok(IndexedVolume {
                    id: Some(row.get(0)?),
                    serial_number: row.get(1)?,
                    label: row.get(2)?,
                    mount_point: row.get(3)?,
                    volume_type: VolumeType::parse(row.get::<_, String>(4)?.as_str()),
                    last_scan_time: row.get::<_, Option<i64>>(5)?.map(unix_to_system_time),
                    last_usn: row.get(6)?,
                    is_online: row.get(7)?,
                })
            })
            .optional()
            .context("Failed to query volume")?;

        Ok(volume)
    }

    /// Get all indexed volumes.
    ///
    /// # Errors
    /// Returns an error if the database operation fails.
    pub fn get_all_volumes(&self) -> Result<Vec<IndexedVolume>> {
        let mut statement = self.connection.prepare(
            r"
            SELECT id, serial_number, label, mount_point, volume_type, last_scan_time, last_usn, is_online
            FROM volumes
            ",
        )?;

        let volumes = statement
            .query_map([], |row| {
                Ok(IndexedVolume {
                    id: Some(row.get(0)?),
                    serial_number: row.get(1)?,
                    label: row.get(2)?,
                    mount_point: row.get(3)?,
                    volume_type: VolumeType::parse(row.get::<_, String>(4)?.as_str()),
                    last_scan_time: row.get::<_, Option<i64>>(5)?.map(unix_to_system_time),
                    last_usn: row.get(6)?,
                    is_online: row.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to query volumes")?;

        Ok(volumes)
    }

    /// Insert a file entry into the database.
    ///
    /// # Errors
    /// Returns an error if the database operation fails.
    pub fn insert_file(&self, file: &FileEntry) -> Result<i64> {
        self.connection
            .execute(
                r"
                INSERT INTO files (volume_id, parent_id, name, full_path, is_directory, size, created_time, modified_time, mft_reference)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                ",
                params![
                    file.volume_id,
                    file.parent_id,
                    file.name,
                    file.full_path,
                    file.is_directory,
                    file.size,
                    file.created_time.map(system_time_to_unix),
                    file.modified_time.map(system_time_to_unix),
                    file.mft_reference,
                ],
            )
            .context("Failed to insert file")?;

        Ok(self.connection.last_insert_rowid())
    }

    /// Insert multiple file entries in a single transaction.
    ///
    /// # Errors
    /// Returns an error if the database operation fails.
    pub fn insert_files_batch(&mut self, files: &[FileEntry]) -> Result<usize> {
        let transaction = self.connection.transaction()?;

        {
            let mut statement = transaction.prepare(
                r"
                INSERT INTO files (volume_id, parent_id, name, full_path, is_directory, size, created_time, modified_time, mft_reference)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                ",
            )?;

            for file in files {
                statement.execute(params![
                    file.volume_id,
                    file.parent_id,
                    file.name,
                    file.full_path,
                    file.is_directory,
                    file.size,
                    file.created_time.map(system_time_to_unix),
                    file.modified_time.map(system_time_to_unix),
                    file.mft_reference,
                ])?;
            }
        }

        transaction.commit()?;
        info!("Inserted {} files in batch", files.len());
        Ok(files.len())
    }

    /// Delete a file entry by its path.
    ///
    /// # Errors
    /// Returns an error if the database operation fails.
    pub fn delete_file_by_path(&self, path: &str) -> Result<bool> {
        let rows_affected = self
            .connection
            .execute("DELETE FROM files WHERE full_path = ?1", params![path])
            .context("Failed to delete file")?;

        Ok(rows_affected > 0)
    }

    /// Delete all files for a specific volume.
    ///
    /// # Errors
    /// Returns an error if the database operation fails.
    pub fn delete_files_for_volume(&self, volume_id: i64) -> Result<usize> {
        let rows_affected = self
            .connection
            .execute("DELETE FROM files WHERE volume_id = ?1", params![volume_id])
            .context("Failed to delete files for volume")?;

        info!("Deleted {} files for volume {}", rows_affected, volume_id);
        Ok(rows_affected)
    }

    /// Search for files by name pattern (case-insensitive).
    ///
    /// # Errors
    /// Returns an error if the database operation fails.
    pub fn search_by_name(&self, pattern: &str, limit: usize) -> Result<Vec<FileEntry>> {
        let search_pattern = format!("%{pattern}%");

        let mut statement = self.connection.prepare(
            r"
            SELECT id, volume_id, parent_id, name, full_path, is_directory, size, created_time, modified_time, mft_reference
            FROM files
            WHERE name LIKE ?1
            ORDER BY name
            LIMIT ?2
            ",
        )?;

        let files = statement
            .query_map(params![search_pattern, limit], row_to_file_entry)?
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to search files")?;

        Ok(files)
    }

    /// Search for files by exact name (case-insensitive).
    ///
    /// # Errors
    /// Returns an error if the database operation fails.
    pub fn search_by_exact_name(&self, name: &str, limit: usize) -> Result<Vec<FileEntry>> {
        let mut statement = self.connection.prepare(
            r"
            SELECT id, volume_id, parent_id, name, full_path, is_directory, size, created_time, modified_time, mft_reference
            FROM files
            WHERE name = ?1 COLLATE NOCASE
            ORDER BY full_path
            LIMIT ?2
            ",
        )?;

        let files = statement
            .query_map(params![name, limit], row_to_file_entry)?
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to search files")?;

        Ok(files)
    }

    /// Search for files by glob pattern.
    ///
    /// Converts glob pattern to SQL LIKE pattern:
    /// - `*` becomes `%`
    /// - `?` becomes `_`
    ///
    /// # Errors
    /// Returns an error if the database operation fails.
    pub fn search_by_glob(&self, pattern: &str, limit: usize) -> Result<Vec<FileEntry>> {
        let sql_pattern = glob_to_sql_like(pattern);

        let mut statement = self.connection.prepare(
            r"
            SELECT id, volume_id, parent_id, name, full_path, is_directory, size, created_time, modified_time, mft_reference
            FROM files
            WHERE name LIKE ?1 ESCAPE '\'
            ORDER BY name
            LIMIT ?2
            ",
        )?;

        let files = statement
            .query_map(params![sql_pattern, limit], row_to_file_entry)?
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to search files by glob")?;

        Ok(files)
    }

    /// Search for files by path pattern.
    ///
    /// # Errors
    /// Returns an error if the database operation fails.
    pub fn search_by_path(&self, pattern: &str, limit: usize) -> Result<Vec<FileEntry>> {
        let search_pattern = format!("%{pattern}%");

        let mut statement = self.connection.prepare(
            r"
            SELECT id, volume_id, parent_id, name, full_path, is_directory, size, created_time, modified_time, mft_reference
            FROM files
            WHERE full_path LIKE ?1
            ORDER BY full_path
            LIMIT ?2
            ",
        )?;

        let files = statement
            .query_map(params![search_pattern, limit], row_to_file_entry)?
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to search files by path")?;

        Ok(files)
    }

    /// Get database statistics.
    ///
    /// # Errors
    /// Returns an error if the database operation fails.
    pub fn get_stats(&self) -> Result<DatabaseStats> {
        let total_files: u64 =
            self.connection
                .query_row("SELECT COUNT(*) FROM files WHERE is_directory = 0", [], |row| {
                    row.get(0)
                })?;

        let total_directories: u64 =
            self.connection
                .query_row("SELECT COUNT(*) FROM files WHERE is_directory = 1", [], |row| {
                    row.get(0)
                })?;

        let volume_count: u64 = self
            .connection
            .query_row("SELECT COUNT(*) FROM volumes", [], |row| row.get(0))?;

        let total_size: u64 = self.connection.query_row(
            "SELECT COALESCE(SUM(size), 0) FROM files WHERE is_directory = 0",
            [],
            |row| row.get(0),
        )?;

        Ok(DatabaseStats {
            total_files,
            total_directories,
            volume_count,
            total_size,
        })
    }

    /// Update the last USN value for a volume.
    ///
    /// # Errors
    /// Returns an error if the database operation fails.
    pub fn update_volume_usn(&self, volume_id: i64, usn: i64) -> Result<()> {
        self.connection
            .execute(
                "UPDATE volumes SET last_usn = ?1, last_scan_time = ?2 WHERE id = ?3",
                params![usn, system_time_to_unix(SystemTime::now()), volume_id],
            )
            .context("Failed to update volume USN")?;

        Ok(())
    }

    /// Mark a volume as online or offline.
    ///
    /// # Errors
    /// Returns an error if the database operation fails.
    pub fn set_volume_online(&self, volume_id: i64, is_online: bool) -> Result<()> {
        self.connection
            .execute(
                "UPDATE volumes SET is_online = ?1 WHERE id = ?2",
                params![is_online, volume_id],
            )
            .context("Failed to update volume online status")?;

        Ok(())
    }

    /// Get the underlying connection for advanced operations.
    #[must_use]
    pub const fn connection(&self) -> &Connection {
        &self.connection
    }
}

/// Convert a database row to a `FileEntry`.
fn row_to_file_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<FileEntry> {
    Ok(FileEntry {
        id: Some(row.get(0)?),
        volume_id: row.get(1)?,
        parent_id: row.get(2)?,
        name: row.get(3)?,
        full_path: row.get(4)?,
        is_directory: row.get(5)?,
        size: row.get(6)?,
        created_time: row.get::<_, Option<i64>>(7)?.map(unix_to_system_time),
        modified_time: row.get::<_, Option<i64>>(8)?.map(unix_to_system_time),
        mft_reference: row.get(9)?,
    })
}

/// Convert a `SystemTime` to a Unix timestamp.
#[allow(clippy::cast_possible_wrap)]
fn system_time_to_unix(time: SystemTime) -> i64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

/// Convert a Unix timestamp to a `SystemTime`.
fn unix_to_system_time(timestamp: i64) -> SystemTime {
    SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(timestamp as u64)
}

/// Convert a glob pattern to a SQL LIKE pattern.
fn glob_to_sql_like(pattern: &str) -> String {
    let mut result = String::with_capacity(pattern.len() * 2);

    for character in pattern.chars() {
        match character {
            '*' => result.push('%'),
            '?' => result.push('_'),
            '%' => result.push_str("\\%"),
            '_' => result.push_str("\\_"),
            '\\' => result.push_str("\\\\"),
            _ => result.push(character),
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_in_memory() {
        let database = Database::open_in_memory().unwrap();
        let stats = database.get_stats().unwrap();
        assert_eq!(stats.total_files, 0);
        assert_eq!(stats.volume_count, 0);
    }

    #[test]
    fn test_insert_and_search_file() {
        let database = Database::open_in_memory().unwrap();

        // Insert a volume first
        let volume = IndexedVolume {
            id: None,
            serial_number: "TEST123".to_string(),
            label: Some("Test Volume".to_string()),
            mount_point: "C:".to_string(),
            volume_type: VolumeType::Ntfs,
            last_scan_time: None,
            last_usn: None,
            is_online: true,
        };
        let volume_id = database.upsert_volume(&volume).unwrap();

        // Insert a file
        let file = FileEntry {
            id: None,
            volume_id,
            parent_id: None,
            name: "test_document.pdf".to_string(),
            full_path: "C:\\Documents\\test_document.pdf".to_string(),
            is_directory: false,
            size: 1024,
            created_time: Some(SystemTime::now()),
            modified_time: Some(SystemTime::now()),
            mft_reference: None,
        };
        database.insert_file(&file).unwrap();

        // Search for the file
        let results = database.search_by_name("document", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "test_document.pdf");
    }

    #[test]
    fn test_glob_to_sql_like() {
        assert_eq!(glob_to_sql_like("*.txt"), "%.txt");
        assert_eq!(glob_to_sql_like("file?.txt"), "file_.txt");
        assert_eq!(glob_to_sql_like("test%file"), "test\\%file");
        assert_eq!(glob_to_sql_like("test_file"), "test\\_file");
    }

    #[test]
    fn test_search_by_glob() {
        let database = Database::open_in_memory().unwrap();

        let volume = IndexedVolume {
            id: None,
            serial_number: "TEST456".to_string(),
            label: None,
            mount_point: "D:".to_string(),
            volume_type: VolumeType::Ntfs,
            last_scan_time: None,
            last_usn: None,
            is_online: true,
        };
        let volume_id = database.upsert_volume(&volume).unwrap();

        // Insert test files
        for name in ["report.txt", "report.pdf", "data.txt", "image.png"] {
            let file = FileEntry {
                id: None,
                volume_id,
                parent_id: None,
                name: name.to_string(),
                full_path: format!("D:\\{name}"),
                is_directory: false,
                size: 100,
                created_time: None,
                modified_time: None,
                mft_reference: None,
            };
            database.insert_file(&file).unwrap();
        }

        // Search with glob pattern
        let results = database.search_by_glob("*.txt", 10).unwrap();
        assert_eq!(results.len(), 2);

        let results = database.search_by_glob("report.*", 10).unwrap();
        assert_eq!(results.len(), 2);

        let results = database.search_by_glob("data.???", 10).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_database_stats() {
        let database = Database::open_in_memory().unwrap();

        let volume = IndexedVolume {
            id: None,
            serial_number: "STATS123".to_string(),
            label: None,
            mount_point: "E:".to_string(),
            volume_type: VolumeType::Ntfs,
            last_scan_time: None,
            last_usn: None,
            is_online: true,
        };
        let volume_id = database.upsert_volume(&volume).unwrap();

        // Insert files and directories
        let file = FileEntry {
            id: None,
            volume_id,
            parent_id: None,
            name: "file.txt".to_string(),
            full_path: "E:\\file.txt".to_string(),
            is_directory: false,
            size: 1000,
            created_time: None,
            modified_time: None,
            mft_reference: None,
        };
        database.insert_file(&file).unwrap();

        let directory = FileEntry {
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
        database.insert_file(&directory).unwrap();

        let stats = database.get_stats().unwrap();
        assert_eq!(stats.total_files, 1);
        assert_eq!(stats.total_directories, 1);
        assert_eq!(stats.volume_count, 1);
        assert_eq!(stats.total_size, 1000);
    }
}
