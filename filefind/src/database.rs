//! `SQLite` database operations for filefind.
//!
//! Handles storing and querying the file index.

use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{Context, Result};
use regex::Regex;
use rusqlite::functions::FunctionFlags;
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

/// Statistics about a single volume.
#[derive(Debug, Default, Clone)]
pub struct VolumeStats {
    /// Total number of indexed files on this volume.
    pub file_count: u64,
    /// Total number of indexed directories on this volume.
    pub directory_count: u64,
    /// Total size of all indexed files on this volume in bytes.
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
        self.register_regexp_function()?;

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
                CREATE UNIQUE INDEX IF NOT EXISTS idx_files_path ON files(full_path);
                CREATE INDEX IF NOT EXISTS idx_files_name ON files(name COLLATE NOCASE);
                CREATE INDEX IF NOT EXISTS idx_files_volume ON files(volume_id);
                CREATE INDEX IF NOT EXISTS idx_files_parent ON files(parent_id);
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

    /// Register the REGEXP function for regex searches.
    ///
    /// This enables SQL queries like: `SELECT * FROM files WHERE name REGEXP 'pattern'`
    fn register_regexp_function(&self) -> Result<()> {
        self.connection.create_scalar_function(
            "regexp",
            2,
            FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
            |ctx| {
                // Get the pattern and compile/cache it
                let pattern: Arc<Regex> = ctx.get_or_create_aux(0, |vr| {
                    let pattern_str = vr
                        .as_str()
                        .map_err(|e| rusqlite::Error::UserFunctionError(Box::new(e)))?;
                    Regex::new(pattern_str).map_err(|e| rusqlite::Error::UserFunctionError(Box::new(e)))
                })?;

                // Get the text to match against
                let text = ctx
                    .get_raw(1)
                    .as_str()
                    .map_err(|e| rusqlite::Error::UserFunctionError(Box::new(e)))?;

                Ok(pattern.is_match(text))
            },
        )?;

        debug!("Registered REGEXP function");
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

        // last_insert_rowid() returns 0 when ON CONFLICT triggers an UPDATE,
        // so we need to query for the actual ID by serial number
        let volume_id: i64 = self
            .connection
            .query_row(
                "SELECT id FROM volumes WHERE serial_number = ?1",
                params![volume.serial_number],
                |row| row.get(0),
            )
            .context("Failed to get volume ID after upsert")?;

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
                    last_scan_time: row.get::<_, Option<i64>>(5)?.and_then(unix_to_system_time),
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
                    last_scan_time: row.get::<_, Option<i64>>(5)?.and_then(unix_to_system_time),
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
                ON CONFLICT(full_path) DO UPDATE SET
                    volume_id = excluded.volume_id,
                    parent_id = excluded.parent_id,
                    name = excluded.name,
                    is_directory = excluded.is_directory,
                    size = excluded.size,
                    created_time = excluded.created_time,
                    modified_time = excluded.modified_time,
                    mft_reference = excluded.mft_reference
                ",
                params![
                    file.volume_id,
                    file.parent_id,
                    file.name,
                    file.full_path,
                    file.is_directory,
                    i64::try_from(file.size).unwrap_or(i64::MAX),
                    file.created_time.map(system_time_to_unix),
                    file.modified_time.map(system_time_to_unix),
                    file.mft_reference.map(|v| i64::try_from(v).unwrap_or(i64::MAX)),
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
                ON CONFLICT(full_path) DO UPDATE SET
                    volume_id = excluded.volume_id,
                    parent_id = excluded.parent_id,
                    name = excluded.name,
                    is_directory = excluded.is_directory,
                    size = excluded.size,
                    created_time = excluded.created_time,
                    modified_time = excluded.modified_time,
                    mft_reference = excluded.mft_reference
                ",
            )?;

            for file in files {
                statement.execute(params![
                    file.volume_id,
                    file.parent_id,
                    file.name,
                    file.full_path,
                    file.is_directory,
                    i64::try_from(file.size).unwrap_or(i64::MAX),
                    file.created_time.map(system_time_to_unix),
                    file.modified_time.map(system_time_to_unix),
                    file.mft_reference.map(|v| i64::try_from(v).unwrap_or(i64::MAX)),
                ])?;
            }
        }

        transaction.commit()?;
        debug!("Inserted {} files to database", files.len());
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
            .query_map(
                params![search_pattern, i64::try_from(limit).unwrap_or(i64::MAX)],
                row_to_file_entry,
            )?
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to search files")?;

        Ok(files)
    }

    /// Search for files matching ALL patterns (AND mode, case-insensitive).
    ///
    /// Returns files where the name contains all of the given patterns.
    ///
    /// # Errors
    /// Returns an error if the database operation fails.
    pub fn search_by_names_all(&self, patterns: &[String], limit: usize) -> Result<Vec<FileEntry>> {
        if patterns.is_empty() {
            return Ok(Vec::new());
        }

        // Build WHERE clause with AND for each pattern
        let where_clauses: Vec<String> = (1..=patterns.len()).map(|i| format!("name LIKE ?{i}")).collect();
        let where_clause = where_clauses.join(" AND ");

        let sql = format!(
            r"
            SELECT id, volume_id, parent_id, name, full_path, is_directory, size, created_time, modified_time, mft_reference
            FROM files
            WHERE {where_clause}
            ORDER BY name
            LIMIT ?{}
            ",
            patterns.len() + 1
        );

        let mut statement = self.connection.prepare(&sql)?;

        // Bind all pattern parameters
        let search_patterns: Vec<String> = patterns.iter().map(|p| format!("%{p}%")).collect();
        let mut params_vec: Vec<&dyn rusqlite::ToSql> =
            search_patterns.iter().map(|p| p as &dyn rusqlite::ToSql).collect();
        let limit_value = i64::try_from(limit).unwrap_or(i64::MAX);
        params_vec.push(&limit_value);

        let files = statement
            .query_map(params_vec.as_slice(), row_to_file_entry)?
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
            .query_map(
                params![name, i64::try_from(limit).unwrap_or(i64::MAX)],
                row_to_file_entry,
            )?
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
            .query_map(
                params![sql_pattern, i64::try_from(limit).unwrap_or(i64::MAX)],
                row_to_file_entry,
            )?
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to search files by glob")?;

        Ok(files)
    }

    /// Search for files matching ALL glob patterns (AND mode).
    ///
    /// Returns files where the name matches all of the given glob patterns.
    ///
    /// # Errors
    /// Returns an error if the database operation fails.
    pub fn search_by_globs_all(&self, patterns: &[String], limit: usize) -> Result<Vec<FileEntry>> {
        if patterns.is_empty() {
            return Ok(Vec::new());
        }

        // Build WHERE clause with AND for each pattern
        let where_clauses: Vec<String> = (1..=patterns.len())
            .map(|i| format!("name LIKE ?{i} ESCAPE '\\'"))
            .collect();
        let where_clause = where_clauses.join(" AND ");

        let sql = format!(
            r"
            SELECT id, volume_id, parent_id, name, full_path, is_directory, size, created_time, modified_time, mft_reference
            FROM files
            WHERE {where_clause}
            ORDER BY name
            LIMIT ?{}
            ",
            patterns.len() + 1
        );

        let mut statement = self.connection.prepare(&sql)?;

        // Bind all pattern parameters
        let sql_patterns: Vec<String> = patterns.iter().map(|p| glob_to_sql_like(p)).collect();
        let mut params_vec: Vec<&dyn rusqlite::ToSql> =
            sql_patterns.iter().map(|p| p as &dyn rusqlite::ToSql).collect();
        let limit_value = i64::try_from(limit).unwrap_or(i64::MAX);
        params_vec.push(&limit_value);

        let files = statement
            .query_map(params_vec.as_slice(), row_to_file_entry)?
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to search files by glob")?;

        Ok(files)
    }

    /// Search for files by regex pattern.
    ///
    /// Uses `SQLite`'s `REGEXP` function (registered at database initialization).
    /// The regex is matched against the file name only, not the full path.
    ///
    /// # Arguments
    /// * `pattern` - A regular expression pattern (Rust regex syntax)
    /// * `case_sensitive` - Whether the match should be case-sensitive
    /// * `limit` - Maximum number of results to return
    ///
    /// # Errors
    /// Returns an error if the regex pattern is invalid or if the database operation fails.
    pub fn search_by_regex(&self, pattern: &str, case_sensitive: bool, limit: usize) -> Result<Vec<FileEntry>> {
        // Validate the regex pattern before querying
        Regex::new(pattern).with_context(|| format!("Invalid regex pattern: {pattern}"))?;

        // Prepend case-insensitive flag if needed
        let effective_pattern = if case_sensitive {
            pattern.to_string()
        } else {
            format!("(?i){pattern}")
        };

        let mut statement = self.connection.prepare(
            r"
            SELECT id, volume_id, parent_id, name, full_path, is_directory, size, created_time, modified_time, mft_reference
            FROM files
            WHERE name REGEXP ?1
            ORDER BY name
            LIMIT ?2
            ",
        )?;

        let files = statement
            .query_map(
                params![effective_pattern, i64::try_from(limit).unwrap_or(i64::MAX)],
                row_to_file_entry,
            )?
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to search files by regex")?;

        Ok(files)
    }

    /// Search for files matching ALL regex patterns (AND mode).
    ///
    /// Returns files where the name matches all of the given regex patterns.
    ///
    /// # Errors
    /// Returns an error if any regex pattern is invalid or if the database operation fails.
    pub fn search_by_regexes_all(
        &self,
        patterns: &[String],
        case_sensitive: bool,
        limit: usize,
    ) -> Result<Vec<FileEntry>> {
        if patterns.is_empty() {
            return Ok(Vec::new());
        }

        // Validate all regex patterns before querying
        for pattern in patterns {
            Regex::new(pattern).with_context(|| format!("Invalid regex pattern: {pattern}"))?;
        }

        // Build WHERE clause with AND for each pattern
        let where_clauses: Vec<String> = (1..=patterns.len()).map(|i| format!("name REGEXP ?{i}")).collect();
        let where_clause = where_clauses.join(" AND ");

        let sql = format!(
            r"
            SELECT id, volume_id, parent_id, name, full_path, is_directory, size, created_time, modified_time, mft_reference
            FROM files
            WHERE {where_clause}
            ORDER BY name
            LIMIT ?{}
            ",
            patterns.len() + 1
        );

        let mut statement = self.connection.prepare(&sql)?;

        // Bind all pattern parameters with case-insensitive flag if needed
        let effective_patterns: Vec<String> = patterns
            .iter()
            .map(|p| if case_sensitive { p.clone() } else { format!("(?i){p}") })
            .collect();
        let mut params_vec: Vec<&dyn rusqlite::ToSql> =
            effective_patterns.iter().map(|p| p as &dyn rusqlite::ToSql).collect();
        let limit_value = i64::try_from(limit).unwrap_or(i64::MAX);
        params_vec.push(&limit_value);

        let files = statement
            .query_map(params_vec.as_slice(), row_to_file_entry)?
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to search files by regex")?;

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
            .query_map(
                params![search_pattern, i64::try_from(limit).unwrap_or(i64::MAX)],
                row_to_file_entry,
            )?
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to search files by path")?;

        Ok(files)
    }

    /// Get database statistics.
    ///
    /// # Errors
    /// Returns an error if the database operation fails.
    pub fn get_stats(&self) -> Result<DatabaseStats> {
        let total_files: i64 =
            self.connection
                .query_row("SELECT COUNT(*) FROM files WHERE is_directory = 0", [], |row| {
                    row.get(0)
                })?;

        let total_directories: i64 =
            self.connection
                .query_row("SELECT COUNT(*) FROM files WHERE is_directory = 1", [], |row| {
                    row.get(0)
                })?;

        let volume_count: i64 = self
            .connection
            .query_row("SELECT COUNT(*) FROM volumes", [], |row| row.get(0))?;

        let total_size: i64 = self.connection.query_row(
            "SELECT COALESCE(SUM(size), 0) FROM files WHERE is_directory = 0",
            [],
            |row| row.get(0),
        )?;

        Ok(DatabaseStats {
            total_files: u64::try_from(total_files).unwrap_or(0),
            total_directories: u64::try_from(total_directories).unwrap_or(0),
            volume_count: u64::try_from(volume_count).unwrap_or(0),
            total_size: u64::try_from(total_size).unwrap_or(0),
        })
    }

    /// Get statistics for a specific volume.
    ///
    /// # Errors
    /// Returns an error if the database operation fails.
    pub fn get_volume_stats(&self, volume_id: i64) -> Result<VolumeStats> {
        let file_count: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM files WHERE volume_id = ?1 AND is_directory = 0",
            params![volume_id],
            |row| row.get(0),
        )?;

        let directory_count: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM files WHERE volume_id = ?1 AND is_directory = 1",
            params![volume_id],
            |row| row.get(0),
        )?;

        let total_size: i64 = self.connection.query_row(
            "SELECT COALESCE(SUM(size), 0) FROM files WHERE volume_id = ?1 AND is_directory = 0",
            params![volume_id],
            |row| row.get(0),
        )?;

        Ok(VolumeStats {
            file_count: u64::try_from(file_count).unwrap_or(0),
            directory_count: u64::try_from(directory_count).unwrap_or(0),
            total_size: u64::try_from(total_size).unwrap_or(0),
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

    /// Update the last USN value for a volume by drive letter.
    ///
    /// # Errors
    /// Returns an error if the database operation fails.
    pub fn update_volume_usn_by_drive(&self, drive_letter: char, usn: i64) -> Result<()> {
        let mount_point = format!("{}:", drive_letter.to_ascii_uppercase());
        let mount_point_with_slash = format!("{mount_point}\\");

        self.connection
            .execute(
                "UPDATE volumes SET last_usn = ?1, last_scan_time = ?2 WHERE mount_point = ?3 OR mount_point = ?4",
                params![
                    usn,
                    system_time_to_unix(SystemTime::now()),
                    mount_point,
                    mount_point_with_slash
                ],
            )
            .context("Failed to update volume USN")?;

        Ok(())
    }

    /// Get the last USN value for a volume by drive letter.
    ///
    /// # Errors
    /// Returns an error if the database operation fails.
    pub fn get_volume_last_usn(&self, drive_letter: char) -> Result<Option<i64>> {
        let mount_point = format!("{}:", drive_letter.to_ascii_uppercase());

        let mut statement = self.connection.prepare(
            r"
            SELECT last_usn
            FROM volumes
            WHERE mount_point = ?1 OR mount_point = ?2
            ",
        )?;

        let mount_point_with_slash = format!("{mount_point}\\");

        let usn = statement
            .query_row(params![mount_point, mount_point_with_slash], |row| row.get(0))
            .optional()
            .context("Failed to query volume USN")?;

        Ok(usn.flatten())
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
    // Size is stored as INTEGER (i64) in SQLite, convert safely to u64
    let size_i64: i64 = row.get(6)?;
    let size = u64::try_from(size_i64).unwrap_or(0);

    // MFT reference is stored as INTEGER (i64) in SQLite, convert safely to u64
    let mft_reference: Option<i64> = row.get(9)?;
    let mft_reference = mft_reference.and_then(|v| u64::try_from(v).ok());

    Ok(FileEntry {
        id: Some(row.get(0)?),
        volume_id: row.get(1)?,
        parent_id: row.get(2)?,
        name: row.get(3)?,
        full_path: row.get(4)?,
        is_directory: row.get(5)?,
        size,
        created_time: row.get::<_, Option<i64>>(7)?.and_then(unix_to_system_time),
        modified_time: row.get::<_, Option<i64>>(8)?.and_then(unix_to_system_time),
        mft_reference,
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
///
/// Returns `None` if the timestamp is negative (before Unix epoch).
fn unix_to_system_time(timestamp: i64) -> Option<SystemTime> {
    if timestamp >= 0 {
        Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(timestamp as u64))
    } else {
        None
    }
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

    /// Helper to create a test volume.
    fn create_test_volume(serial: &str, mount_point: &str) -> IndexedVolume {
        IndexedVolume {
            id: None,
            serial_number: serial.to_string(),
            label: Some(format!("Test Volume {serial}")),
            mount_point: mount_point.to_string(),
            volume_type: VolumeType::Ntfs,
            last_scan_time: None,
            last_usn: None,
            is_online: true,
        }
    }

    /// Helper to create a test file entry.
    fn create_test_file(volume_id: i64, name: &str, path: &str, size: u64) -> FileEntry {
        FileEntry {
            id: None,
            volume_id,
            parent_id: None,
            name: name.to_string(),
            full_path: path.to_string(),
            is_directory: false,
            size,
            created_time: Some(SystemTime::now()),
            modified_time: Some(SystemTime::now()),
            mft_reference: None,
        }
    }

    /// Helper to create a test directory entry.
    fn create_test_directory(volume_id: i64, name: &str, path: &str) -> FileEntry {
        FileEntry {
            id: None,
            volume_id,
            parent_id: None,
            name: name.to_string(),
            full_path: path.to_string(),
            is_directory: true,
            size: 0,
            created_time: Some(SystemTime::now()),
            modified_time: Some(SystemTime::now()),
            mft_reference: None,
        }
    }

    #[test]
    fn test_open_in_memory() {
        let database = Database::open_in_memory().unwrap();
        let stats = database.get_stats().unwrap();
        assert_eq!(stats.total_files, 0);
        assert_eq!(stats.volume_count, 0);
    }

    #[test]
    fn test_open_with_temp_file() {
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join(format!("test_filefind_{}.db", std::process::id()));

        // Open/create database
        let database = Database::open(&db_path).unwrap();
        let stats = database.get_stats().unwrap();
        assert_eq!(stats.total_files, 0);

        // Clean up
        drop(database);
        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn test_insert_and_search_file() {
        let database = Database::open_in_memory().unwrap();

        // Insert a volume first
        let volume = create_test_volume("TEST123", "C:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        // Insert a file
        let file = create_test_file(volume_id, "test_document.pdf", "C:\\Documents\\test_document.pdf", 1024);
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
        assert_eq!(glob_to_sql_like("\\path\\to\\file"), "\\\\path\\\\to\\\\file");
        assert_eq!(glob_to_sql_like("*.*"), "%.%");
        assert_eq!(glob_to_sql_like("???"), "___");
        assert_eq!(glob_to_sql_like("file"), "file");
        assert_eq!(glob_to_sql_like(""), "");
    }

    #[test]
    fn test_search_by_glob() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("TEST456", "D:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        // Insert test files
        for name in ["report.txt", "report.pdf", "data.txt", "image.png"] {
            let file = create_test_file(volume_id, name, &format!("D:\\{name}"), 100);
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
    fn test_search_by_regex() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("REGEX_VOL", "R:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        // Insert test files
        let files = [
            "IMG_0001.jpg",
            "IMG_0002.jpg",
            "IMG_1234.png",
            "photo_001.jpg",
            "document.pdf",
            "report2024.txt",
        ];

        for name in files {
            let file = create_test_file(volume_id, name, &format!("R:\\{name}"), 100);
            database.insert_file(&file).unwrap();
        }

        // Search for IMG_ followed by digits
        let results = database.search_by_regex(r"IMG_\d+", false, 10).unwrap();
        assert_eq!(results.len(), 3);

        // Search for files ending in .jpg
        let results = database.search_by_regex(r"\.jpg$", false, 10).unwrap();
        assert_eq!(results.len(), 3);

        // Search for files with exactly 4 digits
        let results = database.search_by_regex(r"\d{4}", false, 10).unwrap();
        assert_eq!(results.len(), 4); // IMG_0001, IMG_0002, IMG_1234, report2024

        // Search for files starting with photo or IMG
        let results = database.search_by_regex(r"^(photo|IMG)", false, 10).unwrap();
        assert_eq!(results.len(), 4);
    }

    #[test]
    fn test_search_by_regex_case_sensitivity() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("CASE_VOL", "C:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        let files = ["README.md", "readme.txt", "ReadMe.doc", "other.txt"];

        for name in files {
            let file = create_test_file(volume_id, name, &format!("C:\\{name}"), 100);
            database.insert_file(&file).unwrap();
        }

        // Case-insensitive search (default)
        let results = database.search_by_regex(r"^readme", false, 10).unwrap();
        assert_eq!(results.len(), 3);

        // Case-sensitive search
        let results = database.search_by_regex(r"^readme", true, 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "readme.txt");

        // Case-sensitive search for uppercase
        let results = database.search_by_regex(r"^README", true, 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "README.md");
    }

    #[test]
    fn test_search_by_regex_invalid_pattern() {
        let database = Database::open_in_memory().unwrap();

        // Invalid regex pattern (unclosed bracket)
        let result = database.search_by_regex(r"[invalid", false, 10);
        assert!(result.is_err());

        // Invalid regex pattern (bad repetition)
        let result = database.search_by_regex(r"*invalid", false, 10);
        assert!(result.is_err());
    }

    #[test]
    fn test_search_by_regex_no_results() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("EMPTY_VOL", "E:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        let file = create_test_file(volume_id, "document.txt", "E:\\document.txt", 100);
        database.insert_file(&file).unwrap();

        // Search for pattern that won't match
        let results = database.search_by_regex(r"^xyz\d+\.pdf$", false, 10).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_by_regex_special_characters() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("SPECIAL_VOL", "S:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        let files = [
            "file.test.txt",
            "file-test.txt",
            "file_test.txt",
            "file(1).txt",
            "file[2].txt",
        ];

        for name in files {
            let file = create_test_file(volume_id, name, &format!("S:\\{name}"), 100);
            database.insert_file(&file).unwrap();
        }

        // Search for literal dot (escaped)
        let results = database.search_by_regex(r"file\.test", false, 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "file.test.txt");

        // Search for parentheses (escaped)
        let results = database.search_by_regex(r"\(\d\)", false, 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "file(1).txt");

        // Search for brackets (escaped)
        let results = database.search_by_regex(r"\[\d\]", false, 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "file[2].txt");
    }

    #[test]
    fn test_search_by_glob_with_special_characters() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("SPECIAL", "C:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        // Insert files with special characters in names
        let files = ["file_with_underscore.txt", "file%with%percent.txt", "normal.txt"];

        for name in files {
            let file = create_test_file(volume_id, name, &format!("C:\\{name}"), 100);
            database.insert_file(&file).unwrap();
        }

        // Searching for literal underscore should match only files with underscore
        let results = database.search_by_glob("*_*", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "file_with_underscore.txt");

        // Searching for literal percent should match only files with percent
        let results = database.search_by_glob("*%*", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "file%with%percent.txt");
    }

    #[test]
    fn test_database_stats() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("STATS123", "E:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        // Insert files and directories
        let file = create_test_file(volume_id, "file.txt", "E:\\file.txt", 1000);
        database.insert_file(&file).unwrap();

        let directory = create_test_directory(volume_id, "folder", "E:\\folder");
        database.insert_file(&directory).unwrap();

        let stats = database.get_stats().unwrap();
        assert_eq!(stats.total_files, 1);
        assert_eq!(stats.total_directories, 1);
        assert_eq!(stats.volume_count, 1);
        assert_eq!(stats.total_size, 1000);
    }

    #[test]
    fn test_database_stats_empty() {
        let database = Database::open_in_memory().unwrap();

        let stats = database.get_stats().unwrap();
        assert_eq!(stats.total_files, 0);
        assert_eq!(stats.total_directories, 0);
        assert_eq!(stats.volume_count, 0);
        assert_eq!(stats.total_size, 0);
    }

    #[test]
    fn test_database_stats_with_multiple_volumes() {
        let database = Database::open_in_memory().unwrap();

        // Create multiple volumes
        let volume1 = create_test_volume("VOL1", "C:");
        let volume2 = create_test_volume("VOL2", "D:");
        let volume_id1 = database.upsert_volume(&volume1).unwrap();
        let volume_id2 = database.upsert_volume(&volume2).unwrap();

        // Add files to both volumes
        database
            .insert_file(&create_test_file(volume_id1, "file1.txt", "C:\\file1.txt", 500))
            .unwrap();
        database
            .insert_file(&create_test_file(volume_id1, "file2.txt", "C:\\file2.txt", 300))
            .unwrap();
        database
            .insert_file(&create_test_file(volume_id2, "file3.txt", "D:\\file3.txt", 200))
            .unwrap();

        let stats = database.get_stats().unwrap();
        assert_eq!(stats.total_files, 3);
        assert_eq!(stats.volume_count, 2);
        assert_eq!(stats.total_size, 1000);
    }

    #[test]
    fn test_get_volume_stats() {
        let database = Database::open_in_memory().unwrap();

        // Create two volumes
        let volume1 = create_test_volume("VOL1", "C:");
        let volume2 = create_test_volume("VOL2", "D:");
        let volume_id1 = database.upsert_volume(&volume1).unwrap();
        let volume_id2 = database.upsert_volume(&volume2).unwrap();

        // Add files and directories to volume 1
        database
            .insert_file(&create_test_file(volume_id1, "file1.txt", "C:\\file1.txt", 500))
            .unwrap();
        database
            .insert_file(&create_test_file(volume_id1, "file2.txt", "C:\\file2.txt", 300))
            .unwrap();
        database
            .insert_file(&create_test_directory(volume_id1, "folder", "C:\\folder"))
            .unwrap();

        // Add files to volume 2
        database
            .insert_file(&create_test_file(volume_id2, "file3.txt", "D:\\file3.txt", 1000))
            .unwrap();

        // Check stats for volume 1
        let stats1 = database.get_volume_stats(volume_id1).unwrap();
        assert_eq!(stats1.file_count, 2);
        assert_eq!(stats1.directory_count, 1);
        assert_eq!(stats1.total_size, 800);

        // Check stats for volume 2
        let stats2 = database.get_volume_stats(volume_id2).unwrap();
        assert_eq!(stats2.file_count, 1);
        assert_eq!(stats2.directory_count, 0);
        assert_eq!(stats2.total_size, 1000);
    }

    #[test]
    fn test_get_volume_stats_empty_volume() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("EMPTY", "E:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        let stats = database.get_volume_stats(volume_id).unwrap();
        assert_eq!(stats.file_count, 0);
        assert_eq!(stats.directory_count, 0);
        assert_eq!(stats.total_size, 0);
    }

    #[test]
    fn test_upsert_volume_insert() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("NEW_VOL", "F:");
        let volume_id = database.upsert_volume(&volume).unwrap();
        assert!(volume_id > 0);

        let retrieved = database.get_volume_by_serial("NEW_VOL").unwrap();
        assert!(retrieved.is_some());

        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.serial_number, "NEW_VOL");
        assert_eq!(retrieved.mount_point, "F:");
        assert!(retrieved.is_online);
    }

    #[test]
    fn test_upsert_volume_update() {
        let database = Database::open_in_memory().unwrap();

        // Insert initial volume
        let mut volume = create_test_volume("UPDATE_VOL", "G:");
        volume.label = Some("Original Label".to_string());
        database.upsert_volume(&volume).unwrap();

        // Update the same volume with new data
        volume.label = Some("Updated Label".to_string());
        volume.mount_point = "H:".to_string();
        database.upsert_volume(&volume).unwrap();

        // Verify update
        let retrieved = database.get_volume_by_serial("UPDATE_VOL").unwrap().unwrap();
        assert_eq!(retrieved.label, Some("Updated Label".to_string()));
        assert_eq!(retrieved.mount_point, "H:");

        // Should still be only one volume
        let all_volumes = database.get_all_volumes().unwrap();
        assert_eq!(all_volumes.len(), 1);
    }

    #[test]
    fn test_upsert_volume_returns_correct_id_on_update() {
        let database = Database::open_in_memory().unwrap();

        // Insert initial volume and get its ID
        let volume = create_test_volume("ID_CHECK_VOL", "I:");
        let first_id = database.upsert_volume(&volume).unwrap();
        assert!(first_id > 0, "First insert should return a valid ID");

        // Update the same volume and verify we get the same ID back
        let mut updated_volume = create_test_volume("ID_CHECK_VOL", "I:");
        updated_volume.label = Some("Updated".to_string());
        let second_id = database.upsert_volume(&updated_volume).unwrap();

        assert_eq!(
            first_id, second_id,
            "upsert_volume should return the same ID on update, not 0"
        );
        assert!(second_id > 0, "ID should not be 0 after update");

        // Verify the ID can be used as a foreign key
        let file = create_test_file(second_id, "test.txt", "I:\\test.txt", 100);
        let insert_result = database.insert_file(&file);
        assert!(
            insert_result.is_ok(),
            "Should be able to insert file with volume_id from upsert: {:?}",
            insert_result.err()
        );
    }

    #[test]
    fn test_get_volume_by_serial_not_found() {
        let database = Database::open_in_memory().unwrap();

        let result = database.get_volume_by_serial("NONEXISTENT").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_get_all_volumes() {
        let database = Database::open_in_memory().unwrap();

        // Start empty
        let volumes = database.get_all_volumes().unwrap();
        assert!(volumes.is_empty());

        // Add some volumes
        database.upsert_volume(&create_test_volume("VOL_A", "A:")).unwrap();
        database.upsert_volume(&create_test_volume("VOL_B", "B:")).unwrap();
        database.upsert_volume(&create_test_volume("VOL_C", "C:")).unwrap();

        let volumes = database.get_all_volumes().unwrap();
        assert_eq!(volumes.len(), 3);

        let serials: Vec<_> = volumes.iter().map(|v| v.serial_number.as_str()).collect();
        assert!(serials.contains(&"VOL_A"));
        assert!(serials.contains(&"VOL_B"));
        assert!(serials.contains(&"VOL_C"));
    }

    #[test]
    fn test_insert_files_batch() {
        let mut database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("BATCH_VOL", "C:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        let files: Vec<FileEntry> = (0..100)
            .map(|index| {
                create_test_file(
                    volume_id,
                    &format!("file{index}.txt"),
                    &format!("C:\\file{index}.txt"),
                    100,
                )
            })
            .collect();

        let count = database.insert_files_batch(&files).unwrap();
        assert_eq!(count, 100);

        let stats = database.get_stats().unwrap();
        assert_eq!(stats.total_files, 100);
    }

    #[test]
    fn test_insert_files_batch_empty() {
        let mut database = Database::open_in_memory().unwrap();

        let files: Vec<FileEntry> = vec![];
        let count = database.insert_files_batch(&files).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_delete_file_by_path() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("DELETE_VOL", "C:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        let file_path = "C:\\to_delete.txt";
        database
            .insert_file(&create_test_file(volume_id, "to_delete.txt", file_path, 100))
            .unwrap();

        // Verify file exists
        let results = database.search_by_name("to_delete", 10).unwrap();
        assert_eq!(results.len(), 1);

        // Delete the file
        let deleted = database.delete_file_by_path(file_path).unwrap();
        assert!(deleted);

        // Verify file is gone
        let results = database.search_by_name("to_delete", 10).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_delete_file_by_path_not_found() {
        let database = Database::open_in_memory().unwrap();

        let deleted = database.delete_file_by_path("C:\\nonexistent.txt").unwrap();
        assert!(!deleted);
    }

    #[test]
    fn test_delete_files_for_volume() {
        let database = Database::open_in_memory().unwrap();

        let volume1 = create_test_volume("VOL_DEL1", "C:");
        let volume2 = create_test_volume("VOL_DEL2", "D:");
        let volume_id1 = database.upsert_volume(&volume1).unwrap();
        let volume_id2 = database.upsert_volume(&volume2).unwrap();

        // Add files to both volumes
        for index in 0..5 {
            database
                .insert_file(&create_test_file(
                    volume_id1,
                    &format!("file{index}.txt"),
                    &format!("C:\\file{index}.txt"),
                    100,
                ))
                .unwrap();
        }
        for index in 0..3 {
            database
                .insert_file(&create_test_file(
                    volume_id2,
                    &format!("other{index}.txt"),
                    &format!("D:\\other{index}.txt"),
                    100,
                ))
                .unwrap();
        }

        // Delete files for volume 1
        let deleted_count = database.delete_files_for_volume(volume_id1).unwrap();
        assert_eq!(deleted_count, 5);

        // Volume 2 files should remain
        let stats = database.get_stats().unwrap();
        assert_eq!(stats.total_files, 3);
    }

    #[test]
    fn test_search_by_name_case_insensitive() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("CASE_VOL", "C:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        database
            .insert_file(&create_test_file(volume_id, "Document.PDF", "C:\\Document.PDF", 100))
            .unwrap();

        // Search should be case-insensitive
        let results = database.search_by_name("document", 10).unwrap();
        assert_eq!(results.len(), 1);

        let results = database.search_by_name("DOCUMENT", 10).unwrap();
        assert_eq!(results.len(), 1);

        let results = database.search_by_name("pdf", 10).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_search_by_name_limit() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("LIMIT_VOL", "C:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        // Insert many matching files
        for index in 0..50 {
            database
                .insert_file(&create_test_file(
                    volume_id,
                    &format!("document{index}.txt"),
                    &format!("C:\\document{index}.txt"),
                    100,
                ))
                .unwrap();
        }

        // Search with limit
        let results = database.search_by_name("document", 10).unwrap();
        assert_eq!(results.len(), 10);

        let results = database.search_by_name("document", 25).unwrap();
        assert_eq!(results.len(), 25);

        let results = database.search_by_name("document", 100).unwrap();
        assert_eq!(results.len(), 50);
    }

    #[test]
    fn test_search_by_exact_name() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("EXACT_VOL", "C:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        database
            .insert_file(&create_test_file(volume_id, "readme.txt", "C:\\readme.txt", 100))
            .unwrap();
        database
            .insert_file(&create_test_file(volume_id, "README.txt", "C:\\docs\\README.txt", 200))
            .unwrap();
        database
            .insert_file(&create_test_file(
                volume_id,
                "readme_backup.txt",
                "C:\\readme_backup.txt",
                150,
            ))
            .unwrap();

        // Exact name search should only match exact names (case-insensitive)
        let results = database.search_by_exact_name("readme.txt", 10).unwrap();
        assert_eq!(results.len(), 2); // readme.txt and README.txt

        // Should not match partial names
        let results = database.search_by_exact_name("readme", 10).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_by_path() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("PATH_VOL", "C:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        database
            .insert_file(&create_test_file(
                volume_id,
                "file.txt",
                "C:\\Users\\test\\Documents\\file.txt",
                100,
            ))
            .unwrap();
        database
            .insert_file(&create_test_file(
                volume_id,
                "other.txt",
                "C:\\Users\\admin\\Documents\\other.txt",
                100,
            ))
            .unwrap();
        database
            .insert_file(&create_test_file(volume_id, "readme.txt", "C:\\readme.txt", 100))
            .unwrap();

        // Search by path fragment
        let results = database.search_by_path("Documents", 10).unwrap();
        assert_eq!(results.len(), 2);

        let results = database.search_by_path("Users\\test", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "file.txt");
    }

    #[test]
    fn test_update_volume_usn() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("USN_VOL", "C:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        // Update USN
        database.update_volume_usn(volume_id, 12345).unwrap();

        // Verify update
        let retrieved = database.get_volume_by_serial("USN_VOL").unwrap().unwrap();
        assert_eq!(retrieved.last_usn, Some(12345));
        assert!(retrieved.last_scan_time.is_some());
    }

    #[test]
    fn test_update_volume_usn_by_drive() {
        let database = Database::open_in_memory().unwrap();

        // Test with mount point without trailing slash
        let mut volume1 = create_test_volume("DRIVE_USN1", "C:");
        volume1.mount_point = "C:".to_string();
        database.upsert_volume(&volume1).unwrap();

        // Test with mount point with trailing slash
        let mut volume2 = create_test_volume("DRIVE_USN2", "D:\\");
        volume2.mount_point = "D:\\".to_string();
        database.upsert_volume(&volume2).unwrap();

        // Update USN by drive letter
        database.update_volume_usn_by_drive('C', 111).unwrap();
        database.update_volume_usn_by_drive('D', 222).unwrap();

        // Verify updates
        let vol1 = database.get_volume_by_serial("DRIVE_USN1").unwrap().unwrap();
        assert_eq!(vol1.last_usn, Some(111));

        let vol2 = database.get_volume_by_serial("DRIVE_USN2").unwrap().unwrap();
        assert_eq!(vol2.last_usn, Some(222));
    }

    #[test]
    fn test_get_volume_last_usn() {
        let database = Database::open_in_memory().unwrap();

        // No volume yet
        let usn = database.get_volume_last_usn('X').unwrap();
        assert!(usn.is_none());

        // Add volume with USN
        let mut volume = create_test_volume("USN_GET", "X:");
        volume.last_usn = Some(99999);
        database.upsert_volume(&volume).unwrap();

        let usn = database.get_volume_last_usn('X').unwrap();
        assert_eq!(usn, Some(99999));

        // Test lowercase drive letter
        let usn = database.get_volume_last_usn('x').unwrap();
        assert_eq!(usn, Some(99999));
    }

    #[test]
    fn test_set_volume_online() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("ONLINE_VOL", "Z:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        // Initially online
        let vol = database.get_volume_by_serial("ONLINE_VOL").unwrap().unwrap();
        assert!(vol.is_online);

        // Set offline
        database.set_volume_online(volume_id, false).unwrap();
        let vol = database.get_volume_by_serial("ONLINE_VOL").unwrap().unwrap();
        assert!(!vol.is_online);

        // Set back online
        database.set_volume_online(volume_id, true).unwrap();
        let vol = database.get_volume_by_serial("ONLINE_VOL").unwrap().unwrap();
        assert!(vol.is_online);
    }

    #[test]
    fn test_volume_type_preserved() {
        let database = Database::open_in_memory().unwrap();

        let volume_types = [
            (VolumeType::Ntfs, "NTFS_VOL"),
            (VolumeType::Local, "LOCAL_VOL"),
            (VolumeType::Network, "NET_VOL"),
            (VolumeType::Removable, "REM_VOL"),
        ];

        for (volume_type, serial) in volume_types {
            let volume = IndexedVolume {
                id: None,
                serial_number: serial.to_string(),
                label: None,
                mount_point: "X:".to_string(),
                volume_type,
                last_scan_time: None,
                last_usn: None,
                is_online: true,
            };
            database.upsert_volume(&volume).unwrap();

            let retrieved = database.get_volume_by_serial(serial).unwrap().unwrap();
            assert_eq!(retrieved.volume_type, volume_type);
        }
    }

    #[test]
    fn test_file_with_timestamps() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("TIME_VOL", "C:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        let now = SystemTime::now();
        let created = now - std::time::Duration::from_secs(3600);
        let modified = now - std::time::Duration::from_secs(60);

        let file = FileEntry {
            id: None,
            volume_id,
            parent_id: None,
            name: "timed_file.txt".to_string(),
            full_path: "C:\\timed_file.txt".to_string(),
            is_directory: false,
            size: 500,
            created_time: Some(created),
            modified_time: Some(modified),
            mft_reference: Some(12345),
        };

        database.insert_file(&file).unwrap();

        let results = database.search_by_exact_name("timed_file.txt", 10).unwrap();
        assert_eq!(results.len(), 1);

        let retrieved = &results[0];
        assert!(retrieved.created_time.is_some());
        assert!(retrieved.modified_time.is_some());
        assert_eq!(retrieved.mft_reference, Some(12345));

        // Verify timestamps are approximately correct (within 1 second due to precision loss)
        let created_diff = retrieved
            .created_time
            .unwrap()
            .duration_since(created)
            .unwrap_or_default();
        assert!(created_diff.as_secs() < 2);
    }

    #[test]
    fn test_file_entry_id_assigned() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("ID_VOL", "C:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        let file = create_test_file(volume_id, "test.txt", "C:\\test.txt", 100);
        let file_id = database.insert_file(&file).unwrap();
        assert!(file_id > 0);

        let results = database.search_by_exact_name("test.txt", 10).unwrap();
        assert!(results[0].id.is_some());
        assert_eq!(results[0].id.unwrap(), file_id);
    }

    #[test]
    fn test_system_time_conversions() {
        // Test epoch
        let epoch = SystemTime::UNIX_EPOCH;
        let unix = system_time_to_unix(epoch);
        assert_eq!(unix, 0);

        let back = unix_to_system_time(unix);
        assert_eq!(back, Some(epoch));

        // Test a known timestamp
        let timestamp = 1_700_000_000i64;
        let time = unix_to_system_time(timestamp).expect("valid timestamp");
        let back = system_time_to_unix(time);
        assert_eq!(back, timestamp);

        // Test negative timestamp returns None
        let negative = unix_to_system_time(-1);
        assert_eq!(negative, None);
    }

    #[test]
    fn test_search_empty_pattern() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("EMPTY_VOL", "C:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        database
            .insert_file(&create_test_file(volume_id, "file.txt", "C:\\file.txt", 100))
            .unwrap();

        // Empty pattern matches all (because of %% pattern)
        let results = database.search_by_name("", 10).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_search_no_results() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("NO_RES_VOL", "C:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        database
            .insert_file(&create_test_file(volume_id, "file.txt", "C:\\file.txt", 100))
            .unwrap();

        let results = database.search_by_name("nonexistent_xyz", 10).unwrap();
        assert!(results.is_empty());

        let results = database.search_by_glob("*.xyz", 10).unwrap();
        assert!(results.is_empty());

        let results = database.search_by_exact_name("nothere.txt", 10).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_large_file_size() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("LARGE_VOL", "C:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        // Test with a very large file size (10 TB)
        let large_size: u64 = 10 * 1024 * 1024 * 1024 * 1024;
        let file = create_test_file(volume_id, "huge.bin", "C:\\huge.bin", large_size);
        database.insert_file(&file).unwrap();

        let results = database.search_by_exact_name("huge.bin", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].size, large_size);

        let stats = database.get_stats().unwrap();
        assert_eq!(stats.total_size, large_size);
    }

    #[test]
    fn test_unicode_filenames() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("UNICODE_VOL", "C:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        let unicode_names = [
            "文档.txt",
            "документ.pdf",
            "αρχείο.doc",
            "ファイル.txt",
            "emoji_😀_file.txt",
        ];

        for name in unicode_names {
            let file = create_test_file(volume_id, name, &format!("C:\\{name}"), 100);
            database.insert_file(&file).unwrap();
        }

        // Search for unicode files
        let results = database.search_by_name("文档", 10).unwrap();
        assert_eq!(results.len(), 1);

        let results = database.search_by_glob("*.txt", 10).unwrap();
        assert_eq!(results.len(), 3);

        let results = database.search_by_name("emoji", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].name.contains("😀"));
    }

    #[test]
    fn test_file_with_parent_id() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("PARENT_VOL", "C:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        // Insert parent directory
        let parent_dir = create_test_directory(volume_id, "Documents", "C:\\Documents");
        let parent_id = database.insert_file(&parent_dir).unwrap();

        // Insert child file with parent reference
        let mut child_file = create_test_file(volume_id, "file.txt", "C:\\Documents\\file.txt", 100);
        child_file.parent_id = Some(parent_id);
        database.insert_file(&child_file).unwrap();

        // Search and verify parent_id is preserved
        let results = database.search_by_exact_name("file.txt", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].parent_id, Some(parent_id));
    }

    #[test]
    fn test_database_stats_default() {
        let stats = DatabaseStats::default();
        assert_eq!(stats.total_files, 0);
        assert_eq!(stats.total_directories, 0);
        assert_eq!(stats.volume_count, 0);
        assert_eq!(stats.total_size, 0);
    }

    #[test]
    fn test_connection_accessor() {
        let database = Database::open_in_memory().unwrap();
        let connection = database.connection();

        // Verify we can use the connection for raw queries
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM volumes", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_volume_label_optional() {
        let database = Database::open_in_memory().unwrap();

        // Volume without label
        let mut volume = create_test_volume("NO_LABEL", "X:");
        volume.label = None;
        database.upsert_volume(&volume).unwrap();

        let retrieved = database.get_volume_by_serial("NO_LABEL").unwrap().unwrap();
        assert!(retrieved.label.is_none());
    }

    #[test]
    fn test_glob_single_character_wildcard() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("SINGLE_WILD", "C:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        let files = ["file1.txt", "file2.txt", "file10.txt", "fileX.txt"];
        for name in files {
            database
                .insert_file(&create_test_file(volume_id, name, &format!("C:\\{name}"), 100))
                .unwrap();
        }

        // ? should match single character
        let results = database.search_by_glob("file?.txt", 10).unwrap();
        assert_eq!(results.len(), 3); // file1, file2, fileX

        // Multiple ? wildcards
        let results = database.search_by_glob("file??.txt", 10).unwrap();
        assert_eq!(results.len(), 1); // file10
    }

    #[test]
    fn test_negative_timestamp_returns_none() {
        // Negative timestamps (before Unix epoch) should return None
        assert_eq!(unix_to_system_time(-1), None);
        assert_eq!(unix_to_system_time(-1000), None);
        assert_eq!(unix_to_system_time(i64::MIN), None);

        // Zero and positive timestamps should work
        assert!(unix_to_system_time(0).is_some());
        assert!(unix_to_system_time(1).is_some());
        assert!(unix_to_system_time(1_700_000_000).is_some());

        // Very large timestamps (far future) - use a reasonable upper bound
        // Year 3000 is approximately 32503680000 seconds from epoch
        assert!(unix_to_system_time(32_503_680_000).is_some());
    }

    #[test]
    fn test_file_with_negative_timestamps_in_database() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("NEG_TIME_VOL", "C:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        // Insert a file with valid timestamps
        let file = FileEntry {
            id: None,
            volume_id,
            parent_id: None,
            name: "old_file.txt".to_string(),
            full_path: "C:\\old_file.txt".to_string(),
            is_directory: false,
            size: 100,
            created_time: Some(SystemTime::UNIX_EPOCH),
            modified_time: Some(SystemTime::UNIX_EPOCH),
            mft_reference: None,
        };
        database.insert_file(&file).unwrap();

        // Manually insert a file with negative timestamps using raw SQL
        database
            .connection
            .execute(
                "INSERT INTO files (volume_id, name, full_path, is_directory, size, created_time, modified_time)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    volume_id,
                    "negative_time.txt",
                    "C:\\negative_time.txt",
                    false,
                    200,
                    -1000i64,
                    -500i64
                ],
            )
            .unwrap();

        // Search should succeed and return the file with None timestamps
        let results = database.search_by_exact_name("negative_time.txt", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "negative_time.txt");
        assert_eq!(results[0].size, 200);
        assert!(results[0].created_time.is_none());
        assert!(results[0].modified_time.is_none());
    }

    #[test]
    fn test_file_with_max_u64_size() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("MAX_SIZE_VOL", "C:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        // SQLite stores integers as i64, so the max safe positive value is i64::MAX
        let max_safe_size = i64::MAX as u64;
        let file = create_test_file(volume_id, "max_size.bin", "C:\\max_size.bin", max_safe_size);
        database.insert_file(&file).unwrap();

        let results = database.search_by_exact_name("max_size.bin", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].size, max_safe_size);
    }

    #[test]
    fn test_file_with_negative_size_in_database() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("NEG_SIZE_VOL", "C:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        // Manually insert a file with negative size using raw SQL (simulating corrupted data)
        database
            .connection
            .execute(
                "INSERT INTO files (volume_id, name, full_path, is_directory, size)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![volume_id, "negative_size.txt", "C:\\negative_size.txt", false, -100i64],
            )
            .unwrap();

        // Search should succeed and return the file with size defaulting to 0
        let results = database.search_by_exact_name("negative_size.txt", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "negative_size.txt");
        assert_eq!(results[0].size, 0); // Negative size should default to 0
    }

    #[test]
    fn test_file_with_mft_reference_edge_cases() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("MFT_REF_VOL", "C:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        // Test with valid MFT reference
        let mut file = create_test_file(volume_id, "valid_mft.txt", "C:\\valid_mft.txt", 100);
        file.mft_reference = Some(12345);
        database.insert_file(&file).unwrap();

        let results = database.search_by_exact_name("valid_mft.txt", 10).unwrap();
        assert_eq!(results[0].mft_reference, Some(12345));

        // Test with large MFT reference (max i64 as u64)
        let mut file2 = create_test_file(volume_id, "large_mft.txt", "C:\\large_mft.txt", 100);
        file2.mft_reference = Some(i64::MAX as u64);
        database.insert_file(&file2).unwrap();

        let results = database.search_by_exact_name("large_mft.txt", 10).unwrap();
        assert_eq!(results[0].mft_reference, Some(i64::MAX as u64));

        // Manually insert a file with negative MFT reference (simulating corrupted data)
        database
            .connection
            .execute(
                "INSERT INTO files (volume_id, name, full_path, is_directory, size, mft_reference)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![volume_id, "neg_mft.txt", "C:\\neg_mft.txt", false, 100, -1i64],
            )
            .unwrap();

        // Search should succeed and return the file with mft_reference as None
        let results = database.search_by_exact_name("neg_mft.txt", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].mft_reference, None); // Negative MFT reference should become None
    }

    #[test]
    fn test_volume_with_negative_last_scan_time() {
        let database = Database::open_in_memory().unwrap();

        // Manually insert a volume with negative last_scan_time
        database
            .connection
            .execute(
                "INSERT INTO volumes (serial_number, label, mount_point, volume_type, last_scan_time, is_online)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params!["NEG_SCAN_VOL", "Test", "C:", "ntfs", -1000i64, true],
            )
            .unwrap();

        let volume = database.get_volume_by_serial("NEG_SCAN_VOL").unwrap();
        assert!(volume.is_some());
        let volume = volume.unwrap();
        assert!(volume.last_scan_time.is_none()); // Negative timestamp should become None
    }

    #[test]
    fn test_search_with_corrupted_integer_data() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("CORRUPT_VOL", "C:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        // Insert multiple files with various edge case values
        database
            .connection
            .execute_batch(&format!(
                "INSERT INTO files (volume_id, name, full_path, is_directory, size, created_time, modified_time, mft_reference)
                 VALUES
                 ({volume_id}, 'normal.txt', 'C:\\normal.txt', 0, 100, 1700000000, 1700000000, 12345),
                 ({volume_id}, 'neg_size.txt', 'C:\\neg_size.txt', 0, -999, 1700000000, 1700000000, NULL),
                 ({volume_id}, 'neg_time.txt', 'C:\\neg_time.txt', 0, 500, -1, -1, 67890),
                 ({volume_id}, 'neg_mft.txt', 'C:\\neg_mft.txt', 0, 750, 1700000000, 1700000000, -42),
                 ({volume_id}, 'all_neg.txt', 'C:\\all_neg.txt', 0, -1, -1000, -2000, -3000)"
            ))
            .unwrap();

        // Search should return all files without errors
        let results = database.search_by_glob("*.txt", 100).unwrap();
        assert_eq!(results.len(), 5);

        // Verify the corrupted values are handled correctly
        let neg_size = results.iter().find(|f| f.name == "neg_size.txt").unwrap();
        assert_eq!(neg_size.size, 0);

        let neg_time = results.iter().find(|f| f.name == "neg_time.txt").unwrap();
        assert!(neg_time.created_time.is_none());
        assert!(neg_time.modified_time.is_none());

        let neg_mft = results.iter().find(|f| f.name == "neg_mft.txt").unwrap();
        assert!(neg_mft.mft_reference.is_none());

        let all_neg = results.iter().find(|f| f.name == "all_neg.txt").unwrap();
        assert_eq!(all_neg.size, 0);
        assert!(all_neg.created_time.is_none());
        assert!(all_neg.modified_time.is_none());
        assert!(all_neg.mft_reference.is_none());
    }

    #[test]
    fn test_search_by_names_all() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("AND_NAME_VOL", "A:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        // Insert test files - designed to test AND logic thoroughly:
        // - Files with "config" only
        // - Files with "backup" only
        // - Files with "json" only
        // - Files with combinations of two terms
        // - Files with all three terms
        // - Unrelated files
        let files = [
            // Has: config, backup, json (all three)
            "config_backup.json",
            // Has: config, json (two terms)
            "config_settings.json",
            "my_config_file.json",
            // Has: config, backup (two terms)
            "config_backup.yaml",
            "config_backup.xml",
            // Has: backup, json (two terms)
            "data_backup.json",
            "system_backup.json",
            // Has: config only
            "config.yaml",
            "config.toml",
            "myconfig.txt",
            "app_config_settings.ini",
            // Has: backup only
            "backup.zip",
            "full_backup.tar",
            "backup_2024.db",
            // Has: json only
            "data.json",
            "settings.json",
            "package.json",
            // Has: none of the terms
            "readme.txt",
            "document.pdf",
            "image.png",
        ];

        for name in files {
            let file = create_test_file(volume_id, name, &format!("A:\\{name}"), 100);
            database.insert_file(&file).unwrap();
        }

        // Test 1: "config" AND "backup" AND "json" - should match only 1 file
        let patterns = vec!["config".to_string(), "backup".to_string(), "json".to_string()];
        let results = database.search_by_names_all(&patterns, 100).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "config_backup.json");

        // Test 2: "config" AND "backup" - should match files with both terms
        let patterns = vec!["config".to_string(), "backup".to_string()];
        let results = database.search_by_names_all(&patterns, 100).unwrap();
        assert_eq!(results.len(), 3); // config_backup.json, config_backup.yaml, config_backup.xml

        // Test 3: "config" AND "json" - should match files with both terms
        let patterns = vec!["config".to_string(), "json".to_string()];
        let results = database.search_by_names_all(&patterns, 100).unwrap();
        assert_eq!(results.len(), 3); // config_backup.json, config_settings.json, my_config_file.json

        // Test 4: "backup" AND "json" - should match files with both terms
        let patterns = vec!["backup".to_string(), "json".to_string()];
        let results = database.search_by_names_all(&patterns, 100).unwrap();
        assert_eq!(results.len(), 3); // config_backup.json, data_backup.json, system_backup.json

        // Test 5: Single pattern "config" - should match all files containing config
        // config_backup.json, config_settings.json, my_config_file.json, config_backup.yaml,
        // config_backup.xml, config.yaml, config.toml, myconfig.txt, app_config_settings.ini
        let patterns = vec!["config".to_string()];
        let results = database.search_by_names_all(&patterns, 100).unwrap();
        assert_eq!(results.len(), 9); // All files with "config" in name

        // Test 6: No matches - "config" AND "pdf"
        let patterns = vec!["config".to_string(), "pdf".to_string()];
        let results = database.search_by_names_all(&patterns, 100).unwrap();
        assert!(results.is_empty());

        // Test 7: No matches - "backup" AND "png"
        let patterns = vec!["backup".to_string(), "png".to_string()];
        let results = database.search_by_names_all(&patterns, 100).unwrap();
        assert!(results.is_empty());

        // Test 8: Empty patterns should return empty results
        let patterns: Vec<String> = vec![];
        let results = database.search_by_names_all(&patterns, 100).unwrap();
        assert!(results.is_empty());

        // Test 9: Four patterns - very restrictive
        let patterns = vec![
            "config".to_string(),
            "backup".to_string(),
            "json".to_string(),
            "xyz".to_string(),
        ];
        let results = database.search_by_names_all(&patterns, 100).unwrap();
        assert!(results.is_empty()); // No file has all four terms
    }

    #[test]
    fn test_search_by_globs_all() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("AND_GLOB_VOL", "G:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        // Insert test files - designed to test glob AND logic:
        // - Various combinations of: report/summary, 2024/2023, draft/final, pdf/txt/xlsx
        let files = [
            // report + 2024 + final + pdf (all four criteria)
            "report_2024_final.pdf",
            // report + 2024 + draft + pdf
            "report_2024_draft.pdf",
            // report + 2024 + pdf (missing final/draft distinction)
            "report_2024.pdf",
            // report + 2023 + final + pdf
            "report_2023_final.pdf",
            // report + 2023 + draft + pdf
            "report_2023_draft.pdf",
            // summary + 2024 + final + pdf
            "summary_2024_final.pdf",
            // summary + 2024 + pdf
            "summary_2024.pdf",
            // summary + 2023 + pdf
            "summary_2023.pdf",
            // report + 2024 + txt (different extension)
            "report_2024_notes.txt",
            "report_2024_final.txt",
            // report + 2024 + xlsx
            "report_2024_data.xlsx",
            // Just 2024
            "calendar_2024.pdf",
            "notes_2024.txt",
            // Just report
            "report_template.docx",
            "report_old.pdf",
            // Just final
            "final_submission.pdf",
            "final_draft.txt",
            // Unrelated
            "readme.md",
            "config.json",
            "data.csv",
        ];

        for name in files {
            let file = create_test_file(volume_id, name, &format!("G:\\{name}"), 100);
            database.insert_file(&file).unwrap();
        }

        // Test 1: "report*" AND "*2024*" AND "*final*" AND "*.pdf"
        let patterns = vec![
            "report*".to_string(),
            "*2024*".to_string(),
            "*final*".to_string(),
            "*.pdf".to_string(),
        ];
        let results = database.search_by_globs_all(&patterns, 100).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "report_2024_final.pdf");

        // Test 2: "report*" AND "*2024*" AND "*.pdf" - more results
        let patterns = vec!["report*".to_string(), "*2024*".to_string(), "*.pdf".to_string()];
        let results = database.search_by_globs_all(&patterns, 100).unwrap();
        assert_eq!(results.len(), 3); // report_2024_final.pdf, report_2024_draft.pdf, report_2024.pdf

        // Test 3: "report*" AND "*final*" - across years
        let patterns = vec!["report*".to_string(), "*final*".to_string()];
        let results = database.search_by_globs_all(&patterns, 100).unwrap();
        assert_eq!(results.len(), 3); // report_2024_final.pdf, report_2023_final.pdf, report_2024_final.txt

        // Test 4: "*2024*" AND "*.pdf" - reports and summaries
        // report_2024_final.pdf, report_2024_draft.pdf, report_2024.pdf, summary_2024_final.pdf,
        // summary_2024.pdf, calendar_2024.pdf
        let patterns = vec!["*2024*".to_string(), "*.pdf".to_string()];
        let results = database.search_by_globs_all(&patterns, 100).unwrap();
        assert_eq!(results.len(), 6); // All 2024 PDFs

        // Test 5: "*final*" AND "*.pdf" - final PDFs from any category
        let patterns = vec!["*final*".to_string(), "*.pdf".to_string()];
        let results = database.search_by_globs_all(&patterns, 100).unwrap();
        assert_eq!(results.len(), 4); // report_2024_final.pdf, report_2023_final.pdf, summary_2024_final.pdf, final_submission.pdf

        // Test 6: "summary*" AND "*2024*" - summaries from 2024
        let patterns = vec!["summary*".to_string(), "*2024*".to_string()];
        let results = database.search_by_globs_all(&patterns, 100).unwrap();
        assert_eq!(results.len(), 2); // summary_2024_final.pdf, summary_2024.pdf

        // Test 7: No matches - "report*" AND "*2025*"
        let patterns = vec!["report*".to_string(), "*2025*".to_string()];
        let results = database.search_by_globs_all(&patterns, 100).unwrap();
        assert!(results.is_empty());

        // Test 8: No matches - "summary*" AND "*.xlsx"
        let patterns = vec!["summary*".to_string(), "*.xlsx".to_string()];
        let results = database.search_by_globs_all(&patterns, 100).unwrap();
        assert!(results.is_empty());

        // Test 9: Single character wildcard - "report_202?_final.pdf"
        let patterns = vec!["report_202?_final.pdf".to_string()];
        let results = database.search_by_globs_all(&patterns, 100).unwrap();
        assert_eq!(results.len(), 2); // report_2024_final.pdf, report_2023_final.pdf

        // Test 10: Empty patterns
        let patterns: Vec<String> = vec![];
        let results = database.search_by_globs_all(&patterns, 100).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_by_regexes_all() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("AND_REGEX_VOL", "R:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        // Insert test files - designed to test regex AND logic:
        // Pattern components: IMG/photo/scan prefix, 3/4 digit numbers, edited/raw/original suffix, jpg/png/tiff extension
        let files = [
            // IMG + 4 digits + edited + jpg (all criteria)
            "IMG_0001_edited.jpg",
            "IMG_1234_edited.jpg",
            // IMG + 4 digits + raw + jpg
            "IMG_0002_raw.jpg",
            "IMG_5678_raw.jpg",
            // IMG + 4 digits + edited + png (different extension)
            "IMG_0003_edited.png",
            "IMG_9999_edited.png",
            // IMG + 4 digits + original + tiff
            "IMG_0004_original.tiff",
            // IMG + 3 digits (fewer digits)
            "IMG_001_edited.jpg",
            "IMG_999_raw.jpg",
            // photo + 4 digits + edited + jpg (different prefix)
            "photo_0001_edited.jpg",
            "photo_1234_edited.jpg",
            // photo + 3 digits + edited + jpg
            "photo_001_edited.jpg",
            "photo_999_raw.jpg",
            // scan + 4 digits + jpg
            "scan_0001_processed.jpg",
            "scan_1234_final.jpg",
            // No digits
            "IMG_test_edited.jpg",
            "photo_summer_raw.jpg",
            // Different patterns entirely
            "document_v1.pdf",
            "report_2024.docx",
            "readme.txt",
            "data_export_12345.csv",
        ];

        for name in files {
            let file = create_test_file(volume_id, name, &format!("R:\\{name}"), 100);
            database.insert_file(&file).unwrap();
        }

        // Test 1: "^IMG_" AND "\d{4}" AND "edited" AND "\.jpg$" - most restrictive
        let patterns = vec![
            r"^IMG_".to_string(),
            r"\d{4}".to_string(),
            r"edited".to_string(),
            r"\.jpg$".to_string(),
        ];
        let results = database.search_by_regexes_all(&patterns, false, 100).unwrap();
        assert_eq!(results.len(), 2); // IMG_0001_edited.jpg, IMG_1234_edited.jpg

        // Test 2: "^IMG_" AND "\d{4}" AND "\.jpg$" - without edited requirement
        let patterns = vec![r"^IMG_".to_string(), r"\d{4}".to_string(), r"\.jpg$".to_string()];
        let results = database.search_by_regexes_all(&patterns, false, 100).unwrap();
        assert_eq!(results.len(), 4); // All IMG with 4 digits and .jpg

        // Test 3: "\d{4}" AND "edited" - 4 digits and edited, any prefix/extension
        // IMG_0001_edited.jpg, IMG_1234_edited.jpg, IMG_0003_edited.png, IMG_9999_edited.png,
        // photo_0001_edited.jpg, photo_1234_edited.jpg
        let patterns = vec![r"\d{4}".to_string(), r"edited".to_string()];
        let results = database.search_by_regexes_all(&patterns, false, 100).unwrap();
        assert_eq!(results.len(), 6); // IMG and photo with 4 digits and edited

        // Test 4: "^IMG_" AND "edited" - IMG prefix with edited, any digit count
        // IMG_0001_edited.jpg, IMG_1234_edited.jpg, IMG_0003_edited.png, IMG_9999_edited.png,
        // IMG_001_edited.jpg, IMG_test_edited.jpg
        let patterns = vec![r"^IMG_".to_string(), r"edited".to_string()];
        let results = database.search_by_regexes_all(&patterns, false, 100).unwrap();
        assert_eq!(results.len(), 6); // All IMG_*_edited.* files

        // Test 5: "\.jpg$" AND "raw" - raw JPGs from any source
        // IMG_0002_raw.jpg, IMG_5678_raw.jpg, IMG_999_raw.jpg, photo_999_raw.jpg, photo_summer_raw.jpg
        let patterns = vec![r"\.jpg$".to_string(), r"raw".to_string()];
        let results = database.search_by_regexes_all(&patterns, false, 100).unwrap();
        assert_eq!(results.len(), 5);

        // Test 6: "^photo_" AND "\d{4}" AND "\.jpg$" - photo with 4 digits, jpg
        let patterns = vec![r"^photo_".to_string(), r"\d{4}".to_string(), r"\.jpg$".to_string()];
        let results = database.search_by_regexes_all(&patterns, false, 100).unwrap();
        assert_eq!(results.len(), 2); // photo_0001_edited.jpg, photo_1234_edited.jpg

        // Test 7: "\d{5}" - 5+ consecutive digits
        let patterns = vec![r"\d{5}".to_string()];
        let results = database.search_by_regexes_all(&patterns, false, 100).unwrap();
        assert_eq!(results.len(), 1); // data_export_12345.csv

        // Test 8: "^scan_" AND "\.jpg$" - scan JPGs
        let patterns = vec![r"^scan_".to_string(), r"\.jpg$".to_string()];
        let results = database.search_by_regexes_all(&patterns, false, 100).unwrap();
        assert_eq!(results.len(), 2); // scan_0001_processed.jpg, scan_1234_final.jpg

        // Test 9: No matches - "^IMG_" AND "\.pdf$"
        let patterns = vec![r"^IMG_".to_string(), r"\.pdf$".to_string()];
        let results = database.search_by_regexes_all(&patterns, false, 100).unwrap();
        assert!(results.is_empty());

        // Test 10: No matches - "^photo_" AND "\d{4}" AND "\.tiff$"
        let patterns = vec![r"^photo_".to_string(), r"\d{4}".to_string(), r"\.tiff$".to_string()];
        let results = database.search_by_regexes_all(&patterns, false, 100).unwrap();
        assert!(results.is_empty());

        // Test 11: Empty patterns
        let patterns: Vec<String> = vec![];
        let results = database.search_by_regexes_all(&patterns, false, 100).unwrap();
        assert!(results.is_empty());

        // Test 12: Invalid regex should return error
        let patterns = vec![r"[invalid".to_string()];
        let result = database.search_by_regexes_all(&patterns, false, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_search_by_names_all_single_pattern() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("SINGLE_VOL", "S:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        let file = create_test_file(volume_id, "test_file.txt", "S:\\test_file.txt", 100);
        database.insert_file(&file).unwrap();

        // Single pattern should work like regular search
        let patterns = vec!["test".to_string()];
        let results = database.search_by_names_all(&patterns, 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "test_file.txt");
    }

    #[test]
    fn test_search_by_names_all_case_insensitive() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("CASE_AND_VOL", "C:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        // Files with various case combinations
        let files = [
            "Config_Settings.json",
            "CONFIG_BACKUP.JSON",
            "config_data.json",
            "MyConfig.yaml",
            "SETTINGS_config.xml",
            "Config.txt",
            "settings.json",
            "backup.json",
            "other.txt",
        ];
        for name in files {
            let file = create_test_file(volume_id, name, &format!("C:\\{name}"), 100);
            database.insert_file(&file).unwrap();
        }

        // Test 1: Case-insensitive AND search - "CONFIG" AND "json"
        let patterns = vec!["CONFIG".to_string(), "json".to_string()];
        let results = database.search_by_names_all(&patterns, 100).unwrap();
        assert_eq!(results.len(), 3); // Config_Settings.json, CONFIG_BACKUP.JSON, config_data.json

        // Test 2: Mixed case patterns - "config" AND "SETTINGS"
        let patterns = vec!["config".to_string(), "SETTINGS".to_string()];
        let results = database.search_by_names_all(&patterns, 100).unwrap();
        assert_eq!(results.len(), 2); // Config_Settings.json, SETTINGS_config.xml

        // Test 3: "JSON" alone (uppercase)
        let patterns = vec!["JSON".to_string()];
        let results = database.search_by_names_all(&patterns, 100).unwrap();
        assert_eq!(results.len(), 5); // All .json files
    }

    #[test]
    fn test_search_by_names_all_with_limit() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("LIMIT_AND_VOL", "L:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        // Insert many matching files
        for i in 0..10 {
            let name = format!("config_settings_{i}.json");
            let file = create_test_file(volume_id, &name, &format!("L:\\{name}"), 100);
            database.insert_file(&file).unwrap();
        }

        // Search with limit
        let patterns = vec!["config".to_string(), "settings".to_string()];
        let results = database.search_by_names_all(&patterns, 5).unwrap();
        assert_eq!(results.len(), 5);
    }

    #[test]
    fn test_search_by_names_all_three_patterns() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("THREE_PAT_VOL", "T:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        // Files designed to test three-pattern AND logic
        // Each file has different combinations of: app, config, backup, data
        let files = [
            // Has all three: app, config, backup
            "app_config_backup.json",
            "app_backup_config.yaml",
            // Has app + config (missing backup)
            "app_config.json",
            "app_config_settings.yaml",
            "my_app_config.toml",
            // Has app + backup (missing config)
            "app_backup.json",
            "app_data_backup.zip",
            // Has config + backup (missing app)
            "config_backup.json",
            "system_config_backup.tar",
            // Has only app
            "app.exe",
            "myapp.dll",
            "app_launcher.bat",
            // Has only config
            "config.yaml",
            "nginx_config.conf",
            // Has only backup
            "backup.zip",
            "daily_backup.tar.gz",
            // Has none
            "readme.txt",
            "document.pdf",
            "data.csv",
        ];
        for name in files {
            let file = create_test_file(volume_id, name, &format!("T:\\{name}"), 100);
            database.insert_file(&file).unwrap();
        }

        // Test 1: Three patterns - "app" AND "config" AND "backup"
        let patterns = vec!["app".to_string(), "config".to_string(), "backup".to_string()];
        let results = database.search_by_names_all(&patterns, 100).unwrap();
        assert_eq!(results.len(), 2); // app_config_backup.json, app_backup_config.yaml

        // Test 2: Two of the three - "app" AND "config"
        let patterns = vec!["app".to_string(), "config".to_string()];
        let results = database.search_by_names_all(&patterns, 100).unwrap();
        assert_eq!(results.len(), 5); // All files with both app and config

        // Test 3: Two of the three - "app" AND "backup"
        let patterns = vec!["app".to_string(), "backup".to_string()];
        let results = database.search_by_names_all(&patterns, 100).unwrap();
        assert_eq!(results.len(), 4); // All files with both app and backup

        // Test 4: Two of the three - "config" AND "backup"
        let patterns = vec!["config".to_string(), "backup".to_string()];
        let results = database.search_by_names_all(&patterns, 100).unwrap();
        assert_eq!(results.len(), 4); // All files with both config and backup

        // Test 5: Four patterns with impossible fourth term
        let patterns = vec![
            "app".to_string(),
            "config".to_string(),
            "backup".to_string(),
            "xyz".to_string(),
        ];
        let results = database.search_by_names_all(&patterns, 100).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_by_names_all_no_matches() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("NO_MATCH_VOL", "N:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        let file = create_test_file(volume_id, "document.txt", "N:\\document.txt", 100);
        database.insert_file(&file).unwrap();

        // Patterns that can't all match
        let patterns = vec!["document".to_string(), "xyz".to_string()];
        let results = database.search_by_names_all(&patterns, 10).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_by_globs_all_with_limit() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("GLOB_LIMIT_VOL", "G:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        for i in 0..10 {
            let name = format!("report_{i}_final.pdf");
            let file = create_test_file(volume_id, &name, &format!("G:\\{name}"), 100);
            database.insert_file(&file).unwrap();
        }

        let patterns = vec!["report*".to_string(), "*final*".to_string()];
        let results = database.search_by_globs_all(&patterns, 3).unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_search_by_globs_all_question_mark() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("GLOB_Q_VOL", "Q:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        let files = ["file1.txt", "file2.txt", "file10.txt", "data1.txt"];
        for name in files {
            let file = create_test_file(volume_id, name, &format!("Q:\\{name}"), 100);
            database.insert_file(&file).unwrap();
        }

        // file?.txt matches single char, *.txt matches all
        let patterns = vec!["file?.txt".to_string(), "*.txt".to_string()];
        let results = database.search_by_globs_all(&patterns, 10).unwrap();
        assert_eq!(results.len(), 2); // file1.txt and file2.txt (file10 has 2 chars)
    }

    #[test]
    fn test_search_by_regexes_all_case_sensitive() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("REGEX_CASE_VOL", "R:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        let files = ["README.txt", "readme.md", "ReadMe.html"];
        for name in files {
            let file = create_test_file(volume_id, name, &format!("R:\\{name}"), 100);
            database.insert_file(&file).unwrap();
        }

        // Case-sensitive: only README matches ^README
        let patterns = vec![r"^README".to_string()];
        let results = database.search_by_regexes_all(&patterns, true, 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "README.txt");

        // Case-insensitive: all match ^readme
        let patterns = vec![r"^readme".to_string()];
        let results = database.search_by_regexes_all(&patterns, false, 10).unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_search_by_regexes_all_complex_patterns() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("REGEX_COMPLEX_VOL", "X:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        // Files with various combinations of: type (report/summary/invoice), year (2023/2024), month (01-12), format (pdf/xlsx/docx)
        let files = [
            // report + 2024 + various months + pdf
            "report_2024_01.pdf",
            "report_2024_02.pdf",
            "report_2024_06.pdf",
            "report_2024_12.pdf",
            // report + 2024 + xlsx
            "report_2024_01.xlsx",
            "report_2024_q1.xlsx",
            // report + 2023 + pdf
            "report_2023_01.pdf",
            "report_2023_12.pdf",
            // summary + 2024 + pdf
            "summary_2024_01.pdf",
            "summary_2024_annual.pdf",
            // summary + 2023 + pdf
            "summary_2023_q4.pdf",
            // invoice + 2024 + pdf
            "invoice_2024_001.pdf",
            "invoice_2024_002.pdf",
            // invoice + 2024 + docx
            "invoice_2024_draft.docx",
            // Mixed/other
            "report_template.docx",
            "2024_calendar.pdf",
            "notes_2024.txt",
            "readme.md",
        ];
        for name in files {
            let file = create_test_file(volume_id, name, &format!("X:\\{name}"), 100);
            database.insert_file(&file).unwrap();
        }

        // Test 1: "^report" AND "2024" AND "\.pdf$" - 2024 report PDFs
        let patterns = vec![r"^report".to_string(), r"2024".to_string(), r"\.pdf$".to_string()];
        let results = database.search_by_regexes_all(&patterns, false, 100).unwrap();
        assert_eq!(results.len(), 4); // report_2024_01/02/06/12.pdf

        // Test 2: "^report" AND "2024" - 2024 reports in any format
        let patterns = vec![r"^report".to_string(), r"2024".to_string()];
        let results = database.search_by_regexes_all(&patterns, false, 100).unwrap();
        assert_eq!(results.len(), 6); // All report_2024_* files

        // Test 3: "2024" AND "\.pdf$" - all 2024 PDFs
        let patterns = vec![r"2024".to_string(), r"\.pdf$".to_string()];
        let results = database.search_by_regexes_all(&patterns, false, 100).unwrap();
        assert_eq!(results.len(), 9); // All *2024*.pdf files

        // Test 4: "^invoice" AND "2024" AND "\.pdf$"
        let patterns = vec![r"^invoice".to_string(), r"2024".to_string(), r"\.pdf$".to_string()];
        let results = database.search_by_regexes_all(&patterns, false, 100).unwrap();
        assert_eq!(results.len(), 2); // invoice_2024_001.pdf, invoice_2024_002.pdf

        // Test 5: Month pattern - "_0[1-6]\." AND "2024" (first half of year)
        let patterns = vec![r"_0[1-6]\.".to_string(), r"2024".to_string()];
        let results = database.search_by_regexes_all(&patterns, false, 100).unwrap();
        assert_eq!(results.len(), 5); // Files with months 01-06 and 2024

        // Test 6: "^(report|summary)" AND "2024" AND "\.pdf$" - reports or summaries
        let patterns = vec![
            r"^(report|summary)".to_string(),
            r"2024".to_string(),
            r"\.pdf$".to_string(),
        ];
        let results = database.search_by_regexes_all(&patterns, false, 100).unwrap();
        assert_eq!(results.len(), 6); // 4 reports + 2 summaries

        // Test 7: No matches - "^invoice" AND "2023"
        let patterns = vec![r"^invoice".to_string(), r"2023".to_string()];
        let results = database.search_by_regexes_all(&patterns, false, 100).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_by_regexes_all_multiple_invalid() {
        let database = Database::open_in_memory().unwrap();

        // Second pattern is invalid
        let patterns = vec![r"valid".to_string(), r"[invalid".to_string()];
        let result = database.search_by_regexes_all(&patterns, false, 10);
        assert!(result.is_err());
    }

    #[test]
    fn test_search_by_names_all_overlapping_patterns() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("OVERLAP_VOL", "O:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        // Files with overlapping/repeated substrings
        let files = [
            "configconfig.txt",       // config appears twice
            "config.txt",             // config once
            "myconfig.txt",           // config once
            "config_config_file.txt", // config twice with separator
            "testtest.txt",           // test appears twice
            "test.txt",               // test once
            "other.txt",              // no config or test
        ];
        for name in files {
            let file = create_test_file(volume_id, name, &format!("O:\\{name}"), 100);
            database.insert_file(&file).unwrap();
        }

        // Test 1: Both patterns are "config" - should match all files with "config"
        let patterns = vec!["config".to_string(), "config".to_string()];
        let results = database.search_by_names_all(&patterns, 100).unwrap();
        assert_eq!(results.len(), 4);

        // Test 2: "config" AND "file" - only one file has both
        let patterns = vec!["config".to_string(), "file".to_string()];
        let results = database.search_by_names_all(&patterns, 100).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "config_config_file.txt");

        // Test 3: "test" twice - matches files with "test"
        let patterns = vec!["test".to_string(), "test".to_string()];
        let results = database.search_by_names_all(&patterns, 100).unwrap();
        assert_eq!(results.len(), 2); // testtest.txt, test.txt

        // Test 4: "config" AND "test" - no file has both
        let patterns = vec!["config".to_string(), "test".to_string()];
        let results = database.search_by_names_all(&patterns, 100).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_by_names_all_special_sql_characters() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("SQL_CHAR_VOL", "S:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        // Files with SQL special characters
        let files = ["100%_complete.txt", "test_file.txt", "100%_done.txt"];
        for name in files {
            let file = create_test_file(volume_id, name, &format!("S:\\{name}"), 100);
            database.insert_file(&file).unwrap();
        }

        // Search for files with "100" and "%" - the % in the search is literal
        let patterns = vec!["100".to_string(), "%".to_string()];
        let results = database.search_by_names_all(&patterns, 10).unwrap();
        assert_eq!(results.len(), 2); // 100%_complete.txt and 100%_done.txt
    }

    #[test]
    fn test_search_by_globs_all_no_matches() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("GLOB_NO_MATCH", "G:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        // Files with various extensions and prefixes
        let files = [
            "document.pdf",
            "report.pdf",
            "notes.txt",
            "readme.txt",
            "data.csv",
            "image.png",
            "photo.jpg",
        ];
        for name in files {
            let file = create_test_file(volume_id, name, &format!("G:\\{name}"), 100);
            database.insert_file(&file).unwrap();
        }

        // Test 1: Impossible - same file can't have two different extensions
        let patterns = vec!["*.pdf".to_string(), "*.txt".to_string()];
        let results = database.search_by_globs_all(&patterns, 100).unwrap();
        assert!(results.is_empty());

        // Test 2: Impossible - "report*" AND "*.txt" (report files are PDFs)
        let patterns = vec!["report*".to_string(), "*.txt".to_string()];
        let results = database.search_by_globs_all(&patterns, 100).unwrap();
        assert!(results.is_empty());

        // Test 3: Impossible - "data*" AND "*.pdf"
        let patterns = vec!["data*".to_string(), "*.pdf".to_string()];
        let results = database.search_by_globs_all(&patterns, 100).unwrap();
        assert!(results.is_empty());

        // Test 4: Pattern that matches nothing at all
        let patterns = vec!["xyz*".to_string(), "*.abc".to_string()];
        let results = database.search_by_globs_all(&patterns, 100).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_by_names_all_unicode() {
        let database = Database::open_in_memory().unwrap();

        let volume = create_test_volume("UNICODE_AND_VOL", "U:");
        let volume_id = database.upsert_volume(&volume).unwrap();

        // Files with various unicode characters from different languages
        let files = [
            // Japanese + config
            "日本語_config.txt",
            "設定_config.json",
            // Chinese + config
            "config_设置.txt",
            "中文_config.yaml",
            // Japanese + Chinese + config (all three)
            "日本語_设置_config.xml",
            // config only (ASCII)
            "config_test.txt",
            "myconfig.ini",
            // Japanese only
            "日本語_ファイル.txt",
            "設定.yaml",
            // Chinese only
            "设置_文件.txt",
            "中文文档.pdf",
            // Other unicode (Korean, emoji)
            "한국어_config.txt",
            "config_📁_folder.txt",
            // No unicode
            "readme.txt",
            "document.pdf",
        ];
        for name in files {
            let file = create_test_file(volume_id, name, &format!("U:\\{name}"), 100);
            database.insert_file(&file).unwrap();
        }

        // Test 1: "config" AND "日本語" (Japanese)
        let patterns = vec!["config".to_string(), "日本語".to_string()];
        let results = database.search_by_names_all(&patterns, 100).unwrap();
        assert_eq!(results.len(), 2); // 日本語_config.txt, 日本語_设置_config.xml

        // Test 2: "config" AND "设置" (Chinese for "settings")
        let patterns = vec!["config".to_string(), "设置".to_string()];
        let results = database.search_by_names_all(&patterns, 100).unwrap();
        assert_eq!(results.len(), 2); // config_设置.txt, 日本語_设置_config.xml

        // Test 3: "日本語" AND "设置" AND "config" (Japanese + Chinese + English)
        let patterns = vec!["日本語".to_string(), "设置".to_string(), "config".to_string()];
        let results = database.search_by_names_all(&patterns, 100).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "日本語_设置_config.xml");

        // Test 4: "config" AND emoji
        let patterns = vec!["config".to_string(), "📁".to_string()];
        let results = database.search_by_names_all(&patterns, 100).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "config_📁_folder.txt");

        // Test 5: Korean AND config
        let patterns = vec!["한국어".to_string(), "config".to_string()];
        let results = database.search_by_names_all(&patterns, 100).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "한국어_config.txt");

        // Test 6: No matches - Japanese AND Chinese without config
        let patterns = vec!["日本語".to_string(), "中文".to_string()];
        let results = database.search_by_names_all(&patterns, 100).unwrap();
        assert!(results.is_empty());
    }
}
