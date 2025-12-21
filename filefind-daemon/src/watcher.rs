//! File system watcher for non-NTFS drives.
//!
//! This module provides file system monitoring for drives that don't support
//! MFT/USN Journal access (network drives, FAT32, exFAT, etc.) using the
//! `notify` crate which wraps platform-native file watching APIs.
//!
//! On Windows, this uses `ReadDirectoryChangesW`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use filefind::types::FileChangeEvent;

/// Default debounce duration to coalesce rapid file changes.
const DEFAULT_DEBOUNCE_MS: u64 = 1000;

/// File system watcher for monitoring directories.
pub struct FileWatcher {
    /// The paths being watched.
    watched_paths: Vec<PathBuf>,

    /// Patterns to exclude from watching.
    exclude_patterns: Vec<String>,

    /// Debounce duration in milliseconds.
    debounce_ms: u64,

    /// Whether to watch recursively.
    recursive: bool,

    /// Shutdown flag.
    shutdown: Arc<AtomicBool>,
}

impl Default for FileWatcher {
    fn default() -> Self {
        Self {
            watched_paths: Vec::new(),
            exclude_patterns: Vec::new(),
            debounce_ms: DEFAULT_DEBOUNCE_MS,
            recursive: true,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl FileWatcher {
    /// Create a new file watcher.
    #[must_use]
    pub fn new(paths: Vec<PathBuf>, exclude_patterns: Vec<String>, debounce_ms: u64, recursive: bool) -> Self {
        Self {
            watched_paths: paths,
            exclude_patterns,
            debounce_ms,
            recursive,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Create a new file watcher for a single path.
    #[cfg(test)]
    #[must_use]
    pub fn for_path(path: PathBuf) -> Self {
        Self {
            watched_paths: vec![path],
            exclude_patterns: Vec::new(),
            debounce_ms: DEFAULT_DEBOUNCE_MS,
            recursive: true,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Add a path to watch.
    #[cfg(test)]
    pub fn add_path(&mut self, path: PathBuf) {
        if !self.watched_paths.contains(&path) {
            self.watched_paths.push(path);
        }
    }

    /// Add an exclusion pattern.
    #[cfg(test)]
    pub fn add_exclude_pattern(&mut self, pattern: String) {
        if !self.exclude_patterns.contains(&pattern) {
            self.exclude_patterns.push(pattern);
        }
    }

    /// Check if a path should be excluded based on the exclusion patterns.
    #[cfg(test)]
    fn should_exclude(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();

        for pattern in &self.exclude_patterns {
            // Simple glob matching for common cases
            if pattern.starts_with('*') && pattern.ends_with('*') {
                // *pattern* - contains
                let inner = &pattern[1..pattern.len() - 1];
                if path_str.contains(inner) {
                    return true;
                }
            } else if let Some(suffix) = pattern.strip_prefix('*') {
                // *pattern - ends with
                if path_str.ends_with(suffix) {
                    return true;
                }
            } else if pattern.ends_with('*') {
                // pattern* - starts with
                let prefix = &pattern[..pattern.len() - 1];
                if path_str.starts_with(prefix) {
                    return true;
                }
            } else {
                // Exact match or contains
                if path_str.contains(pattern.as_str()) {
                    return true;
                }
            }
        }

        false
    }

    /// Start watching for file changes with debouncing.
    ///
    /// Returns a channel receiver for change events and a shutdown handle.
    ///
    /// Events for the same path within `debounce_ms` milliseconds are coalesced
    /// to avoid processing rapid duplicate events.
    #[allow(clippy::too_many_lines)]
    pub fn start(self) -> Result<(mpsc::Receiver<FileChangeEvent>, Arc<AtomicBool>)> {
        let (event_tx, event_rx) = mpsc::channel(1000);
        let shutdown = self.shutdown.clone();
        let watched_paths = self.watched_paths.clone();
        let exclude_patterns = self.exclude_patterns.clone();
        let debounce_ms = self.debounce_ms;
        let recursive = self.recursive;

        // Create a channel for notify events
        let (notify_tx, mut notify_rx) = mpsc::channel(1000);

        // Create the watcher
        let watcher_shutdown = shutdown.clone();
        let mut watcher: RecommendedWatcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            if watcher_shutdown.load(Ordering::Relaxed) {
                return;
            }

            match res {
                Ok(event) => {
                    // Use blocking send since we're in a sync callback
                    let _ = notify_tx.blocking_send(event);
                }
                Err(error) => {
                    error!("File watcher error: {}", error);
                }
            }
        })
        .context("Failed to create file watcher")?;

        // Add paths to watch
        let mode = if recursive {
            RecursiveMode::Recursive
        } else {
            RecursiveMode::NonRecursive
        };

        for path in &watched_paths {
            if path.exists() {
                match watcher.watch(path, mode) {
                    Ok(()) => {
                        info!("Watching path: {}", path.display());
                    }
                    Err(error) => {
                        warn!("Failed to watch path {}: {}", path.display(), error);
                    }
                }
            } else {
                warn!("Path does not exist, skipping: {}", path.display());
            }
        }

        // Spawn async task to process events with debouncing
        let process_shutdown = shutdown.clone();
        let debounce_duration = Duration::from_millis(debounce_ms);
        tokio::spawn(async move {
            // Keep watcher alive
            let _watcher = watcher;

            info!("File watcher started (debounce: {}ms)", debounce_ms);

            // Track pending events with their timestamps for debouncing
            // Key: path, Value: (event_kind, first_seen_time)
            let mut pending_events: HashMap<PathBuf, (FileChangeEvent, std::time::Instant)> = HashMap::new();
            let mut last_flush = std::time::Instant::now();

            while !process_shutdown.load(Ordering::Relaxed) {
                // Wait for events with a timeout proportional to debounce duration
                // Use half the debounce time (clamped) for responsive flushing
                let poll_interval = Duration::from_millis((debounce_ms / 2).clamp(50, 1000));
                match tokio::time::timeout(poll_interval, notify_rx.recv()).await {
                    Ok(Some(event)) => {
                        let now = std::time::Instant::now();

                        // Convert and filter events
                        for path in event.paths {
                            if exclude_patterns.iter().any(|p| {
                                let path_str = path.to_string_lossy();
                                path_str.contains(p.as_str())
                            }) {
                                continue;
                            }

                            let change = match event.kind {
                                EventKind::Create(_) => Some(FileChangeEvent::Created(path.clone())),
                                EventKind::Modify(_) => Some(FileChangeEvent::Modified(path.clone())),
                                EventKind::Remove(_) => Some(FileChangeEvent::Deleted(path.clone())),
                                _ => None,
                            };

                            if let Some(change) = change {
                                // Update or insert the pending event
                                // If an event already exists for this path, keep the original timestamp
                                // but update to the latest event type (e.g., Create -> Modify -> Delete)
                                pending_events
                                    .entry(path)
                                    .and_modify(|(existing_change, _timestamp)| {
                                        // Keep Created if file was created then modified
                                        // (a new file being modified is still "created")
                                        // Otherwise, update to the latest event type
                                        if !matches!(
                                            (&existing_change, &change),
                                            (FileChangeEvent::Created(_), FileChangeEvent::Modified(_))
                                        ) {
                                            *existing_change = change.clone();
                                        }
                                    })
                                    .or_insert((change, now));
                            }
                        }
                    }
                    Ok(None) => {
                        // Channel closed
                        break;
                    }
                    Err(_) => {
                        // Timeout - check for events to flush
                    }
                }

                // Flush events that have been pending longer than debounce_duration
                let now = std::time::Instant::now();
                if now.duration_since(last_flush) >= debounce_duration {
                    let mut to_send = Vec::new();

                    pending_events.retain(|_path, (change, timestamp)| {
                        if now.duration_since(*timestamp) >= debounce_duration {
                            to_send.push(change.clone());
                            false // Remove from pending
                        } else {
                            true // Keep in pending
                        }
                    });

                    for change in to_send {
                        debug!("File change detected (debounced): {}", change);
                        if event_tx.send(change).await.is_err() {
                            // Receiver dropped
                            break;
                        }
                    }

                    last_flush = now;
                }
            }

            // Flush any remaining pending events on shutdown
            for (change, _) in pending_events.into_values() {
                let _ = event_tx.send(change).await;
            }

            info!("File watcher stopped");
        });

        Ok((event_rx, shutdown))
    }

    /// Stop the file watcher.
    pub fn stop(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    /// Get the paths being watched.
    #[must_use]
    pub fn watched_paths(&self) -> &[PathBuf] {
        &self.watched_paths
    }

    /// Get the exclusion patterns.
    #[cfg(test)]
    #[must_use]
    pub fn exclude_patterns(&self) -> &[String] {
        &self.exclude_patterns
    }
}

/// Default number of concurrent directory scan tasks.
/// Optimized for HDDs (NCQ depth) and network shares (latency hiding).
const DEFAULT_SCAN_CONCURRENCY: usize = 32;

/// Perform an initial directory scan to populate the index.
///
/// This walks the directory tree and returns all files and directories found.
/// Uses parallel scanning with tokio for better performance.
pub async fn scan_directory(root: &Path, exclude_patterns: &[String]) -> Result<Vec<ScanEntry>> {
    scan_directory_with_concurrency(root, exclude_patterns, DEFAULT_SCAN_CONCURRENCY).await
}

/// Perform an initial directory scan with configurable concurrency.
///
/// # Arguments
/// * `root` - Root directory to scan
/// * `exclude_patterns` - Patterns to exclude from scanning
/// * `max_concurrency` - Maximum number of concurrent directory scan tasks
pub async fn scan_directory_with_concurrency(
    root: &Path,
    exclude_patterns: &[String],
    max_concurrency: usize,
) -> Result<Vec<ScanEntry>> {
    info!("{} Starting file scan", root.display());

    let root = root.to_path_buf();
    let exclude_patterns: Arc<[String]> = exclude_patterns.to_vec().into();
    let entries: Arc<tokio::sync::Mutex<Vec<ScanEntry>>> = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrency));

    // Add the root directory itself
    if let Ok(metadata) = tokio::fs::metadata(&root).await {
        let root_entry = ScanEntry {
            path: root.clone(),
            name: root.file_name().map_or_else(
                || root.to_string_lossy().into_owned(),
                |n| n.to_string_lossy().into_owned(),
            ),
            is_directory: metadata.is_dir(),
            size: 0,
            modified: metadata.modified().ok(),
            created: metadata.created().ok(),
        };
        entries.lock().await.push(root_entry);
    }

    // Process directories with bounded concurrency using a semaphore
    let mut dirs_to_process = vec![root.clone()];

    while !dirs_to_process.is_empty() {
        // Process current batch with concurrency limit
        let batch: Vec<_> = std::mem::take(&mut dirs_to_process);
        let mut tasks = Vec::with_capacity(batch.len());

        for dir in batch {
            let entries = entries.clone();
            let exclude_patterns = exclude_patterns.clone();
            let semaphore = semaphore.clone();

            tasks.push(tokio::spawn(async move {
                // Acquire permit before scanning (limits concurrent I/O)
                let permit = semaphore.acquire().await.expect("Semaphore should not be closed");
                let result = scan_single_directory(dir, exclude_patterns, entries).await;
                drop(permit);
                result
            }));
        }

        // Collect results (subdirectories to process next)
        for task in tasks {
            match task.await {
                Ok(subdirs) => dirs_to_process.extend(subdirs),
                Err(error) => warn!("Directory scan task failed: {error}"),
            }
        }
    }

    let mut result = Arc::try_unwrap(entries)
        .expect("All references should be dropped")
        .into_inner();

    // Sort by path for consistent ordering
    result.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(result)
}

/// Scan a single directory and return its subdirectories.
async fn scan_single_directory(
    dir: PathBuf,
    exclude_patterns: Arc<[String]>,
    entries: Arc<tokio::sync::Mutex<Vec<ScanEntry>>>,
) -> Vec<PathBuf> {
    let mut read_dir = match tokio::fs::read_dir(&dir).await {
        Ok(read_dir) => read_dir,
        Err(error) => {
            warn!("Error reading directory {}: {error}", dir.display());
            return Vec::new();
        }
    };

    let mut subdirs = Vec::new();
    let mut local_entries = Vec::new();

    while let Ok(Some(entry)) = read_dir.next_entry().await {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();

        // Skip hidden files/directories
        if name.starts_with('.') && !name.starts_with(".tmp") {
            continue;
        }

        // Check exclusion patterns
        if matches_exclude_patterns(&path.to_string_lossy(), &exclude_patterns) {
            continue;
        }

        let metadata = match entry.metadata().await {
            Ok(metadata) => metadata,
            Err(error) => {
                warn!("Error reading metadata for {}: {error}", path.display());
                continue;
            }
        };

        let is_directory = metadata.is_dir();

        let scan_entry = ScanEntry {
            path: path.clone(),
            name,
            is_directory,
            size: if metadata.is_file() { metadata.len() } else { 0 },
            modified: metadata.modified().ok(),
            created: metadata.created().ok(),
        };

        local_entries.push(scan_entry);

        if is_directory {
            subdirs.push(path);
        }
    }

    // Add local entries to the shared collection
    {
        let mut guard = entries.lock().await;
        guard.extend(local_entries);
    }

    subdirs
}

/// Check if a path matches any of the exclusion patterns.
///
/// Supports glob-style patterns:
/// - `*pattern` - matches paths ending with "pattern"
/// - `pattern*` - matches paths starting with "pattern"
/// - `*pattern*` - matches paths containing "pattern"
/// - `pattern` - matches paths containing "pattern" anywhere
pub fn matches_exclude_patterns(path_str: &str, exclude_patterns: &[String]) -> bool {
    for pattern in exclude_patterns {
        if pattern.starts_with('*') && pattern.ends_with('*') {
            let inner = &pattern[1..pattern.len() - 1];
            if path_str.contains(inner) {
                return true;
            }
        } else if let Some(suffix) = pattern.strip_prefix('*') {
            if path_str.ends_with(suffix) {
                return true;
            }
        } else if pattern.ends_with('*') {
            let prefix = &pattern[..pattern.len() - 1];
            if path_str.starts_with(prefix) {
                return true;
            }
        } else if path_str.contains(pattern) {
            return true;
        }
    }

    false
}

/// Entry from a directory scan.
#[derive(Debug, Clone)]
pub struct ScanEntry {
    /// Full path to the file or directory.
    pub path: PathBuf,

    /// File or directory name.
    pub name: String,

    /// Whether this is a directory.
    pub is_directory: bool,

    /// File size in bytes (0 for directories).
    pub size: u64,

    /// Last modified time.
    pub modified: Option<std::time::SystemTime>,

    /// Creation time.
    pub created: Option<std::time::SystemTime>,
}

impl ScanEntry {
    /// Convert to a `FileEntry` for database storage.
    #[must_use]
    pub fn to_file_entry(&self, volume_id: i64) -> filefind::types::FileEntry {
        filefind::types::FileEntry {
            id: None,
            volume_id,
            parent_id: None,
            name: self.name.clone(),
            full_path: self.path.to_string_lossy().into_owned(),
            is_directory: self.is_directory,
            size: self.size,
            created_time: self.created,
            modified_time: self.modified,
            mft_reference: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::SystemTime;
    use tempfile::tempdir;

    #[test]
    fn test_should_exclude() {
        let watcher = FileWatcher {
            watched_paths: vec![],
            exclude_patterns: vec![
                "*.tmp".to_string(),
                "*\\node_modules\\*".to_string(),
                "Thumbs.db".to_string(),
            ],
            debounce_ms: DEFAULT_DEBOUNCE_MS,
            recursive: true,
            shutdown: Arc::new(AtomicBool::new(false)),
        };

        assert!(watcher.should_exclude(Path::new("test.tmp")));
        assert!(watcher.should_exclude(Path::new("C:\\project\\node_modules\\pkg")));
        assert!(watcher.should_exclude(Path::new("C:\\photos\\Thumbs.db")));
        assert!(!watcher.should_exclude(Path::new("document.pdf")));
    }

    #[test]
    fn test_should_exclude_suffix_pattern() {
        // Pattern "*pattern" matches paths ending with "pattern"
        let watcher = FileWatcher {
            watched_paths: vec![],
            exclude_patterns: vec!["*.bak".to_string(), "*.tmp".to_string()],
            debounce_ms: DEFAULT_DEBOUNCE_MS,
            recursive: true,
            shutdown: Arc::new(AtomicBool::new(false)),
        };

        // Should match - ends with .bak
        assert!(watcher.should_exclude(Path::new("file.bak")));
        assert!(watcher.should_exclude(Path::new("C:\\folder\\data.bak")));
        assert!(watcher.should_exclude(Path::new("test.tmp")));

        // Should not match - different extension
        assert!(!watcher.should_exclude(Path::new("file.txt")));
        assert!(!watcher.should_exclude(Path::new("file.bak.txt")));
    }

    #[test]
    fn test_should_exclude_contains_pattern() {
        // Pattern "*pattern*" matches paths containing "pattern"
        let watcher = FileWatcher {
            watched_paths: vec![],
            exclude_patterns: vec!["*cache*".to_string(), "*node_modules*".to_string()],
            debounce_ms: DEFAULT_DEBOUNCE_MS,
            recursive: true,
            shutdown: Arc::new(AtomicBool::new(false)),
        };

        // Should match - contains "cache"
        assert!(watcher.should_exclude(Path::new("C:\\mycache\\file.txt")));
        assert!(watcher.should_exclude(Path::new("cache_dir")));
        assert!(watcher.should_exclude(Path::new("filecache")));

        // Should match - contains "node_modules"
        assert!(watcher.should_exclude(Path::new("C:\\project\\node_modules\\pkg")));

        // Should not match
        assert!(!watcher.should_exclude(Path::new("C:\\important\\file.txt")));
    }

    #[test]
    fn test_should_exclude_exact_substring_pattern() {
        // Pattern without wildcards matches if path contains the pattern anywhere
        let watcher = FileWatcher {
            watched_paths: vec![],
            exclude_patterns: vec!["Thumbs.db".to_string(), ".git".to_string()],
            debounce_ms: DEFAULT_DEBOUNCE_MS,
            recursive: true,
            shutdown: Arc::new(AtomicBool::new(false)),
        };

        // Should match - contains exact substring
        assert!(watcher.should_exclude(Path::new("Thumbs.db")));
        assert!(watcher.should_exclude(Path::new("C:\\photos\\Thumbs.db")));
        assert!(watcher.should_exclude(Path::new("C:\\project\\.git\\config")));

        // Should not match
        assert!(!watcher.should_exclude(Path::new("thumbs.db"))); // case sensitive
        assert!(!watcher.should_exclude(Path::new("file.txt")));
    }

    #[test]
    fn test_should_exclude_empty_patterns() {
        let watcher = FileWatcher {
            watched_paths: vec![],
            exclude_patterns: vec![],
            debounce_ms: DEFAULT_DEBOUNCE_MS,
            recursive: true,
            shutdown: Arc::new(AtomicBool::new(false)),
        };

        // With no patterns, nothing should be excluded
        assert!(!watcher.should_exclude(Path::new("any_file.txt")));
        assert!(!watcher.should_exclude(Path::new("C:\\Windows\\System32")));
        assert!(!watcher.should_exclude(Path::new(".hidden")));
    }

    #[test]
    fn test_should_exclude_multiple_patterns_first_match_wins() {
        let watcher = FileWatcher {
            watched_paths: vec![],
            exclude_patterns: vec!["*.log".to_string(), "*temp*".to_string(), "secret.txt".to_string()],
            debounce_ms: DEFAULT_DEBOUNCE_MS,
            recursive: true,
            shutdown: Arc::new(AtomicBool::new(false)),
        };

        // Each pattern can independently match
        assert!(watcher.should_exclude(Path::new("app.log")));
        assert!(watcher.should_exclude(Path::new("C:\\temp\\file.txt")));
        assert!(watcher.should_exclude(Path::new("secret.txt")));

        // None match
        assert!(!watcher.should_exclude(Path::new("important.txt")));
    }

    #[test]
    fn test_scan_entry_to_file_entry() {
        let entry = ScanEntry {
            path: PathBuf::from("C:\\test\\document.pdf"),
            name: "document.pdf".to_string(),
            is_directory: false,
            size: 1024,
            modified: None,
            created: None,
        };

        let file_entry = entry.to_file_entry(1);
        assert_eq!(file_entry.name, "document.pdf");
        assert_eq!(file_entry.volume_id, 1);
        assert!(!file_entry.is_directory);
        assert_eq!(file_entry.size, 1024);
    }

    #[test]
    fn test_scan_entry_to_file_entry_with_timestamps() {
        let now = SystemTime::now();
        let created = now;
        let modified = now;

        let entry = ScanEntry {
            path: PathBuf::from("C:\\folder\\file.txt"),
            name: "file.txt".to_string(),
            is_directory: false,
            size: 500,
            modified: Some(modified),
            created: Some(created),
        };

        let file_entry = entry.to_file_entry(42);
        assert_eq!(file_entry.volume_id, 42);
        assert!(file_entry.created_time.is_some());
        assert!(file_entry.modified_time.is_some());
        assert_eq!(file_entry.size, 500);
    }

    #[test]
    fn test_scan_entry_to_file_entry_directory() {
        let entry = ScanEntry {
            path: PathBuf::from("C:\\folder"),
            name: "folder".to_string(),
            is_directory: true,
            size: 0,
            modified: None,
            created: None,
        };

        let file_entry = entry.to_file_entry(1);
        assert!(file_entry.is_directory);
        assert_eq!(file_entry.size, 0);
        assert_eq!(file_entry.full_path, "C:\\folder");
    }

    #[test]
    fn test_scan_entry_clone() {
        let entry = ScanEntry {
            path: PathBuf::from("C:\\test.txt"),
            name: "test.txt".to_string(),
            is_directory: false,
            size: 100,
            modified: Some(SystemTime::now()),
            created: None,
        };

        let cloned = entry.clone();
        assert_eq!(entry.name, cloned.name);
        assert_eq!(entry.path, cloned.path);
        assert_eq!(entry.size, cloned.size);
        assert_eq!(entry.is_directory, cloned.is_directory);
    }

    #[test]
    fn test_scan_entry_debug() {
        let entry = ScanEntry {
            path: PathBuf::from("C:\\debug.txt"),
            name: "debug.txt".to_string(),
            is_directory: false,
            size: 0,
            modified: None,
            created: None,
        };

        let debug_str = format!("{entry:?}");
        assert!(debug_str.contains("ScanEntry"));
        assert!(debug_str.contains("debug.txt"));
    }

    #[tokio::test]
    async fn test_scan_directory() {
        let temp = tempdir().unwrap();
        let root = temp.path();

        // Create some test files
        fs::create_dir_all(root.join("subdir")).unwrap();
        fs::write(root.join("file1.txt"), "content").unwrap();
        fs::write(root.join("subdir").join("file2.txt"), "content").unwrap();

        let entries = scan_directory(root, &[]).await.unwrap();

        // Debug output
        eprintln!("Scanned {} entries from {}", entries.len(), root.display());
        for entry in &entries {
            eprintln!("  - {} (dir={})", entry.name, entry.is_directory);
        }

        // Check that we found the expected files
        let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"file1.txt"), "Should find file1.txt, got: {names:?}");
        assert!(names.contains(&"file2.txt"), "Should find file2.txt, got: {names:?}");
        assert!(names.contains(&"subdir"), "Should find subdir, got: {names:?}");

        // Verify file entry properties
        let file1 = entries.iter().find(|e| e.name == "file1.txt").unwrap();
        assert!(!file1.is_directory);
        assert_eq!(file1.size, 7); // "content" is 7 bytes

        let subdir = entries.iter().find(|e| e.name == "subdir").unwrap();
        assert!(subdir.is_directory);
    }

    #[tokio::test]
    async fn test_scan_directory_empty() {
        let temp = tempdir().unwrap();
        let root = temp.path();

        // Empty directory - but the root itself is included
        let entries = scan_directory(root, &[]).await.unwrap();

        // Should include the root directory itself
        assert!(!entries.is_empty());
    }

    #[tokio::test]
    async fn test_scan_directory_with_exclusions() {
        let temp = tempdir().unwrap();
        let root = temp.path();

        // Create files
        fs::write(root.join("keep.txt"), "keep").unwrap();
        fs::write(root.join("skip.tmp"), "skip").unwrap();
        fs::write(root.join("another.txt"), "another").unwrap();

        let entries = scan_directory(root, &["*.tmp".to_string()]).await.unwrap();

        let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"keep.txt"));
        assert!(names.contains(&"another.txt"));
        assert!(!names.contains(&"skip.tmp"));
    }

    #[tokio::test]
    async fn test_scan_directory_nested_structure() {
        let temp = tempdir().unwrap();
        let root = temp.path();

        // Create nested structure
        fs::create_dir_all(root.join("a").join("b").join("c")).unwrap();
        fs::write(root.join("a").join("file_a.txt"), "a").unwrap();
        fs::write(root.join("a").join("b").join("file_b.txt"), "b").unwrap();
        fs::write(root.join("a").join("b").join("c").join("file_c.txt"), "c").unwrap();

        let entries = scan_directory(root, &[]).await.unwrap();

        let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"a"));
        assert!(names.contains(&"b"));
        assert!(names.contains(&"c"));
        assert!(names.contains(&"file_a.txt"));
        assert!(names.contains(&"file_b.txt"));
        assert!(names.contains(&"file_c.txt"));
    }

    #[tokio::test]
    async fn test_scan_directory_file_sizes() {
        let temp = tempdir().unwrap();
        let root = temp.path();

        fs::write(root.join("small.txt"), "x").unwrap();
        fs::write(root.join("medium.txt"), "x".repeat(1000)).unwrap();
        fs::write(root.join("empty.txt"), "").unwrap();

        let entries = scan_directory(root, &[]).await.unwrap();

        let small = entries.iter().find(|e| e.name == "small.txt").unwrap();
        assert_eq!(small.size, 1);

        let medium = entries.iter().find(|e| e.name == "medium.txt").unwrap();
        assert_eq!(medium.size, 1000);

        let empty = entries.iter().find(|e| e.name == "empty.txt").unwrap();
        assert_eq!(empty.size, 0);
    }

    #[test]
    fn test_file_watcher_new() {
        let watcher = FileWatcher::new(
            vec![PathBuf::from("C:\\Test1"), PathBuf::from("D:\\Test2")],
            vec!["*.bak".to_string()],
            200,
            true,
        );

        assert_eq!(watcher.watched_paths().len(), 2);
        assert_eq!(watcher.exclude_patterns().len(), 1);
        assert!(!watcher.shutdown.load(Ordering::Relaxed));
    }

    #[test]
    fn test_file_watcher_for_path() {
        let path = PathBuf::from("C:\\SinglePath");
        let watcher = FileWatcher::for_path(path.clone());

        assert_eq!(watcher.watched_paths().len(), 1);
        assert_eq!(watcher.watched_paths()[0], path);
        assert!(watcher.exclude_patterns().is_empty());
    }

    #[test]
    fn test_file_watcher_add_path() {
        let mut watcher = FileWatcher::new(vec![], vec![], DEFAULT_DEBOUNCE_MS, true);

        watcher.add_path(PathBuf::from("C:\\Path1"));
        assert_eq!(watcher.watched_paths.len(), 1);

        watcher.add_path(PathBuf::from("D:\\Path2"));
        assert_eq!(watcher.watched_paths.len(), 2);

        // Adding duplicate path should not increase count
        watcher.add_path(PathBuf::from("C:\\Path1"));
        assert_eq!(watcher.watched_paths.len(), 2);
    }

    #[test]
    fn test_file_watcher_add_exclude_pattern() {
        let mut watcher = FileWatcher::new(vec![], vec![], DEFAULT_DEBOUNCE_MS, true);

        watcher.add_exclude_pattern("*.tmp".to_string());
        assert_eq!(watcher.exclude_patterns.len(), 1);

        watcher.add_exclude_pattern("*.bak".to_string());
        assert_eq!(watcher.exclude_patterns.len(), 2);

        // Adding duplicate pattern should not increase count
        watcher.add_exclude_pattern("*.tmp".to_string());
        assert_eq!(watcher.exclude_patterns.len(), 2);
    }

    #[test]
    fn test_file_watcher_watched_paths() {
        let watcher = FileWatcher::new(
            vec![PathBuf::from("C:\\A"), PathBuf::from("D:\\B")],
            vec![],
            DEFAULT_DEBOUNCE_MS,
            true,
        );
        let paths = watcher.watched_paths();

        assert_eq!(paths.len(), 2);
        assert!(paths.contains(&PathBuf::from("C:\\A")));
        assert!(paths.contains(&PathBuf::from("D:\\B")));
    }

    #[test]
    fn test_file_watcher_stop() {
        let watcher = FileWatcher::new(vec![], vec![], DEFAULT_DEBOUNCE_MS, true);

        assert!(!watcher.shutdown.load(Ordering::Relaxed));

        watcher.stop();

        assert!(watcher.shutdown.load(Ordering::Relaxed));
    }

    #[test]
    fn test_scan_entry_with_unicode_name() {
        let entry = ScanEntry {
            path: PathBuf::from("C:\\文档\\文件.txt"),
            name: "文件.txt".to_string(),
            is_directory: false,
            size: 100,
            modified: None,
            created: None,
        };

        let file_entry = entry.to_file_entry(1);
        assert_eq!(file_entry.name, "文件.txt");
        assert!(file_entry.full_path.contains("文档"));
    }

    #[test]
    fn test_scan_entry_with_long_path() {
        let long_name = "a".repeat(200);
        let long_path = format!("C:\\{long_name}");

        let entry = ScanEntry {
            path: PathBuf::from(&long_path),
            name: long_name,
            is_directory: false,
            size: 0,
            modified: None,
            created: None,
        };

        let file_entry = entry.to_file_entry(1);
        assert_eq!(file_entry.name.len(), 200);
        assert_eq!(file_entry.full_path, long_path);
    }

    #[test]
    fn test_should_exclude_is_case_sensitive() {
        let watcher = FileWatcher {
            watched_paths: vec![],
            exclude_patterns: vec!["*.TMP".to_string(), "README.md".to_string()],
            debounce_ms: DEFAULT_DEBOUNCE_MS,
            recursive: true,
            shutdown: Arc::new(AtomicBool::new(false)),
        };

        // Exact case matches
        assert!(watcher.should_exclude(Path::new("file.TMP")));
        assert!(watcher.should_exclude(Path::new("README.md")));

        // Different case does not match
        assert!(!watcher.should_exclude(Path::new("file.tmp")));
        assert!(!watcher.should_exclude(Path::new("readme.md")));
        assert!(!watcher.should_exclude(Path::new("README.MD")));
    }

    #[test]
    fn test_matches_exclude_patterns_suffix() {
        let patterns = vec!["*.tmp".to_string(), "*.log".to_string()];

        assert!(matches_exclude_patterns("file.tmp", &patterns));
        assert!(matches_exclude_patterns("C:\\Users\\test.log", &patterns));
        assert!(!matches_exclude_patterns("file.txt", &patterns));
    }

    #[test]
    fn test_matches_exclude_patterns_prefix() {
        let patterns = vec!["temp*".to_string()];

        assert!(matches_exclude_patterns("temp_file.txt", &patterns));
        assert!(matches_exclude_patterns("temporary", &patterns));
        assert!(!matches_exclude_patterns("file_temp.txt", &patterns));
    }

    #[test]
    fn test_matches_exclude_patterns_contains() {
        let patterns = vec!["*cache*".to_string()];

        assert!(matches_exclude_patterns("my_cache_dir", &patterns));
        assert!(matches_exclude_patterns("C:\\cache\\file.txt", &patterns));
        assert!(!matches_exclude_patterns("file.txt", &patterns));
    }

    #[test]
    fn test_matches_exclude_patterns_exact_substring() {
        let patterns = vec!["node_modules".to_string()];

        assert!(matches_exclude_patterns("C:\\project\\node_modules\\pkg", &patterns));
        assert!(matches_exclude_patterns("node_modules", &patterns));
        assert!(!matches_exclude_patterns("C:\\project\\modules", &patterns));
    }

    #[test]
    fn test_matches_exclude_patterns_empty() {
        let patterns: Vec<String> = vec![];

        assert!(!matches_exclude_patterns("any_file.txt", &patterns));
        assert!(!matches_exclude_patterns("", &patterns));
    }
}
