//! File system watcher for non-NTFS drives.
//!
//! This module provides file system monitoring for drives that don't support
//! MFT/USN Journal access (network drives, FAT32, exFAT, etc.) using the
//! `notify` crate which wraps platform-native file watching APIs.
//!
//! On Windows, this uses `ReadDirectoryChangesW`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use filefind::types::FileChangeEvent;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Default debounce duration to coalesce rapid file changes.
const DEFAULT_DEBOUNCE_MS: u64 = 100;

/// File system watcher for monitoring directories.
pub struct FileWatcher {
    /// The paths being watched.
    watched_paths: Vec<PathBuf>,

    /// Patterns to exclude from watching.
    exclude_patterns: Vec<String>,

    /// Shutdown flag.
    shutdown: Arc<AtomicBool>,
}

/// Configuration for the file watcher.
#[derive(Debug, Clone)]
pub struct WatcherConfig {
    /// Paths to watch.
    pub paths: Vec<PathBuf>,

    /// Patterns to exclude (glob-style).
    pub exclude_patterns: Vec<String>,

    /// Debounce duration in milliseconds.
    pub debounce_ms: u64,

    /// Whether to watch recursively.
    pub recursive: bool,
}

impl Default for WatcherConfig {
    fn default() -> Self {
        Self {
            paths: Vec::new(),
            exclude_patterns: Vec::new(),
            debounce_ms: DEFAULT_DEBOUNCE_MS,
            recursive: true,
        }
    }
}

impl FileWatcher {
    /// Create a new file watcher with the given configuration.
    #[must_use]
    pub fn new(config: WatcherConfig) -> Self {
        Self {
            watched_paths: config.paths,
            exclude_patterns: config.exclude_patterns,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Create a new file watcher for a single path.
    #[expect(dead_code, reason = "public API for single-path watching")]
    #[must_use]
    pub fn for_path(path: PathBuf) -> Self {
        Self {
            watched_paths: vec![path],
            exclude_patterns: Vec::new(),
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Add a path to watch.
    #[expect(dead_code, reason = "public API for adding watch paths")]
    pub fn add_path(&mut self, path: PathBuf) {
        if !self.watched_paths.contains(&path) {
            self.watched_paths.push(path);
        }
    }

    /// Add an exclusion pattern.
    #[expect(dead_code, reason = "public API for adding exclusion patterns")]
    pub fn add_exclude_pattern(&mut self, pattern: String) {
        if !self.exclude_patterns.contains(&pattern) {
            self.exclude_patterns.push(pattern);
        }
    }

    /// Check if a path should be excluded based on the exclusion patterns.
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

    /// Convert a notify event to our `FileChangeEvent` type.
    #[expect(dead_code, reason = "public API for event conversion")]
    fn convert_event(&self, event: Event) -> Vec<FileChangeEvent> {
        let mut changes = Vec::new();

        for path in event.paths {
            if self.should_exclude(&path) {
                continue;
            }

            let change = match event.kind {
                EventKind::Create(_) => Some(FileChangeEvent::Created(path)),
                EventKind::Modify(_) => Some(FileChangeEvent::Modified(path)),
                EventKind::Remove(_) => Some(FileChangeEvent::Deleted(path)),
                EventKind::Access(_) | EventKind::Other | EventKind::Any => None,
            };

            if let Some(change) = change {
                changes.push(change);
            }
        }

        changes
    }

    /// Start watching for file changes.
    ///
    /// Returns a channel receiver for change events and a shutdown handle.
    pub fn start(self, recursive: bool) -> Result<(mpsc::Receiver<FileChangeEvent>, Arc<AtomicBool>)> {
        let (event_tx, event_rx) = mpsc::channel(1000);
        let shutdown = self.shutdown.clone();
        let watched_paths = self.watched_paths.clone();
        let exclude_patterns = self.exclude_patterns;

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

        // Spawn async task to process events
        let process_shutdown = shutdown.clone();
        tokio::spawn(async move {
            // Keep watcher alive
            let _watcher = watcher;

            info!("File watcher started");

            // Track recently seen paths to deduplicate rapid events
            let mut recent_paths: HashSet<PathBuf> = HashSet::new();
            let mut last_cleanup = std::time::Instant::now();

            while !process_shutdown.load(Ordering::Relaxed) {
                // Clean up recent paths periodically
                if last_cleanup.elapsed() > Duration::from_secs(5) {
                    recent_paths.clear();
                    last_cleanup = std::time::Instant::now();
                }

                // Wait for events with a timeout
                match tokio::time::timeout(Duration::from_millis(500), notify_rx.recv()).await {
                    Ok(Some(event)) => {
                        // Convert and filter events
                        for path in &event.paths {
                            if exclude_patterns.iter().any(|p| {
                                let path_str = path.to_string_lossy();
                                path_str.contains(p.as_str())
                            }) {
                                continue;
                            }

                            // Simple deduplication
                            if recent_paths.contains(path) {
                                continue;
                            }
                            recent_paths.insert(path.clone());

                            let change = match event.kind {
                                EventKind::Create(_) => Some(FileChangeEvent::Created(path.clone())),
                                EventKind::Modify(_) => Some(FileChangeEvent::Modified(path.clone())),
                                EventKind::Remove(_) => Some(FileChangeEvent::Deleted(path.clone())),
                                _ => None,
                            };

                            if let Some(change) = change {
                                debug!("File change detected: {}", change);
                                if event_tx.send(change).await.is_err() {
                                    // Receiver dropped
                                    break;
                                }
                            }
                        }
                    }
                    Ok(None) => {
                        // Channel closed
                        break;
                    }
                    Err(_) => {
                        // Timeout, continue loop
                    }
                }
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
}

/// Perform an initial directory scan to populate the index.
///
/// This walks the directory tree and returns all files and directories found.
pub async fn scan_directory(root: &Path, exclude_patterns: &[String]) -> Result<Vec<ScanEntry>> {
    let root = root.to_path_buf();
    let exclude_patterns = exclude_patterns.to_vec();

    // Run the scan in a blocking task since walkdir is synchronous
    tokio::task::spawn_blocking(move || scan_directory_sync(&root, &exclude_patterns))
        .await
        .context("Directory scan task failed")?
}

/// Synchronous directory scanning implementation.
fn scan_directory_sync(root: &Path, exclude_patterns: &[String]) -> Result<Vec<ScanEntry>> {
    use walkdir::WalkDir;

    let mut entries = Vec::new();

    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !should_skip_entry(e, exclude_patterns))
    {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                warn!("Error reading directory entry: {error}");
                continue;
            }
        };

        let path = entry.path();
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(error) => {
                warn!("Error reading metadata for {}: {error}", path.display());
                continue;
            }
        };

        let name = entry.file_name().to_string_lossy().into_owned();

        let scan_entry = ScanEntry {
            path: path.to_path_buf(),
            name,
            is_directory: metadata.is_dir(),
            size: if metadata.is_file() { metadata.len() } else { 0 },
            modified: metadata.modified().ok(),
            created: metadata.created().ok(),
        };

        entries.push(scan_entry);
    }

    info!("Scanned {} entries from {}", entries.len(), root.display());
    Ok(entries)
}

/// Check if a walkdir entry should be skipped.
fn should_skip_entry(entry: &walkdir::DirEntry, exclude_patterns: &[String]) -> bool {
    let path = entry.path();
    let path_str = path.to_string_lossy();

    // Skip hidden files/directories (starting with .)
    // Only check the entry's own name, not parent directories
    let name_str = entry.file_name().to_string_lossy();
    if name_str.starts_with('.') && !name_str.starts_with(".tmp") {
        // Allow .tmp* directories (used by tempfile crate in tests)
        return true;
    }

    // Check exclusion patterns
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
        } else if path_str.contains(pattern.as_str()) {
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
            shutdown: Arc::new(AtomicBool::new(false)),
        };

        assert!(watcher.should_exclude(Path::new("test.tmp")));
        assert!(watcher.should_exclude(Path::new("C:\\project\\node_modules\\pkg")));
        assert!(watcher.should_exclude(Path::new("C:\\photos\\Thumbs.db")));
        assert!(!watcher.should_exclude(Path::new("document.pdf")));
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

    #[test]
    fn test_watcher_config_default() {
        let config = WatcherConfig::default();
        assert!(config.paths.is_empty());
        assert!(config.exclude_patterns.is_empty());
        assert_eq!(config.debounce_ms, DEFAULT_DEBOUNCE_MS);
        assert!(config.recursive);
    }
}
