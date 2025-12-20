//! Core data types for filefind.

use std::path::PathBuf;
use std::str::FromStr;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

/// Type of volume/drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VolumeType {
    /// NTFS formatted drive (supports MFT reading).
    Ntfs,
    /// Other local file system (FAT32, exFAT, etc.).
    Local,
    /// Network share or mapped network drive.
    Network,
    /// Removable drive (USB, etc.).
    Removable,
}

/// Information about an indexed volume/drive.
#[derive(Debug, Clone)]
pub struct IndexedVolume {
    /// Database ID (None if not yet persisted).
    pub id: Option<i64>,

    /// Volume serial number for unique identification.
    pub serial_number: String,

    /// Volume label/name.
    pub label: Option<String>,

    /// Mount point or root path (e.g., "C:" on Windows).
    pub mount_point: String,

    /// Type of volume.
    pub volume_type: VolumeType,

    /// Whether the volume is currently online/accessible.
    pub is_online: bool,

    /// Last time this volume was scanned.
    pub last_scan_time: Option<SystemTime>,

    /// Last USN Journal ID (for NTFS volumes).
    pub last_usn: Option<i64>,
}

/// A file or directory entry in the index.
#[derive(Debug, Clone)]
pub struct FileEntry {
    /// Database ID (None if not yet persisted).
    pub id: Option<i64>,

    /// Volume database ID this file belongs to.
    pub volume_id: i64,

    /// Parent directory database ID (None for root entries).
    pub parent_id: Option<i64>,

    /// File or directory name.
    pub name: String,

    /// Full path to the file.
    pub full_path: String,

    /// Whether this is a directory.
    pub is_directory: bool,

    /// File size in bytes (0 for directories).
    pub size: u64,

    /// Created timestamp.
    pub created_time: Option<SystemTime>,

    /// Last modified timestamp.
    pub modified_time: Option<SystemTime>,

    /// MFT reference number (for NTFS files).
    pub mft_reference: Option<u64>,
}

/// Search result with match information.
#[derive(Debug, Clone)]
pub struct SearchResult {
    /// The matched file entry.
    pub entry: FileEntry,

    /// Match score for ranking (higher is better).
    pub score: u32,

    /// Highlighted name with match positions.
    pub highlighted_name: Option<String>,
}

/// Statistics about the file index.
#[derive(Debug, Clone, Default)]
pub struct IndexStats {
    /// Total number of indexed files.
    pub total_files: u64,

    /// Total number of indexed directories.
    pub total_directories: u64,

    /// Total size of all indexed files in bytes.
    pub total_size: u64,

    /// Number of indexed volumes.
    pub volume_count: usize,

    /// Database file size in bytes.
    pub database_size: u64,

    /// Last time the index was updated.
    pub last_updated: Option<SystemTime>,
}

/// File change event from the watcher.
#[derive(Debug, Clone)]
pub enum FileChangeEvent {
    /// File or directory was created.
    Created(PathBuf),

    /// File or directory was modified.
    Modified(PathBuf),

    /// File or directory was deleted.
    Deleted(PathBuf),

    /// File or directory was renamed.
    Renamed { from: PathBuf, to: PathBuf },
}

impl VolumeType {
    /// Convert to a string representation for database storage.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Ntfs => "ntfs",
            Self::Local => "local",
            Self::Network => "network",
            Self::Removable => "removable",
        }
    }

    /// Parse from a string representation.
    #[must_use]
    pub fn parse(string: &str) -> Self {
        match string.to_lowercase().as_str() {
            "ntfs" => Self::Ntfs,
            "network" => Self::Network,
            "removable" => Self::Removable,
            _ => Self::Local,
        }
    }
}

impl FromStr for VolumeType {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::parse(s))
    }
}

impl IndexedVolume {
    /// Create a new indexed volume with default values.
    #[must_use]
    pub const fn new(serial_number: String, mount_point: String, volume_type: VolumeType) -> Self {
        Self {
            id: None,
            serial_number,
            label: None,
            mount_point,
            volume_type,
            is_online: true,
            last_scan_time: None,
            last_usn: None,
        }
    }
}

impl FileEntry {
    /// Create a new file entry.
    #[must_use]
    pub const fn new(volume_id: i64, name: String, full_path: String, is_directory: bool) -> Self {
        Self {
            id: None,
            volume_id,
            parent_id: None,
            name,
            full_path,
            is_directory,
            size: 0,
            created_time: None,
            modified_time: None,
            mft_reference: None,
        }
    }

    /// Get the file extension, if any.
    #[must_use]
    pub fn extension(&self) -> Option<&str> {
        if self.is_directory {
            return None;
        }
        std::path::Path::new(&self.full_path)
            .extension()
            .and_then(|ext| ext.to_str())
    }
}

impl std::fmt::Display for VolumeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ntfs => write!(f, "NTFS"),
            Self::Local => write!(f, "Local"),
            Self::Network => write!(f, "Network"),
            Self::Removable => write!(f, "Removable"),
        }
    }
}

impl std::fmt::Display for FileChangeEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Created(path) => write!(f, "Created: {}", path.display()),
            Self::Modified(path) => write!(f, "Modified: {}", path.display()),
            Self::Deleted(path) => write!(f, "Deleted: {}", path.display()),
            Self::Renamed { from, to } => {
                write!(f, "Renamed: {} -> {}", from.display(), to.display())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_volume_type_display() {
        assert_eq!(VolumeType::Ntfs.to_string(), "NTFS");
        assert_eq!(VolumeType::Local.to_string(), "Local");
        assert_eq!(VolumeType::Network.to_string(), "Network");
        assert_eq!(VolumeType::Removable.to_string(), "Removable");
    }

    #[test]
    fn test_volume_type_as_str() {
        assert_eq!(VolumeType::Ntfs.as_str(), "ntfs");
        assert_eq!(VolumeType::Local.as_str(), "local");
        assert_eq!(VolumeType::Network.as_str(), "network");
        assert_eq!(VolumeType::Removable.as_str(), "removable");
    }

    #[test]
    fn test_volume_type_roundtrip() {
        for volume_type in [
            VolumeType::Ntfs,
            VolumeType::Local,
            VolumeType::Network,
            VolumeType::Removable,
        ] {
            let string = volume_type.as_str();
            let parsed: VolumeType = string.parse().expect("Should parse volume type");
            assert_eq!(volume_type, parsed);
        }
    }

    #[test]
    fn test_volume_type_parse() {
        assert_eq!(VolumeType::parse("ntfs"), VolumeType::Ntfs);
        assert_eq!(VolumeType::parse("NTFS"), VolumeType::Ntfs);
        assert_eq!(VolumeType::parse("NtFs"), VolumeType::Ntfs);
        assert_eq!(VolumeType::parse("local"), VolumeType::Local);
        assert_eq!(VolumeType::parse("LOCAL"), VolumeType::Local);
        assert_eq!(VolumeType::parse("network"), VolumeType::Network);
        assert_eq!(VolumeType::parse("NETWORK"), VolumeType::Network);
        assert_eq!(VolumeType::parse("removable"), VolumeType::Removable);
        assert_eq!(VolumeType::parse("REMOVABLE"), VolumeType::Removable);
    }

    #[test]
    fn test_volume_type_parse_unknown() {
        // Unknown values should default to Local
        assert_eq!(VolumeType::parse("unknown"), VolumeType::Local);
        assert_eq!(VolumeType::parse(""), VolumeType::Local);
        assert_eq!(VolumeType::parse("invalid"), VolumeType::Local);
        assert_eq!(VolumeType::parse("fat32"), VolumeType::Local);
    }

    #[test]
    fn test_volume_type_from_str() {
        let result: Result<VolumeType, _> = "ntfs".parse();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), VolumeType::Ntfs);

        // FromStr should never fail due to Infallible error type
        let result: Result<VolumeType, _> = "anything".parse();
        assert!(result.is_ok());
    }

    #[test]
    fn test_volume_type_equality() {
        assert_eq!(VolumeType::Ntfs, VolumeType::Ntfs);
        assert_ne!(VolumeType::Ntfs, VolumeType::Local);
        assert_ne!(VolumeType::Network, VolumeType::Removable);
    }

    #[test]
    fn test_volume_type_clone() {
        let original = VolumeType::Network;
        let cloned = original;
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_volume_type_debug() {
        let debug_str = format!("{:?}", VolumeType::Ntfs);
        assert!(debug_str.contains("Ntfs"));
    }

    #[test]
    fn test_file_entry_extension() {
        let file = FileEntry::new(
            1,
            "document.pdf".to_string(),
            "C:\\Documents\\document.pdf".to_string(),
            false,
        );
        assert_eq!(file.extension(), Some("pdf"));

        let dir = FileEntry::new(1, "folder".to_string(), "C:\\folder".to_string(), true);
        assert_eq!(dir.extension(), None);
    }

    #[test]
    fn test_file_entry_extension_directories_always_none() {
        // Directories should always return None, even if name looks like it has extension
        let dir = FileEntry::new(1, "folder.d".to_string(), "C:\\folder.d".to_string(), true);
        assert_eq!(dir.extension(), None);

        let dir = FileEntry::new(1, "archive.zip".to_string(), "C:\\archive.zip".to_string(), true);
        assert_eq!(dir.extension(), None);
    }

    #[test]
    fn test_file_entry_new() {
        let file = FileEntry::new(42, "test.txt".to_string(), "C:\\folder\\test.txt".to_string(), false);

        assert!(file.id.is_none());
        assert_eq!(file.volume_id, 42);
        assert!(file.parent_id.is_none());
        assert_eq!(file.name, "test.txt");
        assert_eq!(file.full_path, "C:\\folder\\test.txt");
        assert!(!file.is_directory);
        assert_eq!(file.size, 0);
        assert!(file.created_time.is_none());
        assert!(file.modified_time.is_none());
        assert!(file.mft_reference.is_none());
    }

    #[test]
    fn test_file_entry_new_directory() {
        let dir = FileEntry::new(1, "Documents".to_string(), "C:\\Documents".to_string(), true);

        assert!(dir.is_directory);
        assert_eq!(dir.size, 0);
    }

    #[test]
    fn test_indexed_volume_new() {
        let volume = IndexedVolume::new("ABC123".to_string(), "C:".to_string(), VolumeType::Ntfs);

        assert!(volume.id.is_none());
        assert_eq!(volume.serial_number, "ABC123");
        assert!(volume.label.is_none());
        assert_eq!(volume.mount_point, "C:");
        assert_eq!(volume.volume_type, VolumeType::Ntfs);
        assert!(volume.is_online);
        assert!(volume.last_scan_time.is_none());
        assert!(volume.last_usn.is_none());
    }

    #[test]
    fn test_indexed_volume_with_different_types() {
        for volume_type in [
            VolumeType::Ntfs,
            VolumeType::Local,
            VolumeType::Network,
            VolumeType::Removable,
        ] {
            let volume = IndexedVolume::new("SERIAL".to_string(), "X:".to_string(), volume_type);
            assert_eq!(volume.volume_type, volume_type);
        }
    }

    #[test]
    fn test_search_result_fields() {
        let entry = FileEntry::new(1, "test.txt".to_string(), "C:\\test.txt".to_string(), false);

        let result = SearchResult {
            entry,
            score: 100,
            highlighted_name: Some("*test*.txt".to_string()),
        };

        assert_eq!(result.score, 100);
        assert_eq!(result.highlighted_name, Some("*test*.txt".to_string()));
        assert_eq!(result.entry.name, "test.txt");
    }

    #[test]
    fn test_search_result_without_highlight() {
        let entry = FileEntry::new(1, "file.txt".to_string(), "C:\\file.txt".to_string(), false);

        let result = SearchResult {
            entry,
            score: 50,
            highlighted_name: None,
        };

        assert!(result.highlighted_name.is_none());
    }

    #[test]
    fn test_index_stats_default() {
        let stats = IndexStats::default();

        assert_eq!(stats.total_files, 0);
        assert_eq!(stats.total_directories, 0);
        assert_eq!(stats.total_size, 0);
        assert_eq!(stats.volume_count, 0);
        assert_eq!(stats.database_size, 0);
        assert!(stats.last_updated.is_none());
    }

    #[test]
    fn test_index_stats_with_values() {
        let now = SystemTime::now();

        let stats = IndexStats {
            total_files: 1000,
            total_directories: 100,
            total_size: 1_000_000,
            volume_count: 3,
            database_size: 50_000,
            last_updated: Some(now),
        };

        assert_eq!(stats.total_files, 1000);
        assert_eq!(stats.total_directories, 100);
        assert_eq!(stats.total_size, 1_000_000);
        assert_eq!(stats.volume_count, 3);
        assert_eq!(stats.database_size, 50_000);
        assert!(stats.last_updated.is_some());
    }

    #[test]
    fn test_file_change_event_created() {
        let path = PathBuf::from("C:\\new_file.txt");
        let event = FileChangeEvent::Created(path.clone());

        if let FileChangeEvent::Created(p) = event {
            assert_eq!(p, path);
        } else {
            panic!("Expected Created event");
        }
    }

    #[test]
    fn test_file_change_event_modified() {
        let path = PathBuf::from("C:\\modified.txt");
        let event = FileChangeEvent::Modified(path.clone());

        if let FileChangeEvent::Modified(p) = event {
            assert_eq!(p, path);
        } else {
            panic!("Expected Modified event");
        }
    }

    #[test]
    fn test_file_change_event_deleted() {
        let path = PathBuf::from("C:\\deleted.txt");
        let event = FileChangeEvent::Deleted(path.clone());

        if let FileChangeEvent::Deleted(p) = event {
            assert_eq!(p, path);
        } else {
            panic!("Expected Deleted event");
        }
    }

    #[test]
    fn test_file_change_event_renamed() {
        let from = PathBuf::from("C:\\old_name.txt");
        let to = PathBuf::from("C:\\new_name.txt");
        let event = FileChangeEvent::Renamed {
            from: from.clone(),
            to: to.clone(),
        };

        if let FileChangeEvent::Renamed { from: f, to: t } = event {
            assert_eq!(f, from);
            assert_eq!(t, to);
        } else {
            panic!("Expected Renamed event");
        }
    }

    #[test]
    fn test_file_change_event_display_created() {
        let event = FileChangeEvent::Created(PathBuf::from("C:\\test.txt"));
        let display = event.to_string();
        assert!(display.contains("Created"));
        assert!(display.contains("test.txt"));
    }

    #[test]
    fn test_file_change_event_display_modified() {
        let event = FileChangeEvent::Modified(PathBuf::from("C:\\test.txt"));
        let display = event.to_string();
        assert!(display.contains("Modified"));
        assert!(display.contains("test.txt"));
    }

    #[test]
    fn test_file_change_event_display_deleted() {
        let event = FileChangeEvent::Deleted(PathBuf::from("C:\\test.txt"));
        let display = event.to_string();
        assert!(display.contains("Deleted"));
        assert!(display.contains("test.txt"));
    }

    #[test]
    fn test_file_change_event_display_renamed() {
        let event = FileChangeEvent::Renamed {
            from: PathBuf::from("C:\\old.txt"),
            to: PathBuf::from("C:\\new.txt"),
        };
        let display = event.to_string();
        assert!(display.contains("Renamed"));
        assert!(display.contains("old.txt"));
        assert!(display.contains("new.txt"));
        assert!(display.contains("->"));
    }

    #[test]
    fn test_file_change_event_clone() {
        let original = FileChangeEvent::Created(PathBuf::from("C:\\test.txt"));
        let cloned = original.clone();

        if let (FileChangeEvent::Created(p1), FileChangeEvent::Created(p2)) = (&original, &cloned) {
            assert_eq!(p1, p2);
        } else {
            panic!("Clone failed");
        }
    }

    #[test]
    fn test_file_change_event_debug() {
        let event = FileChangeEvent::Created(PathBuf::from("C:\\test.txt"));
        let debug_str = format!("{event:?}");
        assert!(debug_str.contains("Created"));
    }

    #[test]
    fn test_file_entry_clone() {
        let original = FileEntry::new(1, "test.txt".to_string(), "C:\\test.txt".to_string(), false);
        let cloned = original.clone();

        assert_eq!(original.name, cloned.name);
        assert_eq!(original.full_path, cloned.full_path);
        assert_eq!(original.volume_id, cloned.volume_id);
    }

    #[test]
    fn test_file_entry_debug() {
        let entry = FileEntry::new(1, "test.txt".to_string(), "C:\\test.txt".to_string(), false);
        let debug_str = format!("{entry:?}");
        assert!(debug_str.contains("test.txt"));
        assert!(debug_str.contains("FileEntry"));
    }

    #[test]
    fn test_indexed_volume_clone() {
        let original = IndexedVolume::new("SERIAL".to_string(), "C:".to_string(), VolumeType::Ntfs);
        let cloned = original.clone();

        assert_eq!(original.serial_number, cloned.serial_number);
        assert_eq!(original.mount_point, cloned.mount_point);
    }

    #[test]
    fn test_indexed_volume_debug() {
        let volume = IndexedVolume::new("SERIAL".to_string(), "C:".to_string(), VolumeType::Ntfs);
        let debug_str = format!("{volume:?}");
        assert!(debug_str.contains("SERIAL"));
        assert!(debug_str.contains("IndexedVolume"));
    }

    #[test]
    fn test_search_result_clone() {
        let entry = FileEntry::new(1, "test.txt".to_string(), "C:\\test.txt".to_string(), false);
        let original = SearchResult {
            entry,
            score: 100,
            highlighted_name: Some("test".to_string()),
        };
        let cloned = original.clone();

        assert_eq!(original.score, cloned.score);
        assert_eq!(original.highlighted_name, cloned.highlighted_name);
    }

    #[test]
    fn test_index_stats_clone() {
        let original = IndexStats {
            total_files: 100,
            total_directories: 10,
            total_size: 1000,
            volume_count: 2,
            database_size: 500,
            last_updated: None,
        };
        let cloned = original.clone();

        assert_eq!(original.total_files, cloned.total_files);
        assert_eq!(original.total_size, cloned.total_size);
    }

    #[test]
    fn test_file_entry_with_all_fields() {
        let now = SystemTime::now();

        let file = FileEntry {
            id: Some(42),
            volume_id: 1,
            parent_id: Some(10),
            name: "complete_file.txt".to_string(),
            full_path: "C:\\folder\\complete_file.txt".to_string(),
            is_directory: false,
            size: 1024,
            created_time: Some(now),
            modified_time: Some(now),
            mft_reference: Some(12345),
        };

        assert_eq!(file.id, Some(42));
        assert_eq!(file.parent_id, Some(10));
        assert_eq!(file.size, 1024);
        assert_eq!(file.mft_reference, Some(12345));
        assert!(file.created_time.is_some());
        assert!(file.modified_time.is_some());
    }

    #[test]
    fn test_indexed_volume_with_all_fields() {
        let now = SystemTime::now();

        let volume = IndexedVolume {
            id: Some(1),
            serial_number: "ABC123".to_string(),
            label: Some("My Volume".to_string()),
            mount_point: "D:".to_string(),
            volume_type: VolumeType::Removable,
            is_online: false,
            last_scan_time: Some(now),
            last_usn: Some(999_999),
        };

        assert_eq!(volume.id, Some(1));
        assert_eq!(volume.label, Some("My Volume".to_string()));
        assert!(!volume.is_online);
        assert_eq!(volume.last_usn, Some(999_999));
        assert!(volume.last_scan_time.is_some());
    }

    #[test]
    fn test_file_entry_extension_unicode() {
        let file = FileEntry::new(1, "文档.txt".to_string(), "C:\\文档.txt".to_string(), false);
        assert_eq!(file.extension(), Some("txt"));

        let file = FileEntry::new(1, "файл.документ".to_string(), "C:\\файл.документ".to_string(), false);
        assert_eq!(file.extension(), Some("документ"));
    }
}
