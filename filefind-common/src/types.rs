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
        assert_eq!(VolumeType::Network.to_string(), "Network");
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
    fn test_indexed_volume_new() {
        let volume = IndexedVolume::new("ABC123".to_string(), "C:".to_string(), VolumeType::Ntfs);
        assert_eq!(volume.serial_number, "ABC123");
        assert_eq!(volume.mount_point, "C:");
        assert!(volume.is_online);
        assert!(volume.id.is_none());
    }
}
