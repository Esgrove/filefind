//! Shared helpers for unit tests.

use std::time::SystemTime;

use filefind::FileEntry;

/// Build a platform-native absolute test path: `native_path(&["Dir", "file.txt"])`
/// yields `C:\Dir\file.txt` on Windows and `/Dir/file.txt` on Unix.
pub fn native_path(segments: &[&str]) -> String {
    #[cfg(windows)]
    {
        format!("C:\\{}", segments.join("\\"))
    }
    #[cfg(not(windows))]
    {
        format!("/{}", segments.join("/"))
    }
}

/// Create a test file entry with the given name, path, and size.
pub fn make_file(name: &str, path: &str, size: u64) -> FileEntry {
    FileEntry {
        id: None,
        volume_id: 1,
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

/// Create a test directory entry with the given name and path.
pub fn make_dir(name: &str, path: &str) -> FileEntry {
    FileEntry {
        id: None,
        volume_id: 1,
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
