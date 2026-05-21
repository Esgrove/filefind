//! Shared helpers for unit tests.

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
