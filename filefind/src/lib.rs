//! Shared library for filefind - configuration, database, and common types.

pub mod config;
pub mod database;
pub mod ipc;
pub mod types;

pub use config::{CONFIG_PATH, UserConfig as Config};
pub use database::Database;
pub use ipc::{
    DaemonCommand, DaemonResponse, DaemonStateInfo, DaemonStatus, IpcClient, deserialize_command, deserialize_response,
    get_ipc_path, read_message, serialize_command, serialize_response, write_message,
};
pub use types::{FileChangeEvent, FileEntry, IndexedVolume, VolumeType};

use std::path::Path;

use colored::Colorize;

/// Project name constant.
pub const PROJECT_NAME: &str = "filefind";

/// Type of path for determining the appropriate scanning strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathType {
    /// Local NTFS drive root (e.g., "C:\") - can use fast MFT scanning.
    NtfsDriveRoot,
    /// Local directory on an NTFS drive - uses MFT scanning with path filtering.
    LocalDirectory,
    /// Mapped network drive (e.g., "Z:\") - try MFT scanning first, fall back to directory walking.
    ///
    /// Some NAS devices support MFT-like scanning even over the network.
    /// We attempt MFT scanning first and fall back gracefully if it fails.
    MappedNetworkDrive,
    /// UNC network path (e.g., "\\server\share") - must use directory walking.
    ///
    /// UNC paths don't have a drive letter, so MFT scanning isn't possible.
    UncPath,
}

impl std::fmt::Display for PathType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NtfsDriveRoot => write!(f, "NTFS drive root"),
            Self::LocalDirectory => write!(f, "local directory"),
            Self::MappedNetworkDrive => write!(f, "mapped network drive"),
            Self::UncPath => write!(f, "UNC path"),
        }
    }
}

/// Classify a path to determine the appropriate scanning strategy.
///
/// Returns the type of path which determines how it should be indexed:
/// - `NtfsDriveRoot`: Can use fast MFT scanning
/// - `LocalDirectory`: Uses MFT scanning with path filtering
/// - `MappedNetworkDrive`: Try MFT first, fall back to directory walking
/// - `UncPath`: Must use directory walking (no drive letter for MFT)
#[must_use]
pub fn classify_path(path: &Path) -> PathType {
    if is_unc_path(path) {
        PathType::UncPath
    } else if is_mapped_network_drive(path) {
        PathType::MappedNetworkDrive
    } else if is_drive_root(path) {
        PathType::NtfsDriveRoot
    } else {
        PathType::LocalDirectory
    }
}

/// Check if a path is a UNC path (e.g., `\\server\share`).
///
/// UNC paths start with `\\` and don't have a drive letter.
#[must_use]
pub fn is_unc_path(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    path_str.starts_with(r"\\")
}

/// Check if a path is on a mapped network drive (e.g., `Z:\`).
///
/// This detects drive letters that are mapped to network locations,
/// but NOT UNC paths.
#[cfg(windows)]
#[must_use]
pub fn is_mapped_network_drive(path: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;

    const DRIVE_REMOTE: u32 = 4;

    // UNC paths are not mapped drives
    if is_unc_path(path) {
        return false;
    }

    // Check drive type for mapped network drives
    if let Some(prefix) = path.components().next() {
        let prefix_str = prefix.as_os_str();
        // Create a root path like "X:\"
        let mut root: Vec<u16> = prefix_str.encode_wide().collect();
        if root.len() >= 2 && root[1] == u16::from(b':') {
            root.push(u16::from(b'\\'));
            root.push(0); // null terminator

            // SAFETY: GetDriveTypeW is a safe Windows API call that only reads
            // the null-terminated string to determine drive type
            #[allow(unsafe_code)]
            let drive_type = unsafe { GetDriveTypeW(root.as_ptr()) };
            return drive_type == DRIVE_REMOTE;
        }
    }

    false
}

/// Check if a path is on a mapped network drive (non-Windows stub).
#[cfg(not(windows))]
#[must_use]
pub const fn is_mapped_network_drive(_path: &Path) -> bool {
    false
}

/// Check if a path is a drive root (e.g., "C:\", "D:", "E:\").
///
/// Returns true for paths like "C:", "C:\", "D:/", etc.
#[must_use]
pub fn is_drive_root(path: &Path) -> bool {
    let path_str = path.to_string_lossy();

    // Check if it's a drive root like "C:\", "C:", "C:/"
    if path_str.len() <= 3 {
        let chars: Vec<char> = path_str.chars().collect();
        if !chars.is_empty() && chars[0].is_ascii_alphabetic() && chars.len() >= 2 && chars[1] == ':' {
            // "C:" or "C:\" or "C:/"
            if chars.len() == 2 {
                return true;
            }
            if chars.len() == 3 && (chars[2] == '\\' || chars[2] == '/') {
                return true;
            }
        }
    }

    false
}

/// Check if a path is on a network drive (either UNC or mapped).
///
/// On Windows, detects mapped network drives and UNC paths.
/// On other platforms, always returns false.
#[must_use]
pub fn is_network_path(path: &Path) -> bool {
    is_unc_path(path) || is_mapped_network_drive(path)
}

/// Print an error message in red.
pub fn print_error(message: &str) {
    eprintln!("{}", message.red());
}

/// Print an error message in red with formatting support.
#[macro_export]
macro_rules! print_error {
    ($($arg:tt)*) => {
        $crate::print_error(&format!($($arg)*))
    };
}

/// Print a warning message in yellow.
pub fn print_warning(message: &str) {
    eprintln!("{}", message.yellow());
}

/// Print a warning message in yellow with formatting support.
#[macro_export]
macro_rules! print_warning {
    ($($arg:tt)*) => {
        $crate::print_warning(&format!($($arg)*))
    };
}

/// Print a success message in green.
pub fn print_success(message: &str) {
    println!("{}", message.green());
}

/// Print a success message in green with formatting support.
#[macro_export]
macro_rules! print_success {
    ($($arg:tt)*) => {
        $crate::print_success(&format!($($arg)*))
    };
}

/// Print an info message in cyan.
pub fn print_info(message: &str) {
    println!("{}", message.cyan());
}

/// Print an info message in cyan with formatting support.
#[macro_export]
macro_rules! print_info {
    ($($arg:tt)*) => {
        $crate::print_info(&format!($($arg)*))
    };
}

/// Format a file size in bytes to a human-readable string.
#[must_use]
pub fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_drive_root() {
        assert!(is_drive_root(Path::new("C:")));
        assert!(is_drive_root(Path::new("C:\\")));
        assert!(is_drive_root(Path::new("D:")));
        assert!(is_drive_root(Path::new("D:\\")));
        assert!(is_drive_root(Path::new("E:/")));

        assert!(!is_drive_root(Path::new("C:\\Users")));
        assert!(!is_drive_root(Path::new("C:\\Windows\\System32")));
        assert!(!is_drive_root(Path::new("/home/user")));
        assert!(!is_drive_root(Path::new("relative/path")));
    }

    #[test]
    fn test_is_network_path() {
        // UNC paths should be detected as network paths
        assert!(is_network_path(Path::new(r"\\server\share")));
        assert!(is_network_path(Path::new(r"\\192.168.1.1\share")));
        assert!(is_network_path(Path::new(r"\\server\share\folder")));

        // Local drives are not network paths
        assert!(!is_network_path(Path::new("C:\\")));
        assert!(!is_network_path(Path::new("C:\\Users")));
    }

    #[test]
    fn test_is_unc_path() {
        assert!(is_unc_path(Path::new(r"\\server\share")));
        assert!(is_unc_path(Path::new(r"\\192.168.1.1\share")));
        assert!(is_unc_path(Path::new(r"\\server\share\folder")));

        assert!(!is_unc_path(Path::new("C:\\")));
        assert!(!is_unc_path(Path::new("Z:\\")));
        assert!(!is_unc_path(Path::new("C:\\Users")));
    }

    #[test]
    fn test_classify_path() {
        // UNC paths should be classified as UNC
        assert_eq!(classify_path(Path::new(r"\\server\share")), PathType::UncPath);
        assert_eq!(classify_path(Path::new(r"\\server\share\subfolder")), PathType::UncPath);

        // Local drive roots should be classified as NTFS drive root
        // Note: mapped network drives will be detected as MappedNetworkDrive
        assert_eq!(classify_path(Path::new("C:\\")), PathType::NtfsDriveRoot);
        assert_eq!(classify_path(Path::new("D:")), PathType::NtfsDriveRoot);

        // Subdirectories on local drives should be classified as local directory
        assert_eq!(classify_path(Path::new("C:\\Users")), PathType::LocalDirectory);
        assert_eq!(classify_path(Path::new("D:\\Projects\\test")), PathType::LocalDirectory);
    }

    #[test]
    fn test_path_type_display() {
        assert_eq!(PathType::NtfsDriveRoot.to_string(), "NTFS drive root");
        assert_eq!(PathType::LocalDirectory.to_string(), "local directory");
        assert_eq!(PathType::MappedNetworkDrive.to_string(), "mapped network drive");
        assert_eq!(PathType::UncPath.to_string(), "UNC path");
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1024), "1.00 KB");
        assert_eq!(format_size(1536), "1.50 KB");
        assert_eq!(format_size(1_048_576), "1.00 MB");
        assert_eq!(format_size(1_073_741_824), "1.00 GB");
        assert_eq!(format_size(1_099_511_627_776), "1.00 TB");
    }
}
