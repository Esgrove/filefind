//! Shared library for filefind - configuration, database, and common types.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Command;
use clap_complete::Shell;
use colored::Colorize;

pub mod config;
pub mod database;
pub mod ipc;
pub mod types;

pub use config::{CONFIG_PATH, LogLevel, UserConfig as Config};
pub use database::Database;
pub use ipc::{
    DaemonCommand, DaemonResponse, DaemonStateInfo, DaemonStatus, IpcClient, deserialize_command, deserialize_response,
    get_ipc_path, read_message, serialize_command, serialize_response, write_message,
};
pub use types::{FileChangeEvent, FileEntry, IndexedVolume, VolumeType};

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

/// Print a message in bold magenta.
pub fn print_bold_magenta(message: &str) {
    println!("{}", message.bold().magenta());
}

/// Print a message in bold magenta with formatting support.
#[macro_export]
macro_rules! print_bold_magenta {
    ($($arg:tt)*) => {
        $crate::print_bold_magenta(&format!($($arg)*))
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

/// Format a large number with thousands separators (e.g., 1234567 -> "1,234,567").
#[must_use]
pub fn format_number(number: u64) -> String {
    let string = number.to_string();
    let mut result = String::new();

    for (count, character) in string.chars().rev().enumerate() {
        if count > 0 && count % 3 == 0 {
            result.insert(0, ',');
        }
        result.insert(0, character);
    }

    result
}

/// Get the log directory path: ~/logs/filefind/
///
/// # Errors
/// Returns an error if the home directory cannot be determined.
pub fn get_log_directory() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Could not determine home directory")?;
    Ok(home.join("logs").join(PROJECT_NAME))
}

/// Determine the appropriate directory for storing shell completions.
///
/// First checks if the user-specific directory exists,
/// then checks for the global directory.
/// If neither exist, creates and uses the user-specific dir.
fn get_shell_completion_dir(shell: Shell, name: &str) -> Result<PathBuf> {
    let home = dirs::home_dir().expect("Failed to get home directory");

    // Special handling for oh-my-zsh.
    // Create custom "plugin", which will then have to be loaded in .zshrc
    if shell == Shell::Zsh {
        let omz_plugins = home.join(".oh-my-zsh/custom/plugins");
        if omz_plugins.exists() {
            let plugin_dir = omz_plugins.join(name);
            std::fs::create_dir_all(&plugin_dir)?;
            return Ok(plugin_dir);
        }
    }

    let user_dir = match shell {
        Shell::PowerShell => {
            if cfg!(windows) {
                home.join(r"Documents\PowerShell\completions")
            } else {
                home.join(".config/powershell/completions")
            }
        }
        Shell::Bash => home.join(".bash_completion.d"),
        Shell::Elvish => home.join(".elvish"),
        Shell::Fish => home.join(".config/fish/completions"),
        Shell::Zsh => home.join(".zsh/completions"),
        _ => anyhow::bail!("Unsupported shell"),
    };

    if user_dir.exists() {
        return Ok(user_dir);
    }

    let global_dir = match shell {
        Shell::PowerShell => {
            if cfg!(windows) {
                home.join(r"Documents\PowerShell\completions")
            } else {
                home.join(".config/powershell/completions")
            }
        }
        Shell::Bash => PathBuf::from("/etc/bash_completion.d"),
        Shell::Fish => PathBuf::from("/usr/share/fish/completions"),
        Shell::Zsh => PathBuf::from("/usr/share/zsh/site-functions"),
        _ => anyhow::bail!("Unsupported shell"),
    };

    if global_dir.exists() {
        return Ok(global_dir);
    }

    std::fs::create_dir_all(&user_dir)?;
    Ok(user_dir)
}

/// Generate a shell completion script for the given shell.
///
/// # Errors
/// Returns an error if:
/// - The shell completion directory cannot be determined or created
/// - The completion file cannot be generated or written
pub fn generate_shell_completion(shell: Shell, mut command: Command, install: bool, command_name: &str) -> Result<()> {
    if install {
        let out_dir = get_shell_completion_dir(shell, command_name)?;
        let path = clap_complete::generate_to(shell, &mut command, command_name, out_dir)?;
        println!("Completion file generated to: {}", path.display());
    } else {
        clap_complete::generate(shell, &mut command, command_name, &mut std::io::stdout());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_drive_root() {
        // Valid drive roots
        assert!(is_drive_root(Path::new("C:")));
        assert!(is_drive_root(Path::new("C:\\")));
        assert!(is_drive_root(Path::new("D:")));
        assert!(is_drive_root(Path::new("D:\\")));
        assert!(is_drive_root(Path::new("E:/")));
        assert!(is_drive_root(Path::new("Z:")));
        assert!(is_drive_root(Path::new("a:")));
        assert!(is_drive_root(Path::new("z:\\")));

        // Not drive roots
        assert!(!is_drive_root(Path::new("C:\\Users")));
        assert!(!is_drive_root(Path::new("C:\\Windows\\System32")));
        assert!(!is_drive_root(Path::new("/home/user")));
        assert!(!is_drive_root(Path::new("relative/path")));
        assert!(!is_drive_root(Path::new("")));
        assert!(!is_drive_root(Path::new("C")));
        assert!(!is_drive_root(Path::new("CC:")));
        assert!(!is_drive_root(Path::new("1:")));
        assert!(!is_drive_root(Path::new("C:\\a")));
    }

    #[test]
    fn test_is_drive_root_edge_cases() {
        // Single character paths
        assert!(!is_drive_root(Path::new("C")));
        assert!(!is_drive_root(Path::new(":")));

        // Four character paths (should not match)
        assert!(!is_drive_root(Path::new("C:\\a")));
        assert!(!is_drive_root(Path::new("D:/x")));

        // Non-alphabetic first characters
        assert!(!is_drive_root(Path::new("1:")));
        assert!(!is_drive_root(Path::new("@:")));
        assert!(!is_drive_root(Path::new(" :")));
    }

    #[test]
    fn test_is_network_path() {
        // UNC paths should be detected as network paths
        assert!(is_network_path(Path::new(r"\\server\share")));
        assert!(is_network_path(Path::new(r"\\192.168.1.1\share")));
        assert!(is_network_path(Path::new(r"\\server\share\folder")));
        assert!(is_network_path(Path::new(r"\\?\UNC\server\share")));
        assert!(is_network_path(Path::new(r"\\")));

        // Local drives are not network paths (unless mapped)
        assert!(!is_network_path(Path::new("C:\\")));
        assert!(!is_network_path(Path::new("C:\\Users")));
        assert!(!is_network_path(Path::new("relative\\path")));
    }

    #[test]
    fn test_is_unc_path() {
        // Valid UNC paths
        assert!(is_unc_path(Path::new(r"\\server\share")));
        assert!(is_unc_path(Path::new(r"\\192.168.1.1\share")));
        assert!(is_unc_path(Path::new(r"\\server\share\folder")));
        assert!(is_unc_path(Path::new(r"\\server")));
        assert!(is_unc_path(Path::new(r"\\")));

        // Not UNC paths
        assert!(!is_unc_path(Path::new("C:\\")));
        assert!(!is_unc_path(Path::new("Z:\\")));
        assert!(!is_unc_path(Path::new("C:\\Users")));
        assert!(!is_unc_path(Path::new(r"\single\backslash")));
        assert!(!is_unc_path(Path::new("")));
        assert!(!is_unc_path(Path::new("relative")));
    }

    #[test]
    fn test_classify_path_unc() {
        // UNC paths should be classified as UNC
        assert_eq!(classify_path(Path::new(r"\\server\share")), PathType::UncPath);
        assert_eq!(classify_path(Path::new(r"\\server\share\subfolder")), PathType::UncPath);
        assert_eq!(classify_path(Path::new(r"\\192.168.1.1\data")), PathType::UncPath);
        assert_eq!(
            classify_path(Path::new(r"\\server\share\deep\nested\path")),
            PathType::UncPath
        );
    }

    #[test]
    fn test_classify_path_drive_root() {
        // Local drive roots should be classified as NTFS drive root OR MappedNetworkDrive
        // depending on whether the drive is actually mapped. We test that it's one of these.
        let c_type = classify_path(Path::new("C:\\"));
        assert!(
            c_type == PathType::NtfsDriveRoot || c_type == PathType::MappedNetworkDrive,
            "C:\\ should be NtfsDriveRoot or MappedNetworkDrive, got {c_type:?}"
        );

        // For drives that may or may not exist, just verify they're classified as either
        // NtfsDriveRoot or MappedNetworkDrive (not UncPath or LocalDirectory)
        for drive in ["D:", "E:/", "Z:"] {
            let path_type = classify_path(Path::new(drive));
            assert!(
                path_type == PathType::NtfsDriveRoot || path_type == PathType::MappedNetworkDrive,
                "{drive} should be NtfsDriveRoot or MappedNetworkDrive, got {path_type:?}"
            );
        }
    }

    #[test]
    fn test_classify_path_local_directory() {
        // Subdirectories on local drives should be classified as local directory
        assert_eq!(classify_path(Path::new("C:\\Users")), PathType::LocalDirectory);
        assert_eq!(classify_path(Path::new("D:\\Projects\\test")), PathType::LocalDirectory);
        assert_eq!(
            classify_path(Path::new("E:\\some\\deep\\nested\\path")),
            PathType::LocalDirectory
        );
        assert_eq!(classify_path(Path::new("C:\\a")), PathType::LocalDirectory);
    }

    #[test]
    fn test_classify_path_relative() {
        // Relative paths are classified as local directory
        assert_eq!(classify_path(Path::new("relative")), PathType::LocalDirectory);
        assert_eq!(classify_path(Path::new("relative/path")), PathType::LocalDirectory);
        assert_eq!(classify_path(Path::new(".")), PathType::LocalDirectory);
        assert_eq!(classify_path(Path::new("..")), PathType::LocalDirectory);
    }

    #[test]
    fn test_path_type_display() {
        assert_eq!(PathType::NtfsDriveRoot.to_string(), "NTFS drive root");
        assert_eq!(PathType::LocalDirectory.to_string(), "local directory");
        assert_eq!(PathType::MappedNetworkDrive.to_string(), "mapped network drive");
        assert_eq!(PathType::UncPath.to_string(), "UNC path");
    }

    #[test]
    fn test_path_type_equality() {
        assert_eq!(PathType::NtfsDriveRoot, PathType::NtfsDriveRoot);
        assert_ne!(PathType::NtfsDriveRoot, PathType::LocalDirectory);
        assert_ne!(PathType::UncPath, PathType::MappedNetworkDrive);
    }

    #[test]
    fn test_path_type_clone() {
        let original = PathType::NtfsDriveRoot;
        let cloned = original;
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_format_size_bytes() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(1), "1 B");
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1023), "1023 B");
    }

    #[test]
    fn test_format_size_kilobytes() {
        assert_eq!(format_size(1024), "1.00 KB");
        assert_eq!(format_size(1536), "1.50 KB");
        assert_eq!(format_size(2048), "2.00 KB");
        assert_eq!(format_size(1024 * 1023), "1023.00 KB");
    }

    #[test]
    fn test_format_size_megabytes() {
        assert_eq!(format_size(1_048_576), "1.00 MB");
        assert_eq!(format_size(1_572_864), "1.50 MB");
        assert_eq!(format_size(10_485_760), "10.00 MB");
        assert_eq!(format_size(104_857_600), "100.00 MB");
    }

    #[test]
    fn test_format_size_gigabytes() {
        assert_eq!(format_size(1_073_741_824), "1.00 GB");
        assert_eq!(format_size(1_610_612_736), "1.50 GB");
        assert_eq!(format_size(10_737_418_240), "10.00 GB");
        assert_eq!(format_size(107_374_182_400), "100.00 GB");
    }

    #[test]
    fn test_format_size_terabytes() {
        assert_eq!(format_size(1_099_511_627_776), "1.00 TB");
        assert_eq!(format_size(1_649_267_441_664), "1.50 TB");
        assert_eq!(format_size(10_995_116_277_760), "10.00 TB");
    }

    #[test]
    fn test_format_size_large_values() {
        // Test very large values (petabyte range, still shown as TB)
        assert_eq!(format_size(1_125_899_906_842_624), "1024.00 TB");
        assert_eq!(format_size(u64::MAX), "16777216.00 TB");
    }

    #[test]
    fn test_format_size_boundary_values() {
        // Just below each boundary
        assert_eq!(format_size(1023), "1023 B");
        assert_eq!(format_size(1024 * 1024 - 1), "1024.00 KB");
        assert_eq!(format_size(1024 * 1024 * 1024 - 1), "1024.00 MB");
        assert_eq!(format_size(1024u64 * 1024 * 1024 * 1024 - 1), "1024.00 GB");
    }

    #[test]
    fn test_project_name_constant() {
        assert_eq!(PROJECT_NAME, "filefind");
        assert!(!PROJECT_NAME.is_empty());
    }

    #[test]
    fn test_is_unc_path_with_special_characters() {
        // UNC paths can have various characters in server/share names
        assert!(is_unc_path(Path::new(r"\\server-name\share")));
        assert!(is_unc_path(Path::new(r"\\server_name\share")));
        assert!(is_unc_path(Path::new(r"\\SERVER\SHARE")));
        assert!(is_unc_path(Path::new(r"\\server.domain.com\share")));
    }

    #[test]
    fn test_path_type_debug() {
        // Test Debug trait implementation
        let debug_str = format!("{:?}", PathType::NtfsDriveRoot);
        assert!(debug_str.contains("NtfsDriveRoot"));

        let debug_str = format!("{:?}", PathType::UncPath);
        assert!(debug_str.contains("UncPath"));
    }

    #[test]
    fn test_classify_path_empty() {
        // Empty path should be classified as local directory
        assert_eq!(classify_path(Path::new("")), PathType::LocalDirectory);
    }

    #[test]
    fn test_format_size_precision() {
        // Test that decimal formatting is correct
        // 1.5 KB = 1536 bytes
        let result = format_size(1536);
        assert!(result.contains("1.50"));

        // Test rounding - 1.999... should round to 2.00
        let result = format_size(2047);
        // 2047 / 1024 = 1.9990234375
        assert!(result.contains("KB"));
    }

    #[cfg(not(windows))]
    #[test]
    fn test_is_mapped_network_drive_non_windows() {
        // On non-Windows, this should always return false
        assert!(!is_mapped_network_drive(Path::new("C:\\")));
        assert!(!is_mapped_network_drive(Path::new("Z:\\")));
        assert!(!is_mapped_network_drive(Path::new(r"\\server\share")));
    }

    #[test]
    fn test_format_number_zero() {
        assert_eq!(format_number(0), "0");
    }

    #[test]
    fn test_format_number_small() {
        assert_eq!(format_number(1), "1");
        assert_eq!(format_number(12), "12");
        assert_eq!(format_number(123), "123");
        assert_eq!(format_number(999), "999");
    }

    #[test]
    fn test_format_number_thousands() {
        assert_eq!(format_number(1000), "1,000");
        assert_eq!(format_number(1234), "1,234");
        assert_eq!(format_number(12345), "12,345");
        assert_eq!(format_number(123_456), "123,456");
    }

    #[test]
    fn test_format_number_millions() {
        assert_eq!(format_number(1_000_000), "1,000,000");
        assert_eq!(format_number(1_234_567), "1,234,567");
        assert_eq!(format_number(12_345_678), "12,345,678");
        assert_eq!(format_number(123_456_789), "123,456,789");
    }

    #[test]
    fn test_format_number_billions() {
        assert_eq!(format_number(1_000_000_000), "1,000,000,000");
        assert_eq!(format_number(1_234_567_890), "1,234,567,890");
    }

    #[test]
    fn test_format_number_large() {
        // Test u64 max value
        assert_eq!(format_number(u64::MAX), "18,446,744,073,709,551,615");
    }

    #[test]
    fn test_get_log_directory() {
        let result = get_log_directory();
        assert!(result.is_ok());

        let path = result.expect("should return path");
        let path_str = path.to_string_lossy();

        // Should contain the project name
        assert!(path_str.contains(PROJECT_NAME));
        // Should contain "logs" directory
        assert!(path_str.contains("logs"));
    }
}
