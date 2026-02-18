//! Shared library for filefind - configuration, database, and common types.

use std::collections::HashMap;
use std::hash::BuildHasher;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Command;
use clap_complete::Shell;
use colored::Colorize;

pub mod config;
pub mod database;
pub mod ipc;
pub mod types;

pub use config::{CONFIG_PATH, LogLevel, PathMapping, UserConfig as Config};
pub use database::{Database, VolumeStats};
pub use ipc::{
    DaemonCommand, DaemonResponse, DaemonStateInfo, DaemonStatus, IpcClient, get_ipc_path, read_message, write_message,
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
    let bytes = path.to_string_lossy();
    let bytes = bytes.as_bytes();

    // Check if it's a drive root like "C:\", "C:", "C:/"
    matches!(
        bytes,
        [letter, b':', ..] if letter.is_ascii_alphabetic() && (
            bytes.len() == 2 || (bytes.len() == 3 && (bytes[2] == b'\\' || bytes[2] == b'/'))
        )
    )
}

/// Check if a path is on a network drive (either UNC or mapped).
///
/// On Windows, detects mapped network drives and UNC paths.
/// On other platforms, always returns false.
#[must_use]
pub fn is_network_path(path: &Path) -> bool {
    is_unc_path(path) || is_mapped_network_drive(path)
}

/// Extract a lowercase volume prefix from a path for same-volume comparison.
///
/// Returns the drive letter (e.g., `"c:"`) for local paths, or the UNC server
/// and share (e.g., `"\\server\share"`) for network paths. The `\\?\` prefix
/// added by [`Path::canonicalize`] on Windows is stripped before extraction.
///
/// Returns `None` if the path has no recognizable volume root.
///
/// # Examples
///
/// ```
/// # use filefind::get_volume_prefix;
/// assert_eq!(get_volume_prefix(r"C:\Users\foo"), Some("c:".to_string()));
/// assert_eq!(get_volume_prefix(r"\\?\D:\data"), Some("d:".to_string()));
/// assert_eq!(get_volume_prefix(r"\\server\share\folder"), Some(r"\\server\share".to_string()));
/// assert_eq!(get_volume_prefix("relative/path"), None);
/// ```
#[must_use]
pub fn get_volume_prefix(path: &str) -> Option<String> {
    // Strip the \\?\ extended-length prefix that canonicalize adds on Windows
    let path = path.strip_prefix(r"\\?\").unwrap_or(path);

    // UNC path: \\server\share\...
    if let Some(remainder) = path.strip_prefix(r"\\") {
        // Find server\share — the first two path components
        let mut components = remainder.splitn(3, '\\');
        let server = components.next()?;
        let share = components.next()?;
        if server.is_empty() || share.is_empty() {
            return None;
        }
        return Some(format!(r"\\{server}\{share}").to_lowercase());
    }

    // Drive letter path: C:\..., C:/..., C:...
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Some(path[..2].to_lowercase());
    }

    None
}

/// Get the UNC path that a mapped network drive letter points to.
///
/// Given a drive letter like 'X', returns the UNC path (e.g., `\\192.168.1.106\Home`)
/// if the drive is a mapped network drive. Returns `None` for local drives or
/// if the query fails.
#[cfg(windows)]
#[must_use]
pub fn get_unc_for_drive(drive_letter: char) -> Option<String> {
    use windows_sys::Win32::Foundation::NO_ERROR;
    use windows_sys::Win32::NetworkManagement::WNet::WNetGetConnectionW;

    let drive_letter = drive_letter.to_ascii_uppercase();
    let local_name: Vec<u16> = format!("{drive_letter}:")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // Start with a reasonable buffer size
    let mut buffer: Vec<u16> = vec![0u16; 512];
    let mut buffer_len = u32::try_from(buffer.len()).unwrap_or(512);

    // SAFETY: `WNetGetConnectionW` is a safe Windows API call that reads the
    // null-terminated local name string and writes the remote name into the buffer.
    #[allow(unsafe_code)]
    let result = unsafe { WNetGetConnectionW(local_name.as_ptr(), buffer.as_mut_ptr(), &raw mut buffer_len) };

    if result != NO_ERROR {
        return None;
    }

    // Find the null terminator and convert to String
    let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    String::from_utf16(&buffer[..len]).ok()
}

/// Get the UNC path for a mapped network drive letter (non-Windows stub).
#[cfg(not(windows))]
#[must_use]
pub fn get_unc_for_drive(_drive_letter: char) -> Option<String> {
    None
}

/// Get drive letter → UNC path mappings for the specified drive letters.
///
/// Only checks the provided drive letters instead of iterating all A–Z.
/// Returns a map from lowercase UNC prefix to the uppercase drive letter.
/// For example: `{"\\\\192.168.1.106\\home": 'X'}`.
///
/// This enables resolving UNC paths to their corresponding mapped drive letters
/// so that paths stored in the database use drive letters that Windows recognizes.
#[must_use]
pub fn get_drive_mappings(drive_letters: &[char]) -> HashMap<String, char> {
    let mut mappings = HashMap::new();
    for &drive_letter in drive_letters {
        if let Some(unc_path) = get_unc_for_drive(drive_letter) {
            // Store lowercase for case-insensitive matching
            mappings.insert(unc_path.to_lowercase(), drive_letter.to_ascii_uppercase());
        }
    }
    mappings
}

/// Build a combined path mapping table from auto-detected drive mappings and manual config overrides.
///
/// The `drive_letters` parameter specifies which drive letters to check for UNC mappings.
/// Only existing drives relevant to the current scan should be passed in.
/// The `manual_mappings` parameter is a list of UNC prefix → drive letter pairs from the user config.
/// Manual mappings take priority over auto-detected ones.
///
/// Returns a map from lowercase UNC prefix to the drive letter prefix (e.g., `"X:"`).
#[must_use]
pub fn build_path_mappings(drive_letters: &[char], manual_mappings: &[PathMapping]) -> HashMap<String, String> {
    // Start with auto-detected mappings for the specified drives
    let auto_mappings = get_drive_mappings(drive_letters);
    let mut result: HashMap<String, String> = auto_mappings
        .into_iter()
        .map(|(unc, letter)| (unc, format!("{letter}:")))
        .collect();

    // Manual mappings override auto-detected ones
    for mapping in manual_mappings {
        let unc_prefix = mapping.unc.to_lowercase();
        // Normalize drive letter to have a colon (e.g., "X" -> "X:")
        let drive_prefix = if mapping.drive.ends_with(':') {
            mapping.drive.clone()
        } else {
            format!("{}:", mapping.drive)
        };
        result.insert(unc_prefix, drive_prefix);
    }

    result
}

/// Try to resolve a UNC path to use a mapped drive letter prefix.
///
/// If the path starts with a known UNC prefix (from `mappings`), the UNC prefix
/// is replaced with the corresponding drive letter prefix.
///
/// For example, with mapping `"\\\\192.168.1.106\\home" → "X:"`:
/// - `\\192.168.1.106\Home\Data\file.txt` → `X:\Data\file.txt`
/// - `\\other\share\file.txt` → `None` (no matching mapping)
#[must_use]
pub fn resolve_unc_to_mapped_path<S: BuildHasher>(path: &str, mappings: &HashMap<String, String, S>) -> Option<String> {
    let path_lower = path.to_lowercase();
    for (unc_prefix, drive_prefix) in mappings {
        if path_lower.starts_with(unc_prefix) {
            let remainder = &path[unc_prefix.len()..];
            return Some(format!("{drive_prefix}{remainder}"));
        }
    }
    None
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
pub fn print_cyan(message: &str) {
    println!("{}", message.cyan());
}

/// Print an info message in cyan with formatting support.
#[macro_export]
macro_rules! print_cyan {
    ($($arg:tt)*) => {
        $crate::print_cyan(&format!($($arg)*))
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

/// Print a message in bold yellow.
pub fn print_bold_yellow(message: &str) {
    println!("{}", message.bold().yellow());
}

/// Print a message in bold yellow with formatting support.
#[macro_export]
macro_rules! print_bold_yellow {
    ($($arg:tt)*) => {
        $crate::print_bold_yellow(&format!($($arg)*))
    };
}

/// Print a message in bold red.
pub fn print_bold_red(message: &str) {
    println!("{}", message.bold().red());
}

/// Print a message in bold red with formatting support.
#[macro_export]
macro_rules! print_bold_red {
    ($($arg:tt)*) => {
        $crate::print_bold_red(&format!($($arg)*))
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
    let bytes = string.as_bytes();
    let len = bytes.len();

    if len <= 3 {
        return string;
    }

    // Pre-allocate: original length + number of commas
    let comma_count = (len - 1) / 3;
    let mut result = String::with_capacity(len + comma_count);

    for (index, &byte) in bytes.iter().enumerate() {
        if index > 0 && (len - index).is_multiple_of(3) {
            result.push(',');
        }
        result.push(byte as char);
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
        Shell::Elvish => home.join(".elvish/lib"),
        Shell::Fish => home.join(".config/fish/completions"),
        Shell::Zsh => home.join(".zsh/completions"),
        _ => anyhow::bail!("Unsupported shell"),
    };

    if user_dir.exists() {
        return Ok(user_dir);
    }

    // PowerShell has no separate global directory; skip the global fallback for it.
    let global_dir = match shell {
        Shell::Bash => Some(PathBuf::from("/etc/bash_completion.d")),
        Shell::Fish => Some(PathBuf::from("/usr/share/fish/completions")),
        Shell::Zsh => Some(PathBuf::from("/usr/share/zsh/site-functions")),
        _ => None,
    };

    if let Some(global) = global_dir
        && global.exists()
    {
        return Ok(global);
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

    #[test]
    fn test_resolve_unc_to_mapped_path_basic() {
        let mut mappings = HashMap::new();
        mappings.insert(r"\\192.168.1.106\home".to_string(), "X:".to_string());

        // Matching UNC path should be resolved
        let result = resolve_unc_to_mapped_path(r"\\192.168.1.106\Home\Data\file.txt", &mappings);
        assert_eq!(result, Some(r"X:\Data\file.txt".to_string()));
    }

    #[test]
    fn test_resolve_unc_to_mapped_path_exact_prefix() {
        let mut mappings = HashMap::new();
        mappings.insert(r"\\server\share".to_string(), "Z:".to_string());

        // Exact prefix match with trailing content
        let result = resolve_unc_to_mapped_path(r"\\server\share\folder\doc.pdf", &mappings);
        assert_eq!(result, Some(r"Z:\folder\doc.pdf".to_string()));
    }

    #[test]
    fn test_resolve_unc_to_mapped_path_no_match() {
        let mut mappings = HashMap::new();
        mappings.insert(r"\\192.168.1.106\home".to_string(), "X:".to_string());

        // Non-matching UNC path should return None
        let result = resolve_unc_to_mapped_path(r"\\other-server\share\file.txt", &mappings);
        assert_eq!(result, None);
    }

    #[test]
    fn test_resolve_unc_to_mapped_path_case_insensitive() {
        let mut mappings = HashMap::new();
        mappings.insert(r"\\server\share".to_string(), "Z:".to_string());

        // Different case should still match (UNC prefix stored lowercase)
        let result = resolve_unc_to_mapped_path(r"\\SERVER\SHARE\file.txt", &mappings);
        assert_eq!(result, Some(r"Z:\file.txt".to_string()));
    }

    #[test]
    fn test_resolve_unc_to_mapped_path_preserves_original_case_in_remainder() {
        let mut mappings = HashMap::new();
        mappings.insert(r"\\server\share".to_string(), "Z:".to_string());

        // The remainder after the prefix should preserve original casing
        let result = resolve_unc_to_mapped_path(r"\\Server\Share\MyFolder\README.md", &mappings);
        assert_eq!(result, Some(r"Z:\MyFolder\README.md".to_string()));
    }

    #[test]
    fn test_resolve_unc_to_mapped_path_empty_mappings() {
        let mappings: HashMap<String, String> = HashMap::new();

        let result = resolve_unc_to_mapped_path(r"\\server\share\file.txt", &mappings);
        assert_eq!(result, None);
    }

    #[test]
    fn test_resolve_unc_to_mapped_path_multiple_mappings() {
        let mut mappings = HashMap::new();
        mappings.insert(r"\\nas1\media".to_string(), "Y:".to_string());
        mappings.insert(r"\\nas2\backup".to_string(), "Z:".to_string());

        let result1 = resolve_unc_to_mapped_path(r"\\nas1\media\movies\film.mkv", &mappings);
        assert_eq!(result1, Some(r"Y:\movies\film.mkv".to_string()));

        let result2 = resolve_unc_to_mapped_path(r"\\nas2\backup\docs\report.pdf", &mappings);
        assert_eq!(result2, Some(r"Z:\docs\report.pdf".to_string()));
    }

    #[test]
    fn test_resolve_unc_to_mapped_path_root_only() {
        let mut mappings = HashMap::new();
        mappings.insert(r"\\server\share".to_string(), "Z:".to_string());

        // Path that is exactly the prefix with no remainder
        let result = resolve_unc_to_mapped_path(r"\\server\share", &mappings);
        assert_eq!(result, Some("Z:".to_string()));
    }

    #[test]
    fn test_resolve_unc_to_mapped_path_local_path_not_matched() {
        let mut mappings = HashMap::new();
        mappings.insert(r"\\server\share".to_string(), "Z:".to_string());

        // Local paths should not match UNC mappings
        let result = resolve_unc_to_mapped_path(r"C:\Users\file.txt", &mappings);
        assert_eq!(result, None);
    }

    #[test]
    fn test_build_path_mappings_manual_only() {
        let manual = vec![PathMapping {
            unc: r"\\myserver\data".to_string(),
            drive: "W".to_string(),
        }];

        let result = build_path_mappings(&[], &manual);

        // Manual mapping should be present (normalized to lowercase key)
        assert_eq!(result.get(r"\\myserver\data"), Some(&"W:".to_string()));
    }

    #[test]
    fn test_build_path_mappings_empty() {
        let manual: Vec<PathMapping> = vec![];

        // Should not panic with empty manual mappings
        let result = build_path_mappings(&[], &manual);

        // Result contains auto-detected mappings (may be empty on test machine)
        // Just verify it doesn't panic and returns a valid HashMap
        drop(result);
    }

    #[test]
    fn test_build_path_mappings_manual_normalizes_case() {
        let manual = vec![PathMapping {
            unc: r"\\SERVER\SHARE".to_string(),
            drive: "X:".to_string(),
        }];

        let result = build_path_mappings(&[], &manual);

        // Key should be normalized to lowercase
        assert_eq!(result.get(r"\\server\share"), Some(&"X:".to_string()));
        // Original case key should not exist
        assert_eq!(result.get(r"\\SERVER\SHARE"), None);
    }

    #[test]
    fn test_get_drive_mappings_returns_valid_map() {
        // This test just ensures the function doesn't panic and returns a valid HashMap.
        // Actual mappings depend on the system state.
        let mappings = get_drive_mappings(&['C', 'D', 'E', 'X', 'Y', 'Z']);
        for (unc, letter) in &mappings {
            // All UNC keys should be lowercase
            assert_eq!(unc, &unc.to_lowercase(), "UNC key should be lowercase: {unc}");
            // All drive letters should be uppercase A-Z
            assert!(
                letter.is_ascii_uppercase(),
                "Drive letter should be uppercase: {letter}"
            );
        }
    }

    #[test]
    fn test_get_drive_mappings_empty_input() {
        let mappings = get_drive_mappings(&[]);
        assert!(mappings.is_empty());
    }

    #[test]
    fn test_get_unc_for_drive_local_drive() {
        // C: is almost always a local drive, not a mapped network drive
        let result = get_unc_for_drive('C');
        assert_eq!(result, None, "C: should not be a mapped network drive");
    }

    // --- get_volume_prefix tests ---

    #[test]
    fn test_get_volume_prefix_drive_letter() {
        assert_eq!(get_volume_prefix(r"C:\Users\foo"), Some("c:".to_string()));
        assert_eq!(get_volume_prefix(r"D:\"), Some("d:".to_string()));
        assert_eq!(get_volume_prefix("E:"), Some("e:".to_string()));
        assert_eq!(get_volume_prefix("f:/some/path"), Some("f:".to_string()));
    }

    #[test]
    fn test_get_volume_prefix_drive_letter_case_insensitive() {
        assert_eq!(get_volume_prefix(r"C:\file"), get_volume_prefix(r"c:\other"));
        assert_eq!(get_volume_prefix(r"Z:\a"), Some("z:".to_string()));
    }

    #[test]
    fn test_get_volume_prefix_unc_path() {
        assert_eq!(
            get_volume_prefix(r"\\server\share\folder\file.txt"),
            Some(r"\\server\share".to_string())
        );
        assert_eq!(
            get_volume_prefix(r"\\192.168.1.1\data"),
            Some(r"\\192.168.1.1\data".to_string())
        );
    }

    #[test]
    fn test_get_volume_prefix_unc_case_insensitive() {
        assert_eq!(
            get_volume_prefix(r"\\SERVER\Share\foo"),
            Some(r"\\server\share".to_string())
        );
    }

    #[test]
    fn test_get_volume_prefix_with_extended_length_prefix() {
        assert_eq!(get_volume_prefix(r"\\?\C:\Users\foo"), Some("c:".to_string()));
        assert_eq!(get_volume_prefix(r"\\?\D:\"), Some("d:".to_string()));
    }

    #[test]
    fn test_get_volume_prefix_edge_cases() {
        assert_eq!(get_volume_prefix(""), None);
        assert_eq!(get_volume_prefix("relative/path"), None);
        assert_eq!(get_volume_prefix("/unix/style"), None);
        assert_eq!(get_volume_prefix("C"), None);
        // Malformed UNC: missing share
        assert_eq!(get_volume_prefix(r"\\server\"), None);
        // Malformed UNC: nothing after \\
        assert_eq!(get_volume_prefix(r"\\"), None);
    }

    #[test]
    fn test_get_unc_for_drive_non_existent() {
        // Drive letter that very likely doesn't exist
        // We just check it returns None and doesn't panic
        let result = get_unc_for_drive('!');
        assert_eq!(result, None);
    }
}
