//! Shared library for filefind - configuration, database, and common types.

pub mod config;
pub mod database;
pub mod types;

pub use config::{CONFIG_PATH, UserConfig as Config};
pub use database::Database;
pub use types::{FileEntry, IndexedVolume, VolumeType};

use colored::Colorize;

/// Project name constant.
pub const PROJECT_NAME: &str = "filefind";

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
