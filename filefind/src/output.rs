//! Shared colored terminal messages and human-readable numeric formatting.

use colored::Colorize;

/// Print an error message in red to stderr.
///
/// # Examples
///
/// ```
/// filefind::print_error("something went wrong");
/// ```
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

/// Print a warning message in yellow to stderr.
///
/// # Examples
///
/// ```
/// filefind::print_warning("this might be a problem");
/// ```
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

/// Print a success message in green to stdout.
///
/// # Examples
///
/// ```
/// filefind::print_success("operation completed");
/// ```
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

/// Print an info message in cyan to stdout.
///
/// # Examples
///
/// ```
/// filefind::print_cyan("indexing files...");
/// ```
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

/// Print a message in bold magenta to stdout.
///
/// # Examples
///
/// ```
/// filefind::print_bold_magenta("highlighted info");
/// ```
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

/// Print a message in bold yellow to stdout.
///
/// # Examples
///
/// ```
/// filefind::print_bold_yellow("important notice");
/// ```
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

/// Print a message in bold red to stdout.
///
/// # Examples
///
/// ```
/// filefind::print_bold_red("critical error");
/// ```
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
///
/// Uses binary units (1 KB = 1024 bytes).
///
/// # Examples
///
/// ```
/// use filefind::format_size;
///
/// assert_eq!(format_size(0), "0 B");
/// assert_eq!(format_size(512), "512 B");
/// assert_eq!(format_size(1024), "1.00 KB");
/// assert_eq!(format_size(1_048_576), "1.00 MB");
/// assert_eq!(format_size(1_073_741_824), "1.00 GB");
/// ```
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
///
/// # Examples
///
/// ```
/// use filefind::format_number;
///
/// assert_eq!(format_number(0), "0");
/// assert_eq!(format_number(999), "999");
/// assert_eq!(format_number(1_000), "1,000");
/// assert_eq!(format_number(1_234_567), "1,234,567");
/// ```
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
