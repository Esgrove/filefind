use std::borrow::Cow;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use colored::Colorize;
use filefind::FileEntry;

const CHECK_TIMEOUT: Duration = Duration::from_millis(250);

/// Highlight multiple patterns within the given text (case-insensitive).
///
/// Finds all matches for all patterns, merges overlapping ranges, and highlights them.
pub fn highlight_match<'a>(text: &'a str, patterns: &[&str]) -> Cow<'a, str> {
    if patterns.is_empty() {
        return Cow::Borrowed(text);
    }

    let text_lower = text.to_lowercase();

    // Pre-lowercase all patterns once instead of per-match
    let patterns_lower: Vec<String> = patterns.iter().map(|p| p.to_lowercase()).collect();

    // Collect all match ranges (start, end) for all patterns
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for pattern_lower in &patterns_lower {
        for (start, matched) in text_lower.match_indices(pattern_lower.as_str()) {
            ranges.push((start, start + matched.len()));
        }
    }

    if ranges.is_empty() {
        return Cow::Borrowed(text);
    }

    // Sort by start position, then by end position (longer matches first)
    ranges.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));

    // Merge overlapping ranges
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (start, end) in ranges {
        if let Some(last) = merged.last_mut() {
            if start <= last.1 {
                // Overlapping or adjacent, extend the range
                last.1 = last.1.max(end);
            } else {
                merged.push((start, end));
            }
        } else {
            merged.push((start, end));
        }
    }

    // Build result with highlighted ranges
    let mut result = String::new();
    let mut last_end = 0;

    for (start, end) in merged {
        // Add text before the match
        result.push_str(&text[last_end..start]);
        // Add highlighted match using original case from text
        let matched_text = &text[start..end];
        result.push_str(&matched_text.green().bold().to_string());
        last_end = end;
    }

    // Add remaining text
    result.push_str(&text[last_end..]);
    Cow::Owned(result)
}

/// Check if a directory is truly empty on the filesystem.
/// Returns true if the directory exists and contains no entries.
/// Returns false if the directory has contents, doesn't exist, or check times out.
pub fn is_directory_empty_on_disk(path: &str) -> bool {
    let path = path.to_string();
    let (sender, receiver) = mpsc::channel();

    thread::spawn(move || {
        let is_empty = Path::new(&path)
            .read_dir()
            .map(|mut entries| entries.next().is_none())
            .unwrap_or(false);
        let _ = sender.send(is_empty);
    });

    receiver.recv_timeout(CHECK_TIMEOUT).unwrap_or(false)
}

/// Check if a path is accessible with a timeout.
/// Returns false if the path doesn't exist or if the check takes longer than the timeout time.
pub fn check_path_accessible(path: &str) -> bool {
    let path = path.to_string();
    let (sender, receiver) = mpsc::channel();

    thread::spawn(move || {
        let exists = Path::new(&path).exists();
        let _ = sender.send(exists);
    });

    receiver.recv_timeout(CHECK_TIMEOUT).unwrap_or(false)
}

/// Check if a directory exists on disk with a timeout.
/// Returns true if the directory exists and is a directory.
/// Returns false if it doesn't exist, is not a directory, or the check times out.
pub fn check_directory_exists(path: &str) -> bool {
    let path = path.to_string();
    let (sender, receiver) = mpsc::channel();

    thread::spawn(move || {
        let path = Path::new(&path);
        let exists = path.is_dir();
        let _ = sender.send(exists);
    });

    receiver.recv_timeout(CHECK_TIMEOUT).unwrap_or(false)
}

/// Calculate the total size of files under each directory.
pub fn calculate_directory_sizes(files: &[&FileEntry]) -> HashMap<String, u64> {
    let mut dir_sizes: HashMap<String, u64> = HashMap::new();

    for file in files {
        if let Some(parent) = PathBuf::from(&file.full_path).parent() {
            let parent_str = parent.to_string_lossy().to_string();
            *dir_sizes.entry(parent_str).or_insert(0) += file.size;
        }
    }

    dir_sizes
}

/// Count all matching files under a directory (including subdirectories).
pub fn count_files_under_directory(files: &[&FileEntry], dir_path: &str) -> usize {
    let dir_prefix_backslash = format!("{dir_path}\\");
    let dir_prefix_forward = format!("{dir_path}/");
    files
        .iter()
        .filter(|f| f.full_path.starts_with(&dir_prefix_backslash) || f.full_path.starts_with(&dir_prefix_forward))
        .count()
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;

    #[test]
    fn test_highlight_match_empty_patterns_returns_borrowed() {
        let text = "C:\\Users\\file.txt";
        let result = highlight_match(text, &[]);
        assert!(matches!(result, Cow::Borrowed(_)));
        assert_eq!(result, text);
    }

    #[test]
    fn test_highlight_match_no_match_returns_borrowed() {
        let text = "C:\\Users\\file.txt";
        let result = highlight_match(text, &["nonexistent"]);
        assert!(matches!(result, Cow::Borrowed(_)));
        assert_eq!(result, text);
    }

    #[test]
    fn test_highlight_match_with_match_returns_owned() {
        let text = "C:\\Users\\file.txt";
        let result = highlight_match(text, &["file"]);
        assert!(matches!(result, Cow::Owned(_)));
        // The result should contain the matched text (with or without ANSI codes depending on terminal)
        assert!(result.contains("file"));
    }

    #[test]
    fn test_highlight_match_case_insensitive() {
        let text = "MyDocument.TXT";
        let result = highlight_match(text, &["mydocument"]);
        assert!(matches!(result, Cow::Owned(_)));
        // Original case should be preserved in the highlighted output
        assert!(result.contains("MyDocument"));
    }

    #[test]
    fn test_highlight_match_multiple_patterns() {
        let text = "C:\\Users\\Documents\\report.pdf";
        let result = highlight_match(text, &["Users", "report"]);
        assert!(matches!(result, Cow::Owned(_)));
        assert!(result.contains("Users"));
        assert!(result.contains("report"));
    }

    #[test]
    fn test_highlight_match_overlapping_patterns() {
        let text = "abcdef";
        // "bcd" and "cde" overlap
        let result = highlight_match(text, &["bcd", "cde"]);
        assert!(matches!(result, Cow::Owned(_)));
        // The merged highlight should cover "bcde"
        assert!(result.contains("bcde"));
    }

    #[test]
    fn test_highlight_match_multiple_occurrences() {
        let text = "test_test_test";
        let result = highlight_match(text, &["test"]);
        assert!(matches!(result, Cow::Owned(_)));
    }

    #[test]
    fn test_highlight_match_full_text_match() {
        let text = "hello";
        let result = highlight_match(text, &["hello"]);
        assert!(matches!(result, Cow::Owned(_)));
        assert!(result.contains("hello"));
    }

    #[test]
    fn test_highlight_match_empty_text() {
        let result = highlight_match("", &["pattern"]);
        assert!(matches!(result, Cow::Borrowed(_)));
        assert_eq!(result, "");
    }

    #[test]
    fn test_highlight_match_empty_text_empty_patterns() {
        let result = highlight_match("", &[]);
        assert!(matches!(result, Cow::Borrowed(_)));
        assert_eq!(result, "");
    }
}
