use std::borrow::Cow;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use colored::Colorize;
use filefind::FileEntry;
use filefind::is_network_path;

const CHECK_TIMEOUT: Duration = Duration::from_millis(250);

/// Highlight multiple patterns within the given text (case-insensitive).
///
/// Finds all matches for all patterns, merges overlapping ranges, and highlights them.
/// Returns a borrowed `Cow` if no matches are found, or an owned `Cow` with ANSI
/// color codes applied to matched regions.
///
/// # Examples
///
/// ```ignore
/// use std::borrow::Cow;
///
/// // No patterns returns the original text borrowed
/// let result = highlight_match("hello world", &[]);
/// assert!(matches!(result, Cow::Borrowed(_)));
///
/// // No match also returns borrowed
/// let result = highlight_match("hello world", &["xyz"]);
/// assert!(matches!(result, Cow::Borrowed(_)));
///
/// // A match returns an owned string with highlighting
/// let result = highlight_match("hello world", &["hello"]);
/// assert!(matches!(result, Cow::Owned(_)));
/// ```
pub fn highlight_match<'a>(text: &'a str, patterns: &[&str]) -> Cow<'a, str> {
    if patterns.is_empty() {
        return Cow::Borrowed(text);
    }

    let text_lower = text.to_lowercase();

    // Pre-lowercase all patterns once instead of per-match
    let patterns_lower: Vec<String> = patterns.iter().map(|pattern| pattern.to_lowercase()).collect();

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
///
/// Returns `true` if the directory exists and contains no entries.
/// Returns `false` if the directory has contents, doesn't exist, or the check
/// times out (250ms).
///
/// The check runs in a separate thread to avoid blocking on network paths.
///
/// # Examples
///
/// ```ignore
/// // A newly created temp directory is empty
/// let dir = std::env::temp_dir().join("filefind_test_empty");
/// std::fs::create_dir_all(&dir).unwrap();
/// assert!(is_directory_empty_on_disk(&dir.to_string_lossy()));
/// std::fs::remove_dir(&dir).unwrap();
/// ```
pub fn is_directory_empty_on_disk(path: &str) -> bool {
    let path = Path::new(path);
    if !is_network_path(path) {
        return path.read_dir().is_ok_and(|mut entries| entries.next().is_none());
    }

    let path = path.to_string_lossy().into_owned();
    let (sender, receiver) = mpsc::channel();

    thread::spawn(move || {
        let is_empty = Path::new(&path)
            .read_dir()
            .is_ok_and(|mut entries| entries.next().is_none());
        let _ = sender.send(is_empty);
    });

    receiver.recv_timeout(CHECK_TIMEOUT).unwrap_or(false)
}

/// Check if a path is accessible with a timeout.
///
/// Returns `false` if the path doesn't exist or if the check takes longer than
/// 250ms. The check runs in a separate thread to avoid blocking on unresponsive
/// network paths.
///
/// # Examples
///
/// ```ignore
/// assert!(check_path_accessible(&std::env::temp_dir().to_string_lossy()));
/// let missing_path = std::env::temp_dir().join("filefind_missing_path_example");
/// assert!(!check_path_accessible(&missing_path.to_string_lossy()));
/// ```
pub fn check_path_accessible(path: &str) -> bool {
    let path = Path::new(path);
    if !is_network_path(path) {
        return path.exists();
    }

    let path = path.to_string_lossy().into_owned();
    let (sender, receiver) = mpsc::channel();

    thread::spawn(move || {
        let exists = Path::new(&path).exists();
        let _ = sender.send(exists);
    });

    receiver.recv_timeout(CHECK_TIMEOUT).unwrap_or(false)
}

/// Check if a directory exists on disk with a timeout.
///
/// Returns `true` if the path exists and is a directory.
/// Returns `false` if it doesn't exist, is not a directory, or the check times
/// out (250ms). The check runs in a separate thread to avoid blocking on
/// unresponsive network paths.
///
/// # Examples
///
/// ```ignore
/// assert!(check_directory_exists(&std::env::temp_dir().to_string_lossy()));
/// let missing_dir = std::env::temp_dir().join("filefind_missing_dir_example");
/// assert!(!check_directory_exists(&missing_dir.to_string_lossy()));
/// ```
pub fn check_directory_exists(path: &str) -> bool {
    let path = Path::new(path);
    if !is_network_path(path) {
        return path.is_dir();
    }

    let path = path.to_string_lossy().into_owned();
    let (sender, receiver) = mpsc::channel();

    thread::spawn(move || {
        let path = Path::new(&path);
        let exists = path.is_dir();
        let _ = sender.send(exists);
    });

    receiver.recv_timeout(CHECK_TIMEOUT).unwrap_or(false)
}

/// Calculate the total size of files under each directory.
///
/// Groups the given file entries by their parent directory and sums the file sizes
/// for each directory.
///
/// # Examples
///
/// ```ignore
/// let file = FileEntry {
///     name: "readme.md".to_string(),
///     full_path: r"C:\project\readme.md".to_string(),
///     size: 1024,
///     is_directory: false,
///     ..Default::default()
/// };
/// let files = vec![&file];
/// let sizes = calculate_directory_sizes(&files);
/// assert_eq!(sizes.get(r"C:\project"), Some(&1024));
/// ```
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
///
/// Matches files whose `full_path` starts with the directory path followed by
/// a separator (`\` or `/`).
///
/// # Examples
///
/// ```ignore
/// let file = FileEntry {
///     name: "readme.md".to_string(),
///     full_path: r"C:\project\src\readme.md".to_string(),
///     ..Default::default()
/// };
/// let files = vec![&file];
/// assert_eq!(count_files_under_directory(&files, r"C:\project"), 1);
/// assert_eq!(count_files_under_directory(&files, r"D:\other"), 0);
/// ```
pub fn count_files_under_directory(files: &[&FileEntry], dir_path: &str) -> usize {
    let dir_prefix_backslash = format!("{dir_path}\\");
    let dir_prefix_forward = format!("{dir_path}/");
    files
        .iter()
        .filter(|file| {
            file.full_path.starts_with(&dir_prefix_backslash) || file.full_path.starts_with(&dir_prefix_forward)
        })
        .count()
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::fs;
    use std::time::SystemTime;

    use filefind::FileEntry;
    use tempfile::tempdir;

    use super::*;

    /// Helper to create a test file entry.
    fn make_file(name: &str, path: &str, size: u64) -> FileEntry {
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

    // ── highlight_match ───────────────────────────────────────────

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

    #[test]
    fn test_highlight_match_adjacent_patterns() {
        let text = "abcd";
        // "ab" and "cd" are adjacent but not overlapping
        let result = highlight_match(text, &["ab", "cd"]);
        assert!(matches!(result, Cow::Owned(_)));
        assert!(result.contains("ab"));
        assert!(result.contains("cd"));
    }

    #[test]
    fn test_highlight_match_pattern_at_start() {
        let text = "hello world";
        let result = highlight_match(text, &["hello"]);
        assert!(matches!(result, Cow::Owned(_)));
        assert!(result.contains("hello"));
        assert!(result.contains(" world"));
    }

    #[test]
    fn test_highlight_match_pattern_at_end() {
        let text = "hello world";
        let result = highlight_match(text, &["world"]);
        assert!(matches!(result, Cow::Owned(_)));
        assert!(result.contains("world"));
    }

    // ── calculate_directory_sizes ─────────────────────────────────

    #[test]
    fn test_calculate_directory_sizes_empty() {
        let files: Vec<&FileEntry> = Vec::new();
        let sizes = calculate_directory_sizes(&files);
        assert!(sizes.is_empty());
    }

    #[test]
    fn test_calculate_directory_sizes_single_file() {
        let file = make_file("test.txt", "C:\\Projects\\test.txt", 1024);
        let files: Vec<&FileEntry> = vec![&file];
        let sizes = calculate_directory_sizes(&files);
        assert_eq!(sizes.len(), 1);
        assert_eq!(*sizes.get("C:\\Projects").expect("Missing directory"), 1024);
    }

    #[test]
    fn test_calculate_directory_sizes_multiple_files_same_dir() {
        let file1 = make_file("a.txt", "C:\\Dir\\a.txt", 100);
        let file2 = make_file("b.txt", "C:\\Dir\\b.txt", 200);
        let file3 = make_file("c.txt", "C:\\Dir\\c.txt", 300);
        let all_files: Vec<&FileEntry> = vec![&file1, &file2, &file3];
        let sizes = calculate_directory_sizes(&all_files);
        assert_eq!(sizes.len(), 1);
        assert_eq!(*sizes.get("C:\\Dir").expect("Missing directory"), 600);
    }

    #[test]
    fn test_calculate_directory_sizes_multiple_directories() {
        let file1 = make_file("a.txt", "C:\\DirA\\a.txt", 100);
        let file2 = make_file("b.txt", "C:\\DirB\\b.txt", 200);
        let file3 = make_file("c.txt", "C:\\DirA\\c.txt", 50);
        let all_files: Vec<&FileEntry> = vec![&file1, &file2, &file3];
        let sizes = calculate_directory_sizes(&all_files);
        assert_eq!(sizes.len(), 2);
        assert_eq!(*sizes.get("C:\\DirA").expect("Missing DirA"), 150);
        assert_eq!(*sizes.get("C:\\DirB").expect("Missing DirB"), 200);
    }

    #[test]
    fn test_calculate_directory_sizes_nested_directories() {
        let file1 = make_file("a.txt", "C:\\Parent\\Child\\a.txt", 100);
        let file2 = make_file("b.txt", "C:\\Parent\\b.txt", 200);
        let all_files: Vec<&FileEntry> = vec![&file1, &file2];
        let sizes = calculate_directory_sizes(&all_files);
        assert_eq!(sizes.len(), 2);
        assert_eq!(*sizes.get("C:\\Parent\\Child").expect("Missing Child"), 100);
        assert_eq!(*sizes.get("C:\\Parent").expect("Missing Parent"), 200);
    }

    #[test]
    fn test_calculate_directory_sizes_zero_size_file() {
        let file = make_file("empty.txt", "C:\\Dir\\empty.txt", 0);
        let files: Vec<&FileEntry> = vec![&file];
        let sizes = calculate_directory_sizes(&files);
        assert_eq!(*sizes.get("C:\\Dir").expect("Missing directory"), 0);
    }

    #[test]
    fn test_calculate_directory_sizes_large_sizes() {
        let file1 = make_file("big1.bin", "C:\\Dir\\big1.bin", 5_000_000_000);
        let file2 = make_file("big2.bin", "C:\\Dir\\big2.bin", 5_000_000_000);
        let all_files: Vec<&FileEntry> = vec![&file1, &file2];
        let sizes = calculate_directory_sizes(&all_files);
        assert_eq!(*sizes.get("C:\\Dir").expect("Missing directory"), 10_000_000_000);
    }

    // ── count_files_under_directory ───────────────────────────────

    #[test]
    fn test_count_files_under_directory_empty() {
        let files: Vec<&FileEntry> = Vec::new();
        assert_eq!(count_files_under_directory(&files, "C:\\Dir"), 0);
    }

    #[test]
    fn test_count_files_under_directory_direct_children() {
        let file1 = make_file("a.txt", "C:\\Dir\\a.txt", 100);
        let file2 = make_file("b.txt", "C:\\Dir\\b.txt", 200);
        let file3 = make_file("c.txt", "D:\\Other\\c.txt", 300);
        let all_files: Vec<&FileEntry> = vec![&file1, &file2, &file3];
        assert_eq!(count_files_under_directory(&all_files, "C:\\Dir"), 2);
    }

    #[test]
    fn test_count_files_under_directory_nested_children() {
        let file1 = make_file("a.txt", "C:\\Dir\\sub1\\a.txt", 100);
        let file2 = make_file("b.txt", "C:\\Dir\\sub2\\b.txt", 200);
        let file3 = make_file("c.txt", "C:\\Dir\\c.txt", 300);
        let all_files: Vec<&FileEntry> = vec![&file1, &file2, &file3];
        assert_eq!(count_files_under_directory(&all_files, "C:\\Dir"), 3);
    }

    #[test]
    fn test_count_files_under_directory_no_match() {
        let file = make_file("a.txt", "C:\\Other\\a.txt", 100);
        let files: Vec<&FileEntry> = vec![&file];
        assert_eq!(count_files_under_directory(&files, "C:\\Dir"), 0);
    }

    #[test]
    fn test_count_files_under_directory_similar_prefix_no_false_match() {
        // "C:\DirExtra\a.txt" should NOT match "C:\Dir"
        let file = make_file("a.txt", "C:\\DirExtra\\a.txt", 100);
        let files: Vec<&FileEntry> = vec![&file];
        assert_eq!(count_files_under_directory(&files, "C:\\Dir"), 0);
    }

    #[test]
    fn test_count_files_under_directory_forward_slash() {
        let file = make_file("a.txt", "C:/Dir/a.txt", 100);
        let files: Vec<&FileEntry> = vec![&file];
        assert_eq!(count_files_under_directory(&files, "C:/Dir"), 1);
    }

    #[test]
    fn test_count_files_under_directory_deeply_nested() {
        let file = make_file("deep.txt", "C:\\Dir\\a\\b\\c\\d\\deep.txt", 100);
        let files: Vec<&FileEntry> = vec![&file];
        assert_eq!(count_files_under_directory(&files, "C:\\Dir"), 1);
    }

    // ── is_directory_empty_on_disk ────────────────────────────────

    #[test]
    fn test_is_directory_empty_on_disk_empty_dir() {
        let temp = tempdir().expect("Failed to create temp directory");
        let empty_dir = temp.path().join("empty");
        fs::create_dir(&empty_dir).expect("Failed to create directory");
        assert!(is_directory_empty_on_disk(&empty_dir.to_string_lossy()));
    }

    #[test]
    fn test_is_directory_empty_on_disk_nonempty_dir() {
        let temp = tempdir().expect("Failed to create temp directory");
        let dir = temp.path().join("nonempty");
        fs::create_dir(&dir).expect("Failed to create directory");
        fs::write(dir.join("file.txt"), "content").expect("Failed to write file");
        assert!(!is_directory_empty_on_disk(&dir.to_string_lossy()));
    }

    #[test]
    fn test_is_directory_empty_on_disk_nonexistent() {
        let temp = tempdir().expect("Failed to create temp directory");
        let missing_dir = temp.path().join("missing_subdir");
        assert!(!is_directory_empty_on_disk(&missing_dir.to_string_lossy()));
    }

    #[test]
    fn test_is_directory_empty_on_disk_with_subdirectory() {
        let temp = tempdir().expect("Failed to create temp directory");
        let dir = temp.path().join("has_subdir");
        fs::create_dir(&dir).expect("Failed to create directory");
        fs::create_dir(dir.join("subdir")).expect("Failed to create subdirectory");
        assert!(!is_directory_empty_on_disk(&dir.to_string_lossy()));
    }

    // ── check_path_accessible ─────────────────────────────────────

    #[test]
    fn test_check_path_accessible_existing_dir() {
        let temp = tempdir().expect("Failed to create temp directory");
        assert!(check_path_accessible(&temp.path().to_string_lossy()));
    }

    #[test]
    fn test_check_path_accessible_existing_file() {
        let temp = tempdir().expect("Failed to create temp directory");
        let file_path = temp.path().join("test.txt");
        fs::write(&file_path, "content").expect("Failed to write file");
        assert!(check_path_accessible(&file_path.to_string_lossy()));
    }

    #[test]
    fn test_check_path_accessible_nonexistent() {
        let temp = tempdir().expect("Failed to create temp directory");
        let missing_path = temp.path().join("missing_entry");
        assert!(!check_path_accessible(&missing_path.to_string_lossy()));
    }

    #[test]
    fn test_check_path_accessible_empty_string() {
        // Empty path should not be accessible
        assert!(!check_path_accessible(""));
    }

    // ── check_directory_exists ────────────────────────────────────

    #[test]
    fn test_check_directory_exists_real_dir() {
        let temp = tempdir().expect("Failed to create temp directory");
        assert!(check_directory_exists(&temp.path().to_string_lossy()));
    }

    #[test]
    fn test_check_directory_exists_file_not_dir() {
        let temp = tempdir().expect("Failed to create temp directory");
        let file_path = temp.path().join("file.txt");
        fs::write(&file_path, "content").expect("Failed to write file");
        // A file is not a directory
        assert!(!check_directory_exists(&file_path.to_string_lossy()));
    }

    #[test]
    fn test_check_directory_exists_nonexistent() {
        let temp = tempdir().expect("Failed to create temp directory");
        let missing_dir = temp.path().join("missing_subdir");
        assert!(!check_directory_exists(&missing_dir.to_string_lossy()));
    }

    #[test]
    fn test_check_directory_exists_subdirectory() {
        let temp = tempdir().expect("Failed to create temp directory");
        let sub = temp.path().join("subdir");
        fs::create_dir(&sub).expect("Failed to create subdirectory");
        assert!(check_directory_exists(&sub.to_string_lossy()));
    }

    #[test]
    fn test_check_directory_exists_empty_string() {
        assert!(!check_directory_exists(""));
    }
}
