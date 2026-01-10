use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use colored::Colorize;

use filefind::config::OutputFormat;
use filefind::{Database, format_size, print_bold_magenta, print_error};

use crate::VolumeSortBy;
use crate::config::{CliConfig, DisplayOptions};

const CHECK_TIMEOUT: Duration = Duration::from_millis(250);

/// List all indexed volumes.
pub fn list_volumes(database: &Database, sort_by: VolumeSortBy) -> Result<()> {
    let volumes = database.get_all_volumes()?;

    if volumes.is_empty() {
        println!("No volumes indexed yet");
        return Ok(());
    }

    // Collect volume data with stats for alignment calculations
    // (mount_and_label, volume_type, status_str, is_online, file_count, size_str, total_size_bytes)
    let mut volume_data: Vec<(String, String, String, bool, u64, String, u64)> = Vec::new();

    for volume in &volumes {
        let label = volume.label.as_deref().unwrap_or("");
        let mount_and_label = if label.is_empty() {
            volume.mount_point.clone()
        } else {
            format!("{} {}", volume.mount_point, label)
        };

        let (file_count, size_str, total_size) = if let Some(volume_id) = volume.id {
            let volume_stats = database.get_volume_stats(volume_id)?;
            (
                volume_stats.file_count,
                format_size(volume_stats.total_size),
                volume_stats.total_size,
            )
        } else {
            (0, String::from("N/A"), 0)
        };

        // Check if the volume is actually accessible
        let is_online = check_path_accessible(&volume.mount_point);

        volume_data.push((
            mount_and_label,
            volume.volume_type.to_string(),
            if is_online { "online" } else { "offline" }.to_string(),
            is_online,
            file_count,
            size_str,
            total_size,
        ));
    }

    // Sort by the specified field
    match sort_by {
        VolumeSortBy::Name => volume_data.sort_by(|a, b| a.0.cmp(&b.0)),
        VolumeSortBy::Size => volume_data.sort_by(|a, b| b.6.cmp(&a.6)),
        VolumeSortBy::Files => volume_data.sort_by(|a, b| b.4.cmp(&a.4)),
    }

    // Calculate maximum widths for alignment in a single pass
    let (max_mount_label_width, max_type_width, max_status_width, max_file_count_width, max_size_width) =
        volume_data.iter().fold(
            (0, 0, 0, 0, 0),
            |(mount, vtype, status, files, size),
             (mount_label, volume_type, status_str, _, file_count, size_str, _)| {
                (
                    mount.max(mount_label.len()),
                    vtype.max(volume_type.len() + 2), // +2 for brackets
                    status.max(status_str.len() + 2), // +2 for parentheses
                    files.max(file_count.to_string().len()),
                    size.max(size_str.len()),
                )
            },
        );

    // Print aligned output
    for (mount_label, volume_type, status_str, is_online, file_count, size_str, _) in volume_data {
        // Pad status string first, then colorize to avoid ANSI codes affecting width calculation
        let status_padded = format!("({status_str})");
        let status_padded = format!("{status_padded:<max_status_width$}");
        let status_colored = if is_online {
            status_padded.green()
        } else {
            status_padded.red()
        };

        let type_bracketed = format!("[{volume_type}]");

        println!(
            "{:<mount_width$}   {:<type_width$} {}   {:>file_width$} files   {:>size_width$}",
            mount_label.bold(),
            type_bracketed,
            status_colored,
            file_count,
            size_str,
            mount_width = max_mount_label_width,
            type_width = max_type_width,
            file_width = max_file_count_width,
            size_width = max_size_width,
        );
    }

    Ok(())
}

/// Run the search with the given configuration.
pub fn run_search(config: &CliConfig, database: &Database) -> Result<()> {
    if config.patterns.is_empty() {
        print_error!("No search pattern provided");
        bail!("Usage: filefind <pattern> [patterns...]\n       filefind stats\n       filefind volumes");
    }

    let start_time = Instant::now();

    // Search with all patterns and combine results
    let results = if config.match_all {
        // AND mode: find results that match ALL patterns
        search_all_patterns(config, database)?
    } else {
        // OR mode (default): find results that match ANY pattern
        search_any_pattern(config, database)?
    };

    let search_duration = start_time.elapsed();

    // Filter results by drive
    let mut results: Vec<_> = filter_by_drives(results, &config.drives);

    results.sort_unstable_by(|a, b| a.full_path.cmp(&b.full_path));

    // Separate directories and files
    let (directories, files): (Vec<_>, Vec<_>) = results.iter().partition(|e| e.is_directory);

    // Collect patterns to highlight (only simple patterns, not regex or glob)
    let highlight_patterns: Vec<&str> = if config.regex {
        Vec::new()
    } else {
        config
            .patterns
            .iter()
            .filter(|p| !p.contains('*') && !p.contains('?'))
            .map(String::as_str)
            .collect()
    };

    // Display results based on mode
    let display_options = DisplayOptions {
        directories_only: config.dirs_only,
        files_only: config.files_only,
        files_per_dir: config.files_per_dir,
    };

    match config.output_format {
        OutputFormat::Grouped => display_grouped_output(&directories, &files, &display_options, &highlight_patterns),
        OutputFormat::Simple => display_simple(&directories, &files, &display_options, &highlight_patterns),
    }

    // Show search stats if verbose
    if config.verbose {
        let total_results = directories.len() + files.len();
        eprintln!(
            "\n{} results ({} directories, {} files) in {:.2}ms",
            total_results,
            directories.len(),
            files.len(),
            search_duration.as_secs_f64() * 1000.0
        );
    }

    Ok(())
}

/// Show index statistics.
pub fn show_stats(database: &Database) -> Result<()> {
    let stats = database.get_stats()?;

    println!("Volumes:     {}", stats.volume_count);
    println!("Files:       {}", stats.total_files);
    println!("Directories: {}", stats.total_directories);
    println!("Total size:  {}", format_size(stats.total_size));

    Ok(())
}

/// Filter results to only include entries on specified drives.
fn filter_by_drives(results: Vec<filefind::types::FileEntry>, drives: &[String]) -> Vec<filefind::types::FileEntry> {
    if drives.is_empty() {
        return results;
    }

    results
        .into_iter()
        .filter(|entry| {
            let entry_drive = entry.full_path.chars().next().map(|c| c.to_ascii_uppercase());
            entry_drive.is_some_and(|drive_char| {
                drives
                    .iter()
                    .any(|d| d.chars().next().is_some_and(|c| c.to_ascii_uppercase() == drive_char))
            })
        })
        .collect()
}

/// Search for results matching ANY pattern (OR mode).
fn search_any_pattern(config: &CliConfig, database: &Database) -> Result<Vec<filefind::types::FileEntry>> {
    let mut seen_paths: HashSet<String> = HashSet::new();
    let mut results = Vec::new();

    for pattern in &config.patterns {
        let pattern_results = if config.regex {
            database.search_by_regex(pattern, config.case_sensitive, usize::MAX)?
        } else if pattern.contains('*') || pattern.contains('?') {
            database.search_by_glob(pattern, usize::MAX)?
        } else {
            database.search_by_name(pattern, usize::MAX)?
        };

        // Deduplicate results across patterns
        for entry in pattern_results {
            if seen_paths.insert(entry.full_path.clone()) {
                results.push(entry);
            }
        }
    }

    Ok(results)
}

/// Search for results matching ALL patterns (AND mode).
///
/// Uses SQL-level AND for efficient single-query search.
fn search_all_patterns(config: &CliConfig, database: &Database) -> Result<Vec<filefind::types::FileEntry>> {
    if config.patterns.is_empty() {
        return Ok(Vec::new());
    }

    // Check if all patterns are the same type (all glob or all plain)
    let all_glob = config.patterns.iter().all(|p| p.contains('*') || p.contains('?'));
    let any_glob = config.patterns.iter().any(|p| p.contains('*') || p.contains('?'));

    if config.regex {
        // All regex patterns - use SQL-level AND
        database.search_by_regexes_all(&config.patterns, config.case_sensitive, usize::MAX)
    } else if all_glob {
        // All glob patterns - use SQL-level AND
        database.search_by_globs_all(&config.patterns, usize::MAX)
    } else if !any_glob {
        // All plain name patterns - use SQL-level AND
        database.search_by_names_all(&config.patterns, usize::MAX)
    } else {
        // Mixed glob and plain patterns - fall back to multiple queries with intersection
        search_all_patterns_mixed(config, database)
    }
}

/// Search for results matching ALL patterns when patterns are mixed (some glob, some plain).
///
/// Falls back to multiple queries with intersection.
fn search_all_patterns_mixed(config: &CliConfig, database: &Database) -> Result<Vec<filefind::types::FileEntry>> {
    let first_pattern = &config.patterns[0];
    let mut results: Vec<filefind::types::FileEntry> = if first_pattern.contains('*') || first_pattern.contains('?') {
        database.search_by_glob(first_pattern, usize::MAX)?
    } else {
        database.search_by_name(first_pattern, usize::MAX)?
    };

    // For each additional pattern, filter results to only those that also match
    for pattern in config.patterns.iter().skip(1) {
        let pattern_results: HashSet<String> = if pattern.contains('*') || pattern.contains('?') {
            database.search_by_glob(pattern, usize::MAX)?
        } else {
            database.search_by_name(pattern, usize::MAX)?
        }
        .into_iter()
        .map(|entry| entry.full_path)
        .collect();

        // Keep only results that also match this pattern
        results.retain(|entry| pattern_results.contains(&entry.full_path));

        // Early exit if no results remain
        if results.is_empty() {
            break;
        }
    }

    Ok(results)
}

/// Highlight multiple patterns within text (case-insensitive).
///
/// Finds all matches for all patterns, merges overlapping ranges, and highlights them.
fn highlight_match(text: &str, patterns: &[&str]) -> String {
    if patterns.is_empty() {
        return text.to_string();
    }

    let text_lower = text.to_lowercase();

    // Collect all match ranges (start, end) for all patterns
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for pattern in patterns {
        let pattern_lower = pattern.to_lowercase();
        for (start, matched) in text_lower.match_indices(&pattern_lower) {
            ranges.push((start, start + matched.len()));
        }
    }

    if ranges.is_empty() {
        return text.to_string();
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
    result
}

/// Display results in grouped format (files grouped by directory).
fn display_grouped_output(
    directories: &[&filefind::types::FileEntry],
    files: &[&filefind::types::FileEntry],
    options: &DisplayOptions,
    highlight_patterns: &[&str],
) {
    if options.files_only {
        // Files only mode: show full paths
        for file in files {
            println!("{}", highlight_match(&file.full_path, highlight_patterns));
        }
    } else if options.directories_only {
        // Dirs only mode: show full path with file count
        for directory in directories {
            let file_count = count_files_in_directory(files, &directory.full_path);
            if file_count > 0 {
                println!(
                    "{} ({} files)",
                    highlight_match(&directory.full_path, highlight_patterns),
                    file_count
                );
            } else {
                println!("{}", highlight_match(&directory.full_path, highlight_patterns));
            }
        }
    } else {
        // Normal mode: group files under directories
        display_grouped(directories, files, options.files_per_dir, highlight_patterns);
    }
}

/// Display results grouped by directory.
fn display_grouped(
    directories: &[&filefind::types::FileEntry],
    files: &[&filefind::types::FileEntry],
    files_per_dir: usize,
    highlight_patterns: &[&str],
) {
    // Group files by their parent directory
    let mut files_by_dir: HashMap<String, Vec<&filefind::types::FileEntry>> = HashMap::new();
    for file in files {
        let parent = PathBuf::from(&file.full_path)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        files_by_dir.entry(parent).or_default().push(file);
    }

    // First, show matched directories with their files
    for directory in directories {
        print_bold_magenta(&directory.full_path);
        if let Some(dir_files) = files_by_dir.get(&directory.full_path) {
            let total_files = dir_files.len();
            for file in dir_files.iter().take(files_per_dir) {
                println!("  {}", highlight_match(&file.name, highlight_patterns));
            }
            if total_files > files_per_dir {
                println!("  {} ({} files)", "...".dimmed(), total_files - files_per_dir);
            }
        }
        println!();
    }

    // Then show files in directories that weren't matched
    let matched_dirs: HashSet<_> = directories.iter().map(|d| &d.full_path).collect();

    let mut other_dirs: Vec<_> = files_by_dir.keys().filter(|dir| !matched_dirs.contains(*dir)).collect();
    other_dirs.sort();

    for dir_path in other_dirs {
        if let Some(dir_files) = files_by_dir.get(dir_path) {
            print_bold_magenta(dir_path);
            let total_files = dir_files.len();
            for file in dir_files.iter().take(files_per_dir) {
                println!("  {}", highlight_match(&file.name, highlight_patterns));
            }
            if total_files > files_per_dir {
                println!("  {} ({} files)", "...".dimmed(), total_files - files_per_dir);
            }
            println!();
        }
    }
}

/// Count files that are directly inside a directory.
fn count_files_in_directory(files: &[&filefind::types::FileEntry], dir_path: &str) -> usize {
    files
        .iter()
        .filter(|f| {
            PathBuf::from(&f.full_path)
                .parent()
                .is_some_and(|p| p.to_string_lossy() == dir_path)
        })
        .count()
}

/// Display results in simple list format
fn display_simple(
    directories: &[&filefind::types::FileEntry],
    files: &[&filefind::types::FileEntry],
    options: &DisplayOptions,
    highlight_patterns: &[&str],
) {
    if options.files_only {
        for file in files {
            println!("{}", highlight_match(&file.full_path, highlight_patterns));
        }
    } else if options.directories_only {
        for directory in directories {
            println!("{}", highlight_match(&directory.full_path, highlight_patterns));
        }
    } else {
        // Combine all entries and sort by path
        let mut all_entries: Vec<_> = directories.iter().chain(files.iter()).collect();
        all_entries.sort_by(|a, b| a.full_path.cmp(&b.full_path));

        for entry in all_entries {
            if entry.is_directory {
                println!("{}", entry.full_path.cyan());
            } else {
                println!("{}", highlight_match(&entry.full_path, highlight_patterns));
            }
        }
    }
}

/// Check if a path is accessible with a timeout.
/// Returns false if the path doesn't exist or if the check takes longer than the timeout time.
fn check_path_accessible(path: &str) -> bool {
    let path = path.to_string();
    let (sender, receiver) = mpsc::channel();

    thread::spawn(move || {
        let exists = Path::new(&path).exists();
        let _ = sender.send(exists);
    });

    receiver.recv_timeout(CHECK_TIMEOUT).unwrap_or(false)
}
