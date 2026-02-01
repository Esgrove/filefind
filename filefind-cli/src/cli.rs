use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Result, bail};
use colored::Colorize;

use filefind::config::OutputFormat;
use filefind::types::FileEntry;
use filefind::{Database, IndexedVolume, format_size, print_bold_magenta, print_bold_yellow, print_error};

use crate::config::CliConfig;
use crate::{SortBy, VolumeSortBy, utils};

/// Data for displaying volume information.
struct VolumeDisplayData {
    /// Mount point and label combined (e.g., "C: Windows").
    mount_label: String,
    /// Volume type (e.g., "NTFS", "Network").
    volume_type: String,
    /// Status string ("online" or "offline").
    status: String,
    /// Whether the volume is currently accessible.
    is_online: bool,
    /// Number of indexed files on this volume.
    file_count: u64,
    /// Human-readable size string (e.g., "1.5 GB").
    size_formatted: String,
    /// Total size in bytes for sorting.
    total_size_bytes: u64,
}

/// List all indexed volumes.
pub fn list_volumes(database: &Database, sort_by: VolumeSortBy) -> Result<()> {
    let volumes = database.get_all_volumes()?;

    if volumes.is_empty() {
        println!("No volumes indexed yet");
        return Ok(());
    }

    let mut volume_data = get_volume_data(database, &volumes)?;

    // Sort by the specified field
    match sort_by {
        VolumeSortBy::Name => volume_data.sort_by(|a, b| a.mount_label.cmp(&b.mount_label)),
        VolumeSortBy::Size => volume_data.sort_by(|a, b| b.total_size_bytes.cmp(&a.total_size_bytes)),
        VolumeSortBy::Files => volume_data.sort_by(|a, b| b.file_count.cmp(&a.file_count)),
    }

    // Calculate maximum widths for alignment in a single pass
    let (max_mount_label_width, max_type_width, max_status_width, max_file_count_width, max_size_width) = volume_data
        .iter()
        .fold((0, 0, 0, 0, 0), |(mount, vtype, status, files, size), vol| {
            (
                mount.max(vol.mount_label.len()),
                vtype.max(vol.volume_type.len() + 2), // +2 for brackets
                status.max(vol.status.len() + 2),     // +2 for parentheses
                files.max(vol.file_count.to_string().len()),
                size.max(vol.size_formatted.len()),
            )
        });

    // Print aligned output
    for vol in volume_data {
        // Pad status string first, then colorize to avoid ANSI codes affecting width calculation
        let status_padded = format!("({})", vol.status);
        let status_padded = format!("{status_padded:<max_status_width$}");
        let status_colored = if vol.is_online {
            status_padded.green()
        } else {
            status_padded.red()
        };

        let type_bracketed = format!("[{}]", vol.volume_type);

        println!(
            "{:<mount_width$}   {:<type_width$} {}   {:>file_width$} files   {:>size_width$}",
            vol.mount_label.bold(),
            type_bracketed,
            status_colored,
            vol.file_count,
            vol.size_formatted,
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

    match config.sort_by {
        SortBy::Name => results.sort_unstable_by(|a, b| a.full_path.cmp(&b.full_path)),
        SortBy::Size => results.sort_unstable_by(|a, b| b.size.cmp(&a.size)),
    }

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

    match config.output_format {
        OutputFormat::Grouped => display_grouped_output(&directories, &files, config, &highlight_patterns),
        OutputFormat::List => display_list(&directories, &files, config, &highlight_patterns),
        OutputFormat::Info => display_info(&directories, &files, config, &highlight_patterns),
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

/// Display results in grouped format (files grouped by directory).
fn display_grouped_output(
    directories: &[&FileEntry],
    files: &[&FileEntry],
    config: &CliConfig,
    highlight_patterns: &[&str],
) {
    if config.files_only {
        // Files only mode: show full paths
        for file in files {
            println!("{}", utils::highlight_match(&file.full_path, highlight_patterns));
        }
    } else if config.directories_only {
        // Dirs only mode: show full path with file count
        for directory in directories {
            let file_count = utils::count_files_under_directory(files, &directory.full_path);
            if file_count > 0 {
                println!(
                    "{} ({} files)",
                    utils::highlight_match(&directory.full_path, highlight_patterns),
                    file_count
                );
            } else if utils::is_directory_empty_on_disk(&directory.full_path) {
                // Truly empty folder on disk: print in bold yellow (no highlight to avoid mixed colors)
                print_bold_yellow!("{} (empty)", &directory.full_path);
            } else {
                // Directory has files but none match the search: print in magenta (no highlight to avoid mixed colors)
                print_bold_magenta!("{}", &directory.full_path);
            }
        }
    } else {
        // Normal mode: group files under directories
        display_grouped(directories, files, config, highlight_patterns);
    }
}

/// Display results grouped by directory.
fn display_grouped(directories: &[&FileEntry], files: &[&FileEntry], config: &CliConfig, highlight_patterns: &[&str]) {
    // Group files by their parent directory
    let mut files_by_dir: HashMap<String, Vec<&FileEntry>> = HashMap::new();
    for file in files {
        let parent = PathBuf::from(&file.full_path)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        files_by_dir.entry(parent).or_default().push(file);
    }

    // First, show matched directories with their files
    for directory in directories {
        let file_count = utils::count_files_under_directory(files, &directory.full_path);
        if let Some(dir_files) = files_by_dir.get(&directory.full_path) {
            print_bold_magenta!("{} ({} files)", &directory.full_path, file_count);
            let total_files = dir_files.len();
            for file in dir_files.iter().take(config.files_per_dir) {
                println!("  {}", utils::highlight_match(&file.name, highlight_patterns));
            }
            if total_files > config.files_per_dir {
                println!("  {} ({} files)", "...".dimmed(), total_files - config.files_per_dir);
            }
        } else if utils::is_directory_empty_on_disk(&directory.full_path) {
            // Truly empty folder on disk: print in bold yellow
            print_bold_yellow!("{} (empty)", &directory.full_path);
        } else {
            // Directory has files but none match the search: print in magenta
            print_bold_magenta(&directory.full_path);
        }
        println!();
    }

    // Then show files in directories that weren't matched
    let matched_dirs: HashSet<_> = directories.iter().map(|d| &d.full_path).collect();

    let mut other_dirs: Vec<_> = files_by_dir.keys().filter(|dir| !matched_dirs.contains(*dir)).collect();
    other_dirs.sort();

    for dir_path in other_dirs {
        if let Some(dir_files) = files_by_dir.get(dir_path) {
            let file_count = dir_files.len();
            print_bold_magenta!("{} ({} files)", dir_path, file_count);
            for file in dir_files.iter().take(config.files_per_dir) {
                println!("  {}", utils::highlight_match(&file.name, highlight_patterns));
            }
            if file_count > config.files_per_dir {
                println!("  {} ({} files)", "...".dimmed(), file_count - config.files_per_dir);
            }
            println!();
        }
    }
}

/// Display results in list format
fn display_list(directories: &[&FileEntry], files: &[&FileEntry], config: &CliConfig, highlight_patterns: &[&str]) {
    if config.files_only {
        for file in files {
            println!("{}", utils::highlight_match(&file.full_path, highlight_patterns));
        }
    } else if config.directories_only {
        for directory in directories {
            if utils::is_directory_empty_on_disk(&directory.full_path) {
                // Empty folder: print in yellow (no highlight to avoid mixed colors)
                println!("{}", directory.full_path.yellow());
            } else {
                println!("{}", utils::highlight_match(&directory.full_path, highlight_patterns));
            }
        }
    } else {
        // Show directories first, then files (both already sorted by caller)
        for directory in directories {
            if utils::is_directory_empty_on_disk(&directory.full_path) {
                println!("{}", directory.full_path.yellow());
            } else {
                println!("{}", directory.full_path.cyan());
            }
        }
        for file in files {
            println!("{}", utils::highlight_match(&file.full_path, highlight_patterns));
        }
    }
}

/// Display results in info format with size.
fn display_info(directories: &[&FileEntry], files: &[&FileEntry], config: &CliConfig, highlight_patterns: &[&str]) {
    // Print header if verbose
    if config.verbose {
        println!("{:>10}{:>8}  PATH", "SIZE", "FILES");
    }

    // Show directories first, then files (both already sorted by caller)
    if !config.files_only {
        // Build a map of directory path -> total size of files under it
        let dir_sizes = utils::calculate_directory_sizes(files);

        // Sort directories by size if requested
        let mut sorted_dirs: Vec<_> = directories.to_vec();
        if matches!(config.sort_by, SortBy::Size) {
            sorted_dirs.sort_by(|a, b| {
                let size_a = dir_sizes.get(&a.full_path).copied().unwrap_or(0);
                let size_b = dir_sizes.get(&b.full_path).copied().unwrap_or(0);
                size_b.cmp(&size_a)
            });
        }

        for directory in sorted_dirs {
            let size = dir_sizes.get(&directory.full_path).copied();
            let file_count = utils::count_files_under_directory(files, &directory.full_path);
            let is_empty = utils::is_directory_empty_on_disk(&directory.full_path);
            print_entry_info(directory, size, Some(file_count), highlight_patterns, is_empty);
        }
    }
    if !config.directories_only {
        for file in files {
            print_entry_info(file, None, None, highlight_patterns, false);
        }
    }
}

/// Collect volume data with stats for alignment calculations
fn get_volume_data(database: &Database, volumes: &[IndexedVolume]) -> Result<Vec<VolumeDisplayData>> {
    volumes
        .iter()
        .map(|volume| {
            let label = volume.label.as_deref().unwrap_or("");
            let mount_label = if label.is_empty() {
                volume.mount_point.clone()
            } else {
                format!("{} {}", volume.mount_point, label)
            };

            let (file_count, size_formatted, total_size_bytes) = if let Some(volume_id) = volume.id {
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
            let is_online = utils::check_path_accessible(&volume.mount_point);

            Ok(VolumeDisplayData {
                mount_label,
                volume_type: volume.volume_type.to_string(),
                status: if is_online { "online" } else { "offline" }.to_string(),
                is_online,
                file_count,
                size_formatted,
                total_size_bytes,
            })
        })
        .collect()
}

/// Filter results to only include entries on specified drives.
fn filter_by_drives(results: Vec<FileEntry>, drives: &[String]) -> Vec<FileEntry> {
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

/// Print a single entry with size info.
///
/// For directories, `calculated_size` can provide the sum of contained files,
/// and `file_count` shows the number of matching files under the directory.
/// If `is_empty` is true, the directory path is printed in yellow.
fn print_entry_info(
    entry: &FileEntry,
    calculated_size: Option<u64>,
    file_count: Option<usize>,
    highlight_patterns: &[&str],
    is_empty: bool,
) {
    let size_str = if entry.is_directory {
        calculated_size.map_or_else(|| format!("{:>10}", "-"), |size| format!("{:>10}", format_size(size)))
    } else {
        format!("{:>10}", format_size(entry.size))
    };

    let count_str = file_count.map_or_else(String::new, |count| format!("{count:>8}"));

    let path_display = if entry.is_directory {
        if is_empty {
            entry.full_path.yellow().to_string()
        } else {
            entry.full_path.cyan().to_string()
        }
    } else {
        utils::highlight_match(&entry.full_path, highlight_patterns)
    };

    println!("{size_str}{count_str}  {path_display}");
}

/// Search for results matching ANY pattern (OR mode).
fn search_any_pattern(config: &CliConfig, database: &Database) -> Result<Vec<FileEntry>> {
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
fn search_all_patterns(config: &CliConfig, database: &Database) -> Result<Vec<FileEntry>> {
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
fn search_all_patterns_mixed(config: &CliConfig, database: &Database) -> Result<Vec<FileEntry>> {
    let first_pattern = &config.patterns[0];
    let mut results: Vec<FileEntry> = if first_pattern.contains('*') || first_pattern.contains('?') {
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
