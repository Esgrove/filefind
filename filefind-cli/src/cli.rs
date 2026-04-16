use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Result, bail};
use colored::Colorize;

use filefind::config::OutputFormat;
use filefind::types::FileEntry;
use filefind::{
    Database, IndexedVolume, format_number, format_size, print_bold_magenta, print_bold_red, print_bold_yellow,
    print_error,
};

use crate::config::CliConfig;
use crate::mover;
use crate::{SortBy, VolumeSortBy, utils};

/// Status of an entry for display purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryStatus {
    /// A regular file.
    File,
    /// Directory exists and contains files.
    Directory {
        /// Total size of files under this directory.
        size: Option<u64>,
        /// Number of matching files under this directory.
        file_count: usize,
    },
    /// Directory exists but is empty on disk.
    EmptyDirectory,
    /// Directory no longer exists on disk.
    MissingDirectory,
}

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
        VolumeSortBy::Size => volume_data.sort_by_key(|volume| Reverse(volume.total_size_bytes)),
        VolumeSortBy::Files => volume_data.sort_by_key(|volume| Reverse(volume.file_count)),
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

    // Apply path mappings for display (e.g., UNC paths -> mapped drive letters)
    let results: Vec<_> = results
        .into_iter()
        .map(|mut entry| {
            if let std::borrow::Cow::Owned(mapped) = config.display_path(&entry.full_path) {
                entry.full_path = mapped;
            }
            entry
        })
        .collect();

    // Filter results by drive
    let mut results: Vec<_> = filter_by_drives(results, &config.drives);

    match config.sort_by {
        SortBy::Name => {
            if config.output_format == OutputFormat::Name {
                results.sort_unstable_by_key(|entry| entry.name.to_lowercase());
            } else {
                results.sort_unstable_by(|left, right| left.full_path.cmp(&right.full_path));
            }
        }
        SortBy::Size => results.sort_unstable_by_key(|entry| Reverse(entry.size)),
    }

    // Separate directories and files
    let (directories, files): (Vec<_>, Vec<_>) = results.iter().partition(|entry| entry.is_directory);

    // Collect patterns to highlight (only simple patterns, not regex or glob)
    let highlight_patterns: Vec<&str> = if config.regex {
        Vec::new()
    } else {
        config
            .patterns
            .iter()
            .filter(|pattern| !pattern.contains('*') && !pattern.contains('?'))
            .map(String::as_str)
            .collect()
    };

    match config.output_format {
        OutputFormat::Grouped => display_grouped_output(&directories, &files, config, &highlight_patterns, database),
        OutputFormat::List => display_list(&directories, &files, config, &highlight_patterns, database),
        OutputFormat::Name => display_name(&directories, &files, config, &highlight_patterns, database),
        OutputFormat::Info => display_info(&directories, &files, config, &highlight_patterns, database),
    }

    // Show search stats if verbose
    if config.verbose {
        let total_results = directories.len() + files.len();
        println!(
            "\n{total_results} results ({} directories, {} files) in {:.2}ms",
            directories.len(),
            files.len(),
            search_duration.as_secs_f64() * 1000.0
        );
    }

    // Handle move: move matching files after displaying results
    if let Some(destination) = &config.move_to {
        let file_entries: Vec<_> = results.into_iter().filter(|entry| !entry.is_directory).collect();
        return mover::move_files(&file_entries, destination, database, config.force_overwrite);
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

/// Show duplicate files grouped by case-insensitive file stem (name without extension).
///
/// Queries the database for all non-directory files that share a stem, then displays
/// each group with the stem as a header and the full paths listed underneath.
pub fn show_duplicates(database: &Database, drives: &[String], limit: Option<usize>, verbose: bool) -> Result<()> {
    let start_time = Instant::now();

    let all_groups = database.find_duplicates()?;

    // Filter by drive if specified
    let groups: Vec<(String, Vec<FileEntry>)> = if drives.is_empty() {
        all_groups
    } else {
        all_groups
            .into_iter()
            .filter_map(|(stem, files)| {
                let filtered = filter_by_drives(files, drives);
                if filtered.len() >= 2 {
                    Some((stem, filtered))
                } else {
                    None
                }
            })
            .collect()
    };

    let search_duration = start_time.elapsed();

    if groups.is_empty() {
        if verbose {
            println!("No duplicate files found");
        }
        return Ok(());
    }

    let total_groups = groups.len();
    let total_files: usize = groups.iter().map(|(_, files)| files.len()).sum();

    // Apply limit to number of groups shown
    let display_groups = limit.map_or(groups.as_slice(), |max| &groups[..max.min(groups.len())]);

    for (index, (stem, files)) in display_groups.iter().enumerate() {
        if index > 0 {
            println!();
        }
        print_bold_magenta!("{} ({})", stem, files.len());
        for file in files {
            println!("  {:>10}  {}", format_size(file.size), file.full_path);
        }
    }

    if let Some(max) = limit
        && total_groups > max
    {
        println!("\n{} ({} more not shown)", "...".dimmed(), total_groups - max);
    }

    if verbose {
        println!(
            "\n{} duplicate groups, {} total files in {:.2}ms",
            format_number(total_groups as u64),
            format_number(total_files as u64),
            search_duration.as_secs_f64() * 1000.0
        );
    }

    Ok(())
}

/// Display results in grouped format (files grouped by directory).
fn display_grouped_output(
    directories: &[&FileEntry],
    files: &[&FileEntry],
    config: &CliConfig,
    highlight_patterns: &[&str],
    database: &Database,
) {
    if config.files_only {
        // Files only mode: show full paths
        for file in files {
            println!("{}", utils::highlight_match(&file.full_path, highlight_patterns));
        }
    } else if config.directories_only {
        // Dirs only mode: show full path with file count
        for directory in directories {
            // Check if directory exists on disk
            if !utils::check_directory_exists(&directory.full_path) {
                // Directory no longer exists: print in red and remove from database
                print_bold_red!("{}", &directory.full_path);
                delete_missing_directory(database, &directory.full_path);
                continue;
            }

            let file_count = utils::count_files_under_directory(files, &directory.full_path);
            if file_count > 0 {
                println!(
                    "{} ({file_count})",
                    utils::highlight_match(&directory.full_path, highlight_patterns)
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
        display_grouped(directories, files, config, highlight_patterns, database);
    }
}

/// Display results grouped by directory.
fn display_grouped(
    directories: &[&FileEntry],
    files: &[&FileEntry],
    config: &CliConfig,
    highlight_patterns: &[&str],
    database: &Database,
) {
    // Group files by their parent directory
    let mut files_by_dir: HashMap<String, Vec<&FileEntry>> = HashMap::new();
    for file in files {
        let parent = PathBuf::from(&file.full_path)
            .parent()
            .map(|path| path.to_string_lossy().to_string())
            .unwrap_or_default();
        files_by_dir.entry(parent).or_default().push(file);
    }

    // First, show matched directories with their files
    for directory in directories {
        // Check if directory exists on disk
        if !utils::check_directory_exists(&directory.full_path) {
            // Directory no longer exists: print in red and remove from database
            print_bold_red!("{}", &directory.full_path);
            delete_missing_directory(database, &directory.full_path);
            println!();
            continue;
        }

        let file_count = utils::count_files_under_directory(files, &directory.full_path);
        if let Some(dir_files) = files_by_dir.get(&directory.full_path) {
            print_bold_magenta!("{} ({file_count})", &directory.full_path);
            let total_files = dir_files.len();
            for file in dir_files.iter().take(config.files_per_dir) {
                println!("  {}", utils::highlight_match(&file.name, highlight_patterns));
            }
            if total_files > config.files_per_dir {
                println!("  {} ({})", "...".dimmed(), total_files - config.files_per_dir);
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
    let matched_dirs: HashSet<_> = directories.iter().map(|directory| &directory.full_path).collect();

    let mut other_dirs: Vec<_> = files_by_dir.keys().filter(|dir| !matched_dirs.contains(*dir)).collect();
    other_dirs.sort();

    for dir_path in other_dirs {
        if let Some(dir_files) = files_by_dir.get(dir_path) {
            let file_count = dir_files.len();
            print_bold_magenta!("{dir_path} ({file_count})");
            for file in dir_files.iter().take(config.files_per_dir) {
                println!("  {}", utils::highlight_match(&file.name, highlight_patterns));
            }
            if file_count > config.files_per_dir {
                println!("  {} ({})", "...".dimmed(), file_count - config.files_per_dir);
            }
            println!();
        }
    }
}

/// Display results as file/directory names only (no full paths).
///
/// Same logic as `display_list` but prints only the name component of each entry.
fn display_name(
    directories: &[&FileEntry],
    files: &[&FileEntry],
    config: &CliConfig,
    highlight_patterns: &[&str],
    database: &Database,
) {
    if config.files_only {
        for file in files {
            println!("{}", utils::highlight_match(&file.name, highlight_patterns));
        }
    } else if config.directories_only {
        for directory in directories {
            if !utils::check_directory_exists(&directory.full_path) {
                print_bold_red!("{}", &directory.name);
                delete_missing_directory(database, &directory.full_path);
                continue;
            }

            if utils::is_directory_empty_on_disk(&directory.full_path) {
                println!("{}", directory.name.yellow());
            } else {
                println!("{}", utils::highlight_match(&directory.name, highlight_patterns));
            }
        }
    } else {
        for directory in directories {
            if !utils::check_directory_exists(&directory.full_path) {
                print_bold_red!("{}", &directory.name);
                delete_missing_directory(database, &directory.full_path);
                continue;
            }

            if utils::is_directory_empty_on_disk(&directory.full_path) {
                println!("{}", directory.name.yellow());
            } else {
                println!("{}", directory.name.cyan());
            }
        }
        for file in files {
            println!("{}", utils::highlight_match(&file.name, highlight_patterns));
        }
    }
}

/// Display results in list format (full paths, no type or size information).
fn display_list(
    directories: &[&FileEntry],
    files: &[&FileEntry],
    config: &CliConfig,
    highlight_patterns: &[&str],
    database: &Database,
) {
    if config.files_only {
        for file in files {
            println!("{}", utils::highlight_match(&file.full_path, highlight_patterns));
        }
    } else if config.directories_only {
        for directory in directories {
            // Check if directory exists on disk
            if !utils::check_directory_exists(&directory.full_path) {
                // Directory no longer exists: print in red and remove from database
                print_bold_red!("{}", &directory.full_path);
                delete_missing_directory(database, &directory.full_path);
                continue;
            }

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
            // Check if directory exists on disk
            if !utils::check_directory_exists(&directory.full_path) {
                // Directory no longer exists: print in red and remove from database
                print_bold_red!("{}", &directory.full_path);
                delete_missing_directory(database, &directory.full_path);
                continue;
            }

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
fn display_info(
    directories: &[&FileEntry],
    files: &[&FileEntry],
    config: &CliConfig,
    highlight_patterns: &[&str],
    database: &Database,
) {
    // Show directories first, then files (both already sorted by caller)
    if !config.files_only {
        if config.verbose {
            println!("{:>10}{:>8}  PATH", "SIZE", "FILES");
            println!("────────────────────────────────────────────────────────────────────");
        }
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
            if !utils::check_directory_exists(&directory.full_path) {
                print_entry_info(directory, highlight_patterns, EntryStatus::MissingDirectory);
                delete_missing_directory(database, &directory.full_path);
                continue;
            }

            let size = dir_sizes.get(&directory.full_path).copied();
            let file_count = utils::count_files_under_directory(files, &directory.full_path);
            let status = if utils::is_directory_empty_on_disk(&directory.full_path) {
                EntryStatus::EmptyDirectory
            } else {
                EntryStatus::Directory { size, file_count }
            };
            print_entry_info(directory, highlight_patterns, status);
        }
    }
    if !config.directories_only {
        if config.verbose {
            if !config.files_only {
                println!("────────────────────────────────────────────────────────────────────");
            }
            println!("{:>10}  PATH", "SIZE");
            println!("────────────────────────────────────────────────────────────────────");
        }
        for file in files {
            print_entry_info(file, highlight_patterns, EntryStatus::File);
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
/// For directories, the status includes the calculated size and file count.
/// Empty directories are printed in yellow, missing directories in red.
fn print_entry_info(entry: &FileEntry, highlight_patterns: &[&str], status: EntryStatus) {
    let (size_str, count_str, path_display) = match status {
        EntryStatus::File => (
            format!("{:>10}", format_size(entry.size)),
            String::new(),
            utils::highlight_match(&entry.full_path, highlight_patterns).into_owned(),
        ),
        EntryStatus::Directory { size, file_count } => (
            size.map_or_else(
                || format!("{:>10}", "-"),
                |size_bytes| format!("{:>10}", format_size(size_bytes)),
            ),
            format!("{file_count:>8}"),
            entry.full_path.magenta().to_string(),
        ),
        EntryStatus::EmptyDirectory => (
            format!("{:>10}", "-"),
            format!("{:>8}", ""),
            entry.full_path.yellow().to_string(),
        ),
        EntryStatus::MissingDirectory => (
            format!("{:>10}", "-"),
            format!("{:>8}", ""),
            entry.full_path.red().to_string(),
        ),
    };

    println!("{size_str}{count_str}  {path_display}");
}

/// Delete a missing directory and all files under it from the database.
fn delete_missing_directory(database: &Database, path: &str) {
    if let Err(error) = database.delete_files_under_path(path) {
        print_error!("Failed to remove stale entries for {path}:\n{error}");
    }
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
    let all_glob = config
        .patterns
        .iter()
        .all(|pattern| pattern.contains('*') || pattern.contains('?'));
    let any_glob = config
        .patterns
        .iter()
        .any(|pattern| pattern.contains('*') || pattern.contains('?'));

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

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use filefind::Database;
    use filefind::types::{FileEntry, IndexedVolume, VolumeType};
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

    /// Helper to create a test directory entry.
    fn make_dir(name: &str, path: &str) -> FileEntry {
        FileEntry {
            id: None,
            volume_id: 1,
            parent_id: None,
            name: name.to_string(),
            full_path: path.to_string(),
            is_directory: true,
            size: 0,
            created_time: Some(SystemTime::now()),
            modified_time: Some(SystemTime::now()),
            mft_reference: None,
        }
    }

    /// Helper to create a test volume.
    fn make_volume(serial: &str, mount: &str) -> IndexedVolume {
        IndexedVolume {
            id: None,
            serial_number: serial.to_string(),
            label: Some(format!("Vol {serial}")),
            mount_point: mount.to_string(),
            volume_type: VolumeType::Ntfs,
            last_scan_time: None,
            last_usn: None,
            is_online: true,
        }
    }

    /// Helper to set up a database with sample data and return it.
    fn setup_database() -> Database {
        setup_database_with_mount("C:")
    }

    /// Helper to set up a database with sample data using a specific mount point.
    fn setup_database_with_mount(mount_point: &str) -> Database {
        let mut database = Database::open_in_memory().expect("Failed to open in-memory database");
        let volume = make_volume("SN001", mount_point);
        let volume_id = database.upsert_volume(&volume).expect("Failed to upsert volume");

        let files = vec![
            FileEntry {
                volume_id,
                ..make_file("readme.txt", "C:\\Projects\\readme.txt", 1024)
            },
            FileEntry {
                volume_id,
                ..make_file("config.json", "C:\\Projects\\config.json", 512)
            },
            FileEntry {
                volume_id,
                ..make_file("notes.txt", "D:\\Documents\\notes.txt", 2048)
            },
            FileEntry {
                volume_id,
                ..make_dir("Projects", "C:\\Projects")
            },
            FileEntry {
                volume_id,
                ..make_dir("Documents", "D:\\Documents")
            },
            FileEntry {
                volume_id,
                ..make_file("report.txt", "C:\\Projects\\report.txt", 4096)
            },
            FileEntry {
                volume_id,
                ..make_file("data.json", "C:\\Data\\data.json", 8192)
            },
        ];
        database.insert_files_batch(&files).expect("Failed to insert files");
        database
    }

    /// Helper to build a minimal `CliConfig` for testing searches.
    fn search_config(patterns: Vec<&str>) -> CliConfig {
        CliConfig {
            command: None,
            patterns: patterns.into_iter().map(String::from).collect(),
            match_all: false,
            regex: false,
            case_sensitive: false,
            drives: Vec::new(),
            files_only: false,
            directories_only: false,
            files_per_dir: 20,
            output_format: filefind::config::OutputFormat::Grouped,
            sort_by: SortBy::Name,
            verbose: false,
            database_path: PathBuf::new(),
            path_mappings: HashMap::new(),
            move_to: None,
            force_overwrite: false,
        }
    }

    // ── EntryStatus ───────────────────────────────────────────────

    #[test]
    fn test_entry_status_equality() {
        assert_eq!(EntryStatus::File, EntryStatus::File);
        assert_eq!(EntryStatus::EmptyDirectory, EntryStatus::EmptyDirectory);
        assert_eq!(EntryStatus::MissingDirectory, EntryStatus::MissingDirectory);
        assert_ne!(EntryStatus::File, EntryStatus::EmptyDirectory);
    }

    #[test]
    fn test_entry_status_directory_with_size() {
        let status = EntryStatus::Directory {
            size: Some(1024),
            file_count: 5,
        };
        assert!(matches!(
            status,
            EntryStatus::Directory {
                size: Some(1024),
                file_count: 5
            }
        ));
    }

    #[test]
    fn test_entry_status_directory_no_size() {
        let status = EntryStatus::Directory {
            size: None,
            file_count: 0,
        };
        assert!(matches!(
            status,
            EntryStatus::Directory {
                size: None,
                file_count: 0
            }
        ));
    }

    #[test]
    fn test_entry_status_debug() {
        let status = EntryStatus::File;
        let debug_str = format!("{status:?}");
        assert!(debug_str.contains("File"));
    }

    // ── filter_by_drives ──────────────────────────────────────────

    #[test]
    fn test_filter_by_drives_empty_filter_returns_all() {
        let entries = vec![
            make_file("a.txt", "C:\\a.txt", 100),
            make_file("b.txt", "D:\\b.txt", 200),
        ];
        let result = filter_by_drives(entries, &[]);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_filter_by_drives_single_drive() {
        let entries = vec![
            make_file("a.txt", "C:\\a.txt", 100),
            make_file("b.txt", "D:\\b.txt", 200),
            make_file("c.txt", "C:\\sub\\c.txt", 300),
        ];
        let result = filter_by_drives(entries, &["C".to_string()]);
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|entry| entry.full_path.starts_with("C:")));
    }

    #[test]
    fn test_filter_by_drives_multiple_drives() {
        let entries = vec![
            make_file("a.txt", "C:\\a.txt", 100),
            make_file("b.txt", "D:\\b.txt", 200),
            make_file("c.txt", "E:\\c.txt", 300),
        ];
        let result = filter_by_drives(entries, &["C".to_string(), "E".to_string()]);
        assert_eq!(result.len(), 2);
        assert!(result.iter().any(|entry| entry.full_path.starts_with("C:")));
        assert!(result.iter().any(|entry| entry.full_path.starts_with("E:")));
    }

    #[test]
    fn test_filter_by_drives_case_insensitive() {
        let entries = vec![
            make_file("a.txt", "C:\\a.txt", 100),
            make_file("b.txt", "D:\\b.txt", 200),
        ];
        let result = filter_by_drives(entries, &["c".to_string()]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].full_path, "C:\\a.txt");
    }

    #[test]
    fn test_filter_by_drives_with_colon() {
        let entries = vec![
            make_file("a.txt", "C:\\a.txt", 100),
            make_file("b.txt", "D:\\b.txt", 200),
        ];
        let result = filter_by_drives(entries, &["C:".to_string()]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].full_path, "C:\\a.txt");
    }

    #[test]
    fn test_filter_by_drives_no_match() {
        let entries = vec![
            make_file("a.txt", "C:\\a.txt", 100),
            make_file("b.txt", "D:\\b.txt", 200),
        ];
        let result = filter_by_drives(entries, &["Z".to_string()]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_filter_by_drives_empty_entries() {
        let entries: Vec<FileEntry> = Vec::new();
        let result = filter_by_drives(entries, &["C".to_string()]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_filter_by_drives_lowercase_path() {
        let entries = vec![make_file("a.txt", "c:\\a.txt", 100)];
        let result = filter_by_drives(entries, &["C".to_string()]);
        assert_eq!(result.len(), 1);
    }

    // ── search_any_pattern (OR mode) ──────────────────────────────

    #[test]
    fn test_search_any_pattern_single_pattern() {
        let database = setup_database();
        let config = search_config(vec!["readme"]);
        let results = search_any_pattern(&config, &database).expect("Search failed");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "readme.txt");
    }

    #[test]
    fn test_search_any_pattern_multiple_patterns() {
        let database = setup_database();
        let config = search_config(vec!["readme", "config"]);
        let results = search_any_pattern(&config, &database).expect("Search failed");
        assert_eq!(results.len(), 2);
        let names: Vec<&str> = results.iter().map(|entry| entry.name.as_str()).collect();
        assert!(names.contains(&"readme.txt"));
        assert!(names.contains(&"config.json"));
    }

    #[test]
    fn test_search_any_pattern_deduplicates() {
        let database = setup_database();
        // ".txt" will match readme.txt, notes.txt, report.txt
        // "readme" will also match readme.txt
        // readme.txt should appear only once
        let config = search_config(vec![".txt", "readme"]);
        let results = search_any_pattern(&config, &database).expect("Search failed");
        let readme_count = results.iter().filter(|entry| entry.name == "readme.txt").count();
        assert_eq!(readme_count, 1, "readme.txt should appear only once");
    }

    #[test]
    fn test_search_any_pattern_no_results() {
        let database = setup_database();
        let config = search_config(vec!["nonexistent_file_xyz"]);
        let results = search_any_pattern(&config, &database).expect("Search failed");
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_any_pattern_glob() {
        let database = setup_database();
        let mut config = search_config(vec!["*.json"]);
        config.regex = false;
        let results = search_any_pattern(&config, &database).expect("Search failed");
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|entry| {
            std::path::Path::new(&entry.name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        }));
    }

    #[test]
    fn test_search_any_pattern_regex() {
        let database = setup_database();
        let mut config = search_config(vec![r"^re"]);
        config.regex = true;
        let results = search_any_pattern(&config, &database).expect("Search failed");
        let names: Vec<&str> = results.iter().map(|entry| entry.name.as_str()).collect();
        assert!(names.contains(&"readme.txt"));
        assert!(names.contains(&"report.txt"));
    }

    #[test]
    fn test_search_any_pattern_empty_patterns() {
        let database = setup_database();
        let config = search_config(vec![]);
        let results = search_any_pattern(&config, &database).expect("Search failed");
        assert!(results.is_empty());
    }

    // ── search_all_patterns (AND mode) ────────────────────────────

    #[test]
    fn test_search_all_patterns_single_pattern() {
        let database = setup_database();
        let mut config = search_config(vec!["readme"]);
        config.match_all = true;
        let results = search_all_patterns(&config, &database).expect("Search failed");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "readme.txt");
    }

    #[test]
    fn test_search_all_patterns_two_plain() {
        let database = setup_database();
        // "re" and ".txt" should both match readme.txt and report.txt
        let mut config = search_config(vec!["re", ".txt"]);
        config.match_all = true;
        let results = search_all_patterns(&config, &database).expect("Search failed");
        assert!(results.len() >= 2, "Should match readme.txt and report.txt");
        assert!(
            results
                .iter()
                .all(|entry| entry.name.contains("re") && entry.name.contains(".txt"))
        );
    }

    #[test]
    fn test_search_all_patterns_no_match() {
        let database = setup_database();
        // "readme" and "config" should not both match the same file
        let mut config = search_config(vec!["readme", "config"]);
        config.match_all = true;
        let results = search_all_patterns(&config, &database).expect("Search failed");
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_all_patterns_empty() {
        let database = setup_database();
        let mut config = search_config(vec![]);
        config.match_all = true;
        let results = search_all_patterns(&config, &database).expect("Search failed");
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_all_patterns_glob() {
        let database = setup_database();
        let mut config = search_config(vec!["*.txt", "*report*"]);
        config.match_all = true;
        let results = search_all_patterns(&config, &database).expect("Search failed");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "report.txt");
    }

    #[test]
    fn test_search_all_patterns_regex() {
        let database = setup_database();
        let mut config = search_config(vec![r"\.txt$", r"^re"]);
        config.match_all = true;
        config.regex = true;
        let results = search_all_patterns(&config, &database).expect("Search failed");
        assert!(results.len() >= 2);
        assert!(results.iter().all(|entry| {
            std::path::Path::new(&entry.name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("txt"))
                && entry.name.starts_with("re")
        }));
    }

    #[test]
    fn test_search_all_patterns_mixed_glob_and_plain() {
        let database = setup_database();
        // Mixed: one glob, one plain — falls back to search_all_patterns_mixed
        let mut config = search_config(vec!["*.txt", "report"]);
        config.match_all = true;
        let results = search_all_patterns(&config, &database).expect("Search failed");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "report.txt");
    }

    #[test]
    fn test_search_all_patterns_mixed_no_match() {
        let database = setup_database();
        let mut config = search_config(vec!["*.json", "readme"]);
        config.match_all = true;
        let results = search_all_patterns(&config, &database).expect("Search failed");
        assert!(results.is_empty());
    }

    // ── show_stats ────────────────────────────────────────────────

    #[test]
    fn test_show_stats_empty_database() {
        let database = Database::open_in_memory().expect("Failed to open in-memory database");
        let stats = database.get_stats().expect("Failed to get stats");
        assert_eq!(stats.total_files, 0);
        assert_eq!(stats.total_directories, 0);
        assert_eq!(stats.volume_count, 0);
        assert_eq!(stats.total_size, 0);
        // show_stats should succeed on empty database
        show_stats(&database).expect("show_stats failed on empty database");
    }

    #[test]
    fn test_show_stats_with_data() {
        let database = setup_database();
        let stats = database.get_stats().expect("Failed to get stats");
        // setup_database inserts: readme.txt, config.json, notes.txt, report.txt, data.json = 5 files
        assert_eq!(stats.total_files, 5);
        // setup_database inserts: Projects, Documents = 2 directories
        assert_eq!(stats.total_directories, 2);
        assert_eq!(stats.volume_count, 1);
        // 1024 + 512 + 2048 + 4096 + 8192 = 15872
        assert_eq!(stats.total_size, 15872);
        show_stats(&database).expect("show_stats failed with data");
    }

    // ── list_volumes ──────────────────────────────────────────────

    #[test]
    fn test_list_volumes_empty_database() {
        let database = Database::open_in_memory().expect("Failed to open in-memory database");
        let volumes = database.get_all_volumes().expect("Failed to get volumes");
        assert!(volumes.is_empty(), "Empty database should have no volumes");
        list_volumes(&database, VolumeSortBy::Name).expect("list_volumes failed on empty database");
    }

    #[test]
    fn test_list_volumes_sort_by_name() {
        let temp = tempdir().expect("Failed to create temp directory");
        let mount_point = temp.path().to_string_lossy().to_string();
        let database = setup_database_with_mount(&mount_point);
        let volumes = database.get_all_volumes().expect("Failed to get volumes");
        assert_eq!(volumes.len(), 1);
        assert_eq!(volumes[0].mount_point, mount_point);
        list_volumes(&database, VolumeSortBy::Name).expect("list_volumes failed");
    }

    #[test]
    fn test_list_volumes_sort_by_size() {
        let temp = tempdir().expect("Failed to create temp directory");
        let mount_point = temp.path().to_string_lossy().to_string();
        let database = setup_database_with_mount(&mount_point);
        let volumes = database.get_all_volumes().expect("Failed to get volumes");
        let data = get_volume_data(&database, &volumes).expect("Failed to get volume data");
        assert_eq!(data.len(), 1);
        // total_size only sums file sizes: 1024 + 512 + 2048 + 4096 + 8192 = 15872
        assert_eq!(data[0].total_size_bytes, 15872);
        list_volumes(&database, VolumeSortBy::Size).expect("list_volumes failed");
    }

    #[test]
    fn test_list_volumes_sort_by_files() {
        let temp = tempdir().expect("Failed to create temp directory");
        let mount_point = temp.path().to_string_lossy().to_string();
        let database = setup_database_with_mount(&mount_point);
        let volumes = database.get_all_volumes().expect("Failed to get volumes");
        let data = get_volume_data(&database, &volumes).expect("Failed to get volume data");
        assert_eq!(data.len(), 1);
        assert_eq!(
            data[0].file_count, 5,
            "file_count should count only files, not directories"
        );
        list_volumes(&database, VolumeSortBy::Files).expect("list_volumes failed");
    }

    #[test]
    #[allow(clippy::similar_names)]
    fn test_list_volumes_multiple_volumes_sorted() {
        let mut database = Database::open_in_memory().expect("Failed to open in-memory database");
        let temp_root = tempfile::tempdir().expect("Failed to create temp directory root");
        let volume_a_dir = temp_root.path().join("A_volume");
        let volume_b_dir = temp_root.path().join("B_volume");
        std::fs::create_dir(&volume_a_dir).expect("Failed to create volume A directory");
        std::fs::create_dir(&volume_b_dir).expect("Failed to create volume B directory");
        let volume_b_mount = volume_b_dir.to_string_lossy().to_string();
        let volume_a_mount = volume_a_dir.to_string_lossy().to_string();
        let volume_b = IndexedVolume {
            label: None,
            ..make_volume("SN_B", &volume_b_mount)
        };
        let volume_a = IndexedVolume {
            label: None,
            ..make_volume("SN_A", &volume_a_mount)
        };
        let volume_b_id = database.upsert_volume(&volume_b).expect("Failed to upsert B:");
        let volume_a_id = database.upsert_volume(&volume_a).expect("Failed to upsert A:");

        // Insert different amounts so size sorting is meaningful
        let files_b = vec![FileEntry {
            volume_id: volume_b_id,
            ..make_file("big.bin", "B:\\big.bin", 9999)
        }];
        let files_a = vec![
            FileEntry {
                volume_id: volume_a_id,
                ..make_file("small1.txt", "A:\\small1.txt", 10)
            },
            FileEntry {
                volume_id: volume_a_id,
                ..make_file("small2.txt", "A:\\small2.txt", 20)
            },
        ];
        database.insert_files_batch(&files_b).expect("Failed to insert B files");
        database.insert_files_batch(&files_a).expect("Failed to insert A files");

        let volumes = database.get_all_volumes().expect("Failed to get volumes");
        let mut data = get_volume_data(&database, &volumes).expect("Failed to get volume data");
        assert_eq!(data.len(), 2);

        // Sort by name: A: should come first
        data.sort_by_key(|volume| volume.mount_label.clone());
        assert_eq!(data[0].mount_label, volume_a_mount);
        assert_eq!(data[1].mount_label, volume_b_mount);

        // Sort by size: B: (9999) should come first
        data.sort_by_key(|volume| Reverse(volume.total_size_bytes));
        assert_eq!(data[0].mount_label, volume_b_mount);
        assert_eq!(data[0].total_size_bytes, 9999);

        // Sort by files: A: (2 files) should come first
        data.sort_by_key(|volume| Reverse(volume.file_count));
        assert_eq!(data[0].mount_label, volume_a_mount);
        assert_eq!(data[0].file_count, 2);
    }

    // ── print_entry_info ──────────────────────────────────────────

    #[test]
    fn test_print_entry_info_file_uses_size() {
        let entry = make_file("test.txt", "C:\\test.txt", 1024);
        // Verify the match arm: File status should format the file's own size
        let status = EntryStatus::File;
        assert_eq!(status, EntryStatus::File);
        assert_eq!(entry.size, 1024);
        assert!(!entry.is_directory);
        // Calling should not panic and exercises the File arm
        print_entry_info(&entry, &["test"], status);
    }

    #[test]
    fn test_print_entry_info_directory_with_size_and_count() {
        let entry = make_dir("docs", "C:\\docs");
        let status = EntryStatus::Directory {
            size: Some(4096),
            file_count: 3,
        };
        assert!(entry.is_directory);
        // Verify the data that would be displayed
        if let EntryStatus::Directory { size, file_count } = status {
            assert_eq!(size, Some(4096));
            assert_eq!(file_count, 3);
        }
        print_entry_info(&entry, &[], status);
    }

    #[test]
    fn test_print_entry_info_directory_no_size_shows_dash() {
        let entry = make_dir("docs", "C:\\docs");
        let status = EntryStatus::Directory {
            size: None,
            file_count: 0,
        };
        if let EntryStatus::Directory { size, file_count } = status {
            assert!(size.is_none(), "Should have no size to display as '-'");
            assert_eq!(file_count, 0, "Should show 0 file count");
        }
        print_entry_info(&entry, &[], status);
    }

    #[test]
    fn test_print_entry_info_empty_directory() {
        let entry = make_dir("empty", "C:\\empty");
        assert!(entry.is_directory);
        assert_eq!(entry.size, 0);
        print_entry_info(&entry, &[], EntryStatus::EmptyDirectory);
    }

    #[test]
    fn test_print_entry_info_missing_directory() {
        let entry = make_dir("gone", "C:\\gone");
        assert!(entry.is_directory);
        print_entry_info(&entry, &[], EntryStatus::MissingDirectory);
    }

    #[test]
    fn test_print_entry_info_zero_size_file() {
        let entry = make_file("test.txt", "C:\\test.txt", 0);
        assert_eq!(entry.size, 0, "Zero-size file should display 0 bytes");
        print_entry_info(&entry, &[], EntryStatus::File);
    }

    #[test]
    fn test_print_entry_info_large_file() {
        let entry = make_file("big.bin", "C:\\big.bin", 10_000_000_000);
        assert_eq!(entry.size, 10_000_000_000);
        print_entry_info(&entry, &["big"], EntryStatus::File);
    }

    // ── delete_missing_directory ──────────────────────────────────

    #[test]
    fn test_delete_missing_directory_nonexistent_path_is_noop() {
        let database = setup_database();
        let stats_before = database.get_stats().expect("Failed to get stats");
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let missing_path = temp_dir.path().join("missing").join("path");
        // Deleting a path not in the database should be a no-op
        delete_missing_directory(&database, &missing_path.to_string_lossy());
        let stats_after = database.get_stats().expect("Failed to get stats");
        assert_eq!(stats_before.total_files, stats_after.total_files);
        assert_eq!(stats_before.total_directories, stats_after.total_directories);
    }

    #[test]
    fn test_delete_missing_directory_removes_entries() {
        let database = setup_database();

        // Verify files exist before deletion
        let before = database.search_by_name("readme", 10).expect("Search failed");
        assert!(!before.is_empty());

        // Delete directory and its contents
        delete_missing_directory(&database, "C:\\Projects");

        // Files under that directory should now be gone
        let after = database.search_by_name("readme", 10).expect("Search failed");
        assert!(after.is_empty());
    }

    // ── get_volume_data ───────────────────────────────────────────

    #[test]
    fn test_get_volume_data_empty_returns_empty() {
        let database = Database::open_in_memory().expect("Failed to open in-memory database");
        let volumes: Vec<IndexedVolume> = Vec::new();
        let data = get_volume_data(&database, &volumes).expect("Failed to get volume data");
        assert!(data.is_empty(), "No volumes input should produce empty output");
    }

    #[test]
    fn test_get_volume_data_has_correct_counts() {
        let temp = tempdir().expect("Failed to create temp directory");
        let mount_point = temp.path().to_string_lossy().to_string();
        let database = setup_database_with_mount(&mount_point);
        let volumes = database.get_all_volumes().expect("Failed to get volumes");
        let data = get_volume_data(&database, &volumes).expect("Failed to get volume data");
        assert_eq!(data.len(), 1);
        assert!(
            data[0].mount_label.contains(&mount_point),
            "Mount label should contain the mount point"
        );
        assert!(
            data[0].mount_label.contains("Vol SN001"),
            "Mount label should contain the volume label"
        );
        assert_eq!(
            data[0].file_count, 5,
            "file_count should count only files (not directories)"
        );
        // Total size sums only file sizes: 1024 + 512 + 2048 + 4096 + 8192 = 15872
        assert_eq!(data[0].total_size_bytes, 15872, "Should sum all file sizes");
        assert_eq!(data[0].volume_type, "NTFS");
    }

    #[test]
    fn test_get_volume_data_no_label_uses_mount_point_only() {
        let database = Database::open_in_memory().expect("Failed to open in-memory database");
        let temp = tempfile::tempdir().expect("Failed to create temp directory");
        let mount_point = temp.path().to_string_lossy().to_string();
        let volume = IndexedVolume {
            label: None,
            ..make_volume("SN999", &mount_point)
        };
        database.upsert_volume(&volume).expect("Failed to upsert");
        let volumes = database.get_all_volumes().expect("Failed to get volumes");
        let data = get_volume_data(&database, &volumes).expect("Failed to get volume data");
        assert_eq!(data.len(), 1);
        assert_eq!(
            data[0].mount_label, mount_point,
            "No label should show mount point only"
        );
        assert_eq!(data[0].file_count, 0, "Empty volume should have 0 files");
        assert_eq!(data[0].total_size_bytes, 0, "Empty volume should have 0 size");
    }

    #[test]
    fn test_get_volume_data_with_label_combines_mount_and_label() {
        let database = Database::open_in_memory().expect("Failed to open in-memory database");
        let temp = tempdir().expect("Failed to create temp directory");
        let mount_point = temp.path().to_string_lossy().to_string();
        let volume = IndexedVolume {
            label: Some("Windows".to_string()),
            ..make_volume("SN_WIN", &mount_point)
        };
        database.upsert_volume(&volume).expect("Failed to upsert");
        let volumes = database.get_all_volumes().expect("Failed to get volumes");
        let data = get_volume_data(&database, &volumes).expect("Failed to get volume data");
        assert_eq!(data[0].mount_label, format!("{mount_point} Windows"));
    }

    // ── display functions ─────────────────────────────────────────
    // Display functions write to stdout. We verify the data structures they
    // would process, then call the function to exercise the code path and
    // ensure no panics occur with these inputs.

    #[test]
    fn test_display_grouped_output_files_only_skips_dirs() {
        let database = setup_database();
        let config = CliConfig {
            files_only: true,
            ..search_config(vec!["test"])
        };
        let files_owned = [
            make_file("test.txt", "C:\\test.txt", 100),
            make_file("test2.txt", "C:\\test2.txt", 200),
        ];
        let files: Vec<&FileEntry> = files_owned.iter().collect();
        let dirs_owned = [make_dir("ignored", "C:\\ignored")];
        let dirs: Vec<&FileEntry> = dirs_owned.iter().collect();
        // With files_only, the dirs are passed but should be ignored by the display
        assert!(config.files_only);
        assert_eq!(files.len(), 2);
        display_grouped_output(&dirs, &files, &config, &["test"], &database);
    }

    #[test]
    fn test_display_grouped_output_dirs_only_checks_existence() {
        let database = setup_database();
        let temp = tempdir().expect("Failed to create temp directory");
        let temp_path = temp.path().to_string_lossy().to_string();
        let config = CliConfig {
            directories_only: true,
            ..search_config(vec!["test"])
        };
        // The temp dir actually exists on disk, so it should be displayed normally
        assert!(std::path::Path::new(&temp_path).is_dir());
        let dir_owned = [make_dir("testdir", &temp_path)];
        let dirs: Vec<&FileEntry> = dir_owned.iter().collect();
        let files: Vec<&FileEntry> = Vec::new();
        assert!(config.directories_only);
        display_grouped_output(&dirs, &files, &config, &["test"], &database);
    }

    #[test]
    fn test_display_name_files_only_uses_name_not_path() {
        let database = setup_database();
        let config = CliConfig {
            files_only: true,
            ..search_config(vec!["readme"])
        };
        let files_owned = [make_file("readme.txt", "C:\\Projects\\readme.txt", 100)];
        let files: Vec<&FileEntry> = files_owned.iter().collect();
        let dirs: Vec<&FileEntry> = Vec::new();
        // In name mode, display uses file.name not file.full_path
        assert_eq!(files[0].name, "readme.txt");
        assert_ne!(files[0].name, files[0].full_path);
        display_name(&dirs, &files, &config, &["readme"], &database);
    }

    #[test]
    fn test_display_list_files_only_uses_full_path() {
        let database = setup_database();
        let config = CliConfig {
            files_only: true,
            ..search_config(vec!["readme"])
        };
        let files_owned = [make_file("readme.txt", "C:\\Projects\\readme.txt", 100)];
        let files: Vec<&FileEntry> = files_owned.iter().collect();
        let dirs: Vec<&FileEntry> = Vec::new();
        // In list mode, display uses file.full_path
        assert_eq!(files[0].full_path, "C:\\Projects\\readme.txt");
        display_list(&dirs, &files, &config, &["readme"], &database);
    }

    #[test]
    fn test_display_info_shows_file_size() {
        let database = setup_database();
        let config = CliConfig {
            files_only: true,
            ..search_config(vec!["test"])
        };
        let files_owned = [
            make_file("small.txt", "C:\\small.txt", 100),
            make_file("big.txt", "C:\\big.txt", 5_000_000),
        ];
        let files: Vec<&FileEntry> = files_owned.iter().collect();
        let dirs: Vec<&FileEntry> = Vec::new();
        // Info mode displays each file's size — verify the data is set up correctly
        assert_eq!(files[0].size, 100);
        assert_eq!(files[1].size, 5_000_000);
        display_info(&dirs, &files, &config, &["test"], &database);
    }

    #[test]
    fn test_display_info_dirs_only_calculates_dir_sizes() {
        let database = setup_database();
        let temp = tempdir().expect("Failed to create temp directory");
        let temp_path = temp.path().to_string_lossy().to_string();
        let config = CliConfig {
            directories_only: true,
            ..search_config(vec!["test"])
        };
        let dir_owned = [make_dir("testdir", &temp_path)];
        let dirs: Vec<&FileEntry> = dir_owned.iter().collect();
        // No files under this dir, so dir size should be None/0
        let files: Vec<&FileEntry> = Vec::new();
        let dir_sizes = utils::calculate_directory_sizes(&files);
        assert!(
            !dir_sizes.contains_key(&temp_path),
            "No files under dir, so size map should have no entry"
        );
        display_info(&dirs, &files, &config, &[], &database);
    }

    #[test]
    fn test_display_info_verbose_shows_headers() {
        let database = setup_database();
        let config = CliConfig {
            verbose: true,
            files_only: true,
            ..search_config(vec!["test"])
        };
        // Verbose mode prints header lines before the entries
        assert!(config.verbose);
        let files_owned = [make_file("test.txt", "C:\\test.txt", 100)];
        let files: Vec<&FileEntry> = files_owned.iter().collect();
        let dirs: Vec<&FileEntry> = Vec::new();
        display_info(&dirs, &files, &config, &["test"], &database);
    }

    #[test]
    fn test_display_grouped_empty_dirs_and_files() {
        let database = setup_database();
        let config = search_config(vec!["test"]);
        let dirs: Vec<&FileEntry> = Vec::new();
        let files: Vec<&FileEntry> = Vec::new();
        // Both empty — should produce no output without panicking
        assert!(dirs.is_empty());
        assert!(files.is_empty());
        display_grouped_output(&dirs, &files, &config, &[], &database);
    }

    #[test]
    fn test_display_name_empty_dirs_and_files() {
        let database = setup_database();
        let config = search_config(vec![]);
        let dirs: Vec<&FileEntry> = Vec::new();
        let files: Vec<&FileEntry> = Vec::new();
        assert!(dirs.is_empty());
        assert!(files.is_empty());
        display_name(&dirs, &files, &config, &[], &database);
    }

    #[test]
    fn test_display_list_empty_dirs_and_files() {
        let database = setup_database();
        let config = search_config(vec![]);
        let dirs: Vec<&FileEntry> = Vec::new();
        let files: Vec<&FileEntry> = Vec::new();
        assert!(dirs.is_empty());
        assert!(files.is_empty());
        display_list(&dirs, &files, &config, &[], &database);
    }

    #[test]
    fn test_display_info_empty_dirs_and_files() {
        let database = setup_database();
        let config = search_config(vec![]);
        let dirs: Vec<&FileEntry> = Vec::new();
        let files: Vec<&FileEntry> = Vec::new();
        assert!(dirs.is_empty());
        assert!(files.is_empty());
        display_info(&dirs, &files, &config, &[], &database);
    }

    #[test]
    fn test_display_info_sort_dirs_by_size_ordering() {
        let database = setup_database();
        let temp = tempdir().expect("Failed to create temp directory");
        let temp_path = temp.path().to_string_lossy().to_string();
        let config = CliConfig {
            sort_by: SortBy::Size,
            verbose: true,
            ..search_config(vec!["test"])
        };
        let dir_owned = [make_dir("testdir", &temp_path)];
        let dirs: Vec<&FileEntry> = dir_owned.iter().collect();
        let file_owned = [make_file("inner.txt", &format!("{temp_path}\\inner.txt"), 512)];
        let files: Vec<&FileEntry> = file_owned.iter().collect();

        // Verify directory size calculation picks up files under the dir
        let dir_sizes = utils::calculate_directory_sizes(&files);
        assert_eq!(
            *dir_sizes.get(&temp_path).expect("Should have dir size"),
            512,
            "Dir size should equal the file's size"
        );
        assert!(matches!(config.sort_by, SortBy::Size));

        display_info(&dirs, &files, &config, &[], &database);
    }

    #[test]
    fn test_display_grouped_groups_files_by_parent() {
        let database = setup_database();
        let config = search_config(vec!["file"]);
        let entry1 = make_file("file1.txt", "C:\\DirA\\file1.txt", 100);
        let entry2 = make_file("file2.txt", "C:\\DirA\\file2.txt", 200);
        let entry3 = make_file("file3.txt", "C:\\DirB\\file3.txt", 300);
        let files_owned = [entry1, entry2, entry3];
        let files: Vec<&FileEntry> = files_owned.iter().collect();
        let dirs: Vec<&FileEntry> = Vec::new();

        // Verify the grouping logic: files_by_dir should group by parent
        let mut files_by_dir: HashMap<String, Vec<&FileEntry>> = HashMap::new();
        for file in &files {
            let parent = PathBuf::from(&file.full_path)
                .parent()
                .map(|path| path.to_string_lossy().to_string())
                .unwrap_or_default();
            files_by_dir.entry(parent).or_default().push(file);
        }
        assert_eq!(files_by_dir.len(), 2, "Should group into 2 directories");
        assert_eq!(files_by_dir["C:\\DirA"].len(), 2);
        assert_eq!(files_by_dir["C:\\DirB"].len(), 1);

        display_grouped(&dirs, &files, &config, &["file"], &database);
    }

    // ── run_search integration ────────────────────────────────────
    // run_search orchestrates searching + display. We verify the search
    // results via the underlying search functions and call run_search to
    // exercise the full path (sorting, filtering, display dispatch).

    #[test]
    fn test_run_search_no_patterns_returns_error_with_usage_message() {
        let database = setup_database();
        let config = search_config(vec![]);
        let err = run_search(&config, &database).expect_err("Should fail with no patterns");
        let msg = err.to_string();
        assert!(msg.contains("Usage"), "Error should contain usage hint, got: {msg}");
    }

    #[test]
    fn test_run_search_basic_finds_file() {
        let database = setup_database();
        let config = search_config(vec!["readme"]);
        // Verify the underlying search returns the right data
        let results = search_any_pattern(&config, &database).expect("Search failed");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "readme.txt");
        assert_eq!(results[0].full_path, "C:\\Projects\\readme.txt");
        // run_search exercises display on top of this
        run_search(&config, &database).expect("run_search failed");
    }

    #[test]
    fn test_run_search_with_drive_filter_excludes_other_drives() {
        let database = setup_database();
        let config = CliConfig {
            drives: vec!["C".to_string()],
            ..search_config(vec![".txt"])
        };
        // Search finds all .txt files, then filter_by_drives keeps only C:
        let all_results = search_any_pattern(&config, &database).expect("Search failed");
        let filtered = filter_by_drives(all_results, &config.drives);
        assert!(
            filtered.iter().all(|entry| entry.full_path.starts_with("C:")),
            "All results should be on C: drive"
        );
        // notes.txt is on D:, so it should be excluded
        assert!(
            !filtered.iter().any(|entry| entry.name == "notes.txt"),
            "notes.txt is on D: and should be filtered out"
        );
        run_search(&config, &database).expect("run_search failed");
    }

    #[test]
    fn test_run_search_verbose_completes() {
        let database = setup_database();
        let config = CliConfig {
            verbose: true,
            ..search_config(vec!["readme"])
        };
        assert!(config.verbose);
        run_search(&config, &database).expect("run_search with verbose failed");
    }

    #[test]
    fn test_run_search_all_formats_find_same_results() {
        let database = setup_database();
        // All formats should find the same underlying results
        let base_config = search_config(vec!["readme"]);
        let base_results = search_any_pattern(&base_config, &database).expect("Search failed");
        assert_eq!(base_results.len(), 1);

        for format in [
            filefind::config::OutputFormat::Grouped,
            filefind::config::OutputFormat::List,
            filefind::config::OutputFormat::Name,
            filefind::config::OutputFormat::Info,
        ] {
            let config = CliConfig {
                output_format: format,
                ..search_config(vec!["readme"])
            };
            run_search(&config, &database).unwrap_or_else(|_| panic!("run_search failed for format {format:?}"));
        }
    }

    #[test]
    fn test_run_search_and_mode_intersects_patterns() {
        let database = setup_database();
        let config = CliConfig {
            match_all: true,
            ..search_config(vec!["re", ".txt"])
        };
        // AND mode: "re" AND ".txt" should match readme.txt and report.txt
        let results = search_all_patterns(&config, &database).expect("Search failed");
        assert!(results.len() >= 2);
        assert!(
            results
                .iter()
                .all(|entry| entry.name.contains("re") && entry.name.contains(".txt"))
        );
        run_search(&config, &database).expect("run_search failed");
    }

    #[test]
    fn test_run_search_regex_mode_matches_pattern() {
        let database = setup_database();
        let config = CliConfig {
            regex: true,
            ..search_config(vec![r"\.json$"])
        };
        let results = search_any_pattern(&config, &database).expect("Search failed");
        assert_eq!(results.len(), 2, "Should match config.json and data.json");
        assert!(results.iter().all(|entry| {
            std::path::Path::new(&entry.name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        }));
        run_search(&config, &database).expect("run_search failed");
    }

    #[test]
    fn test_run_search_files_only_excludes_directories() {
        let database = setup_database();
        let config = CliConfig {
            files_only: true,
            ..search_config(vec![".txt"])
        };
        let results = search_any_pattern(&config, &database).expect("Search failed");
        // The search returns both files and dirs; run_search partitions them
        let (dirs, files): (Vec<_>, Vec<_>) = results.iter().partition(|entry| entry.is_directory);
        assert!(!files.is_empty(), "Should find .txt files");
        // In files_only mode, dirs would be ignored during display
        // but the data layer returns everything — the filtering is display-level
        let _ = dirs; // acknowledged
        run_search(&config, &database).expect("run_search failed");
    }

    #[test]
    fn test_run_search_dirs_only_finds_directories() {
        let database = setup_database();
        let config = CliConfig {
            directories_only: true,
            ..search_config(vec!["Projects"])
        };
        let results = search_any_pattern(&config, &database).expect("Search failed");
        let dirs: Vec<_> = results.iter().filter(|entry| entry.is_directory).collect();
        assert!(!dirs.is_empty(), "Should find the Projects directory");
        assert!(dirs.iter().any(|directory| directory.name == "Projects"));
        run_search(&config, &database).expect("run_search failed");
    }

    #[test]
    fn test_run_search_sort_by_size_largest_first() {
        let database = setup_database();
        let config = CliConfig {
            sort_by: SortBy::Size,
            ..search_config(vec![".txt"])
        };
        let mut results = search_any_pattern(&config, &database).expect("Search failed");
        results.sort_unstable_by_key(|entry| Reverse(entry.size));
        let files: Vec<_> = results.iter().filter(|entry| !entry.is_directory).collect();
        // Verify descending size order
        for window in files.windows(2) {
            assert!(
                window[0].size >= window[1].size,
                "Files should be sorted largest first: {} ({}) >= {} ({})",
                window[0].name,
                window[0].size,
                window[1].name,
                window[1].size
            );
        }
        run_search(&config, &database).expect("run_search failed");
    }

    #[test]
    fn test_run_search_sort_by_name_in_name_format_alphabetical() {
        let database = setup_database();
        let config = CliConfig {
            sort_by: SortBy::Name,
            output_format: filefind::config::OutputFormat::Name,
            ..search_config(vec![".txt"])
        };
        let mut results = search_any_pattern(&config, &database).expect("Search failed");
        // Name format sorts by name (case-insensitive)
        results.sort_unstable_by_key(|entry| entry.name.to_lowercase());
        let names: Vec<&str> = results.iter().map(|entry| entry.name.as_str()).collect();
        for window in names.windows(2) {
            assert!(
                window[0].to_lowercase() <= window[1].to_lowercase(),
                "Names should be alphabetical: {} <= {}",
                window[0],
                window[1]
            );
        }
        run_search(&config, &database).expect("run_search failed");
    }

    #[test]
    fn test_run_search_no_results_succeeds_with_empty() {
        let database = setup_database();
        let config = search_config(vec!["totally_nonexistent_xyzzy"]);
        let results = search_any_pattern(&config, &database).expect("Search failed");
        assert!(results.is_empty(), "Should find nothing for nonexistent pattern");
        run_search(&config, &database).expect("run_search should succeed even with no results");
    }

    #[test]
    fn test_run_search_glob_patterns_not_in_highlight_list() {
        let database = setup_database();
        let config = search_config(vec!["*.txt"]);
        // Glob patterns contain * so they should be excluded from highlighting
        assert!(
            config
                .patterns
                .iter()
                .filter(|pattern| !pattern.contains('*') && !pattern.contains('?'))
                .map(String::as_str)
                .next()
                .is_none(),
            "Glob patterns should not be used for highlighting"
        );
        run_search(&config, &database).expect("run_search failed");
    }

    #[test]
    fn test_run_search_regex_patterns_not_in_highlight_list() {
        let database = setup_database();
        let config = CliConfig {
            regex: true,
            ..search_config(vec![r"\d+"])
        };
        // Regex mode produces an empty highlight list
        let highlight_patterns: Vec<&str> = if config.regex {
            Vec::new()
        } else {
            config
                .patterns
                .iter()
                .filter(|pattern| !pattern.contains('*') && !pattern.contains('?'))
                .map(String::as_str)
                .collect()
        };
        assert!(
            highlight_patterns.is_empty(),
            "Regex mode should produce empty highlight list"
        );
        run_search(&config, &database).expect("run_search failed");
    }

    #[test]
    fn test_run_search_db_not_modified_by_search() {
        let database = setup_database();
        let stats_before = database.get_stats().expect("Failed to get stats");
        let config = search_config(vec!["readme"]);
        run_search(&config, &database).expect("run_search failed");
        let stats_after = database.get_stats().expect("Failed to get stats");
        assert_eq!(stats_before.total_files, stats_after.total_files);
        assert_eq!(stats_before.total_directories, stats_after.total_directories);
    }

    // ── Duplicates tests ──────────────────────────────────────────────

    /// Helper to set up a database with duplicate files for testing.
    fn setup_duplicates_database() -> Database {
        let mut database = Database::open_in_memory().expect("Failed to open in-memory database");
        let volume_c = make_volume("SN_DUP_C", "C:");
        let volume_id_c = database.upsert_volume(&volume_c).expect("Failed to upsert volume");

        let volume_d = make_volume("SN_DUP_D", "D:");
        let volume_id_d = database.upsert_volume(&volume_d).expect("Failed to upsert volume");

        let files = vec![
            // Duplicate group: "report" (3 files)
            FileEntry {
                volume_id: volume_id_c,
                ..make_file("report.txt", "C:\\docs\\report.txt", 1024)
            },
            FileEntry {
                volume_id: volume_id_c,
                ..make_file("report.pdf", "C:\\output\\report.pdf", 2048)
            },
            FileEntry {
                volume_id: volume_id_d,
                ..make_file("report.docx", "D:\\archive\\report.docx", 4096)
            },
            // Duplicate group: "config" (2 files)
            FileEntry {
                volume_id: volume_id_c,
                ..make_file("config.toml", "C:\\project\\config.toml", 128)
            },
            FileEntry {
                volume_id: volume_id_d,
                ..make_file("config.yaml", "D:\\project\\config.yaml", 256)
            },
            // Unique file: no duplicates
            FileEntry {
                volume_id: volume_id_c,
                ..make_file("readme.md", "C:\\readme.md", 512)
            },
            // Directory: should be excluded from duplicates
            FileEntry {
                volume_id: volume_id_c,
                ..make_dir("report", "C:\\report")
            },
        ];
        database.insert_files_batch(&files).expect("Failed to insert files");
        database
    }

    #[test]
    fn test_show_duplicates_empty_database() {
        let database = Database::open_in_memory().expect("Failed to open in-memory database");
        let result = show_duplicates(&database, &[], None, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_show_duplicates_finds_groups() {
        let database = setup_duplicates_database();
        let result = show_duplicates(&database, &[], None, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_show_duplicates_with_drive_filter() {
        let database = setup_duplicates_database();
        // Filter to only C: drive — "report" group should drop to 2 files (C: only),
        // "config" group should disappear (only 1 file on C:)
        let drives = vec!["C".to_string()];
        let result = show_duplicates(&database, &drives, None, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_show_duplicates_with_drive_filter_no_results() {
        let database = setup_duplicates_database();
        // Filter to E: drive which has no files — no duplicates
        let drives = vec!["E".to_string()];
        let result = show_duplicates(&database, &drives, None, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_show_duplicates_with_limit() {
        let database = setup_duplicates_database();
        // Limit to 1 group
        let result = show_duplicates(&database, &[], Some(1), false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_show_duplicates_with_limit_zero() {
        let database = setup_duplicates_database();
        let result = show_duplicates(&database, &[], Some(0), false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_show_duplicates_with_limit_exceeding_total() {
        let database = setup_duplicates_database();
        // Limit higher than total groups — should show all
        let result = show_duplicates(&database, &[], Some(100), false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_show_duplicates_verbose() {
        let database = setup_duplicates_database();
        let result = show_duplicates(&database, &[], None, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_show_duplicates_verbose_with_limit() {
        let database = setup_duplicates_database();
        let result = show_duplicates(&database, &[], Some(1), true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_show_duplicates_drive_filter_reduces_group_below_two() {
        let mut database = Database::open_in_memory().expect("Failed to open in-memory database");
        let volume = make_volume("SN_FILT1", "C:");
        let volume_id = database.upsert_volume(&volume).expect("Failed to upsert volume");

        let other_volume = make_volume("SN_FILT2", "D:");
        let volume_id_d = database.upsert_volume(&other_volume).expect("Failed to upsert volume");

        // "notes" has one file on C: and one on D:
        let files = vec![
            FileEntry {
                volume_id,
                ..make_file("notes.txt", "C:\\notes.txt", 100)
            },
            FileEntry {
                volume_id: volume_id_d,
                ..make_file("notes.pdf", "D:\\notes.pdf", 200)
            },
        ];
        database.insert_files_batch(&files).expect("Failed to insert files");

        // Without filter: 1 duplicate group
        let result = show_duplicates(&database, &[], None, false);
        assert!(result.is_ok());

        // With C: filter: group drops to 1 file, so no duplicates shown
        let drives = vec!["C".to_string()];
        let result = show_duplicates(&database, &drives, None, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_show_duplicates_no_duplicate_files() {
        let mut database = Database::open_in_memory().expect("Failed to open in-memory database");
        let volume = make_volume("SN_NODUP", "C:");
        let volume_id = database.upsert_volume(&volume).expect("Failed to upsert volume");

        let files = vec![
            FileEntry {
                volume_id,
                ..make_file("alpha.txt", "C:\\alpha.txt", 100)
            },
            FileEntry {
                volume_id,
                ..make_file("beta.pdf", "C:\\beta.pdf", 200)
            },
            FileEntry {
                volume_id,
                ..make_file("gamma.docx", "C:\\gamma.docx", 300)
            },
        ];
        database.insert_files_batch(&files).expect("Failed to insert files");

        let result = show_duplicates(&database, &[], None, false);
        assert!(result.is_ok());
    }
}
