//! Command-line interface for filefind file search.

mod config;

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

use anyhow::Result;
use anyhow::bail;
use clap::{CommandFactory, Parser, ValueEnum};
use clap_complete::Shell;
use colored::Colorize;

use filefind::config::OutputFormat;
use filefind::database::Database;
use filefind::{format_size, print_error};

use crate::config::{CliConfig, DisplayOptions};

/// Fast file search using the filefind index
#[allow(clippy::struct_excessive_bools)]
#[derive(Parser)]
#[command(
    author,
    version,
    name = env!("CARGO_BIN_NAME"),
    about = "Fast file search using the filefind index"
)]
pub struct Args {
    /// Search pattern (supports glob patterns like *.txt)
    pub pattern: Option<String>,

    /// Use regex pattern for search
    #[arg(short = 'r', long)]
    pub regex: bool,

    /// Case-sensitive search
    #[arg(short = 'c', long)]
    pub case: bool,

    /// Search only in specific drives. Accepts: "C", "C:", or "C:\"
    #[arg(short = 'd', long, name = "DRIVE", action = clap::ArgAction::Append)]
    pub drive: Vec<String>,

    /// Only show files
    #[arg(short = 'f', long)]
    pub files: bool,

    /// Only show directories
    #[arg(short = 'D', long)]
    pub dirs: bool,

    /// Maximum number of files to show per directory
    #[arg(short = 'n', long, name = "COUNT", default_value_t = 20)]
    pub limit: usize,

    /// Output format.
    #[arg(short = 'o', long, value_enum)]
    pub output: Option<OutputFormatArg>,

    /// Show index statistics
    #[arg(short = 's', long)]
    pub stats: bool,

    /// List all indexed volumes
    #[arg(short = 'l', long)]
    pub list: bool,

    /// Generate shell completion
    #[arg(short = 'C', long, name = "SHELL")]
    pub completion: Option<Shell>,

    /// Print verbose output.
    #[arg(short = 'v', long)]
    pub verbose: bool,
}

/// Output format argument for CLI.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormatArg {
    /// Simple list of paths without type or size information.
    Simple,
    /// Files grouped by directory (default).
    Grouped,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Handle shell completion generation
    if let Some(shell) = args.completion {
        clap_complete::generate(
            shell,
            &mut Args::command(),
            env!("CARGO_BIN_NAME"),
            &mut std::io::stdout(),
        );
        return Ok(());
    }

    // Build the final config from user config and CLI args
    let config = CliConfig::from_args(args)?;

    run(config)
}

/// Run the CLI with the given configuration.
fn run(config: CliConfig) -> Result<()> {
    if !config.database_path.exists() {
        print_error!("Database not found at: {}", config.database_path.display());
        bail!("Run the filefind daemon first to build the index");
    }

    let database = Database::open(&config.database_path)?;

    if config.show_stats {
        return show_stats(&database);
    }

    if config.list_volumes {
        return list_volumes(&database);
    }

    let Some(pattern) = config.pattern else {
        print_error!("No search pattern provided");
        bail!("Usage: filefind <pattern>\n       filefind --stats\n       filefind --list");
    };

    let start_time = Instant::now();

    let results = if config.regex {
        database.search_by_regex(&pattern, config.case_sensitive, usize::MAX)?
    } else if pattern.contains('*') || pattern.contains('?') {
        database.search_by_glob(&pattern, usize::MAX)?
    } else {
        database.search_by_name(&pattern, usize::MAX)?
    };

    let search_duration = start_time.elapsed();

    // Filter results by drive
    let mut results: Vec<_> = filter_by_drives(results, &config.drives);

    results.sort_unstable_by(|a, b| a.full_path.cmp(&b.full_path));

    // Separate directories and files
    let (directories, files): (Vec<_>, Vec<_>) = results.iter().partition(|e| e.is_directory);

    // Determine if we should highlight (only for simple patterns, not regex or glob)
    let highlight_pattern = if !config.regex && !pattern.contains('*') && !pattern.contains('?') {
        Some(pattern.as_str())
    } else {
        None
    };

    // Display results based on mode
    let display_options = DisplayOptions {
        directories_only: config.dirs_only,
        files_only: config.files_only,
        files_per_dir: config.files_per_dir,
    };

    match config.output_format {
        OutputFormat::Grouped => display_grouped_output(&directories, &files, &display_options, highlight_pattern),
        OutputFormat::Simple => display_simple(&directories, &files, &display_options, highlight_pattern),
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

/// Highlight a pattern within text (case-insensitive).
fn highlight_match(text: &str, pattern: Option<&str>) -> String {
    let Some(pattern) = pattern else {
        return text.to_string();
    };

    let text_lower = text.to_lowercase();
    let pattern_lower = pattern.to_lowercase();

    let mut result = String::new();
    let mut last_end = 0;

    for (start, _) in text_lower.match_indices(&pattern_lower) {
        // Add text before the match
        result.push_str(&text[last_end..start]);
        // Add highlighted match using original case from text
        let matched_text = &text[start..start + pattern.len()];
        result.push_str(&matched_text.green().bold().to_string());
        last_end = start + pattern.len();
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
    highlight_pattern: Option<&str>,
) {
    if options.files_only {
        // Files only mode: show full paths
        for file in files {
            println!("{}", highlight_match(&file.full_path, highlight_pattern));
        }
    } else if options.directories_only {
        // Dirs only mode: show full path with file count
        for directory in directories {
            let file_count = count_files_in_directory(files, &directory.full_path);
            if file_count > 0 {
                println!(
                    "{} ({} files)",
                    highlight_match(&directory.full_path, highlight_pattern),
                    file_count
                );
            } else {
                println!("{}", highlight_match(&directory.full_path, highlight_pattern));
            }
        }
    } else {
        // Normal mode: group files under directories
        display_grouped(directories, files, options.files_per_dir, highlight_pattern);
    }
}

/// Display results grouped by directory.
fn display_grouped(
    directories: &[&filefind::types::FileEntry],
    files: &[&filefind::types::FileEntry],
    files_per_dir: usize,
    highlight_pattern: Option<&str>,
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
        println!("{}", highlight_match(&directory.full_path, highlight_pattern).bold());
        if let Some(dir_files) = files_by_dir.get(&directory.full_path) {
            let total_files = dir_files.len();
            for file in dir_files.iter().take(files_per_dir) {
                println!("  {}", highlight_match(&file.name, highlight_pattern));
            }
            if total_files > files_per_dir {
                println!("  {} ({} files)", "...".dimmed(), total_files - files_per_dir);
            }
        }
    }

    // Then show files in directories that weren't matched
    let matched_dirs: std::collections::HashSet<_> = directories.iter().map(|d| &d.full_path).collect();

    let mut other_dirs: Vec<_> = files_by_dir.keys().filter(|dir| !matched_dirs.contains(*dir)).collect();
    other_dirs.sort();

    for dir_path in other_dirs {
        if let Some(dir_files) = files_by_dir.get(dir_path) {
            println!("{}", highlight_match(dir_path, highlight_pattern).bold());
            let total_files = dir_files.len();
            for file in dir_files.iter().take(files_per_dir) {
                println!("  {}", highlight_match(&file.name, highlight_pattern));
            }
            if total_files > files_per_dir {
                println!("  {} ({} files)", "...".dimmed(), total_files - files_per_dir);
            }
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
    highlight_pattern: Option<&str>,
) {
    // Sort directories by path
    let mut sorted_directories: Vec<_> = directories.to_vec();
    sorted_directories.sort_by(|a, b| a.full_path.cmp(&b.full_path));

    if options.files_only {
        for file in files {
            println!("{}", highlight_match(&file.full_path, highlight_pattern));
        }
    } else if options.directories_only {
        for directory in &sorted_directories {
            println!("{}", highlight_match(&directory.full_path, highlight_pattern));
        }
    } else {
        // Show all directories first, then all files
        for directory in &sorted_directories {
            println!("{}", highlight_match(&directory.full_path, highlight_pattern));
        }
        for file in files {
            println!("{}", highlight_match(&file.full_path, highlight_pattern));
        }
    }
}

/// Show index statistics.
fn show_stats(database: &Database) -> Result<()> {
    let stats = database.get_stats()?;

    println!("{}", "Index Statistics".bold().underline());
    println!();
    println!("  Volumes:     {}", stats.volume_count);
    println!("  Files:       {}", stats.total_files);
    println!("  Directories: {}", stats.total_directories);
    println!("  Total size:  {}", format_size(stats.total_size));

    Ok(())
}

/// List all indexed volumes.
fn list_volumes(database: &Database) -> Result<()> {
    let volumes = database.get_all_volumes()?;

    if volumes.is_empty() {
        println!("No volumes indexed yet.");
        return Ok(());
    }

    println!("{}", "Indexed Volumes".bold().underline());
    println!();

    for volume in volumes {
        let status = if volume.is_online {
            "online".green()
        } else {
            "offline".red()
        };

        let label = volume.label.as_deref().unwrap_or("-");

        println!(
            "  {} [{}] {} ({})",
            volume.mount_point.bold(),
            volume.volume_type,
            label,
            status
        );
    }

    Ok(())
}
