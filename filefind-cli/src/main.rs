//! Command-line interface for filefind file search.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

use anyhow::Result;
use clap::{CommandFactory, Parser, ValueEnum};
use clap_complete::Shell;
use colored::Colorize;

use filefind_common::config::{OutputFormat, UserConfig};
use filefind_common::database::Database;
use filefind_common::format_size;

/// Fast file search using the filefind index
#[allow(clippy::struct_excessive_bools)]
#[derive(Parser)]
#[command(
    author,
    version,
    name = "filefind",
    about = "Fast file search using the filefind index"
)]
struct Args {
    /// Search pattern (supports glob patterns like *.txt)
    pattern: Option<String>,

    /// Use regex pattern for search
    #[arg(short = 'r', long)]
    regex: bool,

    /// Case-sensitive search
    #[arg(short = 'c', long)]
    case: bool,

    /// Search only in specific drives. Accepts: "C", "C:", or "C:\"
    #[arg(short = 'd', long, name = "DRIVE", action = clap::ArgAction::Append)]
    drive: Vec<String>,

    /// Only show files
    #[arg(short = 'f', long)]
    files: bool,

    /// Only show directories
    #[arg(short = 'D', long)]
    dirs: bool,

    /// Maximum number of file results to show (does not affect directories)
    #[arg(short = 'n', long, name = "COUNT")]
    limit: Option<usize>,

    /// Maximum files to show per directory in grouped output
    #[arg(long, name = "COUNT", default_value = "20")]
    files_per_dir: usize,

    /// Output format.
    #[arg(short = 'o', long, value_enum)]
    output: Option<OutputFormatArg>,

    /// Show index statistics
    #[arg(short = 's', long)]
    stats: bool,

    /// List all indexed volumes
    #[arg(short = 'l', long)]
    list: bool,

    /// Generate shell completion
    #[arg(short = 'C', long, name = "SHELL")]
    completion: Option<Shell>,

    /// Print verbose output.
    #[arg(short = 'V', long)]
    verbose: bool,
}

/// Output format argument for CLI.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormatArg {
    Simple,
    Detailed,
}

impl From<OutputFormatArg> for OutputFormat {
    fn from(value: OutputFormatArg) -> Self {
        match value {
            OutputFormatArg::Simple => Self::Simple,
            OutputFormatArg::Detailed => Self::Detailed,
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Handle shell completion generation
    if let Some(shell) = args.completion {
        generate_completion(shell);
        return Ok(());
    }

    // Load configuration
    let config = UserConfig::load();

    // Open the database
    let database_path = config.database_path();
    if !database_path.exists() {
        eprintln!("{}: Database not found at {}", "Error".red(), database_path.display());
        eprintln!("Run the filefind daemon first to build the index.");
        std::process::exit(1);
    }

    let database = Database::open(&database_path)?;

    // Handle special commands
    if args.stats {
        return show_stats(&database);
    }

    if args.list {
        return list_volumes(&database);
    }

    // Require a search pattern for regular search
    let Some(pattern) = args.pattern else {
        eprintln!("{}: No search pattern provided", "Error".red());
        eprintln!("Usage: filefind <pattern>");
        eprintln!("       filefind --stats");
        eprintln!("       filefind --list-volumes");
        std::process::exit(1);
    };

    // Determine output format
    let output_format = args.output.map_or(config.cli.format, OutputFormat::from);

    // Determine result limit (only applies to files)
    let file_limit = args.limit.unwrap_or(config.cli.max_results);
    let effective_file_limit = if file_limit == 0 { usize::MAX } else { file_limit };

    // Perform the search - fetch more results since limit only applies to files
    let start_time = Instant::now();

    let results = if args.regex {
        // For now, fall back to glob search - regex support can be added later
        database.search_by_name(&pattern, usize::MAX)?
    } else if pattern.contains('*') || pattern.contains('?') {
        database.search_by_glob(&pattern, usize::MAX)?
    } else {
        database.search_by_name(&pattern, usize::MAX)?
    };

    let search_duration = start_time.elapsed();

    // Filter results by drive
    let results: Vec<_> = results
        .into_iter()
        .filter(|entry| {
            if !args.drive.is_empty() {
                let entry_drive = entry.full_path.chars().next().map(|c| c.to_ascii_uppercase());
                let matches_drive = entry_drive.is_some_and(|drive_char| {
                    args.drive
                        .iter()
                        .any(|d| d.chars().next().is_some_and(|c| c.to_ascii_uppercase() == drive_char))
                });
                if !matches_drive {
                    return false;
                }
            }
            true
        })
        .collect();

    // Separate directories and files
    let (directories, files): (Vec<_>, Vec<_>) = results.iter().partition(|e| e.is_directory);

    // Apply limit only to files
    let limited_files: Vec<_> = files.into_iter().take(effective_file_limit).collect();

    // Display results based on mode
    let display_options = DisplayOptions {
        dirs_only: args.dirs,
        files_only: args.files,
        files_per_dir: args.files_per_dir,
    };

    match output_format {
        OutputFormat::Simple => display_simple(&directories, &limited_files, &display_options),
        OutputFormat::Detailed => display_detailed(&directories, &limited_files, &display_options),
    }

    // Show search stats if verbose
    if args.verbose {
        let total_results = directories.len() + limited_files.len();
        eprintln!(
            "\n{} results ({} directories, {} files) in {:.2}ms",
            total_results,
            directories.len(),
            limited_files.len(),
            search_duration.as_secs_f64() * 1000.0
        );
    }

    Ok(())
}

/// Display options for formatting output.
struct DisplayOptions {
    dirs_only: bool,
    files_only: bool,
    files_per_dir: usize,
}

/// Display results in simple format.
fn display_simple(
    directories: &[&filefind_common::types::FileEntry],
    files: &[&filefind_common::types::FileEntry],
    options: &DisplayOptions,
) {
    if options.files_only {
        // Files only mode: show full paths
        for file in files {
            println!("{}", file.full_path);
        }
    } else if options.dirs_only {
        // Dirs only mode: show full path with file count
        for directory in directories {
            let file_count = count_files_in_directory(files, &directory.full_path);
            if file_count > 0 {
                println!("{} ({} files)", directory.full_path, file_count);
            } else {
                println!("{}", directory.full_path);
            }
        }
    } else {
        // Normal mode: group files under directories
        display_grouped(directories, files, options.files_per_dir);
    }
}

/// Display results grouped by directory.
fn display_grouped(
    directories: &[&filefind_common::types::FileEntry],
    files: &[&filefind_common::types::FileEntry],
    files_per_dir: usize,
) {
    // Group files by their parent directory
    let mut files_by_dir: HashMap<String, Vec<&filefind_common::types::FileEntry>> = HashMap::new();
    for file in files {
        let parent = PathBuf::from(&file.full_path)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        files_by_dir.entry(parent).or_default().push(file);
    }

    // First, show matched directories with their files
    for directory in directories {
        println!("{}", directory.full_path.bold());
        if let Some(dir_files) = files_by_dir.get(&directory.full_path) {
            let total_files = dir_files.len();
            for file in dir_files.iter().take(files_per_dir) {
                println!("  {}", file.name);
            }
            if total_files > files_per_dir {
                println!("  {} (+{} more files)", "...".dimmed(), total_files - files_per_dir);
            }
        }
    }

    // Then show files in directories that weren't matched
    let matched_dirs: std::collections::HashSet<_> = directories.iter().map(|d| &d.full_path).collect();

    let mut other_dirs: Vec<_> = files_by_dir.keys().filter(|dir| !matched_dirs.contains(*dir)).collect();
    other_dirs.sort();

    for dir_path in other_dirs {
        if let Some(dir_files) = files_by_dir.get(dir_path) {
            println!("{}", dir_path.bold());
            let total_files = dir_files.len();
            for file in dir_files.iter().take(files_per_dir) {
                println!("  {}", file.name);
            }
            if total_files > files_per_dir {
                println!("  {} (+{} more files)", "...".dimmed(), total_files - files_per_dir);
            }
        }
    }
}

/// Count files that are directly inside a directory.
fn count_files_in_directory(files: &[&filefind_common::types::FileEntry], dir_path: &str) -> usize {
    files
        .iter()
        .filter(|f| {
            PathBuf::from(&f.full_path)
                .parent()
                .is_some_and(|p| p.to_string_lossy() == dir_path)
        })
        .count()
}

/// Display results in detailed format.
fn display_detailed(
    directories: &[&filefind_common::types::FileEntry],
    files: &[&filefind_common::types::FileEntry],
    options: &DisplayOptions,
) {
    if options.files_only {
        for file in files {
            let size_str = format_size(file.size);
            println!("{} {:>10}  {}", "FILE".normal(), size_str, file.full_path.bold());
        }
    } else if options.dirs_only {
        for directory in directories {
            let file_count = count_files_in_directory(files, &directory.full_path);
            if file_count > 0 {
                println!(
                    "{} {:>10}  {} ({} files)",
                    "DIR ".cyan(),
                    "-",
                    directory.full_path.bold(),
                    file_count
                );
            } else {
                println!("{} {:>10}  {}", "DIR ".cyan(), "-", directory.full_path.bold());
            }
        }
    } else {
        // Show all directories first, then all files
        for directory in directories {
            println!("{} {:>10}  {}", "DIR ".cyan(), "-", directory.full_path.bold());
        }
        for file in files {
            let size_str = format_size(file.size);
            println!("{} {:>10}  {}", "FILE".normal(), size_str, file.full_path.bold());
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

/// Generate shell completion script.
fn generate_completion(shell: Shell) {
    let mut command = Args::command();
    let name = command.get_name().to_string();
    clap_complete::generate(shell, &mut command, name, &mut std::io::stdout());
}
