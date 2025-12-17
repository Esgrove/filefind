//! Command-line interface for filefind file search.

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

    /// Search only in a specific drive ("C:" or "D:")
    #[arg(short = 'd', long, name = "DRIVE")]
    drive: Option<String>,

    /// Only show files
    #[arg(short = 'f', long)]
    files: bool,

    /// Only show directories
    #[arg(short = 'D', long)]
    dirs: bool,

    /// Maximum number of results to show
    #[arg(short = 'n', long, name = "COUNT")]
    limit: Option<usize>,

    /// Output format.
    #[arg(short = 'o', long, value_enum)]
    output: Option<OutputFormatArg>,

    /// Show full paths instead of just filenames
    #[arg(short = 'p', long)]
    full_path: bool,

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
    Json,
}

impl From<OutputFormatArg> for OutputFormat {
    fn from(value: OutputFormatArg) -> Self {
        match value {
            OutputFormatArg::Simple => Self::Simple,
            OutputFormatArg::Detailed => Self::Detailed,
            OutputFormatArg::Json => Self::Json,
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

    // Determine result limit
    let limit = args.limit.unwrap_or(config.cli.max_results);
    let effective_limit = if limit == 0 { usize::MAX } else { limit };

    // Perform the search
    let start_time = Instant::now();

    let results = if args.regex {
        // For now, fall back to glob search - regex support can be added later
        database.search_by_name(&pattern, effective_limit)?
    } else if pattern.contains('*') || pattern.contains('?') {
        database.search_by_glob(&pattern, effective_limit)?
    } else {
        database.search_by_name(&pattern, effective_limit)?
    };

    let search_duration = start_time.elapsed();

    // Filter results
    let results: Vec<_> = results
        .into_iter()
        .filter(|entry| {
            if args.files && entry.is_directory {
                return false;
            }
            if args.dirs && !entry.is_directory {
                return false;
            }
            true
        })
        .collect();

    // Display results
    match output_format {
        OutputFormat::Simple => display_simple(&results, args.full_path),
        OutputFormat::Detailed => display_detailed(&results),
        OutputFormat::Json => display_json(&results),
    }

    // Show search stats if verbose
    if args.verbose {
        eprintln!(
            "\n{} results in {:.2}ms",
            results.len(),
            search_duration.as_secs_f64() * 1000.0
        );
    }

    Ok(())
}

/// Display results in simple format.
fn display_simple(results: &[filefind_common::types::FileEntry], full_path: bool) {
    for entry in results {
        if full_path {
            println!("{}", entry.full_path);
        } else {
            // Show the filename with the parent directory for context
            let path = PathBuf::from(&entry.full_path);
            if let Some(parent) = path.parent() {
                if let Some(parent_name) = parent.file_name() {
                    println!(
                        "{}{}{}",
                        parent_name.to_string_lossy(),
                        std::path::MAIN_SEPARATOR,
                        entry.name
                    );
                } else {
                    println!("{}", entry.name);
                }
            } else {
                println!("{}", entry.name);
            }
        }
    }
}

/// Display results in detailed format.
fn display_detailed(results: &[filefind_common::types::FileEntry]) {
    for entry in results {
        let type_indicator = if entry.is_directory {
            "DIR ".cyan()
        } else {
            "FILE".normal()
        };

        let size_str = if entry.is_directory {
            "-".to_string()
        } else {
            format_size(entry.size)
        };

        println!("{} {:>10}  {}", type_indicator, size_str, entry.full_path.bold());
    }
}

/// Display results in JSON format.
fn display_json(results: &[filefind_common::types::FileEntry]) {
    // Simple JSON output without pulling in serde_json
    println!("[");
    for (index, entry) in results.iter().enumerate() {
        let comma = if index < results.len() - 1 { "," } else { "" };
        println!(
            r#"  {{"name": "{}", "path": "{}", "is_directory": {}, "size": {}}}{}"#,
            escape_json(&entry.name),
            escape_json(&entry.full_path),
            entry.is_directory,
            entry.size,
            comma
        );
    }
    println!("]");
}

/// Escape special characters for JSON string.
fn escape_json(string: &str) -> String {
    string
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
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
