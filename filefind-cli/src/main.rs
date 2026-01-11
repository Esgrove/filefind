//! Command-line interface for filefind file search.

mod cli;
mod config;

use anyhow::Result;
use anyhow::bail;
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;

use filefind::database::Database;
use filefind::{generate_shell_completion, print_error};

use crate::config::CliConfig;

/// Fast file search using the filefind index
#[allow(clippy::struct_excessive_bools)]
#[derive(Parser)]
#[command(
    author,
    version,
    name = env!("CARGO_BIN_NAME"),
    about = "Fast file search using the filefind index"
)]
pub struct FileFindCli {
    /// Subcommand to execute
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Search patterns (supports glob patterns like *.txt)
    pub patterns: Vec<String>,

    /// Match all patterns (logical AND)
    #[arg(short = 'a', long)]
    pub all: bool,

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
    #[arg(short = 'o', long, value_enum, conflicts_with_all = ["list", "info"])]
    pub output: Option<OutputFormatArg>,

    /// List output (shortcut for --output list)
    #[arg(short = 'l', long, conflicts_with_all = ["output", "info"])]
    pub list: bool,

    /// Sort results by this field.
    #[arg(short = 's', long, value_enum)]
    pub sort: Option<SortBy>,

    /// Info output with file sizes (shortcut for --output info)
    #[arg(short = 'i', long, conflicts_with_all = ["output", "list"])]
    pub info: bool,

    /// Print verbose output.
    #[arg(short = 'v', long)]
    pub verbose: bool,

    /// Exact pattern matches only
    #[arg(short = 'e', long)]
    pub exact: bool,
}

/// Subcommands for the CLI.
#[derive(Subcommand)]
pub enum Command {
    /// Show index statistics
    Stats,

    /// List all indexed volumes
    Volumes {
        /// Sort volumes by this field
        #[arg(short, long, value_enum, num_args = 0..=1, default_missing_value = "size")]
        sort: Option<VolumeSortBy>,
    },

    /// Generate shell completion scripts
    Completion {
        /// Shell to generate completion for
        #[arg(value_enum)]
        shell: Shell,

        /// Install the completion script to the appropriate location
        #[arg(short = 'I', long)]
        install: bool,
    },
}

/// Output format argument for CLI.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormatArg {
    /// List of paths without type or size information.
    List,
    /// Files grouped by directory.
    Grouped,
    /// Detailed info format with file size.
    Info,
}

/// Sort order for volumes listing.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum VolumeSortBy {
    /// Sort alphabetically by name (default).
    #[default]
    Name,
    /// Sort by total size.
    Size,
    /// Sort by number of files.
    Files,
}

/// Sort order for search results.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum SortBy {
    /// Sort alphabetically by name (default).
    #[default]
    Name,
    /// Sort by file size (largest first).
    Size,
}

fn main() -> Result<()> {
    let args = FileFindCli::parse();

    // Handle completion subcommand early (no config needed)
    if let Some(Command::Completion { shell, install }) = &args.command {
        return generate_shell_completion(*shell, FileFindCli::command(), *install, env!("CARGO_BIN_NAME"));
    }

    // Build the final config from user config and CLI args
    let config = CliConfig::from_args(args)?;

    // Check the database exists for all commands that need it
    if !config.database_path.exists() {
        print_error!("Database not found at: {}", config.database_path.display());
        bail!("Run the filefind daemon first to build the index");
    }

    let database = Database::open(&config.database_path)?;

    // Handle subcommands
    match &config.command {
        Some(Command::Stats) => cli::show_stats(&database),
        Some(Command::Volumes { sort }) => cli::list_volumes(&database, sort.unwrap_or(VolumeSortBy::Name)),
        Some(Command::Completion { .. }) => unreachable!("Handled above"),
        None => cli::run_search(&config, &database),
    }
}
