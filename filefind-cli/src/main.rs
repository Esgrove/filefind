//! Command-line interface for filefind file search.

mod cli;
mod config;
mod mover;
mod utils;

use std::path::PathBuf;

use anyhow::Result;
use anyhow::bail;
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;

use filefind::database::Database;
use filefind::{generate_shell_completion, print_error};

use crate::config::CliConfig;

#[allow(clippy::struct_excessive_bools)]
#[derive(Parser)]
#[command(
    author,
    version,
    name = env!("CARGO_BIN_NAME"),
    about
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

    /// Move all matching files to the specified directory
    #[arg(short = 'm', long = "move", value_name = "DIR", conflicts_with = "dirs")]
    pub move_to: Option<PathBuf>,

    /// Force overwrite existing files at the move destination
    #[arg(short = 'F', long, requires = "move_to")]
    pub force: bool,

    /// Maximum number of files to show per directory
    #[arg(short = 'n', long, name = "COUNT", default_value_t = 20)]
    pub limit: usize,

    /// Output format.
    #[arg(short = 'o', long, value_enum, conflicts_with_all = ["list", "info", "name"])]
    pub output: Option<OutputFormatArg>,

    /// List output (shortcut for --output list)
    #[arg(short = 'l', long, conflicts_with_all = ["output", "info", "name"])]
    pub list: bool,

    /// Name-only output (shortcut for --output name)
    #[arg(short = 'N', long, conflicts_with_all = ["output", "list", "info"])]
    pub name: bool,

    /// Sort results by this field.
    #[arg(short = 's', long, value_enum)]
    pub sort: Option<SortBy>,

    /// Info output with file sizes (shortcut for --output info)
    #[arg(short = 'i', long, conflicts_with_all = ["output", "list", "name"])]
    pub info: bool,

    /// Print verbose output.
    #[arg(short = 'v', long)]
    pub verbose: bool,

    /// Exact pattern matches only
    #[arg(short = 'e', long)]
    pub exact: bool,
}

/// Subcommands for the CLI.
#[derive(Debug, Subcommand)]
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
    /// File names only without full paths.
    Name,
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

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    /// Helper to parse CLI args from a string slice, prefixed with the binary name.
    fn parse(args: &[&str]) -> FileFindCli {
        let mut full_args = vec!["filefind"];
        full_args.extend_from_slice(args);
        FileFindCli::try_parse_from(full_args).expect("Failed to parse args")
    }

    /// Helper that expects parsing to fail.
    fn parse_err(args: &[&str]) {
        let mut full_args = vec!["filefind"];
        full_args.extend_from_slice(args);
        assert!(
            FileFindCli::try_parse_from(full_args).is_err(),
            "Expected parse to fail for args: {args:?}"
        );
    }

    // ── No arguments ──────────────────────────────────────────────

    #[test]
    fn test_no_args() {
        let cli = parse(&[]);
        assert!(cli.patterns.is_empty());
        assert!(cli.command.is_none());
        assert!(!cli.all);
        assert!(!cli.regex);
        assert!(!cli.case);
        assert!(!cli.files);
        assert!(!cli.dirs);
        assert!(!cli.verbose);
        assert!(!cli.exact);
        assert!(!cli.force);
        assert!(cli.move_to.is_none());
        assert!(cli.output.is_none());
        assert!(cli.sort.is_none());
        assert!(!cli.list);
        assert!(!cli.name);
        assert!(!cli.info);
        assert_eq!(cli.limit, 20);
        assert!(cli.drive.is_empty());
    }

    // ── Patterns ──────────────────────────────────────────────────

    #[test]
    fn test_single_pattern() {
        let cli = parse(&["myfile"]);
        assert_eq!(cli.patterns, vec!["myfile"]);
    }

    #[test]
    fn test_multiple_patterns() {
        let cli = parse(&["foo", "bar", "baz"]);
        assert_eq!(cli.patterns, vec!["foo", "bar", "baz"]);
    }

    #[test]
    fn test_glob_pattern() {
        let cli = parse(&["*.txt"]);
        assert_eq!(cli.patterns, vec!["*.txt"]);
    }

    #[test]
    fn test_dot_separated_pattern() {
        let cli = parse(&["some.name"]);
        assert_eq!(cli.patterns, vec!["some.name"]);
    }

    // ── Boolean flags ─────────────────────────────────────────────

    #[test]
    fn test_regex_flag_short() {
        let cli = parse(&["-r", "pattern"]);
        assert!(cli.regex);
    }

    #[test]
    fn test_regex_flag_long() {
        let cli = parse(&["--regex", "pattern"]);
        assert!(cli.regex);
    }

    #[test]
    fn test_case_flag() {
        let cli = parse(&["-c", "pattern"]);
        assert!(cli.case);
    }

    #[test]
    fn test_case_flag_long() {
        let cli = parse(&["--case", "pattern"]);
        assert!(cli.case);
    }

    #[test]
    fn test_files_only_flag() {
        let cli = parse(&["-f", "pattern"]);
        assert!(cli.files);
    }

    #[test]
    fn test_dirs_only_flag() {
        let cli = parse(&["-D", "pattern"]);
        assert!(cli.dirs);
    }

    #[test]
    fn test_verbose_flag() {
        let cli = parse(&["-v", "pattern"]);
        assert!(cli.verbose);
    }

    #[test]
    fn test_exact_flag() {
        let cli = parse(&["-e", "pattern"]);
        assert!(cli.exact);
    }

    #[test]
    fn test_all_flag() {
        let cli = parse(&["-a", "foo", "bar"]);
        assert!(cli.all);
    }

    #[test]
    fn test_combined_short_flags() {
        let cli = parse(&["-rcev", "pattern"]);
        assert!(cli.regex);
        assert!(cli.case);
        assert!(cli.exact);
        assert!(cli.verbose);
    }

    // ── Output format ─────────────────────────────────────────────

    #[test]
    fn test_list_output_shortcut() {
        let cli = parse(&["-l", "pattern"]);
        assert!(cli.list);
        assert!(cli.output.is_none());
    }

    #[test]
    fn test_name_output_shortcut() {
        let cli = parse(&["-N", "pattern"]);
        assert!(cli.name);
    }

    #[test]
    fn test_info_output_shortcut() {
        let cli = parse(&["-i", "pattern"]);
        assert!(cli.info);
    }

    #[test]
    fn test_output_list() {
        let cli = parse(&["--output", "list", "pattern"]);
        assert!(matches!(cli.output, Some(OutputFormatArg::List)));
    }

    #[test]
    fn test_output_grouped() {
        let cli = parse(&["--output", "grouped", "pattern"]);
        assert!(matches!(cli.output, Some(OutputFormatArg::Grouped)));
    }

    #[test]
    fn test_output_name() {
        let cli = parse(&["-o", "name", "pattern"]);
        assert!(matches!(cli.output, Some(OutputFormatArg::Name)));
    }

    #[test]
    fn test_output_info() {
        let cli = parse(&["-o", "info", "pattern"]);
        assert!(matches!(cli.output, Some(OutputFormatArg::Info)));
    }

    #[test]
    fn test_output_conflicts_with_list_shortcut() {
        parse_err(&["--output", "list", "-l", "pattern"]);
    }

    #[test]
    fn test_output_conflicts_with_name_shortcut() {
        parse_err(&["--output", "name", "-N", "pattern"]);
    }

    #[test]
    fn test_output_conflicts_with_info_shortcut() {
        parse_err(&["--output", "info", "-i", "pattern"]);
    }

    #[test]
    fn test_list_conflicts_with_name() {
        parse_err(&["-l", "-N", "pattern"]);
    }

    #[test]
    fn test_list_conflicts_with_info() {
        parse_err(&["-l", "-i", "pattern"]);
    }

    // ── Sort ──────────────────────────────────────────────────────

    #[test]
    fn test_sort_by_name() {
        let cli = parse(&["-s", "name", "pattern"]);
        assert!(matches!(cli.sort, Some(SortBy::Name)));
    }

    #[test]
    fn test_sort_by_size() {
        let cli = parse(&["--sort", "size", "pattern"]);
        assert!(matches!(cli.sort, Some(SortBy::Size)));
    }

    #[test]
    fn test_sort_default_is_none() {
        let cli = parse(&["pattern"]);
        assert!(cli.sort.is_none());
    }

    // ── Drive filter ──────────────────────────────────────────────

    #[test]
    fn test_single_drive_filter() {
        let cli = parse(&["-d", "C", "pattern"]);
        assert_eq!(cli.drive, vec!["C"]);
    }

    #[test]
    fn test_multiple_drive_filters() {
        let cli = parse(&["-d", "C", "-d", "D", "pattern"]);
        assert_eq!(cli.drive, vec!["C", "D"]);
    }

    #[test]
    fn test_drive_filter_with_colon() {
        let cli = parse(&["-d", "C:", "pattern"]);
        assert_eq!(cli.drive, vec!["C:"]);
    }

    // ── Limit ─────────────────────────────────────────────────────

    #[test]
    fn test_limit_default() {
        let cli = parse(&["pattern"]);
        assert_eq!(cli.limit, 20);
    }

    #[test]
    fn test_limit_custom() {
        let cli = parse(&["-n", "50", "pattern"]);
        assert_eq!(cli.limit, 50);
    }

    #[test]
    fn test_limit_long() {
        let cli = parse(&["--limit", "100", "pattern"]);
        assert_eq!(cli.limit, 100);
    }

    // ── Move ──────────────────────────────────────────────────────

    #[test]
    fn test_move_to() {
        let cli = parse(&["--move", "C:\\dest", "pattern"]);
        assert_eq!(cli.move_to, Some(PathBuf::from("C:\\dest")));
    }

    #[test]
    fn test_move_short() {
        let cli = parse(&["-m", "C:\\dest", "pattern"]);
        assert_eq!(cli.move_to, Some(PathBuf::from("C:\\dest")));
    }

    #[test]
    fn test_move_with_force() {
        let cli = parse(&["--move", "C:\\dest", "--force", "pattern"]);
        assert!(cli.force);
        assert!(cli.move_to.is_some());
    }

    #[test]
    fn test_force_requires_move() {
        parse_err(&["--force", "pattern"]);
    }

    #[test]
    fn test_move_conflicts_with_dirs() {
        parse_err(&["--move", "C:\\dest", "-D", "pattern"]);
    }

    // ── Subcommands ───────────────────────────────────────────────

    #[test]
    fn test_stats_subcommand() {
        let cli = parse(&["stats"]);
        assert!(matches!(cli.command, Some(Command::Stats)));
    }

    #[test]
    fn test_volumes_subcommand() {
        let cli = parse(&["volumes"]);
        assert!(matches!(cli.command, Some(Command::Volumes { sort: None })));
    }

    #[test]
    fn test_volumes_sort_by_size() {
        let cli = parse(&["volumes", "--sort", "size"]);
        match &cli.command {
            Some(Command::Volumes { sort }) => {
                assert!(matches!(sort, Some(VolumeSortBy::Size)));
            }
            other => panic!("Expected Volumes command, got {other:?}"),
        }
    }

    #[test]
    fn test_volumes_sort_by_files() {
        let cli = parse(&["volumes", "-s", "files"]);
        match &cli.command {
            Some(Command::Volumes { sort }) => {
                assert!(matches!(sort, Some(VolumeSortBy::Files)));
            }
            other => panic!("Expected Volumes command, got {other:?}"),
        }
    }

    #[test]
    fn test_volumes_sort_default_missing_value() {
        let cli = parse(&["volumes", "-s"]);
        match &cli.command {
            Some(Command::Volumes { sort }) => {
                assert!(matches!(sort, Some(VolumeSortBy::Size)));
            }
            other => panic!("Expected Volumes command, got {other:?}"),
        }
    }

    #[test]
    fn test_completion_subcommand_bash() {
        let cli = parse(&["completion", "bash"]);
        assert!(matches!(
            cli.command,
            Some(Command::Completion {
                shell: Shell::Bash,
                install: false
            })
        ));
    }

    #[test]
    fn test_completion_subcommand_with_install() {
        let cli = parse(&["completion", "powershell", "--install"]);
        match &cli.command {
            Some(Command::Completion { shell, install }) => {
                assert!(matches!(shell, Shell::PowerShell));
                assert!(install);
            }
            other => panic!("Expected Completion command, got {other:?}"),
        }
    }

    // ── Invalid args ──────────────────────────────────────────────

    #[test]
    fn test_invalid_output_format() {
        parse_err(&["--output", "invalid", "pattern"]);
    }

    #[test]
    fn test_invalid_sort() {
        parse_err(&["--sort", "invalid", "pattern"]);
    }

    // ── Verify command_factory ─────────────────────────────────────

    #[test]
    fn test_command_factory_debug_assert() {
        // Ensures the clap configuration is internally consistent
        FileFindCli::command().debug_assert();
    }
}
