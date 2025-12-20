//! CLI configuration.
//!
//! This module provides the `CliConfig` struct that combines user configuration with CLI arguments,
//! where CLI arguments take precedence.

use std::path::PathBuf;

use anyhow::{Context, Result};
use filefind::config::{OutputFormat, UserConfig};
use regex::Regex;

use crate::{Args, OutputFormatArg};

/// Combined configuration from user config and CLI arguments.
///
/// CLI arguments take precedence over user config.
#[allow(clippy::struct_excessive_bools)]
pub struct CliConfig {
    /// Search pattern
    pub pattern: Option<String>,

    /// Use regex pattern for search
    pub regex: bool,

    /// Case-sensitive search
    #[allow(dead_code)]
    pub case_sensitive: bool,

    /// Filter results to specific drives
    pub drives: Vec<String>,

    /// Only show files
    pub files_only: bool,

    /// Only show directories
    pub dirs_only: bool,

    /// Maximum files to show per directory in grouped output
    pub files_per_dir: usize,

    /// Output format
    pub output_format: OutputFormat,

    /// Show index statistics
    pub show_stats: bool,

    /// List all indexed volumes
    pub list_volumes: bool,

    /// Print verbose output
    pub verbose: bool,

    /// Path to the database
    pub database_path: PathBuf,
}

/// Display options for formatting output.
pub struct DisplayOptions {
    /// Only show directories.
    pub directories_only: bool,

    /// Only show files.
    pub files_only: bool,

    /// Maximum files to show per directory in grouped output.
    pub files_per_dir: usize,
}

impl CliConfig {
    /// Build a search config by merging user config with CLI arguments.
    ///
    /// CLI arguments take precedence over user config values.
    ///
    /// # Errors
    /// Returns an error if regex mode is enabled and the pattern is invalid.
    pub fn from_args(args: Args) -> Result<Self> {
        let user_config = UserConfig::load();

        // Validate regex pattern if regex mode is enabled
        if args.regex
            && let Some(ref pattern) = args.pattern
        {
            Regex::new(pattern).with_context(|| format!("Invalid regex pattern: {pattern}"))?;
        }

        // Determine the output format: CLI arg overrides user config
        let output_format = args.output.map_or(user_config.cli.format, OutputFormat::from);

        // Case sensitivity: CLI arg overrides user config
        let case_sensitive = args.case || user_config.cli.case_sensitive;

        Ok(Self {
            pattern: args.pattern,
            regex: args.regex,
            case_sensitive,
            drives: args.drive,
            files_only: args.files,
            dirs_only: args.dirs,
            files_per_dir: args.limit,
            output_format,
            show_stats: args.stats,
            list_volumes: args.list,
            verbose: args.verbose,
            database_path: user_config.database_path(),
        })
    }
}

impl From<OutputFormatArg> for OutputFormat {
    fn from(value: OutputFormatArg) -> Self {
        match value {
            OutputFormatArg::Simple => Self::Simple,
            OutputFormatArg::Detailed => Self::Detailed,
        }
    }
}
