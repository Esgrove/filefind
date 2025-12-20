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
    /// Search patterns
    pub patterns: Vec<String>,

    /// Use regex pattern for search
    pub regex: bool,

    /// Case-sensitive search
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

        // Trim patterns and filter empty strings
        let trimmed_patterns: Vec<String> = args
            .patterns
            .iter()
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect();

        // Expand patterns unless exact mode or regex mode is enabled
        let patterns = if args.exact || args.regex {
            trimmed_patterns
        } else {
            Self::expand_patterns(&trimmed_patterns)
        };

        // Validate regex patterns if regex mode is enabled
        if args.regex {
            for pattern in &patterns {
                Regex::new(pattern).with_context(|| format!("Invalid regex pattern: {pattern}"))?;
            }
        }

        // Determine the output format: CLI arg overrides user config
        let output_format = args.output.map_or(user_config.cli.format, OutputFormat::from);

        // Case sensitivity: CLI arg overrides user config
        let case_sensitive = args.case || user_config.cli.case_sensitive;

        Ok(Self {
            patterns,
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

    /// Expand patterns by adding variants for dot-separated patterns.
    ///
    /// For example, `some.name` becomes `["some.name", "some name", "somename"]`.
    /// This helps match different naming conventions (dots, spaces, or no separator).
    fn expand_patterns(patterns: &[String]) -> Vec<String> {
        let mut expanded = Vec::new();

        for pattern in patterns {
            expanded.push(pattern.clone());

            // If pattern contains dots (but isn't a glob pattern with wildcards),
            // also add space-separated and no-separator variants
            if pattern.contains('.') && !pattern.contains('*') && !pattern.contains('?') {
                let space_variant = pattern.replace('.', " ");
                if !space_variant.is_empty() && space_variant != *pattern {
                    expanded.push(space_variant);
                }

                let empty_variant = pattern.replace('.', "");
                if !empty_variant.is_empty() && empty_variant != *pattern {
                    expanded.push(empty_variant);
                }
            }
        }

        expanded
    }
}

impl From<OutputFormatArg> for OutputFormat {
    fn from(value: OutputFormatArg) -> Self {
        match value {
            OutputFormatArg::Simple => Self::Simple,
            OutputFormatArg::Grouped => Self::Grouped,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Args;

    /// Helper to create Args with patterns for testing.
    fn args_with_patterns(patterns: Vec<&str>) -> Args {
        Args {
            patterns: patterns.into_iter().map(String::from).collect(),
            regex: false,
            case: false,
            drive: Vec::new(),
            files: false,
            dirs: false,
            limit: 20,
            output: None,
            stats: false,
            list: false,
            completion: None,
            verbose: false,
            exact: false,
        }
    }

    #[test]
    fn test_expand_patterns_single_dot() {
        let patterns = vec!["some.name".to_string()];
        let expanded = CliConfig::expand_patterns(&patterns);
        assert_eq!(expanded, vec!["some.name", "some name", "somename"]);
    }

    #[test]
    fn test_expand_patterns_multiple_dots() {
        let patterns = vec!["some.name.here".to_string()];
        let expanded = CliConfig::expand_patterns(&patterns);
        assert_eq!(expanded, vec!["some.name.here", "some name here", "somenamehere"]);
    }

    #[test]
    fn test_expand_patterns_no_dots() {
        let patterns = vec!["somename".to_string()];
        let expanded = CliConfig::expand_patterns(&patterns);
        assert_eq!(expanded, vec!["somename"]);
    }

    #[test]
    fn test_expand_patterns_glob_not_expanded() {
        let patterns = vec!["*.txt".to_string()];
        let expanded = CliConfig::expand_patterns(&patterns);
        assert_eq!(expanded, vec!["*.txt"]);
    }

    #[test]
    fn test_expand_patterns_question_mark_not_expanded() {
        let patterns = vec!["file?.txt".to_string()];
        let expanded = CliConfig::expand_patterns(&patterns);
        assert_eq!(expanded, vec!["file?.txt"]);
    }

    #[test]
    fn test_expand_patterns_multiple_patterns() {
        let patterns = vec!["some.name".to_string(), "other".to_string()];
        let expanded = CliConfig::expand_patterns(&patterns);
        assert_eq!(expanded, vec!["some.name", "some name", "somename", "other"]);
    }

    #[test]
    fn test_expand_patterns_only_dots_filtered() {
        let patterns = vec!["...".to_string()];
        let expanded = CliConfig::expand_patterns(&patterns);
        // Original is kept, space variant "   " is not empty so kept, empty variant "" is filtered
        assert_eq!(expanded, vec!["...", "   "]);
    }

    #[test]
    fn test_expand_patterns_empty_input() {
        let patterns: Vec<String> = Vec::new();
        let expanded = CliConfig::expand_patterns(&patterns);
        assert!(expanded.is_empty());
    }

    #[test]
    fn test_from_args_trims_patterns() {
        let mut args = args_with_patterns(vec!["  some.name  ", "  other  "]);
        args.exact = true; // Use exact to see trimmed patterns without expansion
        let config = CliConfig::from_args(args).unwrap();
        assert_eq!(config.patterns, vec!["some.name", "other"]);
    }

    #[test]
    fn test_from_args_filters_empty_patterns() {
        let mut args = args_with_patterns(vec!["some.name", "", "  ", "other"]);
        args.exact = true;
        let config = CliConfig::from_args(args).unwrap();
        assert_eq!(config.patterns, vec!["some.name", "other"]);
    }

    #[test]
    fn test_from_args_exact_disables_expansion() {
        let mut args = args_with_patterns(vec!["some.name"]);
        args.exact = true;
        let config = CliConfig::from_args(args).unwrap();
        assert_eq!(config.patterns, vec!["some.name"]);
    }

    #[test]
    fn test_from_args_regex_disables_expansion() {
        let mut args = args_with_patterns(vec!["some.name"]);
        args.regex = true;
        let config = CliConfig::from_args(args).unwrap();
        assert_eq!(config.patterns, vec!["some.name"]);
    }

    #[test]
    fn test_from_args_expands_by_default() {
        let args = args_with_patterns(vec!["some.name"]);
        let config = CliConfig::from_args(args).unwrap();
        assert_eq!(config.patterns, vec!["some.name", "some name", "somename"]);
    }

    #[test]
    fn test_from_args_multiple_patterns_expanded() {
        let args = args_with_patterns(vec!["some.name", "test.file"]);
        let config = CliConfig::from_args(args).unwrap();
        assert_eq!(
            config.patterns,
            vec![
                "some.name",
                "some name",
                "somename",
                "test.file",
                "test file",
                "testfile"
            ]
        );
    }

    #[test]
    fn test_from_args_mixed_patterns() {
        let args = args_with_patterns(vec!["some.name", "plain", "*.txt"]);
        let config = CliConfig::from_args(args).unwrap();
        assert_eq!(
            config.patterns,
            vec!["some.name", "some name", "somename", "plain", "*.txt"]
        );
    }
}
