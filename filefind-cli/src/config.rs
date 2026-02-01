//! CLI configuration.
//!
//! This module provides the `CliConfig` struct that combines user configuration with CLI arguments,
//! where CLI arguments take precedence.

use std::path::PathBuf;

use anyhow::{Context, Result};
use regex::Regex;

use filefind::config::{OutputFormat, UserConfig};

use crate::{Command, FileFindCli, OutputFormatArg, SortBy};

/// Combined configuration from user config and CLI arguments.
///
/// CLI arguments take precedence over user config.
#[allow(clippy::struct_excessive_bools)]
pub struct CliConfig {
    /// Subcommand to execute
    pub command: Option<Command>,

    /// Search patterns
    pub patterns: Vec<String>,

    /// Match all patterns (AND) instead of any pattern (OR)
    pub match_all: bool,

    /// Use regex pattern for search
    pub regex: bool,

    /// Case-sensitive search
    pub case_sensitive: bool,

    /// Filter results to specific drives
    pub drives: Vec<String>,

    /// Only show files
    pub files_only: bool,

    /// Only show directories
    pub directories_only: bool,

    /// Maximum files to show per directory in grouped output
    pub files_per_dir: usize,

    /// Output format
    pub output_format: OutputFormat,

    /// Sort order for results
    pub sort_by: SortBy,

    /// Print verbose output
    pub verbose: bool,

    /// Path to the database
    pub database_path: PathBuf,
}

impl CliConfig {
    /// Build a search config by merging user config with CLI arguments.
    ///
    /// CLI arguments take precedence over user config values.
    ///
    /// # Errors
    /// Returns an error if regex mode is enabled and the pattern is invalid.
    pub fn from_args(args: FileFindCli) -> Result<Self> {
        let user_config = UserConfig::load();

        // Trim patterns and filter empty strings
        let trimmed_patterns: Vec<String> = args
            .patterns
            .iter()
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect();

        // Expand patterns unless exact mode, regex mode, or AND mode is enabled
        // (pattern expansion doesn't make sense for AND mode where all patterns must match)
        let patterns = if args.exact || args.regex || args.all {
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
        // --list and --info flags are shortcuts for --output list/info
        let output_format = if args.list {
            OutputFormat::List
        } else if args.info {
            OutputFormat::Info
        } else {
            args.output.map_or(user_config.cli.format, OutputFormat::from)
        };

        // Case sensitivity: CLI arg overrides user config
        let case_sensitive = args.case || user_config.cli.case_sensitive;

        Ok(Self {
            command: args.command,
            patterns,
            match_all: args.all,
            regex: args.regex,
            case_sensitive,
            drives: args.drive,
            files_only: args.files,
            directories_only: args.dirs,
            files_per_dir: args.limit,
            output_format,
            sort_by: args.sort.unwrap_or(SortBy::Name),
            verbose: args.verbose,
            database_path: user_config.database_path(),
        })
    }

    /// Expand patterns by adding variants for dot-separated and space-separated patterns.
    ///
    /// For example:
    /// - `some.name` becomes `["some.name", "some name", "somename"]`
    /// - `some name` becomes `["some name", "some.name", "somename"]`
    ///
    /// This helps match different naming conventions (dots, spaces, or no separator).
    fn expand_patterns(patterns: &[String]) -> Vec<String> {
        let mut expanded = Vec::new();

        for pattern in patterns {
            expanded.push(pattern.clone());

            // Skip glob patterns with wildcards
            if pattern.contains('*') || pattern.contains('?') {
                continue;
            }

            // If pattern contains dots, add space-separated and no-separator variants
            if pattern.contains('.') {
                let space_variant = pattern.replace('.', " ");
                if !space_variant.is_empty() && space_variant != *pattern {
                    expanded.push(space_variant);
                }

                let empty_variant = pattern.replace('.', "");
                if !empty_variant.is_empty() && empty_variant != *pattern {
                    expanded.push(empty_variant);
                }
            }
            // If pattern contains spaces, add dot-separated and no-separator variants
            else if pattern.contains(' ') {
                let dot_variant = pattern.replace(' ', ".");
                if !dot_variant.is_empty() && dot_variant != *pattern {
                    expanded.push(dot_variant);
                }

                let empty_variant = pattern.replace(' ', "");
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
            OutputFormatArg::List => Self::List,
            OutputFormatArg::Grouped => Self::Grouped,
            OutputFormatArg::Info => Self::Info,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FileFindCli;

    /// Helper to create Args with patterns for testing.
    fn args_with_patterns(patterns: Vec<&str>) -> FileFindCli {
        FileFindCli {
            command: None,
            patterns: patterns.into_iter().map(String::from).collect(),
            all: false,
            regex: false,
            case: false,
            drive: Vec::new(),
            files: false,
            dirs: false,
            limit: 20,
            output: None,
            list: false,
            sort: Some(SortBy::Name),
            info: false,
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
    fn test_expand_patterns_single_space() {
        let patterns = vec!["some name".to_string()];
        let expanded = CliConfig::expand_patterns(&patterns);
        assert_eq!(expanded, vec!["some name", "some.name", "somename"]);
    }

    #[test]
    fn test_expand_patterns_multiple_spaces() {
        let patterns = vec!["some name here".to_string()];
        let expanded = CliConfig::expand_patterns(&patterns);
        assert_eq!(expanded, vec!["some name here", "some.name.here", "somenamehere"]);
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

    #[test]
    fn test_from_args_all_mode_disables_expansion() {
        let mut args = args_with_patterns(vec!["some.name", "test.file"]);
        args.all = true;
        let config = CliConfig::from_args(args).unwrap();
        // AND mode should not expand patterns
        assert_eq!(config.patterns, vec!["some.name", "test.file"]);
        assert!(config.match_all);
    }

    #[test]
    fn test_from_args_all_mode_single_pattern() {
        let mut args = args_with_patterns(vec!["config"]);
        args.all = true;
        let config = CliConfig::from_args(args).unwrap();
        assert_eq!(config.patterns, vec!["config"]);
        assert!(config.match_all);
    }

    #[test]
    fn test_from_args_all_mode_with_globs() {
        let mut args = args_with_patterns(vec!["*.txt", "*config*"]);
        args.all = true;
        let config = CliConfig::from_args(args).unwrap();
        assert_eq!(config.patterns, vec!["*.txt", "*config*"]);
        assert!(config.match_all);
    }

    #[test]
    fn test_from_args_all_mode_with_regex() {
        let mut args = args_with_patterns(vec![r"\d+", r"\.txt$"]);
        args.all = true;
        args.regex = true;
        let config = CliConfig::from_args(args).unwrap();
        assert_eq!(config.patterns, vec![r"\d+", r"\.txt$"]);
        assert!(config.match_all);
        assert!(config.regex);
    }

    #[test]
    fn test_from_args_all_mode_empty_patterns() {
        let mut args = args_with_patterns(vec![]);
        args.all = true;
        let config = CliConfig::from_args(args).unwrap();
        assert!(config.patterns.is_empty());
        assert!(config.match_all);
    }

    #[test]
    fn test_from_args_all_mode_trims_and_filters() {
        let mut args = args_with_patterns(vec!["  config  ", "", "  ", "json"]);
        args.all = true;
        let config = CliConfig::from_args(args).unwrap();
        // Should trim whitespace and filter empty patterns
        assert_eq!(config.patterns, vec!["config", "json"]);
        assert!(config.match_all);
    }

    #[test]
    fn test_from_args_all_mode_preserves_dot_patterns() {
        // In AND mode, dot patterns should NOT be expanded
        let mut args = args_with_patterns(vec!["some.config", "test.json"]);
        args.all = true;
        let config = CliConfig::from_args(args).unwrap();
        // Patterns should remain as-is, not expanded
        assert_eq!(config.patterns, vec!["some.config", "test.json"]);
    }

    #[test]
    fn test_from_args_all_mode_mixed_pattern_types() {
        // Mix of plain, glob, and dot-separated patterns
        let mut args = args_with_patterns(vec!["config", "*.json", "test.file"]);
        args.all = true;
        let config = CliConfig::from_args(args).unwrap();
        assert_eq!(config.patterns, vec!["config", "*.json", "test.file"]);
        assert!(config.match_all);
    }

    #[test]
    fn test_from_args_all_mode_with_case_sensitive() {
        let mut args = args_with_patterns(vec!["Config", "JSON"]);
        args.all = true;
        args.case = true;
        let config = CliConfig::from_args(args).unwrap();
        assert_eq!(config.patterns, vec!["Config", "JSON"]);
        assert!(config.match_all);
        assert!(config.case_sensitive);
    }

    #[test]
    fn test_from_args_default_is_or_mode() {
        let args = args_with_patterns(vec!["config", "json"]);
        let config = CliConfig::from_args(args).unwrap();
        assert!(!config.match_all); // Default should be OR mode (match_all = false)
    }

    #[test]
    fn test_from_args_all_mode_with_exact_flag() {
        // Both --all and --exact should disable expansion
        let mut args = args_with_patterns(vec!["some.name"]);
        args.all = true;
        args.exact = true;
        let config = CliConfig::from_args(args).unwrap();
        assert_eq!(config.patterns, vec!["some.name"]);
        assert!(config.match_all);
    }

    #[test]
    fn test_from_args_all_mode_many_patterns() {
        let mut args = args_with_patterns(vec!["a", "b", "c", "d", "e"]);
        args.all = true;
        let config = CliConfig::from_args(args).unwrap();
        assert_eq!(config.patterns, vec!["a", "b", "c", "d", "e"]);
        assert!(config.match_all);
    }

    #[test]
    fn test_from_args_regex_default_is_or_mode() {
        // Multiple regex patterns should use OR mode by default (match_all = false)
        let mut args = args_with_patterns(vec![r"\d+", r"\.txt$"]);
        args.regex = true;
        let config = CliConfig::from_args(args).unwrap();
        assert!(!config.match_all); // Should be OR mode by default
        assert!(config.regex);
        assert_eq!(config.patterns, vec![r"\d+", r"\.txt$"]);
    }

    #[test]
    fn test_from_args_regex_with_all_flag_is_and_mode() {
        // Regex patterns with --all flag should use AND mode
        let mut args = args_with_patterns(vec![r"\d+", r"\.txt$"]);
        args.regex = true;
        args.all = true;
        let config = CliConfig::from_args(args).unwrap();
        assert!(config.match_all); // Should be AND mode with --all
        assert!(config.regex);
        assert_eq!(config.patterns, vec![r"\d+", r"\.txt$"]);
    }

    #[test]
    fn test_from_args_regex_single_pattern_or_mode() {
        // Single regex pattern in OR mode
        let mut args = args_with_patterns(vec![r"test.*file"]);
        args.regex = true;
        let config = CliConfig::from_args(args).unwrap();
        assert!(!config.match_all);
        assert!(config.regex);
    }

    #[test]
    fn test_from_args_regex_single_pattern_and_mode() {
        // Single regex pattern in AND mode (--all flag)
        let mut args = args_with_patterns(vec![r"test.*file"]);
        args.regex = true;
        args.all = true;
        let config = CliConfig::from_args(args).unwrap();
        assert!(config.match_all);
        assert!(config.regex);
    }

    #[test]
    fn test_from_args_multiple_regex_patterns_no_expansion() {
        // Regex mode should not expand patterns regardless of dots
        let mut args = args_with_patterns(vec![r"some\.name", r"test\.file"]);
        args.regex = true;
        let config = CliConfig::from_args(args).unwrap();
        // Patterns should NOT be expanded in regex mode
        assert_eq!(config.patterns, vec![r"some\.name", r"test\.file"]);
        assert!(!config.match_all); // Default OR mode
    }

    #[test]
    fn test_from_args_regex_and_mode_no_expansion() {
        // Regex + AND mode should not expand patterns
        let mut args = args_with_patterns(vec![r"config\.json", r"settings"]);
        args.regex = true;
        args.all = true;
        let config = CliConfig::from_args(args).unwrap();
        assert_eq!(config.patterns, vec![r"config\.json", r"settings"]);
        assert!(config.match_all);
        assert!(config.regex);
    }
}
