//! User configuration handling for filefind.
//!
//! Configuration is read from `~/.config/filefind.toml`.

use std::fs;
use std::path::PathBuf;
use std::sync::LazyLock;

use serde::Deserialize;
use tracing::warn;

const PROJECT_NAME: &str = "filefind";

/// Path to the user configuration file.
pub static CONFIG_PATH: LazyLock<Option<PathBuf>> = LazyLock::new(|| {
    let home_dir = dirs::home_dir()?;
    let config_path = home_dir.join(".config").join(format!("{PROJECT_NAME}.toml"));

    if config_path.exists() { Some(config_path) } else { None }
});

/// Path to the default database file.
pub static DATABASE_PATH: LazyLock<PathBuf> = LazyLock::new(|| {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(PROJECT_NAME)
        .join(format!("{PROJECT_NAME}.db"))
});

/// Root configuration structure that wraps all sections.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct UserConfig {
    #[serde(default)]
    pub daemon: DaemonConfig,
    #[serde(default)]
    pub cli: CliConfig,
}

/// Configuration for the daemon process.
#[derive(Debug, Clone, Deserialize)]
pub struct DaemonConfig {
    /// Paths to index.
    ///
    /// Can include:
    /// - Drive letters (e.g., "C:", "D:") - will use fast MFT scanning for NTFS
    /// - Specific directories (e.g., "C:\\Users", "D:\\Projects")
    /// - Network paths (e.g., "\\\\server\\share", "Z:")
    ///
    /// If empty, all available NTFS drives will be auto-detected and indexed.
    /// Network paths are automatically detected and handled appropriately.
    #[serde(default)]
    pub paths: Vec<String>,

    /// Directories to exclude from indexing.
    #[serde(default)]
    pub exclude: Vec<String>,

    /// File patterns to exclude (glob syntax).
    #[serde(default)]
    pub exclude_patterns: Vec<String>,

    /// Rescan interval for non-NTFS/network drives (seconds).
    #[serde(default = "default_scan_interval")]
    pub scan_interval: u64,

    /// Log level.
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Database file path.
    #[serde(default)]
    pub database_path: Option<PathBuf>,
}

/// Configuration for the CLI tool.
#[derive(Debug, Clone, Deserialize)]
pub struct CliConfig {
    /// Default output format.
    #[serde(default = "default_format")]
    pub format: OutputFormat,

    /// Maximum number of results to show (0 = unlimited).
    #[serde(default = "default_max_results")]
    pub max_results: usize,

    /// Enable colored output.
    #[serde(default = "default_true")]
    pub color: bool,

    /// Case-sensitive search by default.
    #[serde(default)]
    pub case_sensitive: bool,

    /// Show hidden files in results.
    #[serde(default)]
    pub show_hidden: bool,
}

/// Output format for search results.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    #[default]
    Simple,
    Detailed,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            paths: Vec::new(),
            exclude: vec![
                "C:\\Windows".to_string(),
                "C:\\$Recycle.Bin".to_string(),
                "C:\\System Volume Information".to_string(),
            ],
            exclude_patterns: Vec::new(),
            scan_interval: default_scan_interval(),
            log_level: default_log_level(),
            database_path: None,
        }
    }
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            format: OutputFormat::default(),
            max_results: default_max_results(),
            color: true,
            case_sensitive: false,
            show_hidden: false,
        }
    }
}

impl UserConfig {
    /// Load configuration from the default config file path.
    ///
    /// Returns default configuration if the file doesn't exist or can't be parsed.
    #[must_use]
    pub fn load() -> Self {
        Self::load_from_path(CONFIG_PATH.as_deref())
    }

    /// Load configuration from a specific path.
    ///
    /// Returns default configuration if the file doesn't exist or can't be parsed.
    #[must_use]
    pub fn load_from_path(path: Option<&std::path::Path>) -> Self {
        let Some(path) = path else {
            return Self::default();
        };

        let config_string = match fs::read_to_string(path) {
            Ok(content) => content,
            Err(error) => {
                warn!("Failed to read config file {}: {error}", path.display());
                return Self::default();
            }
        };

        match toml::from_str(&config_string) {
            Ok(config) => config,
            Err(error) => {
                warn!("Failed to parse config file {}: {error}", path.display());
                Self::default()
            }
        }
    }

    /// Get the database path, using the configured path or the default.
    #[must_use]
    pub fn database_path(&self) -> PathBuf {
        self.daemon
            .database_path
            .clone()
            .unwrap_or_else(|| DATABASE_PATH.clone())
    }
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Simple => write!(f, "simple"),
            Self::Detailed => write!(f, "detailed"),
        }
    }
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "simple" => Ok(Self::Simple),
            "detailed" => Ok(Self::Detailed),
            _ => Err(format!("Unknown output format: {s}")),
        }
    }
}

const fn default_scan_interval() -> u64 {
    3600
}

fn default_log_level() -> String {
    "info".to_string()
}

const fn default_format() -> OutputFormat {
    OutputFormat::Simple
}

const fn default_max_results() -> usize {
    100
}

const fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_config() {
        let config = UserConfig::default();
        assert!(config.daemon.paths.is_empty());
        assert_eq!(config.daemon.scan_interval, 3600);
        assert_eq!(config.cli.max_results, 100);
        assert!(config.cli.color);
    }

    #[test]
    fn test_daemon_config_default() {
        let config = DaemonConfig::default();

        assert!(config.paths.is_empty());
        assert!(!config.exclude.is_empty()); // Has default exclusions
        assert!(config.exclude_patterns.is_empty());
        assert_eq!(config.scan_interval, 3600);
        assert_eq!(config.log_level, "info");
        assert!(config.database_path.is_none());

        // Verify default exclusions
        assert!(config.exclude.contains(&"C:\\Windows".to_string()));
        assert!(config.exclude.contains(&"C:\\$Recycle.Bin".to_string()));
        assert!(config.exclude.contains(&"C:\\System Volume Information".to_string()));
    }

    #[test]
    fn test_cli_config_default() {
        let config = CliConfig::default();

        assert_eq!(config.format, OutputFormat::Simple);
        assert_eq!(config.max_results, 100);
        assert!(config.color);
        assert!(!config.case_sensitive);
        assert!(!config.show_hidden);
    }

    #[test]
    fn test_load_nonexistent_config() {
        let config = UserConfig::load_from_path(Some(std::path::Path::new("/nonexistent/path.toml")));
        assert!(config.daemon.paths.is_empty());
    }

    #[test]
    fn test_load_from_none_path() {
        let config = UserConfig::load_from_path(None);

        // Should return default config
        assert!(config.daemon.paths.is_empty());
        assert_eq!(config.daemon.scan_interval, 3600);
        assert_eq!(config.cli.max_results, 100);
    }

    #[test]
    fn test_output_format_display() {
        assert_eq!(OutputFormat::Simple.to_string(), "simple");
        assert_eq!(OutputFormat::Detailed.to_string(), "detailed");
    }

    #[test]
    fn test_output_format_from_str() {
        assert_eq!("simple".parse::<OutputFormat>().unwrap(), OutputFormat::Simple);
        assert_eq!("DETAILED".parse::<OutputFormat>().unwrap(), OutputFormat::Detailed);
        assert_eq!("Simple".parse::<OutputFormat>().unwrap(), OutputFormat::Simple);
        assert_eq!("SIMPLE".parse::<OutputFormat>().unwrap(), OutputFormat::Simple);
        assert!("invalid".parse::<OutputFormat>().is_err());
        assert!("".parse::<OutputFormat>().is_err());
    }

    #[test]
    fn test_output_format_default() {
        let format = OutputFormat::default();
        assert_eq!(format, OutputFormat::Simple);
    }

    #[test]
    fn test_output_format_equality() {
        assert_eq!(OutputFormat::Simple, OutputFormat::Simple);
        assert_eq!(OutputFormat::Detailed, OutputFormat::Detailed);
        assert_ne!(OutputFormat::Simple, OutputFormat::Detailed);
    }

    #[test]
    fn test_output_format_clone_copy() {
        let original = OutputFormat::Detailed;
        let cloned = original;
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_load_valid_config_file() {
        let mut temp_file = NamedTempFile::new().expect("create temp file");

        let config_content = r#"
[daemon]
paths = ["C:\\", "D:\\"]
exclude = ["C:\\Windows", "C:\\Temp"]
scan_interval = 7200
log_level = "debug"

[cli]
format = "detailed"
max_results = 50
color = false
case_sensitive = true
show_hidden = true
"#;

        temp_file.write_all(config_content.as_bytes()).expect("write config");

        let config = UserConfig::load_from_path(Some(temp_file.path()));

        assert_eq!(config.daemon.paths, vec!["C:\\", "D:\\"]);
        assert_eq!(config.daemon.exclude, vec!["C:\\Windows", "C:\\Temp"]);
        assert_eq!(config.daemon.scan_interval, 7200);
        assert_eq!(config.daemon.log_level, "debug");
        assert_eq!(config.cli.format, OutputFormat::Detailed);
        assert_eq!(config.cli.max_results, 50);
        assert!(!config.cli.color);
        assert!(config.cli.case_sensitive);
        assert!(config.cli.show_hidden);
    }

    #[test]
    fn test_load_partial_config_file() {
        let mut temp_file = NamedTempFile::new().expect("create temp file");

        // Only specify some fields, others should use defaults
        let config_content = r#"
[daemon]
paths = ["E:\\"]

[cli]
max_results = 200
"#;

        temp_file.write_all(config_content.as_bytes()).expect("write config");

        let config = UserConfig::load_from_path(Some(temp_file.path()));

        // Specified values
        assert_eq!(config.daemon.paths, vec!["E:\\"]);
        assert_eq!(config.cli.max_results, 200);

        // Default values
        assert_eq!(config.daemon.scan_interval, 3600);
        assert_eq!(config.cli.format, OutputFormat::Simple);
        assert!(config.cli.color);
    }

    #[test]
    fn test_load_invalid_toml_config() {
        let mut temp_file = NamedTempFile::new().expect("create temp file");

        let invalid_content = "this is not valid toml [[[";
        temp_file.write_all(invalid_content.as_bytes()).expect("write config");

        // Should return default config on parse error
        let config = UserConfig::load_from_path(Some(temp_file.path()));
        assert!(config.daemon.paths.is_empty());
        assert_eq!(config.cli.max_results, 100);
    }

    #[test]
    fn test_load_empty_config_file() {
        let mut temp_file = NamedTempFile::new().expect("create temp file");

        temp_file.write_all(b"").expect("write empty config");

        let config = UserConfig::load_from_path(Some(temp_file.path()));

        // Should use defaults
        assert!(config.daemon.paths.is_empty());
        assert_eq!(config.daemon.scan_interval, 3600);
    }

    #[test]
    fn test_database_path_from_config() {
        let mut temp_file = NamedTempFile::new().expect("create temp file");

        let config_content = r#"
[daemon]
database_path = "C:\\custom\\path\\filefind.db"
"#;

        temp_file.write_all(config_content.as_bytes()).expect("write config");

        let config = UserConfig::load_from_path(Some(temp_file.path()));

        assert_eq!(config.database_path(), PathBuf::from("C:\\custom\\path\\filefind.db"));
    }

    #[test]
    fn test_database_path_default() {
        let config = UserConfig::default();

        // Should use the default DATABASE_PATH
        let db_path = config.database_path();
        assert!(db_path.to_string_lossy().contains("filefind"));
    }

    #[test]
    fn test_database_path_static() {
        // DATABASE_PATH should be initialized and contain expected components
        let path = &*DATABASE_PATH;
        assert!(path.to_string_lossy().contains("filefind"));
    }

    #[test]
    fn test_config_with_exclude_patterns() {
        let mut temp_file = NamedTempFile::new().expect("create temp file");

        let config_content = r#"
[daemon]
exclude_patterns = ["*.tmp", "*.bak", "~*"]
"#;

        temp_file.write_all(config_content.as_bytes()).expect("write config");

        let config = UserConfig::load_from_path(Some(temp_file.path()));

        assert_eq!(config.daemon.exclude_patterns.len(), 3);
        assert!(config.daemon.exclude_patterns.contains(&"*.tmp".to_string()));
        assert!(config.daemon.exclude_patterns.contains(&"*.bak".to_string()));
        assert!(config.daemon.exclude_patterns.contains(&"~*".to_string()));
    }

    #[test]
    fn test_default_scan_interval_value() {
        assert_eq!(default_scan_interval(), 3600);
    }

    #[test]
    fn test_default_log_level_value() {
        assert_eq!(default_log_level(), "info");
    }

    #[test]
    fn test_default_format_value() {
        assert_eq!(default_format(), OutputFormat::Simple);
    }

    #[test]
    fn test_default_max_results_value() {
        assert_eq!(default_max_results(), 100);
    }

    #[test]
    fn test_default_true_value() {
        assert!(default_true());
    }

    #[test]
    fn test_output_format_from_str_error_message() {
        let result = "unknown_format".parse::<OutputFormat>();
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert!(error.contains("Unknown output format"));
        assert!(error.contains("unknown_format"));
    }

    #[test]
    fn test_daemon_config_clone() {
        let original = DaemonConfig::default();
        let cloned = original.clone();

        assert_eq!(original.scan_interval, cloned.scan_interval);
        assert_eq!(original.log_level, cloned.log_level);
    }

    #[test]
    fn test_cli_config_clone() {
        let original = CliConfig::default();
        let cloned = original.clone();

        assert_eq!(original.max_results, cloned.max_results);
        assert_eq!(original.format, cloned.format);
    }

    #[test]
    fn test_user_config_clone() {
        let original = UserConfig::default();
        let cloned = original.clone();

        assert_eq!(original.daemon.scan_interval, cloned.daemon.scan_interval);
        assert_eq!(original.cli.max_results, cloned.cli.max_results);
    }

    #[test]
    fn test_output_format_debug() {
        let format = OutputFormat::Simple;
        let debug_str = format!("{format:?}");
        assert!(debug_str.contains("Simple"));
    }

    #[test]
    fn test_config_with_network_paths() {
        let mut temp_file = NamedTempFile::new().expect("create temp file");

        let config_content = r#"
[daemon]
paths = ["\\\\server\\share", "Z:\\", "C:\\Local"]
"#;

        temp_file.write_all(config_content.as_bytes()).expect("write config");

        let config = UserConfig::load_from_path(Some(temp_file.path()));

        assert_eq!(config.daemon.paths.len(), 3);
        assert!(config.daemon.paths.contains(&"\\\\server\\share".to_string()));
        assert!(config.daemon.paths.contains(&"Z:\\".to_string()));
        assert!(config.daemon.paths.contains(&"C:\\Local".to_string()));
    }
}
