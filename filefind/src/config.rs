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

    #[test]
    fn test_default_config() {
        let config = UserConfig::default();
        assert!(config.daemon.paths.is_empty());
        assert_eq!(config.daemon.scan_interval, 3600);
        assert_eq!(config.cli.max_results, 100);
        assert!(config.cli.color);
    }

    #[test]
    fn test_load_nonexistent_config() {
        let config = UserConfig::load_from_path(Some(std::path::Path::new("/nonexistent/path.toml")));
        assert!(config.daemon.paths.is_empty());
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
        assert!("invalid".parse::<OutputFormat>().is_err());
    }
}
