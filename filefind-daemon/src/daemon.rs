//! Core daemon lifecycle and monitoring logic.
//!
//! This module provides the main daemon struct that manages:
//! - Daemon lifecycle (start, stop, status)
//! - Background monitoring of file changes via USN Journal (NTFS) and file watcher
//! - Coordinating updates to the database based on file changes

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use colored::Colorize;
use filefind::{Config, Database, print_error, print_info, print_success, print_warning};
use tracing::{error, info, warn};

use crate::mft::detect_ntfs_volumes;
use crate::scanner::{format_number, run_scan};
use crate::usn::UsnMonitor;
use crate::watcher::{FileWatcher, WatcherConfig};

/// Default USN Journal poll interval in milliseconds.
const DEFAULT_USN_POLL_INTERVAL_MS: u64 = 1000;

/// Default file watcher debounce interval in milliseconds.
const DEFAULT_WATCHER_DEBOUNCE_MS: u64 = 500;

/// Represents the running state of the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonState {
    /// Daemon is not running.
    Stopped,
    /// Daemon is starting up (scanning, initializing monitors).
    Starting,
    /// Daemon is running and monitoring for changes.
    Running,
    /// Daemon is shutting down.
    Stopping,
}

impl std::fmt::Display for DaemonState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stopped => write!(f, "stopped"),
            Self::Starting => write!(f, "starting"),
            Self::Running => write!(f, "running"),
            Self::Stopping => write!(f, "stopping"),
        }
    }
}

/// Configuration for the daemon.
#[derive(Debug, Clone)]
pub struct DaemonOptions {
    /// Run in foreground instead of daemonizing.
    #[allow(dead_code)]
    pub foreground: bool,

    /// Force a full rescan on startup.
    pub rescan: bool,

    /// USN Journal poll interval in milliseconds.
    #[allow(dead_code)]
    pub usn_poll_interval_ms: u64,

    /// File watcher debounce interval in milliseconds.
    pub watcher_debounce_ms: u64,
}

impl Default for DaemonOptions {
    fn default() -> Self {
        Self {
            foreground: false,
            rescan: false,
            usn_poll_interval_ms: DEFAULT_USN_POLL_INTERVAL_MS,
            watcher_debounce_ms: DEFAULT_WATCHER_DEBOUNCE_MS,
        }
    }
}

/// Volume monitor that tracks a single volume.
struct VolumeMonitor {
    /// Drive letter for this volume.
    #[allow(dead_code)]
    drive_letter: char,

    /// USN monitor for NTFS volumes (None for non-NTFS).
    usn_monitor: Option<UsnMonitor>,

    /// Last processed USN for this volume.
    last_usn: i64,
}

/// The main daemon struct that manages file indexing.
pub struct Daemon {
    /// Current daemon state.
    state: DaemonState,

    /// Configuration.
    config: Config,

    /// Daemon options.
    options: DaemonOptions,

    /// Database connection.
    database: Option<Database>,

    /// Shutdown signal.
    shutdown: Arc<AtomicBool>,

    /// Active volume monitors (keyed by drive letter).
    volume_monitors: HashMap<char, VolumeMonitor>,

    /// File watcher for non-NTFS paths.
    file_watcher: Option<FileWatcher>,
}

impl Daemon {
    /// Create a new daemon instance.
    #[must_use]
    pub fn new(config: Config, options: DaemonOptions) -> Self {
        Self {
            state: DaemonState::Stopped,
            config,
            options,
            database: None,
            shutdown: Arc::new(AtomicBool::new(false)),
            volume_monitors: HashMap::new(),
            file_watcher: None,
        }
    }

    /// Get the current daemon state.
    #[must_use]
    #[allow(dead_code)]
    pub const fn state(&self) -> DaemonState {
        self.state
    }

    /// Check if the daemon is running.
    #[must_use]
    #[allow(dead_code)]
    pub const fn is_running(&self) -> bool {
        matches!(self.state, DaemonState::Running)
    }

    /// Get the shutdown signal handle.
    #[must_use]
    pub fn shutdown_handle(&self) -> Arc<AtomicBool> {
        self.shutdown.clone()
    }

    /// Start the daemon.
    ///
    /// This initializes the database, performs an initial scan if needed,
    /// and starts monitoring for file changes.
    pub async fn start(&mut self) -> Result<()> {
        if self.state != DaemonState::Stopped {
            print_warning!("Daemon is already {}", self.state);
            return Ok(());
        }

        self.state = DaemonState::Starting;
        self.shutdown.store(false, Ordering::Relaxed);

        print_info!("Starting filefind daemon...");

        // Initialize database
        let database_path = self.config.database_path();
        if let Some(parent) = database_path.parent() {
            std::fs::create_dir_all(parent).context("Failed to create database directory")?;
        }

        let database = Database::open(&database_path).context("Failed to open database")?;
        print_info!("Database: {}", database_path.display());

        self.database = Some(database);

        // Perform initial scan if requested or if database is empty
        if self.options.rescan || self.should_perform_initial_scan()? {
            print_info!("Performing initial scan...");
            run_scan(None, self.options.rescan, &self.config).await?;
        }

        // Start monitoring
        self.start_monitors().await?;

        self.state = DaemonState::Running;
        print_success!("Daemon started successfully");

        Ok(())
    }

    /// Stop the daemon.
    #[allow(clippy::unused_async)]
    pub async fn stop(&mut self) -> Result<()> {
        if self.state == DaemonState::Stopped {
            print_warning!("Daemon is already stopped");
            return Ok(());
        }

        self.state = DaemonState::Stopping;
        self.shutdown.store(true, Ordering::Relaxed);

        print_info!("Stopping daemon...");

        // Stop all USN monitors
        for (drive_letter, monitor) in &self.volume_monitors {
            if let Some(ref usn) = monitor.usn_monitor {
                info!("Stopping USN monitor for {}:\\", drive_letter);
                usn.stop();
            }
        }
        self.volume_monitors.clear();

        // Stop file watcher
        if let Some(ref watcher) = self.file_watcher {
            info!("Stopping file watcher");
            watcher.stop();
        }
        self.file_watcher = None;

        // Close database
        self.database = None;

        self.state = DaemonState::Stopped;
        print_success!("Daemon stopped");

        Ok(())
    }

    /// Run the daemon's main loop.
    ///
    /// This runs until shutdown is signaled.
    pub async fn run(&mut self) -> Result<()> {
        if self.state != DaemonState::Running {
            self.start().await?;
        }

        print_info!("Daemon running. Press Ctrl+C to stop.");

        // Main loop - wait for shutdown signal
        while !self.shutdown.load(Ordering::Relaxed) {
            // Process any pending changes
            self.process_changes().await?;

            // Small sleep to prevent busy-waiting
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        self.stop().await?;

        Ok(())
    }

    /// Check if an initial scan should be performed.
    fn should_perform_initial_scan(&self) -> Result<bool> {
        let Some(ref database) = self.database else {
            return Ok(true);
        };

        let stats = database.get_stats()?;
        Ok(stats.total_files == 0 && stats.total_directories == 0)
    }

    /// Start all monitors (USN Journal and file watcher).
    async fn start_monitors(&mut self) -> Result<()> {
        // Detect NTFS volumes and start USN monitors
        match detect_ntfs_volumes() {
            Ok(ntfs_drives) => {
                for drive_letter in ntfs_drives {
                    if let Err(error) = self.start_usn_monitor(drive_letter).await {
                        warn!("Failed to start USN monitor for {}:\\: {}", drive_letter, error);
                    }
                }
            }
            Err(error) => {
                warn!("Failed to detect NTFS volumes: {}", error);
            }
        }

        // Start file watcher for non-NTFS paths
        let non_ntfs_paths = self.get_non_ntfs_paths();
        if !non_ntfs_paths.is_empty() {
            self.start_file_watcher(non_ntfs_paths)?;
        }

        Ok(())
    }

    /// Start USN Journal monitor for a specific drive.
    #[allow(clippy::unused_async)]
    async fn start_usn_monitor(&mut self, drive_letter: char) -> Result<()> {
        // Get last USN from database
        let last_usn = self
            .database
            .as_ref()
            .and_then(|db| db.get_volume_last_usn(drive_letter).ok())
            .flatten()
            .unwrap_or(0);

        info!("Starting USN monitor for {}:\\ (last USN: {})", drive_letter, last_usn);

        let usn_monitor = UsnMonitor::new(drive_letter, last_usn)?;

        let monitor = VolumeMonitor {
            drive_letter,
            usn_monitor: Some(usn_monitor),
            last_usn,
        };

        self.volume_monitors.insert(drive_letter, monitor);

        Ok(())
    }

    /// Start file watcher for non-NTFS paths.
    #[allow(clippy::unnecessary_wraps)]
    fn start_file_watcher(&mut self, paths: Vec<PathBuf>) -> Result<()> {
        let config = WatcherConfig {
            paths,
            exclude_patterns: self.config.daemon.exclude.clone(),
            debounce_ms: self.options.watcher_debounce_ms,
            recursive: true,
        };

        let watcher = FileWatcher::new(config);
        info!("Started file watcher for {} paths", watcher.watched_paths().len());

        self.file_watcher = Some(watcher);

        Ok(())
    }

    /// Get paths that are not on NTFS volumes.
    fn get_non_ntfs_paths(&self) -> Vec<PathBuf> {
        let ntfs_drives: Vec<char> = self.volume_monitors.keys().copied().collect();

        self.config
            .daemon
            .paths
            .iter()
            .filter_map(|path_str| {
                let path = PathBuf::from(path_str);
                let first_char = path_str.chars().next()?;

                // Skip if this is on an NTFS drive we're monitoring
                if ntfs_drives.contains(&first_char.to_ascii_uppercase()) {
                    return None;
                }

                // Include UNC paths and non-NTFS drives
                Some(path)
            })
            .collect()
    }

    /// Process any pending file changes.
    #[allow(clippy::unused_async)]
    async fn process_changes(&mut self) -> Result<()> {
        // Process USN Journal changes
        for monitor in self.volume_monitors.values_mut() {
            if let Some(ref mut usn) = monitor.usn_monitor {
                match usn.read_changes() {
                    Ok((changes, new_usn)) => {
                        if !changes.is_empty() {
                            info!("Processing {} USN changes", changes.len());
                            // TODO: Process changes and update database
                            monitor.last_usn = new_usn;
                        }
                    }
                    Err(error) => {
                        error!("Error reading USN changes: {}", error);
                    }
                }
            }
        }

        // TODO: Process file watcher events

        Ok(())
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        // Ensure shutdown is signaled
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

/// Start the daemon process.
///
/// This is the main entry point called from CLI.
pub fn start_daemon(foreground: bool, rescan: bool, config: &Config) -> Result<()> {
    let options = DaemonOptions {
        foreground,
        rescan,
        ..Default::default()
    };

    let mut daemon = Daemon::new(config.clone(), options);

    if foreground {
        print_info!("Starting daemon in foreground mode...");

        // Run in foreground with tokio runtime
        tokio::runtime::Runtime::new()?.block_on(async {
            // Set up Ctrl+C handler
            let shutdown = daemon.shutdown_handle();
            tokio::spawn(async move {
                if let Err(error) = tokio::signal::ctrl_c().await {
                    error!("Failed to listen for Ctrl+C: {}", error);
                }
                info!("Received Ctrl+C, shutting down...");
                shutdown.store(true, Ordering::Relaxed);
            });

            daemon.run().await
        })
    } else {
        // TODO: Implement proper daemonization on Windows
        // For now, just run in foreground
        print_warning!("Background daemon mode not yet implemented. Running in foreground.");
        print_info!("Use 'filefindd start -f' for foreground mode.");

        tokio::runtime::Runtime::new()?.block_on(async {
            let shutdown = daemon.shutdown_handle();
            tokio::spawn(async move {
                if let Err(error) = tokio::signal::ctrl_c().await {
                    error!("Failed to listen for Ctrl+C: {}", error);
                }
                info!("Received Ctrl+C, shutting down...");
                shutdown.store(true, Ordering::Relaxed);
            });

            daemon.run().await
        })
    }
}

/// Stop the running daemon.
#[allow(clippy::unnecessary_wraps)]
pub fn stop_daemon() -> Result<()> {
    print_info!("Stopping daemon...");

    // TODO: Implement proper daemon stop logic
    // - Find running daemon process (via PID file or named pipe)
    // - Send stop signal
    // - Wait for graceful shutdown

    print_warning!("Daemon stop not yet implemented");
    print_info!("If running in foreground, press Ctrl+C to stop.");

    Ok(())
}

/// Show daemon status.
pub fn show_status(config: &Config) -> Result<()> {
    println!("{}", "Filefind Daemon Status".bold());
    println!();

    // TODO: Implement proper status check
    // - Check if daemon process is running (via PID file or named pipe)
    // - Show uptime, memory usage
    // - Show indexing progress if active

    let database_path = config.database_path();

    if database_path.exists() {
        let database = Database::open(&database_path)?;
        let stats = database.get_stats()?;

        println!("  State:        {}", "unknown".yellow());
        println!("  Files:        {}", format_number(stats.total_files));
        println!("  Directories:  {}", format_number(stats.total_directories));
        println!("  Volumes:      {}", stats.volume_count);
        println!();
        println!("  Database:     {}", database_path.display());

        if let Ok(metadata) = std::fs::metadata(&database_path) {
            println!("  DB size:      {}", filefind::format_size(metadata.len()));
        }
    } else {
        println!("  State:        {}", "not initialized".yellow());
        println!();
        println!("  Database not found at: {}", database_path.display());
        println!("  Run 'filefindd scan' to create the index.");
    }

    println!();
    print_warning!("Status check not fully implemented - cannot detect running daemon.");

    Ok(())
}

/// Detect available drives and show their types.
pub fn detect_drives() -> Result<()> {
    println!("{}", "Detected Drives".bold());
    println!();

    match detect_ntfs_volumes() {
        Ok(volumes) => {
            if volumes.is_empty() {
                println!("  No NTFS volumes detected.");
            } else {
                println!("  NTFS volumes (fast MFT scanning available):");
                for letter in &volumes {
                    println!("    {letter}:\\");
                }
            }
        }
        Err(error) => {
            print_error!("Failed to detect volumes: {}", error);
        }
    }

    println!();
    print_info!("Run 'filefindd scan' to index all detected NTFS volumes.");
    print_info!("Run 'filefindd scan <path>' to scan a specific directory.");

    Ok(())
}

/// Show index statistics.
pub fn show_stats(config: &Config) -> Result<()> {
    let database_path = config.database_path();

    if !database_path.exists() {
        print_error!("Database not found at: {}", database_path.display());
        println!("Run 'filefindd scan' to create the index.");
        return Ok(());
    }

    let database = Database::open(&database_path)?;
    let stats = database.get_stats()?;

    println!("{}", "Index Statistics".bold());
    println!();
    println!("  Files:        {}", format_number(stats.total_files));
    println!("  Directories:  {}", format_number(stats.total_directories));
    println!("  Volumes:      {}", stats.volume_count);
    println!("  Total size:   {}", filefind::format_size(stats.total_size));
    println!();
    println!("  Database:     {}", database_path.display());

    // Show database file size
    if let Ok(metadata) = std::fs::metadata(&database_path) {
        println!("  DB file size: {}", filefind::format_size(metadata.len()));
    }

    Ok(())
}

/// List indexed volumes.
#[allow(clippy::unnecessary_wraps)]
pub fn list_volumes(detailed: bool, config: &Config) -> Result<()> {
    let database_path = config.database_path();

    if !database_path.exists() {
        print_error!("Database not found at: {}", database_path.display());
        println!("Run 'filefindd scan' to create the index.");
        return Ok(());
    }

    let database = Database::open(&database_path)?;
    let volumes = database.get_all_volumes()?;

    if volumes.is_empty() {
        println!("No volumes indexed yet.");
        println!("Run 'filefindd scan' to index your drives.");
        return Ok(());
    }

    println!("{}", "Indexed Volumes".bold());
    println!();

    for volume in &volumes {
        let status = if volume.is_online {
            "online".green()
        } else {
            "offline".red()
        };

        println!("  {} ({}) - {}", volume.mount_point.bold(), volume.volume_type, status);

        if detailed {
            if let Some(ref label) = volume.label {
                println!("    Label: {label}");
            }
            println!("    Serial: {}", volume.serial_number);
            if let Some(last_scan) = volume.last_scan_time {
                println!("    Last scan: {last_scan:?}");
            }
            if let Some(usn) = volume.last_usn {
                println!("    Last USN: {usn}");
            }
            println!();
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_daemon_state_display() {
        assert_eq!(DaemonState::Stopped.to_string(), "stopped");
        assert_eq!(DaemonState::Starting.to_string(), "starting");
        assert_eq!(DaemonState::Running.to_string(), "running");
        assert_eq!(DaemonState::Stopping.to_string(), "stopping");
    }

    #[test]
    fn test_daemon_options_default() {
        let options = DaemonOptions::default();
        assert!(!options.foreground);
        assert!(!options.rescan);
        assert_eq!(options.usn_poll_interval_ms, DEFAULT_USN_POLL_INTERVAL_MS);
        assert_eq!(options.watcher_debounce_ms, DEFAULT_WATCHER_DEBOUNCE_MS);
    }

    #[test]
    fn test_daemon_new() {
        let config = Config::default();
        let options = DaemonOptions::default();
        let daemon = Daemon::new(config, options);

        assert_eq!(daemon.state(), DaemonState::Stopped);
        assert!(!daemon.is_running());
        assert!(daemon.database.is_none());
        assert!(daemon.volume_monitors.is_empty());
        assert!(daemon.file_watcher.is_none());
    }
}
