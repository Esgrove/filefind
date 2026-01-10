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
use filefind::{
    Config, DaemonStateInfo, Database, FileChangeEvent, FileEntry, IpcClient, format_number, print_error, print_info,
    print_success, print_warning,
};
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

use crate::ipc_server::{IpcServerState, IpcToDaemon, spawn_ipc_server};
use crate::mft::detect_ntfs_volumes;
use crate::scanner::run_scan;
use crate::usn::UsnMonitor;
use crate::watcher::FileWatcher;

/// Default USN Journal poll interval in milliseconds.
const DEFAULT_USN_POLL_INTERVAL_MS: u64 = 1000;

/// Default file watcher debounce interval in milliseconds.
const DEFAULT_WATCHER_DEBOUNCE_MS: u64 = 2000;

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

    /// Receiver for file watcher events.
    watcher_receiver: Option<mpsc::Receiver<FileChangeEvent>>,

    /// Cache of MFT file reference to full path (for path resolution).
    path_cache: HashMap<u64, String>,

    /// Shared state for IPC server.
    ipc_state: Arc<IpcServerState>,

    /// Receiver for IPC commands.
    ipc_receiver: Option<mpsc::Receiver<IpcToDaemon>>,

    /// Whether indexing is currently paused.
    is_paused: bool,
}

/// Configuration for the daemon.
#[derive(Debug, Clone)]
pub struct DaemonOptions {
    /// Force a full rescan on startup.
    pub rescan: bool,

    /// USN Journal poll interval in milliseconds.
    /// Controls how often the daemon checks for NTFS file system changes.
    pub usn_poll_interval_ms: u64,

    /// File watcher debounce interval in milliseconds.
    pub watcher_debounce_ms: u64,
}

impl Default for DaemonOptions {
    fn default() -> Self {
        Self {
            rescan: false,
            usn_poll_interval_ms: DEFAULT_USN_POLL_INTERVAL_MS,
            watcher_debounce_ms: DEFAULT_WATCHER_DEBOUNCE_MS,
        }
    }
}

/// Volume monitor that tracks a single volume.
struct VolumeMonitor {
    /// USN monitor for NTFS volumes (None for non-NTFS).
    usn_monitor: Option<UsnMonitor>,

    /// Last processed USN for this volume.
    last_usn: i64,
}

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
            watcher_receiver: None,
            path_cache: HashMap::new(),
            ipc_state: Arc::new(IpcServerState::new()),
            ipc_receiver: None,
            is_paused: false,
        }
    }

    /// Get the current daemon state.
    #[must_use]
    #[allow(dead_code)]
    pub const fn state(&self) -> DaemonState {
        self.state
    }

    /// Check if verbose output is enabled.
    #[must_use]
    pub const fn verbose(&self) -> bool {
        self.config.daemon.verbose
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
        info!("Starting filefind daemon");
        if self.state != DaemonState::Stopped {
            warn!("Daemon is already {}", self.state);
            return Ok(());
        }

        self.state = DaemonState::Starting;
        self.ipc_state.state.store(DaemonStateInfo::Starting);
        self.shutdown.store(false, Ordering::Relaxed);

        // Start IPC server
        let ipc_receiver = spawn_ipc_server(Arc::clone(&self.ipc_state), Arc::clone(&self.shutdown));
        self.ipc_receiver = Some(ipc_receiver);

        // Initialize database
        let database_path = self.config.database_path();
        if let Some(parent) = database_path.parent() {
            std::fs::create_dir_all(parent).context("Failed to create database directory")?;
        }

        debug!("Opening database: {}", database_path.display());
        let database = Database::open(&database_path).context("Failed to open database")?;

        self.database = Some(database);

        // Update IPC state with database stats
        if let Some(ref database) = self.database {
            self.ipc_state.update_from_database(database);
        }

        // Perform initial scan if requested or if database is empty
        if self.options.rescan || self.should_perform_initial_scan()? {
            info!("Performing scan");
            self.ipc_state.state.store(DaemonStateInfo::Scanning);

            run_scan(None, &self.config).await?;

            // Update stats after scan
            if let Some(ref database) = self.database {
                self.ipc_state.update_from_database(database);
            }
        }

        // Build path cache for USN path resolution
        self.build_path_cache()?;

        // Start monitoring
        self.start_monitors()?;

        // Update monitored volumes count
        self.ipc_state
            .monitored_volumes
            .store(self.volume_monitors.len() as u64, Ordering::Relaxed);

        self.state = DaemonState::Running;
        self.ipc_state.state.store(DaemonStateInfo::Running);
        if self.verbose() {
            print_success!("Daemon started successfully");
        }

        Ok(())
    }

    /// Stop the daemon.
    pub fn stop(&mut self) {
        info!("Stopping daemon");
        if self.state == DaemonState::Stopped {
            warn!("Daemon is already stopped");
            return;
        }

        self.state = DaemonState::Stopping;
        self.ipc_state.state.store(DaemonStateInfo::Stopping);
        self.shutdown.store(true, Ordering::Relaxed);

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
            info!("Stopping file watcher for {} paths", watcher.watched_paths().len());
            for path in watcher.watched_paths() {
                info!("Stopping file watcher for {}", path.display());
            }
            watcher.stop();
        }

        self.state = DaemonState::Stopped;
        self.ipc_state.state.store(DaemonStateInfo::Stopped);
        if self.config.daemon.verbose {
            print_success!("Daemon stopped");
        }
    }

    /// Run the daemon's main loop.
    ///
    /// This runs until shutdown is signaled.
    pub async fn run(&mut self) -> Result<()> {
        if self.state != DaemonState::Running {
            self.start().await?;
        }

        if self.verbose() {
            print_info!("Daemon running. Press Ctrl+C to stop.");
        }

        // Main loop - wait for shutdown signal
        while !self.shutdown.load(Ordering::Relaxed) {
            // Process IPC commands
            self.process_ipc_commands().await?;

            // Process any pending file changes (unless paused)
            if !self.is_paused {
                self.process_changes().await?;
            }

            // Sleep for the configured poll interval
            tokio::time::sleep(Duration::from_millis(self.options.usn_poll_interval_ms)).await;
        }

        self.stop();

        Ok(())
    }

    /// Process incoming IPC commands.
    async fn process_ipc_commands(&mut self) -> Result<()> {
        let Some(ref mut receiver) = self.ipc_receiver else {
            return Ok(());
        };

        // Process all available commands without blocking
        while let Ok(command) = receiver.try_recv() {
            match command {
                IpcToDaemon::Stop => {
                    info!("Received stop command via IPC");
                    self.shutdown.store(true, Ordering::Relaxed);
                }
                IpcToDaemon::Rescan => {
                    info!("Received rescan command via IPC");
                    self.ipc_state.state.store(DaemonStateInfo::Scanning);
                    if let Err(error) = run_scan(None, &self.config).await {
                        error!("Rescan failed: {}", error);
                    }
                    // Update stats after rescan
                    if let Some(ref database) = self.database {
                        self.ipc_state.update_from_database(database);
                    }
                    self.ipc_state.state.store(DaemonStateInfo::Running);
                }
                IpcToDaemon::Pause => {
                    info!("Received pause command via IPC");
                    self.is_paused = true;
                    self.ipc_state.is_paused.store(true, Ordering::Relaxed);
                }
                IpcToDaemon::Resume => {
                    info!("Received resume command via IPC");
                    self.is_paused = false;
                    self.ipc_state.is_paused.store(false, Ordering::Relaxed);
                }
            }
        }

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
    fn start_monitors(&mut self) -> Result<()> {
        // Get drives that are referenced in configured paths
        let configured_drives = self.get_configured_drives();

        // Detect NTFS volumes and start USN monitors only for configured drives
        let ntfs_drives = detect_ntfs_volumes();
        for drive_letter in ntfs_drives {
            if !configured_drives.contains(&drive_letter) {
                debug!("Skipping USN monitor for {drive_letter}:\\ (not in configured paths)");
                continue;
            }
            if let Err(error) = self.start_usn_monitor(drive_letter) {
                warn!("Failed to start USN monitor for {drive_letter}:\\ - {error}");
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
    fn start_usn_monitor(&mut self, drive_letter: char) -> Result<()> {
        // Get last USN from database
        let last_usn = self
            .database
            .as_ref()
            .and_then(|db| db.get_volume_last_usn(drive_letter).ok())
            .flatten()
            .unwrap_or(0);

        info!("Starting USN monitor for {drive_letter}:");

        let usn_monitor = UsnMonitor::new(drive_letter, last_usn)?;

        let monitor = VolumeMonitor {
            usn_monitor: Some(usn_monitor),
            last_usn,
        };

        self.volume_monitors.insert(drive_letter, monitor);

        Ok(())
    }

    /// Start file watcher for non-NTFS paths.
    fn start_file_watcher(&mut self, paths: Vec<PathBuf>) -> Result<()> {
        let watcher = FileWatcher::new(
            paths,
            self.config.daemon.exclude.clone(),
            self.options.watcher_debounce_ms,
            true,
        );
        let watched_paths = watcher.watched_paths();

        info!("Starting file watcher for {} paths", watched_paths.len());
        for path in watched_paths {
            info!("Watching {}", path.display());
        }

        // Start the watcher and get the event receiver
        let (receiver, _shutdown) = watcher.start()?;

        self.watcher_receiver = Some(receiver);

        Ok(())
    }

    /// Extract drive letters from configured paths.
    ///
    /// Returns a list of uppercase drive letters that are referenced in the
    /// daemon's configured paths. This is used to filter which NTFS volumes
    /// should have USN monitors started.
    fn get_configured_drives(&self) -> Vec<char> {
        let mut drives: Vec<char> = self
            .config
            .daemon
            .paths
            .iter()
            .filter_map(|path_str| {
                let mut chars = path_str.chars();
                let first = chars.next()?;
                let second = chars.next()?;

                // Check for drive letter pattern like "C:" or "C:\"
                if first.is_ascii_alphabetic() && second == ':' {
                    Some(first.to_ascii_uppercase())
                } else {
                    None
                }
            })
            .collect();

        drives.sort_unstable();
        drives.dedup();
        drives
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
        // Collect raw USN changes first to avoid borrow issues
        let mut raw_changes: Vec<(char, Vec<crate::usn::UsnChange>, i64)> = Vec::new();

        for monitor in self.volume_monitors.values_mut() {
            if let Some(ref mut usn) = monitor.usn_monitor {
                match usn.read_changes() {
                    Ok((changes, new_usn)) => {
                        if !changes.is_empty() {
                            debug!("Processing {} USN changes", changes.len());
                            let drive_letter = usn.get_drive_letter();
                            raw_changes.push((drive_letter, changes, new_usn));
                            monitor.last_usn = new_usn;
                        }
                    }
                    Err(error) => {
                        error!("Error reading USN changes: {}", error);
                    }
                }
            }
        }

        // Now process the collected changes (no longer borrowing volume_monitors)
        let mut usn_events: Vec<FileChangeEvent> = Vec::new();
        let mut usn_updates: Vec<(char, i64)> = Vec::new();

        for (drive_letter, changes, new_usn) in raw_changes {
            for change in &changes {
                // Try to resolve the path from parent reference and name
                let full_path = self.resolve_usn_path_inner(drive_letter, change.parent_reference, &change.name);

                if let Some(path) = full_path {
                    // Convert to event
                    if let Some(event) = Self::usn_change_to_event(change, &path) {
                        usn_events.push(event);
                    }
                }
            }
            usn_updates.push((drive_letter, new_usn));
        }

        // Process collected USN events
        for event in usn_events {
            self.handle_change_event(event);
        }

        // Update USN values in database
        if let Some(ref db) = self.database {
            for (drive_letter, new_usn) in usn_updates {
                let _ = db.update_volume_usn_by_drive(drive_letter, new_usn);
            }
        }

        // Collect file watcher events
        let mut watcher_events: Vec<FileChangeEvent> = Vec::new();
        if let Some(ref mut receiver) = self.watcher_receiver {
            while let Ok(event) = receiver.try_recv() {
                watcher_events.push(event);
            }
        }

        // Process collected watcher events
        for event in watcher_events {
            self.handle_change_event(event);
        }

        Ok(())
    }

    /// Convert a USN change to a file change event.
    fn usn_change_to_event(change: &crate::usn::UsnChange, full_path: &str) -> Option<FileChangeEvent> {
        use std::path::PathBuf;

        let path = PathBuf::from(full_path);

        if change.is_create() {
            Some(FileChangeEvent::Created(path))
        } else if change.is_delete() {
            Some(FileChangeEvent::Deleted(path))
        } else if change.is_rename_new() {
            Some(FileChangeEvent::Created(path))
        } else if change.is_modify() {
            Some(FileChangeEvent::Modified(path))
        } else {
            None
        }
    }

    /// Resolve a full path from USN change data (inner version that borrows `path_cache`).
    fn resolve_usn_path_inner(&self, drive_letter: char, parent_reference: u64, name: &str) -> Option<String> {
        // Try to get parent path from cache
        if let Some(parent_path) = self.path_cache.get(&parent_reference) {
            return Some(format!("{parent_path}\\{name}"));
        }

        // If parent is root (reference 5), construct path directly
        if parent_reference == 5 {
            return Some(format!("{drive_letter}:\\{name}"));
        }

        // Could not resolve path - would need MFT lookup
        // This is common for files in directories not in our cache, so use trace level
        trace!(
            "Could not resolve path for file '{}' with parent ref {}",
            name, parent_reference
        );
        None
    }

    /// Handle a file change event by updating the database.
    fn handle_change_event(&self, event: FileChangeEvent) {
        let Some(ref db) = self.database else {
            return;
        };

        match event {
            FileChangeEvent::Created(path) => {
                debug!("File created: {}", path.display());

                // Get volume_id from drive letter
                let Some(volume_id) = self.get_volume_id_for_path(&path) else {
                    trace!("No volume found for path: {}", path.display());
                    return;
                };

                // Get file metadata and insert into database
                if let Ok(metadata) = std::fs::metadata(&path) {
                    let name = path
                        .file_name()
                        .map(|name| name.to_string_lossy().to_string())
                        .unwrap_or_default();

                    let entry = FileEntry {
                        id: None,
                        volume_id,
                        parent_id: None,
                        name,
                        full_path: path.to_string_lossy().to_string(),
                        is_directory: metadata.is_dir(),
                        size: if metadata.is_file() { metadata.len() } else { 0 },
                        created_time: metadata.created().ok(),
                        modified_time: metadata.modified().ok(),
                        mft_reference: None,
                    };

                    if let Err(error) = db.insert_file(&entry) {
                        debug!("Failed to insert file {}: {}", path.display(), error);
                    }
                }
            }
            FileChangeEvent::Modified(path) => {
                debug!("File modified: {}", path.display());
            }
            FileChangeEvent::Deleted(path) => {
                debug!("File deleted: {}", path.display());

                let path_str = path.to_string_lossy();
                if let Err(error) = db.delete_file_by_path(&path_str) {
                    debug!("Failed to delete file {}: {}", path.display(), error);
                }
            }
            FileChangeEvent::Renamed { from, to } => {
                debug!("File renamed: {} -> {}", from.display(), to.display());

                // Delete old entry
                let from_str = from.to_string_lossy();
                let _ = db.delete_file_by_path(&from_str);

                // Get volume_id from drive letter
                let Some(volume_id) = self.get_volume_id_for_path(&to) else {
                    trace!("No volume found for renamed path: {}", to.display());
                    return;
                };

                // Insert new entry
                if let Ok(metadata) = std::fs::metadata(&to) {
                    let name = to
                        .file_name()
                        .map(|name| name.to_string_lossy().to_string())
                        .unwrap_or_default();

                    let entry = FileEntry {
                        id: None,
                        volume_id,
                        parent_id: None,
                        name,
                        full_path: to.to_string_lossy().to_string(),
                        is_directory: metadata.is_dir(),
                        size: if metadata.is_file() { metadata.len() } else { 0 },
                        created_time: metadata.created().ok(),
                        modified_time: metadata.modified().ok(),
                        mft_reference: None,
                    };

                    if let Err(error) = db.insert_file(&entry) {
                        debug!("Failed to insert renamed file {}: {}", to.display(), error);
                    }
                }
            }
        }
    }

    /// Get the volume ID for a given path by looking up the drive letter.
    fn get_volume_id_for_path(&self, path: &std::path::Path) -> Option<i64> {
        let path_str = path.to_string_lossy();
        let drive_letter = path_str.chars().next()?;

        let db = self.database.as_ref()?;

        // Query volume by mount point (drive letter)
        let mount_point = format!("{}:", drive_letter.to_ascii_uppercase());
        let volumes = db.get_all_volumes().ok()?;

        volumes
            .iter()
            .find(|v| v.mount_point.eq_ignore_ascii_case(&mount_point))
            .and_then(|v| v.id)
    }

    /// Build the path cache from the database for faster path resolution.
    fn build_path_cache(&mut self) -> Result<()> {
        let Some(ref db) = self.database else {
            return Ok(());
        };

        // Query all directories with MFT references
        let connection = db.connection();
        let mut stmt = connection.prepare(
            "SELECT mft_reference, full_path FROM files WHERE is_directory = 1 AND mft_reference IS NOT NULL",
        )?;

        let entries = stmt.query_map([], |row| {
            let mft_ref: i64 = row.get(0)?;
            let path: String = row.get(1)?;
            Ok((mft_ref as u64, path))
        })?;

        for entry in entries.flatten() {
            self.path_cache.insert(entry.0, entry.1);
        }

        info!("Built path cache with {} directory entries", self.path_cache.len());

        Ok(())
    }
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
        rescan,
        ..Default::default()
    };

    let mut daemon = Daemon::new(config.clone(), options);

    if foreground {
        if config.daemon.verbose {
            print_info!("Starting daemon in foreground mode...");
        }

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
        // Spawn a detached background process
        spawn_background_daemon(rescan)?;
        Ok(())
    }
}

/// Spawn the daemon as a detached background process.
///
/// This function spawns a new instance of the daemon executable with the `-f` (foreground)
/// flag, but detached from the current console. The spawned process runs independently
/// and survives after this process exits.
///
/// # Platform Support
///
/// - **Windows**: Uses `DETACHED_PROCESS` and `CREATE_NO_WINDOW` creation flags
/// - **Unix**: Uses `setsid` to create a new session (not yet implemented)
#[cfg(windows)]
fn spawn_background_daemon(rescan: bool) -> Result<()> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    // Windows process creation flags
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let exe_path = std::env::current_exe().context("Failed to get current executable path")?;

    let mut command = Command::new(&exe_path);
    command.arg("start").arg("-f"); // Run in foreground mode in the detached process

    if rescan {
        command.arg("--rescan");
    }

    // Detach from console and create without a window
    command.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);

    let child = command.spawn().context("Failed to spawn background daemon process")?;

    print_success!("Daemon started in background (PID: {})", child.id());
    print_info!("Use 'filefindd status' to check daemon status");
    print_info!("Use 'filefindd stop' to stop the daemon");

    Ok(())
}

/// Spawn the daemon as a detached background process (non-Windows stub).
#[cfg(not(windows))]
fn spawn_background_daemon(_rescan: bool) -> Result<()> {
    // On Unix, we would use fork() or nohup-style daemonization
    // For now, just print a message suggesting foreground mode
    print_warning!("Background daemon mode not implemented on this platform.");
    print_info!("Use 'filefindd start -f' for foreground mode.");
    print_info!("Or use 'nohup filefindd start -f &' to run in background.");
    Ok(())
}

/// Stop the running daemon.
pub fn stop_daemon() {
    print_info!("Stopping daemon...");

    let client = IpcClient::new();

    if !client.is_daemon_running() {
        print_warning!("Daemon is not running");
        return;
    }

    match client.stop_daemon() {
        Ok(()) => {
            print_success!("Stop command sent to daemon");
            // Wait a moment and check if it stopped
            std::thread::sleep(std::time::Duration::from_millis(500));
            if client.is_daemon_running() {
                print_warning!("Daemon is still running - it may take a moment to shut down");
            } else {
                print_success!("Daemon stopped");
            }
        }
        Err(error) => {
            print_error!("Failed to stop daemon: {}", error);
        }
    }
}

/// Show daemon status.
pub fn show_status(config: &Config) -> Result<()> {
    println!("{}", "Filefind daemon status".bold());

    let client = IpcClient::new();

    // Try to get status from running daemon
    if let Ok(status) = client.get_status() {
        let state_str = match status.state {
            DaemonStateInfo::Running => "running".green(),
            DaemonStateInfo::Scanning => "scanning".cyan(),
            DaemonStateInfo::Starting => "starting".yellow(),
            DaemonStateInfo::Stopping => "stopping".yellow(),
            DaemonStateInfo::Stopped => "stopped".red(),
        };

        println!("  State:        {state_str}");
        println!("  Files:        {}", format_number(status.indexed_files));
        println!("  Directories:  {}", format_number(status.indexed_directories));
        println!("  Volumes:      {}", status.monitored_volumes);
        println!("  Uptime:       {}s", status.uptime_seconds);
        if status.is_paused {
            println!("  Paused:       {}", "yes".yellow());
        }
    } else {
        // Daemon not running - show database info if available
        println!("  State:        {}", "not running".red());

        let database_path = config.database_path();
        if database_path.exists() {
            let database = Database::open(&database_path)?;
            let stats = database.get_stats()?;

            println!();
            println!("  {} (from database)", "Index Statistics".bold());
            println!("  Files:        {}", format_number(stats.total_files));
            println!("  Directories:  {}", format_number(stats.total_directories));
            println!("  Volumes:      {}", stats.volume_count);
        } else {
            println!();
            println!("  Database not found at: {}", database_path.display());
            println!("  Run 'filefindd scan' to create the index.");
        }
    }

    println!();

    let database_path = config.database_path();
    if database_path.exists() {
        println!("  Database:     {}", database_path.display());
        if let Ok(metadata) = std::fs::metadata(&database_path) {
            println!("  DB size:      {}", filefind::format_size(metadata.len()));
        }
    }

    Ok(())
}

/// Detect available drives and show their types.
pub fn detect_drives() {
    println!("{}", "Detected Drives".bold());
    println!();

    let volumes = detect_ntfs_volumes();
    if volumes.is_empty() {
        println!("  No NTFS volumes detected");
    } else {
        println!("  NTFS volumes (fast MFT scanning available):");
        for letter in &volumes {
            println!("    {letter}:\\");
        }
    }

    println!();
    print_info!("Run 'filefindd scan' to index all detected NTFS volumes");
    print_info!("Run 'filefindd scan <path>' to scan a specific directory");
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

    println!("{}", "Filefind index".bold());
    println!("  Files:          {}", format_number(stats.total_files));
    println!("  Directories:    {}", format_number(stats.total_directories));
    println!("  Volumes:        {}", stats.volume_count);
    println!("  Total size:     {}", filefind::format_size(stats.total_size));
    println!();
    println!("  Database:       {}", database_path.display());

    // Show database file size
    if let Ok(metadata) = std::fs::metadata(&database_path) {
        println!("  DB file size:   {}", filefind::format_size(metadata.len()));
    }

    Ok(())
}

/// List indexed volumes.
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
    fn test_daemon_state_display_all_variants() {
        // Verify all variants have distinct display strings
        let states = [
            DaemonState::Stopped,
            DaemonState::Starting,
            DaemonState::Running,
            DaemonState::Stopping,
        ];

        let displays: Vec<String> = states.iter().map(std::string::ToString::to_string).collect();

        // All should be unique
        for (index, display) in displays.iter().enumerate() {
            for (index_other, other) in displays.iter().enumerate() {
                if index != index_other {
                    assert_ne!(display, other, "State displays should be unique");
                }
            }
        }
    }

    #[test]
    fn test_daemon_state_debug() {
        let state = DaemonState::Running;
        let debug_str = format!("{state:?}");
        assert!(debug_str.contains("Running"));
    }

    #[test]
    fn test_daemon_state_clone_copy() {
        let state = DaemonState::Starting;
        let copied = state;
        assert_eq!(state, copied);
    }

    #[test]
    fn test_daemon_state_equality() {
        assert_eq!(DaemonState::Stopped, DaemonState::Stopped);
        assert_ne!(DaemonState::Stopped, DaemonState::Running);
        assert_ne!(DaemonState::Starting, DaemonState::Stopping);
    }

    #[test]
    fn test_daemon_options_default() {
        let options = DaemonOptions::default();
        assert!(!options.rescan);
        assert_eq!(options.usn_poll_interval_ms, DEFAULT_USN_POLL_INTERVAL_MS);
        assert_eq!(options.watcher_debounce_ms, DEFAULT_WATCHER_DEBOUNCE_MS);
    }

    #[test]
    fn test_daemon_options_custom() {
        let options = DaemonOptions {
            rescan: true,
            usn_poll_interval_ms: 500,
            watcher_debounce_ms: 200,
        };

        assert!(options.rescan);
        assert_eq!(options.usn_poll_interval_ms, 500);
        assert_eq!(options.watcher_debounce_ms, 200);
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

    #[test]
    fn test_daemon_new_with_rescan_option() {
        let config = Config::default();
        let options = DaemonOptions {
            rescan: true,
            ..Default::default()
        };
        let daemon = Daemon::new(config, options);

        assert!(daemon.options.rescan);
        assert_eq!(daemon.state(), DaemonState::Stopped);
    }

    #[test]
    fn test_daemon_options_watcher_debounce_range() {
        // Test that custom debounce intervals work
        let options = DaemonOptions {
            watcher_debounce_ms: 1,
            ..Default::default()
        };
        assert_eq!(options.watcher_debounce_ms, 1);

        let options = DaemonOptions {
            watcher_debounce_ms: 10000,
            ..Default::default()
        };
        assert_eq!(options.watcher_debounce_ms, 10000);
    }

    #[test]
    fn test_daemon_options_usn_poll_interval_range() {
        // Test that custom poll intervals work
        let options = DaemonOptions {
            usn_poll_interval_ms: 100,
            ..Default::default()
        };
        assert_eq!(options.usn_poll_interval_ms, 100);

        let options = DaemonOptions {
            usn_poll_interval_ms: 5000,
            ..Default::default()
        };
        assert_eq!(options.usn_poll_interval_ms, 5000);
    }

    #[test]
    fn test_daemon_shutdown_handle() {
        let config = Config::default();
        let options = DaemonOptions::default();
        let daemon = Daemon::new(config, options);

        let shutdown = daemon.shutdown_handle();
        assert!(!shutdown.load(std::sync::atomic::Ordering::Relaxed));
    }

    #[test]
    fn test_daemon_shutdown_handle_set() {
        let config = Config::default();
        let options = DaemonOptions::default();
        let daemon = Daemon::new(config, options);

        let shutdown = daemon.shutdown_handle();

        // Initially not set
        assert!(!shutdown.load(std::sync::atomic::Ordering::Relaxed));

        // Set shutdown
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);

        // Verify it's set
        assert!(shutdown.load(std::sync::atomic::Ordering::Relaxed));
    }

    #[test]
    fn test_daemon_initial_state() {
        let config = Config::default();
        let options = DaemonOptions::default();
        let daemon = Daemon::new(config, options);

        // Verify initial state is Stopped
        assert_eq!(daemon.state(), DaemonState::Stopped);
        assert!(!daemon.is_running());

        // Verify no monitors are set up
        assert!(daemon.volume_monitors.is_empty());
        assert!(daemon.file_watcher.is_none());
        assert!(daemon.watcher_receiver.is_none());

        // Verify path cache is empty
        assert!(daemon.path_cache.is_empty());
    }

    #[test]
    fn test_daemon_is_paused_initially_false() {
        let config = Config::default();
        let options = DaemonOptions::default();
        let daemon = Daemon::new(config, options);

        assert!(!daemon.is_paused);
    }

    #[test]
    fn test_daemon_options_debug() {
        let options = DaemonOptions::default();
        let debug_str = format!("{options:?}");
        assert!(debug_str.contains("DaemonOptions"));
        assert!(debug_str.contains("rescan"));
    }

    #[test]
    fn test_volume_monitor_struct() {
        // VolumeMonitor is private, but we can test it exists via its usage in Daemon
        let config = Config::default();
        let options = DaemonOptions::default();
        let daemon = Daemon::new(config, options);

        // Volume monitors should be empty initially
        assert!(daemon.volume_monitors.is_empty());
    }

    #[test]
    fn test_daemon_state_not_running_when_stopped() {
        let config = Config::default();
        let options = DaemonOptions::default();
        let daemon = Daemon::new(config, options);

        assert_eq!(daemon.state(), DaemonState::Stopped);
        assert!(!daemon.is_running());
    }

    #[test]
    fn test_daemon_ipc_state_initialized() {
        let config = Config::default();
        let options = DaemonOptions::default();
        let daemon = Daemon::new(config, options);

        // IPC state should be initialized
        assert_eq!(daemon.ipc_state.state.load(), filefind::DaemonStateInfo::Stopped);
        assert!(!daemon.ipc_state.is_paused.load(std::sync::atomic::Ordering::Relaxed));
    }

    #[test]
    fn test_get_configured_drives_empty() {
        let config = Config::default();
        let options = DaemonOptions::default();
        let daemon = Daemon::new(config, options);

        let drives = daemon.get_configured_drives();
        assert!(drives.is_empty());
    }

    #[test]
    fn test_get_configured_drives_single_drive() {
        let mut config = Config::default();
        config.daemon.paths = vec!["C:\\Users".to_string()];
        let options = DaemonOptions::default();
        let daemon = Daemon::new(config, options);

        let drives = daemon.get_configured_drives();
        assert_eq!(drives, vec!['C']);
    }

    #[test]
    fn test_get_configured_drives_multiple_drives() {
        let mut config = Config::default();
        config.daemon.paths = vec![
            "C:\\Users".to_string(),
            "D:\\Projects".to_string(),
            "E:\\Data".to_string(),
        ];
        let options = DaemonOptions::default();
        let daemon = Daemon::new(config, options);

        let drives = daemon.get_configured_drives();
        assert_eq!(drives, vec!['C', 'D', 'E']);
    }

    #[test]
    fn test_get_configured_drives_deduplicates() {
        let mut config = Config::default();
        config.daemon.paths = vec![
            "C:\\Users".to_string(),
            "C:\\Projects".to_string(),
            "D:\\Data".to_string(),
            "C:\\Documents".to_string(),
        ];
        let options = DaemonOptions::default();
        let daemon = Daemon::new(config, options);

        let drives = daemon.get_configured_drives();
        assert_eq!(drives, vec!['C', 'D']);
    }

    #[test]
    fn test_get_configured_drives_lowercase_normalized() {
        let mut config = Config::default();
        config.daemon.paths = vec!["c:\\Users".to_string(), "d:\\Projects".to_string()];
        let options = DaemonOptions::default();
        let daemon = Daemon::new(config, options);

        let drives = daemon.get_configured_drives();
        assert_eq!(drives, vec!['C', 'D']);
    }

    #[test]
    fn test_get_configured_drives_ignores_unc_paths() {
        let mut config = Config::default();
        config.daemon.paths = vec![
            "C:\\Users".to_string(),
            "\\\\server\\share".to_string(),
            "\\\\192.168.1.1\\data".to_string(),
        ];
        let options = DaemonOptions::default();
        let daemon = Daemon::new(config, options);

        let drives = daemon.get_configured_drives();
        assert_eq!(drives, vec!['C']);
    }

    #[test]
    fn test_get_configured_drives_drive_letter_only() {
        let mut config = Config::default();
        config.daemon.paths = vec!["C:".to_string(), "D:\\".to_string()];
        let options = DaemonOptions::default();
        let daemon = Daemon::new(config, options);

        let drives = daemon.get_configured_drives();
        assert_eq!(drives, vec!['C', 'D']);
    }
}
