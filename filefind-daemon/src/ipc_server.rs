//! IPC server for daemon communication.
//!
//! This module provides the server-side implementation of the IPC protocol,
//! allowing clients (CLI, tray app) to control and query the daemon.
//!
//! Uses postcard binary serialization for efficient, compact messages.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use anyhow::Result;
use filefind::{
    DaemonCommand, DaemonResponse, DaemonStateInfo, DaemonStatus, Database, deserialize_command, get_ipc_path,
    read_message, serialize_response, write_message,
};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Commands that can be sent to the daemon from the IPC server.
#[derive(Debug)]
pub enum IpcToDaemon {
    /// Request to stop the daemon.
    Stop,
    /// Request to rescan.
    Rescan,
    /// Request to pause indexing.
    Pause,
    /// Request to resume indexing.
    Resume,
    /// Request to prune missing entries from the database.
    Prune,
}

/// Shared state that the IPC server uses to report daemon status.
pub struct IpcServerState {
    /// Current daemon state.
    pub state: AtomicDaemonState,
    /// Whether indexing is paused.
    pub is_paused: AtomicBool,
    /// Number of indexed files.
    pub indexed_files: AtomicU64,
    /// Number of indexed directories.
    pub indexed_directories: AtomicU64,
    /// Number of monitored volumes.
    pub monitored_volumes: AtomicU64,
    /// Daemon start time.
    pub start_time: Instant,
}

/// Atomic wrapper for daemon state.
pub struct AtomicDaemonState(AtomicU8);

/// Internal representation for atomic state.
use std::sync::atomic::AtomicU8;

impl AtomicDaemonState {
    /// Create a new atomic daemon state.
    #[must_use]
    pub const fn new(state: DaemonStateInfo) -> Self {
        Self(AtomicU8::new(state_to_u8(state)))
    }

    /// Load the current state.
    #[must_use]
    pub fn load(&self) -> DaemonStateInfo {
        u8_to_state(self.0.load(Ordering::Relaxed))
    }

    /// Store a new state.
    pub fn store(&self, state: DaemonStateInfo) {
        self.0.store(state_to_u8(state), Ordering::Relaxed);
    }
}

/// Convert daemon state to u8 for atomic storage.
const fn state_to_u8(state: DaemonStateInfo) -> u8 {
    match state {
        DaemonStateInfo::Stopped => 0,
        DaemonStateInfo::Starting => 1,
        DaemonStateInfo::Running => 2,
        DaemonStateInfo::Scanning => 3,
        DaemonStateInfo::Stopping => 4,
    }
}

/// Convert u8 to daemon state.
const fn u8_to_state(value: u8) -> DaemonStateInfo {
    match value {
        1 => DaemonStateInfo::Starting,
        2 => DaemonStateInfo::Running,
        3 => DaemonStateInfo::Scanning,
        4 => DaemonStateInfo::Stopping,
        // 0 and any other value default to Stopped
        _ => DaemonStateInfo::Stopped,
    }
}

impl IpcServerState {
    /// Create a new IPC server state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: AtomicDaemonState::new(DaemonStateInfo::Stopped),
            is_paused: AtomicBool::new(false),
            indexed_files: AtomicU64::new(0),
            indexed_directories: AtomicU64::new(0),
            monitored_volumes: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }

    /// Get the current daemon status.
    #[must_use]
    pub fn get_status(&self) -> DaemonStatus {
        DaemonStatus {
            state: self.state.load(),
            indexed_files: self.indexed_files.load(Ordering::Relaxed),
            indexed_directories: self.indexed_directories.load(Ordering::Relaxed),
            monitored_volumes: self.monitored_volumes.load(Ordering::Relaxed) as u32,
            uptime_seconds: self.start_time.elapsed().as_secs(),
            is_paused: self.is_paused.load(Ordering::Relaxed),
        }
    }

    /// Update file counts from database.
    pub fn update_from_database(&self, database: &Database) {
        if let Ok(stats) = database.get_stats() {
            self.indexed_files.store(stats.total_files, Ordering::Relaxed);
            self.indexed_directories
                .store(stats.total_directories, Ordering::Relaxed);
            self.monitored_volumes.store(stats.volume_count, Ordering::Relaxed);
        }
    }
}

impl Default for IpcServerState {
    fn default() -> Self {
        Self::new()
    }
}

/// IPC server that handles client connections.
pub struct IpcServer {
    /// Shared state for reporting daemon status.
    state: Arc<IpcServerState>,
    /// Channel to send commands to the daemon.
    command_sender: mpsc::Sender<IpcToDaemon>,
    /// Shutdown signal.
    shutdown: Arc<AtomicBool>,
}

impl IpcServer {
    /// Create a new IPC server.
    #[must_use]
    pub const fn new(
        state: Arc<IpcServerState>,
        command_sender: mpsc::Sender<IpcToDaemon>,
        shutdown: Arc<AtomicBool>,
    ) -> Self {
        Self {
            state,
            command_sender,
            shutdown,
        }
    }

    /// Start the IPC server.
    ///
    /// This runs in a separate task and handles incoming client connections.
    pub fn run_blocking(&self) {
        info!("Starting IPC server");

        #[cfg(windows)]
        {
            self.run_windows_blocking();
        }

        #[cfg(not(windows))]
        {
            self.run_unix_blocking();
        }
    }

    /// Run the IPC server on Windows using named pipes (blocking version).
    #[cfg(windows)]
    fn run_windows_blocking(&self) {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::io::{FromRawHandle, IntoRawHandle, RawHandle};
        use windows::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows::Win32::Storage::FileSystem::{FlushFileBuffers, PIPE_ACCESS_DUPLEX};
        use windows::Win32::System::Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE,
            PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
        };

        let pipe_path = get_ipc_path();
        let pipe_path_wide: Vec<u16> = OsStr::new(pipe_path.to_str().unwrap_or(r"\\.\pipe\filefind-daemon"))
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        info!("IPC server listening on: {}", pipe_path.display());

        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                info!("IPC server shutting down");
                break;
            }

            // Create named pipe instance
            // SAFETY: CreateNamedPipeW is safe with valid parameters
            let pipe_handle = unsafe {
                CreateNamedPipeW(
                    windows::core::PCWSTR(pipe_path_wide.as_ptr()),
                    PIPE_ACCESS_DUPLEX,
                    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                    PIPE_UNLIMITED_INSTANCES,
                    4096,
                    4096,
                    0,
                    None,
                )
            };

            if pipe_handle == INVALID_HANDLE_VALUE {
                error!("Failed to create named pipe");
                std::thread::sleep(std::time::Duration::from_secs(1));
                continue;
            }

            // Wait for a client to connect (blocking)
            // SAFETY: ConnectNamedPipe is safe with valid handle
            let connected = unsafe { ConnectNamedPipe(pipe_handle, None) };

            if connected.is_err() && !self.shutdown.load(Ordering::Relaxed) {
                // Check if it's ERROR_PIPE_CONNECTED (client already connected)
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(535) {
                    // ERROR_PIPE_CONNECTED
                    warn!("ConnectNamedPipe failed: {}", error);
                    // SAFETY: CloseHandle is safe with valid handle
                    unsafe {
                        let _ = CloseHandle(pipe_handle);
                    }
                    continue;
                }
            }

            if self.shutdown.load(Ordering::Relaxed) {
                // SAFETY: CloseHandle is safe with valid handle
                unsafe {
                    let _ = CloseHandle(pipe_handle);
                }
                break;
            }

            debug!("Client connected to IPC server");

            // Handle the client connection
            let raw_handle = pipe_handle.0 as RawHandle;

            // SAFETY: We own this handle and will manage its lifetime
            let file = unsafe { std::fs::File::from_raw_handle(raw_handle) };

            if let Err(error) = self.handle_windows_client_sync(&file) {
                warn!("Error handling client: {}", error);
            }

            // Flush the pipe
            // SAFETY: FlushFileBuffers is safe with valid handle
            unsafe {
                let _ = FlushFileBuffers(pipe_handle);
            }

            // Take back the raw handle without closing it
            let _ = file.into_raw_handle();

            // Disconnect and close pipe
            // SAFETY: DisconnectNamedPipe and CloseHandle are safe with valid handle
            unsafe {
                let _ = DisconnectNamedPipe(pipe_handle);
                let _ = CloseHandle(pipe_handle);
            }
        }
    }

    /// Handle a Windows named pipe client synchronously.
    #[cfg(windows)]
    fn handle_windows_client_sync(&self, file: &std::fs::File) -> Result<()> {
        // Read the command using binary protocol
        let mut reader = file;
        let Ok(command_bytes) = read_message(&mut reader) else {
            return Ok(());
        };

        if command_bytes.is_empty() {
            return Ok(());
        }

        // Parse and handle the command
        let response = match deserialize_command(&command_bytes) {
            Ok(command) => {
                debug!("Received command: {:?}", command);
                self.handle_command_sync(command)
            }
            Err(error) => {
                warn!("Failed to parse command: {}", error);
                DaemonResponse::Error(format!("Invalid command: {error}"))
            }
        };

        // Send response
        let response_bytes = serialize_response(&response)?;
        let mut write_file = file;
        write_message(&mut write_file, &response_bytes)?;

        Ok(())
    }

    /// Run the IPC server on Unix using domain sockets (blocking version).
    #[cfg(not(windows))]
    fn run_unix_blocking(&self) {
        use std::os::unix::net::UnixListener;

        let socket_path = get_ipc_path();

        // Remove existing socket file if it exists
        let _ = std::fs::remove_file(&socket_path);

        // Create the socket directory if needed
        if let Some(parent) = socket_path.parent()
            && let Err(error) = std::fs::create_dir_all(parent)
        {
            error!("Failed to create socket directory: {}", error);
            return;
        }

        let listener = match UnixListener::bind(&socket_path) {
            Ok(listener) => listener,
            Err(error) => {
                error!("Failed to bind Unix socket: {}", error);
                return;
            }
        };

        // Set non-blocking to allow periodic shutdown checks
        if let Err(error) = listener.set_nonblocking(true) {
            error!("Failed to set non-blocking: {}", error);
            return;
        }

        info!("IPC server listening on: {}", socket_path.display());

        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                info!("IPC server shutting down");
                break;
            }

            // Try to accept a connection
            match listener.accept() {
                Ok((stream, _)) => {
                    debug!("Client connected to IPC server");
                    if let Err(error) = self.handle_unix_client_sync(stream) {
                        warn!("Error handling client: {}", error);
                    }
                }
                Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    // No connection available, sleep briefly and try again
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    continue;
                }
                Err(error) => {
                    warn!("Failed to accept connection: {}", error);
                }
            }
        }

        // Clean up socket file
        let _ = std::fs::remove_file(&socket_path);
    }

    /// Handle a Unix domain socket client synchronously.
    #[cfg(not(windows))]
    fn handle_unix_client_sync(&self, stream: std::os::unix::net::UnixStream) -> Result<()> {
        // Set blocking for this connection
        stream.set_nonblocking(false)?;

        // Read the command using binary protocol
        let mut reader = &stream;
        let Ok(command_bytes) = read_message(&mut reader) else {
            return Ok(());
        };

        if command_bytes.is_empty() {
            return Ok(());
        }

        // Parse and handle the command
        let response = match deserialize_command(&command_bytes) {
            Ok(command) => {
                debug!("Received command: {:?}", command);
                self.handle_command_sync(command)
            }
            Err(error) => {
                warn!("Failed to parse command: {}", error);
                DaemonResponse::Error(format!("Invalid command: {error}"))
            }
        };

        // Send response
        let response_bytes = serialize_response(&response)?;
        let mut write_stream = &stream;
        write_message(&mut write_stream, &response_bytes)?;

        Ok(())
    }

    /// Handle a daemon command synchronously and return a response.
    fn handle_command_sync(&self, command: DaemonCommand) -> DaemonResponse {
        match command {
            DaemonCommand::Ping => {
                debug!("Received ping");
                DaemonResponse::Pong
            }
            DaemonCommand::GetStatus => {
                debug!("Received status request");
                let status = self.state.get_status();
                DaemonResponse::Status(status)
            }
            DaemonCommand::Stop => {
                info!("Received stop command");
                if self.command_sender.blocking_send(IpcToDaemon::Stop).is_ok() {
                    DaemonResponse::Ok
                } else {
                    DaemonResponse::Error("Failed to send stop command".to_string())
                }
            }
            DaemonCommand::Rescan => {
                info!("Received rescan command");
                if self.command_sender.blocking_send(IpcToDaemon::Rescan).is_ok() {
                    DaemonResponse::Ok
                } else {
                    DaemonResponse::Error("Failed to send rescan command".to_string())
                }
            }
            DaemonCommand::Pause => {
                info!("Received pause command");
                if self.command_sender.blocking_send(IpcToDaemon::Pause).is_ok() {
                    self.state.is_paused.store(true, Ordering::Relaxed);
                    DaemonResponse::Ok
                } else {
                    DaemonResponse::Error("Failed to send pause command".to_string())
                }
            }
            DaemonCommand::Resume => {
                info!("Received resume command");
                if self.command_sender.blocking_send(IpcToDaemon::Resume).is_ok() {
                    self.state.is_paused.store(false, Ordering::Relaxed);
                    DaemonResponse::Ok
                } else {
                    DaemonResponse::Error("Failed to send resume command".to_string())
                }
            }
            DaemonCommand::Prune => {
                info!("Received prune command");
                if self.command_sender.blocking_send(IpcToDaemon::Prune).is_ok() {
                    DaemonResponse::Ok
                } else {
                    DaemonResponse::Error("Failed to send prune command".to_string())
                }
            }
        }
    }
}

/// Spawn the IPC server as a background thread.
///
/// Returns a channel receiver for commands from clients.
pub fn spawn_ipc_server(state: Arc<IpcServerState>, shutdown: Arc<AtomicBool>) -> mpsc::Receiver<IpcToDaemon> {
    let (command_sender, command_receiver) = mpsc::channel(32);

    let server = IpcServer::new(state, command_sender, shutdown);

    std::thread::Builder::new()
        .name("ipc-server".to_string())
        .spawn(move || {
            server.run_blocking();
        })
        .expect("Failed to spawn IPC server thread");

    command_receiver
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_atomic_daemon_state() {
        let state = AtomicDaemonState::new(DaemonStateInfo::Stopped);
        assert_eq!(state.load(), DaemonStateInfo::Stopped);

        state.store(DaemonStateInfo::Running);
        assert_eq!(state.load(), DaemonStateInfo::Running);

        state.store(DaemonStateInfo::Scanning);
        assert_eq!(state.load(), DaemonStateInfo::Scanning);
    }

    #[test]
    fn test_atomic_daemon_state_all_states() {
        let state = AtomicDaemonState::new(DaemonStateInfo::Stopped);

        // Test all state transitions
        for daemon_state in [
            DaemonStateInfo::Stopped,
            DaemonStateInfo::Starting,
            DaemonStateInfo::Running,
            DaemonStateInfo::Scanning,
            DaemonStateInfo::Stopping,
        ] {
            state.store(daemon_state);
            assert_eq!(state.load(), daemon_state);
        }
    }

    #[test]
    fn test_daemon_state_info_conversion() {
        let states = [
            DaemonStateInfo::Stopped,
            DaemonStateInfo::Starting,
            DaemonStateInfo::Running,
            DaemonStateInfo::Scanning,
            DaemonStateInfo::Stopping,
        ];

        for state in states {
            let value: u8 = state_to_u8(state);
            let converted: DaemonStateInfo = u8_to_state(value);
            assert_eq!(state, converted);
        }
    }

    #[test]
    fn test_state_to_u8_values() {
        assert_eq!(state_to_u8(DaemonStateInfo::Stopped), 0);
        assert_eq!(state_to_u8(DaemonStateInfo::Starting), 1);
        assert_eq!(state_to_u8(DaemonStateInfo::Running), 2);
        assert_eq!(state_to_u8(DaemonStateInfo::Scanning), 3);
        assert_eq!(state_to_u8(DaemonStateInfo::Stopping), 4);
    }

    #[test]
    fn test_u8_to_state_values() {
        assert_eq!(u8_to_state(0), DaemonStateInfo::Stopped);
        assert_eq!(u8_to_state(1), DaemonStateInfo::Starting);
        assert_eq!(u8_to_state(2), DaemonStateInfo::Running);
        assert_eq!(u8_to_state(3), DaemonStateInfo::Scanning);
        assert_eq!(u8_to_state(4), DaemonStateInfo::Stopping);
    }

    #[test]
    fn test_u8_to_state_invalid_values() {
        // Invalid values should default to Stopped
        assert_eq!(u8_to_state(5), DaemonStateInfo::Stopped);
        assert_eq!(u8_to_state(100), DaemonStateInfo::Stopped);
        assert_eq!(u8_to_state(255), DaemonStateInfo::Stopped);
    }

    #[test]
    fn test_ipc_server_state_default() {
        let state = IpcServerState::default();
        assert_eq!(state.state.load(), DaemonStateInfo::Stopped);
        assert!(!state.is_paused.load(Ordering::Relaxed));
        assert_eq!(state.indexed_files.load(Ordering::Relaxed), 0);
        assert_eq!(state.indexed_directories.load(Ordering::Relaxed), 0);
        assert_eq!(state.monitored_volumes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_ipc_server_state_new() {
        let state = IpcServerState::new();

        assert_eq!(state.state.load(), DaemonStateInfo::Stopped);
        assert!(!state.is_paused.load(Ordering::Relaxed));
        assert_eq!(state.indexed_files.load(Ordering::Relaxed), 0);
        assert_eq!(state.indexed_directories.load(Ordering::Relaxed), 0);
        assert_eq!(state.monitored_volumes.load(Ordering::Relaxed), 0);
        // start_time should be initialized to now (roughly)
        assert!(state.start_time.elapsed().as_secs() < 1);
    }

    #[test]
    fn test_ipc_server_state_get_status() {
        let state = IpcServerState::new();
        state.state.store(DaemonStateInfo::Running);
        state.indexed_files.store(1000, Ordering::Relaxed);
        state.indexed_directories.store(100, Ordering::Relaxed);
        state.monitored_volumes.store(2, Ordering::Relaxed);

        let status = state.get_status();
        assert_eq!(status.state, DaemonStateInfo::Running);
        assert_eq!(status.indexed_files, 1000);
        assert_eq!(status.indexed_directories, 100);
        assert_eq!(status.monitored_volumes, 2);
        assert!(!status.is_paused);
    }

    #[test]
    fn test_ipc_server_state_get_status_paused() {
        let state = IpcServerState::new();
        state.state.store(DaemonStateInfo::Running);
        state.is_paused.store(true, Ordering::Relaxed);

        let status = state.get_status();
        assert!(status.is_paused);
    }

    #[test]
    fn test_ipc_server_state_get_status_uptime() {
        let state = IpcServerState::new();

        // Wait a tiny bit to ensure uptime is > 0
        std::thread::sleep(std::time::Duration::from_millis(10));

        let status = state.get_status();
        // Uptime should be at least 0 (could be 0 if very fast)
        assert!(status.uptime_seconds < 10); // Should definitely be less than 10 seconds
    }

    #[test]
    fn test_ipc_server_state_large_values() {
        let state = IpcServerState::new();

        state.indexed_files.store(u64::MAX, Ordering::Relaxed);
        state.indexed_directories.store(u64::MAX, Ordering::Relaxed);
        state.monitored_volumes.store(u64::MAX, Ordering::Relaxed);

        let status = state.get_status();
        assert_eq!(status.indexed_files, u64::MAX);
        assert_eq!(status.indexed_directories, u64::MAX);
        // monitored_volumes is cast to u32
        assert_eq!(status.monitored_volumes, u32::MAX);
    }

    #[test]
    fn test_ipc_server_state_concurrent_updates() {
        use std::sync::Arc;
        use std::thread;

        let state = Arc::new(IpcServerState::new());

        let handles: Vec<_> = (0..4)
            .map(|index| {
                let state_clone = Arc::clone(&state);
                thread::spawn(move || {
                    for _ in 0..100 {
                        state_clone.indexed_files.fetch_add(1, Ordering::Relaxed);
                        state_clone.indexed_directories.fetch_add(1, Ordering::Relaxed);

                        // Toggle state
                        if index % 2 == 0 {
                            state_clone.state.store(DaemonStateInfo::Running);
                        } else {
                            state_clone.state.store(DaemonStateInfo::Scanning);
                        }
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("Thread panicked");
        }

        // Each of 4 threads added 100, so total should be 400
        assert_eq!(state.indexed_files.load(Ordering::Relaxed), 400);
        assert_eq!(state.indexed_directories.load(Ordering::Relaxed), 400);
    }

    #[test]
    fn test_ipc_server_state_update_is_paused() {
        let state = IpcServerState::new();

        assert!(!state.is_paused.load(Ordering::Relaxed));

        state.is_paused.store(true, Ordering::Relaxed);
        assert!(state.is_paused.load(Ordering::Relaxed));

        let status = state.get_status();
        assert!(status.is_paused);

        state.is_paused.store(false, Ordering::Relaxed);
        assert!(!state.is_paused.load(Ordering::Relaxed));
    }

    #[test]
    fn test_ipc_server_state_state_transitions() {
        let state = IpcServerState::new();

        // Simulate typical lifecycle
        assert_eq!(state.state.load(), DaemonStateInfo::Stopped);

        state.state.store(DaemonStateInfo::Starting);
        assert_eq!(state.state.load(), DaemonStateInfo::Starting);

        state.state.store(DaemonStateInfo::Scanning);
        assert_eq!(state.state.load(), DaemonStateInfo::Scanning);

        state.state.store(DaemonStateInfo::Running);
        assert_eq!(state.state.load(), DaemonStateInfo::Running);

        state.state.store(DaemonStateInfo::Stopping);
        assert_eq!(state.state.load(), DaemonStateInfo::Stopping);

        state.state.store(DaemonStateInfo::Stopped);
        assert_eq!(state.state.load(), DaemonStateInfo::Stopped);
    }

    #[test]
    fn test_atomic_daemon_state_default_is_stopped() {
        let state = AtomicDaemonState::new(DaemonStateInfo::Stopped);
        assert_eq!(state.load(), DaemonStateInfo::Stopped);
    }

    #[test]
    fn test_ipc_server_state_monitored_volumes_increment() {
        let state = IpcServerState::new();

        state.monitored_volumes.store(0, Ordering::Relaxed);
        assert_eq!(state.monitored_volumes.load(Ordering::Relaxed), 0);

        state.monitored_volumes.fetch_add(1, Ordering::Relaxed);
        assert_eq!(state.monitored_volumes.load(Ordering::Relaxed), 1);

        state.monitored_volumes.fetch_add(5, Ordering::Relaxed);
        assert_eq!(state.monitored_volumes.load(Ordering::Relaxed), 6);
    }

    #[test]
    fn test_daemon_state_info_debug() {
        let state = DaemonStateInfo::Running;
        let debug_str = format!("{state:?}");
        assert!(debug_str.contains("Running"));
    }

    #[test]
    fn test_ipc_to_daemon_debug() {
        let command = IpcToDaemon::Stop;
        let debug_str = format!("{command:?}");
        assert!(debug_str.contains("Stop"));
    }

    #[test]
    fn test_ipc_server_state_zero_uptime_immediately() {
        let state = IpcServerState::new();
        let status = state.get_status();

        // Uptime should be 0 or very close to 0 immediately after creation
        assert!(status.uptime_seconds < 2);
    }
}
