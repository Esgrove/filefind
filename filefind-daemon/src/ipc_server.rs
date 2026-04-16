//! IPC server for daemon communication.
//!
//! This module provides the server-side implementation of the IPC protocol,
//! allowing clients (CLI, tray app) to control and query the daemon.
//!
//! Uses postcard binary serialization for efficient, compact messages.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use anyhow::Result;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use filefind::{DaemonCommand, DaemonResponse, DaemonStateInfo, DaemonStatus, Database, get_ipc_path};

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

/// IPC server that handles client connections.
pub struct IpcServer {
    /// Shared state for reporting daemon status.
    state: Arc<IpcServerState>,
    /// Channel to send commands to the daemon.
    command_sender: mpsc::Sender<IpcToDaemon>,
    /// Shutdown signal.
    shutdown: Arc<AtomicBool>,
    /// Custom pipe/socket path. When `None`, uses the default from [`get_ipc_path`].
    pipe_path: Option<PathBuf>,
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

impl AtomicDaemonState {
    /// Create a new atomic daemon state.
    #[must_use]
    pub const fn new(state: DaemonStateInfo) -> Self {
        Self(AtomicU8::new(Self::state_to_u8(state)))
    }

    /// Load the current state.
    #[must_use]
    pub fn load(&self) -> DaemonStateInfo {
        Self::u8_to_state(self.0.load(Ordering::Relaxed))
    }

    /// Store a new state.
    pub fn store(&self, state: DaemonStateInfo) {
        self.0.store(Self::state_to_u8(state), Ordering::Relaxed);
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
            pipe_path: None,
        }
    }

    /// Set a custom pipe/socket path for this server.
    ///
    /// When set, the server listens on this path instead of the default.
    /// Primarily useful for integration testing with isolated pipe names.
    #[must_use]
    pub fn with_pipe_path(mut self, path: PathBuf) -> Self {
        self.pipe_path = Some(path);
        self
    }

    /// Get the effective pipe/socket path.
    ///
    /// Returns the custom path if set, otherwise the default from [`get_ipc_path`].
    fn effective_pipe_path(&self) -> &Path {
        self.pipe_path.as_deref().unwrap_or_else(|| get_ipc_path().as_path())
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
        use windows::Win32::Security::{SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR};
        use windows::Win32::Storage::FileSystem::{FlushFileBuffers, PIPE_ACCESS_DUPLEX};
        use windows::Win32::System::Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE,
            PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
        };

        let pipe_path = self.effective_pipe_path();
        let pipe_path_wide: Vec<u16> = OsStr::new(pipe_path.to_str().unwrap_or(r"\\.\pipe\filefind-daemon"))
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        // Create a permissive security descriptor so non-elevated processes
        // (CLI, tray app) can connect when the daemon runs elevated.
        let mut security_descriptor = SECURITY_DESCRIPTOR::default();
        let security_attributes: SECURITY_ATTRIBUTES =
            match Self::create_permissive_security_attributes(&mut security_descriptor) {
                Ok(sa) => sa,
                Err(error) => {
                    error!("Failed to create pipe security attributes: {error}");
                    return;
                }
            };

        info!("IPC server listening on: {}", pipe_path.display());

        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                info!("IPC server shutting down");
                break;
            }

            // Create named pipe instance with permissive security so non-elevated
            // clients can connect when the daemon runs with admin privileges.
            // SAFETY: CreateNamedPipeW is safe with valid parameters.
            let pipe_handle = unsafe {
                CreateNamedPipeW(
                    windows::core::PCWSTR(pipe_path_wide.as_ptr()),
                    PIPE_ACCESS_DUPLEX,
                    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                    PIPE_UNLIMITED_INSTANCES,
                    4096,
                    4096,
                    0,
                    Some((&raw const security_attributes).cast()),
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

    /// Create a [`SECURITY_ATTRIBUTES`] with a null DACL.
    ///
    /// A null DACL grants full access to everyone, which is acceptable for a
    /// local-only named pipe used for desktop IPC. This allows non-elevated
    /// processes (CLI, tray app) to connect when the daemon runs with admin
    /// privileges (e.g. started by a scheduled task for MFT/USN access).
    ///
    /// The returned struct borrows `security_descriptor`, so the caller must
    /// keep it alive for as long as the attributes are in use.
    #[cfg(windows)]
    fn create_permissive_security_attributes(
        security_descriptor: &mut windows::Win32::Security::SECURITY_DESCRIPTOR,
    ) -> Result<windows::Win32::Security::SECURITY_ATTRIBUTES> {
        use windows::Win32::Security::{
            InitializeSecurityDescriptor, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, SetSecurityDescriptorDacl,
        };

        /// Revision level for `InitializeSecurityDescriptor` (always 1).
        const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

        // SAFETY: InitializeSecurityDescriptor initializes an allocated descriptor.
        unsafe {
            InitializeSecurityDescriptor(
                PSECURITY_DESCRIPTOR((&raw mut *security_descriptor).cast()),
                SECURITY_DESCRIPTOR_REVISION,
            )
        }
        .map_err(|error| anyhow::anyhow!("InitializeSecurityDescriptor failed: {error}"))?;

        // Set a null DACL which grants full access to everyone.
        // SAFETY: The security descriptor was just initialized above.
        unsafe {
            SetSecurityDescriptorDacl(
                PSECURITY_DESCRIPTOR((&raw mut *security_descriptor).cast()),
                true,
                None,
                false,
            )
        }
        .map_err(|error| anyhow::anyhow!("SetSecurityDescriptorDacl failed: {error}"))?;

        Ok(SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
                .expect("SECURITY_ATTRIBUTES size fits u32"),
            lpSecurityDescriptor: (&raw mut *security_descriptor).cast(),
            bInheritHandle: false.into(),
        })
    }

    /// Handle a Windows named pipe client synchronously.
    #[cfg(windows)]
    fn handle_windows_client_sync(&self, file: &std::fs::File) -> Result<()> {
        // Read the command using binary protocol
        let mut reader = file;
        let response = match DaemonCommand::read_from(&mut reader) {
            Ok(command) => {
                debug!("Received command: {:?}", command);
                self.handle_command_sync(command)
            }
            Err(error) => {
                warn!("Failed to parse command from Windows named pipe client: {}", error);
                DaemonResponse::Error(format!("Invalid command: failed to read/parse IPC message: {error}"))
            }
        };

        // Send response
        let mut write_file = file;
        response.write_to(&mut write_file)?;

        Ok(())
    }

    /// Run the IPC server on Unix using domain sockets (blocking version).
    #[cfg(not(windows))]
    fn run_unix_blocking(&self) {
        use std::os::unix::net::UnixListener;

        let socket_path = self.effective_pipe_path();

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
        let response = match DaemonCommand::read_from(&mut reader) {
            Ok(command) => {
                debug!("Received command: {:?}", command);
                self.handle_command_sync(command)
            }
            Err(error) => {
                warn!("Failed to parse command from Unix domain socket client: {}", error);
                DaemonResponse::Error(format!("Invalid command: failed to read/parse IPC message: {error}"))
            }
        };

        // Send response
        let mut write_stream = &stream;
        response.write_to(&mut write_stream)?;

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

impl Default for IpcServerState {
    fn default() -> Self {
        Self::new()
    }
}

/// Spawn the IPC server as a background thread.
///
/// Returns a channel receiver for commands from clients.
pub fn spawn_ipc_server(state: Arc<IpcServerState>, shutdown: Arc<AtomicBool>) -> mpsc::Receiver<IpcToDaemon> {
    spawn_ipc_server_with_path(state, shutdown, None)
}

/// Spawn the IPC server as a background thread with an optional custom pipe path.
///
/// When `pipe_path` is `None`, the server listens on the default path.
/// Returns a channel receiver for commands from clients.
pub fn spawn_ipc_server_with_path(
    state: Arc<IpcServerState>,
    shutdown: Arc<AtomicBool>,
    pipe_path: Option<PathBuf>,
) -> mpsc::Receiver<IpcToDaemon> {
    let (command_sender, command_receiver) = mpsc::channel(32);

    let mut server = IpcServer::new(state, command_sender, shutdown);
    if let Some(path) = pipe_path {
        server = server.with_pipe_path(path);
    }

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
            let value: u8 = AtomicDaemonState::state_to_u8(state);
            let converted: DaemonStateInfo = AtomicDaemonState::u8_to_state(value);
            assert_eq!(state, converted);
        }
    }

    #[test]
    fn test_state_to_u8_values() {
        assert_eq!(AtomicDaemonState::state_to_u8(DaemonStateInfo::Stopped), 0);
        assert_eq!(AtomicDaemonState::state_to_u8(DaemonStateInfo::Starting), 1);
        assert_eq!(AtomicDaemonState::state_to_u8(DaemonStateInfo::Running), 2);
        assert_eq!(AtomicDaemonState::state_to_u8(DaemonStateInfo::Scanning), 3);
        assert_eq!(AtomicDaemonState::state_to_u8(DaemonStateInfo::Stopping), 4);
    }

    #[test]
    fn test_u8_to_state_values() {
        assert_eq!(AtomicDaemonState::u8_to_state(0), DaemonStateInfo::Stopped);
        assert_eq!(AtomicDaemonState::u8_to_state(1), DaemonStateInfo::Starting);
        assert_eq!(AtomicDaemonState::u8_to_state(2), DaemonStateInfo::Running);
        assert_eq!(AtomicDaemonState::u8_to_state(3), DaemonStateInfo::Scanning);
        assert_eq!(AtomicDaemonState::u8_to_state(4), DaemonStateInfo::Stopping);
    }

    #[test]
    fn test_u8_to_state_invalid_values() {
        // Invalid values should default to Stopped
        assert_eq!(AtomicDaemonState::u8_to_state(5), DaemonStateInfo::Stopped);
        assert_eq!(AtomicDaemonState::u8_to_state(100), DaemonStateInfo::Stopped);
        assert_eq!(AtomicDaemonState::u8_to_state(255), DaemonStateInfo::Stopped);
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

    #[test]
    fn test_ipc_server_new() {
        let state = Arc::new(IpcServerState::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let (sender, _receiver) = mpsc::channel(32);

        let _server = IpcServer::new(Arc::clone(&state), sender, Arc::clone(&shutdown));

        // Server should be constructable without panic
        assert!(!shutdown.load(Ordering::Relaxed));
        assert_eq!(state.state.load(), DaemonStateInfo::Stopped);
    }

    #[test]
    fn test_ipc_server_with_pipe_path() {
        let state = Arc::new(IpcServerState::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let (sender, _receiver) = mpsc::channel(32);

        let custom_path = PathBuf::from(r"\\.\pipe\filefind-test-custom");
        let server =
            IpcServer::new(Arc::clone(&state), sender, Arc::clone(&shutdown)).with_pipe_path(custom_path.clone());

        assert_eq!(server.effective_pipe_path(), &custom_path);
    }

    #[test]
    fn test_ipc_server_effective_pipe_path_default() {
        let state = Arc::new(IpcServerState::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let (sender, _receiver) = mpsc::channel(32);

        let server = IpcServer::new(state, sender, shutdown);
        assert_eq!(server.effective_pipe_path(), filefind::get_ipc_path());
    }

    #[test]
    fn test_handle_command_sync_ping() {
        let state = Arc::new(IpcServerState::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let (sender, _receiver) = mpsc::channel(32);
        let server = IpcServer::new(state, sender, shutdown);

        let response = server.handle_command_sync(DaemonCommand::Ping);
        assert!(matches!(response, DaemonResponse::Pong));
    }

    #[test]
    fn test_handle_command_sync_get_status() {
        let state = Arc::new(IpcServerState::new());
        state.state.store(DaemonStateInfo::Running);
        state.indexed_files.store(42, Ordering::Relaxed);
        state.indexed_directories.store(7, Ordering::Relaxed);
        state.monitored_volumes.store(2, Ordering::Relaxed);

        let shutdown = Arc::new(AtomicBool::new(false));
        let (sender, _receiver) = mpsc::channel(32);
        let server = IpcServer::new(Arc::clone(&state), sender, shutdown);

        let response = server.handle_command_sync(DaemonCommand::GetStatus);
        match response {
            DaemonResponse::Status(status) => {
                assert_eq!(status.state, DaemonStateInfo::Running);
                assert_eq!(status.indexed_files, 42);
                assert_eq!(status.indexed_directories, 7);
                assert_eq!(status.monitored_volumes, 2);
                assert!(!status.is_paused);
            }
            other => panic!("Expected Status response, got {other:?}"),
        }
    }

    #[test]
    fn test_handle_command_sync_get_status_paused() {
        let state = Arc::new(IpcServerState::new());
        state.state.store(DaemonStateInfo::Running);
        state.is_paused.store(true, Ordering::Relaxed);

        let shutdown = Arc::new(AtomicBool::new(false));
        let (sender, _receiver) = mpsc::channel(32);
        let server = IpcServer::new(Arc::clone(&state), sender, shutdown);

        let response = server.handle_command_sync(DaemonCommand::GetStatus);
        match response {
            DaemonResponse::Status(status) => {
                assert!(status.is_paused);
            }
            other => panic!("Expected Status response, got {other:?}"),
        }
    }

    #[test]
    fn test_handle_command_sync_stop() {
        let state = Arc::new(IpcServerState::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let (sender, mut receiver) = mpsc::channel(32);
        let server = IpcServer::new(state, sender, shutdown);

        let response = server.handle_command_sync(DaemonCommand::Stop);
        assert!(matches!(response, DaemonResponse::Ok));

        // Verify the command was sent through the channel
        let command = receiver.try_recv().expect("Should have received a command");
        assert!(matches!(command, IpcToDaemon::Stop));
    }

    #[test]
    fn test_handle_command_sync_rescan() {
        let state = Arc::new(IpcServerState::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let (sender, mut receiver) = mpsc::channel(32);
        let server = IpcServer::new(state, sender, shutdown);

        let response = server.handle_command_sync(DaemonCommand::Rescan);
        assert!(matches!(response, DaemonResponse::Ok));

        let command = receiver.try_recv().expect("Should have received a command");
        assert!(matches!(command, IpcToDaemon::Rescan));
    }

    #[test]
    fn test_handle_command_sync_pause() {
        let state = Arc::new(IpcServerState::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let (sender, mut receiver) = mpsc::channel(32);
        let server = IpcServer::new(Arc::clone(&state), sender, shutdown);

        // Initially not paused
        assert!(!state.is_paused.load(Ordering::Relaxed));

        let response = server.handle_command_sync(DaemonCommand::Pause);
        assert!(matches!(response, DaemonResponse::Ok));

        // State should reflect paused
        assert!(state.is_paused.load(Ordering::Relaxed));

        let command = receiver.try_recv().expect("Should have received a command");
        assert!(matches!(command, IpcToDaemon::Pause));
    }

    #[test]
    fn test_handle_command_sync_resume() {
        let state = Arc::new(IpcServerState::new());
        state.is_paused.store(true, Ordering::Relaxed);

        let shutdown = Arc::new(AtomicBool::new(false));
        let (sender, mut receiver) = mpsc::channel(32);
        let server = IpcServer::new(Arc::clone(&state), sender, shutdown);

        let response = server.handle_command_sync(DaemonCommand::Resume);
        assert!(matches!(response, DaemonResponse::Ok));

        // State should reflect resumed
        assert!(!state.is_paused.load(Ordering::Relaxed));

        let command = receiver.try_recv().expect("Should have received a command");
        assert!(matches!(command, IpcToDaemon::Resume));
    }

    #[test]
    fn test_handle_command_sync_prune() {
        let state = Arc::new(IpcServerState::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let (sender, mut receiver) = mpsc::channel(32);
        let server = IpcServer::new(state, sender, shutdown);

        let response = server.handle_command_sync(DaemonCommand::Prune);
        assert!(matches!(response, DaemonResponse::Ok));

        let command = receiver.try_recv().expect("Should have received a command");
        assert!(matches!(command, IpcToDaemon::Prune));
    }

    #[test]
    fn test_handle_command_sync_stop_with_dropped_receiver() {
        let state = Arc::new(IpcServerState::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let (sender, receiver) = mpsc::channel(32);

        // Drop the receiver so the sender will fail
        drop(receiver);

        let server = IpcServer::new(state, sender, shutdown);

        let response = server.handle_command_sync(DaemonCommand::Stop);
        match response {
            DaemonResponse::Error(message) => {
                assert!(message.contains("Failed to send stop command"), "Got: {message}");
            }
            other => panic!("Expected Error response, got {other:?}"),
        }
    }

    #[test]
    fn test_handle_command_sync_rescan_with_dropped_receiver() {
        let state = Arc::new(IpcServerState::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let (sender, receiver) = mpsc::channel(32);
        drop(receiver);

        let server = IpcServer::new(state, sender, shutdown);

        let response = server.handle_command_sync(DaemonCommand::Rescan);
        match response {
            DaemonResponse::Error(message) => {
                assert!(message.contains("Failed to send rescan command"), "Got: {message}");
            }
            other => panic!("Expected Error response, got {other:?}"),
        }
    }

    #[test]
    fn test_handle_command_sync_pause_with_dropped_receiver() {
        let state = Arc::new(IpcServerState::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let (sender, receiver) = mpsc::channel(32);
        drop(receiver);

        let server = IpcServer::new(Arc::clone(&state), sender, shutdown);

        let response = server.handle_command_sync(DaemonCommand::Pause);
        match response {
            DaemonResponse::Error(message) => {
                assert!(message.contains("Failed to send pause command"), "Got: {message}");
            }
            other => panic!("Expected Error response, got {other:?}"),
        }

        // is_paused should NOT have been set because the send failed
        assert!(!state.is_paused.load(Ordering::Relaxed));
    }

    #[test]
    fn test_handle_command_sync_resume_with_dropped_receiver() {
        let state = Arc::new(IpcServerState::new());
        state.is_paused.store(true, Ordering::Relaxed);

        let shutdown = Arc::new(AtomicBool::new(false));
        let (sender, receiver) = mpsc::channel(32);
        drop(receiver);

        let server = IpcServer::new(Arc::clone(&state), sender, shutdown);

        let response = server.handle_command_sync(DaemonCommand::Resume);
        match response {
            DaemonResponse::Error(message) => {
                assert!(message.contains("Failed to send resume command"), "Got: {message}");
            }
            other => panic!("Expected Error response, got {other:?}"),
        }

        // is_paused should still be true because the send failed
        assert!(state.is_paused.load(Ordering::Relaxed));
    }

    #[test]
    fn test_handle_command_sync_prune_with_dropped_receiver() {
        let state = Arc::new(IpcServerState::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let (sender, receiver) = mpsc::channel(32);
        drop(receiver);

        let server = IpcServer::new(state, sender, shutdown);

        let response = server.handle_command_sync(DaemonCommand::Prune);
        match response {
            DaemonResponse::Error(message) => {
                assert!(message.contains("Failed to send prune command"), "Got: {message}");
            }
            other => panic!("Expected Error response, got {other:?}"),
        }
    }

    #[test]
    fn test_handle_command_sync_multiple_commands_sequentially() {
        let state = Arc::new(IpcServerState::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let (sender, mut receiver) = mpsc::channel(32);
        let server = IpcServer::new(Arc::clone(&state), sender, shutdown);

        // Send a sequence of commands
        assert!(matches!(
            server.handle_command_sync(DaemonCommand::Ping),
            DaemonResponse::Pong
        ));
        assert!(matches!(
            server.handle_command_sync(DaemonCommand::Pause),
            DaemonResponse::Ok
        ));
        assert!(matches!(
            server.handle_command_sync(DaemonCommand::GetStatus),
            DaemonResponse::Status(_)
        ));
        assert!(matches!(
            server.handle_command_sync(DaemonCommand::Resume),
            DaemonResponse::Ok
        ));
        assert!(matches!(
            server.handle_command_sync(DaemonCommand::Stop),
            DaemonResponse::Ok
        ));

        // Verify commands arrived in order (Ping and GetStatus don't send to channel)
        let cmd1 = receiver.try_recv().expect("Should have Pause");
        assert!(matches!(cmd1, IpcToDaemon::Pause));

        let cmd2 = receiver.try_recv().expect("Should have Resume");
        assert!(matches!(cmd2, IpcToDaemon::Resume));

        let cmd3 = receiver.try_recv().expect("Should have Stop");
        assert!(matches!(cmd3, IpcToDaemon::Stop));

        // No more commands
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn test_update_from_database() {
        let state = IpcServerState::new();
        let database = Database::open_in_memory().expect("Failed to create in-memory database");

        // Initially zero
        assert_eq!(state.indexed_files.load(Ordering::Relaxed), 0);
        assert_eq!(state.indexed_directories.load(Ordering::Relaxed), 0);
        assert_eq!(state.monitored_volumes.load(Ordering::Relaxed), 0);

        // Update from empty database
        state.update_from_database(&database);

        // Should remain zero for an empty database
        assert_eq!(state.indexed_files.load(Ordering::Relaxed), 0);
        assert_eq!(state.indexed_directories.load(Ordering::Relaxed), 0);
        assert_eq!(state.monitored_volumes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_update_from_database_with_data() {
        use filefind::{FileEntry, IndexedVolume, VolumeType};

        let state = IpcServerState::new();
        let database = Database::open_in_memory().expect("Failed to create in-memory database");

        // Insert a volume
        let volume = IndexedVolume {
            id: None,
            serial_number: "TEST-1234".to_string(),
            label: Some("TestVol".to_string()),
            mount_point: "C:".to_string(),
            volume_type: VolumeType::Ntfs,
            is_online: true,
            last_scan_time: None,
            last_usn: None,
        };
        let volume_id = database.upsert_volume(&volume).expect("Failed to upsert volume");

        // Insert a file entry
        let file_entry = FileEntry {
            id: None,
            volume_id,
            parent_id: None,
            name: "test.txt".to_string(),
            full_path: "C:\\test.txt".to_string(),
            size: 100,
            is_directory: false,
            created_time: None,
            modified_time: None,
            mft_reference: None,
        };
        database.insert_file(&file_entry).expect("Failed to insert file");

        // Insert a directory entry
        let dir_entry = FileEntry {
            id: None,
            volume_id,
            parent_id: None,
            name: "docs".to_string(),
            full_path: "C:\\docs".to_string(),
            size: 0,
            is_directory: true,
            created_time: None,
            modified_time: None,
            mft_reference: None,
        };
        database.insert_file(&dir_entry).expect("Failed to insert directory");

        state.update_from_database(&database);

        assert_eq!(state.indexed_files.load(Ordering::Relaxed), 1);
        assert_eq!(state.indexed_directories.load(Ordering::Relaxed), 1);
        assert_eq!(state.monitored_volumes.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_ipc_to_daemon_all_variants_debug() {
        // Ensure all variants have distinct debug representations
        let variants = [
            IpcToDaemon::Stop,
            IpcToDaemon::Rescan,
            IpcToDaemon::Pause,
            IpcToDaemon::Resume,
            IpcToDaemon::Prune,
        ];

        let debug_strings: Vec<String> = variants.iter().map(|variant| format!("{variant:?}")).collect();

        assert!(debug_strings[0].contains("Stop"));
        assert!(debug_strings[1].contains("Rescan"));
        assert!(debug_strings[2].contains("Pause"));
        assert!(debug_strings[3].contains("Resume"));
        assert!(debug_strings[4].contains("Prune"));

        // All should be unique
        for (index, debug_str) in debug_strings.iter().enumerate() {
            for (other_index, other) in debug_strings.iter().enumerate() {
                if index != other_index {
                    assert_ne!(debug_str, other, "IpcToDaemon debug strings should be unique");
                }
            }
        }
    }

    #[test]
    fn test_ipc_server_state_get_status_reflects_updates() {
        let state = IpcServerState::new();

        // Set various values
        state.state.store(DaemonStateInfo::Scanning);
        state.indexed_files.store(5000, Ordering::Relaxed);
        state.indexed_directories.store(300, Ordering::Relaxed);
        state.monitored_volumes.store(3, Ordering::Relaxed);
        state.is_paused.store(true, Ordering::Relaxed);

        let status = state.get_status();
        assert_eq!(status.state, DaemonStateInfo::Scanning);
        assert_eq!(status.indexed_files, 5000);
        assert_eq!(status.indexed_directories, 300);
        assert_eq!(status.monitored_volumes, 3);
        assert!(status.is_paused);

        // Update values and verify status changes
        state.state.store(DaemonStateInfo::Running);
        state.is_paused.store(false, Ordering::Relaxed);

        let status2 = state.get_status();
        assert_eq!(status2.state, DaemonStateInfo::Running);
        assert!(!status2.is_paused);
    }

    #[test]
    fn test_handle_command_sync_status_during_scanning() {
        let state = Arc::new(IpcServerState::new());
        state.state.store(DaemonStateInfo::Scanning);
        state.indexed_files.store(10_000, Ordering::Relaxed);

        let shutdown = Arc::new(AtomicBool::new(false));
        let (sender, _receiver) = mpsc::channel(32);
        let server = IpcServer::new(Arc::clone(&state), sender, shutdown);

        let response = server.handle_command_sync(DaemonCommand::GetStatus);
        match response {
            DaemonResponse::Status(status) => {
                assert_eq!(status.state, DaemonStateInfo::Scanning);
                assert_eq!(status.indexed_files, 10_000);
            }
            other => panic!("Expected Status response, got {other:?}"),
        }
    }

    #[test]
    fn test_handle_command_sync_pause_then_resume() {
        let state = Arc::new(IpcServerState::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let (sender, mut receiver) = mpsc::channel(32);
        let server = IpcServer::new(Arc::clone(&state), sender, shutdown);

        // Pause
        let response = server.handle_command_sync(DaemonCommand::Pause);
        assert!(matches!(response, DaemonResponse::Ok));
        assert!(state.is_paused.load(Ordering::Relaxed));

        // Verify status reflects paused
        let status_response = server.handle_command_sync(DaemonCommand::GetStatus);
        match status_response {
            DaemonResponse::Status(status) => assert!(status.is_paused),
            other => panic!("Expected Status response, got {other:?}"),
        }

        // Resume
        let response = server.handle_command_sync(DaemonCommand::Resume);
        assert!(matches!(response, DaemonResponse::Ok));
        assert!(!state.is_paused.load(Ordering::Relaxed));

        // Verify status reflects resumed
        let status_response = server.handle_command_sync(DaemonCommand::GetStatus);
        match status_response {
            DaemonResponse::Status(status) => assert!(!status.is_paused),
            other => panic!("Expected Status response, got {other:?}"),
        }

        // Drain channel
        let cmd1 = receiver.try_recv().expect("Should have Pause");
        assert!(matches!(cmd1, IpcToDaemon::Pause));
        let cmd2 = receiver.try_recv().expect("Should have Resume");
        assert!(matches!(cmd2, IpcToDaemon::Resume));
    }

    /// Generate a batch of test [`FileEntry`] values for a given volume and index range.
    fn make_test_file_entries(volume_id: i64, range: std::ops::Range<usize>) -> Vec<filefind::FileEntry> {
        use filefind::FileEntry;

        range
            .map(|index| FileEntry {
                id: None,
                volume_id,
                parent_id: None,
                name: format!("file{index}.txt"),
                full_path: format!("D:\\file{index}.txt"),
                size: 50,
                is_directory: false,
                created_time: None,
                modified_time: None,
                mft_reference: None,
            })
            .collect()
    }

    #[test]
    fn test_ipc_server_state_update_from_database_multiple_times() {
        use filefind::{IndexedVolume, VolumeType};

        let state = IpcServerState::new();
        let mut database = Database::open_in_memory().expect("Failed to create in-memory database");

        let volume = IndexedVolume {
            id: None,
            serial_number: "SN-5678".to_string(),
            label: None,
            mount_point: "D:".to_string(),
            volume_type: VolumeType::Ntfs,
            is_online: true,
            last_scan_time: None,
            last_usn: None,
        };
        let volume_id = database.upsert_volume(&volume).expect("Failed to upsert volume");

        // Insert files in batch
        let entries = make_test_file_entries(volume_id, 0..10);
        database.insert_files_batch(&entries).expect("Failed to insert batch");

        state.update_from_database(&database);
        assert_eq!(state.indexed_files.load(Ordering::Relaxed), 10);

        // Insert more files and update again
        let more_entries = make_test_file_entries(volume_id, 10..15);
        database
            .insert_files_batch(&more_entries)
            .expect("Failed to insert more files");

        state.update_from_database(&database);
        assert_eq!(state.indexed_files.load(Ordering::Relaxed), 15);
    }

    // ==================== Integration Tests ====================
    // These tests start a real IPC server and connect real clients through
    // named pipes (Windows) or Unix domain sockets (other platforms).

    /// Generate a unique pipe/socket path for an integration test.
    ///
    /// Each test gets its own path to avoid conflicts when tests run in parallel.
    fn unique_pipe_path(test_name: &str) -> PathBuf {
        #[cfg(windows)]
        {
            PathBuf::from(format!(r"\\.\pipe\filefind-test-{}-{}", test_name, std::process::id()))
        }
        #[cfg(not(windows))]
        {
            std::env::temp_dir().join(format!("filefind-test-{}-{}.sock", test_name, std::process::id()))
        }
    }

    /// Helper: start an IPC server on a unique pipe and return the pieces needed
    /// to interact with it from the test.
    ///
    /// Returns `(pipe_path, server_state, shutdown_flag, command_receiver)`.
    fn start_test_server(
        test_name: &str,
    ) -> (
        PathBuf,
        Arc<IpcServerState>,
        Arc<AtomicBool>,
        mpsc::Receiver<IpcToDaemon>,
    ) {
        let pipe_path = unique_pipe_path(test_name);
        let state = Arc::new(IpcServerState::new());
        let shutdown = Arc::new(AtomicBool::new(false));

        let receiver = spawn_ipc_server_with_path(Arc::clone(&state), Arc::clone(&shutdown), Some(pipe_path.clone()));

        // Give the server thread a moment to start listening.
        std::thread::sleep(std::time::Duration::from_millis(200));

        (pipe_path, state, shutdown, receiver)
    }

    /// Helper: create an `IpcClient` pointed at a test pipe.
    fn test_client(pipe_path: &Path) -> filefind::IpcClient {
        filefind::IpcClient::new().with_pipe_path(pipe_path.to_path_buf())
    }

    /// Send a command with retries to handle the brief window between named pipe
    /// instances where no pipe exists on Windows.
    ///
    /// The server destroys the old pipe and creates a new one after each client,
    /// so a client connecting during that gap gets "file not found". This helper
    /// retries with short back-off to tolerate that race.
    fn send_command_retry(
        client: &filefind::IpcClient,
        command: DaemonCommand,
        max_attempts: u32,
    ) -> anyhow::Result<DaemonResponse> {
        let mut last_error = None;
        for attempt in 0..max_attempts {
            match client.send_command(command) {
                Ok(response) => return Ok(response),
                Err(error) => {
                    last_error = Some(error);
                    // Exponential back-off: 50ms, 100ms, 200ms, …
                    std::thread::sleep(std::time::Duration::from_millis(50 << attempt));
                }
            }
        }
        Err(last_error.expect("at least one attempt"))
    }

    /// Helper: shut down a test server and wait briefly for the thread to exit.
    fn stop_test_server(shutdown: &Arc<AtomicBool>, pipe_path: &Path) {
        shutdown.store(true, Ordering::Relaxed);
        // On Windows the server thread may be blocked in ConnectNamedPipe.
        // Opening a throwaway connection unblocks it so the thread can see
        // the shutdown flag and exit.
        #[cfg(windows)]
        {
            let _ = std::fs::OpenOptions::new().read(true).write(true).open(pipe_path);
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }

    // --- Ping / Pong ---

    #[test]
    fn test_integration_server_ping_pong() {
        let (pipe_path, _state, shutdown, _receiver) = start_test_server("ping_pong");

        let client = test_client(&pipe_path);
        let response = client.send_command(DaemonCommand::Ping).expect("Ping should succeed");

        assert!(
            matches!(response, DaemonResponse::Pong),
            "Expected Pong, got {response:?}"
        );

        stop_test_server(&shutdown, &pipe_path);
    }

    // --- is_daemon_running ---

    #[test]
    fn test_integration_is_daemon_running() {
        let (pipe_path, _state, shutdown, _receiver) = start_test_server("is_running");

        let client = test_client(&pipe_path);
        assert!(client.is_daemon_running(), "Daemon should appear running");

        stop_test_server(&shutdown, &pipe_path);
    }

    // --- GetStatus ---

    #[test]
    fn test_integration_get_status() {
        let (pipe_path, state, shutdown, _receiver) = start_test_server("get_status");

        // Configure some state before querying.
        state.state.store(DaemonStateInfo::Running);
        state.indexed_files.store(42_000, Ordering::Relaxed);
        state.indexed_directories.store(1_234, Ordering::Relaxed);
        state.monitored_volumes.store(3, Ordering::Relaxed);

        let client = test_client(&pipe_path);
        let status = client.get_status().expect("get_status should succeed");

        assert_eq!(status.state, DaemonStateInfo::Running);
        assert_eq!(status.indexed_files, 42_000);
        assert_eq!(status.indexed_directories, 1_234);
        assert_eq!(status.monitored_volumes, 3);
        assert!(!status.is_paused);
        // Uptime should be tiny (server just started).
        assert!(status.uptime_seconds < 10);

        stop_test_server(&shutdown, &pipe_path);
    }

    // --- Stop command ---

    #[test]
    fn test_integration_stop_command() {
        let (pipe_path, _state, shutdown, mut receiver) = start_test_server("stop_cmd");

        let client = test_client(&pipe_path);
        client.stop_daemon().expect("stop_daemon should succeed");

        // The server should have forwarded the command through the channel.
        let command = receiver.try_recv().expect("Should have received Stop");
        assert!(matches!(command, IpcToDaemon::Stop));

        stop_test_server(&shutdown, &pipe_path);
    }

    // --- Rescan command ---

    #[test]
    fn test_integration_rescan_command() {
        let (pipe_path, _state, shutdown, mut receiver) = start_test_server("rescan_cmd");

        let client = test_client(&pipe_path);
        client.rescan().expect("rescan should succeed");

        let command = receiver.try_recv().expect("Should have received Rescan");
        assert!(matches!(command, IpcToDaemon::Rescan));

        stop_test_server(&shutdown, &pipe_path);
    }

    // --- Pause / Resume ---

    #[test]
    fn test_integration_pause_and_resume() {
        let (pipe_path, state, shutdown, mut receiver) = start_test_server("pause_resume");

        let client = test_client(&pipe_path);

        // Initially not paused.
        assert!(!state.is_paused.load(Ordering::Relaxed));

        // Pause
        client.pause().expect("pause should succeed");
        assert!(state.is_paused.load(Ordering::Relaxed));

        let command = receiver.try_recv().expect("Should have received Pause");
        assert!(matches!(command, IpcToDaemon::Pause));

        // Confirm status reflects paused (retry to handle pipe recreation gap).
        let response = send_command_retry(&client, DaemonCommand::GetStatus, 5).expect("get_status after pause");
        match response {
            DaemonResponse::Status(status) => assert!(status.is_paused),
            other => panic!("Expected Status, got {other:?}"),
        }

        // Resume (retry to handle pipe recreation gap).
        let response = send_command_retry(&client, DaemonCommand::Resume, 5).expect("resume should succeed");
        assert!(matches!(response, DaemonResponse::Ok));
        assert!(!state.is_paused.load(Ordering::Relaxed));

        let command = receiver.try_recv().expect("Should have received Resume");
        assert!(matches!(command, IpcToDaemon::Resume));

        let response = send_command_retry(&client, DaemonCommand::GetStatus, 5).expect("get_status after resume");
        match response {
            DaemonResponse::Status(status) => assert!(!status.is_paused),
            other => panic!("Expected Status, got {other:?}"),
        }

        stop_test_server(&shutdown, &pipe_path);
    }

    // --- Prune command ---

    #[test]
    fn test_integration_prune_command() {
        let (pipe_path, _state, shutdown, mut receiver) = start_test_server("prune_cmd");

        let client = test_client(&pipe_path);
        client.prune().expect("prune should succeed");

        let command = receiver.try_recv().expect("Should have received Prune");
        assert!(matches!(command, IpcToDaemon::Prune));

        stop_test_server(&shutdown, &pipe_path);
    }

    // --- Multiple sequential commands ---

    #[test]
    fn test_integration_all_commands_sequence() {
        let (pipe_path, state, shutdown, mut receiver) = start_test_server("all_cmds");

        state.state.store(DaemonStateInfo::Running);
        state.indexed_files.store(100, Ordering::Relaxed);

        let client = test_client(&pipe_path);

        // Ping
        let response = client.send_command(DaemonCommand::Ping).expect("Ping");
        assert!(matches!(response, DaemonResponse::Pong));

        // GetStatus (retry for pipe gap)
        let response = send_command_retry(&client, DaemonCommand::GetStatus, 5).expect("GetStatus");
        match response {
            DaemonResponse::Status(status) => assert_eq!(status.indexed_files, 100),
            other => panic!("Expected Status, got {other:?}"),
        }

        // Pause (retry for pipe gap)
        let response = send_command_retry(&client, DaemonCommand::Pause, 5).expect("Pause");
        assert!(matches!(response, DaemonResponse::Ok));
        let cmd = receiver.try_recv().expect("channel Pause");
        assert!(matches!(cmd, IpcToDaemon::Pause));

        // Resume (retry for pipe gap)
        let response = send_command_retry(&client, DaemonCommand::Resume, 5).expect("Resume");
        assert!(matches!(response, DaemonResponse::Ok));
        let cmd = receiver.try_recv().expect("channel Resume");
        assert!(matches!(cmd, IpcToDaemon::Resume));

        // Rescan (retry for pipe gap)
        let response = send_command_retry(&client, DaemonCommand::Rescan, 5).expect("Rescan");
        assert!(matches!(response, DaemonResponse::Ok));
        let cmd = receiver.try_recv().expect("channel Rescan");
        assert!(matches!(cmd, IpcToDaemon::Rescan));

        // Prune (retry for pipe gap)
        let response = send_command_retry(&client, DaemonCommand::Prune, 5).expect("Prune");
        assert!(matches!(response, DaemonResponse::Ok));
        let cmd = receiver.try_recv().expect("channel Prune");
        assert!(matches!(cmd, IpcToDaemon::Prune));

        // Stop (retry for pipe gap, last since a real daemon would exit)
        let response = send_command_retry(&client, DaemonCommand::Stop, 5).expect("Stop");
        assert!(matches!(response, DaemonResponse::Ok));
        let cmd = receiver.try_recv().expect("channel Stop");
        assert!(matches!(cmd, IpcToDaemon::Stop));

        stop_test_server(&shutdown, &pipe_path);
    }

    // --- Multiple clients connecting sequentially ---

    #[test]
    fn test_integration_multiple_clients_sequential() {
        let (pipe_path, _state, shutdown, _receiver) = start_test_server("multi_client");

        // Five separate clients, each doing a full connect-send-receive cycle.
        // Use retry to handle the gap between pipe instances.
        for index in 0..5 {
            let client = test_client(&pipe_path);
            let response = send_command_retry(&client, DaemonCommand::Ping, 5)
                .unwrap_or_else(|error| panic!("Ping from client {index}: {error}"));
            assert!(
                matches!(response, DaemonResponse::Pong),
                "Client {index}: expected Pong, got {response:?}"
            );
        }

        stop_test_server(&shutdown, &pipe_path);
    }

    // --- Status reflects live state mutations ---

    #[test]
    fn test_integration_status_reflects_state_changes() {
        let (pipe_path, state, shutdown, _receiver) = start_test_server("state_changes");

        let client = test_client(&pipe_path);

        // Stopped → Starting → Running → Scanning → Stopping → Stopped
        let transitions = [
            DaemonStateInfo::Stopped,
            DaemonStateInfo::Starting,
            DaemonStateInfo::Running,
            DaemonStateInfo::Scanning,
            DaemonStateInfo::Stopping,
            DaemonStateInfo::Stopped,
        ];

        for expected_state in transitions {
            state.state.store(expected_state);
            let response = send_command_retry(&client, DaemonCommand::GetStatus, 5).expect("get_status");
            match response {
                DaemonResponse::Status(status) => assert_eq!(
                    status.state, expected_state,
                    "Expected {expected_state}, got {}",
                    status.state
                ),
                other => panic!("Expected Status, got {other:?}"),
            }
        }

        stop_test_server(&shutdown, &pipe_path);
    }

    // --- File/directory counts update between queries ---

    #[test]
    fn test_integration_status_counts_update_live() {
        let (pipe_path, state, shutdown, _receiver) = start_test_server("counts_update");

        let client = test_client(&pipe_path);

        // Start with zeroes.
        let status = client.get_status().expect("initial status");
        assert_eq!(status.indexed_files, 0);
        assert_eq!(status.indexed_directories, 0);

        // Simulate indexing progress.
        state.indexed_files.store(10_000, Ordering::Relaxed);
        state.indexed_directories.store(500, Ordering::Relaxed);

        let response = send_command_retry(&client, DaemonCommand::GetStatus, 5).expect("mid-scan status");
        match response {
            DaemonResponse::Status(status) => {
                assert_eq!(status.indexed_files, 10_000);
                assert_eq!(status.indexed_directories, 500);
            }
            other => panic!("Expected Status, got {other:?}"),
        }

        // More progress.
        state.indexed_files.store(1_000_000, Ordering::Relaxed);
        state.indexed_directories.store(50_000, Ordering::Relaxed);
        state.monitored_volumes.store(4, Ordering::Relaxed);

        let response = send_command_retry(&client, DaemonCommand::GetStatus, 5).expect("final status");
        match response {
            DaemonResponse::Status(status) => {
                assert_eq!(status.indexed_files, 1_000_000);
                assert_eq!(status.indexed_directories, 50_000);
                assert_eq!(status.monitored_volumes, 4);
            }
            other => panic!("Expected Status, got {other:?}"),
        }

        stop_test_server(&shutdown, &pipe_path);
    }

    // --- Client to non-existent server returns error ---

    #[test]
    fn test_integration_client_no_server() {
        let pipe_path = unique_pipe_path("no_server");
        let client = test_client(&pipe_path);

        // No server is listening, so this should fail.
        assert!(!client.is_daemon_running());
        assert!(client.get_status().is_err());
        assert!(client.stop_daemon().is_err());
    }

    // --- Server shutdown stops accepting ---

    #[test]
    fn test_integration_server_shutdown() {
        let (pipe_path, _state, shutdown, _receiver) = start_test_server("shutdown");

        // Server is alive.
        let client = test_client(&pipe_path);
        assert!(client.is_daemon_running());

        // Signal shutdown and wake the server thread.
        shutdown.store(true, Ordering::Relaxed);

        // On Windows, open a throwaway connection to unblock ConnectNamedPipe.
        #[cfg(windows)]
        {
            let _ = std::fs::OpenOptions::new().read(true).write(true).open(&pipe_path);
        }

        // Give the server thread time to exit.
        std::thread::sleep(std::time::Duration::from_millis(500));

        // Now the server should no longer be reachable.
        // Retry a few times since the server thread may still be mid-teardown.
        let client_after = test_client(&pipe_path);
        let mut stopped = false;
        for _ in 0..5 {
            if !client_after.is_daemon_running() {
                stopped = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(stopped, "Server should be unreachable after shutdown");
    }

    // --- Concurrent clients from multiple threads ---

    #[test]
    fn test_integration_concurrent_clients() {
        let (pipe_path, _state, shutdown, _receiver) = start_test_server("concurrent");

        let mut handles = Vec::new();

        for thread_index in 0..4 {
            let path = pipe_path.clone();
            let handle = std::thread::spawn(move || {
                for iteration in 0..3 {
                    let client = test_client(&path);
                    let response = send_command_retry(&client, DaemonCommand::Ping, 5)
                        .unwrap_or_else(|error| panic!("Thread {thread_index} iteration {iteration} failed: {error}"));
                    assert!(
                        matches!(response, DaemonResponse::Pong),
                        "Thread {thread_index} iteration {iteration}: expected Pong"
                    );
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().expect("Thread should not panic");
        }

        stop_test_server(&shutdown, &pipe_path);
    }

    // --- GetStatus with large counter values ---

    #[test]
    fn test_integration_status_large_values() {
        let (pipe_path, state, shutdown, _receiver) = start_test_server("large_values");

        state.state.store(DaemonStateInfo::Running);
        state.indexed_files.store(10_000_000_000, Ordering::Relaxed);
        state.indexed_directories.store(1_000_000_000, Ordering::Relaxed);
        state.monitored_volumes.store(26, Ordering::Relaxed);

        let client = test_client(&pipe_path);
        let status = client.get_status().expect("get_status with large values");

        assert_eq!(status.indexed_files, 10_000_000_000);
        assert_eq!(status.indexed_directories, 1_000_000_000);
        assert_eq!(status.monitored_volumes, 26);

        stop_test_server(&shutdown, &pipe_path);
    }
}
