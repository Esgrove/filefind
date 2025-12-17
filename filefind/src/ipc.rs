//! Inter-process communication for daemon control and status.
//!
//! This module provides a simple IPC mechanism using named pipes (Windows)
//! or Unix domain sockets (other platforms) for communication between
//! the daemon and client applications (CLI, tray app).

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Default timeout for IPC operations.
pub const IPC_TIMEOUT: Duration = Duration::from_secs(5);

/// Name of the named pipe (Windows) or socket file (Unix).
pub const IPC_PIPE_NAME: &str = "filefind-daemon";

/// Commands that can be sent to the daemon.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DaemonCommand {
    /// Request daemon to stop.
    Stop,
    /// Request current status.
    GetStatus,
    /// Request daemon to perform a rescan.
    Rescan,
    /// Pause indexing.
    Pause,
    /// Resume indexing.
    Resume,
    /// Ping to check if daemon is alive.
    Ping,
}

/// Response from the daemon.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DaemonResponse {
    /// Acknowledgement of command.
    Ok,
    /// Error response with message.
    Error(String),
    /// Status information.
    Status(DaemonStatus),
    /// Pong response to ping.
    Pong,
}

/// Current daemon status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonStatus {
    /// Current state of the daemon.
    pub state: DaemonStateInfo,
    /// Number of indexed files.
    pub indexed_files: u64,
    /// Number of indexed directories.
    pub indexed_directories: u64,
    /// Number of monitored volumes.
    pub monitored_volumes: u32,
    /// Uptime in seconds.
    pub uptime_seconds: u64,
    /// Whether indexing is currently paused.
    pub is_paused: bool,
}

/// Simplified daemon state for IPC.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DaemonStateInfo {
    /// Daemon is stopped.
    Stopped,
    /// Daemon is starting up.
    Starting,
    /// Daemon is running normally.
    Running,
    /// Daemon is currently scanning.
    Scanning,
    /// Daemon is stopping.
    Stopping,
}

impl std::fmt::Display for DaemonStateInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stopped => write!(f, "stopped"),
            Self::Starting => write!(f, "starting"),
            Self::Running => write!(f, "running"),
            Self::Scanning => write!(f, "scanning"),
            Self::Stopping => write!(f, "stopping"),
        }
    }
}

impl Default for DaemonStatus {
    fn default() -> Self {
        Self {
            state: DaemonStateInfo::Stopped,
            indexed_files: 0,
            indexed_directories: 0,
            monitored_volumes: 0,
            uptime_seconds: 0,
            is_paused: false,
        }
    }
}

/// Get the path to the IPC socket/pipe.
#[must_use]
pub fn get_ipc_path() -> PathBuf {
    #[cfg(windows)]
    {
        // Windows named pipe path
        PathBuf::from(format!(r"\\.\pipe\{IPC_PIPE_NAME}"))
    }
    #[cfg(not(windows))]
    {
        // Unix domain socket in runtime directory
        let runtime_dir = dirs::runtime_dir()
            .or_else(dirs::cache_dir)
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        runtime_dir.join(format!("{IPC_PIPE_NAME}.sock"))
    }
}

/// IPC client for communicating with the daemon.
pub struct IpcClient {
    /// Timeout for operations.
    #[allow(dead_code)]
    timeout: Duration,
}

impl IpcClient {
    /// Create a new IPC client with default timeout.
    #[must_use]
    pub const fn new() -> Self {
        Self { timeout: IPC_TIMEOUT }
    }

    /// Create a new IPC client with custom timeout.
    #[must_use]
    pub const fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Check if the daemon is running.
    #[must_use]
    pub fn is_daemon_running(&self) -> bool {
        self.send_command(DaemonCommand::Ping).is_ok()
    }

    /// Send a command to the daemon and receive a response.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection to the daemon fails or if the
    /// response cannot be parsed.
    pub fn send_command(&self, command: DaemonCommand) -> Result<DaemonResponse> {
        #[cfg(windows)]
        {
            self.send_command_windows(command)
        }
        #[cfg(not(windows))]
        {
            self.send_command_unix(command)
        }
    }

    /// Get the current daemon status.
    ///
    /// # Errors
    ///
    /// Returns an error if communication with the daemon fails.
    pub fn get_status(&self) -> Result<DaemonStatus> {
        match self.send_command(DaemonCommand::GetStatus)? {
            DaemonResponse::Status(status) => Ok(status),
            DaemonResponse::Error(error) => anyhow::bail!("Daemon error: {error}"),
            other => anyhow::bail!("Unexpected response: {other:?}"),
        }
    }

    /// Request the daemon to stop.
    ///
    /// # Errors
    ///
    /// Returns an error if the daemon cannot be stopped.
    pub fn stop_daemon(&self) -> Result<()> {
        match self.send_command(DaemonCommand::Stop)? {
            DaemonResponse::Ok => Ok(()),
            DaemonResponse::Error(error) => anyhow::bail!("Failed to stop daemon: {error}"),
            other => anyhow::bail!("Unexpected response: {other:?}"),
        }
    }

    /// Request the daemon to rescan.
    ///
    /// # Errors
    ///
    /// Returns an error if the rescan cannot be triggered.
    pub fn rescan(&self) -> Result<()> {
        match self.send_command(DaemonCommand::Rescan)? {
            DaemonResponse::Ok => Ok(()),
            DaemonResponse::Error(error) => anyhow::bail!("Failed to trigger rescan: {error}"),
            other => anyhow::bail!("Unexpected response: {other:?}"),
        }
    }

    /// Pause indexing.
    ///
    /// # Errors
    ///
    /// Returns an error if indexing cannot be paused.
    pub fn pause(&self) -> Result<()> {
        match self.send_command(DaemonCommand::Pause)? {
            DaemonResponse::Ok => Ok(()),
            DaemonResponse::Error(error) => anyhow::bail!("Failed to pause: {error}"),
            other => anyhow::bail!("Unexpected response: {other:?}"),
        }
    }

    /// Resume indexing.
    ///
    /// # Errors
    ///
    /// Returns an error if indexing cannot be resumed.
    pub fn resume(&self) -> Result<()> {
        match self.send_command(DaemonCommand::Resume)? {
            DaemonResponse::Ok => Ok(()),
            DaemonResponse::Error(error) => anyhow::bail!("Failed to resume: {error}"),
            other => anyhow::bail!("Unexpected response: {other:?}"),
        }
    }

    #[cfg(windows)]
    #[allow(clippy::unused_self, clippy::needless_pass_by_value)]
    fn send_command_windows(&self, command: DaemonCommand) -> Result<DaemonResponse> {
        use std::fs::OpenOptions;
        use std::os::windows::fs::OpenOptionsExt;

        const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;

        let pipe_path = get_ipc_path();

        // Try to connect to the named pipe
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_OVERLAPPED)
            .open(&pipe_path)
            .context("Failed to connect to daemon - is it running?")?;

        // Serialize and send command
        let command_json = serde_json::to_string(&command)?;
        writeln!(file, "{command_json}")?;
        file.flush()?;

        // Read response
        let mut reader = BufReader::new(&file);
        let mut response_line = String::new();
        reader.read_line(&mut response_line)?;

        let response: DaemonResponse = serde_json::from_str(response_line.trim())?;
        Ok(response)
    }

    #[cfg(not(windows))]
    fn send_command_unix(&self, command: DaemonCommand) -> Result<DaemonResponse> {
        use std::os::unix::net::UnixStream;

        let socket_path = get_ipc_path();

        // Connect to Unix domain socket
        let stream = UnixStream::connect(&socket_path).context("Failed to connect to daemon - is it running?")?;

        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;

        // Serialize and send command
        let command_json = serde_json::to_string(&command)?;
        let mut stream_write = &stream;
        writeln!(stream_write, "{command_json}")?;
        stream_write.flush()?;

        // Read response
        let mut reader = BufReader::new(&stream);
        let mut response_line = String::new();
        reader.read_line(&mut response_line)?;

        let response: DaemonResponse = serde_json::from_str(response_line.trim())?;
        Ok(response)
    }
}

impl Default for IpcClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Serialize a command to JSON for transmission.
///
/// # Errors
///
/// Returns an error if serialization fails.
pub fn serialize_command(command: &DaemonCommand) -> Result<String> {
    serde_json::to_string(command).context("Failed to serialize command")
}

/// Deserialize a command from JSON.
///
/// # Errors
///
/// Returns an error if the JSON is invalid or cannot be parsed.
pub fn deserialize_command(json: &str) -> Result<DaemonCommand> {
    serde_json::from_str(json).context("Failed to deserialize command")
}

/// Serialize a response to JSON for transmission.
///
/// # Errors
///
/// Returns an error if serialization fails.
pub fn serialize_response(response: &DaemonResponse) -> Result<String> {
    serde_json::to_string(response).context("Failed to serialize response")
}

/// Deserialize a response from JSON.
///
/// # Errors
///
/// Returns an error if the JSON is invalid or cannot be parsed.
pub fn deserialize_response(json: &str) -> Result<DaemonResponse> {
    serde_json::from_str(json).context("Failed to deserialize response")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_daemon_command_serialization() {
        let commands = vec![
            DaemonCommand::Stop,
            DaemonCommand::GetStatus,
            DaemonCommand::Rescan,
            DaemonCommand::Pause,
            DaemonCommand::Resume,
            DaemonCommand::Ping,
        ];

        for command in commands {
            let json = serialize_command(&command).expect("serialize");
            let parsed = deserialize_command(&json).expect("deserialize");
            assert_eq!(command, parsed);
        }
    }

    #[test]
    fn test_daemon_response_serialization() {
        let responses = vec![
            DaemonResponse::Ok,
            DaemonResponse::Error("test error".to_string()),
            DaemonResponse::Status(DaemonStatus::default()),
            DaemonResponse::Pong,
        ];

        for response in responses {
            let json = serialize_response(&response).expect("serialize");
            let parsed = deserialize_response(&json).expect("deserialize");
            assert_eq!(response, parsed);
        }
    }

    #[test]
    fn test_daemon_state_info_display() {
        assert_eq!(DaemonStateInfo::Stopped.to_string(), "stopped");
        assert_eq!(DaemonStateInfo::Starting.to_string(), "starting");
        assert_eq!(DaemonStateInfo::Running.to_string(), "running");
        assert_eq!(DaemonStateInfo::Scanning.to_string(), "scanning");
        assert_eq!(DaemonStateInfo::Stopping.to_string(), "stopping");
    }

    #[test]
    fn test_daemon_status_default() {
        let status = DaemonStatus::default();
        assert_eq!(status.state, DaemonStateInfo::Stopped);
        assert_eq!(status.indexed_files, 0);
        assert_eq!(status.indexed_directories, 0);
        assert_eq!(status.monitored_volumes, 0);
        assert_eq!(status.uptime_seconds, 0);
        assert!(!status.is_paused);
    }

    #[test]
    fn test_get_ipc_path() {
        let path = get_ipc_path();
        #[cfg(windows)]
        assert!(path.to_string_lossy().contains("pipe"));
        #[cfg(not(windows))]
        assert!(path.to_string_lossy().contains("sock") || path.to_string_lossy().contains("filefind"));
    }

    #[test]
    fn test_ipc_client_creation() {
        let client = IpcClient::new();
        assert_eq!(client.timeout, IPC_TIMEOUT);

        let custom_timeout = Duration::from_secs(10);
        let client_custom = IpcClient::with_timeout(custom_timeout);
        assert_eq!(client_custom.timeout, custom_timeout);
    }
}
