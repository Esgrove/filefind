//! Inter-process communication for daemon control and status.
//!
//! This module provides a simple IPC mechanism using named pipes (Windows)
//! or Unix domain sockets (other platforms) for communication between
//! the daemon and client applications (CLI, tray app).
//!
//! Uses postcard binary serialization for efficient, compact messages.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Default timeout for IPC operations.
pub const IPC_TIMEOUT: Duration = Duration::from_secs(5);

/// Name of the named pipe (Windows) or socket file (Unix).
pub const IPC_PIPE_NAME: &str = "filefind-daemon";

/// Maximum message size in bytes.
const MAX_MESSAGE_SIZE: usize = 1024;

/// Commands that can be sent to the daemon.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
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

/// Serialize a command to bytes for transmission.
///
/// Format: [length: u16 LE][postcard data...]
///
/// # Errors
///
/// Returns an error if serialization fails.
pub fn serialize_command(command: &DaemonCommand) -> Result<Vec<u8>> {
    let data = postcard::to_stdvec(command).context("Failed to serialize command")?;
    let len = u16::try_from(data.len()).context("Command too large")?;
    let mut buffer = Vec::with_capacity(2 + data.len());
    buffer.extend_from_slice(&len.to_le_bytes());
    buffer.extend_from_slice(&data);
    Ok(buffer)
}

/// Deserialize a command from bytes.
///
/// # Errors
///
/// Returns an error if deserialization fails.
pub fn deserialize_command(bytes: &[u8]) -> Result<DaemonCommand> {
    postcard::from_bytes(bytes).context("Failed to deserialize command")
}

/// Serialize a response to bytes for transmission.
///
/// Format: [length: u16 LE][postcard data...]
///
/// # Errors
///
/// Returns an error if serialization fails.
pub fn serialize_response(response: &DaemonResponse) -> Result<Vec<u8>> {
    let data = postcard::to_stdvec(response).context("Failed to serialize response")?;
    let len = u16::try_from(data.len()).context("Response too large")?;
    let mut buffer = Vec::with_capacity(2 + data.len());
    buffer.extend_from_slice(&len.to_le_bytes());
    buffer.extend_from_slice(&data);
    Ok(buffer)
}

/// Deserialize a response from bytes.
///
/// # Errors
///
/// Returns an error if deserialization fails.
pub fn deserialize_response(bytes: &[u8]) -> Result<DaemonResponse> {
    postcard::from_bytes(bytes).context("Failed to deserialize response")
}

/// Write a length-prefixed message to a writer.
///
/// # Errors
///
/// Returns an error if writing fails.
pub fn write_message<W: Write>(writer: &mut W, data: &[u8]) -> Result<()> {
    writer.write_all(data)?;
    writer.flush()?;
    Ok(())
}

/// Read a length-prefixed message from a reader.
///
/// # Errors
///
/// Returns an error if reading fails or message is too large.
pub fn read_message<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    // Read length prefix
    let mut len_bytes = [0u8; 2];
    reader.read_exact(&mut len_bytes)?;
    let len = u16::from_le_bytes(len_bytes) as usize;

    if len > MAX_MESSAGE_SIZE {
        anyhow::bail!("Message too large: {len} bytes");
    }

    // Read message data
    let mut buffer = vec![0u8; len];
    reader.read_exact(&mut buffer)?;
    Ok(buffer)
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
    #[allow(clippy::unused_self)]
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
        let command_bytes = serialize_command(&command)?;
        write_message(&mut file, &command_bytes)?;

        // Read response
        let response_bytes = read_message(&mut file)?;
        deserialize_response(&response_bytes)
    }

    #[cfg(not(windows))]
    fn send_command_unix(&self, command: DaemonCommand) -> Result<DaemonResponse> {
        use std::os::unix::net::UnixStream;

        let socket_path = get_ipc_path();

        // Connect to Unix domain socket
        let mut stream = UnixStream::connect(&socket_path).context("Failed to connect to daemon - is it running?")?;

        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;

        // Serialize and send command
        let command_bytes = serialize_command(&command)?;
        write_message(&mut stream, &command_bytes)?;

        // Read response
        let response_bytes = read_message(&mut stream)?;
        deserialize_response(&response_bytes)
    }
}

impl Default for IpcClient {
    fn default() -> Self {
        Self::new()
    }
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
            let bytes = serialize_command(&command).expect("serialize");
            // Skip the 2-byte length prefix
            let parsed = deserialize_command(&bytes[2..]).expect("deserialize");
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
            let bytes = serialize_response(&response).expect("serialize");
            // Skip the 2-byte length prefix
            let parsed = deserialize_response(&bytes[2..]).expect("deserialize");
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

    #[test]
    fn test_message_size_compact() {
        // Verify that postcard produces compact output
        let command = DaemonCommand::Ping;
        let bytes = serialize_command(&command).expect("serialize");
        // Length prefix (2) + minimal enum representation (1)
        assert!(
            bytes.len() <= 4,
            "Command should be very compact: {} bytes",
            bytes.len()
        );

        let status = DaemonStatus::default();
        let response = DaemonResponse::Status(status);
        let bytes = serialize_response(&response).expect("serialize");
        // Should be much smaller than JSON
        assert!(
            bytes.len() < 50,
            "Status response should be compact: {} bytes",
            bytes.len()
        );
    }

    #[test]
    fn test_read_write_message_roundtrip() {
        use std::io::Cursor;

        let original_data = b"test message data";
        let serialized = {
            let len = original_data.len() as u16;
            let mut buffer = Vec::with_capacity(2 + original_data.len());
            buffer.extend_from_slice(&len.to_le_bytes());
            buffer.extend_from_slice(original_data);
            buffer
        };

        // Write and read back
        let mut cursor = Cursor::new(Vec::new());
        write_message(&mut cursor, &serialized).expect("write");

        cursor.set_position(0);
        // Skip the length prefix we added to serialized, read the actual message
        let mut read_cursor = Cursor::new(cursor.into_inner());
        let read_data = read_message(&mut read_cursor).expect("read");

        assert_eq!(read_data, original_data);
    }

    #[test]
    fn test_read_message_too_large() {
        use std::io::Cursor;

        // Create a message claiming to be larger than MAX_MESSAGE_SIZE
        let large_len: u16 = 2000; // Greater than MAX_MESSAGE_SIZE (1024)
        let mut data = Vec::new();
        data.extend_from_slice(&large_len.to_le_bytes());
        data.extend(vec![0u8; 100]); // Some dummy data

        let mut cursor = Cursor::new(data);
        let result = read_message(&mut cursor);

        assert!(result.is_err());
        let error = result.unwrap_err().to_string();
        assert!(error.contains("too large"));
    }

    #[test]
    fn test_daemon_command_all_variants_serialize() {
        let commands = [
            DaemonCommand::Stop,
            DaemonCommand::GetStatus,
            DaemonCommand::Rescan,
            DaemonCommand::Pause,
            DaemonCommand::Resume,
            DaemonCommand::Ping,
        ];

        for command in commands {
            let bytes = serialize_command(&command);
            assert!(bytes.is_ok(), "Failed to serialize {command:?}");

            let bytes = bytes.unwrap();
            assert!(bytes.len() >= 3, "Serialized data too small for {command:?}");

            // Skip length prefix and deserialize
            let deserialized = deserialize_command(&bytes[2..]);
            assert!(deserialized.is_ok(), "Failed to deserialize {command:?}");
            assert_eq!(deserialized.unwrap(), command);
        }
    }

    #[test]
    fn test_daemon_response_all_variants_serialize() {
        let responses = [
            DaemonResponse::Ok,
            DaemonResponse::Pong,
            DaemonResponse::Error("test error message".to_string()),
            DaemonResponse::Error(String::new()),
            DaemonResponse::Status(DaemonStatus::default()),
            DaemonResponse::Status(DaemonStatus {
                state: DaemonStateInfo::Running,
                indexed_files: 1_000_000,
                indexed_directories: 100_000,
                monitored_volumes: 5,
                uptime_seconds: 86400,
                is_paused: true,
            }),
        ];

        for response in responses {
            let bytes = serialize_response(&response);
            assert!(bytes.is_ok(), "Failed to serialize {response:?}");

            let bytes = bytes.unwrap();
            let deserialized = deserialize_response(&bytes[2..]);
            assert!(deserialized.is_ok(), "Failed to deserialize {response:?}");
            assert_eq!(deserialized.unwrap(), response);
        }
    }

    #[test]
    fn test_daemon_status_with_values() {
        let status = DaemonStatus {
            state: DaemonStateInfo::Scanning,
            indexed_files: 123_456,
            indexed_directories: 7890,
            monitored_volumes: 3,
            uptime_seconds: 3600,
            is_paused: false,
        };

        assert_eq!(status.state, DaemonStateInfo::Scanning);
        assert_eq!(status.indexed_files, 123_456);
        assert_eq!(status.indexed_directories, 7890);
        assert_eq!(status.monitored_volumes, 3);
        assert_eq!(status.uptime_seconds, 3600);
        assert!(!status.is_paused);
    }

    #[test]
    fn test_daemon_state_info_all_variants_display() {
        let states = [
            (DaemonStateInfo::Stopped, "stopped"),
            (DaemonStateInfo::Starting, "starting"),
            (DaemonStateInfo::Running, "running"),
            (DaemonStateInfo::Scanning, "scanning"),
            (DaemonStateInfo::Stopping, "stopping"),
        ];

        for (state, expected) in states {
            assert_eq!(state.to_string(), expected);
        }
    }

    #[test]
    fn test_daemon_state_info_equality() {
        assert_eq!(DaemonStateInfo::Running, DaemonStateInfo::Running);
        assert_ne!(DaemonStateInfo::Running, DaemonStateInfo::Stopped);
        assert_ne!(DaemonStateInfo::Scanning, DaemonStateInfo::Starting);
    }

    #[test]
    fn test_daemon_state_info_clone_copy() {
        let original = DaemonStateInfo::Scanning;
        let copied = original;
        assert_eq!(original, copied);
    }

    #[test]
    fn test_daemon_response_error_with_long_message() {
        let long_message = "a".repeat(500);
        let response = DaemonResponse::Error(long_message.clone());

        let bytes = serialize_response(&response).expect("serialize");
        let deserialized = deserialize_response(&bytes[2..]).expect("deserialize");

        if let DaemonResponse::Error(msg) = deserialized {
            assert_eq!(msg, long_message);
        } else {
            panic!("Expected Error response");
        }
    }

    #[test]
    fn test_daemon_response_error_with_unicode() {
        let unicode_message = "Error: 文件未找到 αβγ 🚫";
        let response = DaemonResponse::Error(unicode_message.to_string());

        let bytes = serialize_response(&response).expect("serialize");
        let deserialized = deserialize_response(&bytes[2..]).expect("deserialize");

        if let DaemonResponse::Error(msg) = deserialized {
            assert_eq!(msg, unicode_message);
        } else {
            panic!("Expected Error response");
        }
    }

    #[test]
    fn test_daemon_status_large_values() {
        let status = DaemonStatus {
            state: DaemonStateInfo::Running,
            indexed_files: u64::MAX,
            indexed_directories: u64::MAX,
            monitored_volumes: u32::MAX,
            uptime_seconds: u64::MAX,
            is_paused: false,
        };

        let response = DaemonResponse::Status(status);
        let bytes = serialize_response(&response).expect("serialize");
        let deserialized = deserialize_response(&bytes[2..]).expect("deserialize");

        if let DaemonResponse::Status(s) = deserialized {
            assert_eq!(s.indexed_files, u64::MAX);
            assert_eq!(s.indexed_directories, u64::MAX);
            assert_eq!(s.monitored_volumes, u32::MAX);
        } else {
            panic!("Expected Status response");
        }
    }

    #[test]
    fn test_ipc_client_default() {
        let client = IpcClient::default();
        assert_eq!(client.timeout, IPC_TIMEOUT);
    }

    #[test]
    fn test_deserialize_invalid_command() {
        let invalid_bytes = [0xFF, 0xFF, 0xFF];
        let result = deserialize_command(&invalid_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_invalid_response() {
        let invalid_bytes = [0xFF, 0xFF, 0xFF];
        let result = deserialize_response(&invalid_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_empty_bytes() {
        let empty: [u8; 0] = [];
        let result = deserialize_command(&empty);
        assert!(result.is_err());

        let result = deserialize_response(&empty);
        assert!(result.is_err());
    }

    #[test]
    fn test_serialize_command_length_prefix() {
        let command = DaemonCommand::Ping;
        let bytes = serialize_command(&command).expect("serialize");

        // Extract length prefix
        let len = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;

        // Length should match remaining bytes
        assert_eq!(len, bytes.len() - 2);
    }

    #[test]
    fn test_serialize_response_length_prefix() {
        let response = DaemonResponse::Ok;
        let bytes = serialize_response(&response).expect("serialize");

        // Extract length prefix
        let len = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;

        // Length should match remaining bytes
        assert_eq!(len, bytes.len() - 2);
    }

    #[test]
    fn test_daemon_status_clone() {
        let original = DaemonStatus {
            state: DaemonStateInfo::Running,
            indexed_files: 100,
            indexed_directories: 10,
            monitored_volumes: 2,
            uptime_seconds: 3600,
            is_paused: true,
        };

        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_daemon_command_debug() {
        let command = DaemonCommand::Ping;
        let debug_str = format!("{command:?}");
        assert!(debug_str.contains("Ping"));
    }

    #[test]
    fn test_daemon_response_debug() {
        let response = DaemonResponse::Ok;
        let debug_str = format!("{response:?}");
        assert!(debug_str.contains("Ok"));
    }

    #[test]
    fn test_daemon_status_debug() {
        let status = DaemonStatus::default();
        let debug_str = format!("{status:?}");
        assert!(debug_str.contains("DaemonStatus"));
        assert!(debug_str.contains("state"));
    }

    #[test]
    fn test_daemon_state_info_debug() {
        let state = DaemonStateInfo::Scanning;
        let debug_str = format!("{state:?}");
        assert!(debug_str.contains("Scanning"));
    }

    #[test]
    fn test_ipc_client_is_daemon_running_when_not_running() {
        // When daemon is not running, this should return false
        let client = IpcClient::new();
        // This test just verifies the method exists and doesn't panic
        let _result = client.is_daemon_running();
    }

    #[test]
    fn test_read_message_exact_max_size() {
        use std::io::Cursor;

        // Create a message exactly at MAX_MESSAGE_SIZE
        let len: u16 = 1024; // MAX_MESSAGE_SIZE
        let mut data = Vec::new();
        data.extend_from_slice(&len.to_le_bytes());
        data.extend(vec![0u8; 1024]);

        let mut cursor = Cursor::new(data);
        let result = read_message(&mut cursor);

        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1024);
    }

    #[test]
    fn test_read_message_just_over_max_size() {
        use std::io::Cursor;

        // Create a message just over MAX_MESSAGE_SIZE
        let len: u16 = 1025; // MAX_MESSAGE_SIZE + 1
        let mut data = Vec::new();
        data.extend_from_slice(&len.to_le_bytes());
        data.extend(vec![0u8; 1025]);

        let mut cursor = Cursor::new(data);
        let result = read_message(&mut cursor);

        assert!(result.is_err());
    }

    #[test]
    fn test_write_message_empty() {
        use std::io::Cursor;

        let mut cursor = Cursor::new(Vec::new());
        let result = write_message(&mut cursor, &[]);

        assert!(result.is_ok());
        assert!(cursor.into_inner().is_empty());
    }
}
