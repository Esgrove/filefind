//! Inter-process communication for daemon control and status.
//!
//! This module provides a simple IPC mechanism using named pipes (Windows)
//! or Unix domain sockets (other platforms) for communication between
//! the daemon and client applications (CLI, tray app).
//!
//! Uses postcard binary serialization for efficient, compact messages.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::LazyLock;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Default timeout for IPC operations.
pub const IPC_TIMEOUT: Duration = Duration::from_secs(2);

/// Name of the named pipe (Windows) or socket file (Unix).
pub const IPC_PIPE_NAME: &str = "filefind-daemon";

/// Maximum message size in bytes.
const MAX_MESSAGE_SIZE: usize = 1024;

/// Path to the IPC socket/pipe.
static IPC_PATH: LazyLock<PathBuf> = LazyLock::new(|| {
    #[cfg(windows)]
    {
        PathBuf::from(format!(r"\\.\pipe\{IPC_PIPE_NAME}"))
    }
    #[cfg(not(windows))]
    {
        let runtime_dir = dirs::runtime_dir()
            .or_else(dirs::cache_dir)
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        runtime_dir.join(format!("{IPC_PIPE_NAME}.sock"))
    }
});

/// Commands that can be sent to the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Prune database entries for files/directories that no longer exist.
    Prune,
}

/// Response from the daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

/// IPC client for communicating with the daemon.
pub struct IpcClient {
    /// Timeout for operations.
    timeout: Duration,
}

impl DaemonCommand {
    /// Serialize this command to bytes for transmission.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn serialize(&self) -> Result<Vec<u8>> {
        postcard::to_stdvec(self).context("Failed to serialize command")
    }

    /// Serialize and write this command to a writer with length framing.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization or writing fails.
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        let data = self.serialize()?;
        write_message(writer, &data)
    }

    /// Read and deserialize a command from a reader.
    ///
    /// # Errors
    ///
    /// Returns an error if reading or deserialization fails.
    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        let data = read_message(reader)?;
        Self::deserialize(&data)
    }

    /// Deserialize a command from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails.
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        postcard::from_bytes(bytes).context("Failed to deserialize command")
    }
}

impl DaemonResponse {
    /// Serialize and write this response to a writer with length framing.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization or writing fails.
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        let data = self.serialize()?;
        write_message(writer, &data)
    }

    /// Serialize this response to bytes for transmission.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn serialize(&self) -> Result<Vec<u8>> {
        postcard::to_stdvec(self).context("Failed to serialize response")
    }

    /// Read and deserialize a response from a reader.
    ///
    /// # Errors
    ///
    /// Returns an error if reading or deserialization fails.
    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        let data = read_message(reader)?;
        Self::deserialize(&data)
    }

    /// Deserialize a response from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails.
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        postcard::from_bytes(bytes).context("Failed to deserialize response")
    }
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

    /// Prune database entries for files/directories that no longer exist.
    ///
    /// # Errors
    ///
    /// Returns an error if the prune cannot be triggered.
    pub fn prune(&self) -> Result<()> {
        match self.send_command(DaemonCommand::Prune)? {
            DaemonResponse::Ok => Ok(()),
            DaemonResponse::Error(error) => anyhow::bail!("Failed to trigger prune: {error}"),
            other => anyhow::bail!("Unexpected response: {other:?}"),
        }
    }

    #[cfg(windows)]
    fn send_command_windows(&self, command: DaemonCommand) -> Result<DaemonResponse> {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::windows::fs::OpenOptionsExt;

        const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;

        let pipe_path = get_ipc_path();

        // Try to connect to the named pipe
        let mut pipe = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_OVERLAPPED)
            .open(pipe_path)
            .context("Failed to connect to daemon - is it running?")?;

        // Wrap in a struct that implements timeout via polling
        // Windows named pipes don't support set_read_timeout directly,
        // but we can use the timeout for overall operation timing
        let start = std::time::Instant::now();

        // Serialize and send command
        command.write_to(&mut pipe)?;
        pipe.flush()?;

        // Check timeout before reading
        if start.elapsed() > self.timeout {
            anyhow::bail!("IPC operation timed out");
        }

        // Read response
        DaemonResponse::read_from(&mut pipe)
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
        command.write_to(&mut stream)?;

        // Read response
        DaemonResponse::read_from(&mut stream)
    }
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

impl Default for IpcClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Get the path to the IPC socket/pipe.
#[must_use]
pub fn get_ipc_path() -> &'static PathBuf {
    &IPC_PATH
}

/// Write a length-prefixed message to a writer.
///
/// # Errors
///
/// Returns an error if writing fails.
pub fn write_message<W: Write>(writer: &mut W, data: &[u8]) -> Result<()> {
    // Write length prefix (2 bytes, little-endian)
    let len = u16::try_from(data.len()).context("Message too large to send")?;
    writer.write_all(&len.to_le_bytes())?;
    // Write message data
    writer.write_all(data)?;
    writer.flush()?;
    Ok(())
}

/// Read a length-prefixed message from a reader.
///
/// # Errors
///
/// Returns an error if reading fails or the message is too large.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    use std::os::windows::io::FromRawHandle;
    #[cfg(windows)]
    use std::os::windows::io::OwnedHandle;

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
            let bytes = command.serialize().expect("serialize");
            // Raw postcard bytes, no length prefix
            let parsed = DaemonCommand::deserialize(&bytes).expect("deserialize");
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
            let bytes = response.serialize().expect("serialize");
            // Raw postcard bytes, no length prefix
            let parsed = DaemonResponse::deserialize(&bytes).expect("deserialize");
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
        let bytes = command.serialize().expect("serialize");
        // Length prefix (2) + minimal enum representation (1)
        assert!(
            bytes.len() <= 4,
            "Command should be very compact: {} bytes",
            bytes.len()
        );

        let status = DaemonStatus::default();
        let response = DaemonResponse::Status(status);
        let bytes = response.serialize().expect("serialize");
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

        // Write message (write_message now adds length prefix automatically)
        let mut cursor = Cursor::new(Vec::new());
        write_message(&mut cursor, original_data).expect("write");

        // Read it back
        cursor.set_position(0);
        let read_data = read_message(&mut cursor).expect("read");

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
            let bytes = command.serialize();
            assert!(bytes.is_ok(), "Failed to serialize {command:?}");

            let bytes = bytes.unwrap();
            assert!(!bytes.is_empty(), "Serialized data empty for {command:?}");

            // Raw postcard bytes, no length prefix
            let deserialized = DaemonCommand::deserialize(&bytes);
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
            let bytes = response.serialize();
            assert!(bytes.is_ok(), "Failed to serialize {response:?}");

            let bytes = bytes.unwrap();
            // Raw postcard bytes, no length prefix
            let deserialized = DaemonResponse::deserialize(&bytes);
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

        let bytes = response.serialize().expect("serialize");
        let deserialized = DaemonResponse::deserialize(&bytes).expect("deserialize");

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

        let bytes = response.serialize().expect("serialize");
        let deserialized = DaemonResponse::deserialize(&bytes).expect("deserialize");

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
        let bytes = response.serialize().expect("serialize");
        let deserialized = DaemonResponse::deserialize(&bytes).expect("deserialize");

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
        let result = DaemonCommand::deserialize(&invalid_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_invalid_response() {
        let invalid_bytes = [0xFF, 0xFF, 0xFF];
        let result = DaemonResponse::deserialize(&invalid_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_empty_bytes() {
        let empty: [u8; 0] = [];
        let result = DaemonCommand::deserialize(&empty);
        assert!(result.is_err());

        let result = DaemonResponse::deserialize(&empty);
        assert!(result.is_err());
    }

    #[test]
    fn test_serialize_command_raw_bytes() {
        let command = DaemonCommand::Ping;
        let bytes = command.serialize().expect("serialize");

        // Should be raw postcard bytes (no length prefix)
        // Verify we can deserialize directly
        let decoded = DaemonCommand::deserialize(&bytes).expect("deserialize");
        assert_eq!(decoded, command);
    }

    #[test]
    fn test_serialize_response_raw_bytes() {
        let response = DaemonResponse::Ok;
        let bytes = response.serialize().expect("serialize");

        // Should be raw postcard bytes (no length prefix)
        // Verify we can deserialize directly
        let decoded = DaemonResponse::deserialize(&bytes).expect("deserialize");
        assert_eq!(decoded, response);
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
        // Empty message still has 2-byte length prefix (0x00, 0x00)
        assert_eq!(cursor.into_inner(), vec![0, 0]);
    }

    // ==================== Integration Tests ====================
    // These tests simulate the full send/receive flow through pipes

    /// Simulates the full client->server command flow using in-memory buffers.
    #[test]
    fn test_integration_command_roundtrip() {
        use std::io::Cursor;

        let commands = [
            DaemonCommand::Stop,
            DaemonCommand::GetStatus,
            DaemonCommand::Rescan,
            DaemonCommand::Pause,
            DaemonCommand::Resume,
            DaemonCommand::Ping,
        ];

        for original_command in commands {
            // Client side: serialize and write
            let mut buffer = Vec::new();
            original_command.write_to(&mut buffer).expect("write command");

            // Server side: read and deserialize
            let mut cursor = Cursor::new(buffer);
            let received_command = DaemonCommand::read_from(&mut cursor).expect("read command");

            assert_eq!(original_command, received_command);
        }
    }

    /// Simulates the full server->client response flow using in-memory buffers.
    #[test]
    fn test_integration_response_roundtrip() {
        use std::io::Cursor;

        let responses = [
            DaemonResponse::Ok,
            DaemonResponse::Pong,
            DaemonResponse::Error("test error".to_string()),
            DaemonResponse::Error(String::new()),
            DaemonResponse::Status(DaemonStatus::default()),
            DaemonResponse::Status(DaemonStatus {
                state: DaemonStateInfo::Running,
                indexed_files: 1_234_567,
                indexed_directories: 89_012,
                monitored_volumes: 3,
                uptime_seconds: 86400,
                is_paused: false,
            }),
        ];

        for original_response in responses {
            // Server side: serialize and write
            let mut buffer = Vec::new();
            original_response.write_to(&mut buffer).expect("write response");

            // Client side: read and deserialize
            let mut cursor = Cursor::new(buffer);
            let received_response = DaemonResponse::read_from(&mut cursor).expect("read response");

            assert_eq!(original_response, received_response);
        }
    }

    /// Simulates a full request/response cycle (client sends command, server responds).
    #[test]
    fn test_integration_full_request_response_cycle() {
        use std::io::Cursor;

        // Step 1: Client sends GetStatus command
        let command = DaemonCommand::GetStatus;
        let mut request_buffer = Vec::new();
        command.write_to(&mut request_buffer).expect("write command");

        // Step 2: Server receives and parses command
        let mut request_cursor = Cursor::new(request_buffer);
        let received_command = DaemonCommand::read_from(&mut request_cursor).expect("read command");
        assert_eq!(received_command, DaemonCommand::GetStatus);

        // Step 3: Server generates response
        let status = DaemonStatus {
            state: DaemonStateInfo::Running,
            indexed_files: 500_000,
            indexed_directories: 50_000,
            monitored_volumes: 2,
            uptime_seconds: 3600,
            is_paused: false,
        };
        let response = DaemonResponse::Status(status);

        // Step 4: Server sends response
        let mut response_buffer = Vec::new();
        response.write_to(&mut response_buffer).expect("write response");

        // Step 5: Client receives and parses response
        let mut response_cursor = Cursor::new(response_buffer);
        let received_response = DaemonResponse::read_from(&mut response_cursor).expect("read response");

        // Verify the full cycle
        match received_response {
            DaemonResponse::Status(received_status) => {
                assert_eq!(received_status.state, DaemonStateInfo::Running);
                assert_eq!(received_status.indexed_files, 500_000);
                assert_eq!(received_status.indexed_directories, 50_000);
                assert_eq!(received_status.monitored_volumes, 2);
                assert_eq!(received_status.uptime_seconds, 3600);
                assert!(!received_status.is_paused);
            }
            other => panic!("Expected Status response, got {other:?}"),
        }
    }

    /// Tests multiple commands/responses in sequence on same buffer.
    #[test]
    fn test_integration_multiple_messages_in_sequence() {
        use std::io::Cursor;

        let mut buffer = Vec::new();

        // Write multiple commands to buffer
        let commands = [DaemonCommand::Ping, DaemonCommand::GetStatus, DaemonCommand::Pause];

        for command in &commands {
            command.write_to(&mut buffer).expect("write");
        }

        // Read them back in order
        let mut cursor = Cursor::new(buffer);
        for expected_command in &commands {
            let received_command = DaemonCommand::read_from(&mut cursor).expect("read");
            assert_eq!(&received_command, expected_command);
        }
    }

    /// Tests that the message framing handles various payload sizes correctly.
    #[test]
    fn test_integration_various_payload_sizes() {
        use std::io::Cursor;

        // Test with error messages of various lengths
        let sizes = [0, 1, 10, 100, 255, 256, 500, 1000];

        for size in sizes {
            let error_message = "x".repeat(size);
            let response = DaemonResponse::Error(error_message.clone());

            // Serialize and write
            let mut buffer = Vec::new();
            response.write_to(&mut buffer).expect("write");

            // Read and deserialize
            let mut cursor = Cursor::new(buffer);
            let received_response = DaemonResponse::read_from(&mut cursor).expect("read");

            match received_response {
                DaemonResponse::Error(msg) => assert_eq!(msg, error_message),
                other => panic!("Expected Error response, got {other:?}"),
            }
        }
    }

    /// Tests status with all daemon states.
    #[test]
    fn test_integration_all_daemon_states() {
        use std::io::Cursor;

        let states = [
            DaemonStateInfo::Stopped,
            DaemonStateInfo::Starting,
            DaemonStateInfo::Running,
            DaemonStateInfo::Scanning,
            DaemonStateInfo::Stopping,
        ];

        for daemon_state in states {
            let daemon_status = DaemonStatus {
                state: daemon_state,
                indexed_files: 123,
                indexed_directories: 45,
                monitored_volumes: 2,
                uptime_seconds: 60,
                is_paused: false,
            };
            let response = DaemonResponse::Status(daemon_status);

            // Full roundtrip
            let mut buffer = Vec::new();
            response.write_to(&mut buffer).expect("write");

            let mut cursor = Cursor::new(buffer);
            let received_response = DaemonResponse::read_from(&mut cursor).expect("read");

            match received_response {
                DaemonResponse::Status(s) => assert_eq!(s.state, daemon_state),
                other => panic!("Expected Status response, got {other:?}"),
            }
        }
    }

    /// Tests that paused flag is correctly transmitted.
    #[test]
    fn test_integration_paused_flag_transmission() {
        use std::io::Cursor;

        for is_paused in [true, false] {
            let status = DaemonStatus {
                state: DaemonStateInfo::Running,
                indexed_files: 100,
                indexed_directories: 10,
                monitored_volumes: 1,
                uptime_seconds: 30,
                is_paused,
            };
            let response = DaemonResponse::Status(status);

            let mut buffer = Vec::new();
            response.write_to(&mut buffer).expect("write");

            let mut cursor = Cursor::new(buffer);
            let received_response = DaemonResponse::read_from(&mut cursor).expect("read");

            match received_response {
                DaemonResponse::Status(s) => assert_eq!(s.is_paused, is_paused),
                other => panic!("Expected Status response, got {other:?}"),
            }
        }
    }

    /// Tests error message with unicode characters.
    #[test]
    fn test_integration_unicode_error_message() {
        use std::io::Cursor;

        let unicode_messages = [
            "文件未找到",
            "Ошибка доступа",
            "αβγδε",
            "🚫 Error: File not found 📁",
            "Mixed: Hello 世界 🌍",
        ];

        for message in unicode_messages {
            let response = DaemonResponse::Error(message.to_string());

            let mut buffer = Vec::new();
            response.write_to(&mut buffer).expect("write");

            let mut cursor = Cursor::new(buffer);
            let received_response = DaemonResponse::read_from(&mut cursor).expect("read");

            match received_response {
                DaemonResponse::Error(msg) => assert_eq!(msg, message),
                other => panic!("Expected Error response, got {other:?}"),
            }
        }
    }

    /// Tests boundary values for numeric fields in `DaemonStatus`.
    #[test]
    fn test_integration_status_boundary_values() {
        use std::io::Cursor;

        let test_cases = [
            // (indexed_files, indexed_directories, monitored_volumes, uptime_seconds)
            (0, 0, 0, 0),
            (1, 1, 1, 1),
            (u64::MAX, u64::MAX, u32::MAX, u64::MAX),
            (u64::MAX / 2, u64::MAX / 2, u32::MAX / 2, u64::MAX / 2),
            (1_000_000_000, 100_000_000, 100, 365 * 24 * 3600), // Realistic large values
        ];

        for (files, dirs, volumes, uptime) in test_cases {
            let status = DaemonStatus {
                state: DaemonStateInfo::Running,
                indexed_files: files,
                indexed_directories: dirs,
                monitored_volumes: volumes,
                uptime_seconds: uptime,
                is_paused: false,
            };
            let response = DaemonResponse::Status(status);

            let mut buffer = Vec::new();
            response.write_to(&mut buffer).expect("write");

            let mut cursor = Cursor::new(buffer);
            let received_response = DaemonResponse::read_from(&mut cursor).expect("read");

            match received_response {
                DaemonResponse::Status(s) => {
                    assert_eq!(s.indexed_files, files);
                    assert_eq!(s.indexed_directories, dirs);
                    assert_eq!(s.monitored_volumes, volumes);
                    assert_eq!(s.uptime_seconds, uptime);
                }
                other => panic!("Expected Status response, got {other:?}"),
            }
        }
    }

    /// Tests that partial reads fail gracefully.
    #[test]
    fn test_integration_partial_read_fails() {
        use std::io::Cursor;

        // Create a valid message
        let response = DaemonResponse::Ok;
        let mut buffer = Vec::new();
        response.write_to(&mut buffer).expect("write");

        // Truncate the buffer to simulate partial transmission
        buffer.truncate(buffer.len() / 2);

        let mut cursor = Cursor::new(buffer);
        let result = read_message(&mut cursor);

        // Should fail because message is incomplete
        assert!(result.is_err());
    }

    /// Tests that corrupted length prefix is handled.
    #[test]
    fn test_integration_corrupted_length_prefix() {
        use std::io::Cursor;

        // Create a buffer with a length prefix that claims more data than available
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&100u16.to_le_bytes()); // Claims 100 bytes
        buffer.extend_from_slice(&[0u8; 10]); // But only 10 bytes of data

        let mut cursor = Cursor::new(buffer);
        let result = read_message(&mut cursor);

        // Should fail because not enough data
        assert!(result.is_err());
    }

    /// Tests that invalid postcard data is handled gracefully.
    #[test]
    fn test_integration_invalid_postcard_data() {
        use std::io::Cursor;

        // Create a message with valid framing but invalid postcard content
        let mut buffer = Vec::new();
        let garbage_data = [0xFF, 0xFE, 0xFD, 0xFC, 0xFB];
        write_message(&mut buffer, &garbage_data).expect("write");

        let mut cursor = Cursor::new(buffer);
        let received_bytes = read_message(&mut cursor).expect("read");

        // read_message should succeed (framing is valid)
        assert_eq!(received_bytes, garbage_data);

        // But deserialization should fail
        let result = DaemonCommand::deserialize(&received_bytes);
        assert!(result.is_err());

        let result = DaemonResponse::deserialize(&received_bytes);
        assert!(result.is_err());
    }

    /// Tests bidirectional communication simulation.
    #[test]
    fn test_integration_bidirectional_communication() {
        use std::io::Cursor;

        // Simulate a conversation:
        // Client: Ping
        // Server: Pong
        // Client: GetStatus
        // Server: Status(...)
        // Client: Stop
        // Server: Ok

        // Request 1: Ping
        let mut req1_buf = Vec::new();
        DaemonCommand::Ping.write_to(&mut req1_buf).unwrap();

        let mut cursor = Cursor::new(req1_buf);
        let cmd = DaemonCommand::read_from(&mut cursor).unwrap();
        assert_eq!(cmd, DaemonCommand::Ping);

        // Response 1: Pong
        let mut resp1_buf = Vec::new();
        DaemonResponse::Pong.write_to(&mut resp1_buf).unwrap();

        let mut cursor = Cursor::new(resp1_buf);
        let resp = DaemonResponse::read_from(&mut cursor).unwrap();
        assert_eq!(resp, DaemonResponse::Pong);

        // Request 2: GetStatus
        let mut req2_buf = Vec::new();
        DaemonCommand::GetStatus.write_to(&mut req2_buf).unwrap();

        let mut cursor = Cursor::new(req2_buf);
        let cmd = DaemonCommand::read_from(&mut cursor).unwrap();
        assert_eq!(cmd, DaemonCommand::GetStatus);

        // Response 2: Status
        let status = DaemonStatus {
            state: DaemonStateInfo::Running,
            indexed_files: 42,
            indexed_directories: 7,
            monitored_volumes: 1,
            uptime_seconds: 100,
            is_paused: false,
        };
        let mut resp2_buf = Vec::new();
        DaemonResponse::Status(status).write_to(&mut resp2_buf).unwrap();

        let mut cursor = Cursor::new(resp2_buf);
        let resp = DaemonResponse::read_from(&mut cursor).unwrap();
        match resp {
            DaemonResponse::Status(s) => assert_eq!(s.indexed_files, 42),
            other => panic!("Expected Status, got {other:?}"),
        }

        // Request 3: Stop
        let mut req3_buf = Vec::new();
        DaemonCommand::Stop.write_to(&mut req3_buf).unwrap();

        let mut cursor = Cursor::new(req3_buf);
        let cmd = DaemonCommand::read_from(&mut cursor).unwrap();
        assert_eq!(cmd, DaemonCommand::Stop);

        // Response 3: Ok
        let mut resp3_buf = Vec::new();
        DaemonResponse::Ok.write_to(&mut resp3_buf).unwrap();

        let mut cursor = Cursor::new(resp3_buf);
        let resp = DaemonResponse::read_from(&mut cursor).unwrap();
        assert_eq!(resp, DaemonResponse::Ok);
    }

    /// Tests that zero-length messages work correctly.
    #[test]
    fn test_integration_zero_length_payload() {
        use std::io::Cursor;

        // Write a zero-length message
        let mut buffer = Vec::new();
        write_message(&mut buffer, &[]).expect("write empty");

        // Should be just the length prefix (2 bytes of zeros)
        assert_eq!(buffer.len(), 2);
        assert_eq!(buffer, vec![0, 0]);

        // Read it back
        let mut cursor = Cursor::new(buffer);
        let received = read_message(&mut cursor).expect("read empty");
        assert!(received.is_empty());
    }

    /// Tests message at maximum allowed size.
    #[test]
    fn test_integration_max_size_message() {
        use std::io::Cursor;

        // Create a message at exactly MAX_MESSAGE_SIZE (1024 bytes)
        let large_payload = vec![0xABu8; 1024];

        let mut buffer = Vec::new();
        write_message(&mut buffer, &large_payload).expect("write max size");

        let mut cursor = Cursor::new(buffer);
        let received = read_message(&mut cursor).expect("read max size");

        assert_eq!(received.len(), 1024);
        assert_eq!(received, large_payload);
    }

    // ==================== Real Pipe Integration Tests ====================
    // These tests use actual OS pipes for more realistic testing

    /// Creates an anonymous pipe pair for testing.
    /// Returns (reader, writer) file handles.
    #[cfg(windows)]
    fn create_test_pipe() -> (std::fs::File, std::fs::File) {
        use windows_sys::Win32::System::Pipes::CreatePipe;

        let mut read_handle = std::ptr::null_mut();
        let mut write_handle = std::ptr::null_mut();

        let result = unsafe { CreatePipe(&raw mut read_handle, &raw mut write_handle, std::ptr::null(), 0) };

        assert!(result != 0, "Failed to create pipe");

        unsafe {
            let read_owned = OwnedHandle::from_raw_handle(read_handle);
            let write_owned = OwnedHandle::from_raw_handle(write_handle);
            (std::fs::File::from(read_owned), std::fs::File::from(write_owned))
        }
    }

    /// Tests command roundtrip through a real OS pipe.
    #[test]
    #[cfg(windows)]
    fn test_real_pipe_command_roundtrip() {
        let (mut reader, mut writer) = create_test_pipe();

        let commands = [
            DaemonCommand::Stop,
            DaemonCommand::GetStatus,
            DaemonCommand::Rescan,
            DaemonCommand::Pause,
            DaemonCommand::Resume,
            DaemonCommand::Ping,
        ];

        for original_command in commands {
            // Write command to pipe
            original_command.write_to(&mut writer).expect("write to pipe");

            // Read from pipe
            let received_command = DaemonCommand::read_from(&mut reader).expect("read from pipe");

            assert_eq!(original_command, received_command);
        }
    }

    /// Tests response roundtrip through a real OS pipe.
    #[test]
    #[cfg(windows)]
    fn test_real_pipe_response_roundtrip() {
        let (mut reader, mut writer) = create_test_pipe();

        let responses = [
            DaemonResponse::Ok,
            DaemonResponse::Pong,
            DaemonResponse::Error("test error message".to_string()),
            DaemonResponse::Status(DaemonStatus {
                state: DaemonStateInfo::Running,
                indexed_files: 123_456,
                indexed_directories: 7_890,
                monitored_volumes: 3,
                uptime_seconds: 3600,
                is_paused: true,
            }),
        ];

        for original_response in responses {
            // Write response to pipe
            original_response.write_to(&mut writer).expect("write to pipe");

            // Read from pipe
            let received_response = DaemonResponse::read_from(&mut reader).expect("read from pipe");

            assert_eq!(original_response, received_response);
        }
    }

    /// Tests full request/response cycle through real pipes (simulating bidirectional communication).
    #[test]
    #[cfg(windows)]
    fn test_real_pipe_full_cycle() {
        // Create two pipe pairs: one for client->server, one for server->client
        let (mut server_reader, mut client_writer) = create_test_pipe();
        let (mut client_reader, mut server_writer) = create_test_pipe();

        // Client sends GetStatus command
        let command = DaemonCommand::GetStatus;
        command.write_to(&mut client_writer).expect("client write");

        // Server receives command
        let received_command = DaemonCommand::read_from(&mut server_reader).expect("server read");
        assert_eq!(received_command, DaemonCommand::GetStatus);

        // Server sends response
        let status = DaemonStatus {
            state: DaemonStateInfo::Running,
            indexed_files: 999_999,
            indexed_directories: 88_888,
            monitored_volumes: 4,
            uptime_seconds: 7200,
            is_paused: false,
        };
        let response = DaemonResponse::Status(status);
        response.write_to(&mut server_writer).expect("server write");

        // Client receives response
        let received_response = DaemonResponse::read_from(&mut client_reader).expect("client read");

        match received_response {
            DaemonResponse::Status(s) => {
                assert_eq!(s.state, DaemonStateInfo::Running);
                assert_eq!(s.indexed_files, 999_999);
                assert_eq!(s.indexed_directories, 88_888);
                assert_eq!(s.monitored_volumes, 4);
                assert_eq!(s.uptime_seconds, 7200);
                assert!(!s.is_paused);
            }
            other => panic!("Expected Status response, got {other:?}"),
        }
    }

    /// Tests multiple sequential messages through real pipe.
    #[test]
    #[cfg(windows)]
    fn test_real_pipe_multiple_messages() {
        let (mut reader, mut writer) = create_test_pipe();

        // Write multiple messages
        let messages = [
            DaemonCommand::Ping,
            DaemonCommand::GetStatus,
            DaemonCommand::Pause,
            DaemonCommand::Resume,
            DaemonCommand::Rescan,
        ];

        for command in &messages {
            command.write_to(&mut writer).expect("write");
        }

        // Read back all messages
        for expected in &messages {
            let received = DaemonCommand::read_from(&mut reader).expect("read");
            assert_eq!(&received, expected);
        }
    }

    /// Tests threaded pipe communication (writer and reader in different threads).
    #[test]
    #[cfg(windows)]
    fn test_real_pipe_threaded_communication() {
        use std::sync::mpsc;
        use std::thread;

        let (mut reader, mut writer) = create_test_pipe();

        let (tx, rx) = mpsc::channel();

        // Spawn writer thread
        let writer_handle = thread::spawn(move || {
            let commands = [DaemonCommand::Ping, DaemonCommand::GetStatus, DaemonCommand::Stop];

            for command in commands {
                command.write_to(&mut writer).expect("write");
            }
        });

        // Spawn reader thread
        let reader_handle = thread::spawn(move || {
            let mut received = Vec::new();
            for _ in 0..3 {
                let command = DaemonCommand::read_from(&mut reader).expect("read");
                received.push(command);
            }
            tx.send(received).expect("send to channel");
        });

        writer_handle.join().expect("writer thread");
        reader_handle.join().expect("reader thread");

        let received = rx.recv().expect("receive from channel");
        assert_eq!(received.len(), 3);
        assert_eq!(received[0], DaemonCommand::Ping);
        assert_eq!(received[1], DaemonCommand::GetStatus);
        assert_eq!(received[2], DaemonCommand::Stop);
    }

    /// Tests that large status responses work through real pipe.
    #[test]
    #[cfg(windows)]
    fn test_real_pipe_large_status() {
        let (mut reader, mut writer) = create_test_pipe();

        // Create status with large values
        let status = DaemonStatus {
            state: DaemonStateInfo::Scanning,
            indexed_files: 10_000_000_000, // 10 billion files
            indexed_directories: 1_000_000_000,
            monitored_volumes: 26,
            uptime_seconds: 365 * 24 * 3600, // 1 year
            is_paused: false,
        };
        let response = DaemonResponse::Status(status);

        // Send through pipe
        response.write_to(&mut writer).expect("write");

        // Receive from pipe
        let received = DaemonResponse::read_from(&mut reader).expect("read");

        match received {
            DaemonResponse::Status(s) => {
                assert_eq!(s.indexed_files, 10_000_000_000);
                assert_eq!(s.indexed_directories, 1_000_000_000);
                assert_eq!(s.monitored_volumes, 26);
                assert_eq!(s.uptime_seconds, 365 * 24 * 3600);
            }
            other => panic!("Expected Status, got {other:?}"),
        }
    }

    /// Tests error response with long message through real pipe.
    #[test]
    #[cfg(windows)]
    fn test_real_pipe_long_error_message() {
        let (mut reader, mut writer) = create_test_pipe();

        let long_error = "Error: ".to_string() + &"x".repeat(500);
        let response = DaemonResponse::Error(long_error.clone());

        response.write_to(&mut writer).expect("write");

        let received = DaemonResponse::read_from(&mut reader).expect("read");

        match received {
            DaemonResponse::Error(msg) => assert_eq!(msg, long_error),
            other => panic!("Expected Error, got {other:?}"),
        }
    }
}
