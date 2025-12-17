//! NTFS USN (Update Sequence Number) Journal monitor.
//!
//! This module provides efficient change tracking for NTFS volumes by monitoring
//! the USN Journal. Instead of rescanning the entire file system, we can query
//! "what changed since USN X" to get incremental updates.
//!
//! # Requirements
//! - Administrator privileges are required to read the USN Journal.
//! - Only works on NTFS-formatted volumes.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};

use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

#[cfg(windows)]
use windows::Win32::Foundation::{CloseHandle, HANDLE};

/// A wrapper around Windows HANDLE that is Send + Sync.
/// This is safe because we only use the HANDLE for `DeviceIoControl` calls
/// which are thread-safe for read operations on the same handle.
#[cfg(windows)]
#[derive(Debug)]
struct SendableHandle(HANDLE);

#[cfg(windows)]
unsafe impl Send for SendableHandle {}

#[cfg(windows)]
unsafe impl Sync for SendableHandle {}

#[cfg(windows)]
impl SendableHandle {
    const fn new(handle: HANDLE) -> Self {
        Self(handle)
    }

    const fn get(&self) -> HANDLE {
        self.0
    }
}
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
#[cfg(windows)]
use windows::Win32::System::IO::DeviceIoControl;
#[cfg(windows)]
use windows::Win32::System::Ioctl::{
    FSCTL_QUERY_USN_JOURNAL, FSCTL_READ_USN_JOURNAL, READ_USN_JOURNAL_DATA_V0, USN_JOURNAL_DATA_V0,
};
#[cfg(windows)]
use windows::core::PCWSTR;

/// Size of the buffer for reading USN journal records.
const USN_BUFFER_SIZE: usize = 64 * 1024;

/// Reason flags for file changes.
#[expect(dead_code, reason = "constants for USN reason flag parsing")]
#[cfg(windows)]
mod reason_flags {
    pub const USN_REASON_DATA_OVERWRITE: u32 = 0x0000_0001;
    pub const USN_REASON_DATA_EXTEND: u32 = 0x0000_0002;
    pub const USN_REASON_DATA_TRUNCATION: u32 = 0x0000_0004;
    pub const USN_REASON_NAMED_DATA_OVERWRITE: u32 = 0x0000_0010;
    pub const USN_REASON_NAMED_DATA_EXTEND: u32 = 0x0000_0020;
    pub const USN_REASON_NAMED_DATA_TRUNCATION: u32 = 0x0000_0040;
    pub const USN_REASON_FILE_CREATE: u32 = 0x0000_0100;
    pub const USN_REASON_FILE_DELETE: u32 = 0x0000_0200;
    pub const USN_REASON_EA_CHANGE: u32 = 0x0000_0400;
    pub const USN_REASON_SECURITY_CHANGE: u32 = 0x0000_0800;
    pub const USN_REASON_RENAME_OLD_NAME: u32 = 0x0000_1000;
    pub const USN_REASON_RENAME_NEW_NAME: u32 = 0x0000_2000;
    pub const USN_REASON_INDEXABLE_CHANGE: u32 = 0x0000_4000;
    pub const USN_REASON_BASIC_INFO_CHANGE: u32 = 0x0000_8000;
    pub const USN_REASON_HARD_LINK_CHANGE: u32 = 0x0001_0000;
    pub const USN_REASON_COMPRESSION_CHANGE: u32 = 0x0002_0000;
    pub const USN_REASON_ENCRYPTION_CHANGE: u32 = 0x0004_0000;
    pub const USN_REASON_OBJECT_ID_CHANGE: u32 = 0x0008_0000;
    pub const USN_REASON_REPARSE_POINT_CHANGE: u32 = 0x0010_0000;
    pub const USN_REASON_STREAM_CHANGE: u32 = 0x0020_0000;
    pub const USN_REASON_CLOSE: u32 = 0x8000_0000;
}

/// File attribute flag for directories.
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;

/// USN Journal monitor for tracking file system changes.
pub struct UsnMonitor {
    /// Drive letter being monitored.
    drive_letter: char,

    /// Volume handle for journal access (wrapped for Send safety).
    #[cfg(windows)]
    volume_handle: SendableHandle,

    /// Last processed USN.
    last_usn: i64,

    /// Journal ID to detect journal resets.
    #[cfg(windows)]
    journal_id: u64,

    /// Shutdown flag.
    shutdown: Arc<AtomicBool>,

    /// Placeholder for non-Windows.
    #[cfg(not(windows))]
    _placeholder: (),
}

/// Information about a USN Journal change.
#[expect(dead_code, reason = "fields used via Debug trait and future expansion")]
#[derive(Debug, Clone)]
pub struct UsnChange {
    /// The USN of this change.
    pub usn: i64,

    /// File reference number.
    pub file_reference: u64,

    /// Parent directory reference number.
    pub parent_reference: u64,

    /// File name.
    pub name: String,

    /// Reason flags indicating what changed.
    pub reason: u32,

    /// File attributes.
    pub attributes: u32,

    /// Whether this is a directory.
    pub is_directory: bool,
}

impl UsnMonitor {
    /// Create a new USN Journal monitor for the specified drive.
    ///
    /// # Arguments
    /// * `drive_letter` - The drive letter to monitor (e.g., 'C').
    /// * `last_usn` - The last processed USN (0 to start from the beginning).
    ///
    /// # Errors
    /// Returns an error if the USN Journal cannot be accessed.
    #[cfg(windows)]
    pub fn new(drive_letter: char, last_usn: i64) -> Result<Self> {
        let drive_letter = drive_letter.to_ascii_uppercase();

        // Open the volume for journal access
        let volume_path: Vec<u16> = format!("\\\\.\\{drive_letter}:")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let volume_handle = unsafe {
            CreateFileW(
                PCWSTR(volume_path.as_ptr()),
                0x8000_0000, // GENERIC_READ
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )
            .context("Failed to open volume for USN Journal access")?
        };

        // Query the USN Journal to get the journal ID
        let journal_data = Self::query_usn_journal_static(volume_handle)?;

        info!(
            "Opened USN Journal for {}:\\ (Journal ID: {}, First USN: {}, Next USN: {})",
            drive_letter, journal_data.UsnJournalID, journal_data.FirstUsn, journal_data.NextUsn
        );

        Ok(Self {
            drive_letter,
            volume_handle: SendableHandle::new(volume_handle),
            last_usn,
            journal_id: journal_data.UsnJournalID,
            shutdown: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Create a new USN Journal monitor (non-Windows stub).
    #[cfg(not(windows))]
    pub fn new(drive_letter: char, last_usn: i64) -> Result<Self> {
        bail!("USN Journal monitoring is only supported on Windows");
    }

    /// Query USN Journal information (static helper).
    #[cfg(windows)]
    fn query_usn_journal_static(handle: HANDLE) -> Result<USN_JOURNAL_DATA_V0> {
        let mut journal_data: USN_JOURNAL_DATA_V0 = unsafe { std::mem::zeroed() };
        let mut bytes_returned: u32 = 0;

        let success = unsafe {
            DeviceIoControl(
                handle,
                FSCTL_QUERY_USN_JOURNAL,
                None,
                0,
                Some((&raw mut journal_data).cast()),
                std::mem::size_of::<USN_JOURNAL_DATA_V0>() as u32,
                Some(&raw mut bytes_returned),
                None,
            )
            .is_ok()
        };

        if !success {
            bail!("Failed to query USN Journal. Ensure the journal is enabled and you have admin privileges.");
        }

        Ok(journal_data)
    }

    /// Query current USN Journal information.
    #[cfg(windows)]
    pub fn query_journal(&self) -> Result<UsnJournalInfo> {
        let journal_data = Self::query_usn_journal_static(self.volume_handle.get())?;

        Ok(UsnJournalInfo {
            journal_id: journal_data.UsnJournalID,
            first_usn: journal_data.FirstUsn,
            next_usn: journal_data.NextUsn,
            lowest_valid_usn: journal_data.LowestValidUsn,
            max_usn: journal_data.MaxUsn,
            maximum_size: journal_data.MaximumSize,
            allocation_delta: journal_data.AllocationDelta,
        })
    }

    /// Query current USN Journal information (non-Windows stub).
    #[cfg(not(windows))]
    pub fn query_journal(&self) -> Result<UsnJournalInfo> {
        bail!("USN Journal monitoring is only supported on Windows");
    }

    /// Read changes from the USN Journal since the last processed USN.
    ///
    /// # Returns
    /// A vector of changes and the new last USN value.
    ///
    /// # Note
    /// Returns `Result` for cross-platform API consistency - the non-Windows stub
    /// returns an error since USN Journal only exists on Windows/NTFS.
    #[cfg(windows)]
    #[allow(clippy::unnecessary_wraps)]
    pub fn read_changes(&mut self) -> Result<(Vec<UsnChange>, i64)> {
        let mut changes = Vec::new();
        let mut buffer = vec![0u8; USN_BUFFER_SIZE];
        let mut current_usn = self.last_usn;

        // Prepare read request
        let mut read_data = READ_USN_JOURNAL_DATA_V0 {
            StartUsn: current_usn,
            ReasonMask: 0xFFFF_FFFF, // All reasons
            ReturnOnlyOnClose: 0,
            Timeout: 0,
            BytesToWaitFor: 0,
            UsnJournalID: self.journal_id,
        };

        loop {
            let mut bytes_returned: u32 = 0;

            let success = unsafe {
                DeviceIoControl(
                    self.volume_handle.get(),
                    FSCTL_READ_USN_JOURNAL,
                    Some((&raw const read_data).cast()),
                    std::mem::size_of::<READ_USN_JOURNAL_DATA_V0>() as u32,
                    Some(buffer.as_mut_ptr().cast()),
                    buffer.len() as u32,
                    Some(&raw mut bytes_returned),
                    None,
                )
                .is_ok()
            };

            if !success {
                // Check if journal was reset
                if let Ok(journal_info) = self.query_journal()
                    && journal_info.journal_id != self.journal_id
                {
                    warn!("USN Journal was reset, need full rescan");
                    self.journal_id = journal_info.journal_id;
                    self.last_usn = journal_info.first_usn;
                    return Ok((changes, self.last_usn));
                }
                break;
            }

            if bytes_returned < 8 {
                break;
            }

            // First 8 bytes contain the next USN
            let next_usn = i64::from_le_bytes(buffer[0..8].try_into().unwrap_or([0; 8]));

            if next_usn == current_usn {
                // No more records
                break;
            }

            // Parse USN records
            let mut offset = 8usize;
            while offset < bytes_returned as usize {
                if offset + 4 > bytes_returned as usize {
                    break;
                }

                let record_length =
                    u32::from_le_bytes(buffer[offset..offset + 4].try_into().unwrap_or([0; 4])) as usize;

                if record_length == 0 || offset + record_length > bytes_returned as usize {
                    break;
                }

                if let Some(change) = Self::parse_usn_record(&buffer[offset..offset + record_length]) {
                    changes.push(change);
                }

                offset += record_length;
            }

            current_usn = next_usn;
            read_data.StartUsn = next_usn;

            // If we got fewer bytes than the buffer, we've read all available records
            if bytes_returned < buffer.len() as u32 {
                break;
            }
        }

        self.last_usn = current_usn;
        Ok((changes, current_usn))
    }

    /// Read changes from the USN Journal (non-Windows stub).
    #[cfg(not(windows))]
    pub fn read_changes(&mut self) -> Result<(Vec<UsnChange>, i64)> {
        bail!("USN Journal monitoring is only supported on Windows");
    }

    /// Parse a USN record from raw bytes.
    #[cfg(windows)]
    fn parse_usn_record(data: &[u8]) -> Option<UsnChange> {
        if data.len() < 60 {
            return None;
        }

        // Check record version
        let major_version = u16::from_le_bytes(data[4..6].try_into().ok()?);

        match major_version {
            2 => Self::parse_usn_record_v2(data),
            3 => Self::parse_usn_record_v3(data),
            _ => None,
        }
    }

    /// Parse a `USN_RECORD_V2` structure.
    #[cfg(windows)]
    fn parse_usn_record_v2(data: &[u8]) -> Option<UsnChange> {
        if data.len() < 60 {
            return None;
        }

        let file_reference = u64::from_le_bytes(data[8..16].try_into().ok()?) & 0x0000_FFFF_FFFF_FFFF;
        let parent_reference = u64::from_le_bytes(data[16..24].try_into().ok()?) & 0x0000_FFFF_FFFF_FFFF;
        let usn = i64::from_le_bytes(data[24..32].try_into().ok()?);
        let reason = u32::from_le_bytes(data[40..44].try_into().ok()?);
        let file_attributes = u32::from_le_bytes(data[52..56].try_into().ok()?);
        let file_name_length = u16::from_le_bytes(data[56..58].try_into().ok()?) as usize;
        let file_name_offset = u16::from_le_bytes(data[58..60].try_into().ok()?) as usize;

        if file_name_offset + file_name_length > data.len() {
            return None;
        }

        let name_bytes = &data[file_name_offset..file_name_offset + file_name_length];
        let name = String::from_utf16_lossy(
            &name_bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect::<Vec<_>>(),
        );

        let is_directory = (file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

        Some(UsnChange {
            usn,
            file_reference,
            parent_reference,
            name,
            reason,
            attributes: file_attributes,
            is_directory,
        })
    }

    /// Parse a `USN_RECORD_V3` structure.
    #[cfg(windows)]
    fn parse_usn_record_v3(data: &[u8]) -> Option<UsnChange> {
        if data.len() < 76 {
            return None;
        }

        let file_reference = u64::from_le_bytes(data[8..16].try_into().ok()?) & 0x0000_FFFF_FFFF_FFFF;
        let parent_reference = u64::from_le_bytes(data[24..32].try_into().ok()?) & 0x0000_FFFF_FFFF_FFFF;
        let usn = i64::from_le_bytes(data[40..48].try_into().ok()?);
        let reason = u32::from_le_bytes(data[56..60].try_into().ok()?);
        let file_attributes = u32::from_le_bytes(data[68..72].try_into().ok()?);
        let file_name_length = u16::from_le_bytes(data[72..74].try_into().ok()?) as usize;
        let file_name_offset = u16::from_le_bytes(data[74..76].try_into().ok()?) as usize;

        if file_name_offset + file_name_length > data.len() {
            return None;
        }

        let name_bytes = &data[file_name_offset..file_name_offset + file_name_length];
        let name = String::from_utf16_lossy(
            &name_bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect::<Vec<_>>(),
        );

        let is_directory = (file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

        Some(UsnChange {
            usn,
            file_reference,
            parent_reference,
            name,
            reason,
            attributes: file_attributes,
            is_directory,
        })
    }

    /// Start monitoring the USN Journal in the background.
    ///
    /// Returns a channel receiver for change events.
    #[expect(dead_code, reason = "public API for background monitoring")]
    pub fn start_monitoring(mut self, poll_interval: Duration) -> (mpsc::Receiver<Vec<UsnChange>>, Arc<AtomicBool>) {
        let (sender, receiver) = mpsc::channel(100);
        let shutdown = self.shutdown.clone();

        tokio::spawn(async move {
            info!("Started USN Journal monitoring for {}:\\", self.drive_letter);

            while !self.shutdown.load(Ordering::Relaxed) {
                match self.read_changes() {
                    Ok((changes, _new_usn)) => {
                        if !changes.is_empty() {
                            debug!("USN Journal: {} changes detected", changes.len());
                            if sender.send(changes).await.is_err() {
                                // Receiver dropped, stop monitoring
                                break;
                            }
                        }
                    }
                    Err(error) => {
                        error!("Error reading USN Journal: {}", error);
                    }
                }

                tokio::time::sleep(poll_interval).await;
            }

            info!("Stopped USN Journal monitoring for {}:\\", self.drive_letter);
        });

        (receiver, shutdown)
    }

    /// Get the current last USN value.
    #[cfg(test)]
    #[must_use]
    pub const fn get_last_usn(&self) -> i64 {
        self.last_usn
    }

    /// Get the drive letter being monitored.
    #[must_use]
    pub const fn get_drive_letter(&self) -> char {
        self.drive_letter
    }

    /// Signal the monitor to stop.
    pub fn stop(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

#[cfg(windows)]
impl Drop for UsnMonitor {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.volume_handle.get());
        }
    }
}

/// Information about a USN Journal.
#[expect(dead_code, reason = "fields used via Debug trait and journal monitoring")]
#[derive(Debug, Clone)]
pub struct UsnJournalInfo {
    /// Unique identifier for this journal instance.
    pub journal_id: u64,

    /// First valid USN in the journal.
    pub first_usn: i64,

    /// Next USN to be assigned.
    pub next_usn: i64,

    /// Lowest valid USN in the journal.
    pub lowest_valid_usn: i64,

    /// Maximum USN value.
    pub max_usn: i64,

    /// Maximum size of the journal in bytes.
    pub maximum_size: u64,

    /// Allocation delta for journal growth.
    pub allocation_delta: u64,
}

impl UsnChange {
    /// Check if this change represents a file creation.
    #[cfg(windows)]
    #[must_use]
    pub const fn is_create(&self) -> bool {
        self.reason & reason_flags::USN_REASON_FILE_CREATE != 0
    }

    /// Check if this change represents a file deletion.
    #[cfg(windows)]
    #[must_use]
    pub const fn is_delete(&self) -> bool {
        self.reason & reason_flags::USN_REASON_FILE_DELETE != 0
    }

    /// Check if this change represents a rename (new name).
    #[cfg(windows)]
    #[must_use]
    pub const fn is_rename_new(&self) -> bool {
        self.reason & reason_flags::USN_REASON_RENAME_NEW_NAME != 0
    }

    /// Check if this change represents a rename (old name).
    #[expect(dead_code, reason = "public API for rename detection")]
    #[cfg(windows)]
    #[must_use]
    pub const fn is_rename_old(&self) -> bool {
        self.reason & reason_flags::USN_REASON_RENAME_OLD_NAME != 0
    }

    /// Check if this change represents a data modification.
    #[cfg(windows)]
    #[must_use]
    pub const fn is_modify(&self) -> bool {
        self.reason
            & (reason_flags::USN_REASON_DATA_OVERWRITE
                | reason_flags::USN_REASON_DATA_EXTEND
                | reason_flags::USN_REASON_DATA_TRUNCATION)
            != 0
    }

    /// Check if this is a close event (final event for a change).
    #[expect(dead_code, reason = "public API for close detection")]
    #[cfg(windows)]
    #[must_use]
    pub const fn is_close(&self) -> bool {
        self.reason & reason_flags::USN_REASON_CLOSE != 0
    }

    /// Non-Windows stubs.
    #[cfg(not(windows))]
    #[must_use]
    pub fn is_create(&self) -> bool {
        false
    }

    #[cfg(not(windows))]
    #[must_use]
    pub fn is_delete(&self) -> bool {
        false
    }

    #[cfg(not(windows))]
    #[must_use]
    pub fn is_rename_new(&self) -> bool {
        false
    }

    #[expect(dead_code, reason = "public API for rename detection")]
    #[cfg(not(windows))]
    #[must_use]
    pub fn is_rename_old(&self) -> bool {
        false
    }

    #[cfg(not(windows))]
    #[must_use]
    pub fn is_modify(&self) -> bool {
        false
    }

    #[expect(dead_code, reason = "public API for close detection")]
    #[cfg(not(windows))]
    #[must_use]
    pub fn is_close(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(windows)]
    fn test_usn_monitor_creation() {
        // This test requires admin privileges
        match UsnMonitor::new('C', 0) {
            Ok(monitor) => {
                assert_eq!(monitor.get_drive_letter(), 'C');
                assert_eq!(monitor.get_last_usn(), 0);
            }
            Err(e) => {
                // Expected if not running as admin
                println!("Skipping test (requires admin): {e}");
            }
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_query_journal() {
        match UsnMonitor::new('C', 0) {
            Ok(monitor) => {
                let info = monitor.query_journal().unwrap();
                assert!(info.journal_id > 0);
                assert!(info.next_usn >= info.first_usn);
            }
            Err(e) => {
                println!("Skipping test (requires admin): {e}");
            }
        }
    }
}
