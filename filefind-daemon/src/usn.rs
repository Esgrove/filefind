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
use tracing::{debug, error, info};

#[cfg(windows)]
use windows::Win32::Foundation::{CloseHandle, HANDLE};

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

/// Reason flags for file changes.
#[expect(dead_code, reason = "constants for USN reason flag parsing")]
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

/// Size of the buffer for reading USN journal records.
const USN_BUFFER_SIZE: usize = 64 * 1024;

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
#[derive(Debug, Clone)]
#[cfg_attr(not(test), allow(dead_code))]
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

/// A wrapper around Windows HANDLE that is Send + Sync.
/// This is safe because we only use the HANDLE for `DeviceIoControl` calls
/// which are thread-safe for read operations on the same handle.
#[cfg(windows)]
#[derive(Debug)]
struct SendableHandle(HANDLE);

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

        debug!(
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
    pub fn new(_drive_letter: char, _last_usn: i64) -> Result<Self> {
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
                    tracing::warn!("USN Journal was reset, need full rescan");
                    self.journal_id = journal_info.journal_id;
                    self.last_usn = journal_info.first_usn;
                    return Ok((changes, self.last_usn));
                }
                break;
            }

            if bytes_returned < 8 {
                break;
            }

            let (new_changes, next_usn) = Self::parse_usn_buffer(&buffer, bytes_returned as usize);

            if next_usn == current_usn {
                // No more records
                break;
            }

            changes.extend(new_changes);
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

    /// Parse a buffer of USN records returned by `FSCTL_READ_USN_JOURNAL`.
    ///
    /// The buffer layout matches the Windows kernel output:
    /// - `[0..8]`: Next USN value (`i64`, little-endian)
    /// - `[8..]`:  Packed `USN_RECORD_V2`/`USN_RECORD_V3` records, each 8-byte aligned
    ///
    /// Each record's `RecordLength` field (first 4 bytes) gives the total size
    /// including any alignment padding.  Walking stops when `RecordLength` is
    /// zero or would exceed the buffer.
    ///
    /// Returns the parsed changes and the next USN from the buffer header.
    fn parse_usn_buffer(buffer: &[u8], bytes_returned: usize) -> (Vec<UsnChange>, i64) {
        let mut changes = Vec::new();

        if bytes_returned < 8 || buffer.len() < 8 {
            return (changes, 0);
        }

        // First 8 bytes contain the next USN
        let next_usn = i64::from_le_bytes(buffer[0..8].try_into().unwrap_or([0; 8]));

        let mut offset = 8usize;
        while offset < bytes_returned {
            if offset + 4 > bytes_returned {
                break;
            }

            let record_length = u32::from_le_bytes(buffer[offset..offset + 4].try_into().unwrap_or([0; 4])) as usize;

            if record_length == 0 || offset + record_length > bytes_returned {
                break;
            }

            if let Some(change) = Self::parse_usn_record(&buffer[offset..offset + record_length]) {
                changes.push(change);
            }

            offset += record_length;
        }

        (changes, next_usn)
    }

    /// Parse a USN record from raw bytes.
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
            info!("Started USN Journal monitoring for {}:", self.drive_letter);

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

            info!("Stopped USN Journal monitoring for {}:", self.drive_letter);
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

impl UsnChange {
    /// Check if this change represents a file creation.
    #[must_use]
    pub const fn is_create(&self) -> bool {
        self.reason & reason_flags::USN_REASON_FILE_CREATE != 0
    }

    /// Check if this change represents a file deletion.
    #[must_use]
    pub const fn is_delete(&self) -> bool {
        self.reason & reason_flags::USN_REASON_FILE_DELETE != 0
    }

    /// Check if this change represents a rename (new name).
    #[must_use]
    pub const fn is_rename_new(&self) -> bool {
        self.reason & reason_flags::USN_REASON_RENAME_NEW_NAME != 0
    }

    /// Check if this change represents a rename (old name).
    #[must_use]
    pub const fn is_rename_old(&self) -> bool {
        self.reason & reason_flags::USN_REASON_RENAME_OLD_NAME != 0
    }

    /// Check if this change represents a data modification.
    #[must_use]
    pub const fn is_modify(&self) -> bool {
        self.reason
            & (reason_flags::USN_REASON_DATA_OVERWRITE
                | reason_flags::USN_REASON_DATA_EXTEND
                | reason_flags::USN_REASON_DATA_TRUNCATION)
            != 0
    }

    /// Check if this is a close event (final event for a change).
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub const fn is_close(&self) -> bool {
        self.reason & reason_flags::USN_REASON_CLOSE != 0
    }
}

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
impl Drop for UsnMonitor {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.volume_handle.get());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Test data builders ──────────────────────────────────────────────

    /// Align a size up to the nearest 8-byte boundary (matching real Windows output).
    const fn align8(size: usize) -> usize {
        (size + 7) & !7
    }

    /// Build a fake `USN_RECORD_V2` byte buffer.
    fn build_usn_v2_record(
        file_ref: u64,
        parent_ref: u64,
        usn: i64,
        reason: u32,
        attributes: u32,
        name: &str,
    ) -> Vec<u8> {
        let name_utf16: Vec<u16> = name.encode_utf16().collect();
        let name_bytes_len = name_utf16.len() * 2;
        let file_name_offset: u16 = 60;
        let record_length = file_name_offset as usize + name_bytes_len;

        let mut data = vec![0u8; record_length];

        // RecordLength (0..4)
        data[0..4].copy_from_slice(&(record_length as u32).to_le_bytes());
        // MajorVersion = 2 (4..6)
        data[4..6].copy_from_slice(&2u16.to_le_bytes());
        // MinorVersion = 0 (6..8)
        data[6..8].copy_from_slice(&0u16.to_le_bytes());
        // FileReferenceNumber (8..16)
        data[8..16].copy_from_slice(&file_ref.to_le_bytes());
        // ParentFileReferenceNumber (16..24)
        data[16..24].copy_from_slice(&parent_ref.to_le_bytes());
        // Usn (24..32)
        data[24..32].copy_from_slice(&usn.to_le_bytes());
        // TimeStamp (32..40) — leave as zero
        // Reason (40..44)
        data[40..44].copy_from_slice(&reason.to_le_bytes());
        // SourceInfo (44..48) — leave as zero
        // SecurityId (48..52) — leave as zero
        // FileAttributes (52..56)
        data[52..56].copy_from_slice(&attributes.to_le_bytes());
        // FileNameLength (56..58)
        data[56..58].copy_from_slice(&(name_bytes_len as u16).to_le_bytes());
        // FileNameOffset (58..60)
        data[58..60].copy_from_slice(&file_name_offset.to_le_bytes());
        // FileName UTF-16LE (60..)
        for (index, code_unit) in name_utf16.iter().enumerate() {
            let offset = file_name_offset as usize + index * 2;
            data[offset..offset + 2].copy_from_slice(&code_unit.to_le_bytes());
        }

        data
    }

    /// Build a fake `USN_RECORD_V3` byte buffer.
    fn build_usn_v3_record(
        file_ref: u64,
        parent_ref: u64,
        usn: i64,
        reason: u32,
        attributes: u32,
        name: &str,
    ) -> Vec<u8> {
        let name_utf16: Vec<u16> = name.encode_utf16().collect();
        let name_bytes_len = name_utf16.len() * 2;
        let file_name_offset: u16 = 76;
        let record_length = file_name_offset as usize + name_bytes_len;

        let mut data = vec![0u8; record_length];

        // RecordLength (0..4)
        data[0..4].copy_from_slice(&(record_length as u32).to_le_bytes());
        // MajorVersion = 3 (4..6)
        data[4..6].copy_from_slice(&3u16.to_le_bytes());
        // MinorVersion = 0 (6..8)
        data[6..8].copy_from_slice(&0u16.to_le_bytes());
        // FileReferenceNumber lower 64 bits (8..16)
        data[8..16].copy_from_slice(&file_ref.to_le_bytes());
        // FileReferenceNumber upper 64 bits (16..24) — zero
        // ParentFileReferenceNumber lower 64 bits (24..32)
        data[24..32].copy_from_slice(&parent_ref.to_le_bytes());
        // ParentFileReferenceNumber upper 64 bits (32..40) — zero
        // Usn (40..48)
        data[40..48].copy_from_slice(&usn.to_le_bytes());
        // TimeStamp (48..56) — zero
        // Reason (56..60)
        data[56..60].copy_from_slice(&reason.to_le_bytes());
        // SourceInfo (60..64) — zero
        // SecurityId (64..68) — zero
        // FileAttributes (68..72)
        data[68..72].copy_from_slice(&attributes.to_le_bytes());
        // FileNameLength (72..74)
        data[72..74].copy_from_slice(&(name_bytes_len as u16).to_le_bytes());
        // FileNameOffset (74..76)
        data[74..76].copy_from_slice(&file_name_offset.to_le_bytes());
        // FileName UTF-16LE (76..)
        for (index, code_unit) in name_utf16.iter().enumerate() {
            let offset = file_name_offset as usize + index * 2;
            data[offset..offset + 2].copy_from_slice(&code_unit.to_le_bytes());
        }

        data
    }

    /// Helper to create a `UsnChange` with the given reason flags.
    fn make_change(reason: u32) -> UsnChange {
        UsnChange {
            usn: 0,
            file_reference: 100,
            parent_reference: 5,
            name: String::from("test.txt"),
            reason,
            attributes: 0,
            is_directory: false,
        }
    }

    /// Build a `USN_RECORD_V2` with 8-byte aligned `RecordLength` (as Windows produces).
    fn build_aligned_v2_record(
        file_ref: u64,
        parent_ref: u64,
        usn: i64,
        reason: u32,
        attributes: u32,
        name: &str,
    ) -> Vec<u8> {
        let name_utf16: Vec<u16> = name.encode_utf16().collect();
        let name_bytes_len = name_utf16.len() * 2;
        let file_name_offset: u16 = 60;
        let raw_length = file_name_offset as usize + name_bytes_len;
        let record_length = align8(raw_length);

        let mut data = vec![0u8; record_length];

        data[0..4].copy_from_slice(&(record_length as u32).to_le_bytes());
        data[4..6].copy_from_slice(&2u16.to_le_bytes());
        data[8..16].copy_from_slice(&file_ref.to_le_bytes());
        data[16..24].copy_from_slice(&parent_ref.to_le_bytes());
        data[24..32].copy_from_slice(&usn.to_le_bytes());
        data[40..44].copy_from_slice(&reason.to_le_bytes());
        data[52..56].copy_from_slice(&attributes.to_le_bytes());
        data[56..58].copy_from_slice(&(name_bytes_len as u16).to_le_bytes());
        data[58..60].copy_from_slice(&file_name_offset.to_le_bytes());
        for (index, code_unit) in name_utf16.iter().enumerate() {
            let offset = file_name_offset as usize + index * 2;
            data[offset..offset + 2].copy_from_slice(&code_unit.to_le_bytes());
        }

        data
    }

    /// Build a `USN_RECORD_V3` with 8-byte aligned `RecordLength` (as Windows produces).
    fn build_aligned_v3_record(
        file_ref: u64,
        parent_ref: u64,
        usn: i64,
        reason: u32,
        attributes: u32,
        name: &str,
    ) -> Vec<u8> {
        let name_utf16: Vec<u16> = name.encode_utf16().collect();
        let name_bytes_len = name_utf16.len() * 2;
        let file_name_offset: u16 = 76;
        let raw_length = file_name_offset as usize + name_bytes_len;
        let record_length = align8(raw_length);

        let mut data = vec![0u8; record_length];

        data[0..4].copy_from_slice(&(record_length as u32).to_le_bytes());
        data[4..6].copy_from_slice(&3u16.to_le_bytes());
        data[8..16].copy_from_slice(&file_ref.to_le_bytes());
        data[24..32].copy_from_slice(&parent_ref.to_le_bytes());
        data[40..48].copy_from_slice(&usn.to_le_bytes());
        data[56..60].copy_from_slice(&reason.to_le_bytes());
        data[68..72].copy_from_slice(&attributes.to_le_bytes());
        data[72..74].copy_from_slice(&(name_bytes_len as u16).to_le_bytes());
        data[74..76].copy_from_slice(&file_name_offset.to_le_bytes());
        for (index, code_unit) in name_utf16.iter().enumerate() {
            let offset = file_name_offset as usize + index * 2;
            data[offset..offset + 2].copy_from_slice(&code_unit.to_le_bytes());
        }

        data
    }

    /// Assemble a complete USN journal output buffer.
    ///
    /// Matches the `FSCTL_READ_USN_JOURNAL` output layout:
    /// `[0..8]` next USN (i64 LE) followed by packed records.
    fn build_usn_journal_buffer(next_usn: i64, records: &[Vec<u8>]) -> Vec<u8> {
        let total: usize = 8 + records.iter().map(Vec::len).sum::<usize>();
        let mut buffer = Vec::with_capacity(total);
        buffer.extend_from_slice(&next_usn.to_le_bytes());
        for record in records {
            buffer.extend_from_slice(record);
        }
        buffer
    }

    // ── Live monitor tests (require admin on Windows) ───────────────────

    #[test]
    #[cfg(windows)]
    fn test_usn_monitor_creation() {
        // This test requires admin privileges
        match UsnMonitor::new('C', 0) {
            Ok(monitor) => {
                assert_eq!(monitor.get_drive_letter(), 'C');
                assert_eq!(monitor.get_last_usn(), 0);
            }
            Err(error) => {
                // Expected if not running as admin
                println!("Skipping test (requires admin): {error}");
            }
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_query_journal() {
        match UsnMonitor::new('C', 0) {
            Ok(monitor) => {
                let info = monitor.query_journal().expect("query_journal should succeed");
                assert!(info.journal_id > 0);
                assert!(info.next_usn >= info.first_usn);
            }
            Err(error) => {
                println!("Skipping test (requires admin): {error}");
            }
        }
    }

    // ── V2 record parsing ───────────────────────────────────────────────

    #[test]
    fn test_parse_usn_v2_file() {
        let data = build_usn_v2_record(42, 5, 1000, 0x100, 0x20, "hello.txt");
        let change = UsnMonitor::parse_usn_record(&data).expect("should parse V2 file record");

        assert_eq!(change.name, "hello.txt");
        assert_eq!(change.file_reference, 42);
        assert_eq!(change.parent_reference, 5);
        assert_eq!(change.usn, 1000);
        assert_eq!(change.reason, 0x100);
        assert_eq!(change.attributes, 0x20);
        assert!(!change.is_directory);
    }

    #[test]
    fn test_parse_usn_v2_directory() {
        let data = build_usn_v2_record(99, 5, 2000, 0x100, FILE_ATTRIBUTE_DIRECTORY, "Documents");
        let change = UsnMonitor::parse_usn_record(&data).expect("should parse V2 directory record");

        assert_eq!(change.name, "Documents");
        assert!(change.is_directory);
    }

    #[test]
    fn test_parse_usn_v2_unicode_name() {
        let data = build_usn_v2_record(50, 10, 3000, 0x100, 0x20, "日本語ファイル.txt");
        let change = UsnMonitor::parse_usn_record(&data).expect("should parse V2 unicode name");

        assert_eq!(change.name, "日本語ファイル.txt");
    }

    #[test]
    fn test_parse_usn_v2_long_name() {
        let long_name = "a".repeat(255);
        let data = build_usn_v2_record(60, 5, 4000, 0x100, 0x20, &long_name);
        let change = UsnMonitor::parse_usn_record(&data).expect("should parse V2 long name");

        assert_eq!(change.name, long_name);
    }

    #[test]
    fn test_parse_usn_v2_empty_name() {
        let data = build_usn_v2_record(70, 5, 5000, 0x100, 0x20, "");
        let change = UsnMonitor::parse_usn_record(&data).expect("should parse V2 empty name");

        assert_eq!(change.name, "");
    }

    #[test]
    fn test_parse_usn_v2_reference_mask() {
        // File references are masked to 48 bits (lower 6 bytes).
        // Set upper bytes to verify they are stripped.
        let full_ref: u64 = 0xABCD_0000_1234_5678;
        let expected_ref: u64 = 0x0000_0000_1234_5678;

        let data = build_usn_v2_record(full_ref, full_ref, 6000, 0x100, 0x20, "masked.txt");
        let change = UsnMonitor::parse_usn_record(&data).expect("should parse V2 with masked refs");

        assert_eq!(change.file_reference, expected_ref);
        assert_eq!(change.parent_reference, expected_ref);
    }

    #[test]
    fn test_parse_usn_v2_truncated_name() {
        let mut data = build_usn_v2_record(42, 5, 7000, 0x100, 0x20, "hello.txt");
        // Truncate the buffer so the filename extends beyond it
        data.truncate(64);

        let result = UsnMonitor::parse_usn_record(&data);
        assert!(result.is_none(), "should return None for truncated name data");
    }

    // ── V3 record parsing ───────────────────────────────────────────────

    #[test]
    fn test_parse_usn_v3_file() {
        let data = build_usn_v3_record(42, 5, 8000, 0x200, 0x20, "world.txt");
        let change = UsnMonitor::parse_usn_record(&data).expect("should parse V3 file record");

        assert_eq!(change.name, "world.txt");
        assert_eq!(change.file_reference, 42);
        assert_eq!(change.parent_reference, 5);
        assert_eq!(change.usn, 8000);
        assert_eq!(change.reason, 0x200);
        assert_eq!(change.attributes, 0x20);
        assert!(!change.is_directory);
    }

    #[test]
    fn test_parse_usn_v3_directory() {
        let data = build_usn_v3_record(88, 5, 9000, 0x100, FILE_ATTRIBUTE_DIRECTORY, "Projects");
        let change = UsnMonitor::parse_usn_record(&data).expect("should parse V3 directory record");

        assert_eq!(change.name, "Projects");
        assert!(change.is_directory);
    }

    #[test]
    fn test_parse_usn_v3_unicode_name() {
        let data = build_usn_v3_record(55, 10, 10_000, 0x100, 0x20, "données_résumé.pdf");
        let change = UsnMonitor::parse_usn_record(&data).expect("should parse V3 unicode name");

        assert_eq!(change.name, "données_résumé.pdf");
    }

    #[test]
    fn test_parse_usn_v3_reference_mask() {
        let full_ref: u64 = 0xFF00_0000_DEAD_BEEF;
        let expected_ref: u64 = 0x0000_0000_DEAD_BEEF;

        let data = build_usn_v3_record(full_ref, full_ref, 11_000, 0x100, 0x20, "v3mask.txt");
        let change = UsnMonitor::parse_usn_record(&data).expect("should parse V3 with masked refs");

        assert_eq!(change.file_reference, expected_ref);
        assert_eq!(change.parent_reference, expected_ref);
    }

    #[test]
    fn test_parse_usn_v3_truncated_name() {
        let mut data = build_usn_v3_record(42, 5, 12_000, 0x100, 0x20, "hello.txt");
        data.truncate(80);

        let result = UsnMonitor::parse_usn_record(&data);
        assert!(result.is_none(), "should return None for truncated V3 name data");
    }

    // ── Version dispatch & edge cases ───────────────────────────────────

    #[test]
    fn test_parse_usn_record_dispatches_v2() {
        let data = build_usn_v2_record(1, 2, 100, 0, 0, "v2.txt");
        let change = UsnMonitor::parse_usn_record(&data).expect("should dispatch to V2 parser");
        assert_eq!(change.name, "v2.txt");
    }

    #[test]
    fn test_parse_usn_record_dispatches_v3() {
        let data = build_usn_v3_record(1, 2, 200, 0, 0, "v3.txt");
        let change = UsnMonitor::parse_usn_record(&data).expect("should dispatch to V3 parser");
        assert_eq!(change.name, "v3.txt");
    }

    #[test]
    fn test_parse_usn_record_unknown_version() {
        let mut data = build_usn_v2_record(1, 2, 300, 0, 0, "unknown.txt");
        // Set major version to 99
        data[4..6].copy_from_slice(&99u16.to_le_bytes());

        let result = UsnMonitor::parse_usn_record(&data);
        assert!(result.is_none(), "should return None for unknown version");
    }

    #[test]
    fn test_parse_usn_record_too_short() {
        // Less than 60 bytes — should be rejected immediately
        let data = vec![0u8; 30];
        let result = UsnMonitor::parse_usn_record(&data);
        assert!(result.is_none(), "should return None for data shorter than 60 bytes");
    }

    #[test]
    fn test_parse_usn_record_exactly_minimum_v2() {
        // Exactly 60 bytes with an empty name is valid for V2
        let data = build_usn_v2_record(1, 2, 400, 0, 0, "");
        assert_eq!(data.len(), 60);

        let change = UsnMonitor::parse_usn_record(&data).expect("should parse minimal V2 record");
        assert_eq!(change.name, "");
    }

    #[test]
    fn test_parse_usn_v3_too_short_for_v3() {
        // 60 bytes is enough for V2 but not V3 (needs 76 minimum)
        let mut data = vec![0u8; 60];
        data[4..6].copy_from_slice(&3u16.to_le_bytes()); // version 3

        let result = UsnMonitor::parse_usn_record(&data);
        assert!(result.is_none(), "should return None for V3 data shorter than 76 bytes");
    }

    // ── UsnChange flag methods ──────────────────────────────────────────

    #[test]
    fn test_usn_change_is_create() {
        let change = make_change(reason_flags::USN_REASON_FILE_CREATE);
        assert!(change.is_create());
        assert!(!change.is_delete());
        assert!(!change.is_rename_new());
        assert!(!change.is_rename_old());
        assert!(!change.is_modify());
        assert!(!change.is_close());
    }

    #[test]
    fn test_usn_change_is_delete() {
        let change = make_change(reason_flags::USN_REASON_FILE_DELETE);
        assert!(change.is_delete());
        assert!(!change.is_create());
    }

    #[test]
    fn test_usn_change_is_rename_new() {
        let change = make_change(reason_flags::USN_REASON_RENAME_NEW_NAME);
        assert!(change.is_rename_new());
        assert!(!change.is_rename_old());
    }

    #[test]
    fn test_usn_change_is_rename_old() {
        let change = make_change(reason_flags::USN_REASON_RENAME_OLD_NAME);
        assert!(change.is_rename_old());
        assert!(!change.is_rename_new());
    }

    #[test]
    fn test_usn_change_is_modify_overwrite() {
        let change = make_change(reason_flags::USN_REASON_DATA_OVERWRITE);
        assert!(change.is_modify());
    }

    #[test]
    fn test_usn_change_is_modify_extend() {
        let change = make_change(reason_flags::USN_REASON_DATA_EXTEND);
        assert!(change.is_modify());
    }

    #[test]
    fn test_usn_change_is_modify_truncation() {
        let change = make_change(reason_flags::USN_REASON_DATA_TRUNCATION);
        assert!(change.is_modify());
    }

    #[test]
    fn test_usn_change_is_close() {
        let change = make_change(reason_flags::USN_REASON_CLOSE);
        assert!(change.is_close());
        assert!(!change.is_create());
    }

    #[test]
    fn test_usn_change_no_flags() {
        let change = make_change(0);
        assert!(!change.is_create());
        assert!(!change.is_delete());
        assert!(!change.is_rename_new());
        assert!(!change.is_rename_old());
        assert!(!change.is_modify());
        assert!(!change.is_close());
    }

    #[test]
    fn test_usn_change_combined_flags() {
        let reason = reason_flags::USN_REASON_FILE_CREATE
            | reason_flags::USN_REASON_DATA_EXTEND
            | reason_flags::USN_REASON_CLOSE;
        let change = make_change(reason);

        assert!(change.is_create());
        assert!(change.is_modify());
        assert!(change.is_close());
        assert!(!change.is_delete());
        assert!(!change.is_rename_new());
    }

    #[test]
    fn test_usn_change_all_modify_variants() {
        let reason = reason_flags::USN_REASON_DATA_OVERWRITE
            | reason_flags::USN_REASON_DATA_EXTEND
            | reason_flags::USN_REASON_DATA_TRUNCATION;
        let change = make_change(reason);

        assert!(change.is_modify());
    }

    // ── Round-trip: build record → parse → check flags ──────────────────

    #[test]
    fn test_v2_roundtrip_create_event() {
        let data = build_usn_v2_record(
            100,
            5,
            500,
            reason_flags::USN_REASON_FILE_CREATE | reason_flags::USN_REASON_CLOSE,
            0x20,
            "new_file.txt",
        );
        let change = UsnMonitor::parse_usn_record(&data).expect("should parse roundtrip V2");

        assert!(change.is_create());
        assert!(change.is_close());
        assert!(!change.is_delete());
        assert_eq!(change.name, "new_file.txt");
    }

    #[test]
    fn test_v3_roundtrip_rename_event() {
        let data = build_usn_v3_record(
            200,
            10,
            600,
            reason_flags::USN_REASON_RENAME_NEW_NAME,
            FILE_ATTRIBUTE_DIRECTORY,
            "Renamed Folder",
        );
        let change = UsnMonitor::parse_usn_record(&data).expect("should parse roundtrip V3");

        assert!(change.is_rename_new());
        assert!(change.is_directory);
        assert_eq!(change.name, "Renamed Folder");
    }

    #[test]
    fn test_v2_roundtrip_delete_event() {
        let data = build_usn_v2_record(
            300,
            5,
            700,
            reason_flags::USN_REASON_FILE_DELETE | reason_flags::USN_REASON_CLOSE,
            0x20,
            "deleted.log",
        );
        let change = UsnMonitor::parse_usn_record(&data).expect("should parse roundtrip delete");

        assert!(change.is_delete());
        assert!(change.is_close());
        assert!(!change.is_create());
    }

    // ── Realistic golden data ───────────────────────────────────────────
    //
    // Hand-crafted byte arrays that match the exact binary layout Windows
    // produces, verified against the Microsoft USN_RECORD_V2 / V3 docs.
    // Every field offset is annotated so reviewers can cross-check against
    // https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2

    #[test]
    fn test_golden_v2_file_create_close() {
        // USN_RECORD_V2 representing Windows creating "test.txt".
        //
        //   FileReferenceNumber  = 0x0001_0000_0000_1A2B  (seq=1, ref=0x1A2B)
        //   ParentFileReference  = 0x0003_0000_0000_0005  (seq=3, ref=5 = root)
        //   Usn                  = 12_345_678  (0x00BC614E)
        //   Reason               = FILE_CREATE | CLOSE  (0x8000_0100)
        //   FileAttributes       = ARCHIVE  (0x20)
        //   FileName             = "test.txt"  (8 wchars = 16 bytes)
        //   RecordLength         = 80  (60 header + 16 name + 4 pad → 80, 8-aligned)
        #[rustfmt::skip]
        let record: [u8; 80] = [
            // 0x00  RecordLength = 80
            0x50, 0x00, 0x00, 0x00,
            // 0x04  MajorVersion = 2, MinorVersion = 0
            0x02, 0x00, 0x00, 0x00,
            // 0x08  FileReferenceNumber
            0x2B, 0x1A, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            // 0x10  ParentFileReferenceNumber
            0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00,
            // 0x18  Usn = 12_345_678
            0x4E, 0x61, 0xBC, 0x00, 0x00, 0x00, 0x00, 0x00,
            // 0x20  TimeStamp (FILETIME, not parsed)
            0x00, 0x50, 0x7C, 0xA6, 0x9A, 0x5E, 0xDA, 0x01,
            // 0x28  Reason = FILE_CREATE | CLOSE
            0x00, 0x01, 0x00, 0x80,
            // 0x2C  SourceInfo = 0
            0x00, 0x00, 0x00, 0x00,
            // 0x30  SecurityId = 300
            0x2C, 0x01, 0x00, 0x00,
            // 0x34  FileAttributes = ARCHIVE
            0x20, 0x00, 0x00, 0x00,
            // 0x38  FileNameLength = 16
            0x10, 0x00,
            // 0x3A  FileNameOffset = 60
            0x3C, 0x00,
            // 0x3C  FileName "test.txt" UTF-16LE
            0x74, 0x00,  // t
            0x65, 0x00,  // e
            0x73, 0x00,  // s
            0x74, 0x00,  // t
            0x2E, 0x00,  // .
            0x74, 0x00,  // t
            0x78, 0x00,  // x
            0x74, 0x00,  // t
            // 0x4C  Alignment padding
            0x00, 0x00, 0x00, 0x00,
        ];

        let change = UsnMonitor::parse_usn_record(&record).expect("golden V2 record should parse");

        assert_eq!(change.name, "test.txt");
        // Upper 16 bits (sequence number) must be masked off
        assert_eq!(change.file_reference, 0x1A2B);
        assert_eq!(change.parent_reference, 5);
        assert_eq!(change.usn, 12_345_678);
        assert!(change.is_create());
        assert!(change.is_close());
        assert!(!change.is_directory);
        assert_eq!(change.attributes, 0x20);
    }

    #[test]
    fn test_golden_v3_rename_new() {
        // USN_RECORD_V3 representing a rename to "readme.md".
        //
        //   FileReferenceNumber  = 128-bit, lower 0x2A3B
        //   ParentFileReference  = 128-bit, lower 0x1E
        //   Usn                  = 87_654_321
        //   Reason               = RENAME_NEW_NAME | CLOSE  (0x8000_2000)
        //   FileAttributes       = ARCHIVE  (0x20)
        //   FileName             = "readme.md"  (9 wchars = 18 bytes)
        //   RecordLength         = 96  (76 header + 18 name + 2 pad → 96, 8-aligned)
        #[rustfmt::skip]
        let record: [u8; 96] = [
            // 0x00  RecordLength = 96
            0x60, 0x00, 0x00, 0x00,
            // 0x04  MajorVersion = 3, MinorVersion = 0
            0x03, 0x00, 0x00, 0x00,
            // 0x08  FileReferenceNumber (128-bit LE)
            0x3B, 0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // 0x18  ParentFileReferenceNumber (128-bit LE)
            0x1E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // 0x28  Usn = 87_654_321
            0xB1, 0x7F, 0x39, 0x05, 0x00, 0x00, 0x00, 0x00,
            // 0x30  TimeStamp
            0x00, 0x50, 0x7C, 0xA6, 0x9A, 0x5E, 0xDA, 0x01,
            // 0x38  Reason = RENAME_NEW_NAME | CLOSE
            0x00, 0x20, 0x00, 0x80,
            // 0x3C  SourceInfo = 0
            0x00, 0x00, 0x00, 0x00,
            // 0x40  SecurityId = 500
            0xF4, 0x01, 0x00, 0x00,
            // 0x44  FileAttributes = ARCHIVE
            0x20, 0x00, 0x00, 0x00,
            // 0x48  FileNameLength = 18
            0x12, 0x00,
            // 0x4A  FileNameOffset = 76
            0x4C, 0x00,
            // 0x4C  FileName "readme.md" UTF-16LE
            0x72, 0x00,  // r
            0x65, 0x00,  // e
            0x61, 0x00,  // a
            0x64, 0x00,  // d
            0x6D, 0x00,  // m
            0x65, 0x00,  // e
            0x2E, 0x00,  // .
            0x6D, 0x00,  // m
            0x64, 0x00,  // d
            // 0x5E  Alignment padding
            0x00, 0x00,
        ];

        let change = UsnMonitor::parse_usn_record(&record).expect("golden V3 record should parse");

        assert_eq!(change.name, "readme.md");
        assert_eq!(change.file_reference, 0x2A3B);
        assert_eq!(change.parent_reference, 0x1E);
        assert_eq!(change.usn, 87_654_321);
        assert!(change.is_rename_new());
        assert!(change.is_close());
        assert!(!change.is_delete());
        assert!(!change.is_directory);
    }

    #[test]
    fn test_golden_v2_hidden_system_file() {
        // "desktop.ini" with HIDDEN | SYSTEM | ARCHIVE attributes (0x26),
        // basic-info-change + close.
        #[rustfmt::skip]
        let record: [u8; 88] = [
            // RecordLength = 88
            0x58, 0x00, 0x00, 0x00,
            // MajorVersion = 2, MinorVersion = 0
            0x02, 0x00, 0x00, 0x00,
            // FileReferenceNumber = 0x0002_0000_0000_04D2 (ref=1234, seq=2)
            0xD2, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
            // ParentFileReferenceNumber = 0x0001_0000_0000_001F (ref=31, seq=1)
            0x1F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            // Usn = 500_000
            0x20, 0xA1, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00,
            // TimeStamp
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // Reason = BASIC_INFO_CHANGE | CLOSE (0x8000_8000)
            0x00, 0x80, 0x00, 0x80,
            // SourceInfo = 0
            0x00, 0x00, 0x00, 0x00,
            // SecurityId = 0
            0x00, 0x00, 0x00, 0x00,
            // FileAttributes = HIDDEN | SYSTEM | ARCHIVE (0x26)
            0x26, 0x00, 0x00, 0x00,
            // FileNameLength = 22 (11 wchars)
            0x16, 0x00,
            // FileNameOffset = 60
            0x3C, 0x00,
            // FileName "desktop.ini" UTF-16LE
            0x64, 0x00,  // d
            0x65, 0x00,  // e
            0x73, 0x00,  // s
            0x6B, 0x00,  // k
            0x74, 0x00,  // t
            0x6F, 0x00,  // o
            0x70, 0x00,  // p
            0x2E, 0x00,  // .
            0x69, 0x00,  // i
            0x6E, 0x00,  // n
            0x69, 0x00,  // i
            // Alignment padding (60 + 22 = 82, align to 88)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let change = UsnMonitor::parse_usn_record(&record).expect("golden hidden-system V2 record should parse");

        assert_eq!(change.name, "desktop.ini");
        assert_eq!(change.file_reference, 0x04D2);
        assert_eq!(change.parent_reference, 0x1F);
        assert_eq!(change.attributes, 0x26);
        assert!(!change.is_create());
        assert!(!change.is_delete());
        assert!(change.is_close());
    }

    #[test]
    fn test_golden_v2_directory_create() {
        // Creating a new directory "Projects".
        // Attributes = DIRECTORY | NOT_CONTENT_INDEXED (0x8010)
        // Reason     = FILE_CREATE | CLOSE
        #[rustfmt::skip]
        let record: [u8; 80] = [
            // RecordLength = 80
            0x50, 0x00, 0x00, 0x00,
            // MajorVersion = 2
            0x02, 0x00, 0x00, 0x00,
            // FileReferenceNumber = 0x0001_0000_0000_ABCD
            0xCD, 0xAB, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            // ParentFileReferenceNumber = 5 (root)
            0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // Usn = 999_999
            0x3F, 0x42, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00,
            // TimeStamp
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // Reason = FILE_CREATE | CLOSE
            0x00, 0x01, 0x00, 0x80,
            // SourceInfo
            0x00, 0x00, 0x00, 0x00,
            // SecurityId
            0x00, 0x00, 0x00, 0x00,
            // FileAttributes = DIRECTORY | NOT_CONTENT_INDEXED (0x8010)
            0x10, 0x80, 0x00, 0x00,
            // FileNameLength = 16 (8 wchars)
            0x10, 0x00,
            // FileNameOffset = 60
            0x3C, 0x00,
            // FileName "Projects" UTF-16LE
            0x50, 0x00,  // P
            0x72, 0x00,  // r
            0x6F, 0x00,  // o
            0x6A, 0x00,  // j
            0x65, 0x00,  // e
            0x63, 0x00,  // c
            0x74, 0x00,  // t
            0x73, 0x00,  // s
            // Padding
            0x00, 0x00, 0x00, 0x00,
        ];

        let change = UsnMonitor::parse_usn_record(&record).expect("golden directory-create record should parse");

        assert_eq!(change.name, "Projects");
        assert_eq!(change.file_reference, 0xABCD);
        assert!(change.is_directory);
        assert!(change.is_create());
        assert!(change.is_close());
    }

    // ── Realistic scenario tests ────────────────────────────────────────

    #[test]
    fn test_realistic_rename_pair() {
        // A rename produces TWO USN records: one with RENAME_OLD_NAME for the
        // old filename, and one with RENAME_NEW_NAME | CLOSE for the new name.
        // Both share the same FileReferenceNumber.
        let file_ref: u64 = 0x0002_0000_0000_1234;
        let parent_ref: u64 = 0x0001_0000_0000_0005;

        let old_record = build_usn_v2_record(
            file_ref,
            parent_ref,
            10_000,
            reason_flags::USN_REASON_RENAME_OLD_NAME,
            0x20,
            "old_report.docx",
        );
        let new_record = build_usn_v2_record(
            file_ref,
            parent_ref,
            10_001,
            reason_flags::USN_REASON_RENAME_NEW_NAME | reason_flags::USN_REASON_CLOSE,
            0x20,
            "Q4_Report_Final.docx",
        );

        let old_change = UsnMonitor::parse_usn_record(&old_record).expect("old-name record should parse");
        let new_change = UsnMonitor::parse_usn_record(&new_record).expect("new-name record should parse");

        // Same file reference, different names
        assert_eq!(old_change.file_reference, new_change.file_reference);
        assert_eq!(old_change.file_reference, 0x1234);

        assert!(old_change.is_rename_old());
        assert!(!old_change.is_rename_new());
        assert_eq!(old_change.name, "old_report.docx");

        assert!(new_change.is_rename_new());
        assert!(new_change.is_close());
        assert!(!new_change.is_rename_old());
        assert_eq!(new_change.name, "Q4_Report_Final.docx");
    }

    #[test]
    fn test_realistic_modify_overwrite_extend_close() {
        // Common pattern when saving a file: DATA_OVERWRITE | DATA_EXTEND | CLOSE
        let data = build_usn_v2_record(
            0x0005_0000_0000_2345,
            0x0001_0000_0000_0020,
            50_000,
            reason_flags::USN_REASON_DATA_OVERWRITE
                | reason_flags::USN_REASON_DATA_EXTEND
                | reason_flags::USN_REASON_CLOSE,
            0x20,
            "config.json",
        );

        let change = UsnMonitor::parse_usn_record(&data).expect("modify record should parse");

        assert_eq!(change.name, "config.json");
        assert!(change.is_modify());
        assert!(change.is_close());
        assert!(!change.is_create());
        assert!(!change.is_delete());
        assert_eq!(change.file_reference, 0x2345);
    }

    #[test]
    fn test_realistic_delete_close() {
        let data = build_usn_v2_record(
            0x0007_0000_0000_FFFF,
            0x0001_0000_0000_001A,
            75_000,
            reason_flags::USN_REASON_FILE_DELETE | reason_flags::USN_REASON_CLOSE,
            0x20,
            "temp_build_artifact.o",
        );

        let change = UsnMonitor::parse_usn_record(&data).expect("delete record should parse");

        assert_eq!(change.name, "temp_build_artifact.o");
        assert!(change.is_delete());
        assert!(change.is_close());
        assert!(!change.is_create());
        assert_eq!(change.file_reference, 0xFFFF);
    }

    #[test]
    fn test_realistic_security_change() {
        // Changing permissions on a file
        let data = build_usn_v2_record(
            0x0001_0000_0000_0800,
            0x0001_0000_0000_0005,
            90_000,
            reason_flags::USN_REASON_SECURITY_CHANGE | reason_flags::USN_REASON_CLOSE,
            0x20,
            "sensitive_data.xlsx",
        );

        let change = UsnMonitor::parse_usn_record(&data).expect("security-change record should parse");

        assert_eq!(change.name, "sensitive_data.xlsx");
        assert!(change.is_close());
        // Security change is not create, delete, rename, or modify
        assert!(!change.is_create());
        assert!(!change.is_delete());
        assert!(!change.is_rename_new());
        assert!(!change.is_modify());
    }

    // ── Multi-record buffer parsing (parse_usn_buffer) ──────────────────

    #[test]
    fn test_parse_usn_buffer_empty() {
        let buffer = 42i64.to_le_bytes().to_vec();
        let (changes, next_usn) = UsnMonitor::parse_usn_buffer(&buffer, buffer.len());

        assert!(changes.is_empty());
        assert_eq!(next_usn, 42);
    }

    #[test]
    fn test_parse_usn_buffer_too_small() {
        let buffer = vec![0u8; 4]; // Less than 8 bytes
        let (changes, next_usn) = UsnMonitor::parse_usn_buffer(&buffer, buffer.len());

        assert!(changes.is_empty());
        assert_eq!(next_usn, 0);
    }

    #[test]
    fn test_parse_usn_buffer_single_record() {
        let record = build_aligned_v2_record(
            100,
            5,
            1000,
            reason_flags::USN_REASON_FILE_CREATE | reason_flags::USN_REASON_CLOSE,
            0x20,
            "hello.txt",
        );
        let buffer = build_usn_journal_buffer(2000, &[record]);

        let (changes, next_usn) = UsnMonitor::parse_usn_buffer(&buffer, buffer.len());

        assert_eq!(next_usn, 2000);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].name, "hello.txt");
        assert!(changes[0].is_create());
    }

    #[test]
    fn test_parse_usn_buffer_multiple_records() {
        // Simulate a journal buffer with three events:
        // 1. File created
        // 2. File modified
        // 3. File deleted
        let create_record = build_aligned_v2_record(
            100,
            5,
            1000,
            reason_flags::USN_REASON_FILE_CREATE | reason_flags::USN_REASON_CLOSE,
            0x20,
            "new_file.txt",
        );
        let modify_record = build_aligned_v2_record(
            200,
            30,
            2000,
            reason_flags::USN_REASON_DATA_OVERWRITE | reason_flags::USN_REASON_CLOSE,
            0x20,
            "existing.log",
        );
        let delete_record = build_aligned_v2_record(
            300,
            5,
            3000,
            reason_flags::USN_REASON_FILE_DELETE | reason_flags::USN_REASON_CLOSE,
            0x20,
            "obsolete.tmp",
        );

        let buffer = build_usn_journal_buffer(4000, &[create_record, modify_record, delete_record]);

        let (changes, next_usn) = UsnMonitor::parse_usn_buffer(&buffer, buffer.len());

        assert_eq!(next_usn, 4000);
        assert_eq!(changes.len(), 3);
        assert_eq!(changes[0].name, "new_file.txt");
        assert!(changes[0].is_create());
        assert_eq!(changes[1].name, "existing.log");
        assert!(changes[1].is_modify());
        assert_eq!(changes[2].name, "obsolete.tmp");
        assert!(changes[2].is_delete());
    }

    #[test]
    fn test_parse_usn_buffer_mixed_v2_v3() {
        let v2_record = build_aligned_v2_record(100, 5, 1000, reason_flags::USN_REASON_FILE_CREATE, 0x20, "v2file.txt");
        let v3_record = build_aligned_v3_record(
            200,
            10,
            2000,
            reason_flags::USN_REASON_FILE_DELETE | reason_flags::USN_REASON_CLOSE,
            FILE_ATTRIBUTE_DIRECTORY,
            "v3dir",
        );

        let buffer = build_usn_journal_buffer(3000, &[v2_record, v3_record]);
        let (changes, next_usn) = UsnMonitor::parse_usn_buffer(&buffer, buffer.len());

        assert_eq!(next_usn, 3000);
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].name, "v2file.txt");
        assert!(!changes[0].is_directory);
        assert_eq!(changes[1].name, "v3dir");
        assert!(changes[1].is_directory);
        assert!(changes[1].is_delete());
    }

    #[test]
    fn test_parse_usn_buffer_rename_pair_in_sequence() {
        // Real rename: two records back-to-back, same file ref
        let file_ref = 500u64;
        let old_record = build_aligned_v2_record(
            file_ref,
            5,
            10_000,
            reason_flags::USN_REASON_RENAME_OLD_NAME,
            0x20,
            "before.txt",
        );
        let new_record = build_aligned_v2_record(
            file_ref,
            5,
            10_001,
            reason_flags::USN_REASON_RENAME_NEW_NAME | reason_flags::USN_REASON_CLOSE,
            0x20,
            "after.txt",
        );

        let buffer = build_usn_journal_buffer(11_000, &[old_record, new_record]);
        let (changes, _) = UsnMonitor::parse_usn_buffer(&buffer, buffer.len());

        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].file_reference, changes[1].file_reference);
        assert!(changes[0].is_rename_old());
        assert_eq!(changes[0].name, "before.txt");
        assert!(changes[1].is_rename_new());
        assert_eq!(changes[1].name, "after.txt");
    }

    #[test]
    fn test_parse_usn_buffer_bytes_returned_less_than_buffer() {
        // Simulate bytes_returned being smaller than buffer.len()
        // (only the first record should be visible).
        let record1 = build_aligned_v2_record(100, 5, 1000, reason_flags::USN_REASON_FILE_CREATE, 0x20, "visible.txt");
        let record2 = build_aligned_v2_record(
            200,
            5,
            2000,
            reason_flags::USN_REASON_FILE_DELETE,
            0x20,
            "invisible.txt",
        );
        let buffer = build_usn_journal_buffer(3000, &[record1.clone(), record2]);

        // Only report the header + first record as "returned"
        let bytes_returned = 8 + record1.len();
        let (changes, _) = UsnMonitor::parse_usn_buffer(&buffer, bytes_returned);

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].name, "visible.txt");
    }

    #[test]
    fn test_parse_usn_buffer_truncated_last_record() {
        // A record whose RecordLength would extend past bytes_returned
        let record = build_aligned_v2_record(100, 5, 1000, reason_flags::USN_REASON_FILE_CREATE, 0x20, "complete.txt");
        let buffer = build_usn_journal_buffer(2000, &[record.clone()]);

        // Lie about bytes_returned — cut the last record short
        let truncated_len = 8 + record.len() - 4;
        let (changes, _) = UsnMonitor::parse_usn_buffer(&buffer, truncated_len);

        // The truncated record should be skipped (RecordLength > remaining)
        assert!(changes.is_empty());
    }

    #[test]
    fn test_parse_usn_buffer_zero_record_length_stops() {
        // If RecordLength is 0 the walker must stop to avoid infinite loop
        let mut buffer = vec![0u8; 80];
        // Header: next_usn = 999
        buffer[0..8].copy_from_slice(&999i64.to_le_bytes());
        // Record at offset 8: RecordLength = 0 (rest is junk)
        // Already zero from vec initialization

        let (changes, next_usn) = UsnMonitor::parse_usn_buffer(&buffer, buffer.len());

        assert_eq!(next_usn, 999);
        assert!(changes.is_empty());
    }

    // ── UsnJournalInfo struct ───────────────────────────────────────────

    #[test]
    fn test_usn_journal_info_fields() {
        let info = UsnJournalInfo {
            journal_id: 12_345,
            first_usn: 100,
            next_usn: 50_000,
            lowest_valid_usn: 50,
            max_usn: 1_000_000,
            maximum_size: 33_554_432,
            allocation_delta: 4_194_304,
        };

        assert_eq!(info.journal_id, 12_345);
        assert_eq!(info.first_usn, 100);
        assert_eq!(info.next_usn, 50_000);
        assert!(info.next_usn >= info.first_usn);
    }

    #[test]
    fn test_usn_journal_info_clone() {
        let info = UsnJournalInfo {
            journal_id: 1,
            first_usn: 0,
            next_usn: 100,
            lowest_valid_usn: 0,
            max_usn: 999,
            maximum_size: 1024,
            allocation_delta: 256,
        };

        let cloned = info.clone();
        assert_eq!(cloned.journal_id, info.journal_id);
        assert_eq!(cloned.next_usn, info.next_usn);
    }

    #[test]
    fn test_usn_change_clone_and_debug() {
        let change = make_change(reason_flags::USN_REASON_FILE_CREATE);
        let cloned = change.clone();
        assert_eq!(cloned.name, change.name);
        assert_eq!(cloned.reason, change.reason);

        // Verify Debug impl doesn't panic
        let debug_str = format!("{change:?}");
        assert!(debug_str.contains("test.txt"));
    }
}
