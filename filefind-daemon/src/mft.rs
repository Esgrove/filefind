//! NTFS Master File Table (MFT) scanner.
//!
//! This module provides direct MFT reading for fast file system indexing on Windows.
//! Reading the MFT directly bypasses Windows file APIs and can scan millions of files
//! in seconds.
//!
//! # Requirements
//! - Administrator privileges are required to read the MFT directly.
//! - Only works on NTFS-formatted volumes.
//! - Does NOT work on network drives, even if they report as NTFS.

use std::collections::HashMap;
use std::time::SystemTime;

use anyhow::{Context, Result, bail};
use filefind::types::{FileEntry, IndexedVolume};
use tracing::debug;

#[cfg(windows)]
use windows::Win32::Foundation::{CloseHandle, HANDLE};
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    GetFileAttributesExW, GetFileExInfoStandard, GetVolumeInformationW, OPEN_EXISTING, WIN32_FILE_ATTRIBUTE_DATA,
};
#[cfg(windows)]
use windows::Win32::System::IO::DeviceIoControl;
#[cfg(windows)]
use windows::Win32::System::Ioctl::{FSCTL_ENUM_USN_DATA, FSCTL_GET_NTFS_VOLUME_DATA, NTFS_VOLUME_DATA_BUFFER};
#[cfg(windows)]
use windows::core::PCWSTR;

use filefind::types::VolumeType;

/// Size of the buffer for reading MFT records.
const MFT_BUFFER_SIZE: usize = 64 * 1024;

/// Path patterns that should never be indexed.
const IGNORED_PATH_PATTERNS: &[&str] = &[
    "$Recycle", // Windows Recycle Bin
    "#Recycle", // NAS Recycle Bin
];

/// File attribute flag for directories.
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;

/// File attribute flag for hidden files.
#[cfg_attr(not(test), allow(dead_code))]
const FILE_ATTRIBUTE_HIDDEN: u32 = 0x02;

/// MFT scanner for indexing NTFS volumes.
pub struct MftScanner {
    /// Drive letter (e.g., "C").
    drive_letter: char,

    /// Volume handle.
    #[cfg(windows)]
    volume_handle: HANDLE,

    /// Placeholder for non-Windows.
    #[cfg(not(windows))]
    _placeholder: (),
}

/// Raw MFT entry data before path resolution.
#[derive(Debug, Clone)]
#[cfg_attr(not(test), allow(dead_code))]
struct MftEntry {
    /// File reference number (unique ID within the volume).
    file_reference: u64,

    /// Parent file reference number.
    parent_reference: u64,

    /// File name.
    name: String,

    /// File attributes.
    attributes: u32,

    /// File size in bytes.
    size: u64,

    /// Whether this is a directory.
    is_directory: bool,
}

impl MftScanner {
    /// Create a new MFT scanner for the specified drive.
    ///
    /// # Arguments
    /// * `drive_letter` - The drive letter to scan (e.g., 'C').
    ///
    /// # Errors
    /// Returns an error if the volume cannot be opened or is not NTFS.
    #[cfg(windows)]
    pub fn new(drive_letter: char) -> Result<Self> {
        let drive_letter = drive_letter.to_ascii_uppercase();

        // Verify the volume is NTFS
        if !Self::is_ntfs_volume(drive_letter)? {
            bail!("Volume {drive_letter}:\\ is not an NTFS volume");
        }

        // Open the volume for direct access
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
            .context("Failed to open volume for MFT access")?
        };

        debug!("Opened volume {drive_letter}: for MFT scanning");

        Ok(Self {
            drive_letter,
            volume_handle,
        })
    }

    /// Create a new MFT scanner (non-Windows stub).
    #[cfg(not(windows))]
    pub fn new(_drive_letter: char) -> Result<Self> {
        bail!("MFT scanning is only supported on Windows");
    }

    /// Check if a volume is NTFS formatted.
    #[cfg(windows)]
    fn is_ntfs_volume(drive_letter: char) -> Result<bool> {
        let root_path: Vec<u16> = format!("{drive_letter}:\\")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut fs_name_buffer = [0u16; 256];

        let success = unsafe {
            GetVolumeInformationW(
                PCWSTR(root_path.as_ptr()),
                None,
                None,
                None,
                None,
                Some(&mut fs_name_buffer),
            )
            .is_ok()
        };

        if !success {
            bail!("Failed to get volume information for {drive_letter}:\\");
        }

        let fs_name = String::from_utf16_lossy(&fs_name_buffer)
            .trim_end_matches('\0')
            .to_uppercase();

        Ok(fs_name == "NTFS")
    }

    /// Check if a volume is NTFS formatted (non-Windows stub).
    #[cfg(not(windows))]
    const fn is_ntfs_volume(_drive_letter: char) -> Result<bool> {
        Ok(false)
    }

    /// Scan the MFT and return all file entries.
    ///
    /// # Errors
    /// Returns an error if the MFT cannot be read.
    #[expect(dead_code, reason = "public API for full volume scanning")]
    #[cfg(windows)]
    pub fn scan(&self) -> Result<Vec<FileEntry>> {
        self.scan_filtered(&[])
    }

    /// Scan the MFT (non-Windows stub).
    #[expect(dead_code, reason = "public API for full volume scanning")]
    #[cfg(not(windows))]
    pub fn scan(&self) -> Result<Vec<FileEntry>> {
        bail!("MFT scanning is only supported on Windows");
    }

    /// Scan the MFT and return file entries filtered by path prefixes.
    ///
    /// If `path_filters` is empty, returns all entries.
    /// Otherwise, only returns entries whose full path starts with one of the filter paths.
    ///
    /// This allows using fast MFT scanning even when only indexing specific directories.
    ///
    /// # Arguments
    /// * `path_filters` - List of path prefixes to filter by (e.g., `["C:\\Users", "C:\\Projects"]`)
    ///
    /// # Errors
    /// Returns an error if the MFT cannot be read.
    #[cfg(windows)]
    pub fn scan_filtered(&self, path_filters: &[String]) -> Result<Vec<FileEntry>> {
        if path_filters.is_empty() {
            debug!("{}: Scanning full drive", self.drive_letter);
        } else {
            debug!(
                "{}: Filtering to {} path(s): {:?}",
                self.drive_letter,
                path_filters.len(),
                path_filters
            );
        }

        // Get NTFS volume data
        let volume_data = self.get_ntfs_volume_data()?;
        let total_mft_records =
            volume_data.MftValidDataLength as u64 / u64::from(volume_data.BytesPerFileRecordSegment);

        debug!("MFT contains approximately {} records", total_mft_records);

        // Read all MFT entries
        let mft_entries = self.enumerate_mft_entries();
        debug!("Read {} MFT entries", mft_entries.len());

        // Build directory tree and resolve full paths
        let file_entries = self.resolve_paths(&mft_entries);
        debug!("Resolved {} file entries with paths", file_entries.len());

        // Filter out system directories that should never be indexed
        let file_entries: Vec<FileEntry> = file_entries
            .into_iter()
            .filter(|entry| {
                !IGNORED_PATH_PATTERNS
                    .iter()
                    .any(|pattern| entry.full_path.contains(pattern))
            })
            .collect();

        // Filter entries if path filters are specified
        if path_filters.is_empty() {
            debug!("{}: Found {} file entries", self.drive_letter, file_entries.len());
            Ok(file_entries)
        } else {
            let filtered: Vec<FileEntry> = file_entries
                .into_iter()
                .filter(|entry| {
                    let path_lower = entry.full_path.to_lowercase();
                    path_filters
                        .iter()
                        .any(|filter| path_lower.starts_with(&filter.to_lowercase()))
                })
                .collect();

            debug!("{}: Filtered to {} file entries", self.drive_letter, filtered.len());
            Ok(filtered)
        }
    }

    /// Scan the MFT with path filters (non-Windows stub).
    #[cfg(not(windows))]
    pub fn scan_filtered(&self, _path_filters: &[String]) -> Result<Vec<FileEntry>> {
        bail!("MFT scanning is only supported on Windows");
    }

    /// Get NTFS volume data structure.
    #[cfg(windows)]
    fn get_ntfs_volume_data(&self) -> Result<NTFS_VOLUME_DATA_BUFFER> {
        let mut volume_data: NTFS_VOLUME_DATA_BUFFER = unsafe { std::mem::zeroed() };
        let mut bytes_returned: u32 = 0;

        let success = unsafe {
            DeviceIoControl(
                self.volume_handle,
                FSCTL_GET_NTFS_VOLUME_DATA,
                None,
                0,
                Some((&raw mut volume_data).cast()),
                std::mem::size_of::<NTFS_VOLUME_DATA_BUFFER>() as u32,
                Some(&raw mut bytes_returned),
                None,
            )
            .is_ok()
        };

        if !success {
            bail!("Failed to get NTFS volume data");
        }

        Ok(volume_data)
    }

    /// Enumerate all MFT entries using `FSCTL_ENUM_USN_DATA`.
    #[cfg(windows)]
    fn enumerate_mft_entries(&self) -> Vec<MftEntry> {
        // Input structure for FSCTL_ENUM_USN_DATA
        #[repr(C)]
        struct MftEnumData {
            start_file_reference_number: u64,
            low_usn: i64,
            high_usn: i64,
            min_major_version: u16,
            max_major_version: u16,
        }

        let mut entries = Vec::new();
        let mut buffer = vec![0u8; MFT_BUFFER_SIZE];

        let mut enum_data = MftEnumData {
            start_file_reference_number: 0,
            low_usn: 0,
            high_usn: i64::MAX,
            min_major_version: 2,
            max_major_version: 3,
        };

        loop {
            let mut bytes_returned: u32 = 0;

            let success = unsafe {
                DeviceIoControl(
                    self.volume_handle,
                    FSCTL_ENUM_USN_DATA,
                    Some((&raw const enum_data).cast()),
                    std::mem::size_of::<MftEnumData>() as u32,
                    Some(buffer.as_mut_ptr().cast()),
                    buffer.len() as u32,
                    Some(&raw mut bytes_returned),
                    None,
                )
                .is_ok()
            };

            if !success || bytes_returned == 0 {
                break;
            }

            // First 8 bytes contain the next starting reference number
            if bytes_returned < 8 {
                break;
            }

            let (new_entries, next_ref) = Self::parse_mft_buffer(&buffer, bytes_returned as usize);
            entries.extend(new_entries);

            // Continue from the next reference number
            enum_data.start_file_reference_number = next_ref;

            // Log progress periodically
            if entries.len() % 100_000 == 0 && !entries.is_empty() {
                debug!("Read {} MFT entries so far...", entries.len());
            }
        }

        entries
    }

    /// Parse a buffer of MFT entries returned by `FSCTL_ENUM_USN_DATA`.
    ///
    /// The buffer layout matches the Windows kernel output:
    /// - `[0..8]`: Next file reference number (`u64`, little-endian)
    /// - `[8..]`:  Packed `USN_RECORD_V2`/`USN_RECORD_V3` records, each 8-byte aligned
    ///
    /// System MFT entries (file reference < 24) and entries with empty names
    /// are filtered out automatically.
    ///
    /// Returns the parsed entries and the next file reference from the buffer header.
    fn parse_mft_buffer(buffer: &[u8], bytes_returned: usize) -> (Vec<MftEntry>, u64) {
        let mut entries = Vec::new();

        if bytes_returned < 8 || buffer.len() < 8 {
            return (entries, 0);
        }

        let next_ref = u64::from_le_bytes(buffer[0..8].try_into().unwrap_or([0; 8]));

        let mut offset = 8usize;
        while offset < bytes_returned {
            if offset + 4 > bytes_returned {
                break;
            }

            let record_length = u32::from_le_bytes(buffer[offset..offset + 4].try_into().unwrap_or([0; 4])) as usize;

            if record_length == 0 || offset + record_length > bytes_returned {
                break;
            }

            if let Some(entry) = Self::parse_usn_record(&buffer[offset..offset + record_length]) {
                // Skip system files and special entries
                if entry.file_reference >= 24 && !entry.name.is_empty() {
                    entries.push(entry);
                }
            }

            offset += record_length;
        }

        (entries, next_ref)
    }

    /// Parse a USN record from raw bytes.
    fn parse_usn_record(data: &[u8]) -> Option<MftEntry> {
        if data.len() < 60 {
            return None;
        }

        // Check record version (offset 4-5)
        let major_version = u16::from_le_bytes(data[4..6].try_into().ok()?);

        match major_version {
            2 => Self::parse_usn_record_v2(data),
            3 => Self::parse_usn_record_v3(data),
            _ => None,
        }
    }

    /// Parse a `USN_RECORD_V2` structure.
    fn parse_usn_record_v2(data: &[u8]) -> Option<MftEntry> {
        if data.len() < 60 {
            return None;
        }

        let file_reference = u64::from_le_bytes(data[8..16].try_into().ok()?) & 0x0000_FFFF_FFFF_FFFF;
        let parent_reference = u64::from_le_bytes(data[16..24].try_into().ok()?) & 0x0000_FFFF_FFFF_FFFF;
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

        Some(MftEntry {
            file_reference,
            parent_reference,
            name,
            attributes: file_attributes,
            size: 0, // Size not available in USN record
            is_directory,
        })
    }

    /// Parse a `USN_RECORD_V3` structure.
    fn parse_usn_record_v3(data: &[u8]) -> Option<MftEntry> {
        if data.len() < 76 {
            return None;
        }

        // V3 uses 128-bit file references, but we only use the lower 64 bits
        let file_reference = u64::from_le_bytes(data[8..16].try_into().ok()?) & 0x0000_FFFF_FFFF_FFFF;
        let parent_reference = u64::from_le_bytes(data[24..32].try_into().ok()?) & 0x0000_FFFF_FFFF_FFFF;
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

        Some(MftEntry {
            file_reference,
            parent_reference,
            name,
            attributes: file_attributes,
            size: 0,
            is_directory,
        })
    }

    /// Get file size using Windows API.
    ///
    /// Returns 0 if the file size cannot be determined.
    #[cfg(windows)]
    fn get_file_size(path: &str) -> u64 {
        let wide_path: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

        let mut file_data: WIN32_FILE_ATTRIBUTE_DATA = unsafe { std::mem::zeroed() };

        let success = unsafe {
            GetFileAttributesExW(
                PCWSTR(wide_path.as_ptr()),
                GetFileExInfoStandard,
                (&raw mut file_data).cast(),
            )
            .is_ok()
        };

        if success {
            // Combine high and low parts into a 64-bit size
            (u64::from(file_data.nFileSizeHigh) << 32) | u64::from(file_data.nFileSizeLow)
        } else {
            0
        }
    }

    /// Resolve full paths for all MFT entries.
    #[cfg(windows)]
    fn resolve_paths(&self, mft_entries: &[MftEntry]) -> Vec<FileEntry> {
        // Root directory reference number is 5
        const ROOT_REF: u64 = 5;

        // Build a map of file reference -> entry for path resolution
        let mut ref_to_entry: HashMap<u64, &MftEntry> = HashMap::with_capacity(mft_entries.len());
        for entry in mft_entries {
            ref_to_entry.insert(entry.file_reference, entry);
        }

        let mut file_entries = Vec::with_capacity(mft_entries.len());
        let volume_id = 0i64;

        for entry in mft_entries {
            // Skip entries without names
            if entry.name.is_empty() {
                continue;
            }

            // Build full path by walking up the directory tree
            let full_path = self.build_full_path(entry, &ref_to_entry, ROOT_REF);

            // Get actual file size for non-directories
            let size = if entry.is_directory {
                0
            } else {
                Self::get_file_size(&full_path)
            };

            let file_entry = FileEntry {
                id: None,
                volume_id,
                parent_id: None,
                name: entry.name.clone(),
                full_path,
                is_directory: entry.is_directory,
                size,
                created_time: None,
                modified_time: None,
                mft_reference: Some(entry.file_reference),
            };

            file_entries.push(file_entry);
        }

        file_entries
    }

    /// Build the full path for an entry by walking up the directory tree.
    fn build_full_path(&self, entry: &MftEntry, ref_map: &HashMap<u64, &MftEntry>, root_ref: u64) -> String {
        const MAX_DEPTH: usize = 256;

        let mut path_parts = vec![entry.name.clone()];
        let mut current_ref = entry.parent_reference;
        let mut depth = 0;

        while current_ref != root_ref && depth < MAX_DEPTH {
            if let Some(parent) = ref_map.get(&current_ref) {
                if !parent.name.is_empty() {
                    path_parts.push(parent.name.clone());
                }
                current_ref = parent.parent_reference;
            } else {
                break;
            }
            depth += 1;
        }

        path_parts.reverse();
        format!("{}:\\{}", self.drive_letter, path_parts.join("\\"))
    }

    /// Get volume information for the scanned drive.
    #[cfg(windows)]
    pub fn get_volume_info(&self) -> Result<IndexedVolume> {
        let root_path: Vec<u16> = format!("{}:\\", self.drive_letter)
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut volume_name_buffer = [0u16; 256];
        let mut serial_number: u32 = 0;

        let success = unsafe {
            GetVolumeInformationW(
                PCWSTR(root_path.as_ptr()),
                Some(&mut volume_name_buffer),
                Some(&raw mut serial_number),
                None,
                None,
                None,
            )
            .is_ok()
        };

        if !success {
            bail!("Failed to get volume information for {}:\\", self.drive_letter);
        }

        let label = String::from_utf16_lossy(&volume_name_buffer)
            .trim_end_matches('\0')
            .to_string();

        Ok(IndexedVolume {
            id: None,
            serial_number: format!("{serial_number:08X}"),
            label: if label.is_empty() { None } else { Some(label) },
            mount_point: format!("{}:", self.drive_letter),
            volume_type: VolumeType::Ntfs,
            is_online: true,
            last_scan_time: Some(SystemTime::now()),
            last_usn: None,
        })
    }

    /// Get volume information (non-Windows stub).
    #[cfg(not(windows))]
    pub fn get_volume_info(&self) -> Result<IndexedVolume> {
        bail!("MFT scanning is only supported on Windows");
    }
}

#[cfg(windows)]
impl Drop for MftScanner {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.volume_handle);
        }
    }
}

/// Detect all available local NTFS volumes on the system.
#[cfg(windows)]
pub fn detect_ntfs_volumes() -> Vec<char> {
    let mut volumes = Vec::new();

    for letter in 'A'..='Z' {
        let drive_path = format!("{letter}:\\");

        let root_path: Vec<u16> = drive_path.encode_utf16().chain(std::iter::once(0)).collect();

        let mut fs_name_buffer = [0u16; 256];

        let success = unsafe {
            GetVolumeInformationW(
                PCWSTR(root_path.as_ptr()),
                None,
                None,
                None,
                None,
                Some(&mut fs_name_buffer),
            )
            .is_ok()
        };

        if success {
            let fs_name = String::from_utf16_lossy(&fs_name_buffer)
                .trim_end_matches('\0')
                .to_uppercase();

            if fs_name == "NTFS" {
                debug!("Detected local NTFS volume: {letter}:");
                volumes.push(letter);
            }
        }
    }

    volumes
}

/// Detect all available NTFS volumes (non-Windows stub).
#[cfg(not(windows))]
pub const fn detect_ntfs_volumes() -> Vec<char> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Test helpers ────────────────────────────────────────────────────

    /// Align a size up to the nearest 8-byte boundary (matching real Windows output).
    const fn align8(size: usize) -> usize {
        (size + 7) & !7
    }

    /// Create a test-only `MftScanner` without opening a real volume handle.
    fn make_test_scanner(drive_letter: char) -> MftScanner {
        MftScanner {
            drive_letter,
            #[cfg(windows)]
            volume_handle: HANDLE::default(),
            #[cfg(not(windows))]
            _placeholder: (),
        }
    }

    /// Build a fake `USN_RECORD_V2` byte buffer for MFT enumeration.
    fn build_mft_v2_record(file_ref: u64, parent_ref: u64, attributes: u32, name: &str) -> Vec<u8> {
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
        // Usn (24..32) — leave as zero for MFT
        // TimeStamp (32..40) — zero
        // Reason (40..44) — zero
        // SourceInfo (44..48) — zero
        // SecurityId (48..52) — zero
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

    /// Build a fake `USN_RECORD_V3` byte buffer for MFT enumeration.
    fn build_mft_v3_record(file_ref: u64, parent_ref: u64, attributes: u32, name: &str) -> Vec<u8> {
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
        // Usn (40..48) — zero
        // TimeStamp (48..56) — zero
        // Reason (56..60) — zero
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

    /// Build a `USN_RECORD_V2` with 8-byte aligned `RecordLength` (as Windows produces).
    fn build_aligned_v2_record(file_ref: u64, parent_ref: u64, attributes: u32, name: &str) -> Vec<u8> {
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
    fn build_aligned_v3_record(file_ref: u64, parent_ref: u64, attributes: u32, name: &str) -> Vec<u8> {
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
        data[68..72].copy_from_slice(&attributes.to_le_bytes());
        data[72..74].copy_from_slice(&(name_bytes_len as u16).to_le_bytes());
        data[74..76].copy_from_slice(&file_name_offset.to_le_bytes());
        for (index, code_unit) in name_utf16.iter().enumerate() {
            let offset = file_name_offset as usize + index * 2;
            data[offset..offset + 2].copy_from_slice(&code_unit.to_le_bytes());
        }

        data
    }

    /// Assemble a complete MFT enumeration output buffer.
    ///
    /// Matches the `FSCTL_ENUM_USN_DATA` output layout:
    /// `[0..8]` next file reference (u64 LE) followed by packed records.
    fn build_mft_enum_buffer(next_ref: u64, records: &[Vec<u8>]) -> Vec<u8> {
        let total: usize = 8 + records.iter().map(Vec::len).sum::<usize>();
        let mut buffer = Vec::with_capacity(total);
        buffer.extend_from_slice(&next_ref.to_le_bytes());
        for record in records {
            buffer.extend_from_slice(record);
        }
        buffer
    }

    /// Create a test `MftEntry` with common defaults.
    fn make_entry(file_ref: u64, parent_ref: u64, name: &str, is_directory: bool) -> MftEntry {
        MftEntry {
            file_reference: file_ref,
            parent_reference: parent_ref,
            name: String::from(name),
            attributes: if is_directory { FILE_ATTRIBUTE_DIRECTORY } else { 0x20 },
            size: 0,
            is_directory,
        }
    }

    // ── Live system tests (require Windows / admin) ─────────────────────

    #[test]
    #[cfg(windows)]
    fn test_detect_ntfs_volumes() {
        let volumes = detect_ntfs_volumes();
        // Most Windows systems have at least C: as NTFS
        assert!(!volumes.is_empty(), "Should detect at least one NTFS volume");
        assert!(volumes.contains(&'C'), "C: drive should be NTFS");
    }

    #[test]
    #[cfg(not(windows))]
    fn test_detect_ntfs_volumes_non_windows() {
        let volumes = detect_ntfs_volumes();
        assert!(volumes.is_empty());
    }

    // ── V2 record parsing ───────────────────────────────────────────────

    #[test]
    fn test_parse_mft_v2_file() {
        let data = build_mft_v2_record(42, 5, 0x20, "report.docx");
        let entry = MftScanner::parse_usn_record(&data).expect("should parse V2 file record");

        assert_eq!(entry.name, "report.docx");
        assert_eq!(entry.file_reference, 42);
        assert_eq!(entry.parent_reference, 5);
        assert!(!entry.is_directory);
        assert_eq!(entry.size, 0);
    }

    #[test]
    fn test_parse_mft_v2_directory() {
        let data = build_mft_v2_record(99, 5, FILE_ATTRIBUTE_DIRECTORY, "Documents");
        let entry = MftScanner::parse_usn_record(&data).expect("should parse V2 directory record");

        assert_eq!(entry.name, "Documents");
        assert!(entry.is_directory);
        assert_eq!(entry.file_reference, 99);
    }

    #[test]
    fn test_parse_mft_v2_unicode_name() {
        let data = build_mft_v2_record(50, 10, 0x20, "日本語ファイル.txt");
        let entry = MftScanner::parse_usn_record(&data).expect("should parse V2 unicode name");

        assert_eq!(entry.name, "日本語ファイル.txt");
    }

    #[test]
    fn test_parse_mft_v2_long_name() {
        let long_name = "a".repeat(255);
        let data = build_mft_v2_record(60, 5, 0x20, &long_name);
        let entry = MftScanner::parse_usn_record(&data).expect("should parse V2 long name");

        assert_eq!(entry.name, long_name);
    }

    #[test]
    fn test_parse_mft_v2_empty_name() {
        let data = build_mft_v2_record(70, 5, 0x20, "");
        let entry = MftScanner::parse_usn_record(&data).expect("should parse V2 empty name");

        assert_eq!(entry.name, "");
    }

    #[test]
    fn test_parse_mft_v2_reference_mask() {
        // File references are masked to 48 bits (lower 6 bytes).
        let full_ref: u64 = 0xABCD_0000_1234_5678;
        let expected_ref: u64 = 0x0000_0000_1234_5678;

        let data = build_mft_v2_record(full_ref, full_ref, 0x20, "masked.txt");
        let entry = MftScanner::parse_usn_record(&data).expect("should parse V2 with masked refs");

        assert_eq!(entry.file_reference, expected_ref);
        assert_eq!(entry.parent_reference, expected_ref);
    }

    #[test]
    fn test_parse_mft_v2_truncated_name() {
        let mut data = build_mft_v2_record(42, 5, 0x20, "hello.txt");
        // Truncate so the filename extends beyond the buffer
        data.truncate(64);

        let result = MftScanner::parse_usn_record(&data);
        assert!(result.is_none(), "should return None for truncated name data");
    }

    #[test]
    fn test_parse_mft_v2_directory_combined_attributes() {
        // Directory attribute combined with other attributes (e.g., hidden)
        let attrs = FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_HIDDEN;
        let data = build_mft_v2_record(80, 5, attrs, "HiddenDir");
        let entry = MftScanner::parse_usn_record(&data).expect("should parse combined attrs");

        assert!(entry.is_directory);
        assert_eq!(entry.attributes, attrs);
    }

    // ── V3 record parsing ───────────────────────────────────────────────

    #[test]
    fn test_parse_mft_v3_file() {
        let data = build_mft_v3_record(42, 5, 0x20, "image.png");
        let entry = MftScanner::parse_usn_record(&data).expect("should parse V3 file record");

        assert_eq!(entry.name, "image.png");
        assert_eq!(entry.file_reference, 42);
        assert_eq!(entry.parent_reference, 5);
        assert!(!entry.is_directory);
    }

    #[test]
    fn test_parse_mft_v3_directory() {
        let data = build_mft_v3_record(88, 5, FILE_ATTRIBUTE_DIRECTORY, "Projects");
        let entry = MftScanner::parse_usn_record(&data).expect("should parse V3 directory");

        assert_eq!(entry.name, "Projects");
        assert!(entry.is_directory);
    }

    #[test]
    fn test_parse_mft_v3_unicode_name() {
        let data = build_mft_v3_record(55, 10, 0x20, "données_résumé.pdf");
        let entry = MftScanner::parse_usn_record(&data).expect("should parse V3 unicode name");

        assert_eq!(entry.name, "données_résumé.pdf");
    }

    #[test]
    fn test_parse_mft_v3_reference_mask() {
        let full_ref: u64 = 0xFF00_0000_DEAD_BEEF;
        let expected_ref: u64 = 0x0000_0000_DEAD_BEEF;

        let data = build_mft_v3_record(full_ref, full_ref, 0x20, "v3mask.bin");
        let entry = MftScanner::parse_usn_record(&data).expect("should parse V3 with masked refs");

        assert_eq!(entry.file_reference, expected_ref);
        assert_eq!(entry.parent_reference, expected_ref);
    }

    #[test]
    fn test_parse_mft_v3_truncated_name() {
        let mut data = build_mft_v3_record(42, 5, 0x20, "hello.txt");
        data.truncate(80);

        let result = MftScanner::parse_usn_record(&data);
        assert!(result.is_none(), "should return None for truncated V3 name data");
    }

    // ── Version dispatch & edge cases ───────────────────────────────────

    #[test]
    fn test_parse_mft_record_dispatches_v2() {
        let data = build_mft_v2_record(1, 2, 0x20, "v2file.txt");
        let entry = MftScanner::parse_usn_record(&data).expect("should dispatch to V2 parser");
        assert_eq!(entry.name, "v2file.txt");
    }

    #[test]
    fn test_parse_mft_record_dispatches_v3() {
        let data = build_mft_v3_record(1, 2, 0x20, "v3file.txt");
        let entry = MftScanner::parse_usn_record(&data).expect("should dispatch to V3 parser");
        assert_eq!(entry.name, "v3file.txt");
    }

    #[test]
    fn test_parse_mft_record_unknown_version() {
        let mut data = build_mft_v2_record(1, 2, 0x20, "unknown.txt");
        // Set major version to 99
        data[4..6].copy_from_slice(&99u16.to_le_bytes());

        let result = MftScanner::parse_usn_record(&data);
        assert!(result.is_none(), "should return None for unknown version");
    }

    #[test]
    fn test_parse_mft_record_too_short() {
        let data = vec![0u8; 30];
        let result = MftScanner::parse_usn_record(&data);
        assert!(result.is_none(), "should return None for data shorter than 60 bytes");
    }

    #[test]
    fn test_parse_mft_record_exactly_minimum_v2() {
        let data = build_mft_v2_record(1, 2, 0, "");
        assert_eq!(data.len(), 60);

        let entry = MftScanner::parse_usn_record(&data).expect("should parse minimal V2 record");
        assert_eq!(entry.name, "");
    }

    #[test]
    fn test_parse_mft_v3_too_short_for_v3() {
        // 60 bytes is enough for V2 but V3 needs 76 minimum
        let mut data = vec![0u8; 60];
        data[4..6].copy_from_slice(&3u16.to_le_bytes());

        let result = MftScanner::parse_usn_record(&data);
        assert!(result.is_none(), "should return None for V3 data shorter than 76 bytes");
    }

    #[test]
    fn test_parse_mft_v2_size_always_zero() {
        // MFT entries parsed from USN records always have size 0;
        // actual size is resolved later via `get_file_size`.
        let data = build_mft_v2_record(42, 5, 0x20, "file.txt");
        let entry = MftScanner::parse_usn_record(&data).expect("should parse");
        assert_eq!(entry.size, 0);
    }

    // ── Path resolution (build_full_path) ───────────────────────────────

    #[test]
    fn test_build_full_path_root_file() {
        let scanner = make_test_scanner('C');
        let entry = make_entry(100, 5, "boot.ini", false);

        let mut ref_map: HashMap<u64, &MftEntry> = HashMap::new();
        ref_map.insert(100, &entry);

        let path = scanner.build_full_path(&entry, &ref_map, 5);
        assert_eq!(path, "C:\\boot.ini");
    }

    #[test]
    fn test_build_full_path_one_level() {
        let scanner = make_test_scanner('D');
        let dir = make_entry(30, 5, "Users", true);
        let file = make_entry(100, 30, "readme.txt", false);

        let mut ref_map: HashMap<u64, &MftEntry> = HashMap::new();
        ref_map.insert(30, &dir);
        ref_map.insert(100, &file);

        let path = scanner.build_full_path(&file, &ref_map, 5);
        assert_eq!(path, "D:\\Users\\readme.txt");
    }

    #[test]
    fn test_build_full_path_nested() {
        let scanner = make_test_scanner('C');
        let users = make_entry(30, 5, "Users", true);
        let john = make_entry(40, 30, "John", true);
        let docs = make_entry(50, 40, "Documents", true);
        let file = make_entry(100, 50, "report.pdf", false);

        let mut ref_map: HashMap<u64, &MftEntry> = HashMap::new();
        ref_map.insert(30, &users);
        ref_map.insert(40, &john);
        ref_map.insert(50, &docs);
        ref_map.insert(100, &file);

        let path = scanner.build_full_path(&file, &ref_map, 5);
        assert_eq!(path, "C:\\Users\\John\\Documents\\report.pdf");
    }

    #[test]
    fn test_build_full_path_deeply_nested() {
        let scanner = make_test_scanner('E');

        let mut entries: Vec<MftEntry> = Vec::new();
        // Build a chain: root(5) -> dir_1(10) -> dir_2(11) -> ... -> dir_10(19) -> file(100)
        for index in 0..10 {
            let file_ref = 10 + index as u64;
            let parent_ref = if index == 0 { 5 } else { 10 + (index - 1) as u64 };
            entries.push(make_entry(file_ref, parent_ref, &format!("level_{index}"), true));
        }
        let file = make_entry(100, 19, "deep_file.txt", false);
        entries.push(file);

        let mut ref_map: HashMap<u64, &MftEntry> = HashMap::new();
        for entry in &entries {
            ref_map.insert(entry.file_reference, entry);
        }

        let target = ref_map.get(&100).expect("file should exist");
        let path = scanner.build_full_path(target, &ref_map, 5);

        assert!(path.starts_with("E:\\level_0\\"));
        assert!(path.ends_with("\\deep_file.txt"));
        // Should contain all 10 directory levels
        for index in 0..10 {
            assert!(
                path.contains(&format!("level_{index}")),
                "path should contain level_{index}: {path}"
            );
        }
    }

    #[test]
    fn test_build_full_path_orphaned_entry() {
        // Entry whose parent is not in the ref_map — stops walking
        let scanner = make_test_scanner('C');
        let file = make_entry(100, 999, "orphan.txt", false);

        let mut ref_map: HashMap<u64, &MftEntry> = HashMap::new();
        ref_map.insert(100, &file);

        let path = scanner.build_full_path(&file, &ref_map, 5);
        // Can't resolve parent 999, so just the drive + filename
        assert_eq!(path, "C:\\orphan.txt");
    }

    #[test]
    fn test_build_full_path_different_drive_letters() {
        for drive in ['A', 'C', 'D', 'Z'] {
            let scanner = make_test_scanner(drive);
            let entry = make_entry(100, 5, "file.txt", false);

            let mut ref_map: HashMap<u64, &MftEntry> = HashMap::new();
            ref_map.insert(100, &entry);

            let path = scanner.build_full_path(&entry, &ref_map, 5);
            assert!(
                path.starts_with(&format!("{drive}:\\")),
                "path should start with {drive}:\\ but got: {path}"
            );
        }
    }

    #[test]
    fn test_build_full_path_directory_entry() {
        let scanner = make_test_scanner('C');
        let parent = make_entry(30, 5, "Windows", true);
        let child = make_entry(40, 30, "System32", true);

        let mut ref_map: HashMap<u64, &MftEntry> = HashMap::new();
        ref_map.insert(30, &parent);
        ref_map.insert(40, &child);

        let path = scanner.build_full_path(&child, &ref_map, 5);
        assert_eq!(path, "C:\\Windows\\System32");
    }

    #[test]
    fn test_build_full_path_skips_empty_parent_names() {
        let scanner = make_test_scanner('C');
        // Parent with an empty name should be skipped in path construction
        let empty_parent = make_entry(30, 5, "", true);
        let file = make_entry(100, 30, "file.txt", false);

        let mut ref_map: HashMap<u64, &MftEntry> = HashMap::new();
        ref_map.insert(30, &empty_parent);
        ref_map.insert(100, &file);

        let path = scanner.build_full_path(&file, &ref_map, 5);
        assert_eq!(path, "C:\\file.txt");
    }

    // ── IGNORED_PATH_PATTERNS ───────────────────────────────────────────

    #[test]
    fn test_ignored_path_patterns_recycle_bin() {
        let path = "C:\\$Recycle.Bin\\S-1-5-21\\file.txt";
        let matches_ignored = IGNORED_PATH_PATTERNS.iter().any(|pattern| path.contains(pattern));
        assert!(matches_ignored, "$Recycle.Bin paths should be ignored");
    }

    #[test]
    fn test_ignored_path_patterns_nas_recycle() {
        let path = "Z:\\#Recycle\\old_file.doc";
        let matches_ignored = IGNORED_PATH_PATTERNS.iter().any(|pattern| path.contains(pattern));
        assert!(matches_ignored, "#Recycle paths should be ignored");
    }

    #[test]
    fn test_ignored_path_patterns_normal_path() {
        let path = "C:\\Users\\John\\Documents\\report.pdf";
        let matches_ignored = IGNORED_PATH_PATTERNS.iter().any(|pattern| path.contains(pattern));
        assert!(!matches_ignored, "normal paths should not be ignored");
    }

    #[test]
    fn test_ignored_path_patterns_partial_match() {
        // "$Recycle" should match "$Recycle.Bin" via substring
        let path = "D:\\$Recycle.Bin\\info.dat";
        let matches_ignored = IGNORED_PATH_PATTERNS.iter().any(|pattern| path.contains(pattern));
        assert!(matches_ignored);
    }

    // ── MftEntry struct ─────────────────────────────────────────────────

    #[test]
    fn test_mft_entry_clone_and_debug() {
        let entry = make_entry(42, 5, "test.txt", false);
        let cloned = entry.clone();
        assert_eq!(cloned.name, entry.name);
        assert_eq!(cloned.file_reference, entry.file_reference);
        assert_eq!(cloned.parent_reference, entry.parent_reference);
        assert_eq!(cloned.is_directory, entry.is_directory);

        // Verify Debug impl doesn't panic
        let debug_str = format!("{entry:?}");
        assert!(debug_str.contains("test.txt"));
    }

    #[test]
    fn test_mft_entry_file_attributes_preserved() {
        let data = build_mft_v2_record(42, 5, 0x2022, "attrs.txt");
        let entry = MftScanner::parse_usn_record(&data).expect("should parse");
        assert_eq!(entry.attributes, 0x2022);
    }

    // ── Round-trip: build record → parse → build path ───────────────────

    #[test]
    fn test_roundtrip_v2_parse_and_path() {
        let scanner = make_test_scanner('C');

        // Parse parent directory from V2 record
        let dir_data = build_mft_v2_record(30, 5, FILE_ATTRIBUTE_DIRECTORY, "Users");
        let dir_entry = MftScanner::parse_usn_record(&dir_data).expect("should parse dir");

        // Parse file from V2 record
        let file_data = build_mft_v2_record(100, 30, 0x20, "photo.jpg");
        let file_entry = MftScanner::parse_usn_record(&file_data).expect("should parse file");

        let mut ref_map: HashMap<u64, &MftEntry> = HashMap::new();
        ref_map.insert(dir_entry.file_reference, &dir_entry);
        ref_map.insert(file_entry.file_reference, &file_entry);

        let path = scanner.build_full_path(&file_entry, &ref_map, 5);
        assert_eq!(path, "C:\\Users\\photo.jpg");
    }

    #[test]
    fn test_roundtrip_v3_parse_and_path() {
        let scanner = make_test_scanner('D');

        let dir_data = build_mft_v3_record(25, 5, FILE_ATTRIBUTE_DIRECTORY, "Projects");
        let dir_entry = MftScanner::parse_usn_record(&dir_data).expect("should parse V3 dir");

        let subdir_data = build_mft_v3_record(26, 25, FILE_ATTRIBUTE_DIRECTORY, "rust");
        let subdir_entry = MftScanner::parse_usn_record(&subdir_data).expect("should parse V3 subdir");

        let file_data = build_mft_v3_record(200, 26, 0x20, "main.rs");
        let file_entry = MftScanner::parse_usn_record(&file_data).expect("should parse V3 file");

        let mut ref_map: HashMap<u64, &MftEntry> = HashMap::new();
        ref_map.insert(dir_entry.file_reference, &dir_entry);
        ref_map.insert(subdir_entry.file_reference, &subdir_entry);
        ref_map.insert(file_entry.file_reference, &file_entry);

        let path = scanner.build_full_path(&file_entry, &ref_map, 5);
        assert_eq!(path, "D:\\Projects\\rust\\main.rs");
    }

    #[test]
    fn test_roundtrip_mixed_v2_v3_records() {
        let scanner = make_test_scanner('C');

        // Parse a V2 directory and a V3 file — both should work together
        let dir_data = build_mft_v2_record(30, 5, FILE_ATTRIBUTE_DIRECTORY, "MixedDir");
        let dir_entry = MftScanner::parse_usn_record(&dir_data).expect("should parse V2 dir");

        let file_data = build_mft_v3_record(200, 30, 0x20, "mixed_file.dat");
        let file_entry = MftScanner::parse_usn_record(&file_data).expect("should parse V3 file");

        let mut ref_map: HashMap<u64, &MftEntry> = HashMap::new();
        ref_map.insert(dir_entry.file_reference, &dir_entry);
        ref_map.insert(file_entry.file_reference, &file_entry);

        let path = scanner.build_full_path(&file_entry, &ref_map, 5);
        assert_eq!(path, "C:\\MixedDir\\mixed_file.dat");
    }

    // ── Realistic golden data ───────────────────────────────────────────
    //
    // Hand-crafted byte arrays that match the exact binary layout Windows
    // produces via FSCTL_ENUM_USN_DATA, verified against the Microsoft
    // USN_RECORD_V2 / V3 documentation.
    // https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2

    #[test]
    fn test_golden_mft_v2_file_entry() {
        // USN_RECORD_V2 for "report.pdf" as returned by FSCTL_ENUM_USN_DATA.
        //
        //   FileReferenceNumber  = 0x0002_0000_0000_1A2B (seq=2, ref=0x1A2B)
        //   ParentFileReference  = 0x0001_0000_0000_001F (seq=1, ref=31)
        //   FileAttributes       = ARCHIVE (0x20)
        //   FileName             = "report.pdf" (10 wchars = 20 bytes)
        //   RecordLength         = 80 (60 + 20 = 80, already 8-aligned)
        #[rustfmt::skip]
        let record: [u8; 80] = [
            // 0x00  RecordLength = 80
            0x50, 0x00, 0x00, 0x00,
            // 0x04  MajorVersion = 2, MinorVersion = 0
            0x02, 0x00, 0x00, 0x00,
            // 0x08  FileReferenceNumber
            0x2B, 0x1A, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
            // 0x10  ParentFileReferenceNumber
            0x1F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            // 0x18  Usn (not used for MFT enum, but present in record)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // 0x20  TimeStamp
            0x00, 0x50, 0x7C, 0xA6, 0x9A, 0x5E, 0xDA, 0x01,
            // 0x28  Reason (not meaningful for MFT enum)
            0x00, 0x00, 0x00, 0x00,
            // 0x2C  SourceInfo
            0x00, 0x00, 0x00, 0x00,
            // 0x30  SecurityId = 256
            0x00, 0x01, 0x00, 0x00,
            // 0x34  FileAttributes = ARCHIVE
            0x20, 0x00, 0x00, 0x00,
            // 0x38  FileNameLength = 20
            0x14, 0x00,
            // 0x3A  FileNameOffset = 60
            0x3C, 0x00,
            // 0x3C  FileName "report.pdf" UTF-16LE
            0x72, 0x00,  // r
            0x65, 0x00,  // e
            0x70, 0x00,  // p
            0x6F, 0x00,  // o
            0x72, 0x00,  // r
            0x74, 0x00,  // t
            0x2E, 0x00,  // .
            0x70, 0x00,  // p
            0x64, 0x00,  // d
            0x66, 0x00,  // f
        ];

        let entry = MftScanner::parse_usn_record(&record).expect("golden V2 MFT record should parse");

        assert_eq!(entry.name, "report.pdf");
        // Upper 16 bits (sequence number) must be masked off
        assert_eq!(entry.file_reference, 0x1A2B);
        assert_eq!(entry.parent_reference, 0x1F);
        assert!(!entry.is_directory);
        assert_eq!(entry.attributes, 0x20);
        assert_eq!(entry.size, 0, "MFT enum records always have size 0");
    }

    #[test]
    fn test_golden_mft_v2_directory_entry() {
        // "Windows" directory with DIRECTORY | NOT_CONTENT_INDEXED (0x8010).
        //
        //   FileReferenceNumber  = 0x0001_0000_0000_0028 (seq=1, ref=40)
        //   ParentFileReference  = 0x0001_0000_0000_0005 (seq=1, ref=5 = root)
        //   FileAttributes       = DIRECTORY | NOT_CONTENT_INDEXED (0x8010)
        //   FileName             = "Windows" (7 wchars = 14 bytes)
        //   RecordLength         = 80 (60 + 14 = 74, aligned to 80)
        #[rustfmt::skip]
        let record: [u8; 80] = [
            // RecordLength = 80
            0x50, 0x00, 0x00, 0x00,
            // MajorVersion = 2
            0x02, 0x00, 0x00, 0x00,
            // FileReferenceNumber (ref=40, seq=1)
            0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            // ParentFileReferenceNumber (ref=5, seq=1)
            0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            // Usn
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // TimeStamp
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // Reason
            0x00, 0x00, 0x00, 0x00,
            // SourceInfo
            0x00, 0x00, 0x00, 0x00,
            // SecurityId
            0x00, 0x00, 0x00, 0x00,
            // FileAttributes = DIRECTORY | NOT_CONTENT_INDEXED
            0x10, 0x80, 0x00, 0x00,
            // FileNameLength = 14
            0x0E, 0x00,
            // FileNameOffset = 60
            0x3C, 0x00,
            // FileName "Windows" UTF-16LE
            0x57, 0x00,  // W
            0x69, 0x00,  // i
            0x6E, 0x00,  // n
            0x64, 0x00,  // d
            0x6F, 0x00,  // o
            0x77, 0x00,  // w
            0x73, 0x00,  // s
            // Alignment padding (60 + 14 = 74, pad to 80)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let entry = MftScanner::parse_usn_record(&record).expect("golden V2 directory record should parse");

        assert_eq!(entry.name, "Windows");
        assert_eq!(entry.file_reference, 0x28);
        assert_eq!(entry.parent_reference, 5);
        assert!(entry.is_directory);
        assert_eq!(entry.attributes, 0x8010);
    }

    #[test]
    fn test_golden_mft_v3_file_entry() {
        // USN_RECORD_V3 for "ntuser.dat" with 128-bit references.
        //
        //   FileReferenceNumber  = 128-bit, lower 0x0005_0000_0000_3456
        //   ParentFileReference  = 128-bit, lower 0x0002_0000_0000_001A
        //   FileAttributes       = HIDDEN | SYSTEM | ARCHIVE (0x26)
        //   FileName             = "ntuser.dat" (10 wchars = 20 bytes)
        //   RecordLength         = 96 (76 + 20 = 96, already 8-aligned)
        #[rustfmt::skip]
        let record: [u8; 96] = [
            // 0x00  RecordLength = 96
            0x60, 0x00, 0x00, 0x00,
            // 0x04  MajorVersion = 3, MinorVersion = 0
            0x03, 0x00, 0x00, 0x00,
            // 0x08  FileReferenceNumber (128-bit LE)
            0x56, 0x34, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // 0x18  ParentFileReferenceNumber (128-bit LE)
            0x1A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // 0x28  Usn
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // 0x30  TimeStamp
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // 0x38  Reason
            0x00, 0x00, 0x00, 0x00,
            // 0x3C  SourceInfo
            0x00, 0x00, 0x00, 0x00,
            // 0x40  SecurityId
            0x00, 0x00, 0x00, 0x00,
            // 0x44  FileAttributes = HIDDEN | SYSTEM | ARCHIVE
            0x26, 0x00, 0x00, 0x00,
            // 0x48  FileNameLength = 20
            0x14, 0x00,
            // 0x4A  FileNameOffset = 76
            0x4C, 0x00,
            // 0x4C  FileName "ntuser.dat" UTF-16LE
            0x6E, 0x00,  // n
            0x74, 0x00,  // t
            0x75, 0x00,  // u
            0x73, 0x00,  // s
            0x65, 0x00,  // e
            0x72, 0x00,  // r
            0x2E, 0x00,  // .
            0x64, 0x00,  // d
            0x61, 0x00,  // a
            0x74, 0x00,  // t
        ];

        let entry = MftScanner::parse_usn_record(&record).expect("golden V3 MFT record should parse");

        assert_eq!(entry.name, "ntuser.dat");
        // Upper 16 bits (seq) masked off: 0x0005_0000_0000_3456 -> 0x0000_0000_0000_3456
        assert_eq!(entry.file_reference, 0x3456);
        assert_eq!(entry.parent_reference, 0x1A);
        assert!(!entry.is_directory);
        assert_eq!(entry.attributes, 0x26);
    }

    // ── Multi-record buffer parsing (parse_mft_buffer) ──────────────────

    #[test]
    fn test_parse_mft_buffer_empty() {
        let buffer = 9999u64.to_le_bytes().to_vec();
        let (entries, next_ref) = MftScanner::parse_mft_buffer(&buffer, buffer.len());

        assert!(entries.is_empty());
        assert_eq!(next_ref, 9999);
    }

    #[test]
    fn test_parse_mft_buffer_too_small() {
        let buffer = vec![0u8; 4]; // Less than 8 bytes
        let (entries, next_ref) = MftScanner::parse_mft_buffer(&buffer, buffer.len());

        assert!(entries.is_empty());
        assert_eq!(next_ref, 0);
    }

    #[test]
    fn test_parse_mft_buffer_single_entry() {
        let record = build_aligned_v2_record(100, 5, 0x20, "single.txt");
        let buffer = build_mft_enum_buffer(200, &[record]);

        let (entries, next_ref) = MftScanner::parse_mft_buffer(&buffer, buffer.len());

        assert_eq!(next_ref, 200);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "single.txt");
        assert_eq!(entries[0].file_reference, 100);
    }

    #[test]
    fn test_parse_mft_buffer_filters_system_entries() {
        // MFT entries 0-23 are reserved NTFS system files ($MFT, $MFTMirr, etc.)
        // and should be filtered out.
        let system_entry = build_aligned_v2_record(10, 5, 0x20, "$MFT");
        let user_entry = build_aligned_v2_record(100, 5, 0x20, "user_file.txt");
        let buffer = build_mft_enum_buffer(200, &[system_entry, user_entry]);

        let (entries, _) = MftScanner::parse_mft_buffer(&buffer, buffer.len());

        assert_eq!(entries.len(), 1, "system entry (ref < 24) should be filtered");
        assert_eq!(entries[0].name, "user_file.txt");
    }

    #[test]
    fn test_parse_mft_buffer_filters_empty_names() {
        let empty_name = build_aligned_v2_record(100, 5, 0x20, "");
        let valid_entry = build_aligned_v2_record(200, 5, 0x20, "valid.txt");
        let buffer = build_mft_enum_buffer(300, &[empty_name, valid_entry]);

        let (entries, _) = MftScanner::parse_mft_buffer(&buffer, buffer.len());

        assert_eq!(entries.len(), 1, "entry with empty name should be filtered");
        assert_eq!(entries[0].name, "valid.txt");
    }

    #[test]
    fn test_parse_mft_buffer_entry_at_boundary_ref_24() {
        // Reference 24 is the first non-system entry (boundary case)
        let boundary = build_aligned_v2_record(24, 5, 0x20, "boundary.txt");
        let below = build_aligned_v2_record(23, 5, 0x20, "system.txt");
        let buffer = build_mft_enum_buffer(100, &[below, boundary]);

        let (entries, _) = MftScanner::parse_mft_buffer(&buffer, buffer.len());

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "boundary.txt");
        assert_eq!(entries[0].file_reference, 24);
    }

    #[test]
    fn test_parse_mft_buffer_realistic_directory_tree() {
        // Simulate a realistic MFT enumeration buffer for a small tree:
        //   C:\
        //   ├── Users\          (ref=30, parent=5)
        //   │   └── John\       (ref=31, parent=30)
        //   │       └── Documents\  (ref=32, parent=31)
        //   │           ├── report.pdf   (ref=1000, parent=32)
        //   │           └── photo.jpg    (ref=1001, parent=32)
        //   └── Windows\        (ref=40, parent=5)
        //       └── System32\   (ref=41, parent=40)
        let records = vec![
            build_aligned_v2_record(30, 5, FILE_ATTRIBUTE_DIRECTORY, "Users"),
            build_aligned_v2_record(31, 30, FILE_ATTRIBUTE_DIRECTORY, "John"),
            build_aligned_v2_record(32, 31, FILE_ATTRIBUTE_DIRECTORY, "Documents"),
            build_aligned_v2_record(1000, 32, 0x20, "report.pdf"),
            build_aligned_v2_record(1001, 32, 0x20, "photo.jpg"),
            build_aligned_v2_record(40, 5, FILE_ATTRIBUTE_DIRECTORY, "Windows"),
            build_aligned_v2_record(41, 40, FILE_ATTRIBUTE_DIRECTORY, "System32"),
        ];
        let buffer = build_mft_enum_buffer(2000, &records);

        let (entries, next_ref) = MftScanner::parse_mft_buffer(&buffer, buffer.len());

        assert_eq!(next_ref, 2000);
        assert_eq!(entries.len(), 7);

        // Verify we can build correct paths from parsed entries
        let scanner = make_test_scanner('C');
        let mut ref_map: HashMap<u64, &MftEntry> = HashMap::new();
        for entry in &entries {
            ref_map.insert(entry.file_reference, entry);
        }

        let report = entries.iter().find(|e| e.name == "report.pdf").expect("report.pdf");
        let path = scanner.build_full_path(report, &ref_map, 5);
        assert_eq!(path, "C:\\Users\\John\\Documents\\report.pdf");

        let photo = entries.iter().find(|e| e.name == "photo.jpg").expect("photo.jpg");
        let path = scanner.build_full_path(photo, &ref_map, 5);
        assert_eq!(path, "C:\\Users\\John\\Documents\\photo.jpg");

        let system32 = entries.iter().find(|e| e.name == "System32").expect("System32");
        let path = scanner.build_full_path(system32, &ref_map, 5);
        assert_eq!(path, "C:\\Windows\\System32");
    }

    #[test]
    fn test_parse_mft_buffer_mixed_v2_v3() {
        let v2_record = build_aligned_v2_record(100, 5, FILE_ATTRIBUTE_DIRECTORY, "DirV2");
        let v3_record = build_aligned_v3_record(200, 100, 0x20, "file_v3.txt");
        let buffer = build_mft_enum_buffer(300, &[v2_record, v3_record]);

        let (entries, next_ref) = MftScanner::parse_mft_buffer(&buffer, buffer.len());

        assert_eq!(next_ref, 300);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "DirV2");
        assert!(entries[0].is_directory);
        assert_eq!(entries[1].name, "file_v3.txt");
        assert!(!entries[1].is_directory);

        // Verify path resolution works across V2/V3 records
        let scanner = make_test_scanner('D');
        let mut ref_map: HashMap<u64, &MftEntry> = HashMap::new();
        for entry in &entries {
            ref_map.insert(entry.file_reference, entry);
        }
        let path = scanner.build_full_path(&entries[1], &ref_map, 5);
        assert_eq!(path, "D:\\DirV2\\file_v3.txt");
    }

    #[test]
    fn test_parse_mft_buffer_bytes_returned_less_than_buffer() {
        // Simulate bytes_returned being smaller than buffer.len(),
        // only the first record should be visible.
        let record1 = build_aligned_v2_record(100, 5, 0x20, "visible.txt");
        let record2 = build_aligned_v2_record(200, 5, 0x20, "invisible.txt");
        let buffer = build_mft_enum_buffer(300, &[record1.clone(), record2]);

        let bytes_returned = 8 + record1.len();
        let (entries, _) = MftScanner::parse_mft_buffer(&buffer, bytes_returned);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "visible.txt");
    }

    #[test]
    fn test_parse_mft_buffer_truncated_last_record() {
        let record = build_aligned_v2_record(100, 5, 0x20, "complete.txt");
        let buffer = build_mft_enum_buffer(200, &[record.clone()]);

        // Lie about bytes_returned — cut the record short
        let truncated_len = 8 + record.len() - 4;
        let (entries, _) = MftScanner::parse_mft_buffer(&buffer, truncated_len);

        assert!(entries.is_empty(), "truncated record should be skipped");
    }

    #[test]
    fn test_parse_mft_buffer_zero_record_length_stops() {
        // RecordLength = 0 must stop the walker to prevent infinite loops
        let mut buffer = vec![0u8; 80];
        buffer[0..8].copy_from_slice(&42u64.to_le_bytes());
        // Record at offset 8 has RecordLength = 0 (all zeros)

        let (entries, next_ref) = MftScanner::parse_mft_buffer(&buffer, buffer.len());

        assert_eq!(next_ref, 42);
        assert!(entries.is_empty());
    }

    // ── End-to-end: golden buffer → parse → resolve paths ───────────────

    #[test]
    fn test_golden_buffer_to_resolved_paths() {
        // Build a complete FSCTL_ENUM_USN_DATA output buffer using
        // golden hand-verified V2 records, parse it, then resolve paths.
        //
        // Simulated tree on E:\
        //   E:\
        //   ├── Projects\        (ref=50, parent=5)
        //   │   ├── rust\        (ref=60, parent=50)
        //   │   │   └── main.rs  (ref=500, parent=60)
        //   │   └── go\          (ref=61, parent=50)
        //   │       └── main.go  (ref=501, parent=61)
        //   └── README.md        (ref=100, parent=5)

        // Hand-build aligned records using realistic reference numbers
        // with sequence numbers in the upper 16 bits.
        let records = vec![
            build_aligned_v2_record(
                0x0001_0000_0000_0032,
                0x0001_0000_0000_0005,
                FILE_ATTRIBUTE_DIRECTORY,
                "Projects",
            ),
            build_aligned_v2_record(
                0x0001_0000_0000_003C,
                0x0001_0000_0000_0032,
                FILE_ATTRIBUTE_DIRECTORY,
                "rust",
            ),
            build_aligned_v2_record(
                0x0001_0000_0000_003D,
                0x0001_0000_0000_0032,
                FILE_ATTRIBUTE_DIRECTORY,
                "go",
            ),
            build_aligned_v2_record(0x0002_0000_0000_01F4, 0x0001_0000_0000_003C, 0x20, "main.rs"),
            build_aligned_v2_record(0x0003_0000_0000_01F5, 0x0001_0000_0000_003D, 0x20, "main.go"),
            build_aligned_v2_record(0x0001_0000_0000_0064, 0x0001_0000_0000_0005, 0x20, "README.md"),
        ];

        let buffer = build_mft_enum_buffer(0x0000_0000_0000_1000, &records);
        let (entries, next_ref) = MftScanner::parse_mft_buffer(&buffer, buffer.len());

        assert_eq!(next_ref, 0x1000);
        assert_eq!(entries.len(), 6);

        // Resolve full paths
        let scanner = make_test_scanner('E');
        let mut ref_map: HashMap<u64, &MftEntry> = HashMap::new();
        for entry in &entries {
            ref_map.insert(entry.file_reference, entry);
        }

        // Verify sequence numbers were masked off correctly
        let projects = entries.iter().find(|e| e.name == "Projects").expect("Projects");
        assert_eq!(projects.file_reference, 0x32);
        assert_eq!(projects.parent_reference, 5);

        let main_rs = entries.iter().find(|e| e.name == "main.rs").expect("main.rs");
        assert_eq!(main_rs.file_reference, 0x01F4);
        assert_eq!(main_rs.parent_reference, 0x3C);

        // Build and verify full paths
        let path = scanner.build_full_path(main_rs, &ref_map, 5);
        assert_eq!(path, "E:\\Projects\\rust\\main.rs");

        let main_go = entries.iter().find(|e| e.name == "main.go").expect("main.go");
        let path = scanner.build_full_path(main_go, &ref_map, 5);
        assert_eq!(path, "E:\\Projects\\go\\main.go");

        let readme = entries.iter().find(|e| e.name == "README.md").expect("README.md");
        let path = scanner.build_full_path(readme, &ref_map, 5);
        assert_eq!(path, "E:\\README.md");
    }

    #[test]
    fn test_golden_buffer_ignored_paths_filtered() {
        // After parsing, entries under $Recycle.Bin should be excluded by
        // the IGNORED_PATH_PATTERNS filter (applied in scan_filtered).
        let scanner = make_test_scanner('C');

        let records = vec![
            build_aligned_v2_record(30, 5, FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_HIDDEN, "$Recycle.Bin"),
            build_aligned_v2_record(100, 30, 0x20, "deleted_file.txt"),
            build_aligned_v2_record(200, 5, 0x20, "important.doc"),
        ];
        let buffer = build_mft_enum_buffer(300, &records);

        let (entries, _) = MftScanner::parse_mft_buffer(&buffer, buffer.len());
        assert_eq!(entries.len(), 3, "parse_mft_buffer returns all entries unfiltered");

        // Build paths and apply the same filter scan_filtered uses
        let mut ref_map: HashMap<u64, &MftEntry> = HashMap::new();
        for entry in &entries {
            ref_map.insert(entry.file_reference, entry);
        }

        let paths: Vec<String> = entries
            .iter()
            .map(|e| scanner.build_full_path(e, &ref_map, 5))
            .collect();

        let filtered: Vec<&String> = paths
            .iter()
            .filter(|path| !IGNORED_PATH_PATTERNS.iter().any(|pattern| path.contains(pattern)))
            .collect();

        // $Recycle.Bin and its child should be excluded
        assert_eq!(filtered.len(), 1);
        assert!(filtered[0].ends_with("important.doc"));
    }
}
