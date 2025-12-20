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
use tracing::{debug, info};

#[cfg(windows)]
use windows::Win32::Foundation::{CloseHandle, HANDLE};
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    GetVolumeInformationW, OPEN_EXISTING,
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
#[expect(dead_code, reason = "will be used for hidden file filtering")]
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
#[expect(dead_code, reason = "fields used via Debug trait and future expansion")]
#[derive(Debug, Clone)]
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

        info!("Opened volume {}:\\ for MFT scanning", drive_letter);

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
        info!("Starting MFT scan for {}:\\", self.drive_letter);

        if path_filters.is_empty() {
            info!("No path filters, returning all entries");
        } else {
            info!("Filtering to {} path(s): {:?}", path_filters.len(), path_filters);
        }

        // Get NTFS volume data
        let volume_data = self.get_ntfs_volume_data()?;
        let total_mft_records =
            volume_data.MftValidDataLength as u64 / u64::from(volume_data.BytesPerFileRecordSegment);

        info!("MFT contains approximately {} records", total_mft_records);

        // Read all MFT entries
        let mft_entries = self.enumerate_mft_entries();
        info!("Read {} MFT entries", mft_entries.len());

        // Build directory tree and resolve full paths
        let file_entries = self.resolve_paths(&mft_entries);
        info!("Resolved {} file entries with full paths", file_entries.len());

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

            info!("Filtered to {} entries matching path filters", filtered.len());
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

            let next_ref = u64::from_le_bytes(buffer[0..8].try_into().unwrap_or([0; 8]));

            // Parse USN records from the buffer
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

                if let Some(entry) = Self::parse_usn_record(&buffer[offset..offset + record_length]) {
                    // Skip system files and special entries
                    if entry.file_reference >= 24 && !entry.name.is_empty() {
                        entries.push(entry);
                    }
                }

                offset += record_length;
            }

            // Continue from the next reference number
            enum_data.start_file_reference_number = next_ref;

            // Log progress periodically
            if entries.len() % 100_000 == 0 && !entries.is_empty() {
                debug!("Read {} MFT entries so far...", entries.len());
            }
        }

        entries
    }

    /// Parse a USN record from raw bytes.
    #[cfg(windows)]
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
    #[cfg(windows)]
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
    #[cfg(windows)]
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
        let volume_id = 0i64; // Will be set by caller

        for entry in mft_entries {
            // Skip entries without names
            if entry.name.is_empty() {
                continue;
            }

            // Build full path by walking up the directory tree
            let full_path = self.build_full_path(entry, &ref_to_entry, ROOT_REF);

            let file_entry = FileEntry {
                id: None,
                volume_id,
                parent_id: None,
                name: entry.name.clone(),
                full_path,
                is_directory: entry.is_directory,
                size: entry.size,
                created_time: None,
                modified_time: None,
                mft_reference: Some(entry.file_reference),
            };

            file_entries.push(file_entry);
        }

        file_entries
    }

    /// Build the full path for an entry by walking up the directory tree.
    #[cfg(windows)]
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
                info!("Detected local NTFS volume: {letter}:\\");
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
}
