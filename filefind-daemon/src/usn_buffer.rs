//! Bounds-checked helpers for parsing raw USN record buffers.
//!
//! Both `FSCTL_ENUM_USN_DATA` (MFT enumeration) and `FSCTL_READ_USN_JOURNAL` (change journal)
//! return buffers with the same layout:
//! - `[0..8]`: An 8-byte header (next file reference or next USN, little-endian)
//! - `[8..]`:  Packed `USN_RECORD_V2`/`USN_RECORD_V3` records, each starting with its `u32` record length
//!
//! All readers return `None` instead of panicking when the requested bytes are out of bounds.

#![cfg_attr(not(windows), allow(dead_code))]

/// Size of the buffer header preceding the first record.
const HEADER_SIZE: usize = 8;

/// Read the 8-byte little-endian buffer header.
///
/// Returns `None` if the buffer is shorter than the header.
pub fn read_header(buffer: &[u8]) -> Option<[u8; HEADER_SIZE]> {
    read_array(buffer, 0)
}

/// Iterate over the packed records following the buffer header.
///
/// Iteration stops at the first record with a zero length,
/// or a record whose length field or declared length runs past the end of the buffer.
pub fn records(buffer: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut offset = HEADER_SIZE;
    std::iter::from_fn(move || {
        let record_length = read_u32_le(buffer, offset)? as usize;
        if record_length == 0 {
            return None;
        }
        let record = byte_range(buffer, offset, record_length)?;
        offset = offset.checked_add(record_length)?;
        Some(record)
    })
}

/// Read a little-endian `u16` at `offset`.
pub fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    read_array(data, offset).map(u16::from_le_bytes)
}

/// Read a little-endian `u32` at `offset`.
pub fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    read_array(data, offset).map(u32::from_le_bytes)
}

/// Read a little-endian `u64` at `offset`.
pub fn read_u64_le(data: &[u8], offset: usize) -> Option<u64> {
    read_array(data, offset).map(u64::from_le_bytes)
}

/// Read a little-endian `i64` at `offset`.
pub fn read_i64_le(data: &[u8], offset: usize) -> Option<i64> {
    read_array(data, offset).map(i64::from_le_bytes)
}

/// Decode `byte_length` bytes of little-endian UTF-16 starting at `offset`.
///
/// Invalid UTF-16 is replaced with the Unicode replacement character.
/// A trailing odd byte is ignored.
pub fn read_utf16_le_string(data: &[u8], offset: usize, byte_length: usize) -> Option<String> {
    let bytes = byte_range(data, offset, byte_length)?;
    let code_units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&pair| u16::from_le_bytes(pair))
        .collect();
    Some(String::from_utf16_lossy(&code_units))
}

/// Return `length` bytes starting at `offset`, or `None` if the range is out of bounds.
fn byte_range(data: &[u8], offset: usize, length: usize) -> Option<&[u8]> {
    data.get(offset..offset.checked_add(length)?)
}

/// Copy `N` bytes starting at `offset` into an array.
fn read_array<const N: usize>(data: &[u8], offset: usize) -> Option<[u8; N]> {
    data.get(offset..)?.first_chunk::<N>().copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a buffer with an 8-byte header followed by the given records.
    fn build_buffer(header: u64, records: &[&[u8]]) -> Vec<u8> {
        let mut buffer = header.to_le_bytes().to_vec();
        for record in records {
            buffer.extend_from_slice(record);
        }
        buffer
    }

    /// Build a record of `length` bytes whose first four bytes hold the record length.
    fn build_record(length: u32, fill: u8) -> Vec<u8> {
        let mut record = length.to_le_bytes().to_vec();
        record.resize(length as usize, fill);
        record
    }

    #[test]
    fn test_read_integers() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];
        assert_eq!(read_u16_le(&data, 0), Some(0x0201));
        assert_eq!(read_u16_le(&data, 1), Some(0x0302));
        assert_eq!(read_u32_le(&data, 0), Some(0x0403_0201));
        assert_eq!(read_u64_le(&data, 0), Some(0x0807_0605_0403_0201));
        assert_eq!(read_u64_le(&data, 1), Some(0x0908_0706_0504_0302));
        assert_eq!(read_i64_le(&(-2_i64).to_le_bytes(), 0), Some(-2));
    }

    #[test]
    fn test_read_integers_out_of_bounds() {
        let data = [0u8; 4];
        assert_eq!(read_u16_le(&data, 3), None);
        assert_eq!(read_u32_le(&data, 1), None);
        assert_eq!(read_u64_le(&data, 0), None);
        assert_eq!(read_i64_le(&data, 0), None);
        assert_eq!(read_u16_le(&data, 4), None);
        assert_eq!(read_u16_le(&data, usize::MAX), None);
        assert_eq!(read_u16_le(&[], 0), None);
    }

    #[test]
    fn test_read_header() {
        let buffer = build_buffer(0x1234_5678, &[]);
        assert_eq!(read_header(&buffer).map(u64::from_le_bytes), Some(0x1234_5678));
        assert_eq!(read_header(&buffer[..7]), None);
        assert_eq!(read_header(&[]), None);
    }

    #[test]
    fn test_read_utf16_le_string() {
        let mut data = vec![0xFF, 0xFF];
        data.extend("héllo 日本".encode_utf16().flat_map(u16::to_le_bytes));
        let byte_length = data.len() - 2;
        assert_eq!(
            read_utf16_le_string(&data, 2, byte_length),
            Some("héllo 日本".to_string())
        );
        assert_eq!(read_utf16_le_string(&data, 2, 0), Some(String::new()));
    }

    #[test]
    fn test_read_utf16_le_string_ignores_trailing_odd_byte() {
        let data = [b'A', 0, b'B', 0, b'C'];
        assert_eq!(read_utf16_le_string(&data, 0, 5), Some("AB".to_string()));
    }

    #[test]
    fn test_read_utf16_le_string_invalid_is_lossy() {
        // Unpaired high surrogate
        let data = [0x00, 0xD8, b'A', 0];
        assert_eq!(read_utf16_le_string(&data, 0, 4), Some("\u{FFFD}A".to_string()));
    }

    #[test]
    fn test_read_utf16_le_string_out_of_bounds() {
        let data = [b'A', 0, b'B', 0];
        assert_eq!(read_utf16_le_string(&data, 0, 6), None);
        assert_eq!(read_utf16_le_string(&data, 4, 2), None);
        assert_eq!(read_utf16_le_string(&data, 2, usize::MAX), None);
        assert_eq!(read_utf16_le_string(&data, usize::MAX, 2), None);
    }

    #[test]
    fn test_byte_range() {
        let data = [1, 2, 3, 4];
        assert_eq!(byte_range(&data, 1, 2), Some(&[2, 3][..]));
        assert_eq!(byte_range(&data, 4, 0), Some(&[][..]));
        assert_eq!(byte_range(&data, 3, 2), None);
        assert_eq!(byte_range(&data, 5, 0), None);
        assert_eq!(byte_range(&data, usize::MAX, 1), None);
    }

    #[test]
    fn test_records_iterates_all_records() {
        let first = build_record(12, 0xAA);
        let second = build_record(16, 0xBB);
        let buffer = build_buffer(1, &[&first, &second]);

        let parsed: Vec<&[u8]> = records(&buffer).collect();
        assert_eq!(parsed, vec![first.as_slice(), second.as_slice()]);
    }

    #[test]
    fn test_records_empty_buffers() {
        assert_eq!(records(&[]).count(), 0);
        assert_eq!(records(&build_buffer(1, &[])).count(), 0);
    }

    #[test]
    fn test_records_stops_at_zero_length() {
        let first = build_record(12, 0xAA);
        let zero = [0u8; 12];
        let third = build_record(12, 0xCC);
        let buffer = build_buffer(1, &[&first, &zero, &third]);

        assert_eq!(records(&buffer).count(), 1);
    }

    #[test]
    fn test_records_stops_at_truncated_record() {
        let first = build_record(12, 0xAA);
        let second = build_record(16, 0xBB);
        let buffer = build_buffer(1, &[&first, &second]);

        // Cut the second record short
        let truncated = &buffer[..buffer.len() - 1];
        assert_eq!(records(truncated).count(), 1);
    }

    #[test]
    fn test_records_stops_at_truncated_length_field() {
        let first = build_record(12, 0xAA);
        let mut buffer = build_buffer(1, &[&first]);
        // Only three bytes of the next record's length field
        buffer.extend_from_slice(&[0x10, 0, 0]);

        assert_eq!(records(&buffer).count(), 1);
    }

    #[test]
    fn test_records_huge_record_length_does_not_panic() {
        let mut buffer = build_buffer(1, &[]);
        buffer.extend_from_slice(&u32::MAX.to_le_bytes());
        buffer.extend_from_slice(&[0u8; 8]);

        assert_eq!(records(&buffer).count(), 0);
    }
}
