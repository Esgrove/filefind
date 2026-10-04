//! Filesystem transfer, chunked copy, verification, and cross-device error detection.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use indicatif::ProgressBar;

use filefind::print_warning;

use super::COPY_BUFFER_SIZE;

/// Errors that can occur when moving a single file.
pub(super) enum MoveError {
    /// The move was aborted by the user (Ctrl+C during copy).
    Aborted,
    /// The move failed with an error.
    Failed(anyhow::Error),
}

/// Move a single file from source to destination.
///
/// Tries `fs::rename` first for same-device moves, then falls back to copy+verify+delete for cross-device moves.
pub(super) fn move_single_file(
    source: &Path,
    destination: &Path,
    expected_size: u64,
    progress_bar: &ProgressBar,
    abort_flag: &AtomicBool,
) -> Result<(), MoveError> {
    // Try fast rename first (works only on same filesystem)
    match fs::rename(source, destination) {
        Ok(()) => {
            progress_bar.inc(expected_size);
            return Ok(());
        }
        Err(rename_error) => {
            // Verify file state after a failed rename.
            // On network drives (SMB), the server can complete the rename but the client receives an error
            // (e.g., timeout or dropped response).
            // Without this check, the file appears "lost":
            // gone from the source but the code never checks the destination.
            if !source.exists() {
                if destination.exists() {
                    // Rename appears to have succeeded despite the error.
                    // Verify the file size as a sanity check.
                    if let Ok(meta) = fs::metadata(destination)
                        && meta.len() == expected_size
                    {
                        progress_bar.inc(expected_size);
                        return Ok(());
                    }
                    // Destination exists but size is wrong or unreadable
                    return Err(MoveError::Failed(anyhow::anyhow!(
                        "Rename of {} -> {} reported an error but moved the file. \
                         Destination exists but size verification failed \
                         (expected {expected_size} bytes). Original error: {rename_error}",
                        source.display(),
                        destination.display(),
                    )));
                }
                // Source gone, destination not created: file is lost
                return Err(MoveError::Failed(anyhow::anyhow!(
                    "File lost during rename of {} -> {}: source no longer exists \
                     and destination was not created. The file may have been moved \
                     or deleted by another process. Original error: {rename_error}",
                    source.display(),
                    destination.display(),
                )));
            }

            // Source still exists. No data lost. For cross-device errors we always fall through to copy+delete.
            // For other errors (e.g., network drives returning unexpected error codes) we also fall through,
            // since the copy path is a safe fallback.
            if !is_cross_device_error(&rename_error) {
                progress_bar.suspend(|| {
                    print_warning!(
                        "Rename failed for {} -> {} (error: {rename_error}), falling back to copy",
                        source.display(),
                        destination.display(),
                    );
                });
            }
        }
    }

    // Cross-device move: copy with progress, verify, then delete.
    // The copy function returns Ok only
    // when the destination file has been fully written, flushed, and its handle closed.
    // On error or abort the partial destination file is cleaned up *after* the handle is dropped.
    copy_file_with_progress(source, destination, expected_size, progress_bar, abort_flag)?;

    // Verify the copy by checking the on-disk file size.
    // defense-in-depth:
    // the copy function already verifies the byte count,
    // but the metadata check guards against silent filesystem corruption.
    let dest_metadata = fs::metadata(destination).map_err(|error| {
        MoveError::Failed(anyhow::Error::new(error).context(format!(
            "Failed to read metadata of copied file: {}",
            destination.display()
        )))
    })?;

    let copied_size = dest_metadata.len();
    if copied_size != expected_size {
        // Size mismatch: delete the bad copy and report error
        if let Err(cleanup_error) = fs::remove_file(destination) {
            print_warning!(
                "Failed to clean up mismatched copy at {}: {cleanup_error}",
                destination.display()
            );
        }
        return Err(MoveError::Failed(anyhow::anyhow!(
            "Size verification failed for {}: expected {} bytes, got {copied_size} bytes. Original file preserved.",
            source.display(),
            expected_size,
        )));
    }

    // Copy verified: delete the original
    fs::remove_file(source).map_err(|error| {
        MoveError::Failed(anyhow::Error::new(error).context(format!(
            "File copied successfully but failed to delete original: {}. You may have a duplicate.",
            source.display()
        )))
    })?;

    Ok(())
}

/// Copy a file in chunks while updating the progress bar.
///
/// Checks the abort flag between chunks so we can stop gracefully.
/// On any error or abort, the destination file handle is closed
/// before attempting to remove the partial file (required on Windows where open handles prevent deletion).
pub(super) fn copy_file_with_progress(
    source: &Path,
    destination: &Path,
    expected_size: u64,
    progress_bar: &ProgressBar,
    abort_flag: &AtomicBool,
) -> Result<(), MoveError> {
    // Perform the actual copy in an inner function so that all file handles are guaranteed to be dropped
    // before we attempt cleanup on error.
    let result = copy_file_inner(source, destination, expected_size, progress_bar, abort_flag);

    // At this point both source_file and dest_file handles have been dropped,
    // so cleanup will succeed even on Windows.
    if let Err(ref error) = result {
        let is_abort = matches!(error, MoveError::Aborted);
        if let Err(cleanup_error) = fs::remove_file(destination) {
            // Only warn when the file actually exists — if File::create never
            // succeeded there is nothing to remove.
            if destination.exists() {
                if is_abort {
                    print_warning!(
                        "Failed to clean up partial file after abort at {}: {cleanup_error}",
                        destination.display()
                    );
                } else {
                    print_warning!(
                        "Failed to clean up partial file at {}: {cleanup_error}",
                        destination.display()
                    );
                }
            }
        }
    }

    result
}

/// Inner copy loop. File handles are dropped when this function returns,
/// making it safe for the caller to remove the destination on error.
pub(super) fn copy_file_inner(
    source: &Path,
    destination: &Path,
    expected_size: u64,
    progress_bar: &ProgressBar,
    abort_flag: &AtomicBool,
) -> Result<(), MoveError> {
    let mut source_file = File::open(source).map_err(|error| {
        MoveError::Failed(
            anyhow::Error::new(error).context(format!("Failed to open source file: {}", source.display())),
        )
    })?;

    let mut dest_file = File::create(destination).map_err(|error| {
        MoveError::Failed(
            anyhow::Error::new(error).context(format!("Failed to create destination file: {}", destination.display())),
        )
    })?;

    let mut buffer = vec![0u8; COPY_BUFFER_SIZE];
    let mut bytes_copied: u64 = 0;

    loop {
        // Check abort flag between chunks
        if abort_flag.load(Ordering::SeqCst) {
            return Err(MoveError::Aborted);
        }

        let bytes_read = source_file.read(&mut buffer).map_err(|error| {
            MoveError::Failed(anyhow::Error::new(error).context(format!("Failed to read from: {}", source.display())))
        })?;

        if bytes_read == 0 {
            break;
        }

        #[expect(
            clippy::indexing_slicing,
            reason = "Read::read guarantees bytes_read <= buffer.len()"
        )]
        let chunk = &buffer[..bytes_read];
        dest_file.write_all(chunk).map_err(|error| {
            MoveError::Failed(
                anyhow::Error::new(error).context(format!("Failed to write to: {}", destination.display())),
            )
        })?;

        bytes_copied += bytes_read as u64;
        progress_bar.inc(bytes_read as u64);
    }

    // Flush to ensure all data is written to disk
    dest_file.flush().map_err(|error| {
        MoveError::Failed(anyhow::Error::new(error).context(format!("Failed to flush: {}", destination.display())))
    })?;

    // Verify we copied the expected amount
    if bytes_copied != expected_size {
        return Err(MoveError::Failed(anyhow::anyhow!(
            "Incomplete copy for {}: expected {expected_size} bytes, copied {bytes_copied} bytes. Original file preserved.",
            source.display(),
        )));
    }

    // dest_file and source_file are dropped here, releasing their handles
    Ok(())
}

/// Check if an I/O error indicates a cross-device move attempt.
///
/// On Windows, this is `ERROR_NOT_SAME_DEVICE` (error code 17).
/// On Unix, this is `EXDEV` (error code 18).
pub(super) fn is_cross_device_error(error: &io::Error) -> bool {
    // Windows: ERROR_NOT_SAME_DEVICE = 17
    // Unix: EXDEV = 18
    error.raw_os_error() == Some(17) || error.raw_os_error() == Some(18)
}
