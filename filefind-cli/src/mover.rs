//! File move operations for search results.
//!
//! Handles moving matched files to a destination directory with progress reporting,
//! disk space verification, and graceful Ctrl+C abort handling.
//!
//! Move strategy:
//! 1. Try `std::fs::rename` first (atomic, instant on same filesystem)
//! 2. Fall back to copy+delete for cross-device moves (internal → network drives)
//! 3. Verify file size after copy before deleting original

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result, bail};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};

use filefind::database::Database;
use filefind::types::FileEntry;
use filefind::{format_size, get_volume_prefix, print_error, print_success, print_warning};

/// Size of the buffer used for chunked file copying (256 KB).
const COPY_BUFFER_SIZE: usize = 256 * 1024;

/// Calculate the total size of files that will require a cross-device copy.
///
/// Same-device moves use `fs::rename` which is instant and consumes no
/// additional disk space. Only cross-device moves need free space at the
/// destination for the copied data.
fn cross_device_size(files: &[&FileEntry], destination: &Path) -> u64 {
    let dest_prefix = get_volume_prefix(&destination.to_string_lossy());

    files
        .iter()
        .filter(|file| {
            let source_prefix = get_volume_prefix(&file.full_path);
            // If either prefix is unknown, conservatively assume cross-device
            match (&source_prefix, &dest_prefix) {
                (Some(source), Some(dest)) => source != dest,
                _ => true,
            }
        })
        .map(|file| file.size)
        .sum()
}

/// Reason a file was skipped during the move operation.
#[derive(Debug)]
enum SkipReason {
    /// Another search result has the same filename (duplicate).
    DuplicateName,
    /// A file with the same name already exists at the destination (no --force).
    ExistsAtDestination,
}

/// A file that was skipped during the move, with the reason.
struct SkippedFile {
    /// Full path of the skipped file.
    path: String,
    /// Why the file was skipped.
    reason: SkipReason,
}

/// Result of filtering files before a move operation.
struct FilterResult<'a> {
    /// Files that need to be moved.
    files_to_move: Vec<&'a FileEntry>,
    /// Number of files already located in the destination directory.
    already_at_destination: u64,
    /// Files that were skipped because they could not be moved.
    skipped_files: Vec<SkippedFile>,
}

/// Bundles the parameters needed to execute a batch of file moves.
struct MoveContext<'a> {
    /// Canonical destination directory.
    destination: &'a Path,
    /// Whether to overwrite existing files at the destination.
    force_overwrite: bool,
    /// Database to update after each successful move.
    database: &'a Database,
    /// Flag set by the Ctrl+C handler to request graceful abort.
    abort_flag: &'a AtomicBool,
}

/// Summary of a completed move operation.
struct MoveSummary {
    /// Number of files successfully moved.
    moved: u64,
    /// Number of files that were already in the destination directory.
    already_at_destination: u64,
    /// Files that were skipped because they could not be moved.
    skipped_files: Vec<SkippedFile>,
    /// Number of files that failed to move.
    failed: u64,
    /// Total size (in bytes) of all successfully moved files.
    ///
    /// This counts the logical file size regardless of whether the move was an
    /// instant same-device rename or a cross-device copy.
    total_size_moved: u64,
    /// Whether the operation was aborted by Ctrl+C.
    aborted: bool,
}

impl MoveSummary {
    /// Get the total number of skipped files (excludes already-at-destination).
    const fn skipped_count(&self) -> usize {
        self.skipped_files.len()
    }
}

/// Move matching files to the specified destination directory.
///
/// Shows a confirmation prompt with the total size before proceeding.
/// Filters out directories and files already at the destination,
/// checks disk space, and moves files with a progress bar.
/// Handles Ctrl+C gracefully by finishing the current file before stopping.
/// Updates the database after each successful move.
///
/// When `force_overwrite` is true, existing files at the destination will be
/// overwritten. Otherwise they are skipped and listed at the end.
///
/// # Ctrl+C handler
///
/// This function registers a global `ctrlc` handler via [`ctrlc::set_handler`].
/// That function can only be called **once** per process. If another handler has
/// already been registered (or if this function is called a second time), the
/// registration will fail and an error is returned.
///
/// # Errors
/// Returns an error if the destination directory cannot be created or accessed.
pub fn move_files(files: &[FileEntry], destination: &Path, database: &Database, force_overwrite: bool) -> Result<()> {
    if files.is_empty() {
        println!("{}", "No files found to move.".yellow());
        return Ok(());
    }

    // Ensure destination directory exists
    if !destination.exists() {
        fs::create_dir_all(destination)
            .with_context(|| format!("Failed to create destination directory: {}", destination.display()))?;
        println!("Created destination directory: {}", destination.display());
    } else if !destination.is_dir() {
        bail!(
            "Destination path exists but is not a directory: {}",
            destination.display()
        );
    }

    // Canonicalize destination for reliable path comparison
    let destination = destination
        .canonicalize()
        .with_context(|| format!("Failed to resolve destination path: {}", destination.display()))?;

    // Filter out files already in the destination directory and detect name conflicts
    let filter_result = filter_files(files, &destination, force_overwrite);

    if filter_result.files_to_move.is_empty() {
        if filter_result.skipped_files.is_empty() {
            println!(
                "{}",
                "All matching files are already in the destination directory.".yellow()
            );
        } else {
            println!("{}", "No files to move after filtering.".yellow());
            print_skipped_files(&filter_result.skipped_files);
        }
        return Ok(());
    }

    // Calculate total size of all files (for progress bar) and the subset that
    // will actually require disk space (cross-device copies only).
    let total_size: u64 = filter_result.files_to_move.iter().map(|file| file.size).sum();
    let required_space = cross_device_size(&filter_result.files_to_move, &destination);

    // Only check disk space for files that need a cross-device copy.
    // Same-device moves use fs::rename which is instant and free.
    if required_space > 0 {
        check_disk_space(&destination, required_space)?;
    }

    // Print move plan and ask for confirmation
    print_move_plan(
        &filter_result.files_to_move,
        &destination,
        total_size,
        filter_result.already_at_destination,
        &filter_result.skipped_files,
        force_overwrite,
    );

    if !prompt_confirmation()? {
        println!("{}", "Move cancelled.".yellow());
        return Ok(());
    }

    // Set up Ctrl+C handler (can only be called once per process)
    let abort_flag = Arc::new(AtomicBool::new(false));
    let abort_flag_handler = Arc::clone(&abort_flag);
    ctrlc::set_handler(move || {
        if abort_flag_handler.load(Ordering::SeqCst) {
            // Second Ctrl+C: hard exit
            eprintln!("\nForce quitting...");
            std::process::exit(1);
        }
        abort_flag_handler.store(true, Ordering::SeqCst);
        eprintln!(
            "\n{}",
            "Aborting after current file completes... (press Ctrl+C again to force quit)"
                .yellow()
                .bold()
        );
    })
    .context("Failed to set Ctrl+C handler (it may already be registered)")?;

    let context = MoveContext {
        destination: &destination,
        force_overwrite,
        database,
        abort_flag: &abort_flag,
    };

    // Execute the moves with progress
    let summary = execute_moves(
        &filter_result.files_to_move,
        total_size,
        filter_result.already_at_destination,
        filter_result.skipped_files,
        &context,
    );

    // Print final summary
    print_summary(&summary);

    Ok(())
}

/// Filter files to determine which ones need to be moved.
///
/// Removes files already in the destination directory and handles
/// duplicate filenames by keeping only the first occurrence.
/// When `force_overwrite` is false, also skips files whose name already
/// exists at the destination.
///
/// Returns a `FilterResult` with the files to move, a count of files already
/// at the destination, and a list of files that were skipped with reasons.
fn filter_files<'a>(files: &'a [FileEntry], destination: &Path, force_overwrite: bool) -> FilterResult<'a> {
    let dest_str = destination.to_string_lossy().to_lowercase();
    // Also handle the \\?\ prefix that canonicalize adds on Windows
    let dest_str_prefixed = dest_str
        .strip_prefix(r"\\?\")
        .map_or_else(|| dest_str.clone(), str::to_string);

    let mut files_to_move = Vec::new();
    let mut already_at_destination: u64 = 0;
    let mut skipped_files = Vec::new();
    let mut seen_names = std::collections::HashSet::new();

    for file in files {
        // Check if file is already in the destination directory
        let file_parent = Path::new(&file.full_path)
            .parent()
            .map(|p| p.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        let file_parent_clean = file_parent
            .strip_prefix(r"\\?\")
            .map_or_else(|| file_parent.clone(), str::to_string);

        if file_parent_clean == dest_str_prefixed || file_parent == dest_str {
            already_at_destination += 1;
            continue;
        }

        // Check for duplicate filenames across search results (keep first occurrence)
        let file_name = Path::new(&file.full_path)
            .file_name()
            .map(|name| name.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        if !seen_names.insert(file_name) {
            skipped_files.push(SkippedFile {
                path: file.full_path.clone(),
                reason: SkipReason::DuplicateName,
            });
            continue;
        }

        // Check if a file with this name already exists at the destination
        if !force_overwrite {
            let dest_file = destination.join(Path::new(&file.full_path).file_name().unwrap_or_default());
            if dest_file.exists() {
                skipped_files.push(SkippedFile {
                    path: file.full_path.clone(),
                    reason: SkipReason::ExistsAtDestination,
                });
                continue;
            }
        }

        files_to_move.push(file);
    }

    FilterResult {
        files_to_move,
        already_at_destination,
        skipped_files,
    }
}

/// Print the move plan before executing.
fn print_move_plan(
    files: &[&FileEntry],
    destination: &Path,
    total_size: u64,
    already_at_destination: u64,
    skipped_files: &[SkippedFile],
    force_overwrite: bool,
) {
    println!(
        "\n{} {} ({}) → {}",
        "Moving".bold(),
        format!("{} files", files.len()).cyan(),
        format_size(total_size).cyan(),
        destination.display().to_string().green()
    );

    if already_at_destination > 0 {
        println!(
            "  {} already in destination",
            format!("{already_at_destination} files").dimmed(),
        );
    }

    if !skipped_files.is_empty() {
        println!(
            "{} {}",
            "Skipping".bold(),
            format!("{} files", skipped_files.len()).yellow(),
        );
    }

    if force_overwrite {
        println!(
            "{}",
            "Force mode: existing files at destination will be overwritten"
                .yellow()
                .bold()
        );
    }
}

/// Ask the user for confirmation before proceeding with the move.
///
/// Returns true if the user confirms, false otherwise.
fn prompt_confirmation() -> Result<bool> {
    eprint!("\n{} ", "Proceed with move? [y/N]".bold());
    io::stderr().flush().context("Failed to flush stderr")?;

    let mut input = String::new();
    io::stdin().read_line(&mut input).context("Failed to read user input")?;

    let trimmed = input.trim().to_lowercase();
    Ok(trimmed == "y" || trimmed == "yes")
}

/// Check if there is enough disk space at the destination.
///
/// # Errors
/// Returns an error if the space cannot be determined or is insufficient.
fn check_disk_space(destination: &Path, required_bytes: u64) -> Result<()> {
    let available = get_available_space(destination)?;

    if available < required_bytes {
        bail!(
            "Not enough disk space at destination.\nRequired: {}\nAvailable: {}\nShortfall: {}",
            format_size(required_bytes),
            format_size(available),
            format_size(required_bytes - available)
        );
    }

    Ok(())
}

/// Get available disk space at the given path.
///
/// On Windows, uses `GetDiskFreeSpaceExW`. On other platforms, returns `u64::MAX`
/// as a fallback (skip the check).
#[cfg(windows)]
fn get_available_space(path: &Path) -> Result<u64> {
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

    let wide_path: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();

    let mut free_bytes_available: u64 = 0;
    let mut total_bytes: u64 = 0;
    let mut total_free_bytes: u64 = 0;

    // SAFETY: `GetDiskFreeSpaceExW` is a safe Windows API call that writes
    // disk space information to the provided output pointers.
    #[allow(unsafe_code)]
    let result = unsafe {
        GetDiskFreeSpaceExW(
            wide_path.as_ptr(),
            &raw mut free_bytes_available,
            &raw mut total_bytes,
            &raw mut total_free_bytes,
        )
    };

    if result == 0 {
        bail!(
            "Failed to get disk space for {}. Error code: {}",
            path.display(),
            io::Error::last_os_error()
        );
    }

    Ok(free_bytes_available)
}

/// Fallback for non-Windows platforms: skip disk space check.
#[cfg(not(windows))]
fn get_available_space(_path: &Path) -> Result<u64> {
    Ok(u64::MAX)
}

/// Execute the file moves with progress reporting and abort handling.
///
/// Updates the database after each successful move.
fn execute_moves(
    files: &[&FileEntry],
    total_size: u64,
    already_at_destination: u64,
    skipped_files: Vec<SkippedFile>,
    context: &MoveContext<'_>,
) -> MoveSummary {
    let progress_bar = ProgressBar::new(total_size);
    progress_bar.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta}) {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("█▓░"),
    );

    let mut summary = MoveSummary {
        moved: 0,
        already_at_destination,
        skipped_files,
        failed: 0,
        total_size_moved: 0,
        aborted: false,
    };

    for (index, file) in files.iter().enumerate() {
        // Check abort flag before starting next file
        if context.abort_flag.load(Ordering::SeqCst) {
            summary.aborted = true;
            progress_bar.abandon_with_message("Aborted by user");
            break;
        }

        let file_name = Path::new(&file.full_path)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();

        progress_bar.set_message(format!("[{}/{}] {file_name}", index + 1, files.len()));

        let dest_path = context.destination.join(&*file_name);
        let source_path = Path::new(&file.full_path);

        // If force overwrite and destination exists, remove it first
        if context.force_overwrite
            && dest_path.exists()
            && let Err(error) = fs::remove_file(&dest_path)
        {
            summary.failed += 1;
            progress_bar.suspend(|| {
                print_error!(
                    "Failed to remove existing file at destination {}: {error}",
                    dest_path.display()
                );
            });
            progress_bar.inc(file.size);
            continue;
        }

        match move_single_file(source_path, &dest_path, file.size, &progress_bar, context.abort_flag) {
            Ok(()) => {
                summary.moved += 1;
                summary.total_size_moved += file.size;

                // Update the database: change the stored path to the new location
                let new_path = dest_path.to_string_lossy();
                if let Err(error) = context
                    .database
                    .update_file_path(&file.full_path, &new_path, &file_name)
                {
                    progress_bar.suspend(|| {
                        print_warning!("Moved file but failed to update database for {}: {error}", file_name);
                    });
                }
            }
            Err(MoveError::Aborted) => {
                summary.aborted = true;
                progress_bar.abandon_with_message("Aborted by user");
                break;
            }
            Err(MoveError::Failed(error)) => {
                summary.failed += 1;
                progress_bar.suspend(|| {
                    print_error!("Failed to move {}: {error}", file.full_path);
                });
                // Advance progress bar past this file so totals stay correct
                progress_bar.inc(file.size);
            }
        }
    }

    if !summary.aborted {
        progress_bar.finish_with_message("Done");
    }

    summary
}

/// Errors that can occur when moving a single file.
enum MoveError {
    /// The move was aborted by the user (Ctrl+C during copy).
    Aborted,
    /// The move failed with an error.
    Failed(anyhow::Error),
}

/// Move a single file from source to destination.
///
/// Tries `fs::rename` first for same-device moves, then falls back
/// to copy+verify+delete for cross-device moves.
fn move_single_file(
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
        Err(error) => {
            // Check if it's a cross-device error
            if !is_cross_device_error(&error) {
                return Err(MoveError::Failed(anyhow::Error::new(error).context(format!(
                    "Failed to rename {} -> {}",
                    source.display(),
                    destination.display()
                ))));
            }
            // Cross-device: fall through to copy+delete
        }
    }

    // Cross-device move: copy with progress, verify, then delete.
    // The copy function returns Ok only when the destination file has been
    // fully written, flushed, and its handle closed. On error or abort the
    // partial destination file is cleaned up *after* the handle is dropped.
    copy_file_with_progress(source, destination, expected_size, progress_bar, abort_flag)?;

    // Verify the copy by checking the on-disk file size (defense-in-depth:
    // the copy function already verifies the byte count, but the metadata
    // check guards against silent filesystem corruption).
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
/// On any error or abort, the destination file handle is closed before
/// attempting to remove the partial file (required on Windows where open
/// handles prevent deletion).
fn copy_file_with_progress(
    source: &Path,
    destination: &Path,
    expected_size: u64,
    progress_bar: &ProgressBar,
    abort_flag: &AtomicBool,
) -> Result<(), MoveError> {
    // Perform the actual copy in an inner function so that all file handles
    // are guaranteed to be dropped before we attempt cleanup on error.
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
fn copy_file_inner(
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

        dest_file.write_all(&buffer[..bytes_read]).map_err(|error| {
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
fn is_cross_device_error(error: &io::Error) -> bool {
    // Windows: ERROR_NOT_SAME_DEVICE = 17
    // Unix: EXDEV = 18
    error.raw_os_error() == Some(17) || error.raw_os_error() == Some(18)
}

/// Print the list of skipped files grouped by reason.
fn print_skipped_files(skipped_files: &[SkippedFile]) {
    if skipped_files.is_empty() {
        return;
    }

    let duplicates: Vec<_> = skipped_files
        .iter()
        .filter(|skipped| matches!(skipped.reason, SkipReason::DuplicateName))
        .collect();

    let exists: Vec<_> = skipped_files
        .iter()
        .filter(|skipped| matches!(skipped.reason, SkipReason::ExistsAtDestination))
        .collect();

    if !duplicates.is_empty() {
        println!(
            "\n{} ({}):",
            "Duplicate filenames in results".yellow().bold(),
            duplicates.len()
        );
        for skipped in &duplicates {
            println!("  {}", skipped.path.dimmed());
        }
    }

    if !exists.is_empty() {
        println!(
            "\n{} ({}):",
            "Already exists at destination (use --force to overwrite)"
                .yellow()
                .bold(),
            exists.len()
        );
        for skipped in &exists {
            println!("  {}", skipped.path.dimmed());
        }
    }
}

/// Print the final summary of the move operation.
fn print_summary(summary: &MoveSummary) {
    println!();

    if summary.moved > 0 {
        print_success!(
            "Moved {} files ({})",
            summary.moved,
            format_size(summary.total_size_moved)
        );
    }

    if summary.already_at_destination > 0 {
        println!(
            "  {} already in destination",
            format!("{} files", summary.already_at_destination).dimmed(),
        );
    }

    if summary.skipped_count() > 0 {
        println!(
            "{} {} skipped",
            "⚠".yellow(),
            format!("{} files", summary.skipped_count()).yellow()
        );
        print_skipped_files(&summary.skipped_files);
    }

    if summary.failed > 0 {
        print_error!("{} files failed to move", summary.failed);
    }

    if summary.aborted {
        print_warning!("Operation was aborted by user");
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicBool;

    use tempfile::TempDir;

    use super::*;

    // --- cross_device_size tests ---

    #[test]
    fn test_cross_device_size_all_same_volume() {
        let destination = PathBuf::from(r"C:\dest");
        let files = [
            make_file_entry("a.txt", r"C:\source\a.txt", 1000),
            make_file_entry("b.txt", r"C:\other\b.txt", 2000),
        ];
        let refs: Vec<&FileEntry> = files.iter().collect();

        // All files on C:, destination on C: — no space needed
        assert_eq!(cross_device_size(&refs, &destination), 0);
    }

    #[test]
    fn test_cross_device_size_all_different_volume() {
        let destination = PathBuf::from(r"D:\dest");
        let files = [
            make_file_entry("a.txt", r"C:\source\a.txt", 1000),
            make_file_entry("b.txt", r"E:\other\b.txt", 2000),
        ];
        let refs: Vec<&FileEntry> = files.iter().collect();

        // All files on different volumes than D: — full size needed
        assert_eq!(cross_device_size(&refs, &destination), 3000);
    }

    #[test]
    fn test_cross_device_size_mixed_volumes() {
        let destination = PathBuf::from(r"C:\dest");
        let files = [
            make_file_entry("a.txt", r"C:\source\a.txt", 1000),
            make_file_entry("b.txt", r"D:\other\b.txt", 2000),
            make_file_entry("c.txt", r"C:\more\c.txt", 3000),
        ];
        let refs: Vec<&FileEntry> = files.iter().collect();

        // Only b.txt (on D:) needs space
        assert_eq!(cross_device_size(&refs, &destination), 2000);
    }

    #[test]
    fn test_cross_device_size_unc_destination() {
        let destination = PathBuf::from(r"\\server\share\dest");
        let files = [
            make_file_entry("a.txt", r"\\server\share\source\a.txt", 1000),
            make_file_entry("b.txt", r"C:\local\b.txt", 2000),
        ];
        let refs: Vec<&FileEntry> = files.iter().collect();

        // a.txt is on same UNC share, b.txt is cross-device
        assert_eq!(cross_device_size(&refs, &destination), 2000);
    }

    #[test]
    fn test_cross_device_size_with_canonicalized_destination() {
        // Destination has \\?\ prefix from canonicalize, source does not
        let destination = PathBuf::from(r"\\?\C:\dest");
        let files = [make_file_entry("a.txt", r"C:\source\a.txt", 5000)];
        let refs: Vec<&FileEntry> = files.iter().collect();

        // Both resolve to c: — same volume, no space needed
        assert_eq!(cross_device_size(&refs, &destination), 0);
    }

    #[test]
    fn test_cross_device_size_empty_files() {
        let destination = PathBuf::from(r"C:\dest");
        let files: Vec<FileEntry> = Vec::new();
        let refs: Vec<&FileEntry> = files.iter().collect();

        assert_eq!(cross_device_size(&refs, &destination), 0);
    }

    #[test]
    fn test_cross_device_size_unknown_prefix_conservative() {
        // Files with unrecognizable paths should be counted conservatively
        let destination = PathBuf::from(r"C:\dest");
        let files = [make_file_entry("a.txt", "relative/path/a.txt", 1000)];
        let refs: Vec<&FileEntry> = files.iter().collect();

        // Unknown prefix → conservatively assumed cross-device
        assert_eq!(cross_device_size(&refs, &destination), 1000);
    }

    // --- is_cross_device_error tests ---

    #[test]
    fn test_is_cross_device_error_windows() {
        let error = io::Error::from_raw_os_error(17);
        assert!(is_cross_device_error(&error));
    }

    #[test]
    fn test_is_cross_device_error_unix() {
        let error = io::Error::from_raw_os_error(18);
        assert!(is_cross_device_error(&error));
    }

    #[test]
    fn test_is_cross_device_error_other() {
        let error = io::Error::from_raw_os_error(2);
        assert!(!is_cross_device_error(&error));
    }

    /// Helper to create a test `FileEntry` with a given name, path, and size.
    fn make_file_entry(name: &str, full_path: &str, size: u64) -> FileEntry {
        let mut entry = FileEntry::new(1, name.to_string(), full_path.to_string(), false);
        entry.size = size;
        entry
    }

    #[test]
    fn test_filter_files_removes_duplicates() {
        let destination = PathBuf::from("C:\\dest");
        let files = vec![
            make_file_entry("file.txt", "C:\\source1\\file.txt", 100),
            make_file_entry("file.txt", "C:\\source2\\file.txt", 200),
        ];

        let result = filter_files(&files, &destination, false);

        assert_eq!(result.files_to_move.len(), 1);
        assert_eq!(result.files_to_move[0].full_path, "C:\\source1\\file.txt");
        assert_eq!(result.already_at_destination, 0);
        assert_eq!(result.skipped_files.len(), 1);
        assert!(matches!(result.skipped_files[0].reason, SkipReason::DuplicateName));
    }

    #[test]
    fn test_filter_files_tracks_already_at_destination() {
        let destination = PathBuf::from("C:\\dest");
        let files = vec![
            make_file_entry("file1.txt", "C:\\dest\\file1.txt", 100),
            make_file_entry("file2.txt", "C:\\source\\file2.txt", 200),
        ];

        let result = filter_files(&files, &destination, false);

        assert_eq!(result.files_to_move.len(), 1);
        assert_eq!(result.files_to_move[0].full_path, "C:\\source\\file2.txt");
        assert_eq!(result.already_at_destination, 1);
        assert!(result.skipped_files.is_empty());
    }

    #[test]
    fn test_filter_files_empty_input() {
        let destination = PathBuf::from("C:\\dest");
        let files: Vec<FileEntry> = Vec::new();

        let result = filter_files(&files, &destination, false);

        assert!(result.files_to_move.is_empty());
        assert_eq!(result.already_at_destination, 0);
        assert!(result.skipped_files.is_empty());
    }

    #[test]
    fn test_filter_files_all_unique() {
        let destination = PathBuf::from("C:\\dest");
        let files = vec![
            make_file_entry("file1.txt", "C:\\source\\file1.txt", 100),
            make_file_entry("file2.txt", "C:\\source\\file2.txt", 200),
            make_file_entry("file3.txt", "C:\\other\\file3.txt", 300),
        ];

        let result = filter_files(&files, &destination, false);

        assert_eq!(result.files_to_move.len(), 3);
        assert_eq!(result.already_at_destination, 0);
        assert!(result.skipped_files.is_empty());
    }

    #[test]
    fn test_filter_files_duplicates_skipped_regardless_of_force() {
        let destination = PathBuf::from("C:\\dest");
        let files = vec![
            make_file_entry("file.txt", "C:\\source1\\file.txt", 100),
            make_file_entry("file.txt", "C:\\source2\\file.txt", 200),
        ];

        // Even with force=true, duplicate names from search results should be skipped
        let result = filter_files(&files, &destination, true);

        assert_eq!(result.files_to_move.len(), 1);
        assert_eq!(result.files_to_move[0].full_path, "C:\\source1\\file.txt");
        assert_eq!(result.skipped_files.len(), 1);
        assert!(matches!(result.skipped_files[0].reason, SkipReason::DuplicateName));
    }

    #[test]
    fn test_filter_files_already_at_destination_regardless_of_force() {
        let destination = PathBuf::from("C:\\dest");
        let files = vec![make_file_entry("file1.txt", "C:\\dest\\file1.txt", 100)];

        // Even with force=true, files already at destination are counted, not skipped
        let result = filter_files(&files, &destination, true);

        assert!(result.files_to_move.is_empty());
        assert_eq!(result.already_at_destination, 1);
        assert!(result.skipped_files.is_empty());
    }

    #[test]
    fn test_filter_files_mixed_reasons() {
        let destination = PathBuf::from("C:\\dest");
        let files = vec![
            make_file_entry("file1.txt", "C:\\dest\\file1.txt", 100),
            make_file_entry("file2.txt", "C:\\source1\\file2.txt", 200),
            make_file_entry("file2.txt", "C:\\source2\\file2.txt", 300),
            make_file_entry("file3.txt", "C:\\other\\file3.txt", 400),
        ];

        let result = filter_files(&files, &destination, false);

        assert_eq!(result.files_to_move.len(), 2);
        assert_eq!(result.files_to_move[0].full_path, "C:\\source1\\file2.txt");
        assert_eq!(result.files_to_move[1].full_path, "C:\\other\\file3.txt");
        assert_eq!(result.already_at_destination, 1);
        assert_eq!(result.skipped_files.len(), 1);
        assert!(matches!(result.skipped_files[0].reason, SkipReason::DuplicateName));
    }

    #[test]
    fn test_filter_files_all_at_destination() {
        let destination = PathBuf::from("C:\\dest");
        let files = vec![
            make_file_entry("a.txt", "C:\\dest\\a.txt", 100),
            make_file_entry("b.txt", "C:\\dest\\b.txt", 200),
        ];

        let result = filter_files(&files, &destination, false);

        assert!(result.files_to_move.is_empty());
        assert_eq!(result.already_at_destination, 2);
        assert!(result.skipped_files.is_empty());
    }

    #[test]
    fn test_move_summary_skipped_count() {
        let summary = MoveSummary {
            moved: 5,
            already_at_destination: 2,
            skipped_files: vec![
                SkippedFile {
                    path: "b.txt".to_string(),
                    reason: SkipReason::DuplicateName,
                },
                SkippedFile {
                    path: "c.txt".to_string(),
                    reason: SkipReason::ExistsAtDestination,
                },
            ],
            failed: 1,
            total_size_moved: 1024,
            aborted: false,
        };

        // skipped_count only counts actual skips, not already-at-destination
        assert_eq!(summary.skipped_count(), 2);
        assert_eq!(summary.already_at_destination, 2);
    }

    #[test]
    fn test_move_summary_no_skips() {
        let summary = MoveSummary {
            moved: 3,
            already_at_destination: 1,
            skipped_files: Vec::new(),
            failed: 0,
            total_size_moved: 512,
            aborted: false,
        };

        assert_eq!(summary.skipped_count(), 0);
        assert_eq!(summary.already_at_destination, 1);
    }

    #[test]
    fn test_filter_files_force_allows_existing_at_destination() {
        // Create a real temp directory so the exists() check inside filter_files works
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let destination = temp_dir.path().to_path_buf();

        // Create a file at the destination so exists() returns true
        let existing_file = destination.join("report.txt");
        fs::write(&existing_file, "existing content").expect("failed to write test file");

        let source_path = "C:\\other\\report.txt".to_string();
        let files = vec![make_file_entry("report.txt", &source_path, 500)];

        // Without force: file is skipped because it exists at destination
        let result = filter_files(&files, &destination, false);
        assert!(result.files_to_move.is_empty());
        assert_eq!(result.skipped_files.len(), 1);
        assert!(matches!(
            result.skipped_files[0].reason,
            SkipReason::ExistsAtDestination
        ));

        // With force: file is NOT skipped, it passes through
        let result_force = filter_files(&files, &destination, true);
        assert_eq!(result_force.files_to_move.len(), 1);
        assert_eq!(result_force.files_to_move[0].full_path, source_path);
        assert!(result_force.skipped_files.is_empty());
    }

    #[test]
    fn test_filter_files_case_insensitive_duplicates() {
        let destination = PathBuf::from("C:\\dest");
        let files = vec![
            make_file_entry("Report.TXT", "C:\\source1\\Report.TXT", 100),
            make_file_entry("report.txt", "C:\\source2\\report.txt", 200),
            make_file_entry("REPORT.txt", "C:\\source3\\REPORT.txt", 300),
        ];

        let result = filter_files(&files, &destination, false);

        // Only the first occurrence should pass; the rest are case-insensitive duplicates
        assert_eq!(result.files_to_move.len(), 1);
        assert_eq!(result.files_to_move[0].full_path, "C:\\source1\\Report.TXT");
        assert_eq!(result.skipped_files.len(), 2);
        assert!(matches!(result.skipped_files[0].reason, SkipReason::DuplicateName));
        assert!(matches!(result.skipped_files[1].reason, SkipReason::DuplicateName));
    }

    #[test]
    fn test_filter_files_with_unc_prefix_destination() {
        // Simulate a canonicalized Windows path with \\?\ prefix
        let destination = PathBuf::from(r"\\?\C:\dest");
        let files = vec![
            // Source file whose parent matches the destination when prefix is stripped
            make_file_entry("file1.txt", r"C:\dest\file1.txt", 100),
            // Source file from a different directory
            make_file_entry("file2.txt", r"C:\source\file2.txt", 200),
        ];

        let result = filter_files(&files, &destination, false);

        // file1.txt should be recognized as already at destination despite prefix mismatch
        assert_eq!(result.files_to_move.len(), 1);
        assert_eq!(result.files_to_move[0].full_path, r"C:\source\file2.txt");
        assert_eq!(result.already_at_destination, 1);
    }

    #[test]
    fn test_filter_files_with_unc_prefix_source() {
        // Destination without prefix, source path with prefix
        let destination = PathBuf::from(r"C:\dest");
        let files = vec![
            make_file_entry("file1.txt", r"\\?\C:\dest\file1.txt", 100),
            make_file_entry("file2.txt", r"C:\source\file2.txt", 200),
        ];

        let result = filter_files(&files, &destination, false);

        assert_eq!(result.files_to_move.len(), 1);
        assert_eq!(result.files_to_move[0].full_path, r"C:\source\file2.txt");
        assert_eq!(result.already_at_destination, 1);
    }

    #[test]
    fn test_filter_files_force_with_already_at_dest_and_same_name_source() {
        // Edge case: a file named X is already at destination, AND another file
        // named X exists in a different source directory.
        // With force=true, the source file should be allowed through (it will
        // overwrite the one at the destination during the actual move).
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let destination = temp_dir.path().to_path_buf();

        // Create the file that's "already at destination"
        let existing = destination.join("data.bin");
        fs::write(&existing, "original").expect("failed to write test file");

        let dest_str = destination.to_string_lossy().to_string();
        let files = vec![
            // This file IS in the destination directory
            make_file_entry("data.bin", &format!("{dest_str}\\data.bin"), 100),
            // This file has the same name but lives elsewhere
            make_file_entry("data.bin", "C:\\incoming\\data.bin", 500),
        ];

        // With force=true:
        // - First entry: already at destination (counted, not in seen_names)
        // - Second entry: not a duplicate (seen_names is empty), force skips exists check
        let result = filter_files(&files, &destination, true);
        assert_eq!(result.already_at_destination, 1);
        assert_eq!(result.files_to_move.len(), 1);
        assert_eq!(result.files_to_move[0].full_path, "C:\\incoming\\data.bin");
        assert!(result.skipped_files.is_empty());
    }

    #[test]
    fn test_filter_files_no_force_with_already_at_dest_and_same_name_source() {
        // Same scenario as above, but without force — the source file should be
        // skipped because it already exists at the destination.
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let destination = temp_dir.path().to_path_buf();

        let existing = destination.join("data.bin");
        fs::write(&existing, "original").expect("failed to write test file");

        let dest_str = destination.to_string_lossy().to_string();
        let files = vec![
            make_file_entry("data.bin", &format!("{dest_str}\\data.bin"), 100),
            make_file_entry("data.bin", "C:\\incoming\\data.bin", 500),
        ];

        let result = filter_files(&files, &destination, false);
        assert_eq!(result.already_at_destination, 1);
        assert!(result.files_to_move.is_empty());
        assert_eq!(result.skipped_files.len(), 1);
        assert!(matches!(
            result.skipped_files[0].reason,
            SkipReason::ExistsAtDestination
        ));
    }

    #[test]
    fn test_move_single_file_same_device_rename() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let source_dir = temp_dir.path().join("source");
        let dest_dir = temp_dir.path().join("dest");
        fs::create_dir_all(&source_dir).expect("failed to create source dir");
        fs::create_dir_all(&dest_dir).expect("failed to create dest dir");

        let source_file = source_dir.join("testfile.txt");
        let content = b"hello world";
        fs::write(&source_file, content).expect("failed to write source file");

        let dest_file = dest_dir.join("testfile.txt");
        let abort_flag = AtomicBool::new(false);
        let progress_bar = ProgressBar::hidden();

        let result = move_single_file(
            &source_file,
            &dest_file,
            content.len() as u64,
            &progress_bar,
            &abort_flag,
        );

        assert!(result.is_ok());
        assert!(!source_file.exists(), "source should be gone after rename");
        assert!(dest_file.exists(), "destination should exist");
        assert_eq!(
            fs::read_to_string(&dest_file).expect("failed to read dest"),
            "hello world"
        );
    }

    #[test]
    fn test_move_single_file_source_not_found() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let source_file = temp_dir.path().join("nonexistent.txt");
        let dest_file = temp_dir.path().join("dest.txt");
        let abort_flag = AtomicBool::new(false);
        let progress_bar = ProgressBar::hidden();

        let result = move_single_file(&source_file, &dest_file, 100, &progress_bar, &abort_flag);

        assert!(matches!(result, Err(MoveError::Failed(_))));
        assert!(!dest_file.exists(), "destination should not be created");
    }

    #[test]
    fn test_copy_file_inner_success() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let source_file = temp_dir.path().join("source.bin");
        let dest_file = temp_dir.path().join("dest.bin");

        // Write some test data
        let content = vec![42u8; 1024];
        fs::write(&source_file, &content).expect("failed to write source");

        let abort_flag = AtomicBool::new(false);
        let progress_bar = ProgressBar::hidden();

        let result = copy_file_inner(
            &source_file,
            &dest_file,
            content.len() as u64,
            &progress_bar,
            &abort_flag,
        );

        assert!(result.is_ok());
        assert!(dest_file.exists());
        let written = fs::read(&dest_file).expect("failed to read dest");
        assert_eq!(written.len(), content.len());
        assert_eq!(written, content);
    }

    #[test]
    fn test_copy_file_inner_size_mismatch() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let source_file = temp_dir.path().join("source.bin");
        let dest_file = temp_dir.path().join("dest.bin");

        let content = b"short";
        fs::write(&source_file, content).expect("failed to write source");

        let abort_flag = AtomicBool::new(false);
        let progress_bar = ProgressBar::hidden();

        // Claim the file is 9999 bytes — the actual file is only 5 bytes
        let result = copy_file_inner(&source_file, &dest_file, 9999, &progress_bar, &abort_flag);

        assert!(matches!(result, Err(MoveError::Failed(_))));
    }

    #[test]
    fn test_copy_file_inner_abort_during_copy() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let source_file = temp_dir.path().join("source.bin");
        let dest_file = temp_dir.path().join("dest.bin");

        // Write enough data that the loop iterates at least once
        let content = vec![0u8; COPY_BUFFER_SIZE * 3];
        fs::write(&source_file, &content).expect("failed to write source");

        // Set abort flag BEFORE starting — the copy loop checks it at the top
        let abort_flag = AtomicBool::new(true);
        let progress_bar = ProgressBar::hidden();

        let result = copy_file_inner(
            &source_file,
            &dest_file,
            content.len() as u64,
            &progress_bar,
            &abort_flag,
        );

        assert!(matches!(result, Err(MoveError::Aborted)));
    }

    #[test]
    fn test_copy_file_with_progress_cleans_up_on_abort() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let source_file = temp_dir.path().join("source.bin");
        let dest_file = temp_dir.path().join("dest.bin");

        let content = vec![0u8; COPY_BUFFER_SIZE * 3];
        fs::write(&source_file, &content).expect("failed to write source");

        let abort_flag = AtomicBool::new(true);
        let progress_bar = ProgressBar::hidden();

        let result = copy_file_with_progress(
            &source_file,
            &dest_file,
            content.len() as u64,
            &progress_bar,
            &abort_flag,
        );

        assert!(matches!(result, Err(MoveError::Aborted)));
        // The outer function should have cleaned up the partial destination file
        assert!(
            !dest_file.exists(),
            "partial destination file should be removed after abort"
        );
    }

    #[test]
    fn test_copy_file_with_progress_cleans_up_on_size_mismatch() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let source_file = temp_dir.path().join("source.bin");
        let dest_file = temp_dir.path().join("dest.bin");

        let content = b"small file";
        fs::write(&source_file, content).expect("failed to write source");

        let abort_flag = AtomicBool::new(false);
        let progress_bar = ProgressBar::hidden();

        // Claim expected size is much larger than actual — triggers size mismatch
        let result = copy_file_with_progress(&source_file, &dest_file, 9999, &progress_bar, &abort_flag);

        assert!(matches!(result, Err(MoveError::Failed(_))));
        // The outer function should have cleaned up the mismatched destination file
        assert!(
            !dest_file.exists(),
            "mismatched destination file should be removed after error"
        );
    }

    #[test]
    fn test_copy_file_inner_source_not_found() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let source_file = temp_dir.path().join("nonexistent.bin");
        let dest_file = temp_dir.path().join("dest.bin");

        let abort_flag = AtomicBool::new(false);
        let progress_bar = ProgressBar::hidden();

        let result = copy_file_inner(&source_file, &dest_file, 100, &progress_bar, &abort_flag);

        assert!(matches!(result, Err(MoveError::Failed(_))));
    }

    #[test]
    fn test_copy_file_inner_empty_file() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let source_file = temp_dir.path().join("empty.bin");
        let dest_file = temp_dir.path().join("dest.bin");

        fs::write(&source_file, b"").expect("failed to write empty file");

        let abort_flag = AtomicBool::new(false);
        let progress_bar = ProgressBar::hidden();

        let result = copy_file_inner(&source_file, &dest_file, 0, &progress_bar, &abort_flag);

        assert!(result.is_ok());
        assert!(dest_file.exists());
        assert_eq!(fs::read(&dest_file).expect("failed to read dest").len(), 0);
    }

    #[test]
    fn test_copy_file_inner_large_file_multiple_chunks() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let source_file = temp_dir.path().join("large.bin");
        let dest_file = temp_dir.path().join("dest.bin");

        // Create a file larger than COPY_BUFFER_SIZE to exercise multiple loop iterations
        let size = COPY_BUFFER_SIZE * 2 + 1234;
        let mut file = File::create(&source_file).expect("failed to create source");
        let chunk = vec![0xABu8; size];
        file.write_all(&chunk).expect("failed to write source");
        drop(file);

        let abort_flag = AtomicBool::new(false);
        let progress_bar = ProgressBar::hidden();

        let result = copy_file_inner(&source_file, &dest_file, size as u64, &progress_bar, &abort_flag);

        assert!(result.is_ok());
        let written = fs::read(&dest_file).expect("failed to read dest");
        assert_eq!(written.len(), size);
        assert!(written.iter().all(|&byte| byte == 0xAB));
    }

    #[test]
    fn test_move_single_file_preserves_content() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let source_dir = temp_dir.path().join("src");
        let dest_dir = temp_dir.path().join("dst");
        fs::create_dir_all(&source_dir).expect("failed to create dirs");
        fs::create_dir_all(&dest_dir).expect("failed to create dirs");

        let source_file = source_dir.join("binary.dat");
        // Use recognizable content pattern
        let content: Vec<u8> = (0..=255).cycle().take(4096).collect();
        fs::write(&source_file, &content).expect("failed to write source");

        let dest_file = dest_dir.join("binary.dat");
        let abort_flag = AtomicBool::new(false);
        let progress_bar = ProgressBar::hidden();

        let result = move_single_file(
            &source_file,
            &dest_file,
            content.len() as u64,
            &progress_bar,
            &abort_flag,
        );

        assert!(result.is_ok());
        assert!(!source_file.exists());
        let moved_content = fs::read(&dest_file).expect("failed to read dest");
        assert_eq!(moved_content, content);
    }

    #[test]
    fn test_filter_files_three_duplicates_different_cases() {
        // Verify that duplicate detection works across many case variants
        let destination = PathBuf::from("C:\\dest");
        let files = vec![
            make_file_entry("readme.md", "C:\\a\\readme.md", 10),
            make_file_entry("README.MD", "C:\\b\\README.MD", 20),
            make_file_entry("Readme.Md", "C:\\c\\Readme.Md", 30),
            make_file_entry("ReadMe.md", "C:\\d\\ReadMe.md", 40),
            make_file_entry("other.txt", "C:\\e\\other.txt", 50),
        ];

        let result = filter_files(&files, &destination, false);

        // Only the first readme and other.txt should pass
        assert_eq!(result.files_to_move.len(), 2);
        assert_eq!(result.files_to_move[0].full_path, "C:\\a\\readme.md");
        assert_eq!(result.files_to_move[1].full_path, "C:\\e\\other.txt");
        // 3 duplicates skipped
        assert_eq!(result.skipped_files.len(), 3);
        for skipped in &result.skipped_files {
            assert!(matches!(skipped.reason, SkipReason::DuplicateName));
        }
    }

    #[test]
    fn test_filter_files_already_at_destination_not_counted_as_duplicate() {
        // A file at the destination should NOT poison the seen_names set.
        // A different source file with the same name should still be considered
        // for moving (subject to force/exists checks).
        let destination = PathBuf::from("C:\\dest");
        let files = vec![
            make_file_entry("shared.txt", "C:\\dest\\shared.txt", 100),
            make_file_entry("shared.txt", "C:\\incoming\\shared.txt", 200),
            make_file_entry("unique.txt", "C:\\incoming\\unique.txt", 300),
        ];

        // Without force: incoming/shared.txt would be caught by exists-at-dest
        // if the directory existed, but since C:\dest doesn't really exist on
        // disk, the exists() check returns false and the file passes through.
        let result = filter_files(&files, &destination, false);
        assert_eq!(result.already_at_destination, 1);
        // incoming/shared.txt passes (not a seen_names duplicate, dest doesn't exist on disk)
        // unique.txt passes
        assert_eq!(result.files_to_move.len(), 2);
        assert!(result.skipped_files.is_empty());
    }

    // --- get_available_space tests ---

    #[test]
    fn test_get_available_space_temp_dir() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let available = get_available_space(temp_dir.path()).expect("failed to get available space");
        // Any real filesystem should report some available space
        assert!(available > 0, "Available space should be greater than 0");
    }

    #[test]
    fn test_get_available_space_root_drive() {
        // The current directory's drive root should always be accessible
        let current_dir = std::env::current_dir().expect("failed to get current dir");
        let available = get_available_space(&current_dir).expect("failed to get available space");
        assert!(
            available > 0,
            "Available space on current drive should be greater than 0"
        );
    }

    // --- check_disk_space tests ---

    #[test]
    fn test_check_disk_space_sufficient() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        // Requesting 1 byte should always succeed on a real filesystem
        let result = check_disk_space(temp_dir.path(), 1);
        assert!(result.is_ok(), "1 byte should fit on any filesystem");
    }

    #[test]
    fn test_check_disk_space_zero_bytes() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let result = check_disk_space(temp_dir.path(), 0);
        assert!(result.is_ok(), "0 bytes required should always succeed");
    }

    #[test]
    fn test_check_disk_space_insufficient() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        // Request an absurdly large amount that no disk could have
        let result = check_disk_space(temp_dir.path(), u64::MAX);
        assert!(result.is_err(), "u64::MAX bytes should exceed any disk");

        let error_message = result.unwrap_err().to_string();
        assert!(
            error_message.contains("Not enough disk space"),
            "Error should mention insufficient disk space, got: {error_message}"
        );
        assert!(error_message.contains("Required"), "Error should show required space");
        assert!(error_message.contains("Available"), "Error should show available space");
        assert!(error_message.contains("Shortfall"), "Error should show shortfall");
    }

    #[test]
    fn test_check_disk_space_exactly_available() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let available = get_available_space(temp_dir.path()).expect("failed to get available space");
        // Requesting exactly what's available should succeed
        let result = check_disk_space(temp_dir.path(), available);
        assert!(result.is_ok(), "Requesting exactly the available space should succeed");
    }

    #[test]
    fn test_check_disk_space_one_over_available() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let available = get_available_space(temp_dir.path()).expect("failed to get available space");
        // Requesting one byte more than available should fail
        let result = check_disk_space(temp_dir.path(), available + 1);
        assert!(result.is_err(), "Requesting one byte more than available should fail");
    }
}
