# filefind

Fast file indexing and search tool for Windows.

Uses NTFS Master File Table (MFT) direct reading for extremely fast initial indexing,
and USN Journal monitoring for efficient incremental updates.
Indexes millions of files in seconds and keeps the database updated in real-time.

## Features

- **Fast NTFS scanning**: Reads MFT directly, bypassing Windows file APIs
- **Real-time updates**: Monitors USN Journal for file changes
- **Network drive support**: Falls back to traditional scanning for non-NTFS drives
- **Instant search**: Query millions of indexed files instantly
- **Flexible search**: Supports glob patterns, regex, and fuzzy matching
- **Smart pattern expansion**: Automatically searches for "some.name", "some name", and "somename"
- **Background daemon**: Runs quietly, keeping the index up-to-date
- **File moving**: Move matching files to a directory with progress, disk space checks, and graceful abort
- **Clickable results**: Result paths are terminal hyperlinks that open in the default application

## Components

This project is organized as a Cargo workspace with multiple crates:

- **filefind**: Shared library with database schema, configuration, and utilities
- **filefind-daemon**: Background service that indexes and monitors file systems
- **filefind-cli**: Command-line interface for searching the file index
- **filefind-tray**: System tray application for daemon control

## Installation

### Build from source

```shell
# Build all binaries
./build.sh

# Install to Cargo bin directory
./install.sh
```

## Usage

### Daemon

```shell
# Start in background (spawns detached process)
filefindd start

# Start in foreground (stays attached to terminal)
filefindd start -f

# Start with forced full rescan
filefindd start -r

# Check daemon status
filefindd status

# Stop the daemon
filefindd stop

# Trigger a rescan of all volumes
filefindd scan

# Scan a specific path
filefindd scan "D:\Projects"

# Force a clean scan (delete existing entries before inserting new ones)
filefindd scan --force

# Show index statistics
filefindd stats

# List indexed volumes
filefindd volumes
filefindd volumes --detailed

# Detect available drives and their types
filefindd detect

# Reset (delete) the database
filefindd reset
```

### CLI

Search for files

```shell
# Basic search (auto-expands patterns: "some.name" also searches "some name" and "somename")
filefind "document.pdf"

# Glob pattern search
filefind "*.mp4"

# Regex search
filefind -r "IMG_\d{4}\.jpg"

# Exact pattern matching (disable auto-expansion)
filefind -e "some.name"

# Case-sensitive search
filefind -c "README"

# Search in specific drives
filefind -d C -d D "project"

# Show only files
filefind -f "config.toml"

# Show only directories
filefind -D "projects"

# Move matching files to a directory (matches already under it stay in place)
filefind "*.mp4" --move D:\Videos

# Move with force overwrite of existing files
filefind "*.mp4" --move D:\Videos --force

# List output — one full path per line
filefind -l "*.mp4"
filefind -o list "*.mp4"

# Name-only output — just filenames, no directory paths
filefind -N "*.mp4"
filefind -o name "*.mp4"

# Info output — paths with file sizes
filefind -i "*.mp4"
filefind -o info "*.mp4"

# Limit files shown per directory
filefind -n 10 "*.txt"

# Force clickable hyperlinks even when the output is piped or redirected
filefind -L always "*.mp4"

# Disable clickable hyperlinks
filefind -L never "*.mp4"

# Show index statistics
filefind stats

# List all indexed volumes
filefind volumes

# Generate shell completion (bash, zsh, fish, powershell)
filefind completion powershell
filefind completion bash

# Install shell completion to standard location
filefind completion powershell --install
filefind completion bash --install
```

### System tray application

The tray application provides a convenient way to control the daemon from the system tray:

```shell
# Start the tray application
filefind-tray
```

Features:

- **Status indicator**: Icon color shows daemon state (green=running, gray=stopped, orange=scanning)
- **Tooltip**: Shows indexed file and directory counts
- **Menu options**: Start, Stop, Rescan, About, Quit

The tray application can be added to Windows startup the same way as the daemon.

## Configuration

Configuration is read from `~/.config/filefind.toml`.

See `filefind.toml` in the repository root for an example configuration file.

```toml
[daemon]
# Paths to index (drives, directories, or network locations).
#
# Can include:
# - Drive letters (e.g., "C:", "D:") - indexes entire drive using fast NTFS MFT scanning
# - Specific directories (e.g., "C:\\Users", "D:\\Projects") - uses MFT scanning but
#   only stores entries under the specified paths (fast AND selective)
# - Mapped network drives (e.g., "Z:") - MFT scanning is attempted first; if not
#   available (most NAS devices), falls back to directory walking automatically
# - UNC paths (e.g., "\\\\server\\share") - uses directory walking (no drive letter)
#
# If empty or not specified, all available local NTFS drives will be auto-detected.
# Network drives are NOT auto-detected - add them explicitly if needed.
paths = ["C:", "D:", "E:"]

# Directories to exclude from indexing (case-insensitive).
# Plain entries match whole path components: "Epic" skips "D:\Games\Epic\..."
# but not "D:\Videos\EpicTrailer.mp4". Use "*text*" to match any substring.
exclude = [
    "C:\\Windows",
    "C:\\$Recycle.Bin",
    "C:\\System Volume Information",
]

# File patterns to exclude (glob syntax)
exclude_patterns = ["*.tmp", "~$*", "Thumbs.db"]

# Rescan interval for non-NTFS/network drives in seconds
scan_interval_seconds = 3600

# Log level: "error", "warn", "info", "debug", "trace"
log_level = "info"

# Force clean scan (delete existing entries before inserting new ones).
# When false (default), uses incremental scan with USN-based cleanup for NTFS.
# Clean scan is always performed automatically if the database is empty.
# force_clean_scan = false

[cli]
# Default output format: "simple" (list of paths) or "grouped" (files grouped by directory)
format = "grouped"

# Maximum number of results to show (0 = unlimited)
max_results = 100

# Enable colored output
color = true

# Case-sensitive search by default
case_sensitive = false

# Show hidden files in results
show_hidden = false

# Emit clickable terminal hyperlinks for result paths: "auto", "always", or "never"
hyperlinks = "auto"

# URI scheme used for terminal hyperlinks
hyperlink_scheme = "file"
```

## How it works

### NTFS Master File Table (MFT)

On NTFS drives, filefind reads the MFT directly from disk.
The MFT is a special hidden file that NTFS uses to track all files and folders.
By reading it directly,
we bypass the overhead of Windows file system APIs and can scan millions of files in seconds.

### USN Journal

NTFS maintains a Update Sequence Number (USN) Journal that logs all file system changes.
Instead of periodically rescanning the entire drive,
filefind monitors this journal to efficiently detect new, modified, renamed, and deleted files.

### Non-NTFS drives

For network drives and non-NTFS file systems,
filefind falls back to traditional directory scanning with file system watchers for real-time updates.

### Pattern Expansion

When searching without glob or regex mode, filefind automatically expands dot-separated patterns.
For example, searching for "some.name" will also find "some name" and "somename".
This helps match files regardless of naming convention. Use `-e` (exact) mode to disable this.

### Clickable Results

Result paths are wrapped in OSC 8 terminal hyperlinks.
Ctrl+Click (Windows Terminal, Warp) or Cmd+Click (iTerm2)
opens the file with the application the operating system associates with its type,
and directories open in the file manager.
To always open videos in VLC, for example, associate the video file types with VLC in the operating system,
or register a custom protocol handler and set `hyperlink_scheme` to it.

Links are only emitted when the output goes to a terminal that is known to support them,
so piped and redirected output stays free of escape sequences.
Use `-L always` to force links (for example when paging with `less -R`)
and `-L never` when a terminal or multiplexer does not handle them.

## Requirements

- Windows 10/11
- Administrator privileges (required for MFT and USN Journal access)

## Development

### Code Coverage

Code coverage is generated using [cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov)
with [cargo-nextest](https://nexte.st/) as the test runner.

Install both tools:

```shell
cargo install cargo-llvm-cov cargo-nextest
```

Usage:

```shell
# Run tests with coverage (text summary)
cargo llvm-cov nextest

# Generate HTML report and open in browser
cargo llvm-cov nextest --open
```

### Database Benchmarks

The shared `filefind` crate has Criterion benchmarks for batch insertion, name/glob/regex search,
and duplicate detection using deterministic in-memory SQLite indexes.
Fixtures are built outside the measured search and duplicate operations.
Batch insertion uses a fresh in-memory database for each measurement.
No live index, filesystem scan, or administrator privileges are required.

```shell
cargo bench -p filefind --bench database -- --quick
cargo bench -p filefind --bench database
# Include an optional 1,000,000-row search and duplicates fixture:
$env:FILEFIND_BENCH_LARGE = '1'; cargo bench -p filefind --bench database
```

The default search and duplicate fixtures contain 10,000 and 100,000 rows.
Insert measurements use 1,000 and 10,000 rows.
Search queries return at most 100 rows, and duplicate fixtures vary the repeated-stem density.
Criterion writes HTML reports to `target/criterion/`.
For comparisons, run the standard benchmark on the same machine with the same fixture sizes.

An initial `--quick` run on an AMD Ryzen 9 7950X with a 100,000-row in-memory fixture measured approximately
7.3 ms for common-name search, 8.2 ms for glob search, 8.9 ms for regex search,
and 86 to 118 ms for duplicate detection depending on duplicate density.
These are local quick-run baselines, not performance targets or an optimization comparison.

## Index Recovery

Configured paths are scanned independently. An inaccessible directory is logged without interrupting scans of other paths.
Failed scans retain their previous entries and USN position, and the daemon retries reconciliation while it runs.
Watcher errors request a rescan; non-NTFS paths are also reconciled at `scan_interval_seconds` intervals.
On NTFS, live changes respect configured roots and exclusion patterns, including directories renamed out of scope.

Forced moves compare BLAKE3 hashes when a destination exists.
If both files are identical, the destination remains untouched and the source is removed after index reconciliation.
Moves into an indexed destination volume record its volume ID even when the destination file was not indexed.
An unindexed cross-volume destination is rejected rather than recording the wrong volume ID.

The elevated NTFS tests are ignored by default and operate only in disposable temporary directories.
From an elevated terminal on an NTFS volume, run:

```shell
cargo test -p filefind-daemon test_live_ -- --ignored
```

These tests inspect journal changes and expired cursors without resetting the system journal.
CI runs the full suite on Windows and portable database and directory-walk checks on Linux and macOS.
Filesystem and SQLite updates still cannot share a single atomic transaction: after a process crash,
an interrupted file move may require manual inspection of a preserved `.filefind-backup-*` directory.

## License

MIT
