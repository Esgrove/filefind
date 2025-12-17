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
- **Background daemon**: Runs quietly, keeping the index up-to-date

## Components

This project is organized as a Cargo workspace with multiple crates:

- **filefind-common**: Shared library with database schema, configuration, and utilities
- **filefind-daemon**: Background service that indexes and monitors file systems
- **filefind-cli**: Command-line interface for searching the file index

## Installation

### Build from source

```shell
# Build all binaries
./build.sh

# Install to Cargo bin directory
./install.sh
```

### Manual build

```shell
cargo build --release
```

## Usage

### Start the daemon

```shell
# Start indexing and monitoring
filefindd start

# Check daemon status
filefindd status

# Stop the daemon
filefindd stop
```

### Search for files

```shell
# Basic search
filefind "document.pdf"

# Glob pattern search
filefind "*.mp4"

# Regex search
filefind -r "IMG_\d{4}\.jpg"

# Search in specific drive
filefind -d D: "project"

# Show full paths
filefind -f "config.toml"
```

## Configuration

Configuration is read from `~/.config/filefind.toml`.

See `filefind.toml` in the repository root for an example configuration file.

```toml
[daemon]
# Drives to index (empty = all available NTFS drives)
drives = ["C:", "D:", "E:"]

# Directories to exclude from indexing
exclude = [
    "C:\\Windows",
    "C:\\$Recycle.Bin",
]

# Update interval for non-NTFS drives (seconds)
scan_interval = 3600

[cli]
# Default output format: "simple", "detailed", "json"
format = "simple"

# Maximum number of results to show
max_results = 100

# Enable colored output
color = true
```

## How it works

### NTFS Master File Table (MFT)

On NTFS drives, filefind reads the MFT directly from disk. The MFT is a special hidden file
that NTFS uses to track all files and folders. By reading it directly, we bypass the overhead
of Windows file system APIs and can scan millions of files in seconds.

### USN Journal

NTFS maintains a Update Sequence Number (USN) Journal that logs all file system changes.
Instead of periodically rescanning the entire drive, filefind monitors this journal to
efficiently detect new, modified, renamed, and deleted files.

### Non-NTFS drives

For network drives and non-NTFS file systems, filefind falls back to traditional directory
scanning with file system watchers for real-time updates.

## Requirements

- Windows 10/11
- Administrator privileges (required for MFT and USN Journal access)
- Rust 1.85+ (for building from source)

## License

MIT
