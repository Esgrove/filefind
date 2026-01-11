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

### Start the daemon

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

### Auto-start on login (Windows Scheduled Task)

To have filefind start automatically when you log in, create a scheduled task:

1. Open Task Scheduler (`taskschd.msc`)
2. Click "Create Basic Task..."
3. Name: `filefind daemon`
4. Trigger: "When I log on"
5. Action: "Start a program"
6. Program: `C:\Users\<username>\.cargo\bin\filefindd.exe`
7. Arguments: `start -f`
8. Finish and optionally check "Open Properties" to:
    - Enable "Run with highest privileges" (required for MFT/USN access)
    - Under Conditions, uncheck "Start only if on AC power"

Or via PowerShell (run as Administrator):

```powershell
$action = New-ScheduledTaskAction -Execute "$env:USERPROFILE\.cargo\bin\filefindd.exe" -Argument "start -f"
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName "filefind daemon" -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest
```

The daemon can still be stopped anytime using `filefindd stop` or the tray application.

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

### Search for files

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

# Simple output (just paths)
filefind -o simple "*.mp4"

# Grouped output (files grouped by directory, default)
filefind -o grouped "*.mp4"

# Limit files shown per directory
filefind -n 10 "*.txt"

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

# Directories to exclude from indexing
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
```

## How it works

### NTFS Master File Table (MFT)

On NTFS drives, filefind reads the MFT directly from disk.
The MFT is a special hidden file that NTFS uses to track all files and folders.
By reading it directly,
we bypass the overhead of Windows file system APIs and can scan millions of files in seconds.

### USN Journal

NTFS maintains a Update Sequence Number (USN) Journal that logs all file system changes.
Instead of periodically rescanning the entire drive, filefind monitors this journal to
efficiently detect new, modified, renamed, and deleted files.

### Non-NTFS drives

For network drives and non-NTFS file systems,
filefind falls back to traditional directory scanning with file system watchers for real-time updates.

### Pattern Expansion

When searching without glob or regex mode, filefind automatically expands dot-separated patterns.
For example, searching for "some.name" will also find "some name" and "somename".
This helps match files regardless of naming convention. Use `-e` (exact) mode to disable this.

## Requirements

- Windows 10/11
- Administrator privileges (required for MFT and USN Journal access)

## License

MIT
