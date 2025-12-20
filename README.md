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

# Check daemon status
filefindd status

# Stop the daemon
filefindd stop
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
- **Menu options**: Start, Stop, Rescan, Open CLI, Quit

The tray application can be added to Windows startup the same way as the daemon.

### Search for files

```shell
# Basic search
filefind "document.pdf"

# Glob pattern search
filefind "*.mp4"

# Regex search
filefind -r "IMG_\d{4}\.jpg"

# Search in specific drives
filefind -d C -d D "project"

# Show only files
filefind -f "config.toml"

# Show only directories
filefind -D "projects"

# Detailed output with file sizes
filefind -o detailed "*.mp4"
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
# Default output format: "simple" or "detailed"
format = "simple"

# Maximum number of results to show
max_results = 100

# Enable colored output
color = true
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

## Requirements

- Windows 10/11
- Administrator privileges (required for MFT and USN Journal access)

## License

MIT
