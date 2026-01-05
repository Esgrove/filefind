# filefind-daemon

Background file indexing service for the filefind system.

This daemon monitors file systems and keeps the file index up to date using:

- **NTFS MFT scanning**: Direct Master File Table reading for fast initial indexing
- **USN Journal monitoring**: Efficient incremental change detection for NTFS drives
- **File system watching**: Fallback for non-NTFS and network drives

## Features

- Index millions of files in seconds using MFT direct reading
- Real-time updates via USN Journal monitoring
- Support for full drives, specific directories, and network paths
- Background operation with IPC control interface
- Configurable exclusions and logging

## Usage

```
Background file indexing daemon for filefind

Usage: filefindd.exe [OPTIONS] [COMMAND]

Commands:
  start    Start the daemon and begin indexing
  stop     Stop the daemon
  status   Check daemon status
  scan     Perform a one-time scan without starting the daemon
  stats    Show index statistics
  volumes  List indexed volumes
  detect   Detect available drives and their types
  reset    Delete the database and start fresh
  help     Print this message or the help of the given subcommand(s)

Options:
  -C, --completion <SHELL>
          Generate shell completion

          [possible values: bash, elvish, fish, powershell, zsh]

  -l, --log <LOG_LEVEL>
          Set the log level

          Possible values:
          - error: Error messages only
          - warn:  Warnings and errors
          - info:  Informational messages
          - debug: Debug messages
          - trace: Trace messages

  -v, --verbose
          Print verbose output

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

### Subcommands

#### start

Start the daemon and begin indexing:

```
Usage: filefindd.exe start [OPTIONS]

Options:
  -f, --foreground  Run in foreground instead of daemonizing
  -r, --rescan      Force a full rescan of all volumes
```

#### scan

Perform a one-time scan without starting the daemon:

```
Usage: filefindd.exe scan [OPTIONS] [PATH]

Arguments:
  [PATH]  Specific path to scan (defaults to all configured drives)

Options:
  -f, --force  Force a full rescan even if already indexed
```

#### volumes

List indexed volumes:

```
Usage: filefindd.exe volumes [OPTIONS]

Options:
  -d, --detailed  Show detailed information
```

#### reset

Delete the database and start fresh:

```
Usage: filefindd.exe reset [OPTIONS]

Options:
  -f, --force  Skip confirmation prompt
```

## Examples

```shell
# Start daemon in background
filefindd start

# Start in foreground (for debugging)
filefindd start -f

# Start with forced full rescan
filefindd start -r

# Check daemon status
filefindd status

# Stop the daemon
filefindd stop

# One-time scan of all configured paths
filefindd scan

# Scan a specific directory
filefindd scan "D:\Projects"

# Show index statistics
filefindd stats

# List indexed volumes
filefindd volumes
filefindd volumes --detailed

# Detect available drives
filefindd detect

# Reset database
filefindd reset
filefindd reset --force
```

## Configuration

Daemon settings can be configured in `~/.config/filefind.toml`:

```toml
[daemon]
# Paths to index (drives, directories, or network locations)
# If empty, all available local NTFS drives will be auto-detected
paths = ["C:", "D:", "E:\\Photos"]

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

# Database location (default: ~/.local/share/filefind/filefind.db)
# database_path = ""
```

## Path Types

The daemon supports multiple path types:

| Path Type            | Example              | Scanning Method                      |
| -------------------- | -------------------- | ------------------------------------ |
| Drive root           | `C:`, `D:`           | Fast MFT scanning                    |
| Local directory      | `C:\Users\Documents` | MFT scanning (filtered)              |
| Mapped network drive | `Z:`                 | MFT attempted, falls back to walking |
| UNC path             | `\\server\share`     | Directory walking                    |

## Requirements

- Windows 10/11
- Administrator privileges (required for MFT and USN Journal access)

## Architecture

### MFT Reading

On NTFS drives, the daemon reads the Master File Table directly from disk, bypassing Windows file system APIs. This allows indexing millions of files in seconds.

### USN Journal Monitoring

After the initial scan, the daemon monitors the NTFS Update Sequence Number Journal to efficiently detect file system changes without rescanning.

### File System Watcher

For non-NTFS drives and network paths, the daemon falls back to the `notify` crate using `ReadDirectoryChangesW` on Windows for real-time change notifications.

### IPC Server

The daemon runs an IPC server (named pipes on Windows) to accept commands from the CLI and tray application:

- `stop` - Shut down the daemon
- `status` - Get current daemon status
- `rescan` - Trigger a full rescan
- `pause` / `resume` - Pause/resume monitoring
- `ping` - Health check

## Logging

In foreground mode, logs are written to stdout.
In background mode, logs are written to rolling files in `~/logs/filefind/` with daily rotation.
