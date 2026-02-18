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
Filefind background file indexing daemon

Usage: filefindd.exe [OPTIONS] [COMMAND]

Commands:
  start       Start the daemon and begin indexing
  stop        Stop the running daemon
  status      Check daemon status
  scan        Perform a one-time scan without starting the daemon
  stats       Show index statistics
  volumes     List indexed volumes
  detect      Detect available drives and their types
  reset       Delete the database and start fresh
  prune       Remove database entries for files/directories that no longer exist
  completion  Generate shell completion scripts
  help        Print this message or the help of the given subcommand(s)

Options:
  -l, --log <LOG_LEVEL>  Set the log level [possible values: error, warn, info, debug, trace]
  -v, --verbose          Print verbose output
  -h, --help             Print help (see more with '--help')
  -V, --version          Print version
```

### Subcommands

#### start

Start the daemon and begin indexing:

```
Start the daemon and begin indexing

Usage: filefindd.exe start [OPTIONS]

Options:
  -f, --foreground       Run in foreground instead of daemonizing
  -r, --rescan           Force a full rescan of all volumes
  -l, --log <LOG_LEVEL>  Set the log level [possible values: error, warn, info, debug, trace]
  -v, --verbose          Print verbose output
  -h, --help             Print help (see more with '--help')
```

#### scan

Perform a one-time scan without starting the daemon:

```
Perform a one-time scan without starting the daemon

Usage: filefindd.exe scan [OPTIONS] [PATH]

Arguments:
  [PATH]  Specific path to scan (defaults to all configured drives)

Options:
  -f, --force            Force a clean scan (delete existing entries before inserting new ones)
  -l, --log <LOG_LEVEL>  Set the log level [possible values: error, warn, info, debug, trace]
  -v, --verbose          Print verbose output
  -h, --help             Print help (see more with '--help')
```

#### volumes

List indexed volumes:

```
List indexed volumes

Usage: filefindd.exe volumes [OPTIONS]

Options:
  -d, --detailed         Show detailed information
  -l, --log <LOG_LEVEL>  Set the log level [possible values: error, warn, info, debug, trace]
  -v, --verbose          Print verbose output
  -h, --help             Print help (see more with '--help')
```

#### reset

Delete the database and start fresh:

```
Delete the database and start fresh

Usage: filefindd.exe reset [OPTIONS]

Options:
  -f, --force            Skip confirmation prompt
  -l, --log <LOG_LEVEL>  Set the log level [possible values: error, warn, info, debug, trace]
  -v, --verbose          Print verbose output
  -h, --help             Print help (see more with '--help')
```

#### prune

Remove database entries for files/directories that no longer exist:

```
Remove database entries for files/directories that no longer exist

Usage: filefindd.exe prune [OPTIONS]

Options:
  -l, --log <LOG_LEVEL>  Set the log level [possible values: error, warn, info, debug, trace]
  -v, --verbose          Print verbose output
  -h, --help             Print help (see more with '--help')
```

#### completion

Generate shell completion scripts:

```
Generate shell completion scripts

Usage: filefindd.exe completion [OPTIONS] <SHELL>

Arguments:
  <SHELL>  Shell to generate completion for [possible values: bash, elvish, fish, powershell, zsh]

Options:
  -I, --install          Install the completion script to the appropriate location
  -l, --log <LOG_LEVEL>  Set the log level [possible values: error, warn, info, debug, trace]
  -v, --verbose          Print verbose output
  -h, --help             Print help (see more with '--help')
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

# Force a clean scan
filefindd scan --force

# Show index statistics
filefindd stats

# List indexed volumes
filefindd volumes
filefindd volumes --detailed

# Detect available drives
filefindd detect

# Remove stale database entries
filefindd prune

# Reset database
filefindd reset
filefindd reset --force

# Generate shell completion
filefindd completion powershell
filefindd completion bash --install
```

### Auto-start on login (Windows Scheduled Task)

To have filefind deamon start automatically when you log in, create a scheduled task:

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

The `-f` (foreground) flag is important here: it tells the daemon to run directly in the
calling process rather than spawning a detached child. Since the task scheduler already
manages the process lifecycle, this ensures proper logging and clean shutdown behavior.

The daemon can still be stopped anytime using `filefindd stop` or the tray application.

### Logging

In interactive foreground mode (terminal attached), logs are written to stdout.
When no terminal is detected (background mode, scheduled tasks, detached processes),
logs are written to rolling files in `~/logs/filefind/` with daily rotation.

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

## Network Drives

The daemon requires administrator privileges for NTFS MFT scanning.
By default, Windows does not make mapped network drives (e.g., `X:`, `Z:`) visible to elevated processes,
because drive mappings are tied to the non-elevated user session.

This means that if you have a network share mapped to `X:`,
the daemon running as admin won't be able to access it,
and you would have to use UNC paths like `\\192.168.1.106\Home` instead.
However, Windows does not always handle UNC paths correctly in shell operations.

### Enable mapped drives for elevated processes

Set the `EnableLinkedConnections` registry value so that
mapped network drives are shared between elevated and non-elevated sessions:

```powershell
# Run in an elevated PowerShell
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "EnableLinkedConnections" -Value 1 -PropertyType DWORD -Force
```

A **reboot is required** for the change to take effect.

After rebooting, you can use mapped drive letters directly in your daemon config:

```toml
[daemon]
paths = ["C:", "X:", "Z:"]
```

To verify the setting is active:

```powershell
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "EnableLinkedConnections"
```

To remove the setting:

```powershell
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "EnableLinkedConnections"
```

### Alternative: manual path mappings

If you prefer not to change the registry, you can use UNC paths for scanning
and configure `path_mappings` so the CLI displays results with drive letter paths:

```toml
[daemon]
paths = [
    "C:",
    "\\\\192.168.1.106\\Home",
    "\\\\192.168.1.107\\NAS\\Data",
]
path_mappings = [["\\\\192.168.1.106\\Home", "X"], ["\\\\192.168.1.107\\NAS\\Data", "Z"]]
```

The daemon scans via UNC paths (which work from elevated processes) and the database
stores the real UNC paths internally. The path mappings are applied at display time
by the CLI, so search results show `X:\file.txt` instead of `\\192.168.1.106\Home\file.txt`.

This keeps the database consistent with paths the daemon can actually access,
while giving you usable drive letter paths in search output.

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
