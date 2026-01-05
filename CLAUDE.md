# CLAUDE.md

## Project Overview

Filefind is a fast file indexing and search tool for Windows.
It uses NTFS Master File Table (MFT) direct reading for extremely fast initial scans,
and the USN Journal for efficient incremental change detection.

The project is organized as a Cargo workspace with multiple crates:

- `filefind` - Shared library (config, database, types, IPC)
- `filefind-daemon` - Background service that monitors file changes
- `filefind-cli` - Command-line search tool
- `filefind-tray` - System tray application for daemon control

## Build and Test Commands

After making code changes, always run:

```shell
cargo clippy --fix --allow-dirty
cargo fmt
cargo test
```

### Other commands

```shell
# Build all crates
cargo build

# Build a specific crate
cargo build -p filefind-cli

# Format code
cargo fmt

# Run tests for a specific crate
cargo test -p filefind
```

## Project Structure

- `filefind/` - Shared library code
    - `src/lib.rs` - Library root, re-exports, path utilities
    - `src/config.rs` - User configuration file handling
    - `src/database.rs` - SQLite database operations
    - `src/ipc.rs` - Inter-process communication for daemon control
    - `src/types.rs` - Common types and structures
- `filefind-daemon/` - Background file monitoring service
    - `src/main.rs` - Daemon entry point, CLI argument handling
    - `src/daemon.rs` - Core daemon logic and lifecycle
    - `src/ipc_server.rs` - IPC server for handling client commands
    - `src/mft.rs` - NTFS MFT reading
    - `src/scanner.rs` - File scanning logic (MFT and directory walking)
    - `src/usn.rs` - USN Journal monitoring
    - `src/watcher.rs` - File system watcher for non-NTFS drives
- `filefind-cli/` - Command-line search interface
    - `src/main.rs` - CLI entry point and search logic
    - `src/config.rs` - CLI configuration merging (user config + CLI args)
- `filefind-tray/` - System tray application
    - `src/main.rs` - Tray app entry point
    - `src/app.rs` - Main application logic and event loop
    - `src/icons.rs` - Tray icon generation

## Code Organization

All Rust source files should be organized in this order:

1. Structs (public before private)
2. Enums (public before private)
3. Trait implementations and impl blocks (in the order structs/enums are defined)
4. Public functions
5. Private functions
6. Tests module

Within implementation blocks:

- Public methods before private methods
- Associated functions (those without `self` parameter) last

## Code Style and Conventions

- Uses Rust 2024 edition
- Clippy is configured with pedantic and nursery lints enabled
- Do not use plain unwrap. Use proper error handling or `.expect()` in constants and test cases.
- Use `anyhow` for error handling with `Result<T>` return types
- Use `clap` with derive macros for CLI argument parsing
- Use `colored` crate for terminal output coloring
- Use descriptive variable and function names. No single character variables.
- Prefer full names over abbreviations. For example: `directories` instead of `dirs`.
- Create docstrings for structs and functions.
- Avoid trailing comments.

## Configuration

User configuration is read from `~/.config/filefind.toml`.
See `filefind.toml` in the repo root for an example.
Remember to update the example config file when adding new config options.

### Daemon Configuration Options

- `paths` - Drives, directories, or network paths to index
- `exclude` - Directories to exclude from indexing
- `exclude_patterns` - Glob patterns for files to exclude
- `scan_interval` - Rescan interval for non-NTFS drives (seconds)
- `log_level` - Log level: error, warn, info, debug, trace
- `verbose` - Enable verbose output
- `database_path` - Custom database file location

### CLI Configuration Options

- `format` - Output format: "simple" or "grouped"
- `max_results` - Maximum results to show
- `color` - Enable colored output
- `case_sensitive` - Case-sensitive search by default
- `show_hidden` - Show hidden files in results

## Architecture Notes

### MFT Reading (NTFS drives)

- Requires administrator privileges
- Reads Master File Table directly for fast initial indexing
- Can index millions of files in seconds
- Works with both full drives and specific directories

### USN Journal (NTFS drives)

- Tracks file system changes efficiently
- Query "what changed since USN X" instead of rescanning
- Handles creates, deletes, renames, modifications

### File Watcher (non-NTFS/network drives)

- Falls back to `notify` crate (ReadDirectoryChangesW on Windows)
- Traditional directory walking for initial scan
- Real-time change notifications

### Path Types

The daemon supports multiple path types:

- **Drive roots** (e.g., "C:", "D:") - Fast MFT scanning for entire drive
- **Local directories** (e.g., "C:\\Users\\Documents") - MFT scanning filtered to path
- **Mapped network drives** (e.g., "Z:") - MFT attempted first, falls back to walking
- **UNC paths** (e.g., "\\\\server\\share") - Directory walking (no drive letter)

### Database

- SQLite for persistent storage
- Indexed by filename for fast searches
- Tracks volume serial numbers to handle drive reconnection

### IPC (Inter-Process Communication)

- Named pipes on Windows for daemon communication
- Unix domain sockets on other platforms
- JSON-serialized commands and responses
- Supports: stop, status, rescan, pause, resume, ping

The IPC system has two parts:

- **Client** (`filefind/src/ipc.rs`): Used by CLI and tray app to send commands
- **Server** (`filefind-daemon/src/ipc_server.rs`): Runs in daemon, handles incoming commands

The server runs in a dedicated thread and communicates with the main daemon loop via tokio channels.
Shared state (`IpcServerState`) uses atomic types to safely share status information between threads.

### CLI Search Features

- **Pattern expansion**: Dot-separated patterns like "some.name" automatically expand to also search "some name" and "somename"
- **Glob patterns**: Supports `*` and `?` wildcards
- **Regex search**: Full regex support with `-r` flag
- **Exact matching**: Disable pattern expansion with `-e` flag

### System Tray Application

- Minimal UI for daemon control
- Shows daemon status via icon color (green=running, gray=stopped, orange=scanning)
- Menu items: Start, Stop, Rescan, Open CLI, Quit
- Tooltip shows indexed file/directory counts
