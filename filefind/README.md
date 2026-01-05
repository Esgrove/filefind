# filefind

Shared library for the filefind file indexing and search system.

This crate provides common functionality used by all other filefind crates:

- **Configuration** - User configuration file handling (`~/.config/filefind.toml`)
- **Database** - SQLite database operations for file index storage
- **IPC** - Inter-process communication for daemon control (named pipes on Windows)
- **Types** - Common data structures and type definitions
- **Utilities** - Path classification, formatting helpers, and logging utilities

## Usage

This crate is not intended to be used directly. Instead, use one of the following:

- [`filefind-cli`](../filefind-cli) - Command-line search interface
- [`filefind-daemon`](../filefind-daemon) - Background indexing service
- [`filefind-tray`](../filefind-tray) - System tray application

## Modules

### `config`

Handles user configuration loading and defaults:

- `UserConfig` - Root configuration structure
- `DaemonConfig` - Daemon-specific settings (paths, exclusions, logging)
- `CliConfig` - CLI-specific settings (output format, colors)

### `database`

SQLite database operations:

- File and directory entry storage
- Volume tracking with serial numbers
- Fast indexed search by filename
- Support for glob patterns and regex searches

### `ipc`

Inter-process communication:

- Named pipe client for Windows
- Commands: stop, status, rescan, pause, resume, ping
- Serialization using postcard (binary format)

### `types`

Common data structures:

- `FileEntry` - Represents an indexed file or directory
- `VolumeInfo` - Information about indexed volumes

### Utilities

Path and formatting helpers:

- `PathType` enum for classifying paths (drive root, directory, UNC, network)
- `format_size()` - Human-readable file sizes
- `format_number()` - Number formatting with separators
- Print macros for colored terminal output
