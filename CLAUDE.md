# CLAUDE.md

## Project Overview

Filefind is a fast file indexing and search tool for Windows.
It uses NTFS Master File Table (MFT) direct reading for extremely fast initial scans,
and the USN Journal for efficient incremental change detection.

The project is organized as a Cargo workspace with multiple crates:

- `filefind` - Shared library (config, database, types)
- `filefind-daemon` - Background service that monitors file changes
- `filefind-cli` - Command-line search tool

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

# Build release binaries
cargo build --release

# Build a specific crate
cargo build -p filefind-cli

# Run the CLI
cargo run -p filefind-cli -- [args]

# Run the daemon
cargo run -p filefind-daemon -- [args]

# Detect available NTFS volumes
cargo run -p filefind-daemon -- detect

# Scan all NTFS drives
cargo run -p filefind-daemon -- scan

# Scan a specific path
cargo run -p filefind-daemon -- scan C:\Users

# Format code
cargo fmt

# Run tests for a specific crate
cargo test -p filefind
```

## Project Structure

- `filefind/` - Shared library code
    - `src/lib.rs` - Library root, re-exports
    - `src/config.rs` - User configuration file handling
    - `src/database.rs` - SQLite database operations
    - `src/types.rs` - Common types and structures
- `filefind-daemon/` - Background file monitoring service
    - `src/main.rs` - Daemon entry point
    - `src/mft.rs` - NTFS MFT reading
    - `src/usn.rs` - USN Journal monitoring
    - `src/watcher.rs` - File system watcher for non-NTFS drives
- `filefind-cli/` - Command-line search interface
    - `src/main.rs` - CLI entry point

## Code Organization

- Put all struct definitions before their implementations
- Functions after implementations
- In implementations, order public methods before private methods
- In implementations, put associated functions last

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

## Architecture Notes

### MFT Reading (NTFS drives)

- Requires administrator privileges
- Reads Master File Table directly for fast initial indexing
- Can index millions of files in seconds

### USN Journal (NTFS drives)

- Tracks file system changes efficiently
- Query "what changed since USN X" instead of rescanning
- Handles creates, deletes, renames, modifications

### File Watcher (non-NTFS/network drives)

- Falls back to `notify` crate (ReadDirectoryChangesW on Windows)
- Traditional directory walking for initial scan
- Real-time change notifications

### Database

- SQLite for persistent storage
- Indexed by filename for fast searches
- Tracks volume serial numbers to handle drive reconnection
