# filefind-cli

Command-line interface for searching the filefind file index.

This is the main user-facing tool for searching files indexed by the filefind daemon.

## Features

- **Fast search**: Query millions of indexed files instantly
- **Case insensitive**: Case-insensitive search by default with option to enable case-sensitive search
- **Glob patterns**: Support for `*` and `?` wildcards
- **Regex search**: Full regular expression support
- **Pattern expansion**: Automatically expands "some.name" to also search "some name" and "somename"
- **Multiple patterns**: Search with multiple patterns.
  Defaults to logical OR search to match any single pattern with option to match all patterns (logical AND)
- **Multiple display modes**: Grouped, list, name-only, and info output formats
- **Sorting**: Sort results by name or file size
- **File moving**: Move matching files to a directory with `--move`, with progress bar, disk space checks, and graceful abort

## Usage

```
Command-line interface for filefind file search

Usage: filefind.exe [OPTIONS] [PATTERNS]... [COMMAND]

Commands:
  stats       Show index statistics
  volumes     List all indexed volumes
  completion  Generate shell completion scripts
  help        Print this message or the help of the given subcommand(s)

Arguments:
  [PATTERNS]...  Search patterns (supports glob patterns like *.txt)

Options:
  -a, --all              Match all patterns (logical AND)
  -r, --regex            Use regex pattern for search
  -c, --case             Case-sensitive search
  -d, --drive <DRIVE>    Search only in specific drives. Accepts: "C", "C:", or "C:\"
  -f, --files            Only show files
  -D, --dirs             Only show directories
  -m, --move <DIR>       Move all matching files to the specified directory
  -F, --force            Force overwrite existing files at the move destination
  -n, --limit <COUNT>    Maximum number of files to show per directory [default: 20]
  -o, --output <OUTPUT>  Output format [possible values: list, name, grouped, info]
  -l, --list             List output (shortcut for --output list)
  -N, --name             Name-only output (shortcut for --output name)
  -s, --sort <SORT>      Sort results by this field [possible values: name, size]
  -i, --info             Info output with file sizes (shortcut for --output info)
  -v, --verbose          Print verbose output
  -e, --exact            Exact pattern matches only
  -h, --help             Print help (see more with '--help')
  -V, --version          Print version
```

### Subcommands

#### stats

Show index statistics:

```
Usage: filefind.exe stats
```

#### volumes

List all indexed volumes:

```
List all indexed volumes

Usage: filefind.exe volumes [OPTIONS]

Options:
  -s, --sort [<SORT>]  Sort volumes by this field [possible values: name, size, files]
  -h, --help           Print help (see more with '--help')
```

#### completion

Generate shell completion scripts:

```
Generate shell completion scripts

Usage: filefind.exe completion [OPTIONS] <SHELL>

Arguments:
  <SHELL>  Shell to generate completion for [possible values: bash, elvish, fish, powershell, zsh]

Options:
  -I, --install  Install the completion script to the appropriate location
  -h, --help     Print help
```

## Display Modes

The CLI supports four output formats, selectable with `-o <FORMAT>` or shortcut flags:

| Format    | Flag      | Description                         |
| --------- | --------- | ----------------------------------- |
| `grouped` | (default) | Files grouped by parent directory   |
| `list`    | `-l`      | Simple list of full paths           |
| `name`    | `-N`      | File names only, without full paths |
| `info`    | `-i`      | Paths with file sizes               |

```shell
# Grouped output (default) — files organized under their parent directory
filefind "*.mp4"

# List output — one full path per line, no decoration
filefind -l "*.mp4"
filefind -o list "*.mp4"

# Name-only output — just filenames, no directory paths
filefind -N "*.mp4"
filefind -o name "*.mp4"

# Info output — paths with file sizes
filefind -i "*.mp4"
filefind -o info "*.mp4"
```

## Examples

```shell
# Basic search (auto-expands patterns: "some.name" also searches "some name" and "somename")
filefind "document.pdf"

# Multiple patterns (OR — match any pattern)
filefind "*.mp4" "*.mkv" "*.avi"

# Multiple patterns (AND — match all patterns)
filefind -a "report" "2024"

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

# Sort results by size (largest first)
filefind -s size "*.mp4"

# Limit files shown per directory
filefind -n 10 "*.txt"

# Move matching files to a directory
filefind "*.mp4" --move D:\Videos

# Move with force overwrite
filefind "*.mp4" --move D:\Videos --force

# Show index statistics
filefind stats

# List all indexed volumes
filefind volumes

# List volumes sorted by size
filefind volumes --sort size

# Generate shell completion
filefind completion powershell
filefind completion bash

# Install shell completion to standard location
filefind completion powershell --install
filefind completion bash --install
```

## Move Feature

The `--move <DIR>` option moves all matching **files** (not directories) to the
specified destination directory after displaying the normal search results.

### Move behavior

- **Confirmation prompt**: A summary of the move plan is shown before any files
  are touched (file count, total size, skipped files). You must confirm with `y`.
- **Same-device moves** use `fs::rename` (atomic and instant).
- **Cross-device moves** (e.g., local drive → network share) fall back to
  chunked copy + size verification + delete. The original is only deleted after
  the copy is verified.
- **Disk space check**: Only cross-device files are counted against free space.
  Same-device renames consume no additional disk space.
- **Progress bar** shows bytes transferred, ETA, and current filename.
- **Ctrl+C** finishes the current file then stops. Press Ctrl+C a second time
  to force-quit immediately.
- **Database update**: After each successful move the file index is updated with
  the new path.

### Conflict handling

- **Duplicate filenames** in the search results: only the first occurrence is
  moved; the rest are skipped and reported.
- **File already exists** at the destination: skipped unless `--force` is given.
- **File already in the destination directory**: silently counted, not moved or
  reported as a skip.

## Pattern Expansion

When searching without glob or regex mode, filefind automatically expands dot-separated patterns:

- `some.name` → searches for "some.name", "some name", and "somename"

This helps match files regardless of naming convention.
Use `-e | --exact` mode to disable this behavior.

## Configuration

CLI settings can be configured in `~/.config/filefind.toml`:

```toml
[cli]
# Default output format:
#   "list"    - list of paths
#   "name"    - file names only (no full paths)
#   "grouped" - files grouped by directory (default)
#   "info"    - paths with file size
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

## Requirements

- The filefind daemon must be running and have indexed files
- Database file at `~/.local/share/filefind/filefind.db`
