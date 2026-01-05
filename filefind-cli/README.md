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

## Usage

```
Fast file search using the filefind index

Usage: filefind.exe [OPTIONS] [PATTERNS]... [COMMAND]

Commands:
  stats       Show index statistics
  volumes     List all indexed volumes
  completion  Generate shell completion scripts
  help        Print this message or the help of the given subcommand(s)

Arguments:
  [PATTERNS]...
          Search patterns (supports glob patterns like *.txt)

Options:
  -r, --regex
          Use regex pattern for search

  -c, --case
          Case-sensitive search

  -d, --drive <DRIVE>
          Search only in specific drives. Accepts: "C", "C:", or "C:\"

  -f, --files
          Only show files

  -D, --dirs
          Only show directories

  -n, --limit <COUNT>
          Maximum number of files to show per directory

          [default: 20]

  -o, --output <OUTPUT>
          Output format

          Possible values:
          - simple:  Simple list of paths without type or size information
          - grouped: Files grouped by directory (default)

  -v, --verbose
          Print verbose output

  -e, --exact
          Exact pattern matches only

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
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
Usage: filefind.exe volumes
```

#### completion

Generate shell completion scripts:

```
Usage: filefind.exe completion [OPTIONS] <SHELL>

Arguments:
  <SHELL>  Shell to generate completion for [possible values: bash, elvish, fish, powershell, zsh]

Options:
  -I, --install  Install the completion script to the appropriate location
```

## Examples

```shell
# Basic search (auto-expands patterns)
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

# Limit files shown per directory
filefind -n 10 "*.txt"

# Show index statistics
filefind stats

# List all indexed volumes
filefind volumes

# Generate shell completion
filefind completion powershell > _filefind.ps1
filefind completion bash > filefind.bash

# Install shell completion to standard location
filefind completion powershell --install
filefind completion bash --install
```

## Pattern Expansion

When searching without glob or regex mode, filefind automatically expands dot-separated patterns:

- `some.name` → searches for "some.name", "some name", and "somename"

This helps match files regardless of naming convention.
Use `-e | --exact` mode to disable this behavior.

## Configuration

CLI settings can be configured in `~/.config/filefind.toml`:

```toml
[cli]
# Default output format: "simple" or "grouped"
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
