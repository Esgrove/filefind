#!/bin/bash
set -eo pipefail

# Install the Rust binaries to path.

# Import common functions
DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=./common.sh
source "$DIR/common.sh"

if [ -z "$(command -v cargo)" ]; then
    print_error_and_exit "Cargo not found in path. Maybe install rustup?"
fi

print_magenta "Installing binaries..."
cd "$REPO_ROOT"

# Remove existing release binaries to force recompilation with current version number.
if [ -d "target/release" ]; then
    for executable in $(get_rust_executable_names); do
        rm -f "target/release/${executable}"
    done
fi

# Touch source files to ensure recompilation
find filefind filefind-cli filefind-daemon filefind-tray -name "*.rs" -exec touch {} \;

cargo install --force --path filefind-cli
cargo install --force --path filefind-daemon
cargo install --force --path filefind-tray
echo ""

print_green "Installed binaries:"
for executable in $(get_rust_executable_names); do
    if [ -z "$(command -v "$executable")" ]; then
        print_error_and_exit "Binary not found. Is the Cargo install directory in path?"
    fi
    echo "$($executable --version) from $(which "$executable")"
done
