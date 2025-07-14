#!/bin/bash
#
# SeedPass Uninstaller for Linux and macOS
#
# Removes the SeedPass application files but preserves user data under ~/.seedpass

set -e

APP_ROOT_DIR="$HOME/.seedpass"
INSTALL_DIR="$APP_ROOT_DIR/app"
LAUNCHER_PATH="$HOME/.local/bin/seedpass"

print_info() { echo -e "\033[1;34m[INFO]\033[0m $1"; }
print_success() { echo -e "\033[1;32m[SUCCESS]\033[0m $1"; }
print_warning() { echo -e "\033[1;33m[WARNING]\033[0m $1"; }
print_error() { echo -e "\033[1;31m[ERROR]\033[0m $1"; }

# Remove any stale 'seedpass' executables that may still be on the PATH.
remove_stale_executables() {
    IFS=':' read -ra DIRS <<< "$PATH"
    for dir in "${DIRS[@]}"; do
        candidate="$dir/seedpass"
        if [ -f "$candidate" ] && [ "$candidate" != "$LAUNCHER_PATH" ]; then
            print_info "Removing old executable '$candidate'..."
            if rm -f "$candidate"; then
                rm_status=0
            else
                rm_status=$?
            fi
            if [ $rm_status -ne 0 ] && [ -f "$candidate" ]; then
                print_warning "Failed to remove $candidate – try deleting it manually"
            fi
        fi
    done
}

main() {
    if [ -d "$INSTALL_DIR" ]; then
        print_info "Removing installation directory '$INSTALL_DIR'..."
        rm -rf "$INSTALL_DIR"
    else
        print_info "Installation directory not found."
    fi


    if [ -f "$LAUNCHER_PATH" ]; then
        print_info "Removing launcher script '$LAUNCHER_PATH'..."
        rm -f "$LAUNCHER_PATH"
    else
        print_info "Launcher script not found."
    fi

    remove_stale_executables

    print_info "Attempting to uninstall any global 'seedpass' package with pip..."
    if command -v python3 &> /dev/null; then
        python3 -m pip uninstall -y seedpass >/dev/null 2>&1 || true
    elif command -v pip &> /dev/null; then
        pip uninstall -y seedpass >/dev/null 2>&1 || true
    fi
    if command -v pipx &> /dev/null; then
        pipx uninstall -y seedpass >/dev/null 2>&1 || true
    fi

    print_success "SeedPass uninstalled."
    print_warning "User data in '$APP_ROOT_DIR' was left intact."
}

main "$@"

