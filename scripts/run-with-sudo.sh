#!/bin/sh
# Workspace runner for binaries that may load and attach XDP.
# Set XLB_DISABLE_SUDO=1 for host-side tests and other unprivileged commands.

# Skip sudo for xtask (doesn't need elevated privileges)
case "$1" in
    */xtask)
        exec "$@"
        ;;
esac

if [ "${XLB_DISABLE_SUDO:-0}" = "1" ]; then
    exec "$@"
fi

# Try running under sudo when available and permitted.
if command -v sudo >/dev/null 2>&1; then
    exec sudo -E "$@"
fi

exec "$@"
