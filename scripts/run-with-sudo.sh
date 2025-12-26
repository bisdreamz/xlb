#!/bin/sh
# Wrapper to execute binaries under sudo by default. Set XLB_DISABLE_SUDO=1 to run without sudo.

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
