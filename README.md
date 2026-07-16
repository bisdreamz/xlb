# XLB - eBPF Layer 4 Load Balancer

XDP-native IPv4/TCP Layer 4 load balancer. UDP and IPv6 balancing are not yet implemented.

## Project Structure

- **xlb/** - Main userspace application (config, backend providers, eBPF loader, metrics)
- **xlb-common/** - Shared types between userspace and eBPF (`no_std` compatible)
- **xlb-ebpf/** - eBPF XDP kernel program (packet processing, connection tracking)

## Dependencies

```bash
# The eBPF build uses build-std and therefore requires a pinned nightly.
rustup toolchain install nightly-2026-07-09 --profile minimal --component rust-src

# Install the linker on Arch Linux or any other supported Linux distribution.
cargo install cargo-binstall --locked
cargo binstall bpf-linker@0.10.4

# Documentation (optional)
pipx install mkdocs-material
pipx install json-schema-for-humans
```

## Build

```bash
XLB_EBPF_TOOLCHAIN=nightly-2026-07-09 cargo build --locked --release
```

## Documentation

```bash
# Generate docs from config structs
cargo run --package xtask -- gendocs

# Serve locally
cd docs && mkdocs serve
```

## License

MIT OR Apache-2.0
