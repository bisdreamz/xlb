# XLB - eBPF Layer 4 Load Balancer

High-performance Layer 4 (TCP/UDP) load balancer powered by eBPF XDP. Handles >100k RPS with 2-4 CPU cores.

## Project Structure

- **xlb/** - Main userspace application (config, backend providers, eBPF loader, metrics)
- **xlb-common/** - Shared types between userspace and eBPF (`no_std` compatible)
- **xlb-ebpf/** - eBPF XDP kernel program (packet processing, connection tracking)

## Dependencies

```bash
# Rust toolchains
rustup install stable nightly
rustup component add rust-src --toolchain nightly

# eBPF build tools
sudo apt-get install llvm clang libbpf-dev linux-headers-$(uname -r)

# Documentation (optional)
pipx install mkdocs-material json-schema-for-humans
```

## Build

```bash
cargo build --release
```

## Documentation

```bash
# Generate docs from config structs
cargo xtask gendocs

# Serve locally
cd docs && mkdocs serve
```

## License

MIT OR Apache-2.0
