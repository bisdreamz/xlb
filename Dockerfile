FROM rustlang/rust:nightly-bookworm AS builder

RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    llvm-dev \
    libclang-dev \
    libelf-dev \
    linux-headers-amd64 \
    build-essential \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install rust-src component for eBPF compilation
RUN rustup component add rust-src --toolchain nightly-x86_64-unknown-linux-gnu

# Install bpf-linker (required by xlb-ebpf/build.rs)
RUN cargo install bpf-linker

WORKDIR /build
COPY . .

# Build the workspace (includes eBPF compilation)
RUN cargo build --release --workspace

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    iproute2 \
    iputils-ping \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /build/target/release/xlb /app/xlb
COPY xlb.yaml /app/xlb.yaml

ENV RUST_LOG=info

CMD ["/app/xlb"]
