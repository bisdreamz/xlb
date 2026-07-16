# syntax=docker/dockerfile:1.7

ARG RUST_IMAGE=rustlang/rust:nightly-trixie-2026-07-08@sha256:c13f4238a353659e2538b32c10aeb3c1754a4633f57fdd51bd933d62647eb40b
ARG RUNTIME_IMAGE=debian:trixie-slim@sha256:28de0877c2189802884ccd20f15ee41c203573bd87bb6b883f5f46362d24c5c2

FROM ${RUST_IMAGE} AS builder

ARG TARGETARCH
ARG BPF_LINKER_VERSION=0.10.4
ARG BPF_LINKER_SHA256_AMD64=4dda77daab6c5f120a468e6d3ede2498f5bd47ece712172cfb7290176d93d015
ARG BPF_LINKER_SHA256_ARM64=c3638cd3cb735ff85705905a07e0df61c0f9426480334c8e2efe5cb92fd9d3de
ARG RUST_NIGHTLY=nightly-2026-07-09

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        zstd \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) rust_arch=x86_64; checksum="${BPF_LINKER_SHA256_AMD64}" ;; \
        arm64) rust_arch=aarch64; checksum="${BPF_LINKER_SHA256_ARM64}" ;; \
        *) echo "unsupported Docker architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    asset="bpf-linker-${rust_arch}-unknown-linux-musl.tar.zst"; \
    url="https://github.com/aya-rs/bpf-linker/releases/download/v${BPF_LINKER_VERSION}/${asset}"; \
    curl --fail --location --proto '=https' --tlsv1.2 --retry 5 --output "/tmp/${asset}" "${url}"; \
    echo "${checksum}  /tmp/${asset}" | sha256sum --check -; \
    tar --extract --use-compress-program=unzstd --file "/tmp/${asset}" --directory /usr/local/bin; \
    rm "/tmp/${asset}"; \
    bpf-linker --version

RUN rustup toolchain install "${RUST_NIGHTLY}" --profile minimal --component rust-src

ENV RUSTUP_TOOLCHAIN=${RUST_NIGHTLY} \
    XLB_EBPF_TOOLCHAIN=${RUST_NIGHTLY}

WORKDIR /build
COPY . .

RUN --mount=type=cache,id=xlb-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=xlb-cargo-git,target=/usr/local/cargo/git/db,sharing=locked \
    --mount=type=cache,id=xlb-target-${TARGETARCH}-${RUST_NIGHTLY},target=/build/target,sharing=locked \
    cargo build --locked --release --package xlb \
    && install -D -m 0755 target/release/xlb /out/xlb \
    && strip --strip-unneeded /out/xlb

FROM ${RUNTIME_IMAGE} AS runtime

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        iproute2 \
        iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /out/xlb /usr/local/bin/xlb

ENV RUST_LOG=info

# Mount the deployment-specific configuration read-only at /app/xlb.yaml.
# XLB currently loads and attaches eBPF programs with elevated host privileges.
USER 0:0
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/xlb"]
