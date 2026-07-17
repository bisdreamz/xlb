# XLB instance console

This Vue application is the local operations console served by each XLB process at `/admin/`. It polls the existing `/api/v1/status` endpoint once per second and retains up to 30 minutes of samples in the browser. Fleet-wide and durable history remains the responsibility of the configured OpenTelemetry backend.

## Local development

```bash
npm ci
npm run dev
```

Vite serves the console at `http://127.0.0.1:4173/admin/` and proxies `/api` to the XLB admin server at `http://127.0.0.1:9090`. If the API is unavailable, the console shows a disconnected state and never substitutes fabricated operational values.

An explicit demo mode is available for design review or a future hosted product demo:

```bash
npm run dev:demo
```

Demo mode is visibly labeled and never polls the status API. `npm run build:demo` creates an equivalent static demo build. Normal development, production, and Docker builds cannot enter demo mode as a fallback.

Run the production build and browser checks with:

```bash
npm run build
npm run test:e2e
```

## Production embedding

The production build is emitted to `admin-ui/dist/`. XLB embeds that directory in its binary and serves it from the existing admin listener; there is no Node.js process in the runtime image. The Docker build installs frontend dependencies, builds the assets, then compiles XLB.

For a local release binary, build the UI before Rust:

```bash
npm ci --prefix admin-ui
npm run build --prefix admin-ui
cargo build --locked --release --package xlb
```

If the Rust binary is built without `dist/index.html`, `/admin/` returns a clear `503 Service Unavailable`; health, readiness, and status API routes remain available.

## Data boundaries

The foundation consumes fields already present in status schema v1. UI destinations for lifecycle events, passive backend handshake latency, load-distribution scoring, and failed-work counters are labeled as planned API extensions. Their collection belongs in independently reviewed dataplane or userspace branches rather than in the presentation layer.
