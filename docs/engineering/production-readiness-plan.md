# XLB Production Readiness and Correctness Plan

- Status: working implementation plan
- Last consolidated: 2026-07-16
- Primary product scope: very-high-throughput IPv4/TCP Layer-4 load balancing
  for OpenRTB and similar workloads
- Current default forwarding mode: bidirectional NAT through XDP

## Purpose

This document is the durable source of truth for the correctness, lifecycle,
Kubernetes, health, observability, status UI, and performance work discussed
during the Aya update and subsequent packet-flow review. It records confirmed
bugs, explicit product decisions, accepted external-review amendments, deferred
work, tests, and implementation order so that later implementation does not
depend on chat history.

The immediate product is deliberately narrower than a general-purpose network
load balancer:

- IPv4 and TCP are the supported OpenRTB-first dataplane.
- NAT is the operationally simple default.
- Kubernetes readiness is authoritative in Kubernetes deployments.
- Static/bare-metal deployments need XLB-owned active health checks.
- Existing OTEL metrics are a useful base; the next product layer is a small
  HAProxy-style status page, standard dashboards, alerts, and backend latency.
- UDP, full IPv6 load balancing, DSR automation, sophisticated balancing, and
  strong SYN-flood defenses are later work unless customer demand changes the
  order.

## Completed maintenance baseline

- Aya was moved back to the public crate release and the XDP flags API was
  updated in commit `73814b5` (`Update aya crate and compat for xdpflags`) on
  `main` and `aya-update-flags`.
- Release eBPF trace/debug packet logging is compiled out, avoiding Aya log transport on the
  production packet path. `aya-build` may still present its nested compiler progress with Cargo's
  `warning:` prefix; those status lines are not runtime packet warnings.
- The Docker build/runtime modernization is commit `920416a`
  (`Modernize Docker build and runtime image`) on `docker-update-07-2026`.
- Native/driver XDP is attempted first; generic/SKB mode is the compatibility
  fallback.

## Product and protocol decisions

### Established connections to removed or unhealthy backends

Do not automatically manufacture RSTs merely because a Kubernetes endpoint is
NotReady, terminating, absent from the eligible set, or failing an active health
check. Those signals are enough to stop new connections but are not definitive
proof that forcibly closing every established connection is safe.

The desired lifecycle is:

1. Backend becomes NotReady or terminating.
2. XLB stops assigning new flows to it.
3. Existing flow entries remain pinned to it.
4. The backend handles graceful shutdown and emits its own FIN/RST as appropriate.
5. XLB observes closure, or eventually removes the pair through configured
   orphan cleanup.

An explicit future administrator operation such as `force-close-backend` may
mark a backend terminal and reset connections on their next packet. It must be
an intentional policy/action, not the default interpretation of health failure.

### XLB process shutdown

Process shutdown is different from backend removal. The current global shutdown
flag reacts to packets during the configured grace window by returning a reset.
This is reactive, not proactive: an idle connection that sends no packet during
the window will not receive a generated RST. Keep that distinction visible in
documentation and status output.

Never emit an RST in response to an incoming RST. A mapped incoming RST should
be handled/forwarded normally so the other endpoint can observe closure.

### Connection stability

Stable connections across LB process replacement are not an immediate product
requirement. OpenRTB clients are generally expected to reconnect. However,
shutdown behavior must be accurate and documented, and deploy tests should
measure reconnection bursts. DSR plus deterministic hashing may later enable a
more stable active/active architecture.

### SYN-flood scope

Strong SYN-flood protection is deferred for the initial OpenRTB product, but the
architecture must be described accurately: XLB creates map state in XDP before
the SYN reaches the backend kernel, so backend SYN cookies do not protect XLB's
flow-map capacity. Fixing retransmission amplification is required correctness
work. A short handshake-state timeout is the preferred later mitigation.

Do not convert the paired flow map to `LRU_HASH` as a one-line workaround. Each
connection currently has two independently stored entries, so arbitrary LRU
eviction can itself create half-pairs and evict an active connection based on
only one direction's recency.

## Current architecture and capacity facts

- `FLOW_MAP` is a plain hash map with 1,000,000 directional entries
  (`xlb-common/src/consts.rs`). It therefore holds roughly 500,000 complete
  bidirectional connections at maximum, before accounting for broken pairs.
- A connection is represented by independent ToServer and ToClient entries.
  Each entry stores its counterpart key.
- The NAT port allocator tries five random ports from 5000 through 54999. This
  is approximately 50,000 possible concurrent translations per backend/LB
  source-IP combination, with possible failure before exhaustion due to the
  five-probe limit and races.
- The userspace maintenance loop currently scans the flow map to aggregate
  statistics and scans it again for cleanup every second.
- Round-robin backend selection uses one shared `RR_COUNTER` array element. It
  only runs for new SYNs, so it is not an immediate blocker, but it can race or
  become a shared cache line at very high connection-establishment rates.
- Maps are not pinned. The embedded eBPF object and userspace map types are built
  from the same workspace and loaded fresh at process start. Key/value ABI
  changes therefore do not need live map migration today.

## Confirmed correctness defects

The following were confirmed against the source and independently reviewed.

### RST transformed and then passed

On ephemeral-port exhaustion, `packet.rst()` mutates the packet but
`handle_tcp_packet` returns `Ok(None)`. The caller interprets `None` as Pass, so
the rewritten reset enters the local networking stack instead of returning via
`XDP_TX`.

### Shutdown answers RST with RST

The shutdown branch currently resets every matched TCP packet, including a
packet that already has RST set. This violates TCP reset handling and can create
reset loops/noise.

### Lossy and incomplete flow identity

`FlowKey::hash_key()` compresses the IPv4 address and port to
`ip * 31 + port`. Thus `(N, P + 31)` and `(N + 1, P)` collide exactly.

There is also a separate tuple-identity bug: the ToServer key is only client IP
plus client source port. These are valid, distinct connections:

```text
1.2.3.4:50000 -> VIP:80
1.2.3.4:50000 -> VIP:443
```

The current key aliases them because it omits the service destination port.
Packing only `IP << 16 | port` fixes the arithmetic collision but not this
multi-service collision or the shared-map direction namespace.

### Half-deleted pairs

Userspace cleanup selects and removes directional entries independently. If one
direction expires before the other, the survivor contains a dangling
counterpart key. The `/ 2` cleanup accounting is then incorrect. A later FIN/RST
can take the missing-counterpart error path, which becomes `XDP_DROP` and
black-holes retransmitted closure packets.

### SYN retransmission churn and leaks

Every ToServer packet with SYN currently performs backend selection and NAT port
allocation again. A retransmitted SYN can silently change backend, leak the old
reverse entry, and overwrite the forward entry because map insertion uses
`BPF_ANY`. `is_syn()` also matches SYN|ACK; new-client handling must require
`SYN && !ACK`.

If the first directional insert succeeds and the second insert fails for any
reason, the first entry is currently leaked with a dangling counterpart.

### Unsupported packet behavior

Full IPv6 load balancing is not required immediately, but unsupported IPv6 must
not be parsed as all-zero addresses or returned as `XDP_ABORTED` on an otherwise
healthy dual-stack interface. An IPv6 listen configuration should be rejected
until supported; unrelated IPv6 traffic should take an explicit safe pass path.

UDP is parsed partially but is not currently rewritten/balanced. Product claims
must say IPv4/TCP until that changes.

Configuration must fail fast for unsupported dataplane modes. Reject
`proto: udp`, IPv6 listen addresses, and `mode: dsr` at startup until each path
is implemented and tested; accepting a configuration that merely passes its
traffic is operationally unsafe.

IPv4 TCP parsing assumes a 20-byte header. IPv4 options (`IHL > 5`) can therefore
misplace the TCP header, and the current generated-RST checksum routine only
sums the fixed header. Until full option handling exists, validate/reject that
packet shape before TCP manipulation rather than emitting a malformed packet.

IPv4 fragmentation needs its own explicit policy. Non-initial fragments do not
contain a TCP header, but a fixed-offset protocol path can interpret payload
bytes as one. XLB passes IPv4 options, first fragments, non-initial fragments,
and declared-short TCP packets untouched before transport parsing; it does not
perform IP reassembly in XDP. Frames physically truncated before the required
fixed headers are silently dropped without release packet logging. Valid IPv6
and non-TCP traffic is likewise passed before unsupported header parsing.

## Correctness implementation plan

### Work item 0: test foundations

Focused control-plane and host-side packet/state tests now cover the implemented
branches, but the repository still has no real-map dataplane packet harness.
Treat that harness as its own deliverable rather than hiding its cost in an
individual TCP patch.

Build two layers:

1. Continue adding focused host-side unit tests for tuple construction, packet
   flag/state decisions, checksum arithmetic, RST sequence/acknowledgement
   construction, and timeout helpers. The current correctness branches include
   this coverage for their pure decisions and helpers.
2. A privileged Linux network-namespace/veth integration harness that loads the
   XDP program, sends crafted packets, inspects actions/map state, and verifies
   actual forwarding and returned resets.

The integration harness should be reusable by every subsequent work item and
should have a clear kernel/tooling prerequisite check.

### Work item 1: exact IPv4 flow keys

Replace the lossy `u64` application-level hash key with an exact, fixed-layout
IPv4 key used directly as the kernel hash-map key. Proposed layout:

```rust
#[repr(C)]
struct FlowKeyV4 {
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    direction: u8,
    reserved: [u8; 2],
}
```

Requirements:

- Use constructors for all keys and always zero `reserved`; the kernel hashes
  every key byte.
- Add `Copy`, `Clone`, `Eq`, `PartialEq`, `Hash`, and `Debug` as appropriate.
- Add userspace `aya::Pod` under the `user` feature.
- Add compile-time size/alignment assertions.
- Convert `FlowDirection` to the key's `u8`; do not change
  `FlowDirection`'s representation because it is embedded in `Flow`.
- Store the exact counterpart key in `Flow` and rename
  `counter_flow_key_hash` accordingly.
- Update userspace map and previous-stat snapshot key types.
- Add a note that a future pinned/live-upgrade design will need explicit map
  versioning/migration.

The estimated growth versus the current `u64` map key/counter reference is
approximately 16 MB at one million entries before allocator/alignment details.
Verify the real `size_of` values in tests rather than relying on estimates.

Mandatory key tests:

- The known `(N, P + 31)` / `(N + 1, P)` collision becomes distinct.
- Same client IP/source port to service ports 80 and 443 becomes distinct.
- ToServer and ToClient namespaces cannot alias.
- Constructor output has deterministic zeroed reserved bytes.
- Userspace and eBPF agree on exact size/layout.

### Work item 2: explicit TCP outcomes and correct RST emission

This is a logical protocol umbrella, not one implementation branch. Deliver
shutdown RST handling, shared packet construction, and ephemeral-port outcome
handling in the separate branches listed in the delivery matrix below.

Replace `Option<PacketFlow>` as an overloaded control signal with an explicit
outcome type, for example:

```rust
enum TcpOutcome {
    Forward(PacketFlow),
    Reply,
    Pass,
    Drop,
}
```

Requirements:

- NAT-port exhaustion produces a valid reset and returns `Reply`, mapped to
  `XDP_TX`.
- Never generate a reset in response to a reset.
- A mapped RST is recorded and forwarded to its peer.
- Missing-counterpart handling in `close_flow` is nonfatal. If the current
  recipe survives, forward the FIN/RST and record an invariant violation rather
  than converting it to `XDP_DROP`.
- Generated IPv4 resets use TTL 64 rather than inheriting the incoming residual
  TTL.
- Validate `IHL == 5` before the currently fixed-offset TCP/RST path, or fully
  implement options/checksum handling before accepting options.
- Preserve RFC-compatible RST SEQ/ACK behavior already implemented in the TCP
  header helper.
- `bpf_xdp_adjust_tail` invalidates packet pointers. TCP/IP mutation and checksum
  calculation must happen before it, and the caller must immediately return
  after adjustment without touching cached packet/header pointers.
- Decide the unmatched ToServer policy explicitly. A reactive RST is reasonable
  and has amplification no greater than one because payload is truncated, but
  it should never answer RST and may later need a cheap per-CPU rate limiter.

Mandatory RST/outcome tests:

- Port exhaustion returns `XDP_TX`, not Pass.
- Incoming RST never receives a generated RST.
- Mapped FIN and RST survive a missing counterpart without being dropped.
- ACK and non-ACK RST sequence construction matches expected behavior.
- SYN/FIN are included in segment-length acknowledgement calculations.
- Generated RST payload is truncated.
- Generated IPv4 and TCP checksums validate.
- Generated TTL is 64.
- `IHL > 5` cannot yield a malformed generated RST.

### Work item 3: pair-safe lifecycle cleanup

Keep independent per-direction `last_seen_ns` values for observation and
half-open/asymmetric metrics. When either side reaches a terminal cleanup
condition, remove the complete pair.

Terminal/cleanup conditions include:

- RST grace elapsed.
- Both FINs observed and configured TIME_WAIT elapsed.
- Either direction reaches configured orphan idle timeout.

Requirements:

- Resolve the counterpart before selecting deletion keys.
- Delete/count a connection once rather than assuming the number of selected
  directional keys can always be divided by two.
- Record the triggering direction and reason before removing both entries.
- Record an invariant metric for missing/mismatched counterparts.
- Preserve the configured side-independent timestamps even though cleanup is
  pair-wide.
- Document the userspace snapshot race: a tuple can theoretically be recreated
  between selection and deletion, and concurrent iteration can delay cleanup by
  one tick. A generation field/check can reduce but not fully eliminate the
  delete race without a deeper design.

Mandatory cleanup tests:

- One stale direction removes both entries exactly once.
- FIN/RST closure removes both according to grace/TIME_WAIT.
- Side/reason accounting remains accurate for asymmetric expiry.
- A pre-existing half-pair is detected and safely cleaned.
- Concurrent map modification never panics; skipped cleanup is retried later.

### Work item 4: idempotent, transactional SYN handling

New connection detection must be `SYN && !ACK` in the ToServer direction.

Rules:

```text
Complete nonterminal pair found:
    Treat as SYN retransmission and reuse the winning forward recipe.

Terminal pair found (rst_ns or fin_both_ns set):
    Delete both terminal entries and create a fresh connection.

Incomplete/dangling pair found:
    Record an invariant failure, repair/remove the survivor, and create fresh.

No pair found:
    Select backend, allocate translation, and install a new pair.
```

Requirements:

- Use `BPF_NOEXIST` for pair installation rather than silent overwrite.
- Roll back the first insert on any second-insert failure, including map-full
  errors and reverse-key races.
- If another CPU wins the forward insertion, never install or forward the
  loser's selected backend; reuse the winner when its pair is complete. Backend
  selection happens before the `BPF_NOEXIST` reservation, so simultaneous first
  SYNs can advance round-robin more than once even though only one recipe wins.
  This negligible selection skew avoids a second reservation map/lock. If the
  winner is still between its two inserts, use an explicit initializing
  state/bounded retry/drop policy; do not misclassify the transient as
  corruption and delete the winner.
- If reverse-port insertion loses a race, remove only entries installed by the
  losing attempt and retry allocation within a bounded verifier-safe loop.
- Pair cleanup and this transactional creation work should land in the same PR
  or release. Otherwise the new invariant metric will report known insertion
  leaks as corruption between deployments.

Mandatory SYN tests:

- Retransmitted SYN keeps the same backend and XLB ephemeral port.
- Retransmission does not create additional map entries.
- SYN|ACK never enters new-client flow creation.
- A SYN during the prior pair's terminal/TIME_WAIT retention creates a fresh
  connection instead of reusing the dead recipe or black-holing for 60 seconds.
- Second-insert failure removes the first entry.
- Two concurrent identical SYNs converge on one complete pair.
- Reverse-port allocation races do not leak entries.

Current validation boundary (July 2026): host-side tests cover the SYN/ACK
admission guard, complete/terminal/incomplete pair classification, initializing
state policy, and publication rejection for every FIN/RST/invariant marker. A
locked release build also verifies that the real eBPF object links, both map
updates use `BPF_NOEXIST`, `Flow` remains padding-free at 160 bytes, and compiled
BPF stack offsets remain below the 512-byte limit.

The current host test environment cannot mutate an Aya eBPF map or schedule two
real XDP executions concurrently. The following map-level cases remain an
explicit temporary test waiver, not claimed coverage: stable backend/translation
on retransmission, unchanged entry count, rollback after the second insert
fails, convergence of simultaneous identical SYNs, and reverse-key-race leak
freedom. Add those cases with the deferred privileged BPF/XDP harness in
`tcp-test-foundations`; do not add a large mock state machine merely to imitate
kernel map semantics in this branch.

## TCP timeout and half-open policy

Current defaults/behavior:

- Orphan idle timeout: 300 seconds.
- Post-bidirectional-FIN TIME_WAIT retention: 60 seconds in userspace.
- Independent activity timestamps exist for each direction.

Treat 300 seconds as the effective minimum orphan idle timeout for the initial
product, not only the default. Normalize lower values to 300 during configuration
loading and emit one clear startup warning rather than failing startup. Document
the normalization policy and keep Helm's default at 300 seconds. A previously
observed 30-second setting expired valid idle connections and caused resumed
traffic to hit the missing-flow path continuously.

An expired/missing flow is an expected dataplane condition and must not emit an
eBPF warning for every subsequent packet. Per-packet Aya warnings are delivered,
decoded, and formatted in userspace and can create a CPU-consuming log storm.
Demote expected `ErrOrphanedFlow` packet logging to release-compiled-out debug or
trace output, and expose aggregate orphan/missing-flow counters instead. Reserve
warning/error logs for unexpected invariant failures and rate-limit or sample
any warning that can be triggered by network traffic. A surviving flow whose
stored counterpart is absent is not an expected expired-flow event: mark the
surviving entry as pair-invalid, forward its still-valid rewrite recipe, and
keep the invariant visible in aggregated release telemetry until userspace
removes it.

The operating system's TCP keepalive configuration cannot be inferred from the
initial TCP window, and ordinary keepalive settings are not negotiated in packet
headers. XLB can only observe packets that actually arrive. A TCP keepalive probe
and its ACK naturally refresh the appropriate directional entries. Endpoints
that need a connection to survive an otherwise idle period must send keepalives
or application traffic more frequently than `orphan_ttl_secs`, or the operator
must configure a longer timeout.

Keep independent timestamps because they expose asymmetric and half-open
behavior. On expiration, record which side went quiet and then remove the pair;
leaving only one mapping does not preserve a usable TCP connection.

Future state-aware timeouts may distinguish:

- Incomplete handshake/SYN state: short timeout.
- Established idle connection: configurable service timeout.
- Closing pair: RST grace or TIME_WAIT policy.

Do not raise the 300-second default solely to mimic the Linux two-hour keepalive
default. Validate longer values against actual OpenRTB connection-pool idle
times and keep the configured value explicit in deployment examples, while
retaining the 300-second safety floor.

## Kubernetes discovery and compatibility

### Current state

- XLB has a custom Pod watcher in `xlb/src/provider/kubernetes.rs`.
- `neuronictechnologies/rust-ad-exchange-ai` (local checkout
  `../neuronicai/rust-ad-exchange-ai`) uses the adjacent `../kube-discovery` crate.
- `kube-discovery` also watches Pods selected from a Service; it does not use
  EndpointSlices today.
- `kube-discovery` uses `kube 0.98` / `k8s-openapi 0.24` while XLB uses
  `kube 2.0` / `k8s-openapi 0.26`.
- Before the `kube-watcher-hygiene` branch, Helm granted core `endpoints` and
  `services` while XLB actually watched `pods`, so chart-created service
  accounts could fail discovery with an authorization error.

### Interim Pod-watcher hygiene

Keep this work separate from EndpointSlice migration. The focused
`kube-watcher-hygiene` branch must:

- Treat `deletionTimestamp.is_some()` as ineligible for new flows even if the
  Pod's Ready condition remains true.
- Handle watcher `Init`, `InitApply`, and `InitDone` as a complete snapshot,
  retaining existing backends during the relist and removing entries absent
  from the completed snapshot.
- Reconcile by Pod name so an IP replacement cannot leave the old address.
- Grant the current implementation only `services:get` for the configured
  Service and `pods:list,watch` in the backend namespace.
- Render no discovery RBAC for the static provider.

This branch changes eligibility for new connections only. It does not reset or
remove established flows when a Pod becomes terminating or NotReady.

### Target shared design

Upgrade and generalize `kube-discovery` around a lower-level EndpointSlice
service watcher that emits a neutral endpoint model:

```rust
struct ServiceEndpoint {
    name: Option<String>,
    ip: IpAddr,
    node: Option<String>,
    zone: Option<String>,
    ready: Option<bool>,
    serving: Option<bool>,
    terminating: Option<bool>,
}
```

The watcher must:

- List/watch every EndpointSlice labeled for the configured Service.
- Merge all slices for that Service.
- Handle initial synchronization, watcher restart/resync, stale removal, and
  last-error/last-success state.
- Preserve endpoint conditions rather than collapsing immediately to one list.
- Support IPv4 now while leaving the model capable of IPv6 later.
- Upgrade the shared crate to the kube versions used by XLB, then compile/test
  both XLB and `neuronictechnologies/rust-ad-exchange-ai` against the change.

Consumers:

- `rust-ad-exchange-ai` filters itself and converts eligible endpoints into peers.
- XLB uses eligible endpoints for new-flow backend selection and retains
  condition/reason data for status output.

Preserve the nullable EndpointSlice values at the shared-library boundary and
normalize them explicitly: `ready: null` and `serving: null` mean true, while
`terminating: null` means false. Do not silently map `None` to false.

`publishNotReadyAddresses` can cause the API to report `ready=true` for
endpoints that are not Pod-Ready. Before migrating XLB, decide explicitly
whether new-flow eligibility follows Service publishing policy or preserves
today's stricter drain behavior. The initial recommendation for XLB is
`serving && !terminating`; retain `ready` separately for status and policy.

Normalized EndpointSlice conditions then mean:

- `serving && !terminating`: eligible for new connections under the recommended
  strict XLB policy.
- `terminating && serving`: not eligible for new connections, but visible as
  draining; existing XLB flows remain untouched.
- not serving/removed: not eligible; existing flows remain until the endpoint
  or configured lifecycle naturally closes them.

Kubernetes documents EndpointSlices as the service-routing source of truth and
provides `ready`, `serving`, and `terminating` specifically for consumers that
need correct drain behavior.

### EndpointSlice RBAC target

Update Helm RBAC to the resources actually watched:

```yaml
- apiGroups: [""]
  resources: ["services"]
  verbs: ["get"]

- apiGroups: ["discovery.k8s.io"]
  resources: ["endpointslices"]
  verbs: ["get", "list", "watch"]
```

Use a namespace-scoped Role and RoleBinding in the backend namespace. The
RoleBinding can name XLB's ServiceAccount in the Helm release namespace, so
cross-namespace deployment does not itself require a ClusterRole.

## Active health checks

### Bare metal/static provider

Add XLB-owned active checks with configurable:

- TCP connect.
- HTTP or HTTPS request/path and accepted status range.
- Check port override.
- Interval, timeout, jitter.
- Consecutive healthy/unhealthy thresholds.
- Optional initial health threshold before accepting new flows.

### Optional Kubernetes checks

Kubernetes remains the upper authority. A stricter XLB check is an additional
gate, not a competing record:

```text
eligible_for_new_flows =
    kubernetes_ready
    && (custom_check_disabled || custom_check_healthy)
```

A custom check may subtract a Kubernetes-ready endpoint but must never resurrect
a Kubernetes-unready endpoint. Health failure does not automatically reset
established flows.

Export and display the provider state and health state separately so operators
can tell whether Kubernetes, an XLB check, route resolution, or configuration
excluded a backend.

## Management API and mini status page

Add a lightweight management HTTP server inspired by the classic HAProxy stats
page. It should be useful without creating a second frontend application or
Node build pipeline. Embed static HTML/CSS and minimal JavaScript in the Rust
binary.

Initial endpoints:

```text
GET /                  Human-readable auto-refreshing status page
GET /api/v1/status     Versioned JSON status snapshot
GET /healthz           Liveness: process/event loop is alive
GET /readyz            Readiness: config loaded, XDP attached, provider synced,
                       and at least one backend eligible
```

Semantics:

- `/healthz` must not fail merely because there are zero backends; restarting
  XLB is not a remedy for an empty backend set.
- `/readyz` should fail when XLB cannot serve new traffic: no successful eBPF
  attachment, initial provider sync incomplete/failed, shutdown in progress, or
  no eligible backend.
- Publish one immutable `StatusSnapshot` from the existing maintenance loop.
  HTTP requests read the snapshot and must never iterate BPF maps themselves.
- A future `xlb status` CLI should consume the same JSON endpoint rather than
  implement separate map inspection.

Status snapshot/page content:

- Build version/commit, uptime, shutdown state.
- Listen address, protocol, routing mode, port mappings.
- Attached interfaces and actual native/driver versus generic/SKB mode.
- Flow-map entries, estimated complete connections, capacity percentage, and
  insertion/invariant errors.
- Current/new/closed/orphan flows and closure reason/side.
- Per-backend eligibility, Kubernetes conditions, custom-health state, route
  resolution, active flows, clients, ingress/egress PPS, Mbps, and bytes.
- Active health-check duration and passive TCP handshake latency.
- Provider watcher synchronized/alive state, last successful update, and last
  error.
- Recent high-value warnings such as no backend, SKB fallback, map pressure, or
  repeated pair-invariant failures.

Security/deployment:

- Bind management to localhost by default for direct/bare-metal use.
- Make the bind address/port configurable.
- Allow optional authentication when exposed beyond localhost.
- Do not expose client IP/flow detail by default; the page is aggregate/backend
  operational data.
- Replace the Helm shell probes (`ip link | grep xdp`) with HTTP `/healthz` and
  `/readyz` probes. Kubernetes `httpGet` normally targets the Pod IP, so the
  chart must either bind the management listener to the Pod/host-network address
  for Kubernetes, or set an explicit loopback probe host if the kubelet/network
  topology supports it. Do not assume a loopback-only default is reachable.
- Keep the management endpoint off the public load-balanced service unless the
  operator explicitly enables it. Support `kubectl port-forward` for normal
  inspection.

## Observability and dashboards

### Existing useful OTEL base

XLB already exports useful global and per-backend values:

- Available backends.
- Active/opened/closed/orphan connections.
- FIN/RST closure side and type.
- Per-backend ingress/egress flows.
- PPS, Mbps, and transferred bytes.

Per-core metrics are not a customer-facing requirement. Per-CPU BPF maps are
only a possible internal implementation if profiling later shows contention or
map-scan cost.

### Packaging work

Ship:

- A supported OpenTelemetry Collector example.
- Prometheus export example through the collector.
- A Grafana dashboard JSON file.
- Suggested alert rules.

Initial alerts:

- No eligible backends.
- Provider watcher unhealthy or stale.
- Unexpected backend-count churn.
- Flow map above configured pressure thresholds.
- Flow insertion or NAT-port allocation failures.
- Pair-invariant violations.
- Sharp orphan/RST increase.
- Ingress traffic without expected backend egress/returns.
- Native-XDP fallback to SKB when strict mode was expected.
- Backend health/handshake latency regression.

Profile the one-second full-map aggregation and cleanup scans under realistic
map occupancy before redesigning telemetry. If they become material, move hot
aggregate counters into per-CPU BPF maps and make detailed connection inspection
less frequent. Reuse the maintenance snapshot for the UI rather than adding
another scan.

## Backend latency design

Backend latency is more operationally useful than continuously timing XLB's own
instructions.

### Active health-check latency

Measure TCP connect duration or HTTP(S) health response duration in userspace.
Export at least:

```text
xlb.backend.health_check.duration
xlb.backend.health_check.failures
xlb.backend.health_check.status
```

### Passive real-traffic TCP handshake latency

For the first backend SYN-ACK of a newly selected flow:

```text
backend_handshake_duration =
    syn_ack_arrival_at_xlb - client_syn_arrival_at_xlb
```

This includes initial XLB forwarding, network travel to the backend, backend TCP
stack response, and travel back to XLB. It excludes the client-to-XLB path and
does not pretend to be application response time.

Requirements:

- Record at most once per connection; ignore SYN-ACK retransmissions.
- Attribute by backend with bounded cardinality.
- Export a histogram suitable for p50/p95/p99 plus sample count.
- Track handshake timeout/failure later when explicit handshake state exists.
- Display recent percentile/EWMA values on the status page.
- Do not use latency for backend selection initially; first observe correlation
  with application behavior.

Possible implementation choices:

- Simple first version: store a one-time handshake duration/observed flag in the
  flow and aggregate during the existing maintenance scan.
- Scalable later version: update a per-CPU backend histogram once per completed
  handshake and merge in userspace.

XLB cannot reliably measure every OpenRTB request/response on persistent TCP,
TLS, pipelining, or HTTP/2 at Layer 4. Actual auction duration, TTFB, and `tmax`
deadline misses must come from application OTEL. Dashboards should correlate
application latency with XLB backend health/handshake latency.

### XLB-added latency and performance claims

Do not add always-on per-packet self-timing solely for marketing. Clock reads
and histogram writes affect the path being measured, and XDP execution still
has map/cache/checksum/redirect costs that can be hundreds or thousands of
nanoseconds depending on hardware.

The meaningful measurement is an external differential benchmark:

```text
direct client -> backend
versus
client -> XLB -> backend
```

Measure the added p50/p99/p99.9 latency and throughput in both native and SKB
modes. Kernel BPF runtime statistics or sampled internal timing can be enabled
for benchmark/debug diagnosis, not as a required production metric.

## Backend selection strategy

Round-robin on new connection creation is adequate for the immediate product
when there are many broadly comparable connections and homogeneous backends.
Established TCP connections cannot be moved based on later packet activity.

Do not prioritize packet-activity balancing. Packet count is a weak proxy for
OpenRTB compute cost, especially with persistent connections. If overload-aware
selection is needed later:

1. Prefer backend application feedback such as in-flight auctions, queue depth,
   CPU, or deadline misses.
2. Publish slowly changing weights/scores from userspace to the dataplane.
3. Use power-of-two choices or weighted consistent hashing for new flows only.

Potential later selector work:

- Replace the global shared RR counter with per-CPU RR or tuple hashing.
- Maglev/rendezvous hashing for stable placement during backend-set changes and
  active/active DSR deployments.
- Weighted selection for unequal backend capacity.
- Zone/topology-aware preference using EndpointSlice metadata.

## DSR, UDP, and IPv6 roadmap

### DSR

The routing-mode enum and some dataplane concepts already anticipate DSR, but
full behavior is not implemented. NAT remains the default because DSR requires
VIP ownership/loopback configuration, ARP behavior, backend routing, MTU/tunnel
decisions, and deployment validation.

Offer DSR later as an advanced automated mode with:

- Backend/VIP setup tooling or operator automation.
- ARP/sysctl/routing preflight validation.
- Helm annotations/configuration.
- Clear failure diagnostics.
- Separate NAT versus DSR benchmarks.

### UDP

UDP is not required for the OpenRTB-first release, but is required before making
a general game-server product claim. It needs actual port accessors, checksum
and rewrite support, flow affinity/timeouts, health semantics, and tests.

### IPv6

Full IPv6 translation can remain deferred. Immediate requirements are:

- Reject an IPv6 listen/backend configuration until supported.
- Safely pass unrelated IPv6 traffic instead of aborting/dropping it.
- Do not key IPv6 packets as all-zero addresses.

## Deployment and runtime-mode behavior

- Continue native XDP first with generic/SKB fallback for compatibility.
- Expose the actual mode on the status page and through OTEL.
- Add an optional strict performance mode that fails startup when native XDP is
  unavailable instead of silently accepting SKB fallback.
- Generic XDP still avoids TCP termination and much of a userspace proxy path,
  but performance comparisons with HAProxy or other products must be measured,
  not assumed.
- LoxiLB's published architecture performs most L4 processing at TC eBPF while
  using XDP for selected operations; XLB's native driver-XDP path is a real
  architectural differentiator, but the product claim should be backed by
  repeatable results.

Benchmark matrix:

- Native and generic/SKB XDP.
- Packets/sec, new connections/sec, and throughput.
- Added p50/p99/p99.9 latency.
- CPU per traffic unit.
- Small and representative OpenRTB packet/request sizes.
- Persistent HTTP/1.1 and, where relevant, HTTP/2 connection patterns.
- Backend churn, drain, failure, and reconnection bursts.
- Flow map at low and high occupancy.
- NAT-port pressure.
- Comparisons with HAProxy TCP mode, IPVS, and relevant eBPF/XDP alternatives
  on equivalent hardware/topology.

Until those results exist, prefer a defensible statement such as “XDP-native
Layer-4 load balancing with predictable low latency and no TCP termination” over
an unqualified “world's highest performance” claim.

## Delivery branches and review gates

Logical dependencies do not imply one combined implementation branch. Keep each
branch narrowly reviewable, use focused commits inside it, and merge branches in
dependency order. Every branch requires its focused tests, a release build where
applicable, a written peer review, and resolution of all blocking findings before
merge. Merge and push it to `main`, then delete the branch before starting the
next branch. Do not mix opportunistic cleanup into a TCP correctness branch.

| Order | Branch | Scope | Status |
| --- | --- | --- | --- |
| 1 | `docker-update-07-2026` | Container/runtime modernization only | Implemented and independently reviewed |
| 2 | `dependency-refresh-07-2026` | Lockfile refresh only | Implemented and independently reviewed |
| 3 | `kube-watcher-hygiene` | `deletionTimestamp`, watcher snapshot reconciliation, current Pod RBAC | Implemented and independently reviewed |
| 4 | `orphan-timeout-clamp` | Warning-and-clamp 300-second floor and expired-flow log-storm guard | Implemented and independently reviewed |
| 5 | `docs-update-07-2026` | Accurate public docs, strict generation, and this durable plan | Implemented and independently reviewed |
| 6 | `tcp-test-foundations` | Host-side packet/state tests and reusable privileged netns/veth harness | Deferred; focused host-side unit tests are added with each branch |
| 7 | `tcp-flow-key-v4` | Exact map key and tuple identity only | Implemented and independently reviewed |
| 8 | `shutdown-rst-correctness` | XLB process-shutdown behavior only; never answer RST with RST | Implemented and independently reviewed |
| 9 | `tcp-rst-packet-construction` | Shared TTL/IHL/checksum/sequence and pointer-order safety | Implemented and independently reviewed |
| 10 | `ephemeral-rst-outcome` | Explicit TCP outcome and port-exhaustion `XDP_TX` fix | Implemented and independently reviewed |
| 11 | `tcp-pair-cleanup` | Pair-wide expiry/closure and invariant accounting | Implemented and independently reviewed |
| 12 | `tcp-syn-idempotency` | SYN-only guard, retransmission reuse, terminal eviction, transactional inserts | Implemented and independently reviewed; privileged map-race coverage deferred under item 6 |
| 13 | `unsupported-config-packets` | Reject UDP/DSR/IPv6 config; safe IPv4 option/fragment policy | Implemented and independently reviewed; privileged action coverage deferred under item 6 |
| 14 | `rust-module-cleanup-07-2026` | Extract pair cleanup and tests from `mloop.rs`, without behavior changes | Implemented and independently reviewed |
| 15 | `rust-tooling-cleanup-07-2026` | Userspace Clippy baseline, stable rustfmt configuration, and test-runner documentation | Implemented and independently reviewed |
| 16 | `endpoint-slice-discovery` | Shared nullable-condition model and both consumers | Planned |
| 17 | `status-health-api` | `StatusSnapshot`, `/healthz`, `/readyz`, JSON and mini status page | Planned |
| 18 | `backend-health-checks` | Static checks and optional Kubernetes secondary checks | Planned |
| 19 | `observability-packaging` | Latency, Collector, Prometheus, Grafana, and alerts | Planned |

After those correctness/product branches, run the benchmark matrix before
optimizing map scans or round-robin selection and before making comparative
performance claims. DSR automation, UDP/game support, and full IPv6 remain
demand-driven follow-ups.

### Maintainability checkpoint after packet correctness

Use two sequential, bounded branches after item 13 rather than combining code
movement and build-tool policy in one review:

1. `rust-module-cleanup-07-2026` only extracts pair cleanup and its tests from
   the oversized maintenance-loop module. Do not reorganize the cohesive SYN
   state machine without a separate concrete defect or proposed boundary. The
   focused tests must remain unchanged and the generated eBPF object must be
   byte-identical because this branch is userspace-only movement.
2. `rust-tooling-cleanup-07-2026` uses separate commits for userspace Clippy
   fixes and formatter/test-runner documentation. Its lint gate is
   `XLB_EBPF_TOOLCHAIN=nightly-2026-07-09 cargo clippy --locked --release -p xlb --bin xlb --no-deps`;
   it must clear that command's current warnings without
   opportunistic module renames. Use `cargo fmt --all -- --check` with stable
   rustfmt. Nightly-only import grouping is intentionally excluded because it
   produces broad cosmetic churn without improving the correctness gate.
   Document the release eBPF test runner and privileged boundary in a separate
   commit. If either commit expands beyond mechanical changes, split it into
   another branch before implementation.

Keep packet-path behavior and performance changes out of both branches. Any
future eBPF cleanup requires the focused eBPF Clippy command, an explicit lint
baseline/allowlist, generated layout/stack measurements, and an instruction
diff rather than being folded into these userspace maintenance branches.

## Open implementation decisions

These require an explicit decision during implementation rather than an
accidental default:

- Exact behavior for unmatched ToServer non-RST packets: Drop versus generated
  RST, and whether rate limiting is initially required.
- Representation of pair installation-in-progress so a losing concurrent SYN
  does not mistake the winner's transient half-pair for corruption.
- Whether a generation field is worth adding now to reduce userspace cleanup
  races.
- Management bind/port defaults and authentication scope.
- Whether zero eligible backends should always fail `/readyz` or be configurable
  for fail-open environments. Initial recommendation: fail readiness.
- Health-check schema and whether HTTP(S) support lands with TCP or afterward.
- Initial passive latency storage: per-flow observation versus per-CPU histogram.
- Whether strict native-XDP mode is a global config or per-interface policy.
- When NAT source-IP pools/stronger port allocation become necessary based on
  measured concurrency.

## Review record

An external Claude review independently verified the RST-then-Pass bug,
RST-in-response-to-RST, lossy key collision, omitted service destination port,
half-deleted pairs, SYN churn, second-insert leak, and existing RFC-compatible
RST SEQ/ACK construction.

Accepted review amendments incorporated above:

- Terminal pair eviction before same-tuple reconnect in SYN handling.
- Rollback on every second-insert failure, not only lost races.
- Lower ABI risk because maps are not pinned.
- Deterministic key padding and explicit direction conversion.
- TTL 64 and IPv4-option handling for generated resets.
- Preserve pointer-invalidating `adjust_tail` ordering.
- Missing-counterpart close handling must not drop FIN/RST.
- Pair cleanup and transactional creation should land close together.
- Test harness cost must be planned explicitly.

One review suggestion was not accepted as stated: automatic `LRU_HASH` eviction
is unsafe as a one-line mitigation while each connection is represented by two
independently evictable entries.

## Primary code references

- Flow map declaration: `xlb-ebpf/src/main.rs`
- Flow key/value layout: `xlb-common/src/types.rs`
- Direction and flow-key construction: `xlb-ebpf/src/handler/utils.rs`
- TCP creation/existing/closure paths: `xlb-ebpf/src/handler/tcp.rs`
- Packet outcomes/reroute/RST: `xlb-ebpf/src/handler/handler.rs` and
  `xlb-ebpf/src/net/packet/packet.rs`
- TCP RST/checksum construction: `xlb-ebpf/src/net/proto/tcp/header.rs`
- IPv4 checksum implementation: `xlb-ebpf/src/net/ip/v4/header.rs`
- Userspace aggregation/cleanup: `xlb/src/loop/mloop.rs` and
  `xlb/src/loop/utils.rs`
- Current OTEL instruments: `xlb/src/metrics/`
- Current Kubernetes provider: `xlb/src/provider/kubernetes.rs`
- Shared discovery crate: `../kube-discovery/`
- Exchange consumer:
  `../neuronicai/rust-ad-exchange-ai/src/core/cluster/impls/kube.rs`
- Helm RBAC/probes: `helm/xlb/templates/rbac.yaml` and `helm/xlb/values.yaml`
