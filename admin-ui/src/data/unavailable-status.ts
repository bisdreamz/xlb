import type { StatusSnapshot } from '../api/status'

/**
 * Neutral shape used before the first successful status response. The app
 * renders a disconnected state while this value is active, so zeroes here are
 * never presented as operational measurements.
 */
export const unavailableStatus: StatusSnapshot = {
  schema_version: 1,
  service: 'XLB',
  version: 'Unavailable',
  lifecycle: 'starting',
  uptime_seconds: 0,
  health: { healthy: false, reason: 'status_api_unavailable' },
  readiness: { ready: false, reason: 'status_api_unavailable' },
  sampled_at_unix_ms: null,
  sample_age_ms: null,
  provider: {
    kind: 'static',
    healthy: false,
    discovered_backends: 0,
    routable_backends: 0,
  },
  dataplane: {
    listen_address: 'Unavailable',
    listen_interface: 'Unavailable',
    attached_interfaces: [],
    xdp_attachments: [],
    protocol: 'Unavailable',
    routing_mode: 'Unavailable',
    ports: [],
    directional_flow_entries: 0,
    flow_map_complete: false,
  },
  connections: {
    active: 0,
    active_clients: 0,
    opened_per_second: 0,
    opened_total: 0,
    closed_per_second: 0,
    closed_total: 0,
    orphaned_per_second: 0,
    orphaned_total: 0,
  },
  ingress: {
    packets_per_second: 0,
    megabits_per_second: 0,
    bytes_per_second: 0,
    bytes_total: 0,
  },
  egress: {
    packets_per_second: 0,
    megabits_per_second: 0,
    bytes_per_second: 0,
    bytes_total: 0,
  },
  resources: {
    cpu_percent: null,
    host_cpu_percent: null,
    process_cpu_percent: null,
    network_percent: null,
    flow_map_percent: null,
    overall_percent: null,
  },
  backends: [],
}
