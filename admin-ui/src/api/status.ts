export type Lifecycle = 'starting' | 'running' | 'shutting_down'
export type ProviderKind = 'static' | 'kubernetes'

export interface HealthStatus {
  healthy: boolean
  reason: string
}

export interface ReadinessStatus {
  ready: boolean
  reason: string
}

export interface TrafficStatus {
  packets_per_second: number
  megabits_per_second: number
  bytes_per_second: number
  bytes_total: number
}

export interface ConnectionStatus {
  active: number
  active_clients: number
  opened_per_second: number
  opened_total: number
  closed_per_second: number
  closed_total: number
  orphaned_per_second: number
  orphaned_total: number
}

export interface ResourceStatus {
  cpu_percent: number | null
  host_cpu_percent: number | null
  process_cpu_percent: number | null
  network_percent: number | null
  flow_map_percent: number | null
  overall_percent: number | null
}

export interface BackendStatus {
  name: string
  address: string
  discovered: boolean
  available_for_new_connections: boolean
  connections: ConnectionStatus
  ingress: TrafficStatus
  egress: TrafficStatus
}

export interface StatusSnapshot {
  schema_version: number
  service: string
  version: string
  lifecycle: Lifecycle
  uptime_seconds: number
  health: HealthStatus
  readiness: ReadinessStatus
  sampled_at_unix_ms: number | null
  sample_age_ms: number | null
  provider: {
    kind: ProviderKind
    healthy: boolean
    discovered_backends: number
    routable_backends: number
  }
  dataplane: {
    listen_address: string
    listen_interface: string
    attached_interfaces: string[]
    protocol: string
    routing_mode: string
    ports: Array<{ listen: number; backend: number }>
    directional_flow_entries: number
    flow_map_complete: boolean
  }
  connections: ConnectionStatus
  ingress: TrafficStatus
  egress: TrafficStatus
  resources: ResourceStatus
  backends: BackendStatus[]
}

export async function fetchStatus(signal?: AbortSignal): Promise<StatusSnapshot> {
  const response = await fetch('/api/v1/status', {
    cache: 'no-store',
    headers: { Accept: 'application/json' },
    signal,
  })
  if (!response.ok) throw new Error(`Status API returned HTTP ${response.status}`)
  const status = (await response.json()) as StatusSnapshot
  if (status.schema_version !== 1) throw new Error(`Unsupported status schema ${status.schema_version}`)
  return status
}
