import { computed, reactive, readonly, ref } from 'vue'
import { fetchStatus } from '../api/status'
import type { StatusSnapshot } from '../api/status'
import { backends, connectionHistory, overviewHistory, trafficHistory } from '../data/mock'
import { demoStatus } from '../data/demo-status'
import { unavailableStatus } from '../data/unavailable-status'
import type { Backend } from '../types'

const MAX_HISTORY_POINTS = 30 * 60
const MAX_BACKEND_HISTORY_POINTS = 15 * 60
const STATUS_REQUEST_TIMEOUT_MS = 5_000
const demoMode = import.meta.env.MODE === 'demo'

export type StatusSource = 'live' | 'stale' | 'disconnected' | 'demo'

const snapshot = ref<StatusSnapshot>(demoMode ? demoStatus : unavailableStatus)
const source = ref<StatusSource>(demoMode ? 'demo' : 'disconnected')
const error = ref<string | null>(null)
const lastUpdatedAt = ref<number | null>(demoMode ? Date.now() : null)
const polling = ref(false)
const clock = ref(Date.now())
const seed = (values: number[]) => (demoMode ? [...values] : [])
const resourceSeed = (values: number[]): Array<number | null> => seed(values)

const history = reactive({
  ingressGbps: seed(trafficHistory.ingress),
  egressGbps: seed(trafficHistory.egress),
  openedKps: seed(connectionHistory.opened),
  closedKps: seed(connectionHistory.closed),
  orphanedRate: seed(connectionHistory.orphaned),
  backendCount: seed(overviewHistory.backends),
  activeConnections: seed(overviewHistory.activeConnections),
  packetMpps: seed(overviewHistory.packetsMpps),
  overallPercent: resourceSeed(overviewHistory.resourcePercent),
  hostCpuPercent: resourceSeed(overviewHistory.resourcePercent.map((value) => Math.max(0, value - 24))),
  processCpuPercent: resourceSeed(overviewHistory.resourcePercent.map((value) => Math.max(0, value - 48))),
  networkPercent: resourceSeed(overviewHistory.resourcePercent),
  flowMapPercent: resourceSeed(overviewHistory.resourcePercent.map((value) => Math.max(0, value - 45))),
})

let timer: number | undefined
let controller: AbortController | undefined
let lastSampleTimestamp: number | null = null

interface BackendHistory {
  ingressMbps: number[]
  egressMbps: number[]
  openedPerSecond: number[]
  closedPerSecond: number[]
}

const backendHistories = reactive(new Map<string, BackendHistory>())

const appendNumber = (values: number[], value: number, limit = MAX_HISTORY_POINTS) => {
  values.push(Number.isFinite(value) ? value : 0)
  if (values.length > limit) values.splice(0, values.length - limit)
}

const appendResource = (values: Array<number | null>, value: number | null, limit = MAX_HISTORY_POINTS) => {
  values.push(value !== null && Number.isFinite(value) ? value : null)
  if (values.length > limit) values.splice(0, values.length - limit)
}

const appendBackendSamples = (status: StatusSnapshot) => {
  const present = new Set<string>()
  for (const backend of status.backends) {
    present.add(backend.address)
    let values = backendHistories.get(backend.address)
    if (!values) {
      values = {
        ingressMbps: [],
        egressMbps: [],
        openedPerSecond: [],
        closedPerSecond: [],
      }
      backendHistories.set(backend.address, values)
    }
    appendNumber(values.ingressMbps, backend.ingress.megabits_per_second, MAX_BACKEND_HISTORY_POINTS)
    appendNumber(values.egressMbps, backend.egress.megabits_per_second, MAX_BACKEND_HISTORY_POINTS)
    appendNumber(values.openedPerSecond, backend.connections.opened_per_second, MAX_BACKEND_HISTORY_POINTS)
    appendNumber(values.closedPerSecond, backend.connections.closed_per_second, MAX_BACKEND_HISTORY_POINTS)
  }

  for (const address of backendHistories.keys()) {
    if (!present.has(address)) backendHistories.delete(address)
  }
}

const appendSample = (status: StatusSnapshot) => {
  const timestamp = status.sampled_at_unix_ms
  if (timestamp !== null && timestamp === lastSampleTimestamp) return
  lastSampleTimestamp = timestamp

  appendNumber(history.ingressGbps, status.ingress.megabits_per_second / 1_000)
  appendNumber(history.egressGbps, status.egress.megabits_per_second / 1_000)
  appendNumber(history.openedKps, status.connections.opened_per_second / 1_000)
  appendNumber(history.closedKps, status.connections.closed_per_second / 1_000)
  appendNumber(history.orphanedRate, status.connections.orphaned_per_second)
  appendNumber(history.backendCount, status.provider.discovered_backends)
  appendNumber(history.activeConnections, status.connections.active)
  appendNumber(
    history.packetMpps,
    (status.ingress.packets_per_second + status.egress.packets_per_second) / 1_000_000,
  )
  appendResource(history.overallPercent, status.resources.overall_percent)
  appendResource(history.hostCpuPercent, status.resources.host_cpu_percent)
  appendResource(history.processCpuPercent, status.resources.process_cpu_percent)
  appendResource(history.networkPercent, status.resources.network_percent)
  appendResource(history.flowMapPercent, status.resources.flow_map_percent)
  appendBackendSamples(status)
}

const emptyHistory = (): BackendHistory => ({
  ingressMbps: [],
  egressMbps: [],
  openedPerSecond: [],
  closedPerSecond: [],
})

const liveBackend = (backend: StatusSnapshot['backends'][number]): Backend => {
  const values = backendHistories.get(backend.address) ?? emptyHistory()
  return {
    id: backend.address,
    name: backend.name,
    ip: backend.address,
    state: backend.available_for_new_connections ? 'available' : 'draining',
    timeInPoolSeconds: backend.time_in_pool_seconds ?? null,
    activeConnections: backend.connections.active,
    activeClients: backend.connections.active_clients,
    newConnectionsPerSecond: backend.connections.opened_per_second,
    closedConnectionsPerSecond: backend.connections.closed_per_second,
    orphanedPerSecond: backend.connections.orphaned_per_second,
    ingressMbps: backend.ingress.megabits_per_second,
    egressMbps: backend.egress.megabits_per_second,
    packetsPerSecond: backend.ingress.packets_per_second + backend.egress.packets_per_second,
    openedTotal: backend.connections.opened_total,
    closedTotal: backend.connections.closed_total,
    ingressBytesTotal: backend.ingress.bytes_total,
    egressBytesTotal: backend.egress.bytes_total,
    ingressHistory: values.ingressMbps,
    egressHistory: values.egressMbps,
    openedHistory: values.openedPerSecond,
    closedHistory: values.closedPerSecond,
  }
}

const backendRows = computed(() =>
  source.value === 'demo' ? backends : snapshot.value.backends.map(liveBackend),
)

const sampleAgeSeconds = computed(() => {
  if (source.value === 'demo') return null
  if (source.value === 'disconnected') return null
  const sampledAt = snapshot.value.sampled_at_unix_ms
  return sampledAt === null ? null : Math.max(0, (clock.value - sampledAt) / 1_000)
})

const poll = async () => {
  if (controller) return
  const ownController = new AbortController()
  let timedOut = false
  const timeout = window.setTimeout(() => {
    timedOut = true
    ownController.abort()
  }, STATUS_REQUEST_TIMEOUT_MS)
  controller = ownController
  try {
    const next = await fetchStatus(ownController.signal)
    if (timedOut) throw new Error('Status API request timed out')
    if (ownController.signal.aborted || !polling.value) return
    snapshot.value = next
    source.value = 'live'
    error.value = null
    lastUpdatedAt.value = Date.now()
    appendSample(next)
  } catch (cause) {
    if (ownController.signal.aborted && !timedOut) return
    error.value = timedOut
      ? 'Status API request timed out'
      : cause instanceof Error
        ? cause.message
        : 'Status API request failed'
    if (source.value === 'live' || source.value === 'stale') source.value = 'stale'
  } finally {
    window.clearTimeout(timeout)
    if (controller === ownController) controller = undefined
  }
}

const start = () => {
  if (demoMode || polling.value) return
  polling.value = true
  void poll()
  timer = window.setInterval(() => {
    clock.value = Date.now()
    void poll()
  }, 1_000)
}

const stop = () => {
  polling.value = false
  if (timer !== undefined) window.clearInterval(timer)
  timer = undefined
  controller?.abort()
  controller = undefined
}

export const useStatusStore = () => ({
  snapshot: readonly(snapshot),
  source: readonly(source),
  error: readonly(error),
  polling: readonly(polling),
  lastUpdatedAt: readonly(lastUpdatedAt),
  history: readonly(history),
  backendRows,
  sampleAgeSeconds,
  start,
  stop,
})
