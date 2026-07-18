export type BackendState = 'available' | 'draining'
export type BackendSortKey =
  | 'name'
  | 'state'
  | 'timeInPoolSeconds'
  | 'activeConnections'
  | 'newConnectionsPerSecond'
  | 'ingressMbps'
  | 'egressMbps'
  | 'orphanedPerSecond'

export interface Backend {
  id: string
  name: string
  ip: string
  state: BackendState
  timeInPoolSeconds: number | null
  activeConnections: number
  activeClients: number
  newConnectionsPerSecond: number
  closedConnectionsPerSecond: number
  orphanedPerSecond: number
  ingressMbps: number
  egressMbps: number
  packetsPerSecond: number
  openedTotal: number
  closedTotal: number
  ingressBytesTotal: number
  egressBytesTotal: number
  ingressHistory: number[]
  egressHistory: number[]
  openedHistory: number[]
  closedHistory: number[]
}

export interface ChartSeries {
  name: string
  color: string
  values: ReadonlyArray<number | null>
  fill?: boolean
}
