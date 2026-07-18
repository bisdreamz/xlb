import type { Backend } from '../types'

const wave = (base: number, variance: number, phase: number, points = 36) =>
  Array.from({ length: points }, (_, index) => {
    const primary = Math.sin(index / 4 + phase) * variance
    const secondary = Math.cos(index / 2.7 + phase * 1.8) * variance * 0.28
    return Math.max(0, Number((base + primary + secondary).toFixed(2)))
  })

const definitions = [
  ['bidder-api-7f8797d8f4-2kq9p', '10.42.18.21', 'available'],
  ['bidder-api-7f8797d8f4-5hrtx', '10.42.23.14', 'available'],
  ['bidder-api-7f8797d8f4-7vmcs', '10.42.31.08', 'available'],
  ['bidder-api-7f8797d8f4-b9l2n', '10.42.18.34', 'available'],
  ['bidder-api-7f8797d8f4-f4x2m', '10.42.23.27', 'available'],
  ['bidder-api-7f8797d8f4-h7d6q', '10.42.31.19', 'available'],
  ['bidder-api-7f8797d8f4-k8m4r', '10.42.18.47', 'available'],
  ['bidder-api-7f8797d8f4-m2n8s', '10.42.23.39', 'draining'],
  ['bidder-api-7f8797d8f4-p5t7v', '10.42.31.28', 'available'],
  ['bidder-api-7f8797d8f4-r6w3x', '10.42.18.53', 'available'],
  ['bidder-api-7f8797d8f4-v9c2z', '10.42.23.46', 'available'],
  ['bidder-api-7f8797d8f4-x3j5k', '10.42.31.36', 'available'],
] as const

export const backends: Backend[] = definitions.map((definition, index) => {
  const [name, ip, state] = definition
  const active = state === 'draining' ? 1238 : 13200 + ((index * 1783) % 5100)
  const ingress = state === 'draining' ? 94 : 710 + ((index * 97) % 290)
  const egress = state === 'draining' ? 53 : 480 + ((index * 71) % 220)
  const closed = state === 'draining' ? 147 : 2110 + ((index * 277) % 990)

  return {
    id: ip,
    name,
    ip,
    state,
    timeInPoolSeconds: 86_400 + index * 3_600,
    activeConnections: active,
    activeClients: Math.round(active * 0.61),
    newConnectionsPerSecond: state === 'draining' ? 0 : 2180 + ((index * 293) % 1040),
    closedConnectionsPerSecond: closed,
    orphanedPerSecond: index === 4 ? 1.7 : index === 7 ? 0.4 : Number(((index % 3) * 0.1).toFixed(1)),
    ingressMbps: ingress,
    egressMbps: egress,
    packetsPerSecond: 172000 + index * 7100,
    openedTotal: 8240000 + index * 527000,
    closedTotal: 8170000 + index * 519000,
    ingressBytesTotal: 1490000000000 + index * 91000000000,
    egressBytesTotal: 1010000000000 + index * 72000000000,
    ingressHistory: wave(ingress, 68, index * 0.47),
    egressHistory: wave(egress, 51, index * 0.39),
    openedHistory: wave(state === 'draining' ? 0 : 2180 + ((index * 293) % 1040), 270, index * 0.31),
    closedHistory: wave(closed, 240, index * 0.55),
  }
})

export const trafficHistory = {
  ingress: wave(10.72, 1.08, 0.2),
  egress: wave(7.68, 0.79, 1.1),
}

export const connectionHistory = {
  opened: wave(31.84, 3.7, 0.4),
  closed: wave(30.97, 3.1, 0.9),
  orphaned: wave(1.9, 0.75, 2.1),
}

export const overviewHistory = {
  backends: [12, 12, 12, 12, 12, 12, 12, 11, 11, 12, 12, 12, 12, 12, 12, 12, 12, 12],
  activeConnections: wave(184_219, 11_500, 0.7),
  packetsMpps: wave(2.63, 0.21, 1.1),
  resourcePercent: wave(62, 5.2, 1.8),
}
