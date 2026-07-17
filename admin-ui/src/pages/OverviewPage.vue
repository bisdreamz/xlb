<script setup lang="ts">
import { computed } from 'vue'
import { RouterLink } from 'vue-router'
import ComingSoon from '../components/ComingSoon.vue'
import HelpTip from '../components/HelpTip.vue'
import MetricCard from '../components/MetricCard.vue'
import UPlotChart from '../components/UPlotChart.vue'
import { useStatusStore } from '../stores/status'

const status = useStatusStore()
const snapshot = computed(() => status.snapshot.value)
const integer = new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 })
const compact = new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 1 })

const percent = (value: number | null) => (value === null ? null : Math.round(value))
const percentLabel = (value: number | null) => {
  const reported = percent(value)
  return reported === null ? 'Unavailable' : `${reported}%`
}
const barWidth = (value: number | null) => `${percent(value) ?? 0}%`
const capacityHeadroom = computed(() => {
  const overall = percent(snapshot.value.resources.overall_percent)
  return overall === null ? null : 100 - overall
})
const missingCapacitySignals = computed(() => {
  const resources = snapshot.value.resources
  return [
    resources.cpu_percent === null ? 'CPU pressure' : null,
    resources.network_percent === null ? 'NIC capacity' : null,
    resources.flow_map_percent === null ? 'flow-map pressure' : null,
  ].filter((signal): signal is string => signal !== null)
})
const missingCapacityLabel = computed(() =>
  missingCapacitySignals.value.length === 0
    ? 'Composite resource signal unavailable'
    : `Missing ${missingCapacitySignals.value.join(', ')}`,
)
const sourceLabel = computed(
  () =>
    ({
      live: 'Live',
      stale: 'Stale',
      disconnected: 'Disconnected',
      demo: 'Demo data',
    })[status.source.value],
)
const uptime = computed(() => {
  const seconds = snapshot.value.uptime_seconds
  const days = Math.floor(seconds / 86_400)
  const hours = Math.floor((seconds % 86_400) / 3_600)
  const minutes = Math.floor((seconds % 3_600) / 60)
  return `${days}d ${hours.toString().padStart(2, '0')}h ${minutes.toString().padStart(2, '0')}m`
})

const trafficSeries = computed(() => [
  { name: 'Ingress', color: '#ef4b23', values: status.history.ingressGbps, fill: true },
  { name: 'Egress', color: '#167452', values: status.history.egressGbps },
])

const totalTraffic = computed(
  () => snapshot.value.ingress.megabits_per_second + snapshot.value.egress.megabits_per_second,
)
const totalPackets = computed(
  () => snapshot.value.ingress.packets_per_second + snapshot.value.egress.packets_per_second,
)
const draining = computed(() =>
  Math.max(0, snapshot.value.provider.discovered_backends - snapshot.value.provider.routable_backends),
)
</script>

<template>
  <section class="instance-hero page-shell">
    <div class="instance-hero__copy">
      <p class="eyebrow-label"><i></i> XDP dataplane / Local instance</p>
      <h1>{{ snapshot.service }} <span>/</span> {{ snapshot.dataplane.listen_interface }}</h1>
      <p>
        Direct visibility into the load balancer serving this page. Fleet-wide and durable history remains in
        your OpenTelemetry platform.
      </p>
    </div>
    <div class="instance-identity" aria-label="Instance identity">
      <div>
        <span>Provider</span><strong>{{ snapshot.provider.kind }}</strong>
      </div>
      <div>
        <span>Listen</span
        ><strong>{{ snapshot.dataplane.listen_address }} / {{ snapshot.dataplane.listen_interface }}</strong>
      </div>
      <div>
        <span>Version</span
        ><strong
          >{{ snapshot.version }} / {{ snapshot.dataplane.routing_mode }}
          {{ snapshot.dataplane.protocol }}</strong
        >
      </div>
      <div>
        <span>Uptime</span><strong>{{ uptime }}</strong>
      </div>
    </div>
  </section>

  <section class="health-strip page-shell" aria-label="Current service health">
    <div class="health-strip__status">
      <span class="health-icon" :class="{ 'health-icon--warning': !snapshot.readiness.ready }">{{
        snapshot.readiness.ready ? '✓' : '!'
      }}</span>
      <div>
        <strong>{{
          snapshot.readiness.ready ? 'Ready for new connections' : 'Not ready for new connections'
        }}</strong
        ><small
          >Provider {{ snapshot.provider.healthy ? 'synchronized' : 'unhealthy' }} · dataplane
          {{ snapshot.dataplane.flow_map_complete ? 'current' : 'incomplete' }} ·
          {{ snapshot.provider.routable_backends }} accepting backends</small
        >
      </div>
    </div>
    <div class="health-strip__note">
      <span>{{ draining }} draining</span
      ><span>{{ snapshot.connections.orphaned_per_second.toFixed(1) }}/s idle removals</span
      ><RouterLink to="/backends">Review backend pool →</RouterLink>
    </div>
  </section>

  <section class="metric-grid page-shell" aria-label="Key instance metrics">
    <MetricCard
      index="01"
      label="Backend pool"
      :value="integer.format(snapshot.provider.discovered_backends)"
      :detail="`${snapshot.provider.routable_backends} accepting${draining ? ` · ${draining} draining` : ''}`"
      tone="mint"
      :history="status.history.backendCount"
    />
    <MetricCard
      index="02"
      label="Active connections"
      :value="integer.format(snapshot.connections.active)"
      :detail="`${integer.format(snapshot.connections.active_clients)} active clients`"
      :history="status.history.activeConnections"
    />
    <MetricCard
      index="03"
      label="New connections"
      :value="`${integer.format(snapshot.connections.opened_per_second)}/s`"
      :detail="`${integer.format(snapshot.connections.closed_per_second)}/s closed`"
      :history="status.history.openedKps"
    />
    <MetricCard
      index="04"
      label="Bidirectional traffic"
      :value="`${(totalTraffic / 1_000).toFixed(1)} Gbps`"
      :detail="`${(snapshot.ingress.megabits_per_second / 1_000).toFixed(1)} in / ${(snapshot.egress.megabits_per_second / 1_000).toFixed(1)} out`"
      :history="
        status.history.ingressGbps.map((value, index) => value + (status.history.egressGbps[index] ?? 0))
      "
    />
    <MetricCard
      index="05"
      label="Packet rate"
      :value="`${(totalPackets / 1_000_000).toFixed(2)} Mpps`"
      :detail="`${(snapshot.ingress.packets_per_second / 1_000_000).toFixed(2)} in / ${(snapshot.egress.packets_per_second / 1_000_000).toFixed(2)} out`"
      :history="status.history.packetMpps"
    />
    <MetricCard
      index="06"
      label="Resource pressure"
      :value="percentLabel(snapshot.resources.overall_percent)"
      :detail="
        snapshot.resources.overall_percent === null
          ? missingCapacityLabel
          : 'Highest CPU, network, or flow-map signal'
      "
      tone="lime"
      :bar="percent(snapshot.resources.overall_percent) ?? undefined"
      :history="snapshot.resources.overall_percent === null ? [] : status.history.overallPercent"
    />
  </section>

  <section class="trend-layout page-shell">
    <article class="panel traffic-panel">
      <header class="panel-head">
        <div>
          <span class="section-index">01 / Traffic</span>
          <h2>Bidirectional throughput</h2>
          <p>One-second local status samples retained in this browser for up to 30 minutes.</p>
        </div>
        <RouterLink class="panel-link" to="/connections">Connection detail →</RouterLink>
      </header>
      <UPlotChart :series="trafficSeries" unit=" Gbps" range-label="Browser history" />
      <footer class="panel-foot">
        <span
          >Ingress <strong>{{ compact.format(snapshot.ingress.bytes_total) }}B total</strong></span
        ><span
          >Egress <strong>{{ compact.format(snapshot.egress.bytes_total) }}B total</strong></span
        >
      </footer>
    </article>

    <aside class="panel resource-panel">
      <header class="panel-head">
        <div>
          <span class="section-index">02 / Capacity</span>
          <h2>Resource pressure</h2>
          <p>The highest complete signal determines overall utilization.</p>
        </div>
      </header>
      <div
        class="resource-score"
        :class="{ 'resource-score--unavailable': snapshot.resources.overall_percent === null }"
      >
        <template v-if="snapshot.resources.overall_percent !== null">
          <strong>{{ percent(snapshot.resources.overall_percent) }}</strong
          ><span>%</span>
        </template>
        <strong v-else>Not available</strong>
        <small>Overall</small>
      </div>
      <div class="resource-bars">
        <div>
          <span
            ><b
              >Network
              <HelpTip
                v-if="snapshot.resources.network_percent === null"
                explanation="This host does not report NIC line rate, so XLB cannot calculate a network-capacity percentage. Traffic rates remain available."
              /> </b
            ><small>{{
              snapshot.resources.network_percent === null
                ? 'Capacity unknown'
                : percentLabel(snapshot.resources.network_percent)
            }}</small></span
          ><i><em :style="{ width: barWidth(snapshot.resources.network_percent) }"></em></i>
        </div>
        <div>
          <span
            ><b>Host CPU</b><small>{{ percentLabel(snapshot.resources.host_cpu_percent) }}</small></span
          ><i><em :style="{ width: barWidth(snapshot.resources.host_cpu_percent) }"></em></i>
        </div>
        <div>
          <span
            ><b>Process CPU</b><small>{{ percentLabel(snapshot.resources.process_cpu_percent) }}</small></span
          ><i><em :style="{ width: barWidth(snapshot.resources.process_cpu_percent) }"></em></i>
        </div>
        <div>
          <span
            ><b>Flow map</b><small>{{ percentLabel(snapshot.resources.flow_map_percent) }}</small></span
          ><i><em :style="{ width: barWidth(snapshot.resources.flow_map_percent) }"></em></i>
        </div>
      </div>
      <div class="resource-note">
        <span>Capacity headroom</span
        ><strong>{{ capacityHeadroom === null ? '—' : `${capacityHeadroom}%` }}</strong
        ><small>{{
          capacityHeadroom === null
            ? `${missingCapacityLabel}; reported signals remain visible above`
            : 'Composite signal available for autoscaling'
        }}</small>
      </div>
    </aside>
  </section>

  <section class="overview-lower page-shell">
    <article class="runtime-card activity-card">
      <div class="activity-head">
        <span class="section-index">Recent activity</span><RouterLink to="/events">All events →</RouterLink>
      </div>
      <ComingSoon
        class="coming-soon--dark"
        title="Lifecycle activity is not collected yet"
        description="Status schema v1 does not contain an event stream. This area stays empty in both live and demo modes—no backend or runtime events are fabricated."
        compact
      />
    </article>

    <article class="runtime-card overview-health-card">
      <span class="section-index">Current health</span>
      <h2>
        {{
          snapshot.health.healthy
            ? 'All core systems are reporting normally.'
            : 'This instance needs attention.'
        }}
      </h2>
      <dl>
        <div>
          <dt>Backend discovery</dt>
          <dd>{{ snapshot.provider.healthy ? 'Current' : 'Unhealthy' }}</dd>
        </div>
        <div>
          <dt>Connection-map scan</dt>
          <dd>{{ snapshot.dataplane.flow_map_complete ? 'Complete' : 'Incomplete' }}</dd>
        </div>
        <div>
          <dt>Attached interfaces</dt>
          <dd>{{ snapshot.dataplane.attached_interfaces.length }}</dd>
        </div>
        <div>
          <dt>Status source</dt>
          <dd>{{ sourceLabel }}</dd>
        </div>
      </dl>
      <RouterLink class="panel-link" to="/diagnostics">Open diagnostics →</RouterLink>
    </article>
  </section>
</template>
