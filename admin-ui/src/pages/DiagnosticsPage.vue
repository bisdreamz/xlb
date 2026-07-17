<script setup lang="ts">
import { computed } from 'vue'
import ComingSoon from '../components/ComingSoon.vue'
import UPlotChart from '../components/UPlotChart.vue'
import { useStatusStore } from '../stores/status'

const status = useStatusStore()
const snapshot = computed(() => status.snapshot.value)
const integer = new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 })
const percentLabel = (value: number | null) => (value === null ? 'Unavailable' : `${Math.round(value)}%`)
const sourceLabel = computed(
  () =>
    ({
      live: 'Live',
      stale: 'Stale',
      disconnected: 'Disconnected',
      demo: 'Demo data',
    })[status.source.value],
)
const xdpModeLabel = computed(() => {
  const dataplane = snapshot.value.dataplane
  const attachments = dataplane.xdp_attachments ?? []
  if (attachments.length === 0) {
    if (dataplane.attached_interfaces.length > 0) {
      return `Mode not reported · ${dataplane.attached_interfaces.join(', ')}`
    }
    return status.source.value === 'live' || status.source.value === 'stale' ? 'Not attached' : 'Unavailable'
  }

  const modeName = (mode: (typeof attachments)[number]['mode']) =>
    mode === 'native' ? 'Native driver' : 'Generic (SKB fallback)'
  const modes = new Set(attachments.map((attachment) => attachment.mode))
  if (modes.size === 1) {
    return `${modeName(attachments[0].mode)} · ${attachments.map(({ interface: name }) => name).join(', ')}`
  }
  return attachments.map((attachment) => `${attachment.interface}: ${modeName(attachment.mode)}`).join(' · ')
})

const resourceSeries = computed(() => [
  { name: 'Network', color: '#ef4b23', values: status.history.networkPercent },
  { name: 'Host CPU', color: '#167452', values: status.history.hostCpuPercent },
  { name: 'Process CPU', color: '#7199ad', values: status.history.processCpuPercent },
  { name: 'Flow map', color: '#94ad3b', values: status.history.flowMapPercent },
])
</script>

<template>
  <section class="route-hero page-shell">
    <div>
      <p class="eyebrow-label"><i></i> Diagnostics</p>
      <h1>Why traffic might not be routed.</h1>
      <p>
        Runtime integrity, capacity pressure, and failed-work counters are kept off the overview until they
        require attention.
      </p>
    </div>
    <div class="route-hero__facts">
      <div>
        <span>Map scan</span
        ><strong>{{ snapshot.dataplane.flow_map_complete ? 'Complete' : 'Incomplete' }}</strong>
      </div>
      <div>
        <span>Overall pressure</span><strong>{{ percentLabel(snapshot.resources.overall_percent) }}</strong>
      </div>
    </div>
  </section>

  <section class="page-shell">
    <div class="diagnostic-failures">
      <header>
        <div>
          <span class="section-index">01 / Failed work</span>
          <h2>Traffic XLB could not route</h2>
        </div>
        <span class="planned-badge">Coming soon</span>
      </header>
      <ComingSoon
        title="Failed-work counters are not collected yet"
        description="No route-failure, map-insertion, port-allocation, malformed-packet, or repair values are estimated here. This panel will activate after reviewed per-CPU counters reach the status API."
      />
    </div>
  </section>

  <section class="diagnostics-grid page-shell">
    <article class="panel">
      <header class="panel-head">
        <div>
          <span class="section-index">02 / Resource history</span>
          <h2>Capacity pressure</h2>
          <p>Every series is already available from the one-second status snapshot.</p>
        </div>
      </header>
      <UPlotChart :series="resourceSeries" unit="%" range-label="Browser history" />
    </article>

    <article class="runtime-card runtime-card--dark">
      <span class="section-index">03 / Dataplane</span>
      <h2>Fast path attached and current.</h2>
      <dl>
        <div>
          <dt>Attached interfaces</dt>
          <dd>{{ snapshot.dataplane.attached_interfaces.join(', ') || 'None' }}</dd>
        </div>
        <div>
          <dt>Routing</dt>
          <dd>{{ snapshot.dataplane.routing_mode }} / {{ snapshot.dataplane.protocol }}</dd>
        </div>
        <div>
          <dt>Directional entries</dt>
          <dd>{{ integer.format(snapshot.dataplane.directional_flow_entries) }}</dd>
        </div>
        <div>
          <dt>Map scan</dt>
          <dd>{{ snapshot.dataplane.flow_map_complete ? 'Complete' : 'Incomplete' }}</dd>
        </div>
        <div>
          <dt>XDP attachment mode</dt>
          <dd>{{ xdpModeLabel }}</dd>
        </div>
        <div>
          <dt>Status schema</dt>
          <dd>v{{ snapshot.schema_version }}</dd>
        </div>
      </dl>
    </article>
  </section>

  <section class="status-contract page-shell">
    <div>
      <span class="section-index">Status contract</span>
      <h2>Current data boundaries are explicit.</h2>
    </div>
    <dl>
      <div>
        <dt>Live endpoint</dt>
        <dd>/api/v1/status</dd>
      </div>
      <div>
        <dt>Health</dt>
        <dd>/healthz</dd>
      </div>
      <div>
        <dt>Readiness</dt>
        <dd>/readyz</dd>
      </div>
      <div>
        <dt>UI source</dt>
        <dd>{{ sourceLabel }}</dd>
      </div>
    </dl>
  </section>
</template>
