<script setup lang="ts">
import { computed, ref } from 'vue'
import ComingSoon from '../components/ComingSoon.vue'
import HelpTip from '../components/HelpTip.vue'
import MetricCard from '../components/MetricCard.vue'
import UPlotChart from '../components/UPlotChart.vue'
import { useStatusStore } from '../stores/status'

const status = useStatusStore()
const range = ref<'5m' | '15m' | '30m'>('15m')
const integer = new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 })

const rangePoints = computed(() => ({ '5m': 300, '15m': 900, '30m': 1_800 })[range.value])
const rangeLabel = computed(
  () => ({ '5m': '5 minutes', '15m': '15 minutes', '30m': '30 minutes' })[range.value],
)
const tail = (values: readonly number[]) => values.slice(-rangePoints.value)

const connectionSeries = computed(() => [
  { name: 'Opened', color: '#ef4b23', values: tail(status.history.openedKps) },
  { name: 'Closed', color: '#167452', values: tail(status.history.closedKps) },
])
</script>

<template>
  <section class="route-hero page-shell">
    <div>
      <p class="eyebrow-label"><i></i> Connections</p>
      <h1>How traffic sessions behave.</h1>
      <p>Separate connection volume from close behavior, idle removals, and backend response latency.</p>
    </div>
    <div class="route-hero__facts">
      <div>
        <span>Active</span><strong>{{ integer.format(status.snapshot.value.connections.active) }}</strong>
      </div>
      <div>
        <span>Idle removals</span
        ><strong>{{ status.snapshot.value.connections.orphaned_per_second.toFixed(1) }}/s</strong>
      </div>
    </div>
  </section>

  <section class="connection-summary-grid page-shell">
    <MetricCard
      index="01"
      label="Active connections"
      :value="integer.format(status.snapshot.value.connections.active)"
      :detail="`${integer.format(status.snapshot.value.connections.active_clients)} active clients`"
      :history="status.history.activeConnections"
    />
    <MetricCard
      index="02"
      label="Opened"
      :value="`${integer.format(status.snapshot.value.connections.opened_per_second)}/s`"
      :detail="`${integer.format(status.snapshot.value.connections.opened_total)} process total`"
      :history="status.history.openedKps"
    />
    <MetricCard
      index="03"
      label="Closed"
      :value="`${integer.format(status.snapshot.value.connections.closed_per_second)}/s`"
      :detail="`${integer.format(status.snapshot.value.connections.closed_total)} process total`"
      :history="status.history.closedKps"
    />
    <MetricCard
      index="04"
      label="Idle-timeout removal"
      :value="`${status.snapshot.value.connections.orphaned_per_second.toFixed(1)}/s`"
      :detail="`${integer.format(status.snapshot.value.connections.orphaned_total)} process total`"
      tone="orange"
      :history="status.history.orphanedRate"
    />
  </section>

  <section class="page-shell connection-route-panel">
    <article class="panel connection-panel">
      <header class="panel-head">
        <div>
          <span class="section-index">01 / Connection behavior</span>
          <h2>Connection lifecycle</h2>
          <p>Opened and closed volume share one scale. Close details separate the actor and reason.</p>
        </div>
        <div class="range-control" aria-label="Chart time range">
          <button
            v-for="option in ['5m', '15m', '30m'] as const"
            :key="option"
            type="button"
            :class="{ active: range === option }"
            @click="range = option"
          >
            {{ option }}
          </button>
        </div>
      </header>
      <div class="connection-view-tabs" aria-label="Connection graph">
        <button type="button" class="active">Opened and closed</button>
        <button type="button" disabled title="Close breakdown coming soon">
          Close breakdown <span>Coming soon</span>
        </button>
      </div>
      <UPlotChart :series="connectionSeries" unit="k/s" :range-label="rangeLabel" />
    </article>
  </section>

  <section class="page-shell connection-latency-layout">
    <article class="panel latency-panel">
      <header class="panel-head">
        <div>
          <span class="section-index">02 / Passive backend latency</span>
          <h2>Backend connection response</h2>
          <p>Time from a client connection attempt reaching XLB until the selected backend responds.</p>
        </div>
        <span class="planned-badge">Coming soon</span>
      </header>
      <ComingSoon
        title="Passive backend latency is not collected yet"
        description="This panel will activate after the reviewed dataplane timing metric and status API extension land. No latency values are estimated or simulated here."
      />
    </article>

    <aside class="connection-meaning panel">
      <span class="section-index">Reading the signals</span>
      <h2>What deserves attention?</h2>
      <dl>
        <div>
          <dt>
            Unexpected reset
            <HelpTip
              explanation="A client or backend terminated a connection immediately instead of using the normal close sequence."
            />
          </dt>
          <dd>Investigate when its share rises above the application's normal baseline.</dd>
        </div>
        <div>
          <dt>No close received</dt>
          <dd>
            Usually the strongest signal. It can also mean XLB's idle timeout is shorter than the
            application's connection lifetime.
          </dd>
        </div>
        <div>
          <dt>Backend response <span class="proposed-text">Coming soon</span></dt>
          <dd>Passive latency will identify a reachable but overloaded backend after collection lands.</dd>
        </div>
      </dl>
    </aside>
  </section>
</template>
