<script setup lang="ts">
import { computed, nextTick, ref, watch } from 'vue'
import type { Backend } from '../types'
import ComingSoon from './ComingSoon.vue'
import HelpTip from './HelpTip.vue'
import UPlotChart from './UPlotChart.vue'

type HistoryView = 'connections' | 'closures' | 'latency' | 'traffic'

const props = defineProps<{
  backend: Backend | null
  sampleDescription: string
}>()

const emit = defineEmits<{
  close: []
}>()

const integer = new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 })
const bytes = new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 2 })
const duration = (seconds: number | null) => {
  if (seconds === null) return 'Unavailable'
  const days = Math.floor(seconds / 86_400)
  const hours = Math.floor((seconds % 86_400) / 3_600)
  const minutes = Math.floor((seconds % 3_600) / 60)
  if (days > 0) return `${days}d ${hours}h`
  if (hours > 0) return `${hours}h ${minutes}m`
  if (minutes > 0) return `${minutes}m`
  return `${seconds}s`
}
const historyView = ref<HistoryView>('connections')
const historyViews: HistoryView[] = ['connections', 'closures', 'latency', 'traffic']
const historyViewLabels: Record<HistoryView, string> = {
  connections: 'Activity',
  closures: 'Close breakdown',
  latency: 'Latency',
  traffic: 'Traffic',
}
const futureView = (view: HistoryView) => view === 'closures' || view === 'latency'
const drawer = ref<HTMLElement | null>(null)
const closeButton = ref<HTMLButtonElement | null>(null)
let returnFocus: HTMLElement | null = null

const close = () => emit('close')
const handleKeydown = (event: KeyboardEvent) => {
  if (event.key === 'Escape') {
    event.preventDefault()
    close()
    return
  }
  if (event.key !== 'Tab' || !drawer.value) return

  const focusable = [
    ...drawer.value.querySelectorAll<HTMLElement>(
      'button:not(:disabled), a[href], input:not(:disabled), select:not(:disabled), [tabindex]:not([tabindex="-1"])',
    ),
  ]
  if (!focusable.length) {
    event.preventDefault()
    drawer.value.focus()
    return
  }

  const first = focusable[0]
  const last = focusable.at(-1)!
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault()
    last.focus()
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault()
    first.focus()
  }
}

watch(
  () => props.backend,
  async (backend, previous) => {
    if (backend && !previous) {
      returnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null
      await nextTick()
      const focusTarget = closeButton.value ?? drawer.value
      focusTarget?.focus()
    } else if (!backend && previous) {
      await nextTick()
      returnFocus?.focus()
      returnFocus = null
    }
  },
  { immediate: true },
)

const chartSeries = computed(() => {
  if (!props.backend) return []

  if (historyView.value === 'traffic') {
    return [
      { name: 'Ingress', color: '#ef4b23', values: props.backend.ingressHistory, fill: true },
      { name: 'Egress', color: '#167452', values: props.backend.egressHistory },
    ]
  }

  return [
    { name: 'Opened', color: '#ef4b23', values: props.backend.openedHistory },
    { name: 'Closed', color: '#167452', values: props.backend.closedHistory },
  ]
})

const chartTitle = computed(
  () =>
    ({
      connections: 'Connection lifecycle',
      closures: 'Close breakdown',
      latency: 'TCP handshake latency',
      traffic: 'Traffic rate',
    })[historyView.value],
)

const chartUnit = computed(
  () =>
    ({
      connections: ' /s',
      closures: ' /s',
      latency: ' ms',
      traffic: ' Mbps',
    })[historyView.value],
)
</script>

<template>
  <Teleport to="body">
    <Transition name="drawer">
      <div v-if="backend" class="drawer-layer" @click.self="close">
        <aside
          ref="drawer"
          class="backend-drawer"
          role="dialog"
          aria-modal="true"
          aria-labelledby="backend-drawer-title"
          tabindex="-1"
          @keydown="handleKeydown"
        >
          <header class="backend-drawer__head">
            <div>
              <span class="eyebrow-label">Backend drill-down</span>
              <h2 id="backend-drawer-title">{{ backend.name }}</h2>
              <p>{{ backend.ip }}</p>
            </div>
            <button
              ref="closeButton"
              class="icon-button"
              type="button"
              aria-label="Close backend details"
              @click="close"
            >
              ×
            </button>
          </header>

          <div class="backend-drawer__state">
            <span class="state-label" :class="`state-label--${backend.state}`">{{ backend.state }}</span>
            <span>{{ sampleDescription }}</span>
          </div>

          <section class="drawer-section">
            <div class="drawer-section__title">
              <span>Current load</span>
              <small>Live / 1 sec</small>
            </div>
            <div class="drawer-metrics">
              <div>
                <span>Active connections</span
                ><strong>{{ integer.format(backend.activeConnections) }}</strong>
              </div>
              <div>
                <span>Active clients</span><strong>{{ integer.format(backend.activeClients) }}</strong>
              </div>
              <div>
                <span>New / sec</span><strong>{{ integer.format(backend.newConnectionsPerSecond) }}</strong>
              </div>
              <div>
                <span>Closed / sec</span
                ><strong>{{ integer.format(backend.closedConnectionsPerSecond) }}</strong>
              </div>
              <div>
                <span>Ingress</span
                ><strong>{{ integer.format(backend.ingressMbps) }} <small>Mbps</small></strong>
              </div>
              <div>
                <span>Egress</span
                ><strong>{{ integer.format(backend.egressMbps) }} <small>Mbps</small></strong>
              </div>
              <div>
                <span>Packet rate</span
                ><strong>{{ integer.format(backend.packetsPerSecond) }} <small>/ sec</small></strong>
              </div>
              <div>
                <span>Idle-timeout removals</span
                ><strong>{{ backend.orphanedPerSecond.toFixed(1) }} <small>/ sec</small></strong>
              </div>
            </div>
          </section>

          <section class="drawer-section drawer-chart-section backend-history">
            <div class="drawer-history-tabs" aria-label="Backend history metric">
              <button
                v-for="view in historyViews"
                :key="view"
                type="button"
                :class="{ active: historyView === view }"
                :disabled="futureView(view)"
                :title="futureView(view) ? `${historyViewLabels[view]} coming soon` : undefined"
                @click="historyView = view"
              >
                <span>{{ historyViewLabels[view] }}</span
                ><small v-if="futureView(view)">Coming soon</small>
              </button>
            </div>
            <div class="drawer-section__title">
              <span>{{ chartTitle }}</span>
              <small v-if="futureView(historyView)" class="proposed-text">Coming soon</small>
              <small v-else>In-browser history</small>
            </div>
            <div v-if="!futureView(historyView)" class="drawer-chart-legend">
              <span v-for="item in chartSeries" :key="item.name"
                ><i :style="{ background: item.color }"></i>{{ item.name }}</span
              >
              <small>Up to 15 minutes</small>
            </div>
            <UPlotChart
              v-if="!futureView(historyView)"
              :series="chartSeries"
              :unit="chartUnit"
              range-label="15 minutes"
              compact
            />
            <ComingSoon
              v-else
              :title="`${chartTitle} is not collected yet`"
              description="No values are estimated or simulated. This view will activate after its reviewed dataplane metrics and status API fields land."
              compact
            />
            <p v-if="historyView === 'connections'" class="metric-boundary-note">
              Opened and closed connections share the same per-second scale. The current idle-timeout removal
              rate stays separate above because its volume can be much lower.
            </p>
          </section>

          <section class="drawer-section">
            <div class="drawer-section__title">
              <span>Passive TCP handshake</span>
              <small class="proposed-text">Coming soon</small>
            </div>
            <ComingSoon
              title="Passive TCP handshake latency is not collected yet"
              description="No p50, p95, p99, or sample-rate values are estimated or simulated. These fields will appear after the reviewed dataplane timing metric and status API extension land."
              compact
            />
          </section>

          <section class="drawer-section">
            <div class="drawer-section__title">
              <span>Lifetime counters</span><small>Process lifetime</small>
            </div>
            <dl class="detail-list">
              <div>
                <dt>
                  Time in pool
                  <HelpTip
                    explanation="Time since this XLB instance discovered the backend. May include periods when it was not accepting new connections."
                  />
                </dt>
                <dd>{{ duration(backend.timeInPoolSeconds) }}</dd>
              </div>
              <div>
                <dt>Opened connections</dt>
                <dd>{{ integer.format(backend.openedTotal) }}</dd>
              </div>
              <div>
                <dt>Closed connections</dt>
                <dd>{{ integer.format(backend.closedTotal) }}</dd>
              </div>
              <div>
                <dt>Ingress bytes</dt>
                <dd>{{ bytes.format(backend.ingressBytesTotal) }}B</dd>
              </div>
              <div>
                <dt>Egress bytes</dt>
                <dd>{{ bytes.format(backend.egressBytesTotal) }}B</dd>
              </div>
            </dl>
          </section>

          <footer class="backend-drawer__footer">
            <span>Durable history</span>
            <strong>Use your OpenTelemetry backend for fleet-wide retention.</strong>
          </footer>
        </aside>
      </div>
    </Transition>
  </Teleport>
</template>
