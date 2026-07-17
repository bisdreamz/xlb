<script setup lang="ts">
import { computed } from 'vue'
import UPlotChart from './UPlotChart.vue'

const props = withDefaults(
  defineProps<{
    clientNormalHistory: number[]
    clientResetHistory: number[]
    backendNormalHistory: number[]
    backendResetHistory: number[]
    idleTimeoutHistory: number[]
    clientNormalCurrent: number
    clientResetCurrent: number
    backendNormalCurrent: number
    backendResetCurrent: number
    idleTimeoutCurrent: number
    rangeLabel?: string
    stacked?: boolean
  }>(),
  {
    rangeLabel: '15 minutes',
    stacked: false,
  },
)

const integer = new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 })
const rate = (value: number) => (value < 10 ? `${value.toFixed(1)}/s` : `${integer.format(value)}/s`)

const clientSeries = computed(() => [
  { name: 'Normal close', color: '#167452', values: props.clientNormalHistory },
  { name: 'Unexpected reset', color: '#c93615', values: props.clientResetHistory },
])

const backendSeries = computed(() => [
  { name: 'Normal close', color: '#167452', values: props.backendNormalHistory },
  { name: 'Unexpected reset', color: '#c93615', values: props.backendResetHistory },
])

const idleSeries = computed(() => [
  { name: 'No close received', color: '#7b3422', values: props.idleTimeoutHistory },
])
</script>

<template>
  <div class="close-breakdown" :class="{ 'close-breakdown--stacked': stacked }">
    <div class="close-breakdown__graphs">
      <article class="close-event-chart">
        <header>
          <div><strong>Client ended connection</strong><small>Who: client</small></div>
          <dl>
            <div>
              <dt><i class="close-color--normal"></i>Normal close</dt>
              <dd>{{ rate(clientNormalCurrent) }}</dd>
            </div>
            <div>
              <dt><i class="close-color--reset"></i>Unexpected reset</dt>
              <dd>{{ rate(clientResetCurrent) }}</dd>
            </div>
          </dl>
        </header>
        <UPlotChart :series="clientSeries" unit=" /s" :range-label="rangeLabel" compact />
      </article>

      <article class="close-event-chart">
        <header>
          <div><strong>Backend ended connection</strong><small>Who: backend</small></div>
          <dl>
            <div>
              <dt><i class="close-color--normal"></i>Normal close</dt>
              <dd>{{ rate(backendNormalCurrent) }}</dd>
            </div>
            <div>
              <dt><i class="close-color--reset"></i>Unexpected reset</dt>
              <dd>{{ rate(backendResetCurrent) }}</dd>
            </div>
          </dl>
        </header>
        <UPlotChart :series="backendSeries" unit=" /s" :range-label="rangeLabel" compact />
      </article>
    </div>

    <article class="close-timeout-chart">
      <header>
        <div>
          <strong>No close received</strong
          ><small>Connection removed after the configured idle timeout</small>
        </div>
        <b>{{ rate(idleTimeoutCurrent) }}</b>
      </header>
      <UPlotChart :series="idleSeries" unit=" /s" :range-label="rangeLabel" compact />
      <p>
        This is usually the strongest signal to investigate. It can also mean the configured idle timeout is
        shorter than the application’s connection lifetime.
      </p>
    </article>

    <p class="close-breakdown__scale-note">
      Normal closes and unexpected resets share one events-per-second scale within each actor graph. The
      timeout trend is separate because its volume is much lower and neither side sent a close.
    </p>
  </div>
</template>
