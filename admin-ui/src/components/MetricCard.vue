<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  index: string
  label: string
  value: string
  detail: string
  tone?: 'default' | 'orange' | 'mint' | 'lime'
  bar?: number
  history?: ReadonlyArray<number | null>
  historyLabel?: string
}>()

const sparklinePoints = computed(() => {
  const history = props.history ?? []
  const values = history.slice(history.lastIndexOf(null) + 1) as number[]
  if (values.length < 2) return ''
  const minimum = Math.min(...values)
  const maximum = Math.max(...values)
  const span = Math.max(1, maximum - minimum)
  return values
    .map((value, index) => {
      const x = (index / (values.length - 1)) * 180
      const y = 30 - ((value - minimum) / span) * 24
      return `${x.toFixed(2)},${y.toFixed(2)}`
    })
    .join(' ')
})
</script>

<template>
  <article class="metric-card" :class="`metric-card--${tone ?? 'default'}`">
    <div class="metric-card__head">
      <span>{{ index }}</span>
      <span class="metric-card__signal" aria-hidden="true"></span>
    </div>
    <p class="metric-card__label">{{ label }}</p>
    <strong class="metric-card__value">{{ value }}</strong>
    <div v-if="bar !== undefined" class="metric-card__bar" aria-hidden="true">
      <i :style="{ width: `${Math.min(100, Math.max(0, bar))}%` }"></i>
    </div>
    <p class="metric-card__detail">{{ detail }}</p>
    <div v-if="sparklinePoints" class="metric-card__sparkline">
      <svg
        viewBox="0 0 180 34"
        preserveAspectRatio="none"
        role="img"
        :aria-label="historyLabel ?? `${label} recent trend`"
      >
        <line x1="0" x2="180" y1="30" y2="30" />
        <polyline :points="sparklinePoints" />
      </svg>
      <span>{{ historyLabel ?? 'Recent browser history' }}</span>
    </div>
  </article>
</template>
