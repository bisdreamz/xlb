<script setup lang="ts">
import { nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import uPlot from 'uplot'
import 'uplot/dist/uPlot.min.css'
import type { ChartSeries } from '../types'

const props = withDefaults(
  defineProps<{
    series: ChartSeries[]
    unit?: string
    rangeLabel?: string
    compact?: boolean
    height?: number
  }>(),
  {
    unit: '',
    rangeLabel: '15 minutes',
    compact: false,
    height: 246,
  },
)

const host = ref<HTMLDivElement | null>(null)
const tooltip = ref<HTMLDivElement | null>(null)
let plot: uPlot | undefined
let resizeObserver: ResizeObserver | undefined
let themeObserver: MutationObserver | undefined
let resizeFrame: number | undefined
const tooltipTime = new Intl.DateTimeFormat('en-US', {
  hour: 'numeric',
  minute: '2-digit',
  second: '2-digit',
})

const chartData = (): uPlot.AlignedData => {
  const pointCount = Math.max(2, ...props.series.map((series) => series.values.length))
  const now = Math.floor(Date.now() / 1_000)
  const timestamps = Array.from({ length: pointCount }, (_, index) => now - pointCount + index + 1)
  const values = props.series.map((series) => {
    const missing = pointCount - series.values.length
    return [...Array.from({ length: missing }, () => null), ...series.values]
  })
  return [timestamps, ...values] as uPlot.AlignedData
}

const axisValue = (value: number | null | undefined) => {
  if (value === null || value === undefined) return '—'
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)}M${props.unit}`
  if (value >= 1_000) return `${(value / 1_000).toFixed(value >= 10_000 ? 0 : 1)}k${props.unit}`
  return `${value.toFixed(value < 10 ? 1 : 0)}${props.unit}`
}

const measuredWidth = () => Math.floor(host.value?.getBoundingClientRect().width ?? 0)

const hideTooltip = () => {
  if (tooltip.value) tooltip.value.hidden = true
}

const updateTooltip = (chart: uPlot) => {
  const element = tooltip.value
  const index = chart.cursor.idx
  if (!element || props.compact || index == null) {
    hideTooltip()
    return
  }

  const timestamp = chart.data[0][index]
  if (typeof timestamp !== 'number') {
    hideTooltip()
    return
  }

  const time = element.querySelector<HTMLElement>('[data-chart-tooltip-time]')
  if (time) time.textContent = tooltipTime.format(new Date(timestamp * 1_000))
  element.querySelectorAll<HTMLElement>('[data-chart-tooltip-value]').forEach((value, seriesIndex) => {
    value.textContent = axisValue(chart.data[seriesIndex + 1]?.[index])
  })

  element.hidden = false
  const cursorLeft = chart.cursor.left ?? 0
  const container = element.offsetParent as HTMLElement | null
  const containerLeft = container?.getBoundingClientRect().left ?? 0
  const plotLeft = chart.over.getBoundingClientRect().left - containerLeft
  const preferredLeft = plotLeft + cursorLeft + 18
  const containerWidth = container?.clientWidth ?? chart.width
  const maximumLeft = Math.max(8, containerWidth - element.offsetWidth - 8)
  element.style.left = `${Math.max(8, Math.min(preferredLeft, maximumLeft))}px`
  element.style.top = '1.4rem'
}

const responsiveHeight = (width: number) => {
  const maximum = props.compact ? 164 : props.height
  const minimum = props.compact ? Math.min(124, maximum) : Math.min(184, maximum)
  const ratio = props.compact ? 0.45 : 0.48
  return Math.min(maximum, Math.max(minimum, Math.round(width * ratio)))
}

const resize = () => {
  if (!plot) return
  const width = measuredWidth()
  if (width < 1) return
  plot.setSize({ width, height: responsiveHeight(width) })
}

const scheduleResize = () => {
  if (resizeFrame !== undefined) return
  resizeFrame = requestAnimationFrame(() => {
    resizeFrame = undefined
    resize()
  })
}

const build = async () => {
  await nextTick()
  if (!host.value) return
  const width = measuredWidth()
  if (width < 1) return

  hideTooltip()
  plot?.destroy()
  const styles = getComputedStyle(document.documentElement)
  const muted = styles.getPropertyValue('--ink-muted').trim() || '#637078'
  const grid = styles.getPropertyValue('--line-soft').trim() || '#ddd9cf'

  const options: uPlot.Options = {
    width,
    height: responsiveHeight(width),
    padding: props.compact ? [12, 8, 8, 8] : [12, 16, 4, 8],
    legend: { show: false },
    cursor: { show: !props.compact, drag: { x: false, y: false } },
    hooks: {
      setCursor: [updateTooltip],
      setData: [updateTooltip],
    },
    scales: { x: { time: true } },
    axes: props.compact
      ? []
      : [
          { stroke: muted, grid: { stroke: grid, width: 1 }, ticks: { stroke: grid } },
          {
            stroke: muted,
            grid: { stroke: grid, width: 1, dash: [2, 4] },
            ticks: { stroke: grid },
            size: 60,
            values: (_plot, values) => values.map(axisValue),
          },
        ],
    series: [
      { label: 'Time', value: () => '' },
      ...props.series.map((series) => ({
        label: series.name,
        stroke: series.color,
        width: 2,
        fill: series.fill ? `${series.color}22` : undefined,
        points: { show: false },
        value: (_plot: uPlot, value: number, _seriesIndex: number, dataIndex: number | null) => {
          const latest = series.values.at(-1)
          const displayed = dataIndex === null ? latest : value
          return displayed === undefined || displayed === null ? '—' : axisValue(displayed)
        },
      })),
    ],
  }
  plot = new uPlot(options, chartData(), host.value)
}

watch(
  () => props.series.map((series) => series.values),
  () => {
    if (!plot) return
    const data = chartData()
    if (data.length === plot.series.length) plot.setData(data)
  },
  { deep: true },
)

watch(
  () =>
    `${props.compact}:${props.height}:${props.unit}:${props.series
      .map((series) => `${series.name}:${series.color}:${series.fill}`)
      .join('|')}`,
  () => void build(),
)

onMounted(() => {
  void build()
  resizeObserver = new ResizeObserver(() => {
    if (plot) scheduleResize()
    else void build()
  })
  if (host.value) resizeObserver.observe(host.value)
  window.addEventListener('resize', scheduleResize, { passive: true })
  themeObserver = new MutationObserver(() => void build())
  themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] })
})

onBeforeUnmount(() => {
  resizeObserver?.disconnect()
  themeObserver?.disconnect()
  window.removeEventListener('resize', scheduleResize)
  if (resizeFrame !== undefined) cancelAnimationFrame(resizeFrame)
  plot?.destroy()
})
</script>

<template>
  <div class="uplot-chart" :class="{ 'uplot-chart--compact': compact }">
    <div ref="host" class="uplot-chart__host"></div>
    <div v-if="!compact" ref="tooltip" class="uplot-chart__tooltip" aria-hidden="true" hidden>
      <span data-chart-tooltip-time></span>
      <ul>
        <li v-for="item in series" :key="item.name">
          <i :style="{ background: item.color }"></i>
          <span>{{ item.name }}</span>
          <strong data-chart-tooltip-value>—</strong>
        </li>
      </ul>
    </div>
    <ul v-if="!compact" class="uplot-chart__legend" aria-label="Latest chart values">
      <li v-for="item in series" :key="item.name">
        <i
          :style="{ borderColor: item.color, background: item.fill ? `${item.color}22` : 'transparent' }"
        ></i>
        <span>{{ item.name }}</span>
        <strong>{{ axisValue(item.values.at(-1)) }}</strong>
      </li>
    </ul>
    <small v-if="!compact">{{ rangeLabel }}</small>
  </div>
</template>

<style scoped>
.uplot-chart__tooltip {
  position: absolute;
  z-index: 5;
  width: max-content;
  min-width: 10.5rem;
  max-width: min(18rem, calc(100% - 1rem));
  padding: 0.65rem 0.75rem;
  border: 1px solid var(--line-dark);
  background: color-mix(in srgb, var(--navy) 96%, transparent);
  box-shadow: var(--shadow);
  color: #edf1ea;
  font-family: var(--mono);
  pointer-events: none;
}

.uplot-chart__tooltip[hidden] {
  display: none;
}

.uplot-chart__tooltip [data-chart-tooltip-time] {
  display: block;
  padding-bottom: 0.45rem;
  border-bottom: 1px solid var(--line-dark);
  color: #9fb0b9;
  font-size: 0.6rem;
  text-transform: uppercase;
}

.uplot-chart__tooltip ul {
  display: grid;
  margin: 0.45rem 0 0;
  padding: 0;
  gap: 0.35rem;
  list-style: none;
}

.uplot-chart__tooltip li {
  display: grid;
  align-items: center;
  gap: 0.4rem;
  grid-template-columns: auto 1fr auto;
  font-size: 0.64rem;
}

.uplot-chart__tooltip li i {
  width: 0.55rem;
  height: 0.55rem;
}

.uplot-chart__tooltip li span {
  color: #c2ccd0;
}

.uplot-chart__tooltip li strong {
  color: #fff;
  font-weight: 750;
}

.uplot-chart__legend {
  display: flex;
  margin: 0.65rem 0 0;
  padding: 0;
  flex-wrap: wrap;
  justify-content: center;
  gap: 0.55rem 1.35rem;
  list-style: none;
}

.uplot-chart__legend li {
  display: inline-flex;
  align-items: center;
  gap: 0.38rem;
  color: var(--ink-soft);
  font-family: var(--mono);
  font-size: 0.65rem;
}

.uplot-chart__legend i {
  width: 0.7rem;
  height: 0.7rem;
  border: 2px solid;
}

.uplot-chart__legend strong {
  color: var(--ink);
  font-weight: 700;
}
</style>
