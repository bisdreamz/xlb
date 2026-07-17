<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { RouterLink, RouterView } from 'vue-router'
import XlbMark from './components/XlbMark.vue'
import { useStatusStore } from './stores/status'

type Theme = 'light' | 'dark'

const initialTheme = (): Theme => {
  const stored = localStorage.getItem('xlb-admin-theme')
  if (stored === 'dark' || stored === 'light') return stored
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

const theme = ref<Theme>(initialTheme())
const status = useStatusStore()
const sourceLabel = computed(
  () =>
    ({
      live: 'Live',
      stale: 'Stale',
      disconnected: 'Disconnected',
      demo: 'Demo data',
    })[status.source.value],
)

const toggleTheme = () => {
  theme.value = theme.value === 'light' ? 'dark' : 'light'
}

watch(
  theme,
  (value) => {
    document.documentElement.dataset.theme = value
    localStorage.setItem('xlb-admin-theme', value)
    document
      .querySelector('meta[name="theme-color"]')
      ?.setAttribute('content', value === 'dark' ? '#0d1c27' : '#f1efe7')
  },
  { immediate: true },
)

onMounted(() => {
  status.start()
})

onUnmounted(status.stop)
</script>

<template>
  <div class="app-frame">
    <a class="skip-link" href="#main-content">Skip to status</a>
    <header class="console-header">
      <RouterLink class="console-header__brand" to="/" aria-label="XLB overview">
        <XlbMark />
        <div><strong>XLB</strong><span>Instance console</span></div>
      </RouterLink>

      <nav class="console-nav" aria-label="Console sections">
        <RouterLink to="/">Overview</RouterLink>
        <RouterLink to="/backends">Backends</RouterLink>
        <RouterLink to="/connections">Connections</RouterLink>
        <RouterLink to="/events">Events</RouterLink>
        <RouterLink to="/diagnostics">Diagnostics</RouterLink>
      </nav>

      <div class="console-header__actions">
        <div class="sample-indicator" :class="`sample-indicator--${status.source.value}`">
          <i></i><span>{{ sourceLabel }}</span>
        </div>
        <button
          class="theme-toggle"
          type="button"
          :aria-label="`Use ${theme === 'light' ? 'dark' : 'light'} theme`"
          @click="toggleTheme"
        >
          <span aria-hidden="true">{{ theme === 'light' ? '◐' : '○' }}</span>
        </button>
      </div>
    </header>

    <main id="main-content">
      <div
        v-if="status.source.value === 'demo' || status.source.value === 'stale'"
        class="source-banner"
        :class="`source-banner--${status.source.value}`"
        role="status"
      >
        <div class="source-banner__content page-shell">
          <strong>{{
            status.source.value === 'demo' ? 'Interactive demo' : 'Status updates interrupted'
          }}</strong>
          <span v-if="status.source.value === 'demo'"
            >Values are illustrative and do not come from a running XLB instance.</span
          >
          <span v-else>Showing the last successful snapshot while the console reconnects.</span>
        </div>
      </div>

      <RouterView v-if="status.source.value !== 'disconnected'" />
      <section v-else class="status-unavailable page-shell" aria-live="polite">
        <div>
          <p class="eyebrow-label"><i></i> Status unavailable</p>
          <h1>Unable to reach this XLB instance.</h1>
          <p>
            The console could not load <code>/api/v1/status</code>. No operational values are being shown, and
            the connection will be retried automatically.
          </p>
        </div>
        <dl>
          <div>
            <dt>Endpoint</dt>
            <dd>/api/v1/status</dd>
          </div>
          <div>
            <dt>Last error</dt>
            <dd>{{ status.error.value ?? 'Connecting…' }}</dd>
          </div>
        </dl>
      </section>
    </main>

    <footer class="console-footer page-shell">
      <div><XlbMark /><strong>XLB</strong><span>Local instance console</span></div>
      <p>{{ sourceLabel }} · durable history via OpenTelemetry</p>
    </footer>
  </div>
</template>
