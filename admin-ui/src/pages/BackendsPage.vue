<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import BackendDrawer from '../components/BackendDrawer.vue'
import BackendTable from '../components/BackendTable.vue'
import { useStatusStore } from '../stores/status'
import type { Backend, BackendSortKey, BackendState } from '../types'

type StateFilter = 'all' | BackendState | 'attention'

const status = useStatusStore()
const route = useRoute()
const router = useRouter()
const query = ref('')
const stateFilter = ref<StateFilter>('all')
const selectedId = ref(typeof route.query.backend === 'string' ? route.query.backend : '')
const sortKey = ref<BackendSortKey>('activeConnections')
const sortDirection = ref<'asc' | 'desc'>('desc')
const page = ref(1)
const pageSize = ref(10)

const backends = computed(() => status.backendRows.value)
const selectedBackend = computed(
  () => backends.value.find((backend) => backend.id === selectedId.value) ?? null,
)
const sampleDescription = computed(() => {
  if (status.source.value === 'demo') return 'Demo sample'
  const age = status.sampleAgeSeconds.value
  return age === null ? 'Sample time unavailable' : `Sampled ${age.toFixed(1)} seconds ago`
})

const filteredBackends = computed(() => {
  const normalized = query.value.trim().toLowerCase()
  return backends.value.filter((backend) => {
    const matchesQuery =
      !normalized || [backend.name, backend.ip].some((value) => value.toLowerCase().includes(normalized))
    const matchesState =
      stateFilter.value === 'all' ||
      backend.state === stateFilter.value ||
      (stateFilter.value === 'attention' && backend.orphanedPerSecond >= 1)
    return matchesQuery && matchesState
  })
})

const sortedBackends = computed(() =>
  [...filteredBackends.value].sort((left, right) => {
    const leftValue = left[sortKey.value]
    const rightValue = right[sortKey.value]
    const comparison =
      typeof leftValue === 'string' && typeof rightValue === 'string'
        ? leftValue.localeCompare(rightValue)
        : Number(leftValue) - Number(rightValue)
    return sortDirection.value === 'asc' ? comparison : -comparison
  }),
)

const totalPages = computed(() => Math.max(1, Math.ceil(sortedBackends.value.length / pageSize.value)))
const paginatedBackends = computed(() => {
  const start = (page.value - 1) * pageSize.value
  return sortedBackends.value.slice(start, start + pageSize.value)
})

const stateCounts = computed(() => ({
  all: backends.value.length,
  available: backends.value.filter((backend) => backend.state === 'available').length,
  draining: backends.value.filter((backend) => backend.state === 'draining').length,
  attention: backends.value.filter((backend) => backend.orphanedPerSecond >= 1).length,
}))

const activeCounts = computed(() =>
  backends.value
    .filter((backend) => backend.state === 'available')
    .map((backend) => backend.activeConnections)
    .filter((value) => value > 0),
)
const distribution = computed(() => {
  if (!activeCounts.value.length) return { spread: 0, zero: 0 }
  const busiest = Math.max(...activeCounts.value)
  const least = Math.min(...activeCounts.value)
  return {
    spread: busiest === 0 ? 0 : ((busiest - least) / busiest) * 100,
    zero: backends.value.filter(
      (backend) => backend.state === 'available' && backend.newConnectionsPerSecond === 0,
    ).length,
  }
})

const chooseBackend = (backend: Backend) => {
  selectedId.value = backend.id
}

const resetFilters = () => {
  query.value = ''
  stateFilter.value = 'all'
}

const changeSort = (key: BackendSortKey) => {
  if (sortKey.value === key) sortDirection.value = sortDirection.value === 'asc' ? 'desc' : 'asc'
  else {
    sortKey.value = key
    sortDirection.value = key === 'name' || key === 'state' ? 'asc' : 'desc'
  }
  page.value = 1
}

const changePage = (nextPage: number) => {
  page.value = Math.min(totalPages.value, Math.max(1, nextPage))
}

watch([query, stateFilter, pageSize], () => (page.value = 1))
watch(totalPages, (availablePages) => (page.value = Math.min(page.value, availablePages)))
watch(selectedId, (backend) => {
  const nextQuery = { ...route.query }
  if (backend) nextQuery.backend = backend
  else delete nextQuery.backend
  void router.replace({ query: nextQuery })
})
</script>

<template>
  <section class="route-hero page-shell">
    <div>
      <p class="eyebrow-label"><i></i> Backend pool</p>
      <h1>Where this instance sends traffic.</h1>
      <p>
        Compare current load, identify uneven distribution, and drill into one backend without mixing
        fleet-wide history into this local console.
      </p>
    </div>
    <div class="route-hero__facts">
      <div>
        <span>Discovered</span><strong>{{ stateCounts.all }}</strong>
      </div>
      <div>
        <span>Accepting</span><strong>{{ stateCounts.available }}</strong>
      </div>
    </div>
  </section>

  <section class="backend-distribution page-shell" aria-label="Backend distribution summary">
    <article>
      <span>Connection spread</span><strong>{{ distribution.spread.toFixed(1) }}%</strong
      ><small>Difference between busiest and least busy accepting backend</small>
    </article>
    <article>
      <span>Available with no new traffic</span><strong>{{ distribution.zero }}</strong
      ><small>Potential discovery or routing imbalance</small>
    </article>
    <article>
      <span>Needs attention</span><strong>{{ stateCounts.attention }}</strong
      ><small>Idle-timeout threshold crossed</small>
    </article>
    <p>
      Distribution and attention summaries are calculated in this browser from the current per-backend status
      snapshot.
    </p>
  </section>

  <section class="backend-section backend-section--route page-shell">
    <div class="backend-toolbar">
      <label class="search-field"
        ><span aria-hidden="true">⌕</span
        ><input
          v-model="query"
          type="search"
          placeholder="Search backend name or IP"
          aria-label="Search backends"
      /></label>
      <div class="state-filters" aria-label="Filter backend state">
        <button
          v-for="option in ['all', 'available', 'draining', 'attention'] as StateFilter[]"
          :key="option"
          type="button"
          :class="{ active: stateFilter === option }"
          @click="stateFilter = option"
        >
          {{ option }} <span>{{ stateCounts[option] }}</span>
        </button>
      </div>
      <label class="page-size-filter"
        ><span>Rows</span
        ><select v-model="pageSize">
          <option :value="10">10</option>
          <option :value="25">25</option>
          <option :value="50">50</option>
        </select></label
      >
      <button v-if="query || stateFilter !== 'all'" class="clear-filter" type="button" @click="resetFilters">
        Clear
      </button>
    </div>

    <BackendTable
      :backends="paginatedBackends"
      :total="sortedBackends.length"
      :page="page"
      :page-size="pageSize"
      :sort-key="sortKey"
      :sort-direction="sortDirection"
      :selected-id="selectedId"
      @select="chooseBackend"
      @sort="changeSort"
      @page="changePage"
    />
  </section>

  <BackendDrawer
    :backend="selectedBackend"
    :sample-description="sampleDescription"
    @close="selectedId = ''"
  />
</template>
