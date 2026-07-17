<script setup lang="ts">
import { computed } from 'vue'
import type { Backend, BackendSortKey } from '../types'

const props = defineProps<{
  backends: Backend[]
  total: number
  page: number
  pageSize: number
  sortKey: BackendSortKey
  sortDirection: 'asc' | 'desc'
  selectedId?: string
}>()

defineEmits<{
  select: [backend: Backend]
  sort: [key: BackendSortKey]
  page: [page: number]
}>()

const integer = new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 })
const compact = new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 1 })
const totalPages = computed(() => Math.max(1, Math.ceil(props.total / props.pageSize)))
const firstRow = computed(() => (props.total === 0 ? 0 : (props.page - 1) * props.pageSize + 1))
const lastRow = computed(() => Math.min(props.total, props.page * props.pageSize))
const sortMark = (key: BackendSortKey) =>
  props.sortKey === key ? (props.sortDirection === 'asc' ? '↑' : '↓') : '↕'
const sortAria = (key: BackendSortKey) =>
  props.sortKey === key ? (props.sortDirection === 'asc' ? 'ascending' : 'descending') : 'none'
</script>

<template>
  <div class="backend-table-wrap">
    <table class="backend-table">
      <thead>
        <tr>
          <th :aria-sort="sortAria('name')">
            <button type="button" @click="$emit('sort', 'name')">
              Backend <i>{{ sortMark('name') }}</i>
            </button>
          </th>
          <th>
            <button type="button" disabled title="Backend placement coming soon">
              Placement <small>Coming soon</small>
            </button>
          </th>
          <th :aria-sort="sortAria('state')">
            <button type="button" @click="$emit('sort', 'state')">
              State <i>{{ sortMark('state') }}</i>
            </button>
          </th>
          <th class="numeric" :aria-sort="sortAria('activeConnections')">
            <button type="button" @click="$emit('sort', 'activeConnections')">
              Active <i>{{ sortMark('activeConnections') }}</i>
            </button>
          </th>
          <th class="numeric" :aria-sort="sortAria('newConnectionsPerSecond')">
            <button type="button" @click="$emit('sort', 'newConnectionsPerSecond')">
              New / sec <i>{{ sortMark('newConnectionsPerSecond') }}</i>
            </button>
          </th>
          <th class="numeric" :aria-sort="sortAria('ingressMbps')">
            <button type="button" @click="$emit('sort', 'ingressMbps')">
              Ingress <i>{{ sortMark('ingressMbps') }}</i>
            </button>
          </th>
          <th class="numeric" :aria-sort="sortAria('egressMbps')">
            <button type="button" @click="$emit('sort', 'egressMbps')">
              Egress <i>{{ sortMark('egressMbps') }}</i>
            </button>
          </th>
          <th class="numeric proposed-column">
            <button type="button" disabled title="Passive backend latency coming soon">
              Latency p95 <small>Coming soon</small>
            </button>
          </th>
          <th class="numeric" :aria-sort="sortAria('orphanedPerSecond')">
            <button
              type="button"
              title="Connections removed after the configured idle timeout"
              @click="$emit('sort', 'orphanedPerSecond')"
            >
              Idle removed / sec <i>{{ sortMark('orphanedPerSecond') }}</i>
            </button>
          </th>
          <th aria-label="Open details"></th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="backend in backends"
          :key="backend.id"
          :class="{ selected: backend.id === selectedId, warning: backend.orphanedPerSecond >= 1 }"
          @click="$emit('select', backend)"
        >
          <td>
            <div class="backend-identity">
              <span class="state-square" :class="`state-square--${backend.state}`"></span>
              <div>
                <strong>{{ backend.name }}</strong>
                <small>{{ backend.ip }}</small>
              </div>
            </div>
          </td>
          <td aria-label="Placement coming soon">—</td>
          <td>
            <span class="state-label" :class="`state-label--${backend.state}`">{{ backend.state }}</span>
          </td>
          <td class="numeric emphasis">{{ integer.format(backend.activeConnections) }}</td>
          <td class="numeric">{{ integer.format(backend.newConnectionsPerSecond) }}</td>
          <td class="numeric">{{ integer.format(backend.ingressMbps) }} <small>Mbps</small></td>
          <td class="numeric">{{ integer.format(backend.egressMbps) }} <small>Mbps</small></td>
          <td class="numeric proposed-column" aria-label="Latency coming soon">—</td>
          <td class="numeric" :class="{ danger: backend.orphanedPerSecond >= 1 }">
            {{ backend.orphanedPerSecond.toFixed(1) }}
          </td>
          <td class="row-action">
            <button
              type="button"
              :aria-label="`Open details for ${backend.name}`"
              @click.stop="$emit('select', backend)"
            >
              <span aria-hidden="true">→</span>
            </button>
          </td>
        </tr>
      </tbody>
    </table>

    <div v-if="backends.length === 0" class="empty-state">
      <span>0 / No matches</span>
      <strong>No backends match these filters.</strong>
      <p>Clear one or more filters to return to the active backend pool.</p>
    </div>

    <div class="backend-table-summary">
      <span>Showing {{ firstRow }}–{{ lastRow }} of {{ total }} backends</span>
      <span class="backend-table-summary__load"
        >{{ compact.format(backends.reduce((sum, backend) => sum + backend.activeConnections, 0)) }} active
        connections on this page</span
      >
      <div class="pagination" aria-label="Backend pages">
        <button
          type="button"
          :disabled="page === 1"
          aria-label="Previous page"
          @click="$emit('page', page - 1)"
        >
          ←
        </button>
        <span>Page {{ page }} / {{ totalPages }}</span>
        <button
          type="button"
          :disabled="page === totalPages"
          aria-label="Next page"
          @click="$emit('page', page + 1)"
        >
          →
        </button>
      </div>
    </div>
  </div>
</template>
