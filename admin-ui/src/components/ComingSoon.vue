<script setup lang="ts">
withDefaults(
  defineProps<{
    title: string
    description: string
    compact?: boolean
  }>(),
  { compact: false },
)
</script>

<template>
  <div class="coming-soon" :class="{ 'coming-soon--compact': compact }" role="note">
    <strong class="coming-soon__label">Coming soon</strong>
    <div>
      <b>{{ title }}</b>
      <p>{{ description }}</p>
    </div>
  </div>
</template>
