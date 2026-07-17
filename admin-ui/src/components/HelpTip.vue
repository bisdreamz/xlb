<script setup lang="ts">
defineProps<{
  explanation: string
}>()
</script>

<template>
  <span class="help-tip" tabindex="0" role="note" :aria-label="explanation" :data-tooltip="explanation"
    >?</span
  >
</template>
