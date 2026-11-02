<script setup lang="ts">
import { computed } from 'vue'
import type { Severity } from '../types'

const props = defineProps<{ severity: Severity | string }>()

const labels: Record<string, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
}

const label = computed(() => labels[props.severity] ?? props.severity)
const klass = computed(() => `sev-${props.severity || 'low'}`)
</script>

<template>
  <span class="badge" :class="klass">
    <span class="badge-dot" />
    {{ label }}
  </span>
</template>
