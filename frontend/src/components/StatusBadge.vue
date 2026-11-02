<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  status?: string
  verdict?: string | null
  pulse?: boolean
}>()

const view = computed(() => {
  const verdict = props.verdict ?? ''
  const status = props.status ?? ''

  if (verdict === 'block') return { text: '阻断', klass: 'st-block' }
  if (verdict === 'pass') return { text: '通过', klass: 'st-pass' }
  if (verdict === 'human_review') return { text: '待人工裁决', klass: 'st-warn' }
  if (verdict === 'error' || status === 'failed') return { text: '失败', klass: 'st-block' }
  if (status === 'running') return { text: '运行中', klass: 'st-running' }
  if (status === 'paused') return { text: '暂停', klass: 'st-warn' }
  if (status === 'completed') return { text: '完成', klass: 'st-pass' }
  return { text: status || '未知', klass: 'st-muted' }
})

const animate = computed(() => props.pulse ?? props.status === 'running')
</script>

<template>
  <span class="badge" :class="view.klass">
    <span class="badge-dot" :class="{ pulse: animate }" />
    {{ view.text }}
  </span>
</template>
