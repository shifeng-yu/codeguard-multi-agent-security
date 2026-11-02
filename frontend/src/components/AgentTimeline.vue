<script setup lang="ts">
import { computed } from 'vue'
import type { TimelineEvent } from '../types'

const props = defineProps<{ events: TimelineEvent[]; live?: boolean }>()

const NAME: Record<string, string> = {
  preprocess: '预处理 · 代码解析',
  security: '安全审计 Agent',
  conflict: '冲突消解 Agent',
  migration: '迁移评估 Agent',
  reporter: '报告聚合 Agent',
  security_chain: '安全主链',
  pipeline: '编排流水线',
  scan: '扫描结束',
}

const ORDER = ['preprocess', 'security', 'conflict', 'migration', 'reporter', 'scan']

interface Node {
  agent: string
  name: string
  status: string
  statusText: string
  tone: string
  badgeClass: string
  duration: number | null
  pct: number
  chips: string[]
  running: boolean
}

const nodes = computed<Node[]>(() => {
  const merged = new Map<string, TimelineEvent & { started?: boolean }>()

  for (const event of props.events) {
    const key = event.agent || 'pipeline'
    const current = merged.get(key) ?? { ...event, started: false }
    if (event.status === 'started') {
      current.started = true
      current.seq = Math.min(current.seq || event.seq, event.seq)
    } else {
      current.status = event.status
      current.duration_ms = event.duration_ms ?? current.duration_ms
      current.payload = event.payload ?? current.payload
      current.seq = current.seq || event.seq
      if (event.event === 'scan.finished') current.status = 'finished'
    }
    merged.set(key, current)
  }

  const list = [...merged.values()].sort((a, b) => {
    const ai = ORDER.indexOf(a.agent)
    const bi = ORDER.indexOf(b.agent)
    return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi) || a.seq - b.seq
  })

  const max = Math.max(1, ...list.map((e) => e.duration_ms ?? 0))

  return list.map((event) => {
    const status = event.status === 'started' ? 'running' : event.status
    const tone =
      status === 'finished'
        ? 'ok'
        : status === 'degraded'
          ? 'warn'
          : status === 'failed'
            ? 'danger'
            : status === 'skipped'
              ? 'muted'
              : 'run'

    const statusText =
      status === 'finished'
        ? '完成'
        : status === 'degraded'
          ? '降级完成'
          : status === 'failed'
            ? '失败'
            : status === 'skipped'
              ? '跳过'
              : '执行中'

    const badgeClass =
      status === 'finished'
        ? 'st-pass'
        : status === 'degraded'
          ? 'st-warn'
          : status === 'failed'
            ? 'st-block'
            : status === 'skipped'
              ? 'st-muted'
              : 'st-running'

    const chips: string[] = []
    const payload = (event.payload ?? {}) as Record<string, unknown>
    if (typeof payload.vulnerabilities === 'number') chips.push(`依赖漏洞 ${payload.vulnerabilities}`)
    if (typeof payload.code_issues === 'number') chips.push(`代码问题 ${payload.code_issues}`)
    if (typeof payload.decisions === 'number') chips.push(`裁决 ${payload.decisions}`)
    if (typeof payload.language === 'string' && payload.language) chips.push(String(payload.language))
    if (typeof payload.framework === 'string' && payload.framework) chips.push(String(payload.framework))
    if (typeof payload.reason === 'string' && payload.reason) chips.push(String(payload.reason))
    if (payload.verdict) chips.push(`结论 ${payload.verdict}`)
    if (payload.error) chips.push('错误已记录')

    return {
      agent: event.agent,
      name: NAME[event.agent] ?? event.agent,
      status,
      statusText,
      tone,
      badgeClass,
      duration: event.duration_ms ?? null,
      pct: Math.max(3, Math.round(((event.duration_ms ?? 0) / max) * 100)),
      chips,
      running: status === 'running',
    }
  })
})

function fmt(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)} ms`
  return `${(ms / 1000).toFixed(2)} s`
}
</script>

<template>
  <div class="timeline">
    <div v-if="!nodes.length" class="empty">尚未接收到执行事件</div>

    <div v-for="(node, index) in nodes" :key="node.agent" class="node" :class="node.tone">
      <div class="rail">
        <span class="dot" :class="{ pulse: node.running }" />
        <span v-if="index < nodes.length - 1" class="line" />
      </div>

      <div class="body">
        <div class="row">
          <span class="name">{{ node.name }}</span>
          <span class="dur mono">{{ node.duration != null ? fmt(node.duration) : '—' }}</span>
        </div>
        <div class="bar">
          <i :class="{ pulse: node.running }" :style="{ width: node.running ? 100 : node.pct + '%' }" />
        </div>
        <div class="meta">
          <span class="badge" :class="node.badgeClass">{{ node.statusText }}</span>
          <span v-for="chip in node.chips" :key="chip" class="chip">{{ chip }}</span>
        </div>
      </div>
    </div>

    <div v-if="live" class="live-hint">
      <span class="spinner" />
      正在接收实时事件流
    </div>
  </div>
</template>

<style scoped>
.timeline {
  display: flex;
  flex-direction: column;
}

.node {
  display: grid;
  grid-template-columns: 22px 1fr;
  gap: 10px;
}

.rail {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding-top: 5px;
}

.dot {
  width: 9px;
  height: 9px;
  border-radius: 50%;
  background: #cbd5e1;
  box-shadow: 0 0 0 3px #f1f5f9;
  flex: 0 0 auto;
}

.line {
  width: 1.5px;
  flex: 1;
  background: #e5e7eb;
  margin: 4px 0;
}

.node.ok .dot {
  background: #16a34a;
  box-shadow: 0 0 0 3px #dcfce7;
}

.node.warn .dot {
  background: #d97706;
  box-shadow: 0 0 0 3px #fef3c7;
}

.node.danger .dot {
  background: #dc2626;
  box-shadow: 0 0 0 3px #fee2e2;
}

.node.run .dot {
  background: #2563eb;
  box-shadow: 0 0 0 3px #dbeafe;
}

.node.muted .dot {
  background: #cbd5e1;
}

.body {
  padding-bottom: 16px;
  min-width: 0;
}

.row {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 10px;
}

.name {
  font-size: 13px;
  font-weight: 560;
}

.dur {
  font-size: 12px;
  color: #4b5563;
}

.bar {
  height: 3px;
  border-radius: 2px;
  background: #f1f5f9;
  margin: 6px 0 7px;
  overflow: hidden;
}

.bar i {
  display: block;
  height: 100%;
  border-radius: 2px;
  background: #93c5fd;
  transition: width 0.35s ease;
}

.node.ok .bar i {
  background: #4ade80;
}

.node.warn .bar i {
  background: #fbbf24;
}

.node.danger .bar i {
  background: #f87171;
}

.node.run .bar i {
  background: #3b82f6;
}

.node.muted .bar i {
  background: #e2e8f0;
}

.meta {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}

.chip {
  font-size: 11px;
  color: #4b5563;
  background: #f3f4f6;
  border-radius: 5px;
  padding: 1px 6px;
}

.live-hint {
  display: flex;
  align-items: center;
  gap: 7px;
  font-size: 12px;
  color: #2563eb;
  padding: 8px 0 0 32px;
}
</style>
