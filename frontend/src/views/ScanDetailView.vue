<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import AgentTimeline from '../components/AgentTimeline.vue'
import SeverityTag from '../components/SeverityTag.vue'
import StatusBadge from '../components/StatusBadge.vue'
import { api } from '../api'
import { fmtDuration, fmtTime } from '../format'
import type { Finding, ScanDetail, TimelineEvent } from '../types'

const route = useRoute()
const router = useRouter()
const scanId = computed(() => String(route.params.id))

const detail = ref<ScanDetail | null>(null)
const events = ref<TimelineEvent[]>([])
const loading = ref(true)
const error = ref('')
const live = ref(false)
const severityFilter = ref('')
const report = ref<Record<string, unknown> | null>(null)
const reportError = ref('')

let source: EventSource | null = null

const findings = computed<Finding[]>(() => {
  const list = detail.value?.findings ?? []
  if (!severityFilter.value) return list
  return list.filter((item) => item.severity === severityFilter.value)
})

const blockingCount = computed(() => (detail.value?.findings ?? []).filter((f) => f.blocking).length)
const breakdown = computed(() => detail.value?.severity_breakdown ?? { critical: 0, high: 0, medium: 0, low: 0 })

const canLive = computed(() => detail.value?.status === 'running')

async function load() {
  loading.value = true
  error.value = ''
  try {
    const data = await api.getScan(scanId.value)
    detail.value = data
    events.value = data.timeline ?? []
    if (data.status === 'running') connect()
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

function connect() {
  closeStream()
  const lastSeq = events.value.reduce((max, item) => Math.max(max, item.seq ?? 0), 0)
  const url = api.streamUrl(scanId.value, lastSeq)
  source = new EventSource(url)
  live.value = true

  source.onmessage = (message) => {
    let event: TimelineEvent
    try {
      event = JSON.parse(message.data) as TimelineEvent
    } catch {
      return
    }
    apply(event)
  }

  source.onerror = () => {
    live.value = false
    closeStream()
  }
}

function apply(event: TimelineEvent) {
  if (event.seq) {
    const seen = events.value.some((item) => item.seq === event.seq)
    if (seen) return
  }
  events.value = [...events.value, event]

  if (event.event === 'scan.finished') {
    live.value = false
    closeStream()
    if (detail.value) {
      detail.value.status = String(event.status ?? 'completed')
      detail.value.verdict = (event.verdict as ScanDetail['verdict']) ?? null
      if (event.duration_ms) detail.value.duration_ms = Number(event.duration_ms)
    }
    // Findings are written at the end of the scan, so re-read once.
    setTimeout(() => refreshFindings(), 400)
  }
}

async function refreshFindings() {
  try {
    const data = await api.getScan(scanId.value)
    if (detail.value) {
      detail.value.findings = data.findings
      detail.value.severity_breakdown = data.severity_breakdown
      detail.value.timeline = data.timeline
      events.value = data.timeline ?? events.value
    }
  } catch {
    /* keep the streamed data if the refresh fails */
  }
}

function closeStream() {
  source?.close()
  source = null
}

async function toggleReport() {
  if (report.value) {
    report.value = null
    return
  }
  reportError.value = ''
  try {
    const response = await fetch(`/api/v1/scans/${encodeURIComponent(scanId.value)}/report`)
    if (!response.ok) throw new Error(`HTTP ${response.status}`)
    const body = await response.json()
    report.value = body.report ?? body
  } catch (err) {
    reportError.value = err instanceof Error ? err.message : String(err)
  }
}

onMounted(load)
onBeforeUnmount(closeStream)
</script>

<template>
  <div class="page-head">
    <div>
      <div class="dim" style="font-size: 12px; margin-bottom: 2px">
        <span class="link" @click="router.push('/scans')">任务列表</span> / {{ scanId }}
      </div>
      <h1 class="page-title">{{ detail?.repo || '扫描详情' }}</h1>
      <p class="page-desc">
        <span v-if="detail?.pr_number">PR #{{ detail.pr_number }} · </span>
        commit {{ detail?.head_sha?.slice(0, 8) || '—' }} · {{ detail?.trigger_type === 'webhook' ? 'Webhook 触发' : '手动触发' }}
      </p>
    </div>
    <div class="toolbar">
      <StatusBadge v-if="detail" :status="detail.status" :verdict="detail.verdict" />
      <button v-if="canLive && !live" class="btn" @click="connect">重连事件流</button>
      <button class="btn" @click="load">刷新</button>
    </div>
  </div>

  <div v-if="error" class="error-box" style="margin-bottom: 14px">加载失败：{{ error }}</div>

  <div class="grid grid-4" style="margin-bottom: 16px">
    <div class="card kpi">
      <div class="kpi-label">总耗时</div>
      <div class="kpi-value">{{ fmtDuration(detail?.duration_ms) }}</div>
      <div class="kpi-foot">{{ detail?.scan_scope === 'diff' ? '仅扫描 PR 差异' : '全量扫描' }}</div>
    </div>
    <div class="card kpi">
      <div class="kpi-label">阻断项</div>
      <div class="kpi-value" style="color: var(--danger)">{{ detail?.blocker_count ?? 0 }}</div>
      <div class="kpi-foot">发现项中判为 block 的数量</div>
    </div>
    <div class="card kpi">
      <div class="kpi-label">CVE / 代码问题</div>
      <div class="kpi-value">{{ detail?.cve_count ?? 0 }} <span class="dim" style="font-size: 15px">/ {{ detail?.code_issue_count ?? 0 }}</span></div>
      <div class="kpi-foot">三级缓存溯源，可回溯证据</div>
    </div>
    <div class="card kpi">
      <div class="kpi-label">严重级分布</div>
      <div class="sev-row">
        <span class="sev-chip sev-critical">{{ breakdown.critical }}</span>
        <span class="sev-chip sev-high">{{ breakdown.high }}</span>
        <span class="sev-chip sev-medium">{{ breakdown.medium }}</span>
        <span class="sev-chip sev-low">{{ breakdown.low }}</span>
      </div>
      <div class="kpi-foot">严重 / 高危 / 中危 / 低危</div>
    </div>
  </div>

  <div class="grid grid-3-2" style="margin-bottom: 16px">
    <div class="card">
      <div class="card-head">
        <h2 class="card-title">Agent 执行链路</h2>
        <span v-if="live" class="badge st-running"><span class="badge-dot pulse" />SSE 实时</span>
        <span v-else class="dim" style="font-size: 12px">已结束 · 事件可回放</span>
      </div>
      <div class="card-body">
        <AgentTimeline :events="events" :live="live" />
      </div>
    </div>

    <div>
      <div class="card" style="margin-bottom: 16px">
        <div class="card-head"><h2 class="card-title">扫描元信息</h2></div>
        <div class="card-body" style="padding-top: 8px">
          <div class="kv"><span>scan_id</span><span class="mono">{{ detail?.scan_id }}</span></div>
          <div class="kv"><span>开始</span><span class="mono">{{ fmtTime(detail?.started_at) }}</span></div>
          <div class="kv"><span>结束</span><span class="mono">{{ fmtTime(detail?.finished_at) }}</span></div>
          <div class="kv"><span>裁决</span><span class="mono">{{ detail?.verdict ?? '—' }}</span></div>
          <div class="kv">
            <span>LLM 降级</span>
            <span :style="{ color: detail?.llm_degraded ? 'var(--warn)' : 'var(--ink-2)' }">
              {{ detail?.llm_degraded ? '是（已降级为空模）' : '否' }}
            </span>
          </div>
          <div v-if="detail?.degraded_reasons?.length" class="divider" />
          <div v-for="reason in detail?.degraded_reasons ?? []" :key="reason" class="dim" style="font-size: 12px">
            · {{ reason }}
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-head">
          <h2 class="card-title">完整报告</h2>
          <button class="btn" style="height: 26px; font-size: 12px" @click="toggleReport">
            {{ report ? '收起' : '查看 JSON' }}
          </button>
        </div>
        <div class="card-body">
          <div v-if="reportError" class="error-box">{{ reportError }}</div>
          <pre v-else-if="report" class="pre" style="max-height: 320px">{{ JSON.stringify(report, null, 2) }}</pre>
          <div v-else class="dim" style="font-size: 12px">
            报告由报告聚合 Agent 落盘，保留 PR 评论 Markdown 与结构化 JSON。
          </div>
        </div>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-head">
      <h2 class="card-title">发现项 · {{ findings.length }} 项</h2>
      <div class="toolbar">
        <select v-model="severityFilter" class="select" style="height: 28px; font-size: 12px">
          <option value="">全部严重级</option>
          <option value="critical">严重</option>
          <option value="high">高危</option>
          <option value="medium">中危</option>
          <option value="low">低危</option>
        </select>
        <span class="dim" style="font-size: 12px">阻断 {{ blockingCount }} 项</span>
      </div>
    </div>
    <div class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th>严重级</th>
            <th>类型</th>
            <th>标识</th>
            <th>包 / 位置</th>
            <th>版本影响</th>
            <th>裁决</th>
            <th>证据来源</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="item in findings" :key="item.id">
            <td><SeverityTag :severity="item.severity" /></td>
            <td>
              <span class="badge" :class="item.finding_type === 'vulnerability' ? 'st-warn' : 'st-muted'">
                {{ item.finding_type === 'vulnerability' ? '依赖漏洞' : '代码问题' }}
              </span>
            </td>
            <td class="mono">{{ item.finding_id || '—' }}</td>
            <td>
              <span v-if="item.package_name" class="mono">{{ item.package_name }}</span>
              <span v-else class="mono">{{ item.file_path }}<span v-if="item.line_number">:L{{ item.line_number }}</span></span>
              <div v-if="item.message" class="dim" style="font-size: 11.5px; max-width: 380px">
                {{ item.message.slice(0, 90) }}
              </div>
            </td>
            <td class="mono" style="font-size: 12px">
              <span v-if="item.package_name">{{ item.installed_version || '?' }} → {{ item.fixed_version || '无修复版本' }}</span>
              <span v-else class="dim">—</span>
            </td>
            <td>
              <span class="badge" :class="item.verdict === 'block' ? 'st-block' : item.verdict === 'waive' ? 'st-muted' : 'st-warn'">
                {{ item.verdict === 'block' ? '阻断' : item.verdict === 'waive' ? '豁免' : item.verdict === 'defer' ? '延期' : '未裁决' }}
              </span>
            </td>
            <td>
              <span class="dim" style="font-size: 12px">{{ item.evidence_source || '—' }}</span>
            </td>
          </tr>
          <tr v-if="!findings.length">
            <td colspan="7" class="empty">
              <strong>{{ detail?.status === 'running' ? '扫描进行中' : '没有发现项' }}</strong>
              {{ detail?.status === 'running' ? '安全链路完成后会自动回填' : '该次扫描未命中漏洞或规则' }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<style scoped>
.kv {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 6px 0;
  font-size: 12.5px;
  color: var(--ink-2);
  border-bottom: 1px dashed #f1f2f4;
}

.kv:last-child {
  border-bottom: none;
}

.kv .mono {
  color: var(--ink);
  max-width: 60%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.sev-row {
  display: flex;
  gap: 6px;
  margin-top: 8px;
}

.sev-chip {
  font-family: var(--mono);
  font-size: 13px;
  font-weight: 600;
  border-radius: 6px;
  padding: 2px 9px;
}
</style>
