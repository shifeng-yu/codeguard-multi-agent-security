<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import StatusBadge from '../components/StatusBadge.vue'
import { api } from '../api'
import { fmtDuration, fmtTime } from '../format'
import type { ScanItem } from '../types'

const router = useRouter()

const loading = ref(true)
const error = ref('')
const items = ref<ScanItem[]>([])
const total = ref(0)
const page = ref(1)
const pageSize = ref(20)

const repo = ref('')
const verdict = ref('')
const status = ref('')

const totalPages = computed(() => Math.max(1, Math.ceil(total.value / pageSize.value)))

async function load() {
  loading.value = true
  error.value = ''
  try {
    const data = await api.listScans({
      page: page.value,
      page_size: pageSize.value,
      repo: repo.value.trim() || undefined,
      verdict: verdict.value || undefined,
      status: status.value || undefined,
    })
    items.value = data.items
    total.value = data.total
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

function applyFilters() {
  page.value = 1
  load()
}

function reset() {
  repo.value = ''
  verdict.value = ''
  status.value = ''
  applyFilters()
}

function go(next: number) {
  const target = Math.min(Math.max(1, next), totalPages.value)
  if (target === page.value) return
  page.value = target
  load()
}

onMounted(load)
</script>

<template>
  <div class="page-head">
    <div>
      <h1 class="page-title">任务列表</h1>
      <p class="page-desc">PR 触发的每一次扫描，含触发方式、结论与耗时</p>
    </div>
    <div class="toolbar">
      <button class="btn" :disabled="loading" @click="load">
        <span v-if="loading" class="spinner" />刷新
      </button>
    </div>
  </div>

  <div v-if="error" class="error-box" style="margin-bottom: 14px">加载失败：{{ error }}</div>

  <div class="card" style="margin-bottom: 14px">
    <div class="card-body toolbar">
      <input
        v-model="repo"
        class="input"
        style="width: 260px"
        placeholder="按仓库过滤，如 encode/fastapi"
        @keyup.enter="applyFilters"
      />
      <select v-model="verdict" class="select" @change="applyFilters">
        <option value="">全部结论</option>
        <option value="block">阻断</option>
        <option value="pass">通过</option>
        <option value="human_review">待人工裁决</option>
      </select>
      <select v-model="status" class="select" @change="applyFilters">
        <option value="">全部状态</option>
        <option value="running">运行中</option>
        <option value="completed">已完成</option>
        <option value="failed">失败</option>
      </select>
      <button class="btn btn-primary" @click="applyFilters">查询</button>
      <button class="btn" @click="reset">重置</button>
      <span class="dim" style="margin-left: auto; font-size: 12px">共 {{ total }} 条</span>
    </div>
  </div>

  <div class="card">
    <div class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th>仓库</th>
            <th>PR / Commit</th>
            <th>触发</th>
            <th>状态</th>
            <th>结论</th>
            <th>CVE</th>
            <th>代码问题</th>
            <th>耗时</th>
            <th>开始时间</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="scan in items"
            :key="scan.scan_id"
            class="row-link"
            @click="router.push(`/scans/${scan.scan_id}`)"
          >
            <td>
              <div class="mono">{{ scan.repo || '—' }}</div>
              <div class="dim" style="font-size: 11px">{{ scan.scan_id }}</div>
            </td>
            <td class="num">
              <span v-if="scan.pr_number">#{{ scan.pr_number }}</span>
              <span v-else class="dim">—</span>
              <div class="dim" style="font-size: 11px">{{ scan.head_sha?.slice(0, 8) || '—' }}</div>
            </td>
            <td>
              <span class="badge" :class="scan.trigger_type === 'webhook' ? 'st-running' : 'st-muted'">
                {{ scan.trigger_type === 'webhook' ? 'Webhook' : '手动' }}
              </span>
            </td>
            <td><StatusBadge :status="scan.status" :verdict="scan.verdict" /></td>
            <td>
              <span class="mono" style="font-size: 12px">
                {{ scan.verdict === 'block' ? `阻断 ${scan.blocker_count}` : scan.verdict ?? '—' }}
              </span>
            </td>
            <td class="num">{{ scan.cve_count }}</td>
            <td class="num">{{ scan.code_issue_count }}</td>
            <td class="num">{{ fmtDuration(scan.duration_ms) }}</td>
            <td class="dim nowrap" style="font-size: 12px">{{ fmtTime(scan.started_at) }}</td>
          </tr>
          <tr v-if="!items.length && !loading">
            <td colspan="9" class="empty">
              <strong>没有匹配的扫描</strong>换个过滤条件，或先触发一次 PR 扫描
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="card-body toolbar" style="border-top: 1px solid var(--line)">
      <button class="btn" :disabled="page <= 1" @click="go(page - 1)">上一页</button>
      <span class="dim" style="font-size: 12px">第 {{ page }} / {{ totalPages }} 页</span>
      <button class="btn" :disabled="page >= totalPages" @click="go(page + 1)">下一页</button>
    </div>
  </div>
</template>
