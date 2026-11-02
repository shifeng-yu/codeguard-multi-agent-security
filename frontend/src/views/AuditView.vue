<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api } from '../api'
import { fmtTime } from '../format'
import type { AuditItem } from '../types'

const ACTION_OPTIONS = [
  'scan_started',
  'verdict_made',
  'vulnerability_found',
  'appeal_submitted',
  'appeal_approved',
  'blocking_executed',
  'repo_authorized',
  'repo_toggled',
]

const loading = ref(true)
const error = ref('')
const items = ref<AuditItem[]>([])
const total = ref(0)
const page = ref(1)
const pageSize = 20

const action = ref('')
const scanId = ref('')
const operator = ref('')

const expanded = ref<number | null>(null)
const verifying = ref(false)
const verifyResult = ref<{ valid: boolean; total_rows: number; bad_rows: unknown[] } | null>(null)

const totalPages = computed(() => Math.max(1, Math.ceil(total.value / pageSize)))

async function load() {
  loading.value = true
  error.value = ''
  try {
    const data = await api.listAudit({
      action: action.value || undefined,
      scan_id: scanId.value.trim() || undefined,
      operator: operator.value.trim() || undefined,
      limit: pageSize,
      offset: (page.value - 1) * pageSize,
    })
    items.value = data.items
    total.value = data.count
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
  action.value = ''
  scanId.value = ''
  operator.value = ''
  applyFilters()
}

async function verify() {
  verifying.value = true
  verifyResult.value = null
  try {
    verifyResult.value = await api.verifyAudit()
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    verifying.value = false
  }
}

onMounted(load)
</script>

<template>
  <div class="page-head">
    <div>
      <h1 class="page-title">审计检索</h1>
      <p class="page-desc">只追加日志，行哈希串成链；点「校验链完整性」重算全表哈希</p>
    </div>
    <div class="toolbar">
      <button class="btn" :disabled="verifying" @click="verify">
        <span v-if="verifying" class="spinner" />校验链完整性
      </button>
      <button class="btn" :disabled="loading" @click="load">刷新</button>
    </div>
  </div>

  <div v-if="verifyResult" class="verify" :class="verifyResult.valid ? 'verify-ok' : 'verify-bad'">
    <strong>{{ verifyResult.valid ? '链完整' : '检测到篡改' }}</strong>
    <span>
      共 {{ verifyResult.total_rows }} 行，
      {{ verifyResult.valid ? '逐行 SHA-256 与存储哈希一致' : `发现 ${verifyResult.bad_rows.length} 行不匹配` }}
    </span>
  </div>

  <div v-if="error" class="error-box" style="margin-bottom: 14px">{{ error }}</div>

  <div class="card" style="margin-bottom: 14px">
    <div class="card-body toolbar">
      <select v-model="action" class="select" style="width: 190px" @change="applyFilters">
        <option value="">全部动作</option>
        <option v-for="option in ACTION_OPTIONS" :key="option" :value="option">{{ option }}</option>
      </select>
      <input
        v-model="scanId"
        class="input"
        style="width: 240px"
        placeholder="scan_id"
        @keyup.enter="applyFilters"
      />
      <input
        v-model="operator"
        class="input"
        style="width: 160px"
        placeholder="operator（system / console）"
        @keyup.enter="applyFilters"
      />
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
            <th style="width: 64px">#</th>
            <th>时间</th>
            <th>动作</th>
            <th>操作者</th>
            <th>scan_id</th>
            <th>行哈希</th>
          </tr>
        </thead>
        <tbody>
          <template v-for="item in items" :key="item.id">
            <tr class="row-link" @click="expanded = expanded === item.id ? null : item.id">
              <td class="num dim">{{ item.id }}</td>
              <td class="mono" style="font-size: 12px">{{ fmtTime(item.timestamp) }}</td>
              <td>
                <span class="badge" :class="item.action.includes('block') || item.action.includes('verdict') ? 'st-block' : 'st-muted'">
                  {{ item.action }}
                </span>
              </td>
              <td class="mono" style="font-size: 12px">{{ item.operator }}</td>
              <td class="mono dim" style="font-size: 11.5px">{{ item.scan_id || '—' }}</td>
              <td class="hash">{{ item.row_hash.slice(0, 18) }}…</td>
            </tr>
            <tr v-if="expanded === item.id">
              <td colspan="6" style="background: #fbfcfe">
                <pre class="pre" style="margin: 0">{{ JSON.stringify(item.detail, null, 2) }}</pre>
                <div class="hash" style="margin-top: 6px">row_hash: {{ item.row_hash }}</div>
              </td>
            </tr>
          </template>
          <tr v-if="!items.length && !loading">
            <td colspan="6" class="empty"><strong>没有匹配的审计记录</strong>触发一次扫描或授权仓库后会写入</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="card-body toolbar" style="border-top: 1px solid var(--line)">
      <button class="btn" :disabled="page <= 1" @click="page--, load()">上一页</button>
      <span class="dim" style="font-size: 12px">第 {{ page }} / {{ totalPages }} 页</span>
      <button class="btn" :disabled="page >= totalPages" @click="page++, load()">下一页</button>
    </div>
  </div>
</template>

<style scoped>
.verify {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 11px 14px;
  border-radius: 8px;
  font-size: 13px;
  margin-bottom: 14px;
}

.verify-ok {
  border: 1px solid #bbf7d0;
  background: var(--ok-soft);
  color: #166534;
}

.verify-bad {
  border: 1px solid #fecaca;
  background: var(--danger-soft);
  color: #991b1b;
}
</style>
