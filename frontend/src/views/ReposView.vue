<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api } from '../api'
import { fmtTime } from '../format'
import type { RepoItem } from '../types'

const loading = ref(true)
const error = ref('')
const notice = ref('')
const repos = ref<RepoItem[]>([])
const install = ref<{ url: string; app_slug: string; configured: boolean } | null>(null)

const form = ref<{ repo_full_name: string; installation_id: number | string }>({
  repo_full_name: '',
  installation_id: '',
})
const saving = ref(false)

const enabledCount = computed(() => repos.value.filter((repo) => repo.enabled).length)

async function load() {
  loading.value = true
  error.value = ''
  try {
    const [repoData, installData] = await Promise.all([api.listRepos(), api.installUrl()])
    repos.value = repoData.items
    install.value = installData
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

async function addRepo() {
  const name = form.value.repo_full_name.trim()
  if (!name) return
  saving.value = true
  error.value = ''
  notice.value = ''
  try {
    await api.authorizeRepo({
      repo_full_name: name,
      installation_id: Number(form.value.installation_id) || 0,
    })
    form.value = { repo_full_name: '', installation_id: '' }
    notice.value = `已授权 ${name}`
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    saving.value = false
  }
}

async function toggle(repo: RepoItem) {
  try {
    await api.toggleRepo({ repo_full_name: repo.repo_full_name, enabled: !repo.enabled })
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  }
}

function openInstall() {
  if (install.value?.url) {
    window.open(install.value.url, '_blank', 'noopener')
  }
}

onMounted(load)
</script>

<template>
  <div class="page-head">
    <div>
      <h1 class="page-title">仓库授权</h1>
      <p class="page-desc">GitHub App 安装后自动同步仓库，也可在离线演示下手动登记</p>
    </div>
    <div class="toolbar">
      <button class="btn" :disabled="loading" @click="load"><span v-if="loading" class="spinner" />刷新</button>
      <button class="btn btn-primary" :disabled="!install?.configured" @click="openInstall">
        安装 GitHub App
      </button>
    </div>
  </div>

  <div v-if="error" class="error-box" style="margin-bottom: 14px">{{ error }}</div>
  <div v-if="notice" class="notice">{{ notice }}</div>

  <div class="repo-cards" style="margin-bottom: 16px">
    <div class="card kpi">
      <div class="kpi-label">已授权仓库</div>
      <div class="kpi-value">{{ repos.length }}</div>
      <div class="kpi-foot">installation 归属唯一</div>
    </div>
    <div class="card kpi">
      <div class="kpi-label">启用扫描</div>
      <div class="kpi-value" style="color: var(--ok)">{{ enabledCount }}</div>
      <div class="kpi-foot">关闭后 webhook 直接忽略</div>
    </div>
    <div class="card kpi">
      <div class="kpi-label">GitHub App 状态</div>
      <div class="kpi-value" style="font-size: 16px; font-family: inherit">
        <span v-if="install?.configured" style="color: var(--ok)">已配置 · {{ install.app_slug }}</span>
        <span v-else style="color: var(--warn)">未配置</span>
      </div>
      <div class="kpi-foot">
        {{ install?.configured
          ? 'JWT（RS256）→ installation token 已就绪'
          : '需要 GITHUB_APP_ID / GITHUB_APP_PRIVATE_KEY；离线演示可走下方手动登记' }}
      </div>
    </div>
  </div>

  <div class="card" style="margin-bottom: 16px">
    <div class="card-head"><h2 class="card-title">手动登记仓库</h2></div>
    <div class="card-body toolbar">
      <input
        v-model="form.repo_full_name"
        class="input"
        style="width: 300px"
        placeholder="owner/repo，如 encode/fastapi"
        @keyup.enter="addRepo"
      />
      <input
        v-model.number="form.installation_id"
        class="input"
        style="width: 160px"
        type="number"
        placeholder="installation_id"
      />
      <button class="btn btn-primary" :disabled="saving || !form.repo_full_name.trim()" @click="addRepo">
        <span v-if="saving" class="spinner" />授权
      </button>
      <span class="dim" style="font-size: 12px">写库并记一条审计日志（repo_authorized）</span>
    </div>
  </div>

  <div class="card">
    <div class="card-head">
      <h2 class="card-title">授权列表</h2>
      <span class="dim" style="font-size: 12px">{{ repos.length }} 个仓库</span>
    </div>
    <div class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th>仓库</th>
            <th>installation</th>
            <th>默认分支</th>
            <th>授权时间</th>
            <th>最近扫描</th>
            <th>状态</th>
            <th style="text-align: right">操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="repo in repos" :key="repo.repo_full_name">
            <td class="mono">{{ repo.repo_full_name }}</td>
            <td class="num">{{ repo.installation_id || '—' }}</td>
            <td class="mono" style="font-size: 12px">{{ repo.default_branch }}</td>
            <td class="dim" style="font-size: 12px">{{ fmtTime(repo.authorized_at) }}</td>
            <td class="dim" style="font-size: 12px">{{ fmtTime(repo.last_scan_at) }}</td>
            <td>
              <span class="badge" :class="repo.enabled ? 'st-pass' : 'st-muted'">
                <span class="badge-dot" />{{ repo.enabled ? '扫描中' : '已暂停' }}
              </span>
            </td>
            <td style="text-align: right">
              <button class="btn" style="height: 26px; font-size: 12px" @click="toggle(repo)">
                {{ repo.enabled ? '暂停' : '启用' }}
              </button>
            </td>
          </tr>
          <tr v-if="!repos.length && !loading">
            <td colspan="7" class="empty">
              <strong>还没有授权仓库</strong>安装 GitHub App，或用上方表单手动登记一个
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<style scoped>
.repo-cards {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 16px;
}

@media (max-width: 1100px) {
  .repo-cards {
    grid-template-columns: 1fr;
  }
}

.notice {
  border: 1px solid #bbf7d0;
  background: var(--ok-soft);
  color: #166534;
  padding: 9px 12px;
  border-radius: 8px;
  font-size: 13px;
  margin-bottom: 14px;
}
</style>
